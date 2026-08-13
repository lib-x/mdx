package mdx

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/op/go-logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLoggerSuppressesDebug(t *testing.T) {
	assert.False(t, log.IsEnabledFor(logging.DEBUG))
}

func TestPrepareForResolveSkipsKeyEntries(t *testing.T) {
	dictPath, entries := writeSyntheticMDX(t, 10_000)

	dict, err := New(dictPath)
	require.NoError(t, err)
	require.NoError(t, dict.PrepareForResolve())

	assert.Nil(t, dict.keyBlockInfo)
	assert.Nil(t, dict.keyBlockData)
	assert.Equal(t, int64(len(entries)), dict.DictionaryInfo().EntryCount)

	content, err := dict.Resolve(entries[0])
	require.NoError(t, err)
	assert.Equal(t, "definition-00000", string(content))
}

func TestPrepareForExternalIndexStillExportsAndResolves(t *testing.T) {
	dictPath, entries := writeSyntheticMDX(t, 100)

	dict, err := New(dictPath)
	require.NoError(t, err)
	require.NoError(t, dict.PrepareForExternalIndex())

	exported, err := dict.ExportIndex()
	require.NoError(t, err)
	require.Len(t, exported, len(entries))
	for i := range len(exported) - 1 {
		assert.Equal(t, entries[i].Keyword, exported[i].Keyword)
		assert.Equal(t, entries[i].RecordStartOffset, exported[i].RecordStartOffset)
		assert.Equal(t, entries[i].RecordEndOffset, exported[i].RecordEndOffset)
	}
	assert.Equal(t, entries[len(entries)-1].Keyword, exported[len(exported)-1].Keyword)
	assert.Equal(t, entries[len(entries)-1].RecordStartOffset, exported[len(exported)-1].RecordStartOffset)
	assert.Zero(t, exported[len(exported)-1].RecordEndOffset)

	content, err := dict.Resolve(exported[len(exported)-1])
	require.NoError(t, err)
	assert.Equal(t, "definition-00099", string(content))
}

func TestResolveReusesSameRecordBlock(t *testing.T) {
	dictPath, entries := writeSyntheticMDX(t, 10)
	dict, err := New(dictPath)
	require.NoError(t, err)
	require.NoError(t, dict.PrepareForResolve())

	first, err := dict.Resolve(entries[0])
	require.NoError(t, err)
	assert.Equal(t, "definition-00000", string(first))
	first[0] = 'X'
	require.NoError(t, os.Remove(dictPath))
	firstAgain, err := dict.Resolve(entries[0])
	require.NoError(t, err)
	assert.Equal(t, "definition-00000", string(firstAgain))

	second, err := dict.Resolve(entries[1])
	require.NoError(t, err)
	assert.Equal(t, "definition-00001", string(second))
}

func TestRecordBlockCacheCombinesConcurrentMisses(t *testing.T) {
	t.Parallel()

	var cache recordBlockCache
	var loads atomic.Int64
	key := recordBlockCacheKey{fileOffset: 42, compressedSize: 8, decompressedSize: 4}

	const goroutines = 32
	type cacheResult struct {
		data []byte
		err  error
	}
	results := make(chan cacheResult, goroutines)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := cache.get(key, func() ([]byte, error) {
				loads.Add(1)
				return []byte("data"), nil
			})
			results <- cacheResult{data: data, err: err}
		}()
	}
	wg.Wait()
	close(results)

	assert.Equal(t, int64(1), loads.Load())
	for result := range results {
		require.NoError(t, result.err)
		assert.Equal(t, []byte("data"), result.data)
	}
}

func TestRecordBlockCacheLoadsDifferentBlocksConcurrently(t *testing.T) {
	t.Parallel()

	var cache recordBlockCache
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan error, 2)
	load := func(value string) func() ([]byte, error) {
		return func() ([]byte, error) {
			started <- struct{}{}
			<-release
			return []byte(value), nil
		}
	}

	go func() {
		_, err := cache.get(recordBlockCacheKey{fileOffset: 10}, load("one"))
		results <- err
	}()
	go func() {
		_, err := cache.get(recordBlockCacheKey{fileOffset: 20}, load("two"))
		results <- err
	}()

	<-started
	<-started
	close(release)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
}

func TestRecordBlockCacheEvictsPreviousBlock(t *testing.T) {
	t.Parallel()

	var cache recordBlockCache
	firstKey := recordBlockCacheKey{fileOffset: 10, compressedSize: 8, decompressedSize: 4}
	secondKey := recordBlockCacheKey{fileOffset: 20, compressedSize: 8, decompressedSize: 4}

	first, err := cache.get(firstKey, func() ([]byte, error) { return []byte("one"), nil })
	require.NoError(t, err)
	assert.Equal(t, []byte("one"), first)
	second, err := cache.get(secondKey, func() ([]byte, error) { return []byte("two"), nil })
	require.NoError(t, err)
	assert.Equal(t, []byte("two"), second)

	var reloads atomic.Int64
	first, err = cache.get(firstKey, func() ([]byte, error) {
		reloads.Add(1)
		return []byte("one-reloaded"), nil
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("one-reloaded"), first)
	assert.Equal(t, int64(1), reloads.Load())
}

func TestResolveEvictsPreviousRecordBlock(t *testing.T) {
	t.Parallel()

	firstBlock := uncompressedRecordBlock([]byte("one"))
	secondBlock := uncompressedRecordBlock([]byte("two"))
	path := filepath.Join(t.TempDir(), "two-blocks.mdx")
	require.NoError(t, os.WriteFile(path, append(firstBlock, secondBlock...), 0o600))

	base := &MdictBase{
		filePath: path,
		fileType: MdictTypeMdx,
		meta:     &mdictMeta{encoding: EncodingUtf8},
	}
	first := &MDictKeywordIndex{
		KeywordEntry: MDictKeywordEntry{KeyWord: "first"},
		RecordBlock: MDictKeywordIndexRecordBlock{
			DataStartOffset:          0,
			CompressSize:             int64(len(firstBlock)),
			DeCompressSize:           3,
			KeyWordPartDataEndOffset: 3,
		},
	}
	second := &MDictKeywordIndex{
		KeywordEntry: MDictKeywordEntry{KeyWord: "second"},
		RecordBlock: MDictKeywordIndexRecordBlock{
			DataStartOffset:          int64(len(firstBlock)),
			CompressSize:             int64(len(secondBlock)),
			DeCompressSize:           3,
			KeyWordPartDataEndOffset: 3,
		},
	}

	data, err := base.locateByKeywordIndex(first)
	require.NoError(t, err)
	assert.Equal(t, []byte("one"), data)
	data, err = base.locateByKeywordIndex(second)
	require.NoError(t, err)
	assert.Equal(t, []byte("two"), data)
	require.NoError(t, os.Remove(path))

	_, err = base.locateByKeywordIndex(first)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error opening file")
}

func TestBuildIndexStillSupportsLookup(t *testing.T) {
	dictPath, _ := writeSyntheticMDX(t, 100)

	dict, err := New(dictPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	content, err := dict.Lookup("word-00042")
	require.NoError(t, err)
	assert.Equal(t, "definition-00042", string(content))
}

func BenchmarkMdictPreparation(b *testing.B) {
	dictPath, _ := writeSyntheticMDX(b, 10_000)

	b.Run("external-index", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dict, err := New(dictPath)
			if err != nil {
				b.Fatal(err)
			}
			if err := dict.PrepareForExternalIndex(); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("resolve", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dict, err := New(dictPath)
			if err != nil {
				b.Fatal(err)
			}
			if err := dict.PrepareForResolve(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkMdictResolveSameRecordBlock(b *testing.B) {
	dictPath, entries := writeSyntheticMDX(b, 100)
	dict, err := New(dictPath)
	if err != nil {
		b.Fatal(err)
	}
	if err := dict.PrepareForResolve(); err != nil {
		b.Fatal(err)
	}
	entries = entries[:10]

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resolvedBytes := 0
		for _, entry := range entries {
			definition, err := dict.Resolve(entry)
			if err != nil {
				b.Fatal(err)
			}
			resolvedBytes += len(definition)
		}
		if resolvedBytes == 0 {
			b.Fatal("resolved definitions are empty")
		}
	}
}

func writeSyntheticMDX(tb testing.TB, entryCount int) (string, []IndexEntry) {
	tb.Helper()

	definitions := make([]byte, 0, entryCount*16)
	keyBlock := make([]byte, 0, entryCount*24)
	entries := make([]IndexEntry, 0, entryCount)
	for i := range entryCount {
		keyword := []byte(formatSyntheticValue("word", i))
		definition := []byte(formatSyntheticValue("definition", i))
		start := int64(len(definitions))
		definitions = append(definitions, definition...)
		end := int64(len(definitions))

		keyBlock = binary.BigEndian.AppendUint64(keyBlock, uint64(start))
		keyBlock = append(keyBlock, keyword...)
		keyBlock = append(keyBlock, 0)
		entries = append(entries, IndexEntry{
			Keyword:           string(keyword),
			RecordStartOffset: start,
			RecordEndOffset:   end,
		})
	}

	compressedKeyBlock := zlibBytes(tb, keyBlock)
	keyBlockData := make([]byte, 0, len(compressedKeyBlock)+8)
	keyBlockData = append(keyBlockData, 2, 0, 0, 0)
	keyBlockData = binary.BigEndian.AppendUint32(keyBlockData, adler32.Checksum(keyBlock))
	keyBlockData = append(keyBlockData, compressedKeyBlock...)

	firstKeyword := []byte(entries[0].Keyword)
	lastKeyword := []byte(entries[len(entries)-1].Keyword)
	keyInfo := make([]byte, 0, 64)
	keyInfo = binary.BigEndian.AppendUint64(keyInfo, uint64(entryCount))
	keyInfo = binary.BigEndian.AppendUint16(keyInfo, uint16(len(firstKeyword)))
	keyInfo = append(keyInfo, firstKeyword...)
	keyInfo = append(keyInfo, 0)
	keyInfo = binary.BigEndian.AppendUint16(keyInfo, uint16(len(lastKeyword)))
	keyInfo = append(keyInfo, lastKeyword...)
	keyInfo = append(keyInfo, 0)
	keyInfo = binary.BigEndian.AppendUint64(keyInfo, uint64(len(keyBlockData)))
	keyInfo = binary.BigEndian.AppendUint64(keyInfo, uint64(len(keyBlock)))
	compressedKeyInfo := zlibBytes(tb, keyInfo)
	keyInfoBlock := make([]byte, 0, len(compressedKeyInfo)+8)
	keyInfoBlock = append(keyInfoBlock, 2, 0, 0, 0)
	keyInfoBlock = binary.BigEndian.AppendUint32(keyInfoBlock, adler32.Checksum(keyInfo))
	keyInfoBlock = append(keyInfoBlock, compressedKeyInfo...)

	header := []byte(`<Dictionary GeneratedByEngineVersion="2.0" Encoding="UTF-8" Title="synthetic" Description="benchmark" />`)
	headerUTF16 := make([]byte, 0, (len(header)+1)*2)
	for _, value := range header {
		headerUTF16 = append(headerUTF16, value, 0)
	}
	headerUTF16 = append(headerUTF16, 0, 0)

	var file bytes.Buffer
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint32(len(headerUTF16))))
	_, err := file.Write(headerUTF16)
	require.NoError(tb, err)
	require.NoError(tb, binary.Write(&file, binary.LittleEndian, adler32.Checksum(headerUTF16)))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(1)))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(entryCount)))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(len(keyInfo))))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(len(keyInfoBlock))))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(len(keyBlockData))))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint32(0)))
	_, err = file.Write(keyInfoBlock)
	require.NoError(tb, err)
	_, err = file.Write(keyBlockData)
	require.NoError(tb, err)

	recordBlock := make([]byte, 0, len(definitions)+8)
	recordBlock = append(recordBlock, 0, 0, 0, 0)
	recordBlock = binary.BigEndian.AppendUint32(recordBlock, adler32.Checksum(definitions))
	recordBlock = append(recordBlock, definitions...)
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(1)))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(entryCount)))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(16)))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(len(recordBlock))))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(len(recordBlock))))
	require.NoError(tb, binary.Write(&file, binary.BigEndian, uint64(len(definitions))))
	_, err = file.Write(recordBlock)
	require.NoError(tb, err)

	path := filepath.Join(tb.TempDir(), "synthetic.mdx")
	require.NoError(tb, os.WriteFile(path, file.Bytes(), 0o600))
	return path, entries
}

func zlibBytes(tb testing.TB, data []byte) []byte {
	tb.Helper()
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	_, err := writer.Write(data)
	require.NoError(tb, err)
	require.NoError(tb, writer.Close())
	return compressed.Bytes()
}

func uncompressedRecordBlock(data []byte) []byte {
	block := []byte{0, 0, 0, 0}
	block = binary.BigEndian.AppendUint32(block, adler32.Checksum(data))
	return append(block, data...)
}

func formatSyntheticValue(prefix string, value int) string {
	buf := make([]byte, 0, len(prefix)+6)
	buf = append(buf, prefix...)
	buf = append(buf, '-')
	for divisor := 10_000; divisor > 0; divisor /= 10 {
		buf = append(buf, byte('0'+value/divisor%10))
	}
	return string(buf)
}
