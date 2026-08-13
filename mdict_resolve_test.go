package mdx

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
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

func formatSyntheticValue(prefix string, value int) string {
	buf := make([]byte, 0, len(prefix)+6)
	buf = append(buf, prefix...)
	buf = append(buf, '-')
	for divisor := 10_000; divisor > 0; divisor /= 10 {
		buf = append(buf, byte('0'+value/divisor%10))
	}
	return string(buf)
}
