package mdx

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadMDictFileHeader_ReadsLittleEndianChecksum(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "header.mdx")

	headerText := []byte{'D', 0, 'i', 0, 'c', 0, 't', 0, 0, 0}
	checksum := uint32(0x01020304)

	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	require.NoError(t, binary.Write(file, binary.BigEndian, uint32(len(headerText))))
	_, err = file.Write(headerText)
	require.NoError(t, err)
	require.NoError(t, binary.Write(file, binary.LittleEndian, checksum))
	require.NoError(t, file.Close())

	header, err := readMDictFileHeader(path)
	require.NoError(t, err)
	assert.Equal(t, checksum, header.adler32Checksum)
	assert.Equal(t, "Dict\x00", header.headerInfo)
}

func TestParseXMLHeader_SupportsEncodingAndCreationDateAttributes(t *testing.T) {
	t.Parallel()

	header, err := parseXMLHeader(`<Dictionary GeneratedByEngineVersion="2.0" Encoding="UTF-8" CreationDate="2019-8-19" StripKey="Yes" Title="demo" />`)
	require.NoError(t, err)
	assert.Equal(t, "UTF-8", header.Encoding)
	assert.Equal(t, "2019-8-19", header.CreationDate)
	assert.Equal(t, "Yes", header.StripKey)
	assert.Equal(t, "demo", header.Title)
}

func TestMdictBaseDecodeRecordBlockMeta_RejectsEntryMismatch(t *testing.T) {
	t.Parallel()

	base := &MdictBase{
		filePath:     "unit-test.mdx",
		meta:         &mdictMeta{version: 2, numberWidth: 8},
		keyBlockMeta: &mdictKeyBlockMeta{entriesNum: 10},
	}

	buf := make([]byte, 32)
	binary.BigEndian.PutUint64(buf[0:8], 2)
	binary.BigEndian.PutUint64(buf[8:16], 9)
	binary.BigEndian.PutUint64(buf[16:24], 16)
	binary.BigEndian.PutUint64(buf[24:32], 32)

	err := base.decodeRecordBlockMeta(buf, 100, 132)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match key block entries number")
}

func TestMdictBaseBuildExactLookup_FindsUnsortedEntry(t *testing.T) {
	t.Parallel()

	ability := &MDictKeywordEntry{KeyWord: "ability", RecordStartOffset: 10, RecordEndOffset: 20}
	base := &MdictBase{
		keyBlockData: &mdictKeyBlockData{
			keyEntries: []*MDictKeywordEntry{
				{KeyWord: "a big fish", RecordStartOffset: 1},
				ability,
				{KeyWord: "abject", RecordStartOffset: 30},
			},
		},
	}

	base.buildExactLookup()
	require.NotNil(t, base.exactLookup)
	assert.Same(t, ability, base.exactLookup["ability"])
}

func TestReadFileFromPos_RejectsRangeBeyondFileSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "small.bin")
	require.NoError(t, os.WriteFile(path, []byte("abcd"), 0o600))

	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	_, err = readFileFromPos(file, 2, 8)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds file size")
}

func TestMdictBaseReadKeyBlockMeta_FallsBackWhenEncryptedMetadataLooksInvalid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted-meta.mdx")

	headerText := []byte{'D', 0, 'i', 0, 'c', 0, 't', 0, 0, 0}
	rawMeta := make([]byte, 40)
	binary.BigEndian.PutUint64(rawMeta[0:8], 3)
	binary.BigEndian.PutUint64(rawMeta[8:16], 9)
	binary.BigEndian.PutUint64(rawMeta[16:24], 128)
	binary.BigEndian.PutUint64(rawMeta[24:32], 64)
	binary.BigEndian.PutUint64(rawMeta[32:40], 256)

	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	require.NoError(t, binary.Write(file, binary.BigEndian, uint32(len(headerText))))
	_, err = file.Write(headerText)
	require.NoError(t, err)
	require.NoError(t, binary.Write(file, binary.LittleEndian, uint32(0)))
	_, err = file.Write(rawMeta)
	require.NoError(t, err)

	paddingSize := 44 + 64 + 256
	_, err = file.Write(make([]byte, paddingSize))
	require.NoError(t, err)
	require.NoError(t, file.Close())

	base := &MdictBase{
		filePath: path,
		meta: &mdictMeta{
			version:                 2,
			numberWidth:             8,
			encryptType:             EncryptKeyInfoEnc,
			keyBlockMetaStartOffset: int64(4 + len(headerText) + 4),
		},
	}

	require.NoError(t, base.readKeyBlockMeta())
	require.NotNil(t, base.keyBlockMeta)
	assert.Equal(t, int64(3), base.keyBlockMeta.keyBlockNum)
	assert.Equal(t, int64(9), base.keyBlockMeta.entriesNum)
	assert.Equal(t, int64(128), base.keyBlockMeta.keyBlockInfoDecompressSize)
	assert.Equal(t, int64(64), base.keyBlockMeta.keyBlockInfoCompressedSize)
	assert.Equal(t, int64(256), base.keyBlockMeta.keyBlockDataTotalSize)
	assert.Equal(t, int64(62), base.keyBlockMeta.keyBlockInfoStartOffset)
}
