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
