package mdx

import (
	"encoding/binary"
	"hash/adler32"
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
	require.NotNil(t, base.comparableLookup)
	require.NotNil(t, base.resourceComparableLookup)
	assert.Same(t, ability, base.exactLookup["ability"])
	assert.Same(t, ability, base.comparableLookup["ability"])
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

func TestMdictBaseParseKeyBlockMeta_UsesPlainMetadataWhenKeyInfoIsEncrypted(t *testing.T) {
	t.Parallel()

	rawMeta := make([]byte, 40)
	binary.BigEndian.PutUint64(rawMeta[0:8], 3)
	binary.BigEndian.PutUint64(rawMeta[8:16], 9)
	binary.BigEndian.PutUint64(rawMeta[16:24], 128)
	binary.BigEndian.PutUint64(rawMeta[24:32], 64)
	binary.BigEndian.PutUint64(rawMeta[32:40], 256)

	base := &MdictBase{
		filePath: "encrypted-key-info.mdx",
		meta: &mdictMeta{
			version:                 2,
			numberWidth:             8,
			encryptType:             EncryptKeyInfoEnc,
			keyBlockMetaStartOffset: 18,
		},
	}

	meta, err := base.parseKeyBlockMeta(rawMeta, 422)
	require.NoError(t, err)
	assert.Equal(t, int64(3), meta.keyBlockNum)
	assert.Equal(t, int64(9), meta.entriesNum)
	assert.Equal(t, int64(128), meta.keyBlockInfoDecompressSize)
	assert.Equal(t, int64(64), meta.keyBlockInfoCompressedSize)
	assert.Equal(t, int64(256), meta.keyBlockDataTotalSize)
}

func BenchmarkMdictBaseParseKeyBlockMeta_EncryptedKeyInfoPlainMetadata(b *testing.B) {
	rawMeta := make([]byte, 40)
	binary.BigEndian.PutUint64(rawMeta[0:8], 3)
	binary.BigEndian.PutUint64(rawMeta[8:16], 9)
	binary.BigEndian.PutUint64(rawMeta[16:24], 128)
	binary.BigEndian.PutUint64(rawMeta[24:32], 64)
	binary.BigEndian.PutUint64(rawMeta[32:40], 256)

	base := &MdictBase{
		filePath: "encrypted-key-info.mdx",
		meta: &mdictMeta{
			version:                 2,
			numberWidth:             8,
			encryptType:             EncryptKeyInfoEnc,
			keyBlockMetaStartOffset: 18,
		},
	}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = base.parseKeyBlockMeta(rawMeta, 422)
	}
}

func TestMdictBaseParseKeyBlockMeta_RejectsInvalidPlainAndLegacyMetadata(t *testing.T) {
	t.Parallel()

	base := &MdictBase{
		filePath: "invalid-encrypted-key-info.mdx",
		meta: &mdictMeta{
			version:                 2,
			numberWidth:             8,
			encryptType:             EncryptKeyInfoEnc,
			keyBlockMetaStartOffset: 18,
		},
	}

	meta, err := base.parseKeyBlockMeta(make([]byte, 40), 422)
	require.Error(t, err)
	assert.Nil(t, meta)
	assert.Contains(t, err.Error(), "parse key block metadata")
}

func TestMdictBaseDecodeKeyBlockInfo_StillDecryptsEncryptedKeyInfo(t *testing.T) {
	t.Parallel()

	keyInfo := make([]byte, 0, 40)
	keyInfo = binary.BigEndian.AppendUint64(keyInfo, 1)
	keyInfo = binary.BigEndian.AppendUint16(keyInfo, 1)
	keyInfo = append(keyInfo, 'a', 0)
	keyInfo = binary.BigEndian.AppendUint16(keyInfo, 1)
	keyInfo = append(keyInfo, 'z', 0)
	keyInfo = binary.BigEndian.AppendUint64(keyInfo, 8)
	keyInfo = binary.BigEndian.AppendUint64(keyInfo, 4)
	compressedKeyInfo := zlibBytes(t, keyInfo)
	keyInfoBlock := []byte{2, 0, 0, 0}
	keyInfoBlock = binary.BigEndian.AppendUint32(keyInfoBlock, adler32.Checksum(keyInfo))
	keyInfoBlock = append(keyInfoBlock, compressedKeyInfo...)
	encryptedKeyInfoBlock := encryptMDXBlockForTest(keyInfoBlock)

	base := &MdictBase{
		filePath: "encrypted-key-info.mdx",
		fileType: MdictTypeMdx,
		meta: &mdictMeta{
			version:     2,
			numberWidth: 8,
			encryptType: EncryptKeyInfoEnc,
			encoding:    EncodingUtf8,
		},
		keyBlockMeta: &mdictKeyBlockMeta{
			keyBlockNum:                1,
			entriesNum:                 1,
			keyBlockInfoDecompressSize: int64(len(keyInfo)),
			keyBlockInfoCompressedSize: int64(len(encryptedKeyInfoBlock)),
			keyBlockDataTotalSize:      8,
			keyBlockInfoStartOffset:    44,
		},
	}

	require.NoError(t, base.decodeKeyBlockInfo(encryptedKeyInfoBlock))
	require.NotNil(t, base.keyBlockInfo)
	require.Len(t, base.keyBlockInfo.keyBlockInfoList, 1)
	item := base.keyBlockInfo.keyBlockInfoList[0]
	assert.Equal(t, "a", item.firstKey)
	assert.Equal(t, "z", item.lastKey)
	assert.Equal(t, int64(8), item.keyBlockCompressSize)
	assert.Equal(t, int64(4), item.keyBlockDeCompressSize)
}

func TestMdictBaseReadKeyBlockMeta_RetriesLegacyMetadataDecryption(t *testing.T) {
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
	encryptedMeta := encryptMDXBlockForTest(rawMeta)

	file, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	require.NoError(t, binary.Write(file, binary.BigEndian, uint32(len(headerText))))
	_, err = file.Write(headerText)
	require.NoError(t, err)
	require.NoError(t, binary.Write(file, binary.LittleEndian, uint32(0)))
	_, err = file.Write(encryptedMeta)
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

func encryptMDXBlockForTest(plain []byte) []byte {
	encrypted := append([]byte(nil), plain...)
	keyInput := make([]byte, 8)
	copy(keyInput, encrypted[4:8])
	keyInput[4] = 0x95
	keyInput[5] = 0x36
	key := ripemd128bytes(keyInput)

	previous := byte(0x36)
	for i := range encrypted[8:] {
		ciphertext := encrypted[i+8] ^ byte(i) ^ key[i%len(key)] ^ previous
		ciphertext = ciphertext>>4 | ciphertext<<4
		encrypted[i+8] = ciphertext
		previous = ciphertext
	}
	return encrypted
}
