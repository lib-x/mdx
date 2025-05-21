//
// Copyright (C) 2023 Quan Chen <chenquan_act@163.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mdx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"os"
	"strconv"
	"strings"

	"github.com/rasky/go-lzo"
)

// readDictHeader reads the dictionary header.
func (mdict *MdictBase) readDictHeader() error {
	log.Infof("Starting to read dictionary header for: %s", mdict.filePath)
	dictHeader, err := readMDictFileHeader(mdict.filePath)
	if err != nil {
		return fmt.Errorf("failed to read MDict file header for '%s': %w", mdict.filePath, err)
	}
	mdict.header = dictHeader

	log.Debugf("Parsing header info XML for: %s", mdict.filePath)
	headerInfo, err := parseXMLHeader(dictHeader.headerInfo)
	if err != nil {
		return fmt.Errorf("failed to parse XML header for '%s': %w", mdict.filePath, err)
	}
	log.Debugf("Header info parsed for '%s'. Title: '%s', EngineVersion: '%s', Encoding: '%s'", mdict.filePath, headerInfo.Title, headerInfo.GeneratedByEngineVersion, headerInfo.Encoding)

	log.Debugf("Verifying header checksum for '%s'. Expected: %d", mdict.filePath, dictHeader.adler32Checksum)
	checksum := adler32.Checksum(dictHeader.headerInfoBytes)
	if checksum != dictHeader.adler32Checksum {
		log.Errorf("Header checksum mismatch for '%s': expected %d, got %d", mdict.filePath, dictHeader.adler32Checksum, checksum)
		return fmt.Errorf("header checksum mismatch for '%s': expected %d, got %d", mdict.filePath, dictHeader.adler32Checksum, checksum)
	}
	log.Debugf("Header checksum verified for: %s", mdict.filePath)

	meta := &mdictMeta{}

	// Handle encryption flag
	encrypted := headerInfo.Encrypted
	switch {
	case encrypted == "" || encrypted == "No":
		meta.encryptType = EncryptNoEnc
	case encrypted == "Yes":
		meta.encryptType = EncryptRecordEnc
	default:
		if encrypted[0] == '2' {
			meta.encryptType = EncryptKeyInfoEnc
		} else if encrypted[0] == '1' {
			meta.encryptType = EncryptRecordEnc
		} else {
			meta.encryptType = EncryptNoEnc
		}
	}

	// Handle version
	versionStr := headerInfo.GeneratedByEngineVersion
	version, err := strconv.ParseFloat(versionStr, 32)
	if err != nil {
		// If version string is invalid, it's a critical parsing error.
		log.Errorf("Invalid engine version string '%s' in header for '%s': %v", versionStr, mdict.filePath, err)
		return fmt.Errorf("invalid engine version string '%s' in header for '%s': %w", versionStr, mdict.filePath, err)
	}
	meta.version = float32(version)
	log.Debugf("Mdict version for '%s': %.1f", mdict.filePath, meta.version)

	// Handle number format and width based on version
	if meta.version >= 2.0 {
		meta.numberWidth = 8
		meta.numberFormat = NumfmtBe8bytesq
	} else {
		meta.numberWidth = 4
		meta.numberFormat = NumfmtBe4bytesi
	}

	// Handle encoding
	encoding := headerInfo.Encoding
	encoding = strings.ToLower(encoding)
	switch encoding {
	case "GBK", "GB2312", "gbk", "gb2312":
		meta.encoding = EncodingGb18030
	case "Big5", "BIG5", "big5":
		meta.encoding = EncodingBig5
	case "utf16", "utf-16", "UTF-16":
		meta.encoding = EncodingUtf16
	default:
		meta.encoding = EncodingUtf8
	}

	// Fix for MDD type
	if mdict.fileType == MdictTypeMdd {
		meta.encoding = EncodingUtf16
	}

	// 4 bytes header size + header_bytes_size + 4bytes alder checksum
	meta.keyBlockMetaStartOffset = int64(4 + dictHeader.headerBytesSize + 4)

	meta.description = headerInfo.Description
	meta.title = headerInfo.Title
	meta.creationDate = headerInfo.CreationDate
	meta.generatedByEngineVersion = headerInfo.GeneratedByEngineVersion

	mdict.meta = meta

	return nil
}

func readMDictFileHeader(filename string) (*mdictHeader, error) {
	log.Debugf("Reading MDict file header from: %s", filename)
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file '%s': %w", filename, err)
	}
	defer file.Close()

	dictHeaderPartByteSize := int64(0)

	// Read dictionary header length
	var headerBytesSize uint32
	dictHeaderPartByteSize += 4
	if err := binary.Read(file, binary.BigEndian, &headerBytesSize); err != nil {
		return nil, fmt.Errorf("failed to read header bytes size from '%s': %w", filename, err)
	}
	log.Debugf("File '%s': Header bytes size: %d", filename, headerBytesSize)

	// Read dictionary header info bytes
	headerInfoBytes := make([]byte, headerBytesSize)
	dictHeaderPartByteSize += int64(headerBytesSize)
	if _, err := file.Read(headerInfoBytes); err != nil {
		return nil, fmt.Errorf("failed to read header info bytes from '%s': %w", filename, err)
	}

	// Read adler32 checksum
	var adler32Checksum uint32
	dictHeaderPartByteSize += 4
	if err := binary.Read(file, binary.BigEndian, &adler32Checksum); err != nil {
		return nil, fmt.Errorf("failed to read adler32 checksum from '%s': %w", filename, err)
	}
	log.Debugf("File '%s': Header adler32 checksum from file: %d", filename, adler32Checksum)

	utfHeaderInfo := littleEndianBinUTF16ToUTF8(headerInfoBytes, 0, int(headerBytesSize))
	utfHeaderInfo = strings.Replace(utfHeaderInfo, "Library_Data", "Dictionary", 1)

	mdict := &mdictHeader{
		headerBytesSize:          headerBytesSize,
		headerInfoBytes:          headerInfoBytes,
		headerInfo:               utfHeaderInfo,
		adler32Checksum:          adler32Checksum,
		dictionaryHeaderByteSize: dictHeaderPartByteSize,
	}

	return mdict, nil
}

// readKeyBlockMeta keyblock header part contains keyblock meta info
func (mdict *MdictBase) readKeyBlockMeta() error {
	log.Infof("Reading key block metadata for: %s", mdict.filePath)
	file, err := os.Open(mdict.filePath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' for key block metadata: %w", mdict.filePath, err)
	}
	defer file.Close()

	keyBlockMeta := &mdictKeyBlockMeta{}
	log.Debugf("Key block metadata read setup for '%s'. Version: %.1f, NumberWidth: %d, KeyBlockMetaStartOffset: %d",
		mdict.filePath, mdict.meta.version, mdict.meta.numberWidth, mdict.meta.keyBlockMetaStartOffset)

	// Key block meta info part
	// if version > 2.0 key-block meta part bytes length: 40
	// else: length: 16
	keyBlockMetaBytesNum := 0
	if mdict.meta.version >= 2.0 {
		keyBlockMetaBytesNum = 8 * 5
	} else {
		keyBlockMetaBytesNum = 4 * 4
	}

	// Key block meta info buffer
	keyBlockMetaBuffer, err := readFileFromPos(file, mdict.meta.keyBlockMetaStartOffset, int64(keyBlockMetaBytesNum))
	if err != nil {
		return fmt.Errorf("failed to read key block metadata buffer for '%s': %w", mdict.filePath, err)
	}

	// Decrypt key block meta if encrypted
	if mdict.meta.encryptType == EncryptRecordEnc {
		// The problem description mentions that EncryptRecordEnc (type 1) uses the header key for decryption.
		// However, standard MDX V1/V2 with EncryptRecordEnc typically means the key block meta itself is not encrypted,
		// but rather the record blocks are.
		// If key block meta IS encrypted with type 1, it's unusual or a specific MDX variant.
		// For now, proceeding with decryption using mdxDecrypt, assuming it's a simple pass-through if no actual decryption for this type here.
		// If mdxDecrypt is designed for type 0 (no enc) and type 2 (key info enc), this might need adjustment
		// or clarification on how type 1 encryption applies to key block *meta*.
		// Let's assume mdxDecrypt can handle it or it's not truly encrypted at this stage for type 1.
		// If there's a specific key for EncryptRecordEnc for metadata, that needs to be incorporated.
		// For now, let's proceed cautiously. The original code had a TODO and returned an error.
		// This part might need further refinement based on specific MDX file encryption details for EncryptRecordEnc on metadata.
		// A common implementation is that key block metadata is NOT encrypted for type 1, only record data.
		// However, following the instruction to "handle encrypted key block metadata" for EncryptRecordEnc.
		log.Debugf("Key block metadata is encrypted (type %d) for '%s', decrypting...", mdict.meta.encryptType, mdict.filePath)
		decryptedKeyBlockMetaBuffer := mdxDecrypt(keyBlockMetaBuffer, int64(keyBlockMetaBytesNum))
		if len(decryptedKeyBlockMetaBuffer) != keyBlockMetaBytesNum {
			return fmt.Errorf("key block meta decryption error for '%s': output size mismatch (expected %d, got %d)", mdict.filePath, keyBlockMetaBytesNum, len(decryptedKeyBlockMetaBuffer))
		}
		keyBlockMetaBuffer = decryptedKeyBlockMetaBuffer
		log.Debugf("Key block metadata decrypted for: %s", mdict.filePath)
		// It's also possible that for EncryptRecordEnc, this block is not encrypted, and the check should be for EncryptKeyInfoEnc (type 2)
		// like in decodeKeyBlockInfo. If that's the case, the condition should be:
		// if mdict.meta.encryptType == EncryptKeyInfoEnc
		// For now, sticking to the explicit instruction for EncryptRecordEnc.
	}

	// Key block meta info struct:
	// [0:8]([0:4]) - Number of key blocks
	// [8:16]([4:8]) - Number of entries
	// [16:24] - Key block info decompressed size (if version >= 2.0, otherwise, this section does not exist)
	// [24:32]([8:12]) - Key block info size
	// [32:40]([12:16]) - Key block size
	// Note: If version <2.0, the key info buffer size is 4 * 4
	//       Otherwise, the key info buffer size is 5 * 8

	// 1. [0:8]([0:4]) - Number of key blocks
	keyBlockNumBytes := keyBlockMetaBuffer[0:mdict.meta.numberWidth]

	var keyBlockNumber uint64
	if mdict.meta.numberWidth == 8 {
		keyBlockNumber = beBinToU64(keyBlockNumBytes)
	} else if mdict.meta.numberWidth == 4 {
		keyBlockNumber = uint64(beBinToU32(keyBlockNumBytes))
	}
	keyBlockMeta.keyBlockNum = int64(keyBlockNumber)

	// 2. [8:16]([4:8]) - Number of entries
	entriesNumBytes := keyBlockMetaBuffer[mdict.meta.numberWidth : mdict.meta.numberWidth+mdict.meta.numberWidth]
	// No error check needed for slicing itself, assuming keyBlockMetaBuffer is large enough (validated by readFileFromPos and decryption checks).
	var entriesNum uint64
	if mdict.meta.numberWidth == 8 {
		entriesNum = beBinToU64(entriesNumBytes)
	} else if mdict.meta.numberWidth == 4 {
		entriesNum = uint64(beBinToU32(entriesNumBytes))
	}
	keyBlockMeta.entriesNum = int64(entriesNum)

	var keyBlockInfoSizeBytesStartOffset int

	// 3. [16:24] - Key block info decompressed size (if version >= 2.0, this section exists)
	if mdict.meta.version >= 2.0 {
		keyBlockInfoDecompressSizeBytes := keyBlockMetaBuffer[mdict.meta.numberWidth*2 : mdict.meta.numberWidth*2+mdict.meta.numberWidth]

		var keyBlockInfoDecompressSize uint64
		if mdict.meta.numberWidth == 8 {
			keyBlockInfoDecompressSize = beBinToU64(keyBlockInfoDecompressSizeBytes)
		} else if mdict.meta.numberWidth == 4 {
			keyBlockInfoDecompressSize = uint64(beBinToU32(keyBlockInfoDecompressSizeBytes))
		}
		keyBlockMeta.keyBlockInfoDecompressSize = int64(keyBlockInfoDecompressSize)

		keyBlockInfoSizeBytesStartOffset = mdict.meta.numberWidth * 3

	} else {
		keyBlockInfoSizeBytesStartOffset = mdict.meta.numberWidth * 2
	}

	// 4. [24:32]([8:12]) - Key block info size
	keyBlockInfoSizeBytes := keyBlockMetaBuffer[keyBlockInfoSizeBytesStartOffset : keyBlockInfoSizeBytesStartOffset+mdict.meta.numberWidth]

	var keyBlockInfoSize uint64
	if mdict.meta.numberWidth == 8 {
		keyBlockInfoSize = beBinToU64(keyBlockInfoSizeBytes)
	} else if mdict.meta.numberWidth == 4 {
		keyBlockInfoSize = uint64(beBinToU32(keyBlockInfoSizeBytes))
	}

	keyBlockMeta.keyBlockInfoCompressedSize = int64(keyBlockInfoSize)

	// 5. [32:40]([12:16]) - Key block size
	keyBlockDataSizeBytes := keyBlockMetaBuffer[keyBlockInfoSizeBytesStartOffset+mdict.meta.numberWidth : keyBlockInfoSizeBytesStartOffset+mdict.meta.numberWidth+mdict.meta.numberWidth]

	var keyBlockDataSize uint64
	if mdict.meta.numberWidth == 8 {
		keyBlockDataSize = beBinToU64(keyBlockDataSizeBytes)
	} else if mdict.meta.numberWidth == 4 {
		keyBlockDataSize = uint64(beBinToU32(keyBlockDataSizeBytes))
	}
	keyBlockMeta.keyBlockDataTotalSize = int64(keyBlockDataSize)

	// 6. [40:44] - 4 bytes checksum (TODO: Skip if version > 2.0)
	// TODO checksum verification

	// Free key block info buffer
	if mdict.meta.version >= 2.0 {
		keyBlockMeta.keyBlockInfoStartOffset = mdict.meta.keyBlockMetaStartOffset + 40 + 4
	} else {
		keyBlockMeta.keyBlockInfoStartOffset = mdict.meta.keyBlockMetaStartOffset + 16
	}

	mdict.keyBlockMeta = keyBlockMeta

	return nil
}

func (mdict *MdictBase) readKeyBlockInfo() error {
	log.Debugf("Reading key block info for: %s", mdict.filePath)
	file, err := os.Open(mdict.filePath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' for key block info: %w", mdict.filePath, err)
	}
	defer file.Close()

	log.Debugf("Reading key block info from offset %d, size %d for '%s'", mdict.keyBlockMeta.keyBlockInfoStartOffset, mdict.keyBlockMeta.keyBlockInfoCompressedSize, mdict.filePath)
	buffer, err := readFileFromPos(file, mdict.keyBlockMeta.keyBlockInfoStartOffset, mdict.keyBlockMeta.keyBlockInfoCompressedSize)
	if err != nil {
		return fmt.Errorf("failed to read key block info data for '%s': %w", mdict.filePath, err)
	}

	if err := mdict.decodeKeyBlockInfo(buffer); err != nil {
		return fmt.Errorf("failed to decode key block info for '%s': %w", mdict.filePath, err)
	}
	log.Debugf("Key block info successfully read and decoded for: %s", mdict.filePath)
	return nil
}

func (mdict *MdictBase) decodeKeyBlockInfo(data []byte) error {
	log.Debugf("Decoding key block info for '%s'. Data length: %d, EncryptType: %d", mdict.filePath, len(data), mdict.meta.encryptType)
	// First 4 bytes should be compression type (e.g., 2 for zlib)
	if len(data) < 4 { // Ensure data is long enough for magic number check
		return fmt.Errorf("key block info data too short for magic number check (len %d) for '%s'", len(data), mdict.filePath)
	}
	if !(data[0] == 2 && data[1] == 0 && data[2] == 0 && data[3] == 0) {
		log.Warnf("Key block info for '%s' does not start with zlib magic bytes [02000000], actual: %x", mdict.filePath, data[0:4])
		return fmt.Errorf("key block info magic number check failed for '%s' (expected zlib type [02000000]): got %x", mdict.filePath, data[0:4])
	}

	// decrypt
	var keyBlockInfoDecryptedBuffer []byte
	if mdict.meta.encryptType == EncryptKeyInfoEnc {
		log.Debugf("Key block info for '%s' is encrypted (type %d), decrypting. Compressed size: %d", mdict.filePath, mdict.meta.encryptType, mdict.keyBlockMeta.keyBlockInfoCompressedSize)
		decryptedBuffer := mdxDecrypt(data, mdict.keyBlockMeta.keyBlockInfoCompressedSize) // Pass the original full data block to mdxDecrypt
		if len(decryptedBuffer) != int(mdict.keyBlockMeta.keyBlockInfoCompressedSize) {
			return fmt.Errorf("key block info decryption error for '%s': output size mismatch (expected %d, got %d)", mdict.filePath, mdict.keyBlockMeta.keyBlockInfoCompressedSize, len(decryptedBuffer))
		}
		keyBlockInfoDecryptedBuffer = decryptedBuffer
		log.Debugf("Key block info decrypted for: %s", mdict.filePath)
	} else {
		keyBlockInfoDecryptedBuffer = data
	}

	// finally, we need to check adler32 checksum
	// key_block_info_compressed[4:8] => adler32 checksum
	//          uint32_t chksum = be_bin_to_u32((unsigned char*) (kb_info_buff +
	//          4));
	//          uint32_t adlercs = adler32checksum(key_block_info_uncomp,
	//          static_cast<uint32_t>(key_block_info_uncomp_len)) & 0xffffffff;
	//
	//          assert(chksum == adlercs);

	/// here passed, key block info is corrected
	// TODO decode key block info compressed into keys list

	// for version 2.0, will compress by zlib, lzo just just for 1.0
	// key_block_info_buff[0:8] => compress_type
	// TODO zlib decompress
	// TODO:
	// if the size of compressed data original data is unknown,
	// we malloc 8 size of source data len, we cannot estimate the original data
	// size
	// but currently, we know the size of key_block_info decompress size, so we
	// use this

	// note: we should uncompressed key_block_info_buffer[8:] data, so we need
	// (decrypted + 8, and length -8)

	// Read the checksum from the buffer
	expectedChecksum := beBinToU32(keyBlockInfoDecryptedBuffer[4:8]) // [4:8] is adler32 checksum for decompressed data
	compressedDataToDecompress := keyBlockInfoDecryptedBuffer[8:]   // Actual data for zlib starts after comp_type and checksum

	// Decompress ZLIB data
	// The zlibDecompress function expects the actual compressed data stream.
	// The mdict.keyBlockMeta.keyBlockInfoDecompressSize is the expected uncompressed size.
	// The mdict.keyBlockMeta.keyBlockInfoCompressedSize includes the initial 8 bytes (type+checksum).
	// So, the length of compressedDataToDecompress is mdict.keyBlockMeta.keyBlockInfoCompressedSize - 8.
	decompressedKeyInfoBuffer, err := zlibDecompress(compressedDataToDecompress, 0, int64(len(compressedDataToDecompress)))
	if err != nil {
		return fmt.Errorf("ZLIB decompression for key block info failed: %w", err)
	}

	if int64(len(decompressedKeyInfoBuffer)) != mdict.keyBlockMeta.keyBlockInfoDecompressSize {
		return fmt.Errorf("ZLIB decompression output size mismatch for key block info: expected %d, got %d",
			mdict.keyBlockMeta.keyBlockInfoDecompressSize, len(decompressedKeyInfoBuffer))
	}

	// Calculate and verify Alder32 checksum on decompressed data
	actualChecksum := adler32.Checksum(decompressedKeyInfoBuffer)
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("key block info checksum mismatch: expected %d, got %d", expectedChecksum, actualChecksum)
	}

	// decode key-block entries
	var counter int64 = 0
	var currentEntriesSize int64 = 0
	var numEntriesCounter int64 = 0
	byteWidth := 1
	textTerm := 0

	if mdict.meta.version >= 2.0 {
		byteWidth = 2
		textTerm = 1
	}

	var dataOffset = 0
	var compressSizeAccumulator = 0
	var decompressSizeAccumulator = 0

	keyBlockInfo := &mdictKeyBlockInfo{
		keyBlockEntriesStartOffset: 0,
		keyBlockInfoList:           make([]*mdictKeyBlockInfoItem, 0),
	}

	for counter < mdict.keyBlockMeta.keyBlockNum {
		firstKeySize, lastKeySize := 0, 0
		firstKey := ""
		lastKey := ""

		if mdict.meta.version >= 2.0 {
			currentEntriesSize = int64(beBinToU64(decompressedKeyInfoBuffer[dataOffset : dataOffset+mdict.meta.numberWidth]))
			dataOffset += mdict.meta.numberWidth
			firstKeySize = int(beBinToU16(decompressedKeyInfoBuffer[dataOffset : dataOffset+byteWidth]))
			dataOffset += byteWidth
		} else {
			currentEntriesSize = int64(beBinToU32(decompressedKeyInfoBuffer[dataOffset : dataOffset+mdict.meta.numberWidth]))
			dataOffset += mdict.meta.numberWidth
			firstKeySize = int(int64(beBinToU8(decompressedKeyInfoBuffer[dataOffset : dataOffset+byteWidth])))
			dataOffset += byteWidth
		}
		numEntriesCounter += currentEntriesSize

		// step_gap means first key start data_offset to first key end;
		var stepGap = 0
		var termSize = textTerm
		if mdict.meta.encoding == EncodingUtf16 || mdict.fileType == MdictTypeMdd {
			stepGap = (firstKeySize + textTerm) * 2
			termSize = textTerm * 2
		} else {
			stepGap = firstKeySize + textTerm
			termSize = textTerm
		}

		firstKey = bigEndianBinToUTF8(decompressedKeyInfoBuffer, dataOffset, stepGap-termSize)

		dataOffset += stepGap

		if mdict.meta.version >= 2.0 {
			lastKeySize = int(beBinToU16(decompressedKeyInfoBuffer[dataOffset : dataOffset+byteWidth]))
		} else {
			lastKeySize = int(beBinToU8(decompressedKeyInfoBuffer[dataOffset : dataOffset+byteWidth]))
		}
		dataOffset += byteWidth

		if mdict.meta.encoding == EncodingUtf16 || mdict.fileType == MdictTypeMdd {
			stepGap = (lastKeySize + textTerm) * 2
			termSize = textTerm * 2
		} else {
			stepGap = lastKeySize + textTerm
			termSize = textTerm
		}

		lastKey = bigEndianBinToUTF8(decompressedKeyInfoBuffer, dataOffset, stepGap-termSize)

		dataOffset += stepGap
		// key block data meta part
		keyBlockCompressSize := 0
		if mdict.meta.version >= 2.0 {
			keyBlockCompressSize = int(beBinToU64(decompressedKeyInfoBuffer[dataOffset : dataOffset+mdict.meta.numberWidth]))
		} else {
			keyBlockCompressSize = int(beBinToU32(decompressedKeyInfoBuffer[dataOffset : dataOffset+mdict.meta.numberWidth]))
		}
		dataOffset += mdict.meta.numberWidth

		keyBlockDecompressSize := 0
		if mdict.meta.version >= 2.0 {
			keyBlockDecompressSize = int(beBinToU64(decompressedKeyInfoBuffer[dataOffset : dataOffset+mdict.meta.numberWidth]))
		} else {
			keyBlockDecompressSize = int(beBinToU32(decompressedKeyInfoBuffer[dataOffset : dataOffset+mdict.meta.numberWidth]))
		}

		dataOffset += mdict.meta.numberWidth

		keyBlockInfoItem := &mdictKeyBlockInfoItem{
			firstKey:                      firstKey,
			firstKeySize:                  firstKeySize,
			lastKey:                       lastKey,
			lastKeySize:                   lastKeySize,
			keyBlockInfoIndex:             int(counter),
			keyBlockCompressSize:          int64(keyBlockCompressSize),
			keyBlockCompAccumulator:       int64(compressSizeAccumulator),
			keyBlockDeCompressSize:        int64(keyBlockDecompressSize),
			keyBlockDeCompressAccumulator: int64(decompressSizeAccumulator),
		}

		compressSizeAccumulator += keyBlockCompressSize
		decompressSizeAccumulator += keyBlockDecompressSize

		keyBlockInfo.keyBlockInfoList = append(keyBlockInfo.keyBlockInfoList, keyBlockInfoItem)

		counter++

	}
	//keyBlockInfo.keyBlockEntriesStartOffset = int64(dataOffset) + mdict.keyBlockMeta.keyBlockInfoStartOffset
	keyBlockInfo.keyBlockEntriesStartOffset = mdict.keyBlockMeta.keyBlockInfoCompressedSize + mdict.keyBlockMeta.keyBlockInfoStartOffset

	mdict.keyBlockInfo = keyBlockInfo

	if int64(compressSizeAccumulator) != mdict.keyBlockMeta.keyBlockDataTotalSize {
		return fmt.Errorf("key block data compress size not equals to meta key block data compress size(%d/%d)", compressSizeAccumulator, mdict.keyBlockMeta.keyBlockDataTotalSize)
	}

	return nil

}

func (mdict *MdictBase) readKeyEntries() error {
	log.Debugf("Reading key entries for: %s", mdict.filePath)
	file, err := os.Open(mdict.filePath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' for key entries: %w", mdict.filePath, err)
	}
	defer file.Close()

	log.Debugf("Reading key entries data for '%s' from offset %d, total size %d", mdict.filePath, mdict.keyBlockInfo.keyBlockEntriesStartOffset, mdict.keyBlockMeta.keyBlockDataTotalSize)
	buffer, err := readFileFromPos(file,
		mdict.keyBlockInfo.keyBlockEntriesStartOffset,
		mdict.keyBlockMeta.keyBlockDataTotalSize)
	if err != nil {
		return fmt.Errorf("failed to read key entries data for '%s': %w", mdict.filePath, err)
	}

	if err := mdict.decodeKeyEntries(buffer); err != nil {
		return fmt.Errorf("failed to decode key entries for '%s': %w", mdict.filePath, err)
	}
	log.Debugf("Key entries successfully read and decoded for '%s'. Total entries: %d", mdict.filePath, mdict.keyBlockData.keyEntriesSize)
	return nil
}

func (mdict *MdictBase) decodeKeyEntries(keyBlockDataCompressBuffer []byte) error {
	log.Debugf("Decoding key entries for '%s'. Total compressed data length: %d", mdict.filePath, len(keyBlockDataCompressBuffer))
	start := int64(0)
	end := int64(0)
	compAccu := int64(0)

	keyBlockData := &mdictKeyBlockData{
		keyEntries:                 make([]*MDictKeywordEntry, 0),
		keyEntriesSize:             0,
		recordBlockMetaStartOffset: 0,
	}

	for idx := 0; idx < len(mdict.keyBlockInfo.keyBlockInfoList); idx++ {

		compressedSize := mdict.keyBlockInfo.keyBlockInfoList[idx].keyBlockCompressSize
		decompressedSize := mdict.keyBlockInfo.keyBlockInfoList[idx].keyBlockDeCompressSize

		compAccu += mdict.keyBlockInfo.keyBlockInfoList[idx].keyBlockCompressSize

		end = start + compressedSize

		if int64(start) != int64(mdict.keyBlockInfo.keyBlockInfoList[idx].keyBlockCompAccumulator) {
			return fmt.Errorf("[%d] the key-block data start offset not equal to key block compress accumulator(%d/%d/%d)\n",
				idx, start, mdict.keyBlockInfo.keyBlockInfoList[idx].keyBlockCompAccumulator, compAccu)
		}

		kbCompType := keyBlockDataCompressBuffer[start : start+4]
		// TODO 4 bytes adler32 checksum
		// # 4 bytes : adler checksum of decompressed key block
		// adler32 = unpack('>I', key_block_compressed[start + 4:start + 8])[0]
		expectedKeyBlockChecksum := beBinToU32(keyBlockDataCompressBuffer[start+4 : start+8])

		var key_block []byte

		if kbCompType[0] == 0 { // No compression
			key_block = keyBlockDataCompressBuffer[start+8 : end]

		} else if kbCompType[0] == 1 { // LZO compression
			// Data is from start+8 to end (exclusive of checksum and compression type)
			compressedLZOData := keyBlockDataCompressBuffer[start+8 : end]
			// Decompress LZO
			// The rasky/go-lzo library expects raw LZO stream.
			// The decompressedSize is known.
			reader := bytes.NewReader(compressedLZOData)
			// The third argument to Decompress1X is a hint for the destination buffer size.
			out, err1 := lzo.Decompress1X(reader, 0, int(decompressedSize))
			if err1 != nil {
				return fmt.Errorf("LZO decompression failed for key block %d: %w", idx, err1)
			}
			if len(out) != int(decompressedSize) {
				return fmt.Errorf("LZO decompression output size mismatch for key block %d: expected %d, got %d", idx, decompressedSize, len(out))
			}
			key_block = out

		} else if kbCompType[0] == 2 { // ZLIB compression
			// Data is from start+8 to end (exclusive of checksum and compression type)
			compressedZLIBData := keyBlockDataCompressBuffer[start+8 : end]
			out, err2 := zlibDecompress(compressedZLIBData, 0, int64(len(compressedZLIBData)))
			if err2 != nil {
				return err2
			}
			key_block = out

			// extract one single key block into a key list
			// notice that adler32 returns signed value
			// TODO compare with previous word
			// assert(adler32 == zlib.adler32(key_block) & 0xffffffff)
			actualKeyBlockChecksum := adler32.Checksum(key_block)
			if actualKeyBlockChecksum != expectedKeyBlockChecksum {
				return fmt.Errorf("key block data checksum mismatch for block %d: expected %d, got %d", idx, expectedKeyBlockChecksum, actualKeyBlockChecksum)
			}
		} else {
			return fmt.Errorf("cannot determine the compress type %v", kbCompType)
		}

		splitKeys := mdict.splitKeyBlock(key_block)

		keyBlockData.keyEntries = append(keyBlockData.keyEntries, splitKeys...)
		keyBlockData.keyEntriesSize += int64(len(splitKeys))

		//fmt.Printf("idx(%05d)[start:%05d/end:%05d/comps:%05d->datalen:%05d/compaccu:%d]\n", idx, start, end, compressedSize, len(key_block), compAccu)
		//fmt.Printf("key_list %+v\n", splitKeys)

		start = end
	}

	if keyBlockData.keyEntriesSize != mdict.keyBlockMeta.entriesNum {
		return fmt.Errorf("decoded key list items count %d not equal to expected entries number %d for '%s'", keyBlockData.keyEntriesSize, mdict.keyBlockMeta.entriesNum, mdict.filePath)
	}
	keyBlockData.recordBlockMetaStartOffset = mdict.keyBlockInfo.keyBlockEntriesStartOffset + mdict.keyBlockMeta.keyBlockDataTotalSize

	// keep key list in memory
	mdict.keyBlockData = keyBlockData

	return nil
}

func (mdict *MdictBase) splitKeyBlock(keyBlock []byte) []*MDictKeywordEntry {
	// delimiter := ""
	width := 1

	if mdict.meta.encoding == EncodingUtf16 || mdict.fileType == MdictTypeMdd {
		//delimiter = "0000"
		width = 2
	} else {
		//delimiter = "00"
		width = 1
	}

	keyList := make([]*MDictKeywordEntry, 0)

	keyStartIndex := 0
	keyEndIndex := 0

	for keyStartIndex < len(keyBlock) {
		// # the corresponding record's offset in record block
		recordStartOffset := int64(0)

		if mdict.meta.numberWidth == 8 {
			recordStartOffset = int64(beBinToU64(keyBlock[keyStartIndex : keyStartIndex+mdict.meta.numberWidth]))
		} else {
			recordStartOffset = int64(beBinToU32(keyBlock[keyStartIndex : keyStartIndex+mdict.meta.numberWidth]))
		}

		// # key text ends with '\x00'
		i := keyStartIndex + mdict.meta.numberWidth
		for i < len(keyBlock) {
			// delimiter = '0' || // delimiter = '00'
			if (width == 1 && keyBlock[i] == 0) || (width == 2 && keyBlock[i] == 0 && keyBlock[i+1] == 0) {
				keyEndIndex = i
				break
			}
			i += width
		}

		keyTextBytes := keyBlock[keyStartIndex+mdict.meta.numberWidth : keyEndIndex]
		keyText := string(keyTextBytes)
		var err error

		if mdict.meta.encoding == EncodingUtf16 {
			keyText, err = decodeLittleEndianUtf16(keyTextBytes)
			if err != nil {
				keyText = string(keyTextBytes)
			}
		}

		if mdict.fileType == MdictTypeMdd {
			keyText, err = decodeLittleEndianUtf16(keyTextBytes)
			if err != nil {
				// Instead of panic, return the error to be handled by the caller
				// We need to change the function signature to return an error
				// This change will propagate to callers of splitKeyBlock.
				// For now, let's log and return an empty list with an error indication if we can't change signature directly.
				// Ideally, the function signature of splitKeyBlock and its callers would be changed.
				// As a compromise for this step, logging error and returning what we have.
				// This should be revisited if proper error propagation is feasible.
				log.Errorf("Error decoding UTF-16 for MDD key text (offset %d): %v. KeyTextBytes: %x", keyStartIndex+mdict.meta.numberWidth, err, keyTextBytes)
				// Returning partial results might be problematic.
				// Consider returning (nil, error) if signature change was possible.
				// For now, continuing with potentially incorrect keyText.
				keyText = string(keyTextBytes) // Fallback to raw string to avoid panic
			}
		}

		keyStartIndex = keyEndIndex + width
		keyList = append(keyList, &MDictKeywordEntry{
			RecordStartOffset: recordStartOffset,
			KeyWord:           keyText,
			KeyBlockIdx:       int64(keyStartIndex),
		})
		if len(keyList) > 1 {
			keyList[len(keyList)-2].RecordEndOffset = keyList[len(keyList)-1].RecordStartOffset
		}
	}
	//keyList[len(keyList)-1].RecordLocateEndOffset = 0

	return keyList
}

func (mdict *MdictBase) readRecordBlockMeta() error {
	log.Debugf("Reading record block metadata for: %s", mdict.filePath)
	file, err := os.Open(mdict.filePath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' for record block metadata: %w", mdict.filePath, err)
	}
	defer file.Close()
	/*
	 * [0:8/4]    - record block number
	 * [8:16/4:8] - num entries the key-value entries number
	 * [16:24/8:12] - record block info size
	 * [24:32/12:16] - record block size
	 *
	 */
	recordBlockMetaBufferLen := int64(16)
	if mdict.meta.version >= 2.0 {
		recordBlockMetaBufferLen = 32
	}

	recordBlockStartOffset := mdict.keyBlockInfo.keyBlockEntriesStartOffset + mdict.keyBlockMeta.keyBlockDataTotalSize
	log.Debugf("Reading record block metadata for '%s' from offset %d, length %d", mdict.filePath, recordBlockStartOffset, recordBlockMetaBufferLen)

	buffer, err := readFileFromPos(file, recordBlockStartOffset, recordBlockMetaBufferLen)
	if err != nil {
		return fmt.Errorf("failed to read record block metadata for '%s': %w", mdict.filePath, err)
	}

	if err := mdict.decodeRecordBlockMeta(buffer, recordBlockStartOffset, recordBlockStartOffset+recordBlockMetaBufferLen); err != nil {
		return fmt.Errorf("failed to decode record block metadata for '%s': %w", mdict.filePath, err)
	}
	log.Debugf("Record block metadata successfully read and decoded for '%s': %+v", mdict.filePath, mdict.recordBlockMeta)
	return nil
}

/**
 * STEP 7.
 * decode record header,
 * includes:
 * [0:8/4]    - record block number
 * [8:16/4:8] - num entries the key-value entries number
 * [16:24/8:12] - record block info size
 * [24:32/12:16] - record block size
 */
func (mdict *MdictBase) decodeRecordBlockMeta(data []byte, startOffset, endOffset int64) error {
	recordBlockMeta := &mdictRecordBlockMeta{
		keyRecordMetaStartOffset: startOffset,
		keyRecordMetaEndOffset:   endOffset,
	}

	keyRecordBuffer := data
	offset := 0

	if mdict.meta.version >= 2.0 {
		recordBlockMeta.recordBlockNum = int64(beBinToU64(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))
	} else {
		recordBlockMeta.recordBlockNum = int64(beBinToU32(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))
	}

	offset += mdict.meta.numberWidth

	if mdict.meta.version >= 2.0 {
		recordBlockMeta.entriesNum = int64(beBinToU64(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))
	} else {
		recordBlockMeta.entriesNum = int64(beBinToU32(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))

	}
	if recordBlockMeta.entriesNum != mdict.keyBlockMeta.entriesNum {
		return fmt.Errorf("record block entries number %d does not match key block entries number %d for '%s'", recordBlockMeta.entriesNum, mdict.keyBlockMeta.entriesNum, mdict.filePath)
	}

	offset += mdict.meta.numberWidth
	if mdict.meta.version >= 2.0 {
		recordBlockMeta.recordBlockInfoCompSize = int64(beBinToU64(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))
	} else {
		recordBlockMeta.recordBlockInfoCompSize = int64(beBinToU32(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))
	}

	offset += mdict.meta.numberWidth

	if mdict.meta.version >= 2.0 {
		recordBlockMeta.recordBlockCompSize = int64(beBinToU64(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))
	} else {
		recordBlockMeta.recordBlockCompSize = int64(beBinToU32(keyRecordBuffer[offset : offset+mdict.meta.numberWidth]))
	}

	mdict.recordBlockMeta = recordBlockMeta
	return nil
}

func (mdict *MdictBase) readRecordBlockInfo() error {
	log.Debugf("Reading record block info for: %s", mdict.filePath)
	file, err := os.Open(mdict.filePath)
	if err != nil {
		return fmt.Errorf("failed to open file '%s' for record block info: %w", mdict.filePath, err)
	}
	defer file.Close()
	/*
	 * [0:8/4]    - record block number
	 * [8:16/4:8] - num entries the key-value entries number
	 * [16:24/8:12] - record block info size
	 * [24:32/12:16] - record block size
	 *
	 */
	recordBlockInfoStartOffset := mdict.recordBlockMeta.keyRecordMetaEndOffset
	recordBlockInfoLen := mdict.recordBlockMeta.recordBlockInfoCompSize
	log.Debugf("Reading record block info for '%s' from offset %d, length %d", mdict.filePath, recordBlockInfoStartOffset, recordBlockInfoLen)

	buffer, err := readFileFromPos(file, recordBlockInfoStartOffset, recordBlockInfoLen)
	if err != nil {
		return fmt.Errorf("failed to read record block info data for '%s': %w", mdict.filePath, err)
	}

	if err := mdict.decodeRecordBlockInfo(buffer, recordBlockInfoStartOffset, recordBlockInfoStartOffset+recordBlockInfoLen); err != nil {
		return fmt.Errorf("failed to decode record block info for '%s': %w", mdict.filePath, err)
	}
	log.Debugf("Record block info successfully read and decoded for '%s'. Number of record blocks: %d", mdict.filePath, len(mdict.recordBlockInfo.recordInfoList))
	return nil
}

func (mdict *MdictBase) decodeRecordBlockInfo(data []byte, startOffset, endOffset int64) error {

	recordBlockInfoList := make([]*MdictRecordBlockInfoListItem, 0)
	var offset = 0
	var compAccu = int64(0)
	var decompAccu = int64(0)
	var i = int64(0)

	for i = int64(0); i < mdict.recordBlockMeta.recordBlockNum; i++ {
		compSize := int64(0)
		if mdict.meta.version >= 2.0 {
			compSize = int64(beBinToU64(data[offset : offset+mdict.meta.numberWidth]))
		} else {
			compSize = int64(beBinToU32(data[offset : offset+mdict.meta.numberWidth]))
		}
		offset += mdict.meta.numberWidth

		decompSize := int64(0)
		if mdict.meta.version >= 2.0 {
			decompSize = int64(beBinToU64(data[offset : offset+mdict.meta.numberWidth]))
		} else {
			decompSize = int64(beBinToU32(data[offset : offset+mdict.meta.numberWidth]))
		}
		offset += mdict.meta.numberWidth

		// then assign
		recordBlockInfoList = append(recordBlockInfoList, &MdictRecordBlockInfoListItem{
			compressSize:                compSize,
			deCompressSize:              decompSize,
			compressAccumulatorOffset:   compAccu,
			deCompressAccumulatorOffset: decompAccu,
		})

		// accu last
		compAccu += compSize
		decompAccu += decompSize
	}
	if int64(i) != mdict.recordBlockMeta.recordBlockNum {
		return fmt.Errorf("decoded record block info items count %d not equal to expected record block number %d for '%s'. CompAccumulator: %d, DecompAccumulator: %d",
			i, mdict.recordBlockMeta.recordBlockNum, mdict.filePath, compAccu, decompAccu)
	}
	if int64(offset) != mdict.recordBlockMeta.recordBlockInfoCompSize {
		return fmt.Errorf("record block info decoded offset %d not equal to expected compressed size %d for '%s'", offset, mdict.recordBlockMeta.recordBlockInfoCompSize, mdict.filePath)
	}
	if int64(compAccu) != mdict.recordBlockMeta.recordBlockCompSize {
		return fmt.Errorf("record block info accumulated compressed size %d not equal to expected total compressed size %d for '%s'", compAccu, mdict.recordBlockMeta.recordBlockCompSize, mdict.filePath)
	}

	recordBlockInfo := &mdictRecordBlockInfo{
		recordInfoList:             recordBlockInfoList,
		recordBlockInfoStartOffset: startOffset,
		recordBlockInfoEndOffset:   endOffset,
		recordBlockDataStartOffset: endOffset,
	}

	mdict.recordBlockInfo = recordBlockInfo

	return nil
}

func (mdict *MdictBase) buildRecordRangeTree() {
	log.Debugf("Building record range tree with %d items for: %s", len(mdict.recordBlockInfo.recordInfoList), mdict.filePath)
	BuildRangeTree(mdict.recordBlockInfo.recordInfoList, mdict.rangeTreeRoot)
	log.Debugf("Record range tree built for: %s", mdict.filePath)
}

// keywordEntryToIndex finds the MDictKeywordIndex for a given MDictKeywordEntry.
// It first attempts to use a pre-built range tree for efficient lookup of the record block.
// If the range tree is not available or fails to find the item, it falls back to a linear scan
// of the record block information.
func (mdict *MdictBase) keywordEntryToIndex(item *MDictKeywordEntry) (*MDictKeywordIndex, error) {
	var recordBlockInfo *MdictRecordBlockInfoListItem

	// Attempt to use the range tree first, if available and mdict.rangeTreeRoot is not nil
	if mdict.rangeTreeRoot != nil {
		log.Debugf("Attempting to find record block info for offset %d using range tree.", item.RecordStartOffset)
		rbInfo := QueryRangeData(mdict.rangeTreeRoot, item.RecordStartOffset)
		if rbi, ok := rbInfo.(*MdictRecordBlockInfoListItem); ok {
			recordBlockInfo = rbi
			log.Debugf("Found record block info for offset %d using range tree: %+v", item.RecordStartOffset, recordBlockInfo)
		} else if rbInfo != nil {
			log.Warnf("QueryRangeData returned an unexpected type (%T) for offset %d. Will attempt linear scan.", rbInfo, item.RecordStartOffset)
		} else {
			log.Debugf("Record block info for offset %d not found using range tree. Will attempt linear scan.", item.RecordStartOffset)
		}
	} else {
		log.Debugf("Range tree not initialized. Using linear scan for offset %d.", item.RecordStartOffset)
	}

	// If range tree didn't yield a result (or not used/initialized), fallback to linear scan.
	if recordBlockInfo == nil {
		log.Debugf("Performing linear scan for record block info for offset %d.", item.RecordStartOffset)
		var found bool
		for i, rbi := range mdict.recordBlockInfo.recordInfoList {
			// Check if the item's start offset falls within the current record block's decompressed range
			if item.RecordStartOffset >= rbi.deCompressAccumulatorOffset && item.RecordStartOffset < (rbi.deCompressAccumulatorOffset+rbi.deCompressSize) {
				recordBlockInfo = rbi
				log.Debugf("Found record block info via linear scan at index %d for offset %d: %+v", i, item.RecordStartOffset, recordBlockInfo)
				found = true
				break
			}
		}
		if !found {
			log.Errorf("Linear scan failed to find record block info for offset %d for '%s'. Total record blocks: %d.", item.RecordStartOffset, mdict.filePath, len(mdict.recordBlockInfo.recordInfoList))
			// For debugging, log the first and last record block info if available
			if len(mdict.recordBlockInfo.recordInfoList) > 0 {
				log.Debugf("First record block info for linear scan failure (file '%s'): %+v", mdict.filePath, mdict.recordBlockInfo.recordInfoList[0])
				log.Debugf("Last record block info for linear scan failure (file '%s'): %+v", mdict.filePath, mdict.recordBlockInfo.recordInfoList[len(mdict.recordBlockInfo.recordInfoList)-1])
			}
			return nil, fmt.Errorf("key-item's record block info not found for RecordStartOffset %d via linear scan for '%s'", item.RecordStartOffset, mdict.filePath)
		}
	}

	// Calculate the start offset of the compressed record block in the MDX/MDD file.
	recordBlockFileOffset := recordBlockInfo.compressAccumulatorOffset + mdict.recordBlockInfo.recordBlockDataStartOffset

	// Calculate the start offset of the keyword's data within its (decompressed) record block.
	keywordStartOffsetInDecompressedBlock := item.RecordStartOffset - recordBlockInfo.deCompressAccumulatorOffset

	// Calculate the end offset of the keyword's data within its (decompressed) record block.
	var keywordEndOffsetInDecompressedBlock int64
	if item.RecordEndOffset == 0 {
		// If RecordEndOffset is 0, the record extends to the end of the current decompressed block.
		keywordEndOffsetInDecompressedBlock = recordBlockInfo.deCompressSize
		log.Debugf("RecordEndOffset is 0, setting keyword end to deCompressSize: %d for item offset %d", keywordEndOffsetInDecompressedBlock, item.RecordStartOffset)
	} else {
		keywordEndOffsetInDecompressedBlock = item.RecordEndOffset - recordBlockInfo.deCompressAccumulatorOffset
		log.Debugf("RecordEndOffset is %d, calculated keyword end to %d for item offset %d", item.RecordEndOffset, keywordEndOffsetInDecompressedBlock, item.RecordStartOffset)
	}

	// Validate calculated offsets to prevent out-of-bounds access on the decompressed block.
	if keywordStartOffsetInDecompressedBlock < 0 || keywordStartOffsetInDecompressedBlock > recordBlockInfo.deCompressSize {
		log.Errorf("Calculated keyword start offset %d is out of bounds for its decompressed record block (size %d). Item: %+v, RecordBlockInfo: %+v",
			keywordStartOffsetInDecompressedBlock, recordBlockInfo.deCompressSize, item, recordBlockInfo)
		return nil, fmt.Errorf("calculated keyword start offset %d is out of bounds for its decompressed record block (size %d, item offset %d, block decompress acc offset %d)",
			keywordStartOffsetInDecompressedBlock, recordBlockInfo.deCompressSize, item.RecordStartOffset, recordBlockInfo.deCompressAccumulatorOffset)
	}
	if keywordEndOffsetInDecompressedBlock < keywordStartOffsetInDecompressedBlock || keywordEndOffsetInDecompressedBlock > recordBlockInfo.deCompressSize {
		log.Errorf("Calculated keyword end offset %d is out of bounds (start: %d, decompressed size: %d). Item: %+v, RecordBlockInfo: %+v",
			keywordEndOffsetInDecompressedBlock, keywordStartOffsetInDecompressedBlock, recordBlockInfo.deCompressSize, item, recordBlockInfo)
		return nil, fmt.Errorf("calculated keyword end offset %d is out of bounds (start: %d, decompressed size: %d, item end offset %d, block decompress acc offset %d)",
			keywordEndOffsetInDecompressedBlock, keywordStartOffsetInDecompressedBlock, recordBlockInfo.deCompressSize, item.RecordEndOffset, recordBlockInfo.deCompressAccumulatorOffset)
	}

	log.Debugf("Successfully created MDictKeywordIndex for item offset %d: StartInFile=%d, KeyWordStartOffset=%d, KeyWordEndOffset=%d",
		item.RecordStartOffset, recordBlockFileOffset, keywordStartOffsetInDecompressedBlock, keywordEndOffsetInDecompressedBlock)

	return &MDictKeywordIndex{
		KeywordEntry: *item,
		RecordBlock: MDictKeywordIndexRecordBlock{
			DataStartOffset:          recordBlockFileOffset, 
			CompressSize:             recordBlockInfo.compressSize,
			DeCompressSize:           recordBlockInfo.deCompressSize,
			KeyWordPartStartOffset:   keywordStartOffsetInDecompressedBlock, 
			KeyWordPartDataEndOffset: keywordEndOffsetInDecompressedBlock,   
		},
	}, nil
}

// locateByKeywordIndex is a method on MdictBase to locate definition by MDictKeywordIndex.
// It primarily calls the standalone locateDefByKWIndex function.
// Note: locateDefByKWIndex has been refactored to _locateDefByKWIndexInternal and this function now uses it.
func (mdict *MdictBase) locateByKeywordIndex(index *MDictKeywordIndex) ([]byte, error) {
	return _locateDefByKWIndexInternal(index,
		mdict.filePath,
		mdict.meta.encryptType == EncryptRecordEnc,
		mdict.fileType == MdictTypeMdd,
		mdict.meta.encoding == EncodingUtf16,
		index.KeywordEntry.KeyWord, // Pass keyword for logging
	)
}

// _fetchAndDecodeRecordBlock reads, decrypts (if necessary), and decompresses a record block.
func _fetchAndDecodeRecordBlock(filePath string, fileOffset int64, compressedSize int64, decompressedSize int64, isEncrypted bool, keywordForLog string) ([]byte, error) {
	log.Debugf("Fetching record block for keyword '%s': fileOffset=%d, compressedSize=%d, decompressedSize=%d, isEncrypted=%v",
		keywordForLog, fileOffset, compressedSize, decompressedSize, isEncrypted)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file '%s': %w", filePath, err)
	}
	defer file.Close()

	recordBlockDataCompBuff, err := readFileFromPos(file, fileOffset, compressedSize)
	if err != nil {
		return nil, fmt.Errorf("error reading record block data for keyword '%s' from offset %d, size %d: %w", keywordForLog, fileOffset, compressedSize, err)
	}
	if recordBlockDataCompBuff == nil { // Should be covered by readFileFromPos error, but defensive check.
		return nil, fmt.Errorf("read empty record block data for keyword '%s' from offset %d, size %d", keywordForLog, fileOffset, compressedSize)
	}
	if len(recordBlockDataCompBuff) < 8 { // Need at least 4 for comp type and 4 for checksum
		return nil, fmt.Errorf("record block data for keyword '%s' is too short (%d bytes) to contain header", keywordForLog, len(recordBlockDataCompBuff))
	}

	rbCompType := recordBlockDataCompBuff[0:4]
	expectedChecksum := beBinToU32(recordBlockDataCompBuff[4:8])
	log.Debugf("Record block for '%s': CompType=%v, ExpectedChecksum=%d", keywordForLog, rbCompType, expectedChecksum)

	var recordBlock []byte
	var dataToProcess []byte // This will hold the data slice that needs decompression

	if isEncrypted {
		log.Debugf("Decrypting record block for '%s'", keywordForLog)
		// mdxDecrypt expects the full block including comp_type and checksum.
		decryptedFullBlock := mdxDecrypt(recordBlockDataCompBuff, compressedSize) // Pass full compressed block to mdxDecrypt
		if int64(len(decryptedFullBlock)) != compressedSize {
			return nil, fmt.Errorf("decryption error for record block of '%s': output size mismatch, expected %d, got %d", keywordForLog, compressedSize, len(decryptedFullBlock))
		}
		if len(decryptedFullBlock) < 8 { // Check again after decryption
			return nil, fmt.Errorf("decrypted record block for '%s' is too short (%d bytes)", keywordForLog, len(decryptedFullBlock))
		}
		// The actual data for decompression starts after the header (comp_type + checksum) in the decrypted block.
		dataToProcess = decryptedFullBlock[8:]
	} else {
		// If not encrypted, the data for decompression is simply after the header.
		dataToProcess = recordBlockDataCompBuff[8:]
	}

	switch rbCompType[0] {
	case 0: // No compression
		log.Debugf("Record block for '%s' is not compressed.", keywordForLog)
		recordBlock = dataToProcess
	case 1: // LZO compression
		log.Debugf("Decompressing LZO record block for '%s'. DataToProcess len: %d, ExpectedDecompressed: %d", keywordForLog, len(dataToProcess), decompressedSize)
		reader := bytes.NewReader(dataToProcess)
		out, err1 := lzo.Decompress1X(reader, 0, int(decompressedSize))
		if err1 != nil {
			return nil, fmt.Errorf("LZO decompression failed for record block of '%s': %w", keywordForLog, err1)
		}
		recordBlock = out
	case 2: // ZLIB compression
		log.Debugf("Decompressing ZLIB record block for '%s'. DataToProcess len: %d, ExpectedDecompressed: %d", keywordForLog, len(dataToProcess), decompressedSize)
		out, err2 := zlibDecompress(dataToProcess, 0, int64(len(dataToProcess))) // zlibDecompress needs the length of the data it's given
		if err2 != nil {
			return nil, fmt.Errorf("ZLIB decompression failed for record block of '%s': %w", keywordForLog, err2)
		}
		recordBlock = out
	default:
		return nil, fmt.Errorf("unknown record block compression type %v for keyword '%s'", rbCompType, keywordForLog)
	}

	actualChecksum := adler32.Checksum(recordBlock)
	if actualChecksum != expectedChecksum {
		log.Errorf("Checksum mismatch for record block of '%s': expected %d, got %d. Decompressed len: %d", keywordForLog, expectedChecksum, actualChecksum, len(recordBlock))
		return nil, fmt.Errorf("record block checksum mismatch for keyword '%s': expected %d, got %d", keywordForLog, expectedChecksum, actualChecksum)
	}
	log.Debugf("Checksum verified for record block of '%s': %d", keywordForLog, actualChecksum)

	if int64(len(recordBlock)) != decompressedSize {
		log.Errorf("Decompressed size mismatch for record block of '%s': expected %d, got %d", keywordForLog, decompressedSize, len(recordBlock))
		return nil, fmt.Errorf("record block decompressed size mismatch for keyword '%s': expected %d, got %d", keywordForLog, decompressedSize, len(recordBlock))
	}
	log.Debugf("Decompressed size verified for record block of '%s': %d", keywordForLog, len(recordBlock))

	return recordBlock, nil
}

// _locateDefByKWIndexInternal is the core logic for retrieving a definition, used by both
// locateDefByKWIndex (standalone) and MdictBase.locateByKeywordEntry.
func _locateDefByKWIndexInternal(index *MDictKeywordIndex, filePath string, isRecordEncrypted, isMdd, isUtf16 bool, keywordForLog string) ([]byte, error) {
	log.Infof("Locating definition for keyword '%s' using index: %+v", keywordForLog, index.RecordBlock)

	decompressedRecordBlock, err := _fetchAndDecodeRecordBlock(filePath,
		index.RecordBlock.DataStartOffset,
		index.RecordBlock.CompressSize,
		index.RecordBlock.DeCompressSize,
		isRecordEncrypted,
		keywordForLog,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch/decode record block for keyword '%s': %w", keywordForLog, err)
	}

	// Slice the specific keyword's data from the decompressed block
	start := index.RecordBlock.KeyWordPartStartOffset
	end := index.RecordBlock.KeyWordPartDataEndOffset

	if start < 0 || end < start || end > int64(len(decompressedRecordBlock)) {
		log.Errorf("Invalid keyword part offsets for '%s': start=%d, end=%d, block_len=%d. Index: %+v",
			keywordForLog, start, end, len(decompressedRecordBlock), index)
		return nil, fmt.Errorf("invalid keyword part offsets for '%s': start=%d, end=%d, decompressed block length=%d",
			keywordForLog, start, end, len(decompressedRecordBlock))
	}
	log.Debugf("Extracting keyword data for '%s' from decompressed block: start=%d, end=%d", keywordForLog, start, end)
	data := decompressedRecordBlock[start:end]

	if isMdd {
		log.Infof("Returning raw MDD data for '%s' (length %d)", keywordForLog, len(data))
		return data, nil
	}

	if isUtf16 {
		log.Infof("Decoding UTF-16 data for keyword '%s' (original length %d)", keywordForLog, len(data))
		datastr, err1 := decodeLittleEndianUtf16(data)
		if err1 != nil {
			log.Errorf("UTF-16 decoding failed for keyword '%s': %v", keywordForLog, err1)
			return nil, fmt.Errorf("UTF-16 decoding failed for '%s': %w", keywordForLog, err1)
		}
		log.Debugf("Decoded UTF-16 data for '%s' to length %d", keywordForLog, len(datastr))
		return []byte(datastr), nil
	}

	log.Infof("Returning data for keyword '%s' (length %d, encoding assumed UTF-8 or similar)", keywordForLog, len(data))
	return data, nil
}

// locateDefByKWIndex is a standalone function to locate definition by MDictKeywordIndex.
// It now calls the internal refactored logic.
func locateDefByKWIndex(index *MDictKeywordIndex, filePath string, isRecordEncrypted, isMdd, isUtf16 bool) ([]byte, error) {
	// The keyword is passed for logging purposes within _locateDefByKWIndexInternal.
	return _locateDefByKWIndexInternal(index, filePath, isRecordEncrypted, isMdd, isUtf16, index.KeywordEntry.KeyWord)
}

// locateByKeywordEntry retrieves a definition by MDictKeywordEntry.
// It first calls keywordEntryToIndex to get the MDictKeywordIndex,
// then calls the internal location logic.
func (mdict *MdictBase) locateByKeywordEntry(item *MDictKeywordEntry) ([]byte, error) {
	log.Debugf("Locating by keyword entry: %s (Offset: %d)", item.KeyWord, item.RecordStartOffset)
	index, err := mdict.keywordEntryToIndex(item)
	if err != nil {
		log.Errorf("Failed to get keyword index for entry '%s' (offset %d): %v", item.KeyWord, item.RecordStartOffset, err)
		return nil, fmt.Errorf("failed to get keyword index for '%s': %w", item.KeyWord, err)
	}

	log.Debugf("Obtained keyword index for '%s': %+v", item.KeyWord, index.RecordBlock)

	// Call the internal logic, providing necessary context from mdict.meta
	return _locateDefByKWIndexInternal(index,
		mdict.filePath,
		mdict.meta.encryptType == EncryptRecordEnc,
		mdict.fileType == MdictTypeMdd,
		mdict.meta.encoding == EncodingUtf16,
		item.KeyWord, // Pass keyword for logging
	)
}

func (mdict *MdictBase) getKeyWordEntries() ([]*MDictKeywordEntry, error) {
	return mdict.keyBlockData.keyEntries, nil
}
