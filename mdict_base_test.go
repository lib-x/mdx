package mdx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMdictBase_ReadDictHeader(t *testing.T) {
	manifest := loadFixtureManifest(t)

	mdictBase := &MdictBase{filePath: manifest.MDXPath, fileType: MdictTypeMdx}
	require.NoError(t, mdictBase.readDictHeader())

	assert.Equal(t, "牛津高阶英汉双解词典（第9版）", mdictBase.meta.title)
	assert.Equal(t, "2019-8-19", mdictBase.meta.creationDate)
	assert.Equal(t, EncodingUtf8, mdictBase.meta.encoding)
}

func TestMdictBase_ReadDictHeaderAndBlocks(t *testing.T) {
	manifest := loadFixtureManifest(t)

	mdictBase := &MdictBase{filePath: manifest.MDXPath, fileType: MdictTypeMdx, rangeTreeRoot: new(RecordBlockRangeTreeNode)}
	require.NoError(t, mdictBase.readDictHeader())
	require.NoError(t, mdictBase.readKeyBlockMeta())
	require.NoError(t, mdictBase.readKeyBlockInfo())
	require.NoError(t, mdictBase.readKeyEntries())
	require.NoError(t, mdictBase.readRecordBlockMeta())
	require.NoError(t, mdictBase.readRecordBlockInfo())
	mdictBase.buildRecordRangeTree()
	mdictBase.buildExactLookup()

	entry := mdictBase.exactLookup[fixtureSampleMDXWord]
	require.NotNil(t, entry)
	data, err := mdictBase.locateByKeywordEntry(entry)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}
