package mdx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.mdx"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.mdd"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.mdx"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644))

	specs, err := ScanDirectory(dir)
	require.NoError(t, err)
	require.Len(t, specs, 2)

	assert.Equal(t, "alpha", specs[0].ID)
	assert.NotEmpty(t, specs[0].MDDPath)
	assert.Equal(t, []string{specs[0].MDDPath}, specs[0].MDDPaths)
	assert.Equal(t, "beta", specs[1].ID)
	assert.Empty(t, specs[1].MDDPath)
	assert.Empty(t, specs[1].MDDPaths)
}

func TestScanDirectoryDetectsMultiVolumeMDD(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "demo.mdx"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "demo.mdd"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "demo.1.mdd"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "demo.2.mdd"), []byte("x"), 0o644))

	specs, err := ScanDirectory(dir)
	require.NoError(t, err)
	require.Len(t, specs, 1)

	assert.Equal(t, filepath.Join(dir, "demo.mdd"), specs[0].MDDPath)
	assert.Equal(t, []string{
		filepath.Join(dir, "demo.mdd"),
		filepath.Join(dir, "demo.1.mdd"),
		filepath.Join(dir, "demo.2.mdd"),
	}, specs[0].MDDPaths)
}

func TestDictionaryRegistry_OpenDictionaryAndSearch(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dir := t.TempDir()
	mdxPath := filepath.Join(dir, "oale9.mdx")
	mddPath := filepath.Join(dir, "oale9.mdd")
	require.NoError(t, os.Symlink(manifest.MDXPath, mdxPath))
	require.NoError(t, os.Symlink(manifest.MDDPath, mddPath))

	registry := NewDictionaryRegistry()
	require.NoError(t, registry.LoadDirectory(dir))

	specs := registry.List()
	require.Len(t, specs, 1)
	assert.Equal(t, "oale9", specs[0].ID)

	mdxDict, mddDict, err := registry.OpenDictionary("oale9")
	require.NoError(t, err)
	require.NotNil(t, mdxDict)
	require.NotNil(t, mddDict)

	hits, err := registry.LibrarySearch("abiliti", 5)
	require.NoError(t, err)
	require.NotEmpty(t, hits)
	assert.Equal(t, "oale9", hits[0].DictID)
	assert.Contains(t, []string{"ability", "abilities"}, hits[0].Hit.Entry.Keyword)
}

func TestConfigureDictionaryPairAssetsUsesMDXDirectoryAsSidecarSource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mdxPath := filepath.Join(dir, "demo.mdx")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audio.spx"), []byte("sidecar-audio"), 0o644))

	mdxDict := &Mdict{
		MdictBase: &MdictBase{
			filePath: mdxPath,
			fileType: MdictTypeMdx,
			meta:     &mdictMeta{},
		},
	}

	ConfigureDictionaryPairAssets(DictionarySpec{MDXPath: mdxPath}, mdxDict, nil)

	data, err := mdxDict.AssetResolver().Read("sound://audio.spx")
	require.NoError(t, err)
	assert.Equal(t, []byte("sidecar-audio"), data)
}

func TestConfigureDictionaryPairAssetsSharesResolverWithMDD(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mdxPath := filepath.Join(dir, "demo.mdx")
	mddPath := filepath.Join(dir, "demo.mdd")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "audio.spx"), []byte("shared-sidecar-audio"), 0o644))

	mdxDict := &Mdict{
		MdictBase: &MdictBase{
			filePath: mdxPath,
			fileType: MdictTypeMdx,
			meta:     &mdictMeta{},
		},
	}
	mddDict := &Mdict{
		MdictBase: &MdictBase{
			filePath: mddPath,
			fileType: MdictTypeMdd,
			meta:     &mdictMeta{},
		},
	}

	ConfigureDictionaryPairAssets(DictionarySpec{MDXPath: mdxPath, MDDPath: mddPath}, mdxDict, mddDict)

	mdxData, err := mdxDict.AssetResolver().Read("sound://audio.spx")
	require.NoError(t, err)
	assert.Equal(t, []byte("shared-sidecar-audio"), mdxData)

	mddData, err := mddDict.AssetResolver().Read("sound://audio.spx")
	require.NoError(t, err)
	assert.Equal(t, []byte("shared-sidecar-audio"), mddData)
}

func TestConfigureDictionaryPairAssetsAppendsAllMDDVolumes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mdxPath := filepath.Join(dir, "demo.mdx")

	mdxDict := &Mdict{MdictBase: &MdictBase{filePath: mdxPath, fileType: MdictTypeMdx, meta: &mdictMeta{}}}
	mddMain := &Mdict{MdictBase: &MdictBase{filePath: filepath.Join(dir, "demo.mdd"), fileType: MdictTypeMdd, meta: &mdictMeta{}}}
	mddVol1 := &Mdict{MdictBase: &MdictBase{filePath: filepath.Join(dir, "demo.1.mdd"), fileType: MdictTypeMdd, meta: &mdictMeta{}}}
	mddVol2 := &Mdict{MdictBase: &MdictBase{filePath: filepath.Join(dir, "demo.2.mdd"), fileType: MdictTypeMdd, meta: &mdictMeta{}}}

	ConfigureDictionaryPairAssets(
		DictionarySpec{
			MDXPath:  mdxPath,
			MDDPath:  filepath.Join(dir, "demo.mdd"),
			MDDPaths: []string{filepath.Join(dir, "demo.mdd"), filepath.Join(dir, "demo.1.mdd"), filepath.Join(dir, "demo.2.mdd")},
		},
		mdxDict,
		mddMain,
		mddVol1,
		mddVol2,
	)

	resolver := mdxDict.AssetResolver()
	require.NotNil(t, resolver)
	assert.Len(t, resolver.sources, 4)
	_, ok1 := resolver.sources[1].(mdictAssetSource)
	_, ok2 := resolver.sources[2].(mdictAssetSource)
	_, ok3 := resolver.sources[3].(mdictAssetSource)
	assert.True(t, ok1 && ok2 && ok3)
}
