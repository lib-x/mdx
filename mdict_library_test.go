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
	assert.Equal(t, "beta", specs[1].ID)
	assert.Empty(t, specs[1].MDDPath)
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
