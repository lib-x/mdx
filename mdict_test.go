package mdx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMdict_Lookup(t *testing.T) {
	manifest := loadFixtureManifest(t)

	mdict, err := New(manifest.MDXPath)
	require.NoError(t, err)
	require.NoError(t, mdict.BuildIndex())

	definition, err := mdict.Lookup(manifest.SampleMDXWord)
	require.NoError(t, err)
	assert.NotEmpty(t, definition)
	assert.True(t, strings.Contains(strings.ToLower(string(definition)), manifest.SampleMDXWord))

	_, err = mdict.Lookup(manifest.MissingMDXWord)
	require.Error(t, err)
}

func BenchmarkMdict_Lookup(b *testing.B) {
	dir := os.Getenv("MDX_TESTDICT_DIR")
	if dir == "" {
		dir = defaultFixtureDir
	}
	path := filepath.Join(dir, "牛津高阶英汉双解词典（第9版）.mdx")
	if _, err := os.Stat(path); err != nil {
		b.Skipf("missing benchmark fixture %q: %v", path, err)
	}

	mdict, err := New(path)
	if err != nil {
		b.Fatal(err)
	}
	if err := mdict.BuildIndex(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mdict.Lookup(fixtureSampleMDXWord)
	}
}
