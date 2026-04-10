package mdx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_OALE9IndexBuilds(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDXPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	keywordEntries, err := dict.GetKeyWordEntries()
	require.NoError(t, err)
	assert.NotEmpty(t, keywordEntries)
	assert.Equal(t, manifest.SampleMDXWord, keywordEntries[226].KeyWord)
}
