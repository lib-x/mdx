package mdx

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMdictIntegration_LookupExactWord(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDXPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	definition, err := dict.Lookup(manifest.SampleMDXWord)
	require.NoError(t, err)
	assert.Contains(t, strings.ToLower(string(definition)), manifest.SampleMDXWord)

	_, err = dict.Lookup(manifest.MissingMDXWord)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "word not found")
}
