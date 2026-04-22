package mdx

import (
	"errors"
	"io"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMdictFSIntegration_OpenMDDResource(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDDPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	mfs := NewMdictFS(dict)
	file, err := mfs.Open(manifest.SampleMDDResource)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	data, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	_, err = mfs.Open(manifest.MissingMDDResource)
	require.Error(t, err)
	assert.True(t, errors.Is(err, fs.ErrNotExist))
}

func TestMdictFSIntegration_OpenMDDResourceCaseInsensitive(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDDPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	mfs := NewMdictFS(dict)
	file, err := mfs.Open("Accordion_Concertina.jpg")
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	data, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestMdictFSIntegration_OpenMDDResourceComparableKey(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDDPath)
	require.NoError(t, err)
	require.NoError(t, dict.BuildIndex())

	mfs := NewMdictFS(dict)
	file, err := mfs.Open("/Accordion_Concertina.jpg")
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	data, err := io.ReadAll(file)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}
