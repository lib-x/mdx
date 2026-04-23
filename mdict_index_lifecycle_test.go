package mdx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubExternalIndexDict struct {
	name         string
	info         DictionaryInfo
	entries      []IndexEntry
	prepareCalls int
}

func (s *stubExternalIndexDict) Name() string { return s.name }
func (s *stubExternalIndexDict) PrepareForExternalIndex() error {
	s.prepareCalls++
	return nil
}
func (s *stubExternalIndexDict) DictionaryInfo() DictionaryInfo { return s.info }
func (s *stubExternalIndexDict) ExportIndex() ([]IndexEntry, error) {
	return append([]IndexEntry(nil), s.entries...), nil
}

func TestResolveIndexSyncConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := ResolveIndexSyncConfig()
	assert.True(t, cfg.ReuseIfUnchanged)
	assert.Zero(t, cfg.MissingSourceTTL)
	assert.False(t, cfg.ForceRebuild)
	assert.NotNil(t, cfg.Fingerprinter)
	assert.NotNil(t, cfg.Now)
	assert.Equal(t, defaultIndexSchemaVersion, cfg.SchemaVersion)
}

func TestEnsureDictionaryIndex_ReusesMatchingManifest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	dictPath := filepath.Join(tmpDir, "demo.mdx")
	require.NoError(t, os.WriteFile(dictPath, []byte("demo"), 0o644))

	store := NewMemoryIndexStore()
	cfg := ResolveIndexSyncConfig(WithClock(func() time.Time {
		return time.Unix(1700000000, 0).UTC()
	}))
	fingerprint, err := cfg.Fingerprinter.Fingerprint(dictPath)
	require.NoError(t, err)
	manifest := buildManifest(cfg, "demo", dictPath, fingerprint, nil)
	require.NoError(t, store.SaveManifest(manifest))
	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{{Keyword: "ability"}}))

	opened := false
	result, err := ensureDictionaryIndexWithDeps(dictPath, store, cfg, func(string) (externalIndexDictionary, error) {
		opened = true
		return nil, errors.New("should not open")
	})
	require.NoError(t, err)
	assert.False(t, opened)
	assert.True(t, result.Reused)
	assert.False(t, result.Rebuilt)
	assert.Equal(t, manifest.Fingerprint, result.Manifest.Fingerprint)
}

func TestEnsureDictionaryIndex_RebuildsWhenFingerprintChanges(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	dictPath := filepath.Join(tmpDir, "demo.mdx")
	require.NoError(t, os.WriteFile(dictPath, []byte("demo-v2"), 0o644))

	store := NewMemoryIndexStore()
	cfg := ResolveIndexSyncConfig(WithClock(func() time.Time {
		return time.Unix(1700000200, 0).UTC()
	}))
	require.NoError(t, store.SaveManifest(IndexManifest{
		DictionaryName: "demo",
		SourcePath:     dictPath,
		Fingerprint:    "stale",
		SchemaVersion:  cfg.SchemaVersion,
		BuiltAt:        time.Unix(1600000000, 0).UTC(),
	}))

	stub := &stubExternalIndexDict{
		name:    "demo",
		info:    DictionaryInfo{Name: "demo"},
		entries: []IndexEntry{{Keyword: "ability"}},
	}
	result, err := ensureDictionaryIndexWithDeps(dictPath, store, cfg, func(string) (externalIndexDictionary, error) {
		return stub, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, stub.prepareCalls)
	assert.False(t, result.Reused)
	assert.True(t, result.Rebuilt)
	entry, err := store.GetExact("demo", "ability")
	require.NoError(t, err)
	assert.Equal(t, "ability", entry.Keyword)
	manifest, err := store.LoadManifest("demo")
	require.NoError(t, err)
	assert.NotEqual(t, "stale", manifest.Fingerprint)
}

func TestEnsureDictionaryIndex_SetsExpiryWhenSourceMissing(t *testing.T) {
	t.Parallel()

	store := NewMemoryIndexStore()
	now := time.Unix(1700001000, 0).UTC()
	manifest := IndexManifest{
		DictionaryName: "missing",
		SourcePath:     "/tmp/missing.mdx",
		Fingerprint:    "fp",
		SchemaVersion:  defaultIndexSchemaVersion,
		BuiltAt:        now.Add(-time.Hour),
	}
	require.NoError(t, store.SaveManifest(manifest))

	result, err := ensureDictionaryIndexWithDeps("/tmp/missing.mdx", store, ResolveIndexSyncConfig(
		WithClock(func() time.Time { return now }),
		WithMissingSourceTTL(2*time.Hour),
	), func(string) (externalIndexDictionary, error) {
		return nil, errors.New("should not open")
	})
	require.NoError(t, err)
	assert.True(t, result.Reused)
	require.NotNil(t, result.Manifest.ExpiresAt)
	assert.Equal(t, now.Add(2*time.Hour), *result.Manifest.ExpiresAt)
}

func TestEnsureDictionaryIndex_DeletesExpiredMissingSourceIndex(t *testing.T) {
	t.Parallel()

	store := NewMemoryIndexStore()
	now := time.Unix(1700002000, 0).UTC()
	expiresAt := now.Add(-time.Minute)
	require.NoError(t, store.Put(DictionaryInfo{Name: "missing"}, []IndexEntry{{Keyword: "ability"}}))
	require.NoError(t, store.SaveManifest(IndexManifest{
		DictionaryName: "missing",
		SourcePath:     "/tmp/missing.mdx",
		Fingerprint:    "fp",
		SchemaVersion:  defaultIndexSchemaVersion,
		BuiltAt:        now.Add(-3 * time.Hour),
		ExpiresAt:      &expiresAt,
	}))

	_, err := ensureDictionaryIndexWithDeps("/tmp/missing.mdx", store, ResolveIndexSyncConfig(
		WithClock(func() time.Time { return now }),
		WithMissingSourceTTL(2*time.Hour),
	), func(string) (externalIndexDictionary, error) {
		return nil, errors.New("should not open")
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist))
	_, loadErr := store.LoadManifest("missing")
	assert.True(t, errors.Is(loadErr, ErrIndexMiss))
	_, getErr := store.GetExact("missing", "ability")
	assert.True(t, errors.Is(getErr, ErrIndexMiss))
}

func TestBuildIndexManifest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	dictPath := filepath.Join(tmpDir, "demo.mdx")
	require.NoError(t, os.WriteFile(dictPath, []byte("demo"), 0o644))

	now := time.Unix(1700003000, 0).UTC()
	manifest, err := BuildIndexManifest(dictPath, "demo", WithClock(func() time.Time { return now }))
	require.NoError(t, err)
	assert.Equal(t, "demo", manifest.DictionaryName)
	assert.Equal(t, defaultIndexSchemaVersion, manifest.SchemaVersion)
	assert.Equal(t, now, manifest.BuiltAt)
	assert.NotEmpty(t, manifest.Fingerprint)
	assert.Nil(t, manifest.ExpiresAt)
}

func TestPrepareForExternalIndex_AllowsExportAndResolve(t *testing.T) {
	manifest := loadFixtureManifest(t)

	dict, err := New(manifest.MDXPath)
	require.NoError(t, err)
	require.NoError(t, dict.PrepareForExternalIndex())
	assert.Nil(t, dict.exactLookup)
	assert.Nil(t, dict.comparableLookup)

	entries, err := dict.ExportEntries()
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	var ability IndexEntry
	found := false
	for _, entry := range entries {
		if entry.Keyword == manifest.SampleMDXWord {
			ability = entry
			found = true
			break
		}
	}
	require.True(t, found)
	definition, err := dict.Resolve(ability)
	require.NoError(t, err)
	assert.Contains(t, string(definition), manifest.SampleMDXWord)
}
