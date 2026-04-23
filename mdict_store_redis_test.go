package mdx

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRedisBackend struct {
	kv        map[string]string
	sets      map[string]map[string]struct{}
	saddCalls map[string]int
}

func newFakeRedisBackend() *fakeRedisBackend {
	return &fakeRedisBackend{
		kv:        make(map[string]string),
		sets:      make(map[string]map[string]struct{}),
		saddCalls: make(map[string]int),
	}
}

func (f *fakeRedisBackend) Set(_ context.Context, key, value string) error {
	f.kv[key] = value
	return nil
}

func (f *fakeRedisBackend) Get(_ context.Context, key string) (string, error) {
	value, ok := f.kv[key]
	if !ok {
		return "", ErrIndexMiss
	}
	return value, nil
}

func (f *fakeRedisBackend) SAdd(_ context.Context, key string, members ...string) error {
	f.saddCalls[key]++
	if _, ok := f.sets[key]; !ok {
		f.sets[key] = make(map[string]struct{})
	}
	for _, member := range members {
		f.sets[key][member] = struct{}{}
	}
	return nil
}

func (f *fakeRedisBackend) SMembers(_ context.Context, key string) ([]string, error) {
	set, ok := f.sets[key]
	if !ok {
		return nil, ErrIndexMiss
	}
	out := make([]string, 0, len(set))
	for member := range set {
		out = append(out, member)
	}
	return out, nil
}

func (f *fakeRedisBackend) Del(_ context.Context, keys ...string) error {
	for _, key := range keys {
		delete(f.kv, key)
		delete(f.sets, key)
		delete(f.saddCalls, key)
	}
	return nil
}

func TestRedisIndexStoreWithFakeBackend(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil,
		WithRedisIndexContext(context.Background()),
		WithRedisKeyPrefix("test:index"),
		WithRedisPrefixIndexMaxLen(4),
	)
	store.backend = backend

	info := DictionaryInfo{Name: "demo"}
	entries := []IndexEntry{
		{Keyword: "ability"},
		{Keyword: "able"},
		{Keyword: `\accordion_concertina.jpg`, NormalizedKeyword: `\accordion_concertina.jpg`, IsResource: true},
	}

	require.NoError(t, store.Put(info, entries))
	assert.Equal(t, 4, store.prefixIndexMaxLen)
	assert.Equal(t, "test:index", store.prefix)

	entry, err := store.GetExact("demo", "ability")
	require.NoError(t, err)
	assert.Equal(t, "ability", entry.Keyword)

	resource, err := store.GetExact("demo", `\accordion_concertina.jpg`)
	require.NoError(t, err)
	assert.True(t, resource.IsResource)

	matches, err := store.PrefixSearch("demo", "ab", 10)
	require.NoError(t, err)
	require.Len(t, matches, 2)

	resourceMatches, err := store.PrefixSearch("demo", `\acc`, 10)
	require.NoError(t, err)
	require.Len(t, resourceMatches, 1)
	assert.True(t, resourceMatches[0].IsResource)

	_, err = store.GetExact("demo", "missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIndexMiss))
}

func TestRedisIndexStorePut_BatchesMembersPerPrefix(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil,
		WithRedisIndexContext(context.Background()),
		WithRedisKeyPrefix("batch:index"),
		WithRedisPrefixIndexMaxLen(3),
	)
	store.backend = backend

	info := DictionaryInfo{Name: "demo"}
	entries := []IndexEntry{
		{Keyword: "ability"},
		{Keyword: "able"},
	}

	require.NoError(t, store.Put(info, entries))

	assert.Equal(t, 1, backend.saddCalls["batch:index:demo:prefix:a"])
	assert.Equal(t, 1, backend.saddCalls["batch:index:demo:prefix:ab"])
	assert.Equal(t, 1, backend.saddCalls["batch:index:demo:prefix:abi"])
	assert.Equal(t, 1, backend.saddCalls["batch:index:demo:prefix:abl"])
}

func TestRedisIndexStore_ManifestAndDeleteDictionary(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil,
		WithRedisIndexContext(context.Background()),
		WithRedisKeyPrefix("managed:index"),
	)
	store.backend = backend

	info := DictionaryInfo{Name: "demo"}
	entries := []IndexEntry{{Keyword: "ability"}}
	require.NoError(t, store.Put(info, entries))

	manifest := IndexManifest{
		DictionaryName: "demo",
		SourcePath:     "/tmp/demo.mdx",
		Fingerprint:    "fp",
		SchemaVersion:  "v1",
	}
	require.NoError(t, store.SaveManifest(manifest))

	loaded, err := store.LoadManifest("demo")
	require.NoError(t, err)
	assert.Equal(t, manifest.DictionaryName, loaded.DictionaryName)
	assert.Equal(t, manifest.Fingerprint, loaded.Fingerprint)

	require.NoError(t, store.DeleteDictionary("demo"))
	_, err = store.LoadManifest("demo")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIndexMiss))
	_, err = store.GetExact("demo", "ability")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIndexMiss))
}
