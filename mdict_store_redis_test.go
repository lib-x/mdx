package mdx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRedisBackend struct {
	kv        map[string]string
	hashes    map[string]map[string]string
	sets      map[string]map[string]struct{}
	zsets     map[string]map[string]struct{}
	saddCalls map[string]int
	getCalls  int
	mgetCalls int
	zAddErr   error
}

func newFakeRedisBackend() *fakeRedisBackend {
	return &fakeRedisBackend{
		kv:        make(map[string]string),
		hashes:    make(map[string]map[string]string),
		sets:      make(map[string]map[string]struct{}),
		zsets:     make(map[string]map[string]struct{}),
		saddCalls: make(map[string]int),
	}
}

func (f *fakeRedisBackend) Set(_ context.Context, key, value string) error {
	f.kv[key] = value
	return nil
}

func (f *fakeRedisBackend) HSetMany(_ context.Context, key string, values map[string]string) error {
	if _, ok := f.hashes[key]; !ok {
		f.hashes[key] = make(map[string]string)
	}
	for field, value := range values {
		f.hashes[key][field] = value
	}
	return nil
}

func (f *fakeRedisBackend) HGet(_ context.Context, key, field string) (string, error) {
	value, ok := f.hashes[key][field]
	if !ok {
		return "", ErrIndexMiss
	}
	return value, nil
}

func (f *fakeRedisBackend) HMGet(_ context.Context, key string, fields ...string) ([]string, error) {
	f.mgetCalls++
	values := make([]string, len(fields))
	for index, field := range fields {
		values[index] = f.hashes[key][field]
	}
	return values, nil
}

func (f *fakeRedisBackend) HLen(_ context.Context, key string) (int64, error) {
	return int64(len(f.hashes[key])), nil
}

func (f *fakeRedisBackend) SetNX(_ context.Context, key, value string, _ time.Duration) (bool, error) {
	if _, ok := f.kv[key]; ok {
		return false, nil
	}
	f.kv[key] = value
	return true, nil
}

func (f *fakeRedisBackend) Get(_ context.Context, key string) (string, error) {
	f.getCalls++
	value, ok := f.kv[key]
	if !ok {
		return "", ErrIndexMiss
	}
	return value, nil
}

func (f *fakeRedisBackend) MGet(_ context.Context, keys ...string) ([]string, error) {
	f.mgetCalls++
	values := make([]string, len(keys))
	for index, key := range keys {
		values[index] = f.kv[key]
	}
	return values, nil
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

func (f *fakeRedisBackend) SAddMany(ctx context.Context, sets map[string][]string) error {
	for key, members := range sets {
		if err := f.SAdd(ctx, key, members...); err != nil {
			return err
		}
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

func (f *fakeRedisBackend) SCard(_ context.Context, key string) (int64, error) {
	return int64(len(f.sets[key])), nil
}

func (f *fakeRedisBackend) ZAddMany(_ context.Context, key string, members []string) error {
	if f.zAddErr != nil {
		return f.zAddErr
	}
	if _, ok := f.zsets[key]; !ok {
		f.zsets[key] = make(map[string]struct{})
	}
	for _, member := range members {
		f.zsets[key][member] = struct{}{}
	}
	return nil
}

func (f *fakeRedisBackend) ZRangeByLex(_ context.Context, key, minValue, maxValue string, limit int64) ([]string, error) {
	members := make([]string, 0, len(f.zsets[key]))
	for member := range f.zsets[key] {
		if (minValue == "-" || member >= strings.TrimPrefix(minValue, "[")) &&
			(maxValue == "+" || member <= strings.TrimPrefix(maxValue, "[")) {
			members = append(members, member)
		}
	}
	sort.Strings(members)
	if limit > 0 && int64(len(members)) > limit {
		members = members[:limit]
	}
	if len(members) == 0 {
		return nil, ErrIndexMiss
	}
	return members, nil
}

func (f *fakeRedisBackend) ZCard(_ context.Context, key string) (int64, error) {
	return int64(len(f.zsets[key])), nil
}

func (f *fakeRedisBackend) CommitIndex(_ context.Context, exactKey, lexKey, readyKey, stagingExactKey, stagingLexKey, readyValue string) error {
	delete(f.hashes, exactKey)
	delete(f.zsets, lexKey)
	if staged, ok := f.hashes[stagingExactKey]; ok {
		f.hashes[exactKey] = staged
		delete(f.hashes, stagingExactKey)
	}
	if staged, ok := f.zsets[stagingLexKey]; ok {
		f.zsets[lexKey] = staged
		delete(f.zsets, stagingLexKey)
	}
	f.kv[readyKey] = readyValue
	return nil
}

func (f *fakeRedisBackend) Del(_ context.Context, keys ...string) error {
	for _, key := range keys {
		delete(f.kv, key)
		delete(f.hashes, key)
		delete(f.sets, key)
		delete(f.zsets, key)
		delete(f.saddCalls, key)
	}
	return nil
}

func (f *fakeRedisBackend) CompareAndDelete(_ context.Context, key, value string) (bool, error) {
	if f.kv[key] != value {
		return false, nil
	}
	delete(f.kv, key)
	return true, nil
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
	assert.Equal(t, 1, backend.mgetCalls)

	resourceMatches, err := store.PrefixSearch("demo", `\acc`, 10)
	require.NoError(t, err)
	require.Len(t, resourceMatches, 1)
	assert.True(t, resourceMatches[0].IsResource)
	assert.Equal(t, 2, backend.mgetCalls)

	_, err = store.GetExact("demo", "missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrIndexMiss))
}

func TestRedisIndexStorePut_StoresOneLexicographicMemberPerKeyword(t *testing.T) {
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

	assert.Len(t, backend.zsets[store.dictLexKey("demo")], 2)
	assert.Empty(t, backend.sets[store.dictPrefixRegistryKey("demo")])
}

func TestRedisIndexStorePut_DuplicateLookupKeepsFirstEntry(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil, WithRedisKeyPrefix("duplicate:index"))
	store.backend = backend
	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{
		{Keyword: "ability", RecordStartOffset: 1},
		{Keyword: "ability", RecordStartOffset: 2},
	}))

	entry, err := store.GetExact("demo", "ability")
	require.NoError(t, err)
	assert.Equal(t, int64(1), entry.RecordStartOffset)
}

func TestRedisIndexStorePut_FailedRebuildKeepsPreviousIndex(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil, WithRedisKeyPrefix("atomic:index"))
	store.backend = backend
	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{{Keyword: "ability"}}))

	backend.zAddErr = errors.New("injected sorted-set write failure")
	err := store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{{Keyword: "able"}})
	require.Error(t, err)
	entry, err := store.GetExact("demo", "ability")
	require.NoError(t, err)
	assert.Equal(t, "ability", entry.Keyword)
	_, err = store.GetExact("demo", "able")
	assert.ErrorIs(t, err, ErrIndexMiss)
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

func TestRedisIndexStore_EmptyDictionaryHasHealthyIndex(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil, WithRedisKeyPrefix("empty:index"))
	store.backend = backend

	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, nil))
	healthy, err := store.HasDictionaryIndex("demo")
	require.NoError(t, err)
	assert.True(t, healthy)
}

func TestRedisIndexStore_DetectsMissingIndexData(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil, WithRedisKeyPrefix("health:index"))
	store.backend = backend
	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{
		{Keyword: "ability"},
		{Keyword: "able"},
	}))

	delete(backend.hashes[store.dictExactHashKey("demo")], "ability")
	healthy, err := store.HasDictionaryIndex("demo")
	require.NoError(t, err)
	assert.False(t, healthy)
	_, err = store.PrefixSearch("demo", "ab", 10)
	assert.ErrorIs(t, err, ErrIndexMiss)
}

func TestRedisIndexStore_V2DoesNotReadStaleLegacyEntry(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil, WithRedisKeyPrefix("migration:index"))
	store.backend = backend
	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{{Keyword: "ability"}}))
	require.NoError(t, backend.Set(context.Background(), store.dictExactKey("demo", "ability"), `{"keyword":"stale"}`))
	delete(backend.hashes[store.dictExactHashKey("demo")], "ability")

	_, err := store.GetExact("demo", "ability")
	assert.ErrorIs(t, err, ErrIndexMiss)
}

func TestRedisIndexStore_LegacyIndexRemainsReadable(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil, WithRedisKeyPrefix("legacy:index"))
	store.backend = backend
	payload := `{"keyword":"ability","record_start_offset":1}`
	require.NoError(t, backend.Set(context.Background(), store.dictExactKey("demo", "ability"), payload))
	require.NoError(t, backend.SAdd(context.Background(), store.dictKeysSetKey("demo"), "ability"))
	require.NoError(t, backend.SAdd(context.Background(), store.dictPrefixSetKey("demo", "ab"), "ability"))

	entry, err := store.GetExact("demo", "ability")
	require.NoError(t, err)
	assert.Equal(t, int64(1), entry.RecordStartOffset)
	results, err := store.PrefixSearch("demo", "ab", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "ability", results[0].Keyword)
	healthy, err := store.HasDictionaryIndex("demo")
	require.NoError(t, err)
	assert.True(t, healthy)
}

func TestRedisIndexStore_AcquireIndexBuildLease(t *testing.T) {
	t.Parallel()

	backend := newFakeRedisBackend()
	store := NewRedisIndexStore(nil,
		WithRedisIndexContext(context.Background()),
		WithRedisKeyPrefix("lease:index"),
	)
	store.backend = backend

	release, acquired, err := store.AcquireIndexBuildLease("demo", time.Minute)
	require.NoError(t, err)
	require.True(t, acquired)
	require.NotNil(t, release)

	_, acquired, err = store.AcquireIndexBuildLease("demo", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired)

	require.NoError(t, release())
	secondRelease, acquired, err := store.AcquireIndexBuildLease("demo", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
	require.NoError(t, secondRelease())
}

func TestRedisIndexStore_ValkeyIntegration(t *testing.T) {
	address := os.Getenv("MDX_TEST_VALKEY_ADDR")
	if address == "" {
		t.Skip("set MDX_TEST_VALKEY_ADDR to run the Valkey integration test")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	ctx := t.Context()
	require.NoError(t, client.Ping(ctx).Err())
	store := NewRedisIndexStore(client,
		WithRedisIndexContext(ctx),
		WithRedisKeyPrefix("mdx:test:valkey:"+strconv.FormatInt(time.Now().UnixNano(), 10)),
	)
	t.Cleanup(func() { _ = store.DeleteDictionary("demo") })

	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{
		{Keyword: "Ability", RecordStartOffset: 1, RecordEndOffset: 2},
		{Keyword: "able", RecordStartOffset: 3, RecordEndOffset: 4},
	}))
	results, err := store.PrefixSearch("demo", "AB", 1)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Ability", results[0].Keyword)
	healthy, err := store.HasDictionaryIndex("demo")
	require.NoError(t, err)
	assert.True(t, healthy)

	require.NoError(t, client.HDel(ctx, store.dictExactHashKey("demo"), "Ability").Err())
	healthy, err = store.HasDictionaryIndex("demo")
	require.NoError(t, err)
	assert.False(t, healthy)

	require.NoError(t, store.Put(DictionaryInfo{Name: "empty"}, nil))
	t.Cleanup(func() { _ = store.DeleteDictionary("empty") })
	healthy, err = store.HasDictionaryIndex("empty")
	require.NoError(t, err)
	assert.True(t, healthy)
}

func TestRedisIndexStore_ValkeyRejectsIncompleteStagingIndex(t *testing.T) {
	address := os.Getenv("MDX_TEST_VALKEY_ADDR")
	if address == "" {
		t.Skip("set MDX_TEST_VALKEY_ADDR to run the Valkey integration test")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	ctx := t.Context()
	store := NewRedisIndexStore(client,
		WithRedisIndexContext(ctx),
		WithRedisKeyPrefix("mdx:test:staging:"+strconv.FormatInt(time.Now().UnixNano(), 10)),
	)
	t.Cleanup(func() { _ = store.DeleteDictionary("demo") })
	require.NoError(t, store.Put(DictionaryInfo{Name: "demo"}, []IndexEntry{{Keyword: "ability"}}))

	stagingExact := store.dictExactHashKey("demo") + ":staging:broken"
	stagingLex := store.dictLexKey("demo") + ":staging:broken"
	require.NoError(t, client.HSet(ctx, stagingExact, "able", `{"keyword":"able"}`).Err())
	defer func() { _ = client.Del(ctx, stagingExact, stagingLex).Err() }()
	err := store.backend.CommitIndex(ctx,
		store.dictExactHashKey("demo"),
		store.dictLexKey("demo"),
		store.dictReadyKey("demo"),
		stagingExact,
		stagingLex,
		"v2:1",
	)
	require.Error(t, err)
	entry, err := store.GetExact("demo", "ability")
	require.NoError(t, err)
	assert.Equal(t, "ability", entry.Keyword)
}

func BenchmarkRedisIndexStorePrefixSearch(b *testing.B) {
	address := os.Getenv("MDX_BENCH_VALKEY_ADDR")
	if address == "" {
		address = os.Getenv("MDX_BENCH_REDIS_ADDR")
	}
	if address == "" {
		b.Skip("set MDX_BENCH_VALKEY_ADDR to run the Valkey integration benchmark")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	b.Cleanup(func() { _ = client.Close() })
	ctx := b.Context()
	if err := client.Ping(ctx).Err(); err != nil {
		b.Fatal(err)
	}
	prefix := "mdx:bench:prefix:" + strconv.FormatInt(time.Now().UnixNano(), 10)
	store := NewRedisIndexStore(client, WithRedisIndexContext(ctx), WithRedisKeyPrefix(prefix))
	entryCount := 10000
	if value := os.Getenv("MDX_BENCH_ENTRY_COUNT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed <= 0 {
			b.Fatalf("invalid MDX_BENCH_ENTRY_COUNT %q", value)
		}
		entryCount = parsed
	}
	entries := make([]IndexEntry, entryCount)
	for index := range entries {
		entries[index] = IndexEntry{Keyword: fmt.Sprintf("benchmark-%03d", index)}
	}
	if err := store.Put(DictionaryInfo{Name: "demo"}, entries); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.DeleteDictionary("demo") })
	legacyPrefix := "mdx:bench:prefix:legacy:" + strconv.FormatInt(time.Now().UnixNano(), 10)
	legacyStore := NewRedisIndexStore(client, WithRedisIndexContext(ctx), WithRedisKeyPrefix(legacyPrefix))
	legacyKeys := make([]string, len(entries))
	for index, entry := range entries {
		payload, err := json.Marshal(entry)
		if err != nil {
			b.Fatal(err)
		}
		legacyKeys[index] = entry.Keyword
		if err := legacyStore.backend.Set(ctx, legacyStore.dictExactKey("demo", entry.Keyword), string(payload)); err != nil {
			b.Fatal(err)
		}
	}
	if err := legacyStore.backend.SAddMany(ctx, map[string][]string{
		legacyStore.dictKeysSetKey("demo"): legacyKeys,
	}); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = legacyStore.DeleteDictionary("demo") })

	b.Run("lex_range_batched", func(b *testing.B) {
		for b.Loop() {
			results, err := store.PrefixSearch("demo", "benchmark", 10)
			if err != nil || len(results) != 10 {
				b.Fatalf("results=%d err=%v", len(results), err)
			}
		}
	})

	b.Run("legacy_n_plus_one", func(b *testing.B) {
		for b.Loop() {
			keys, err := legacyStore.backend.SMembers(ctx, legacyStore.dictKeysSetKey("demo"))
			if err != nil {
				b.Fatal(err)
			}
			sort.Strings(keys)
			count := 0
			for _, key := range keys {
				if _, err := legacyStore.backend.Get(ctx, legacyStore.dictExactKey("demo", key)); err != nil {
					b.Fatal(err)
				}
				count++
				if count == 10 {
					break
				}
			}
		}
	})
}

func BenchmarkRedisIndexStorePut(b *testing.B) {
	address := os.Getenv("MDX_BENCH_VALKEY_ADDR")
	if address == "" {
		address = os.Getenv("MDX_BENCH_REDIS_ADDR")
	}
	if address == "" {
		b.Skip("set MDX_BENCH_VALKEY_ADDR to run the Valkey integration benchmark")
	}
	client := redis.NewClient(&redis.Options{Addr: address})
	b.Cleanup(func() { _ = client.Close() })
	ctx := b.Context()
	if err := client.Ping(ctx).Err(); err != nil {
		b.Fatal(err)
	}
	entries := make([]IndexEntry, 1000)
	for index := range entries {
		entries[index] = IndexEntry{Keyword: fmt.Sprintf("benchmark-%04d", index)}
	}

	b.Run("batched", func(b *testing.B) {
		prefix := "mdx:bench:put:batched:" + strconv.FormatInt(time.Now().UnixNano(), 10)
		store := NewRedisIndexStore(client, WithRedisIndexContext(ctx), WithRedisKeyPrefix(prefix))
		b.Cleanup(func() { _ = store.DeleteDictionary("demo") })
		for b.Loop() {
			if err := store.Put(DictionaryInfo{Name: "demo"}, entries); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("legacy_per_entry_set", func(b *testing.B) {
		prefix := "mdx:bench:put:legacy:" + strconv.FormatInt(time.Now().UnixNano(), 10)
		store := NewRedisIndexStore(client, WithRedisIndexContext(ctx), WithRedisKeyPrefix(prefix))
		b.Cleanup(func() { _ = store.DeleteDictionary("demo") })
		for b.Loop() {
			if err := legacyRedisIndexPut(store, DictionaryInfo{Name: "demo"}, entries); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func legacyRedisIndexPut(store *RedisIndexStore, info DictionaryInfo, entries []IndexEntry) error {
	if err := store.DeleteDictionary(info.Name); err != nil {
		return err
	}
	registry := make([]string, 0, len(entries))
	prefixMembers := make(map[string][]string)
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		key := indexStoreLookupKey(entry)
		if strings.TrimSpace(key) == "" {
			continue
		}
		payload, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := store.backend.Set(store.ctx, store.dictExactKey(info.Name, key), string(payload)); err != nil {
			return err
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		registry = append(registry, key)
		for _, prefix := range legacyPrefixCandidates(key, store.prefixIndexMaxLen) {
			prefixKey := store.dictPrefixSetKey(info.Name, prefix)
			prefixMembers[prefixKey] = append(prefixMembers[prefixKey], key)
		}
	}
	if err := store.backend.SAddMany(store.ctx, map[string][]string{
		store.dictKeysSetKey(info.Name): registry,
	}); err != nil {
		return err
	}
	prefixKeys := make([]string, 0, len(prefixMembers))
	for key := range prefixMembers {
		prefixKeys = append(prefixKeys, key)
	}
	if err := store.backend.SAddMany(store.ctx, prefixMembers); err != nil {
		return err
	}
	return store.backend.SAddMany(store.ctx, map[string][]string{
		store.dictPrefixRegistryKey(info.Name): prefixKeys,
	})
}

func legacyPrefixCandidates(key string, maxLen int) []string {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return nil
	}
	limit := min(len(key), maxLen)
	prefixes := make([]string, limit)
	for index := range limit {
		prefixes[index] = key[:index+1]
	}
	return prefixes
}
