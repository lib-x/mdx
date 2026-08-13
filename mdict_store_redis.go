package mdx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultRedisPrefixIndexMaxLen = 8

const (
	redisWriteBatchSize   = 500
	redisMembersBatchSize = 1000
)

type redisIndexBackend interface {
	Set(ctx context.Context, key, value string) error
	SetNX(ctx context.Context, key, value string, expiration time.Duration) (bool, error)
	Get(ctx context.Context, key string) (string, error)
	MGet(ctx context.Context, keys ...string) ([]string, error)
	HSetMany(ctx context.Context, key string, values map[string]string) error
	HGet(ctx context.Context, key, field string) (string, error)
	HMGet(ctx context.Context, key string, fields ...string) ([]string, error)
	HLen(ctx context.Context, key string) (int64, error)
	SAdd(ctx context.Context, key string, members ...string) error
	SAddMany(ctx context.Context, sets map[string][]string) error
	SMembers(ctx context.Context, key string) ([]string, error)
	SCard(ctx context.Context, key string) (int64, error)
	ZAddMany(ctx context.Context, key string, members []string) error
	ZRangeByLex(ctx context.Context, key, minValue, maxValue string, limit int64) ([]string, error)
	ZCard(ctx context.Context, key string) (int64, error)
	CommitIndex(ctx context.Context, exactKey, comparableKey, lexKey, readyKey, stagingExactKey, stagingComparableKey, stagingLexKey, readyValue string) error
	Del(ctx context.Context, keys ...string) error
	CompareAndDelete(ctx context.Context, key, value string) (bool, error)
}

type redisIndexBackendAdapter struct {
	client *redis.Client
}

func (r *redisIndexBackendAdapter) Set(ctx context.Context, key, value string) error {
	return r.client.Set(ctx, key, value, 0).Err()
}

func (r *redisIndexBackendAdapter) HSetMany(ctx context.Context, key string, values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	args := make([]any, 0, len(values)*2)
	for field, value := range values {
		args = append(args, field, value)
	}
	return r.client.HSet(ctx, key, args...).Err()
}

func (r *redisIndexBackendAdapter) HGet(ctx context.Context, key, field string) (string, error) {
	value, err := r.client.HGet(ctx, key, field).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrIndexMiss
	}
	return value, err
}

func (r *redisIndexBackendAdapter) HMGet(ctx context.Context, key string, fields ...string) ([]string, error) {
	values, err := r.client.HMGet(ctx, key, fields...).Result()
	if err != nil {
		return nil, err
	}
	results := make([]string, len(values))
	found := false
	for index, value := range values {
		switch value := value.(type) {
		case nil:
		case string:
			results[index] = value
			found = true
		case []byte:
			results[index] = string(value)
			found = true
		default:
			return nil, errors.New("unexpected Redis index hash value")
		}
	}
	if !found {
		return nil, ErrIndexMiss
	}
	return results, nil
}

func (r *redisIndexBackendAdapter) HLen(ctx context.Context, key string) (int64, error) {
	return r.client.HLen(ctx, key).Result()
}

func (r *redisIndexBackendAdapter) SetNX(ctx context.Context, key, value string, expiration time.Duration) (bool, error) {
	_, err := r.client.SetArgs(ctx, key, value, redis.SetArgs{Mode: "NX", TTL: expiration}).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	return err == nil, err
}

func (r *redisIndexBackendAdapter) Get(ctx context.Context, key string) (string, error) {
	value, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrIndexMiss
	}
	return value, err
}

func (r *redisIndexBackendAdapter) SAdd(ctx context.Context, key string, members ...string) error {
	args := make([]interface{}, 0, len(members))
	for _, member := range members {
		args = append(args, member)
	}
	return r.client.SAdd(ctx, key, args...).Err()
}

func (r *redisIndexBackendAdapter) SAddMany(ctx context.Context, sets map[string][]string) error {
	if len(sets) == 0 {
		return nil
	}
	type setMembers struct {
		key     string
		members []string
	}
	commands := make([]setMembers, 0, redisWriteBatchSize)
	flush := func() error {
		_, err := r.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
			for _, command := range commands {
				args := make([]any, len(command.members))
				for index, member := range command.members {
					args[index] = member
				}
				pipe.SAdd(ctx, command.key, args...)
			}
			return nil
		})
		commands = commands[:0]
		return err
	}
	for key, members := range sets {
		for start := 0; start < len(members); start += redisMembersBatchSize {
			end := min(start+redisMembersBatchSize, len(members))
			commands = append(commands, setMembers{key: key, members: members[start:end]})
			if len(commands) >= redisWriteBatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
	if len(commands) > 0 {
		return flush()
	}
	return nil
}

func (r *redisIndexBackendAdapter) SMembers(ctx context.Context, key string) ([]string, error) {
	values, err := r.client.SMembers(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrIndexMiss
	}
	return values, err
}

func (r *redisIndexBackendAdapter) SCard(ctx context.Context, key string) (int64, error) {
	return r.client.SCard(ctx, key).Result()
}

func (r *redisIndexBackendAdapter) ZAddMany(ctx context.Context, key string, members []string) error {
	if len(members) == 0 {
		return nil
	}
	_, err := r.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for start := 0; start < len(members); start += redisMembersBatchSize {
			end := min(start+redisMembersBatchSize, len(members))
			values := make([]redis.Z, end-start)
			for index, member := range members[start:end] {
				values[index] = redis.Z{Member: member}
			}
			pipe.ZAdd(ctx, key, values...)
		}
		return nil
	})
	return err
}

func (r *redisIndexBackendAdapter) ZRangeByLex(ctx context.Context, key, minValue, maxValue string, limit int64) ([]string, error) {
	// ZRANGEBYLEX keeps compatibility with Redis protocol servers before 6.2;
	// the newer ZRANGE BYLEX syntax is not accepted by those releases.
	values, err := r.client.ZRangeByLex(ctx, key, &redis.ZRangeBy{ //nolint:staticcheck
		Min:   minValue,
		Max:   maxValue,
		Count: limit,
	}).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, ErrIndexMiss
	}
	return values, nil
}

func (r *redisIndexBackendAdapter) ZCard(ctx context.Context, key string) (int64, error) {
	return r.client.ZCard(ctx, key).Result()
}

func (r *redisIndexBackendAdapter) CommitIndex(ctx context.Context, exactKey, comparableKey, lexKey, readyKey, stagingExactKey, stagingComparableKey, stagingLexKey, readyValue string) error {
	const script = `
local expected_exact = tonumber(ARGV[2])
local expected_comparable = tonumber(ARGV[3])
if redis.call("hlen", KEYS[5]) ~= expected_exact or
   redis.call("hlen", KEYS[6]) ~= expected_comparable or
   redis.call("zcard", KEYS[7]) ~= expected_exact then
  return redis.error_reply("staging index is incomplete")
end
redis.call("del", KEYS[1], KEYS[2], KEYS[3])
if redis.call("exists", KEYS[5]) == 1 then redis.call("rename", KEYS[5], KEYS[1]) end
if redis.call("exists", KEYS[6]) == 1 then redis.call("rename", KEYS[6], KEYS[2]) end
if redis.call("exists", KEYS[7]) == 1 then redis.call("rename", KEYS[7], KEYS[3]) end
redis.call("set", KEYS[4], ARGV[1])
return 1`
	parts := strings.Split(readyValue, ":")
	if len(parts) != 3 || parts[0] != "v3" {
		return errors.New("invalid index ready marker")
	}
	return r.client.Eval(ctx, script,
		[]string{exactKey, comparableKey, lexKey, readyKey, stagingExactKey, stagingComparableKey, stagingLexKey},
		readyValue,
		parts[1],
		parts[2],
	).Err()
}

func (r *redisIndexBackendAdapter) MGet(ctx context.Context, keys ...string) ([]string, error) {
	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	results := make([]string, len(values))
	for index, value := range values {
		switch value := value.(type) {
		case nil:
		case string:
			results[index] = value
		case []byte:
			results[index] = string(value)
		default:
			return nil, errors.New("unexpected Redis index value")
		}
	}
	return results, nil
}

func (r *redisIndexBackendAdapter) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := r.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for start := 0; start < len(keys); start += redisMembersBatchSize {
			end := min(start+redisMembersBatchSize, len(keys))
			pipe.Del(ctx, keys[start:end]...)
		}
		return nil
	})
	return err
}

func (r *redisIndexBackendAdapter) CompareAndDelete(ctx context.Context, key, value string) (bool, error) {
	const script = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`
	deleted, err := r.client.Eval(ctx, script, []string{key}, value).Int64()
	return deleted == 1, err
}

// RedisIndexStoreOption customizes RedisIndexStore construction.
type RedisIndexStoreOption func(*RedisIndexStore)

// WithRedisIndexContext overrides the store context.
func WithRedisIndexContext(ctx context.Context) RedisIndexStoreOption {
	return func(store *RedisIndexStore) {
		if ctx != nil {
			store.ctx = ctx
		}
	}
}

// WithRedisKeyPrefix overrides the Redis key namespace prefix.
func WithRedisKeyPrefix(prefix string) RedisIndexStoreOption {
	return func(store *RedisIndexStore) {
		if strings.TrimSpace(prefix) != "" {
			store.prefix = prefix
		}
	}
}

// WithRedisPrefixIndexMaxLen overrides the maximum stored prefix length.
func WithRedisPrefixIndexMaxLen(maxLen int) RedisIndexStoreOption {
	return func(store *RedisIndexStore) {
		if maxLen > 0 {
			store.prefixIndexMaxLen = maxLen
		}
	}
}

// RedisIndexStore is a Redis-protocol-compatible implementation of ManagedIndexStore.
type RedisIndexStore struct {
	ctx               context.Context
	prefix            string
	prefixIndexMaxLen int
	backend           redisIndexBackend
}

// NewRedisIndexStore creates a Redis-backed store.
func NewRedisIndexStore(client *redis.Client, opts ...RedisIndexStoreOption) *RedisIndexStore {
	store := &RedisIndexStore{
		ctx:               context.Background(),
		prefix:            "mdx:index",
		prefixIndexMaxLen: defaultRedisPrefixIndexMaxLen,
		backend:           &redisIndexBackendAdapter{client: client},
	}
	for _, opt := range opts {
		opt(store)
	}
	return store
}

func (s *RedisIndexStore) dictKeysSetKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":keys"
}

func (s *RedisIndexStore) dictPrefixRegistryKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":prefix-sets"
}

func (s *RedisIndexStore) dictExactKey(dictionaryName, keyword string) string {
	return s.prefix + ":" + dictionaryName + ":exact:" + keyword
}

func (s *RedisIndexStore) dictExactHashKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":entries"
}

func (s *RedisIndexStore) dictComparableHashKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":comparable"
}

func (s *RedisIndexStore) dictPrefixSetKey(dictionaryName, prefix string) string {
	return s.prefix + ":" + dictionaryName + ":prefix:" + prefix
}

func (s *RedisIndexStore) dictManifestKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":manifest"
}

func (s *RedisIndexStore) dictLexKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":lex"
}

func (s *RedisIndexStore) dictReadyKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":ready"
}

func (s *RedisIndexStore) dictBuildLeaseKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":build-lease"
}

// Put stores dictionary metadata and index entries in a Redis-compatible server.
func (s *RedisIndexStore) Put(info DictionaryInfo, entries []IndexEntry) error {
	if strings.TrimSpace(info.Name) == "" {
		return errors.New("dictionary name is required")
	}

	keysSet := s.dictKeysSetKey(info.Name)
	prefixRegistry := s.dictPrefixRegistryKey(info.Name)
	lexKey := s.dictLexKey(info.Name)
	exactHashKey := s.dictExactHashKey(info.Name)
	comparableHashKey := s.dictComparableHashKey(info.Name)
	oldKeys, err := s.backend.SMembers(s.ctx, keysSet)
	if err != nil && !errors.Is(err, ErrIndexMiss) {
		return err
	}
	oldPrefixSets, err := s.backend.SMembers(s.ctx, prefixRegistry)
	if err != nil && !errors.Is(err, ErrIndexMiss) {
		return err
	}

	legacyKeys := make([]string, 0, len(oldKeys)+len(oldPrefixSets)+2)
	legacyKeys = append(legacyKeys, keysSet, prefixRegistry)
	for _, keyword := range oldKeys {
		legacyKeys = append(legacyKeys, s.dictExactKey(info.Name, keyword))
	}
	legacyKeys = append(legacyKeys, oldPrefixSets...)

	token, err := newRedisBuildLeaseToken()
	if err != nil {
		return err
	}
	stagingExactKey := exactHashKey + ":staging:" + token
	stagingComparableKey := comparableHashKey + ":staging:" + token
	stagingLexKey := lexKey + ":staging:" + token
	defer func() {
		if err := s.backend.Del(s.ctx, stagingExactKey, stagingComparableKey, stagingLexKey); err != nil {
			log.Warningf("delete staging index for %s: %v", info.Name, err)
		}
	}()

	registry := make([]string, 0, len(entries))
	seenKeys := make(map[string]struct{}, len(entries))
	seenComparableKeys := make(map[string]struct{}, len(entries))
	lexMembers := make([]string, 0, len(entries))
	exactValues := make(map[string]string, redisWriteBatchSize)
	comparableValues := make(map[string]string, redisWriteBatchSize)
	flushExactValues := func() error {
		if err := s.backend.HSetMany(s.ctx, stagingExactKey, exactValues); err != nil {
			return err
		}
		clear(exactValues)
		return nil
	}
	flushComparableValues := func() error {
		if err := s.backend.HSetMany(s.ctx, stagingComparableKey, comparableValues); err != nil {
			return err
		}
		clear(comparableValues)
		return nil
	}
	for _, entry := range entries {
		key := indexStoreLookupKey(entry)
		if strings.TrimSpace(key) == "" {
			continue
		}
		if _, ok := seenKeys[key]; ok {
			continue
		}

		payload, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		exactValues[key] = string(payload)
		if len(exactValues) >= redisWriteBatchSize {
			if err := flushExactValues(); err != nil {
				return err
			}
		}
		comparableKey := normalizeComparableKey(key)
		if comparableKey != "" {
			if _, exists := seenComparableKeys[comparableKey]; !exists {
				seenComparableKeys[comparableKey] = struct{}{}
				comparableValues[comparableKey] = key
			}
			if len(comparableValues) >= redisWriteBatchSize {
				if err := flushComparableValues(); err != nil {
					return err
				}
			}
		}

		seenKeys[key] = struct{}{}
		registry = append(registry, key)
		lexMembers = append(lexMembers, redisLexMember(key))
	}
	if err := flushExactValues(); err != nil {
		return err
	}
	if err := flushComparableValues(); err != nil {
		return err
	}
	comparableCount, err := s.backend.HLen(s.ctx, stagingComparableKey)
	if err != nil {
		return err
	}

	if err := s.backend.ZAddMany(s.ctx, stagingLexKey, lexMembers); err != nil {
		return err
	}
	if err := s.backend.CommitIndex(s.ctx,
		exactHashKey,
		comparableHashKey,
		lexKey,
		s.dictReadyKey(info.Name),
		stagingExactKey,
		stagingComparableKey,
		stagingLexKey,
		"v3:"+strconv.Itoa(len(registry))+":"+strconv.FormatInt(comparableCount, 10),
	); err != nil {
		return err
	}
	if err := s.backend.Del(s.ctx, legacyKeys...); err != nil {
		log.Warningf("delete legacy index for %s: %v", info.Name, err)
	}
	return nil
}

// GetComparable returns the first entry whose keyword has the same normalized
// comparable form as keyword.
func (s *RedisIndexStore) GetComparable(dictionaryName, keyword string) (IndexEntry, error) {
	comparableKey := normalizeComparableKey(keyword)
	if comparableKey == "" {
		return IndexEntry{}, ErrIndexMiss
	}
	exactKey, err := s.backend.HGet(s.ctx, s.dictComparableHashKey(dictionaryName), comparableKey)
	if err != nil {
		return IndexEntry{}, err
	}
	return s.GetExact(dictionaryName, exactKey)
}

// GetExact returns one exact entry from a Redis-compatible server.
func (s *RedisIndexStore) GetExact(dictionaryName, keyword string) (IndexEntry, error) {
	raw, err := s.backend.HGet(s.ctx, s.dictExactHashKey(dictionaryName), keyword)
	if errors.Is(err, ErrIndexMiss) {
		_, markerErr := s.backend.Get(s.ctx, s.dictReadyKey(dictionaryName))
		if errors.Is(markerErr, ErrIndexMiss) {
			raw, err = s.backend.Get(s.ctx, s.dictExactKey(dictionaryName, keyword))
		} else if markerErr != nil {
			return IndexEntry{}, markerErr
		}
	}
	if err != nil {
		return IndexEntry{}, err
	}

	var entry IndexEntry
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		return IndexEntry{}, err
	}
	return entry, nil
}

// PrefixSearch returns entries that share the supplied prefix.
func (s *RedisIndexStore) PrefixSearch(dictionaryName, prefix string, limit int) ([]IndexEntry, error) {
	prefixLower := strings.ToLower(strings.TrimSpace(prefix))
	keys, err := s.prefixSearchLex(dictionaryName, prefixLower, limit)
	if err == nil {
		return s.loadPrefixEntries(dictionaryName, keys, false)
	}
	if !errors.Is(err, ErrIndexMiss) {
		return nil, err
	}
	_, markerErr := s.backend.Get(s.ctx, s.dictReadyKey(dictionaryName))
	if markerErr == nil {
		return nil, ErrIndexMiss
	}
	if !errors.Is(markerErr, ErrIndexMiss) {
		return nil, markerErr
	}
	return s.prefixSearchLegacy(dictionaryName, prefixLower, limit)
}

func (s *RedisIndexStore) prefixSearchLex(dictionaryName, prefixLower string, limit int) ([]string, error) {
	minValue := "-"
	maxValue := "+"
	if prefixLower != "" {
		minValue = "[" + prefixLower
		maxValue = "[" + prefixLower + "\xff"
	}
	resultLimit := int64(0)
	if limit > 0 {
		resultLimit = int64(limit)
	}
	members, err := s.backend.ZRangeByLex(s.ctx, s.dictLexKey(dictionaryName), minValue, maxValue, resultLimit)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(members))
	for _, member := range members {
		_, key, ok := strings.Cut(member, "\x00")
		if ok {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, ErrIndexMiss
	}
	return keys, nil
}

func (s *RedisIndexStore) prefixSearchLegacy(dictionaryName, prefixLower string, limit int) ([]IndexEntry, error) {
	var setKey string
	if prefixLower == "" {
		setKey = s.dictKeysSetKey(dictionaryName)
	} else {
		lookupPrefix := prefixLower
		if len(lookupPrefix) > s.prefixIndexMaxLen {
			lookupPrefix = lookupPrefix[:s.prefixIndexMaxLen]
		}
		setKey = s.dictPrefixSetKey(dictionaryName, lookupPrefix)
	}
	keys, err := s.backend.SMembers(s.ctx, setKey)
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	selected := keys[:0]
	for _, key := range keys {
		if prefixLower != "" && !strings.HasPrefix(strings.ToLower(key), prefixLower) {
			continue
		}
		selected = append(selected, key)
		if limit > 0 && len(selected) >= limit {
			break
		}
	}
	if len(selected) == 0 {
		return nil, ErrIndexMiss
	}
	return s.loadPrefixEntries(dictionaryName, selected, true)
}

func (s *RedisIndexStore) loadPrefixEntries(dictionaryName string, keys []string, legacy bool) ([]IndexEntry, error) {
	var (
		values []string
		err    error
	)
	if legacy {
		valueKeys := make([]string, len(keys))
		for index, key := range keys {
			valueKeys[index] = s.dictExactKey(dictionaryName, key)
		}
		values, err = s.backend.MGet(s.ctx, valueKeys...)
	} else {
		values, err = s.backend.HMGet(s.ctx, s.dictExactHashKey(dictionaryName), keys...)
	}
	if err != nil {
		return nil, err
	}
	if !legacy {
		for _, value := range values {
			if value == "" {
				return nil, ErrIndexMiss
			}
		}
	}
	return prefixResults(values)
}

func prefixResults(values []string) ([]IndexEntry, error) {
	results := make([]IndexEntry, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		var entry IndexEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			return nil, err
		}
		results = append(results, entry)
	}
	if len(results) == 0 {
		return nil, ErrIndexMiss
	}
	return results, nil
}

// LoadManifest returns lifecycle metadata for one dictionary.
func (s *RedisIndexStore) LoadManifest(dictionaryName string) (IndexManifest, error) {
	raw, err := s.backend.Get(s.ctx, s.dictManifestKey(dictionaryName))
	if err != nil {
		return IndexManifest{}, err
	}
	var manifest IndexManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		return IndexManifest{}, err
	}
	return manifest, nil
}

// SaveManifest stores lifecycle metadata for one dictionary.
func (s *RedisIndexStore) SaveManifest(manifest IndexManifest) error {
	if strings.TrimSpace(manifest.DictionaryName) == "" {
		return errors.New("dictionary name is required")
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return s.backend.Set(s.ctx, s.dictManifestKey(manifest.DictionaryName), string(payload))
}

// HasDictionaryIndex verifies all current-generation derived views. Older
// indexes remain readable but report unhealthy so lifecycle synchronization
// rebuilds the missing comparable-key view.
func (s *RedisIndexStore) HasDictionaryIndex(dictionaryName string) (bool, error) {
	marker, markerErr := s.backend.Get(s.ctx, s.dictReadyKey(dictionaryName))
	if markerErr != nil && !errors.Is(markerErr, ErrIndexMiss) {
		return false, markerErr
	}
	if errors.Is(markerErr, ErrIndexMiss) {
		return false, nil
	}
	parts := strings.Split(marker, ":")
	if len(parts) != 3 || parts[0] != "v3" {
		return false, nil
	}
	expected, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || expected < 0 {
		return false, nil
	}
	expectedComparable, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || expectedComparable < 0 {
		return false, nil
	}
	lexCount, err := s.backend.ZCard(s.ctx, s.dictLexKey(dictionaryName))
	if err != nil {
		return false, err
	}
	exactCount, err := s.backend.HLen(s.ctx, s.dictExactHashKey(dictionaryName))
	if err != nil {
		return false, err
	}
	comparableCount, err := s.backend.HLen(s.ctx, s.dictComparableHashKey(dictionaryName))
	if err != nil {
		return false, err
	}
	return exactCount == expected && lexCount == expected && comparableCount == expectedComparable, nil
}

// DeleteDictionary removes one dictionary's entries and manifest.
func (s *RedisIndexStore) DeleteDictionary(dictionaryName string) error {
	keysSet := s.dictKeysSetKey(dictionaryName)
	prefixRegistry := s.dictPrefixRegistryKey(dictionaryName)
	oldKeys, err := s.backend.SMembers(s.ctx, keysSet)
	if err != nil && !errors.Is(err, ErrIndexMiss) {
		return err
	}
	oldPrefixSets, err := s.backend.SMembers(s.ctx, prefixRegistry)
	if err != nil && !errors.Is(err, ErrIndexMiss) {
		return err
	}

	toDelete := make([]string, 0, len(oldKeys)+len(oldPrefixSets)+7)
	toDelete = append(toDelete, keysSet, prefixRegistry, s.dictLexKey(dictionaryName), s.dictExactHashKey(dictionaryName), s.dictComparableHashKey(dictionaryName), s.dictManifestKey(dictionaryName), s.dictReadyKey(dictionaryName))
	for _, keyword := range oldKeys {
		toDelete = append(toDelete, s.dictExactKey(dictionaryName, keyword))
	}
	toDelete = append(toDelete, oldPrefixSets...)
	return s.backend.Del(s.ctx, toDelete...)
}

func redisLexMember(key string) string {
	return strings.ToLower(key) + "\x00" + key
}

// AcquireIndexBuildLease coordinates dictionary index rebuild ownership across processes.
func (s *RedisIndexStore) AcquireIndexBuildLease(dictionaryName string, ttl time.Duration) (func() error, bool, error) {
	if strings.TrimSpace(dictionaryName) == "" {
		return nil, false, errors.New("dictionary name is required")
	}
	if ttl <= 0 {
		return nil, false, errors.New("index build lease ttl must be positive")
	}
	token, err := newRedisBuildLeaseToken()
	if err != nil {
		return nil, false, err
	}
	key := s.dictBuildLeaseKey(dictionaryName)
	acquired, err := s.backend.SetNX(s.ctx, key, token, ttl)
	if err != nil || !acquired {
		return nil, acquired, err
	}
	release := func() error {
		_, err := s.backend.CompareAndDelete(s.ctx, key, token)
		return err
	}
	return release, true, nil
}

func newRedisBuildLeaseToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
