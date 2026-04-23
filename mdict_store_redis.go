package mdx

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/redis/go-redis/v9"
)

const defaultRedisPrefixIndexMaxLen = 8

type redisIndexBackend interface {
	Set(ctx context.Context, key, value string) error
	Get(ctx context.Context, key string) (string, error)
	SAdd(ctx context.Context, key string, members ...string) error
	SMembers(ctx context.Context, key string) ([]string, error)
	Del(ctx context.Context, keys ...string) error
}

type redisIndexBackendAdapter struct {
	client *redis.Client
}

func (r *redisIndexBackendAdapter) Set(ctx context.Context, key, value string) error {
	return r.client.Set(ctx, key, value, 0).Err()
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

func (r *redisIndexBackendAdapter) SMembers(ctx context.Context, key string) ([]string, error) {
	values, err := r.client.SMembers(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrIndexMiss
	}
	return values, err
}

func (r *redisIndexBackendAdapter) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return r.client.Del(ctx, keys...).Err()
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

// RedisIndexStore is a Redis-backed reference implementation of ManagedIndexStore.
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

func (s *RedisIndexStore) dictPrefixSetKey(dictionaryName, prefix string) string {
	return s.prefix + ":" + dictionaryName + ":prefix:" + prefix
}

func (s *RedisIndexStore) dictManifestKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":manifest"
}

// Put stores dictionary metadata and index entries in Redis.
func (s *RedisIndexStore) Put(info DictionaryInfo, entries []IndexEntry) error {
	if strings.TrimSpace(info.Name) == "" {
		return errors.New("dictionary name is required")
	}

	keysSet := s.dictKeysSetKey(info.Name)
	prefixRegistry := s.dictPrefixRegistryKey(info.Name)
	oldKeys, err := s.backend.SMembers(s.ctx, keysSet)
	if err != nil && !errors.Is(err, ErrIndexMiss) {
		return err
	}
	oldPrefixSets, err := s.backend.SMembers(s.ctx, prefixRegistry)
	if err != nil && !errors.Is(err, ErrIndexMiss) {
		return err
	}

	toDelete := make([]string, 0, len(oldKeys)+len(oldPrefixSets)+2)
	toDelete = append(toDelete, keysSet, prefixRegistry)
	for _, keyword := range oldKeys {
		toDelete = append(toDelete, s.dictExactKey(info.Name, keyword))
	}
	toDelete = append(toDelete, oldPrefixSets...)
	if err := s.backend.Del(s.ctx, toDelete...); err != nil {
		return err
	}

	registry := make([]string, 0, len(entries))
	seenKeys := make(map[string]struct{}, len(entries))
	prefixMembers := make(map[string][]string)
	for _, entry := range entries {
		key := indexStoreLookupKey(entry)
		if strings.TrimSpace(key) == "" {
			continue
		}

		payload, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := s.backend.Set(s.ctx, s.dictExactKey(info.Name, key), string(payload)); err != nil {
			return err
		}

		if _, ok := seenKeys[key]; !ok {
			seenKeys[key] = struct{}{}
			registry = append(registry, key)

			for _, prefix := range prefixCandidatesForKey(key, s.prefixIndexMaxLen) {
				prefixKey := s.dictPrefixSetKey(info.Name, prefix)
				prefixMembers[prefixKey] = append(prefixMembers[prefixKey], key)
			}
		}
	}

	if len(registry) > 0 {
		if err := s.backend.SAdd(s.ctx, keysSet, registry...); err != nil {
			return err
		}
	}

	if len(prefixMembers) > 0 {
		prefixSetKeys := make([]string, 0, len(prefixMembers))
		for prefixKey, members := range prefixMembers {
			if err := s.backend.SAdd(s.ctx, prefixKey, members...); err != nil {
				return err
			}
			prefixSetKeys = append(prefixSetKeys, prefixKey)
		}
		if err := s.backend.SAdd(s.ctx, prefixRegistry, prefixSetKeys...); err != nil {
			return err
		}
	}

	return nil
}

// GetExact returns one exact entry from Redis.
func (s *RedisIndexStore) GetExact(dictionaryName, keyword string) (IndexEntry, error) {
	raw, err := s.backend.Get(s.ctx, s.dictExactKey(dictionaryName, keyword))
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
	var (
		keys []string
		err  error
	)

	if prefixLower == "" {
		keys, err = s.backend.SMembers(s.ctx, s.dictKeysSetKey(dictionaryName))
		if err != nil {
			return nil, err
		}
	} else {
		lookupPrefix := prefixLower
		if len(lookupPrefix) > s.prefixIndexMaxLen {
			lookupPrefix = lookupPrefix[:s.prefixIndexMaxLen]
		}
		keys, err = s.backend.SMembers(s.ctx, s.dictPrefixSetKey(dictionaryName, lookupPrefix))
		if err != nil {
			return nil, err
		}
	}

	results := make([]IndexEntry, 0)
	for _, keyword := range keys {
		if prefixLower != "" && !strings.HasPrefix(strings.ToLower(keyword), prefixLower) {
			continue
		}

		entry, err := s.GetExact(dictionaryName, keyword)
		if err != nil {
			return nil, err
		}
		results = append(results, entry)
		if limit > 0 && len(results) >= limit {
			break
		}
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

	toDelete := make([]string, 0, len(oldKeys)+len(oldPrefixSets)+3)
	toDelete = append(toDelete, keysSet, prefixRegistry, s.dictManifestKey(dictionaryName))
	for _, keyword := range oldKeys {
		toDelete = append(toDelete, s.dictExactKey(dictionaryName, keyword))
	}
	toDelete = append(toDelete, oldPrefixSets...)
	return s.backend.Del(s.ctx, toDelete...)
}
