package mdx

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/redis/go-redis/v9"
)

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

// RedisIndexStore is a Redis-backed reference implementation of IndexStore.
type RedisIndexStore struct {
	ctx     context.Context
	prefix  string
	backend redisIndexBackend
}

// NewRedisIndexStore creates a Redis-backed store with context.Background().
func NewRedisIndexStore(client *redis.Client) *RedisIndexStore {
	return NewRedisIndexStoreWithContext(context.Background(), client)
}

// NewRedisIndexStoreWithContext creates a Redis-backed store with an explicit context.
func NewRedisIndexStoreWithContext(ctx context.Context, client *redis.Client) *RedisIndexStore {
	return &RedisIndexStore{
		ctx:     ctx,
		prefix:  "mdx:index",
		backend: &redisIndexBackendAdapter{client: client},
	}
}

func (s *RedisIndexStore) dictKeysSetKey(dictionaryName string) string {
	return s.prefix + ":" + dictionaryName + ":keys"
}

func (s *RedisIndexStore) dictExactKey(dictionaryName, keyword string) string {
	return s.prefix + ":" + dictionaryName + ":exact:" + keyword
}

func indexStoreLookupKey(entry IndexEntry) string {
	if entry.IsResource && entry.NormalizedKeyword != "" {
		return entry.NormalizedKeyword
	}
	return entry.Keyword
}

// Put stores dictionary metadata and index entries in Redis.
func (s *RedisIndexStore) Put(info DictionaryInfo, entries []IndexEntry) error {
	if strings.TrimSpace(info.Name) == "" {
		return errors.New("dictionary name is required")
	}

	keysSet := s.dictKeysSetKey(info.Name)
	oldKeys, err := s.backend.SMembers(s.ctx, keysSet)
	if err != nil && !errors.Is(err, ErrIndexMiss) {
		return err
	}

	toDelete := make([]string, 0, len(oldKeys)+1)
	toDelete = append(toDelete, keysSet)
	for _, keyword := range oldKeys {
		toDelete = append(toDelete, s.dictExactKey(info.Name, keyword))
	}
	if err := s.backend.Del(s.ctx, toDelete...); err != nil {
		return err
	}

	registry := make([]string, 0, len(entries))
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
		if err := s.backend.Set(s.ctx, s.dictExactKey(info.Name, key), string(payload)); err != nil {
			return err
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		registry = append(registry, key)
	}

	if len(registry) == 0 {
		return nil
	}
	return s.backend.SAdd(s.ctx, keysSet, registry...)
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
	keys, err := s.backend.SMembers(s.ctx, s.dictKeysSetKey(dictionaryName))
	if err != nil {
		return nil, err
	}

	prefixLower := strings.ToLower(prefix)
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
