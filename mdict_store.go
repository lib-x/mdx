package mdx

import (
	"errors"
	"strings"
)

// IndexStore defines the minimal external index boundary for exact and prefix search.
type IndexStore interface {
	Put(info DictionaryInfo, entries []IndexEntry) error
	GetExact(dictionaryName, keyword string) (IndexEntry, error)
	PrefixSearch(dictionaryName, prefix string, limit int) ([]IndexEntry, error)
}

// ErrIndexMiss is returned when no entry exists in the external index store.
var ErrIndexMiss = errors.New("index entry not found")

// MemoryIndexStore is a small in-memory reference implementation of IndexStore.
type MemoryIndexStore struct {
	entriesByDict map[string][]IndexEntry
	exactByDict   map[string]map[string]IndexEntry
}

// NewMemoryIndexStore creates a new in-memory store.
func NewMemoryIndexStore() *MemoryIndexStore {
	return &MemoryIndexStore{
		entriesByDict: make(map[string][]IndexEntry),
		exactByDict:   make(map[string]map[string]IndexEntry),
	}
}

// Put stores dictionary metadata and entries.
func (s *MemoryIndexStore) Put(info DictionaryInfo, entries []IndexEntry) error {
	if info.Name == "" {
		return errors.New("dictionary name is required")
	}

	cloned := make([]IndexEntry, len(entries))
	copy(cloned, entries)
	s.entriesByDict[info.Name] = cloned

	exact := make(map[string]IndexEntry, len(entries))
	for _, entry := range entries {
		key := entry.Keyword
		if entry.IsResource && entry.NormalizedKeyword != "" {
			key = entry.NormalizedKeyword
		}
		if key == "" {
			continue
		}
		if _, exists := exact[key]; !exists {
			exact[key] = entry
		}
	}
	s.exactByDict[info.Name] = exact
	return nil
}

// GetExact retrieves a single exact-match entry.
func (s *MemoryIndexStore) GetExact(dictionaryName, keyword string) (IndexEntry, error) {
	exact, ok := s.exactByDict[dictionaryName]
	if !ok {
		return IndexEntry{}, ErrIndexMiss
	}
	entry, ok := exact[keyword]
	if ok {
		return entry, nil
	}
	return IndexEntry{}, ErrIndexMiss
}

// PrefixSearch returns entries that start with the supplied prefix.
func (s *MemoryIndexStore) PrefixSearch(dictionaryName, prefix string, limit int) ([]IndexEntry, error) {
	entries, ok := s.entriesByDict[dictionaryName]
	if !ok {
		return nil, ErrIndexMiss
	}

	prefix = strings.TrimSpace(prefix)
	results := make([]IndexEntry, 0)
	for _, entry := range entries {
		key := entry.Keyword
		if entry.IsResource && entry.NormalizedKeyword != "" {
			key = entry.NormalizedKeyword
		}
		if prefix == "" || strings.HasPrefix(strings.ToLower(key), strings.ToLower(prefix)) {
			results = append(results, entry)
		}
		if limit > 0 && len(results) >= limit {
			break
		}
	}

	if len(results) == 0 {
		return nil, ErrIndexMiss
	}
	return results, nil
}
