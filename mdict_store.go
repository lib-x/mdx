package mdx

import (
	"cmp"
	"errors"
	"slices"
	"strings"
)

// IndexStore defines the minimal external index boundary for exact and prefix search.
type IndexStore interface {
	Put(info DictionaryInfo, entries []IndexEntry) error
	GetExact(dictionaryName, keyword string) (IndexEntry, error)
	PrefixSearch(dictionaryName, prefix string, limit int) ([]IndexEntry, error)
}

// SearchHit represents a ranked search result from a fuzzy-capable store.
type SearchHit struct {
	Entry  IndexEntry `json:"entry"`
	Score  float64    `json:"score"`
	Source string     `json:"source"`
}

// FuzzyIndexStore defines a fuzzy-search-capable external index boundary.
type FuzzyIndexStore interface {
	Put(info DictionaryInfo, entries []IndexEntry) error
	Search(dictionaryName, query string, limit int) ([]SearchHit, error)
}

// ErrIndexMiss is returned when no entry exists in the external index store.
var ErrIndexMiss = errors.New("index entry not found")

// MemoryIndexStore is a small in-memory reference implementation of ManagedIndexStore.
type MemoryIndexStore struct {
	entriesByDict   map[string][]IndexEntry
	exactByDict     map[string]map[string]IndexEntry
	manifestsByDict map[string]IndexManifest
}

// NewMemoryIndexStore creates a new in-memory store.
func NewMemoryIndexStore() *MemoryIndexStore {
	return &MemoryIndexStore{
		entriesByDict:   make(map[string][]IndexEntry),
		exactByDict:     make(map[string]map[string]IndexEntry),
		manifestsByDict: make(map[string]IndexManifest),
	}
}

// Put stores dictionary metadata and entries.
func (s *MemoryIndexStore) Put(info DictionaryInfo, entries []IndexEntry) error {
	if strings.TrimSpace(info.Name) == "" {
		return errors.New("dictionary name is required")
	}

	cloned := make([]IndexEntry, len(entries))
	copy(cloned, entries)
	s.entriesByDict[info.Name] = cloned

	exact := make(map[string]IndexEntry, len(entries))
	for _, entry := range entries {
		key := indexStoreLookupKey(entry)
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
		key := indexStoreLookupKey(entry)
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

// LoadManifest returns lifecycle metadata for one dictionary.
func (s *MemoryIndexStore) LoadManifest(dictionaryName string) (IndexManifest, error) {
	manifest, ok := s.manifestsByDict[dictionaryName]
	if !ok {
		return IndexManifest{}, ErrIndexMiss
	}
	return manifest, nil
}

// SaveManifest stores lifecycle metadata for one dictionary.
func (s *MemoryIndexStore) SaveManifest(manifest IndexManifest) error {
	if strings.TrimSpace(manifest.DictionaryName) == "" {
		return errors.New("dictionary name is required")
	}
	s.manifestsByDict[manifest.DictionaryName] = manifest
	return nil
}

// DeleteDictionary removes one dictionary's entries and manifest.
func (s *MemoryIndexStore) DeleteDictionary(dictionaryName string) error {
	delete(s.entriesByDict, dictionaryName)
	delete(s.exactByDict, dictionaryName)
	delete(s.manifestsByDict, dictionaryName)
	return nil
}

// MemoryFuzzyIndexStore is a small in-memory reference implementation of FuzzyIndexStore.
type MemoryFuzzyIndexStore struct {
	entriesByDict map[string][]IndexEntry
}

// NewMemoryFuzzyIndexStore creates a new in-memory fuzzy store.
func NewMemoryFuzzyIndexStore() *MemoryFuzzyIndexStore {
	return &MemoryFuzzyIndexStore{
		entriesByDict: make(map[string][]IndexEntry),
	}
}

// Put stores dictionary metadata and entries.
func (s *MemoryFuzzyIndexStore) Put(info DictionaryInfo, entries []IndexEntry) error {
	if strings.TrimSpace(info.Name) == "" {
		return errors.New("dictionary name is required")
	}

	cloned := make([]IndexEntry, len(entries))
	copy(cloned, entries)
	s.entriesByDict[info.Name] = cloned
	return nil
}

// Search performs a simple in-memory fuzzy search suitable for demos and tests.
func (s *MemoryFuzzyIndexStore) Search(dictionaryName, query string, limit int) ([]SearchHit, error) {
	entries, ok := s.entriesByDict[dictionaryName]
	if !ok {
		return nil, ErrIndexMiss
	}

	query = strings.TrimSpace(query)
	if query == "" {
		return nil, ErrIndexMiss
	}

	queryLower := strings.ToLower(query)
	results := make([]SearchHit, 0)
	for _, entry := range entries {
		key := strings.ToLower(indexStoreLookupKey(entry))
		score, source, ok := fuzzyScore(queryLower, key)
		if !ok {
			continue
		}

		results = append(results, SearchHit{
			Entry:  entry,
			Score:  score,
			Source: source,
		})
	}

	if len(results) == 0 {
		return nil, ErrIndexMiss
	}

	slices.SortFunc(results, func(a, b SearchHit) int {
		if scoreCmp := cmp.Compare(b.Score, a.Score); scoreCmp != 0 {
			return scoreCmp
		}
		return cmp.Compare(indexStoreLookupKey(a.Entry), indexStoreLookupKey(b.Entry))
	})

	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	return results, nil
}

func indexStoreLookupKey(entry IndexEntry) string {
	if entry.IsResource && entry.NormalizedKeyword != "" {
		return entry.NormalizedKeyword
	}
	return entry.Keyword
}

func prefixCandidatesForKey(key string, maxLen int) []string {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return nil
	}

	limit := maxLen
	if limit <= 0 || len(key) < limit {
		limit = len(key)
	}

	out := make([]string, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, key[:i])
	}
	return out
}

func fuzzyScore(query, key string) (float64, string, bool) {
	switch {
	case query == key:
		return 1.0, "exact", true
	case strings.HasPrefix(key, query):
		return 0.95, "prefix", true
	case strings.Contains(key, query):
		return 0.8, "contains", true
	}

	distance := levenshteinDistance(query, key)
	maxLen := max(len(query), len(key))
	if maxLen == 0 {
		return 0, "", false
	}

	score := 1 - float64(distance)/float64(maxLen)
	if score < 0.5 {
		return 0, "", false
	}
	return score, "edit-distance", true
}

func levenshteinDistance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			deletion := prev[j] + 1
			insertion := curr[j-1] + 1
			substitution := prev[j-1] + cost
			curr[j] = min(deletion, min(insertion, substitution))
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}
