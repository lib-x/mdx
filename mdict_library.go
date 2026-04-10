package mdx

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// DictionarySpec describes one discoverable dictionary pair.
type DictionarySpec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	MDXPath string `json:"mdx_path"`
	MDDPath string `json:"mdd_path,omitzero"`
}

// LibrarySearchHit describes a search result together with its dictionary source.
type LibrarySearchHit struct {
	DictID   string    `json:"dict_id"`
	DictName string    `json:"dict_name"`
	Hit      SearchHit `json:"hit"`
}

type dictionaryPair struct {
	spec DictionarySpec

	once sync.Once
	mdx  *Mdict
	mdd  *Mdict
	err  error
}

// DictionaryRegistry manages multiple dictionary pairs discovered from disk.
type DictionaryRegistry struct {
	mu    sync.RWMutex
	specs []DictionarySpec
	byID  map[string]*dictionaryPair
}

// NewDictionaryRegistry creates an empty registry.
func NewDictionaryRegistry() *DictionaryRegistry {
	return &DictionaryRegistry{
		byID: make(map[string]*dictionaryPair),
	}
}

// ScanDirectory scans a root directory for MDX/MDD pairs and returns their specs.
func ScanDirectory(root string) ([]DictionarySpec, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("root directory is required")
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	mdxByBase := make(map[string]string)
	mddByBase := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		base := strings.TrimSuffix(name, filepath.Ext(name))
		fullPath := filepath.Join(root, name)

		switch ext {
		case ".mdx":
			mdxByBase[base] = fullPath
		case ".mdd":
			mddByBase[base] = fullPath
		}
	}

	bases := make([]string, 0, len(mdxByBase))
	for base := range mdxByBase {
		bases = append(bases, base)
	}
	slices.Sort(bases)

	specs := make([]DictionarySpec, 0, len(bases))
	for _, base := range bases {
		specs = append(specs, DictionarySpec{
			ID:      base,
			Name:    base,
			MDXPath: mdxByBase[base],
			MDDPath: mddByBase[base],
		})
	}

	return specs, nil
}

// LoadDirectory scans and loads specs from a root directory into the registry.
func (r *DictionaryRegistry) LoadDirectory(root string) error {
	specs, err := ScanDirectory(root)
	if err != nil {
		return err
	}
	r.LoadSpecs(specs)
	return nil
}

// LoadSpecs replaces the registry contents with the provided specs.
func (r *DictionaryRegistry) LoadSpecs(specs []DictionarySpec) {
	byID := make(map[string]*dictionaryPair, len(specs))
	cloned := make([]DictionarySpec, len(specs))
	copy(cloned, specs)
	for i := range cloned {
		spec := cloned[i]
		byID[spec.ID] = &dictionaryPair{spec: spec}
	}

	r.mu.Lock()
	r.specs = cloned
	r.byID = byID
	r.mu.Unlock()
}

// List returns the known dictionary specs.
func (r *DictionaryRegistry) List() []DictionarySpec {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]DictionarySpec, len(r.specs))
	copy(out, r.specs)
	return out
}

// OpenDictionary opens a dictionary pair by ID, lazily building indexes as needed.
func (r *DictionaryRegistry) OpenDictionary(id string) (*Mdict, *Mdict, error) {
	r.mu.RLock()
	pair, ok := r.byID[id]
	r.mu.RUnlock()
	if !ok {
		return nil, nil, ErrIndexMiss
	}

	pair.once.Do(func() {
		pair.mdx, pair.mdd, pair.err = openDictionaryPair(pair.spec)
	})

	return pair.mdx, pair.mdd, pair.err
}

func openDictionaryPair(spec DictionarySpec) (*Mdict, *Mdict, error) {
	if strings.TrimSpace(spec.MDXPath) == "" {
		return nil, nil, errors.New("mdx path is required")
	}

	mdxDict, err := New(spec.MDXPath)
	if err != nil {
		return nil, nil, err
	}
	if err := mdxDict.BuildIndex(); err != nil {
		return nil, nil, err
	}
	if title := strings.TrimSpace(mdxDict.Title()); title != "" {
		mdxDict.meta.title = title
	}

	var mddDict *Mdict
	if strings.TrimSpace(spec.MDDPath) != "" {
		mddDict, err = New(spec.MDDPath)
		if err != nil {
			return nil, nil, err
		}
		if err := mddDict.BuildIndex(); err != nil {
			return nil, nil, err
		}
	}

	return mdxDict, mddDict, nil
}

// LibrarySearch performs a library-wide fuzzy search using the in-memory fuzzy store.
func (r *DictionaryRegistry) LibrarySearch(query string, limit int) ([]LibrarySearchHit, error) {
	specs := r.List()
	if len(specs) == 0 {
		return nil, ErrIndexMiss
	}

	results := make([]LibrarySearchHit, 0)
	for _, spec := range specs {
		mdxDict, _, err := r.OpenDictionary(spec.ID)
		if err != nil || mdxDict == nil {
			continue
		}

		entries, err := mdxDict.ExportEntries()
		if err != nil {
			continue
		}

		store := NewMemoryFuzzyIndexStore()
		info := mdxDict.DictionaryInfo()
		info.Name = spec.ID
		if err := store.Put(info, entries); err != nil {
			continue
		}

		hits, err := store.Search(spec.ID, query, limit)
		if err != nil {
			continue
		}

		dictName := spec.Name
		if title := strings.TrimSpace(mdxDict.Title()); title != "" {
			dictName = title
		}
		for _, hit := range hits {
			results = append(results, LibrarySearchHit{
				DictID:   spec.ID,
				DictName: dictName,
				Hit:      hit,
			})
			if limit > 0 && len(results) >= limit {
				return results, nil
			}
		}
	}

	if len(results) == 0 {
		return nil, ErrIndexMiss
	}
	return results, nil
}
