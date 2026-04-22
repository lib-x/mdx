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
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	MDXPath  string   `json:"mdx_path"`
	MDDPath  string   `json:"mdd_path,omitzero"`
	MDDPaths []string `json:"mdd_paths,omitempty"`
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
	mddByBase := make(map[string][]string)
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
			mainBase, volume, ok := splitMDDBase(name)
			if !ok {
				continue
			}
			if volume == 0 {
				mddByBase[mainBase] = append([]string{fullPath}, mddByBase[mainBase]...)
				continue
			}
			mddByBase[mainBase] = append(mddByBase[mainBase], fullPath)
		}
	}

	bases := make([]string, 0, len(mdxByBase))
	for base := range mdxByBase {
		bases = append(bases, base)
	}
	slices.Sort(bases)

	specs := make([]DictionarySpec, 0, len(bases))
	for _, base := range bases {
		mddPaths := mddByBase[base]
		slices.SortFunc(mddPaths, compareMDDVolumePaths)
		mddPath := ""
		if len(mddPaths) > 0 {
			mddPath = mddPaths[0]
		}
		specs = append(specs, DictionarySpec{
			ID:       base,
			Name:     base,
			MDXPath:  mdxByBase[base],
			MDDPath:  mddPath,
			MDDPaths: append([]string(nil), mddPaths...),
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

	mddPaths := companionMDDPaths(spec)
	var mddDict *Mdict
	mddDicts := make([]*Mdict, 0, len(mddPaths))
	for idx, mddPath := range mddPaths {
		mdd, openErr := New(mddPath)
		if openErr != nil {
			return nil, nil, openErr
		}
		if buildErr := mdd.BuildIndex(); buildErr != nil {
			return nil, nil, buildErr
		}
		if idx == 0 {
			mddDict = mdd
		}
		mddDicts = append(mddDicts, mdd)
	}

	ConfigureDictionaryPairAssets(spec, mdxDict, mddDicts...)

	return mdxDict, mddDict, nil
}

// ConfigureDictionaryPairAssets composes the default shared asset resolver for a dictionary pair.
func ConfigureDictionaryPairAssets(spec DictionarySpec, mdxDict *Mdict, mddDicts ...*Mdict) {
	var opts []AssetResolverOption

	if mdxDir := strings.TrimSpace(filepath.Dir(spec.MDXPath)); mdxDir != "" && mdxDir != "." {
		opts = append(opts, WithAssetSidecarDir(mdxDir))
	}
	if len(mddDicts) > 0 {
		opts = append(opts, WithAssetMdicts(mddDicts...))
	}

	resolver := NewAssetResolver(nil, opts...)
	if mdxDict != nil {
		mdxDict.SetAssetResolver(resolver)
	}
	for _, dict := range mddDicts {
		if dict == nil {
			continue
		}
		dict.SetAssetResolver(resolver)
	}
}

func companionMDDPaths(spec DictionarySpec) []string {
	if len(spec.MDDPaths) > 0 {
		return append([]string(nil), spec.MDDPaths...)
	}
	if strings.TrimSpace(spec.MDDPath) == "" {
		return nil
	}
	return []string{spec.MDDPath}
}

func splitMDDBase(name string) (string, int, bool) {
	if !strings.HasSuffix(strings.ToLower(name), ".mdd") {
		return "", 0, false
	}
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	parts := strings.Split(stem, ".")
	if len(parts) == 1 {
		return stem, 0, true
	}
	last := parts[len(parts)-1]
	if last == "" {
		return "", 0, false
	}
	volume := 0
	for _, ch := range last {
		if ch < '0' || ch > '9' {
			return stem, 0, true
		}
		volume = volume*10 + int(ch-'0')
	}
	return strings.Join(parts[:len(parts)-1], "."), volume, true
}

func compareMDDVolumePaths(left, right string) int {
	_, lvol, _ := splitMDDBase(filepath.Base(left))
	_, rvol, _ := splitMDDBase(filepath.Base(right))
	if lvol != rvol {
		if lvol < rvol {
			return -1
		}
		return 1
	}
	return strings.Compare(left, right)
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
