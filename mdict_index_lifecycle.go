package mdx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultIndexSchemaVersion = "v1"

var indexSyncLocks sync.Map

// Fingerprinter computes a stable fingerprint for a dictionary source.
type Fingerprinter interface {
	Fingerprint(path string) (string, error)
}

// FingerprinterFunc adapts a function into a Fingerprinter.
type FingerprinterFunc func(path string) (string, error)

// Fingerprint implements Fingerprinter.
func (fn FingerprinterFunc) Fingerprint(path string) (string, error) {
	return fn(path)
}

// FileStatFingerprinter fingerprints a dictionary source from cheap filesystem metadata.
type FileStatFingerprinter struct{}

// NewFileStatFingerprinter returns the default filesystem-stat fingerprinter.
func NewFileStatFingerprinter() Fingerprinter {
	return FileStatFingerprinter{}
}

// Fingerprint implements Fingerprinter.
func (FileStatFingerprinter) Fingerprint(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	return fmt.Sprintf("stat:%s:%d:%d", absPath, info.Size(), info.ModTime().UTC().UnixNano()), nil
}

// IndexManifest describes externally stored index metadata used for lifecycle decisions.
type IndexManifest struct {
	DictionaryName string     `json:"dictionary_name"`
	SourcePath     string     `json:"source_path,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	SchemaVersion  string     `json:"schema_version,omitempty"`
	BuiltAt        time.Time  `json:"built_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

// ManagedIndexStore extends IndexStore with lifecycle metadata operations.
type ManagedIndexStore interface {
	IndexStore
	LoadManifest(dictionaryName string) (IndexManifest, error)
	SaveManifest(manifest IndexManifest) error
	DeleteDictionary(dictionaryName string) error
}

// IndexSyncConfig controls external-index lifecycle behavior.
type IndexSyncConfig struct {
	ReuseIfUnchanged bool
	MissingSourceTTL time.Duration
	ForceRebuild     bool
	Fingerprinter    Fingerprinter
	Now              func() time.Time
	SchemaVersion    string
}

// IndexSyncOption customizes IndexSyncConfig.
type IndexSyncOption func(*IndexSyncConfig)

// EnsureIndexResult reports whether EnsureDictionaryIndex reused or rebuilt an index.
type EnsureIndexResult struct {
	DictionaryName string        `json:"dictionary_name"`
	Reused         bool          `json:"reused"`
	Rebuilt        bool          `json:"rebuilt"`
	Manifest       IndexManifest `json:"manifest"`
}

// DefaultIndexSyncConfig returns the default lifecycle configuration.
func DefaultIndexSyncConfig() IndexSyncConfig {
	return IndexSyncConfig{
		ReuseIfUnchanged: true,
		MissingSourceTTL: 0,
		ForceRebuild:     false,
		Fingerprinter:    NewFileStatFingerprinter(),
		Now:              time.Now,
		SchemaVersion:    defaultIndexSchemaVersion,
	}
}

// ResolveIndexSyncConfig applies options onto the default configuration.
func ResolveIndexSyncConfig(opts ...IndexSyncOption) IndexSyncConfig {
	cfg := DefaultIndexSyncConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = defaultIndexSchemaVersion
	}
	if cfg.Fingerprinter == nil {
		cfg.Fingerprinter = NewFileStatFingerprinter()
	}
	return cfg
}

// WithReuseIfUnchanged toggles manifest fingerprint reuse.
func WithReuseIfUnchanged(enabled bool) IndexSyncOption {
	return func(cfg *IndexSyncConfig) {
		cfg.ReuseIfUnchanged = enabled
	}
}

// WithMissingSourceTTL sets how long an index may be reused after its source disappears.
func WithMissingSourceTTL(ttl time.Duration) IndexSyncOption {
	return func(cfg *IndexSyncConfig) {
		cfg.MissingSourceTTL = ttl
	}
}

// WithForceRebuild forces index regeneration even when a manifest matches.
func WithForceRebuild() IndexSyncOption {
	return func(cfg *IndexSyncConfig) {
		cfg.ForceRebuild = true
	}
}

// WithFingerprinter overrides the source fingerprint implementation.
func WithFingerprinter(fp Fingerprinter) IndexSyncOption {
	return func(cfg *IndexSyncConfig) {
		cfg.Fingerprinter = fp
	}
}

// WithSchemaVersion overrides the lifecycle schema version.
func WithSchemaVersion(version string) IndexSyncOption {
	return func(cfg *IndexSyncConfig) {
		if version != "" {
			cfg.SchemaVersion = version
		}
	}
}

// WithClock overrides the clock used for lifecycle calculations.
func WithClock(now func() time.Time) IndexSyncOption {
	return func(cfg *IndexSyncConfig) {
		if now != nil {
			cfg.Now = now
		}
	}
}

type externalIndexDictionary interface {
	Name() string
	PrepareForExternalIndex() error
	DictionaryInfo() DictionaryInfo
	ExportIndex() ([]IndexEntry, error)
}

// BuildIndexManifest builds a lifecycle manifest for the supplied dictionary source.
func BuildIndexManifest(dictPath string, dictName string, opts ...IndexSyncOption) (IndexManifest, error) {
	cfg := ResolveIndexSyncConfig(opts...)
	if strings.TrimSpace(dictPath) == "" {
		return IndexManifest{}, errors.New("dictionary path is required")
	}
	if strings.TrimSpace(dictName) == "" {
		dictName = dictionaryNameFromPath(dictPath)
	}
	fingerprint, err := cfg.Fingerprinter.Fingerprint(dictPath)
	if err != nil {
		return IndexManifest{}, err
	}
	return buildManifest(cfg, dictName, dictPath, fingerprint, nil), nil
}

// EnsureDictionaryIndex ensures the external index for a dictionary is present and reusable.
func EnsureDictionaryIndex(dictPath string, store ManagedIndexStore, opts ...IndexSyncOption) (*EnsureIndexResult, error) {
	cfg := ResolveIndexSyncConfig(opts...)
	return ensureDictionaryIndexWithDeps(dictPath, store, cfg, openDictionaryForExternalIndex)
}

func ensureDictionaryIndexWithDeps(dictPath string, store ManagedIndexStore, cfg IndexSyncConfig, open func(string) (externalIndexDictionary, error)) (*EnsureIndexResult, error) {
	dictPath = strings.TrimSpace(dictPath)
	if dictPath == "" {
		return nil, errors.New("dictionary path is required")
	}
	if store == nil {
		return nil, errors.New("managed index store is required")
	}
	if open == nil {
		return nil, errors.New("dictionary opener is required")
	}

	unlock := lockIndexSync(dictPath)
	defer unlock()

	dictName := dictionaryNameFromPath(dictPath)
	manifest, manifestErr := store.LoadManifest(dictName)
	if manifestErr != nil && !errors.Is(manifestErr, ErrIndexMiss) {
		return nil, manifestErr
	}

	info, statErr := os.Stat(dictPath)
	if statErr != nil {
		if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		return ensureMissingSourceIndex(dictName, store, cfg, manifest, manifestErr)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("dictionary path %q is a directory", dictPath)
	}

	fingerprint, err := cfg.Fingerprinter.Fingerprint(dictPath)
	if err != nil {
		return nil, err
	}

	if manifestErr == nil && shouldReuseManifest(manifest, dictPath, fingerprint, cfg) {
		if manifest.ExpiresAt != nil {
			manifest.ExpiresAt = nil
			if err := store.SaveManifest(manifest); err != nil {
				return nil, err
			}
		}
		return &EnsureIndexResult{
			DictionaryName: dictName,
			Reused:         true,
			Manifest:       manifest,
		}, nil
	}

	dict, err := open(dictPath)
	if err != nil {
		return nil, err
	}
	if err := dict.PrepareForExternalIndex(); err != nil {
		return nil, err
	}
	entries, err := dict.ExportIndex()
	if err != nil {
		return nil, err
	}
	infoToStore := dict.DictionaryInfo()
	if err := store.Put(infoToStore, entries); err != nil {
		return nil, err
	}

	manifest = buildManifest(cfg, dict.Name(), dictPath, fingerprint, nil)
	if err := store.SaveManifest(manifest); err != nil {
		return nil, err
	}
	return &EnsureIndexResult{
		DictionaryName: manifest.DictionaryName,
		Rebuilt:        true,
		Manifest:       manifest,
	}, nil
}

func lockIndexSync(dictPath string) func() {
	key := indexSyncLockKey(dictPath)
	value, _ := indexSyncLocks.LoadOrStore(key, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func indexSyncLockKey(dictPath string) string {
	absPath, err := filepath.Abs(dictPath)
	if err != nil {
		return dictPath
	}
	return absPath
}

func ensureMissingSourceIndex(dictName string, store ManagedIndexStore, cfg IndexSyncConfig, manifest IndexManifest, manifestErr error) (*EnsureIndexResult, error) {
	if manifestErr != nil {
		return nil, os.ErrNotExist
	}
	if cfg.MissingSourceTTL <= 0 {
		if err := store.DeleteDictionary(dictName); err != nil {
			return nil, err
		}
		return nil, os.ErrNotExist
	}

	now := cfg.Now().UTC()
	if manifest.ExpiresAt == nil {
		expiresAt := now.Add(cfg.MissingSourceTTL)
		manifest.ExpiresAt = &expiresAt
		if err := store.SaveManifest(manifest); err != nil {
			return nil, err
		}
	}
	if manifest.ExpiresAt != nil && now.After(*manifest.ExpiresAt) {
		if err := store.DeleteDictionary(dictName); err != nil {
			return nil, err
		}
		return nil, os.ErrNotExist
	}
	return &EnsureIndexResult{
		DictionaryName: dictName,
		Reused:         true,
		Manifest:       manifest,
	}, nil
}

func shouldReuseManifest(manifest IndexManifest, dictPath, fingerprint string, cfg IndexSyncConfig) bool {
	if cfg.ForceRebuild || !cfg.ReuseIfUnchanged {
		return false
	}
	if manifest.DictionaryName == "" || manifest.Fingerprint == "" {
		return false
	}
	if manifest.Fingerprint != fingerprint {
		return false
	}
	if manifest.SchemaVersion != cfg.SchemaVersion {
		return false
	}
	if manifest.SourcePath == "" {
		return true
	}
	manifestAbs, manifestErr := filepath.Abs(manifest.SourcePath)
	if manifestErr != nil {
		manifestAbs = manifest.SourcePath
	}
	dictAbs, dictErr := filepath.Abs(dictPath)
	if dictErr != nil {
		dictAbs = dictPath
	}
	return manifestAbs == dictAbs
}

func buildManifest(cfg IndexSyncConfig, dictName, dictPath, fingerprint string, expiresAt *time.Time) IndexManifest {
	absPath, err := filepath.Abs(dictPath)
	if err != nil {
		absPath = dictPath
	}
	return IndexManifest{
		DictionaryName: dictName,
		SourcePath:     absPath,
		Fingerprint:    fingerprint,
		SchemaVersion:  cfg.SchemaVersion,
		BuiltAt:        cfg.Now().UTC(),
		ExpiresAt:      expiresAt,
	}
}

func dictionaryNameFromPath(dictPath string) string {
	_, raw := filepath.Split(dictPath)
	raw = strings.TrimSuffix(raw, filepath.Ext(raw))
	return strings.TrimSpace(raw)
}

func openDictionaryForExternalIndex(path string) (externalIndexDictionary, error) {
	return New(path)
}
