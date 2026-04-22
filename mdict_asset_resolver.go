package mdx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf16"
)

// AssetSource provides raw dictionary asset bytes for a logical reference.
type AssetSource interface {
	ReadAsset(ref string) ([]byte, error)
}

// AssetResolver resolves dictionary assets from ordered sources and follows MDict-style redirects.
type AssetResolver struct {
	sources []AssetSource
}

// appendSource appends a concrete source to the resolver.
func (r *AssetResolver) appendSource(source AssetSource) {
	if r == nil || source == nil {
		return
	}
	r.sources = append(r.sources, source)
}

// AssetResolverOption configures an AssetResolver.
type AssetResolverOption func(*AssetResolver)

// WithAssetSource appends an ordered asset source to the resolver.
func WithAssetSource(source AssetSource) AssetResolverOption {
	return func(r *AssetResolver) {
		r.appendSource(source)
	}
}

// WithAssetMdicts appends ordered MDD-backed asset sources to the resolver.
func WithAssetMdicts(dicts ...*Mdict) AssetResolverOption {
	return func(r *AssetResolver) {
		for _, dict := range dicts {
			if dict == nil {
				continue
			}
			r.appendSource(mdictAssetSource{dict: dict})
		}
	}
}

// WithAssetSidecarFS appends a sidecar filesystem used as a fallback source for assets.
func WithAssetSidecarFS(fsys fs.FS) AssetResolverOption {
	if fsys == nil {
		return func(*AssetResolver) {}
	}
	return WithAssetSource(fsAssetSource{fsys: fsys})
}

// WithAssetSidecarDir appends an on-disk sidecar directory used as a fallback source for assets.
func WithAssetSidecarDir(dir string) AssetResolverOption {
	if dir == "" {
		return func(*AssetResolver) {}
	}
	return WithAssetSidecarFS(os.DirFS(dir))
}

// NewAssetResolver constructs an AssetResolver.
//
// Ordered options are evaluated first. When mdd is non-nil it is appended after
// those sources, preserving GoldenDict-style sidecar-first precedence by default.
func NewAssetResolver(mdd *Mdict, opts ...AssetResolverOption) *AssetResolver {
	resolver := &AssetResolver{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(resolver)
	}
	if mdd != nil {
		resolver.appendSource(mdictAssetSource{dict: mdd})
	}
	return resolver
}

// Open opens an asset by reference from the configured sources.
func (r *AssetResolver) Open(ref string) (fs.File, error) {
	data, err := r.Read(ref)
	if err != nil {
		return nil, err
	}
	return &assetBytesFile{
		reader: bytes.NewReader(data),
		info: assetBytesFileInfo{
			name:    path.Base(assetSidecarPath(ref)),
			size:    int64(len(data)),
			modTime: time.Now(),
		},
	}, nil
}

// Read reads a resolved asset fully into memory.
func (r *AssetResolver) Read(ref string) ([]byte, error) {
	return r.read(ref, map[string]struct{}{})
}

func (r *AssetResolver) read(ref string, seen map[string]struct{}) ([]byte, error) {
	if r == nil {
		return nil, fs.ErrNotExist
	}

	key := normalizeAssetResolverRef(ref)
	if key == "" {
		return nil, fs.ErrNotExist
	}
	if _, ok := seen[key]; ok {
		return nil, fs.ErrNotExist
	}
	seen[key] = struct{}{}

	for _, source := range r.sources {
		if source == nil {
			continue
		}
		data, err := source.ReadAsset(ref)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if redirect, ok := parseMDictResourceRedirect(data); ok {
			return r.read(redirect, seen)
		}
		return data, nil
	}

	return nil, fs.ErrNotExist
}

type fsAssetSource struct {
	fsys fs.FS
}

func (s fsAssetSource) ReadAsset(ref string) ([]byte, error) {
	if s.fsys == nil {
		return nil, fs.ErrNotExist
	}
	for _, candidate := range AssetLookupCandidates(ref) {
		name := assetSidecarPath(candidate)
		if name == "" {
			continue
		}
		file, err := s.fsys.Open(name)
		if err == nil {
			defer file.Close()
			return io.ReadAll(file)
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return nil, err
	}
	return nil, fs.ErrNotExist
}

type mdictAssetSource struct {
	dict *Mdict
}

func (s mdictAssetSource) ReadAsset(ref string) ([]byte, error) {
	if s.dict == nil {
		return nil, fs.ErrNotExist
	}
	return s.dict.readMDDResource(ref)
}

func assetSidecarPath(candidate string) string {
	cleaned := candidate
	if idx := len(cleaned); idx == 0 {
		return ""
	}
	cleaned = trimResourceScheme(cleaned)
	cleaned = trimLeadingResourceSeparators(cleaned)
	if cleaned == "" || cleaned == "." {
		return ""
	}
	return cleaned
}

func trimResourceScheme(value string) string {
	for _, prefix := range []string{"file://", "sound://", "snd://", "img://", "css://", "js://"} {
		if len(value) >= len(prefix) && equalFoldPrefix(value, prefix) {
			return value[len(prefix):]
		}
	}
	return value
}

func trimLeadingResourceSeparators(value string) string {
	for len(value) > 0 {
		if value[0] != '/' && value[0] != '\\' {
			break
		}
		value = value[1:]
	}
	return value
}

func equalFoldPrefix(value, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	return value[:len(prefix)] == prefix || lowerASCII(value[:len(prefix)]) == prefix
}

func lowerASCII(value string) string {
	buf := make([]byte, len(value))
	for i := range value {
		ch := value[i]
		if ch >= 'A' && ch <= 'Z' {
			ch = ch - 'A' + 'a'
		}
		buf[i] = ch
	}
	return string(buf)
}

func normalizeAssetResolverRef(ref string) string {
	cleaned := strings.TrimSpace(trimResourceScheme(ref))
	cleaned = trimLeadingResourceSeparators(cleaned)
	cleaned = strings.ReplaceAll(cleaned, "\\", "/")
	return strings.ToLower(cleaned)
}

func parseMDictResourceRedirect(data []byte) (string, bool) {
	utf16Prefix := []byte{'@', 0, '@', 0, '@', 0, 'L', 0, 'I', 0, 'N', 0, 'K', 0, '=', 0}
	if len(data) < len(utf16Prefix) || !equalBytes(data[:len(utf16Prefix)], utf16Prefix) {
		return "", false
	}
	payload := data[len(utf16Prefix):]
	if len(payload)%2 != 0 {
		payload = payload[:len(payload)-1]
	}
	if len(payload) == 0 {
		return "", false
	}
	units := make([]uint16, 0, len(payload)/2)
	for i := 0; i+1 < len(payload); i += 2 {
		u := binary.LittleEndian.Uint16(payload[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	if len(units) == 0 {
		return "", false
	}
	target := strings.TrimSpace(string(utf16.Decode(units)))
	if target == "" {
		return "", false
	}
	return target, true
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

type assetBytesFile struct {
	reader *bytes.Reader
	info   assetBytesFileInfo
}

func (f *assetBytesFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *assetBytesFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *assetBytesFile) Close() error               { return nil }

type assetBytesFileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (i assetBytesFileInfo) Name() string       { return i.name }
func (i assetBytesFileInfo) Size() int64        { return i.size }
func (i assetBytesFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i assetBytesFileInfo) ModTime() time.Time { return i.modTime }
func (i assetBytesFileInfo) IsDir() bool        { return false }
func (i assetBytesFileInfo) Sys() any           { return nil }
