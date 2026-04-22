package mdx

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	resourceAttrPattern   = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+)["']`)
	resourceAssignPattern = regexp.MustCompile(`(?i)\b(src|href)\s*=\s*(["'])([^"']+)(["'])`)
	resourceTokenPattern  = regexp.MustCompile(`(?i)\b(?:snd|img|css|js)://[^\s"'<>]+`)
)

// DictionaryInfo describes dictionary metadata suitable for external indexing.
type DictionaryInfo struct {
	Name                     string `json:"name"`
	Title                    string `json:"title"`
	Description              string `json:"description"`
	CreationDate             string `json:"creation_date"`
	GeneratedByEngineVersion string `json:"generated_by_engine_version"`
	Version                  string `json:"version"`
	IsMDD                    bool   `json:"is_mdd"`
	IsUTF16                  bool   `json:"is_utf16"`
	IsRecordEncrypted        bool   `json:"is_record_encrypted"`
	EntryCount               int64  `json:"entry_count"`
}

// IndexEntry is the external-storage-friendly representation of a dictionary entry.
type IndexEntry struct {
	Keyword           string `json:"keyword"`
	NormalizedKeyword string `json:"normalized_keyword,omitempty"`
	RecordStartOffset int64  `json:"record_start_offset"`
	RecordEndOffset   int64  `json:"record_end_offset"`
	KeyBlockIdx       int64  `json:"key_block_idx"`
	IsResource        bool   `json:"is_resource"`
}

// DictionaryInfo returns exported metadata for the current dictionary.
func (mdict *Mdict) DictionaryInfo() DictionaryInfo {
	entryCount := int64(0)
	if mdict.keyBlockData != nil {
		entryCount = mdict.keyBlockData.keyEntriesSize
	}

	return DictionaryInfo{
		Name:                     mdict.Name(),
		Title:                    mdict.Title(),
		Description:              mdict.Description(),
		CreationDate:             mdict.CreationDate(),
		GeneratedByEngineVersion: mdict.GeneratedByEngineVersion(),
		Version:                  mdict.Version(),
		IsMDD:                    mdict.IsMDD(),
		IsUTF16:                  mdict.IsUTF16(),
		IsRecordEncrypted:        mdict.IsRecordEncrypted(),
		EntryCount:               entryCount,
	}
}

// ExportIndex exports the in-memory dictionary index into storage-friendly entries.
func (mdict *Mdict) ExportIndex() ([]IndexEntry, error) {
	entries, err := mdict.GetKeyWordEntries()
	if err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, errors.New("dictionary index is not built")
	}

	exported := make([]IndexEntry, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}

		item := IndexEntry{
			Keyword:           entry.KeyWord,
			RecordStartOffset: entry.RecordStartOffset,
			RecordEndOffset:   entry.RecordEndOffset,
			KeyBlockIdx:       entry.KeyBlockIdx,
			IsResource:        mdict.IsMDD(),
		}
		if item.IsResource {
			item.NormalizedKeyword = NormalizeMDDKey(entry.KeyWord)
		}

		exported = append(exported, item)
	}

	return exported, nil
}

// ExportEntries exports only MDX-style text entries.
func (mdict *Mdict) ExportEntries() ([]IndexEntry, error) {
	entries, err := mdict.ExportIndex()
	if err != nil {
		return nil, err
	}
	if mdict.IsMDD() {
		return []IndexEntry{}, nil
	}
	return entries, nil
}

// ExportResources exports only MDD-style resource entries.
func (mdict *Mdict) ExportResources() ([]IndexEntry, error) {
	entries, err := mdict.ExportIndex()
	if err != nil {
		return nil, err
	}
	if !mdict.IsMDD() {
		return []IndexEntry{}, nil
	}
	return entries, nil
}

// Resolve resolves previously exported index data back into dictionary content.
func (mdict *Mdict) Resolve(entry IndexEntry) ([]byte, error) {
	keyword := entry.Keyword
	if mdict.IsMDD() && keyword == "" {
		keyword = entry.NormalizedKeyword
	}

	return mdict.LocateByKeywordEntry(&MDictKeywordEntry{
		KeyWord:           keyword,
		RecordStartOffset: entry.RecordStartOffset,
		RecordEndOffset:   entry.RecordEndOffset,
		KeyBlockIdx:       entry.KeyBlockIdx,
	})
}

// NormalizeMDDKey normalizes MDD resource names to the dictionary-internal key format.
func NormalizeMDDKey(name string) string {
	normalized := strings.TrimSpace(name)
	normalized = strings.ReplaceAll(normalized, "/", `\`)
	if normalized == "" {
		return `\`
	}
	if !strings.HasPrefix(normalized, `\`) {
		normalized = `\` + normalized
	}
	return normalized
}

// IsResourceRef reports whether the reference looks like an external asset instead of an internal entry link.
func IsResourceRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}

	lower := strings.ToLower(ref)
	switch {
	case strings.HasPrefix(lower, "snd://"),
		strings.HasPrefix(lower, "sound://"),
		strings.HasPrefix(lower, "file://"),
		strings.HasPrefix(lower, "img://"),
		strings.HasPrefix(lower, "css://"),
		strings.HasPrefix(lower, "js://"):
		return true
	case strings.HasPrefix(lower, "http://"),
		strings.HasPrefix(lower, "https://"),
		strings.HasPrefix(lower, "data:"),
		strings.HasPrefix(lower, "mailto:"),
		strings.HasPrefix(lower, "help:"),
		strings.HasPrefix(lower, "entry:"),
		strings.HasPrefix(lower, "mdxentry:"),
		strings.HasPrefix(lower, "dict:"),
		strings.HasPrefix(lower, "d:"),
		strings.HasPrefix(lower, "x:"),
		strings.HasPrefix(lower, "#"):
		return false
	}

	switch strings.ToLower(path.Ext(lower)) {
	case ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".spx", ".snd", ".mp3", ".wav", ".ogg", ".mp4":
		return true
	default:
		return false
	}
}

// ExtractResourceRefs extracts resource-like references from MDX entry content.
func ExtractResourceRefs(content []byte) []string {
	text := string(content)
	seen := make(map[string]struct{})
	refs := make([]string, 0)

	appendRef := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return
		}
		if !IsResourceRef(ref) {
			return
		}
		if _, ok := seen[ref]; ok {
			return
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}

	for _, match := range resourceAttrPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 2 {
			continue
		}
		appendRef(match[1])
	}

	for _, token := range resourceTokenPattern.FindAllString(text, -1) {
		appendRef(token)
	}

	return refs
}

// AssetURL returns a browser-safe URL for a raw asset reference.
func AssetURL(basePath, ref string) string {
	basePath = strings.TrimRight(basePath, "/")
	if basePath == "" {
		basePath = "/"
	}
	return basePath + "/" + url.PathEscape(strings.TrimSpace(ref))
}

// RewriteEntryResourceURLs rewrites asset references inside MDX HTML into browser-servable URLs.
func RewriteEntryResourceURLs(content []byte, assetBasePath string) []byte {
	rewritten := resourceAssignPattern.ReplaceAllStringFunc(string(content), func(match string) string {
		parts := resourceAssignPattern.FindStringSubmatch(match)
		if len(parts) != 5 {
			return match
		}
		ref := parts[3]
		if !IsResourceRef(ref) {
			return match
		}
		return parts[1] + "=" + parts[2] + AssetURL(assetBasePath, ref) + parts[4]
	})

	return []byte(rewritten)
}

// AssetLookupCandidates expands a raw asset reference into possible storage lookup candidates.
func AssetLookupCandidates(ref string) []string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}

	candidates := []string{ref}
	if idx := strings.Index(ref, "://"); idx > 0 && idx+3 < len(ref) {
		candidates = append(candidates, ref[idx+3:])
	}
	if strings.HasPrefix(strings.ToLower(ref), "sound://") {
		candidates = append(candidates, "snd://"+ref[len("sound://"):])
	}
	if strings.HasPrefix(strings.ToLower(ref), "file://") {
		candidates = append(candidates, ref[len("file://"):])
	}

	expanded := make([]string, 0, len(candidates)*4)
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		expanded = append(expanded, trimmed)

		normalized := strings.TrimPrefix(trimmed, "/")
		if normalized != trimmed {
			expanded = append(expanded, normalized)
		}

		mddKey := NormalizeMDDKey(trimmed)
		expanded = append(expanded, mddKey)

		withoutExt := strings.TrimSuffix(normalized, path.Ext(normalized))
		if withoutExt != "" && withoutExt != normalized {
			expanded = append(expanded, withoutExt)
			expanded = append(expanded, NormalizeMDDKey(withoutExt))
		}
	}

	seen := make(map[string]struct{}, len(expanded))
	deduped := make([]string, 0, len(expanded))
	for _, candidate := range expanded {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		deduped = append(deduped, candidate)
	}

	return deduped
}

func parseLinkTarget(content []byte) (string, bool) {
	text := strings.TrimSpace(string(content))
	if !strings.HasPrefix(text, "@@LINK=") {
		return "", false
	}
	target := strings.TrimSpace(strings.TrimPrefix(text, "@@LINK="))
	if target == "" {
		return "", false
	}
	return target, true
}
