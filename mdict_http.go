package mdx

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// AssetHandlerOptions configures HTTP delivery behavior for resolver-backed assets.
type AssetHandlerOptions struct {
	CacheControl       string
	EnableETag         bool
	EnableLastModified bool
}

// LookupAndRewriteHTML looks up an MDX entry and rewrites its asset URLs for web delivery.
func LookupAndRewriteHTML(dict *Mdict, word, assetBasePath string) ([]byte, error) {
	return LookupAndRewriteHTMLWithEntryBase(dict, word, assetBasePath, "")
}

// LookupAndRewriteHTMLWithEntryBase looks up an MDX entry and rewrites its asset and entry URLs for web delivery.
func LookupAndRewriteHTMLWithEntryBase(dict *Mdict, word, assetBasePath, entryBasePath string) ([]byte, error) {
	if dict == nil {
		return nil, errors.New("mdict is nil")
	}

	content, err := dict.Lookup(word)
	if err != nil {
		return nil, err
	}

	return rewriteEntryHTML(content, assetBasePath, entryBasePath), nil
}

func rewriteEntryHTML(content []byte, assetBasePath, entryBasePath string) []byte {
	rewritten := RewriteEntryResourceURLs(content, assetBasePath)
	rewritten = RewriteEntryInternalLinks(rewritten)
	if strings.TrimSpace(entryBasePath) != "" {
		rewritten = RewriteEntryLookupLinks(rewritten, entryBasePath)
	}
	rewritten = RewriteEntryAudioLinks(rewritten, assetBasePath)
	return rewritten
}

// NewAssetHandler creates an HTTP handler that serves MDD-backed assets by raw reference name.
func NewAssetHandler(mdd *Mdict) http.Handler {
	return NewAssetHandlerWithOptions(mdd, AssetHandlerOptions{CacheControl: "public, max-age=3600"})
}

// NewAssetHandlerWithOptions creates an HTTP handler that serves MDD-backed assets with configurable HTTP semantics.
func NewAssetHandlerWithOptions(mdd *Mdict, opts AssetHandlerOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mdd == nil {
			http.Error(w, "mdd is nil", http.StatusInternalServerError)
			return
		}

		raw := strings.TrimPrefix(r.URL.Path, "/")
		if decoded, err := url.PathUnescape(raw); err == nil {
			raw = decoded
		}

		resolver := mdd.AssetResolver()
		if resolver == nil {
			http.NotFound(w, r)
			return
		}

		data, err := resolver.Read(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if opts.CacheControl != "" {
			w.Header().Set("Cache-Control", opts.CacheControl)
		}
		if contentType := http.DetectContentType(data); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}

		name := assetSidecarPath(raw)
		if name == "" {
			name = raw
		}

		modTime := time.Time{}
		if opts.EnableLastModified {
			modTime = assetHandlerModTime(mdd)
			if !modTime.IsZero() {
				w.Header().Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
			}
		}
		if opts.EnableETag {
			sum := sha1.Sum(data)
			w.Header().Set("ETag", fmt.Sprintf(`W/"%x"`, sum[:]))
		}

		http.ServeContent(w, r, name, modTime, bytes.NewReader(data))
	})
}

func assetHandlerModTime(mdd *Mdict) time.Time {
	if mdd == nil {
		return time.Time{}
	}
	if mdd.meta != nil && strings.TrimSpace(mdd.meta.creationDate) != "" {
		for _, layout := range []string{"2006-01-02", "2006.01.02 15:04:05"} {
			parsed, err := time.Parse(layout, mdd.meta.creationDate)
			if err == nil {
				return parsed
			}
		}
	}
	if mdd.filePath != "" {
		info, err := os.Stat(mdd.filePath)
		if err == nil {
			return info.ModTime()
		}
	}
	return time.Time{}
}
