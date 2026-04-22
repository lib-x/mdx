package mdx

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

		w.Header().Set("Cache-Control", "public, max-age=3600")
		if contentType := http.DetectContentType(data); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}

		name := assetSidecarPath(raw)
		if name == "" {
			name = raw
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
}
