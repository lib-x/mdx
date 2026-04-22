package mdx

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// LookupAndRewriteHTML looks up an MDX entry and rewrites its asset URLs for web delivery.
func LookupAndRewriteHTML(dict *Mdict, word, assetBasePath string) ([]byte, error) {
	if dict == nil {
		return nil, errors.New("mdict is nil")
	}

	content, err := dict.Lookup(word)
	if err != nil {
		return nil, err
	}

	rewritten := RewriteEntryResourceURLs(content, assetBasePath)
	rewritten = RewriteEntryInternalLinks(rewritten)
	rewritten = RewriteEntryAudioLinks(rewritten, assetBasePath)
	return rewritten, nil
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

		if contentType := http.DetectContentType(data); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write(data)
	})
}
