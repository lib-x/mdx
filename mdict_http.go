package mdx

import (
	"errors"
	"io"
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

	return RewriteEntryResourceURLs(content, assetBasePath), nil
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

		var lastErr error
		for _, candidate := range AssetLookupCandidates(raw) {
			file, err := NewMdictFS(mdd).Open(candidate)
			if err != nil {
				lastErr = err
				continue
			}

			data, err := io.ReadAll(file)
			_ = file.Close()
			if err != nil {
				lastErr = err
				continue
			}

			if contentType := http.DetectContentType(data); contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
			_, _ = w.Write(data)
			return
		}

		if lastErr != nil {
			http.Error(w, lastErr.Error(), http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	})
}
