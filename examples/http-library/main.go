package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"

	mdx "github.com/lib-x/mdx"
)

func main() {
	root := flag.String("root", "", "directory containing multiple .mdx/.mdd files")
	listen := flag.String("listen", ":8080", "http listen address")
	flag.Parse()

	if *root == "" {
		log.Fatal("--root is required")
	}

	registry := mdx.NewDictionaryRegistry()
	if err := registry.LoadDirectory(*root); err != nil {
		log.Fatalf("load directory: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		specs := registry.List()
		_, _ = fmt.Fprint(w, "<html><body><h1>Dictionaries</h1><ul>")
		for _, spec := range specs {
			_, _ = fmt.Fprintf(w, `<li><a href="/dict/%s/entry?word=ability">%s</a></li>`, url.PathEscape(spec.ID), html.EscapeString(spec.Name))
		}
		_, _ = fmt.Fprint(w, `</ul>
<form action="/library/search" method="get">
  <input type="text" name="q" placeholder="search all dictionaries" />
  <button type="submit">Search</button>
</form>
</body></html>`)
	})

	mux.HandleFunc("/dict/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/dict/")
		dictID, rest, found := strings.Cut(path, "/")
		if !found {
			http.NotFound(w, r)
			return
		}

		mdxDict, mddDict, err := registry.OpenDictionary(dictID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		switch {
		case strings.HasPrefix(rest, "entry"):
			word := strings.TrimSpace(r.URL.Query().Get("word"))
			if word == "" {
				http.Error(w, "missing word", http.StatusBadRequest)
				return
			}
			content, err := mdx.LookupAndRewriteHTML(mdxDict, word, "/dict/"+dictID+"/assets")
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(content)
		case strings.HasPrefix(rest, "assets/"):
			if mddDict == nil {
				http.Error(w, "dictionary has no mdd resources", http.StatusNotFound)
				return
			}
			handler := http.StripPrefix("/dict/"+dictID+"/assets/", mdx.NewAssetHandler(mddDict))
			handler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/library/search", func(w http.ResponseWriter, r *http.Request) {
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		if query == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}

		hits, err := registry.LibrarySearch(query, 20)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<html><body><h1>Library search: %s</h1><ul>", html.EscapeString(query))
		for _, hit := range hits {
			_, _ = fmt.Fprintf(
				w,
				`<li><a href="/dict/%s/entry?word=%s">%s</a> <small>(%s, score=%.2f, source=%s)</small></li>`,
				url.PathEscape(hit.DictID),
				url.QueryEscape(hit.Hit.Entry.Keyword),
				html.EscapeString(hit.Hit.Entry.Keyword),
				html.EscapeString(hit.DictName),
				hit.Hit.Score,
				html.EscapeString(hit.Hit.Source),
			)
		}
		_, _ = fmt.Fprint(w, `</ul><p><a href="/">Back</a></p></body></html>`)
	})

	log.Printf("serving dictionary library on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
