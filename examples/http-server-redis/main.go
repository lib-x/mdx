package main

import (
	"context"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"

	mdx "mdx"

	"github.com/redis/go-redis/v9"
)

func main() {
	mdxPath := flag.String("mdx", "", "path to dictionary .mdx")
	mddPath := flag.String("mdd", "", "path to resource .mdd")
	redisAddr := flag.String("redis", "127.0.0.1:6379", "redis address")
	listen := flag.String("listen", ":8080", "http listen address")
	assetBase := flag.String("asset-base", "/assets", "asset base path")
	flag.Parse()

	if *mdxPath == "" || *mddPath == "" {
		log.Fatal("both --mdx and --mdd are required")
	}

	mdxDict, err := mdx.New(*mdxPath)
	if err != nil {
		log.Fatalf("load mdx: %v", err)
	}
	if err := mdxDict.BuildIndex(); err != nil {
		log.Fatalf("build mdx index: %v", err)
	}

	mddDict, err := mdx.New(*mddPath)
	if err != nil {
		log.Fatalf("load mdd: %v", err)
	}
	if err := mddDict.BuildIndex(); err != nil {
		log.Fatalf("build mdd index: %v", err)
	}

	client := redis.NewClient(&redis.Options{Addr: *redisAddr})
	defer client.Close()
	store := mdx.NewRedisIndexStoreWithContext(context.Background(), client)

	info := mdxDict.DictionaryInfo()
	entries, err := mdxDict.ExportEntries()
	if err != nil {
		log.Fatalf("export entries: %v", err)
	}
	if err := store.Put(info, entries); err != nil {
		log.Fatalf("put redis index: %v", err)
	}

	mux := http.NewServeMux()
	assetPrefix := strings.TrimRight(*assetBase, "/")
	if assetPrefix == "" {
		assetPrefix = "/assets"
	}
	mux.Handle(assetPrefix+"/", http.StripPrefix(assetPrefix+"/", mdx.NewAssetHandler(mddDict)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><body>
<h1>%s</h1>
<form action="/search" method="get">
  <input type="text" name="prefix" placeholder="search prefix" />
  <button type="submit">Search</button>
</form>
<form action="/entry" method="get" style="margin-top:1rem;">
  <input type="text" name="word" placeholder="exact word" />
  <button type="submit">Lookup</button>
</form>
</body></html>`, html.EscapeString(info.Title))
	})

	mux.HandleFunc("/entry", func(w http.ResponseWriter, r *http.Request) {
		word := strings.TrimSpace(r.URL.Query().Get("word"))
		if word == "" {
			http.Error(w, "missing word", http.StatusBadRequest)
			return
		}

		entry, err := store.GetExact(info.Name, word)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		content, err := mdxDict.Resolve(entry)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rewritten := mdx.RewriteEntryResourceURLs(content, assetPrefix)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(rewritten)
	})

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		prefix := strings.TrimSpace(r.URL.Query().Get("prefix"))
		matches, err := store.PrefixSearch(info.Name, prefix, 20)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<html><body><h1>Search: %s</h1><ul>", html.EscapeString(prefix))
		for _, match := range matches {
			_, _ = fmt.Fprintf(w, `<li><a href="/entry?word=%s">%s</a></li>`, url.QueryEscape(match.Keyword), html.EscapeString(match.Keyword))
		}
		_, _ = fmt.Fprint(w, `</ul><p><a href="/">Back</a></p></body></html>`)
	})

	log.Printf("serving redis-backed entry UI on %s", *listen)
	log.Printf("assets served under %s/", assetPrefix)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
