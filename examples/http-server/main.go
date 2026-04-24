package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	mdx "github.com/lib-x/mdx"
)

func main() {
	mdxPath := flag.String("mdx", "", "path to dictionary .mdx")
	mddPath := flag.String("mdd", "", "path to resource .mdd")
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

	mux := http.NewServeMux()
	assetPrefix := strings.TrimRight(*assetBase, "/")
	if assetPrefix == "" {
		assetPrefix = "/assets"
	}
	mux.Handle(assetPrefix+"/", http.StripPrefix(assetPrefix+"/", mdx.NewAssetHandler(mddDict)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `<html><body>
<form action="/entry" method="get">
  <input type="text" name="word" placeholder="enter word" />
  <button type="submit">Lookup</button>
</form>
</body></html>`)
	})

	mux.HandleFunc("/entry", func(w http.ResponseWriter, r *http.Request) {
		word := strings.TrimSpace(r.URL.Query().Get("word"))
		if word == "" {
			http.Error(w, "missing word", http.StatusBadRequest)
			return
		}

		content, err := mdx.LookupAndRewriteHTMLWithEntryBase(mdxDict, word, assetPrefix, "/entry?word=")
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(content)
	})

	log.Printf("serving entry UI on %s", *listen)
	log.Printf("assets served under %s/", assetPrefix)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
