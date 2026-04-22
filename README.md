# MDX/MDD Parser for Go
[CN](README_ZH.md)
This is a high-performance MDict (.mdx/.mdd) file parsing library written in Go. It supports querying dictionary content, retrieving dictionary metadata, and provides a file system wrapper compliant with the `io/fs.FS` interface, making it easy to integrate with other Go ecosystem libraries (such as HTTP servers).

This library was originally based on the [terasum/medict](https://github.com/terasum/medict) project and has undergone extensive bug fixes, performance optimizations, and code refactoring.

## Features

- **High-Performance Queries**: Builds an in-memory exact-match index after `BuildIndex()` for stable fast lookups.
- **MDX/MDD Support**: Supports both .mdx (text dictionaries) and .mdd (resource files) formats.
- **Standard Interface**: Implements the `io/fs.FS` interface, allowing dictionaries to be easily served as a file system.
- **Robust Error Handling**: Comprehensive error handling and logging.
- **Complete Metadata**: Provides an API to access all dictionary metadata (such as title, description, creation date, etc.).

## Installation

```bash
go get github.com/lib-x/mdx
```
*(Note: Please replace `github.com/lib-x/mdx` with the actual repository path)*

## Usage Examples

### Example 1: Querying an MDX Dictionary

Here is a simple example of how to load an MDX dictionary and query a word.

```go
package main

import (
	"fmt"
	"log"

	"github.com/lib-x/mdx" // Assuming this is the module path
)

func main() {
	// 1. Create a new Mdict instance
	// Replace "path/to/your/dictionary.mdx" with your MDX file path
	mdict, err := mdx.New("path/to/your/dictionary.mdx")
	if err != nil {
		log.Fatalf("Failed to load dictionary file: %v", err)
	}

	// 2. Build the index (recommended to be done once at program startup)
	err = mdict.BuildIndex()
	if err != nil {
		log.Fatalf("Failed to build dictionary index: %v", err)
	}

	// 3. Print dictionary information
	fmt.Printf("Dictionary Title: %s\n", mdict.Title())
	fmt.Printf("Dictionary Description: %s\n", mdict.Description())

	// 4. Query a word
	word := "hello"
	definition, err := mdict.Lookup(word)
	if err != nil {
		log.Fatalf("Failed to look up word '%s': %v", word, err)
	}

	fmt.Printf("Definition of '%s':\n%s\n", word, string(definition))

	// 5. Query a non-existent word
	word = "nonexistentword"
	_, err = mdict.Lookup(word)
	if err != nil {
		fmt.Printf("As expected, an error occurred when querying a non-existent word '%s': %v\n", word, err)
	}
}
```

### Example 1.1: Exporting an External Index

If you want to store the index in Redis, SQL, or another external system, export the index entries and store them yourself. Later, load one entry back and resolve it to the real definition.

```go
package main

import (
	"fmt"
	"log"

	"github.com/lib-x/mdx"
)

func main() {
	dict, err := mdx.New("path/to/your/dictionary.mdx")
	if err != nil {
		log.Fatal(err)
	}
	if err := dict.BuildIndex(); err != nil {
		log.Fatal(err)
	}

	info := dict.DictionaryInfo()
	fmt.Printf("title=%s entries=%d\n", info.Title, info.EntryCount)

	entries, err := dict.ExportIndex()
	if err != nil {
		log.Fatal(err)
	}

	// Store entries in Redis / DB here.
	first := entries[0]

	content, err := dict.Resolve(first)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("resolved %q -> %d bytes\n", first.Keyword, len(content))
}
```

### Example 1.2: Explicitly Splitting Dictionary Entries and Resource Entries

```go
mdxDict, _ := mdx.New("path/to/dictionary.mdx")
_ = mdxDict.BuildIndex()
entries, _ := mdxDict.ExportEntries()

mddDict, _ := mdx.New("path/to/dictionary.mdd")
_ = mddDict.BuildIndex()
resources, _ := mddDict.ExportResources()

fmt.Println(len(entries), len(resources))
```

### Example 1.3: Storing the Exported Index in an External Store

The library now exposes a minimal `IndexStore` boundary. You can implement it for Redis, SQL, or another backend. A small in-memory example is included:

```go
store := mdx.NewMemoryIndexStore()

info := dict.DictionaryInfo()
entries, _ := dict.ExportEntries()
_ = store.Put(info, entries)

entry, _ := store.GetExact(info.Name, "ability")
content, _ := dict.Resolve(entry)
fmt.Println(len(content))
```

### Example 2: Listing MDD Resource Files

MDD files typically contain resources like audio and images. The following example shows how to list all resources in an MDD file.

```go
package main

import (
	"fmt"
	"log"

	"github.com/lib-x/mdx" // Assuming this is the module path
)

func main() {
	// 1. Load the MDD file
	// Replace "path/to/your/resource.mdd" with your MDD file path
	mdd, err := mdx.New("path/to/your/resource.mdd")
	if err != nil {
		log.Fatalf("Failed to load MDD file: %v", err)
	}

	// 2. Build the index
	err = mdd.BuildIndex()
	if err != nil {
		log.Fatalf("Failed to build MDD index: %v", err)
	}

	// 3. Get and print all keyword entries (in MDD, this is usually the file path)
	entries, err := mdd.GetKeyWordEntries()
	if err != nil {
		log.Fatalf("Failed to get keyword entries: %v", err)
	}

	fmt.Printf("Found %d resource files in '%s':\n", len(entries), mdd.Name())
	for i, entry := range entries {
		// Print only the first 10 as an example
		if i >= 10 {
			break
		}
		fmt.Println(entry.KeyWord) // The KeyWord field stores the resource file path
	}
}
```

### Example 3: Extracting Resource References from MDX Content

MDX entries often contain references to CSS, JavaScript, image, and audio resources that are actually stored in the companion MDD file.

```go
definition, err := mdict.Lookup("accordion")
if err != nil {
	log.Fatal(err)
}

refs := mdx.ExtractResourceRefs(definition)
for _, ref := range refs {
	fmt.Println(ref)
}

fmt.Println(mdx.NormalizeMDDKey("accordion_concertina.jpg"))
// Output: \accordion_concertina.jpg
```

### Example 4: Serving MDX HTML and MDD Assets over Go HTTP

```go
package main

import (
	"log"
	"net/http"

	"github.com/lib-x/mdx"
)

func main() {
	mdxDict, err := mdx.New("path/to/dictionary.mdx")
	if err != nil {
		log.Fatal(err)
	}
	if err := mdxDict.BuildIndex(); err != nil {
		log.Fatal(err)
	}

	mddDict, err := mdx.New("path/to/dictionary.mdd")
	if err != nil {
		log.Fatal(err)
	}
	if err := mddDict.BuildIndex(); err != nil {
		log.Fatal(err)
	}

	http.Handle("/assets/", http.StripPrefix("/assets/", mdx.NewAssetHandler(mddDict)))

	http.HandleFunc("/entry", func(w http.ResponseWriter, r *http.Request) {
		word := r.URL.Query().Get("word")
		content, err := mdx.LookupAndRewriteHTMLWithEntryBase(mdxDict, word, "/assets", "/entry?word=")
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(content)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

`LookupAndRewriteHTML` rewrites resource references such as:
- `oalecd9.css` -> `/assets/oalecd9.css`
- `thumb_accordion.jpg` -> `/assets/thumb_accordion.jpg`
- `snd://ability__gb_1.spx` -> `/assets/snd:%2F%2Fability__gb_1.spx`

`LookupAndRewriteHTMLWithEntryBase` additionally rewrites internal `entry://word` links into browser-servable lookup URLs such as `/entry?word=word`, normalizes malformed `entry://entry://...` links, and upgrades anchor-based `sound://` / `snd://` audio links into `<audio controls ...>` output.

`NewAssetHandler` now serves resolver-backed assets through `http.ServeContent`, which means browsers can make `Range` requests against large image/audio assets.

For callers that need explicit HTTP cache semantics, `NewAssetHandlerWithOptions` can customize `Cache-Control` and enable `ETag` / `Last-Modified` headers. Conditional requests using `If-None-Match` and `If-Modified-Since` are also supported through the same ServeContent-based path.

Note on audio playback: this library can resolve and serve raw audio resources from MDX/MDD files (including real `sound://...` / `snd://...` references), but browser playback still depends on whether the client can decode the underlying audio format. In particular, `.spx` (Speex) assets usually require transcoding or an application-level playback backend outside this core library.

A runnable demo is available at `examples/http-server`:

```bash
go run ./examples/http-server \
  --mdx /path/to/dictionary.mdx \
  --mdd /path/to/dictionary.mdd \
  --listen :8080
```

A Redis-backed variant is also available:

```bash
go run ./examples/http-server-redis \
  --mdx /path/to/dictionary.mdx \
  --mdd /path/to/dictionary.mdd \
  --redis 127.0.0.1:6379 \
  --listen :8080
```

## Contributing

Issues and Pull Requests are welcome.


## Local fixture tests

Real `.mdx` / `.mdd` fixtures are **not** stored in this repository.

Set `MDX_TESTDICT_DIR` to a local directory containing the external fixture pair, for example:

```bash
MDX_TESTDICT_DIR="/path/to/local/dictionary-dir" go test ./... -run "TestIntegration|TestMdict|TestMdictFS" -v
```

Without local fixtures, external integration tests will skip automatically.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

## Fuzzy Search

A first in-memory fuzzy reference implementation is now available as `MemoryFuzzyIndexStore`. It is suitable for tests and demos, while production fuzzy search should still live in an external store/service.

## Dictionary Library

A multi-dictionary registry is available for directories containing many `.mdx` / `.mdd` pairs.
The registry now auto-discovers companion resource chains such as `demo.mdd`, `demo.1.mdd`, `demo.2.mdd`, and composes resolver-backed sidecar-first resource lookup by default.

Core APIs:
- `ScanDirectory(root string)`
- `DictionaryRegistry`
- `OpenDictionary(id string)`
- `LibrarySearch(query, limit)`

Runnable example:

```bash
go run ./examples/http-library --root /path/to/dictionaries --listen :8080
```

Routes:
- `/dict/{id}/entry?word=...`
- `/dict/{id}/assets/...`
- `/library/search?q=...`
