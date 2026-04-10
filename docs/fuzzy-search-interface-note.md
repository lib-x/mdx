# Fuzzy Search Interface Note

## Goal
Add fuzzy-search support without coupling parser internals to any specific search engine or ranking strategy.

## Current boundary
The repo already has the right low-level split:
- `ExportEntries()` exports searchable MDX entries.
- `ExportResources()` exports MDD resource entries.
- `Resolve(IndexEntry)` turns an external search hit back into real dictionary content.
- `IndexStore` handles exact/prefix retrieval outside the parser.

This means fuzzy search should be layered on top of exported index data, not embedded inside `Mdict` parsing code.

## Recommended public interfaces

```go
type SearchHit struct {
    Entry IndexEntry
    Score float64
    Source string // e.g. "redis", "sqlite-fts", "meilisearch"
}

type FuzzyIndexStore interface {
    Put(info DictionaryInfo, entries []IndexEntry) error
    FuzzySearch(dictionaryName, query string, limit int) ([]SearchHit, error)
}
```

Optional future helper:

```go
type SearchOptions struct {
    Limit int
    Prefix bool
    Fuzzy bool
}
```

## Ranking responsibility
Ranking should live in the external search layer, not in the parser package.

Why:
- ranking logic differs across Redis, SQLite FTS, PostgreSQL trigram, Elasticsearch, Meilisearch, etc.
- parser code should remain responsible for file parsing and content resolution only.
- external stores are better suited for scoring, typo tolerance, tokenization, and language-specific search behavior.

So the parser package should only define hit/result shapes and leave score generation to the store implementation.

## Integration model
Recommended flow:
1. `ExportEntries()` from MDX.
2. Store the exported entries in an external fuzzy-capable system.
3. Query via `FuzzyIndexStore.FuzzySearch(...)`.
4. Pick a `SearchHit.Entry`.
5. Call `Resolve(hit.Entry)` to get the final MDX content.

This preserves one clean boundary:
- search system finds candidates
- parser resolves the exact content bytes

## Staged rollout

### Stage 1
Keep existing `IndexStore` for exact/prefix.
Add only the `SearchHit` + `FuzzyIndexStore` interfaces.

### Stage 2
Provide one reference implementation using an external engine that already supports fuzzy ranking well.
Prefer SQLite FTS / PostgreSQL trigram / Meilisearch over hand-rolled parser-side fuzzy logic.

### Stage 3
Add optional HTTP helpers for returning `[]SearchHit` and resolving a chosen hit.

## Non-goal
Do not add fuzzy ranking directly to `Mdict.Lookup()`.
`Lookup()` should remain exact-match and deterministic.
