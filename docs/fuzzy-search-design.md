# Fuzzy Search Design Notes

## Goal

Keep fuzzy search outside the parser core while reusing the current exported index and resolve APIs.

## Recommended boundary

- Parser layer:
  - `ExportEntries()`
  - `Resolve(IndexEntry)`
  - `DictionaryInfo()`
- Search layer:
  - candidate generation
  - ranking/scoring
  - typo tolerance
  - prefix/fuzzy orchestration

## Suggested interfaces

```go
type SearchHit struct {
    Entry IndexEntry
    Score float64
    Source string
}

type FuzzyIndexStore interface {
    Search(dictionaryName, query string, limit int) ([]SearchHit, error)
}
```

## Why this split

- Parser stays focused on correctness.
- Redis / SQL / Elasticsearch can evolve independently.
- Ranking strategy does not leak into MDict parsing code.

## Rollout

1. Current stage: exact + prefix via `IndexStore`.
2. Next: add `FuzzyIndexStore` in a new file/package.
3. Later: hybrid ranking using prefix + typo tolerance + popularity.

## Guidance

Do not couple fuzzy ranking to `Mdict.Lookup()`.
Use exported `IndexEntry` records as the stable interchange format.
