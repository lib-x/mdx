# Changelog

## Unreleased

### Added
- Added `AssetResolver` and `AssetSource` abstractions to unify resource lookup across sidecar files, companion MDD files, and future sources.
- Added resolver-backed pair composition helpers so MDX/MDD dictionary pairs opened through the registry automatically share one resource resolution pipeline.
- Added support for ordered multi-volume MDD discovery via `DictionarySpec.MDDPaths` and `demo.mdd`, `demo.1.mdd`, `demo.2.mdd` style scanning.
- Added minimal HTML audio adaptation with `RewriteEntryAudioLinks(...)` for both `sound://` and `snd://` links.

### Changed
- Routed `MdictFS` and `NewAssetHandler` through the shared `AssetResolver` so file-system and HTTP delivery now use the same resource semantics.
- `LookupAndRewriteHTML()` now rewrites resource URLs, normalizes malformed internal `entry://entry://...` links, and upgrades audio anchors to browser-playable `<audio controls>` blocks.
- Resource redirect handling now follows UTF-16LE `@@@LINK=` records with loop protection.
- Dictionary pair setup now defaults to sidecar-first resource lookup using the MDX directory plus any discovered companion MDD volumes.

### Validation
- Passed `go test ./...` after each functional slice and again after `gofmt`.
- Manually validated against the real dictionary in `/home/czyt/code/dict`:
  - CSS and image resources rewrite to `/assets/...`.
  - `snd://` audio links upgrade to playable HTML audio output.
  - duplicated `entry://entry://...` links are normalized.
- The local validation directory is **not** used by repository or CI tests.
