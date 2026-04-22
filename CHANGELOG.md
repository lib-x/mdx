# Changelog

## Unreleased

### Added
- Added `AssetResolver` and `AssetSource` abstractions to unify resource lookup across sidecar files, companion MDD files, and future sources.
- Added `LookupAndRewriteHTMLWithEntryBase(...)` for browser-facing output that also rewrites internal `entry://word` links into clickable lookup URLs.
- Added `NewAssetHandlerWithOptions(...)` so callers can customize HTTP cache semantics and enable `ETag` / `Last-Modified` headers.
- Added resolver-backed pair composition helpers so MDX/MDD dictionary pairs opened through the registry automatically share one resource resolution pipeline.
- Added support for ordered multi-volume MDD discovery via `DictionarySpec.MDDPaths` and `demo.mdd`, `demo.1.mdd`, `demo.2.mdd` style scanning.
- Added minimal HTML audio adaptation with `RewriteEntryAudioLinks(...)` for both `sound://` and `snd://` links.

### Changed
- Routed `MdictFS` and `NewAssetHandler` through the shared `AssetResolver` so file-system and HTTP delivery now use the same resource semantics.
- Resolver-backed asset HTTP delivery now uses `http.ServeContent`, adding browser-friendly `Range` handling and a default `Cache-Control: public, max-age=3600` policy.
- `examples/http-server-redis` now uses the same browser-facing rewrite pipeline as the other HTTP examples, including internal-link cleanup and audio-link adaptation.
- `LookupAndRewriteHTML()` now rewrites resource URLs, normalizes malformed internal `entry://entry://...` links, and upgrades audio anchors to browser-playable `<audio controls>` blocks.
- Browser-facing examples now expose cleaner internal entry navigation and share the same resolver/audio rewrite path.
- Resource redirect handling now follows UTF-16LE `@@@LINK=` records with loop protection.
- Dictionary pair setup now defaults to sidecar-first resource lookup using the MDX directory plus any discovered companion MDD volumes.

### Validation
- Passed `go test ./...` after each functional slice and again after `gofmt`.
- Manually validated against the real dictionary in `/home/czyt/code/dict`:
  - CSS and image resources rewrite to `/assets/...`.
  - `snd://` audio links upgrade to playable HTML audio output.
  - duplicated `entry://entry://...` links are normalized.
  - resolver-backed asset HTTP delivery returns `206 Partial Content` with `Content-Range` and cache headers for a real image asset.
  - `NewAssetHandlerWithOptions(...)` was manually verified against the same real image asset, confirming custom `Cache-Control`, `ETag`, and `Last-Modified` headers.
- The local validation directory is **not** used by repository or CI tests.
