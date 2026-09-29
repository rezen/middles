# RubyGems support

Status: initial Bundler adapter implemented. Standalone `gem install`, full-index compatibility, hook inspection, and monthly download evidence remain future work.

## Implemented scope

Bundler resolves dependencies and downloads eligible gems through `/rubygems/`. Age policy applies per name/version/platform during resolution, compressed gemspec access, and archive access. The service remains request-driven, with no registry-wide crawl, Ruby runtime dependency, or persistent archive cache.

| Endpoint | Behavior |
| --- | --- |
| `/rubygems/api/v1/dependencies?gems=...` | Filtered Marshal dependency response; at most 100 distinct names |
| `/rubygems/quick/Marshal.4.8/{filename}.gemspec.rz` | Exact release authorization, then bounded opaque gemspec fetch |
| `/rubygems/gems/{filename}.gem` | Exact release authorization, then byte-preserving archive streaming |
| `/rubygems/versions`, `/rubygems/names`, legacy full indexes | Unsupported, return 404 |

## Protocol decision

The original plan proposed a filtered compact index. Investigation established that Bundler 2.4.22 consults the global `/versions` catalog before fetching package `/info` data: a partial or empty catalog would prevent resolution, and upstream checksums would not describe filtered package data. Producing a complete filtered catalog would conflict with the no-crawler design.

The implemented adapter therefore returns 404 for `/versions` and uses Bundler's dependency-API fallback. This was verified with a local fixture before implementation and then against the production adapter. Bundler 4.0.21's distributed source also retains `[CompactIndex, Dependency, Index]` fallback selection; runtime compatibility with that version has not been verified locally.

Typical verified request sequence:

1. Bundler probes `/rubygems/versions` and receives 404.
2. It probes `/rubygems/api/v1/dependencies`, then queries root and transitive package names.
3. Middles fetches upstream `/info/{name}` on demand and emits eligible dependency records.
4. Bundler fetches eligible compressed gemspecs, including Ruby/RubyGems requirements, followed by `.gem` archives.
5. Subsequent resolutions request dependency metadata again; the proxy recalculates age from cached upstream evidence. Direct gemspec/archive requests always recheck policy.

There is no transformed global index or index validator to keep coherent. Dependency responses are full responses with `Cache-Control: no-store`; upstream range offsets and validators are not forwarded. The dependency API does not convey compact-index artifact checksums to Bundler. Existing client caches and installed gems remain outside the enforcement boundary.

## Implementation

- `src/registry/rubygems.rs` parses bounded upstream compact text and emits only primitive Marshal arrays, hashes, symbols, and strings. It never deserializes upstream Marshal objects or evaluates gemspecs.
- `src/cache.rs` caches UTF-8 text under a separate key namespace using the existing shared metadata budget, SQLite persistence, TTL, and miss coalescing. JSON callers retain their existing behavior.
- `src/config.rs` adds `[rubygems]` overrides and `upstream.rubygems`, defaulting to `https://rubygems.org`. Default archive hosts include `rubygems.org`.
- `src/lib.rs` registers explicit RubyGems routes and shares bounded metadata fetching and archive transport.
- `src/stats.rs` accepts `ecosystem=rubygems`; successful archive transfers record a release including its platform suffix when applicable. Gemspec requests do not count as gem downloads.

Publication age uses `created_at`, never `built_at`. Missing, malformed, and future timestamps fail closed, even with zero-day policy. Versions and constraints retain RubyGems semantics rather than being interpreted as SemVer. Yanks become visible when metadata refreshes; expired evidence is not served on upstream failure.

Conventional filenames are ambiguous when names contain numeric hyphenated segments. The adapter checks at most eight syntactically possible splits against authoritative package metadata and rejects collisions. Arbitrary upstream URLs, encoded separators, traversal, and unsupported paths are not accepted. Archive redirects retain the existing exact-host allowlist and concurrency controls.

## Policy limitations

No suitable package-wide monthly evidence source has been configured. Effective nonzero `min_monthly_downloads`, including inherited values, fails startup validation. Operators must explicitly override RubyGems to zero when the global restriction is enabled. Lifetime counts are not substituted.

Install-hook enforcement and `/inspect/rubygems/` are not implemented. Effective `install_hooks = "deny"` also fails startup validation; an explicit `report` override is required when inherited. `report` does not establish absence of execution: native extensions may run build code, and gem contents are not inspected.

## Verification

`tests/rubygems.rs` covers per-platform age filtering, missing/future/malformed publication times, persisted raw text and policy changes, concurrent misses, yanks after refresh, conventional archive and gemspec denial, malformed requests, upstream failure, numeric names, ranges, transfer statistics, and unsupported inherited policies. Parser tests cover constraints, timestamp colons, checksums, and duplicate identities.

`scripts/rubygems-smoke.py` builds inert local gems and tests fresh/repeat installs, a transitive native-platform dependency, a blocked stale lockfile, and a warm-client update discovering a newly eligible version. Verified locally with Ruby 2.6.10, RubyGems 3.0.3.1, and Bundler 2.4.22. It requires no public registry or package hooks. Run `just ruby-smoke`; use `BUNDLE_COMMAND` to select a specific client.

A live install of `rake 13.2.1` through the production adapter also passed with Bundler 2.4.22, including gemspec fetching and transfer accounting. The existing live multi-registry smoke script can include a public Ruby gem with `MIDDLES_SMOKE_RUBYGEMS=1`. Run the normal formatting, Clippy, Rust tests, and configuration validation checks alongside client verification.

## Remaining milestones

1. Add runtime verification for current Bundler/RubyGems versions to the client matrix. Establish standalone `gem install` requirements before advertising support; never add an unfiltered full-index fallback.
2. Investigate a compact-index design only if it can provide a complete, coherent filtered catalog without a registry-wide crawl. Validate checksum, range, age-transition, and warm-cache behavior before replacing the dependency API.
3. Add metadata-only extension inspection with explicit unknown evidence and exact version/platform selection. Define conservative enforcement before enabling `deny`.
4. Add monthly-download policy only after identifying a provider with documented window semantics, freshness, limits, and fail-closed behavior.
5. Consider optional client-visible artifact integrity support for the dependency API without buffering complete gem archives.

## References

- [RubyGems compact index](https://guides.rubygems.org/rubygems-org-compact-index-api/)
- [RubyGems publication and download APIs](https://guides.rubygems.org/rubygems-org-api/)
- [RubyGems native extensions](https://guides.rubygems.org/specification-reference/#extensions)
