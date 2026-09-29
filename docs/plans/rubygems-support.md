# RubyGems support plan

Status: proposed; no RubyGems endpoints or configuration are implemented.

## Goal and initial scope

Support Bundler dependency resolution and `.gem` downloads through middles, applying minimum-age policy during resolution and again at artifact access. Follow with standalone `gem install` compatibility once its required protocol paths pass equivalent tests.

Reuse the existing policy evaluation, upstream limits, redirect validation, and archive streaming. Preserve npm, pip, and Composer behavior. Keep the service request-driven, without a full-registry crawler or persistent archive cache.

Initially exclude publishing, private upstream authentication, search, and unverified legacy client protocols. Document supported client versions before claiming compatibility.

## 1. Validate client compatibility and index design

Build a small protocol fixture and trace fresh installs, locked installs, and updates with selected Bundler and RubyGems versions. Establish the required endpoint surface under `/rubygems/`:

| Endpoint | Intended role |
| --- | --- |
| `/rubygems/versions` | Compact index discovery and package information checksums |
| `/rubygems/info/{name}` | Filtered versions, platforms, dependencies, and requirements |
| `/rubygems/gems/{filename}` | Policy-checked gem download |

Determine whether compressed gemspecs, `/names`, or legacy indexes are required for the selected clients. Unsupported paths must fail explicitly rather than expose an unfiltered upstream fallback.

Treat the relationship between `/versions` and `/info/{name}` as an implementation gate. The global index carries checksums of package information, while filtering changes those bytes. Determine and test a coherent approach that does not require fetching every gem's metadata. Do not assume that passing through upstream `/versions`, returning a partial catalog, or inventing checksums is compatible.

Record the selected approach, client versions, and request traces before implementing the production adapter. If the approach requires full-registry materialization, revisit scope explicitly rather than silently adding a crawler.

Reference: [RubyGems compact index specification](https://guides.rubygems.org/rubygems-org-compact-index-api/).

## 2. Add configuration and adapter plumbing

- Add `src/registry/rubygems.rs` and register it in `src/registry/mod.rs`.
- Add `/rubygems/` routes in `src/lib.rs`.
- Add `[rubygems]` policy overrides and a configurable RubyGems upstream in `src/config.rs`, defaulting to `https://rubygems.org`.
- Add verified gem download hosts to the artifact allowlist, retaining exact-host and redirect checks.
- Validate gem names, versions, platforms, and filenames with RubyGems-specific rules before upstream access. Cover traversal, encoded separators, and ambiguous filename identities.
- Preserve deployment under a configured public URL prefix.

## 3. Parse metadata and apply age policy

Extend the bounded metadata fetch/cache infrastructure to support text responses. `Store::get` currently assumes JSON; retain JSON callers while adding an appropriate raw/text representation. Preserve request coalescing, memory and disk budgets, TTLs, negative caching, and restart behavior. Coordinate this shared change with other adapters needing raw-response caching.

Represent each release by **name, version, and platform**. Preserve RubyGems dependency constraints, Ruby/RubyGems requirements, prereleases, and artifact checksums; do not interpret RubyGems versions using Rust's SemVer rules.

Use publication `created_at` as age evidence. The current compact index exposes it, and the JSON versions API distinguishes publication time from `built_at`. Do not use build time as publication time. Hide releases with missing, malformed, or future publication timestamps, including under a zero-day policy. If a JSON fallback is needed for older upstream formats, match the exact version and platform and bound the additional requests.

Apply the shared inclusive age boundary to each platform release independently. Cache upstream evidence, not filtered results or authorization decisions, so releases can age into eligibility without waiting for an upstream refresh. Respect yanks and document the existing metadata freshness window.

References: [compact index format](https://guides.rubygems.org/rubygems-org-compact-index-api/), [RubyGems version API](https://guides.rubygems.org/rubygems-org-api/#gem-version-methods).

## 4. Serve coherent indexes and enforce downloads

Generate index checksums and HTTP validators from the actual filtered representation. Account for changes caused by elapsed time, policy changes, upstream updates, and yanks. Preserve artifact checksums independently from index-response checksums.

Start with full metadata responses if the compatibility fixture confirms clients accept them, then consider range optimization. Never forward upstream partial-response offsets or validators for transformed content. Verify warm-client-cache behavior rather than relying on `Cache-Control: no-store` alone. Ensure compression and digest headers describe the correct representation.

Resolve conventional `.gem` filenames to an exact known release and recheck policy before streaming. Do not authorize downloads by filename parsing alone or accept arbitrary target URLs. Direct requests and requests originating from existing lockfiles must receive the same checks as fresh resolutions.

Reuse `App::stream_artifact` for backpressure, range forwarding, timeouts, concurrency permits, and redirect allowlisting. Preserve archive bytes and avoid buffering full gems. Client checksum verification remains necessary; streaming does not provide pre-delivery verification of the entire archive.

Return empty package information when every release is filtered, subject to the client fixture's protocol requirements. Distinguish unknown packages, policy denial, and upstream verification failures using the project's existing error conventions.

## 5. Define unsupported policy behavior

### Monthly downloads

The documented RubyGems download endpoints expose cumulative counts. No documented package-wide monthly source was identified during planning. Initially reject configurations whose effective RubyGems `min_monthly_downloads` is nonzero, including inherited values. Explain that an explicit RubyGems override of zero is required until a suitable provider exists.

Do not substitute lifetime downloads, fabricate zero, or silently skip the restriction. A later monthly provider must define its window, freshness, failure behavior, and request limits.

Reference: [RubyGems download API](https://guides.rubygems.org/rubygems-org-api/#gem-download-methods).

### Install-hook inspection

Report unavailable evidence explicitly, with no claim that a gem has no installation-time execution. Native extension builds are an execution surface requiring coverage. Until reliable extension evidence and enforcement are implemented, reject an effective RubyGems `install_hooks = "deny"`; permit an explicit `report` override.

If adding `/inspect/rubygems/{name}`, require exact version and platform selection and preserve inspection's existing separation from artifact authorization. Do not execute gemspecs or package code. Do not infer extension safety solely from a platform label.

Reference: [RubyGems extensions specification](https://guides.rubygems.org/specification-reference/#extensions).

## 6. Test, document, and extend compatibility

Add deterministic local fixtures covering:

- Platform variants, prereleases, dependency constraints, checksums, and yanks.
- Inclusive age boundaries and missing, malformed, or future timestamps.
- Releases becoming eligible while upstream evidence remains cached.
- Filtered-index consistency, validators, compression, and warm client caches.
- Policy changes after restart, cache persistence, expiry, and concurrent misses.
- Blocked direct downloads and lockfile requests, malformed identities, redirect allowlisting, and range responses.
- Unsupported inherited monthly-download and install-hook policies.
- Upstream failures, oversized metadata, and bounded archive streaming.

Extend `scripts/smoke.py` with opt-in isolated Bundler installs using recorded client versions and fresh caches. Exercise fresh resolution, locked installation, and update. Verify package download requests stay on the proxy and include a platform-specific gem in compatibility coverage.

Update `README.md`, `middles.example.toml`, and package metadata when implementation exists. Provide source configuration examples and explain supported clients, policy limitations, metadata freshness, and bypasses through alternate sources, direct URLs, VCS dependencies, or client caches.

Add standalone `gem install` support as a subsequent milestone after identifying and implementing its additional required endpoints. Give any added metadata paths the same filtering and artifact authorization rules; avoid broad passthrough routes.

## First-release acceptance criteria

- A fresh Bundler resolution selects eligible versions and installs their dependencies through the proxy.
- A blocked version cannot download through a conventional gem URL or an existing lockfile.
- Version/platform identity remains consistent across metadata, policy checks, and archive lookup.
- Warm client caches refresh correctly after upstream changes, policy changes, and age transitions.
- Index checksums and validators match the served representations without a full-registry crawler.
- Unsupported effective policies fail configuration validation with actionable errors.
- Existing npm, pip, Composer, inspection, and cache behavior remains intact.
- `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, and `cargo test --locked` pass, along with the selected real-client smoke checks.
