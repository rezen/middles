# Docker registry proxy plan

Status: proposed; no Docker endpoints or configuration are implemented.

## Goal and initial scope

Let Docker clients pull public container images through middles with its minimum-age policy, bounded metadata caching, and streaming downloads. Start with one operator-configured upstream per instance, defaulting to Docker Hub (`https://registry-1.docker.io`). Retain the existing npm, pip, and Composer behavior.

The first release will support explicit pulls such as `docker pull middles.example.com/library/alpine:3.22` and digest-pinned equivalents. Expose the registry at the origin's `/v2/`, using a dedicated hostname when the existing deployment uses a path prefix. Repository names retain their upstream meaning; Docker Hub official images use `library/`.

Docker Engine's `registry-mirrors` integration is a later compatibility milestone. Docker documents this mechanism for Docker Hub, rather than arbitrary registries. Treat mirror fallback and direct upstream access as deployment concerns requiring client configuration and egress controls; do not promise policy enforcement from mirror configuration alone. See [Docker's mirror documentation](https://docs.docker.com/docker-hub/image-library/mirror/).

Exclude pushes, uploads, deletes, catalog browsing, tag listing, private upstream credentials, schema 1 images, referrers/signature discovery, and persistent layer caching from the initial release. Reject unsupported image/artifact types explicitly. In particular, indexes containing attestations or other unsupported descriptors may initially be rejected; document this compatibility limit before release.

## Protocol surface

Implement a read-only subset of the [Registry HTTP API V2](https://distribution.github.io/distribution/spec/api/):

| Endpoint | Methods | Planned behavior |
| --- | --- | --- |
| `/v2/` | GET, HEAD | Version probe with `Docker-Distribution-API-Version: registry/2.0` |
| `/v2/<name>/manifests/<reference>` | GET, HEAD | Resolve tag or digest, evaluate policy, return original manifest |
| `/v2/<name>/blobs/<digest>` | GET, HEAD | Check eligible manifest membership, then stream or return headers |

Support Docker schema 2 manifests and manifest lists, plus OCI image manifests and indexes. Negotiate supported media types with `Accept`; reject unsupported representations without converting them. Preserve `Content-Type`, `Content-Length`, and `Docker-Content-Digest`. HEAD must apply the same policy as GET and send no body. Return registry-shaped `errors` responses, including `DENIED` for policy failures, `MANIFEST_UNKNOWN`/`BLOB_UNKNOWN` for missing content, and `UNSUPPORTED` for excluded operations.

Use the [OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md) for repository/reference validation, digest requests, HEAD behavior, and range semantics. Initially accept validated `sha256` digests only. Reject malformed paths, traversal, encoded separators, invalid tags, and unsupported digest algorithms before upstream access. Preserve partial-response status and range headers; distinguish absence, denial, rate limiting, and upstream failure.

## Policy decisions

These are proposed middles behaviors, not registry protocol requirements.

### Age evidence

Use durable local first observation of a verified manifest, keyed by upstream identity, repository, and digest. The [OCI image configuration's optional `created` field](https://github.com/opencontainers/image-spec/blob/main/config.md) describes image creation, not registry publication; display it only as informational evidence if inspection is added later. Do not use it, HTTP dates, or tag names to establish publication age.

- Start the waiting period only after fetching and validating the manifest and its required metadata. Record observations even when the age check denies the pull, so retries can eventually succeed.
- Apply the existing inclusive `min_age_days * 86_400` boundary. A new digest starts its own waiting period. Retagging an already observed digest does not restart its digest-based age; this policy does not measure tag age.
- Require the index and every supported descendant image manifest to pass. Traverse the graph with bounds on depth, descriptor count, total metadata bytes, and concurrent fetches; reject cycles, missing children, and unsupported descriptors.
- Return an eligible index unchanged. Never remove platforms or rewrite descriptors: indexes identify child manifests by digest, as described in the [OCI image index specification](https://github.com/opencontainers/image-spec/blob/main/image-index.md).
- Never silently replace a blocked tag with an older image. Direct digest requests receive the same checks.
- Document the cold-start waiting period and request-driven warming. Preserve the ledger across restarts and response eviction; losing the database restarts the wait. An explicit zero-day override allows immediately verified content.

### Blob access

A blob request identifies a repository and digest, not a parent image. Persist verified manifest-to-config/layer relationships alongside observations. Before GET or HEAD, require membership in at least one currently eligible image manifest in that same upstream repository; reload/revalidate its evidence when stale and recalculate policy on every request. Unknown relationships deny access and instruct operators to warm the parent manifest first. This deliberately limits clients that request blobs before manifests and needs compatibility testing.

Shared layers may be served through an eligible parent even if another parent is blocked. Serving an old shared layer must never authorize the blocked manifest or its other blobs. Keep graph discovery internal: fetching metadata to evaluate a denied image confers no client access. No public arbitrary-blob passthrough route.

### Other policies

The initial adapter has no monthly-download evidence provider or install-hook inspection. When enabled, inherit the global policy and reject configuration if effective `min_monthly_downloads` is nonzero or `install_hooks` is `deny`; operators may explicitly override Docker to `0` and `report`. Never silently ignore an inherited restriction or substitute lifetime pull counts for monthly downloads. Container entrypoints and build instructions do not map to the existing package install-hook checks.

## Upstream access and caching

Implement anonymous upstream Bearer authentication following the [registry token specification](https://distribution.github.io/distribution/spec/auth/token/). Validate challenge realms against an operator-configured HTTPS allowlist; request only `repository:<name>:pull`. Bound token responses, cache tokens in memory by upstream/realm/service/scope until shortly before expiry, coalesce concurrent requests, and permit one refresh after an authentication failure. Do not forward client credentials or expose tokens in logs, URLs, SQLite, or error bodies.

Follow redirects internally with hop limits and exact host allowlists. Strip registry authorization on cross-origin redirects, including blob CDN redirects. Never automatically trust a challenge realm, descriptor URL, pagination URL, or redirect destination. Reject manifests requiring external/foreign layer downloads in the first release, since returning those descriptors could let clients fetch outside the proxy.

Add a bounded raw-response cache for manifests and small config blobs. The current `Store::get` exposes parsed `serde_json::Value`, which cannot preserve original JSON serialization when sent back to clients. Store original bytes plus validated media type/digest, with a parsed view for policy; verify manifest/config hashes and descriptor sizes before accepting evidence. Exclude `/v2/` responses from automatic compression and use a client with decompression disabled.

Separate short-lived tag-to-digest resolution from immutable content. Cache keys include upstream, repository, reference, and negotiated representation. Reuse request coalescing and memory/disk budgets; never cache an authorization decision. Keep policy-bearing responses `no-store`, do not serve expired metadata on upstream failure, and document the tag/deletion visibility window.

Stream layers with backpressure and retain concurrency permits until completion or disconnect. Reuse the existing timeout and redirect checks through shared helpers, adding registry authentication and HEAD support. Do not buffer layers in memory or SQLite. Clients verify streamed layer digests; the proxy cannot promise pre-delivery integrity verification without buffering, especially for ranges. Preserve `429` and safe `Retry-After` values, bound retries, and avoid caching transient failures as permanent absence.

## Implementation milestones

1. **Configuration and routes.** Add a disabled-by-default Docker config in `src/config.rs`, an adapter in `src/registry/docker.rs`, registration in `src/registry/mod.rs`, and `/v2/` routing in `src/lib.rs`. Validate upstream/realm/CDN allowlists, root-path deployment, policy overrides, and graph limits. Add registry-specific errors without changing existing package error responses.
2. **Authenticated read transport.** Implement challenge parsing, token caching, safe redirects, media negotiation, and byte-preserving GET/HEAD. Extend `src/cache.rs` with bounded raw entries and transactional graph/observation records, migrating existing databases without resetting Composer observations.
3. **Policy enforcement.** Resolve tags, verify manifests/configs, observe digests, traverse indexes, and enforce parent membership for blobs. Keep durable evidence separate from expiring response caches; define storage accounting and operator cleanup so evidence removal fails closed and never shortens waiting periods.
4. **Streaming and deterministic tests.** Add local registry, token-service, and CDN fixtures in `tests/docker.rs`; cover restart and cache behavior in `tests/cache.rs`. Complete the scenarios below before claiming client support.
5. **Client compatibility and documentation.** Extend `scripts/smoke.py` with an opt-in Docker check using an isolated daemon/content store, public test images, and explicit local zero-age configuration. Verify tag, digest, and multi-platform pulls with recorded client versions. Then test Docker Hub mirror mode and fallback separately. Add runnable config/client examples to the README and `middles.example.toml` only when implementation exists.

## Acceptance criteria

- Real Docker pulls succeed by explicit proxy hostname for supported single-platform and multi-platform images, both by tag and digest. Manifest bytes and digests match upstream; GET and HEAD agree.
- Exact age boundaries, cold starts, moved tags, direct digests, blocked index children, unknown blob membership, and cross-repository attempts behave as specified. Restart and cache eviction retain observations; policy changes immediately affect cached content.
- Tests cover unsupported descriptors, external layer URLs, malformed names/digests, oversized/deep graphs, digest/size mismatches, token expiry, concurrent misses, hostile realms, redirect loops, credential stripping, upstream `404`/`429`/failures, and range `206`/`416` responses.
- Large synthetic layer streams keep memory bounded; disconnects and timeouts release permits. HEAD does not download layer bodies. Warm token caches avoid redundant token requests.
- Existing npm, pip, Composer, and inspection tests pass, along with `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, and `cargo test --locked`. Docker-disabled configurations continue to work unchanged.
- Documentation clearly states the observation-based age model, unsupported artifacts, shared-layer behavior, absent vulnerability/signature scanning, and client cache/egress bypass boundaries.
