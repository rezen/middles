# Homebrew support plan

Status: scoped official-bottle adapter implemented, disabled by default. Following
client compatibility checks, the accepted scope is policy enforcement on official
stable bottle requests that reach middles. Source downloads, local client caches,
bootstrap and other excluded traffic are deployment limitations, not a claim of
installation-wide enforcement. See the [usage guide](../homebrew/README.md),
[compatibility record](../homebrew/compatibility.md), and real adapter smoke traces.
Linux/default-prefix CI and real-client upgrade/rebuild qualification remain open.
Formula identity conservatively uses the full signed Ruby source checksum;
bottle-only formula edits also reset waits until safe execution-only normalization
is implemented. The original strict local-first-observation age basis remains the
default; `age_basis = "oci_created"` is an opt-in build-age heuristic for operators
who accept that build time does not prove publication time.
An explicit `[homebrew] min_age_days = 0` disables either age basis while retaining
signed metadata and bottle relationship verification.


## Goal and first-release scope

Let `brew install` and `brew upgrade` fetch official `homebrew/core` bottles through middles, applying minimum-age policy before artifact access. This plan covers Homebrew as a package ecosystem; distributing the middles binary with `brew install middles` is a separate task.

Start with bottled stable formulae and their bottled dependencies on explicitly tested macOS and Linux platforms. Exclude casks, third-party taps, source builds, HEAD installs, private registries, arbitrary URL downloads, and persistent bottle storage. Unsupported requests must fail explicitly. Keep existing adapters working and retain bounded, request-driven metadata caching and streamed artifacts.

Unlike npm, the initial adapter will not select an older eligible version. A blocked current bottle makes the install fail with a policy reason and, when known, an eligibility time. Homebrew's signed API must remain intact: do not filter signed payloads, replace its trust keys, or require signature verification to be disabled. Homebrew documents JWS verification for its install metadata in its [security and supply-chain documentation](https://docs.brew.sh/Homebrew-Security-and-Supply-Chain).

## 1. Establish real-client compatibility before production work

Build an isolated protocol fixture and record the Homebrew version, platform, request paths, headers, and fallback behavior for fresh installs, dependency installs, upgrades, and warm-cache retries. Use disposable CI installations and caches rather than modifying a developer's normal Homebrew installation.

The proposed client setup is:

```sh
export HOMEBREW_ARTIFACT_DOMAIN=http://127.0.0.1:6280/homebrew
export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1
```

These variables redirect artifact traffic and disable download fallback. API and bottle mirror settings alone permit upstream fallback. `HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK` exists only in recent Homebrew releases; older clients fall back silently, so the supported-client matrix must declare a minimum Homebrew version, not merely record versions. Keep signed API metadata on its normal upstream initially; adding `HOMEBREW_API_DOMAIN` is optional metadata mirroring, not an enforcement mechanism. Confirm the exact prefix mapping with supported clients before publishing these commands as working setup. See the [Homebrew environment variable reference](https://docs.brew.sh/Manpage#environment).

The fixture must resolve these implementation gates:

- Which OCI index, manifest, config, and bottle-blob requests occur, and in which order? Can cached metadata cause a blob request without a preceding manifest request?
- How are formula names such as `openssl@3`, package revisions, bottle rebuilds, and platform tags encoded in GHCR paths? Use Homebrew's mapping rather than generic SemVer assumptions.
- Do policy denials, missing bottles, timeouts, and unsupported platforms trigger an origin retry, source build, or other download strategy despite the chosen settings?
- Does the artifact setting also intercept bootstrap/runtime downloads or formula support files? Identify any required ancillary artifacts individually; do not add an unrestricted proxy to make the smoke test pass.
- Does the client send its anonymous placeholder `Authorization` header (the GHCR `Bearer QQ==` token) to the artifact domain? Decide whether middles ignores or rejects it; never treat it as a credential.
- When middles denies a download, does the client surface the response body? The usefulness of policy-denial messages depends on this; record the observed failure output.
- Can a fully cached bottle install without contacting middles? Record this as a client-cache limitation, and require fresh caches for enforcement tests.

Deliver recorded traces, a supported-client matrix, and an explicit pass/fail decision. If unmodified clients cannot meet the scoped guarantee, revise the client setup or scope before building the adapter. Do not claim installation-wide enforcement from environment variables alone; managed deployments need controlled client configuration and egress.

## 2. Add a narrowly scoped Homebrew adapter

Use the ecosystem key `homebrew` and a disabled-by-default `[homebrew]` configuration. The existing `Override` struct has no enabled flag and `policy_for` panics on unknown ecosystems, so Homebrew needs its own configuration type and an explicit `policy_for` arm. Add `src/registry/homebrew.rs`, register it in `src/registry/mod.rs`, and mount its routes in `src/lib.rs`.

Provisional routes, subject to the client fixture:

| Route | Behavior |
| --- | --- |
| `/homebrew/v2/` | Registry version probe if required by the client |
| `/homebrew/v2/homebrew/core/{repository}/manifests/{reference}` | Validate identity, fetch bounded metadata, and apply the defined manifest policy |
| `/homebrew/v2/homebrew/core/{repository}/blobs/{digest}` | Authorize exact membership, then serve required metadata or stream the bottle |

GHCR encodes versioned formulae as extra path segments (`openssl@3` → `homebrew/core/openssl/3`), so `{repository}` spans one or more segments and a single-segment router parameter cannot match it. Mount one wildcard route under `/homebrew/v2/` and split repository, endpoint, and reference manually with strict validation.

Support GET and HEAD where required, with identical authorization. Reject other repositories, writes, unsupported media types, malformed identities, traversal, encoded separators, and unknown routes. Do not expose a generic `/homebrew/https://...` fetch endpoint. Preserve deployment behind a stripped public URL prefix.

Default the upstream to GHCR's official Homebrew namespace. Keep test-upstream overrides explicit and HTTPS mandatory outside local fixtures. Use Homebrew-specific configuration validation rather than widening every ecosystem's artifact permissions.

## 3. Define release identity and age evidence

Use **durable local first observation of verified bottle evidence** for the default policy. An opt-in `oci_created` mode uses the selected verified OCI manifest's build-date annotation as a weaker age heuristic. Do not equate a formula's upstream release date, Git commit time, HTTP Last-Modified value, or an OCI build timestamp with bottle publication time. A reliable publication-time provider can be considered separately.

Record upstream, canonical formula/repository, version, formula revision, bottle rebuild, platform, selected per-platform child manifest digest, and bottle checksum. Key identity on the per-platform child evidence, never the top-level index digest: platform additions, other platforms' rebuilds, and annotation churn change the index digest and must not reset unrelated waits. Start the waiting period only after validating the metadata-to-artifact relationship. Define a stable identity over the policy-relevant formula definition and selected bottle evidence; exclude analytics and unrelated platform additions so they do not unnecessarily reset an existing bottle's wait. Changed formula execution metadata or bottle content must establish a new identity and waiting period.

Apply the existing inclusive `min_age_days * 86_400` boundary. Record valid evidence even on a denied request, allowing later retries to age into eligibility. Zero days permits immediately verified evidence; it does not permit missing or inconsistent identities. An unknown raw digest must not start an authorized waiting period by itself.

Persist evidence separately from expiring response caches. Recalculate policy on each request, refresh stale associations, and deny when verification fails. Losing the ledger restarts waiting periods. Document warming, backups, restart behavior, and storage accounting; evidence deletion must never shorten a wait.

Unlike npm, no upstream supplies a trusted publication time, so a fresh deployment blocks the entire dependency closure of the first install for the full waiting period. Ship a concrete warming recipe — for example, a script that walks a formula's dependency tree and touches each manifest — rather than documentation alone.

Choose and test the exact index rule during the fixture milestone: an index may be discovery metadata only, but returning it must never authorize all its children. Gate every requested platform manifest and bottle independently. Avoid delaying an old platform bottle solely because another platform was added to the same index. Never rewrite digest-addressed indexes to remove blocked platforms. Expect the blob route to be the primary enforcement point: clients read per-platform bottle digests from index annotations and may never fetch child manifests, so middles must perform child-manifest discovery itself during evidence verification, and a denial surfaces to the user as a failed bottle download.

## 4. Implement verified transport and artifact authorization

Build bounded, byte-preserving metadata fetching for the Homebrew representations found in the fixture. The working tree currently exposes JSON and text cache helpers; neither is a complete raw OCI response cache. Preserve original manifest bytes, media types, sizes, and hashes alongside parsed evidence. Exclude these routes from transformations that invalidate their representation headers.

Bind bottles to authoritative Homebrew formula metadata and verified manifest descriptors. Where signed API data supplies the identity, verify it before trusting it; determine the required signed endpoint, key handling, and maximum payload size in the fixture milestone. Avoid trusting an arbitrary digest merely because GHCR serves it. Persist verified associations so direct bottle requests can be checked after restart. For unknown associations, perform only bounded discovery for the known formula; otherwise deny and require warming its metadata.

Use read-only registry transport for manifests and blobs, retaining content digests, media negotiation, range behavior, and registry-shaped errors. Verify small metadata before accepting it as evidence; bound graph depth, descriptor counts, total bytes, and concurrency. See the [Registry HTTP API](https://distribution.github.io/distribution/spec/api/).

Handle anonymous GHCR Bearer authentication internally, caching tokens in memory keyed by upstream, realm, service, and scope until shortly before expiry, matching the Docker plan. Allowlist challenge realms and redirect hosts, restrict scopes to the configured repository's pull access, coalesce token requests, and bound token lifetime and retries. Ignore or reject the client's placeholder `Authorization` header per the fixture decision; strip authorization on cross-origin redirects; never forward client credentials or persist tokens in SQLite or logs. See the [registry token specification](https://distribution.github.io/distribution/spec/auth/token/).

Reuse or extract the existing artifact transport for streaming, backpressure, ranges, concurrency permits, and timeouts. Never redirect the client to an upstream bottle URL. Do not buffer whole bottles. Homebrew retains checksum verification; middles cannot promise full pre-delivery digest verification while streaming.

Coordinate shared raw-cache and registry-auth work with the [Docker registry proxy plan](docker-registry-proxy.md), which currently specifies the same transport subsystem. Extract the read-only OCI transport — token authentication, realm/redirect allowlists, byte-preserving raw cache — into a shared module (for example `src/registry/oci.rs`) owned by whichever adapter lands first; the other consumes it rather than re-specifying it. Keep Homebrew identity and policy separate; the general Docker adapter is not a prerequisite for this feature.

## 5. Handle other policies and statistics explicitly

- **Monthly downloads:** initially reject an enabled Homebrew configuration whose effective `min_monthly_downloads` is nonzero, including inheritance. Homebrew exposes 30-day installation analytics, but these are a different measurement from package downloads. A later provider needs explicit semantics, coverage, variant aggregation, freshness, and failure rules before mapping it to this policy. See the [Homebrew analytics API](https://formulae.brew.sh/docs/api/).
- **Install hooks:** initially reject effective `install_hooks = "deny"` for Homebrew. Permit an explicit `report` override and report unavailable/incomplete evidence. Bottles do not establish the absence of post-install execution; never execute formula Ruby to inspect it.
- **Local statistics:** add `homebrew` to `src/stats.rs` validation and use a stable release identity that distinguishes revision, rebuild, platform, and content. Count completed bottle transfers using existing full/range semantics; exclude API, manifests, config metadata, denials, and interrupted transfers.

Validate these restrictions only when the adapter is enabled so adding it does not break existing configurations. The RubyGems restriction checks currently run unconditionally; consider retrofitting them to this enabled-gated pattern as separate cleanup.

## 6. Test and release in milestones

1. **Compatibility spike:** record the client matrix and traces; settle routes, signed evidence, direct-blob handling, ancillary downloads, and fallback behavior. This is the go/no-go gate.
2. **Evidence and transport:** implement disabled configuration, raw cache support, authenticated upstream reads, signature/digest checks, and durable observation/association records. Database migration must preserve existing observations and statistics.
3. **Policy and downloads:** add manifest/blob authorization, streaming, explicit unsupported-policy errors, diagnostics, and transfer statistics.
4. **Verification and documentation:** add deterministic integration fixtures and an opt-in Homebrew smoke script; update README, example configuration, and just recipes only when the feature works.

Deterministic tests must cover inclusive age boundaries, changed rebuilds and digests, platform separation, evidence expiry, policy changes, restart persistence, direct blob requests, concurrent misses, invalid signatures/hashes, token challenges, redirect rejection, ranges/HEAD, oversized metadata, and unsupported inherited policies. Verify that no error path becomes an unrestricted fetch or exposes bottle bytes before authorization.

Real-client tests must cover an eligible formula with dependencies, a blocked current bottle, a newly rebuilt bottle, warm metadata with a cold bottle cache, fully cached installs, and upstream failures. Test source fallback, casks, taps, bootstrap artifacts, and unsupported platforms explicitly. Trace requests or deny upstream artifact egress in the test environment to prove a blocked download does not escape the proxy.

## Acceptance criteria

- Documented Homebrew clients install eligible official bottles and dependencies through middles with signature and checksum verification intact.
- A blocked bottle fails with a useful policy reason in the response body and middles diagnostics; whether the client displays it is recorded by the fixture. Normal supported-client retries cannot retrieve it directly upstream.
- Direct digest and range/HEAD requests enforce the same artifact policy as ordinary installs.
- Age is measured and described as local first observation, with durable evidence and a documented cold-start wait.
- Cached local installs and other bypasses are stated clearly; no promise of retrospective enforcement is made.
- Unsupported policies fail configuration validation; unsupported download classes fail explicitly.
- Existing adapters retain their behavior, and formatting, Clippy, locked Rust tests, configuration checks, and the selected real-client smoke tests pass.
