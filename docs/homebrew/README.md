# Homebrew bottle support

Middles can proxy current stable bottles from the official `homebrew/core` GHCR
namespace. It verifies signed Homebrew formula metadata and the selected OCI
manifest/config relationship before allowing a bottle. The adapter is opt-in;
other adapters retain their configuration and behavior.

The guarantee is **policy enforcement on official bottle requests that reach
middles**. The artifact environment variables do not control every Homebrew
installation. Source builds, casks, third-party taps, HEAD installs, arbitrary
URLs, portable-Ruby/bootstrap downloads and already-cached bottles are outside
this scope. Unsupported requests reaching `/homebrew/` fail explicitly. Excluded
traffic that never reaches middles needs separate client and egress controls.

## Configure and install

```toml
[homebrew]
enabled = true
platforms = ["arm64_tahoe"]
# Omit min_age_days to inherit [policy]. Default: 7.
age_basis = "oci_created" # Opt-in build-age heuristic; default is "local_first_seen".
min_monthly_downloads = 0
install_hooks = "report"
max_api_mb = 64
```

Use Homebrew **7.0.6 or newer** for the documented setup; 7.0.6 is the tested
minimum, not a claim about the oldest release with no-fallback support. Provision
Homebrew and its portable Ruby separately. Keep signed API metadata on Homebrew's
normal upstream; no custom `HOMEBREW_API_DOMAIN` or verification-disabling flag is
required for client use.

```sh
export HOMEBREW_ARTIFACT_DOMAIN=https://middles.example.com/homebrew
export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1
brew install --force-bottle hello
brew upgrade --force-bottle hello
```

If your public URL includes a reverse-proxy prefix, append `/homebrew` to that URL,
for example `https://example.com/middles/homebrew`. The reverse proxy must strip
`/middles`, as for the existing adapters. Signed payloads and OCI indexes are never
rewritten. Middles does not redirect the client to GHCR/CDN bottle URLs.

Homebrew 7.0.6 source on arm64 macOS 26.7 (`arm64_tahoe`) passed the isolated
[real adapter smoke](traces/adapter-2026-09-29/report.json) for `hello`, `zstd`,
`lz4` and `xz`, including dependency installation, checksum verification, denied
cold downloads after restart, and local statistics. The copied source uses a
non-default prefix and `--force-bottle`; its absent Git directory causes a `4.X.Y`
User-Agent label. Default-prefix CI, genuinely outdated-client upgrades, newly
published rebuilds, and other client releases still need qualification. The
adapter rechecks upgrade artifacts using the same routes and identity as installs;
that is covered by deterministic rebuild/policy tests, not a real older-version
upgrade claim.
The [build-age smoke](build-age-smoke.md) also passed using
Homebrew 7.0.7 source: at seven days, a forced cold `hello` fetch was denied with
`local_first_seen` and allowed with `oci_created`. The signed API snapshot and
official GHCR bottle were unchanged between those checks.

Other accepted tags are `arm64_sequoia`, `arm64_sonoma`, `sequoia`, `sonoma`,
`arm64_linux` and `x86_64_linux`. Enable only tags you intend to serve. Their
identity/transport handling has deterministic coverage; Linux and other macOS
clients have not passed the real-client matrix and remain experimental. The
default allows only `arm64_tahoe`. Unsupported platform digests are denied even
when the unmodified discovery index lists them. Homebrew itself may warn and exit
successfully for a missing requested bottle tag; middles cannot change a command
that never contacts it.

## Age and warming

The default `age_basis = "local_first_seen"` measures from middles' durable first
observation of verified bottle evidence. Opt in to `age_basis = "oci_created"` to
measure from `org.opencontainers.image.created` on the selected OCI bottle
manifest. This is Homebrew's reported **build date**, not proof of when that
bottle became publicly available. Its value is part of the verified OCI graph,
but it is supplied by the bottle producer and is not a registry upload time.
With a positive age requirement, missing, malformed or future build dates deny
access. The chosen basis appears in the warm response and age-denial message.
HTTP `Last-Modified` and `Date` headers are never used for age decisions.

To remove age as a Homebrew policy, set `[homebrew] min_age_days = 0` and restart
middles. This bypasses both age bases, including build-date validation, while
still requiring signed formula metadata and matching OCI digests. The warm
response then reports `age_basis: "disabled"` and no eligibility time.

Identity binds the registry, canonical formula/repository,
version, formula revision, bottle rebuild, platform, selected child manifest,
bottle checksum/config, and formula execution definition. The signed Ruby source
checksum binds the definition; Ruby is never executed by middles. The bundled
`homebrew-1.der` is the PKCS#1 DER representation of Homebrew 7.0.6's
[`api/homebrew-1.pem`](https://github.com/Homebrew/brew/blob/7.0.6/Library/Homebrew/api/homebrew-1.pem).
Key rotation requires a trusted binary update, not a configurable replacement key. Adding unrelated
index/platform descriptors or changing analytics does not restart another
platform's wait when its child and signed formula definition remain unchanged.
The full Ruby source checksum is conservative: even a bottle-only edit to the
formula file starts a new wait. Normalizing executable Ruby separately from its
bottle stanza is deferred; no parser or formula execution is used to weaken this
check. A changed child, bottle or definition establishes a new local observation
wait; `oci_created` reevaluates the new child's reported build date instead.
The top-level index digest is not age evidence.

A fresh deployment with seven days of minimum age blocks the dependency closure
for seven days under `local_first_seen`. In `oci_created` mode, an already-old
bottle can pass immediately after full verification. Discovery indexes are
returned unchanged without authorizing their children. Merely fetching an index
does not start a wait: a bottle/config/child
request or the warming endpoint must verify evidence first. Denied artifact
requests still record valid evidence. Unknown raw digests do not acquire an
observation or authorize bytes. Zero days allows immediately **verified** evidence;
missing signatures, hashes or relationships fail even at zero days.

Warm a dependency closure without downloading bottles:

```sh
python3 scripts/homebrew-warm.py https://middles.example.com zstd
# Or: just homebrew-warm https://middles.example.com zstd
```

The script calls `/homebrew/warm/<canonical-formula>`, follows signed formula
and verified bottle runtime dependencies, deduplicates the closure, and prints
eligibility times. It uses a 256-formula default bound (adjust with
`--max-formulas`), follows no HTTP redirects, and reports failures. The endpoint
returns unavailable install-hook evidence explicitly. It only fetches bounded
metadata and records observation; it neither downloads a bottle nor executes Ruby.
Warm each dependency independently if a closure contains a formula with no bottle
on the configured platforms. Start installs after the displayed eligibility time;
ordinary retries age into eligibility at the inclusive `days * 86,400` boundary
for either basis. `first_seen` remains recorded in both modes, so switching back
to the strict basis restores its original wait rather than inheriting build age.

## Persistence and transport

Retain `cache.path` across restarts and back up the SQLite database using SQLite's
backup API or stop middles before copying the database and WAL safely. Both
`first_seen` and `homebrew_evidence` are durable, outside expiring response caches.
Records contain associations and observation timestamps, not credentials or
bottle archives. Cache eviction, expiry and restart do not erase waits. Losing
observations restarts local waits. Never edit timestamps to make a bottle eligible.

Evidence is revalidated from current metadata on requests, subject to
`cache.metadata_ttl_secs`; stale responses are never served after a failed
refresh. The durable association table is an audit/observation ledger, not a
stale authorization fallback. Current stable formulae are supported; historical
bottles no longer referenced by current signed metadata are denied. Policy is
recalculated on every artifact request, including HEAD and ranges. If a config is
shared by multiple supported platforms, one eligible verified parent is enough
for that config alone.

Raw OCI metadata participates in the shared SQLite response budget. With
Homebrew enabled, the approximate hot-cache split is 50% parsed metadata, 25% raw
OCI metadata and 25% statistics; when disabled, the existing 75%/25% split is
retained. The signed catalogue is bounded separately by `max_api_mb` (64 MiB
default; maximum 128 MiB) because its payload exceeds the general 32 MiB limit.
Only verified policy inputs for configured platforms are cached from the
catalogue. This is a cache budget, not a process RSS cap: signature verification
and JSON parsing also require transient memory.

OCI metadata has fixed bounds: 1 MiB indexes/manifests, 256 KiB configs, at most 64
index descriptors and at most eight configured platforms. Only an index, its
per-platform manifest, one config and one gzip bottle layer are supported. Nested
indexes, foreign/external URLs, malformed identities, unknown namespaces and
unsupported media types are rejected. No generic URL proxy is exposed. Descriptor
sizes and small-object hashes are verified before observation. Raw metadata is
served byte-for-byte without compression. Metadata range requests may return the
complete representation; bottle ranges retain the upstream 206/416 semantics and
verified total size.

The upstream defaults to `https://ghcr.io`; the signed API defaults to
`https://formulae.brew.sh/api`. Configuration permits only these official endpoints
or explicit loopback fixtures. General `upstream.allow_http` and artifact host
settings do not widen Homebrew permissions. Anonymous Bearer tokens are scoped to
one repository's pull access, coalesced in memory, bounded by expiry, and never
saved to SQLite or logs. Challenges require the upstream's `/token` realm and the
expected service/scope. Only same-origin redirects and GHCR's exact
`pkg-containers.githubusercontent.com` HTTPS CDN are accepted; authorization is
stripped at an origin boundary. Client credentials are rejected, except the
ignored `Bearer QQ==` placeholder. Tokens and redirects never reach the client.

Bottles stream with backpressure and permits held through completion. Middles
cannot verify an entire bottle before delivering its first byte; Homebrew retains
its signed checksum verification. Completed full and range transfers count in
`/stats?ecosystem=homebrew`. API/index/manifest/config traffic, HEAD, denials,
interrupted streams and invalid-length completions do not count. Release keys
include revision, rebuild, platform and content/definition identity.

Evidence/observation rows are deliberately not evicted by `cache.disk_mb`, which
budgets response payloads only. Ledger disk usage grows with distinct verified
releases, separately from cache accounting; inspect `homebrew_evidence` and
`first_seen` when planning storage. There is no persistent bottle storage or
background crawl.

## Diagnostics and verification

Denials return registry-shaped JSON with the formula, platform and eligibility
time, and a warning in middles logs. The tested Homebrew client shows HTTP 403
and the URL, but omits the policy response body. Inspect middles logs for the
reason. Nonzero effective monthly-download policies and `install_hooks = "deny"`
are configuration errors when enabled. A report override means execution evidence
is incomplete, never a claim that bottles have no post-install hooks. No Homebrew
analytics metric is substituted for downloads.

The [initial compatibility record](compatibility.md) documents routing, cache and
source bypasses. To rerun the actual adapter test with isolated Homebrew/client
caches and public GHCR access:

```sh
python3 scripts/homebrew-spike.py --repository /opt/homebrew \
  --api-tag arm64_tahoe --fixtures /tmp/brew-fixtures --output /tmp/brew-spike \
  --prepare
just homebrew-smoke --repository /opt/homebrew \
  --fixtures /tmp/brew-fixtures --output /tmp/brew-adapter-smoke
```

The smoke test starts a disposable middles database, serves an unchanged signed
API snapshot from a loopback fixture, and uses official GHCR artifacts with the
production signature key. It first denies/warm-observes at seven days, restarts
with an explicit zero-day policy to install eligible bottles, then restores seven
days and confirms a cold fetch is denied after restart. It never alters timestamps
or the developer's Cellar. A curl guard records destinations and prevents tested
client requests from escaping directly to upstream artifacts; it is test
instrumentation, not an operating-system egress firewall. Fully cached fetches
remain invisible to middles. No bypass is claimed to be retroactively enforced.
