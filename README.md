# middles

A focused Rust registry proxy for npm, pip/PyPI, Composer 2, and RubyGems through Bundler. It filters out releases younger than your policy allows, optionally requires a minimum monthly download count where evidence is available, and rechecks policy when serving package archives. A [Docker registry proxy](docs/plans/docker-registry-proxy.md) is planned.

One binary, no external database or background registry crawl. Tokio + Axum serve requests, reqwest pools upstream connections, Moka holds hot metadata, and SQLite persists metadata and download statistics locally. Archives stream with backpressure and are not stored or buffered in full.

## Run

Requires current stable Rust and a C toolchain to build bundled SQLite.

```sh
cargo build --release --locked
cp middles.example.toml middles.toml
./target/release/middles --config middles.toml --check
./target/release/middles --config middles.toml
```

Without `--config`, it listens on `127.0.0.1:8080`, requires seven days of age, disables download thresholds, and uses `data/cache.sqlite3`. `GET /healthz` reports process health. Set `RUST_LOG=middles=debug,tower_http=debug` for request logging. SIGINT and SIGTERM initiate graceful shutdown.

Set `public_url` to the address clients can reach. All rewritten archive URLs use this configured value, never the request's Host header. A reverse proxy may mount the service under a prefix if it strips that prefix before forwarding. Restart to apply configuration changes; cached raw metadata is evaluated using the new policy immediately.

## Run with Docker

Build and start with Docker Compose v2:

```sh
docker compose up --build --detach --wait
curl --fail http://127.0.0.1:8080/healthz
docker compose logs --follow
docker compose down
```

The container listens on `0.0.0.0:8080`; Compose publishes it only on the host's
`127.0.0.1:8080`. It runs as UID/GID `10001:10001` with a read-only root filesystem.
The named `middles-data` volume stores SQLite and its WAL files at `/var/lib/middles`.
`docker compose down` preserves that volume. **Do not use `down --volumes` unless
you intend to delete cached data and restart Composer's first-observation waiting periods.**

The image includes [middles.docker.toml](middles.docker.toml), and Compose mounts
that file read-only by default. To customize policy or the client-visible URL:

```sh
cp middles.docker.toml middles.local.toml
# Edit middles.local.toml; add policy/upstream settings from middles.example.toml.
MIDDLES_CONFIG=./middles.local.toml docker compose up --detach --force-recreate --wait
```

Keep `listen = "0.0.0.0:8080"` and `cache.path = "/var/lib/middles/cache.sqlite3"`
when using this setup. Set `public_url` to the address clients actually use:
`http://127.0.0.1:8080` for host clients, a reachable service hostname for clients
in another container, or your external HTTPS URL behind ingress. Other containers'
loopback addresses refer to themselves. If you change the published host port,
update `public_url` too. For shared access, configure authenticated HTTPS ingress
as described under Deployment boundary. Configuration is TOML; `MIDDLES_CONFIG`
selects the Compose mount, and `RUST_LOG` controls logging. There are no implicit
environment overrides for policy settings. Recreate the container to apply edits.

Validate your mounted configuration without starting the service:

```sh
docker compose run --rm middles --config /etc/middles/middles.toml --check
```

Plain Docker works too:

```sh
docker build --tag middles:local .
docker volume create middles-data
docker run --detach --name middles \
  --publish 127.0.0.1:8080:8080 \
  --mount type=volume,src=middles-data,dst=/var/lib/middles \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  middles:local
```

To override configuration with plain Docker, add
`--mount type=bind,src="$PWD/middles.local.toml",dst=/etc/middles/middles.toml,readonly`
before the image name. Passing CLI arguments replaces the image's default
arguments, so include `--config /etc/middles/middles.toml` when adding `--check`.
The image health check probes `/healthz` on port 8080; override it if you change
the internal listening address. This endpoint reports process health, not upstream
registry availability.

Fresh named volumes inherit the image's writable data-directory ownership. If
you use a host directory instead, create it with ownership `10001:10001` and ensure
the mounted configuration is readable by that user. Keep one service instance
per data volume. To back up, stop the service and copy the **entire** data directory
(including any `-wal` and `-shm` files), then start it again. Restore into an empty
volume while the service is stopped and preserve UID/GID `10001:10001`.

After updating the source, rebuild and recreate with
`docker compose up --build --detach --wait`; keep the same Compose project name
and volume to preserve history. Images are built locally; no published image is
required. The builder pins Rust to a patch version and builds the locked Cargo
dependencies; update the builder tag deliberately when upgrading Rust.

`just docker-build`, `just docker-up`, and `just docker-down` wrap these commands.
Run `just docker-test` to build and check configuration validation, non-root
execution, health, graceful shutdown, and durable SQLite/Composer history. These
checks require Python 3 and a local Docker daemon and use a temporary local HTTP
fixture, container, and volume. Building the image downloads base images and build
dependencies; the smoke checks do not contact public package registries.

## Client setup

### npm

```sh
npm install --registry=http://127.0.0.1:8080/npm/ --no-audit
```

Or add to the project's `.npmrc`:

```ini
registry=http://127.0.0.1:8080/npm/
audit=false
```

Scoped packages, exact versions, distribution tags, and conventional npm tarball paths are supported. If `latest` is too young, it resolves to the highest eligible stable version no newer than upstream `latest`. Other blocked tags are removed. Publishing, login, search, npm audit, and private registry authentication are outside this initial scope. Disabling npm audit does not provide a replacement vulnerability scanner.

### pip

```sh
python -m pip install --index-url http://127.0.0.1:8080/pip/simple/ requests
```

Or set `PIP_INDEX_URL=http://127.0.0.1:8080/pip/simple/`. Use this as the sole index; an extra index is another resolution source. Modern JSON Simple API and HTML clients are supported, including hashes, `requires-python`, yanked flags, and PEP 658 core metadata. Policy applies to each individual uploaded file, including new wheels added to an older release. Files without upload times are hidden.

### Composer 2

Merge this into `composer.json`:

```json
{
  "repositories": [
    {"type": "composer", "url": "http://127.0.0.1:8080/composer/"},
    {"packagist.org": false}
  ],
  "config": {"secure-http": false, "preferred-install": "dist"}
}
```

`secure-http: false` is only for the localhost example. Use HTTPS and retain Composer's secure HTTP default for a shared deployment. Disable the default Packagist repository as shown. Distribution archives and metapackages are supported. Source-only packages and mutable development branches are excluded. Source fallback and dist mirrors are removed from emitted metadata so a fresh resolution uses the proxy's archive endpoints.

**Composer has an initial waiting period.** Packagist's `time` is VCS-derived, not a trustworthy publication timestamp. A release must satisfy both its reported age and the time since this proxy first observed its version, time, source, and dist identity. Changing that identity starts a new waiting period. The first request for a package records its releases, even if all are blocked. Warm required packages by fetching `/composer/p2/vendor/package.json`, then wait the configured number of days. There is no automatic full-registry crawler. Persist and back up the SQLite database; losing it restarts these waiting periods. Setting `[composer] min_age_days = 0` explicitly disables this waiting period for local compatibility testing.

### RubyGems / Bundler

Use the proxy as the Gemfile's source:

```ruby
source "http://127.0.0.1:8080/rubygems/"
gem "rake"
```

Then run `bundle install`. Use HTTPS for shared deployments. Replace other RubyGems sources and regenerate affected lockfiles through the proxy; existing installations, cached gems, and direct Git/path sources can bypass it.

The adapter implements Bundler's dependency API plus conventional gemspec and `.gem` downloads. `/versions` intentionally returns 404 so Bundler uses the dependency API; no partial global compact index is published. Upstream compact `/info` metadata is fetched only for requested gems. Publication `created_at` is evaluated separately for each version/platform, and missing or invalid times fail closed. Blocked gemspecs and direct archive requests are denied again, including requests from lockfiles. Ruby and RubyGems requirements are read by Bundler from the eligible gemspec; the dependency API does not carry compact-index artifact checksums to the client.

Fresh installs, repeat installs, native-platform selection, blocked stale lockfiles, and warm-cache updates are verified with Bundler 2.4.22 on Ruby 2.6.10. Bundler 4.0.21's source retains the same fallback, but that runtime has not been verified locally. Standalone `gem install`, full-index mode, search, publishing, and private registry authentication are not claimed as supported.

RubyGems has no configured monthly-download evidence provider or install-hook inspection. Nonzero monthly thresholds and `install_hooks = "deny"`, including inherited values, fail configuration validation. If your global policy enables either restriction, explicitly opt RubyGems out to use this adapter:

```toml
[rubygems]
min_monthly_downloads = 0
install_hooks = "report"
```

`report` does not inspect gem contents or establish that installation is free of code execution; native extensions may run build code. There is currently no `/inspect/rubygems/` endpoint. The adapter never evaluates Ruby gemspecs or deserializes upstream Marshal objects itself. See the [implementation notes and remaining work](docs/plans/rubygems-support.md).

## Policies

```toml
[policy]
min_age_days = 7
min_monthly_downloads = 0

[npm]
min_monthly_downloads = 1000

[pip]
min_age_days = 14
min_monthly_downloads = 500

[composer]
min_age_days = 7
```

Unspecified ecosystem values inherit the global policy. A day is exactly 86,400 seconds, measured in UTC; the age boundary is inclusive. Missing, invalid, and future timestamps fail closed, including when the configured age is zero. Download count zero disables statistics lookups entirely. Package names and paths are validated before contacting upstreams.

| Ecosystem | Age evidence | Optional download evidence |
| --- | --- | --- |
| npm | Registry publication time for the version | npm's last 30 available days, all versions combined |
| pip | Simple API upload time for each file | PyPI Stats `last_month`, package-wide |
| Composer | Reported time plus durable local first observation | Packagist `monthly`, package-wide |
| RubyGems | Compact info publication `created_at`, per version/platform | Unavailable; effective threshold must be zero |

Monthly windows follow each provider's semantics; they are not a single synchronized measurement. Counts are popularity signals, not unique users, evidence of safety, or downloads of the selected version. Missing statistics, malformed responses, rate limits, and upstream failures deny access when a threshold is enabled. The service does not substitute a fabricated zero or serve expired data on failure.

## Local download statistics

`GET /stats` reports packages downloaded through this middles instance, with
totals, per-ecosystem counts, and a paginated list of releases ordered by their
most recent transfer:

```sh
curl 'http://127.0.0.1:8080/stats'
curl 'http://127.0.0.1:8080/stats?ecosystem=npm&package=esbuild'
curl 'http://127.0.0.1:8080/stats?limit=50&offset=50'
```

Each release includes `ecosystem`, `package`, `release`, `full_downloads`,
`range_transfers`, `bytes`, `first_download`, and `last_download`. Totals also
include distinct `packages` and `releases`; the same package name in two
ecosystems counts separately. For RubyGems, `release` includes the platform suffix for non-`ruby` gems. For npm and Composer, `release` is the version;
for Python it is the exact wheel or source filename. Timestamps are Unix seconds
in UTC, and first/last timestamps are null when no transfers have been recorded.
The optional `ecosystem` and exact `package` filters apply to the entire report;
`limit` (default 100, maximum 1000) and `offset` only paginate the release list.
Scoped npm names can be supplied with `curl --get --data-urlencode 'package=@scope/name'`.

These are **observed archive transfers, not confirmed installations**. A full
download counts a completed HTTP 200 body; a completed HTTP 206 body counts only
as a range transfer. Bytes include both kinds of completed transfers. Metadata
lookups (including Python core metadata), HEAD requests, policy denials, upstream
errors, and streams interrupted before completion do not count. Completion means
the proxy read the full body for its response stream, not that the
client acknowledged or installed it. Retries count again; client cache hits,
Composer metapackages, and downloads bypassing middles are invisible. No client
identities, IP addresses, or project names are collected.

Collection starts with this feature; previous downloads cannot be reconstructed
from the metadata cache. Aggregates persist in the existing SQLite database across
restarts and response-cache eviction, with one row per observed package/release.
They have no automatic expiry and are outside `cache.disk_mb`. Failed statistics
writes log a warning without failing the archive transfer. This endpoint uses
`Cache-Control: no-store` and the same access boundary as the registry endpoints;
protect shared deployments with authenticated ingress. Local transfer counts are
independent of the upstream monthly popularity counts used by policy.

## Install-hook inspection

Use the read-only inspection endpoint to see script definitions and execution signals available in cached registry metadata. It does not download archives or execute package code. An exact version is required for npm/Composer; Python inspection selects an exact filename because wheels and source distributions have different behavior:

```sh
curl 'http://127.0.0.1:8080/inspect/npm/esbuild?version=0.25.0'
curl 'http://127.0.0.1:8080/inspect/npm/@scope/package?version=1.0.0'
curl 'http://127.0.0.1:8080/inspect/composer/vendor/package?version=1.0.0'
curl 'http://127.0.0.1:8080/inspect/pip/six?filename=six-1.17.0.tar.gz'
```

Reports include the original `scripts` object when available, hook findings with execution context, `dependency_execution`, and explicit inspection limitations. Custom script definitions are retained so references such as `npm run build` or Composer's `@build` can be reviewed. No commands are resolved or executed. `status: not_reported` is not a safety verdict; `scripts: null` means definitions were not supplied by this metadata. Inspection remains available for blocked packages, evaluates only the hook policy, and confers no artifact access (`other_policies_evaluated: false`).

```toml
[policy]
install_hooks = "report" # default: no hook-based blocking

[npm]
install_hooks = "deny"

[composer]
install_hooks = "deny"

[pip]
install_hooks = "deny"
```

Each ecosystem inherits the global setting unless overridden. In `report` mode, use the endpoint to inspect; there is no per-request script logging. In `deny` mode:

| Ecosystem | Inspection | Rejected as dependencies |
| --- | --- | --- |
| npm | `preinstall`, `install`, `postinstall`; contextual `prepare`, `preprepare`, `postprepare`, `prepublish`; `hasInstallScript` and `gypfile` indicators | Reported dependency install scripts or native-build indicators, including malformed hook metadata. Contextual hooks alone are reported but not rejected. |
| Composer | Available script definitions, plugin/installer package type and plugin class | `composer-plugin` and legacy `composer-installer` packages. Ordinary dependency `scripts` alone do not cause rejection because Composer only executes root-project scripts. |
| pip | Wheel versus source-distribution classification | All non-wheel files, conservatively preventing source builds through this index. This does not claim that a particular source archive contains a postinstall script. |

Blocked releases/files are removed from resolution metadata and rejected again at artifact access, including conventional npm tarball paths and Python `.metadata` requests. Reports reuse the existing raw metadata cache; changing policy takes effect after restart without clearing the cache.

**Coverage limits:** npm registry metadata can differ from the archive's `package.json`, and implicit `binding.gyp` hooks can be unreported. Packagist p2 metadata may omit script definitions, and the proxy cannot see your root `composer.json`. PyPI's Simple API does not expose `pyproject.toml`, `setup.py`, or build-backend definitions. Wheel contents, `.pth` files, plugin code, referenced script bodies, and runtime behavior are not analyzed. This is fast metadata inspection with optional rejection of reported execution signals, not archive verification, malware classification, or a guarantee of no code execution. Retain client-side script/plugin controls where needed.

Execution semantics: [npm lifecycle scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts/), [Composer root-only scripts](https://getcomposer.org/doc/articles/scripts.md), [Composer plugins](https://getcomposer.org/doc/articles/plugins.md), and [pip build-system hooks](https://pip.pypa.io/en/stable/reference/build-system/).

## Cache and performance

- Hot JSON and RubyGems text metadata share a configurable approximate weight budget: 64 MiB by default, split 75% metadata / 25% statistics. Accounting estimates parsed JSON at four times its encoded size; this is not a hard process RSS limit.
- SQLite uses WAL, prepared ledger statements, indexed expiry/eviction, and a small page cache. Blocking database work runs outside the async workers. A 512 MiB default response budget includes payloads and estimated entry overhead; deleted pages are reused. The physical database, indexes, WAL, and Composer safety ledger can exceed this budget.
- Concurrent misses for the same upstream URL share one fetch. Defaults: metadata freshness 5 minutes, statistics freshness 24 hours. Disk hits keep their original expiry. Policy is recalculated on every request, so releases age into eligibility without waiting for metadata refresh.
- Successful index metadata responses persist across restarts. Errors are cached in memory for 30 seconds to reduce repeated failed requests. HTTP 404 remains 404; policy denial is 403; unverifiable/upstream failures are 502. An all-filtered pip/Composer/RubyGems listing is empty, allowing clients to report no matching version.
- Upstream concurrency defaults to 32, applied as separate permit pools for metadata fetches and archive streams so slow archive clients cannot starve resolution. Archive streams retain their permit until completion/disconnect and forward range requests. RubyGems dependency requests fetch per-gem info concurrently within the metadata pool. Metadata responses are bounded at 32 MiB after decompression. Archives use read-idle timeouts and preserve upstream bytes.
- No background polling, archive cache, Redis, or mandatory statistics traffic. This is an initial implementation, not a published throughput benchmark.

A five-minute metadata cache also means upstream deletions or changed metadata can take that long to be noticed. Set a shorter TTL when needed. Policy-bearing responses use `Cache-Control: no-store`; package managers can still maintain their own installed-package and artifact caches.

## Deployment boundary

This is an explicit registry proxy, not an intercepting network firewall. Existing lockfiles with direct upstream URLs, client artifact caches, direct URL/VCS dependencies, other repositories, and Composer plugins can bypass it. For organization-wide enforcement, route package access through this service, regenerate affected lockfiles through it, control alternate sources, and enforce network egress separately. Client credentials are not forwarded upstream.

It binds to loopback by default and has no built-in user authentication. Put shared installations behind authenticated HTTPS ingress. Archive destinations and every redirect must match an exact host in `upstream.artifact_hosts`; arbitrary user-provided URLs are never accepted as fetch targets. Keep that allowlist limited to trusted public archive hosts. HTTPS is required upstream unless `allow_http = true` is explicitly set for local mocks. Custom registry base URLs are trusted operator configuration. No automatic discovery of arbitrary hosts or forwarding of upstream notification hooks is performed.

## Development

With `just` installed, run `just` to list recipes:

```sh
just build                      # Development binary
just release                    # Optimized binary
just check                      # Check compilation
just fmt                        # Format sources
just ci                         # Formatting, Clippy, tests, and config validation
just test --test proxy          # Run one test target
just run --config middles.toml   # Start with a configuration file
just config-check middles.toml  # Validate without starting
just smoke                      # Opt-in live registry/client checks
```

`just docs` generates API documentation; `just clean` removes build artifacts while preserving the proxy cache. Cargo can also be used directly:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

For an opt-in live compatibility check, build the binary and run `python3 scripts/smoke.py` with npm, pip, and Composer installed. It installs/downloads small public packages into a temporary directory with scripts/plugins disabled and isolated caches. It explicitly sets Composer's age to zero to test fresh-cache installation; deterministic tests separately verify its waiting period.

Run `just ruby-smoke` for local-only RubyGems/Bundler compatibility checks with inert generated gems and isolated caches. Requires Ruby, RubyGems, Bundler, and Python 3. Set `BUNDLE_COMMAND` to select a Bundler executable. Set `MIDDLES_SMOKE_RUBYGEMS=1` when running the multi-registry live smoke test to include a public Ruby gem.

Tests use local HTTP fixtures and temporary SQLite databases. They cover age boundaries, missing timestamps, npm tag fallback and scoped packages, blocked direct archives, Python per-file filtering and core metadata, Composer delta expansion and durable first observation, download thresholds, restart behavior, concurrent cache misses, expiry, eviction, range requests, and redirect allowlisting.

Registry-specific parsing, filtering, URL rewriting, and artifact lookup live in `src/registry/`. Shared policy, caching, downloads checks, and streaming live outside the adapters. RubyGems uses a request-driven dependency adapter; its global compact index and legacy full indexes are deliberately unsupported.

The isolated [stats write benchmark](benchmarks/stats/README.md) compares SQLite,
redb, and Fjall with atomic counters and recent-download indexes. Run it with
`just bench-stats --help`; see the [measured results](docs/benchmarks/stats-write-benchmark.md)
for throughput, latency, durability settings, and workload limitations.

## Protocol references

- [npm package metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md) and [download counts](https://github.com/npm/registry/blob/main/docs/download-counts.md)
- [Python Simple repository API](https://packaging.python.org/en/latest/specifications/simple-repository-api/) and [PyPI Stats API](https://pypistats.org/api/)
- [Composer repository protocol](https://getcomposer.org/doc/05-repositories.md), [Composer schema](https://getcomposer.org/doc/04-schema.md), and [Packagist statistics](https://packagist.org/apidoc)

RubyGems references: [compact index metadata](https://guides.rubygems.org/rubygems-org-compact-index-api/), [publication and download APIs](https://guides.rubygems.org/rubygems-org-api/), and [native extensions](https://guides.rubygems.org/specification-reference/#extensions).
