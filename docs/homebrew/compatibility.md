# Homebrew compatibility gate

The [Homebrew support plan](../plans/homebrew-support.md) requires a compatibility
spike before production work. The first spike is implemented in
[`scripts/homebrew-spike.py`](../../scripts/homebrew-spike.py). The decision is
**NO-GO for releasing the full proposed scope with the proposed client setup**.
That decision is historical and applies to the full environment-only contract.
A [scoped official-bottle adapter](README.md) is now implemented, disabled by
default, following the accepted narrower guarantee: enforce requests that reach
middles and document source/cache bypasses. The [adapter smoke report](traces/adapter-2026-09-29/report.json) records real installs through middles.

## Recorded matrix

| Client source | Platform | Result |
| --- | --- | --- |
| Homebrew 7.0.6, commit `4135badeddc3899aa2e89d3ea1caee320c55d299` | macOS 26.7, arm64, `arm64_tahoe`, disposable non-default prefix | Eligible official bottles and dependencies work; full gate remains closed |
| Earlier Homebrew versions | All | Untested; not supported |
| Homebrew 7.0.6 | Linux arm64/amd64 | Untested; not supported |

The code and current portable Ruby were copied without modifying Homebrew source
or trust keys. The copy excludes the original Git directory and therefore labels
its User-Agent `Homebrew/4.X.Y`; the report records the source checkout's actual
version and commit separately. This is a Tier 3, non-default-prefix experiment,
not a default-prefix CI release qualification. Install probes use `--force-bottle`
to separate bottle transport from prefix relocation decisions. **7.0.6 is a tested
candidate, not a declared minimum supported production version.**

[The machine-readable report](traces/2026-09-29/report.json),
[request traces](traces/2026-09-29/requests.jsonl),
[curl destinations](traces/2026-09-29/egress.jsonl), and individual command outputs
are committed. [Input sizes and hashes](traces/2026-09-29/inputs.json) identify
public snapshots; large API payloads and bottle archives are not committed.
Concurrent request ordering can vary on reruns.

| Probe | Observed result |
| --- | --- |
| Fresh denied `hello` install | Index GET, then two denied blob GETs; exit 1; no upstream bottle retry |
| Warm metadata, cold bottle retry | Two denied blob GETs without an index request; exit 1 |
| Eligible `hello` install | Blob GET succeeded; checksum verification and bottle pouring succeeded |
| Fully cached `hello` fetch against a denying fixture | Exit 0 with no fixture requests |
| Eligible `zstd` install | `zstd`, `lz4`, and `xz` indexes/blobs fetched; all three bottles poured |
| Source fetch with both artifact variables set | Original GNU source URL and raw GitHub formula URL attempted; separate test curl guard rejected them |
| Unsupported `arm64_big_sur` bottle tag | Exit 0, warning only, no fixture requests |
| Missing bottle | Fixture 404s, exit 1, no original GHCR retry |
| Upstream failure | Fixture 503s, exit 1, no original GHCR retry |
| Versioned `openssl@3` | Requests used `homebrew/core/openssl/3`; fixture returned 404s; exit 1 |

The denied response contained `bottle minimum age; eligible in 7 days` in a
registry-shaped JSON body. Homebrew displayed the URL and HTTP 403, **not the
policy body**. A production adapter needs middles diagnostics to explain denials.
The smoke server models eligibility as an explicit mode; it does not implement
or test an age ledger.

## Protocol decisions and open gates

- With `HOMEBREW_ARTIFACT_DOMAIN=http://127.0.0.1:PORT/homebrew`, GHCR bottle paths
  become `/homebrew/v2/homebrew/core/...`. The tested client did not probe `/v2/`.
- Index requests negotiate `application/vnd.oci.image.index.v1+json`. Bottle
  requests use `*/*`. No child manifest or config was requested by the client.
  One dependency's blob arrived before its index. Every blob must therefore be
  authorized independently; a prior client metadata request cannot be required.
- No Authorization header was sent to the artifact domain in this setup. A future
  adapter should ignore the known `Bearer QQ==` placeholder and reject other
  client credentials, never forwarding either upstream.
- The current client uses `internal/packages.arm64_tahoe.jws.json`, not only
  `formula.jws.json`. Both downloaded snapshots were checked with the client's
  unchanged `api/homebrew-1.pem`: `homebrew-1`, PS512, unencoded UTF-8 payload,
  `crit: ["b64"]`, SHA-512 PSS salt length 64. Homebrew also performed its own API
  verification. Preparation accepts at most 64 MiB per API object; the recorded
  formula JWS exceeds the proxy's default 32 MiB metadata limit. Any future
  adapter must explicitly settle its signed endpoint and separate size budget.
- Index descriptors contain `sh.brew.bottle.digest`, child manifest digests, and
  platform-specific annotations. Preparation matches the selected signed API
  checksum to an index annotation and verifies downloaded bottle bytes. It does
  **not** validate the complete child/config graph or establish production
  evidence; that work remains gated.
- `hello`'s rebuild maps to tag `2.12.3-1`; `zstd`'s formula revision maps to
  `1.5.7_1`; `openssl@3` maps to repository `openssl/3`. Homebrew also translates
  `+` in formula names to `x`; generic SemVer parsing is insufficient.
- Bootstrap was avoided by copying an already provisioned portable Ruby. Its
  GHCR artifact is a separate ancillary download, not an ordinary signed core
  formula bottle. No unrestricted artifact proxy was added to admit it.

The source bypass was recorded despite both proposed artifact variables being
set. Homebrew 7.0.6's `CurlDownloadStrategy` rewrites GHCR URLs but leaves these
source URLs unchanged. This is narrower than the current environment reference's
description of prefixing all download URLs. Source Ruby downloads also have their
own strategy. `NO_FALLBACK` cannot reject a request that never reaches middles.

These observations **do not demonstrate an escape by a denied official bottle**:
the tested bottle denials, 404s, and 503s stayed at the fixture. They demonstrate
that the environment variables alone cannot provide the plan's explicit rejection
of unsupported downloads, and that cached downloads are invisible. The plan
already anticipates controlled configuration and egress; that deployment contract
must be made concrete before claiming the whole scope works.

The original next steps for the full installation-wide contract were: provision bootstrap
artifacts separately, control bottle-only commands and supported platforms, and
provide actual managed egress controls for excluded source/cask/tap/HEAD traffic.
Alternatively, narrow the guarantee explicitly to authenticated official bottle
requests that reach middles. Then rerun the gate on disposable default-prefix CI
installations with upgrade/rebuild, timeouts, casks, taps, HEAD, bootstrap, and Linux
cases. A missing-bottle-tag `fetch` is only a client probe, not an unsupported-OS
installation test. Neither the test curl guard nor this report is an installation
firewall. The scoped adapter now implements transport, signed evidence, local age policy,
warming and downloads. The broader release matrix remains incomplete.

## Reproduce

Requires Python 3.9+, OpenSSL, curl, and an existing Homebrew source checkout with
portable Ruby already provisioned. The script only reads that checkout; its
installation, caches, Cellar, and home are disposable. Use fresh, separate fixture
and output directories outside the Homebrew installation:

```sh
# Explicit public network access, bounded downloads, signature/checksum checks.
python3 scripts/homebrew-spike.py \
  --repository /opt/homebrew --api-tag arm64_tahoe \
  --fixtures /tmp/middles-brew-fixtures --output /tmp/middles-brew-traces \
  --prepare

# Offline client runs; only exact objects on the loopback fixture can be served.
python3 scripts/homebrew-spike.py \
  --repository /opt/homebrew --api-tag arm64_tahoe \
  --fixtures /tmp/middles-brew-fixtures --output /tmp/middles-brew-traces

# Deterministic harness checks; no public network or Homebrew required.
python3 -m unittest discover -s scripts -p 'test_homebrew_spike.py'
```

Select the matching API tag for your platform. Linux runs are not yet qualified;
the four-formula fixture may need additional explicit dependencies there. The
spike exits 1 for NO-GO or an incomplete matrix, writing `report.json` and command
outputs. Preparation exits 0 on success. It never changes signed payloads or
requires Homebrew signature verification to be disabled. Refresh all snapshots
with `--prepare` if upstream metadata changes.

The curl guard records sanitized URLs, denies non-fixture origins, disables curl
configuration/proxies, and disallows redirects during client tests. It covers the
curl path exercised by these probes, not subprocesses using other networking
libraries or Git. HTTP responses contain only prepared objects from four exact
repositories; arbitrary URL paths and unknown digests return 404. Tokens and
redirect query signatures are excluded from recorded traces. API and bottle
snapshots consume temporary disk space; the fixture copies the current Ruby
runtime and deletes its disposable installation at exit.

References: [Homebrew environment variables](https://docs.brew.sh/Manpage#environment),
[Homebrew signature verification](https://docs.brew.sh/Homebrew-Security-and-Supply-Chain),
[client curl strategy](https://github.com/Homebrew/brew/blob/7.0.6/Library/Homebrew/download_strategy/curl_download_strategy.rb),
[client API verification](https://github.com/Homebrew/brew/blob/7.0.6/Library/Homebrew/api.rb).
