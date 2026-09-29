# APT support plan

Status: implemented (2026-09-29). The real-client compatibility spike in section 1 was
the go/no-go gate before adapter work. The accepted direction is byte-for-byte
passthrough of all signed index material with minimum-age policy enforced only on
binary `.deb` pool access, using durable local first observation as the age basis.
Filtering or re-signing `Packages` is rejected: it breaks the "never rewrite signed
payloads" doctrine and would require operating a trusted signing key. A time-delayed
snapshot view is also rejected: superseded pool files disappear upstream, so serving
an aged index would require storing archives, and middles is not a mirror.

## Goal and first-release scope

Let `apt-get update`, `install`, and `upgrade` work against
`deb http(s)://<middles>/apt/<repo-name> <suite> <components>` sources, with GPG
verification of `InRelease`/`Release.gpg` remaining entirely client-side against the
keys already trusted by the machine. middles neither verifies nor re-signs archive
signatures; it must never alter a byte under `dists/`.

Start with binary packages (`.deb`, including `Architecture: all`) from explicitly
configured (repository, suite, component, architecture) tuples on Debian and Ubuntu
style archives. Exclude `deb-src` downloads (`.dsc`, `.orig.tar.*`), `.udeb` and
debian-installer files, flat repositories without `dists/`, old-style
`stable/updates` suite paths, `Contents-*` files beyond the index size bound, and
mirror auto-discovery. Unsupported requests must fail explicitly. Keep existing
adapters working and retain bounded, request-driven metadata caching and streamed
artifacts.

Unlike npm, the adapter cannot select an older eligible version: Debian and Ubuntu
remove superseded stanzas from `Packages`, so a package updated more recently than
the waiting period is uninstallable in any version until the new release ages in.
One blocked archive also aborts the entire apt transaction, because apt downloads
all archives before installing any. Both consequences must be documented for
operators; the per-repository age override in section 2 exists because this is most
acute for `-security` suites. See the
[Debian repository format](https://wiki.debian.org/DebianRepository/Format).

## 1. Establish real-client compatibility before production work

Build an isolated fixture: a tiny local repository containing inert `.deb` files
(built with `dpkg-deb`, no maintainer scripts), a generated `Packages` index, and an
`InRelease` clearsigned with a throwaway GPG key installed into the client's
`/etc/apt/trusted.gpg.d`. Drive a real apt client in disposable Debian and Ubuntu
containers through a recording passthrough, and commit traces, a supported-client
matrix, and a pass/fail decision to `docs/apt/` before any adapter work.

The fixture must resolve these implementation gates:

- Exactly which files does `apt-get update` fetch, in what order? Expected:
  `InRelease`, falling back to `Release` plus `Release.gpg` on 404; then the index
  files named in the Release hash list. apt performs no content negotiation — it
  requests the exact compressed filename it selected (`Packages.xz`, `Packages.gz`).
  Confirm that middles' 404 mapping preserves the InRelease fallback and the
  "Ign" tolerance for missing `Translation-*` files.
- Debian and Ubuntu advertise `Acquire-By-Hash: yes`, so stock clients fetch
  indexes as `dists/<suite>/<component>/binary-<arch>/by-hash/SHA256/<hex>`.
  Confirm plain passthrough suffices and record how by-hash naturally heals
  cache skew between a refreshed `InRelease` and a stale named index.
- Do repeated updates use `Packages.diff/` pdiffs, `If-Modified-Since`, or `Range`
  requests, and does apt accept always-200 full responses for each? Record the
  cost of 200-always for daily update crons.
- What does the user see when a `.deb` download is denied with 403 during
  `install` and `upgrade`? apt is expected to abort with
  `E: Failed to fetch <uri> 403 Forbidden` and to discard the response body, so
  policy reasons would be visible only in middles diagnostics. Record the exact
  client output; the usefulness of denial messages depends on it.
- Which ancillary files do stock configurations fetch (`Translation-*`,
  `cnf/Commands-*`, `dep11/` metadata and icon tarballs) and what sizes must the
  passthrough bound accommodate?
- Does any client configuration send an `Authorization` header to the proxy?
  Decide whether middles rejects it outright, homebrew-style.

Deliver recorded traces under `docs/apt/traces/`, a compatibility record at
`docs/apt/compatibility.md` with a minimum supported apt version, and an explicit
go/no-go decision. If stock clients cannot meet the scoped guarantee, revise scope
before building the adapter.

## 2. Add a narrowly scoped APT adapter

Use the ecosystem key `apt` and a disabled-by-default `[apt]` configuration in the
rich Homebrew style: `enabled`, a flattened policy `Override`, an APT-specific
`max_index_mb` bound (default 96, because decompressed Ubuntu indexes exceed the
global metadata bound), and a list of named repositories:

```toml
[apt]
enabled = false
max_index_mb = 96

[[apt.repos]]
name = "debian"
url = "https://deb.debian.org/debian"
suites = ["bookworm", "bookworm-updates"]
components = ["main"]
architectures = ["amd64"]

[[apt.repos]]
name = "debian-security"
url = "https://deb.debian.org/debian-security"
suites = ["bookworm-security"]
components = ["main"]
architectures = ["amd64"]
min_age_days = 0
```

Each repository entry accepts an optional `min_age_days` override so operators can
let security suites flow while the main archive waits. When a requested `.deb` is
listed by more than one configured repository, the most permissive configured entry
that lists it applies: the operator explicitly trusted that entry. Clients use
`deb http://<middles>/apt/debian bookworm main`.

Mount one wildcard route `/apt/{*path}` from a `routes()` function merged after the
compression layer, as the Homebrew adapter does, so `dists/` bytes are never
transformed. Split `{repo-name}/{rest}` manually with strict validation. Support
GET and HEAD with identical authorization; reject other methods, query strings,
encoded separators, traversal, empty or dot segments, and `Authorization` headers.
Dispatch on the remainder: paths under `dists/` are bounded byte-preserving cached
passthrough via the raw cache; strictly valid paths ending in `.deb` are authorized
then streamed; everything else fails explicitly. Do not require a `pool/` prefix —
the `Filename` field is repository-root-relative and third-party layouts differ.
Never expose a generic URL fetch endpoint or accept a client-supplied upstream URL.

Configuration validation, gated on `enabled`: repositories non-empty with unique
route-safe names; upstream URLs HTTPS (or HTTP only under `upstream.allow_http` for
fixtures) without credentials, query, or fragment; every repository host present in
`upstream.artifact_hosts` so pool streaming stays on the single existing allowlist;
bounded, well-formed `suites`, `components`, and `architectures` lists; suites
containing `/` rejected while old-style layouts are unsupported.

## 3. Define release identity and age evidence

Use **durable local first observation of the stanza checksum** for the age policy.
Identity is the `SHA256` field of the `Packages` stanza — the content address of the
`.deb` — recorded through the existing durable first-seen ledger under keys shaped
`apt:{sha256}`, following the Composer precedent. The key is deliberately not
repository-qualified: the same bytes reachable through two configured entries share
one clock, because the wait measures content exposure time.

Observe eagerly: when an index is fetched and parsed, record first-seen for every
stanza in one transaction. Clocks therefore start at the first `apt-get update`
through middles and packages age in while nobody requests them — this is the
warming behavior, and a fresh deployment blocks everything for the full waiting
period until observed indexes age. Also observe idempotently at authorization time,
and record evidence even on a denied request so retries age into eligibility. Apply
the existing inclusive `min_age_days * 86_400` boundary and recompute policy on
every request; never cache an eligibility decision. Ledger rows are never deleted —
deletion must never shorten a wait, and retained rows let a stanza that reappears
keep its original clock. Losing the ledger restarts all waits; document backup
guidance with the Homebrew material.

Explicitly rejected as age evidence: the Release file `Date` and `Valid-Until`
fields, HTTP `Last-Modified`, and changelog or build timestamps inside packages.
None proves publication time.

A version replaced upstream disappears from the index; requests for its pool file
then fail closed as unknown even though its ledger row persists. A `Filename` whose
checksum changes across refreshes is a new identity with a new wait. The same
`Filename` carrying different checksums across configured suites at the same time
is denied as ambiguous rather than resolved.

## 4. Implement verified transport and artifact authorization

Fetch `Packages.xz`, then `Packages.gz`, then uncompressed `Packages` per configured
tuple under the metadata concurrency permits, bounded by `max_index_mb` before and
after decompression, with decompression and RFC822 stanza parsing on the blocking
pool. Parse only `Package`, `Version`, `Architecture`, `Filename`, `SHA256`, and
`Size`, all required, with strict charset and length validation; a corrupt stanza
fails the whole index closed rather than silently dropping enforcement. Cache the
derived `Filename → stanza` map through the existing JSON metadata cache under an
`apt-index-v1:` key that includes the repository URL, so TTL, miss coalescing,
memory weighting, disk spillover, and the failure cache all apply unchanged. This
requires new decompression dependencies: `flate2` for gzip and, for xz, `liblzma`
(the repository already accepts bundled C via rusqlite and ring) with pure-Rust
`lzma-rs` recorded as the fallback if avoiding new C code is preferred.

Authorize a `.deb` request by probing the derived maps of every configured tuple of
the named repository for an exact `Filename` match. If any index fetch fails,
propagate the upstream error rather than reporting the file unknown — never let an
upstream flake turn into a 404 or an unrestricted fetch. On a unique identity,
record observation, apply the effective age policy for the matching repository
entries, and on success stream from the configured upstream through the existing
artifact transport, which already provides the exact-host allowlist, redirect
re-checking, range and HEAD handling, backpressure, permits, and transfer
statistics. Denials return 403 with the package, version, age basis
`local_first_seen`, first-seen timestamp, and eligibility time in the body — apt
hides bodies, so also add a diagnostic route
`GET /apt/{name}/check/{*path}` returning the same evidence as JSON, mirroring the
Homebrew `warm/` endpoint.

Take the statistics identity from the stanza (`Version` keeps its epoch while
`Filename` omits it), shaped `{version}_{architecture}`, never from filename
parsing. Because middles fetches indexes over TLS from allowlisted hosts and the
client independently verifies every `.deb` hash against its own signed index, skew
between the two views yields at worst a client hash-sum mismatch and re-update,
never a policy bypass; state this trust argument in the operator guide.

## 5. Handle other policies and statistics explicitly

- **Monthly downloads:** no download-count provider exists for APT archives.
  Reject an enabled configuration whose effective `min_monthly_downloads` is
  nonzero, including inheritance, exactly as Homebrew does.
- **Install hooks:** maintainer scripts (`preinst`, `postinst`) live inside the
  `.deb`, which middles never unpacks, and they run as root on the client. Reject
  effective `install_hooks = "deny"`; permit an explicit `report` override that
  reports evidence as unavailable. Never claim absence of install-time execution.
- **Local statistics:** completed pool transfers record ecosystem `apt` with the
  stanza-derived release identity through the existing full/range semantics.
  Index passthrough, diagnostics, denials, and interrupted transfers do not count.
- **Caching interaction:** the metadata TTL must remain far below any suite's
  `Valid-Until` window (about seven days on Debian security suites) or clients
  report expired Release files; the default TTL is safe, but validate or document
  the constraint.

Validate all restrictions only when the adapter is enabled so adding it cannot
break existing configurations.

## 6. Test and release in milestones

1. **Compatibility spike:** the fixture, traces, client matrix, and go/no-go
   decision from section 1, including the recorded 403 experience and 200-always
   tolerance.
2. **Configuration and passthrough:** disabled-by-default configuration and
   validation, the `Ecosystem::Apt` variant and its forced dispatch arms, routes
   merged after compression, raw-cache enablement, bounded `dists/` passthrough,
   and unit plus adapter passthrough tests. No database schema change — the
   adapter reuses the existing response cache and first-seen ledger.
3. **Index parsing and pool authorization:** decompression dependencies, the
   stanza parser, the derived lookup cache, eager and per-request observation,
   authorization and streaming with statistics, per-repository override
   semantics, and the diagnostic route.
4. **Verification and documentation:** integration tests, an opt-in smoke script
   with a just recipe, the operator guide at `docs/apt/README.md` (sources.list
   setup, memory sizing for large components, the security-suite trade-off, and
   an explicit bypass statement: clients not pointed at middles, local apt
   caches, and already-downloaded archives are outside the enforcement
   boundary), and example configuration — documentation lands only when the
   feature works.

Deterministic tests must cover byte-identical passthrough including by-hash paths
and the InRelease fallback, disabled and unknown-repository 404s, method, query,
encoding, and authorization rejection, oversized and truncated indexes,
decompression bombs, inclusive age boundaries with a backdated ledger, denial
without byte leakage, ambiguity denial, vanished stanzas, upstream index failure
propagating as 502, xz-to-gz fallback, concurrent-miss coalescing, restart
persistence of first observation, range and HEAD on pool paths, and transfer
statistics. Adapter fixtures may serve an unsigned synthetic repository — middles
never inspects signatures, and byte-identity assertions plus the signed smoke
fixture carry the signature claim.

The smoke script follows the RubyGems pattern: local, inert, no public registry. A
Debian container builds inert `.deb`s, a signed repository with a throwaway key,
and asserts update-through-proxy with signature verification intact, a fresh
package blocked with the recorded failure output, the same package installing after
its clock ages, warm repeat updates, and an upgrade aborted by one blocked archive.

## Acceptance criteria

- Documented stock apt clients run `update`, `install`, and `upgrade` through
  middles with GPG verification intact; `dists/` responses are byte-identical to
  upstream, hash-verified in tests.
- A policy-blocked `.deb` fails with 403; the reason and eligibility time appear
  in middles diagnostics and the check route, and the client-visible output is
  recorded by the spike. Blocked files are not retrievable through middles via
  direct, range, or HEAD requests.
- Age is measured and described as durable local first observation keyed on the
  stanza checksum, with the cold-start wait and warming behavior documented.
- Unsupported policies fail configuration validation; unsupported download classes
  fail explicitly; no error path becomes an unrestricted fetch.
- Existing adapters retain their behavior, and formatting, Clippy, locked Rust
  tests, configuration checks, and the apt smoke test pass.

## Open questions

- Conditional-request passthrough (`If-Modified-Since`/304) as an optimization for
  daily update crons, pending spike measurements of 200-always cost.
- An uncached streaming passthrough tier for oversized `dists/` files
  (`Contents-*`, dep11 icon tarballs) versus declaring apt-file workflows
  unsupported at default bounds.
- Memory guidance versus a compact derived-map encoding for very large components
  such as Ubuntu universe, where one decompressed index approaches the hot-cache
  budget.
- A documentation note that every client architecture, including `i386` on
  multi-arch hosts, must appear in `architectures` or its pool downloads fail.

## References

- [Debian repository format](https://wiki.debian.org/DebianRepository/Format)
- [apt-acquire and by-hash behavior](https://manpages.debian.org/apt/apt-transport-http.1.en.html)
- [Debian policy on maintainer scripts](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
