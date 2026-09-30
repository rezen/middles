# APT through middles

Configure a named repository and allowlist its upstream host:

```toml
[upstream]
artifact_hosts = ["deb.debian.org", "security.debian.org"]

[apt]
enabled = true
max_index_mb = 96
install_hooks = "report"

[[apt.repos]]
name = "debian"
url = "https://deb.debian.org/debian"
suites = ["bookworm", "bookworm-updates"]
components = ["main"]
architectures = ["amd64"]

[[apt.repos]]
name = "debian-security"
url = "https://security.debian.org/debian-security"
suites = ["bookworm-security"]
components = ["main"]
architectures = ["amd64"]
min_age_days = 0
```

Point clients at `deb http://<middles>/apt/debian bookworm main` and install the
repository's normal signing key on each client. middles passes every `dists/`
byte through unchanged; apt verifies `InRelease` or `Release.gpg` and package
hashes. middles fetches indexes over TLS from allowlisted hosts, binds its policy
index cache to the Release digest, and verifies the selected index against the
Release SHA256 list. If a pool file changes without an aligned index, apt rejects
its archive hash and needs another update.
middles does not verify signatures or act as a mirror.
`middles configure` generates the matching deb822 stanzas and the client steps
listed under [Client setup](#client-setup).

The age clock starts when middles first observes each `.deb` checksum in a
configured `Packages` index. A fresh deployment blocks packages for the full
waiting period, even if upstream published them earlier. Run `apt-get update`
through middles on clients to warm the ledger. Preserve and back up the SQLite
cache database: losing its `first_seen` rows restarts every waiting period.
Metadata responses expire after `cache.metadata_ttl_secs` (default 300 seconds).
Keep that TTL well below the suite's `Valid-Until` window. Large components such
as Ubuntu universe can require much more than the default 64 MB hot cache;
increase `cache.memory_mb`, `cache.disk_mb`, and `apt.max_index_mb` to fit both
compressed and decompressed indexes. Include every architecture used by clients,
including `i386` on multi-arch hosts.

When a new version replaces an old stanza, the old pool path is denied as unknown
and the new checksum waits from its first local observation. apt downloads all
archives before installing any, so one blocked archive aborts the transaction.
Security suites often warrant an explicit `min_age_days = 0` override. The proxy
cannot select an older version that is absent from the current index.

For a denied archive, inspect middles logs or request
`GET /apt/<repo>/check/<repository-relative-filename>` to see the package,
checksum, `local_first_seen`, and eligibility time. apt itself only shows 403 and
the failed URL. Direct, Range, and HEAD pool requests use the same authorization.
Clients not pointed at middles, local apt caches, and already-downloaded archives
are outside its enforcement boundary. Maintainer scripts remain inside `.deb`
files and may run as root on clients; middles cannot assert their absence.

Only binary `.deb` archives from configured repository/suite/component/architecture
tuples are supported. `deb-src`, `.udeb`, installer files, flat repositories,
old-style suite paths, and mirror discovery are unsupported. A `dists/` file that
exceeds `apt.max_index_mb` fails with 502.

Run the local signed-client check with `just apt-smoke`. It uses throwaway keys and
inert packages in disposable Debian and Ubuntu containers.
Run `just apt-docker-smoke` to exercise the same scenarios with middles inside its
production Docker image, including its read-only filesystem, unprivileged user,
and mounted SQLite state. An existing custom image can be tested with
`python3 scripts/apt-compatibility.py --proxy-image <image:tag>`.
To test a custom apt client image, pass `--client-image <image:tag>` (repeatable);
the image must be `linux/amd64` and have `sh`, `apt-get`, and `dpkg` installed.

## Client setup

`middles configure --config middles.toml` generates one deb822 stanza per
configured repository. Run as root on a Debian or Ubuntu client, it writes them
to `/etc/apt/sources.list.d/middles.sources`; anywhere else it prints them
together with the steps below. For the example configuration above:

```text
Types: deb
URIs: https://middles.example.com/apt/debian
Suites: bookworm bookworm-updates
Components: main
Architectures: amd64

Types: deb
URIs: https://middles.example.com/apt/debian-security
Suites: bookworm-security
Components: main
Architectures: amd64
```

1. Save the stanzas as `/etc/apt/sources.list.d/middles.sources` on each client,
   for example with `sudo tee`, or run
   `sudo middles configure --config middles.toml --only apt` there. Pass `--url`
   when `public_url` is not reachable from the client; a loopback address only
   works on the proxy host itself.
2. Disable the direct entries for the same upstreams, with either scheme:
   comment out their `deb` lines in `/etc/apt/sources.list` and
   `/etc/apt/sources.list.d/*.list`, and add `Enabled: no` to their stanzas in
   `/etc/apt/sources.list.d/*.sources` (Debian 12 and Ubuntu 24.04 keep them in
   `debian.sources` or `ubuntu.sources`). Entries left enabled fetch upstream
   directly and bypass the policy.
3. Keep each repository's signing key installed. The distribution keyrings in
   `/etc/apt/trusted.gpg.d` verify the proxied indexes because middles passes
   them through unchanged. If the original stanza carried a `Signed-By` line,
   add the same line to the middles stanza.
4. Run `sudo apt-get update`. Every index now comes from
   `<public_url>/apt/<name>`; confirm with `apt-cache policy` or
   `apt-get install --print-uris <package>`. Do not set
   `Acquire::http::Proxy`: middles is a repository endpoint, not an HTTP proxy.
5. Packages become installable `min_age_days` after middles first sees them in
   an index, so run the update early to start the clock. A denied download shows
   HTTP 403; `GET /apt/<repo>/check/<repository-relative-filename>` explains it.
