# APT client compatibility gate

**Decision: go for the scoped binary archive adapter.** The local signed fixture in
[`scripts/apt-compatibility.py`](../../scripts/apt-compatibility.py) passed update,
install, InRelease fallback, repeated update, and 403 denial with stock clients.
The recorded requests and exact client output are in `traces/`.
The same six scenarios also passed with `--proxy` through the implemented adapter;
those requests used client-side GPG verification and proxy-side age denial. In
both images, an installed 1.0 fixture package remained installed when the
upstream index switched to 2.0 and the proxy denied its upgrade archive with 403.
The same eight proxy scenarios also passed with middles running from the custom
`middles:apt-test` Docker image as its unprivileged user, with a read-only root
filesystem and mounted SQLite state.

| Client image | apt version | Update/install | Release fallback | 403 denial |
| --- | --- | --- | --- | --- |
| Debian bookworm (`golang:1.24-bookworm`) | 2.6.1 | Pass | Pass | Pass; install and upgrade exit 100 |
| Ubuntu 20.04 (`ubuntu:20.04`) | 2.0.10 | Pass | Pass | Pass; install and upgrade exit 100 |

Minimum verified apt version: **2.0.10**. This is a tested floor, not a claim that
older apt releases fail. Both images were local `linux/amd64` images; the probe did
not test other architectures or apt versions.

Both clients first requested `dists/test/InRelease`, then a
`binary-amd64/by-hash/SHA256/<digest>` index. With `InRelease` returning 404,
both requested `Release` and `Release.gpg`, then the same by-hash index. The
second update sent `If-Modified-Since` for `InRelease` or `Release`, but accepted
the fixture's unconditional 200. Neither client sent a `Range` request or a
`Packages.diff/` request in this small fixture. The fixture advertised no ancillary
indexes, so Translation, Commands, dep11, and icon size behavior remains
unmeasured. No Authorization header appeared. The proxy rejects one if supplied.

On 403, apt showed `E: Failed to fetch ... 403 Forbidden` and exited 100. It did
not display a response body. The proxy's `/apt/<repo>/check/<filename>` endpoint
exposes age evidence for diagnostics. A 200-always response causes one full
`InRelease` transfer per update. Actual daily bandwidth on large archives depends
on their selected indexes and cache TTL; this fixture cannot estimate it.

By-hash requests name the digest selected from a signed Release file. middles
keys its derived policy index by the Release digest and checks the index bytes
against that Release's SHA256 list; a refreshed Release cannot reuse an older
derived index. apt independently checks its signed Release and downloaded archive
hash. The fixture confirms the client's by-hash request shape; it does not force
an upstream cache-skew scenario.
