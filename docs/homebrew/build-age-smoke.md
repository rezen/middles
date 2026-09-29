# Homebrew build-age compatibility check

On 2026-09-29, the isolated Homebrew smoke passed with Homebrew source 7.0.7
(`8e858db5584704dcd469b8e826228c0d5a5a94f6`) on arm64 macOS 26.7. It used
the signed API snapshot with SHA-256
`f884e5fcd64bc02b2a71b7be509e5f43c577e384c1be5ae3fecfabe9c7d8c088`,
official GHCR bottle transport, a disposable non-default prefix and database,
and forced cold bottle fetches.

The seven-day `local_first_seen` policy denied a new `hello` bottle observation.
After a restart using the same database and `age_basis = "oci_created"`, the
same forced cold fetch succeeded. The client also installed `hello` and the
`zstd` dependency closure with bottle checksums intact; a cached fetch and a
denied cold fetch after restart behaved as expected.

Reproduce with:

```sh
just homebrew-smoke --repository /opt/homebrew \
  --fixtures /path/to/fixtures --output /path/to/output
```

The fixture preparation instructions are in the [usage guide](README.md).
Raw traces are kept outside Git because they can include local paths and network
details.
