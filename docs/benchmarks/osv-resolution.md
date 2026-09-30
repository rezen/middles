# OSV resolution query choice

Measured 2026-09-30 against public registry metadata, using a single HTTPS GET
per package and counting listed releases or files. These are representative
sizes, not a throughput guarantee:

| Metadata | Listed entries | Response bytes | 128-version batches (upper bound) |
| --- | ---: | ---: | ---: |
| npm lodash | 117 versions | 247,678 | 1 |
| npm react | 2,959 versions | 7,011,585 | 24 |
| PyPI requests | 244 files | 123,104 | 2 before version deduplication |
| PyPI numpy | 4,232 files | 2,780,148 | 34 before version deduplication |
| Packagist symfony/console | 780 entries | 374,768 | 7 |
| RubyGems rails | 521 compact-info lines | 186,441 | 5 |

One `POST /v1/querybatch` containing 128 historical React versions sent 9,736
bytes, returned 4,353 bytes with 55 version/advisory matches, and took 0.51 s
in the same environment. A one-request-per-version design would require 2,959
requests for that npm package. The implementation batches at 128, deduplicates
PyPI versions and advisory IDs, and fetches full records only for returned IDs.
The batch response provides IDs and modification times, so full records are
needed to apply severity, withdrawal and waiver rules. Both response types use
the advisory evidence TTL. All pages must succeed before a filtered listing is
served.

This preserves OSV's version matching across npm, PyPI, Packagist and RubyGems.
The alternative versionless query would require local interpretation of each
ecosystem's version range syntax. The [OSV querybatch API](https://google.github.io/osv.dev/post-v1-querybatch/)
documents ordered results, IDs-only responses, and per-query pagination.
