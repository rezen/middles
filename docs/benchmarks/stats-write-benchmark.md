# SQLite vs redb vs Fjall: middles stats writes

Measured on September 28, 2026 (Pacific time), on an Apple M4, 10 logical CPUs,
16 GiB RAM, macOS 26.7, local filesystem. Rust 1.97.1, release profile with thin
LTO. SQLite 3.51.1 via rusqlite 0.38.0, redb 4.3.0, Fjall 3.1.10.

This measures the storage portion of middles' stats hot path: atomic counter
updates plus maintenance of the recent-download index. It includes Tokio
`spawn_blocking` scheduling, lock waits, and transaction retries. It does not
measure package downloads or overall HTTP request throughput.

The primary matrix uses 32 concurrent callers, 10,000 prepopulated records,
three independent three-second trials per case, and rotated engine order. Every
trial verifies all counters and the recent index after flushing and reopening.
See the [harness methodology](../../benchmarks/stats/README.md) for the exact
implementation and durability settings, and [environment metadata](stats-environment.json)
for source hashes and toolchain details.

Results below are medians across independent trials. Percentile columns are
medians of per-trial percentiles, not percentiles pooled across trials. The range
shown for throughput is the minimum and maximum trial rate, not a confidence
interval. Batch latency includes the whole transaction and is not divided by
batch size; it excludes waiting for a queue to fill.

## Findings

**Fjall single-writer transactions led individual buffered stats updates.** On the hot-package workload, Fjall reached 102,310 events/s: 2.14× current SQLite, 1.71× SQLite with cached statements, and 1.95× redb. Uniform updates also favored Fjall (94,122 events/s). This changes the earlier expectation that redb would be the first performance candidate for this hot path.

### Buffered writes: hot packages, 32 callers

| Implementation | One event/commit, events/s | p99 per commit | 64 events/commit, events/s | p99 per batch |
|---|---:|---:|---:|---:|
| SQLite, current SQL | 47,728 | 2.12 ms | 175,320 | 16.38 ms |
| SQLite, cached SQL | 59,695 | 2.06 ms | 419,868 | 7.88 ms |
| redb | 52,433 | 1.21 ms | 405,882 | 9.44 ms |
| Fjall, single writer | 102,310 | 1.51 ms | 264,670 | 42.89 ms |
| Fjall, optimistic | 54,742 | 3.04 ms | 153,768 | 96.01 ms |

**These buffered modes do not have identical crash guarantees.** SQLite NORMAL and Fjall Buffer hand writes to OS buffers; redb None requires a later Immediate commit for a persistence guarantee. No periodic durable flush is included in these rates. See the matched durable-commit test below.

Batching and SQL statement reuse mattered substantially. Cached SQLite and redb were both around 400,000 events/s on hot batched updates; their trial ranges overlap, so this is not evidence of a decisive winner between them. With uniform batched updates, Fjall led at 209,781 events/s versus redb at 172,826 and cached SQLite at 142,023. The key distribution changes the ranking.

Fjall optimistic transactions did not improve this workload. Hot batches averaged a median 6.83 retries per committed batch and 96 ms p99, versus 43 ms p99 without optimistic conflicts. A more sophisticated retry/backoff policy might improve this result; the harness uses `yield_now`.

### Disk sync at every commit: hot packages, 32 callers

| Implementation | One event/commit, events/s | 64 events/commit, events/s |
|---|---:|---:|
| SQLite, current SQL | 367 | 13,047 |
| SQLite, cached SQL | 339 | 15,067 |
| redb | 309 | 13,217 |
| Fjall, single writer | 375 | 13,351 |
| Fjall, optimistic | 410 | 12,445 |

Here all engines request stable storage before acknowledging each commit. SQLite uses WAL/FULL with macOS fullfsync enabled; redb uses Immediate, and Fjall uses SyncAll. Disk-sync latency dominated: approximately 300–400 events/s individually, rising to 12,000–15,000 events/s with 64-event commits. Results varied noticeably between trials; small differences should not drive an engine decision. No actual power-cut test was performed.

With 32 saturated callers each submitting entire batches, durable batch p99 was roughly 159–203 ms for SQLite, redb and single-writer Fjall. These are backlog-inclusive saturation latencies, not the expected latency of a lightly loaded single background writer. Optimistic Fjall had much longer tails (974 ms on hot batches).

## Longer run with 100,000 records

One 30-second trial per engine, buffered writes, 32 callers, one event per commit, 100,000 prepopulated records, 90% of writes targeting 100 popular records. This is a follow-up directional check, not a replicated median.

| Implementation | Events/s | p50 | p99 |
|---|---:|---:|---:|
| SQLite, current SQL | 44,358 | 0.56 ms | 3.09 ms |
| SQLite, cached SQL | 52,260 | 0.44 ms | 3.19 ms |
| redb | 40,843 | 0.74 ms | 1.71 ms |
| Fjall, single writer | 90,509 | 0.27 ms | 1.66 ms |

The larger, longer run preserved the individual-write ordering: Fjall was about twice current SQLite and 1.7× cached SQLite. redb did not provide a throughput improvement over SQLite here. This still does not establish performance after hours of compaction, with a mostly cold dataset, or while stats queries contend with writes.

## Recommendation

- For **individual buffered stats updates**, Fjall single-writer transactions are the strongest migration candidate in these measurements. Its optimistic mode added overhead and conflicts without improving throughput here.
- If **batching is acceptable**, test a bounded writer queue that combines updates into transactions. Cached SQLite is competitive on popular-package batches, while Fjall leads with more evenly distributed updates. Batch formation latency and periodic durability work must be included in that next implementation benchmark.
- Do not choose redb on the assumption it will make this hot path faster: its individual-write results were close to, or below, current SQLite, although its hot batched throughput was strong.
- With **durability at every acknowledgement**, batching is the larger improvement. Engine selection did not remove disk-sync latency.

No production storage migration or write-path optimization was made as part of this benchmark. The benchmark dependencies are isolated in their own crate and lockfile.

## Reproduction and evidence

- [Source and methodology](../../benchmarks/stats/README.md)
- [Benchmark implementation](../../benchmarks/stats/src/main.rs)
- [Pinned dependency lockfile](../../benchmarks/stats/Cargo.lock)
- [Machine, versions, commands and source hashes](stats-environment.json)
- [Primary raw trials](stats-primary.jsonl) and [all primary summaries](stats-primary-summary.md)
- [Longer-run raw trials](stats-large.jsonl)

Validation: all 124 reported trials passed full post-reopen verification, covering 33,331,280 timed updates (excluding prepopulation). A separate 40-case short smoke matrix also passed. The isolated crate passes formatting and Clippy with warnings denied. Throughput comparisons use release builds. These are developer-laptop measurements, not an SLA or a deployment-capacity guarantee.
