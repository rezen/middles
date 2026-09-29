# Stats write benchmark

Isolated benchmark crate: does not add database dependencies to the proxy or change
its production storage. Run from the repository root:

```sh
cargo build --release --locked --manifest-path benchmarks/stats/Cargo.toml
benchmarks/stats/target/release/middles-stats-bench \
  --concurrency 32 --seconds 3 --repeats 3 \
  --output docs/benchmarks/stats-primary.jsonl
python3 benchmarks/stats/summarize.py docs/benchmarks/stats-primary.jsonl
```

Output is **append-only** JSON Lines. Choose a new filename for a fresh experiment.
Temporary databases live under `target/bench-data` and are removed after each trial.
The lockfile pins redb 4.3.0, Fjall 3.1.10, and rusqlite 0.38.0 (bundled SQLite).
Use `--help` for engine, workload, duration, batch, cardinality and concurrency options.

## Work represented

- The same stats fields as production: full downloads, range transfers, bytes,
  minimum first timestamp, maximum last timestamp, keyed by ecosystem/package/release.
- SQLite uses the production schema, UPSERT and descending recent-download index.
  `sqlite` reparses the UPSERT as production currently does; `sqlite-prepared` uses
  `prepare_cached` as a low-effort optimization comparison.
- redb and Fjall use a 40-byte binary counter value, composite identity key, and
  a separate descending timestamp+identity index. Counter and index updates occur
  in the **same transaction**, including removing the previous index entry. This
  is more representative than benchmarking blind key-value overwrites.
- `fjall` uses single-writer transactions. `fjall-occ` uses optimistic transactions
  and retries conflicts with `yield_now`; reported latency includes all retries.
  No application-wide lock is added to either Fjall variant or redb.
- 10,000 records are prepopulated by default, then flushed. Setup is not timed.
  `hot`: 90% of updates target 100 popular records, 10% target the full keyspace.
  `uniform`: all records are equally likely. Deterministic per-worker random
  streams, 10% range transfers, 4 KiB–approximately 1 MiB logical bytes per event.
  Timestamps advance once per elapsed second; these tests update existing records.
- Each caller awaits one `spawn_blocking` database job, matching middles' scheduling
  pattern. 4 Tokio worker threads, up to 64 blocking threads. SQLite shares one
  mutex-protected connection, like production. All engines run **sequentially**;
  engine order rotates across repetitions.
- Batch 1 commits each event. Batch 64 performs 64 read-modify-write updates in
  one transaction. Events are **not coalesced** by key. Batches are preassembled;
  this measures storage service time, not waiting to accumulate a real queue.
- Throughput counts events, including in-flight transactions drained at the end.
  Latency is wall time from job submission to successful commit acknowledgement,
  including executor scheduling, locking and retries. For batch 64 it is the
  latency of the entire batch, **not divided by 64**. This is a closed-loop
  saturation test, not an open-loop arrival-rate or HTTP latency benchmark.
- Each trial flushes, closes and reopens its database, then verifies every field
  of every record against independently accumulated expected values. Key-value
  engines also verify that the recent index has exactly one correct entry per
  record; SQLite runs `integrity_check`. Verification is outside the timed region.

## Durability is part of the result

| Mode | SQLite | redb | Fjall |
|---|---|---|---|
| `sync` | WAL + `synchronous=FULL`, `fullfsync=ON`, `checkpoint_fullfsync=ON` | `Durability::Immediate` | transaction `PersistMode::SyncAll` |
| `buffered` | WAL + `synchronous=NORMAL` (production setting) | `Durability::None` | transaction `PersistMode::Buffer` |

`sync` requests stable storage at each commit (or each 64-event commit). On the
macOS test host Rust's `File::sync_data`/`sync_all` use `F_FULLFSYNC`; enabling
SQLite's `fullfsync` avoids comparing its cheaper ordinary `fsync` with the Rust
engines' full device flush. Hardware power-loss behavior is **not tested**.

`buffered` is a useful throughput comparison, **not identical crash semantics**:
SQLite NORMAL and Fjall Buffer send writes to OS buffers; redb None does not
promise recovery of those commits until a subsequent Immediate commit. SQLite
NORMAL may also sync during auto-checkpoints (default 1,000 pages). There is no
periodic flush worker in the harness. The separately reported final flush is
excluded from throughput. A production implementation needing a bounded loss
window must include periodic durable flushes and measure their interference.

All engines get a 4 MiB database/block cache. Fjall additionally gets a 4 MiB
memtable limit per keyspace, with normal background maintenance and default
compression; this is **not an equal total-RSS experiment**. SQLite does not run
metadata-cache work concurrently, and no engine is polled for stats during writes.
These are warm, bounded-cardinality counter workloads, not long-term growth,
crash-injection, disk-full, migration, or mixed read/write tests.

References: [redb durability](https://docs.rs/redb/4.3.0/redb/enum.Durability.html),
[Fjall persistence](https://docs.rs/fjall/3.1.10/fjall/enum.PersistMode.html),
[SQLite synchronous](https://www.sqlite.org/pragma.html#pragma_synchronous),
[SQLite fullfsync](https://www.sqlite.org/pragma.html#pragma_fullfsync).
