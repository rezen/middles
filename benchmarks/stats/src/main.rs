use anyhow::{Result, ensure};
use clap::Parser;
use fjall::Readable;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const ROWS: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("downloads");
const RECENT: redb::TableDefinition<&[u8], u8> = redb::TableDefinition::new("recent");
// Same schema/index and UPSERT as middles' production stats path.
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS downloads (
 ecosystem TEXT NOT NULL, package TEXT NOT NULL, release TEXT NOT NULL,
 full_downloads INTEGER NOT NULL, range_transfers INTEGER NOT NULL,
 bytes INTEGER NOT NULL, first_download INTEGER NOT NULL, last_download INTEGER NOT NULL,
 PRIMARY KEY(ecosystem, package, release));
 CREATE INDEX IF NOT EXISTS downloads_recent ON downloads(last_download DESC);";
const UPSERT: &str = "INSERT INTO downloads VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
 ON CONFLICT(ecosystem, package, release) DO UPDATE SET
 full_downloads=full_downloads+excluded.full_downloads,
 range_transfers=range_transfers+excluded.range_transfers,
 bytes=bytes+excluded.bytes,
 first_download=MIN(first_download, excluded.first_download),
 last_download=MAX(last_download, excluded.last_download)";

#[derive(Parser, Debug, Serialize)]
struct Args {
    #[arg(long, default_value = "sqlite,sqlite-prepared,redb,fjall,fjall-occ")]
    engines: String,
    #[arg(long, default_value = "buffered,sync")]
    modes: String,
    #[arg(long, default_value = "hot,uniform")]
    workloads: String,
    #[arg(long, default_value = "1,32")]
    concurrency: String,
    #[arg(long, default_value = "1,64")]
    batches: String,
    #[arg(long, default_value_t = 3)]
    repeats: usize,
    #[arg(long, default_value_t = 3.0)]
    seconds: f64,
    #[arg(long, default_value_t = 10000)]
    keys: usize,
    #[arg(long, default_value = "results.jsonl")]
    output: PathBuf,
    #[arg(long, default_value = "target/bench-data")]
    data_dir: PathBuf,
}
#[derive(Clone, Debug)]
struct Key {
    eco: &'static str,
    package: String,
    release: String,
    encoded: Vec<u8>,
}
fn keys(n: usize) -> Vec<Key> {
    (0..n)
        .map(|i| {
            let eco = ["npm", "pip", "composer"][i % 3];
            let package = format!("vendor/package-{:06}", i / 4);
            let release = if eco == "pip" {
                format!("package-{}-py3-none-any.whl", i % 4)
            } else {
                format!("1.{}.0", i % 4)
            };
            let encoded = format!("{eco}\0{package}\0{release}").into_bytes();
            Key {
                eco,
                package,
                release,
                encoded,
            }
        })
        .collect()
}
#[derive(Clone, Copy)]
struct Event {
    id: usize,
    partial: bool,
    bytes: u64,
    stamp: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Stats {
    full: u64,
    ranges: u64,
    bytes: u64,
    first: u64,
    last: u64,
}
impl Stats {
    fn add(&mut self, e: Event) {
        if self.full + self.ranges == 0 {
            self.first = e.stamp;
        }
        self.full += u64::from(!e.partial);
        self.ranges += u64::from(e.partial);
        self.bytes += e.bytes;
        self.first = self.first.min(e.stamp);
        self.last = self.last.max(e.stamp);
    }
    fn merge(&mut self, other: Self) {
        if self.full + self.ranges == 0 {
            self.first = other.first;
        }
        self.full += other.full;
        self.ranges += other.ranges;
        self.bytes += other.bytes;
        self.first = self.first.min(other.first);
        self.last = self.last.max(other.last);
    }
    fn encode(self) -> [u8; 40] {
        let mut out = [0; 40];
        for (i, n) in [self.full, self.ranges, self.bytes, self.first, self.last]
            .into_iter()
            .enumerate()
        {
            out[i * 8..i * 8 + 8].copy_from_slice(&n.to_be_bytes());
        }
        out
    }
    fn decode(b: &[u8]) -> Self {
        let n: Vec<_> = b
            .chunks_exact(8)
            .map(|b| u64::from_be_bytes(b.try_into().unwrap()))
            .collect();
        Self {
            full: n[0],
            ranges: n[1],
            bytes: n[2],
            first: n[3],
            last: n[4],
        }
    }
}
fn index_key(key: &[u8], stamp: u64) -> Vec<u8> {
    let mut v = (!stamp).to_be_bytes().to_vec();
    v.extend_from_slice(key);
    v
}

enum Engine {
    Sqlite {
        db: Mutex<Connection>,
        prepared: bool,
    },
    Redb(redb::Database),
    Fjall {
        db: fjall::SingleWriterTxDatabase,
        rows: fjall::SingleWriterTxKeyspace,
        recent: fjall::SingleWriterTxKeyspace,
    },
    Occ {
        db: fjall::OptimisticTxDatabase,
        rows: fjall::OptimisticTxKeyspace,
        recent: fjall::OptimisticTxKeyspace,
    },
}
impl Engine {
    fn open(name: &str, path: &Path, sync: bool) -> Result<Self> {
        Ok(match name {
            "sqlite" | "sqlite-prepared" => {
                let db = Connection::open(path.join("db.sqlite3"))?;
                db.busy_timeout(Duration::from_secs(5))?;
                db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA cache_size=-4096; PRAGMA wal_autocheckpoint=1000;")?;
                // Rust File::sync_{data,all} uses F_FULLFSYNC on macOS. Match it here.
                db.execute_batch(if sync {
                    "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;"
                } else {
                    "PRAGMA synchronous=NORMAL;"
                })?;
                db.execute_batch(SCHEMA)?;
                Self::Sqlite {
                    db: Mutex::new(db),
                    prepared: name == "sqlite-prepared",
                }
            }
            "redb" => {
                let db = redb::Database::builder()
                    .set_cache_size(4 * 1024 * 1024)
                    .create(path.join("db.redb"))?;
                let tx = db.begin_write()?;
                tx.open_table(ROWS)?;
                tx.open_table(RECENT)?;
                tx.commit()?;
                Self::Redb(db)
            }
            "fjall" => {
                let db = fjall::SingleWriterTxDatabase::builder(path.join("fjall"))
                    .cache_size(4 * 1024 * 1024)
                    .open()?;
                let options =
                    || fjall::KeyspaceCreateOptions::default().max_memtable_size(4 * 1024 * 1024);
                let rows = db.keyspace("downloads", options)?;
                let recent = db.keyspace("recent", options)?;
                Self::Fjall { db, rows, recent }
            }
            "fjall-occ" => {
                let db = fjall::OptimisticTxDatabase::builder(path.join("fjall"))
                    .cache_size(4 * 1024 * 1024)
                    .open()?;
                let options =
                    || fjall::KeyspaceCreateOptions::default().max_memtable_size(4 * 1024 * 1024);
                let rows = db.keyspace("downloads", options)?;
                let recent = db.keyspace("recent", options)?;
                Self::Occ { db, rows, recent }
            }
            _ => anyhow::bail!("unknown engine: {name}"),
        })
    }
    fn write(&self, keys: &[Key], events: &[Event], sync: bool) -> Result<u64> {
        let durability = Some(if sync {
            fjall::PersistMode::SyncAll
        } else {
            fjall::PersistMode::Buffer
        });
        match self {
            Self::Sqlite { db, prepared } => {
                let db = db.lock().unwrap();
                // Preserve production autocommit for individual writes.
                let tx = if events.len() > 1 {
                    Some(db.unchecked_transaction()?)
                } else {
                    None
                };
                let conn: &Connection = tx.as_deref().unwrap_or(&db);
                if *prepared {
                    let mut stmt = conn.prepare_cached(UPSERT)?;
                    for e in events {
                        let k = &keys[e.id];
                        stmt.execute(params![
                            k.eco,
                            k.package,
                            k.release,
                            i64::from(!e.partial),
                            i64::from(e.partial),
                            e.bytes as i64,
                            e.stamp as i64
                        ])?;
                    }
                } else {
                    for e in events {
                        let k = &keys[e.id];
                        conn.execute(
                            UPSERT,
                            params![
                                k.eco,
                                k.package,
                                k.release,
                                i64::from(!e.partial),
                                i64::from(e.partial),
                                e.bytes as i64,
                                e.stamp as i64
                            ],
                        )?;
                    }
                }
                if let Some(tx) = tx {
                    tx.commit()?;
                }
            }
            Self::Redb(db) => {
                let mut tx = db.begin_write()?;
                tx.set_durability(if sync {
                    redb::Durability::Immediate
                } else {
                    redb::Durability::None
                })?;
                {
                    let mut rows = tx.open_table(ROWS)?;
                    let mut recent = tx.open_table(RECENT)?;
                    for e in events {
                        let key = &keys[e.id].encoded;
                        let old = rows.get(key.as_slice())?.map(|v| Stats::decode(v.value()));
                        let mut value = old.unwrap_or_default();
                        value.add(*e);
                        if let Some(old) = old {
                            recent.remove(index_key(key, old.last).as_slice())?;
                        }
                        rows.insert(key.as_slice(), value.encode().as_slice())?;
                        recent.insert(index_key(key, value.last).as_slice(), 0)?;
                    }
                }
                tx.commit()?;
            }
            Self::Fjall { db, rows, recent } => {
                let mut tx = db.write_tx().durability(durability);
                for e in events {
                    let key = &keys[e.id].encoded;
                    let old = tx.get(rows, key)?.map(|v| Stats::decode(&v));
                    let mut value = old.unwrap_or_default();
                    value.add(*e);
                    if let Some(old) = old {
                        tx.remove(recent, index_key(key, old.last));
                    }
                    tx.insert(rows, key.clone(), value.encode().as_slice());
                    tx.insert(recent, index_key(key, value.last), [0u8].as_slice());
                }
                tx.commit()?;
            }
            Self::Occ { db, rows, recent } => {
                let mut retries = 0;
                loop {
                    let mut tx = db.write_tx()?.durability(durability);
                    for e in events {
                        let key = &keys[e.id].encoded;
                        let old = tx.get(rows, key)?.map(|v| Stats::decode(&v));
                        let mut value = old.unwrap_or_default();
                        value.add(*e);
                        if let Some(old) = old {
                            tx.remove(recent, index_key(key, old.last));
                        }
                        tx.insert(rows, key.clone(), value.encode().as_slice());
                        tx.insert(recent, index_key(key, value.last), [0u8].as_slice());
                    }
                    if tx.commit()?.is_ok() {
                        return Ok(retries);
                    }
                    retries += 1;
                    std::thread::yield_now();
                }
            }
        }
        Ok(0)
    }
    fn flush(&self) -> Result<()> {
        match self {
            Self::Sqlite { db, .. } => {
                db.lock()
                    .unwrap()
                    .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            }
            Self::Redb(db) => {
                let mut tx = db.begin_write()?;
                tx.set_durability(redb::Durability::Immediate)?;
                tx.commit()?;
            }
            Self::Fjall { db, .. } => db.persist(fjall::PersistMode::SyncAll)?,
            Self::Occ { db, .. } => db.persist(fjall::PersistMode::SyncAll)?,
        }
        Ok(())
    }
    fn verify(&self, keys: &[Key], expected: &[Stats]) -> Result<()> {
        match self {
            Self::Sqlite { db, .. } => {
                let db = db.lock().unwrap();
                let count: i64 =
                    db.query_row("SELECT COUNT(*) FROM downloads", [], |r| r.get(0))?;
                ensure!(count == keys.len() as i64, "wrong row count");
                let mut query=db.prepare("SELECT full_downloads, range_transfers, bytes, first_download, last_download FROM downloads WHERE ecosystem=?1 AND package=?2 AND release=?3")?;
                for (k, want) in keys.iter().zip(expected) {
                    let actual = query.query_row(params![k.eco, k.package, k.release], |r| {
                        Ok(Stats {
                            full: r.get::<_, i64>(0)? as u64,
                            ranges: r.get::<_, i64>(1)? as u64,
                            bytes: r.get::<_, i64>(2)? as u64,
                            first: r.get::<_, i64>(3)? as u64,
                            last: r.get::<_, i64>(4)? as u64,
                        })
                    })?;
                    ensure!(
                        actual == *want,
                        "counter mismatch for {}: {actual:?} != {want:?}",
                        k.package
                    );
                }
                let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
                ensure!(integrity == "ok", "SQLite integrity check: {integrity}");
            }
            Self::Redb(db) => {
                let tx = db.begin_read()?;
                let rows = tx.open_table(ROWS)?;
                let recent = tx.open_table(RECENT)?;
                ensure!(
                    rows.len()? as usize == keys.len() && recent.len()? as usize == keys.len(),
                    "wrong row/index count"
                );
                for (k, want) in keys.iter().zip(expected) {
                    ensure!(
                        Stats::decode(rows.get(k.encoded.as_slice())?.unwrap().value()) == *want,
                        "redb counters differ"
                    );
                    ensure!(
                        recent
                            .get(index_key(&k.encoded, want.last).as_slice())?
                            .is_some(),
                        "redb index mismatch"
                    );
                }
            }
            Self::Fjall { db, rows, recent } => {
                let tx = db.read_tx();
                ensure!(
                    tx.iter(rows).count() == keys.len() && tx.iter(recent).count() == keys.len(),
                    "wrong row/index count"
                );
                for (k, want) in keys.iter().zip(expected) {
                    ensure!(
                        Stats::decode(&tx.get(rows, &k.encoded)?.unwrap()) == *want,
                        "fjall counters differ"
                    );
                    ensure!(
                        tx.get(recent, index_key(&k.encoded, want.last))?.is_some(),
                        "fjall index mismatch"
                    );
                }
            }
            Self::Occ { db, rows, recent } => {
                let tx = db.read_tx();
                ensure!(
                    tx.iter(rows).count() == keys.len() && tx.iter(recent).count() == keys.len(),
                    "wrong row/index count"
                );
                for (k, want) in keys.iter().zip(expected) {
                    ensure!(
                        Stats::decode(&tx.get(rows, &k.encoded)?.unwrap()) == *want,
                        "fjall-occ counters differ"
                    );
                    ensure!(
                        tx.get(recent, index_key(&k.encoded, want.last))?.is_some(),
                        "fjall-occ index mismatch"
                    );
                }
            }
        }
        Ok(())
    }
}
#[derive(Clone, Serialize)]
struct Case {
    engine: String,
    mode: String,
    workload: String,
    concurrency: usize,
    batch: usize,
    repeat: usize,
}
#[derive(Serialize)]
struct Measurement {
    #[serde(flatten)]
    case: Case,
    keys: usize,
    events: u64,
    transactions: u64,
    elapsed_secs: f64,
    events_per_sec: f64,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    max_us: f64,
    retries: u64,
    final_flush_ms: f64,
    verified_after_reopen: bool,
}
fn random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
async fn trial(args: &Args, case: &Case, keys: Arc<Vec<Key>>) -> Result<Measurement> {
    let dir = tempfile::Builder::new()
        .prefix("stats-")
        .tempdir_in(&args.data_dir)?;
    let sync = case.mode == "sync";
    let engine = Arc::new(Engine::open(&case.engine, dir.path(), sync)?);
    let seed: Vec<_> = (0..keys.len())
        .map(|id| Event {
            id,
            partial: false,
            bytes: 4096,
            stamp: 1_700_000_000,
        })
        .collect();
    // Untimed population and warmup. Every key exists at the start of every trial.
    for batch in seed.chunks(1000) {
        engine.write(&keys, batch, false)?;
    }
    engine.flush()?;
    let mut expected = vec![Stats::default(); keys.len()];
    for e in seed {
        expected[e.id].add(e);
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(case.concurrency + 1));
    let deadline = Instant::now() + Duration::from_secs_f64(args.seconds);
    // watch channel starts every worker from one measured timestamp after spawning.
    let (start_tx, start_rx) = tokio::sync::watch::channel(deadline);
    let mut tasks = Vec::new();
    for worker in 0..case.concurrency {
        let engine = engine.clone();
        let keys = keys.clone();
        let barrier = barrier.clone();
        let case = case.clone();
        let start_rx = start_rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = 0x123456789abcdefu64.wrapping_add(worker as u64 * 7919);
            let mut latencies = Vec::new();
            let mut counts = BTreeMap::<usize, Stats>::new();
            let mut event_count = 0u64;
            let mut retries = 0;
            barrier.wait().await;
            let deadline = *start_rx.borrow();
            let begin = Instant::now();
            while Instant::now() < deadline {
                let mut events = Vec::with_capacity(case.batch);
                for _ in 0..case.batch {
                    let n = random(&mut rng);
                    let id = if case.workload == "hot" && n % 10 < 9 {
                        (random(&mut rng) as usize) % keys.len().min(100)
                    } else {
                        (random(&mut rng) as usize) % keys.len()
                    };
                    let stamp = 1_700_000_001 + begin.elapsed().as_secs();
                    events.push(Event {
                        id,
                        partial: n.is_multiple_of(10),
                        bytes: 4096 + n % 1_000_000,
                        stamp,
                    });
                }
                let db = engine.clone();
                let catalog = keys.clone();
                let started = Instant::now();
                let (events, conflicts) = tokio::task::spawn_blocking(move || -> Result<_> {
                    let conflicts = db.write(&catalog, &events, sync)?;
                    Ok((events, conflicts))
                })
                .await??;
                latencies.push(started.elapsed().as_secs_f64() * 1e6);
                retries += conflicts;
                event_count += events.len() as u64;
                for e in events {
                    counts.entry(e.id).or_default().add(e);
                }
            }
            Ok::<_, anyhow::Error>((event_count, retries, latencies, counts))
        }));
    }
    let started = Instant::now();
    start_tx.send(started + Duration::from_secs_f64(args.seconds))?;
    barrier.wait().await;
    let mut events = 0;
    let mut retries = 0;
    let mut latencies = Vec::new();
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await??);
    }
    let elapsed = started.elapsed().as_secs_f64();
    for (n, r, l, counts) in outcomes {
        events += n;
        retries += r;
        latencies.extend(l);
        for (id, count) in counts {
            expected[id].merge(count);
        }
    }
    let flush = Instant::now();
    engine.flush()?;
    let flush_ms = flush.elapsed().as_secs_f64() * 1000.;
    // Reopen and verify every counter and the recent index, outside the measured window.
    drop(engine);
    let reopened = Engine::open(&case.engine, dir.path(), sync)?;
    reopened.verify(&keys, &expected)?;
    drop(reopened);
    ensure!(!latencies.is_empty(), "no completed transactions");
    latencies.sort_unstable_by(f64::total_cmp);
    let percentile =
        |p: f64| latencies[((latencies.len() as f64 * p).ceil() as usize).saturating_sub(1)];
    Ok(Measurement {
        case: case.clone(),
        keys: keys.len(),
        events,
        transactions: latencies.len() as u64,
        elapsed_secs: elapsed,
        events_per_sec: events as f64 / elapsed,
        p50_us: percentile(0.5),
        p95_us: percentile(0.95),
        p99_us: percentile(0.99),
        max_us: *latencies.last().unwrap(),
        retries,
        final_flush_ms: flush_ms,
        verified_after_reopen: true,
    })
}
fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.keys > 0 && args.repeats > 0 && args.seconds > 0.,
        "positive keys/repeats/seconds required"
    );
    std::fs::create_dir_all(&args.data_dir)?;
    let keys = Arc::new(keys(args.keys));
    let engines: Vec<_> = args.engines.split(',').collect();
    let mut cases = Vec::new();
    // Rotate engine order between repetitions to reduce systematic order bias.
    for repeat in 0..args.repeats {
        for mode in args.modes.split(',') {
            ensure!(matches!(mode, "sync" | "buffered"), "unknown mode");
            for workload in args.workloads.split(',') {
                ensure!(matches!(workload, "hot" | "uniform"), "unknown workload");
                for concurrency in args.concurrency.split(',') {
                    let concurrency = concurrency.parse::<usize>()?;
                    ensure!(concurrency > 0, "positive concurrency required");
                    for batch in args.batches.split(',') {
                        let batch = batch.parse::<usize>()?;
                        ensure!(batch > 0, "positive batch required");
                        for offset in 0..engines.len() {
                            cases.push(Case {
                                engine: engines[(offset + repeat) % engines.len()].into(),
                                mode: mode.into(),
                                workload: workload.into(),
                                concurrency,
                                batch,
                                repeat,
                            });
                        }
                    }
                }
            }
        }
    }
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.output)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(64)
        .enable_all()
        .build()?;
    for (i, case) in cases.iter().enumerate() {
        let result = rt.block_on(trial(&args, case, keys.clone()))?;
        writeln!(output, "{}", serde_json::to_string(&result)?)?;
        output.flush()?;
        eprintln!(
            "{}/{} {} {} {} c{} b{}: {:.0} events/s p99 {:.2} ms retries {} verified",
            i + 1,
            cases.len(),
            case.engine,
            case.mode,
            case.workload,
            case.concurrency,
            case.batch,
            result.events_per_sec,
            result.p99_us / 1000.,
            result.retries
        );
    }
    Ok(())
}
