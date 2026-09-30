use crate::{
    config::CacheConfig,
    error::{Error, Result},
};
use chrono::Utc;
use moka::future::Cache;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone)]
struct Entry {
    value: Arc<Value>,
    expires: i64,
    weight: u32,
}

/// Original OCI bytes and their verified representation headers. Never a policy decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RawMetadata {
    pub body: Vec<u8>,
    pub media_type: String,
    pub digest: String,
}

impl RawMetadata {
    pub fn kind(&self) -> &str {
        self.media_type.split(';').next().unwrap_or("").trim()
    }
}

#[derive(Clone)]
struct RawEntry {
    value: Arc<RawMetadata>,
    expires: i64,
    weight: u32,
}

#[derive(Clone)]
pub struct Store {
    db: Arc<Mutex<Connection>>,
    // WAL lets this read-only connection serve statistics queries without
    // waiting on hot-path writes serialized through the main connection.
    read_db: Arc<Mutex<Connection>>,
    metadata: Cache<String, Entry>,
    stats: Cache<String, Entry>,
    raw: Cache<String, RawEntry>,
    failures: Cache<String, Error>,
    config: CacheConfig,
}

impl Store {
    pub async fn open(config: CacheConfig) -> anyhow::Result<Self> {
        Self::open_with_raw(config, false).await
    }

    pub(crate) async fn open_with_raw(
        config: CacheConfig,
        raw_enabled: bool,
    ) -> anyhow::Result<Self> {
        let path = config.path.clone();
        let db = tokio::task::spawn_blocking(move || -> anyhow::Result<Connection> {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) { std::fs::create_dir_all(parent)?; }
            let db = Connection::open(path)?;
            db.busy_timeout(Duration::from_secs(5))?;
            db.execute_batch("
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;
                PRAGMA cache_size=-4096;
                CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, body BLOB NOT NULL, expires INTEGER NOT NULL, written INTEGER NOT NULL, size INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS responses_expiry ON responses(expires);
                CREATE INDEX IF NOT EXISTS responses_written ON responses(written);
                CREATE TABLE IF NOT EXISTS accounting (id INTEGER PRIMARY KEY CHECK(id = 1), bytes INTEGER NOT NULL);
                INSERT OR IGNORE INTO accounting VALUES (1, 0);
                CREATE TRIGGER IF NOT EXISTS responses_insert AFTER INSERT ON responses BEGIN UPDATE accounting SET bytes = bytes + NEW.size WHERE id = 1; END;
                CREATE TRIGGER IF NOT EXISTS responses_delete AFTER DELETE ON responses BEGIN UPDATE accounting SET bytes = bytes - OLD.size WHERE id = 1; END;
                CREATE TABLE IF NOT EXISTS first_seen (key TEXT PRIMARY KEY, timestamp INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS downloads (
                    ecosystem TEXT NOT NULL, package TEXT NOT NULL, release TEXT NOT NULL,
                    full_downloads INTEGER NOT NULL, range_transfers INTEGER NOT NULL,
                    bytes INTEGER NOT NULL, first_download INTEGER NOT NULL, last_download INTEGER NOT NULL,
                    PRIMARY KEY (ecosystem, package, release)
                );
                CREATE INDEX IF NOT EXISTS downloads_recent ON downloads(last_download DESC);
                CREATE TABLE IF NOT EXISTS homebrew_evidence (
                    identity TEXT PRIMARY KEY, evidence TEXT NOT NULL, verified INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS advisories (
                    ecosystem TEXT NOT NULL, package TEXT NOT NULL, id TEXT NOT NULL,
                    body BLOB NOT NULL, PRIMARY KEY (ecosystem, package, id)
                );
                CREATE TABLE IF NOT EXISTS advisory_imports (
                    ecosystem TEXT PRIMARY KEY, imported_at INTEGER NOT NULL,
                    records INTEGER NOT NULL, source TEXT NOT NULL
                );
            ")?;
            Ok(db)
        }).await??;
        // Opened after the writer so the WAL files it reads already exist.
        let read_path = config.path.clone();
        let read_db = tokio::task::spawn_blocking(move || -> anyhow::Result<Connection> {
            let db = Connection::open_with_flags(
                read_path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            db.busy_timeout(Duration::from_secs(5))?;
            Ok(db)
        })
        .await??;
        let hot = |capacity, ttl| {
            Cache::builder()
                .max_capacity(capacity)
                .weigher(|_: &String, entry: &Entry| entry.weight)
                .time_to_live(Duration::from_secs(ttl))
                .build()
        };
        let capacity = config.memory_mb * 1024 * 1024;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            read_db: Arc::new(Mutex::new(read_db)),
            metadata: hot(
                if raw_enabled {
                    capacity / 2
                } else {
                    capacity * 3 / 4
                },
                config.metadata_ttl_secs,
            ),
            stats: hot(capacity / 4, config.stats_ttl_secs),
            raw: Cache::builder()
                .max_capacity(if raw_enabled { capacity / 4 } else { 0 })
                .weigher(|_: &String, e: &RawEntry| e.weight)
                .time_to_live(Duration::from_secs(config.metadata_ttl_secs))
                .build(),
            failures: Cache::builder()
                .max_capacity(1024)
                .time_to_live(Duration::from_secs(30))
                .build(),
            config,
        })
    }

    pub(crate) async fn database<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    ) -> Result<T> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = db
                .lock()
                .map_err(|_| Error::internal("cache lock poisoned"))?;
            f(&mut db).map_err(|e| Error::internal(format!("cache: {e}")))
        })
        .await
        .map_err(|e| Error::internal(e.to_string()))?
    }

    pub(crate) async fn read_database<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    ) -> Result<T> {
        let db = self.read_db.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = db
                .lock()
                .map_err(|_| Error::internal("cache lock poisoned"))?;
            f(&mut db).map_err(|e| Error::internal(format!("cache: {e}")))
        })
        .await
        .map_err(|e| Error::internal(e.to_string()))?
    }

    /// Concurrent misses for the same key share one initializer, including disk reads.
    /// Store raw upstream data; never cache a policy decision or a rewritten URL.
    pub async fn get<F, Fut>(&self, key: String, stats: bool, fetch: F) -> Result<Arc<Value>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        self.get_decoded(key, stats, false, fetch).await
    }

    /// Cache bounded UTF-8 upstream text in the same budget as JSON metadata.
    /// The Value string is an unfiltered representation, not an authorization decision.
    pub async fn get_text<F, Fut>(&self, key: String, fetch: F) -> Result<Arc<Value>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        self.get_decoded(format!("text:{key}"), false, true, fetch)
            .await
    }

    async fn get_decoded<F, Fut>(
        &self,
        key: String,
        stats: bool,
        text: bool,
        fetch: F,
    ) -> Result<Arc<Value>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        let hot = if stats { &self.stats } else { &self.metadata };
        if let Some(e) = self.failures.get(&key).await {
            return Err(e);
        }
        if let Some(entry) = hot.get(&key).await {
            if entry.expires > Utc::now().timestamp() {
                return Ok(entry.value);
            }
            hot.invalidate(&key).await;
        }
        let result = hot.try_get_with(key.clone(), async {
            let lookup = key.clone();
            let disk: Option<(Vec<u8>, i64)> = self.database(move |db| db.query_row("SELECT body, expires FROM responses WHERE key = ?1 AND expires > ?2", params![lookup, Utc::now().timestamp()], |r| Ok((r.get(0)?, r.get(1)?))).optional()).await?;
            let (body, expires, fresh) = match disk {
                Some((body, expires)) => (body, expires, false),
                None => {
                    let body = fetch().await?;
                    let ttl = if stats { self.config.stats_ttl_secs } else { self.config.metadata_ttl_secs };
                    (body, Utc::now().timestamp() + ttl as i64, true)
                }
            };
            let (body, value) = tokio::task::spawn_blocking(move || {
                let value: Value = if text {
                    Value::String(std::str::from_utf8(&body)
                        .map_err(|_| Error::upstream("invalid upstream UTF-8"))?.to_owned())
                } else {
                    serde_json::from_slice(&body).map_err(|_| Error::upstream("invalid upstream JSON"))?
                };
                Ok::<_, Error>((body, value))
            }).await.map_err(|e| Error::internal(e.to_string()))??;
            // Approximate parsed JSON allocation, plus key/entry overhead.
            let weight = body.len().saturating_mul(4).saturating_add(key.len() + 256).min(u32::MAX as usize) as u32;
            if fresh {
                let write_key = key.clone();
                let max_bytes = (self.config.disk_mb * 1024 * 1024) as i64;
                self.database(move |db| {
                    let tx = db.transaction()?;
                    let now = Utc::now().timestamp();
                    tx.execute("DELETE FROM responses WHERE expires <= ?1 OR key = ?2", params![now, write_key])?;
                    let size = (body.len() + write_key.len() + 256) as i64;
                    if size <= max_bytes {
                        tx.execute("INSERT INTO responses VALUES (?1, ?2, ?3, ?4, ?5)", params![write_key, body, expires, now, size])?;
                    }
                    while tx.query_row("SELECT bytes FROM accounting WHERE id = 1", [], |r| r.get::<_, i64>(0))? > max_bytes {
                        tx.execute("DELETE FROM responses WHERE key IN (SELECT key FROM responses WHERE key <> ?1 ORDER BY written LIMIT 32)", [&write_key])?;
                    }
                    tx.commit()
                }).await?;
            }
            Ok::<_, Error>(Entry { value: Arc::new(value), expires, weight })
        }).await;
        match result {
            Ok(entry) => Ok(entry.value),
            Err(e) => {
                self.failures.insert(key, (*e).clone()).await;
                Err((*e).clone())
            }
        }
    }

    /// This compact safety ledger is deliberately not evicted with the response cache.
    pub async fn observe(&self, keys: Vec<String>) -> Result<Vec<i64>> {
        self.database(move |db| {
            let tx = db.transaction()?;
            let now = Utc::now().timestamp();
            let mut times = Vec::with_capacity(keys.len());
            {
                let mut insert =
                    tx.prepare_cached("INSERT OR IGNORE INTO first_seen VALUES (?1, ?2)")?;
                let mut select =
                    tx.prepare_cached("SELECT timestamp FROM first_seen WHERE key = ?1")?;
                for key in keys {
                    insert.execute(params![key, now])?;
                    times.push(select.query_row([key], |r| r.get(0))?);
                }
            }
            tx.commit()?;
            Ok(times)
        })
        .await
    }

    pub(crate) async fn raw<F, Fut>(&self, key: String, fetch: F) -> Result<Arc<RawMetadata>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<RawMetadata>>,
    {
        let key = format!("raw-v1:{key}");
        if let Some(e) = self.failures.get(&key).await {
            return Err(e);
        }
        if let Some(e) = self.raw.get(&key).await {
            if e.expires > Utc::now().timestamp() {
                return Ok(e.value);
            }
            self.raw.invalidate(&key).await;
        }
        let result = self.raw.try_get_with(key.clone(), async {
            let lookup = key.clone();
            let disk: Option<(Vec<u8>, i64)> = self.database(move |db| db.query_row(
                "SELECT body, expires FROM responses WHERE key = ?1 AND expires > ?2",
                params![lookup, Utc::now().timestamp()], |r| Ok((r.get(0)?, r.get(1)?))).optional()).await?;
            let (value, expires) = if let Some((data, expires)) = disk {
                // The header is a small JSON object followed by unchanged upstream bytes.
                let separator = data.iter().position(|b| *b == b'\n')
                    .ok_or_else(|| Error::internal("invalid raw cache entry"))?;
                let mut value: RawMetadata = serde_json::from_slice(&data[..separator])
                    .map_err(|_| Error::internal("invalid raw cache headers"))?;
                value.body = data[separator + 1..].to_vec();
                (value, expires)
            } else {
                let value = fetch().await?;
                let expires = Utc::now().timestamp() + self.config.metadata_ttl_secs as i64;
                let headers = RawMetadata { body: vec![], media_type: value.media_type.clone(), digest: value.digest.clone() };
                let mut data = serde_json::to_vec(&headers).map_err(|_| Error::internal("raw cache serialization"))?;
                data.push(b'\n'); data.extend_from_slice(&value.body);
                let write_key = key.clone();
                let max_bytes = (self.config.disk_mb * 1024 * 1024) as i64;
                self.database(move |db| {
                    let tx = db.transaction()?;
                    let now = Utc::now().timestamp();
                    tx.execute("DELETE FROM responses WHERE expires <= ?1 OR key = ?2", params![now, write_key])?;
                    let size = (data.len() + write_key.len() + 256) as i64;
                    if size <= max_bytes {
                        tx.execute("INSERT INTO responses VALUES (?1, ?2, ?3, ?4, ?5)", params![write_key, data, expires, now, size])?;
                    }
                    while tx.query_row("SELECT bytes FROM accounting WHERE id = 1", [], |r| r.get::<_, i64>(0))? > max_bytes {
                        tx.execute("DELETE FROM responses WHERE key IN (SELECT key FROM responses WHERE key <> ?1 ORDER BY written LIMIT 32)", [&write_key])?;
                    }
                    tx.commit()
                }).await?;
                (value, expires)
            };
            let weight = value.body.len().saturating_add(key.len() + 512).min(u32::MAX as usize) as u32;
            Ok::<_, Error>(RawEntry { value: Arc::new(value), expires, weight })
        }).await;
        match result {
            Ok(e) => Ok(e.value),
            Err(e) => {
                self.failures.insert(key, (*e).clone()).await;
                Err((*e).clone())
            }
        }
    }

    /// Associations survive response eviction. Observation and evidence are committed atomically.
    pub(crate) async fn observe_homebrew(&self, identity: String, evidence: String) -> Result<i64> {
        self.database(move |db| {
            let tx = db.transaction()?;
            let now = Utc::now().timestamp();
            tx.execute("INSERT OR IGNORE INTO first_seen VALUES (?1, ?2)", params![identity, now])?;
            tx.execute("INSERT INTO homebrew_evidence VALUES (?1, ?2, ?3) ON CONFLICT(identity) DO UPDATE SET evidence=excluded.evidence, verified=excluded.verified", params![identity, evidence, now])?;
            let first_seen = tx.query_row("SELECT timestamp FROM first_seen WHERE key=?1", [&identity], |r| r.get(0))?;
            tx.commit()?;
            Ok(first_seen)
        }).await
    }
}
