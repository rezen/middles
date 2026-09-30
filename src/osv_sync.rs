//! Operator-run import of OSV ecosystem dumps into the local advisory mirror.
//! Downloads and validation finish before a single transaction updates live data.
use anyhow::{Context, bail};
use futures_util::StreamExt;
use rusqlite::{Connection, params};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Duration,
};

pub const DEFAULT_ECOSYSTEMS: &[&str] = &["npm", "PyPI", "Packagist", "RubyGems"];
pub const ECOSYSTEMS: &[&str] = &["npm", "PyPI", "Packagist", "RubyGems", "Debian", "Ubuntu"];
const MAX_ZIP_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ENTRIES: usize = 2_000_000;

pub struct Import {
    pub ecosystem: String,
    pub records: i64,
}

pub async fn sync(
    database: &Path,
    selected: &[String],
    source_dir: Option<&Path>,
) -> anyhow::Result<Vec<Import>> {
    let selected = selected.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if selected.is_empty() || selected.iter().any(|name| !ECOSYSTEMS.contains(name)) {
        bail!(
            "ecosystems must be one or more of: {}",
            ECOSYSTEMS.join(", ")
        );
    }
    let temp = tempfile::tempdir().context("create OSV staging directory")?;
    let staging = temp.path().join("staging.sqlite3");
    let mut db = Connection::open(&staging).context("open OSV staging database")?;
    db.execute_batch(
        "CREATE TABLE advisories (ecosystem TEXT NOT NULL, package TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (ecosystem, package, id))",
    )?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let mut sources = Vec::new();
    for ecosystem in selected {
        let local_path = source_dir.map(|dir| dir.join(format!("{ecosystem}.zip")));
        let source = if let Some(path) = &local_path {
            if !path.is_file() {
                bail!("missing OSV archive: {}", path.display());
            }
            path.display().to_string()
        } else {
            format!("https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip")
        };
        let path = if let Some(path) = local_path {
            path
        } else {
            let path = temp.path().join(format!("{ecosystem}.zip"));
            download(&client, &source, &path).await?;
            path
        };
        ingest(&mut db, &path, ecosystem)
            .with_context(|| format!("import {ecosystem} from {}", path.display()))?;
        sources.push((ecosystem.to_owned(), source));
    }
    drop(db);
    install(database, &staging, &sources)
}

async fn download(client: &reqwest::Client, url: &str, path: &Path) -> anyhow::Result<()> {
    let response = client.get(url).send().await?.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_ZIP_BYTES)
    {
        bail!("OSV archive exceeds size bound: {url}");
    }
    let mut file = File::create(path)?;
    let mut total = 0u64;
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        total = total.saturating_add(chunk.len() as u64);
        if total > MAX_ZIP_BYTES {
            bail!("OSV archive exceeds size bound: {url}");
        }
        file.write_all(&chunk)?;
    }
    Ok(())
}

fn belongs(actual: &str, selected: &str) -> bool {
    actual == selected
        || actual
            .strip_prefix(selected)
            .is_some_and(|tail| tail.starts_with(':'))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn ingest(db: &mut Connection, path: &Path, selected: &str) -> anyhow::Result<()> {
    if path.metadata()?.len() > MAX_ZIP_BYTES {
        bail!("OSV archive exceeds size bound");
    }
    let mut archive = zip::ZipArchive::new(File::open(path)?)?;
    if archive.len() > MAX_ENTRIES {
        bail!("OSV archive has too many entries");
    }
    let mut uncompressed = 0u64;
    let mut rows = 0u64;
    let tx = db.transaction()?;
    for index in 0..archive.len() {
        let mut item = archive.by_index(index)?;
        if item.is_dir() || !item.name().ends_with(".json") {
            continue;
        }
        if item.size() > MAX_RECORD_BYTES {
            bail!("oversized OSV record: {}", item.name());
        }
        let mut body = Vec::new();
        item.by_ref()
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut body)?;
        if body.len() as u64 > MAX_RECORD_BYTES {
            bail!("oversized OSV record: {}", item.name());
        }
        uncompressed = uncompressed.saturating_add(body.len() as u64);
        if uncompressed > MAX_UNCOMPRESSED_BYTES {
            bail!("OSV archive exceeds uncompressed size bound");
        }
        let record: Value = serde_json::from_slice(&body)?;
        let object = record.as_object().context("OSV record must be an object")?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .context("invalid OSV advisory ID")?;
        let affected: &[Value] = match object.get("affected") {
            Some(Value::Array(affected)) => affected,
            None => &[],
            _ => bail!("invalid OSV affected list in {id}"),
        };
        let mut identities = BTreeSet::new();
        for entry in affected {
            let package = entry
                .get("package")
                .and_then(Value::as_object)
                .with_context(|| format!("invalid OSV package in {id}"))?;
            let ecosystem = package
                .get("ecosystem")
                .and_then(Value::as_str)
                .with_context(|| format!("missing OSV ecosystem in {id}"))?;
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty() && name.len() <= 512)
                .with_context(|| format!("invalid OSV package name in {id}"))?;
            if belongs(ecosystem, selected) {
                identities.insert((ecosystem, name));
            }
        }
        if !identities.is_empty() {
            let body = serde_json::to_vec(&record)?;
            for (ecosystem, name) in identities {
                tx.execute(
                    "INSERT OR REPLACE INTO advisories VALUES (?1, ?2, ?3, ?4)",
                    params![ecosystem, name, id, body],
                )?;
                rows += 1;
            }
        }
    }
    if rows == 0 {
        bail!("OSV archive has no advisories for {selected}");
    }
    tx.commit()?;
    Ok(())
}

fn install(
    database: &Path,
    staging: &Path,
    sources: &[(String, String)],
) -> anyhow::Result<Vec<Import>> {
    if let Some(parent) = database.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut db = Connection::open(database)?;
    db.busy_timeout(Duration::from_secs(30))?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS advisories (ecosystem TEXT NOT NULL, package TEXT NOT NULL, id TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (ecosystem, package, id));
         CREATE TABLE IF NOT EXISTS advisory_imports (ecosystem TEXT PRIMARY KEY, imported_at INTEGER NOT NULL, records INTEGER NOT NULL, source TEXT NOT NULL);",
    )?;
    db.execute(
        "ATTACH DATABASE ?1 AS staging",
        [staging.to_string_lossy().as_ref()],
    )?;
    let mut imports = Vec::new();
    let now = chrono::Utc::now().timestamp();
    let tx = db.transaction()?;
    for (ecosystem, source) in sources {
        let prefix = format!("{ecosystem}:%");
        tx.execute(
            "DELETE FROM advisories WHERE ecosystem = ?1 OR ecosystem LIKE ?2",
            params![ecosystem, prefix],
        )?;
        tx.execute(
            "INSERT INTO advisories SELECT ecosystem, package, id, body FROM staging.advisories WHERE ecosystem = ?1 OR ecosystem LIKE ?2",
            params![ecosystem, prefix],
        )?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM staging.advisories WHERE ecosystem = ?1 OR ecosystem LIKE ?2",
            params![ecosystem, prefix],
            |row| row.get(0),
        )?;
        tx.execute(
            "INSERT INTO advisory_imports VALUES (?1, ?2, ?3, ?4) ON CONFLICT(ecosystem) DO UPDATE SET imported_at=excluded.imported_at, records=excluded.records, source=excluded.source",
            params![ecosystem, now, count, source],
        )?;
        imports.push(Import {
            ecosystem: ecosystem.clone(),
            records: count,
        });
    }
    tx.commit()?;
    Ok(imports)
}
