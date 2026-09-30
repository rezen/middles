use rusqlite::Connection;
use serde_json::{Value, json};
use std::{fs::File, io::Write, path::Path, process::Command};

fn archive(dir: &Path, ecosystem: &str, records: &[Value]) {
    let file = File::create(dir.join(format!("{ecosystem}.zip"))).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (index, record) in records.iter().enumerate() {
        zip.start_file(
            format!("records/{index}.json"),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(serde_json::to_string(record).unwrap().as_bytes())
            .unwrap();
    }
    zip.finish().unwrap();
}

fn rows(database: &Path) -> Vec<(String, String, String)> {
    let db = Connection::open(database).unwrap();
    let mut query = db
        .prepare("SELECT ecosystem, package, id FROM advisories ORDER BY ecosystem, package, id")
        .unwrap();
    query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn cli_imports_offline_and_preserves_mirror_on_invalid_archive() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("archives");
    std::fs::create_dir(&source).unwrap();
    let database = root.path().join("cache.sqlite3");
    let config = root.path().join("middles.toml");
    std::fs::write(&config, format!("[cache]\npath = {:?}\n", database)).unwrap();
    archive(
        &source,
        "npm",
        &[
            json!({"id":"GHSA-aaaa-bbbb-cccc","affected":[{"package":{"ecosystem":"npm","name":"demo"},"versions":["1.0.0"]}]}),
        ],
    );
    archive(
        &source,
        "Debian",
        &[
            json!({"id":"DEBIAN-CVE-2024-3094","affected":[{"package":{"ecosystem":"Debian:12","name":"xz-utils"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}),
        ],
    );
    let run = |ecosystems: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_middles"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "osv-sync",
                "--source-dir",
                source.to_str().unwrap(),
                "--ecosystems",
            ])
            .args(ecosystems)
            .output()
            .unwrap()
    };
    let success = run(&["npm", "Debian"]);
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let imported = rows(&database);
    assert_eq!(
        imported,
        vec![
            (
                "Debian:12".into(),
                "xz-utils".into(),
                "DEBIAN-CVE-2024-3094".into()
            ),
            ("npm".into(), "demo".into(), "GHSA-aaaa-bbbb-cccc".into()),
        ]
    );
    let db = Connection::open(&database).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT records FROM advisory_imports WHERE ecosystem='Debian'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    drop(db);

    archive(&source, "npm", &[]);
    assert!(!run(&["npm"]).status.success());
    assert_eq!(rows(&database), imported);

    archive(
        &source,
        "npm",
        &[
            json!({"id":"GHSA-dddd-eeee-ffff","affected":[{"package":{"ecosystem":"npm","name":"changed"}}]}),
        ],
    );
    archive(&source, "PyPI", &[json!({"id":"invalid id","affected":[]})]);
    let failure = run(&["npm", "PyPI"]);
    assert!(!failure.status.success());
    assert_eq!(rows(&database), imported);
}
