use middles::{cache::Store, config::CacheConfig, error::Error};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn config(dir: &tempfile::TempDir) -> CacheConfig {
    CacheConfig {
        path: dir.path().join("cache.sqlite3"),
        memory_mb: 1,
        disk_mb: 1,
        ..CacheConfig::default()
    }
}

#[tokio::test]
async fn concurrent_misses_coalesce_and_restart_reuses_disk() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    let cache = Store::open(config.clone()).await.unwrap();
    let fetches = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..24 {
        let cache = cache.clone();
        let fetches = fetches.clone();
        tasks.push(tokio::spawn(async move {
            cache
                .get("key".into(), false, || async {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    Ok(br#"{"value":42}"#.to_vec())
                })
                .await
                .unwrap()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap()["value"], 42);
    }
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    let restarted = Store::open(config).await.unwrap();
    assert_eq!(
        restarted
            .get("key".into(), false, || async { panic!("should hit disk") })
            .await
            .unwrap()["value"],
        42
    );
    let first = cache.observe(vec!["release".into()]).await.unwrap();
    assert_eq!(
        restarted.observe(vec!["release".into()]).await.unwrap(),
        first
    );
}

#[tokio::test]
async fn expiration_refetches_and_outage_never_serves_stale() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(&dir);
    config.metadata_ttl_secs = 1;
    let cache = Store::open(config).await.unwrap();
    cache
        .get("key".into(), false, || async { Ok(b"1".to_vec()) })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(
        cache
            .get("key".into(), false, || async {
                Err(Error::upstream("offline"))
            })
            .await
            .is_err()
    );
    assert!(
        cache
            .get("key".into(), false, || async {
                panic!("failure should be cached briefly")
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn response_budget_evicts_without_losing_safety_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir);
    let cache = Store::open(config.clone()).await.unwrap();
    cache.observe(vec!["keep".into()]).await.unwrap();
    for i in 0..12 {
        let payload = serde_json::to_vec(&json!({"data":"x".repeat(150_000)})).unwrap();
        cache
            .get(format!("key{i}"), false, || async { Ok(payload) })
            .await
            .unwrap();
    }
    let db = rusqlite::Connection::open(config.path).unwrap();
    let total: i64 = db
        .query_row("SELECT COALESCE(SUM(size), 0) FROM responses", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(total <= 1024 * 1024);
    let tracked: i64 = db
        .query_row("SELECT bytes FROM accounting", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, tracked);
    let seen: i64 = db
        .query_row("SELECT COUNT(*) FROM first_seen", [], |r| r.get(0))
        .unwrap();
    assert_eq!(seen, 1);
}
