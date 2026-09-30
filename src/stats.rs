//! Local artifact transfer statistics, independent of upstream popularity counts.
use crate::{
    App,
    cache::Store,
    error::{Error, Result},
    json_response,
    registry::Ecosystem,
};
use axum::{
    extract::{Query, State},
    response::Response,
};
use chrono::Utc;
use rusqlite::params;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone)]
pub(crate) struct Identity {
    ecosystem: String,
    package: String,
    release: String,
}

impl Identity {
    pub(crate) fn new(ecosystem: Ecosystem, package: &str, release: &str) -> Self {
        Self {
            ecosystem: ecosystem.as_str().into(),
            package: package.into(),
            release: release.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatsQuery {
    ecosystem: Option<String>,
    package: Option<String>,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}
fn default_limit() -> u32 {
    100
}

pub(crate) async fn handle(
    State(app): State<App>,
    Query(query): Query<StatsQuery>,
) -> Result<Response> {
    if query.limit == 0 || query.limit > 1000 {
        return Err(Error::bad("limit must be between 1 and 1000"));
    }
    if let Some(ecosystem) = &query.ecosystem {
        Ecosystem::parse(ecosystem)?;
    }
    let report = app.store.download_stats(query).await?;
    Ok(json_response(report, "application/json"))
}

impl Store {
    pub(crate) async fn record_download(
        &self,
        identity: Identity,
        bytes: u64,
        partial: bool,
    ) -> Result<()> {
        let bytes =
            i64::try_from(bytes).map_err(|_| Error::internal("transfer too large to count"))?;
        self.database(move |db| {
            let now = Utc::now().timestamp();
            db.execute(
                "INSERT INTO downloads VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(ecosystem, package, release) DO UPDATE SET
                    full_downloads = full_downloads + excluded.full_downloads,
                    range_transfers = range_transfers + excluded.range_transfers,
                    bytes = bytes + excluded.bytes,
                    first_download = MIN(first_download, excluded.first_download),
                    last_download = MAX(last_download, excluded.last_download)",
                params![
                    identity.ecosystem,
                    identity.package,
                    identity.release,
                    i64::from(!partial),
                    i64::from(partial),
                    bytes,
                    now
                ],
            )?;
            Ok(())
        })
        .await
    }

    async fn download_stats(&self, query: StatsQuery) -> Result<Value> {
        // pip rows are stored under the PEP 503 normalized name; match either
        // spelling so a package filter finds them without an ecosystem selection.
        let pip_package = query
            .package
            .as_deref()
            .and_then(|name| crate::registry::pip::normalize(name).ok());
        self.read_database(move |db| {
            // A transaction keeps totals and the paginated rows on the same snapshot.
            let tx = db.transaction()?;
            let filter = "WHERE (?1 IS NULL OR ecosystem = ?1)
                 AND (?2 IS NULL OR package = ?2 OR (ecosystem = 'pip' AND package = ?3))";
            let args = params![query.ecosystem, query.package, pip_package];
            let totals = tx.query_row(&format!(
                "SELECT COALESCE(SUM(full_downloads), 0), COALESCE(SUM(range_transfers), 0),
                    COALESCE(SUM(bytes), 0), COUNT(*), MIN(first_download), MAX(last_download)
                 FROM downloads {filter}"
            ), args, |r| Ok(json!({
                "full_downloads": r.get::<_, i64>(0)?, "range_transfers": r.get::<_, i64>(1)?,
                "bytes": r.get::<_, i64>(2)?, "releases": r.get::<_, i64>(3)?,
                "first_download": r.get::<_, Option<i64>>(4)?, "last_download": r.get::<_, Option<i64>>(5)?
            })))?;
            let packages: i64 = tx.query_row(&format!(
                "SELECT COUNT(*) FROM (SELECT ecosystem, package FROM downloads {filter} GROUP BY ecosystem, package)"
            ), args, |r| r.get(0))?;
            let mut totals = totals;
            totals["packages"] = json!(packages);
            let ecosystems = {
                let mut statement = tx.prepare(&format!(
                    "SELECT ecosystem, COUNT(DISTINCT package), COUNT(*), SUM(full_downloads), SUM(range_transfers), SUM(bytes)
                     FROM downloads {filter} GROUP BY ecosystem ORDER BY ecosystem"
                ))?;
                statement.query_map(args, |r| Ok(json!({
                    "ecosystem": r.get::<_, String>(0)?, "packages": r.get::<_, i64>(1)?,
                    "releases": r.get::<_, i64>(2)?, "full_downloads": r.get::<_, i64>(3)?,
                    "range_transfers": r.get::<_, i64>(4)?, "bytes": r.get::<_, i64>(5)?
                })))?.collect::<rusqlite::Result<Vec<_>>>()?
            };
            let releases = {
                let mut statement = tx.prepare(&format!(
                    "SELECT ecosystem, package, release, full_downloads, range_transfers, bytes, first_download, last_download
                     FROM downloads {filter} ORDER BY last_download DESC, ecosystem, package, release LIMIT ?4 OFFSET ?5"
                ))?;
                statement.query_map(params![query.ecosystem, query.package, pip_package, query.limit, query.offset], |r| Ok(json!({
                    "ecosystem": r.get::<_, String>(0)?, "package": r.get::<_, String>(1)?,
                    "release": r.get::<_, String>(2)?, "full_downloads": r.get::<_, i64>(3)?,
                    "range_transfers": r.get::<_, i64>(4)?, "bytes": r.get::<_, i64>(5)?,
                    "first_download": r.get::<_, i64>(6)?, "last_download": r.get::<_, i64>(7)?
                })))?.collect::<rusqlite::Result<Vec<_>>>()?
            };
            tx.commit()?;
            Ok(json!({
                "measurement": "proxy_artifact_transfers",
                "totals": totals, "ecosystems": ecosystems, "releases": releases,
                "limit": query.limit, "offset": query.offset,
                "limitations": "Transfers do not confirm installation. Retries count separately; client caches and downloads bypassing middles are invisible. Python releases are filenames. Timestamps are Unix seconds in UTC."
            }))
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, Bytes},
        http::StatusCode,
        routing::get,
    };
    use futures_util::{StreamExt, stream};
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn counts_chunked_completion_but_not_errors_disconnects_or_416() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let upstream = Router::new()
            .route(
                "/chunked",
                get(|| async {
                    Body::from_stream(stream::iter([
                        Ok::<_, std::io::Error>(Bytes::from_static(b"abc")),
                        Ok(Bytes::from_static(b"def")),
                    ]))
                }),
            )
            .route(
                "/interrupted",
                get(|| async {
                    Body::from_stream(
                        stream::once(async { Ok::<_, std::io::Error>(Bytes::from_static(b"abc")) })
                            .chain(stream::pending()),
                    )
                }),
            )
            .route(
                "/error",
                get(|| async {
                    Body::from_stream(
                        stream::once(async { Ok::<_, std::io::Error>(Bytes::from_static(b"abc")) })
                            .chain(stream::once(async {
                                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                Err(std::io::Error::other("broken upstream"))
                            })),
                    )
                }),
            )
            .route(
                "/unsatisfiable",
                get(|| async { (StatusCode::RANGE_NOT_SATISFIABLE, "out of range") }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let mut config = crate::config::Config::default();
        config.cache.path = dir.path().join("stats.sqlite3");
        config.upstream.allow_http = true;
        config.upstream.artifact_hosts = vec!["127.0.0.1".into()];
        let app = App::new(config).await.unwrap();
        for endpoint in ["chunked", "interrupted", "error", "unsatisfiable"] {
            let response = app
                .stream_download(
                    &format!("{origin}/{endpoint}"),
                    Default::default(),
                    Some(Identity::new(Ecosystem::Npm, "test", endpoint)),
                )
                .await
                .unwrap();
            let mut body = response.into_body();
            match endpoint {
                "interrupted" => {
                    assert_eq!(
                        body.frame().await.unwrap().unwrap().into_data().unwrap(),
                        "abc"
                    );
                    drop(body);
                }
                "error" => assert!(body.collect().await.is_err()),
                _ => {
                    body.collect().await.unwrap();
                }
            }
        }
        let stats = app
            .store
            .download_stats(StatsQuery {
                ecosystem: None,
                package: None,
                limit: 100,
                offset: 0,
            })
            .await
            .unwrap();
        assert_eq!(stats["totals"]["full_downloads"], 1);
        assert_eq!(stats["totals"]["range_transfers"], 0);
        assert_eq!(stats["totals"]["bytes"], 6);
        assert_eq!(stats["releases"][0]["release"], "chunked");
        server.abort();
    }

    #[tokio::test]
    async fn package_filter_matches_pip_normalized_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = crate::config::Config::default();
        config.cache.path = dir.path().join("stats.sqlite3");
        let app = App::new(config).await.unwrap();
        let identity = Identity::new(Ecosystem::Pip, "typing-extensions", "t.whl");
        app.store.record_download(identity, 3, false).await.unwrap();
        for (ecosystem, package, expected) in [
            (None, "Typing_Extensions", 1),
            (None, "typing-extensions", 1),
            (Some("pip"), "Typing_Extensions", 1),
            (Some("npm"), "Typing_Extensions", 0),
            (None, "other", 0),
        ] {
            let stats = app
                .store
                .download_stats(StatsQuery {
                    ecosystem: ecosystem.map(String::from),
                    package: Some(package.into()),
                    limit: 100,
                    offset: 0,
                })
                .await
                .unwrap();
            assert_eq!(
                stats["totals"]["full_downloads"], expected,
                "{ecosystem:?} {package}"
            );
        }
    }
}
