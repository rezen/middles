use crate::{
    App,
    error::{Error, Result},
    json_response,
    registry::{Ecosystem, composer_name},
};
use axum::{
    extract::{Path, State},
    response::Response,
};
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub async fn index(State(app): State<App>) -> Response {
    let metadata_url = format!(
        "{}/composer/p2/%package%.json",
        app.config.public_url.trim_end_matches('/')
    );
    json_response(
        json!({"packages": {}, "metadata-url": metadata_url}),
        "application/json",
    )
}

/// Packagist deltas replace whole top-level values; __unset removes a key.
/// Expand *before* filtering or removed versions corrupt later inherited metadata.
pub fn expand(raw: &Value, package: &str) -> Result<Vec<Value>> {
    if let Some(format) = raw.get("minified")
        && format != "composer/2.0"
    {
        return Err(Error::upstream("unsupported Composer minification"));
    }
    let Some(entries) = raw.get("packages").and_then(|p| p.get(package)) else {
        return Ok(Vec::new());
    };
    let entries = entries
        .as_array()
        .ok_or_else(|| Error::upstream("invalid Composer versions"))?;
    if raw.get("minified").is_none() {
        return Ok(entries.clone());
    }
    let mut previous = serde_json::Map::new();
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        for (key, value) in entry
            .as_object()
            .ok_or_else(|| Error::upstream("invalid Composer delta"))?
        {
            if value == "__unset" {
                previous.remove(key);
            } else {
                previous.insert(key.clone(), value.clone());
            }
        }
        result.push(Value::Object(previous.clone()));
    }
    Ok(result)
}

async fn eligible(app: &App, package: &str, dev: bool) -> Result<Vec<Value>> {
    composer_name(package)?;
    let base = app.config.upstream.packagist.trim_end_matches('/');
    let suffix = if dev { "~dev" } else { "" };
    let raw = app
        .metadata(
            format!("{base}/p2/{package}{suffix}.json"),
            "application/json",
            false,
        )
        .await?;
    app.check_downloads(Ecosystem::Composer, package).await?;
    let versions = expand(&raw, package)?;
    let keys = versions
        .iter()
        .map(|v| {
            let identity = json!([
                base,
                package,
                v["version"],
                v["time"],
                v["dist"],
                v["source"]
            ]);
            format!(
                "composer:{:x}",
                Sha256::digest(identity.to_string().as_bytes())
            )
        })
        .collect();
    let seen = app.store.observe(keys).await?;
    let now = Utc::now();
    let policy = app.config.policy_for(Ecosystem::Composer);
    Ok(versions
        .into_iter()
        .zip(seen)
        .filter_map(|(mut v, seen)| {
            if policy.install_hooks == crate::inspection::HookPolicy::Deny
                && crate::inspection::composer(&v).dependency_execution
            {
                return None;
            }
            let version = v["version"].as_str()?;
            if version.starts_with("dev-")
                || version.ends_with("-dev")
                || !policy.allows_time(v["time"].as_str(), now)
                || !policy.allows_timestamp(seen, now.timestamp())
            {
                return None;
            }
            if v["type"] != "metapackage"
                && v.pointer("/dist/url").and_then(Value::as_str).is_none()
            {
                return None;
            }
            // Source fallback leaves this HTTP proxy, so only distribute archives/metapackages.
            v.as_object_mut()?.remove("source");
            Some(v)
        })
        .collect())
}

pub async fn handle(State(app): State<App>, Path(path): Path<String>) -> Result<Response> {
    let package = path
        .strip_suffix(".json")
        .ok_or_else(|| Error::bad("expected a Composer p2 JSON path"))?;
    let (package, dev) = package
        .strip_suffix("~dev")
        .map(|p| (p, true))
        .unwrap_or((package, false));
    let mut versions = eligible(&app, package, dev).await?;
    for info in &mut versions {
        let version = info["version"]
            .as_str()
            .ok_or_else(|| Error::upstream("Composer release missing version"))?
            .to_string();
        if let Some(dist) = info.get_mut("dist").and_then(Value::as_object_mut) {
            dist.insert(
                "url".into(),
                json!(app.artifact_url(Ecosystem::Composer, package, &version, "archive.zip")),
            );
            dist.remove("mirrors");
        }
    }
    Ok(json_response(
        json!({"packages": {package: versions}}),
        "application/json",
    ))
}

pub async fn artifact(app: &App, package: &str, version: &str) -> Result<String> {
    eligible(app, package, false)
        .await?
        .iter()
        .find(|v| v["version"].as_str() == Some(version))
        .and_then(|v| v.pointer("/dist/url"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::denied("Composer release is not eligible (including first-seen age)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expands_before_removal_and_replaces_nested_objects() {
        let doc = json!({"minified":"composer/2.0","packages":{"a/b":[{"version":"2.0","time":"new","require":{"a":"1","b":"2"},"source":{"url":"git"}},{"version":"1.0","time":"old","require":{"a":"0"},"source":"__unset"},{"version":"0.9"}]}});
        let result = expand(&doc, "a/b").unwrap();
        assert_eq!(result[1]["require"], json!({"a":"0"}));
        assert!(result[1].get("source").is_none());
        assert_eq!(result[2]["time"], "old");
    }
}
