use crate::{
    App,
    error::{Error, Result},
    json_response,
    policy::Policy,
    registry::{Ecosystem, npm_name},
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method},
    response::Response,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};

pub(crate) async fn raw(app: &App, package: &str) -> Result<Arc<Value>> {
    npm_name(package)?;
    app.metadata(
        format!(
            "{}/{package}",
            app.config.upstream.npm.trim_end_matches('/')
        ),
        "application/json",
        false,
    )
    .await
}

pub fn filter(raw: &Value, policy: &Policy, now: DateTime<Utc>) -> Result<Value> {
    filter_with_blocked(raw, policy, now, &HashSet::new())
}

fn filter_with_blocked(
    raw: &Value,
    policy: &Policy,
    now: DateTime<Utc>,
    blocked: &HashSet<String>,
) -> Result<Value> {
    let mut doc = raw.clone();
    let times = raw
        .get("time")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::upstream("npm metadata missing publication times"))?;
    let versions = doc
        .get_mut("versions")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::upstream("invalid npm versions"))?;
    versions.retain(|v, info| {
        !blocked.contains(v)
            && policy.allows_time(times.get(v).and_then(Value::as_str), now)
            && (policy.install_hooks != crate::inspection::HookPolicy::Deny
                || !crate::inspection::npm(info).dependency_execution)
    });
    if versions.is_empty() {
        return Err(Error::denied(
            "no npm versions meet the age, hook, and advisory policies",
        ));
    }
    let allowed = versions
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    // Retarget latest to an eligible stable version, without promoting above upstream latest.
    let upstream_latest = raw
        .pointer("/dist-tags/latest")
        .and_then(Value::as_str)
        .and_then(|s| semver::Version::parse(s).ok());
    let fallback = allowed
        .iter()
        .filter_map(|s| semver::Version::parse(s).ok().map(|v| (v, s)))
        .filter(|(v, _)| {
            v.pre.is_empty() && upstream_latest.as_ref().is_some_and(|latest| v <= latest)
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, s)| s.clone());
    if let Some(tags) = doc.get_mut("dist-tags").and_then(Value::as_object_mut) {
        tags.retain(|_, v| v.as_str().is_some_and(|s| allowed.contains(s)));
        if !tags.contains_key("latest")
            && let Some(latest) = fallback
        {
            tags.insert("latest".into(), json!(latest));
        }
    }
    if let Some(times) = doc.get_mut("time").and_then(Value::as_object_mut) {
        times.retain(|k, _| allowed.contains(k) || matches!(k.as_str(), "created" | "modified"));
    }
    Ok(doc)
}

pub async fn handle(
    State(app): State<App>,
    Path(path): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Result<Response> {
    let (package, suffix) = split_path(&path)?;
    let raw = raw(&app, package).await?;
    app.check_downloads(Ecosystem::Npm, package).await?;
    let mut doc = filter(&raw, &app.config.policy_for(Ecosystem::Npm), Utc::now())?;
    let needs_batch = suffix.is_empty() || raw["dist-tags"].get(suffix).is_some();
    if needs_batch {
        let versions = doc["versions"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let blocked = app
            .blocked_advisory_versions(Ecosystem::Npm, package, &versions)
            .await?;
        if !blocked.is_empty() {
            doc = filter_with_blocked(
                &raw,
                &app.config.policy_for(Ecosystem::Npm),
                Utc::now(),
                &blocked,
            )?;
        }
    }
    if let Some(filename) = suffix.strip_prefix("-/") {
        // npm lockfiles may refer to the conventional registry tarball path.
        let (version, url) = doc["versions"]
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(version, v)| {
                v.pointer("/dist/tarball")
                    .and_then(Value::as_str)
                    .map(|url| (version, url))
            })
            .find(|(_, raw)| {
                url::Url::parse(raw)
                    .ok()
                    .is_some_and(|u| u.path().rsplit('/').next() == Some(filename))
            })
            .ok_or_else(|| Error::denied("tarball does not belong to an eligible npm version"))?;
        let identity = (method == Method::GET)
            .then(|| crate::stats::Identity::new(Ecosystem::Npm, package, version));
        app.check_advisories(Ecosystem::Npm, package, version)
            .await?;
        return app.stream_download(url, headers, identity).await;
    }
    for (version, info) in doc["versions"].as_object_mut().unwrap() {
        if let Some(dist) = info.get_mut("dist").and_then(Value::as_object_mut)
            && dist.get("tarball").and_then(Value::as_str).is_some()
        {
            dist.insert(
                "tarball".into(),
                json!(app.artifact_url(Ecosystem::Npm, package, version, "package.tgz")),
            );
        }
    }
    if !suffix.is_empty() {
        let version = doc["dist-tags"]
            .get(suffix)
            .and_then(Value::as_str)
            .unwrap_or(suffix);
        let info = doc["versions"].get(version).cloned().ok_or_else(|| {
            Error::denied("requested npm version or tag is unavailable under policy")
        })?;
        app.check_advisories(Ecosystem::Npm, package, version)
            .await?;
        return Ok(json_response(info, "application/json"));
    }
    Ok(json_response(doc, "application/json"))
}

pub async fn artifact(
    app: &App,
    package: &str,
    version: &str,
    now: DateTime<Utc>,
) -> Result<String> {
    let raw = raw(app, package).await?;
    app.check_downloads(Ecosystem::Npm, package).await?;
    let info = raw["versions"]
        .get(version)
        .ok_or_else(|| Error::denied("npm artifact is not eligible"))?;
    if app.config.policy_for(Ecosystem::Npm).install_hooks == crate::inspection::HookPolicy::Deny
        && crate::inspection::npm(info).dependency_execution
    {
        return Err(Error::denied("npm artifact blocked by install-hook policy"));
    }
    if !app
        .config
        .policy_for(Ecosystem::Npm)
        .allows_time(raw["time"].get(version).and_then(Value::as_str), now)
    {
        return Err(Error::denied("npm artifact is not eligible"));
    }
    app.check_advisories(Ecosystem::Npm, package, version)
        .await?;
    raw["versions"]
        .get(version)
        .and_then(|v| v.pointer("/dist/tarball"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::denied("npm artifact is not eligible"))
}

fn split_path(path: &str) -> Result<(&str, &str)> {
    let end = if path.starts_with('@') {
        let scope = path
            .find('/')
            .ok_or_else(|| Error::bad("invalid scoped npm package"))?;
        path[scope + 1..].find('/').map(|i| scope + 1 + i)
    } else {
        path.find('/')
    };
    let (package, suffix) = match end {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (path, ""),
    };
    npm_name(package)?;
    Ok((package, suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tags_and_timestamps_cannot_expose_young_versions() {
        let raw = json!({"versions":{"1.0.0":{},"2.0.0":{},"3.0.0-beta.1":{},"0.9.0":{}},"time":{"1.0.0":"2020-01-01T00:00:00Z","2.0.0":"2099-01-01T00:00:00Z","3.0.0-beta.1":"2020-01-01T00:00:00Z"},"dist-tags":{"latest":"2.0.0","next":"2.0.0","beta":"3.0.0-beta.1"}});
        let result = filter(&raw, &Policy::default(), Utc::now()).unwrap();
        assert_eq!(result["dist-tags"]["latest"], "1.0.0");
        assert!(result["dist-tags"].get("next").is_none());
        assert!(result["versions"].get("2.0.0").is_none());
        assert!(result["versions"].get("0.9.0").is_none());
        assert!(result["time"].get("2.0.0").is_none());
    }
    #[test]
    fn scoped_and_legacy_paths() {
        assert_eq!(
            split_path("@scope/pkg/-/pkg-1.0.tgz").unwrap(),
            ("@scope/pkg", "-/pkg-1.0.tgz")
        );
        assert_eq!(split_path("name/latest").unwrap(), ("name", "latest"));
        assert!(split_path("../foo").is_err());
    }
}
