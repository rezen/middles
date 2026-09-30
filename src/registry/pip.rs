use crate::{
    App,
    error::{Error, Result},
    json_response,
    policy::Policy,
    registry::Ecosystem,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::sync::Arc;

pub fn normalize(name: &str) -> Result<String> {
    if !crate::registry::component(name)
        || !name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(Error::bad("invalid Python project name"));
    }
    let mut result = String::new();
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !result.ends_with('-') {
                result.push('-');
            }
        } else {
            result.push(c.to_ascii_lowercase());
        }
    }
    Ok(result)
}
pub(crate) async fn raw(app: &App, package: &str) -> Result<Arc<Value>> {
    let name = normalize(package)?;
    app.metadata(
        format!(
            "{}/simple/{name}/",
            app.config.upstream.pypi.trim_end_matches('/')
        ),
        "application/vnd.pypi.simple.v1+json",
        false,
    )
    .await
}
pub fn filter(raw: &Value, policy: &Policy, now: DateTime<Utc>) -> Result<Value> {
    let mut doc = raw.clone();
    let api = raw
        .pointer("/meta/api-version")
        .and_then(Value::as_str)
        .unwrap_or("1.0");
    if !api.starts_with("1.") {
        return Err(Error::upstream("unsupported PyPI Simple API major version"));
    }
    let files = doc
        .get_mut("files")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::upstream("invalid PyPI file listing"))?;
    files.retain(|f| {
        policy.allows_time(f.get("upload-time").and_then(Value::as_str), now)
            && (policy.install_hooks != crate::inspection::HookPolicy::Deny
                || !crate::inspection::pip(f).dependency_execution)
    });
    // Optional version list could include releases for which every file was filtered.
    if let Some(obj) = doc.as_object_mut() {
        obj.remove("versions");
    }
    Ok(doc)
}

pub async fn handle(
    State(app): State<App>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let package = normalize(&name)?;
    let raw = raw(&app, &package).await?;
    app.check_downloads(Ecosystem::Pip, &package).await?;
    let mut doc = filter(&raw, &app.config.policy_for(Ecosystem::Pip), Utc::now())?;
    if app.config.policy_for(Ecosystem::Pip).advisories == crate::policy::AdvisoryPolicy::Deny {
        let versions = doc["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| {
                let filename = file["filename"]
                    .as_str()
                    .ok_or_else(|| Error::upstream("Python file missing filename"))?;
                crate::advisories::pip_version(&package, filename)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut versions = versions
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        versions.sort();
        let blocked = app
            .blocked_advisory_versions(Ecosystem::Pip, &package, &versions)
            .await?;
        doc["files"].as_array_mut().unwrap().retain(|file| {
            file["filename"]
                .as_str()
                .and_then(|name| crate::advisories::pip_version(&package, name).ok())
                .is_some_and(|v| !blocked.contains(&v))
        });
    }
    for file in doc["files"].as_array_mut().unwrap() {
        let name = file["filename"]
            .as_str()
            .ok_or_else(|| Error::upstream("file missing filename"))?;
        file["url"] = json!(app.artifact_url(Ecosystem::Pip, &package, name, name));
    }
    if headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/vnd.pypi.simple.v1+json"))
    {
        let mut response = json_response(doc, "application/vnd.pypi.simple.v1+json");
        response
            .headers_mut()
            .insert("vary", "accept".parse().unwrap());
        return Ok(response);
    }
    Ok((
        [
            ("content-type", "text/html; charset=utf-8"),
            ("cache-control", "no-store"),
            ("vary", "accept"),
        ],
        html(&doc)?,
    )
        .into_response())
}

pub async fn artifact(
    app: &App,
    package: &str,
    filename: &str,
    requested: &str,
    now: DateTime<Utc>,
) -> Result<String> {
    let package = normalize(package)?;
    let raw = raw(app, &package).await?;
    app.check_downloads(Ecosystem::Pip, &package).await?;
    let api = raw
        .pointer("/meta/api-version")
        .and_then(Value::as_str)
        .unwrap_or("1.0");
    if !api.starts_with("1.") {
        return Err(Error::upstream("unsupported PyPI Simple API major version"));
    }
    let file = raw["files"]
        .as_array()
        .ok_or_else(|| Error::upstream("invalid PyPI file listing"))?
        .iter()
        .find(|f| f["filename"].as_str() == Some(filename))
        .ok_or_else(|| Error::denied("Python file is not eligible"))?;
    if app.config.policy_for(Ecosystem::Pip).install_hooks == crate::inspection::HookPolicy::Deny
        && crate::inspection::pip(file).dependency_execution
    {
        return Err(Error::denied(
            "Python source build blocked by install-hook policy",
        ));
    }
    if !app
        .config
        .policy_for(Ecosystem::Pip)
        .allows_time(file["upload-time"].as_str(), now)
    {
        return Err(Error::denied("Python file is not eligible"));
    }
    if app.config.policy_for(Ecosystem::Pip).advisories != crate::policy::AdvisoryPolicy::Off {
        let version = crate::advisories::pip_version(&package, filename)?;
        app.check_advisories(Ecosystem::Pip, &package, &version)
            .await?;
    }
    let raw_url = file["url"]
        .as_str()
        .ok_or_else(|| Error::upstream("Python file missing URL"))?;
    let base = url::Url::parse(&format!(
        "{}/simple/{package}/",
        app.config.upstream.pypi.trim_end_matches('/')
    ))
    .unwrap();
    let mut url = base
        .join(raw_url)
        .map_err(|_| Error::upstream("invalid Python file URL"))?;
    url.set_fragment(None);
    if requested == format!("{filename}.metadata") {
        let metadata = file
            .get("core-metadata")
            .or_else(|| file.get("dist-info-metadata"));
        if !metadata.is_some_and(|v| v == true || v.is_object()) {
            return Err(Error::missing("file has no separate core metadata"));
        }
        url.set_path(&format!("{}.metadata", url.path()));
    } else if requested != filename {
        return Err(Error::missing("filename mismatch"));
    }
    Ok(url.to_string())
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn hash(value: &Value) -> Option<String> {
    let hashes = value.as_object()?;
    let (kind, digest) = hashes
        .get_key_value("sha256")
        .or_else(|| hashes.iter().next())?;
    Some(format!("{kind}={}", digest.as_str()?))
}
pub fn html(doc: &Value) -> Result<String> {
    let mut html = String::from(
        "<!DOCTYPE html><html><head><meta name=\"pypi:repository-version\" content=\"1.0\"></head><body>\n",
    );
    for file in doc["files"]
        .as_array()
        .ok_or_else(|| Error::upstream("invalid files"))?
    {
        let mut href = file["url"]
            .as_str()
            .ok_or_else(|| Error::upstream("missing file URL"))?
            .to_string();
        if let Some(digest) = hash(&file["hashes"]) {
            href.push('#');
            href.push_str(&digest);
        }
        html.push_str(&format!("<a href=\"{}\"", escape(&href)));
        if let Some(python) = file["requires-python"].as_str() {
            html.push_str(&format!(" data-requires-python=\"{}\"", escape(python)));
        }
        if file["yanked"] == true || file["yanked"].is_string() {
            html.push_str(&format!(
                " data-yanked=\"{}\"",
                escape(file["yanked"].as_str().unwrap_or(""))
            ));
        }
        if let Some(meta) = file
            .get("core-metadata")
            .or_else(|| file.get("dist-info-metadata"))
            && (meta == true || meta.is_object())
        {
            let v = escape(&hash(meta).unwrap_or_else(|| "true".into()));
            html.push_str(&format!(
                " data-core-metadata=\"{v}\" data-dist-info-metadata=\"{v}\""
            ));
        }
        html.push_str(&format!(
            ">{}</a>\n",
            escape(file["filename"].as_str().unwrap_or(""))
        ));
    }
    html.push_str("</body></html>");
    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_age_not_first_release_age() {
        let doc = json!({"files":[{"filename":"old.whl","upload-time":"2020-01-01T00:00:00Z"},{"filename":"new.whl","upload-time":"2099-01-01T00:00:00Z"},{"filename":"unknown.whl"}], "versions":["1.0"]});
        let result = filter(&doc, &Policy::default(), Utc::now()).unwrap();
        assert_eq!(result["files"].as_array().unwrap().len(), 1);
        assert!(result.get("versions").is_none());
    }
    #[test]
    fn pep503_metadata_and_escaping() {
        assert_eq!(normalize("My__Package.Name").unwrap(), "my-package-name");
        let out = html(&json!({"files":[{"url":"https://example.test/a.whl","filename":"a.whl", "hashes":{"sha256":"abc"},"requires-python":">=3.9", "yanked":"bad <build>", "core-metadata":{"sha256":"def"}}]})).unwrap();
        assert!(out.contains("#sha256=abc"));
        assert!(out.contains("data-core-metadata=\"sha256=def\""));
        assert!(out.contains("data-requires-python=\"&gt;=3.9\""));
        assert!(out.contains("bad &lt;build&gt;"));
    }
}
