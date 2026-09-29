//! Static registry-metadata inspection. Never executes scripts or fetches archives.
use crate::{
    App,
    error::{Error, Result},
    json_response, registry,
    registry::Ecosystem,
};
use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookPolicy {
    #[default]
    Report,
    Deny,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub name: String,
    pub definition: Value,
    pub context: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub evidence: &'static str,
    /// Detected means evidence of hooks; not_reported is NOT a clean bill of health.
    pub status: &'static str,
    pub scripts: Value,
    pub findings: Vec<Finding>,
    /// Potential execution when installed as a dependency, not only as a root project.
    pub dependency_execution: bool,
    pub limitations: Vec<&'static str>,
}

impl Inspection {
    fn new(scripts: Option<&Value>) -> Self {
        Self {
            evidence: "registry_metadata",
            status: "not_reported",
            scripts: scripts.cloned().unwrap_or(Value::Null),
            findings: Vec::new(),
            dependency_execution: false,
            limitations: vec![
                "Metadata only: archives and referenced script bodies are not inspected; no code is executed. Absence of a reported hook does not establish safety.",
            ],
        }
    }
    fn finding(
        &mut self,
        name: &str,
        definition: Value,
        context: &'static str,
        dependency_execution: bool,
    ) {
        self.findings.push(Finding {
            name: name.into(),
            definition,
            context,
        });
        self.status = "detected";
        self.dependency_execution |= dependency_execution;
    }
}

pub fn npm(info: &Value) -> Inspection {
    let mut report = Inspection::new(info.get("scripts"));
    if let Some(scripts) = info.get("scripts") {
        if let Some(scripts) = scripts.as_object() {
            for (name, definition) in scripts {
                let automatic = matches!(name.as_str(), "preinstall" | "install" | "postinstall");
                let contextual = matches!(
                    name.as_str(),
                    "prepublish" | "preprepare" | "prepare" | "postprepare"
                );
                if (automatic || contextual)
                    && !definition.as_str().is_some_and(|s| s.trim().is_empty())
                {
                    report.finding(
                        name,
                        definition.clone(),
                        if automatic {
                            "dependency_install_if_scripts_enabled"
                        } else {
                            "root_local_or_git_install_not_normal_registry_dependency"
                        },
                        automatic,
                    );
                }
            }
        } else {
            report.finding("invalid_scripts_metadata", scripts.clone(), "unknown", true);
        }
    }
    for name in ["hasInstallScript", "gypfile"] {
        if let Some(value) = info.get(name)
            && value != false
        {
            report.finding(name, value.clone(), "potential_dependency_install", true);
        }
    }
    report.limitations.push("Registry script definitions may differ from package.json in the tarball. Implicit node-gyp installation from binding.gyp can be unreported. Client version and script-approval settings determine actual execution.");
    report
}

pub fn composer(info: &Value) -> Inspection {
    let mut report = Inspection::new(info.get("scripts"));
    if let Some(scripts) = info.get("scripts") {
        if let Some(scripts) = scripts.as_object() {
            for (name, definition) in scripts {
                // Include custom commands too, since lifecycle definitions can reference them.
                report.finding(
                    name,
                    definition.clone(),
                    "root_project_only_not_dependency_scripts",
                    false,
                );
            }
        } else {
            report.finding(
                "invalid_scripts_metadata",
                scripts.clone(),
                "root_project_only",
                false,
            );
        }
    }
    if matches!(
        info["type"].as_str(),
        Some("composer-plugin" | "composer-installer")
    ) {
        report.finding(
            "composer_plugin",
            json!({"type": info["type"], "class": info.pointer("/extra/class")}),
            "dependency_install_if_plugins_allowed",
            true,
        );
    }
    report.limitations.push("Composer runs scripts only from the root project. The proxy cannot inspect the client's root composer.json. Packagist p2 metadata can omit scripts; null means unavailable, not absent. Plugins may execute code without a scripts field; PHP plugin bodies are not inspected.");
    report
}

pub fn pip(file: &Value) -> Inspection {
    let mut report = Inspection::new(None);
    if file["filename"]
        .as_str()
        .is_some_and(|f| f.ends_with(".whl"))
    {
        report.limitations.push("Wheel installation does not invoke source-build hooks. Wheel contents, executable .pth files, entry points, and runtime behavior are not inspected.");
    } else {
        report.finding(
            "source_build",
            json!({"filename": file["filename"], "build_backend": null}),
            "potential_execution_during_metadata_generation_or_wheel_build",
            true,
        );
        report.status = "unknown";
        report.limitations.push("The Simple API does not expose pyproject.toml, setup.py, or backend hook definitions. A source build may execute code even to generate metadata. This is a conservative file-type signal, not detection of a specific script.");
    }
    report
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub version: Option<String>,
    pub filename: Option<String>,
}

/// Reports remain accessible when age/download/hook policies block installation.
/// No archive URLs are returned and no download authorization is conferred.
pub async fn handle(
    State(app): State<App>,
    Path((ecosystem, package)): Path<(String, String)>,
    Query(selection): Query<Selection>,
) -> Result<Response> {
    let unsupported = || Error::bad("unsupported inspection ecosystem");
    let ecosystem = Ecosystem::parse(&ecosystem).map_err(|_| unsupported())?;
    let (package, selected, report) = match ecosystem {
        Ecosystem::Npm => {
            let version = exact_version(&selection)?;
            let raw = registry::npm::raw(&app, &package).await?;
            let info = raw["versions"]
                .get(version)
                .ok_or_else(|| Error::missing("npm version not found"))?;
            (package, version.to_string(), npm(info))
        }
        Ecosystem::Composer => {
            let version = exact_version(&selection)?;
            registry::composer_name(&package)?;
            let suffix = if version.starts_with("dev-") || version.ends_with("-dev") {
                "~dev"
            } else {
                ""
            };
            let raw = app
                .metadata(
                    format!(
                        "{}/p2/{package}{suffix}.json",
                        app.config.upstream.packagist.trim_end_matches('/')
                    ),
                    "application/json",
                    false,
                )
                .await?;
            let versions = registry::composer::expand(&raw, &package)?;
            let info = versions
                .iter()
                .find(|v| v["version"].as_str() == Some(version))
                .ok_or_else(|| Error::missing("Composer version not found"))?;
            (package, version.to_string(), composer(info))
        }
        Ecosystem::Pip => {
            if selection.version.is_some() {
                return Err(Error::bad("pip inspection requires filename, not version"));
            }
            let filename = selection
                .filename
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::bad("pip inspection requires an exact filename"))?;
            let package = registry::pip::normalize(&package)?;
            let raw = registry::pip::raw(&app, &package).await?;
            let file = raw["files"]
                .as_array()
                .ok_or_else(|| Error::upstream("invalid PyPI file listing"))?
                .iter()
                .find(|f| f["filename"].as_str() == Some(filename))
                .ok_or_else(|| Error::missing("Python file not found"))?;
            (package, filename.to_string(), pip(file))
        }
        // Configuration validation rejects RubyGems hook denial; see the plan notes.
        Ecosystem::Rubygems | Ecosystem::Homebrew => return Err(unsupported()),
    };
    let policy = app.config.policy_for(ecosystem).install_hooks;
    Ok(json_response(
        json!({
            "ecosystem": ecosystem.as_str(), "package": package, "selection": selected,
            "inspection": report,
            "hook_policy": policy,
            "blocked_by_hook_policy": policy == HookPolicy::Deny && report.dependency_execution,
            "other_policies_evaluated": false
        }),
        "application/json",
    ))
}

fn exact_version(selection: &Selection) -> Result<&str> {
    if selection.filename.is_some() {
        return Err(Error::bad(
            "npm/Composer inspection requires version, not filename",
        ));
    }
    selection
        .version
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::bad("inspection requires an exact version"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn npm_lifecycle_contexts_and_implicit_signals() {
        let report = npm(
            &json!({"scripts":{"postinstall":"node install.js", "prepare":"npm run build", "build":"tsc"}}),
        );
        assert!(report.dependency_execution);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.scripts["build"], "tsc");
        assert!(!npm(&json!({"scripts":{"prepare":"npm run build"}})).dependency_execution);
        assert!(npm(&json!({"hasInstallScript":true})).dependency_execution);
        assert!(npm(&json!({"gypfile":true})).dependency_execution);
        assert!(npm(&json!({"scripts":{"postinstall":["invalid"]}})).dependency_execution);
        assert!(
            !npm(&json!({"scripts":{"postinstall":""},"hasInstallScript":false}))
                .dependency_execution
        );
    }
    #[test]
    fn composer_scripts_are_not_dependency_hooks_but_plugins_are() {
        let report = composer(
            &json!({"scripts":{"post-install-cmd":["@build", "Vendor\\Setup::run"],"build":"php build.php"}}),
        );
        assert_eq!(report.findings.len(), 2);
        assert!(!report.dependency_execution);
        assert!(
            composer(&json!({"type":"composer-plugin","extra":{"class":"Vendor\\Plugin"}}))
                .dependency_execution
        );
        assert!(composer(&json!({"type":"composer-installer"})).dependency_execution);
        assert!(composer(&json!({})).scripts.is_null());
    }
    #[test]
    fn python_build_hooks_are_unknown_from_index_metadata() {
        let source = pip(&json!({"filename":"demo-1.0.tar.gz"}));
        assert!(source.dependency_execution);
        assert_eq!(source.status, "unknown");
        assert!(!pip(&json!({"filename":"demo-1.0-py3-none-any.whl"})).dependency_execution);
    }
}
