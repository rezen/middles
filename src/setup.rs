//! `middles configure`: point local package-manager clients at this proxy.
//!
//! Planning only reads files and the captured [`Environment`], so `--dry-run`
//! and tests see exactly what [`apply`] would write. Config files are edited
//! in place with unrelated lines preserved; shell profiles only ever receive
//! appended `export` lines, and never when the variable is already set.

use crate::config::Config;
use anyhow::{Context, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

/// Every client tool this command can configure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    Npm,
    Pip,
    Uv,
    Composer,
    Bundler,
    Homebrew,
    Apt,
}

impl Client {
    /// Must list every variant; `plan` iterates this so no client is silently
    /// left out of the report.
    pub const ALL: [Self; 7] = [
        Self::Npm,
        Self::Pip,
        Self::Uv,
        Self::Composer,
        Self::Bundler,
        Self::Homebrew,
        Self::Apt,
    ];
    pub const NAMES: &str = "npm, pip, uv, composer, bundler, homebrew, apt";

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        Ok(match value.trim().to_ascii_lowercase().as_str() {
            "npm" => Self::Npm,
            "pip" => Self::Pip,
            "uv" => Self::Uv,
            "composer" => Self::Composer,
            "bundler" | "rubygems" => Self::Bundler,
            "homebrew" | "brew" => Self::Homebrew,
            "apt" => Self::Apt,
            other => bail!("unknown client {other:?}; expected one of {}", Self::NAMES),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pip => "pip",
            Self::Uv => "uv",
            Self::Composer => "composer",
            Self::Bundler => "bundler",
            Self::Homebrew => "homebrew",
            Self::Apt => "apt",
        }
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Macos,
    Linux,
}

/// Everything about the host the planner consults, captured up front so tests
/// can describe a machine without touching the real one.
#[derive(Clone, Debug)]
pub struct Environment {
    pub home: PathBuf,
    pub os: Os,
    /// Basename of `$SHELL`; selects the profile file and its syntax.
    pub shell: String,
    /// Process environment: path overrides and already-set variables.
    pub vars: BTreeMap<String, String>,
    /// Explicit shell profile (`--profile`) instead of the `$SHELL` default.
    pub profile: Option<PathBuf>,
    /// `/etc/apt/sources.list.d` when this host has apt.
    pub apt_sources: Option<PathBuf>,
    /// Whether `/etc/xdg` exists; part of Composer's home-directory heuristic.
    pub etc_xdg: bool,
}

impl Environment {
    /// Captures the real process environment.
    pub fn detect(profile: Option<PathBuf>) -> anyhow::Result<Self> {
        let os = if cfg!(target_os = "macos") {
            Os::Macos
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            bail!("client configuration is supported on macOS and Linux only");
        };
        let vars: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        let home = vars
            .get("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .context("HOME is not set")?;
        let shell = vars
            .get("SHELL")
            .and_then(|s| Path::new(s).file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let apt = Path::new("/etc/apt/sources.list.d");
        Ok(Self {
            home,
            os,
            shell,
            vars,
            profile,
            apt_sources: apt.is_dir().then(|| apt.to_path_buf()),
            etc_xdg: Path::new("/etc/xdg").is_dir(),
        })
    }
    /// A non-empty environment variable.
    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
    fn xdg_config(&self) -> PathBuf {
        self.var("XDG_CONFIG_HOME")
            .filter(|v| Path::new(v).is_absolute())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.home.join(".config"))
    }
    /// Renders a path with the home directory abbreviated for reports.
    pub fn display(&self, path: &Path) -> String {
        match path.strip_prefix(&self.home) {
            Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => path.display().to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Create,
    Update,
    Unchanged,
    Skipped(String),
    /// Content the user has to install by hand, typically as root.
    Manual(String),
}

#[derive(Clone, Debug)]
pub struct Change {
    pub client: Client,
    pub path: Option<PathBuf>,
    pub outcome: Outcome,
    /// Complete file contents to write, or to show for `Manual`.
    pub content: Option<String>,
    pub notes: Vec<String>,
    /// Numbered follow-up steps the user performs by hand, if any.
    pub steps: Vec<String>,
}

impl Change {
    fn skipped(client: Client, reason: impl Into<String>) -> Self {
        Self {
            client,
            path: None,
            outcome: Outcome::Skipped(reason.into()),
            content: None,
            notes: Vec::new(),
            steps: Vec::new(),
        }
    }
    fn edited(
        client: Client,
        path: PathBuf,
        existing: Option<&str>,
        content: String,
        notes: Vec<String>,
    ) -> Self {
        let outcome = match existing {
            None => Outcome::Create,
            Some(old) if old == content => Outcome::Unchanged,
            Some(_) => Outcome::Update,
        };
        Self {
            client,
            path: Some(path),
            outcome,
            content: Some(content),
            notes,
            steps: Vec::new(),
        }
    }
}

/// Normalizes the proxy base URL clients will be pointed at.
pub fn base_url(value: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(value).context("invalid proxy URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("proxy URL must be an absolute HTTP(S) URL without credentials, query, or fragment");
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// Computes one [`Change`] per client without writing anything. Homebrew and
/// APT follow the configuration's `enabled` flags unless named in `only`.
pub fn plan(
    config: &Config,
    url: &str,
    only: &[Client],
    skip: &[Client],
    env: &Environment,
) -> anyhow::Result<Vec<Change>> {
    let mut changes = Vec::with_capacity(Client::ALL.len());
    for client in Client::ALL {
        let explicit = only.contains(&client);
        let reason = if skip.contains(&client) {
            Some("excluded with --skip".to_owned())
        } else if !only.is_empty() && !explicit {
            Some("not listed in --only".to_owned())
        } else if client == Client::Homebrew && !config.homebrew.enabled && !explicit {
            Some(
                "[homebrew] enabled = false in the configuration; pass --only homebrew to configure it anyway"
                    .to_owned(),
            )
        } else if client == Client::Apt && !config.apt.enabled && !explicit {
            Some(
                "[apt] enabled = false in the configuration; pass --only apt to configure it anyway"
                    .to_owned(),
            )
        } else {
            None
        };
        changes.push(match reason {
            Some(reason) => Change::skipped(client, reason),
            None => match client {
                Client::Npm => npm(url, env)?,
                Client::Pip => pip(url, env)?,
                Client::Uv => uv(url, env)?,
                Client::Composer => composer(url, env)?,
                Client::Bundler => bundler(url, env)?,
                Client::Homebrew => homebrew(url, env)?,
                Client::Apt => apt(config, url, env)?,
            },
        });
    }
    Ok(changes)
}

/// Writes every `Create`/`Update` change. An APT sources file the process may
/// not write becomes `Manual` instead of failing the whole run.
pub fn apply(changes: &mut [Change]) -> anyhow::Result<()> {
    for change in changes.iter_mut() {
        if !matches!(change.outcome, Outcome::Create | Outcome::Update) {
            continue;
        }
        let (Some(path), Some(content)) = (&change.path, &change.content) else {
            continue;
        };
        match write(path, content) {
            Ok(()) => {}
            Err(err)
                if err.kind() == io::ErrorKind::PermissionDenied
                    && change.client == Client::Apt =>
            {
                change.outcome = Outcome::Manual(format!(
                    "cannot write {}: permission denied; install it with sudo",
                    path.display()
                ));
                change
                    .steps
                    .insert(0, apt_save_step(&path.display().to_string()));
            }
            Err(err) => return Err(err).with_context(|| format!("write {}", path.display())),
        }
    }
    Ok(())
}

/// Prints one line per client plus notes; file contents are shown for dry
/// runs and for content that must be installed by hand.
pub fn report(
    out: &mut impl io::Write,
    changes: &[Change],
    env: &Environment,
    dry_run: bool,
) -> io::Result<()> {
    for change in changes {
        let (verb, detail) = match &change.outcome {
            Outcome::Create => (if dry_run { "would create" } else { "created" }, None),
            Outcome::Update => (if dry_run { "would update" } else { "updated" }, None),
            Outcome::Unchanged => ("unchanged", None),
            Outcome::Skipped(reason) => ("skipped", Some(reason)),
            Outcome::Manual(reason) => ("manual", Some(reason)),
        };
        write!(out, "{:<9} {verb}", change.client)?;
        if let Some(path) = &change.path {
            write!(out, " {}", env.display(path))?;
        }
        if let Some(detail) = detail {
            write!(out, ": {detail}")?;
        }
        writeln!(out)?;
        for note in &change.notes {
            writeln!(out, "          - {note}")?;
        }
        let show = match change.outcome {
            Outcome::Manual(_) => true,
            Outcome::Create | Outcome::Update => dry_run,
            _ => false,
        };
        if show && let Some(content) = &change.content {
            for line in content.lines() {
                writeln!(out, "          | {line}")?;
            }
        }
        for (index, step) in change.steps.iter().enumerate() {
            writeln!(out, "          {}. {step}", index + 1)?;
        }
    }
    Ok(())
}

fn read(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

/// Replaces the file atomically, keeping an existing file's permissions.
fn write(path: &Path, content: &str) -> io::Result<()> {
    use io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");
    let tmp = path.with_file_name(format!(".{name}.middles-tmp"));
    let result = (|| {
        let mut file = fs::File::create(&tmp)?;
        #[cfg(unix)]
        if let Ok(meta) = fs::metadata(path) {
            file.set_permissions(meta.permissions())?;
        }
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn override_note(
    env: &Environment,
    name: &str,
    wanted: Option<&str>,
    path: &Path,
) -> Option<String> {
    let value = env.var(name)?;
    (wanted != Some(value)).then(|| {
        format!(
            "{name}={value} is set in this environment and overrides {}",
            env.display(path)
        )
    })
}

// ---------------------------------------------------------------------------
// INI-style files (npmrc, pip.conf)

struct Edit {
    text: String,
    /// `(key, previous value)` for assignments that were rewritten.
    replaced: Vec<(String, String)>,
}

fn norm(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('_', "-")
}

fn is_comment(line: &str) -> bool {
    let line = line.trim_start();
    line.is_empty() || line.starts_with('#') || line.starts_with(';')
}

/// Line range of `[section]` (the whole file for `None`), excluding its header.
fn section_range(lines: &[String], section: Option<&str>) -> Option<(usize, usize)> {
    let Some(name) = section else {
        return Some((0, lines.len()));
    };
    let header = format!("[{name}]");
    let start = lines.iter().position(|l| l.trim() == header)? + 1;
    let end = lines[start..]
        .iter()
        .position(|l| {
            let l = l.trim();
            l.starts_with('[') && l.ends_with(']')
        })
        .map_or(lines.len(), |i| start + i);
    Some((start, end))
}

/// The first live `key` assignment inside `range`: `(line index, value)`.
fn find_key(
    lines: &[String],
    range: (usize, usize),
    separators: &[char],
    key: &str,
) -> Option<(usize, String)> {
    let wanted = norm(key);
    (range.0..range.1).find_map(|i| {
        let line = lines[i].trim_start();
        if is_comment(line) {
            return None;
        }
        let at = line.find(|c| separators.contains(&c))?;
        (norm(&line[..at]) == wanted).then(|| (i, line[at + 1..].trim().to_owned()))
    })
}

/// Sets keys inside `section`, replacing the first live assignment of each and
/// appending missing ones to the end of that section. Comments and unrelated
/// lines are kept verbatim; a missing section is appended.
fn set_keys(
    existing: Option<&str>,
    section: Option<&str>,
    separators: &[char],
    entries: &[(&str, &str)],
    render: impl Fn(&str, &str) -> String,
) -> Edit {
    let mut lines: Vec<String> = existing
        .map(|t| t.lines().map(str::to_owned).collect())
        .unwrap_or_default();
    let (start, mut end) = section_range(&lines, section).unwrap_or_else(|| {
        if lines.last().is_some_and(|l| !l.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push(format!("[{}]", section.unwrap_or_default()));
        (lines.len(), lines.len())
    });
    let mut replaced = Vec::new();
    for (key, value) in entries {
        match find_key(&lines, (start, end), separators, key) {
            Some((i, old)) => {
                if old != *value {
                    replaced.push(((*key).to_owned(), old));
                    lines[i] = render(key, value);
                }
            }
            None => {
                let mut at = end;
                while at > start && lines[at - 1].trim().is_empty() {
                    at -= 1;
                }
                lines.insert(at, render(key, value));
                end += 1;
            }
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    Edit { text, replaced }
}

fn replaced_notes(edit: &Edit) -> Vec<String> {
    edit.replaced
        .iter()
        .map(|(key, old)| format!("replaced {key} (was {old})"))
        .collect()
}

// ---------------------------------------------------------------------------
// npm

fn npm(url: &str, env: &Environment) -> anyhow::Result<Change> {
    let path = env
        .var("NPM_CONFIG_USERCONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| env.home.join(".npmrc"));
    let existing = read(&path)?;
    let registry = format!("{url}/npm/");
    let edit = set_keys(
        existing.as_deref(),
        None,
        &['='],
        &[("registry", &registry), ("audit", "false")],
        |k, v| format!("{k}={v}"),
    );
    let mut notes = replaced_notes(&edit);
    if edit
        .text
        .lines()
        .any(|l| !is_comment(l) && l.trim_start().starts_with('@') && l.contains(":registry="))
    {
        notes.push(
            "scoped registries (@scope:registry) in this file still bypass the proxy".to_owned(),
        );
    }
    for name in ["NPM_CONFIG_REGISTRY", "npm_config_registry"] {
        notes.extend(override_note(env, name, Some(&registry), &path));
    }
    Ok(Change::edited(
        Client::Npm,
        path,
        existing.as_deref(),
        edit.text,
        notes,
    ))
}

// ---------------------------------------------------------------------------
// pip

fn pip_path(env: &Environment) -> PathBuf {
    if let Some(path) = env.var("PIP_CONFIG_FILE") {
        return PathBuf::from(path);
    }
    match env.os {
        Os::Macos => {
            // pip uses the Application Support directory only when it exists.
            let app = env.home.join("Library/Application Support/pip");
            if app.is_dir() {
                app.join("pip.conf")
            } else {
                env.home.join(".config/pip/pip.conf")
            }
        }
        Os::Linux => env.xdg_config().join("pip/pip.conf"),
    }
}

fn pip(url: &str, env: &Environment) -> anyhow::Result<Change> {
    let path = pip_path(env);
    let existing = read(&path)?;
    let index = format!("{url}/pip/simple/");
    let edit = set_keys(
        existing.as_deref(),
        Some("global"),
        &['=', ':'],
        &[("index-url", &index)],
        |k, v| format!("{k} = {v}"),
    );
    let mut notes = replaced_notes(&edit);
    let lines: Vec<String> = edit.text.lines().map(str::to_owned).collect();
    if let Some(range) = section_range(&lines, Some("global"))
        && find_key(&lines, range, &['=', ':'], "extra-index-url").is_some()
    {
        notes.push(
            "extra-index-url in [global] is another resolution source that bypasses the proxy"
                .to_owned(),
        );
    }
    notes.extend(override_note(env, "PIP_INDEX_URL", Some(&index), &path));
    notes.extend(override_note(env, "PIP_EXTRA_INDEX_URL", None, &path));
    Ok(Change::edited(
        Client::Pip,
        path,
        existing.as_deref(),
        edit.text,
        notes,
    ))
}

// ---------------------------------------------------------------------------
// uv

fn uv(url: &str, env: &Environment) -> anyhow::Result<Change> {
    let path = env
        .var("UV_CONFIG_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| env.xdg_config().join("uv/uv.toml"));
    let existing = read(&path)?;
    let index = format!("{url}/pip/simple/");
    let block = format!(
        "# middles: resolve packages through the policy proxy.\n[[index]]\nname = \"middles\"\nurl = \"{index}\"\ndefault = true\n"
    );
    let mut notes = Vec::new();
    let is_ours =
        |item: &toml::Value| item.get("url").and_then(toml::Value::as_str) == Some(&index);
    let content = match existing.as_deref() {
        None => block,
        Some(text) => {
            let mut table: toml::Table =
                toml::from_str(text).with_context(|| format!("parse {}", path.display()))?;
            match table.get("index") {
                None => {
                    let mut text = text.to_owned();
                    if !text.is_empty() {
                        if !text.ends_with('\n') {
                            text.push('\n');
                        }
                        text.push('\n');
                    }
                    text.push_str(&block);
                    text
                }
                Some(toml::Value::Array(items))
                    if items.iter().any(|i| {
                        is_ours(i) && i.get("default").and_then(toml::Value::as_bool) == Some(true)
                    }) =>
                {
                    text.to_owned()
                }
                Some(toml::Value::Array(items)) => {
                    let mut items: Vec<toml::Value> =
                        items.iter().filter(|i| !is_ours(i)).cloned().collect();
                    for item in &mut items {
                        if let Some(entry) = item.as_table_mut()
                            && entry.get("default").and_then(toml::Value::as_bool) == Some(true)
                        {
                            entry.remove("default");
                            let name = entry
                                .get("name")
                                .and_then(toml::Value::as_str)
                                .or_else(|| entry.get("url").and_then(toml::Value::as_str))
                                .unwrap_or("?");
                            notes.push(format!("index {name} is no longer the default"));
                        }
                    }
                    let mut ours = toml::Table::new();
                    ours.insert("name".into(), "middles".into());
                    ours.insert("url".into(), index.clone().into());
                    ours.insert("default".into(), true.into());
                    items.insert(0, toml::Value::Table(ours));
                    table.insert("index".into(), toml::Value::Array(items));
                    notes.push(
                        "rewrote the file to change the default index; comments were not preserved"
                            .to_owned(),
                    );
                    toml::to_string_pretty(&table)?
                }
                Some(_) => bail!("{}: `index` must be an array of tables", path.display()),
            }
        }
    };
    for name in ["UV_DEFAULT_INDEX", "UV_INDEX_URL"] {
        notes.extend(override_note(env, name, Some(&index), &path));
    }
    notes.extend(override_note(env, "UV_INDEX", None, &path));
    let mut change = Change::edited(Client::Uv, path, existing.as_deref(), content, notes);
    if change.outcome != Outcome::Unchanged {
        change.notes.push("existing uv.lock files pin the index recorded at lock time; regenerate them through the proxy".to_owned());
    }
    Ok(change)
}

// ---------------------------------------------------------------------------
// Composer

/// Global `config.json`. Top-level keys and repository order are kept because
/// Composer resolves repositories in declaration order.
#[derive(Deserialize, Serialize)]
struct ComposerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repositories: Option<Repositories>,
    #[serde(flatten)]
    rest: IndexMap<String, Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum Repositories {
    Map(IndexMap<String, Value>),
    List(Vec<Value>),
}

/// Mirrors Composer's `Factory::getHomeDir` for macOS and Linux.
fn composer_home(env: &Environment) -> PathBuf {
    if let Some(home) = env.var("COMPOSER_HOME") {
        return PathBuf::from(home);
    }
    let xdg = env.etc_xdg || env.vars.keys().any(|k| k.starts_with("XDG_"));
    let mut candidates = Vec::new();
    if xdg {
        candidates.push(env.xdg_config().join("composer"));
    }
    candidates.push(env.home.join(".composer"));
    candidates
        .iter()
        .find(|c| c.is_dir())
        .cloned()
        .unwrap_or_else(|| candidates[0].clone())
}

fn pretty_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    value.serialize(&mut serde_json::Serializer::with_formatter(
        &mut out, formatter,
    ))?;
    let mut text = String::from_utf8(out)?;
    text.push('\n');
    Ok(text)
}

fn composer(url: &str, env: &Environment) -> anyhow::Result<Change> {
    let path = composer_home(env).join("config.json");
    let existing = read(&path)?;
    let repo = format!("{url}/composer/");
    let mut doc: ComposerConfig = match existing.as_deref().filter(|t| !t.trim().is_empty()) {
        Some(text) => {
            serde_json::from_str(text).with_context(|| format!("parse {}", path.display()))?
        }
        None => ComposerConfig {
            repositories: None,
            rest: IndexMap::new(),
        },
    };
    let mut notes = Vec::new();
    let ours = json!({"type": "composer", "url": repo});
    let is_ours = |v: &Value| v.get("url").and_then(Value::as_str) == Some(repo.as_str());
    let disabled = Value::Bool(false);
    match doc
        .repositories
        .get_or_insert_with(|| Repositories::Map(IndexMap::new()))
    {
        Repositories::Map(map) => {
            if !map.values().any(is_ours) {
                map.shift_insert(0, "middles".to_owned(), ours);
            }
            // "packagist" is Composer's legacy alias for the default repository.
            let key = ["packagist.org", "packagist"]
                .into_iter()
                .find(|k| map.contains_key(*k));
            match key.and_then(|k| map.get_mut(k)) {
                Some(value) if *value == disabled => {}
                Some(value) => {
                    notes.push("disabled the redefined packagist.org repository".to_owned());
                    *value = disabled.clone();
                }
                None => {
                    map.insert("packagist.org".to_owned(), disabled.clone());
                }
            }
        }
        Repositories::List(list) => {
            if !list.iter().any(is_ours) {
                list.insert(0, ours);
            }
            let disables = |v: &Value| {
                v.as_object().is_some_and(|o| {
                    o.len() == 1
                        && ["packagist.org", "packagist"]
                            .iter()
                            .any(|k| o.get(*k) == Some(&disabled))
                })
            };
            if !list.iter().any(disables) {
                list.push(json!({"packagist.org": false}));
            }
        }
    }
    if url.starts_with("http://") {
        let config = doc
            .rest
            .entry("config".to_owned())
            .or_insert_with(|| json!({}));
        let Some(config) = config.as_object_mut() else {
            bail!("{}: `config` must be an object", path.display());
        };
        if config.get("secure-http") != Some(&disabled) {
            config.insert("secure-http".to_owned(), disabled);
            notes.push("secure-http is disabled because the proxy URL is plain HTTP; use HTTPS for shared deployments".to_owned());
        }
    }
    let content = pretty_json(&doc)?;
    let mut change = Change::edited(Client::Composer, path, existing.as_deref(), content, notes);
    if change.outcome != Outcome::Unchanged {
        change.notes.push("applies to every project; a composer.json that re-enables packagist.org or adds other repositories can still bypass the proxy".to_owned());
    }
    Ok(change)
}

// ---------------------------------------------------------------------------
// Bundler

/// Bundler's settings key for `mirror.https://rubygems.org/`.
const BUNDLER_MIRROR: &str = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/";

fn bundler(url: &str, env: &Environment) -> anyhow::Result<Change> {
    let path = env
        .var("BUNDLE_USER_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env.var("BUNDLE_USER_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| env.home.join(".bundle"))
                .join("config")
        });
    let existing = read(&path)?;
    let mirror = format!("{url}/rubygems/");
    let mut lines: Vec<String> = existing
        .as_deref()
        .map(|t| t.lines().map(str::to_owned).collect())
        .unwrap_or_else(|| vec!["---".to_owned()]);
    let mut notes = Vec::new();
    let entry = format!("{BUNDLER_MIRROR}: \"{mirror}\"");
    let prefix = format!("{BUNDLER_MIRROR}:");
    match lines.iter().position(|l| l.starts_with(&prefix)) {
        Some(i) => {
            let old = unquote(&lines[i][prefix.len()..]);
            if old != mirror {
                notes.push(format!("replaced {BUNDLER_MIRROR} (was {old})"));
                lines[i] = entry;
            }
        }
        None => lines.push(entry),
    }
    let mut content = lines.join("\n");
    content.push('\n');
    notes.extend(override_note(env, BUNDLER_MIRROR, Some(&mirror), &path));
    notes.extend(override_note(
        env,
        "BUNDLE_MIRROR__ALL",
        Some(&mirror),
        &path,
    ));
    let mut change = Change::edited(Client::Bundler, path, existing.as_deref(), content, notes);
    if change.outcome != Outcome::Unchanged {
        change.notes.push("Gemfiles that use https://rubygems.org now fetch through the proxy; other sources are unaffected. Regenerate lockfiles through it.".to_owned());
    }
    Ok(change)
}

// ---------------------------------------------------------------------------
// Homebrew (shell profile environment variables)

/// The profile file that receives `export` lines and whether it is fish syntax.
fn profile(env: &Environment) -> (PathBuf, bool) {
    if let Some(path) = &env.profile {
        let fish = path.extension().is_some_and(|e| e == "fish");
        return (path.clone(), fish);
    }
    match env.shell.as_str() {
        "zsh" => (
            env.var("ZDOTDIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| env.home.clone())
                .join(".zshrc"),
            false,
        ),
        "bash" => {
            // macOS terminals start login shells; Linux ones usually do not.
            let names = match env.os {
                Os::Macos => [".bash_profile", ".bashrc"],
                Os::Linux => [".bashrc", ".bash_profile"],
            };
            let candidates = names.map(|n| env.home.join(n));
            let path = candidates
                .iter()
                .find(|c| c.is_file())
                .cloned()
                .unwrap_or_else(|| candidates[0].clone());
            (path, false)
        }
        "fish" => (env.xdg_config().join("fish/config.fish"), true),
        _ => (env.home.join(".profile"), false),
    }
}

/// Strips one layer of shell quoting, or a trailing comment when unquoted.
fn unquote(value: &str) -> String {
    let value = value.trim();
    for quote in ['"', '\''] {
        if let Some(rest) = value.strip_prefix(quote) {
            return rest.split(quote).next().unwrap_or_default().to_owned();
        }
    }
    value
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_end_matches(';')
        .to_owned()
}

/// The value the profile assigns to `name`, ignoring comments; the last
/// assignment wins, as it would in the shell.
fn profile_value(text: &str, name: &str, fish: bool) -> Option<String> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if is_comment(line) {
            continue;
        }
        let value = if fish {
            let mut words = line.split_whitespace();
            if words.next() != Some("set") {
                continue;
            }
            let rest: Vec<&str> = words.skip_while(|w| w.starts_with('-')).collect();
            if rest.first() != Some(&name) {
                continue;
            }
            rest[1..].join(" ")
        } else {
            let assignment = line.strip_prefix("export ").map_or(line, str::trim_start);
            match assignment
                .strip_prefix(name)
                .and_then(|r| r.strip_prefix('='))
            {
                Some(value) => value.to_owned(),
                None => continue,
            }
        };
        found = Some(unquote(&value));
    }
    found
}

fn homebrew(url: &str, env: &Environment) -> anyhow::Result<Change> {
    let (path, fish) = profile(env);
    let existing = read(&path)?;
    let shown = env.display(&path);
    let wanted = [
        ("HOMEBREW_ARTIFACT_DOMAIN", format!("{url}/homebrew")),
        ("HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK", "1".to_owned()),
    ];
    let mut add = Vec::new();
    let mut notes = Vec::new();
    let mut conflicts = Vec::new();
    for (name, value) in &wanted {
        match profile_value(existing.as_deref().unwrap_or_default(), name, fish) {
            Some(found) if found == *value => {
                notes.push(format!("{name} is already set in {shown}"))
            }
            Some(found) => conflicts.push(format!("{name} is set to {found} in {shown}")),
            None => match env.var(name) {
                Some(found) if found == value => notes.push(format!(
                    "{name} is already set in this environment; not added to {shown}"
                )),
                Some(found) => {
                    conflicts.push(format!("{name} is set to {found} in this environment"))
                }
                None => add.push((name, value)),
            },
        }
    }
    if !conflicts.is_empty() {
        return Ok(Change {
            client: Client::Homebrew,
            path: Some(path),
            outcome: Outcome::Skipped(format!("{}; change it by hand", conflicts.join("; "))),
            content: None,
            notes,
            steps: Vec::new(),
        });
    }
    if add.is_empty() {
        return Ok(Change {
            client: Client::Homebrew,
            path: Some(path),
            outcome: Outcome::Unchanged,
            content: existing,
            notes,
            steps: Vec::new(),
        });
    }
    let mut content = existing.clone().unwrap_or_default();
    if !content.is_empty() {
        if !content.ends_with('\n') {
            content.push('\n');
        }
        content.push('\n');
    }
    content.push_str("# middles: fetch Homebrew bottles through the policy proxy.\n");
    for (name, value) in add {
        if fish {
            content.push_str(&format!("set -gx {name} \"{value}\"\n"));
        } else {
            content.push_str(&format!("export {name}=\"{value}\"\n"));
        }
    }
    notes.push(format!(
        "restart your shell or run `source {shown}` to apply"
    ));
    notes.push("only shells that read this file are affected; cached bottles and excluded downloads never reach the proxy".to_owned());
    Ok(Change::edited(
        Client::Homebrew,
        path,
        existing.as_deref(),
        content,
        notes,
    ))
}

// ---------------------------------------------------------------------------
// APT

const APT_SOURCES: &str = "/etc/apt/sources.list.d/middles.sources";

fn apt_save_step(path: &str) -> String {
    format!(
        "Save the stanzas above as {path} on each Debian or Ubuntu client, for example with `sudo tee`, or run `sudo middles configure --config <file> --only apt` there."
    )
}

/// Client-side steps no file edit can perform: the direct upstream entries
/// must be disabled, signing keys kept, and indexes refreshed.
fn apt_steps(config: &Config, url: &str) -> Vec<String> {
    let upstreams: Vec<String> = config
        .apt
        .repos
        .iter()
        .map(|repo| match url::Url::parse(&repo.url) {
            Ok(u) => format!(
                "{}{}",
                u.host_str().unwrap_or_default(),
                u.path().trim_end_matches('/')
            ),
            Err(_) => repo.url.clone(),
        })
        .collect();
    vec![
        format!(
            "Disable the direct entries for {} (with either scheme): comment out their `deb` lines in /etc/apt/sources.list and /etc/apt/sources.list.d/*.list, and add `Enabled: no` to their stanzas in /etc/apt/sources.list.d/*.sources (Debian 12 and Ubuntu 24.04 keep them in debian.sources or ubuntu.sources). Entries left enabled bypass the proxy.",
            upstreams.join(", ")
        ),
        "Keep each repository's signing key installed: the distribution keyrings in /etc/apt/trusted.gpg.d verify the proxied indexes because middles passes them through unchanged. If the original stanza carried a Signed-By line, add the same line to the middles stanza.".to_owned(),
        format!(
            "Run `sudo apt-get update`; every index now comes from {url}/apt/<name>. Confirm with `apt-cache policy` or `apt-get install --print-uris <package>`. Do not set Acquire::http::Proxy: middles is a repository endpoint, not an HTTP proxy."
        ),
        "Packages become installable min_age_days after middles first sees them in an index, so run the update early to start the clock. A denied download shows HTTP 403; GET /apt/<repo>/check/<filename> on the proxy explains it.".to_owned(),
    ]
}

fn apt(config: &Config, url: &str, env: &Environment) -> anyhow::Result<Change> {
    if config.apt.repos.is_empty() {
        return Ok(Change::skipped(
            Client::Apt,
            "no [[apt.repos]] in the configuration",
        ));
    }
    let mut content = String::from("# middles: APT repositories through the policy proxy.\n");
    for repo in &config.apt.repos {
        content.push_str(&format!(
            "\nTypes: deb\nURIs: {url}/apt/{}\nSuites: {}\nComponents: {}\nArchitectures: {}\n",
            repo.name,
            repo.suites.join(" "),
            repo.components.join(" "),
            repo.architectures.join(" "),
        ));
    }
    let mut steps = apt_steps(config, url);
    match &env.apt_sources {
        Some(dir) => {
            let path = dir.join("middles.sources");
            let existing = read(&path)?;
            let mut change =
                Change::edited(Client::Apt, path, existing.as_deref(), content, Vec::new());
            change.steps = steps;
            Ok(change)
        }
        None => {
            // This host is not the client, so a loopback URL cannot be right there.
            let loopback = url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .is_some_and(|h| h == "localhost" || h == "[::1]" || h.starts_with("127."));
            let notes = loopback
                .then(|| format!("{url} is a loopback address; clients on other hosts need --url with an address they can reach"))
                .into_iter()
                .collect();
            steps.insert(0, apt_save_step(APT_SOURCES));
            Ok(Change {
                client: Client::Apt,
                path: None,
                outcome: Outcome::Manual(format!(
                    "this host has no /etc/apt/sources.list.d; install on Debian or Ubuntu clients as {APT_SOURCES}"
                )),
                content: Some(content),
                notes,
                steps,
            })
        }
    }
}
