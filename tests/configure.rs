use middles::{
    config::{AptRepo, Config},
    setup::{self, Change, Client, Environment, Os, Outcome},
};
use std::{collections::BTreeMap, fs, path::Path};

const URL: &str = "http://127.0.0.1:6280";

fn environment(home: &Path, os: Os) -> Environment {
    Environment {
        home: home.to_path_buf(),
        os,
        shell: "zsh".into(),
        vars: BTreeMap::from([("HOME".to_owned(), home.display().to_string())]),
        profile: None,
        apt_sources: None,
        etc_xdg: false,
    }
}

fn find(changes: &[Change], client: Client) -> &Change {
    changes.iter().find(|c| c.client == client).unwrap()
}

fn run(config: &Config, url: &str, only: &[Client], env: &Environment) -> Vec<Change> {
    let mut changes = setup::plan(config, url, only, &[], env).unwrap();
    setup::apply(&mut changes).unwrap();
    changes
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn homebrew_config() -> Config {
    let mut config = Config::default();
    config.homebrew.enabled = true;
    config
}

fn apt_config() -> Config {
    let mut config = Config::default();
    config.apt.enabled = true;
    config.apt.repos = vec![
        AptRepo {
            name: "debian".into(),
            url: "https://deb.debian.org/debian".into(),
            suites: vec!["bookworm".into(), "bookworm-updates".into()],
            components: vec!["main".into()],
            architectures: vec!["amd64".into()],
            min_age_days: None,
            osv_ecosystem: None,
        },
        AptRepo {
            name: "debian-security".into(),
            url: "https://security.debian.org/debian-security".into(),
            suites: vec!["bookworm-security".into()],
            components: vec!["main".into(), "contrib".into()],
            architectures: vec!["amd64".into(), "i386".into()],
            min_age_days: Some(0),
            osv_ecosystem: None,
        },
    ];
    config
}

#[test]
fn fresh_home_gets_every_client_file_once() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Macos);
    let changes = run(&homebrew_config(), URL, &[], &env);
    for client in [
        Client::Npm,
        Client::Yarn,
        Client::Bun,
        Client::Pip,
        Client::Uv,
        Client::Composer,
        Client::Bundler,
        Client::Homebrew,
    ] {
        assert_eq!(find(&changes, client).outcome, Outcome::Create, "{client}");
    }
    assert!(matches!(
        find(&changes, Client::Apt).outcome,
        Outcome::Skipped(_)
    ));

    assert_eq!(
        read(&home.join(".npmrc")),
        "registry=http://127.0.0.1:6280/npm/\naudit=false\n"
    );
    assert_eq!(
        read(&home.join(".yarnrc.yml")),
        "npmRegistryServer: \"http://127.0.0.1:6280/npm\"\nunsafeHttpWhitelist:\n  - \"127.0.0.1\"\n"
    );
    assert_eq!(
        read(&home.join(".bunfig.toml")),
        "[install]\nregistry = \"http://127.0.0.1:6280/npm/\"\n"
    );
    assert_eq!(
        read(&home.join(".config/pip/pip.conf")),
        "[global]\nindex-url = http://127.0.0.1:6280/pip/simple/\n"
    );
    let uv: toml::Table = toml::from_str(&read(&home.join(".config/uv/uv.toml"))).unwrap();
    let index = &uv["index"].as_array().unwrap()[0];
    assert_eq!(
        index["url"].as_str(),
        Some("http://127.0.0.1:6280/pip/simple/")
    );
    assert_eq!(index["default"].as_bool(), Some(true));
    let composer: serde_json::Value =
        serde_json::from_str(&read(&home.join(".composer/config.json"))).unwrap();
    assert_eq!(
        composer["repositories"]["middles"]["url"],
        "http://127.0.0.1:6280/composer/"
    );
    assert_eq!(composer["repositories"]["packagist.org"], false);
    assert_eq!(composer["config"]["secure-http"], false);
    assert_eq!(
        read(&home.join(".bundle/config")),
        "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"http://127.0.0.1:6280/rubygems/\"\n"
    );
    let zshrc = read(&home.join(".zshrc"));
    assert!(zshrc.contains("export HOMEBREW_ARTIFACT_DOMAIN=\"http://127.0.0.1:6280/homebrew\"\n"));
    assert!(zshrc.contains("export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=\"1\"\n"));

    // A second run finds everything in place and rewrites nothing.
    let again = run(&homebrew_config(), URL, &[], &env);
    for change in again.iter().filter(|c| c.client != Client::Apt) {
        assert_eq!(change.outcome, Outcome::Unchanged, "{}", change.client);
    }
    let zshrc_again = read(&home.join(".zshrc"));
    assert_eq!(zshrc, zshrc_again);
}

#[test]
fn existing_files_keep_unrelated_lines() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Linux);
    write(
        &home.join(".npmrc"),
        "# comment\nregistry = https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=abc\n@corp:registry=https://npm.corp/\n",
    );
    write(
        &home.join(".config/pip/pip.conf"),
        "[install]\nuser = true\n\n[global]\ntimeout = 60\nindex_url: https://pypi.org/simple\n\n[freeze]\ntimeout = 10\n",
    );
    write(
        &home.join(".bundle/config"),
        "---\nBUNDLE_PATH: \"vendor\"\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: 'http://old/'\n",
    );
    let changes = run(&Config::default(), URL, &[], &env);

    let npm = find(&changes, Client::Npm);
    assert_eq!(npm.outcome, Outcome::Update);
    assert_eq!(
        read(&home.join(".npmrc")),
        "# comment\nregistry=http://127.0.0.1:6280/npm/\n//registry.npmjs.org/:_authToken=abc\n@corp:registry=https://npm.corp/\naudit=false\n"
    );
    assert!(
        npm.notes
            .iter()
            .any(|n| n == "replaced registry (was https://registry.npmjs.org/)")
    );
    assert!(npm.notes.iter().any(|n| n.contains("scoped registries")));

    assert_eq!(find(&changes, Client::Pip).outcome, Outcome::Update);
    assert_eq!(
        read(&home.join(".config/pip/pip.conf")),
        "[install]\nuser = true\n\n[global]\ntimeout = 60\nindex-url = http://127.0.0.1:6280/pip/simple/\n\n[freeze]\ntimeout = 10\n"
    );

    let bundler = find(&changes, Client::Bundler);
    assert_eq!(bundler.outcome, Outcome::Update);
    assert_eq!(
        read(&home.join(".bundle/config")),
        "---\nBUNDLE_PATH: \"vendor\"\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"http://127.0.0.1:6280/rubygems/\"\n"
    );
    assert!(
        bundler
            .notes
            .iter()
            .any(|n| n.contains("(was http://old/)"))
    );
}

#[test]
fn pip_section_is_appended_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Linux);
    write(
        &home.join(".config/pip/pip.conf"),
        "[install]\nuser = true\n",
    );
    run(&Config::default(), URL, &[Client::Pip], &env);
    assert_eq!(
        read(&home.join(".config/pip/pip.conf")),
        "[install]\nuser = true\n\n[global]\nindex-url = http://127.0.0.1:6280/pip/simple/\n"
    );
}

#[test]
fn uv_config_appends_or_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Linux);
    let path = home.join(".config/uv/uv.toml");

    // No index yet: the block is appended and the rest is untouched.
    write(&path, "# keep me\npython-preference = \"managed\"\n");
    let changes = run(&Config::default(), URL, &[Client::Uv], &env);
    assert_eq!(find(&changes, Client::Uv).outcome, Outcome::Update);
    let text = read(&path);
    assert!(text.starts_with("# keep me\npython-preference = \"managed\"\n\n# middles"));
    assert!(text.contains("[[index]]\nname = \"middles\"\nurl = \"http://127.0.0.1:6280/pip/simple/\"\ndefault = true\n"));
    let again = run(&Config::default(), URL, &[Client::Uv], &env);
    assert_eq!(find(&again, Client::Uv).outcome, Outcome::Unchanged);

    // Another default index: ours takes over and the other is demoted.
    write(
        &path,
        "[[index]]\nname = \"corp\"\nurl = \"https://corp.example/simple/\"\ndefault = true\n",
    );
    let changes = run(&Config::default(), URL, &[Client::Uv], &env);
    let uv = find(&changes, Client::Uv);
    assert_eq!(uv.outcome, Outcome::Update);
    assert!(
        uv.notes
            .iter()
            .any(|n| n == "index corp is no longer the default")
    );
    let table: toml::Table = toml::from_str(&read(&path)).unwrap();
    let indexes = table["index"].as_array().unwrap();
    assert_eq!(indexes.len(), 2);
    assert_eq!(indexes[0]["name"].as_str(), Some("middles"));
    assert_eq!(indexes[0]["default"].as_bool(), Some(true));
    assert_eq!(indexes[1]["name"].as_str(), Some("corp"));
    assert!(indexes[1].get("default").is_none());
}

#[test]
fn composer_keeps_repository_order_and_settings() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Linux);
    let path = home.join(".composer/config.json");
    write(
        &path,
        r#"{"config": {"github-oauth": {"github.com": "tok"}}, "repositories": {"corp": {"type": "composer", "url": "https://corp.example/"}, "packagist.org": {"type": "composer", "url": "https://repo.packagist.org"}}}"#,
    );
    let changes = run(
        &Config::default(),
        "https://proxy.example.com/middles",
        &[Client::Composer],
        &env,
    );
    let composer = find(&changes, Client::Composer);
    assert_eq!(composer.outcome, Outcome::Update);
    assert!(
        composer
            .notes
            .iter()
            .any(|n| n.contains("redefined packagist.org"))
    );
    let text = read(&path);
    assert!(text.find("\"middles\"").unwrap() < text.find("\"corp\"").unwrap());
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        doc["repositories"]["middles"]["url"],
        "https://proxy.example.com/middles/composer/"
    );
    assert_eq!(doc["repositories"]["corp"]["url"], "https://corp.example/");
    assert_eq!(doc["repositories"]["packagist.org"], false);
    assert_eq!(doc["config"]["github-oauth"]["github.com"], "tok");
    assert!(
        doc["config"].get("secure-http").is_none(),
        "HTTPS keeps secure-http"
    );

    // Array form gets the proxy first and Packagist disabled last.
    write(
        &path,
        r#"{"repositories": [{"type": "vcs", "url": "https://github.com/x/y"}]}"#,
    );
    run(&Config::default(), URL, &[Client::Composer], &env);
    let doc: serde_json::Value = serde_json::from_str(&read(&path)).unwrap();
    let list = doc["repositories"].as_array().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0]["url"], "http://127.0.0.1:6280/composer/");
    assert_eq!(list[1]["type"], "vcs");
    assert_eq!(list[2], serde_json::json!({"packagist.org": false}));
    assert_eq!(doc["config"]["secure-http"], false);
}

#[test]
fn homebrew_respects_variables_already_set() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let zshrc = home.join(".zshrc");
    let config = homebrew_config();

    // Both variables already in the environment: nothing is written at all.
    let mut env = environment(home, Os::Macos);
    env.vars.insert(
        "HOMEBREW_ARTIFACT_DOMAIN".into(),
        "http://127.0.0.1:6280/homebrew".into(),
    );
    env.vars
        .insert("HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK".into(), "1".into());
    let changes = run(&config, URL, &[Client::Homebrew], &env);
    let brew = find(&changes, Client::Homebrew);
    assert_eq!(brew.outcome, Outcome::Unchanged);
    assert!(
        brew.notes
            .iter()
            .any(|n| n.contains("already set in this environment"))
    );
    assert!(!zshrc.exists());

    // A different value in the environment is a conflict, not an override.
    env.vars.insert(
        "HOMEBREW_ARTIFACT_DOMAIN".into(),
        "https://other.example/homebrew".into(),
    );
    let changes = run(&config, URL, &[Client::Homebrew], &env);
    match &find(&changes, Client::Homebrew).outcome {
        Outcome::Skipped(reason) => assert!(
            reason.contains("HOMEBREW_ARTIFACT_DOMAIN is set to https://other.example/homebrew in this environment"),
            "{reason}"
        ),
        other => panic!("{other:?}"),
    }
    assert!(!zshrc.exists());

    // The same in the profile itself, including without `export`.
    let env = environment(home, Os::Macos);
    write(
        &zshrc,
        "HOMEBREW_ARTIFACT_DOMAIN=http://other/homebrew # old\n",
    );
    let changes = run(&config, URL, &[Client::Homebrew], &env);
    assert!(matches!(
        find(&changes, Client::Homebrew).outcome,
        Outcome::Skipped(_)
    ));
    assert_eq!(
        read(&zshrc),
        "HOMEBREW_ARTIFACT_DOMAIN=http://other/homebrew # old\n"
    );

    // Only the missing variable is appended; commented lines do not count.
    write(
        &zshrc,
        "# export HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\nexport HOMEBREW_ARTIFACT_DOMAIN='http://127.0.0.1:6280/homebrew'",
    );
    let changes = run(&config, URL, &[Client::Homebrew], &env);
    assert_eq!(find(&changes, Client::Homebrew).outcome, Outcome::Update);
    let text = read(&zshrc);
    assert_eq!(text.matches("HOMEBREW_ARTIFACT_DOMAIN=").count(), 1);
    assert!(text.ends_with(
        "\n\n# middles: fetch Homebrew bottles through the policy proxy.\nexport HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=\"1\"\n"
    ));
}

#[test]
fn profile_follows_shell_and_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let config = Config::default();
    let brew = |env: &Environment| {
        let changes = setup::plan(&config, URL, &[Client::Homebrew], &[], env).unwrap();
        find(&changes, Client::Homebrew).path.clone().unwrap()
    };

    let mut env = environment(home, Os::Macos);
    assert_eq!(brew(&env), home.join(".zshrc"));
    env.vars
        .insert("ZDOTDIR".into(), home.join("zdot").display().to_string());
    assert_eq!(brew(&env), home.join("zdot/.zshrc"));

    let mut env = environment(home, Os::Linux);
    env.shell = "bash".into();
    assert_eq!(brew(&env), home.join(".bashrc"));
    env.os = Os::Macos;
    assert_eq!(brew(&env), home.join(".bash_profile"));
    write(&home.join(".bashrc"), "");
    assert_eq!(brew(&env), home.join(".bashrc"), "an existing file wins");

    env.shell = "tcsh".into();
    assert_eq!(brew(&env), home.join(".profile"));

    env.profile = Some(home.join("custom.sh"));
    assert_eq!(brew(&env), home.join("custom.sh"));

    let mut env = environment(home, Os::Linux);
    env.shell = "fish".into();
    let fish = home.join(".config/fish/config.fish");
    write(
        &fish,
        "set -gx HOMEBREW_ARTIFACT_DOMAIN http://127.0.0.1:6280/homebrew\n",
    );
    let changes = run(&homebrew_config(), URL, &[], &env);
    let change = find(&changes, Client::Homebrew);
    assert_eq!(change.path.as_deref(), Some(fish.as_path()));
    assert_eq!(change.outcome, Outcome::Update);
    let text = read(&fish);
    assert_eq!(text.matches("HOMEBREW_ARTIFACT_DOMAIN ").count(), 1);
    assert!(text.ends_with("set -gx HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK \"1\"\n"));
}

#[test]
fn apt_sources_are_written_or_shown() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let config = apt_config();
    let expected = "# middles: APT repositories through the policy proxy.\n\
        \n\
        Types: deb\n\
        URIs: http://127.0.0.1:6280/apt/debian\n\
        Suites: bookworm bookworm-updates\n\
        Components: main\n\
        Architectures: amd64\n\
        \n\
        Types: deb\n\
        URIs: http://127.0.0.1:6280/apt/debian-security\n\
        Suites: bookworm-security\n\
        Components: main contrib\n\
        Architectures: amd64 i386\n";

    // No apt on this host: content is shown for manual installation.
    let env = environment(home, Os::Macos);
    let changes = run(&config, URL, &[], &env);
    let apt = find(&changes, Client::Apt);
    assert!(matches!(apt.outcome, Outcome::Manual(_)));
    assert_eq!(apt.path, None);
    assert_eq!(apt.content.as_deref(), Some(expected));
    assert!(
        apt.steps[0]
            .starts_with("Save the stanzas above as /etc/apt/sources.list.d/middles.sources")
    );
    assert!(
        apt.steps
            .iter()
            .any(|s| s.contains("deb.debian.org/debian, security.debian.org/debian-security"))
    );
    assert!(
        apt.steps
            .iter()
            .any(|s| s.contains("`sudo apt-get update`"))
    );
    assert!(apt.notes.iter().any(|n| n.contains("loopback")));

    // A sources directory receives the file; explicit selection ignores `enabled`.
    let sources = home.join("etc/apt/sources.list.d");
    fs::create_dir_all(&sources).unwrap();
    let mut env = environment(home, Os::Linux);
    env.apt_sources = Some(sources.clone());
    let mut disabled = config.clone();
    disabled.apt.enabled = false;
    assert!(matches!(
        find(&run(&disabled, URL, &[], &env), Client::Apt).outcome,
        Outcome::Skipped(_)
    ));
    let changes = run(&disabled, URL, &[Client::Apt], &env);
    let written = find(&changes, Client::Apt);
    assert_eq!(written.outcome, Outcome::Create);
    assert!(
        written.steps[0].starts_with("Disable the direct entries"),
        "file already saved"
    );
    assert!(written.notes.is_empty());
    assert_eq!(read(&sources.join("middles.sources")), expected);
    let again = run(&config, URL, &[], &env);
    assert_eq!(find(&again, Client::Apt).outcome, Outcome::Unchanged);

    // Explicitly requested without repositories: nothing sensible to write.
    let mut empty = Config::default();
    empty.apt.enabled = true;
    match &find(&run(&empty, URL, &[Client::Apt], &env), Client::Apt).outcome {
        Outcome::Skipped(reason) => assert!(reason.contains("[[apt.repos]]")),
        other => panic!("{other:?}"),
    }

    // Unwritable directory (a non-root user on a real host): fall back to manual.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::remove_file(sources.join("middles.sources")).unwrap();
        fs::set_permissions(&sources, fs::Permissions::from_mode(0o555)).unwrap();
        let mut changes = setup::plan(&config, URL, &[], &[], &env).unwrap();
        setup::apply(&mut changes).unwrap();
        fs::set_permissions(&sources, fs::Permissions::from_mode(0o755)).unwrap();
        let apt = find(&changes, Client::Apt);
        match &apt.outcome {
            Outcome::Manual(reason) => assert!(reason.contains("permission denied"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(apt.content.as_deref(), Some(expected));
        assert!(apt.steps[0].starts_with("Save the stanzas above as"));
        assert!(apt.steps[0].contains(sources.to_str().unwrap()));
        assert!(!sources.join("middles.sources").exists());
    }
}

#[test]
fn selection_flags_and_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Linux);
    let config = Config::default();

    let planned = setup::plan(&config, URL, &[], &[], &env).unwrap();
    assert_eq!(find(&planned, Client::Npm).outcome, Outcome::Create);
    assert!(
        fs::read_dir(home).unwrap().next().is_none(),
        "planning writes nothing"
    );

    let only = setup::plan(&config, URL, &[Client::Npm], &[], &env).unwrap();
    assert_eq!(find(&only, Client::Npm).outcome, Outcome::Create);
    assert_eq!(
        find(&only, Client::Pip).outcome,
        Outcome::Skipped("not listed in --only".into())
    );
    let skipped = setup::plan(&config, URL, &[], &[Client::Npm], &env).unwrap();
    assert_eq!(
        find(&skipped, Client::Npm).outcome,
        Outcome::Skipped("excluded with --skip".into())
    );
    assert_eq!(find(&skipped, Client::Pip).outcome, Outcome::Create);
    assert_eq!(planned.len(), Client::ALL.len());
}

#[test]
fn paths_follow_environment_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let path_of = |env: &Environment, client: Client| {
        let changes = setup::plan(&Config::default(), URL, &[], &[], env).unwrap();
        find(&changes, client).path.clone().unwrap()
    };
    let mut env = environment(home, Os::Linux);
    let xdg = home.join("xdg");
    env.vars
        .insert("XDG_CONFIG_HOME".into(), xdg.display().to_string());
    assert_eq!(path_of(&env, Client::Pip), xdg.join("pip/pip.conf"));
    assert_eq!(path_of(&env, Client::Uv), xdg.join("uv/uv.toml"));
    assert_eq!(
        path_of(&env, Client::Composer),
        xdg.join("composer/config.json"),
        "an XDG variable selects Composer's XDG location when neither directory exists"
    );
    fs::create_dir_all(home.join(".composer")).unwrap();
    assert_eq!(
        path_of(&env, Client::Composer),
        home.join(".composer/config.json")
    );

    for (name, value) in [
        ("NPM_CONFIG_USERCONFIG", "npmrc-custom"),
        ("PIP_CONFIG_FILE", "pip-custom.conf"),
        ("UV_CONFIG_FILE", "uv-custom.toml"),
        ("COMPOSER_HOME", "composer-home"),
        ("BUNDLE_USER_CONFIG", "bundle-custom"),
    ] {
        env.vars
            .insert(name.into(), home.join(value).display().to_string());
    }
    assert_eq!(path_of(&env, Client::Npm), home.join("npmrc-custom"));
    assert_eq!(path_of(&env, Client::Pip), home.join("pip-custom.conf"));
    assert_eq!(path_of(&env, Client::Uv), home.join("uv-custom.toml"));
    assert_eq!(
        path_of(&env, Client::Composer),
        home.join("composer-home/config.json")
    );
    assert_eq!(path_of(&env, Client::Bundler), home.join("bundle-custom"));
    env.vars.remove("BUNDLE_USER_CONFIG");
    env.vars.insert(
        "BUNDLE_USER_HOME".into(),
        home.join("bh").display().to_string(),
    );
    assert_eq!(path_of(&env, Client::Bundler), home.join("bh/config"));
    env.vars
        .insert("YARN_RC_FILENAME".into(), ".yarnrc-custom.yml".into());
    assert_eq!(path_of(&env, Client::Yarn), home.join(".yarnrc-custom.yml"));
    // Bun prefers ~/.bunfig.toml and falls back to an existing XDG file.
    assert_eq!(path_of(&env, Client::Bun), home.join(".bunfig.toml"));
    write(&xdg.join(".bunfig.toml"), "");
    assert_eq!(path_of(&env, Client::Bun), xdg.join(".bunfig.toml"));
    write(&home.join(".bunfig.toml"), "");
    assert_eq!(path_of(&env, Client::Bun), home.join(".bunfig.toml"));

    // macOS pip prefers Application Support only when that directory exists.
    let env = environment(home, Os::Macos);
    assert_eq!(
        path_of(&env, Client::Pip),
        home.join(".config/pip/pip.conf")
    );
    fs::create_dir_all(home.join("Library/Application Support/pip")).unwrap();
    assert_eq!(
        path_of(&env, Client::Pip),
        home.join("Library/Application Support/pip/pip.conf")
    );
}

#[test]
fn conflicting_environment_variables_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut env = environment(dir.path(), Os::Linux);
    env.vars.insert(
        "NPM_CONFIG_REGISTRY".into(),
        "https://other.example/".into(),
    );
    env.vars.insert(
        "PIP_INDEX_URL".into(),
        "http://127.0.0.1:6280/pip/simple/".into(),
    );
    env.vars
        .insert("UV_INDEX".into(), "https://extra.example/simple".into());
    env.vars.insert(
        "YARN_NPM_REGISTRY_SERVER".into(),
        "https://other.example".into(),
    );
    env.vars
        .insert("YARN_REGISTRY".into(), "http://127.0.0.1:6280/npm/".into());
    let changes = setup::plan(&Config::default(), URL, &[], &[], &env).unwrap();
    let note = |client: Client| find(&changes, client).notes.join("\n");
    assert!(note(Client::Npm).contains(
        "NPM_CONFIG_REGISTRY=https://other.example/ is set in this environment and overrides ~/.npmrc"
    ));
    assert!(
        !note(Client::Pip).contains("PIP_INDEX_URL"),
        "matching values are fine"
    );
    assert!(note(Client::Uv).contains("UV_INDEX=https://extra.example/simple is set"));
    assert!(note(Client::Yarn).contains(
        "YARN_NPM_REGISTRY_SERVER=https://other.example is set in this environment and overrides ~/.yarnrc.yml"
    ));
    assert!(
        !note(Client::Yarn).contains("YARN_REGISTRY"),
        "matching values are fine"
    );
    assert!(note(Client::Bun).contains(
        "NPM_CONFIG_REGISTRY=https://other.example/ is set in this environment and overrides ~/.bunfig.toml"
    ));
}

#[test]
fn base_url_is_normalized_and_validated() {
    assert_eq!(setup::base_url("http://127.0.0.1:6280/").unwrap(), URL);
    assert_eq!(
        setup::base_url("https://Proxy.Example.com/middles/").unwrap(),
        "https://proxy.example.com/middles"
    );
    for bad in [
        "ftp://x",
        "http://u:p@h",
        "http://h/?q=1",
        "http://h/#f",
        "127.0.0.1:6280",
    ] {
        assert!(setup::base_url(bad).is_err(), "{bad}");
    }
}

#[test]
fn client_names_and_aliases_parse() {
    assert_eq!(Client::parse("rubygems").unwrap(), Client::Bundler);
    assert_eq!(Client::parse(" BREW ").unwrap(), Client::Homebrew);
    assert_eq!(Client::parse("pnpm").unwrap(), Client::Npm);
    assert_eq!(Client::parse("yarn1").unwrap(), Client::Npm);
    assert_eq!(Client::parse("berry").unwrap(), Client::Yarn);
    assert_eq!(Client::parse("Bun").unwrap(), Client::Bun);
    for client in Client::ALL {
        assert_eq!(Client::parse(client.as_str()).unwrap(), client);
    }
    assert!(Client::parse("cargo").is_err());
}

#[test]
fn report_covers_every_client() {
    let dir = tempfile::tempdir().unwrap();
    let env = environment(dir.path(), Os::Macos);
    let changes = setup::plan(&apt_config(), URL, &[], &[], &env).unwrap();
    let mut out = Vec::new();
    setup::report(&mut out, &changes, &env, true).unwrap();
    let text = String::from_utf8(out).unwrap();
    for client in Client::ALL {
        assert!(
            text.lines().any(|l| l.starts_with(client.as_str())),
            "{client} missing from:\n{text}"
        );
    }
    assert!(text.contains("npm       would create ~/.npmrc\n"));
    assert!(text.contains("          | registry=http://127.0.0.1:6280/npm/\n"));
    assert!(text.contains("yarn      would create ~/.yarnrc.yml\n"));
    assert!(text.contains("          | npmRegistryServer: \"http://127.0.0.1:6280/npm\"\n"));
    assert!(text.contains("bun       would create ~/.bunfig.toml\n"));
    assert!(text.contains("apt       manual: this host has no /etc/apt/sources.list.d"));
    assert!(text.contains("          | URIs: http://127.0.0.1:6280/apt/debian\n"));
    assert!(text.contains("          1. Save the stanzas above as"));
    assert!(text.contains("          2. Disable the direct entries for deb.debian.org/debian"));
}

#[test]
fn yarn_rc_is_edited_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Linux);
    let rc = home.join(".yarnrc.yml");

    // Flow-style whitelist without the host, another registry, scopes, comments.
    write(
        &rc,
        "# yarn\nnodeLinker: node-modules\nnpmRegistryServer: 'https://registry.yarnpkg.com'\nunsafeHttpWhitelist: [\"localhost\"] # dev\nnpmScopes:\n  corp:\n    npmRegistryServer: \"https://npm.corp\"\n",
    );
    let changes = run(&Config::default(), URL, &[Client::Yarn], &env);
    let yarn = find(&changes, Client::Yarn);
    assert_eq!(yarn.outcome, Outcome::Update);
    assert_eq!(
        read(&rc),
        "# yarn\nnodeLinker: node-modules\nnpmRegistryServer: \"http://127.0.0.1:6280/npm\"\nunsafeHttpWhitelist: [\"localhost\", \"127.0.0.1\"] # dev\nnpmScopes:\n  corp:\n    npmRegistryServer: \"https://npm.corp\"\n"
    );
    assert!(
        yarn.notes
            .iter()
            .any(|n| n == "replaced npmRegistryServer (was https://registry.yarnpkg.com)")
    );
    assert!(yarn.notes.iter().any(|n| n.contains("npmScopes")));
    assert!(
        yarn.notes
            .iter()
            .any(|n| n.contains("unsafeHttpWhitelist now allows plain HTTP to 127.0.0.1"))
    );

    // Block-style whitelist that already lists the host, trailing-slash registry: nothing to do.
    write(
        &rc,
        "npmRegistryServer: \"http://127.0.0.1:6280/npm/\"\nunsafeHttpWhitelist:\n  - localhost\n  - 127.0.0.1\nenableTelemetry: false\n",
    );
    let before = read(&rc);
    let changes = run(&Config::default(), URL, &[Client::Yarn], &env);
    assert_eq!(find(&changes, Client::Yarn).outcome, Outcome::Unchanged);
    assert_eq!(read(&rc), before);

    // Block-style whitelist missing the host: appended after the last item with its indentation.
    write(
        &rc,
        "unsafeHttpWhitelist:\n    - localhost\n\nenableTelemetry: false\n",
    );
    run(&Config::default(), URL, &[Client::Yarn], &env);
    assert_eq!(
        read(&rc),
        "unsafeHttpWhitelist:\n    - localhost\n    - \"127.0.0.1\"\n\nenableTelemetry: false\nnpmRegistryServer: \"http://127.0.0.1:6280/npm\"\n"
    );

    // An HTTPS proxy needs no whitelist.
    fs::remove_file(&rc).unwrap();
    let changes = run(
        &Config::default(),
        "https://proxy.example.com",
        &[Client::Yarn],
        &env,
    );
    assert_eq!(find(&changes, Client::Yarn).outcome, Outcome::Create);
    assert_eq!(
        read(&rc),
        "npmRegistryServer: \"https://proxy.example.com/npm\"\n"
    );
}

#[test]
fn bunfig_install_registry_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let env = environment(home, Os::Macos);
    let bunfig = home.join(".bunfig.toml");
    write(
        &bunfig,
        "# bun\n[install]\n# dev deps\ndev = true\nregistry = 'https://registry.npmjs.org/'\n\n[install.scopes]\ncorp = \"https://npm.corp\"\n\n[test]\ncoverage = true\n",
    );
    let changes = run(&Config::default(), URL, &[Client::Bun], &env);
    let bun = find(&changes, Client::Bun);
    assert_eq!(bun.outcome, Outcome::Update);
    assert_eq!(
        read(&bunfig),
        "# bun\n[install]\n# dev deps\ndev = true\nregistry = \"http://127.0.0.1:6280/npm/\"\n\n[install.scopes]\ncorp = \"https://npm.corp\"\n\n[test]\ncoverage = true\n"
    );
    assert!(
        bun.notes
            .iter()
            .any(|n| n == "replaced registry (was 'https://registry.npmjs.org/')")
    );
    assert!(bun.notes.iter().any(|n| n.contains("[install.scopes]")));

    // A file without an [install] table gets one appended.
    write(&bunfig, "[test]\ncoverage = true\n");
    run(&Config::default(), URL, &[Client::Bun], &env);
    assert_eq!(
        read(&bunfig),
        "[test]\ncoverage = true\n\n[install]\nregistry = \"http://127.0.0.1:6280/npm/\"\n"
    );
    assert_eq!(
        find(
            &run(&Config::default(), URL, &[Client::Bun], &env),
            Client::Bun
        )
        .outcome,
        Outcome::Unchanged
    );
}
