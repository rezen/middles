#!/usr/bin/env python3
"""Opt-in live registry/client smoke test. Requires built binary, npm, pip, Composer.
Runs clients in a disposable directory with isolated caches; executes no package scripts.
"""
import json
import os
from pathlib import Path
import socket
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "target/debug/middles"


def run(args, cwd, env):
    print("+ " + " ".join(map(str, args)), flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=120)


with tempfile.TemporaryDirectory(prefix="middles-smoke-") as tmp:
    work = Path(tmp)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    config = work / "middles.toml"
    config.write_text(f'''listen = "127.0.0.1:{port}"
public_url = "{origin}"
[cache]
path = "{work}/cache.sqlite3"
[composer]
# Explicit compatibility-test override: production defaults retain first-seen age.
min_age_days = 0
''')
    env = dict(os.environ)
    env.update(COMPOSER_HOME=str(work / "composer-home"), COMPOSER_CACHE_DIR=str(work / "composer-cache"), RUST_LOG="middles=info")
    log = (work / "proxy.log").open("w+")
    proxy = subprocess.Popen([str(BINARY), "--config", str(config)], stdout=log, stderr=log, env=env)
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(origin + "/healthz", timeout=1) as response:
                    assert response.status == 200
                break
            except OSError:
                if proxy.poll() is not None:
                    raise RuntimeError("proxy exited before startup")
                time.sleep(0.05)
        else:
            raise RuntimeError("proxy did not start")

        # Static inspection only: no esbuild archive or install script is fetched/executed.
        with urllib.request.urlopen(origin + "/inspect/npm/esbuild?version=0.25.0", timeout=60) as response:
            report = json.load(response)
        assert report["inspection"]["scripts"]["postinstall"] == "node install.js"
        assert report["inspection"]["dependency_execution"] is True
        assert report["blocked_by_hook_policy"] is False
        with urllib.request.urlopen(origin + "/inspect/pip/six?filename=six-1.17.0.tar.gz", timeout=60) as response:
            report = json.load(response)
        assert report["inspection"]["status"] == "unknown"
        assert report["inspection"]["dependency_execution"] is True

        npm_dir = work / "npm"
        npm_dir.mkdir()
        (npm_dir / "package.json").write_text('{"name":"middles-smoke","version":"1.0.0","private":true}')
        (work / "npm-user.conf").touch()
        (work / "npm-global.conf").touch()
        run(["npm", "install", "is-number@7.0.0", f"--registry={origin}/npm/", "--ignore-scripts", "--no-audit", "--no-fund", f"--cache={work}/npm-cache", f"--userconfig={work}/npm-user.conf", f"--globalconfig={work}/npm-global.conf"], npm_dir, env)
        lock = json.loads((npm_dir / "package-lock.json").read_text())
        assert lock["packages"]["node_modules/is-number"]["resolved"].startswith(origin + "/artifacts/npm/")

        run([sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check", "--no-cache-dir", "download", "six==1.17.0", "--no-deps", "--index-url", origin + "/pip/simple/", "--dest", str(work / "wheels")], work, env)
        assert list((work / "wheels").glob("six-1.17.0-*.whl"))

        composer_dir = work / "composer"
        composer_dir.mkdir()
        (composer_dir / "composer.json").write_text(json.dumps({
            "name": "middles/smoke", "require": {"psr/log": "3.0.2"},
            "repositories": [{"type": "composer", "url": origin + "/composer/"}, {"packagist.org": False}],
            "config": {"secure-http": False, "preferred-install": "dist"}
        }))
        run(["composer", "install", "--no-interaction", "--no-plugins", "--no-scripts", "--no-cache", "--prefer-dist"], composer_dir, env)
        lock = json.loads((composer_dir / "composer.lock").read_text())
        assert lock["packages"][0]["dist"]["url"].startswith(origin + "/artifacts/composer/")
        assert "source" not in lock["packages"][0]
        if os.environ.get("MIDDLES_SMOKE_RUBYGEMS") == "1":
            ruby_dir = work / "ruby"
            ruby_dir.mkdir()
            (ruby_dir / "Gemfile").write_text(f'source "{origin}/rubygems/"\ngem "rake", "13.2.1"\n')
            ruby_env = {key: value for key, value in env.items() if not key.startswith("BUNDLE_")}
            ruby_env.update(BUNDLE_USER_HOME=str(work / "bundle-home"), BUNDLE_PATH=str(work / "gems"),
                            BUNDLE_APP_CONFIG=str(work / "bundle-config"), BUNDLE_PLUGINS="false",
                            BUNDLE_DISABLE_VERSION_CHECK="true", GEM_SPEC_CACHE=str(work / "gem-spec-cache"))
            bundle = shlex.split(os.environ.get("BUNDLE_COMMAND", "bundle"))
            run([*bundle, "install"], ruby_dir, ruby_env)
            assert f"remote: {origin}/rubygems/" in (ruby_dir / "Gemfile.lock").read_text()
            with urllib.request.urlopen(origin + "/stats?ecosystem=rubygems&package=rake") as response:
                assert "rake" in json.dumps(json.load(response))
            print("PASS: live RubyGems download through middles", flush=True)

        print("PASS: live hook inspection plus npm, pip, and Composer downloads through middles", flush=True)
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.wait()
        log.seek(0)
        print(log.read())
        log.close()
