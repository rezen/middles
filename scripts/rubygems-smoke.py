#!/usr/bin/env python3
"""Local-only Bundler compatibility test using inert, generated gems.

Requires ruby, gem, bundle, Python 3, and a built middles binary. BUNDLE_COMMAND
can select a particular Bundler executable (shell-split, never shell-executed).
No public registry access or package hooks are needed.
"""
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "target/debug/middles"
BUNDLE = shlex.split(os.environ.get("BUNDLE_COMMAND", "bundle"))


def run(args, cwd, env=None, success=True):
    print("+ " + " ".join(map(str, args)), flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=90)
    print(result.stdout, flush=True)
    if success and result.returncode:
        raise RuntimeError(f"command failed: {args}")
    if not success and not result.returncode:
        raise AssertionError("blocked lockfile unexpectedly installed")
    return result.stdout


def main():
    with tempfile.TemporaryDirectory(prefix="middles-rubygems-") as tmp:
        work = Path(tmp)
        platform = subprocess.check_output(["ruby", "-rrubygems", "-e", "print Gem::Platform.local"], text=True)
        artifacts = {}
        specs = {}
        releases = {"middles_fixture": [("1.0.0", "ruby"), ("2.0.0", "ruby")],
                    "middles_leaf": [("1.0.0", "ruby"), ("1.0.0", platform)]}
        for name, versions in releases.items():
            for version, target in versions:
                specfile = work / "fixture.gemspec"
                deps = 's.add_runtime_dependency "middles_leaf", "~> 1.0"' if name == "middles_fixture" else ""
                specfile.write_text(f'''Gem::Specification.new do |s|
  s.name = {json.dumps(name)}
  s.version = {json.dumps(version)}
  s.platform = {json.dumps(target)}
  s.summary = "Inert middles compatibility fixture"
  s.authors = ["middles"]
  s.license = "MIT"
  s.homepage = "https://example.invalid"
  s.files = []
  {deps}
end
''')
                run(["gem", "build", str(specfile)], work)
                identity = version + ("-" + target if target != "ruby" else "")
                stem = name + "-" + identity
                artifacts[stem] = (work / (stem + ".gem")).read_bytes()
                specs[stem] = subprocess.check_output([
                    "ruby", "-rrubygems/package", "-rzlib", "-e",
                    "STDOUT.binmode; STDOUT.write Zlib.deflate(Marshal.dump(Gem::Package.new(ARGV[0]).spec))",
                    str(work / (stem + ".gem"))])

        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)).isoformat()
        young = datetime.datetime.now(datetime.timezone.utc).isoformat()
        state = {"block_old": False, "mature_new": False}
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path.startswith("/info/"):
                    name = self.path.removeprefix("/info/")
                    if name not in releases:
                        self.send_error(404)
                        return
                    lines = ["---"]
                    for version, target in releases[name]:
                        identity = version + ("-" + target if target != "ruby" else "")
                        stem = name + "-" + identity
                        date = old
                        if name == "middles_fixture":
                            if version == "1.0.0" and state["block_old"]:
                                date = young
                            elif version == "2.0.0" and not state["mature_new"]:
                                date = young
                        dependency = "middles_leaf:~> 1.0" if name == "middles_fixture" else ""
                        digest = hashlib.sha256(artifacts[stem]).hexdigest()
                        lines.append(f"{identity} {dependency}|checksum:{digest},ruby:>= 2.6,created_at:{date}")
                    body = ("\n".join(lines) + "\n").encode()
                elif self.path.startswith("/gems/"):
                    body = artifacts.get(self.path.removeprefix("/gems/").removesuffix(".gem"))
                elif self.path.startswith("/quick/Marshal.4.8/"):
                    body = specs.get(self.path.removeprefix("/quick/Marshal.4.8/").removesuffix(".gemspec.rz"))
                else:
                    body = None
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        config = work / "middles.toml"
        config.write_text(f'''listen = "127.0.0.1:{port}"
public_url = "{origin}"
[cache]
path = "{work}/cache.sqlite3"
metadata_ttl_secs = 1
[upstream]
rubygems = "http://127.0.0.1:{upstream.server_port}"
allow_http = true
artifact_hosts = ["127.0.0.1"]
''')
        (work / "Gemfile").write_text(f'source "{origin}/rubygems/"\ngem "middles_fixture"\n')
        env = {key: value for key, value in os.environ.items() if not key.startswith("BUNDLE_")}
        env.update(HOME=str(work / "home"), BUNDLE_USER_HOME=str(work / "bundle-home"),
                   BUNDLE_PATH=str(work / "installed"), BUNDLE_DISABLE_VERSION_CHECK="true",
                   BUNDLE_APP_CONFIG=str(work / "bundle-config"), BUNDLE_RETRY="0",
                   BUNDLE_PLUGINS="false", GEM_SPEC_CACHE=str(work / "spec-cache"))
        Path(env["HOME"]).mkdir()
        log = (work / "proxy.log").open("w+")
        proxy = subprocess.Popen([str(BINARY), "--config", str(config)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(origin + "/healthz", timeout=1).close()
                    break
                except OSError:
                    if proxy.poll() is not None:
                        raise RuntimeError("proxy exited before startup")
                    time.sleep(0.05)
            else:
                raise RuntimeError("proxy did not start")
            run([*BUNDLE, "--version"], work, env)
            run([*BUNDLE, "install"], work, env)
            lock = (work / "Gemfile.lock").read_text()
            assert "middles_fixture (1.0.0)" in lock
            assert f"middles_leaf (1.0.0-{platform})" in lock
            assert f"remote: {origin}/rubygems/" in lock
            assert "/gems/middles_fixture-1.0.0.gem" in requests
            assert f"/gems/middles_leaf-1.0.0-{platform}.gem" in requests
            assert "/gems/middles_fixture-2.0.0.gem" not in requests
            run([*BUNDLE, "install"], work, env)

            # Keep lockfile and metadata caches, remove installed artifacts. A stale
            # lock must not grant access after its publication evidence changes.
            shutil.rmtree(work / "installed")
            state["block_old"] = True
            time.sleep(1.1)
            before = requests.count("/gems/middles_fixture-1.0.0.gem")
            run([*BUNDLE, "install"], work, env, success=False)
            assert requests.count("/gems/middles_fixture-1.0.0.gem") == before

            # Warm-client update must discover a newly eligible release.
            state.update(block_old=False, mature_new=True)
            time.sleep(1.1)
            run([*BUNDLE, "update", "middles_fixture"], work, env)
            assert "middles_fixture (2.0.0)" in (work / "Gemfile.lock").read_text()
            assert "/gems/middles_fixture-2.0.0.gem" in requests
            with urllib.request.urlopen(origin + "/stats?ecosystem=rubygems") as response:
                report = json.load(response)
            assert "middles_fixture" in json.dumps(report)
            assert all(path.startswith(("/info/", "/gems/", "/quick/Marshal.4.8/")) for path in requests)
            print("PASS: fresh/locked installs, native platform, dependency resolution, blocked stale lock, warm update, and transfer stats")
            print("Upstream request trace:\n" + "\n".join(requests))
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait()
            upstream.shutdown()
            log.seek(0)
            if sys.exc_info()[0]:
                print(log.read())
            log.close()


if __name__ == "__main__":
    main()
