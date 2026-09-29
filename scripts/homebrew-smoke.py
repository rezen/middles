#!/usr/bin/env python3
"""Opt-in real Homebrew -> middles -> official GHCR bottle smoke test.

Uses the signed snapshots from homebrew-spike.py --prepare, an isolated Homebrew
copy and caches, and a disposable middles database. Public GHCR access is required.
No developer prefix, trust key, or age timestamps are modified.
"""
import argparse
import http.server
import importlib.util
import json
import os
import platform
import hashlib
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("spike", ROOT / "scripts/homebrew-spike.py")
spike = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spike)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--api-tag", default="arm64_tahoe", choices=["arm64_tahoe"])
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/middles")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.repository, args.fixtures, args.binary, args.output = (p.resolve() for p in (args.repository, args.fixtures, args.binary, args.output))
    if args.repository == args.output or args.repository in args.output.parents:
        parser.error("output must be outside the Homebrew installation")
    args.output.mkdir(parents=True, exist_ok=True)
    api = spike.read_bounded(args.fixtures / "formula.jws.json", spike.MAX_API)

    class API(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path != "/api/formula.jws.json":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(api)))
            self.end_headers()
            self.wfile.write(api)

    report = {"source_version": subprocess.check_output(["git", "-C", str(args.repository), "describe", "--tags", "--abbrev=7"], text=True).strip(),
              "source_commit": subprocess.check_output(["git", "-C", str(args.repository), "rev-parse", "HEAD"], text=True).strip(),
              "platform": platform.platform(), "api_sha256": hashlib.sha256(api).hexdigest(), "cases": [], "api_tag": args.api_tag, "scope": "official stable bottles; isolated non-default prefix"}
    with tempfile.TemporaryDirectory(prefix="middles-homebrew-smoke-") as tmp:
        work = Path(tmp)
        prefix, cache = work / "brew", work / "cache"
        spike.copy_brew(args.repository, prefix)
        (cache / "api/internal").mkdir(parents=True)
        shutil.copyfile(args.fixtures / "formula.jws.json", cache / "api/formula.jws.json")
        shutil.copyfile(args.fixtures / f"packages.{args.api_tag}.jws.json", cache / f"api/internal/packages.{args.api_tag}.jws.json")
        api_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
        api_thread = threading.Thread(target=api_server.serve_forever, daemon=True)
        api_thread.start()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        config = work / "middles.toml"
        database = work / "cache.sqlite3"
        log = (args.output / "middles.txt").open("w")
        egress = args.output / "egress.jsonl"
        egress.write_text("")
        wrapper = work / "curl-guard"
        wrapper.write_text("#!/bin/sh\nexec " + shlex.join([sys.executable, str(spike.SCRIPT), "--curl-guard", f"127.0.0.1:{port}", str(egress), shutil.which("curl")]) + ' "$@"\n')
        wrapper.chmod(0o755)
        env = {k: v for k, v in os.environ.items() if not k.startswith("HOMEBREW_") and k.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "GH_TOKEN", "GITHUB_TOKEN"}}
        for name in ("home", "temp", "logs"):
            (work / name).mkdir()
        env.update(HOME=str(work / "home"), HOMEBREW_CACHE=str(cache), HOMEBREW_TEMP=str(work / "temp"),
            HOMEBREW_LOGS=str(work / "logs"), HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1",
            HOMEBREW_NO_INSTALL_CLEANUP="1", HOMEBREW_NO_COLOR="1", HOMEBREW_NO_ENV_HINTS="1",
            HOMEBREW_API_AUTO_UPDATE_SECS="31536000", HOMEBREW_ARTIFACT_DOMAIN=origin + "/homebrew",
            HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK="1", HOMEBREW_CURL_PATH=str(wrapper),
            GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        process = None

        def stop():
            nonlocal process
            if process:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                process = None

        def start(days):
            nonlocal process
            stop()
            config.write_text(f'''listen = "127.0.0.1:{port}"
public_url = "{origin}"
[homebrew]
enabled = true
min_age_days = {days}
platforms = ["{args.api_tag}"]
api = "http://127.0.0.1:{api_server.server_port}/api"
[cache]
path = {json.dumps(str(database))}
''')
            process = subprocess.Popen([str(args.binary), "--config", str(config)], stdout=log, stderr=subprocess.STDOUT)
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("middles exited; inspect middles.txt")
                try:
                    with urllib.request.urlopen(origin + "/healthz", timeout=1):
                        return
                except OSError:
                    time.sleep(0.1)
            raise RuntimeError("middles did not become ready")

        def client(name, command, success):
            result = subprocess.run([str(prefix / "bin/brew"), *command], env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            output = result.stdout.replace(str(work.resolve()), "<isolated>").replace(str(work), "<isolated>")
            output = output.replace(str(port), "<port>")
            (args.output / f"{name}.txt").write_text(output)
            report["cases"].append({"name": name, "command": ["brew", *command], "exit": result.returncode})
            print(f"{name}: exit {result.returncode}", flush=True)
            if (result.returncode == 0) != success:
                raise AssertionError(f"unexpected result for {name}; inspect command output")

        try:
            start(7)
            client("blocked-install", ["install", "--force-bottle", "hello"], False)
            subprocess.run([sys.executable, str(ROOT / "scripts/homebrew-warm.py"), origin, "zstd"], check=True, timeout=180)
            start(0)
            client("eligible-install", ["install", "--force-bottle", "hello"], True)
            client("dependencies-install", ["install", "--force-bottle", "zstd"], True)
            with urllib.request.urlopen(origin + "/stats?ecosystem=homebrew") as response:
                stats = json.load(response)
            if stats["totals"]["full_downloads"] != 4:
                raise AssertionError(f"expected four completed bottles, got {stats['totals']}")
            (args.output / "stats.json").write_text(json.dumps(stats, indent=2) + "\n")
            start(7)
            client("fully-cached-fetch", ["fetch", "--force-bottle", "hello"], True)
            client("restart-cold-bottle-denied", ["fetch", "--force", "--force-bottle", "hello"], False)
            if any(not json.loads(line)["allowed"] for line in egress.read_text().splitlines()):
                raise AssertionError("client attempted an upstream curl destination")
            report["result"] = "PASS"
        finally:
            stop()
            api_server.shutdown()
            api_server.server_close()
            api_thread.join(timeout=5)
            log.close()
            report.setdefault("result", "FAIL")
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: signed API, bottle checksums, dependency installs, denials, restart policy, statistics, and cache limitation")


if __name__ == "__main__":
    main()
