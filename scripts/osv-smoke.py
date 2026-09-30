#!/usr/bin/env python3
"""Opt-in live OSV advisory inspection smoke test. Requires a built middles binary.

Starts an isolated report-mode instance; downloads no package artifacts.
Usage: python3 scripts/osv-smoke.py [target/debug/middles]
"""
import json
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "target/debug/middles"
CASES = (
    ("npm", "lodash", "4.17.20"),
    ("pip", "requests", "2.19.1"),
    ("composer", "symfony/http-foundation", "5.4.0"),
    ("rubygems", "rack", "2.2.3"),
)


def fetch(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="middles-osv-smoke-") as tmp:
        work = Path(tmp)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        config = work / "middles.toml"
        config.write_text(
            f'listen = "127.0.0.1:{port}"\n'
            f'public_url = "{origin}"\n'
            '[policy]\n'
            'advisories = "report"\n'
            '[cache]\n'
            f'path = "{work / "cache.sqlite3"}"\n'
        )
        log = (work / "proxy.log").open("w+")
        proxy = subprocess.Popen([str(BINARY), "--config", str(config)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if proxy.poll() is not None:
                    raise RuntimeError("proxy exited before startup")
                try:
                    urllib.request.urlopen(origin + "/healthz", timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("proxy did not start")
            for ecosystem, package, version in CASES:
                path = urllib.parse.quote(package, safe="/")
                query = urllib.parse.urlencode({"version": version})
                report = fetch(f"{origin}/inspect/advisories/{ecosystem}/{path}?{query}")
                assert report["policy"] == "report", report
                assert report["advisories"], (ecosystem, package, version)
                print(f"PASS: {ecosystem} {package}@{version}: {len(report['advisories'])} advisories")
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait()
            if sys.exc_info()[0] is not None:
                log.seek(0)
                print(log.read(), file=sys.stderr)
            log.close()


if __name__ == "__main__":
    main()
