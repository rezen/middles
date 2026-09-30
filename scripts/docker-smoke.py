#!/usr/bin/env python3
"""Check a built image using a local Docker daemon and a local registry fixture.

Requires Python 3 and Docker Engine 20.10+ (or Docker Desktop). No third-party
Python packages or public registries are used. Run from any working directory.
"""

import argparse
import http.server
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request
import uuid


def docker(*args, check=True):
    return subprocess.run(
        ["docker", *args], check=check, text=True, capture_output=True, timeout=90
    )


class Registry(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/p2/vendor/demo.json":
            self.send_error(404)
            return
        body = json.dumps({"packages": {"vendor/demo": [{
            "name": "vendor/demo", "version": "1.0.0", "type": "metapackage",
            "time": "2020-01-01T00:00:00Z",
        }]}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def inspect(container):
    return json.loads(docker("inspect", container).stdout)[0]


def wait_healthy(container):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = inspect(container)["State"]
        if state["Status"] != "running":
            raise RuntimeError(f"Container exited: {state}")
        if state["Health"]["Status"] == "healthy":
            return
        time.sleep(0.5)
    raise RuntimeError("Container did not become healthy")


def snapshot(container, destination):
    # Stop before copying the entire SQLite directory, including any WAL files.
    docker("stop", "--time", "10", container)
    state = inspect(container)["State"]
    assert state["ExitCode"] == 0 and not state["OOMKilled"], state
    destination.mkdir()
    docker("cp", f"{container}:/var/lib/middles/.", str(destination))
    with sqlite3.connect(destination / "cache.sqlite3") as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("SELECT COUNT(*) FROM responses").fetchone()[0] > 0
        ledger = db.execute("SELECT key, timestamp FROM first_seen ORDER BY key").fetchall()
    assert len(ledger) == 1, ledger
    return ledger


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", default="middles:local")
    args = parser.parse_args()
    docker("info")
    suffix = uuid.uuid4().hex[:12]
    container = f"middles-smoke-{suffix}"
    volume = f"{container}-data"
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Registry)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with tempfile.TemporaryDirectory(prefix="middles-docker-") as temp:
            directory = Path(temp).resolve()
            config = directory / "middles.toml"
            config.write_text(
                'listen = "0.0.0.0:6280"\n'
                'public_url = "http://127.0.0.1:6280"\n'
                '[cache]\npath = "/var/lib/middles/cache.sqlite3"\n'
                '[upstream]\nallow_http = true\n'
                f'packagist = "http://host.docker.internal:{server.server_port}"\n'
            )
            invalid = directory / "invalid.toml"
            invalid.write_text('listen = "invalid"\n')
            # Bind-mounted fixture files must be readable by the image's user.
            config.chmod(0o644)
            invalid.chmod(0o644)
            # Supplying arguments replaces CMD, so include --config explicitly.
            docker("run", "--rm", args.image, "--config", "/etc/middles/middles.toml", "--check")
            failed = docker(
                "run", "--rm", "--mount",
                f"type=bind,src={invalid},dst=/invalid.toml,readonly",
                args.image, "--config", "/invalid.toml", "--check", check=False,
            )
            assert failed.returncode == 1, failed.stderr
            docker("volume", "create", volume)
            ledgers = []
            for attempt in range(2):
                docker(
                    "run", "--detach", "--name", container,
                    "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges:true",
                    "--add-host", "host.docker.internal:host-gateway",
                    "--publish", "127.0.0.1::6280",
                    "--health-interval", "1s", "--health-start-period", "1s",
                    "--mount", f"type=volume,src={volume},dst=/var/lib/middles",
                    "--mount", f"type=bind,src={config},dst=/etc/middles/middles.toml,readonly",
                    args.image,
                )
                wait_healthy(container)
                assert docker("exec", container, "id", "-u").stdout.strip() == "10001"
                port = inspect(container)["NetworkSettings"]["Ports"]["6280/tcp"][0]["HostPort"]
                base = f"http://127.0.0.1:{port}"
                with opener.open(f"{base}/healthz", timeout=5) as response:
                    assert json.load(response) == {"status": "ok"}
                with opener.open(f"{base}/composer/p2/vendor/demo.json", timeout=10) as response:
                    # The default seven-day first-observation policy still applies.
                    assert json.load(response) == {"packages": {"vendor/demo": []}}
                ledgers.append(snapshot(container, directory / f"snapshot-{attempt}"))
                docker("rm", container)
                if attempt == 0:
                    # A recreated ledger must have a different timestamp if data is lost.
                    time.sleep(1.1)
            assert ledgers[0] == ledgers[1], "Composer first-observation history changed"
            print("Docker smoke checks passed: config, non-root, health, SIGTERM, SQLite persistence")
    except Exception:
        logs = docker("logs", container, check=False)
        print(logs.stdout + logs.stderr)
        raise
    finally:
        docker("rm", "--force", container, check=False)
        docker("volume", "rm", volume, check=False)
        server.shutdown()
        server.server_close()
        worker.join()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"Docker command failed: {error.cmd}\n{error.stdout}{error.stderr}")
