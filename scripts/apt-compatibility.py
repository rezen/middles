#!/usr/bin/env python3
"""Local signed-repository apt compatibility probe; requires Docker and GPG."""
import gzip
import argparse
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import socket
import sqlite3

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/apt/traces"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def build(root, version="1.0"):
    pkg = root / "build/pkg/DEBIAN"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "control").write_text(f"Package: middles-fixture\nVersion: {version}\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: inert apt fixture\n")
    (root / "build/pkg/usr/share/middles-fixture").mkdir(parents=True, exist_ok=True)
    (root / "build/pkg/usr/share/middles-fixture/marker").write_text(f"fixture {version}\n")
    pool = root / "repo/pool/main/m/middles-fixture"
    pool.mkdir(parents=True, exist_ok=True)
    deb = pool / f"middles-fixture_{version}_all.deb"
    run("docker", "run", "--rm", "--platform", "linux/amd64", "-v", f"{root}/build:/build", "golang:1.24-bookworm", "dpkg-deb", "--build", "/build/pkg", f"/build/{deb.name}")
    shutil.copy(root / "build" / deb.name, deb)
    idx = root / "repo/dists/test/main/binary-amd64"
    idx.mkdir(parents=True, exist_ok=True)
    stanza = (root / "build/pkg/DEBIAN/control").read_text() + f"Filename: {deb.relative_to(root / 'repo')}\nSize: {deb.stat().st_size}\nSHA256: {hashlib.sha256(deb.read_bytes()).hexdigest()}\n\n"
    (idx / "Packages").write_text(stanza)
    with gzip.GzipFile(filename=str(idx / "Packages.gz"), mode="wb", mtime=0) as f:
        f.write(stanza.encode())
    import lzma
    (idx / "Packages.xz").write_bytes(lzma.compress(stanza.encode()))
    byhash = idx / "by-hash/SHA256"
    byhash.mkdir(parents=True, exist_ok=True)
    for p in [idx / "Packages", idx / "Packages.gz", idx / "Packages.xz"]:
        shutil.copy(p, byhash / hashlib.sha256(p.read_bytes()).hexdigest())
    release = root / "repo/dists/test/Release"
    lines = ["Origin: Middles fixture", "Label: Middles fixture", "Suite: test", "Codename: test", "Architectures: amd64", "Components: main", "Acquire-By-Hash: yes", "Date: Tue, 29 Sep 2026 00:00:00 UTC", "SHA256:"]
    for p in [idx / "Packages", idx / "Packages.gz", idx / "Packages.xz"]:
        lines.append(f" {hashlib.sha256(p.read_bytes()).hexdigest()} {p.stat().st_size} {p.relative_to(release.parent)}")
    release.write_text("\n".join(lines) + "\n")
    gnupg = root / "gnupg"
    gnupg.mkdir(mode=0o700, exist_ok=True)
    env = {**os.environ, "GNUPGHOME": str(gnupg)}
    if not (root / "fixture.asc").exists():
        run("gpg", "--batch", "--passphrase", "", "--quick-generate-key", "Fixture <fixture@example.invalid>", "rsa2048", "sign", "0", env=env)
    run("gpg", "--batch", "--yes", "--clearsign", "--output", str(release.parent / "InRelease"), str(release), env=env)
    run("gpg", "--batch", "--yes", "--armor", "--detach-sign", "--output", str(release.parent / "Release.gpg"), str(release), env=env)
    key = run("gpg", "--armor", "--export", "fixture@example.invalid", env=env).stdout
    (root / "fixture.asc").write_text(key)


def probe(image, fallback=False, deny=False, proxy=False, upgrade=False, proxy_image=None):
    with tempfile.TemporaryDirectory(prefix="middles-apt-") as td:
        root = pathlib.Path(td)
        build(root)
        events = []
        upgraded = [False]

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                events.append({"method": "GET", "path": path, "headers": dict(self.headers)})
                if deny and not proxy and path.endswith(".deb"):
                    self.send_error(403, "Forbidden")
                    return
                if fallback and path.endswith("/InRelease"):
                    self.send_error(404, "Not Found")
                    return
                file = root / "repo" / path.lstrip("/")
                if not file.is_file() or not file.resolve().is_relative_to((root / "repo").resolve()):
                    self.send_error(404, "Not Found")
                    return
                data = file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                if upgrade and path.endswith("_1.0_all.deb") and not upgraded[0]:
                    upgraded[0] = True
                    build(root, "2.0")

        server = socketserver.TCPServer(("0.0.0.0", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        middle = None
        middle_container = None
        client_url = f"http://host.docker.internal:{port}/"
        if proxy:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                middle_port = sock.getsockname()[1]
            cache_dir = root / "cache"
            if proxy_image:
                cache_dir.mkdir(mode=0o777)
                os.chmod(cache_dir, 0o777)
                os.chmod(root, 0o755)
            config = root / "middles.toml"
            upstream_host = "host.docker.internal" if proxy_image else "127.0.0.1"
            cache_path = "/var/lib/middles/cache.sqlite3" if proxy_image else str(root / "cache.sqlite3")
            listen_port = 8080 if proxy_image else middle_port
            config.write_text(f'''listen = "0.0.0.0:{listen_port}"
public_url = "http://host.docker.internal:{middle_port}"
[policy]
min_age_days = {1 if deny or upgrade else 0}
[apt]
enabled = true
max_index_mb = 1
[[apt.repos]]
name = "fixture"
url = "http://{upstream_host}:{port}"
suites = ["test"]
components = ["main"]
architectures = ["amd64"]
[upstream]
allow_http = true
artifact_hosts = ["{upstream_host}"]
[cache]
path = "{cache_path}"
metadata_ttl_secs = {1 if upgrade else 300}
''')
            if proxy_image:
                if upgrade:
                    packages = (root / "repo/dists/test/main/binary-amd64/Packages").read_text()
                    checksum = next(line.split(": ", 1)[1] for line in packages.splitlines() if line.startswith("SHA256: "))
                    seeded = cache_dir / "cache.sqlite3"
                    with sqlite3.connect(seeded) as db:
                        db.execute("CREATE TABLE first_seen (key TEXT PRIMARY KEY, timestamp INTEGER NOT NULL)")
                        db.execute("INSERT INTO first_seen VALUES (?, ?)", (f"apt:{checksum}", int(time.time()) - 172800))
                    os.chmod(seeded, 0o666)
                middle_container = run(
                    "docker", "run", "--rm", "--detach",
                    "--publish", f"127.0.0.1:{middle_port}:{listen_port}",
                    "--add-host", "host.docker.internal:host-gateway",
                    "--mount", f"type=bind,src={root},dst=/fixture,readonly",
                    "--mount", f"type=bind,src={cache_dir},dst=/var/lib/middles",
                    "--read-only", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges:true",
                    proxy_image, "--config", "/fixture/middles.toml",
                ).stdout.strip()
            else:
                middle = subprocess.Popen([str(ROOT / "target/debug/middles"), "--config", str(config)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for _ in range(100):
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{middle_port}/healthz", timeout=0.1).close()
                    break
                except Exception:
                    time.sleep(0.05)
            else:
                if middle:
                    middle.kill()
                details = subprocess.run(["docker", "logs", middle_container], text=True, capture_output=True).stdout if middle_container else ""
                if middle_container:
                    subprocess.run(["docker", "rm", "--force", middle_container], text=True, capture_output=True)
                server.shutdown()
                raise RuntimeError(f"middles failed to start: {details}")
            client_url = f"http://host.docker.internal:{middle_port}/apt/fixture"
            if upgrade:
                urllib.request.urlopen(f"http://127.0.0.1:{middle_port}/apt/fixture/dists/test/InRelease").close()
                if not proxy_image:
                    with sqlite3.connect(root / "cache.sqlite3") as db:
                        observed = db.execute("SELECT count(*) FROM first_seen WHERE key LIKE 'apt:%'").fetchone()[0]
                        if observed == 0:
                            raise RuntimeError("APT prewarm did not populate first_seen")
                        db.execute("UPDATE first_seen SET timestamp = timestamp - 172800 WHERE key LIKE 'apt:%'")
                check = f"http://127.0.0.1:{middle_port}/apt/fixture/check/pool/main/m/middles-fixture/middles-fixture_1.0_all.deb"
                with urllib.request.urlopen(check) as response:
                    evidence = json.load(response)
                if not evidence["age"]["eligible"]:
                    if middle_container:
                        subprocess.run(["docker", "rm", "--force", middle_container], text=True, capture_output=True)
                    if middle:
                        middle.terminate()
                        middle.wait(timeout=5)
                    server.shutdown()
                    raise RuntimeError(f"backdated fixture archive remained blocked: {evidence['age']}")
        setup = f"cp /fixture/fixture.asc /etc/apt/trusted.gpg.d/middles-fixture.asc; printf 'deb {client_url} test main\\n' >/tmp/fixture.list"
        update = "apt-get update -o Dir::Etc::sourcelist=/tmp/fixture.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0"
        install = "apt-get install -y -o Dir::Etc::sourcelist=/tmp/fixture.list -o Dir::Etc::sourceparts=- middles-fixture"
        command = setup + (f"; {update}; {install}; sleep 2; {update}; apt-get upgrade -y -o Dir::Etc::sourcelist=/tmp/fixture.list -o Dir::Etc::sourceparts=-" if upgrade else f"; {update}; {update}; {install}")
        try:
            result = subprocess.run(["docker", "run", "--rm", "--platform", "linux/amd64", "--add-host", "host.docker.internal:host-gateway", "-v", f"{root}:/fixture:ro", image, "sh", "-c", command], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        finally:
            server.shutdown()
            if middle:
                middle.terminate()
                try:
                    middle.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    middle.kill()
                    middle.wait()
            if middle_container:
                subprocess.run(["docker", "rm", "--force", middle_container], text=True, capture_output=True)
        return {"image": image, "fallback": fallback, "deny": deny, "proxy": proxy, "proxy_image": proxy_image, "upgrade": upgrade, "exit": result.returncode, "output": result.stdout, "requests": events}


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--proxy", action="store_true", help="exercise middles rather than direct fixture passthrough")
    args.add_argument("--proxy-image", help="run middles in this existing Docker image instead of as a host process")
    args.add_argument("--client-image", action="append", help="APT client Docker image; repeat to test more than one (requires apt-get and dpkg)")
    options = args.parse_args()
    options.proxy = options.proxy or bool(options.proxy_image)
    OUT.mkdir(parents=True, exist_ok=True)
    images = options.client_image or ["golang:1.24-bookworm", "ubuntu:20.04"]
    for image in images:
        label = "debian-bookworm" if image == "golang:1.24-bookworm" else "ubuntu-20.04" if image == "ubuntu:20.04" else image.replace("/", "-").replace(":", "-")
        for scenario, fallback, deny in [("normal", False, False), ("fallback", True, False), ("denied", False, True)]:
            result = probe(image, fallback, deny, options.proxy, proxy_image=options.proxy_image)
            name = label + "-" + scenario
            if not options.proxy:
                (OUT / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
            expected = 100 if deny else 0
            if result["exit"] != expected:
                raise SystemExit(f"{name}: expected exit {expected}, got {result['exit']}\n{result['output']}")
            print(name, result["exit"], len(result["requests"]))
        if options.proxy:
            result = probe(image, proxy=True, upgrade=True, proxy_image=options.proxy_image)
            name = label + "-upgrade"
            if result["exit"] != 100 or "403" not in result["output"]:
                raise SystemExit(f"{name}: expected blocked upgrade\n{result['output']}")
            print(name, result["exit"], len(result["requests"]))


if __name__ == "__main__":
    main()
