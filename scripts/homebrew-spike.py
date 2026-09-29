#!/usr/bin/env python3
"""Opt-in Homebrew compatibility gate, not a middles adapter or enforcement tool.

Copies Homebrew into a disposable prefix. Public, signed API snapshots and exact
bottle objects are prepared separately; client runs permit curl only to the
fixture. No changes to the caller's prefix, Cellar, caches, or trust keys.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse

MAX_API = 64 * 1024 * 1024
MAX_INDEX = 1024 * 1024
MAX_BOTTLE = 32 * 1024 * 1024
REDIRECT_HOSTS = {"ghcr.io", "pkg-containers.githubusercontent.com"}
FORMULAE = ("hello", "zstd", "lz4", "xz")
SCRIPT = Path(__file__).resolve()


def digest(body):
    return hashlib.sha256(body).hexdigest()


def safe_url(raw):
    u = urllib.parse.urlsplit(raw)
    # Never save credentials, queries (including redirect signatures), or fragments.
    return urllib.parse.urlunsplit((u.scheme, u.hostname or "", u.path, "", ""))


def guard(args, origin, egress, curl):
    """Constrain the exercised curl path; deliberately not a process firewall."""
    urls = [a for a in args if a.startswith(("http://", "https://"))]
    allowed = all(urllib.parse.urlsplit(u).scheme == "http"
                  and urllib.parse.urlsplit(u).netloc == origin for u in urls)
    with open(egress, "a") as out:
        for u in urls:
            out.write(json.dumps({"url": safe_url(u), "allowed": allowed}) + "\n")
    if not allowed:
        print("middles fixture: rejected non-fixture curl destination", file=sys.stderr)
        return 7
    # Reject caller-supplied proxy/config options and force redirects to remain local.
    if any(a in ("--config", "-K", "--proxy", "-x", "--preproxy")
           or a.startswith(("--config=", "--proxy=", "--preproxy=", "-K", "-x")) for a in args):
        return 7
    os.execv(curl, ["curl", "--disable", *args,
               "--noproxy", "*", "--proto-redir", "=http", "--max-redirs", "0"])


def fetch(url, limit, curl):
    """Bounded preparation only, with exact redirect hosts and no client tokens."""
    with tempfile.TemporaryDirectory(prefix="middles-brew-fetch-") as tmp:
        body_path, headers_path = Path(tmp) / "body", Path(tmp) / "headers"
        for _ in range(6):
            u = urllib.parse.urlsplit(url)
            if (u.scheme != "https" or u.hostname not in REDIRECT_HOSTS | {"formulae.brew.sh"}
                    or u.username or u.password or u.port not in (None, 443)):
                raise ValueError("preparation redirect outside the fixture allowlist")
            command = [curl, "--disable", "--silent", "--show-error", "--max-time", "90",
                       "--max-filesize", str(limit), "--dump-header", str(headers_path),
                       "--output", str(body_path), "--write-out", "%{http_code}"]
            if u.hostname == "ghcr.io":
                command += ["--header", "Authorization: Bearer QQ==",
                            "--header", "Accept: application/vnd.oci.image.index.v1+json"]
            result = subprocess.run([*command, url], capture_output=True, text=True, timeout=100)
            if result.returncode:
                # Curl diagnostics may contain signed redirect URLs; don't persist them.
                raise RuntimeError(f"fixture preparation download failed ({result.returncode})")
            status = int(result.stdout)
            if 300 <= status < 400:
                locations = re.findall(r"(?im)^location:\s*(.*?)\r?$", headers_path.read_text())
                if not locations:
                    raise ValueError("redirect without Location")
                url = urllib.parse.urljoin(url, locations[-1])
                continue
            if status != 200 or body_path.stat().st_size > limit:
                raise ValueError(f"invalid fixture response ({status})")
            return body_path.read_bytes()
    raise ValueError("too many fixture redirects")


def read_bounded(path, limit):
    with Path(path).open("rb") as f:
        body = f.read(limit + 1)
    if len(body) > limit:
        raise ValueError("fixture object too large")
    return body


def jws_payload(body, key, work):
    """Verify Homebrew's PS512 unencoded-payload JWS using its unchanged key."""
    import base64
    jws = json.loads(body)
    for s in jws.get("signatures", []):
        if s.get("header", {}).get("kid") != "homebrew-1":
            continue
        protected = s["protected"]
        header = json.loads(base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4)))
        if header != {"alg": "PS512", "b64": False, "crit": ["b64"]}:
            raise ValueError("unsupported Homebrew signature header")
        signature = s["signature"]
        (work / "signature").write_bytes(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
        (work / "message").write_bytes((protected + "." + jws["payload"]).encode())
        r = subprocess.run(["openssl", "dgst", "-sha512", "-verify", str(key),
                            "-signature", str(work / "signature"), "-sigopt", "rsa_padding_mode:pss",
                            "-sigopt", "rsa_pss_saltlen:64", str(work / "message")], capture_output=True)
        if r.returncode:
            raise ValueError("invalid Homebrew signature")
        return json.loads(jws["payload"])
    raise ValueError("Homebrew signature missing")


def prepare(args):
    root = args.fixtures
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="middles-brew-signature-") as tmp:
        key = args.repository / "Library/Homebrew/api/homebrew-1.pem"
        body = fetch("https://formulae.brew.sh/api/formula.jws.json", MAX_API, args.curl)
        formulae = jws_payload(body, key, Path(tmp))
        (root / "formula.jws.json").write_bytes(body)
        endpoint = f"packages.{args.api_tag}.jws.json"
        body = fetch(f"https://formulae.brew.sh/api/internal/{endpoint}", MAX_API, args.curl)
        packages = jws_payload(body, key, Path(tmp))
        if packages["metadata"]["bottle_tag"] != args.api_tag:
            raise ValueError("internal API platform mismatch")
        (root / endpoint).write_bytes(body)
        objects = {}
        for name in FORMULAE:
            if not any(f["name"] == name for f in formulae):
                raise ValueError("formula absent from signed public API")
            selected = packages["formulae"][name]
            checksum = selected["bottle_checksum"]
            if not re.fullmatch("[0-9a-f]{64}", checksum):
                raise ValueError("invalid signed bottle checksum")
            # Use the selected internal API: the two signed APIs can update independently.
            revision = selected.get("revision", 0)
            rebuild = selected.get("bottle_rebuild", 0)
            version = selected["stable_version"] + (f"_{revision}" if revision else "")
            reference = version + (f"-{rebuild}" if rebuild else "")
            if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", reference):
                raise ValueError("invalid bottle tag")
            index_path = f"/homebrew/v2/homebrew/core/{name}/manifests/{reference}"
            index = fetch("https://ghcr.io" + index_path.removeprefix("/homebrew"), MAX_INDEX, args.curl)
            descriptors = json.loads(index)["manifests"]
            if not any(d.get("annotations", {}).get("sh.brew.bottle.digest") == checksum for d in descriptors):
                raise ValueError("signed API/index bottle mismatch")
            blob_path = f"/homebrew/v2/homebrew/core/{name}/blobs/sha256:{checksum}"
            bottle = fetch("https://ghcr.io" + blob_path.removeprefix("/homebrew"), MAX_BOTTLE, args.curl)
            if digest(bottle) != checksum:
                raise ValueError("bottle checksum mismatch")
            for path, data, media in ((index_path, index, "application/vnd.oci.image.index.v1+json"),
                                      (blob_path, bottle, "application/octet-stream")):
                filename = digest(data)
                (root / filename).write_bytes(data)
                objects[path] = {"file": filename, "sha256": filename, "media_type": media}
            print(f"prepared {name} {reference} ({len(bottle)} bottle bytes)", flush=True)
        (root / "objects.json").write_text(json.dumps(objects, indent=2) + "\n")


def load_objects(root):
    records = json.loads(read_bounded(root / "objects.json", MAX_INDEX))
    objects = {}
    if not 1 <= len(records) <= 32:
        raise ValueError("invalid fixture object count")
    for path, record in records.items():
        if not re.fullmatch(r"/homebrew/v2/homebrew/core/(hello|zstd|lz4|xz)/(manifests/[A-Za-z0-9_.-]+|blobs/sha256:[0-9a-f]{64})", path):
            raise ValueError("fixture path outside the exact formula allowlist")
        if not re.fullmatch("[0-9a-f]{64}", record["file"]):
            raise ValueError("invalid fixture filename")
        data = read_bounded(root / record["file"], MAX_INDEX if "/manifests/" in path else MAX_BOTTLE)
        if digest(data) != record["sha256"]:
            raise ValueError("fixture object checksum mismatch")
        objects[path] = (data, record["media_type"])
    return objects


class Fixture(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, objects):
        self.objects = objects
        self.mode = "deny"
        self.phase = "startup"
        self.requests = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.respond(False)

    def do_GET(self):
        self.respond(True)

    def respond(self, send_body):
        server = self.server
        data, media = server.objects.get(self.path, (b"unsupported fixture object", "text/plain"))
        status = 200 if self.path in server.objects else 404
        if status == 200 and "/blobs/" in self.path and server.mode == "deny":
            status = 403
            media = "application/json"
            data = b'{"errors":[{"code":"DENIED","message":"bottle minimum age; eligible in 7 days"}]}'
        if status == 200 and server.mode in ("missing", "upstream-error"):
            status = 404 if server.mode == "missing" else 503
            data, media = b"upstream failure fixture", "text/plain"
        auth = self.headers.get("Authorization")
        with server.lock:
            server.requests.append({"phase": server.phase, "method": self.command,
                "path": self.path, "status": status, "headers": {
                    "accept": self.headers.get("Accept"), "range": self.headers.get("Range"),
                    "user-agent": self.headers.get("User-Agent"),
                    "authorization": "placeholder" if auth == "Bearer QQ==" else "other" if auth else None}})
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if send_body:
            self.wfile.write(data)


def copy_brew(repository, prefix):
    """Copy code and the current runtime; never symlink back into a live prefix."""
    source_library = repository / "Library"
    runtime = (source_library / "Homebrew/vendor/portable-ruby/current").resolve()
    runtime_root = source_library / "Homebrew/vendor/portable-ruby"
    if runtime.parent != runtime_root.resolve() or not runtime.is_dir():
        raise ValueError("provision Homebrew's portable Ruby before running this spike")

    def ignore(path, names):
        if Path(path) == runtime_root:
            return [n for n in names if n not in ("current", runtime.name)]
        return [n for n in names if n in (".git", "Taps", "__pycache__")]

    shutil.copytree(source_library, prefix / "Library", symlinks=True, ignore=ignore)
    (prefix / "bin").mkdir()
    shutil.copy2(repository / "bin/brew", prefix / "bin/brew")
    (prefix / "Cellar").mkdir()
    copied_library = prefix / "Library"
    for directory, dirs, files in os.walk(copied_library):
        for name in dirs + files:
            entry = Path(directory) / name
            if entry.is_symlink() and not entry.resolve().is_relative_to(copied_library.resolve()):
                raise ValueError("Homebrew library symlink escapes the isolated copy")
    # Record original git identity separately; copying a live .git can contain
    # absolute worktree paths. Commands use the original, unmodified code copy.


def run_spike(args):
    objects = load_objects(args.fixtures)
    args.output.mkdir(parents=True, exist_ok=True)
    source_version = subprocess.run(["git", "-C", str(args.repository), "describe", "--tags", "--abbrev=7"],
                                    capture_output=True, text=True).stdout.strip()
    original_version = "Homebrew " + (source_version or "unknown source version")
    commit = subprocess.run(["git", "-C", str(args.repository), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    report = {"client": original_version, "commit": commit, "platform": platform.platform(),
              "api_tag": args.api_tag, "scope": "isolated non-default prefix; four exact official formulae",
              "cases": [], "limitations": ["Curl guard is instrumentation, not an OS egress firewall.",
                  "Portable Ruby is pre-provisioned; bootstrap not tested.",
                  "Upgrade/rebuild and other client/platform versions still need disposable CI coverage."]}
    with tempfile.TemporaryDirectory(prefix="middles-homebrew-") as tmp:
        work = Path(tmp)
        prefix = work / "brew"
        copy_brew(args.repository, prefix)
        cache = work / "cache"
        (cache / "api/internal").mkdir(parents=True)
        with tempfile.TemporaryDirectory(prefix="middles-brew-verify-") as verify:
            for src, dst in (("formula.jws.json", cache / "api/formula.jws.json"),
                             (f"packages.{args.api_tag}.jws.json", cache / f"api/internal/packages.{args.api_tag}.jws.json")):
                body = read_bounded(args.fixtures / src, MAX_API)
                jws_payload(body, prefix / "Library/Homebrew/api/homebrew-1.pem", Path(verify))
                dst.write_bytes(body)
        server = Fixture(objects)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = {k: v for k, v in os.environ.items() if not k.startswith("HOMEBREW_")
                   and k.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "GH_TOKEN", "GITHUB_TOKEN"}}
            for name in ("home", "temp", "logs"):
                (work / name).mkdir()
            # Use a script path with no embedded shell arguments in CURL_PATH.
            import shlex
            wrapper = work / "curl-guard"
            egress = args.output / "egress.jsonl"
            egress.write_text("")
            guard_command = [sys.executable, str(SCRIPT), "--curl-guard",
                             f"127.0.0.1:{server.server_port}", str(egress), args.curl]
            wrapper.write_text("#!/bin/sh\nexec " + shlex.join(guard_command) + ' "$@"\n')
            wrapper.chmod(0o755)
            env.update(HOME=str(work / "home"), HOMEBREW_CACHE=str(cache), HOMEBREW_TEMP=str(work / "temp"),
                HOMEBREW_LOGS=str(work / "logs"), HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1",
                HOMEBREW_NO_INSTALL_CLEANUP="1", HOMEBREW_NO_ENV_HINTS="1", HOMEBREW_NO_COLOR="1",
                HOMEBREW_CURL_RETRIES="0", HOMEBREW_CURL_PATH=str(wrapper),
                HOMEBREW_API_AUTO_UPDATE_SECS="31536000", HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK="1",
                HOMEBREW_ARTIFACT_DOMAIN=f"http://127.0.0.1:{server.server_port}/homebrew",
                GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

            def case(name, mode, command, success):
                server.phase, server.mode = name, mode
                before = len(server.requests)
                before_egress = len(egress.read_text().splitlines())
                result = subprocess.run([str(prefix / "bin/brew"), *command], env=env,
                    capture_output=True, text=True, timeout=180)
                text = result.stdout + result.stderr
                # Temp paths and ports are noise in committed traces.
                for temp_path in sorted({str(work), str(work.resolve())}, key=len, reverse=True):
                    text = text.replace(temp_path, "<isolated>")
                text = text.replace(str(server.server_port), "<port>")
                (args.output / f"{name}.txt").write_text(text)
                attempts = [json.loads(line) for line in egress.read_text().splitlines()[before_egress:]]
                report["cases"].append({"name": name, "command": ["brew", *command],
                    "returncode": result.returncode, "expected_success": success,
                    "expectation_met": ((result.returncode == 0) == success
                        and "Invalid usage:" not in text and "Traceback (most recent call last)" not in text),
                    "requests": server.requests[before:], "rejected_egress": [a for a in attempts if not a["allowed"]],
                    "policy_body_displayed": "bottle minimum age" in text})
                print(f"{name}: exit {result.returncode}, {len(server.requests) - before} fixture requests", flush=True)

            case("blocked-install", "deny", ["install", "--force-bottle", "hello"], False)
            case("warm-metadata-cold-bottle", "deny", ["install", "--force-bottle", "hello"], False)
            case("eligible-install", "eligible", ["install", "--force-bottle", "hello"], True)
            case("fully-cached-fetch", "deny", ["fetch", "--force-bottle", "hello"], True)
            case("dependencies-install", "eligible", ["install", "--force-bottle", "zstd"], True)
            case("source-build", "deny", ["fetch", "--build-from-source", "hello"], False)
            case("unsupported-platform", "deny", ["fetch", "--force", "--bottle-tag=arm64_big_sur", "hello"], False)
            case("missing-bottle", "missing", ["fetch", "--force", "--force-bottle", "hello"], False)
            case("upstream-failure", "upstream-error", ["fetch", "--force", "--force-bottle", "hello"], False)
            case("versioned-formula", "deny", ["fetch", "--force-bottle", "openssl@3"], False)
            # Source requests must fail at the proxy under the proposed scoped
            # setup. An unprefixed destination is a failed gate, even though this
            # test's additional instrumentation prevents the transfer.
            leaks = [a for c in report["cases"] for a in c["rejected_egress"]]
            report["decision"] = "NO-GO" if leaks or any(not c["expectation_met"] for c in report["cases"]) else "INCOMPLETE"
            report["decision_reason"] = ("Unprefixed artifact destinations bypass the proposed proxy settings. "
                "The separate test curl guard, not Homebrew's no-fallback setting, rejected them. "
                "The unsupported-platform fetch also succeeded with a warning." if leaks and
                    any(c["name"] == "unsupported-platform" and c["returncode"] == 0 for c in report["cases"]) else
                "Unprefixed artifact destinations bypass the proposed proxy settings; the test curl guard rejected them." if leaks else
                "A client expectation failed; inspect case output." if any(not c["expectation_met"] for c in report["cases"]) else
                "Covered bottle cases passed, but remaining release-gate cases are not verified.")
            (args.output / "requests.jsonl").write_text("".join(json.dumps(r) + "\n" for r in server.requests))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["decision"] + ": " + report["decision_reason"])
    return 1  # This spike never declares production readiness from a partial matrix.


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--curl-guard":
        return guard(sys.argv[5:], *sys.argv[2:5])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True, help="existing Homebrew checkout; read-only")
    parser.add_argument("--api-tag", required=True, choices=("arm64_tahoe", "arm64_sequoia", "arm64_sonoma", "x86_64_linux", "arm64_linux"))
    parser.add_argument("--fixtures", type=Path, required=True, help="snapshot directory outside the Homebrew checkout")
    parser.add_argument("--output", type=Path, required=True, help="trace directory outside the Homebrew checkout")
    parser.add_argument("--prepare", action="store_true", help="opt in to public API/index/bottle downloads, then exit")
    parser.add_argument("--curl", default=shutil.which("curl"), help="real curl executable")
    args = parser.parse_args()
    args.repository, args.fixtures, args.output = (p.resolve() for p in (args.repository, args.fixtures, args.output))
    if not args.curl or not (args.repository / "bin/brew").is_file():
        parser.error("Homebrew and curl are required")
    if any(p == args.repository or args.repository in p.parents for p in (args.fixtures, args.output)):
        parser.error("fixtures/output must be outside the Homebrew installation")
    if args.fixtures == args.output or args.fixtures in args.output.parents or args.output in args.fixtures.parents:
        parser.error("fixtures and output must be separate directories")
    if args.prepare:
        prepare(args)
        return 0
    return run_spike(args)


if __name__ == "__main__":
    sys.exit(main())
