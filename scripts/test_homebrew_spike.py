"""Deterministic checks for the compatibility fixture (no public network)."""
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("homebrew_spike", Path(__file__).with_name("homebrew-spike.py"))
spike = importlib.util.module_from_spec(spec)
spec.loader.exec_module(spike)


class FixtureTests(unittest.TestCase):
    def test_exact_objects_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"bottle"
            sha = spike.digest(data)
            (root / sha).write_bytes(data)
            path = f"/homebrew/v2/homebrew/core/hello/blobs/sha256:{sha}"
            record = {"file": sha, "sha256": sha, "media_type": "application/octet-stream"}
            (root / "objects.json").write_text(json.dumps({path: record}))
            self.assertEqual(spike.load_objects(root)[path][0], data)
            for invalid in ("/homebrew/https://example.org/file", "/homebrew/v2/other/core/hello/blobs/x",
                            "/homebrew/v2/homebrew/core/../blobs/x", path + "?token=secret"):
                (root / "objects.json").write_text(json.dumps({invalid: record}))
                with self.assertRaises(ValueError):
                    spike.load_objects(root)
            (root / "objects.json").write_text(json.dumps({path: record}))
            (root / sha).write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                spike.load_objects(root)
            record["file"] = "../escape"
            (root / "objects.json").write_text(json.dumps({path: record}))
            with self.assertRaisesRegex(ValueError, "filename"):
                spike.load_objects(root)

    def test_metadata_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large"
            path.write_bytes(b"12345")
            with self.assertRaisesRegex(ValueError, "too large"):
                spike.read_bounded(path, 4)

    def test_guard_rejects_nonfixture_and_redacts_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "egress"
            with patch("sys.stderr", io.StringIO()), patch.object(os, "execv") as execv:
                self.assertEqual(spike.guard(["https://user:secret@ghcr.io/v2/x?token=secret"],
                                             "127.0.0.1:1234", log, "/usr/bin/curl"), 7)
                execv.assert_not_called()
            self.assertNotIn("secret", log.read_text())
            self.assertNotIn("user", log.read_text())
            for url in ("http://127.0.0.1:1235/path", "http://localhost:1234/path",
                        "https://127.0.0.1:1234/path", "http://user:pass@127.0.0.1:1234/path"):
                with patch("sys.stderr", io.StringIO()), patch.object(os, "execv") as execv:
                    self.assertEqual(spike.guard([url], "127.0.0.1:1234", log, "/usr/bin/curl"), 7)
                    execv.assert_not_called()
            with patch.object(os, "execv") as execv:
                spike.guard(["http://127.0.0.1:1234/homebrew/v2/x"], "127.0.0.1:1234", log, "/usr/bin/curl")
                self.assertIn("--disable", execv.call_args.args[1])
                self.assertEqual(execv.call_args.args[1][-2:], ["--max-redirs", "0"])
            with patch.object(os, "execv") as execv:
                self.assertEqual(spike.guard(["--config", "/tmp/config"], "127.0.0.1:1234", log, "/usr/bin/curl"), 7)
                execv.assert_not_called()

    def test_jws_validation_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                            "-out", str(root / "private")], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(root / "private"), "-pubout", "-out", str(root / "public")],
                           check=True, capture_output=True)
            protected = base64.urlsafe_b64encode(b'{"alg":"PS512","b64":false,"crit":["b64"]}').decode().rstrip("=")
            payload = '{"formulae":{}}'
            (root / "input").write_text(protected + "." + payload)
            subprocess.run(["openssl", "dgst", "-sha512", "-sign", str(root / "private"),
                            "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:64",
                            "-out", str(root / "signed"), str(root / "input")], check=True, capture_output=True)
            signature = base64.urlsafe_b64encode((root / "signed").read_bytes()).decode().rstrip("=")
            jws = {"payload": payload, "signatures": [{"header": {"kid": "homebrew-1"},
                    "protected": protected, "signature": signature}]}
            self.assertEqual(spike.jws_payload(json.dumps(jws).encode(), root / "public", root), {"formulae": {}})
            jws["payload"] = '{"formulae":{"injected":{}}}'
            with self.assertRaisesRegex(ValueError, "invalid Homebrew signature"):
                spike.jws_payload(json.dumps(jws).encode(), root / "public", root)
            jws["signatures"][0]["header"]["kid"] = "unknown"
            with self.assertRaisesRegex(ValueError, "signature missing"):
                spike.jws_payload(json.dumps(jws).encode(), root / "public", root)

    def test_head_and_get_deny_identically_and_unknown_objects_fail(self):
        import threading
        from types import SimpleNamespace
        from unittest.mock import Mock
        path = "/homebrew/v2/homebrew/core/hello/blobs/sha256:" + "a" * 64
        server = SimpleNamespace(objects={path: (b"bottle", "application/octet-stream")},
                                 mode="deny", phase="test", requests=[], lock=threading.Lock())
        for method in ("GET", "HEAD"):
            handler = object.__new__(spike.Handler)
            handler.server, handler.path, handler.command = server, path, method
            handler.headers = {"Authorization": "private credential"}
            handler.wfile = io.BytesIO()
            handler.send_response = Mock()
            handler.send_header = Mock()
            handler.end_headers = Mock()
            handler.respond(method == "GET")
            handler.send_response.assert_called_once_with(403)
            self.assertNotEqual(handler.wfile.getvalue(), b"bottle")
            if method == "HEAD":
                self.assertEqual(handler.wfile.getvalue(), b"")
            else:
                self.assertIn(b"DENIED", handler.wfile.getvalue())
        self.assertNotIn("private credential", json.dumps(server.requests))
        handler.path = "/homebrew/https://example.com/unrestricted"
        handler.send_response.reset_mock()
        handler.respond(False)
        handler.send_response.assert_called_once_with(404)

    def test_copy_does_not_reuse_live_prefix_or_old_runtimes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "source"
            repository.joinpath("bin").mkdir(parents=True)
            repository.joinpath("bin/brew").write_text("brew")
            runtime = repository / "Library/Homebrew/vendor/portable-ruby"
            (runtime / "current-version").mkdir(parents=True)
            (runtime / "old-version").mkdir()
            (runtime / "current").symlink_to("current-version", target_is_directory=True)
            (repository / "Library/Taps").mkdir()
            prefix = root / "isolated"
            spike.copy_brew(repository, prefix)
            self.assertTrue((prefix / "Cellar").is_dir())
            self.assertFalse((prefix / "Library/Taps").exists())
            self.assertFalse((prefix / "Library/Homebrew/vendor/portable-ruby/old-version").exists())
            self.assertEqual((prefix / "Library/Homebrew/vendor/portable-ruby/current").resolve().parent,
                             (prefix / "Library/Homebrew/vendor/portable-ruby").resolve())
            self.assertFalse((repository / "Cellar").exists())


if __name__ == "__main__":
    unittest.main()
