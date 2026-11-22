"""One-shot diagnostics: real loopback HTTP, protected fixture and safe CLI."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from scripts import run_connection_diagnostic as runner


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append({"path": self.path, "auth": self.headers.get("Authorization"),
                                     "ua": self.headers.get("User-Agent"),
                                     "id": self.headers.get("X-FuzzingTool-Diagnostic-ID")})
        path = urlsplit(self.path).path
        if path == "/slow-headers":
            time.sleep(.4)
        if path == "/drip-headers":
            try:
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                for _ in range(300):
                    self.connection.sendall(b"x")
                    time.sleep(.02)
            except OSError:
                pass
            return
        status = int(path.rsplit("/", 1)[-1]) if path.startswith("/status/") else 200
        if path == "/redirect":
            status = 302
        body = json.dumps({"identity": "fixture-user-83271", "authenticated": True,
                           "echo": self.headers.get("Authorization", "private-response-fixture-831")}).encode()
        self.send_response(status, "private-reason-fixture-912")
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Private-Echo", self.headers.get("Authorization", "private-header-fixture-315"))
        self.send_header("Content-Length", str(len(body) + (100 if path == "/truncated" else 0)))
        if path == "/redirect":
            self.send_header("Location", "https://outside.invalid/no-follow")
        if path == "/retry-after":
            self.send_header("Retry-After", "120")
        self.end_headers()
        try:
            if path == "/slow-body":
                self.wfile.write(body[:5])
                self.wfile.flush()
                time.sleep(.4)
                self.wfile.write(body[5:])
            else:
                self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args):
        pass


def blocked_dns_worker(options, events):
    # Deterministic substitute for an OS resolver that cannot be interrupted.
    events.put(("progress", {"state": "running", "active_stage": "dns_resolution",
                              "diagnostic_id": options["trace_id"],
                              "stages": [{"name": "dns_resolution", "status": "running"}],
                              "http": {"attempted_requests": 0, "responses_received": 0},
                              "auth": {"assessment": "not_configured"}}))
    time.sleep(10)


class ConnectionDiagnosticRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.observed = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.server.observed.clear()
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def measure(self, path="/ok", **kwargs):
        return runner.core.diagnose_once(self.origin + path, allowed_origin=self.origin,
                                         **{"timeout_seconds": 2, **kwargs})

    def stage(self, result, name):
        return next(row for row in result["stages"] if row["name"] == name)

    def test_dry_run_has_no_dns_no_token_prompt_and_no_secret_url_output(self):
        with patch.object(runner.core.socket, "getaddrinfo", side_effect=AssertionError("No DNS")), \
             patch.object(runner, "_hidden", side_effect=AssertionError("No credentials")), \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = runner.main(["--url", "https://cab.vn/operator-path?secret=private-query-fixture",
                                "--allowed-origin", "https://cab.vn", "--check"])
        self.assertEqual(code, 0)
        data = json.loads(stdout.getvalue())
        self.assertEqual(data["network_attempts"], 0)
        self.assertNotIn("private-query-fixture", stdout.getvalue())
        self.assertNotIn("operator-path", stdout.getvalue())
        self.assertFalse(data["plan"]["auth_configured"])

    def test_success_is_one_get_fixed_ua_and_no_sensitive_content_or_proxy_env(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"}):
            result = self.measure("/ok?secret=private-query-fixture")
        self.assertEqual(result["state"], "completed", result)
        self.assertEqual(result["http"]["attempted_requests"], 1)
        self.assertEqual(result["http"]["responses_received"], 1)
        self.assertEqual(result["http"]["status_code"], 200)
        self.assertTrue(result["http"]["body_complete"])
        self.assertEqual(result["auth"]["assessment"], "not_configured")
        self.assertEqual(len(self.server.observed), 1)
        self.assertEqual(self.server.observed[0]["id"], result["diagnostic_id"])
        self.assertEqual(self.server.observed[0]["ua"], runner.core.DEFAULT_UA)
        for secret in ("private-query-fixture", "private-response-fixture-831", "fixture-user-83271",
                       "private-reason-fixture-912", "private-header-fixture-315"):
            self.assertNotIn(secret, json.dumps(result))

    def test_header_wait_and_body_wait_timeouts_are_distinguished(self):
        header = self.measure("/slow-headers", timeout_seconds=.1)
        self.assertEqual(self.stage(header, "response_headers")["status"], "failed")
        self.assertIsNone(header["http"]["status_code"])
        body = self.measure("/slow-body", timeout_seconds=.1)
        self.assertEqual(self.stage(body, "response_headers")["status"], "success")
        self.assertEqual(self.stage(body, "response_body")["status"], "failed")
        self.assertEqual(body["http"]["status_code"], 200)
        self.assertEqual(body["http"]["bytes_received"], 5)
        self.assertFalse(body["http"]["body_complete"])

    def test_truncated_and_capped_bodies_keep_observed_status(self):
        broken = self.measure("/truncated")
        self.assertEqual(broken["state"], "failed")
        self.assertEqual(self.stage(broken, "response_body")["error"]["kind"], "incomplete_body")
        limited = self.measure(max_response_bytes=16)
        self.assertEqual(limited["stop_reason"], "response_body_limit")
        self.assertEqual(limited["http"]["bytes_received"], 16)
        self.assertFalse(limited["http"]["body_complete"])
        self.assertEqual(limited["http"]["status_code"], 200)

    def test_401_403_429_redirect_retry_after_stop_without_followup_or_body(self):
        for path, reason in (("/status/401", "http_401"), ("/status/403", "http_403"),
                             ("/status/429", "http_429"), ("/redirect", "redirect_requires_review"),
                             ("/retry-after", "retry_after")):
            with self.subTest(path=path):
                self.server.observed.clear()
                result = self.measure(path)
                self.assertEqual(result["state"], "stopped")
                self.assertEqual(result["stop_reason"], reason)
                self.assertEqual(result["http"]["bytes_received"], 0)
                self.assertEqual(result["http"]["attempted_requests"], 1)
                self.assertEqual(len(self.server.observed), 1)

    def test_fake_bearer_200_requires_explicit_response_contract(self):
        token = "fake-bearer-diagnostic-921"
        options = {"bearer_token": token, "auth_origin": self.origin}
        unverified = self.measure(**options)
        self.assertEqual(unverified["auth"]["assessment"], "not_verified")
        matched = self.measure(**options, expected_json_pointer="/identity", expected_json_value="fixture-user-83271")
        self.assertEqual(matched["auth"]["assessment"], "expected_contract_matched")
        self.assertTrue(matched["auth"]["server_confirmation_required"])
        mismatch = self.measure(**options, expected_json_pointer="/identity", expected_json_value="different-fixture-user")
        self.assertEqual(mismatch["auth"]["assessment"], "expected_contract_not_matched")
        for result in (unverified, matched, mismatch):
            self.assertNotIn(token, json.dumps(result))
            self.assertNotIn("fixture-user-83271", json.dumps(result))

    def test_invalid_scope_credentials_and_limits_are_rejected_before_dns(self):
        cases = [{"url": "http://127.0.0.1:0/", "allowed_origin": "http://127.0.0.1:0"},
                 {"url": "https://outside.invalid/"}, {"url": self.origin + "/#fragment"},
                 {"url": self.origin + "/\r\nX: value"}, {"url": "http://user:password@127.0.0.1/"},
                 {"bearer_token": "fake", "auth_origin": "http://127.0.0.1:1"},
                 {"bearer_token": "fake"}, {"timeout_seconds": 9}, {"timeout_seconds": float("nan")},
                 {"max_response_bytes": 65537}, {"trace_id": "not-a-uuid"}]
        with patch.object(runner.core.socket, "getaddrinfo", side_effect=AssertionError("No DNS")):
            for change in cases:
                with self.subTest(keys=list(change)):
                    options = {"url": self.origin + "/ok", "allowed_origin": self.origin, **change}
                    with self.assertRaises(ValueError):
                        runner.core.diagnose_once(**options)

    def test_supervisor_persists_success_and_redacts_fake_bearer_from_all_artifacts(self):
        token = "fake-parent-diagnostic-bearer-731"
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = runner.run_diagnostic({"url": self.origin + "/ok?private-query-fixture=1",
                                           "allowed_origin": self.origin, "auth_origin": self.origin,
                                           "bearer_token": token, "timeout_seconds": 3}, self.directory)
        self.assertEqual(result["state"], "completed", result)
        self.assertTrue(result["counts_complete"])
        self.assertEqual(result["http"]["attempted_requests"], len(self.server.observed))
        saved = json.loads(Path(result["artifacts"]["result"]).read_text(encoding="utf-8"))
        self.assertEqual(saved, result)
        self.assertEqual(json.loads((Path(result["artifacts"]["directory"]) / "plan.json").read_text())["diagnostic_id"], result["diagnostic_id"])
        all_text = stdout.getvalue() + "".join(path.read_text(encoding="utf-8") for path in self.directory.rglob("*") if path.is_file())
        for secret in (token, "private-query-fixture", "fixture-user-83271", "private-reason-fixture-912"):
            self.assertNotIn(secret, all_text)

    def test_supervisor_bounds_blocked_dns_without_http_or_retry(self):
        with contextlib.redirect_stdout(io.StringIO()):
            start = time.monotonic()
            result = runner.run_diagnostic({"url": self.origin + "/ok", "allowed_origin": self.origin,
                                           "timeout_seconds": 1}, self.directory, _worker_target=blocked_dns_worker)
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(result["stop_reason"], "diagnostic_deadline")
        self.assertEqual(result["supervisor"]["last_observed_stage"], "dns_resolution")
        self.assertFalse(result["counts_complete"])
        self.assertEqual(result["http"]["attempted_requests"], 0)
        self.assertEqual(self.server.observed, [])

    def test_supervisor_bounds_trickling_headers_and_retains_last_observation(self):
        with contextlib.redirect_stdout(io.StringIO()):
            start = time.monotonic()
            result = runner.run_diagnostic({"url": self.origin + "/drip-headers", "allowed_origin": self.origin,
                                           "timeout_seconds": 1}, self.directory)
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(result["stop_reason"], "diagnostic_deadline", result)
        self.assertEqual(result["supervisor"]["last_observed_stage"], "response_headers")
        self.assertEqual(result["http"]["attempted_requests"], 1)
        self.assertEqual(result["http"]["responses_received"], 0)
        self.assertEqual(len(self.server.observed), 1)


if __name__ == "__main__":
    unittest.main()
