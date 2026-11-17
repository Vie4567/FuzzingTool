"""Soft404 evidence is measured through bounded, authenticated loopback HTTP."""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import threading
import time
import unittest
from urllib.parse import urlsplit

from src.tools.soft404 import verify_soft404


TOKEN = "soft404_fixture_token_74821"
COOKIE = "fixture_session=soft404_fixture_session_143"
CUSTOM = "soft404_fixture_custom_header_759"
HEADERS = {"Authorization": "Bearer " + TOKEN, "Cookie": COOKIE, "X-Fixture-Key": CUSTOM}


def sized_body(text, size=2219):
    body = text.encode("utf-8")
    if len(body) > size:
        raise ValueError("fixture exceeds expected size")
    return body + b" " * (size - len(body))


FALLBACK = sized_body("<html><head><title>Fixture application</title></head>"
                      "<body><main>Application shell for fixture navigation</main></body></html>")
DISTINCT = sized_body("<html><head><title>Weather station records</title></head><body>"
                      "<article><h1>Ocean measurements</h1><p>Temperature salinity tides "
                      "buoy observations marine forecast and historical rainfall.</p>"
                      "<table><tr><td>station alpha</td><td>27 degrees</td></tr></table>"
                      "</article></body></html>")


class _Server(ThreadingHTTPServer):
    daemon_threads = True


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        server = self.server
        server.observed.append({"path": self.path, "method": self.command,
                                "headers": {name.lower(): value for name, value in self.headers.items()},
                                "at": time.monotonic()})
        index = len(server.observed)
        path = urlsplit(self.path).path
        status, media, body, extra = 200, "text/html", FALLBACK, {}
        required = server.required_headers
        if required and any(self.headers.get(name) != value for name, value in required.items()):
            status, body = 401, b"authentication required"
        elif path in server.responses:
            status, media, body, extra = server.responses[path]
        elif server.mode == "hard404":
            status, body = 404, ("<html><body>Not found: " + self.path + "</body></html>").encode()
        elif server.mode == "dynamic":
            body = (f'<html><head><meta name="csrf-token" content="{index:032x}"></head>'
                    f'<body><main>Missing route {self.path}</main>'
                    f'<time>2026-10-29T10:00:{index % 60:02d}Z</time>'
                    f'<script nonce="{index:032x}">renderApp()</script></body></html>').encode()
        elif server.mode == "unstable":
            status = 200 if index % 2 else 404
            body = ("<html><body><main>Changing fixture response " + str(index) + "</main></body></html>").encode()
        elif server.mode == "block":
            status, body = server.block_status, b"restricted fixture response"
        elif server.mode == "retry_after":
            extra = {"Retry-After": "120"}
        elif server.mode == "oversized":
            body = b"<html><body>" + b"x" * 8192 + b"</body></html>"
        elif server.mode == "empty":
            body = b""
        elif server.mode == "timeout":
            time.sleep(0.15)
        elif server.mode == "query_context":
            body = DISTINCT if "mode=two" in self.path else FALLBACK
        elif server.mode == "business_uuid":
            media = "application/json"
            identifier = "ed8c1d6a-1abc-4bcd-8efd-123456789abc" if path == "/candidate" else "c6a423fa-9def-4bcd-8efd-987654321abc"
            body = json.dumps({"id": identifier}).encode()
        elif server.mode == "path_prefix":
            body = ("<html><body><p>" + " /api/records " * 100 + "</p></body></html>").encode()
        elif server.mode == "large_middle":
            prefix = b"<html><body>" + b"Common prefix text. " * 900
            suffix = b" Common footer text." * 900 + b"</body></html>"
            middle = b"VALID ACCOUNT DETAILS" if path == "/candidate" else b"FALLBACK ROUTE NOTICE"
            body = prefix + middle + suffix
        elif server.mode == "slow_trickle":
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            for _ in range(100):
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.01)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    break
            return
        elif server.mode == "redirect":
            status, extra = 302, {"Location": server.other_origin + "/credential-capture"}
        elif server.mode == "login":
            body = b'<html><body><form action="/login"><input name="user"><input type="password" name="password"></form></body></html>'
        elif server.mode == "challenge":
            body = b"<html><title>Just a moment...</title><body>Verify you are human. Checking your browser before accessing the site.</body></html>"
        elif server.mode == "encoded":
            extra = {"Content-Encoding": "gzip"}
            body = b"not-a-valid-gzip-body"
        self.send_response(status)
        self.send_header("Content-Type", media + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra.items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def log_message(self, *args):
        pass


class Soft404ComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.primary = _Server(("127.0.0.1", 0), _Handler)
        cls.secondary = _Server(("127.0.0.1", 0), _Handler)
        cls.tls = _Server(("127.0.0.1", 0), _Handler)
        fixtures = Path(__file__).parent / "fixtures"
        cls.certificate = fixtures / "proxy_lab_cert.pem"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.certificate, fixtures / "proxy_lab_key.pem")
        cls.tls.socket = context.wrap_socket(cls.tls.socket, server_side=True)
        cls.origin = f"http://127.0.0.1:{cls.primary.server_port}"
        cls.other_origin = f"http://127.0.0.1:{cls.secondary.server_port}"
        cls.tls_origin = f"https://127.0.0.1:{cls.tls.server_port}"
        cls.servers = (cls.primary, cls.secondary, cls.tls)
        cls.threads = []
        for server in cls.servers:
            server.other_origin = cls.other_origin
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=2)

    def setUp(self):
        for server in self.servers:
            server.observed = []
            server.responses = {}
            server.mode = "fallback"
            server.required_headers = None
            server.block_status = 403

    def record(self, path="/candidate", *, origin=None, **changes):
        return {"url": (origin or self.origin) + path, "path": path, "status_code": 200,
                "content_length": 2219, "response_time": 0.123456,
                "body_complete": True, **changes}

    def verify(self, records=None, **options):
        defaults = {"rate_limit": 100, "timeout_seconds": 1, "max_duration_seconds": 10}
        defaults.update(options)
        return verify_soft404(self.origin, [self.record()] if records is None else records, **defaults)

    def all_rows(self, result):
        return result["verified"] + result["false_positives"] + result["unverified"]

    def test_18_equal_2219_byte_fallbacks_are_filtered_using_real_controls(self):
        records = [self.record(f"/candidate-{index}") for index in range(18)]
        result = self.verify(records)
        self.assertEqual(len(result["false_positives"]), 18)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["unverified"], [])
        self.assertTrue(all(row["verification"] == "soft_404" for row in result["false_positives"]))
        self.assertTrue(result["verification_performed"])
        self.assertEqual(result["verification_status"], "completed")
        candidates = {row["path"] for row in records}
        controls = [row for row in self.primary.observed if row["path"] not in candidates]
        self.assertGreaterEqual(len(controls), 2)
        self.assertEqual(len({row["path"] for row in controls}), len(controls))
        self.assertEqual(result["stats"]["total_requests"], len(self.primary.observed))

    def test_equal_length_distinct_content_is_not_soft404(self):
        self.assertEqual(len(FALLBACK), len(DISTINCT))
        self.primary.responses["/weather"] = (200, "text/html", DISTINCT, {})
        result = self.verify([self.record("/weather")])
        self.assertEqual(result["false_positives"], [])
        self.assertEqual(len(result["verified"]), 1)
        self.assertEqual(result["verified"][0]["verification"], "genuine")

    def test_homepage_matching_app_shell_is_not_discarded_as_missing_endpoint(self):
        result = self.verify([self.record("/")])
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["false_positives"], [])
        self.assertEqual(len(result["unverified"]), 1)

    def test_ordinary_404_controls_allow_distinct_valid_endpoint(self):
        self.primary.mode = "hard404"
        self.primary.responses["/weather"] = (200, "text/html", DISTINCT, {})
        result = self.verify([self.record("/weather")])
        self.assertEqual(len(result["verified"]), 1)
        self.assertEqual(result["false_positives"], [])

    def test_candidate_that_now_returns_real_404_is_filtered_without_rewriting_old_status(self):
        self.primary.mode = "hard404"
        record = self.record("/vanished")
        result = self.verify([record])
        self.assertEqual(len(result["false_positives"]), 1)
        self.assertEqual(result["false_positives"][0]["verification"], "http_404")
        self.assertEqual(result["false_positives"][0]["status_code"], 200)

    def test_path_timestamp_and_nonce_reflections_do_not_hide_same_fallback(self):
        self.primary.mode = "dynamic"
        result = self.verify()
        self.assertEqual(len(result["false_positives"]), 1)
        self.assertEqual(result["false_positives"][0]["verification"], "soft_404")

    def test_unstable_controls_leave_candidate_unverified(self):
        self.primary.mode = "unstable"
        self.primary.responses["/candidate"] = (200, "text/html", DISTINCT, {})
        result = self.verify()
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["false_positives"], [])
        self.assertEqual(len(result["unverified"]), 1)

    def test_login_challenge_redirect_and_empty_response_are_not_valid_endpoints(self):
        for mode in ("login", "challenge", "redirect", "empty", "encoded"):
            with self.subTest(mode=mode):
                self.setUp()
                self.primary.mode = mode
                result = self.verify()
                self.assertEqual(result["verified"], [])
                self.assertEqual(result["false_positives"], [])
                self.assertEqual(len(result["unverified"]), 1)
                self.assertEqual(self.secondary.observed, [])
                if mode in {"login", "challenge"}:
                    self.assertEqual(len(self.primary.observed), 1)

    def test_large_pages_with_different_middles_are_not_classified_from_matching_ends(self):
        self.primary.mode = "large_middle"
        result = self.verify()
        self.assertEqual(result["false_positives"], [])
        self.assertEqual(result["verified"], [])
        self.assertEqual(len(result["unverified"]), 1)

    def test_business_identifiers_are_not_erased_as_volatile_trace_ids(self):
        self.primary.mode = "business_uuid"
        result = self.verify()
        self.assertEqual(result["false_positives"], [])

    def test_short_candidate_path_does_not_rewrite_unrelated_prefixes_in_body(self):
        self.primary.mode = "path_prefix"
        result = self.verify([self.record("/a")])
        self.assertEqual(result["verified"], [])
        self.assertEqual(len(result["false_positives"]), 1)

    def test_baselines_are_not_reused_across_different_query_values(self):
        self.primary.mode = "query_context"
        result = self.verify([self.record("/first?mode=one"), self.record("/second?mode=two")])
        self.assertEqual(len(result["baseline"]["groups"]), 2)
        self.assertEqual(len(result["false_positives"]), 2)
        self.assertEqual(result["verified"], [])

    def test_slow_trickle_body_cannot_extend_duration_to_full_response(self):
        self.primary.mode = "slow_trickle"
        start = time.perf_counter()
        result = self.verify(max_duration_seconds=0.08, timeout_seconds=0.08)
        self.assertLess(time.perf_counter() - start, 0.6)
        self.assertEqual(len(self.primary.observed), 1)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["stop_reason"], "max_duration")

    def test_block_or_rate_limit_stops_before_another_request(self):
        for status in (401, 403, 407, 429):
            with self.subTest(status=status):
                self.setUp()
                self.primary.mode = "block"
                self.primary.block_status = status
                result = self.verify([self.record("/first"), self.record("/second")])
                self.assertEqual(result["verified"], [])
                self.assertEqual(len(result["unverified"]), 2)
                self.assertEqual(len(self.primary.observed), 1)
                self.assertEqual(result["stats"]["total_requests"], 1)

    def test_retry_after_stops_even_on_http200(self):
        self.primary.mode = "retry_after"
        result = self.verify()
        self.assertEqual(result["verified"], [])
        self.assertEqual(len(self.primary.observed), 1)

    def test_candidate_block_stops_later_candidates(self):
        self.primary.responses["/first"] = (429, "text/plain", b"slow down", {})
        result = self.verify([self.record("/first"), self.record("/second")])
        self.assertEqual(result["verified"], [])
        self.assertEqual(len(result["unverified"]), 2)
        self.assertNotIn("/second", [request["path"] for request in self.primary.observed])

    def test_disabled_and_previous_stop_do_not_start_network(self):
        for options in ({"enabled": False}, {"stop_reason": "proxy_connect_http_403"},
                        {"stop_reason": "rate_limited_429"}, {"stop_reason": "max_requests"}):
            with self.subTest(options=options):
                result = self.verify(**options)
                self.assertFalse(result["verification_performed"])
                self.assertEqual(result["verified"], [])
                self.assertEqual(len(result["unverified"]), 1)
                self.assertEqual(self.primary.observed, [])

    def test_previous_block_measurements_prevent_new_verification_traffic(self):
        for changes in ({"status_code": 401}, {"status_code": 403}, {"status_code": 407},
                        {"status_code": 429}, {"headers": {"Retry-After": "60"}}):
            with self.subTest(changes=changes):
                records = [self.record("/already-blocked", **changes), self.record("/candidate")]
                result = self.verify(records)
                self.assertEqual(result["verified"], [])
                self.assertEqual(len(result["unverified"]), 2)
                self.assertEqual(self.primary.observed, [])

    def test_request_budget_cannot_be_exceeded_and_incomplete_evidence_is_unverified(self):
        result = self.verify(max_requests=2)
        self.assertEqual(len(self.primary.observed), 2)
        self.assertEqual(result["stats"]["total_requests"], 2)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["false_positives"], [])
        self.assertEqual(len(result["unverified"]), 1)

    def test_deadline_limits_pacing_wait(self):
        started = time.monotonic()
        result = self.verify(rate_limit=1, max_duration_seconds=0.05)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.8)
        self.assertLessEqual(len(self.primary.observed), 1)
        self.assertEqual(result["verified"], [])

    def test_timeout_stops_without_request_retry(self):
        self.primary.mode = "timeout"
        result = self.verify(timeout_seconds=0.03)
        self.assertEqual(len(self.primary.observed), 1)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["false_positives"], [])

    def test_truncated_body_is_never_compared_as_complete(self):
        self.primary.mode = "oversized"
        result = self.verify(max_response_bytes=128)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["false_positives"], [])
        self.assertEqual(len(result["unverified"]), 1)

    def test_headers_match_between_controls_and_candidate_without_leaking_output(self):
        self.primary.required_headers = dict(HEADERS)
        result = self.verify(headers=dict(HEADERS))
        self.assertEqual(len(result["false_positives"]), 1)
        for request in self.primary.observed:
            for key, value in HEADERS.items():
                self.assertEqual(request["headers"].get(key.lower()), value)
        serialized = json.dumps(result)
        for secret in (TOKEN, COOKIE, CUSTOM, FALLBACK.decode().strip()):
            self.assertNotIn(secret, serialized)

    def test_outside_origin_is_not_requested_and_has_no_valid_classification(self):
        record = self.record(origin=self.other_origin)
        result = self.verify([record], headers=dict(HEADERS))
        self.assertEqual(result["verified"], [])
        self.assertEqual(len(result["unverified"]), 1)
        self.assertEqual(self.primary.observed, [])
        self.assertEqual(self.secondary.observed, [])

    def test_explicit_network_scope_does_not_grant_secondary_credentials(self):
        result = self.verify([self.record(origin=self.other_origin)], headers=dict(HEADERS),
                             allowed_origins=[self.origin, self.other_origin])
        self.assertTrue(self.secondary.observed)
        for request in self.secondary.observed:
            for key in HEADERS:
                self.assertNotIn(key.lower(), request["headers"])
        self.assertEqual(self.primary.observed, [])
        self.assertEqual(len(result["false_positives"]), 1)

    def test_untrusted_tls_fails_before_authenticated_http(self):
        result = verify_soft404(self.tls_origin, [self.record(origin=self.tls_origin)],
                                headers=dict(HEADERS), rate_limit=100, timeout_seconds=1)
        self.assertEqual(self.tls.observed, [])
        self.assertEqual(result["verified"], [])
        self.assertEqual(len(result["unverified"]), 1)

    def test_private_ca_keeps_tls_verified_and_passes_auth(self):
        self.tls.required_headers = dict(HEADERS)
        result = verify_soft404(self.tls_origin, [self.record(origin=self.tls_origin)],
                                headers=dict(HEADERS), tls_ca_file=str(self.certificate), rate_limit=100)
        self.assertEqual(len(result["false_positives"]), 1)
        for request in self.tls.observed:
            self.assertEqual(request["headers"]["authorization"], "Bearer " + TOKEN)
        with self.assertRaises(ValueError):
            verify_soft404(self.tls_origin, [self.record(origin=self.tls_origin)], verify_ssl=False)

    def test_unmeasured_or_unsafe_records_are_not_replayed(self):
        records = [
            self.record("/post", method="POST"),
            self.record("/delete", http_method="DELETE"),
            self.record("/fake", simulated=True),
            self.record("/params", result_kind="parameter_candidates"),
            self.record("/incomplete", body_complete=False),
            self.record("/truncated", body_truncated=True),
            self.record("/failed", error="fixture timeout"),
            self.record("/unknown", status_code=None),
            self.record("/get-with-body", request_body="do-not-replay"),
        ]
        for record in records:
            with self.subTest(path=record["path"]):
                result = self.verify([record])
                self.assertEqual(self.primary.observed, [])
                self.assertEqual(result["verified"], [])
                self.assertEqual(len(result["unverified"]), 1)

    def test_original_measurements_and_input_are_preserved_and_stale_labels_removed(self):
        records = [self.record(verification="genuine", verification_performed=True,
                               similarity_to_baseline=0.01,
                               verification_evidence={"old": "untrusted old conclusion"})]
        original = deepcopy(records)
        result = self.verify(records)
        self.assertEqual(records, original)
        row = self.all_rows(result)[0]
        for field in ("status_code", "content_length", "response_time"):
            self.assertEqual(row[field], original[0][field])
            self.assertIs(type(row[field]), type(original[0][field]))
        self.assertEqual(row["verification"], "soft_404")
        self.assertNotIn("untrusted old conclusion", json.dumps(row))
        row["content_length"] = 999
        self.assertEqual(records, original)


if __name__ == "__main__":
    unittest.main()
