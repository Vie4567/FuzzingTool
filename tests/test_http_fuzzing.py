"""Local HTTP contract tests: no external targets or LLM calls."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
import unittest

from src.tools.http_fuzzing import run_http_fuzzing


class _Fixture(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.calls.append((self.command, self.path, None, time.perf_counter()))
        status = 200
        body = "đúng".encode("utf-8")
        if self.path.startswith("/missing"):
            status, body = 404, b"not found"
        elif self.path.startswith("/redirect"):
            status, body = 302, b"redirect"
        elif self.path.startswith("/rate"):
            status, body = 429, b"slow down"
        elif self.path.startswith("/blocked"):
            status, body = 403, b"forbidden"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body) + (5 if self.path == "/short" else 0)))
        if status == 302:
            self.send_header("Location", "http://example.invalid/should-not-be-requested")
        if status == 429:
            self.send_header("Retry-After", "1")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.calls.append((self.command, self.path, body, time.perf_counter()))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RealHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Fixture)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        _Fixture.calls.clear()

    def run_engine(self, words, target=None, **kwargs):
        return run_http_fuzzing(target or self.base, words, rate_limit=100, **kwargs)

    def test_real_body_byte_count_and_error_status(self):
        data = self.run_engine(["ok", "/missing"])
        self.assertFalse(data["simulated"])
        self.assertEqual([r["status_code"] for r in data["results"]], [200, 404])
        self.assertEqual([r["content_length"] for r in data["results"]], [len("đúng".encode()), 9])
        self.assertTrue(all(r["response_time"] > 0 for r in data["results"]))
        self.assertEqual(data["stats"]["status_codes"], {"200": 1, "404": 1})
        self.assertEqual(data["stats"]["successful_responses"], 2)
        self.assertEqual(data["errors"], [])

    def test_redirect_is_observed_without_following(self):
        data = self.run_engine(["redirect"])
        self.assertEqual(data["results"][0]["status_code"], 302)
        self.assertEqual(data["results"][0]["redirect_url"], "http://example.invalid/should-not-be-requested")
        self.assertEqual(len(_Fixture.calls), 1)

    def test_429_stops_immediately_with_retry_after(self):
        data = self.run_engine(["rate", "ok"])
        self.assertEqual(data["stop_reason"], "rate_limited_429")
        self.assertEqual(len(_Fixture.calls), 1)
        self.assertEqual(data["results"][0]["headers"]["Retry-After"], "1")
        self.assertEqual(data["stats"]["remaining_requests"], 1)

    def test_consecutive_403_stops(self):
        data = self.run_engine(["blocked/1", "blocked/2", "blocked/3", "ok"])
        self.assertEqual(data["stop_reason"], "consecutive_403")
        self.assertEqual(len(_Fixture.calls), 3)

    def test_explicit_bounded_retry_after_waits_before_next_candidate(self):
        data = self.run_engine(["rate", "ok"], respect_retry_after=True, stop_on_429=False)
        self.assertEqual(len(_Fixture.calls), 2)
        self.assertGreaterEqual(_Fixture.calls[1][3] - _Fixture.calls[0][3], 0.95)
        self.assertEqual(data["stats"]["status_codes"], {"429": 1, "200": 1})

    def test_retry_after_beyond_explicit_bound_still_stops(self):
        data = self.run_engine(["rate", "ok"], respect_retry_after=True,
                               stop_on_429=False, max_retry_after_seconds=0)
        self.assertEqual(data["stop_reason"], "rate_limited_429")
        self.assertEqual(len(_Fixture.calls), 1)

    def test_run_duration_stops_before_next_rate_limited_request(self):
        data = run_http_fuzzing(self.base, ["one", "two"], max_duration_seconds=0.1)
        self.assertEqual(data["stop_reason"], "max_duration")
        self.assertEqual(data["stats"]["total_requests"], 1)
        self.assertEqual(data["stats"]["remaining_requests"], 1)

    def test_no_synthetic_status_on_connection_error(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        data = self.run_engine(["ok"], target=f"http://127.0.0.1:{port}", timeout_seconds=0.1)
        self.assertIsNone(data["results"][0]["status_code"])
        self.assertIsNone(data["results"][0]["content_length"])
        self.assertIsNone(data["stats"]["avg_response_time"])
        self.assertEqual(data["stats"]["network_errors"], 1)

    def test_query_value_is_encoded_and_origin_is_fixed(self):
        data = self.run_engine(["one&two=3"], target=self.base + "/search?query=FUZZ")
        self.assertEqual(_Fixture.calls[0][1], "/search?query=one%26two%3D3")
        self.assertEqual(data["results"][0]["path"], "/search")

    def test_max_requests_reports_unattempted_candidates(self):
        data = self.run_engine(["one", "two", "three"], max_requests=1)
        self.assertEqual(len(_Fixture.calls), 1)
        self.assertEqual(data["stop_reason"], "max_requests")
        self.assertEqual(data["stats"]["planned_requests"], 3)
        self.assertEqual(data["stats"]["total_requests"], 1)
        self.assertEqual(data["stats"]["remaining_requests"], 2)

    def test_rate_limit_applies_to_request_starts(self):
        run_http_fuzzing(self.base, ["one", "two"], rate_limit=5)
        self.assertGreaterEqual(_Fixture.calls[1][3] - _Fixture.calls[0][3], 0.18)

    def test_body_cap_counts_only_observed_bytes(self):
        data = self.run_engine(["ok"], max_response_bytes=2)
        self.assertEqual(data["results"][0]["content_length"], 2)
        self.assertTrue(data["results"][0]["body_truncated"])
        self.assertFalse(data["results"][0]["body_complete"])

    def test_truncated_content_length_is_an_error_with_real_bytes(self):
        data = self.run_engine(["short"])
        self.assertEqual(data["results"][0]["status_code"], 200)
        self.assertEqual(data["results"][0]["content_length"], len("đúng".encode()))
        self.assertFalse(data["results"][0]["body_complete"])
        self.assertEqual(data["stats"]["network_errors"], 1)

    def test_post_method_and_actual_body(self):
        data = self.run_engine(["value"], target=self.base + "/FUZZ", http_method="POST", post_data="field=FUZZ")
        self.assertEqual(_Fixture.calls[0][:3], ("POST", "/value", b"field=value"))
        self.assertEqual(data["results"][0]["content_length"], 11)

    def test_scope_and_rotation_validation_precede_network(self):
        cases = [
            ({"target": self.base, "words": ["//example.invalid/other"]}, {}),
            ({"target": "http://FUZZ.example.invalid", "words": ["x"]}, {}),
            ({"target": self.base, "words": ["ok"]}, {"rotate_ip": True}),
            ({"target": self.base, "words": ["ok"]}, {"headers": {"X-Forwarded-For": "1.2.3.4"}}),
        ]
        for args, kwargs in cases:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    self.run_engine(args["words"], target=args["target"], **kwargs)
        self.assertEqual(_Fixture.calls, [])


if __name__ == "__main__":
    unittest.main()
