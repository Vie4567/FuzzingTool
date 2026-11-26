"""Local HTTP contract tests: no external targets or LLM calls."""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
import unittest
from unittest.mock import patch

from src.tools.http_fuzzing import run_http_fuzzing
from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session


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
        elif self.path.startswith("/timeout"):
            time.sleep(0.15)
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body) + (5 if self.path == "/short" else 0)))
        if status == 302:
            self.send_header("Location", "http://example.invalid/should-not-be-requested")
        if status == 429:
            self.send_header("Retry-After", "1")
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

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

    def test_direct_engine_deduplicates_root_and_path_aliases(self):
        data = self.run_engine(["/", "/admin", "admin", "login", "/"], target=self.base + "/base")
        self.assertEqual([row["path"] for row in data["results"]], ["/base/", "/base/admin", "/base/login"])
        self.assertEqual(data["stats"]["planned_requests"], 3)
        self.assertEqual(data["stats"]["attempted_requests"], 3)
        self.assertEqual(data["stats"]["remaining_requests"], 0)
        self.assertEqual(len(_Fixture.calls), 3)
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

    def test_all_ten_timeouts_are_failed_measurements_not_completion(self):
        with telemetry_session() as telemetry:
            data = self.run_engine([f"timeout/{i}" for i in range(10)], timeout_seconds=0.03)
        self.assertFalse(data["completed"])
        self.assertFalse(data["success"])
        self.assertTrue(data["partial"])
        self.assertFalse(data["stopped_early"])
        self.assertEqual(data["stop_reason"], "transport_error")
        self.assertEqual(len(data["errors"]), 10)
        self.assertEqual(data["stats"]["attempted_requests"], 10)
        self.assertEqual(data["stats"]["responses_received"], 0)
        self.assertEqual(data["stats"]["network_errors"], 10)
        self.assertEqual(data["stats"]["remaining_requests"], 0)
        self.assertEqual(telemetry.snapshot()["http"]["known_requests"], 10)
        self.assertEqual(len(_Fixture.calls), 10)

    def test_eight_responses_and_two_timeouts_preserve_partial_data(self):
        data = self.run_engine([f"ok/{i}" for i in range(8)] + ["timeout/1", "timeout/2"],
                               timeout_seconds=0.03)
        self.assertFalse(data["completed"])
        self.assertTrue(data["partial"])
        self.assertEqual(data["stop_reason"], "partial_transport_error")
        self.assertEqual(data["stats"]["attempted_requests"], 10)
        self.assertEqual(data["stats"]["responses_received"], 8)
        self.assertEqual(data["stats"]["network_errors"], 2)
        self.assertEqual(len(data["results"]), 10)
        self.assertEqual(len(data["errors"]), 2)
        self.assertTrue(all(row["content_length"] is not None for row in data["results"][:8]))

    def test_ten_http_404_responses_are_transport_complete(self):
        data = self.run_engine([f"missing/{i}" for i in range(10)])
        self.assertTrue(data["completed"])
        self.assertTrue(data["success"])
        self.assertFalse(data["partial"])
        self.assertEqual(data["stats"]["responses_received"], 10)
        self.assertEqual(data["stats"]["network_errors"], 0)
        self.assertEqual(data["errors"], [])

    def test_shared_budget_rejection_does_not_create_phantom_request(self):
        with runtime_session({"http_rate_limit": 100, "http_max_requests": 2}) as budget, \
             telemetry_session() as telemetry:
            data = self.run_engine(["one", "two", "three"])
        self.assertEqual(data["stop_reason"], "http_request_budget")
        self.assertFalse(data["completed"])
        self.assertEqual(data["stats"]["attempted_requests"], 2)
        self.assertEqual(data["stats"]["remaining_requests"], 1)
        self.assertEqual(data["stats"]["network_errors"], 0)
        self.assertEqual(data["errors"], [])
        self.assertEqual(budget.requests, 2)
        self.assertEqual(telemetry.snapshot()["http"]["known_requests"], 2)
        self.assertEqual(len(_Fixture.calls), 2)

    def test_shared_rate_wait_respects_engine_deadline_before_dispatch(self):
        with runtime_session({"http_rate_limit": 1}), telemetry_session() as telemetry:
            data = self.run_engine(["one", "two"], max_duration_seconds=0.1)
        self.assertEqual(data["stop_reason"], "max_duration")
        self.assertEqual(data["stats"]["attempted_requests"], 1)
        self.assertEqual(data["stats"]["remaining_requests"], 1)
        self.assertEqual(telemetry.snapshot()["http"]["known_requests"], 1)
        self.assertEqual(data["errors"], [])

    def test_shared_pipeline_deadline_preserves_reason_and_dispatch_count(self):
        with runtime_session({"http_rate_limit": 1, "pipeline_timeout_seconds": 0.1}), \
             telemetry_session() as telemetry:
            data = self.run_engine(["one", "two"])
        self.assertEqual(data["stop_reason"], "pipeline_deadline")
        self.assertEqual(data["stats"]["attempted_requests"], 1)
        self.assertEqual(data["stats"]["remaining_requests"], 1)
        self.assertEqual(telemetry.snapshot()["http"]["known_requests"], 1)

    def test_transport_errors_do_not_override_request_cap(self):
        data = self.run_engine(["timeout/1", "timeout/2"], timeout_seconds=0.03, max_requests=1)
        self.assertEqual(data["stop_reason"], "max_requests")
        self.assertFalse(data["completed"])
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

    def test_wordlist_query_is_preserved_as_query(self):
        data = self.run_engine(['/api/search?page=1&sort=name'], target=self.base + '?lang=vi')
        self.assertEqual(_Fixture.calls[0][1], '/api/search?lang=vi&page=1&sort=name')
        self.assertEqual(data['results'][0]['path'], '/api/search')

    def test_rate_limit_applies_to_request_starts(self):
        # Measure where the client actually starts each HTTP request: the socket
        # connect after the rate-limit wait. Server handler arrival adds an
        # asymmetric first-request latency that is not part of the limiter.
        starts, connect = [], http.client.HTTPConnection.connect

        def timed_connect(conn):
            starts.append(time.perf_counter())
            return connect(conn)

        with patch.object(http.client.HTTPConnection, "connect", timed_connect):
            run_http_fuzzing(self.base, ["one", "two"], rate_limit=5)
        self.assertEqual([call[1] for call in _Fixture.calls], ["/one", "/two"])
        self.assertEqual(len(starts), 2)
        self.assertGreaterEqual(starts[1] - starts[0], 0.18)

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
