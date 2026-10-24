"""Same-machine contract tests for real loopback source binding; no Internet."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
import unittest
from unittest.mock import patch

from src.tools.loopback_rotation_lab import run_loopback_rotation_lab


class _LabFixture(BaseHTTPRequestHandler):
    peers = []

    def do_GET(self):
        self.peers.append((self.client_address[0], self.path, time.perf_counter()))
        status, body = 200, "local \u0111\u00fang".encode("utf-8")
        if self.path.startswith("/missing"):
            status, body = 404, b"missing"
        elif self.path.startswith("/rate"):
            status, body = 429, b"slow down"
        elif self.path.startswith("/blocked"):
            status, body = 403, b"forbidden"
        elif self.path.startswith("/redirect"):
            status, body = 302, b"redirect"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body) + (3 if self.path == "/short" else 0)))
        if status == 429:
            self.send_header("Retry-After", "1")
        if status == 302:
            self.send_header("Location", "https://cab.vn/do-not-follow")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class LoopbackLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _LabFixture)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        _LabFixture.peers.clear()

    def run_lab(self, words, **options):
        configured = {"rate_limit": 10, "lab_source_ips": ["127.0.0.1"]}
        configured.update(options)
        return run_loopback_rotation_lab(self.base, words, **configured)

    def test_actual_source_ips_are_observed_by_the_server(self):
        data = self.run_lab(["one", "two", "three"], lab_source_ips=["127.0.0.2", "127.0.0.3"])
        if data["errors"]:
            # Some Windows configurations do not bind unconfigured 127/8
            # aliases. Report that real failure instead of inventing rotation.
            self.assertEqual(data["stop_reason"], "transport_error")
            self.assertFalse(data["completed"])
            self.assertIsNone(data["results"][0]["status_code"])
            self.assertEqual(data["results"][0]["selected_source_ip"], "127.0.0.2")
            self.assertEqual(_LabFixture.peers, [])
            self.assertFalse(data["simulated"])
            return
        expected = ["127.0.0.2", "127.0.0.3", "127.0.0.2"]
        self.assertEqual([peer[0] for peer in _LabFixture.peers], expected)
        self.assertEqual([row["selected_source_ip"] for row in data["results"]], expected)
        self.assertEqual([row["bound_source_ip"] for row in data["results"]], expected)
        self.assertTrue(data["completed"])

    def test_real_status_and_bytes_not_header_or_character_count(self):
        data = self.run_lab(["ok", "missing"])
        self.assertEqual(data["engine"], "loopback_lab")
        self.assertFalse(data["simulated"])
        self.assertEqual([row["status_code"] for row in data["results"]], [200, 404])
        self.assertEqual([row["content_length"] for row in data["results"]], [len("local \u0111\u00fang".encode()), 7])
        self.assertEqual(data["stats"]["bytes_read"], len("local \u0111\u00fang".encode()) + 7)
        self.assertTrue(all(row["response_time"] > 0 for row in data["results"]))
        self.assertTrue(all(row["body_complete"] for row in data["results"]))
        self.assertEqual(data["errors"], [])

    def test_429_stops_globally_before_next_source_is_selected(self):
        data = self.run_lab(["rate", "ok"], lab_source_ips=["127.0.0.1", "127.0.0.2"])
        self.assertEqual(data["stop_reason"], "rate_limited_429")
        self.assertEqual([row[0] for row in _LabFixture.peers], ["127.0.0.1"])
        self.assertEqual(len(data["results"]), 1)
        self.assertEqual(data["results"][0]["headers"]["Retry-After"], "1")
        self.assertEqual(data["stats"]["remaining_requests"], 1)
        self.assertFalse(data["completed"])

    def test_three_403_stop_the_whole_lab(self):
        data = self.run_lab(["blocked/one", "blocked/two", "blocked/three", "ok"])
        self.assertEqual(data["stop_reason"], "consecutive_403")
        self.assertEqual(len(_LabFixture.peers), 3)

    def test_external_redirect_is_recorded_and_never_followed(self):
        data = self.run_lab(["redirect"])
        self.assertEqual(len(_LabFixture.peers), 1)
        self.assertEqual(data["results"][0]["status_code"], 302)
        self.assertEqual(data["results"][0]["redirect_url"], "https://cab.vn/do-not-follow")
        self.assertTrue(data["results"][0]["redirect_blocked"])

    def test_localhost_is_rewritten_before_connecting(self):
        original = socket.getaddrinfo
        destinations = []

        def numeric_only(host, *args, **kwargs):
            destinations.append(host)
            self.assertEqual(host, "127.0.0.1")
            return original(host, *args, **kwargs)

        with patch("socket.getaddrinfo", side_effect=numeric_only):
            data = run_loopback_rotation_lab(f"http://localhost:{self.server.server_port}", ["ok"],
                                             lab_source_ips=["127.0.0.1"])
        self.assertEqual(destinations, ["127.0.0.1"])
        self.assertEqual(data["results"][0]["status_code"], 200)
        self.assertTrue(data["results"][0]["url"].startswith(self.base))

    def test_default_four_requests_and_body_cap(self):
        data = self.run_lab(["one", "two", "three", "four", "five", "six"], max_response_bytes=3)
        self.assertEqual(len(_LabFixture.peers), 4)
        self.assertEqual(data["stop_reason"], "max_requests")
        self.assertTrue(all(row["content_length"] == 3 for row in data["results"]))
        self.assertTrue(all(row["body_truncated"] for row in data["results"]))
        self.assertTrue(data["stats"]["candidate_count_is_lower_bound"])

    def test_deadline_stops_before_sending_next_request(self):
        data = self.run_lab(["one", "two"], rate_limit=2, max_duration_seconds=0.1)
        self.assertEqual(data["stop_reason"], "max_duration")
        self.assertEqual(len(_LabFixture.peers), 1)

    def test_partial_body_is_counted_and_is_an_error(self):
        data = self.run_lab(["short", "later"])
        self.assertEqual(data["results"][0]["status_code"], 200)
        self.assertEqual(data["results"][0]["content_length"], len("local \u0111\u00fang".encode()))
        self.assertIn("IncompleteRead", data["results"][0]["error"])
        self.assertFalse(data["results"][0]["body_complete"])
        self.assertEqual(data["stop_reason"], "transport_error")
        self.assertEqual(len(_LabFixture.peers), 1)

    def test_connection_failure_has_no_fabricated_http_measurements(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]
        data = run_loopback_rotation_lab(f"http://127.0.0.1:{port}", ["ok", "later"],
                                         lab_source_ips=["127.0.0.1"], timeout_seconds=0.1)
        self.assertIsNone(data["results"][0]["status_code"])
        self.assertIsNone(data["results"][0]["content_length"])
        self.assertEqual(data["stats"]["network_errors"], 1)
        self.assertEqual(data["stop_reason"], "transport_error")


class LoopbackValidationTests(unittest.TestCase):
    def assert_rejected_without_connection(self, target="http://127.0.0.1:1", words=None, **options):
        with patch("src.tools.loopback_rotation_lab.HTTPConnection.connect") as connect:
            with patch("src.tools.loopback_rotation_lab.HTTPSConnection.connect") as tls_connect:
                with self.assertRaises(ValueError):
                    run_loopback_rotation_lab(target, ["ok"] if words is None else words, **options)
                connect.assert_not_called()
                tls_connect.assert_not_called()

    def test_remote_and_ambiguous_targets_are_rejected_before_http(self):
        for target in ("https://cab.vn/", "http://example.com/", "http://192.168.1.1/",
                       "http://10.0.0.1/", "http://8.8.8.8/", "http://0.0.0.0/",
                       "http://[::]/", "http://[2001:db8::1]/", "http://127.1/",
                       "http://2130706433/", "http://0177.0.0.1/", "http://localhost./",
                       "http://127.0.0.1.evil.test/", "http://127.0.0.1%00.example/",
                       "http://127.0.0.999/", "http://localhost@cab.vn/",
                       "http://user:pass@127.0.0.1/", "ftp://127.0.0.1/",
                       "http://127.0.0.1:0/", "http://127.0.0.1:70000/",
                       "http://[::1%25eth0]/", "http://127.0.0.1/#fragment"):
            with self.subTest(target=target):
                self.assert_rejected_without_connection(target=target)

    def test_remote_or_invalid_sources_are_rejected_before_http(self):
        for sources in (["8.8.8.8"], ["192.168.1.2"], ["localhost"], ["127.1"],
                        ["::1"], ["127.0.0.2", "10.0.0.1"], [], ["127.0.0.1"] * 9,
                        "127.0.0.2,127.0.0.3", ["::ffff:127.0.0.1"], ["127.0.0.999"]):
            with self.subTest(sources=sources):
                self.assert_rejected_without_connection(lab_source_ips=sources)

    def test_proxy_spoofing_and_guard_disabling_are_rejected(self):
        cases = [{"proxy": "http://127.0.0.1:8080"}, {"proxy_pool": ["http://proxy.invalid"]},
                 {"rotation_pool": ["one"]}, {"tor": True}, {"rotate_ip": True},
                 {"follow_redirects": True}, {"recursion": True}, {"threads": 2},
                 {"stop_on_block": False}, {"stop_on_429": False}, {"block_threshold": 4},
                 {"headers": {"Host": "cab.vn"}}, {"headers": {"X-Forwarded-For": "8.8.8.8"}},
                 {"headers": {"Forwarded": "for=8.8.8.8"}}, {"verify": False},
                 {"insecure": True}, {"max_requests": 101}, {"timeout_seconds": 11},
                 {"max_duration_seconds": 61}, {"rate_limit": 11}]
        for options in cases:
            with self.subTest(options=options):
                self.assert_rejected_without_connection(**options)

    def test_external_wordlist_urls_are_rejected_before_any_http(self):
        for word in ("https://cab.vn/", "//cab.vn/", "\\\\cab.vn", "bad\r\nHost: cab.vn"):
            with self.subTest(word=word):
                self.assert_rejected_without_connection(words=["would-be-local", word])


if __name__ == "__main__":
    unittest.main()
