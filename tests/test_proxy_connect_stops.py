"""HTTPS CONNECT rejection stops verified with real loopback proxy sockets.

Only ProxyScrape discovery is mocked. The target records every accepted TCP
connection, so a hidden direct fallback cannot pass merely by failing TLS.
"""

import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socketserver
import threading
import unittest
from unittest.mock import patch

from src.tools.http_fuzzing import run_http_fuzzing


_FETCH = "src.tools.proxy_profiles.proxyscrape.fetch_candidates"
_USER = "connect_fixture_user"
_PASSWORD = "connect_fixture_password"
_TARGET_TOKEN = "Bearer connect_fixture_target_token"


class _UnreachableTarget(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.accepted.append(self.client_address)


class _RejectingConnectProxy(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        state = self.server.state
        state["calls"].append({"path": self.path, "headers": dict(self.headers)})
        if state.get("disconnect"):
            self.close_connection = True
            return
        status = state["status"]
        if state.get("oversized_header"):
            # A recognized security status must survive failure to parse the
            # remaining CONNECT headers. No body or arbitrary header is logged.
            raw = (f"HTTP/1.1 {status} Blocked\r\nX-Oversized: ".encode("ascii")
                   + b"x" * 70000 + b"\r\n\r\n")
            try:
                self.connection.sendall(raw)
            except OSError:
                pass
            self.close_connection = True
            return
        self.send_response(status, f"Rejected {_USER}:{_PASSWORD}")
        self.send_header("Retry-After", "19")
        self.send_header("Proxy-Authenticate", 'Basic realm="local-fixture"')
        self.send_header("Set-Cookie", "connect_fixture_response_cookie=private")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class ProxyConnectStopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _UnreachableTarget)
        cls.target.daemon_threads = True
        cls.target.accepted = []
        cls.origin = f"https://127.0.0.1:{cls.target.server_address[1]}"
        cls.proxies = [ThreadingHTTPServer(("127.0.0.1", 0), _RejectingConnectProxy)
                       for _ in range(2)]
        cls.workers = []
        for server in (cls.target, *cls.proxies):
            if server is not cls.target:
                server.state = {}
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.workers.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target, *cls.proxies):
            server.shutdown()
            server.server_close()
        for worker in cls.workers:
            worker.join(timeout=3)

    def configure(self, status):
        self.target.accepted.clear()
        for proxy in self.proxies:
            proxy.state.clear()
            proxy.state.update(calls=[], status=502)
        self.proxies[0].state["status"] = status
        self.proxy_urls = [f"http://127.0.0.1:{proxy.server_port}" for proxy in self.proxies]

    def run_engine(self, mode):
        options = {
            "engine": "proxy_http", "allowed_origins": [self.origin],
            "rate_limit": 10, "max_requests": 10, "timeout_seconds": 2,
            "max_scan_seconds": 10, "proxy_refresh_seconds": 0,
            "headers": {"Authorization": _TARGET_TOKEN},
        }
        if mode == "auto_health":
            options.update(proxy_source="proxyscrape", proxy_count=2)
        else:
            authenticated = self.proxy_urls[0].replace("http://", f"http://{_USER}:{_PASSWORD}@")
            options["proxy_profiles"] = [
                {"id": "first", "url": authenticated},
                {"id": "second", "url": self.proxy_urls[1]},
            ]
            if mode == "manual_health":
                options["proxy_healthcheck_url"] = self.origin + "/robots.txt"
        with patch(_FETCH, return_value=self.proxy_urls) as fetch, self.assertLogs(
            "sentinel.fuzzing.http", level="INFO"
        ) as logs:
            result = run_http_fuzzing(self.origin, ["one", "two"], **options)
        self.progress = "\n".join(logs.output)
        if mode == "auto_health":
            fetch.assert_called_once()
        else:
            fetch.assert_not_called()
        return result

    def assert_rejection(self, result, mode, status, *, oversized=False):
        expected_reason = {403: "proxy_connect_http_403", 429: "rate_limited_429",
                           407: "proxy_authentication_required"}[status]
        self.assertEqual([len(proxy.state["calls"]) for proxy in self.proxies], [1, 0])
        self.assertEqual(self.target.accepted, [])
        self.assertEqual(result["stop_reason"], expected_reason)
        self.assertFalse(result["completed"])
        self.assertFalse(result["simulated"])
        is_health = mode != "manual_fuzz"
        records = result["health_checks"] if is_health else result["results"]
        self.assertEqual(len(records), 1)
        if is_health:
            self.assertEqual(result["results"], [])
        record = records[0]
        self.assertEqual(record["proxy_connect_status"], status)
        self.assertIsNone(record["status_code"])
        self.assertIsNone(record["content_length"])
        self.assertEqual(record["headers"], {})
        self.assertFalse(record["body_complete"])
        self.assertGreater(record["response_time"], 0)
        if not oversized:
            self.assertEqual(record["proxy_connect_headers"], {"Retry-After": "19"})
        stats = result["stats"]
        self.assertEqual(stats["total_requests"], 1)
        self.assertEqual(stats["responses_received"], 0)
        self.assertEqual(stats["bytes_read"], 0)
        self.assertEqual(stats["status_codes"], {})
        self.assertEqual(stats["network_errors"], 0)
        self.assertEqual(stats["proxy_connect_errors"], 1)
        self.assertEqual(stats["proxy_connect_status_codes"], {str(status): 1})
        first_metrics = stats["proxy_profiles"][record["proxy_profile_id"]]
        self.assertEqual(first_metrics["network_errors"], 0)
        self.assertEqual(first_metrics["responses"], 0)
        self.assertEqual(first_metrics["proxy_connect_errors"], 1)
        self.assertEqual(first_metrics["proxy_connect_status_codes"], {str(status): 1})
        self.assertEqual(first_metrics["error_rate"], 1.0)
        self.assertIn(f"status=None connect_status={status}", self.progress)
        profiles = result["proxy_pool"]["profiles"]
        if is_health:
            self.assertEqual(profiles[0]["state"], "excluded" if status == 407 else "stopped")
            self.assertEqual(profiles[0]["reason"], expected_reason)
        connect_headers = {key.lower(): value for key, value in self.proxies[0].state["calls"][0]["headers"].items()}
        self.assertNotIn("authorization", connect_headers)
        if mode != "auto_health":
            expected_auth = "Basic " + base64.b64encode(f"{_USER}:{_PASSWORD}".encode()).decode()
            self.assertEqual(connect_headers["proxy-authorization"], expected_auth)
        public = json.dumps(result)
        for secret in (_USER, _PASSWORD, _TARGET_TOKEN, "connect_fixture_response_cookie"):
            self.assertNotIn(secret, public)
            self.assertNotIn(secret, self.progress)

    def test_manual_healthcheck_stops_on_connect_restrictions(self):
        for status in (403, 429, 407):
            with self.subTest(status=status):
                self.configure(status)
                self.assert_rejection(self.run_engine("manual_health"), "manual_health", status)

    def test_proxyscrape_healthcheck_stops_on_connect_restrictions(self):
        for status in (403, 429, 407):
            with self.subTest(status=status):
                self.configure(status)
                self.assert_rejection(self.run_engine("auto_health"), "auto_health", status)

    def test_fuzzing_stops_on_connect_restrictions_without_rotating(self):
        for status in (403, 429, 407):
            with self.subTest(status=status):
                self.configure(status)
                self.assert_rejection(self.run_engine("manual_fuzz"), "manual_fuzz", status)

    def test_known_connect_status_survives_oversized_response_header(self):
        for status in (403, 429, 407):
            with self.subTest(status=status):
                self.configure(status)
                self.proxies[0].state["oversized_header"] = True
                self.assert_rejection(self.run_engine("auto_health"), "auto_health", status,
                                      oversized=True)

    def test_disconnect_before_connect_status_remains_a_network_error(self):
        self.configure(403)
        self.proxies[0].state["disconnect"] = True
        self.proxies[1].state["status"] = 403
        result = self.run_engine("auto_health")
        self.assertEqual([len(proxy.state["calls"]) for proxy in self.proxies], [1, 1])
        self.assertEqual(self.target.accepted, [])
        self.assertEqual(result["stop_reason"], "proxy_connect_http_403")
        self.assertEqual(result["stats"]["network_errors"], 1)
        self.assertEqual(result["stats"]["responses_received"], 0)
        self.assertEqual(result["stats"]["total_requests"], 2)
        self.assertEqual(len(result["health_checks"]), 2)
        self.assertIsNone(result["health_checks"][0].get("proxy_connect_status"))
        self.assertTrue(result["health_checks"][0]["error"])
        self.assertEqual(result["health_checks"][1]["proxy_connect_status"], 403)
        self.assertEqual(result["proxy_pool"]["profiles"][0]["state"], "excluded")

    def test_other_connect_failure_can_advance_healthcheck_until_restriction(self):
        self.configure(502)
        self.proxies[1].state["status"] = 403
        result = self.run_engine("auto_health")
        self.assertEqual([len(proxy.state["calls"]) for proxy in self.proxies], [1, 1])
        self.assertEqual(self.target.accepted, [])
        self.assertEqual(result["stop_reason"], "proxy_connect_http_403")
        self.assertEqual(result["stats"]["network_errors"], 0)
        self.assertEqual(result["stats"]["responses_received"], 0)
        self.assertEqual(result["stats"]["proxy_connect_errors"], 2)
        self.assertEqual(result["stats"]["proxy_connect_status_codes"], {"502": 1, "403": 1})
        self.assertEqual(result["proxy_pool"]["profiles"][0]["reason"], "proxy_connect_error")


if __name__ == "__main__":
    unittest.main()
