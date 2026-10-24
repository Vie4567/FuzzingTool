"""The lab engine is explicit, local-only, and records real socket peer IPs."""

import logging
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

logging.getLogger("sentinel").addHandler(logging.NullHandler())

from src.agents.fuzzer import FuzzingAgent
from src.tools.ffuf_helper import FfufToolHelper


class LabHandler(BaseHTTPRequestHandler):
    observed = []
    blocked = False

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).observed.append((self.client_address[0], self.path))
        body = self.client_address[0].encode("ascii")
        self.send_response(429 if type(self).blocked else 200)
        if type(self).blocked:
            self.send_header("Retry-After", "60")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LoopbackLabIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.target = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)

    def setUp(self):
        LabHandler.observed.clear()
        LabHandler.blocked = False

    def test_agent_rotates_actual_loopback_source_addresses(self):
        result = FuzzingAgent(llm=None).execute(
            self.target, ["/one", "/two", "/three"], use_pattern_engine=False,
            engine="loopback_lab", lab_source_ips=["127.0.0.2", "127.0.0.3"],
            max_requests=3, rate_limit=2, delay_ms=0,
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(result["engine"], "loopback_lab")
        self.assertFalse(result["simulated"])
        actual_peers = [ip for ip, path in LabHandler.observed]
        self.assertEqual(actual_peers, ["127.0.0.2", "127.0.0.3", "127.0.0.2"])
        self.assertEqual([row["bound_source_ip"] for row in result["results"]], actual_peers)
        self.assertEqual(result["stats"]["total_requests"], 3)
        for row, actual_ip in zip(result["results"], actual_peers):
            self.assertEqual(row["status_code"], 200)
            self.assertEqual(row["content_length"], len(actual_ip.encode("ascii")))

    def test_block_stops_before_using_next_source_ip(self):
        LabHandler.blocked = True
        result = FfufToolHelper().run(
            target_url=self.target, wordlist=["one", "two", "three"],
            engine="loopback_lab", lab_source_ips=["127.0.0.2", "127.0.0.3"],
            max_requests=3, rate_limit=2,
        )
        self.assertFalse(result.success)
        self.assertTrue(result.result_data["partial"])
        self.assertEqual(len(LabHandler.observed), 1)
        self.assertEqual(LabHandler.observed[0][0], "127.0.0.2")
        self.assertEqual(result.result_data["results"][0]["status_code"], 429)

    def test_public_target_is_rejected_before_connecting(self):
        with patch("http.client.HTTPConnection.connect", side_effect=AssertionError("No external network")) as connect:
            result = FfufToolHelper().run(
                target_url="https://cab.vn/", wordlist=["one"],
                engine="loopback_lab", lab_source_ips=["127.0.0.2", "127.0.0.3"],
            )
        connect.assert_not_called()
        self.assertFalse(result.success)
        self.assertEqual(result.result_data["results"], [])
        self.assertIn("loopback", result.error_message.lower())

    def test_lab_sources_require_explicit_lab_engine(self):
        helper = FfufToolHelper()
        with patch.object(helper, "resolve_binary", side_effect=AssertionError("Must reject before selecting transport")):
            for engine in ("auto", "ffuf_cli", "python_http"):
                with self.subTest(engine=engine):
                    result = helper.run(target_url=self.target, wordlist=["one"],
                                        engine=engine, lab_source_ips=["127.0.0.2"])
                    self.assertFalse(result.success)
                    self.assertIn("requires engine=loopback_lab", result.error_message)
        self.assertEqual(LabHandler.observed, [])

    def test_explicit_oversized_budget_is_rejected_by_agent(self):
        result = FuzzingAgent(llm=None).execute(
            self.target, ["one"], use_pattern_engine=False,
            engine="loopback_lab", max_scan_seconds=120,
        )
        self.assertFalse(result["success"])
        self.assertEqual(result["results"], [])
        self.assertEqual(LabHandler.observed, [])


if __name__ == "__main__":
    unittest.main()
