"""Measured timing changes on one loopback origin, without a live provider.

An earlier root 200 is not proof that the same root can respond within the
timeout later. This fixture demonstrates that distinction, not cab.vn's cause.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest

from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.tools.ffuf_helper import FfufToolHelper
from src.tools.recon_http import DEFAULT_UA, ScopedReconTransport


class TimingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append({
            "path": self.path, "method": self.command,
            "authorization": self.headers.get("Authorization"),
            "user_agent": self.headers.get("User-Agent"),
            "content_length": self.headers.get("Content-Length"),
            "connection": self.headers.get("Connection"),
        })
        if self.server.delay_responses:
            time.sleep(.4)
        body = b"root response from the local fixture"
        try:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            # Timed-out clients have closed the socket before this late reply.
            pass

    def log_message(self, *args):
        pass


class TransportTimingParityTests(unittest.TestCase):
    def test_earlier_recon_root_200_does_not_preclude_later_timeouts_in_both_transports(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), TimingHandler)
        server.observed = []
        server.delay_responses = False
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        headers = {"Authorization": "Bearer transport_timing_fixture_only_78142"}
        try:
            transport = ScopedReconTransport(origin, headers=headers,
                                              allowed_origins=[origin], auth_origins=[origin])
            config = {"http_max_requests": 3, "http_rate_limit": 20,
                      "http_timeout_seconds": .1, "pipeline_timeout_seconds": 5}
            with runtime_session(config) as budget, telemetry_session(max_llm_calls=0) as telemetry:
                first = transport.fetch_result(origin + "/", timeout=.1)
                self.assertEqual(first["status_code"], 200)
                self.assertTrue(first["body_complete"])
                self.assertEqual(first["bytes_received"], len(b"root response from the local fixture"))
                server.delay_responses = True
                late_recon = transport.fetch_result(origin + "/", timeout=.1)
                fuzz = FfufToolHelper().run(
                    target_url=origin, wordlist=["/"], engine="python_http",
                    headers=headers, http_method="GET", rate_limit=20,
                    timeout_seconds=.1, max_requests=1, max_scan_seconds=3,
                ).result_data
                self.assertIsNone(late_recon["status_code"])
                self.assertEqual(late_recon["error"]["error_type"], "transport_error")
                self.assertIn("timed out", late_recon["error"]["message"])
                self.assertEqual(fuzz["stats"]["attempted_requests"], 1)
                self.assertEqual(fuzz["stats"]["responses_received"], 0)
                self.assertEqual(fuzz["stats"]["network_errors"], 1)
                self.assertIsNone(fuzz["results"][0]["status_code"])
                self.assertEqual(fuzz["stop_reason"], "transport_error")
                self.assertFalse(fuzz["completed"])
                self.assertEqual(budget.requests, 3)
                self.assertEqual(telemetry.snapshot()["http"]["total_requests"], 3)
                self.assertEqual(telemetry.snapshot()["llm"]["attempted"], 0)
            self.assertEqual(len(server.observed), 3)
            for request in server.observed:
                self.assertEqual(request["path"], "/")
                self.assertEqual(request["method"], "GET")
                self.assertEqual(request["authorization"], headers["Authorization"])
                self.assertIsNone(request["content_length"])
                self.assertEqual(request["connection"].lower(), "close")
            self.assertEqual([r["user_agent"] for r in server.observed[:2]], [DEFAULT_UA, DEFAULT_UA])
            self.assertEqual(server.observed[2]["user_agent"], "SentinelPentest/1.0 (bounded-http-fuzzing)")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
