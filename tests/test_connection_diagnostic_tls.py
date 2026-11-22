"""Stage diagnostics with localhost TLS and deterministic resolver/socket faults.

The committed certificate/key are public fixtures; no public DNS or HTTP is
used. Loading by file keeps this independent diagnostic free of agent imports.
"""

import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "diagnostic_tls_test_core", ROOT / "src/tools/connection_diagnostics.py"
)
diagnostic = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = diagnostic
SPEC.loader.exec_module(diagnostic)


class LocalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "user_agent": self.headers.get("User-Agent"),
            "diagnostic_id": self.headers.get("X-FuzzingTool-Diagnostic-ID"),
        })
        private = self.headers.get("Authorization", "body-sensitive-fixture-97231")
        body = json.dumps({"authenticated": True, "private": private}, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Fixture-Secret", private)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args):
        pass


class SilentHandshake(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.accepted += 1
        # Accept TCP, but never complete TLS. Do not send an HTTP response.
        self.server.release.wait(2)


class SilentServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ConnectionDiagnosticTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = ROOT / "tests/fixtures/proxy_lab_cert.pem"
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
        cls.server.observed = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.fixture, cls.fixture.with_name("proxy_lab_key.pem"))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.origin = f"https://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)

    def setUp(self):
        self.server.observed.clear()

    def stage(self, result, name):
        return next(row for row in result["stages"] if row["name"] == name)

    def test_verified_tls_records_stages_and_only_sends_scoped_fake_bearer(self):
        token = "local-tls-diagnostic-bearer-5327"
        events = []
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / "must_not_write_tls_secrets.log"
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
                result = diagnostic.diagnose_once(
                    self.origin + "/protected-fixture", allowed_origin=self.origin,
                    auth_origin=self.origin, bearer_token=token, timeout_seconds=2,
                    tls_ca_file=str(self.fixture), progress=events.append,
                    expected_json_pointer="/authenticated", expected_json_value=True,
                )
            self.assertFalse(keylog.exists())
        self.assertEqual(result["state"], "completed", result)
        for name in ("dns_resolution", "tcp_connect", "tls_handshake", "request_send",
                     "response_headers", "response_body"):
            self.assertEqual(self.stage(result, name)["status"], "success", name)
            self.assertGreaterEqual(self.stage(result, name)["duration_seconds"], 0)
        self.assertEqual(result["http"]["attempted_requests"], 1)
        self.assertEqual(result["http"]["responses_received"], 1)
        self.assertEqual(result["http"]["status_code"], 200)
        self.assertTrue(result["http"]["body_complete"])
        for counter in ("dns_attempts", "tcp_attempts", "tls_handshakes"):
            self.assertEqual(result["counts"][counter], 1)
        self.assertGreaterEqual(result["counts"]["resolved_addresses"], 1)
        self.assertEqual(len(self.server.observed), 1)
        request = self.server.observed[0]
        self.assertEqual(request["authorization"], "Bearer " + token)
        self.assertEqual(request["user_agent"], "SentinelPentest/1.0 (bounded-http-fuzzing)")
        self.assertEqual(request["diagnostic_id"], result["diagnostic_id"])
        self.assertTrue(result["auth"]["server_confirmation_required"])
        self.assertNotIn(token, json.dumps(result))
        self.assertNotIn(token, json.dumps(events))
        self.assertNotIn("body-sensitive-fixture-97231", json.dumps(result))

    def test_untrusted_certificate_is_tls_failure_before_any_http_request(self):
        with patch.dict(os.environ, {"SSL_CERT_FILE": "", "SSL_CERT_DIR": ""}):
            result = diagnostic.diagnose_once(
                self.origin + "/protected-fixture", allowed_origin=self.origin,
                timeout_seconds=2,
            )
        self.assertEqual(result["state"], "failed", result)
        self.assertEqual(self.stage(result, "dns_resolution")["status"], "success")
        self.assertEqual(self.stage(result, "tcp_connect")["status"], "success")
        failed = self.stage(result, "tls_handshake")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error"]["exception_type"], "SSLCertVerificationError")
        self.assertEqual(result["http"]["attempted_requests"], 0)
        self.assertEqual(result["http"]["responses_received"], 0)
        self.assertEqual(self.server.observed, [])

    def test_tcp_accept_without_tls_reply_is_handshake_timeout(self):
        server = SilentServer(("127.0.0.1", 0), SilentHandshake)
        server.accepted = 0
        server.release = threading.Event()
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        origin = f"https://127.0.0.1:{server.server_address[1]}"
        try:
            started = time.monotonic()
            result = diagnostic.diagnose_once(origin + "/", allowed_origin=origin,
                                              timeout_seconds=.2)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(result["state"], "failed", result)
            self.assertEqual(self.stage(result, "tcp_connect")["status"], "success")
            self.assertEqual(self.stage(result, "tls_handshake")["status"], "failed")
            self.assertEqual(result["http"]["attempted_requests"], 0)
            self.assertEqual(result["http"]["responses_received"], 0)
            self.assertEqual(server.accepted, 1)
        finally:
            server.release.set()
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)

    def test_dns_error_is_identified_without_tcp_or_secret_exception_text(self):
        secret = "sensitive-resolver-exception-93715"
        with patch.object(diagnostic.socket, "getaddrinfo", side_effect=socket.gaierror(socket.EAI_NONAME, secret)), \
             patch.object(diagnostic.socket, "socket") as connect:
            result = diagnostic.diagnose_once(
                "https://dns-fixture.invalid/path", allowed_origin="https://dns-fixture.invalid",
                timeout_seconds=1,
            )
        connect.assert_not_called()
        self.assertEqual(result["state"], "failed", result)
        stage = self.stage(result, "dns_resolution")
        self.assertEqual(stage["status"], "failed")
        self.assertEqual(stage["error"]["exception_type"], "gaierror")
        self.assertEqual(result["counts"]["tcp_attempts"], 0)
        self.assertEqual(result["http"]["attempted_requests"], 0)
        self.assertNotIn(secret, json.dumps(result))

    def test_connection_refusal_stays_in_tcp_stage_and_does_not_try_another_address(self):
        secret = "sensitive-socket-exception-28133"
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 9)),
                     (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.2", 9))]
        sock = Mock()
        sock.connect.side_effect = ConnectionRefusedError(111, secret)
        with patch.object(diagnostic.socket, "getaddrinfo", return_value=addresses), \
             patch.object(diagnostic.socket, "socket", return_value=sock) as connect:
            result = diagnostic.diagnose_once(
                "https://tcp-fixture.invalid/path", allowed_origin="https://tcp-fixture.invalid",
                timeout_seconds=1,
            )
        connect.assert_called_once()
        sock.connect.assert_called_once_with(("127.0.0.1", 9))
        self.assertEqual(result["counts"]["tcp_attempts"], 1)
        self.assertEqual(self.stage(result, "dns_resolution")["status"], "success")
        stage = self.stage(result, "tcp_connect")
        self.assertEqual(stage["status"], "failed")
        self.assertEqual(stage["error"]["exception_type"], "ConnectionRefusedError")
        self.assertEqual(result["http"]["attempted_requests"], 0)
        self.assertEqual(result["http"]["responses_received"], 0)
        self.assertNotIn(secret, json.dumps(result))

    def test_tiny_body_reads_keep_exact_bytes_without_unbounded_progress(self):
        response = Mock(status=200, length=1024)
        response.getheader.return_value = None

        def tiny_read(_size):
            response.length -= 1
            return b"x"

        response.read1.side_effect = tiny_read
        connection = Mock()
        connection.getresponse.return_value = response
        address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 9))
        events = []
        with patch.object(diagnostic.socket, "getaddrinfo", return_value=[address]), \
             patch.object(diagnostic.socket, "socket"), \
             patch.object(diagnostic.http.client, "HTTPConnection", return_value=connection):
            result = diagnostic.diagnose_once("http://127.0.0.1:9/fixture", allowed_origin="http://127.0.0.1:9",
                                              timeout_seconds=2, progress=events.append)
        self.assertEqual(result["state"], "completed", result)
        self.assertEqual(result["http"]["bytes_received"], 1024)
        self.assertTrue(result["http"]["body_complete"])
        self.assertEqual(response.read1.call_count, 1024)
        self.assertLessEqual(len(events), 40)

    def test_deep_json_is_an_unmatched_contract_not_a_transport_exception(self):
        raw = b"[" * 10000 + b"0" + b"]" * 10000
        self.assertLess(len(raw), 65536)
        self.assertFalse(diagnostic._json_matches(raw, "/authenticated", True))


if __name__ == "__main__":
    unittest.main()
