"""Recon auth, origin scope and TLS verified against loopback HTTP servers."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import threading
import unittest
from unittest.mock import patch
from urllib.request import Request

from src.tools.recon_http import ScopedReconTransport


_HEADERS = {
    "Authorization": "Bearer recon_policy_fixture_token",
    "Cookie": "recon_policy_fixture_session=private",
    "X-API-Key": "recon_policy_fixture_api_key",
}


class _RecordingServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.accepted = []
        self.observed = []
        self.redirect = None

    def get_request(self):
        connection, address = super().get_request()
        self.accepted.append(address)
        return connection, address


class _Handler(BaseHTTPRequestHandler):
    def _respond(self):
        self.server.observed.append({
            "method": self.command,
            "path": self.path,
            "headers": {name.lower(): value for name, value in self.headers.items()},
        })
        if self.path == "/redirect":
            body = b"redirect fixture"
            self.send_response(302)
            self.send_header("Location", self.server.redirect)
        elif self.path == "/restricted":
            body = b"restricted fixture"
            self.send_response(403)
        else:
            body = b"local recon response"
            self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_OPTIONS = _respond
    do_TRACE = _respond

    def log_message(self, *args):
        pass


class ReconHttpPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.primary = _RecordingServer(("127.0.0.1", 0), _Handler)
        cls.secondary = _RecordingServer(("127.0.0.1", 0), _Handler)
        cls.proxy_trap = _RecordingServer(("127.0.0.1", 0), _Handler)
        cls.tls = _RecordingServer(("127.0.0.1", 0), _Handler)
        fixtures = Path(__file__).parent / "fixtures"
        cls.certificate = fixtures / "proxy_lab_cert.pem"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.certificate, fixtures / "proxy_lab_key.pem")
        cls.tls.socket = context.wrap_socket(cls.tls.socket, server_side=True)
        cls.origin = f"http://127.0.0.1:{cls.primary.server_port}"
        cls.other_origin = f"http://127.0.0.1:{cls.secondary.server_port}"
        cls.tls_origin = f"https://127.0.0.1:{cls.tls.server_port}"
        cls.servers = (cls.primary, cls.secondary, cls.proxy_trap, cls.tls)
        cls.workers = []
        for server in cls.servers:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.workers.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for worker in cls.workers:
            worker.join(timeout=3)

    def setUp(self):
        for server in self.servers:
            server.accepted.clear()
            server.observed.clear()
            server.redirect = None

    def transport(self, **options):
        return ScopedReconTransport(self.origin, headers=dict(_HEADERS), **options)

    def assert_credentials(self, observed, *, present):
        for name, value in _HEADERS.items():
            if present:
                self.assertEqual(observed["headers"][name.lower()], value)
            else:
                self.assertNotIn(name.lower(), observed["headers"])

    def test_auth_headers_reach_requested_origin_for_get_and_options(self):
        transport = self.transport()
        for method in ("GET", "OPTIONS"):
            status, _, body = transport.fetch(self.origin + "/measured", timeout=2, method=method)
            self.assertEqual(status, 200)
            self.assertEqual(body, "local recon response")
        self.assertEqual([row["method"] for row in self.primary.observed], ["GET", "OPTIONS"])
        for observed in self.primary.observed:
            self.assert_credentials(observed, present=True)
        self.assertEqual(self.secondary.accepted, [])

    def test_different_port_or_scheme_is_outside_default_scope_before_io(self):
        transport = self.transport()
        for url in (self.other_origin + "/outside", self.origin.replace("http:", "https:") + "/outside"):
            with self.subTest(url=url):
                self.assertFalse(transport.allows(url))
                self.assertFalse(transport.allows_auth(url))
                with self.assertRaises(ValueError):
                    transport.open(Request(url), timeout=1)
        self.assertEqual(self.primary.accepted, [])
        self.assertEqual(self.secondary.accepted, [])

    def test_additional_allowed_origin_receives_no_primary_credentials(self):
        transport = self.transport(allowed_origins=[self.origin, self.other_origin])
        self.assertTrue(transport.allows(self.other_origin))
        self.assertFalse(transport.allows_auth(self.other_origin))
        with self.assertRaises(ValueError):
            transport.check_url(self.other_origin + "/login", credentials=True)
        status, _, _ = transport.fetch(self.other_origin + "/api", timeout=2)
        self.assertEqual(status, 200)
        self.assert_credentials(self.secondary.observed[0], present=False)

    def test_explicit_auth_origin_can_receive_configured_credentials(self):
        transport = self.transport(allowed_origins=[self.origin, self.other_origin],
                                   auth_origins=[self.origin, self.other_origin])
        self.assertTrue(transport.allows_auth(self.other_origin))
        status, _, _ = transport.fetch(self.other_origin + "/api", timeout=2)
        self.assertEqual(status, 200)
        self.assert_credentials(self.secondary.observed[0], present=True)

    def test_auth_origins_cannot_expand_allowed_scope(self):
        with self.assertRaises(ValueError):
            self.transport(allowed_origins=[self.origin], auth_origins=[self.other_origin])
        self.assertEqual(self.primary.accepted, [])
        self.assertEqual(self.secondary.accepted, [])

    def test_redirect_is_recorded_without_forwarding_token_to_another_origin(self):
        self.primary.redirect = self.other_origin + "/credential-trap"
        transport = self.transport(allowed_origins=[self.origin, self.other_origin],
                                   auth_origins=[self.origin, self.other_origin])
        status, headers, body = transport.fetch(self.origin + "/redirect", timeout=2)
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), self.primary.redirect)
        self.assertEqual(body, "redirect fixture")
        self.assertEqual(len(self.primary.observed), 1)
        self.assertEqual(self.secondary.accepted, [])

    def test_trace_omits_auth_headers_even_at_authenticated_origin(self):
        status, _, _ = self.transport().fetch(self.origin + "/trace", timeout=2, method="TRACE")
        self.assertEqual(status, 200)
        self.assert_credentials(self.primary.observed[0], present=False)

    def test_ambient_proxy_is_not_used_for_recon(self):
        trap = f"http://127.0.0.1:{self.proxy_trap.server_port}"
        environment = {"HTTP_PROXY": trap, "http_proxy": trap, "HTTPS_PROXY": trap,
                       "https_proxy": trap, "ALL_PROXY": trap, "all_proxy": trap,
                       "NO_PROXY": "", "no_proxy": ""}
        with patch.dict(os.environ, environment):
            status, _, _ = self.transport().fetch(self.origin + "/direct", timeout=2)
        self.assertEqual(status, 200)
        self.assertEqual(len(self.primary.observed), 1)
        self.assertEqual(self.proxy_trap.accepted, [])

    def test_untrusted_tls_is_rejected_before_authenticated_http_request(self):
        transport = ScopedReconTransport(self.tls_origin, headers=dict(_HEADERS))
        self.assertTrue(transport.ssl_context.check_hostname)
        self.assertEqual(transport.ssl_context.verify_mode, ssl.CERT_REQUIRED)
        status, headers, message = transport.fetch(self.tls_origin + "/secret", timeout=2)
        self.assertIsNone(status)
        self.assertEqual(headers, {})
        self.assertTrue(message)
        self.assertEqual(self.tls.observed, [])
        for secret in _HEADERS.values():
            self.assertNotIn(secret, message)

    def test_explicit_test_ca_preserves_tls_verification_and_auth(self):
        transport = ScopedReconTransport(self.tls_origin, headers=dict(_HEADERS),
                                        tls_ca_file=str(self.certificate.resolve()))
        self.assertTrue(transport.ssl_context.check_hostname)
        self.assertEqual(transport.ssl_context.verify_mode, ssl.CERT_REQUIRED)
        status, _, body = transport.fetch(self.tls_origin + "/trusted", timeout=2)
        self.assertEqual(status, 200)
        self.assertEqual(body, "local recon response")
        self.assert_credentials(self.tls.observed[0], present=True)

    def test_tls_verification_cannot_be_disabled(self):
        with self.assertRaises(ValueError):
            self.transport(verify_ssl=False)
        self.assertEqual(self.primary.accepted, [])

    def test_invalid_or_routing_headers_are_rejected_before_io(self):
        for headers in ({"Authorization": "Bearer x\r\nX-Injected: yes"},
                        {"Bad Header": "value"}, {"Host": "outside.invalid"},
                        {"Proxy-Authorization": "Basic fixture"}):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                ScopedReconTransport(self.origin, headers=headers)
        self.assertEqual(self.primary.accepted, [])

    def test_http_error_is_a_measured_response_not_a_network_failure(self):
        status, _, body = self.transport().fetch(self.origin + "/restricted", timeout=2)
        self.assertEqual(status, 403)
        self.assertEqual(body, "restricted fixture")

    def test_public_redaction_removes_header_values_without_mutating_input(self):
        transport = self.transport()
        private = {"headers": dict(_HEADERS), "nested": ["echo " + _HEADERS["Authorization"]]}
        public = transport.redact(private)
        serialized = json.dumps(public)
        for secret in _HEADERS.values():
            self.assertNotIn(secret, serialized)
        self.assertEqual(private["headers"], _HEADERS)


if __name__ == "__main__":
    unittest.main()
