"""Proxy transport contracts verified using loopback sockets only."""

import base64
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import socket
import ssl
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, Request

from src.tools.proxy_profiles import ProxyProfilePool


class _Target(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.calls.append((self.path, self.headers.get("Proxy-Authorization")))
        body = b"measured-local-response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _Proxy(BaseHTTPRequestHandler):
    calls = []
    target_port = None

    def do_GET(self):
        self.calls.append(("GET", self.path, self.headers.get("Proxy-Authorization")))
        # This fixture only forwards to its one local target, regardless of input.
        connection = HTTPConnection("127.0.0.1", self.target_port, timeout=2)
        try:
            path = self.path.split(f":{self.target_port}", 1)[1]
            connection.request("GET", path)
            upstream = connection.getresponse()
            body = upstream.read()
            self.send_response(upstream.status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            connection.close()

    def do_CONNECT(self):
        self.calls.append(("CONNECT", self.path, self.headers.get("Proxy-Authorization")))
        self.send_response(407)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class _TunnelProxy(BaseHTTPRequestHandler):
    calls = []
    target_port = None

    def do_CONNECT(self):
        self.calls.append((self.path, self.headers.get("Proxy-Authorization")))
        # Forward only to the local TLS fixture; no requested host is resolved.
        with socket.create_connection(("127.0.0.1", self.target_port), timeout=2) as upstream:
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()
            peers = (self.connection, upstream)
            try:
                while True:
                    readable, _, _ = select.select(peers, [], [], 2)
                    if not readable:
                        return
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        destination = upstream if source is self.connection else self.connection
                        destination.sendall(data)
            except OSError:
                return

    def log_message(self, *args):
        pass


class ProxyProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
        _Proxy.target_port = cls.target.server_port
        cls.proxy = ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
        cls.threads = []
        for server in (cls.target, cls.proxy):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)
        cls.base = f"http://127.0.0.1:{cls.target.server_port}"
        cls.proxy_url = f"http://127.0.0.1:{cls.proxy.server_port}"

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target, cls.proxy):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join()

    def setUp(self):
        _Target.calls.clear()
        _Proxy.calls.clear()

    def options(self, **overrides):
        result = {
            "engine": "proxy_http",
            "allowed_origins": [self.base],
            "proxy_profiles": [{"id": "local_a", "url": self.proxy_url}],
        }
        result.update(overrides)
        return result

    def test_explicit_proxy_is_used_despite_environment_bypass(self):
        pool = ProxyProfilePool.from_options(self.options(), self.base)
        with patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*", "HTTP_PROXY": "http://127.0.0.1:1"}):
            identifier, opener = pool.opener_for(0)
            with opener.open(self.base + "/real", timeout=2) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"measured-local-response")
        self.assertEqual(identifier, "local_a")
        self.assertEqual(_Proxy.calls[0][:2], ("GET", self.base + "/real"))
        self.assertEqual(_Target.calls, [("/real", None)])

    def test_proxy_auth_is_sent_only_to_proxy(self):
        credential_url = self.proxy_url.replace("http://", "http://lab_user:lab_secret@")
        pool = ProxyProfilePool.from_options(self.options(proxy_profiles=[{"id": "auth", "url": credential_url}]), self.base)
        _, opener = pool.opener_for(0)
        with opener.open(self.base + "/auth", timeout=2) as response:
            response.read()
        expected = "Basic " + base64.b64encode(b"lab_user:lab_secret").decode("ascii")
        self.assertEqual(_Proxy.calls[0][2], expected)
        self.assertEqual(_Target.calls, [("/auth", None)])

    def test_scope_validation_happens_before_network(self):
        pool = ProxyProfilePool.from_options(self.options(), self.base)
        _, opener = pool.opener_for(0)
        for url in ("http://127.0.0.1:1/outside", "ftp://127.0.0.1/nope", "file:///should-not-be-read"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                opener.open(url, timeout=2)
        self.assertEqual(_Proxy.calls, [])
        self.assertEqual(_Target.calls, [])

    def test_failed_proxy_never_falls_back_to_direct_target(self):
        with socket.socket() as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            port = unavailable.getsockname()[1]
            pool = ProxyProfilePool.from_options(self.options(proxy_profiles=[{"id": "closed", "url": f"http://127.0.0.1:{port}"}]), self.base)
            _, opener = pool.opener_for(0)
            with self.assertRaises(URLError):
                opener.open(self.base + "/direct-must-not-happen", timeout=1)
        self.assertEqual(_Target.calls, [])

    def test_https_uses_connect_and_keeps_tls_verification(self):
        https_target = self.base.replace("http://", "https://")
        authenticated = self.proxy_url.replace("http://", "http://lab_user:lab_secret@")
        pool = ProxyProfilePool.from_options(self.options(allowed_origins=[https_target], proxy_profiles=[{"id": "tls", "url": authenticated}]), https_target)
        _, opener = pool.opener_for(0)
        https_handler = next(handler for handler in opener.handlers if isinstance(handler, HTTPSHandler))
        self.assertEqual(https_handler._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(https_handler._context.check_hostname)
        with self.assertRaises(URLError) as caught:
            opener.open(https_target + "/tls", timeout=2)
        self.assertEqual(_Proxy.calls[0][:2], ("CONNECT", f"127.0.0.1:{self.target.server_port}"))
        self.assertTrue(_Proxy.calls[0][2].startswith("Basic "))
        self.assertNotIn("lab_secret", pool.redact(caught.exception))
        self.assertEqual(_Target.calls, [])

    def test_https_connect_measures_real_tls_response_with_trusted_test_ca(self):
        # The committed key/certificate are public test fixtures only. The CA
        # is trusted through this test's environment, never a certificate store.
        fixtures = Path(__file__).parent / "fixtures"
        certificate = fixtures / "proxy_lab_cert.pem"
        key = fixtures / "proxy_lab_key.pem"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        target = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
        target.socket = context.wrap_socket(target.socket, server_side=True)
        _TunnelProxy.target_port = target.server_port
        _TunnelProxy.calls.clear()
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), _TunnelProxy)
        threads = []
        try:
            for server in (target, proxy):
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            origin = f"https://127.0.0.1:{target.server_port}"
            options = self.options(allowed_origins=[origin], proxy_profiles=[{
                "id": "trusted_tls", "url": f"http://lab_user:lab_secret@127.0.0.1:{proxy.server_port}"
            }])
            with patch.dict(os.environ, {"SSL_CERT_FILE": str(certificate.resolve()), "NO_PROXY": "*"}):
                pool = ProxyProfilePool.from_options(options, origin)
                _, opener = pool.opener_for(0)
                with opener.open(origin + "/verified-tls", timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"measured-local-response")
            self.assertEqual(_TunnelProxy.calls[0][0], f"127.0.0.1:{target.server_port}")
            expected = "Basic " + base64.b64encode(b"lab_user:lab_secret").decode("ascii")
            self.assertEqual(_TunnelProxy.calls[0][1], expected)
            self.assertEqual(_Target.calls, [("/verified-tls", None)])
        finally:
            for server in (target, proxy):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()

    def test_secret_env_profiles_and_cached_profile_selection(self):
        other_port = self.proxy.server_port + 1 if self.proxy.server_port < 65535 else self.proxy.server_port - 1
        profiles = [{"id": "a", "url": self.proxy_url}, {"id": "b", "url": f"http://127.0.0.1:{other_port}"}]
        options = self.options(proxy_profiles=None, proxy_profiles_env="SENTINEL_TEST_PROFILES")
        with patch.dict(os.environ, {"SENTINEL_TEST_PROFILES": json.dumps(profiles)}):
            pool = ProxyProfilePool.from_options(options, self.base)
        self.assertEqual(pool.profile_ids, ["a", "b"])
        self.assertEqual([pool.opener_for(i)[0] for i in range(3)], ["a", "b", "a"])
        self.assertIs(pool.opener_for(0)[1], pool.opener_for(2)[1])
        self.assertEqual(_Proxy.calls, [])

    def test_redaction_covers_encoded_and_decoded_credentials_and_basic(self):
        url = self.proxy_url.replace("http://", "http://secret%5Fuser:s3cr%21t@")
        pool = ProxyProfilePool.from_options(self.options(proxy_profiles=[{"id": "redact", "url": url}]), self.base)
        token = base64.b64encode(b"secret_user:s3cr!t").decode("ascii")
        message = f"{url} secret_user s3cr!t secret%5Fuser s3cr%21t Basic {token} {self.proxy_url[7:]}"
        redacted = pool.redact(message)
        for value in (url, "secret_user", "s3cr!t", "secret%5Fuser", "s3cr%21t", token, self.proxy_url[7:]):
            self.assertNotIn(value, redacted)

    def test_invalid_profiles_rejected_without_io_or_secret_echo(self):
        bad_options = [
            self.options(engine="auto"),
            self.options(allowed_origins=[]),
            self.options(allowed_origins=[self.base + "/path"]),
            self.options(allowed_origins=["http://127.0.0.1:1"]),
            self.options(proxy_profiles=[]),
            self.options(proxy_profiles=[{"id": "unsafe label", "url": self.proxy_url}]),
            self.options(proxy_profiles=[{"id": "a", "url": "http://secret_user:lab_secret@127.0.0.1"}]),
            self.options(proxy_profiles=[{"id": "a", "url": self.proxy_url + "/"}]),
            self.options(proxy_profiles=[{"id": "a", "url": self.proxy_url + "?"}]),
            self.options(proxy_profiles=[{"id": "a", "url": self.proxy_url + "#"}]),
            self.options(proxy_profiles=[{"id": "a", "url": self.proxy_url.replace("http:", "https:")}]),
            self.options(proxy_profiles=[{"id": "a", "url": self.proxy_url}, {"id": "b", "url": self.proxy_url}]),
            self.options(proxy_profiles_env="SENTINEL_TEST_PROFILES"),
        ]
        for options in bad_options:
            with self.subTest(options=options), self.assertRaises(ValueError) as caught:
                ProxyProfilePool.from_options(options, self.base)
            self.assertNotIn("lab_secret", str(caught.exception))
        self.assertEqual(_Proxy.calls, [])
        self.assertEqual(_Target.calls, [])

    def test_env_json_error_does_not_echo_value(self):
        options = self.options(proxy_profiles=None, proxy_profiles_env="SENTINEL_TEST_PROFILES")
        with patch.dict(os.environ, {"SENTINEL_TEST_PROFILES": "broken-secret-url-not-json"}):
            with self.assertRaisesRegex(ValueError, "must contain JSON") as caught:
                ProxyProfilePool.from_options(options, self.base)
        self.assertNotIn("broken-secret", str(caught.exception))

    def test_request_supplied_proxy_auth_cannot_override_profile(self):
        pool = ProxyProfilePool.from_options(self.options(), self.base)
        _, opener = pool.opener_for(0)
        request = Request(self.base + "/no-injected-auth", headers={"Proxy-Authorization": "Basic injected"})
        with opener.open(request, timeout=2) as response:
            response.read()
        self.assertIsNone(_Proxy.calls[0][2])


if __name__ == "__main__":
    unittest.main()
