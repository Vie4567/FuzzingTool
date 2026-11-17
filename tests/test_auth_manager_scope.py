"""Authentication requests stay in explicit origin/TLS scope; localhost only."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from src.tools.auth_manager import AuthManager


_USERNAME = "auth_fixture_username"
_PASSWORD = "auth_fixture_password_739"
_TOKEN = "auth_fixture_opaque_token_284"


class _LoginHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        state = self.server.state
        state["requests"].append(("GET", self.path, dict(self.headers), None))
        if state.get("redirect"):
            self.send_response(302)
            self.send_header("Location", state["redirect"])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        action = state.get("action", "/session")
        body = (f'<form action="{action}" method="POST">'
                '<input type="hidden" name="csrf" value="fixture-csrf">'
                '<input type="text" name="username">'
                '<input type="password" name="password"></form>').encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.state["requests"].append(("POST", self.path, dict(self.headers), data))
        body = json.dumps({"access_token": _TOKEN}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "fixture_session=session_value; Path=/; HttpOnly")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AuthManagerScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
                       for _ in range(3)]
        cls.certificate = Path(__file__).parent / "fixtures/proxy_lab_cert.pem"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.certificate, cls.certificate.with_name("proxy_lab_key.pem"))
        cls.servers[2].socket = context.wrap_socket(cls.servers[2].socket, server_side=True)
        cls.origins = [f'{"https" if index == 2 else "http"}://127.0.0.1:{server.server_port}'
                       for index, server in enumerate(cls.servers)]
        cls.workers = []
        for server in cls.servers:
            server.state = {}
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
            server.state.clear()
            server.state["requests"] = []

    def account(self, **extra):
        return {"username": _USERNAME, "password": _PASSWORD,
                "login_url": "/login", **extra}

    def test_manual_headers_are_private_cached_copies_bound_to_one_origin(self):
        manager = AuthManager(bearer_token=_TOKEN, cookie="fixture_session=private-cookie",
                              allowed_origins=self.origins[:2], auth_origins=self.origins[:2])
        with self.assertLogs("src.tools.auth_manager", level="INFO") as logs:
            headers = manager.get_auth_headers(self.origins[0])
        self.assertEqual(headers["Authorization"], "Bearer " + _TOKEN)
        headers["Authorization"] = "mutated-by-caller"
        self.assertEqual(manager.get_auth_headers(self.origins[0] + "/other")["Authorization"],
                         "Bearer " + _TOKEN)
        with self.assertRaises(ValueError):
            manager.get_auth_headers(self.origins[1])
        self.assertTrue(all(not server.state["requests"] for server in self.servers))
        self.assertNotIn(_TOKEN, "\n".join(logs.output))
        self.assertNotIn(_TOKEN[:20], "\n".join(logs.output))
        self.assertNotIn("private-cookie", "\n".join(logs.output))

    def test_credentials_require_origin_and_reject_header_injection(self):
        with self.assertRaises(ValueError):
            AuthManager(bearer_token=_TOKEN).get_auth_headers()
        with self.assertRaises(ValueError):
            AuthManager(bearer_token="bad\r\nX-Injected: value").get_auth_headers(self.origins[0])
        with self.assertRaises(ValueError):
            AuthManager(custom_headers={"Host": "outside.invalid"}).get_auth_headers(self.origins[0])
        self.assertTrue(all(not server.state["requests"] for server in self.servers))

    def test_account_posts_inside_scope_and_resolves_token_and_cookies(self):
        manager = AuthManager(account=self.account())
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": "", "no_proxy": ""}), \
                self.assertLogs("src.tools.auth_manager", level="INFO") as logs:
            headers = manager.get_auth_headers(self.origins[0])
        self.assertEqual(headers["Authorization"], "Bearer " + _TOKEN)
        self.assertIn("fixture_session=session_value", headers["Cookie"])
        requests = self.servers[0].state["requests"]
        self.assertEqual([(row[0], row[1]) for row in requests], [("GET", "/login"), ("POST", "/session")])
        posted = parse_qs(requests[1][3].decode())
        self.assertEqual(posted, {"csrf": ["fixture-csrf"], "username": [_USERNAME], "password": [_PASSWORD]})
        self.assertEqual(manager.get_auth_headers(self.origins[0]), headers)
        self.assertEqual(len(requests), 2)
        self.assertEqual(self.servers[1].state["requests"], [])
        for secret in (_USERNAME, _PASSWORD, _TOKEN, "session_value"):
            self.assertNotIn(secret, "\n".join(logs.output))
        redacted = manager.redact({"echo": _TOKEN + _PASSWORD + _USERNAME})
        self.assertNotIn(_TOKEN, str(redacted))
        self.assertNotIn(_PASSWORD, str(redacted))
        self.assertNotIn(_USERNAME, str(redacted))

    def test_foreign_login_url_is_blocked_before_network(self):
        manager = AuthManager(account=self.account(login_url=self.origins[1] + "/login"))
        with self.assertRaises(RuntimeError):
            manager.get_auth_headers(self.origins[0])
        self.assertTrue(all(not server.state["requests"] for server in self.servers))

    def test_form_action_on_network_allowed_but_auth_disallowed_origin_is_blocked(self):
        self.servers[0].state["action"] = self.origins[1] + "/collect"
        manager = AuthManager(account=self.account(), allowed_origins=self.origins[:2])
        with self.assertRaises(RuntimeError):
            manager.get_auth_headers(self.origins[0])
        self.assertEqual([(row[0], row[1]) for row in self.servers[0].state["requests"]], [("GET", "/login")])
        self.assertEqual(self.servers[1].state["requests"], [])

    def test_redirect_does_not_forward_credentials_or_follow_destination(self):
        for destination in (self.origins[0] + "/redirected", self.origins[1] + "/collect"):
            with self.subTest(destination=destination):
                self.setUp()
                self.servers[0].state["redirect"] = destination
                manager = AuthManager(account=self.account(), custom_headers={"X-Api-Key": "private_fixture_key"})
                with self.assertRaises(RuntimeError):
                    manager.get_auth_headers(self.origins[0])
                self.assertEqual(len(self.servers[0].state["requests"]), 1)
                self.assertEqual(self.servers[1].state["requests"], [])

    def test_tls_is_verified_by_default_and_insecure_option_is_rejected(self):
        with self.assertRaises(ValueError):
            AuthManager(verify_ssl=False)
        with patch.dict(os.environ, {"SSL_CERT_FILE": "", "SSL_CERT_DIR": ""}):
            manager = AuthManager(account=self.account())
            self.assertTrue(manager.ssl_ctx.check_hostname)
            self.assertEqual(manager.ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
            with self.assertRaises(RuntimeError):
                manager.get_auth_headers(self.origins[2])
        self.assertEqual(self.servers[2].state["requests"], [])

    def test_private_ca_verifies_real_tls_and_retains_auth_context(self):
        manager = AuthManager(account=self.account(), tls_ca_file=str(self.certificate))
        headers = manager.get_auth_headers(self.origins[2])
        self.assertEqual(headers["Authorization"], "Bearer " + _TOKEN)
        self.assertTrue(manager.ssl_ctx.check_hostname)
        self.assertEqual(manager.ssl_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual([(row[0], row[1]) for row in self.servers[2].state["requests"]],
                         [("GET", "/login"), ("POST", "/session")])

    def test_https_login_cannot_submit_credentials_to_http_downgrade(self):
        self.servers[2].state["action"] = self.origins[0] + "/collect"
        manager = AuthManager(account=self.account(), tls_ca_file=str(self.certificate),
                              allowed_origins=[self.origins[2], self.origins[0]])
        with self.assertRaises(RuntimeError):
            manager.get_auth_headers(self.origins[2])
        self.assertEqual(len(self.servers[2].state["requests"]), 1)
        self.assertEqual(self.servers[0].state["requests"], [])


if __name__ == "__main__":
    unittest.main()
