"""B1 real localhost HTTP and independent access logs; never Internet or LLM.

Set B1_EVIDENCE_DIR to retain sanitized artifacts. These tests exercise the
contract + guarded transport, NOT five-Agent multi-origin scheduling.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
from threading import Lock, Thread
import unittest
from urllib.request import Request
from uuid import uuid4

from src.coordinator.artifacts import RunArtifacts
from src.coordinator.origins import add_observation, endpoint_observation, origin_state
from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.tools.origin_scope import OriginCredentialContext, OriginScopePolicy, OriginScopedTransport


AUTH_A, AUTH_B = "Bearer b1-fixture-origin-a", "Bearer b1-fixture-origin-b"
COOKIE_A, COOKIE_B = "sid=b1-fixture-cookie-a", "sid=b1-fixture-cookie-b"


def utc():
    return datetime.now(timezone.utc).isoformat()


class AccessServer(ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self):
        connection = super().get_request()
        with self.lock:
            self.connections += 1
        return connection


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        status = 302 if self.path == "/redirect" else 401 if self.path == "/denied" else 200
        auth, cookie = self.headers.get("Authorization"), self.headers.get("Cookie")
        # Server-owned evidence contains only credential identity labels, never values.
        with self.server.lock:
            self.server.access.append({"utc": utc(), "diagnostic_id": self.server.case_id,
                "method": self.command, "path": self.path, "status": status,
                "authorization_present": auth is not None, "cookie_present": cookie is not None,
                "credential_identity": "frontend" if (auth, cookie) == (AUTH_A, COOKIE_A) else
                                       "gateway" if (auth, cookie) == (AUTH_B, COOKIE_B) else
                                       "anonymous" if auth is None and cookie is None else "unexpected"})
        body = b"local B1 read-only fixture"
        self.send_response(status)
        if status == 302:
            self.send_header("Location", self.server.redirect_to)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET


class OriginScopeHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers, cls.workers = [], []
        for _ in range(3):
            server = AccessServer(("127.0.0.1", 0), Handler)
            server.lock, server.access, server.connections = Lock(), [], 0
            cls.servers.append(server)
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.workers.append(worker)
        cls.a, cls.b, cls.c = [f"http://127.0.0.1:{s.server_port}" for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server, worker in zip(cls.servers, cls.workers):
            server.shutdown()
            server.server_close()
            worker.join(3)

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.case_id = "b1_" + uuid4().hex
        self.started = utc()
        self.checked = False
        for server in self.servers:
            server.access.clear()
            server.connections = 0
            server.case_id, server.redirect_to = self.case_id, self.b + "/shared"
        self.config = {"approved_origins": [self.a, self.b], "origin_policies": {
            self.a: {"credential_profile": "frontend", "rules": [
                {"path": path, "methods": ["GET", "HEAD"], "operation": "read_only"}
                for path in ("/shared", "/redirect", "/denied")]},
            self.b: {"rules": [{"path": "/shared", "query": "", "methods": ["GET"], "operation": "read_only"}]},
        }}
        self.limits = {"http_max_requests": 8, "http_rate_limit": 100, "http_timeout_seconds": 1,
                       "pipeline_timeout_seconds": 10}
        self.telemetry = self.stack.enter_context(telemetry_session(max_llm_calls=0))
        self.runtime = self.stack.enter_context(runtime_session(self.limits))
        self.measurements = []
        self.build()

    def build(self, *, gateway_credentials=False):
        if gateway_credentials:
            self.config["origin_policies"][self.b]["credential_profile"] = "gateway"
        self.policy = OriginScopePolicy(self.config)
        profiles = {self.a: {"profile_id": "frontend", "headers": {"Authorization": AUTH_A, "Cookie": COOKIE_A}}}
        if gateway_credentials:
            profiles[self.b] = {"profile_id": "gateway", "headers": {"Authorization": AUTH_B, "Cookie": COOKIE_B}}
        context = OriginCredentialContext(self.policy, profiles)
        self.transport = OriginScopedTransport(self.a, policy=self.policy, credentials=context)
        self.state = origin_state(self.a, self.config)

    def fetch(self, url, method="GET"):
        result = self.transport.fetch_result(url, timeout=1, method=method)
        self.measurements.append({key: result[key] for key in ("url", "method", "attempted", "status_code",
                                 "body_complete", "bytes_received", "response_time", "stop_reason", "error")})
        return result

    def check_evidence(self, expected):
        counts = [len(s.access) for s in self.servers]
        self.assertEqual(counts, expected)
        self.assertEqual([s.connections for s in self.servers], expected)
        self.assertEqual(sum(bool(row["attempted"]) for row in self.measurements), sum(expected))
        self.assertEqual(self.telemetry.snapshot()["http"]["known_requests"], sum(expected))
        self.assertEqual(self.runtime.snapshot()["http_dispatches"], sum(expected))
        self.assertEqual(self.telemetry.snapshot()["llm"]["attempted"], 0)
        self.assertEqual(self.state["approved_origins"], [self.a, self.b])
        self.checked = True

    def tearDown(self):
        root = os.getenv("B1_EVIDENCE_DIR")
        temporary = None
        if not root:
            temporary = tempfile.TemporaryDirectory()
            root = temporary.name
        try:
            # Keep checkpoint paths below Windows MAX_PATH; full test ID lives
            # in evidence.json rather than being duplicated in directory names.
            directory = Path(root) / self.case_id[:15]
            directory.mkdir(parents=True)
            failed = any(test is self for test, _ in
                         (self._outcome.result.failures + self._outcome.result.errors))
            level = "integration_verified" if self.checked and not failed else "not_verified"
            summary = {"diagnostic_id": self.case_id, "started_at_utc": self.started, "finished_at_utc": utc(),
                "test": self.id(), "verification_status": level, "test_failed": failed,
                "scope": "B1 contract and transport only; no Agent scheduling", "internet_requests": 0,
                "config": self.policy.public_config(), "limits": self.limits,
                "telemetry": self.telemetry.snapshot(), "runtime": self.runtime.snapshot(),
                "measurements": self.measurements, "server_request_counts": [len(s.access) for s in self.servers]}
            for label, server in zip(("frontend", "gateway", "unapproved"), self.servers):
                (directory / (label + "_access.json")).write_text(json.dumps(server.access, indent=2), encoding="utf-8")
            self.state["b1_evidence"] = summary
            artifact = RunArtifacts({"output_dir": str(directory)})
            saved = artifact.save(self.state, node="b1_contract", event=level)
            self.assertEqual(saved["origin_contexts"], self.state["origin_contexts"])
            summary["state_artifact"] = saved["artifacts"]["result"]
            rendered = json.dumps(summary, indent=2)
            for secret in (AUTH_A, AUTH_B, COOKIE_A, COOKIE_B):
                self.assertNotIn(secret, rendered)
                self.assertNotIn(secret, json.dumps(saved))
            (directory / "evidence.json").write_text(rendered, encoding="utf-8")
        finally:
            if temporary:
                temporary.cleanup()

    def test_unapproved_discovery_receives_zero_requests(self):
        add_observation(self.state, endpoint_observation(self.c + "/shared", source="javascript",
                        source_url=self.a + "/app.js", classification="candidate"))
        result = self.fetch(self.c + "/shared")
        self.assertFalse(result["attempted"])
        self.assertIsNone(result["status_code"])
        self.assertIn(self.c, self.state["origin_contexts"])
        self.check_evidence([0, 0, 0])

    def test_frontend_credentials_never_implicitly_reach_approved_gateway(self):
        for origin in (self.a, self.b):
            row = endpoint_observation(origin + "/shared", method="GET", source="operator")
            add_observation(self.state, row)
            self.assertEqual(self.fetch(row["url"])["status_code"], 200)
        self.assertEqual(self.servers[0].access[0]["credential_identity"], "frontend")
        self.assertEqual(self.servers[1].access[0]["credential_identity"], "anonymous")
        self.assertEqual(len(self.state["origin_contexts"]), 2)
        self.check_evidence([1, 1, 0])

    def test_independently_bound_gateway_credentials_are_used_without_frontend_values(self):
        self.build(gateway_credentials=True)
        self.fetch(self.a + "/shared")
        self.fetch(self.b + "/shared")
        self.assertEqual(self.servers[0].access[0]["credential_identity"], "frontend")
        self.assertEqual(self.servers[1].access[0]["credential_identity"], "gateway")
        self.check_evidence([1, 1, 0])

    def test_scheme_hostname_port_path_query_and_write_methods_fail_before_io(self):
        cases = [(self.a.replace("http:", "https:") + "/shared", "GET"),
                 (self.a.replace("127.0.0.1", "localhost") + "/shared", "GET"),
                 (self.c + "/shared", "GET"), (self.a + "/shared/child", "GET"),
                 (self.a + "/shared?p=1", "GET"), (self.a + "/%73hared", "GET")]
        cases += [(self.a + "/shared", method) for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE")]
        for url, method in cases:
            with self.subTest(method=method):
                self.assertFalse(self.fetch(url, method)["attempted"])
        self.check_evidence([0, 0, 0])

    def test_declared_head_and_exact_query_work_without_expanding_path_permission(self):
        self.config["origin_policies"][self.b]["rules"][0]["query"] = "page=1"
        self.build()
        self.assertEqual(self.fetch(self.a + "/shared", "HEAD")["status_code"], 200)
        self.assertEqual(self.fetch(self.b + "/shared?page=1")["status_code"], 200)
        self.assertFalse(self.fetch(self.b + "/shared?page=2")["attempted"])
        self.check_evidence([1, 1, 0])

    def test_redirect_does_not_follow_even_to_an_approved_origin(self):
        self.assertEqual(self.fetch(self.a + "/redirect")["status_code"], 302)
        self.check_evidence([1, 0, 0])

    def test_caller_cannot_bypass_credentials_or_body_policy(self):
        for request in (Request(self.b + "/shared", headers={"Authorization": AUTH_A}),
                        Request(self.b + "/shared", headers={"Cookie": COOKIE_A}),
                        Request(self.a + "/shared", data=b"", method="GET")):
            with self.assertRaises(ValueError):
                self.transport.open(request)
        with self.assertRaises(ValueError):
            self.transport.open(self.a + "/shared", cookie_jar=object())
        self.check_evidence([0, 0, 0])

    def test_existing_global_stop_is_not_bypassed_by_switching_origin(self):
        self.assertEqual(self.fetch(self.a + "/denied")["status_code"], 401)
        self.assertFalse(self.fetch(self.b + "/shared")["attempted"])
        self.assertEqual(self.runtime.stop_reason, "http_401")
        self.check_evidence([1, 0, 0])

    def test_existing_shared_budget_is_not_reset_for_another_origin(self):
        self.runtime.max_requests = 1
        self.assertEqual(self.fetch(self.a + "/shared")["status_code"], 200)
        self.assertFalse(self.fetch(self.b + "/shared")["attempted"])
        self.assertEqual(self.runtime.stop_reason, "http_request_budget")
        self.check_evidence([1, 0, 0])
