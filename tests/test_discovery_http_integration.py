"""Real Agent 1 collection from three localhost servers; no public HTTP/LLM."""
from contextlib import ExitStack
from datetime import datetime, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Thread, Lock
import unittest
from unittest.mock import Mock
from uuid import uuid4

from src.agents.tech_recon import TechReconAgent
from src.coordinator.artifacts import RunArtifacts
from src.coordinator.origins import origin_state, merge_discovery_context
from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.tools.origin_scope import OriginScopePolicy, OriginCredentialContext, OriginScopedTransport


AUTH = "Bearer b21-only-local-fake-token"
COOKIE = "sid=b21-only-local-fake-cookie"


def utc():
    return datetime.now(timezone.utc).isoformat()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body, mime = self.server.documents.get(self.path, ("not in document plan", "text/plain"))
        broken = self.server.mode == "disconnect_js" and self.path == "/app.js"
        blocked = self.server.mode == "blocked" and self.path == "/"
        status = None if broken else 403 if blocked else 200 if self.path in self.server.documents else 404
        raw = body.encode("utf-8")
        a, c = self.headers.get("Authorization"), self.headers.get("Cookie")
        with self.server.lock:
            self.server.access.append({"utc": utc(), "diagnostic_id": self.server.case_id,
                "origin": self.server.origin, "method": self.command, "path": self.path, "status": status,
                "authorization_present": a is not None, "cookie_present": c is not None,
                "credential_identity": "frontend" if (a, c) == (AUTH, COOKIE) else
                                       "anonymous" if a is None and c is None else "unexpected",
                "response_sha256": sha256(raw).hexdigest() if not broken else None})
        if broken:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET


class DiscoveryHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers, cls.workers = [], []
        for role in ("frontend", "gateway", "unapproved"):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            server.lock, server.role = Lock(), role
            server.origin = f"http://127.0.0.1:{server.server_port}"
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.servers.append(server)
            cls.workers.append(worker)
        cls.a, cls.b, cls.c = [s.origin for s in cls.servers]

    @classmethod
    def tearDownClass(cls):
        for server, worker in zip(cls.servers, cls.workers):
            server.shutdown()
            server.server_close()
            worker.join(3)

    def setUp(self):
        self.case_id = "b21_" + uuid4().hex[:10]
        self.started = utc()
        self.checked = False
        self.result = None
        for server in self.servers:
            server.access, server.documents, server.mode, server.case_id = [], {}, "ok", self.case_id
        html = '\n'.join([
            '<a href="/dashboard">Dashboard</a>', '<link href="/style.css" rel="stylesheet">',
            '<img src="/logo.svg">', '<script src="/app.js"></script>',
            '<div data-api="/api/meta"></div>',
            f'<form action="{self.b}/rpc/save" method="POST"><input name="title"></form>',
            '<a href="/guide">Guide</a>'])
        js = '\n'.join([
            f'fetch("{self.b}/users", {{method:"GET"}});',
            f'fetch("{self.b}/rpc/save", {{method:"POST"}});',
            f'fetch("{self.c}/v1/private", {{method:"GET"}});',
            'fetch("/users", {method:"GET"});',
            'fetch("/api/search?q=book", {method:"GET"});',
            'fetch("v1/items", {method:"GET"});',
            'fetch(apiBase + "/dynamic", {method:"GET"});',
            f'const help = "{self.c}/help";', f'const icon = "{self.c}/logo.svg";'])
        schema = json.dumps({"openapi": "3.0.0", "servers": [{"url": self.b}], "paths": {
            "/users": {"get": {"parameters": [{"name": "page", "in": "query"}]}},
            "/rpc/save": {"post": {}}, "/health": {"get": {}}}}, indent=2)
        self.servers[0].documents = {"/": (html, "text/html"), "/app.js": (js, "application/javascript"),
                                    "/guide": ('<a href="/support">Support</a>', "text/html")}
        self.servers[1].documents = {"/openapi.json": (schema, "application/json")}
        self.config = {"approved_origins": [self.a, self.b], "origin_policies": {
            self.a: {"credential_profile": "frontend", "rules": [
                {"path": p, "methods": ["GET"], "operation": "read_only"} for p in self.servers[0].documents]},
            self.b: {"rules": [{"path": "/openapi.json", "methods": ["GET"], "operation": "read_only"}]}}}
        self.plan = [{"url": self.a + "/", "kind": "html"}, {"url": self.a + "/app.js", "kind": "javascript"},
                     {"url": self.a + "/guide", "kind": "html"}, {"url": self.b + "/openapi.json", "kind": "openapi"}]
        self.limits = {"http_max_requests": 8, "http_rate_limit": 100, "http_timeout_seconds": 1,
                       "pipeline_timeout_seconds": 15, "max_retries": 0}
        self.state = {"target_url": self.a + "/", **origin_state(self.a + "/", self.config)}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.telemetry = self.stack.enter_context(telemetry_session(max_llm_calls=0))
        self.runtime = self.stack.enter_context(runtime_session(self.limits))
        policy = OriginScopePolicy(self.config)
        credentials = OriginCredentialContext(policy, {self.a: {
            "profile_id": "frontend", "headers": {"Authorization": AUTH, "Cookie": COOKIE}}})
        self.transport = OriginScopedTransport(self.a, policy=policy, credentials=credentials)
        self.llm = Mock()
        self.agent = TechReconAgent(llm=self.llm)

    def collect(self):
        self.result = self.agent.collect_discovery(self.a + "/", self.plan, transport=self.transport)
        merge_discovery_context(self.state, self.result["discovery_context"])
        self.state["recon_execution"] = self.result["execution"]
        self.state["recon_profile"] = self.result["recon_profile"]
        self.state["telemetry"] = self.telemetry.snapshot()
        self.llm.invoke.assert_not_called()

    def check_counts(self, expected, responses):
        self.assertEqual([len(s.access) for s in self.servers], expected)
        execution = self.result["execution"]
        self.assertEqual(execution["stats"]["attempted_requests"], sum(expected))
        self.assertEqual(execution["stats"]["responses_received"], responses)
        self.assertEqual(self.telemetry.snapshot()["http"]["known_requests"], sum(expected))
        self.assertEqual(self.runtime.snapshot()["http_dispatches"], sum(expected))
        self.assertEqual(self.telemetry.snapshot()["llm"]["attempted"], 0)
        self.assertEqual(self.state["approved_origins"], [self.a, self.b])
        for server in self.servers:
            self.assertTrue(all(row["method"] == "GET" for row in server.access))
            expected_auth = "frontend" if server is self.servers[0] else "anonymous"
            self.assertTrue(all(row["credential_identity"] == expected_auth for row in server.access))
        self.checked = True

    def test_real_documents_merge_provenance_without_executing_api_references(self):
        self.collect()
        self.assertEqual(self.result["execution"]["status"], "completed")
        counts = self.state["discovery_summary"]
        self.assertEqual(counts["unique_endpoints_by_type"],
                         {"frontend_route": 3, "static_asset": 4, "api_reference": 8, "unknown": 1})
        self.assertEqual(counts["unresolved_references"], 1)
        self.assertEqual(counts["rejected_records"], 0)
        api = self.state["origin_contexts"][self.b]["endpoints"]
        users = next(row for row in api if row["url"] == self.b + "/users")
        self.assertEqual(len(users["provenance"]), 2)
        save = next(row for row in api if row["url"] == self.b + "/rpc/save")
        self.assertEqual(save["method"], "POST")
        self.assertEqual({p["source_type"] for p in save["provenance"]}, {"form", "javascript", "openapi"})
        front_users = next(row for row in self.state["origin_contexts"][self.a]["endpoints"] if row["url"] == self.a + "/users")
        self.assertNotEqual(users["endpoint_id"], front_users["endpoint_id"])
        for entry in self.state["origin_contexts"].values():
            self.assertTrue(all(row["verification_status"] == "not_verified" for row in entry["endpoints"]))
        self.assertIn(self.c, self.state["origin_contexts"])
        self.assertIsNone(self.state["origin_contexts"][self.c]["status"])
        self.check_counts([3, 1, 0], 4)

    def test_transport_error_preserves_collected_context_and_does_not_retry(self):
        self.servers[0].mode = "disconnect_js"
        self.collect()
        self.assertEqual(self.result["execution"]["status"], "partial")
        self.assertEqual(self.result["execution"]["stats"]["network_errors"], 1)
        self.assertEqual(self.state["origin_contexts"][self.a]["status"], "partial")
        self.assertTrue(self.state["origin_contexts"][self.b]["endpoints"])
        self.assertEqual(sum(row["path"] == "/app.js" for row in self.servers[0].access), 1)
        self.check_counts([3, 1, 0], 3)

    def test_shared_budget_stops_collection_without_expanding_or_retrying_plan(self):
        self.runtime.max_requests = 2
        self.collect()
        self.assertEqual(self.result["execution"]["stop_reason"], "http_request_budget")
        self.assertEqual(self.result["execution"]["status"], "partial")
        self.assertTrue(self.state["origin_contexts"][self.b]["endpoints"])
        self.assertIsNone(self.state["origin_contexts"][self.b]["status"])
        self.check_counts([2, 0, 0], 2)

    def test_http_block_stops_before_scripts_schema_or_other_origins(self):
        self.servers[0].mode = "blocked"
        self.collect()
        self.assertEqual(self.result["execution"]["stop_reason"], "http_403")
        self.assertNotEqual(self.result["execution"]["status"], "completed")
        self.assertEqual(self.state["discovered_origins"], [])
        self.check_counts([1, 0, 0], 1)

    def test_duplicate_document_plan_never_adds_http_requests(self):
        self.plan.append(dict(self.plan[1]))
        self.collect()
        self.assertEqual(self.result["planned_documents"], 4)
        self.check_counts([3, 1, 0], 4)

    def tearDown(self):
        root = os.getenv("B21_EVIDENCE_DIR")
        temporary = None
        if not root:
            temporary = tempfile.TemporaryDirectory()
            root = temporary.name
        try:
            directory = Path(root) / self.case_id
            directory.mkdir(parents=True)
            failed = any(test is self for test, _ in self._outcome.result.failures + self._outcome.result.errors)
            evidence = {"diagnostic_id": self.case_id, "test": self.id(), "started_at_utc": self.started,
                "finished_at_utc": utc(), "test_outcome": "PASS" if self.checked and not failed else "FAIL",
                "verification_level": "integration_verified" if self.checked and not failed else "not_verified",
                "config": self.config, "plan": self.plan, "limits": self.limits,
                "telemetry": self.telemetry.snapshot(), "runtime": self.runtime.snapshot(),
                "servers": {s.role: s.origin for s in self.servers}, "agent_result": self.result,
                "internet_verification": "not_verified", "pipeline_execution": "not_enabled_b1"}
            for server in self.servers:
                (directory / (server.role + "_access.json")).write_text(json.dumps(server.access, indent=2), encoding="utf-8")
                # Fixture server's actual served content, independent of the parser/client.
                served = {row["path"] for row in server.access if row["status"] == 200}
                content = {server.origin + path: server.documents[path][0] for path in served if path in server.documents}
                (directory / (server.role + "_served.json")).write_text(json.dumps(content, indent=2), encoding="utf-8")
            saved = RunArtifacts({"output_dir": str(directory)}).save(self.state, node="b21_discovery", event=evidence["test_outcome"])
            evidence["state_artifact"] = saved["artifacts"]["result"]
            self.assertEqual(saved["origin_contexts"], self.state["origin_contexts"])
            rendered = json.dumps(evidence, indent=2)
            for secret in (AUTH, COOKIE):
                self.assertNotIn(secret, rendered)
                self.assertNotIn(secret, json.dumps(saved))
            (directory / "evidence.json").write_text(rendered, encoding="utf-8")
        finally:
            if temporary:
                temporary.cleanup()
