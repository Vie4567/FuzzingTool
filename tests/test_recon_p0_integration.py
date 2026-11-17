"""Agent 1 P0: real local HTTP, independent request records, no provider calls."""

from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from src.agents import tech_recon as recon
from src.coordinator import graph
from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_phase, telemetry_session
from src.tools.recon_http import ScopedReconTransport


class ReconP0Handler(BaseHTTPRequestHandler):
    """A known mixed frontend/backend site, deliberately without a WAF."""

    server_version = "ReconP0Fixture/1.0"

    def _respond(self):
        parsed = urlsplit(self.path)
        event = {"method": self.command, "path": self.path, "status_code": None}
        with self.server.event_lock:
            self.server.events.append(event)
        mode = self.server.scenario
        if (mode == "disconnect_home" and parsed.path == "/app/index") or (
                mode == "disconnect_js" and parsed.path == "/static/root.js"):
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        status, media, body = 404, "text/plain", "not found"
        if mode == "all_404":
            pass
        elif mode == "blocked" and parsed.path == "/app/index":
            status, body = 403, "operator stop fixture"
        elif parsed.path in {"/app/index", "/"}:
            status, media = 200, "text/html"
            body = (
                '<html><head><script src="/static/root.js?rev=1"></script>'
                '<script src="local.js"></script></head><body><div data-reactroot="">Catalog</div>'
                '<a href="/inside?from=nav#section">Inside</a>'
                '<form action="/api/search" method="POST"><input name="term">'
                '<select name="category"><option>all</option></select><textarea name="note"></textarea>'
                '</form></body></html>'
            )
        elif parsed.path == "/static/root.js":
            status, media = 200, "application/javascript"
            body = 'fetch("/api/local?item=1"); fetch("' + self.server.other_origin + '/api/remote?q=1");'
        elif parsed.path in {"/app/local.js", "/local.js"}:
            status, media = 200, "application/javascript"
            body = 'fetch("/api/relative");'
        elif parsed.path == "/robots.txt":
            status, body = 200, "User-agent: *\nDisallow: /robot-candidate\n"
        elif parsed.path == "/sitemap.xml":
            status, media = 200, "application/xml"
            body = ('<urlset><url><loc>' + self.server.origin + '/sitemap-local</loc></url>'
                    '<url><loc>' + self.server.other_origin + '/foreign-sitemap</loc></url></urlset>')
        elif parsed.path == "/swagger.json":
            status, media = 200, "application/json"
            body = ('{"openapi":"3.0.0","paths":[]}' if mode == "invalid_schema" else
                    json.dumps({"openapi": "3.0.0", "paths": {
                        "/api/schema": {"get": {"parameters": [{"name": "page", "in": "query"}]}}
                    }}))
        elif parsed.path == "/api/search":
            status, media = 200, "application/json"
            page = parse_qs(parsed.query).get("page", ["all"])[0]
            body = json.dumps({"items": ["catalog", page], "page": page})
        elif parsed.path == "/inside":
            status, media, body = 200, "text/html", "<html><p>inside</p></html>"
        raw = body.encode("utf-8")
        event.update(status_code=status, body_bytes=len(raw))
        self.send_response(status)
        self.send_header("Content-Type", media + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Powered-By", "ASP.NET")
        if self.command == "OPTIONS":
            self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()
        try:
            if mode in {"slow_body", "short_body"} and parsed.path == "/app/index":
                self.wfile.write(raw[:10])
                self.wfile.flush()
                if mode == "slow_body":
                    time.sleep(.2)
                self.close_connection = True
                return
            self.wfile.write(raw)
        except (OSError, ConnectionError):
            pass

    do_GET = _respond
    do_OPTIONS = _respond
    do_TRACE = _respond

    def log_message(self, *_args):
        pass


@contextmanager
def local_recon_fixture(scenario="completed"):
    """Two real origins; only explicitly configured ones may receive requests."""
    servers, workers = [], []
    for _ in range(2):
        server = ThreadingHTTPServer(("127.0.0.1", 0), ReconP0Handler)
        server.events, server.event_lock = [], threading.Lock()
        server.scenario = scenario
        server.origin = f"http://127.0.0.1:{server.server_port}"
        servers.append(server)
    primary, secondary = servers
    primary.other_origin, secondary.other_origin = secondary.origin, primary.origin
    for server in servers:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        workers.append(worker)
    real_connect = socket.socket.connect
    real_socketpair = socket.socketpair
    ipc = threading.local()
    rejected = []

    def local_only(sock, address):
        if (getattr(ipc, "active", False) and isinstance(address, tuple)
                and address[0] in {"127.0.0.1", "::1"}):
            return real_connect(sock, address)
        if not isinstance(address, tuple) or address[:2] not in {
                ("127.0.0.1", primary.server_port), ("127.0.0.1", secondary.server_port)}:
            rejected.append(str(address))
            raise AssertionError("Recon P0 fixture refuses non-fixture network access")
        return real_connect(sock, address)

    def socketpair(*args, **kwargs):
        ipc.active = True
        try:
            return real_socketpair(*args, **kwargs)
        finally:
            ipc.active = False

    loader = recon.TechReconAgent._load_knowledge

    def bounded_knowledge(agent):
        loader(agent)
        agent._spider_cfg = {"limits": {"default_max_depth": 1, "default_max_pages": 8,
                                       "concurrent_requests": 2, "request_delay_ms": 0,
                                       "request_timeout_ms": 1000}}

    try:
        with patch.object(socket, "socketpair", socketpair), \
                patch.object(socket.socket, "connect", local_only), \
                patch.object(recon.TechReconAgent, "_load_knowledge", bounded_knowledge), \
                patch.object(recon, "PROBE_FILES", ["/robots.txt", "/sitemap.xml", "/swagger.json"]):
            yield SimpleNamespace(primary=primary, secondary=secondary,
                                  target=primary.origin + "/app/index", rejected=rejected)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for worker in workers:
            worker.join(timeout=3)


class ReconP0IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)))
        self.stack.enter_context(patch.object(graph, "circuit_breakers", {"tech_recon": Mock(), "wordlist_gen": Mock()}))

    def run_recon(self, fixture, *, config=None, coordinator=False):
        options = {"http_max_requests": 40, "http_rate_limit": 1000,
                   "http_timeout_seconds": 1, "pipeline_timeout_seconds": 15}
        options.update(config or {})
        with runtime_session(options), telemetry_session(max_llm_calls=0) as telemetry, telemetry_phase("run_tech_recon"):
            if coordinator:
                result = graph.run_tech_recon(graph.init_state({"target_url": fixture.target, "config": options}))
            else:
                result = recon.TechReconAgent().execute(fixture.target)
        self.assertEqual(fixture.rejected, [])
        self.assertEqual(fixture.secondary.events, [])
        return result, telemetry.snapshot()

    def assert_measured(self, result, telemetry, fixture):
        stats = result["execution"]["stats"]
        events = fixture.primary.events
        self.assertEqual(stats["attempted_requests"], len(events))
        self.assertEqual(stats["responses_received"], sum(row["status_code"] is not None for row in events))
        self.assertEqual(stats["network_errors"], sum(row["status_code"] is None for row in events))
        self.assertEqual(telemetry["http"]["total_requests"], len(events))
        self.assertEqual(telemetry["llm"]["attempted"], 0)

    def test_successful_recon_preserves_mixed_stack_and_context_through_coordinator(self):
        with local_recon_fixture() as fixture:
            state, telemetry = self.run_recon(fixture, coordinator=True)
            self.assertEqual(state["agent_statuses"]["tech_recon"], "success")
            profile = state["recon_profile"]
            self.assertEqual(profile["target_url"], fixture.target)
            self.assertFalse(state["waf_detected"])
            self.assertEqual(state["tech_stack"]["frontend"].lower(), "react")
            self.assertIn(state["tech_stack"]["backend"].lower(), {"asp.net", "asp_net"})
            # ASP.NET does not establish C# over other supported backend languages.
            self.assertEqual(state["tech_stack"]["language"], "Unknown")
            self.assertTrue(profile["technology_evidence"])
            form = next(row for row in profile["forms"] if row["action"].endswith("/api/search"))
            self.assertEqual(form["method"], "POST")
            self.assertTrue({"term", "category", "note"} <= set(form["params"]))
            self.assertIn("page", {row["name"] for row in profile["parameters"]})
            self.assertTrue(profile["api_context"])
            self.assertEqual(state["recon_execution"]["stats"]["attempted_requests"], len(fixture.primary.events))
            self.assertEqual(telemetry["http"]["total_requests"], len(fixture.primary.events))

    def test_subpath_js_and_query_probes_keep_correct_urls(self):
        with local_recon_fixture() as fixture:
            result, telemetry = self.run_recon(fixture)
            paths = [row["path"] for row in fixture.primary.events]
            self.assertIn("/static/root.js?rev=1", paths)
            self.assertIn("/app/local.js", paths)
            self.assertIn("/robots.txt", paths)
            self.assertFalse(any(path.startswith("/app/index/static") for path in paths))
            self.assertTrue(any("id" in parse_qs(urlsplit(path).query) for path in paths))
            self.assertFalse(any("/id=SENTINEL" in path for path in paths))
            self.assert_measured(result, telemetry, fixture)

    def test_foreign_js_and_sitemap_candidates_keep_origins_without_target_pollution(self):
        with local_recon_fixture() as fixture:
            result, telemetry = self.run_recon(fixture)
            self.assertNotIn("/api/remote", result["discovered_paths"])
            self.assertNotIn("/foreign-sitemap", result["discovered_paths"])
            records = result["recon_profile"]["paths"]
            for path in ("/api/remote", "/foreign-sitemap"):
                rows = [row for row in records if urlsplit(row["url"]).path == path]
                self.assertTrue(rows, path)
                self.assertTrue(all(row["origin"] == fixture.secondary.origin for row in rows))
                self.assertTrue(all(row["classification"] == "candidate" for row in rows))
            self.assert_measured(result, telemetry, fixture)

    def test_partial_js_transport_failure_keeps_homepage_and_other_channel_data(self):
        with local_recon_fixture("disconnect_js") as fixture:
            result, telemetry = self.run_recon(fixture)
            self.assertEqual(result["execution"]["status"], "partial")
            self.assertFalse(result["execution"]["completed"])
            self.assertTrue(result["execution"]["errors"])
            self.assertIn("/api/relative", result["discovered_paths"])
            self.assertEqual(result["status_code"], 200)
            self.assertGreater(result["execution"]["stats"]["network_errors"], 0)
            self.assert_measured(result, telemetry, fixture)

    def test_homepage_transport_failure_returns_failed_measurements_without_followup_requests(self):
        with local_recon_fixture("disconnect_home") as fixture:
            result, telemetry = self.run_recon(fixture)
            self.assertEqual(result["execution"]["status"], "failed")
            self.assertFalse(result["execution"]["success"])
            self.assertIsNone(result["status_code"])
            self.assertEqual(len(fixture.primary.events), 1)
            self.assert_measured(result, telemetry, fixture)

    def test_http_404_responses_are_transport_complete_not_network_errors(self):
        with local_recon_fixture("all_404") as fixture:
            result, telemetry = self.run_recon(fixture)
            self.assertEqual(result["execution"]["status"], "completed")
            self.assertEqual(result["status_code"], 404)
            self.assertEqual(result["execution"]["stats"]["network_errors"], 0)
            self.assert_measured(result, telemetry, fixture)

    def test_malformed_schema_is_partial_without_losing_dom_or_js_observations(self):
        with local_recon_fixture("invalid_schema") as fixture:
            result, telemetry = self.run_recon(fixture)
            self.assertEqual(result["execution"]["status"], "partial")
            self.assertIn("/api/local", result["discovered_paths"])
            self.assertTrue(result["recon_profile"]["forms"])
            self.assertTrue(any("schema" in str(row).lower() for row in result["execution"]["errors"]))
            self.assert_measured(result, telemetry, fixture)

    def test_request_budget_preserves_stop_reason_and_observations(self):
        with local_recon_fixture() as fixture:
            result, telemetry = self.run_recon(fixture, config={"http_max_requests": 3})
            self.assertEqual(result["execution"]["stop_reason"], "http_request_budget")
            self.assertNotEqual(result["execution"]["status"], "completed")
            self.assertEqual(len(fixture.primary.events), 3)
            self.assertEqual(result["status_code"], 200)
            self.assert_measured(result, telemetry, fixture)

    def test_access_block_is_response_and_stops_without_followup_requests(self):
        with local_recon_fixture("blocked") as fixture:
            result, telemetry = self.run_recon(fixture)
            self.assertEqual(result["execution"]["stop_reason"], "http_403")
            self.assertNotEqual(result["execution"]["status"], "completed")
            self.assertEqual(result["status_code"], 403)
            self.assertEqual(len(fixture.primary.events), 1)
            self.assert_measured(result, telemetry, fixture)

    def test_body_limit_retains_response_status_and_records_read_error(self):
        with local_recon_fixture() as fixture, runtime_session({"http_max_response_bytes": 64,
                                                               "http_rate_limit": 1000}), telemetry_session() as telemetry:
            measured = ScopedReconTransport(fixture.target).fetch_result(fixture.target)
            self.assertEqual(measured["status_code"], 200)
            self.assertTrue(measured["attempted"])
            self.assertFalse(measured["body_complete"])
            self.assertIsNotNone(measured["error"])
            self.assertLessEqual(measured["content_length"], 64)
            self.assertEqual(measured["bytes_received"], 65)
            self.assertTrue(measured["body_truncated"])
            self.assertEqual(telemetry.snapshot()["http"]["total_requests"], 1)
            self.assertEqual(len(fixture.primary.events), 1)

    def test_premature_eof_keeps_observed_status_and_bytes_with_incomplete_body(self):
        for use_runtime in (True, False):
            with self.subTest(runtime=use_runtime), local_recon_fixture("short_body") as fixture, ExitStack() as contexts:
                if use_runtime:
                    contexts.enter_context(runtime_session({"http_rate_limit": 1000}))
                measured = ScopedReconTransport(fixture.target).fetch_result(fixture.target)
                self.assertEqual(measured["status_code"], 200)
                self.assertEqual(measured["bytes_received"], 10)
                self.assertEqual(measured["content_length"], 10)
                self.assertFalse(measured["body_complete"])
                self.assertEqual(measured["error"]["error_type"], "response_read_error")

    def test_error_probes_keep_existing_query_and_options_endpoint(self):
        with local_recon_fixture() as fixture:
            fixture.target += "?tenant=fixture"
            result, telemetry = self.run_recon(fixture)
            events = fixture.primary.events
            for event in events:
                if event["method"] in {"OPTIONS", "TRACE"}:
                    self.assertEqual(event["path"], "/app/index?tenant=fixture")
                query = parse_qs(urlsplit(event["path"]).query)
                if "id" in query or "XDEBUG_SESSION" in query:
                    self.assertEqual(query["tenant"], ["fixture"])
            self.assert_measured(result, telemetry, fixture)

    def test_form_query_parameter_method_and_script_provenance_are_preserved(self):
        target = "https://example.invalid/app/index"
        dom = recon._ch2_dom_parse('<form action="/submit?mode=x" method="POST"><input name="term"></form>', target, {})
        self.assertEqual({row["method"] for row in dom["parameters"]}, {"POST"})
        self.assertEqual({row["location"] for row in dom["parameters"]}, {"body", "query"})
        parsed = recon._ch3_js_analyze('fetch("/api/items?q=1")', {}, base_url=target,
                                      source_url="https://cdn.invalid/static.js")
        row = next(item for item in parsed["observations"] if item["path"] == "/api/items")
        self.assertEqual(row["origin"], "https://example.invalid")
        self.assertEqual(row["source_url"], "https://cdn.invalid/static.js")

    def test_html_base_origin_is_preserved_without_polluting_target_paths(self):
        target = "https://example.invalid/app/index"
        dom = recon._ch2_dom_parse('<base href="https://other.invalid/docs/"><a href="page">x</a>', target, {})
        self.assertEqual(dom["paths"], [])
        self.assertEqual(dom["observations"][0]["url"], "https://other.invalid/docs/page")
        self.assertEqual(dom["observations"][0]["source_url"], target)

    def test_invalid_openapi_server_does_not_move_endpoints_to_schema_origin(self):
        import asyncio
        transport = Mock()
        transport.fetch.return_value = (200, {}, json.dumps({"openapi": "3.0.0", "servers": [{"url": "http://[bad"}],
                                                           "paths": {"/api/wrong-origin": {"get": {}}}}))
        result = asyncio.run(recon._ch6_api_schema(["https://example.invalid/openapi.json"], transport=transport))
        self.assertEqual(result["paths"], [])
        self.assertIsNone(result["schema_type"])
        transport.error.assert_called_once()

    def test_incomplete_homepage_marks_dom_unavailable_instead_of_completed(self):
        with local_recon_fixture("short_body") as fixture:
            result, telemetry = self.run_recon(fixture)
            self.assertEqual(result["execution"]["status"], "partial")
            channel = result["execution"]["channels"]["CH-2 DOM"]
            self.assertEqual(channel["status"], "skipped")
            self.assertEqual(channel["reason"], "homepage_body_incomplete")
            self.assertGreater(result["execution"]["stats"]["response_read_errors"], 0)
            self.assert_measured(result, telemetry, fixture)

    def test_body_timeout_keeps_response_and_is_not_a_missing_http_response(self):
        with local_recon_fixture("slow_body") as fixture, runtime_session({"http_timeout_seconds": .05,
                                                                         "http_rate_limit": 1000}), telemetry_session() as telemetry:
            measured = ScopedReconTransport(fixture.target).fetch_result(fixture.target)
            self.assertEqual(measured["status_code"], 200)
            self.assertTrue(measured["attempted"])
            self.assertFalse(measured["body_complete"])
            self.assertEqual(measured["error"]["error_type"], "response_read_error")
            self.assertEqual(measured["content_length"], 10)
            self.assertEqual(telemetry.snapshot()["http"]["total_requests"], 1)


if __name__ == "__main__":
    unittest.main()
