"""B2.1 parser/contract tests: no HTTP or LLM providers."""
from copy import deepcopy
from hashlib import sha256
import unittest
from unittest.mock import Mock, patch

from src.agents.tech_recon import TechReconAgent, _ch2_dom_parse, _ch3_js_analyze
from src.coordinator.origins import origin_state, merge_discovery_context, add_observation
from src.coordinator.runtime import runtime_session
from src.tools.origin_scope import OriginScopePolicy, OriginScopedTransport


A, B, C = "https://front.invalid", "https://api.invalid", "https://unapproved.invalid"


class DiscoveryContextTests(unittest.TestCase):
    def parse(self, text):
        return _ch3_js_analyze(text, {}, base_url=A + "/app/index", source_url=A + "/app.js")

    def test_explicit_fetch_and_axios_methods_preserve_full_url_query_and_source(self):
        text = 'fetch("' + B + '/users?page=1", {method:"GET"}); axios.post("/rpc/save", {});'
        rows = self.parse(text)["observations"]
        self.assertEqual([(r["url"], r.get("method")) for r in rows], [(B + "/users?page=1", "GET"), (A + "/rpc/save", "POST")])
        self.assertTrue(all(r["source_url"] == A + "/app.js" for r in rows))
        self.assertTrue(all(r["verification_status"] == "not_verified" for r in rows))

    def test_implicit_fetch_method_remains_unknown(self):
        row = self.parse('fetch("/api/users")')["observations"][0]
        self.assertIsNone(row.get("method"))
        self.assertEqual(row["resource_type"], "api_reference")

    def test_external_assets_and_links_are_not_api_origins(self):
        result = self.parse('const image="' + C + '/image.svg"; const help="' + C + '/help";')
        self.assertEqual(result["api_origins"], [])
        self.assertEqual([r["resource_type"] for r in result["observations"]], ["static_asset", "unknown"])

    def test_concatenation_template_conditional_and_identifier_do_not_invent_urls(self):
        for expression in ('base + "/users"', '`/users/${id}`', 'endpoint', 'ok ? "/a" : "/b"'):
            with self.subTest(expression=expression):
                result = self.parse('fetch(' + expression + ', {method:"GET"})')
                self.assertEqual(result["observations"], [])
                self.assertEqual(len(result["unresolved_references"]), 1)
                row = result["unresolved_references"][0]
                self.assertIsNone(row["url"])
                self.assertIsNone(row["origin"])
                self.assertIsNone(row["confidence"])
                self.assertEqual(row["method"], "GET")

    def test_incomplete_call_is_unknown_and_does_not_extract_inner_literal(self):
        result = self.parse('fetch("/api/users", {method:')
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["unresolved_references"][0]["reason"], "incomplete_call")

    def test_standalone_concatenated_route_is_not_completed_from_a_fragment(self):
        result = self.parse('const route = "/api/users/" + userId;')
        self.assertEqual(result["observations"], [])
        self.assertEqual(len(result["unresolved_references"]), 1)

    def test_axios_base_url_is_not_ignored_or_guessed(self):
        for text in ('axios.get("/users", {baseURL: dynamicHost})',
                     'axios.defaults.baseURL = dynamicHost; axios.get("/users")'):
            result = self.parse(text)
            self.assertEqual(result["observations"], [])
            self.assertEqual(result["unresolved_references"][0]["reason"], "axios_base_url_not_resolved")

    def test_options_spread_and_dynamic_method_are_not_claimed_as_get(self):
        for options in ('{method: variable}', '{method:"GET", ...opts}', '{method:"GET", method:"POST"}'):
            row = self.parse('fetch("/api/users", ' + options + ')')["observations"][0]
            self.assertIsNone(row.get("method"))

    def test_axios_request_literal_config_is_extracted(self):
        row = self.parse('axios.request({url:"' + B + '/rpc/run", method:"POST"})')["observations"][0]
        self.assertEqual((row["origin"], row["method"], row["resource_type"]), (B, "POST", "api_reference"))

    def test_comments_do_not_generate_requests_or_references(self):
        result = self.parse('// fetch("/api/comment");\n/* axios.post("/api/hidden"); */')
        self.assertEqual(result["observations"], [])
        self.assertEqual(result["unresolved_references"], [])

    def test_line_offset_hash_and_reference_identify_actual_statement(self):
        text = '\n\nfetch("/v1/users?q=1", {method:"GET"});'
        row = self.parse(text)["observations"][0]
        loc = row["evidence_location"]
        self.assertEqual((loc["line"], loc["column"]), (3, 1))
        self.assertIn('/v1/users?q=1', text[loc["offset"]:loc["end_offset"]])
        self.assertEqual(row["source_sha256"], sha256(text.encode()).hexdigest())
        self.assertEqual(row["evidence_refs"], self.parse(text)["observations"][0]["evidence_refs"])

    def test_relative_url_uses_document_base_not_script_origin(self):
        result = _ch3_js_analyze('fetch("api/users", {method:"GET"})', {},
                                 base_url=A + "/app/index", source_url=B + "/static.js")
        self.assertEqual(result["observations"][0]["url"], A + "/app/api/users")

    def test_html_navigation_asset_form_and_base_url_preserve_provenance(self):
        html = '<base href="/app/"><a href="dashboard">go</a><img src="/logo.png">' \
               '<form action="/api/save?mode=1" method="POST"><input name="title"></form>'
        result = _ch2_dom_parse(html, A + "/", {})
        rows = result["observations"]
        self.assertEqual([r["resource_type"] for r in rows], ["frontend_route", "static_asset", "api_reference"])
        self.assertEqual(rows[0]["url"], A + "/app/dashboard")
        self.assertEqual(rows[2]["method"], "POST")
        self.assertEqual(rows[2]["source_type"], "form")
        self.assertTrue(all(r["source_sha256"] == sha256(html.encode()).hexdigest() for r in rows))
        self.assertEqual(result["parameters"][-1]["method"], "POST")

    def test_public_confidence_labels_survive_existing_secret_redaction(self):
        from src.coordinator.llm_logging import sanitize_for_log
        row = _ch2_dom_parse('<form action="/rpc/save" method="POST"></form>', A, {})["observations"][0]
        self.assertEqual(sanitize_for_log(row), row)
        self.assertEqual(row["confidence_basis"], "route_prefix_hint")

    def test_merge_combines_sources_but_never_merges_origins_or_method_variants(self):
        state = origin_state(A)
        first = self.parse('fetch("' + B + '/users", {method:"GET"})')["observations"][0]
        second = deepcopy(first)
        second.update(source="openapi", source_type="openapi", source_url=B + "/openapi.json", evidence_refs=["schema_users"])
        discovery = {"observations": [first, first, second,
                     self.parse('fetch("/users", {method:"GET"})')["observations"][0]]}
        merge_discovery_context(state, discovery)
        row = state["origin_contexts"][B]["endpoints"][0]
        self.assertEqual(len(state["origin_contexts"][B]["endpoints"]), 1)
        self.assertEqual(len(row["provenance"]), 2)
        self.assertNotEqual(row["endpoint_id"], state["origin_contexts"][A]["endpoints"][0]["endpoint_id"])
        self.assertEqual(state["approved_origins"], [A])
        self.assertEqual(row["verification_status"], "not_verified")
        post = deepcopy(first)
        post["method"] = "POST"
        add_observation(state, post)
        self.assertEqual(len(state["origin_contexts"][B]["endpoints"]), 2)

    def test_unknown_reference_is_grouped_by_source_but_keeps_endpoint_origin_null(self):
        state = origin_state(A)
        result = self.parse('fetch(apiBase + "/users")')
        merge_discovery_context(state, result)
        row = state["origin_contexts"][A]["context"]["unresolved_references"][0]
        self.assertIsNone(row["url"])
        self.assertIsNone(row["origin"])
        self.assertEqual(state["discovery_summary"]["unresolved_references"], 1)

    def test_b1_checkpoint_without_new_provenance_fields_can_receive_new_context(self):
        state = origin_state(A)
        row = self.parse('fetch("/users", {method:"GET"})')["observations"][0]
        stored = add_observation(state, row)
        for key in ("provenance", "resource_type", "source_sha256", "source_type", "confidence_basis", "evidence_location"):
            stored.pop(key, None)
        state["origin_contexts"][A]["endpoints"] = [stored]
        merge_discovery_context(state, {"observations": [row]})
        self.assertEqual(state["discovery_summary"]["rejected_records"], 0)
        saved = state["origin_contexts"][A]["endpoints"]
        self.assertEqual(len(saved), 1)
        self.assertEqual(len(saved[0]["provenance"]), 2)
        self.assertEqual(saved[0]["provenance"][0]["source_url"], A + "/app.js")

    def test_conflicting_resource_kinds_keep_both_sources_and_unknown_confidence(self):
        state = origin_state(A)
        route = _ch2_dom_parse('<a href="/users">Users</a>', A, {})["observations"][0]
        api = self.parse('fetch("/users")')["observations"][0]
        merge_discovery_context(state, {"observations": [route, api]})
        row = state["origin_contexts"][A]["endpoints"][0]
        self.assertEqual(len(row["provenance"]), 2)
        self.assertEqual(row["resource_type"], "unknown")
        self.assertIsNone(row["confidence"])

    def test_sensitive_observation_is_rejected_without_losing_other_results(self):
        state = origin_state(A)
        result = self.parse('fetch("/api/users?token=fixture-private"); fetch("/v1/public")')
        merge_discovery_context(state, result)
        self.assertNotIn("fixture-private", str(state))
        self.assertEqual(state["discovery_summary"]["rejected_records"], 2)  # endpoint + parameter URL
        self.assertEqual(len(state["origin_contexts"][A]["endpoints"]), 1)

    def test_collector_validates_whole_plan_before_any_request_or_llm(self):
        policy = OriginScopePolicy({"approved_origins": [A], "origin_policies": {A: {
            "rules": [{"path": "/", "methods": ["GET"], "operation": "read_only"}]}}})
        transport = OriginScopedTransport(A, policy=policy)
        llm = Mock()
        agent = TechReconAgent(llm=llm)
        with runtime_session({}), patch.object(transport, "fetch_result") as fetch:
            with self.assertRaises(ValueError):
                agent.collect_discovery(A, [{"url": A + "/", "kind": "html"},
                                           {"url": C + "/", "kind": "html"}], transport=transport)
            fetch.assert_not_called()
        llm.invoke.assert_not_called()

    def test_collector_drops_sensitive_reference_instead_of_inventing_redacted_candidate(self):
        policy = OriginScopePolicy({"approved_origins": [A], "origin_policies": {A: {
            "rules": [{"path": "/app.js", "methods": ["GET"], "operation": "read_only"}]}}})
        transport = OriginScopedTransport(A, policy=policy)
        body = 'fetch("/api/users?token=fixture-private"); fetch("/api/public")'
        # Unit-only transport fixture: integration evidence uses independent real servers.
        measured = {"url": A + "/app.js", "method": "GET", "attempted": True, "status_code": 200,
                    "body_complete": True, "headers": {}, "body": body, "error": None,
                    "bytes_received": len(body), "content_length": len(body), "body_truncated": False,
                    "response_time": .01, "stop_reason": None}
        with runtime_session({}), patch.object(transport, "fetch_result", return_value=measured):
            result = TechReconAgent().collect_discovery(A, [{"url": A + "/app.js", "kind": "javascript"}], transport=transport)
        context = result["discovery_context"]
        self.assertEqual(context["rejected_sensitive_records"], 2)
        self.assertEqual([r["url"] for r in context["observations"]], [A + "/api/public"])
        self.assertNotIn("fixture-private", str(result))
        self.assertNotIn("REDACTED", str(context))

    def test_coordinator_handoff_merges_context_without_changing_approval(self):
        from src.coordinator import graph
        state = {**origin_state(A), "target_url": A, "config": {}, "agent_statuses": {},
                 "audit_log": [], "error_log": [], "recon_profile": {}, "recon_execution": {}}
        data = self.parse('fetch("' + B + '/users", {method:"POST"})')
        result = {"tech_stack": {}, "discovered_paths": [], "discovery_context": data,
                  "execution": {"status": "completed", "stats": {"attempted_requests": 1,
                                "responses_received": 1}, "errors": []}}
        with patch.object(graph, "_get_decision_engine", return_value=None), \
                patch.object(graph, "TechReconAgent") as factory:
            factory.return_value.execute.return_value = result
            graph.run_tech_recon(state)
        self.assertEqual(state["approved_origins"], [A])
        self.assertEqual(state["origin_contexts"][B]["endpoints"][0]["method"], "POST")
        self.assertEqual(state["origin_execution_mode"], "legacy_untracked")
