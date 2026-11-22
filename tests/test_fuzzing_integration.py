"""Measurement integrity through registry, agent and coordinator. Localhost only."""

import logging
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

logging.getLogger("sentinel").addHandler(logging.NullHandler())

from src.agents.fuzzer import FuzzingAgent
from src.coordinator import graph
from src.tools.ffuf_helper import FfufToolHelper
from src.tools.registry import Tool, ToolRegistry


class FixtureHandler(BaseHTTPRequestHandler):
    body = "Đây là dữ liệu thật\n".encode("utf-8")
    received = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).received.append(self.path)
        content = self.body if self.path == "/ok" else b"missing"
        self.send_response(200 if self.path == "/ok" else 404)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class FuzzingIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        FixtureHandler.received.clear()

    @staticmethod
    def agent_for_payload(payload, success=True, error_message="scan stopped"):
        agent = FuzzingAgent(llm=None)
        registry = ToolRegistry()
        registry.register(Tool("ffuf_fuzzing_tool", "fixture", {}, lambda **kwargs: {
            "success": success, "result_data": payload,
            "error_message": None if success else error_message,
        }))
        agent.tool_registry = registry
        return agent

    def test_real_ffuf_measurements_survive_agent_and_registry(self):
        if not FfufToolHelper.resolve_binary():
            self.skipTest("ffuf is not installed")
        result = FuzzingAgent(llm=None).execute(
            self.target, ["/ok", "/missing"], use_pattern_engine=False,
            engine="ffuf_cli", rate_limit=50, delay_ms=0,
            max_requests=2, timeout_seconds=3, max_scan_seconds=10,
        )
        self.assertTrue(result["success"], result)
        self.assertFalse(result["simulated"])
        self.assertEqual(result["engine"], "ffuf_cli")
        self.assertEqual(sorted(FixtureHandler.received), ["/missing", "/ok"])
        by_path = {urlsplit(row["url"]).path: row for row in result["results"]}
        self.assertEqual(by_path["/ok"]["status_code"], 200)
        self.assertEqual(by_path["/ok"]["content_length"], len(FixtureHandler.body))
        self.assertEqual(by_path["/missing"]["status_code"], 404)
        self.assertEqual(by_path["/missing"]["content_length"], len(b"missing"))
        self.assertGreaterEqual(by_path["/ok"]["response_time"], 0)
        self.assertIsNone(result["stats"]["total_requests"])
        self.assertEqual(result["stats"]["status_codes"], {"200": 1, "404": 1})

    def test_real_native_measurements_through_agent(self):
        result = FuzzingAgent(llm=None).execute(
            self.target, ["/ok", "/missing"], use_pattern_engine=False,
            engine="python_http", rate_limit=50, delay_ms=0, max_requests=2,
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(result["engine"], "python_http")
        self.assertEqual(result["stats"]["total_requests"], 2)
        self.assertEqual(len(FixtureHandler.received), 2)
        self.assertEqual(result["results"][0]["content_length"], len(FixtureHandler.body))

    def test_missing_stats_does_not_replace_real_results(self):
        rows = [{"url": self.target + "/teapot", "status_code": 418,
                 "content_length": 37, "response_time": 0.125}]
        agent = self.agent_for_payload({"engine": "ffuf_cli", "results": rows})
        with patch.object(agent, "_run_fuzzing_internal", side_effect=AssertionError("No replacement scans")):
            result = agent.execute(self.target, ["/teapot"], use_pattern_engine=False)
        self.assertEqual(result["results"], rows)
        self.assertIsNone(result["stats"]["total_requests"])
        self.assertEqual(result["stats"]["status_codes"], {"418": 1})
        self.assertEqual(result["stats"]["avg_response_time"], 0.125)
        self.assertEqual(FixtureHandler.received, [])

    def test_failed_tool_is_not_turned_into_success(self):
        agent = self.agent_for_payload({}, success=False)
        with self.assertRaisesRegex(RuntimeError, "scan stopped"):
            agent.execute(self.target, ["/ok"], use_pattern_engine=False)
        self.assertEqual(FixtureHandler.received, [])

    def test_failed_execution_redacts_exception_before_agent_logging(self):
        agent = FuzzingAgent(llm=None)
        secret = "fixture-opaque-fuzzer-token"
        with patch.object(agent.tool_registry, "execute_tool", side_effect=RuntimeError(secret)), \
                patch("src.agents.fuzzer.log_agent_error") as log_error:
            with self.assertRaises(RuntimeError):
                agent.execute(self.target, ["/ok"], use_pattern_engine=False,
                              headers={"Authorization": "Bearer " + secret})
        self.assertNotIn(secret, str(log_error.call_args))
        self.assertEqual(FixtureHandler.received, [])

    def test_returned_tool_failure_redacts_echoed_credentials_without_losing_measurements(self):
        secret = "opaque_fuzzer_failure_fixture_78129"
        row = {"url": self.target + "/ok", "status_code": 401,
               "content_length": 17, "response_time": 0.125,
               "headers": {"Content-Type": "application/json", "Retry-After": "10"},
               "error": "upstream echoed " + secret}
        payload = {"engine": "python_http", "results": [row], "completed": False, "partial": True,
                   "errors": [{"error": "failure " + secret, "status_code": 401}],
                   "warnings": ["warning " + secret],
                   "stats": {"total_requests": 1, "attempted_requests": 1, "responses_received": 1}}
        agent = self.agent_for_payload(payload, success=False, error_message="tool error " + secret)
        with patch.object(agent, "generate_justification") as justify, \
                patch("src.agents.fuzzer.agent_logger.info") as info, \
                patch("src.agents.fuzzer.logger.warning") as warning:
            result = agent.execute(self.target, ["/ok"], use_pattern_engine=False, engine="python_http",
                                   headers={"Authorization": "Bearer " + secret, "Accept": "application/json"})
        justify.assert_not_called()
        for public in (result, info.call_args_list, warning.call_args_list):
            self.assertNotIn(secret, str(public))
        self.assertFalse(result["success"])
        self.assertEqual(result["stats"]["attempted_requests"], 1)
        self.assertEqual(result["stats"]["responses_received"], 1)
        self.assertEqual(result["results"][0]["headers"], row["headers"])
        for key in ("status_code", "content_length", "response_time"):
            self.assertEqual(result["results"][0][key], row[key])
        self.assertIn(secret, row["error"])  # Do not mutate the tool-owned payload.
        self.assertEqual(FixtureHandler.received, [])

    def test_response_echo_plan_reason_and_justification_are_redacted_before_public_use(self):
        secret = "opaque_fuzzer_success_fixture_37210"
        row = {"url": self.target + "/ok", "status_code": 200,
               "content_length": 37, "response_time": 0.25,
               "headers": {"Content-Type": "application/json", "X-Echo": secret},
               "redirect_url": self.target + "/next?code=" + secret}
        agent = self.agent_for_payload({"engine": "python_http", "results": [row],
                                       "completed": True, "partial": False, "errors": []})
        with patch.object(agent, "plan_tool_execution", return_value={
            "selected_tool": "ffuf_fuzzing_tool", "options": {},
            "tool_selection_reason": "reason " + secret, "options_selection_reason": "options " + secret,
        }), patch.object(agent, "generate_justification", return_value="explanation " + secret) as justify, \
                patch("src.agents.fuzzer.agent_logger.info") as info:
            result = agent.execute(self.target, ["/ok"], use_pattern_engine=False, engine="python_http",
                                   headers={"Authorization": "Bearer " + secret})
        justify.assert_called_once()
        for public in (result, justify.call_args, info.call_args_list):
            self.assertNotIn(secret, str(public))
        self.assertTrue(result["success"])
        self.assertEqual(result["results"][0]["headers"]["Content-Type"], "application/json")
        self.assertEqual(result["results"][0]["content_length"], 37)
        self.assertEqual(result["results"][0]["response_time"], 0.25)
        self.assertEqual(FixtureHandler.received, [])

    def test_agent_preserves_transport_errors_despite_inconsistent_success_flag(self):
        errors = [{"error": "TimeoutError: timed out", "status_code": None}] * 11
        agent = self.agent_for_payload({"engine": "python_http", "results": errors,
                                       "errors": errors, "completed": True})
        with patch.object(agent, "generate_justification") as justify:
            result = agent.execute(self.target, ["/missing"], use_pattern_engine=False)
        self.assertEqual(result["errors"], errors)
        self.assertFalse(result["success"])
        self.assertFalse(result["completed"])
        self.assertTrue(result["partial"])
        justify.assert_not_called()

    def test_partial_records_and_null_metrics_are_preserved(self):
        rows = [{"url": self.target + "/blocked", "status_code": 429,
                 "content_length": 0, "response_time": 0.0}]
        agent = self.agent_for_payload({"engine": "python_http", "results": rows,
                                       "partial": True, "stop_reason": "http_429"}, success=False)
        result = agent.execute(self.target, ["/blocked"], use_pattern_engine=False)
        self.assertFalse(result["success"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["results"], rows)
        self.assertIsNone(result["stats"]["total_requests"])
        self.assertEqual(result["stats"]["avg_response_time"], 0.0)

    def test_explanation_failure_keeps_real_http_measurements(self):
        agent = FuzzingAgent(llm=None)
        with patch.object(agent, "generate_justification", side_effect=TimeoutError("secret-fixture-token")):
            result = agent.execute(self.target, ["/ok"], engine="python_http",
                                   use_pattern_engine=False, rate_limit=50, delay_ms=0)
        self.assertEqual(FixtureHandler.received, ["/ok"])
        self.assertEqual(result["results"][0]["content_length"], len(FixtureHandler.body))
        self.assertEqual(result["stats"]["network_errors"], 0)
        self.assertEqual(result["stats"]["attempted_requests"], 1)
        self.assertFalse(result["success"])
        self.assertEqual(result["stop_reason"], "llm_justification_failed")
        self.assertEqual(result["errors"][0]["error_type"], "llm_justification_error")
        self.assertNotIn("secret-fixture-token", str(result))

    def test_explicit_options_override_plan_and_sensitive_values_are_redacted(self):
        agent = self.agent_for_payload({"engine": "python_http", "results": []})
        with patch.object(agent, "plan_tool_execution", return_value={
            "selected_tool": "ffuf_fuzzing_tool", "options": {
                "target_url": "https://model-target.invalid/FUZZ", "wordlist": ["/model-only"],
                "rate_limit": 200, "delay_between_requests_ms": 300,
                "timeout_seconds": 1, "max_requests": 999, "http_method": "POST",
            }
        }), patch.object(agent.tool_registry, "execute_tool", wraps=agent.tool_registry.execute_tool) as execute:
            result = agent.execute(self.target, ["/ok"], use_pattern_engine=False, rate_limit=2,
                                   timeout_seconds=8, max_requests=40, http_method="GET",
                                   headers={"Authorization": "Bearer fixture-secret"})
        sent = execute.call_args.args[1]
        self.assertEqual(sent["target_url"], self.target)
        self.assertEqual(sent["wordlist"], ["/ok"])
        self.assertEqual(sent["rate_limit"], 2)
        self.assertEqual(sent["timeout_seconds"], 8)
        self.assertEqual(sent["max_requests"], 40)
        self.assertEqual(sent["http_method"], "GET")
        self.assertEqual(sent["delay_ms"], 300)
        self.assertEqual(sent["headers"]["Authorization"], "Bearer fixture-secret")
        self.assertNotIn("fixture-secret", str(result))

    def test_aliases_override_defaults_before_sending_options(self):
        agent = self.agent_for_payload({"engine": "python_http", "results": []})
        with patch.object(agent.tool_registry, "execute_tool", wraps=agent.tool_registry.execute_tool) as execute:
            agent.execute(self.target, ["/ok"], use_pattern_engine=False,
                          timeout=3, max_duration_seconds=5, method="POST", body="fixture")
        sent = execute.call_args.args[1]
        self.assertEqual(sent["timeout_seconds"], 3)
        self.assertEqual(sent["max_scan_seconds"], 5)
        self.assertEqual(sent["http_method"], "POST")
        self.assertEqual(sent["post_data"], "fixture")

    def test_completed_native_scan_still_reaches_normal_decision(self):
        engine = SimpleNamespace(make_decision=lambda **kwargs: {"action": "proceed_to_param"})
        state = {"fuzzing_execution": {"partial": False, "stop_reason": "completed"},
                 "agent_statuses": {"fuzzing": "success"}, "raw_results": [], "config": {}}
        with patch.object(graph, "_get_decision_engine", return_value=engine) as get_engine:
            graph.llm_decide_after_fuzzing(state)
        get_engine.assert_called_once()
        self.assertEqual(state["_last_decision_action"], "proceed_to_param")

    def test_verification_context_describes_operator_fixed_proxy_without_credentials(self):
        agent = self.agent_for_payload({"engine": "python_http", "results": []})
        operator_proxy = "http://fixture-user:fixture-password@127.0.0.1:1"
        with patch.object(agent, "plan_tool_execution", return_value={
            "selected_tool": "ffuf_fuzzing_tool", "options": {
                "proxy": "http://model-route.invalid:3128",
                "headers": {"Authorization": "Bearer planned-fixture-token"}, "rate_limit": 0.5,
            }
        }), patch.object(agent.tool_registry, "execute_tool", wraps=agent.tool_registry.execute_tool) as execute:
            result = agent.execute(self.target, ["/ok"], use_pattern_engine=False,
                                   engine="python_http", proxy=operator_proxy)
        self.assertEqual(execute.call_args.args[1]["proxy"], operator_proxy)
        context = result["verification_context"]
        self.assertEqual(context["route"], "proxy")
        self.assertFalse(context["auth_matches_operator"])
        self.assertEqual(context["rate_limit"], 0.5)
        for secret in ("fixture-password", "planned-fixture-token"):
            self.assertNotIn(secret, str(context))

    def test_direct_engine_does_not_inherit_model_proxy_scope_or_tls_policy(self):
        agent = FuzzingAgent(llm=None)
        planned_network = {
            "engine": "proxy_http", "proxy": "http://model-route.invalid:3128",
            "proxy_source": "proxyscrape", "proxy_profiles": [{"id": "model", "url": "http://model-route.invalid:3128"}],
            "allowed_origins": ["https://model-target.invalid"], "auth_origins": [],
            "lab_source_ips": ["127.0.0.2"], "source_ip": "127.0.0.2",
            "source_address": "127.0.0.2", "verify": False, "verify_ssl": False,
            "insecure": True, "ssl_context": "model-value", "tls_ca_file": "model-file",
        }
        with patch.object(agent, "plan_tool_execution", return_value={
            "selected_tool": "ffuf_fuzzing_tool", "options": planned_network,
        }), patch.object(agent.tool_registry, "execute_tool", wraps=agent.tool_registry.execute_tool) as execute:
            result = agent.execute(self.target, ["/ok"], engine="python_http",
                                   use_pattern_engine=False, max_requests=1, rate_limit=50, delay_ms=0)
        sent = execute.call_args.args[1]
        self.assertEqual(sent["engine"], "python_http")
        for key in set(planned_network) - {"engine"}:
            self.assertNotIn(key, sent)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["verification_context"]["route"], "direct")
        self.assertEqual(result["stats"]["attempted_requests"], 1)
        self.assertEqual(FixtureHandler.received, ["/ok"])

    def test_coordinator_keeps_real_ffuf_data_without_fake_verification(self):
        if not FfufToolHelper.resolve_binary():
            self.skipTest("ffuf is not installed")
        state = {"target_url": self.target, "wordlist": ["/ok", "/missing"],
                 "agent_statuses": {"fuzzing": "pending"}, "audit_log": [], "error_log": [],
                 "config": {"soft404_options": {"enabled": False},
                            "fuzzing_options": {"engine": "ffuf_cli", "use_pattern_engine": False,
                            "rate_limit": 50, "delay_ms": 0, "timeout_seconds": 3, "max_scan_seconds": 10}},
                 "total_http_requests": 0, "circuit_breaker_state": {}}
        with patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)):
            graph.run_fuzzing(state)
        original = [dict(row) for row in state["raw_results"]]
        graph.run_soft404_filter(state)
        self.assertEqual(state["fuzzing_execution"]["engine"], "ffuf_cli")
        self.assertEqual(len(FixtureHandler.received), 2)
        self.assertEqual(state["raw_results"], original)
        self.assertEqual(state["verified_results"], [])
        self.assertEqual(state["verification_status"], "skipped")
        self.assertEqual(state["agent_statuses"]["soft404_filter"], "skipped")
        self.assertEqual(len(state["unverified_results"]), 2)
        self.assertEqual([row["content_length"] for row in state["unverified_results"]],
                         [row["content_length"] for row in original])

    def test_coordinator_preserves_unknown_count_and_partial_state(self):
        response = {"success": False, "partial": True, "engine": "ffuf_cli", "simulated": False,
                    "stop_reason": "http_429", "results": [{"status_code": 429}],
                    "stats": {"total_requests": None, "avg_response_time": None}}
        state = {"target_url": self.target, "wordlist": ["/ok"], "waf_detected": False,
                 "agent_statuses": {"fuzzing": "pending"}, "audit_log": [], "error_log": [],
                 "config": {"fuzzing_options": {"rate_limit": 2}},
                 "_config_adjustments": {"rate_limit": 100}, "total_http_requests": 0,
                 "circuit_breaker_state": {}, "discovered_paths": ["/ok"], "js_endpoints": ["/ok"]}
        with patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)), \
                patch.object(FuzzingAgent, "execute", return_value=response) as execute:
            graph.run_fuzzing(state)
        self.assertIsNone(state["total_http_requests"])
        self.assertEqual(state["raw_results"], response["results"])
        self.assertEqual(state["agent_statuses"]["fuzzing"], "partial")
        self.assertEqual(execute.call_args.kwargs["rate_limit"], 2)
        with patch.object(graph, "_get_decision_engine", side_effect=AssertionError("No repeat scan decision")):
            graph.llm_decide_after_fuzzing(state)
        self.assertEqual(state["_last_decision_action"], "skip_to_filter")


if __name__ == "__main__":
    unittest.main()
