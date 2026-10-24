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
    def agent_for_payload(payload, success=True):
        agent = FuzzingAgent(llm=None)
        registry = ToolRegistry()
        registry.register(Tool("ffuf_fuzzing_tool", "fixture", {}, lambda **kwargs: {
            "success": success, "result_data": payload,
            "error_message": None if success else "scan stopped",
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

    def test_explicit_options_override_plan_and_sensitive_values_are_redacted(self):
        agent = self.agent_for_payload({"engine": "python_http", "results": []})
        with patch.object(agent, "plan_tool_execution", return_value={
            "selected_tool": "ffuf_fuzzing_tool", "options": {"rate_limit": 200, "delay_between_requests_ms": 300}
        }), patch.object(agent.tool_registry, "execute_tool", wraps=agent.tool_registry.execute_tool) as execute:
            result = agent.execute(self.target, ["/ok"], use_pattern_engine=False, rate_limit=2,
                                   headers={"Authorization": "Bearer fixture-secret"})
        sent = execute.call_args.args[1]
        self.assertEqual(sent["rate_limit"], 2)
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

    def test_coordinator_keeps_real_ffuf_data_without_fake_verification(self):
        if not FfufToolHelper.resolve_binary():
            self.skipTest("ffuf is not installed")
        state = {"target_url": self.target, "wordlist": ["/ok", "/missing"],
                 "agent_statuses": {"fuzzing": "pending"}, "audit_log": [], "error_log": [],
                 "config": {"fuzzing_options": {"engine": "ffuf_cli", "use_pattern_engine": False,
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
        self.assertEqual(state["verification_status"], "not_implemented")
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
