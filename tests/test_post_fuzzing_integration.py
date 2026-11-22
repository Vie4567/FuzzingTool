"""Post-fuzzing routing with actual loopback HTTP and no remote LLM/provider.

Recon/wordlist and parameter candidate generation are fixtures so the tests
isolate Agent 3 -> Agent 4 -> Agent 5; HTTP measurements are never mocked.
"""
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from src.coordinator import graph


TOKEN = "post_fuzzing_fixture_bearer_84277"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append({"path": self.path, "auth": self.headers.get("Authorization")})
        path = urlsplit(self.path).path
        if path == "/slow":
            time.sleep(.3)
        status, body, media = 404, b"missing fixture resource", "text/plain"
        if path in {"/search", "/slow"}:
            status, media = 200, "application/json"
            body = (b'{"inventory":["filtered selection"]}' if "filter" in parse_qs(urlsplit(self.path).query)
                    else b'{"inventory":["alpha","beta","gamma"]}')
        elif path.startswith("/status/"):
            status = int(path.rsplit("/", 1)[-1])
            body = b"restricted fixture response"
        try:
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (OSError, ConnectionError):
            pass

    def log_message(self, *args):
        pass


class PostFuzzingIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.observed = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.server.observed.clear()
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.dict(os.environ, {
            "PYTHON_DOTENV_DISABLED": "1", "LANGSMITH_TRACING": "false",
            "LANGCHAIN_TRACING_V2": "false", "LLM_RESPONSE_LOG_FILE": str(self.directory / "llm.jsonl"),
        }))
        for name in ("circuit_breakers", "llm_limiter", "tarpit_detector"):
            self.enterContext(patch.object(graph, name, deepcopy(getattr(graph, name))))

    def run_case(self, paths, *, last_action="proceed_to_param", http_budget=60):
        actions = {"after_tech_recon": "proceed_to_wordlist",
                   "after_wordlist_gen": "proceed_to_fuzzing", "after_fuzzing": last_action}
        decision = Mock(side_effect=lambda **kw: {"action": actions[kw["decision_point"]], "reasoning": "fixture"})
        engine = SimpleNamespace(llm=None, make_decision=decision, reflect_on_session=lambda _: None)
        self.enterContext(patch.object(graph, "_get_decision_engine", return_value=engine))
        self.enterContext(patch.object(graph.TechReconAgent, "execute", return_value={
            "tech_stack": {}, "discovered_paths": paths}))
        self.enterContext(patch.object(graph.WordlistGenAgent, "execute", return_value={"wordlist": paths}))
        self.enterContext(patch.object(graph.FuzzingAgent, "plan_tool_execution", return_value={
            "selected_tool": "ffuf_fuzzing_tool", "options": {}}))

        def candidates(target_url, endpoints, **kwargs):
            return {"param_results": [{"url": row["url"], "discovered_params": [
                {"name": "filter", "location": "query", "method": "GET"}]} for row in endpoints]}

        assembly = self.enterContext(patch.object(graph.ParamDiscoveryAgent, "_run_param_discovery_internal",
                                                 side_effect=candidates))
        result = graph.run_pipeline(self.origin, {
            "artifact_root": str(self.directory), "headers": {"Authorization": "Bearer " + TOKEN},
            "allowed_origins": [self.origin], "auth_origins": [self.origin],
            "http_rate_limit": 100, "http_max_requests": http_budget, "http_timeout_seconds": .1,
            "pipeline_timeout_seconds": 10, "max_retries": 0, "max_iterations": 5,
            "wordlist": paths, "wordlist_mode": "provided", "run_all_modules": True,
            "fuzzing_options": {"engine": "python_http", "headers": {"Authorization": "Bearer " + TOKEN},
                                "rate_limit": 100, "delay_ms": 0, "threads": 1, "max_requests": 10,
                                "timeout_seconds": .05, "max_scan_seconds": 3,
                                "http_method": "GET", "auto_calibrate": False, "recursion": False,
                                "follow_redirects": False},
            "parameter_options": {"rate_limit": 100, "max_requests": 30, "timeout_seconds": 1,
                                  "max_duration_seconds": 3},
            "soft404_options": {"rate_limit": 100, "max_requests": 15, "timeout_seconds": 1,
                                "max_duration_seconds": 3, "baseline_samples": 2},
        })
        self.assertEqual(result["total_http_requests"], len(self.server.observed))
        self.assertLessEqual(result["total_http_requests"], http_budget)
        self.assertEqual(result["llm_call_count"], 0)
        self.assertTrue(all(row["auth"] == "Bearer " + TOKEN for row in self.server.observed))
        saved = json.loads(Path(result["artifacts"]["result"]).read_text(encoding="utf-8"))
        self.assertEqual(saved, result)
        for artifact in self.directory.rglob("*.json"):
            self.assertNotIn(TOKEN, artifact.read_text(encoding="utf-8"))
        return result, assembly, decision

    def test_success_runs_actual_parameter_and_soft404_requests(self):
        result, assembly, _ = self.run_case(["/search"], last_action="skip_to_filter")
        assembly.assert_called_once()
        self.assertEqual(result["pipeline_status"], "completed", result["error_log"])
        self.assertTrue(result["all_modules_successful"])
        for agent in ("fuzzing", "param_disc", "soft404_filter"):
            self.assertEqual(result["agent_statuses"][agent], "success")
        self.assertEqual([row["name"] for row in result["verified_parameters"]], ["filter"])
        self.assertGreater(result["parameter_stats"]["total_requests"], 0)
        self.assertGreater(result["soft404_stats"]["total_requests"], 0)

    def test_all_timeouts_skip_parameter_and_soft404_does_no_io(self):
        result, assembly, decision = self.run_case(["/slow"])
        assembly.assert_not_called()
        self.assertEqual(decision.call_count, 2)
        self.assertEqual(result["fuzzing_stats"]["attempted_requests"], 1)
        self.assertEqual(result["fuzzing_stats"]["responses_received"], 0)
        self.assertEqual(result["agent_statuses"]["fuzzing"], "failed")
        self.assertEqual(result["agent_statuses"]["param_disc"], "skipped")
        self.assertNotIn("param_disc", result["agent_attempts"])
        self.assertEqual(result["agent_attempts"]["soft404_filter"], 1)
        self.assertEqual(result["soft404_stats"]["total_requests"], 0)
        self.assertEqual(result["soft404_stop_reason"], "upstream_transport_error")
        self.assertEqual(result["pipeline_status"], "partial")

    def test_partial_fuzzing_keeps_response_but_does_not_start_verification(self):
        result, assembly, _ = self.run_case(["/search", "/slow"])
        assembly.assert_not_called()
        self.assertEqual(result["fuzzing_stats"]["attempted_requests"], 2)
        self.assertEqual(result["fuzzing_stats"]["responses_received"], 1)
        self.assertEqual(result["fuzzing_stats"]["network_errors"], 1)
        self.assertEqual(result["agent_statuses"]["fuzzing"], "partial")
        self.assertEqual(result["agent_statuses"]["param_disc"], "skipped")
        self.assertEqual(result["soft404_stats"]["total_requests"], 0)
        self.assertEqual(len(result["unverified_results"]), 2)
        self.assertEqual(result["pipeline_status"], "partial")

    def test_no_eligible_http200_does_not_claim_verifier_success(self):
        for action in ("skip_to_filter", "proceed_to_param"):
            with self.subTest(action=action):
                self.server.observed.clear()
                result, assembly, _ = self.run_case(["/missing"], last_action=action)
                if action == "skip_to_filter":
                    assembly.assert_not_called()
                else:
                    assembly.assert_called_once()
                    self.assertEqual(assembly.call_args.kwargs["endpoints"], [])
                    self.assertEqual(result["parameter_stats"]["total_requests"], 0)
                self.assertEqual(result["total_http_requests"], 1)
                self.assertEqual(result["agent_statuses"]["fuzzing"], "success")
                self.assertEqual(result["agent_statuses"]["param_disc"], "skipped")
                self.assertEqual(result["agent_statuses"]["soft404_filter"], "skipped")
                self.assertEqual(result["soft404_stats"]["total_requests"], 0)
                self.assertFalse(result["all_modules_successful"])
                self.assertEqual(result["verified_results"], [])

    def test_401_403_429_stop_global_runtime_before_downstream_nodes(self):
        for status in (401, 403, 429):
            with self.subTest(status=status):
                self.server.observed.clear()
                result, assembly, decision = self.run_case([f"/status/{status}", "/search"])
                assembly.assert_not_called()
                self.assertEqual(decision.call_count, 2)
                self.assertEqual(result["total_http_requests"], 1)
                self.assertEqual(result["raw_results"][0]["status_code"], status)
                self.assertEqual(result["runtime"]["stop_reason"], f"http_{status}")
                self.assertNotEqual(result["pipeline_status"], "completed")
                for agent in ("param_disc", "soft404_filter"):
                    self.assertEqual(result["agent_statuses"][agent], "pending")
                    self.assertNotIn(agent, result["agent_attempts"])

    def test_request_budget_does_not_restart_downstream_or_exceed_shared_cap(self):
        result, assembly, _ = self.run_case(["/search", "/missing"], http_budget=1)
        assembly.assert_not_called()
        self.assertEqual(result["total_http_requests"], 1)
        self.assertEqual(result["runtime"]["stop_reason"], "http_request_budget")
        self.assertNotEqual(result["pipeline_status"], "completed")

    def test_returned_failed_or_unmeasured_payload_is_never_success(self):
        for agent, execute, node, base in (
            ("param_disc", graph.ParamDiscoveryAgent, graph.run_param_discovery, {"param_results": []}),
            ("soft404_filter", graph.Soft404FilterAgent, graph.run_soft404_filter, {"verified": [], "unverified": []}),
        ):
            for status, performed, requests, expected in (
                ("failed", False, 0, "failed"), ("failed", True, 1, "failed"),
                ("partial", True, 1, "partial"), ("unexpected_status", True, 1, "partial"),
                ("not_checked", False, 0, "skipped"), ("completed", False, 0, "skipped"),
            ):
                with self.subTest(agent=agent, status=status, performed=performed):
                    state = graph.init_state({"target_url": self.origin, "config": {}})
                    payload = dict(base, verification_status=status, verification_performed=performed,
                                   stats={"total_requests": requests})
                    with patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)), \
                         patch.object(execute, "execute", return_value=payload):
                        node(state)
                    self.assertEqual(state["agent_statuses"][agent], expected)


if __name__ == "__main__":
    unittest.main()
