"""Coordinator keeps real measurements and respects prior scan stop/routing."""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import Mock, patch

from src.agents.soft404_filter import soft404_options_from_config
from src.coordinator import graph


_AUTH = "Bearer soft404_coordinator_fixture_token"
_SHELL = (b"<html><head><title>Application shell</title></head><body><div id='root'></div>"
          b"<script src='/bundle.js'></script></body></html>")
_SHELL = _SHELL + b" " * (2219 - len(_SHELL))
_REAL = b'{"records":[{"id":7,"name":"fixture inventory"}],"count":1}'


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append({"path": self.path, "auth": self.headers.get("Authorization")})
        if self.headers.get("Authorization") != _AUTH:
            self.send_response(401)
            body, media = b"Authentication required", "text/plain"
        else:
            self.send_response(200)
            body, media = (_REAL, "application/json") if self.path == "/real" else (_SHELL, "text/html")
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Soft404CoordinatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.observed = []
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)

    def setUp(self):
        self.server.observed.clear()
        self.enterContext(patch.object(graph, "circuit_breakers", {"soft404": Mock()}))

    def state(self):
        return {"target_url": self.origin, "agent_statuses": {}, "audit_log": [], "error_log": [],
                "total_http_requests": 10,
                "config": {"fuzzing_options": {"headers": {"Authorization": _AUTH}, "rate_limit": 100},
                           "soft404_options": {"rate_limit": 100}},
                "fuzzing_execution": {"engine": "python_http", "stop_reason": "completed", "success": True,
                                      "verification_context": {"route": "direct", "auth_matches_operator": True,
                                                               "rate_limit": 100, "delay_ms": 0, "http_method": "GET"}},
                "raw_results": [
                    {"url": self.origin + "/missing", "status_code": 200, "content_length": 2219, "response_time": 0.123},
                    {"url": self.origin + "/real", "status_code": 200, "content_length": len(_REAL), "response_time": 0.456},
                    {"url": self.origin + "/", "status_code": 200, "content_length": 2219, "response_time": 0.789},
                ],
                "param_results": [{"url": self.origin + "/real", "result_kind": "parameter_candidates",
                                   "status_code": None, "discovered_params": [{"name": "page"}]}]}

    def test_real_filter_classifies_fallback_without_promoting_parameter_guesses(self):
        state = self.state()
        original = deepcopy(state["raw_results"])
        with patch.object(graph, "_get_decision_engine", side_effect=AssertionError("No LLM needed")):
            graph.run_soft404_filter(state)
        self.assertEqual(state["error_log"], [])
        self.assertEqual(state["raw_results"], original)
        self.assertEqual([row["url"] for row in state["verified_results"]], [self.origin + "/real"])
        self.assertEqual([row["url"] for row in state["false_positives"]], [self.origin + "/missing"])
        self.assertEqual(len(state["unverified_results"]), 2)
        self.assertEqual(state["false_positives"][0]["content_length"], 2219)
        self.assertEqual(state["false_positives"][0]["response_time"], 0.123)
        self.assertTrue(all(row["auth"] == _AUTH for row in self.server.observed))
        count = state["soft404_stats"]["total_requests"]
        self.assertEqual(count, len(self.server.observed))
        self.assertEqual(state["total_http_requests"], 10 + count)
        self.assertEqual(state["soft404_signals"][0]["count"], 2)
        self.assertNotIn(_AUTH, json.dumps({key: value for key, value in state.items() if key != "config"}))

    def test_upstream_stop_and_proxy_route_never_restart_as_direct_verification(self):
        for execution in (
            {"stop_reason": "rate_limited_429", "partial": True},
            {"stop_reason": "proxy_connect_http_403", "partial": True},
            {"stop_reason": "max_requests", "partial": True},
            {"engine": "proxy_http", "stop_reason": "completed", "success": True},
            {"engine": "loopback_lab", "stop_reason": "completed", "success": True},
            {"engine": "python_http", "stop_reason": "completed", "success": True},
            {},
            {"engine": "python_http", "simulated": True, "stop_reason": "completed"},
        ):
            with self.subTest(execution=execution):
                state = self.state()
                state["fuzzing_execution"] = execution
                graph.run_soft404_filter(state)
                self.assertEqual(state["verified_results"], [])
                self.assertEqual(state["false_positives"], [])
                self.assertEqual(len(state["unverified_results"]), 4)
                self.assertEqual(state["soft404_stats"]["total_requests"], 0)
                self.assertEqual(state["total_http_requests"], 10)
        self.assertEqual(self.server.observed, [])

    def test_options_inherit_auth_scope_tls_and_cannot_raise_scan_rate(self):
        config = {"recon_options": {"bearer_token": "recon-secret", "verify_ssl": True,
                                     "allowed_origins": [self.origin], "auth_origins": [self.origin]},
                  "fuzzing_options": {"rate_limit": 2, "delay_ms": 1000,
                                      "headers": {"Authorization": _AUTH}},
                  "soft404_options": {"rate_limit": 100}}
        original = deepcopy(config)
        options = soft404_options_from_config(config)
        self.assertEqual(options["headers"], {"Authorization": _AUTH})
        self.assertEqual(options["allowed_origins"], [self.origin])
        self.assertEqual(options["auth_origins"], [self.origin])
        self.assertEqual(options["rate_limit"], 1)
        self.assertTrue(options["verify_ssl"])
        self.assertEqual(config, original)
        options = soft404_options_from_config({"recon_options": {"bearer_token": "old"},
                                              "soft404_options": {"headers": {"Authorization": _AUTH}}})
        self.assertEqual(options["headers"], {"Authorization": _AUTH})

    def test_runtime_transport_context_gates_auth_method_and_rate(self):
        execution = self.state()["fuzzing_execution"]
        config = self.state()["config"]
        execution["verification_context"].update(rate_limit=0.5, delay_ms=3000)
        options = soft404_options_from_config(config, execution)
        self.assertAlmostEqual(options["rate_limit"], 1 / 3)
        execution["verification_context"]["auth_matches_operator"] = False
        self.assertEqual(soft404_options_from_config(config, execution)["stop_reason"], "authentication_context_unavailable")
        execution["verification_context"].update(auth_matches_operator=True, http_method="POST")
        self.assertEqual(soft404_options_from_config(config, execution)["stop_reason"], "request_context_not_replayable")
        self.assertEqual(soft404_options_from_config({"recon_options": {
            "account": {"username": "fixture", "password": "fixture"},
            "headers": {"User-Agent": "fixture"}}})["stop_reason"], "authentication_context_unavailable")

    def test_failure_clears_stale_verification_and_masks_error_credentials(self):
        state = self.state()
        state["raw_results"][0].update(verification="genuine", verification_performed=True,
                                       similarity_to_baseline=0.1, verification_evidence={"old": True})
        state["false_positives"] = [{"old": True}]
        state["baseline_signature"] = {"old": True}
        original = deepcopy(state["raw_results"])
        with patch.object(graph.Soft404FilterAgent, "execute", side_effect=RuntimeError(_AUTH)):
            graph.run_soft404_filter(state)
        self.assertEqual(state["verification_status"], "failed")
        self.assertEqual(state["raw_results"], original)
        self.assertEqual(state["verified_results"], [])
        self.assertEqual(state["false_positives"], [])
        self.assertIsNone(state["baseline_signature"])
        self.assertFalse(state["unverified_results"][0]["verification_performed"])
        self.assertNotIn("similarity_to_baseline", state["unverified_results"][0])
        self.assertNotIn(_AUTH, str(state["error_log"]))

    def test_model_headers_do_not_become_operator_auth_context(self):
        state = self.state()
        state.update(wordlist=["/missing"], circuit_breaker_state={},
                     _config_adjustments={"headers": {"Authorization": _AUTH}})
        state["config"]["fuzzing_options"].pop("headers")
        payload = {"engine": "python_http", "success": True, "partial": False,
                   "stop_reason": "completed", "results": state["raw_results"],
                   "stats": {"total_requests": 3},
                   "verification_context": {"route": "direct", "auth_matches_operator": True,
                                            "operator_headers_configured": True, "rate_limit": 1}}
        with patch.object(graph, "_get_decision_engine", return_value=None), \
                patch.object(graph, "circuit_breakers", {"fuzzing": Mock(), "soft404": Mock()}), \
                patch.object(graph.FuzzingAgent, "execute", return_value=payload):
            graph.run_fuzzing(state)
            graph.run_soft404_filter(state)
        self.assertFalse(state["fuzzing_execution"]["verification_context"]["auth_matches_operator"])
        self.assertEqual(state["soft404_stats"]["total_requests"], 0)
        self.assertEqual(self.server.observed, [])


if __name__ == "__main__":
    unittest.main()
