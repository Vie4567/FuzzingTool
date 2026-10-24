"""Managed proxy rotation exercised against real, loopback-only HTTP fixtures.

Only the ProxyScrape download is mocked. Proxy health checks and fuzzing both
traverse forwarding proxies, whose distinct source addresses are seen by the
controlled target. No public proxy or Internet service is contacted.
"""

import copy
import json
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import URLError

from src.agents.fuzzer import FuzzingAgent
from src.coordinator import graph
from src.tools.http_fuzzing import run_http_fuzzing
from src.tools.proxy_profiles import OPERATOR_PROXY_OPTIONS, ProxyProfilePool

try:
    from test_proxy_fuzzing import _ForwardProxyHandler, _TargetHandler
except ModuleNotFoundError:
    from tests.test_proxy_fuzzing import _ForwardProxyHandler, _TargetHandler


_FETCH = "src.tools.proxy_profiles.proxyscrape.fetch_candidates"


class _InspectableTarget(_TargetHandler):
    def do_GET(self):
        self.server.state["request_headers"].append(dict(self.headers.items()))
        super().do_GET()


class _DisconnectingProxy(_ForwardProxyHandler):
    def do_GET(self):
        cutoff = self.server.state.get("disconnect_after")
        if cutoff is not None and len(self.server.state["observed"]) >= cutoff:
            self.server.state["broken"] = True
        super().do_GET()


class ManagedProxyEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), _InspectableTarget)
        cls.target.state = {}
        cls.origin = f"http://127.0.0.1:{cls.target.server_port}"
        cls.proxies = []
        for source_ip in ("127.0.0.2", "127.0.0.3"):
            server = ThreadingHTTPServer(("127.0.0.1", 0), _DisconnectingProxy)
            server.source_ip = source_ip
            server.target_port = cls.target.server_port
            server.state = {}
            cls.proxies.append(server)
        cls.workers = []
        for server in (cls.target, *cls.proxies):
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.workers.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target, *cls.proxies):
            server.shutdown()
            server.server_close()
        for worker in cls.workers:
            worker.join(timeout=3)

    def setUp(self):
        self.target.state.clear()
        self.target.state.update(
            observed=[], request_headers=[], codes=[200],
            redirect_to=self.origin + "/landing",
        )
        for proxy in self.proxies:
            proxy.state.clear()
            proxy.state.update(observed=[], broken=False, authentication_required=False)
        self.proxy_urls = [f"http://127.0.0.1:{proxy.server_port}" for proxy in self.proxies]
        self.profiles = [
            {"id": "egress-a", "url": self.proxy_urls[0]},
            {"id": "egress-b", "url": self.proxy_urls[1]},
        ]

    def run_auto(self, words, **overrides):
        options = {
            "engine": "proxy_http", "proxy_source": "proxyscrape",
            "allowed_origins": [self.origin], "proxy_count": 2,
            "rate_limit": 10, "timeout_seconds": 2, "max_requests": 10,
            "proxy_refresh_seconds": 0,
        }
        options.update(overrides)
        return run_http_fuzzing(self.origin, words, **options)

    def assert_no_target_or_proxy_requests(self):
        self.assertEqual(self.target.state["observed"], [])
        self.assertTrue(all(not proxy.state["observed"] for proxy in self.proxies))

    def test_healthchecked_pool_rotates_real_egress_and_preserves_measured_results(self):
        with patch(_FETCH, return_value=self.proxy_urls) as fetch:
            result = self.run_auto(["one", "two", "three"])
        self.assertTrue(result["completed"], result)
        self.assertFalse(result["simulated"])
        fetch.assert_called_once()
        observed = self.target.state["observed"]
        self.assertEqual([row["path"] for row in observed], ["/robots.txt", "/robots.txt", "/one", "/two", "/three"])
        self.assertEqual([row["peer"] for row in observed[2:]], ["127.0.0.2", "127.0.0.3", "127.0.0.2"])
        self.assertEqual(len(result["health_checks"]), 2)
        self.assertEqual(len(result["results"]), 3)
        self.assertEqual(result["stats"]["total_requests"], 5)
        self.assertEqual(result["stats"]["healthcheck_requests"], 2)
        self.assertEqual(result["stats"]["fuzzing_requests"], 3)
        for row, actual in zip(result["results"], observed[2:]):
            self.assertEqual(row["status_code"], actual["status"])
            self.assertEqual(row["content_length"], len(actual["body"]))
            self.assertGreater(row["response_time"], 0)
            self.assertIsNone(row["egress_ip"])
        self.assertEqual(result["results"][0]["proxy_profile_id"], result["results"][2]["proxy_profile_id"])
        self.assertNotEqual(result["results"][0]["proxy_profile_id"], result["results"][1]["proxy_profile_id"])

    def test_failed_healthcheck_is_removed_before_fuzzing_another_vetted_proxy(self):
        self.proxies[0].state["broken"] = True
        with patch(_FETCH, return_value=self.proxy_urls):
            result = self.run_auto(["one", "two"])
        self.assertTrue(result["completed"], result)
        self.assertEqual(len(result["health_checks"]), 2)
        self.assertIsNone(result["health_checks"][0]["status_code"])
        self.assertTrue(result["health_checks"][0]["error"])
        self.assertEqual([row["peer"] for row in self.target.state["observed"]], ["127.0.0.3"] * 3)
        self.assertEqual([len(proxy.state["observed"]) for proxy in self.proxies], [1, 3])
        self.assertTrue(all(row["proxy_profile_id"] != result["health_checks"][0]["proxy_profile_id"] for row in result["results"]))
        self.assertEqual(result["stats"]["network_errors"], 1)
        states = {row["id"]: row for row in result["proxy_pool"]["profiles"]}
        self.assertEqual(states[result["health_checks"][0]["proxy_profile_id"]]["state"], "excluded")

    def test_healthchecks_consume_shared_request_cap_without_fuzzing_after_cap(self):
        with patch(_FETCH, return_value=self.proxy_urls):
            result = self.run_auto(["one", "two"], max_requests=2)
        self.assertEqual(result["stop_reason"], "max_requests")
        self.assertFalse(result["completed"])
        self.assertEqual(result["results"], [])
        self.assertEqual(len(result["health_checks"]), 2)
        self.assertEqual(result["stats"]["total_requests"], 2)
        self.assertEqual(result["stats"]["fuzzing_requests"], 0)
        self.assertEqual([row["path"] for row in self.target.state["observed"]], ["/robots.txt"] * 2)

    def test_healthchecks_and_fuzzing_share_global_rate_limit(self):
        with patch(_FETCH, return_value=self.proxy_urls):
            result = self.run_auto(["one"], rate_limit=2)
        self.assertTrue(result["completed"], result)
        starts = sorted(row["started"] for proxy in self.proxies for row in proxy.state["observed"])
        self.assertEqual(len(starts), 3)
        self.assertTrue(all(later - earlier >= 0.45 for earlier, later in zip(starts, starts[1:])), starts)

    def test_deadline_before_next_healthcheck_records_stopped_without_quarantining(self):
        with patch(_FETCH, return_value=self.proxy_urls):
            result = self.run_auto(["one"], rate_limit=0.1, max_duration_seconds=3)
        self.assertEqual(result["stop_reason"], "max_duration")
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual(result["results"], [])
        self.assertEqual([len(proxy.state["observed"]) for proxy in self.proxies], [1, 0])
        profiles = result["proxy_pool"]["profiles"]
        self.assertEqual([profile["state"] for profile in profiles], ["healthy", "stopped"])
        self.assertEqual(profiles[1]["reason"], "max_duration")
        self.assertEqual(result["proxy_pool"]["healthy_count"], 1)

    def test_healthchecks_and_source_fetch_receive_no_target_authorization_or_cookie(self):
        headers = {"Authorization": "Bearer UnitTestTargetSecret_591", "Cookie": "session=UnitTestCookie_204", "X-Custom": "fuzz-only"}
        with patch(_FETCH, return_value=self.proxy_urls) as fetch:
            result = self.run_auto(["one"], headers=headers)
        self.assertTrue(result["completed"], result)
        captured = [{key.lower(): value for key, value in row.items()} for row in self.target.state["request_headers"]]
        for row in captured[:2]:
            for name in ("authorization", "cookie", "x-custom"):
                self.assertNotIn(name, row)
        self.assertEqual(captured[2]["authorization"], headers["Authorization"])
        self.assertEqual(captured[2]["cookie"], headers["Cookie"])
        self.assertEqual(captured[2]["x-custom"], headers["X-Custom"])
        source_arguments = repr(fetch.call_args)
        public_output = json.dumps(result)
        for secret in headers.values():
            self.assertNotIn(secret, source_arguments)
            self.assertNotIn(secret, public_output)

    def test_healthcheck_403_stops_before_another_proxy_or_fuzz_request(self):
        self.target.state["codes"] = [403, 200]
        with patch(_FETCH, return_value=self.proxy_urls) as fetch:
            result = self.run_auto(["one", "two"])
        self.assertEqual(result["stop_reason"], "proxy_healthcheck_http_403")
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual(result["results"], [])
        self.assertEqual([len(proxy.state["observed"]) for proxy in self.proxies], [1, 0])
        checked = result["proxy_pool"]["profiles"][0]
        self.assertEqual(checked["state"], "stopped")
        self.assertEqual(checked["reason"], "proxy_healthcheck_http_403")
        fetch.assert_called_once()

    def test_healthcheck_429_stops_before_another_proxy_or_fuzz_request(self):
        self.target.state["codes"] = [429, 200]
        with patch(_FETCH, return_value=self.proxy_urls) as fetch:
            result = self.run_auto(["one", "two"], respect_retry_after=True)
        self.assertEqual(result["stop_reason"], "rate_limited_429")
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual(result["results"], [])
        self.assertEqual([len(proxy.state["observed"]) for proxy in self.proxies], [1, 0])
        checked = result["proxy_pool"]["profiles"][0]
        self.assertEqual(checked["state"], "stopped")
        self.assertEqual(checked["reason"], "rate_limited_429")
        fetch.assert_called_once()

    def test_healthcheck_proxy_auth_failure_stops_without_trying_next_proxy(self):
        self.proxies[0].state["authentication_required"] = True
        with patch(_FETCH, return_value=self.proxy_urls):
            result = self.run_auto(["one"])
        self.assertEqual(result["stop_reason"], "proxy_authentication_required")
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual(result["health_checks"][0]["status_code"], 407)
        self.assertEqual(result["results"], [])
        self.assertEqual([len(proxy.state["observed"]) for proxy in self.proxies], [1, 0])
        checked = result["proxy_pool"]["profiles"][0]
        self.assertEqual(checked["state"], "excluded")
        self.assertEqual(checked["reason"], "proxy_authentication_required")

    def test_fuzz_403_pins_same_proxy_until_existing_consecutive_stop_threshold(self):
        self.target.state["codes"] = [200, 200, 403]
        with patch(_FETCH, return_value=self.proxy_urls) as fetch:
            with patch.object(ProxyProfilePool, "refresh_due", return_value=True):
                result = self.run_auto(["one", "two", "three", "four"], proxy_refresh_seconds=30)
        self.assertEqual(result["stop_reason"], "consecutive_403")
        self.assertEqual(len(result["results"]), 3)
        self.assertEqual([row["peer"] for row in self.target.state["observed"][2:]], ["127.0.0.2"] * 3)
        self.assertEqual(len({row["proxy_profile_id"] for row in result["results"]}), 1)
        self.assertEqual(result["stats"]["total_requests"], 5)
        fetch.assert_called_once()

    def test_fuzz_429_stops_without_using_another_vetted_proxy(self):
        self.target.state["codes"] = [200, 200, 429]
        with patch(_FETCH, return_value=self.proxy_urls) as fetch:
            with patch.object(ProxyProfilePool, "refresh_due", return_value=True):
                result = self.run_auto(["one", "two", "three"], proxy_refresh_seconds=30)
        self.assertEqual(result["stop_reason"], "rate_limited_429")
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual([len(proxy.state["observed"]) for proxy in self.proxies], [2, 1])
        fetch.assert_called_once()

    def test_transport_failure_during_fuzzing_stops_with_no_proxy_failover(self):
        self.proxies[0].state["disconnect_after"] = 1
        with patch(_FETCH, return_value=self.proxy_urls):
            result = self.run_auto(["one", "two"])
        self.assertEqual(result["stop_reason"], "transport_error")
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(len(result["results"]), 1)
        self.assertIsNone(result["results"][0]["status_code"])
        self.assertIsNone(result["results"][0]["content_length"])
        self.assertTrue(result["results"][0]["error"])
        self.assertEqual([len(proxy.state["observed"]) for proxy in self.proxies], [2, 1])
        self.assertEqual([row["path"] for row in self.target.state["observed"]], ["/robots.txt"] * 2)
        states = {row["id"]: row for row in result["proxy_pool"]["profiles"]}
        self.assertEqual(states[result["results"][0]["proxy_profile_id"]]["state"], "excluded")

    def test_invalid_wordlist_or_healthcheck_scope_is_rejected_before_source_fetch(self):
        cases = (
            (["one", "https://outside-scope.invalid/path"], {}),
            (["one"], {"proxy_healthcheck_url": "http://outside-scope.invalid/robots.txt"}),
            (["one"], {"allowed_origins": []}),
        )
        for words, overrides in cases:
            with self.subTest(overrides=overrides, words=words):
                with patch(_FETCH, side_effect=AssertionError("Source I/O must not precede validation")) as fetch:
                    with self.assertRaises(ValueError):
                        self.run_auto(words, **overrides)
                fetch.assert_not_called()
        self.assert_no_target_or_proxy_requests()

    def test_invalid_managed_options_are_rejected_before_source_fetch(self):
        cases = (
            {"proxy_count": 0}, {"proxy_count": 9}, {"proxy_count": 1.5},
            {"proxy_candidate_limit": 0}, {"proxy_candidate_limit": 101},
            {"proxy_check_timeout_seconds": 0}, {"proxy_check_timeout_seconds": 31},
            {"proxy_fetch_timeout_seconds": -1}, {"proxy_fetch_timeout_seconds": 31},
            {"proxy_refresh_seconds": -1}, {"proxy_refresh_seconds": 1},
            {"proxy_source": "unknown"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with patch(_FETCH, side_effect=AssertionError("No source I/O expected")) as fetch:
                    with self.assertRaises(ValueError):
                        self.run_auto(["one"], **overrides)
                fetch.assert_not_called()
        self.assert_no_target_or_proxy_requests()

    def test_empty_wordlist_does_not_fetch_or_healthcheck_any_proxy(self):
        with patch(_FETCH, side_effect=AssertionError("No work requires no proxy I/O")) as fetch:
            result = self.run_auto([])
        self.assertTrue(result["completed"], result)
        self.assertEqual(result["stats"]["total_requests"], 0)
        fetch.assert_not_called()
        self.assert_no_target_or_proxy_requests()

    def test_empty_source_reports_failure_without_direct_fallback(self):
        with patch(_FETCH, return_value=[]):
            result = self.run_auto(["one"])
        self.assertIn(result["stop_reason"], {"proxy_source_error", "proxy_pool_empty"})
        self.assertFalse(result["completed"])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["stats"]["total_requests"], 0)
        self.assert_no_target_or_proxy_requests()

    def test_source_failure_reports_failure_without_target_or_proxy_connections(self):
        with patch(_FETCH, side_effect=URLError("controlled source unavailable")):
            result = self.run_auto(["one"])
        self.assertEqual(result["stop_reason"], "proxy_source_error")
        self.assertFalse(result["completed"])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["stats"]["total_requests"], 0)
        self.assert_no_target_or_proxy_requests()

    def test_elapsed_source_fetch_consumes_scan_deadline_before_healthcheck(self):
        def slow_source(**kwargs):
            time.sleep(0.04)
            return self.proxy_urls

        with patch(_FETCH, side_effect=slow_source):
            result = self.run_auto(["one"], max_duration_seconds=0.02)
        self.assertEqual(result["stop_reason"], "max_duration")
        self.assertEqual(result["stats"]["total_requests"], 0)
        self.assert_no_target_or_proxy_requests()

    def test_refresh_vets_new_candidate_between_fuzz_requests_under_same_budget(self):
        # Provider interval logic is tested at pool level. Here its due signal
        # lets the engine exercise refresh without waiting thirty real seconds.
        with patch(_FETCH, side_effect=[[self.proxy_urls[0]], [self.proxy_urls[1]]]) as fetch:
            with patch.object(ProxyProfilePool, "refresh_due", return_value=True):
                result = self.run_auto(["one", "two"], proxy_count=1, proxy_refresh_seconds=30, max_requests=4)
        self.assertTrue(result["completed"], result)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual([row["path"] for row in self.target.state["observed"]], ["/robots.txt", "/one", "/robots.txt", "/two"])
        self.assertEqual([row["peer"] for row in self.target.state["observed"]], ["127.0.0.2"] * 2 + ["127.0.0.3"] * 2)
        self.assertEqual(result["stats"]["total_requests"], 4)
        self.assertEqual(result["stats"]["healthcheck_requests"], 2)
        self.assertEqual(result["stats"]["fuzzing_requests"], 2)

    def test_refresh_healthcheck_cannot_exceed_remaining_request_budget(self):
        with patch(_FETCH, side_effect=[[self.proxy_urls[0]], [self.proxy_urls[1]]]) as fetch:
            with patch.object(ProxyProfilePool, "refresh_due", return_value=True):
                result = self.run_auto(["one", "two"], proxy_count=1, proxy_refresh_seconds=30, max_requests=3)
        self.assertEqual(result["stop_reason"], "max_requests")
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual([row["path"] for row in self.target.state["observed"]], ["/robots.txt", "/one", "/robots.txt"])

    def test_manual_mode_remains_round_robin_without_source_fetch_or_healthcheck(self):
        with patch(_FETCH, side_effect=AssertionError("Manual mode must not download proxies")) as fetch:
            result = run_http_fuzzing(
                self.origin, ["one", "two", "three"], engine="proxy_http",
                proxy_source="manual", proxy_profiles=self.profiles,
                allowed_origins=[self.origin], rate_limit=10, max_requests=3,
            )
        self.assertTrue(result["completed"], result)
        self.assertEqual([row["peer"] for row in self.target.state["observed"]], ["127.0.0.2", "127.0.0.3", "127.0.0.2"])
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(result.get("health_checks", []), [])
        fetch.assert_not_called()

    def test_explicit_manual_healthcheck_is_in_scope_and_uses_shared_budget(self):
        with patch(_FETCH, side_effect=AssertionError("Manual mode must not download proxies")) as fetch:
            result = run_http_fuzzing(
                self.origin, ["one"], engine="proxy_http", proxy_source="manual",
                proxy_profiles=self.profiles, allowed_origins=[self.origin],
                proxy_healthcheck_url=self.origin + "/health", rate_limit=10,
                max_requests=3,
            )
        self.assertTrue(result["completed"], result)
        self.assertEqual([row["path"] for row in self.target.state["observed"]], ["/health", "/health", "/one"])
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(result["stats"]["healthcheck_requests"], 2)
        fetch.assert_not_called()

    def test_llm_cannot_add_automatic_source_or_healthchecks_to_manual_caller(self):
        agent = FuzzingAgent(llm=None)
        injected_options = {
            "engine": "proxy_http", "proxy_source": "proxyscrape",
            "proxy_count": 1, "proxy_candidate_limit": 1,
            "proxy_check_timeout_seconds": 0.1, "proxy_fetch_timeout_seconds": 0.1,
            "proxy_refresh_seconds": 30,
            "proxy_healthcheck_url": "http://outside-scope.invalid/check",
            "proxy_profiles_env": "UNAPPROVED_PROXY_PROFILES",
        }
        plan = {"selected_tool": "ffuf_fuzzing_tool", "options": injected_options}
        with patch.object(agent, "plan_tool_execution", return_value=plan):
            with patch(_FETCH, side_effect=AssertionError("LLM cannot authorize a provider download")) as fetch:
                result = agent.execute(
                    self.origin, ["one", "two", "three"], use_pattern_engine=False,
                    engine="proxy_http", proxy_profiles=self.profiles,
                    allowed_origins=[self.origin], rate_limit=10, max_requests=3,
                )
        self.assertTrue(result["success"], result)
        self.assertEqual(result["health_checks"], [])
        self.assertEqual([row["peer"] for row in self.target.state["observed"]], ["127.0.0.2", "127.0.0.3", "127.0.0.2"])
        forwarded = result["tools_executed"][0]["options"]
        for key in injected_options.keys() - {"engine"}:
            self.assertNotIn(key, forwarded)
        fetch.assert_not_called()
        self.assertEqual(plan["options"], injected_options)

    def test_llm_auto_source_cannot_replace_missing_caller_profiles(self):
        agent = FuzzingAgent(llm=None)
        plan = {"selected_tool": "ffuf_fuzzing_tool", "options": {
            "proxy_source": "proxyscrape", "proxy_count": 2,
            "proxy_healthcheck_url": self.origin + "/health",
        }}
        with patch.object(agent, "plan_tool_execution", return_value=plan):
            with patch(_FETCH, side_effect=AssertionError("LLM cannot authorize a provider download")) as fetch:
                result = agent.execute(
                    self.origin, ["one"], use_pattern_engine=False,
                    engine="proxy_http", allowed_origins=[self.origin],
                )
        self.assertFalse(result["success"], result)
        self.assertEqual(result["results"], [])
        fetch.assert_not_called()
        self.assert_no_target_or_proxy_requests()

    def test_explicit_caller_managed_options_win_over_llm_routing_plan(self):
        agent = FuzzingAgent(llm=None)
        caller_options = {
            "engine": "proxy_http", "proxy_source": "manual",
            "proxy_profiles": self.profiles, "allowed_origins": [self.origin],
            "proxy_count": 1, "proxy_candidate_limit": 4,
            "proxy_check_timeout_seconds": 2, "proxy_fetch_timeout_seconds": 2,
            "proxy_refresh_seconds": 0, "proxy_healthcheck_url": self.origin + "/health",
            "rate_limit": 10, "max_requests": 2,
        }
        snapshot = copy.deepcopy(caller_options)
        plan = {"selected_tool": "ffuf_fuzzing_tool", "options": {
            "engine": "ffuf_cli", "proxy_source": "proxyscrape",
            "proxy_count": 8, "proxy_candidate_limit": 100,
            "proxy_check_timeout_seconds": 0.01, "proxy_fetch_timeout_seconds": 0.01,
            "proxy_refresh_seconds": 30,
            "proxy_healthcheck_url": "http://outside-scope.invalid/check",
            "proxy_profiles_env": "UNAPPROVED_PROXY_PROFILES",
            "allowed_origins": ["http://outside-scope.invalid"],
        }}
        with patch.object(agent, "plan_tool_execution", return_value=plan):
            with patch(_FETCH, side_effect=AssertionError("Caller selected manual profiles")) as fetch:
                result = agent.execute(self.origin, ["one"], use_pattern_engine=False, **caller_options)
        self.assertTrue(result["success"], result)
        self.assertEqual([row["path"] for row in self.target.state["observed"]], ["/health", "/one"])
        self.assertEqual([row["peer"] for row in self.target.state["observed"]], ["127.0.0.2"] * 2)
        forwarded = result["tools_executed"][0]["options"]
        for key in OPERATOR_PROXY_OPTIONS & caller_options.keys() - {"proxy_profiles"}:
            self.assertEqual(forwarded[key], caller_options[key])
        self.assertNotIn("proxy_profiles_env", forwarded)
        self.assertEqual(caller_options, snapshot)
        fetch.assert_not_called()

    def test_per_profile_metrics_account_for_healthchecks_responses_and_failures(self):
        self.proxies[0].state["broken"] = True
        with patch(_FETCH, return_value=self.proxy_urls):
            result = self.run_auto(["one", "two"])
        metrics = result["stats"]["proxy_profiles"]
        if isinstance(metrics, list):
            metrics = {row["proxy_profile_id"]: row for row in metrics}
        failed_id = result["health_checks"][0]["proxy_profile_id"]
        healthy_id = result["health_checks"][1]["proxy_profile_id"]
        self.assertEqual(metrics[failed_id]["requests"], 1)
        self.assertEqual(metrics[failed_id]["responses"], 0)
        self.assertEqual(metrics[failed_id]["network_errors"], 1)
        self.assertEqual(metrics[failed_id]["error_rate"], 1.0)
        self.assertEqual(metrics[healthy_id]["requests"], 3)
        self.assertEqual(metrics[healthy_id]["responses"], 3)
        self.assertEqual(metrics[healthy_id]["network_errors"], 0)
        self.assertEqual(metrics[healthy_id]["error_rate"], 0)
        self.assertEqual(metrics[healthy_id]["status_codes"], {"200": 3})
        self.assertGreater(metrics[healthy_id]["avg_response_time"], 0)
        self.assertEqual(sum(row["requests"] for row in metrics.values()), result["stats"]["total_requests"])


class ManagedProxyCoordinatorProvenanceTests(unittest.TestCase):
    """Source, health-check scope and pool limits originate with the operator."""

    def routing_options(self):
        return {
            "engine": "proxy_http", "proxy_source": "proxyscrape",
            "proxy_count": 2, "proxy_candidate_limit": 20,
            "proxy_check_timeout_seconds": 2, "proxy_fetch_timeout_seconds": 3,
            "proxy_refresh_seconds": 60,
            "proxy_healthcheck_url": "http://127.0.0.1:8765/health",
            "allowed_origins": ["http://127.0.0.1:8765"],
        }

    def run_coordinator(self, manager_options, operator_options=None):
        state = {
            "target_url": "http://127.0.0.1:8765", "wordlist": ["one"],
            "agent_statuses": {"fuzzing": "pending"}, "audit_log": [], "error_log": [],
            "config": {"fuzzing_options": operator_options or {}},
            "_config_adjustments": manager_options, "total_http_requests": 0,
            "circuit_breaker_state": {}, "discovered_paths": [], "js_endpoints": [],
        }
        measurement = {
            "success": True, "partial": False, "simulated": False,
            "engine": "python_http", "stop_reason": "completed", "results": [],
            "stats": {"total_requests": 0, "avg_response_time": None},
        }
        with patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)):
            with patch.object(FuzzingAgent, "execute", return_value=measurement) as execute:
                graph.run_fuzzing(state)
        self.assertEqual(state["agent_statuses"]["fuzzing"], "success", state)
        return state, execute.call_args.kwargs

    def test_manager_cannot_supply_automatic_source_health_url_or_pool_limits(self):
        manager_options = self.routing_options()
        manager_options.update({
            "proxy_profiles": [{"id": "manager", "url": "http://127.0.0.1:9100"}],
            "proxy_profiles_env": "UNAPPROVED_PROXY_PROFILES", "rate_limit": 2,
        })
        snapshot = copy.deepcopy(manager_options)
        state, forwarded = self.run_coordinator(manager_options)
        self.assertEqual(set(manager_options) & OPERATOR_PROXY_OPTIONS, OPERATOR_PROXY_OPTIONS)
        for key in OPERATOR_PROXY_OPTIONS:
            self.assertNotIn(key, forwarded)
            self.assertNotIn(key, state["audit_log"][0]["config_adjustments"])
        self.assertEqual(forwarded["rate_limit"], 2)
        self.assertEqual(manager_options, snapshot)

    def test_operator_automatic_source_and_pool_settings_reach_agent_unchanged(self):
        operator_options = self.routing_options()
        operator_snapshot = copy.deepcopy(operator_options)
        manager_options = {
            "engine": "ffuf_cli", "proxy_source": "manual", "proxy_count": 8,
            "proxy_candidate_limit": 100, "proxy_check_timeout_seconds": 30,
            "proxy_fetch_timeout_seconds": 30, "proxy_refresh_seconds": 300,
            "proxy_healthcheck_url": "http://outside-scope.invalid/check",
            "allowed_origins": ["http://outside-scope.invalid"],
            "proxy_profiles_env": "UNAPPROVED_PROXY_PROFILES",
        }
        state, forwarded = self.run_coordinator(manager_options, operator_options)
        for key, value in operator_options.items():
            self.assertEqual(forwarded[key], value)
            self.assertEqual(state["audit_log"][0]["config_adjustments"][key], value)
        self.assertNotIn("proxy_profiles_env", forwarded)
        self.assertEqual(operator_options, operator_snapshot)


if __name__ == "__main__":
    unittest.main()
