"""Controlled forward proxies prove rotation, measurements and shared stop rules.

All sockets in this module remain on loopback. The two proxy servers bind their
upstream sockets to different loopback addresses, so the target can independently
confirm which egress handled each request without an external IP lookup.
"""

import base64
import copy
import json
import logging
import os
import socket
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit

logging.getLogger("sentinel").addHandler(logging.NullHandler())

from src.agents.fuzzer import FuzzingAgent
from src.coordinator import graph
from src.tools.ffuf_helper import FfufToolHelper
from src.tools.http_fuzzing import run_http_fuzzing


class _TargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        state = self.server.state
        index = len(state["observed"])
        codes = state["codes"]
        status = codes[min(index, len(codes) - 1)]
        if self.path == "/redirect":
            status = 302
        body = f"peer={self.client_address[0]};path={self.path};status={status}".encode("ascii")
        state["observed"].append({
            "peer": self.client_address[0], "path": self.path,
            "started": time.perf_counter(), "status": status,
            "body": body, "proxy_authorization": self.headers.get("Proxy-Authorization"),
        })
        self.send_response(status)
        if status == 302:
            self.send_header("Location", state["redirect_to"])
        if status == 429:
            self.send_header("Retry-After", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ForwardProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        state = self.server.state
        state["observed"].append({
            "url": self.path, "started": time.perf_counter(),
            "proxy_authorization": self.headers.get("Proxy-Authorization"),
        })
        if state["broken"]:
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return
        if state["authentication_required"]:
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="controlled-lab"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        parts = urlsplit(self.path)
        # This test proxy cannot forward to any other host or service.
        if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.port != self.server.target_port:
            self.send_error(502, "Test proxy accepts only its controlled target")
            return
        upstream = HTTPConnection(
            "127.0.0.1", self.server.target_port, timeout=3,
            source_address=(self.server.source_ip, 0),
        )
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        excluded = {"proxy-authorization", "proxy-connection", "connection", "host"}
        headers = {name: value for name, value in self.headers.items() if name.lower() not in excluded}
        try:
            upstream.request("GET", path, headers=headers)
            response = upstream.getresponse()
            body = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {"connection", "transfer-encoding", "server", "date", "content-length"}:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            upstream.close()


class ProxyFuzzingIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        cls.target.state = {}
        cls.origin = f"http://127.0.0.1:{cls.target.server_port}"
        cls.proxies = []
        for source_ip in ("127.0.0.2", "127.0.0.3"):
            server = ThreadingHTTPServer(("127.0.0.1", 0), _ForwardProxyHandler)
            server.source_ip = source_ip
            server.target_port = cls.target.server_port
            server.state = {}
            cls.proxies.append(server)
        cls.workers = []
        for server in [cls.target, *cls.proxies]:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.workers.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in [cls.target, *cls.proxies]:
            server.shutdown()
            server.server_close()
        for worker in cls.workers:
            worker.join(timeout=3)

    def setUp(self):
        self.target.state.clear()
        self.target.state.update(observed=[], codes=[200], redirect_to=self.origin + "/landing")
        for proxy in self.proxies:
            proxy.state.clear()
            proxy.state.update(observed=[], broken=False, authentication_required=False)
        self.profiles = [
            {"id": "egress-a", "url": f"http://127.0.0.1:{self.proxies[0].server_port}"},
            {"id": "egress-b", "url": f"http://127.0.0.1:{self.proxies[1].server_port}"},
        ]

    def run_engine(self, words, **options):
        config = {
            "engine": "proxy_http", "proxy_profiles": self.profiles,
            "allowed_origins": [self.origin], "rate_limit": 10,
            "max_requests": 10, "timeout_seconds": 2,
        }
        config.update(options)
        return run_http_fuzzing(self.origin, words, **config)

    def assert_no_http(self):
        self.assertEqual(self.target.state["observed"], [])
        self.assertTrue(all(not server.state["observed"] for server in self.proxies))

    def test_agent_rotates_real_proxy_egress_and_preserves_measurements(self):
        self.target.state["codes"] = [200, 201, 404]
        # Ambient NO_PROXY must never silently convert this to a direct request.
        with patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"}):
            result = FuzzingAgent(llm=None).execute(
                self.origin, ["one", "two", "three"], use_pattern_engine=False,
                engine="proxy_http", proxy_profiles=self.profiles,
                allowed_origins=[self.origin], rate_limit=2, delay_ms=0,
                max_requests=3,
            )
        self.assertTrue(result["success"], result)
        self.assertEqual(result["engine"], "proxy_http")
        self.assertFalse(result["simulated"])
        observed = self.target.state["observed"]
        self.assertEqual([row["peer"] for row in observed], ["127.0.0.2", "127.0.0.3", "127.0.0.2"])
        self.assertEqual([row["proxy_profile_id"] for row in result["results"]], ["egress-a", "egress-b", "egress-a"])
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(result["stats"]["status_codes"], {"200": 1, "201": 1, "404": 1})
        self.assertEqual([len(server.state["observed"]) for server in self.proxies], [2, 1])
        for row, actual in zip(result["results"], observed):
            self.assertEqual(row["status_code"], actual["status"])
            self.assertEqual(row["content_length"], len(actual["body"]))
            self.assertGreater(row["response_time"], 0)
            self.assertIsNone(row.get("egress_ip"))
            self.assertIsNone(actual["proxy_authorization"])

    def test_rate_limit_is_global_across_profiles(self):
        result = self.run_engine(["one", "two", "three"], rate_limit=2)
        self.assertTrue(result["completed"], result)
        starts = sorted(row["started"] for server in self.proxies for row in server.state["observed"])
        self.assertEqual(len(starts), 3)
        self.assertTrue(all(later - earlier >= 0.45 for earlier, later in zip(starts, starts[1:])), starts)

    def test_request_cap_is_shared_and_does_not_restart_per_profile(self):
        result = self.run_engine(["one", "two", "three", "four", "five"], max_requests=3)
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(len(self.target.state["observed"]), 3)
        self.assertEqual([len(server.state["observed"]) for server in self.proxies], [2, 1])
        self.assertEqual(result["stop_reason"], "max_requests")
        self.assertFalse(result["completed"])

    def test_redirect_is_recorded_without_following_it(self):
        self.target.state["redirect_to"] = "http://outside-scope.invalid/landing"
        result = self.run_engine(["redirect"])
        self.assertEqual(result["results"][0]["status_code"], 302)
        self.assertEqual(result["results"][0]["redirect_url"], "http://outside-scope.invalid/landing")
        self.assertEqual(len(self.target.state["observed"]), 1)
        self.assertEqual(sum(len(server.state["observed"]) for server in self.proxies), 1)

    def test_429_stops_all_profiles_without_using_next_egress(self):
        self.target.state["codes"] = [429, 200]
        result = self.run_engine(["one", "two", "three"], respect_retry_after=True)
        self.assertEqual(result["stop_reason"], "rate_limited_429")
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual([len(server.state["observed"]) for server in self.proxies], [1, 0])

    def test_consecutive_403_counter_is_global_across_profiles(self):
        self.target.state["codes"] = [403]
        result = self.run_engine(["one", "two", "three", "four"])
        self.assertEqual(result["stop_reason"], "consecutive_403")
        self.assertEqual(result["stats"]["total_requests"], 3)
        # A 403 pins the route until success or the existing three-403 stop.
        # Do not choose another source IP to continue after an access denial.
        self.assertEqual([row["peer"] for row in self.target.state["observed"]], ["127.0.0.2", "127.0.0.2", "127.0.0.2"])

    def test_global_stop_rules_cannot_be_disabled_or_delayed(self):
        for override in ({"stop_on_429": False}, {"stop_on_block": False}, {"consecutive_403_limit": 99}):
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    self.run_engine(["one"], **override)
        self.assert_no_http()

    def test_transport_error_stops_without_failover_or_direct_retry(self):
        self.proxies[0].state["broken"] = True
        result = self.run_engine(["one", "two", "three"])
        self.assertEqual(result["stop_reason"], "transport_error")
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual([len(server.state["observed"]) for server in self.proxies], [1, 0])
        self.assertEqual(self.target.state["observed"], [])
        self.assertIsNone(result["results"][0]["status_code"])
        self.assertIsNone(result["results"][0]["content_length"])
        self.assertTrue(result["results"][0]["error"])

    def test_proxy_authentication_failure_stops_without_trying_another_profile(self):
        self.proxies[0].state["authentication_required"] = True
        result = self.run_engine(["one", "two"])
        self.assertEqual(result["stop_reason"], "proxy_authentication_required")
        self.assertEqual(result["results"][0]["status_code"], 407)
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual([len(server.state["observed"]) for server in self.proxies], [1, 0])
        self.assertEqual(self.target.state["observed"], [])

    def test_credentials_are_sent_only_to_proxy_and_redacted_from_agent_result_and_logs(self):
        username, password = "LabProxyUser_931", "LabProxySecret_854"
        profile_url = f"http://{username}:{password}@127.0.0.1:{self.proxies[0].server_port}"
        with self.assertLogs("sentinel", level="INFO") as captured:
            result = FuzzingAgent(llm=None).execute(
                self.origin, ["one"], use_pattern_engine=False,
                engine="proxy_http", proxy_profiles=[{"id": "authenticated", "url": profile_url}],
                allowed_origins=[self.origin], max_requests=1, rate_limit=2,
            )
        self.assertTrue(result["success"], result)
        authorization = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.assertEqual(self.proxies[0].state["observed"][0]["proxy_authorization"], authorization)
        self.assertIsNone(self.target.state["observed"][0]["proxy_authorization"])
        public_output = json.dumps(result) + "\n".join(captured.output)
        for secret in (username, password, profile_url, authorization):
            self.assertNotIn(secret, public_output)

    def test_environment_profiles_are_loaded_and_redacted_on_transport_error(self):
        username, password = "EnvProxyUser_145", "EnvProxySecret_783"
        profile_url = f"http://{username}:{password}@127.0.0.1:{self.proxies[0].server_port}"
        self.proxies[0].state["broken"] = True
        with patch.dict(os.environ, {"SENTINEL_TEST_PROXY_PROFILES": json.dumps([
            {"id": "environment-egress", "url": profile_url},
        ])}):
            with self.assertLogs("sentinel", level="INFO") as captured:
                result = FuzzingAgent(llm=None).execute(
                    self.origin, ["one", "two"], use_pattern_engine=False,
                    engine="proxy_http", proxy_profiles_env="SENTINEL_TEST_PROXY_PROFILES",
                    allowed_origins=[self.origin], max_requests=2,
                )
        self.assertFalse(result["success"])
        self.assertEqual(result["stop_reason"], "transport_error")
        self.assertEqual(result["results"][0]["proxy_profile_id"], "environment-egress")
        public_output = json.dumps(result) + "\n".join(captured.output)
        for secret in (username, password, profile_url):
            self.assertNotIn(secret, public_output)

    def test_missing_or_mismatched_scope_is_rejected_before_any_connection(self):
        for allowed in (None, [], ["https://127.0.0.1"], [self.origin + "/a-path"]):
            with self.subTest(allowed=allowed):
                options = {"engine": "proxy_http", "proxy_profiles": self.profiles}
                if allowed is not None:
                    options["allowed_origins"] = allowed
                with patch("http.client.HTTPConnection.connect", side_effect=AssertionError("No network expected")) as connect:
                    with self.assertRaises(ValueError):
                        run_http_fuzzing(self.origin, ["one"], **options)
                connect.assert_not_called()
        self.assert_no_http()

    def test_all_candidates_are_validated_before_first_request(self):
        with patch("http.client.HTTPConnection.connect", side_effect=AssertionError("No network expected")) as connect:
            with self.assertRaises(ValueError):
                self.run_engine(["valid-first", "http://outside-scope.invalid/escape"])
        connect.assert_not_called()
        self.assert_no_http()

    def test_proxy_profiles_require_explicit_engine_in_native_entry_point(self):
        with patch("http.client.HTTPConnection.connect", side_effect=AssertionError("No network expected")) as connect:
            with self.assertRaises(ValueError):
                run_http_fuzzing(self.origin, ["one"], proxy_profiles=self.profiles, allowed_origins=[self.origin])
        connect.assert_not_called()
        self.assert_no_http()

    def test_existing_engines_reject_new_proxy_options_before_binary_or_network_selection(self):
        helper = FfufToolHelper()
        for engine in ("auto", "ffuf_cli", "python_http"):
            for option in (
                {"proxy_profiles": self.profiles},
                {"proxy_profiles_env": "SENTINEL_TEST_PROXY_PROFILES"},
                {"allowed_origins": [self.origin]},
            ):
                with self.subTest(engine=engine, option=next(iter(option))):
                    with patch.object(helper, "resolve_binary", side_effect=AssertionError("No binary selection expected")):
                        result = helper.run(target_url=self.origin, wordlist=["one"], engine=engine, **option)
                    self.assertFalse(result.success)
                    self.assertEqual(result.result_data["results"], [])
                    self.assertIn("proxy_http", result.error_message)
        self.assert_no_http()

    def test_llm_cannot_enable_proxy_mode(self):
        agent = FuzzingAgent(llm=None)
        plan = {"selected_tool": "ffuf_fuzzing_tool", "options": {
            "engine": "proxy_http", "proxy_profiles": self.profiles, "allowed_origins": [self.origin],
        }}
        with patch.object(agent, "plan_tool_execution", return_value=plan):
            with patch.object(agent.tool_registry, "execute_tool", side_effect=AssertionError("No tool execution expected")) as execute:
                with self.assertRaises(ValueError):
                    agent.execute(self.origin, ["one"], use_pattern_engine=False)
        execute.assert_not_called()
        self.assert_no_http()

    def test_llm_cannot_supply_proxy_profiles_or_scope_for_caller_selected_engine(self):
        for caller_config in (
            {"engine": "proxy_http", "allowed_origins": [self.origin]},
            {"engine": "proxy_http", "proxy_profiles": self.profiles},
        ):
            agent = FuzzingAgent(llm=None)
            plan = {"selected_tool": "ffuf_fuzzing_tool", "options": {
                "engine": "proxy_http", "proxy_profiles": self.profiles, "allowed_origins": [self.origin],
            }}
            with self.subTest(caller_config=list(caller_config)):
                with patch.object(agent, "plan_tool_execution", return_value=plan):
                    result = agent.execute(self.origin, ["one"], use_pattern_engine=False, **caller_config)
                self.assertFalse(result["success"], result)
                self.assertEqual(result["results"], [])
        self.assert_no_http()


class ProxyCoordinatorProvenanceTests(unittest.TestCase):
    """Manager plans cannot become operator authorization or leak routing secrets."""

    def state_for(self, manager_options, operator_options=None):
        return {
            "target_url": "http://127.0.0.1:8765", "wordlist": ["one"],
            "agent_statuses": {"fuzzing": "pending"}, "audit_log": [], "error_log": [],
            "config": {"fuzzing_options": operator_options or {}},
            "_config_adjustments": manager_options, "total_http_requests": 0,
            "circuit_breaker_state": {}, "discovered_paths": [], "js_endpoints": [],
        }

    def completed_measurement(self):
        return {
            "success": True, "partial": False, "simulated": False,
            "engine": "python_http", "stop_reason": "completed", "results": [],
            "stats": {"total_requests": 0, "avg_response_time": None},
        }

    def test_manager_cannot_select_transport_or_supply_profiles_and_scope(self):
        for manager_engine in ("proxy_http", "python_http"):
            manager_options = {
                "engine": manager_engine, "rate_limit": 2,
                "proxy_profiles": [{"id": "manager", "url": "http://manager:Secret_194@127.0.0.1:9000"}],
                "proxy_profiles_env": "MANAGER_PROXY_ENV", "allowed_origins": ["http://outside-scope.invalid"],
            }
            state = self.state_for(manager_options)
            with self.subTest(manager_engine=manager_engine):
                with patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)):
                    with patch.object(FuzzingAgent, "execute", return_value=self.completed_measurement()) as execute:
                        graph.run_fuzzing(state)
                forwarded = execute.call_args.kwargs
                for protected in ("engine", "proxy_profiles", "proxy_profiles_env", "allowed_origins"):
                    self.assertNotIn(protected, forwarded)
                    self.assertNotIn(protected, state["audit_log"][0]["config_adjustments"])
                self.assertEqual(forwarded["rate_limit"], 2)
                self.assertNotIn("Secret_194", json.dumps(state["audit_log"]))
                self.assertEqual(manager_options["engine"], manager_engine)

    def test_operator_routing_reaches_agent_and_audit_redacts_private_configuration(self):
        secret_url = "http://operator_user:OperatorSecret_604@127.0.0.1:9100"
        operator_options = {
            "engine": "proxy_http", "proxy_profiles": [{"id": "operator", "url": secret_url}],
            "allowed_origins": ["http://127.0.0.1:8765"], "rate_limit": 2,
        }
        snapshot = copy.deepcopy(operator_options)
        manager_options = {
            "engine": "ffuf_cli", "proxy_profiles_env": "UNAPPROVED_PROXIES",
            "allowed_origins": ["http://outside-scope.invalid"], "rate_limit": 9,
        }
        state = self.state_for(manager_options, operator_options)
        with patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)):
            with patch.object(FuzzingAgent, "execute", return_value=self.completed_measurement()) as execute:
                graph.run_fuzzing(state)
        forwarded = execute.call_args.kwargs
        for key, value in operator_options.items():
            self.assertEqual(forwarded[key], value)
        self.assertNotIn("proxy_profiles_env", forwarded)
        audit_config = state["audit_log"][0]["config_adjustments"]
        self.assertEqual(audit_config["proxy_profiles"], "<redacted>")
        self.assertEqual(audit_config["allowed_origins"], operator_options["allowed_origins"])
        for secret in (secret_url, "operator_user", "OperatorSecret_604", "UNAPPROVED_PROXIES"):
            self.assertNotIn(secret, json.dumps(state["audit_log"]))
        self.assertEqual(operator_options, snapshot)

    def test_pipeline_returns_redacted_copies_and_preserves_operator_configuration(self):
        secret_url = "http://pipeline_user:PipelineSecret_820@127.0.0.1:9200"
        operator_config = {"fuzzing_options": {
            "engine": "proxy_http", "proxy_profiles": [{"id": "private", "url": secret_url}],
            "allowed_origins": ["http://127.0.0.1:8765"], "max_requests": 3,
        }}
        snapshot = copy.deepcopy(operator_config)
        internal_state = {}

        def invoke(initial_state):
            internal_state.update(initial_state)
            internal_state.update(
                started_at="2026-10-20T00:00:00+00:00", finished_at="2026-10-20T00:00:01+00:00",
                _config_adjustments={"proxy_profiles": [{"id": "private", "url": secret_url}], "rate_limit": 2},
            )
            self.assertEqual(initial_state["config"]["fuzzing_options"]["proxy_profiles"][0]["url"], secret_url)
            return internal_state

        with patch.object(graph, "build_coordinator_graph", return_value=SimpleNamespace(invoke=invoke)):
            with patch.object(graph, "log_pipeline_summary"):
                public_state = graph.run_pipeline("http://127.0.0.1:8765", operator_config)
        self.assertEqual(operator_config, snapshot)
        self.assertEqual(internal_state["config"], snapshot)
        self.assertEqual(internal_state["_config_adjustments"]["proxy_profiles"][0]["url"], secret_url)
        self.assertIsNot(public_state, internal_state)
        self.assertIsNot(public_state["config"], internal_state["config"])
        self.assertIsNot(public_state["config"]["fuzzing_options"], operator_config["fuzzing_options"])
        self.assertEqual(public_state["config"]["fuzzing_options"]["proxy_profiles"], "<redacted>")
        self.assertEqual(public_state["_config_adjustments"]["proxy_profiles"], "<redacted>")
        self.assertEqual(public_state["config"]["fuzzing_options"]["max_requests"], 3)
        for secret in (secret_url, "pipeline_user", "PipelineSecret_820"):
            self.assertNotIn(secret, json.dumps(public_state))


if __name__ == "__main__":
    unittest.main()
