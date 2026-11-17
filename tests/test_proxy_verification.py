"""Real loopback replay through rotating proxies; no public network services.

Successful fuzzing establishes the pool for normal replay tests. CONNECT tests
publish an explicit fixture pool to exercise rejection before any target TLS.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socketserver
import ssl
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.agents.fuzzer import FuzzingAgent
from src.agents.param_discovery import ParamDiscoveryAgent
from src.agents.soft404_filter import Soft404FilterAgent, soft404_options_from_config
from src.tools.http_fuzzing import run_http_fuzzing
from src.tools.parameter_verification import verify_parameters, parameter_options_from_config
from src.tools.proxy_profiles import PROXY_OPTION_KEYS, ProxyProfilePool
from src.tools.soft404 import verify_soft404
from src.tools.verification_http import publish_proxy_pool

try:
    from test_proxy_fuzzing import _ForwardProxyHandler
    from test_proxy_connect_stops import _RejectingConnectProxy, _UnreachableTarget
    from test_proxy_profiles import _TunnelProxy
except ModuleNotFoundError:
    from tests.test_proxy_fuzzing import _ForwardProxyHandler
    from tests.test_proxy_connect_stops import _RejectingConnectProxy, _UnreachableTarget
    from tests.test_proxy_profiles import _TunnelProxy


_TOKEN = "Bearer verification_fixture_access_token"
_COOKIE = "session=verification_fixture_cookie"
_HEADERS = {"Authorization": _TOKEN, "Cookie": _COOKIE}
_RUNTIME = {"http_rate_limit": 100, "http_max_requests": 200, "http_timeout_seconds": 2}


class _ComparisonTarget(BaseHTTPRequestHandler):
    def do_GET(self):
        server = self.server
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        server.observed.append({"path": self.path, "peer": self.client_address[0],
                                "headers": {key.lower(): value for key, value in self.headers.items()}})
        # A completely different fallback per route exposes cross-route baselines.
        if self.client_address[0] == "127.0.0.2":
            body = b'<html><title>Catalog</title><main>Apples pears oranges orchard harvest seasonal produce</main></html>'
        else:
            body = b'<html><title>Maritime</title><aside>Ocean waves tides salinity navigation lighthouse harbour weather</aside></html>'
        if parts.path.startswith("/search") and "page" in query:
            body = b'Catalog first batch' if query["page"] == ["1"] else b'Catalog later batch'
        elif parts.path == "/genuine":
            body = b'<html><title>Account statistics</title><article><h1>Weekly ledger</h1><table><tr><td>Entries and balances</td></tr></table></article></html>'
        status = server.block_status or 200
        self.send_response(status)
        if server.retry_after:
            self.send_header("Retry-After", "5")
        if server.redirect:
            self.send_header("Location", server.redirect)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args):
        pass


class ProxyVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), _ComparisonTarget)
        cls.origin = f"http://127.0.0.1:{cls.target.server_port}"
        cls.proxies = []
        for address in ("127.0.0.2", "127.0.0.3"):
            proxy = ThreadingHTTPServer(("127.0.0.1", 0), _ForwardProxyHandler)
            proxy.source_ip, proxy.target_port = address, cls.target.server_port
            cls.proxies.append(proxy)
        cls.threads = []
        for server in (cls.target, *cls.proxies):
            server.daemon_threads = True
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.threads.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target, *cls.proxies):
            server.shutdown()
            server.server_close()
        for worker in cls.threads:
            worker.join(timeout=3)

    def setUp(self):
        self.target.observed = []
        self.target.block_status, self.target.retry_after, self.target.redirect = None, False, None
        for proxy in self.proxies:
            proxy.state = {"observed": [], "broken": False, "authentication_required": False}
        self.options = {
            "engine": "proxy_http", "allowed_origins": [self.origin],
            "proxy_profiles": [{"id": "route-a", "url": f"http://127.0.0.1:{self.proxies[0].server_port}"},
                               {"id": "route-b", "url": f"http://127.0.0.1:{self.proxies[1].server_port}"}],
            "proxy_count": 2, "proxy_healthcheck_url": self.origin + "/robots.txt",
            "proxy_refresh_seconds": 0, "rate_limit": 10, "timeout_seconds": 2,
            "headers": _HEADERS, "max_requests": 10,
        }
        self.proxy_options = {key: value for key, value in self.options.items()
                              if key in PROXY_OPTION_KEYS or key == "engine"}

    def establish_pool(self):
        result = run_http_fuzzing(self.origin, ["seed"], **self.options)
        self.assertTrue(result["completed"], result)
        self.assertEqual(result["stats"]["total_requests"], 3)
        self.assertEqual(result["stats"]["healthcheck_requests"], 2)
        return result

    def verify(self, module, *, paths=None, **overrides):
        options = {"headers": _HEADERS, "allowed_origins": [self.origin],
                   "proxy_options": self.proxy_options, "rate_limit": 100,
                   "timeout_seconds": 2, "max_requests": 100}
        options.update(overrides)
        if module == "parameter":
            records = [{"url": self.origin + path, "discovered_params": [{"name": "page", "type": "integer"}]}
                       for path in (paths or ["/search-a", "/search-b"])]
            return verify_parameters(self.origin, records, **options)
        records = [{"url": self.origin + path, "status_code": 200, "content_length": 2219}
                   for path in (paths or ["/fallback-a", "/fallback-b", "/genuine"])]
        return verify_soft404(self.origin, records, **options)

    def test_parameter_rotates_between_endpoints_but_pins_all_controls_and_samples(self):
        with runtime_session(_RUNTIME), telemetry_session() as telemetry:
            self.establish_pool()
            result = self.verify("parameter")
            self.assertEqual(telemetry.snapshot()["http"]["total_requests"], len(self.target.observed))
        self.assertEqual(len(result["verified_parameters"]), 2, result)
        self.assertEqual(result["stats"]["total_requests"], 22)
        per_endpoint = []
        for path in ("/search-a", "/search-b"):
            observed = [entry for entry in self.target.observed if urlsplit(entry["path"]).path == path]
            self.assertEqual(len(observed), 11)
            peers = {entry["peer"] for entry in observed}
            self.assertEqual(len(peers), 1, observed)
            per_endpoint.append(peers.pop())
        self.assertEqual(set(per_endpoint), {"127.0.0.2", "127.0.0.3"})
        self.assertEqual(result["http_policy"]["route"], "proxy")
        for candidate in result["verified_parameters"]:
            evidence = candidate["verification_evidence"]
            measurements = evidence["controls"] + evidence["samples"] + evidence["post_controls"]
            self.assertEqual(len({item["proxy_profile_id"] for item in measurements}), 1)

    def test_soft404_baselines_are_route_specific_even_for_same_path_context(self):
        with runtime_session(_RUNTIME), telemetry_session() as telemetry:
            self.establish_pool()
            result = self.verify("soft404")
            self.assertEqual(telemetry.snapshot()["http"]["total_requests"], len(self.target.observed))
        self.assertEqual({urlsplit(row["url"]).path for row in result["false_positives"]},
                         {"/fallback-a", "/fallback-b"}, result)
        self.assertEqual([urlsplit(row["url"]).path for row in result["verified"]], ["/genuine"], result)
        groups = {group["id"]: group for group in result["baseline"]["groups"]}
        for row in result["verified"] + result["false_positives"]:
            evidence = row["verification_evidence"]
            baseline = groups[evidence["baseline_group"]]
            profiles = {sample["proxy_profile_id"] for sample in baseline["samples"]}
            self.assertEqual(profiles, {evidence["candidate"]["proxy_profile_id"]})
            self.assertEqual(row["content_length"], 2219)  # Original scan is unchanged.
        self.assertEqual(len({sample["proxy_profile_id"] for group in groups.values()
                              for sample in group["samples"]}), 2)

    def test_auth_healthchecks_and_proxy_metadata_do_not_expose_credentials(self):
        with runtime_session(_RUNTIME):
            self.establish_pool()
            result = self.verify("parameter", paths=["/search-a"])
        for row in self.target.observed:
            if row["path"] == "/robots.txt":
                self.assertNotIn("authorization", row["headers"])
                self.assertNotIn("cookie", row["headers"])
            else:
                self.assertEqual(row["headers"].get("authorization"), _TOKEN)
                self.assertEqual(row["headers"].get("cookie"), _COOKIE)
            self.assertNotIn("proxy-authorization", row["headers"])
            self.assertNotEqual(row["peer"], "127.0.0.1")
        public = json.dumps(result)
        self.assertNotIn(_TOKEN, public)
        self.assertNotIn(_COOKIE, public)
        self.assertEqual(sum(len(proxy.state["observed"]) for proxy in self.proxies), len(self.target.observed))

    def test_proxyscrape_pool_is_reused_without_refetch_or_new_healthchecks(self):
        urls = [profile["url"] for profile in self.options.pop("proxy_profiles")]
        self.options["proxy_source"] = "proxyscrape"
        self.proxy_options = {key: value for key, value in self.options.items()
                              if key in PROXY_OPTION_KEYS or key == "engine"}
        with patch("src.tools.proxy_profiles.proxyscrape.fetch_candidates", return_value=urls) as fetch:
            with runtime_session(_RUNTIME):
                self.establish_pool()
                result = self.verify("parameter", paths=["/search-a"])
        fetch.assert_called_once()
        self.assertEqual(len(result["verified_parameters"]), 1)
        self.assertEqual(sum(row["path"] == "/robots.txt" for row in self.target.observed), 2)
        self.assertEqual(result["http_policy"]["pool_reuse"], "fuzzing_session")

    def test_http_restrictions_stop_without_next_proxy_or_module_requests(self):
        for module in ("parameter", "soft404"):
            for status in (401, 403, 407, 429, "retry_after"):
                with self.subTest(module=module, status=status):
                    self.setUp()
                    with runtime_session(_RUNTIME), telemetry_session() as telemetry:
                        self.establish_pool()
                        previous = [len(proxy.state["observed"]) for proxy in self.proxies]
                        self.target.block_status = status if isinstance(status, int) else None
                        self.target.retry_after = status == "retry_after"
                        result = self.verify(module)
                        reason = f"http_{status}" if isinstance(status, int) else status
                        self.assertEqual(result["stop_reason"], reason)
                        self.assertEqual(result["stats"]["total_requests"], 1)
                        self.assertEqual(telemetry.snapshot()["http"]["total_requests"], len(self.target.observed))
                        self.assertEqual(sorted(len(proxy.state["observed"]) - old
                                                for proxy, old in zip(self.proxies, previous)), [0, 1])
                        before = len(self.target.observed)
                        self.verify("soft404" if module == "parameter" else "parameter")
                        self.assertEqual(len(self.target.observed), before)

    def test_transport_failure_stops_without_failover_and_preserves_attempt_count(self):
        for module in ("parameter", "soft404"):
            with self.subTest(module=module):
                self.setUp()
                with runtime_session(_RUNTIME), telemetry_session() as telemetry:
                    self.establish_pool()
                    for proxy in self.proxies:
                        proxy.state["broken"] = True
                    before = sum(len(proxy.state["observed"]) for proxy in self.proxies)
                    result = self.verify(module)
                    self.assertEqual(result["stop_reason"], "transport_error")
                    self.assertEqual(result["stats"]["total_requests"], 1)
                    self.assertEqual(result["stats"]["responses_received"], 0)
                    self.assertEqual(result["stats"]["network_errors"], 1)
                    after = sum(len(proxy.state["observed"]) for proxy in self.proxies)
                    self.assertEqual(after - before, 1)
                    self.assertEqual(telemetry.snapshot()["http"]["total_requests"], after)
                    self.assertEqual(len(self.target.observed), 3)

    def test_pool_does_not_escape_runtime_session_or_change_source_silently(self):
        with runtime_session(_RUNTIME):
            self.establish_pool()
        before = len(self.target.observed)
        with runtime_session(_RUNTIME):
            result = self.verify("parameter")
        self.assertEqual(result["stats"]["total_requests"], 0)
        self.assertFalse(result["verified_parameters"])
        self.assertEqual(len(self.target.observed), before)
        with runtime_session(_RUNTIME):
            self.establish_pool()
            altered = {**self.proxy_options, "proxy_count": 1}
            before = len(self.target.observed)
            result = self.verify("soft404", proxy_options=altered)
            self.assertEqual(result["stats"]["total_requests"], 0)
            self.assertEqual(len(self.target.observed), before)

    def test_scope_and_shared_budget_prevent_extra_dispatch(self):
        with runtime_session({**_RUNTIME, "http_max_requests": 5}), telemetry_session() as telemetry:
            self.establish_pool()
            result = self.verify("parameter")
            self.assertFalse(result["verified_parameters"])
            self.assertEqual(len(self.target.observed), 5)
            self.assertEqual(telemetry.snapshot()["http"]["total_requests"], 5)
            self.assertEqual(result["stats"]["total_requests"], 2)
            self.assertEqual(result["stop_reason"], "http_request_budget")
        self.setUp()
        with runtime_session(_RUNTIME):
            self.establish_pool()
            result = verify_soft404(self.origin, [{"url": "http://outside.invalid/no", "status_code": 200}],
                                    proxy_options=self.proxy_options, headers=_HEADERS,
                                    allowed_origins=[self.origin], rate_limit=100)
            self.assertEqual(result["stats"]["total_requests"], 0)
            self.assertEqual(len(self.target.observed), 3)

    def test_shared_rate_wait_cannot_dispatch_after_verification_deadline(self):
        for module in ("parameter", "soft404"):
            with self.subTest(module=module):
                self.setUp()
                with runtime_session(_RUNTIME) as runtime, telemetry_session() as telemetry:
                    self.establish_pool()
                    before = len(self.target.observed)
                    runtime.next_start = time.monotonic() + .12
                    result = self.verify(module, max_duration_seconds=.02)
                    self.assertEqual(result["stop_reason"], "max_duration")
                    self.assertEqual(result["stats"]["total_requests"], 0)
                    self.assertEqual(len(self.target.observed), before)
                    self.assertEqual(telemetry.snapshot()["http"]["total_requests"], before)
                    self.assertEqual(runtime.requests, before)

    def test_real_fuzzer_hands_pool_to_coordinator_verification_options(self):
        config = {"fuzzing_options": self.options,
                  "parameter_options": {"rate_limit": 100},
                  "soft404_options": {"rate_limit": 100}}
        with runtime_session(_RUNTIME), telemetry_session() as telemetry:
            fuzzed = FuzzingAgent(llm=None).execute(
                self.origin, ["search-a"], use_pattern_engine=False,
                delay_ms=0, **self.options)
            self.assertTrue(fuzzed["success"], fuzzed)
            options = parameter_options_from_config(config, fuzzed)
            self.assertNotIn("stop_reason", options)
            candidate_records = [{
                "url": self.origin + "/search-a",
                "discovered_params": [{"name": "page", "type": "integer"}],
            }]
            # Only candidate generation is fixed; both agent HTTP verifiers
            # and the transport handoff execute normally against the lab.
            with patch.object(ParamDiscoveryAgent, "_run_param_discovery_internal",
                              return_value={"param_results": candidate_records}):
                parameters = ParamDiscoveryAgent(llm=None).execute(
                    self.origin, fuzzed["results"], verification_options=options)
            filtered = Soft404FilterAgent().execute(
                self.origin, fuzzed["results"], **soft404_options_from_config(config, fuzzed))
            self.assertEqual(len(parameters["verified_parameters"]), 1, parameters)
            self.assertEqual(len(filtered["false_positives"]), 1, filtered)
            total = (fuzzed["stats"]["total_requests"] + parameters["stats"]["total_requests"]
                     + filtered["stats"]["total_requests"])
            self.assertEqual(total, len(self.target.observed))
            self.assertEqual(telemetry.snapshot()["http"]["total_requests"], total)
            evidence = parameters["verified_parameters"][0]["verification_evidence"]
            self.assertIn(evidence["proxy_profile_id"], {"route-a", "route-b"})
            self.assertTrue(all(sample["proxy_profile_id"] == evidence["proxy_profile_id"]
                                for sample in evidence["controls"] + evidence["samples"] + evidence["post_controls"]))
            self.assertIn(filtered["false_positives"][0]["verification_evidence"]["proxy_profile_id"],
                          {"route-a", "route-b"})

    def test_failed_new_fuzzing_invalidates_prior_pool_in_same_session(self):
        with runtime_session(_RUNTIME):
            self.establish_pool()
            for proxy in self.proxies:
                proxy.state["broken"] = True
            failed = run_http_fuzzing(self.origin, ["seed"], **self.options)
            self.assertFalse(failed["completed"])
            before = sum(len(proxy.state["observed"]) for proxy in self.proxies)
            for module in ("parameter", "soft404"):
                result = self.verify(module)
                self.assertEqual(result["stop_reason"], "verification_route_unavailable")
                self.assertEqual(result["stats"]["total_requests"], 0)
            self.assertEqual(sum(len(proxy.state["observed"]) for proxy in self.proxies), before)

    def test_redirects_never_follow_and_auth_origins_control_token_dispatch(self):
        for module in ("parameter", "soft404"):
            with self.subTest(module=module):
                self.setUp()
                with runtime_session(_RUNTIME):
                    self.establish_pool()
                    before = len(self.target.observed)
                    self.target.block_status = 302
                    self.target.redirect = "http://outside.invalid/landing"
                    result = self.verify(module, paths=["/search-a"], auth_origins=[])
                    self.assertFalse(result.get("verified_parameters", result.get("verified")))
                    self.assertGreater(len(self.target.observed), before)
                    for observed in self.target.observed[before:]:
                        self.assertNotIn("authorization", observed["headers"])
                        self.assertNotIn("cookie", observed["headers"])
                    for proxy in self.proxies:
                        self.assertTrue(all(urlsplit(item["url"]).netloc == urlsplit(self.origin).netloc
                                            for item in proxy.state["observed"]))


class ProxyVerificationConnectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _UnreachableTarget)
        cls.target.daemon_threads = True
        cls.target.accepted = []
        cls.origin = f"https://127.0.0.1:{cls.target.server_address[1]}"
        cls.proxies = [ThreadingHTTPServer(("127.0.0.1", 0), _RejectingConnectProxy) for _ in range(2)]
        cls.threads = []
        for server in (cls.target, *cls.proxies):
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.threads.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target, *cls.proxies):
            server.shutdown()
            server.server_close()
        for worker in cls.threads:
            worker.join(timeout=3)

    def test_connect_rejections_remain_separate_from_target_status_and_never_failover(self):
        for module in ("parameter", "soft404"):
            for status in (403, 407, 429):
                with self.subTest(module=module, status=status):
                    self.target.accepted.clear()
                    for proxy in self.proxies:
                        proxy.state = {"calls": [], "status": status}
                    options = {"engine": "proxy_http", "allowed_origins": [self.origin],
                               "proxy_profiles": [{"id": f"route-{i}", "url": f"http://127.0.0.1:{proxy.server_port}"}
                                                  for i, proxy in enumerate(self.proxies)]}
                    with runtime_session(_RUNTIME), telemetry_session() as telemetry:
                        publish_proxy_pool(self.origin, options, ProxyProfilePool.from_options(options, self.origin))
                        arguments = {"proxy_options": options, "headers": _HEADERS,
                                     "allowed_origins": [self.origin], "rate_limit": 100}
                        if module == "parameter":
                            result = verify_parameters(self.origin, [{"url": self.origin + "/search", "discovered_params": [{"name": "page"}]}], **arguments)
                            measured = result["parameter_candidates"][0]["verification_evidence"]["controls"][0]
                        else:
                            result = verify_soft404(self.origin, [{"url": self.origin + "/candidate", "status_code": 200}], **arguments)
                            measured = result["baseline"]["groups"][0]["samples"][0]
                        self.assertEqual(telemetry.snapshot()["http"]["total_requests"], 1)
                    self.assertEqual([len(proxy.state["calls"]) for proxy in self.proxies], [1, 0])
                    self.assertEqual(self.target.accepted, [])
                    self.assertEqual(measured["proxy_connect_status"], status)
                    self.assertIsNone(measured["status_code"])
                    self.assertIsNone(measured["content_length"])
                    self.assertEqual(result["stats"]["network_errors"], 0)
                    self.assertEqual(result["stats"]["proxy_connect_errors"], 1)
                    headers = {key.lower(): value for key, value in self.proxies[0].state["calls"][0]["headers"].items()}
                    self.assertNotIn("authorization", headers)
                    self.assertNotIn(_TOKEN, json.dumps(result))


class ProxyVerificationTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = ThreadingHTTPServer(("127.0.0.1", 0), _ComparisonTarget)
        cls.target.daemon_threads = True
        fixtures = Path(__file__).parent / "fixtures"
        cls.certificate = fixtures / "proxy_lab_cert.pem"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.certificate, fixtures / "proxy_lab_key.pem")
        cls.target.socket = context.wrap_socket(cls.target.socket, server_side=True)
        cls.origin = f"https://127.0.0.1:{cls.target.server_port}"
        _TunnelProxy.target_port = cls.target.server_port
        cls.proxy = ThreadingHTTPServer(("127.0.0.1", 0), _TunnelProxy)
        cls.proxy.daemon_threads = True
        cls.threads = []
        for server in (cls.target, cls.proxy):
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.threads.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.target, cls.proxy):
            server.shutdown()
            server.server_close()
        for worker in cls.threads:
            worker.join(timeout=3)

    def test_https_proxy_replay_requires_trusted_ca_and_preserves_target_auth(self):
        for module in ("parameter", "soft404"):
            for trusted in (False, True):
                with self.subTest(module=module, trusted=trusted):
                    self.target.observed = []
                    self.target.block_status, self.target.retry_after, self.target.redirect = None, False, None
                    _TunnelProxy.calls.clear()
                    options = {"engine": "proxy_http", "allowed_origins": [self.origin],
                               "proxy_profiles": [{"id": "tls-route", "url": f"http://fixture_user:fixture_password@127.0.0.1:{self.proxy.server_port}"}]}
                    with runtime_session(_RUNTIME):
                        publish_proxy_pool(self.origin, options, ProxyProfilePool.from_options(options, self.origin))
                        arguments = {"proxy_options": options, "headers": _HEADERS,
                                     "allowed_origins": [self.origin], "rate_limit": 100,
                                     "tls_ca_file": str(self.certificate) if trusted else None}
                        if module == "parameter":
                            result = verify_parameters(self.origin, [{"url": self.origin + "/search", "discovered_params": [{"name": "page", "type": "integer"}]}], **arguments)
                            proved = result["verified_parameters"]
                        else:
                            result = verify_soft404(self.origin, [{"url": self.origin + "/fallback", "status_code": 200}], **arguments)
                            proved = result["false_positives"]
                    self.assertEqual(bool(proved), trusted, result)
                    if trusted:
                        self.assertGreater(len(self.target.observed), 0)
                        for row in self.target.observed:
                            self.assertEqual(row["headers"].get("authorization"), _TOKEN)
                            self.assertNotIn("proxy-authorization", row["headers"])
                    else:
                        self.assertEqual(result["stats"]["network_errors"], 1)
                        self.assertEqual(result["stats"]["responses_received"], 0)
                        self.assertEqual(self.target.observed, [])
                        self.assertEqual(len(_TunnelProxy.calls), 1)
                    public = json.dumps(result)
                    for secret in (_TOKEN, _COOKIE, "fixture_password"):
                        self.assertNotIn(secret, public)


if __name__ == "__main__":
    unittest.main()
