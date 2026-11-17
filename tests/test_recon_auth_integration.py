"""Real loopback requests through Recon channels and Coordinator configuration."""

from copy import deepcopy
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from src.agents import tech_recon as recon
from src.coordinator import graph
from src.tools import registry
from src.tools.auth_manager import AuthManager
from src.tools.recon_http import recon_options_from_config


TOKEN = "integration_fixture_bearer_token"
COOKIE = "fixture_session=integration_private_session"
CUSTOM = "integration_fixture_custom_header_secret"
HEADERS = {"Authorization": "Bearer " + TOKEN, "Cookie": COOKIE, "X-Fixture-Key": CUSTOM}


class _ReconHandler(BaseHTTPRequestHandler):
    def _respond(self):
        observed = {
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
        }
        self.server.observed.append(observed)
        status, media, body = 200, "text/plain", "fixture response"
        path = urlsplit(self.path).path
        required = self.server.required_headers
        if required and self.command != "TRACE" and any(
                self.headers.get(key) != value for key, value in required.items()):
            status, body = 401, "authentication required"
        elif path == "/redirect":
            status, body = 302, "redirect fixture"
        elif self.command == "GET" and path == "/" and self.server.is_primary:
            media = "text/html"
            body = (
                '<html><head><meta name="generator" content="' + CUSTOM + '">'
                '<script src="/app.js"></script></head><body>'
                '<a href="/inside">inside</a><a href="/redirect">redirect</a>'
                '<a href="' + self.server.other_origin + '/outside-link">outside</a>'
                + self.server.extra_html +
                '</body></html>'
            )
        elif path == "/app.js":
            media = "application/javascript"
            body = 'fetch("' + self.server.other_origin + '/api/items"); fetch("/api/local");'
        elif path == "/robots.txt":
            body = "User-agent: *\nDisallow: /robot-discovered\n"
        elif path == "/sitemap.xml":
            media = "application/xml"
            body = "<urlset><url><loc>" + self.server.origin + "/sitemap-discovered</loc></url></urlset>"
        elif path == "/swagger.json":
            media = "application/json"
            body = json.dumps({"openapi": "3.0.0", "paths": {
                "/api/schema-discovered": {"get": {"parameters": [{"name": "schema_param", "in": "query"}]}}
            }})
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", media + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if status == 302:
            self.send_header("Location", self.server.other_origin + "/redirect-target")
        if self.command == "OPTIONS":
            self.send_header("Allow", "GET, OPTIONS")
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _respond
    do_OPTIONS = _respond
    do_TRACE = _respond

    def log_message(self, *args):
        pass


class ReconAuthIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.primary = ThreadingHTTPServer(("127.0.0.1", 0), _ReconHandler)
        cls.secondary = ThreadingHTTPServer(("127.0.0.1", 0), _ReconHandler)
        cls.tls = ThreadingHTTPServer(("127.0.0.1", 0), _ReconHandler)
        fixtures = Path(__file__).parent / "fixtures"
        cls.certificate = fixtures / "proxy_lab_cert.pem"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.certificate, fixtures / "proxy_lab_key.pem")
        cls.tls.socket = context.wrap_socket(cls.tls.socket, server_side=True)
        cls.origin = f"http://127.0.0.1:{cls.primary.server_port}"
        cls.other_origin = f"http://127.0.0.1:{cls.secondary.server_port}"
        cls.tls_origin = f"https://127.0.0.1:{cls.tls.server_port}"
        cls.workers = []
        for server, origin, other, is_primary in (
            (cls.primary, cls.origin, cls.other_origin, True),
            (cls.secondary, cls.other_origin, cls.origin, False),
            (cls.tls, cls.tls_origin, cls.other_origin, True),
        ):
            server.observed = []
            server.required_headers = None
            server.extra_html = ""
            server.origin, server.other_origin, server.is_primary = origin, other, is_primary
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cls.workers.append(worker)

    @classmethod
    def tearDownClass(cls):
        for server in (cls.primary, cls.secondary, cls.tls):
            server.shutdown()
            server.server_close()
        for worker in cls.workers:
            worker.join(timeout=3)

    def setUp(self):
        self.primary.observed.clear()
        self.secondary.observed.clear()
        self.tls.observed.clear()
        self.primary.required_headers = dict(HEADERS)
        self.secondary.required_headers = None
        self.tls.required_headers = dict(HEADERS)
        self.primary.extra_html = ""
        original_loader = recon.TechReconAgent._load_knowledge

        def load_bounded_knowledge(agent):
            original_loader(agent)
            agent._spider_cfg = {"limits": {
                "default_max_depth": 1, "default_max_pages": 8,
                "concurrent_requests": 2, "request_delay_ms": 0,
                "request_timeout_ms": 2000,
            }}

        self.enterContext(patch.object(recon.TechReconAgent, "_load_knowledge", load_bounded_knowledge))
        self.enterContext(patch.object(recon, "PROBE_FILES", ["/robots.txt", "/sitemap.xml", "/swagger.json"]))
        self.enterContext(patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)))
        self.enterContext(patch.object(graph, "circuit_breakers", {"tech_recon": Mock()}))

    def assert_auth(self, request, present=True):
        for key, value in HEADERS.items():
            if present:
                self.assertEqual(request["headers"].get(key.lower()), value, request)
            else:
                self.assertNotIn(key.lower(), request["headers"], request)

    def assert_secrets_absent(self, value):
        encoded = json.dumps(value, default=str)
        for secret in (TOKEN, COOKIE, CUSTOM):
            self.assertNotIn(secret, encoded)

    def assert_all_channels_requested(self):
        for request in self.primary.observed:
            self.assert_auth(request, present=request["method"] != "TRACE")
        get_paths = [request["path"] for request in self.primary.observed if request["method"] == "GET"]
        for path in ("/", "/app.js", "/inside", "/robots.txt", "/sitemap.xml", "/swagger.json"):
            self.assertIn(path, get_paths)
        # The probe identifies the protected schema; CH-6 then fetches it again.
        self.assertEqual(get_paths.count("/swagger.json"), 2)
        methods = {request["method"] for request in self.primary.observed}
        self.assertTrue({"OPTIONS", "TRACE"} <= methods)

    def coordinator_recon(self, config, target_url=None, **extra):
        state = graph.init_state({"target_url": target_url or self.origin, "config": config})
        state.update(extra)
        result = graph.run_tech_recon(state)
        self.assertEqual(result["agent_statuses"]["tech_recon"], "success", result["error_log"])
        return result

    def test_coordinator_passes_auth_to_all_channels_and_ignores_llm_policy_changes(self):
        config = {"recon_options": {
            "bearer_token": TOKEN, "cookie": COOKIE, "headers": {"X-Fixture-Key": CUSTOM},
            "allowed_origins": [self.origin], "auth_origins": [self.origin],
        }}
        before = deepcopy(config)
        state = self.coordinator_recon(config, _config_adjustments={
            "headers": {}, "allowed_origins": [self.other_origin], "verify_ssl": False,
        })
        self.assert_all_channels_requested()
        self.assertEqual(self.secondary.observed, [])
        self.assertIn("/api/schema-discovered", state["discovered_paths"])
        self.assertTrue(state["recon_http_policy"]["verify_ssl"])
        self.assertFalse(state["recon_http_policy"]["follow_redirects"])
        self.assertEqual(config, before)
        self.assert_secrets_absent({key: value for key, value in state.items() if key != "config"})

    def test_legacy_fuzzing_header_configuration_is_used_by_recon(self):
        self.coordinator_recon({"fuzzing_options": {
            "headers": dict(HEADERS), "allowed_origins": [self.origin],
            "engine": "proxy_http", "proxy_source": "proxyscrape",
        }})
        self.assert_all_channels_requested()
        self.assertEqual(self.secondary.observed, [])

    def test_explicit_recon_headers_override_legacy_headers(self):
        config = {"fuzzing_options": {"headers": {"Authorization": "Bearer obsolete_fixture"}},
                  "recon_options": {"headers": dict(HEADERS)}}
        self.coordinator_recon(config)
        self.assert_all_channels_requested()

    def test_discovered_backend_origin_is_recorded_but_not_requested_by_default(self):
        agent = recon.TechReconAgent(headers=dict(HEADERS))
        result = agent._run_full_recon_internal(self.origin)
        self.assertIn(self.other_origin, result["architecture"]["backend_api_hosts"])
        self.assertEqual(result["architecture"]["backend_probe"]["skipped_reason"], "outside_allowed_origins")
        self.assertEqual(self.secondary.observed, [])
        self.assertEqual(result["api_schema"]["endpoints_count"], 1)
        self.assert_secrets_absent(result)

    def test_network_scope_does_not_implicitly_expand_credential_scope(self):
        agent = recon.TechReconAgent(headers=dict(HEADERS), allowed_origins=[self.origin, self.other_origin])
        result = agent._run_full_recon_internal(self.origin)
        self.assertEqual(result["architecture"]["backend_probe"]["status_code"], 200)
        self.assertTrue(self.secondary.observed)
        for request in self.secondary.observed:
            self.assert_auth(request, present=False)
        self.assertNotIn("/redirect-target", [request["path"] for request in self.secondary.observed])

    def test_explicit_additional_auth_origin_receives_headers(self):
        agent = recon.TechReconAgent(headers=dict(HEADERS),
                                    allowed_origins=[self.origin, self.other_origin],
                                    auth_origins=[self.origin, self.other_origin])
        agent._run_full_recon_internal(self.origin)
        self.assertTrue(self.secondary.observed)
        for request in self.secondary.observed:
            self.assert_auth(request)
        self.assertNotIn("/redirect-target", [request["path"] for request in self.secondary.observed])

    def test_llm_inputs_and_returned_output_do_not_contain_echoed_credentials(self):
        agent = recon.TechReconAgent(headers=dict(HEADERS))
        with patch.object(agent, "plan_tool_execution", return_value={
            "selected_tool": "full_7channel_recon_suite", "options": {},
        }) as plan, patch.object(agent, "generate_justification", return_value="Fixture justification") as justify:
            result = agent.execute(self.origin)
        self.assertEqual(plan.call_count, 1)
        self.assertEqual(justify.call_count, 1)
        self.assert_secrets_absent(plan.call_args.kwargs)
        self.assert_secrets_absent(justify.call_args.kwargs)
        self.assert_secrets_absent(result)

    def test_registry_recon_wrappers_use_auth_and_scope_transport(self):
        calls = [
            (registry._wrap_ch1, {}), (registry._wrap_ch2, {}),
            (registry._wrap_ch3, {"js_script_paths": ["/app.js", self.other_origin + "/forbidden.js"]}),
            (registry._wrap_ch4, {"max_depth": 1, "max_pages": 5}),
            (registry._wrap_ch5, {}),
            (registry._wrap_ch6, {"discovered_paths": ["/swagger.json"]}),
            (registry._wrap_ch7, {}), (registry._wrap_full_recon, {}),
        ]
        for wrapper, options in calls:
            with self.subTest(wrapper=wrapper.__name__):
                result = wrapper(self.origin, headers=dict(HEADERS), **options)
                self.assertIsInstance(result, dict)
                self.assert_secrets_absent(result)
                if wrapper is registry._wrap_ch2:
                    self.assertIn("/inside", result["ch2_dom_parser"]["paths"])
        self.assertTrue(self.primary.observed)
        for request in self.primary.observed:
            self.assert_auth(request, present=request["method"] != "TRACE")
        self.assertEqual(self.secondary.observed, [])

    def test_pipeline_return_redacts_nested_and_legacy_auth_without_mutating_config(self):
        config = {
            "custom_headers": {"X-Arbitrary-Secret": CUSTOM},
            "recon_options": {"token": TOKEN, "cookie": COOKIE,
                              "custom_headers": {"X-Fixture-Key": CUSTOM},
                              "account": {"username": "private_fixture_user", "password": "private_fixture_password"}},
        }
        original = deepcopy(config)

        def invoke(initial, config=None):
            state = graph.run_tech_recon(graph.init_state(initial))
            state["finished_at"] = datetime.now(timezone.utc).isoformat()
            return state

        with patch.object(graph, "build_coordinator_graph", return_value=SimpleNamespace(invoke=invoke)), \
                patch.object(graph, "llm_limiter"), patch.object(graph, "tarpit_detector"):
            result = graph.run_pipeline(self.origin, config)
        self.assertEqual(result["agent_statuses"]["tech_recon"], "success", result["error_log"])
        self.assert_secrets_absent(result)
        for secret in ("private_fixture_user", "private_fixture_password"):
            self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(config, original)

    def test_recon_options_aliases_do_not_forward_unrelated_engine_options(self):
        options = recon_options_from_config({
            "token": "top_token", "custom_headers": {"X-Fixture": "top"},
            "recon_options": {"token": TOKEN, "custom_headers": dict(HEADERS),
                              "allowed_origins": [self.origin], "proxy_source": "proxyscrape"},
        })
        self.assertEqual(options["bearer_token"], TOKEN)
        self.assertEqual(options["headers"], HEADERS)
        self.assertEqual(options["allowed_origins"], [self.origin])
        self.assertNotIn("proxy_source", options)

    def test_provided_manager_cannot_login_with_a_different_origin_policy(self):
        account = {"username": "fixture_user", "password": "fixture_password",
                   "login_url": self.other_origin + "/login"}
        for agent_scope in (
            {"allowed_origins": [self.origin], "auth_origins": [self.origin]},
            {"allowed_origins": [self.origin, self.other_origin], "auth_origins": [self.origin]},
        ):
            with self.subTest(scope=agent_scope):
                manager = AuthManager(account=account, allowed_origins=[self.origin, self.other_origin],
                                      auth_origins=[self.origin, self.other_origin])
                agent = recon.TechReconAgent(auth_manager=manager, **agent_scope)
                with patch.object(manager, "_auto_login") as login:
                    with self.assertRaisesRegex(ValueError, "same origin and TLS policy"):
                        agent.execute(self.origin)
                    login.assert_not_called()
                self.assertEqual(self.primary.observed, [])
                self.assertEqual(self.secondary.observed, [])

    def test_provided_manager_cannot_login_with_a_different_ca_policy(self):
        manager = AuthManager(account={"username": "fixture_user", "password": "fixture_password"})
        agent = recon.TechReconAgent(auth_manager=manager, tls_ca_file=str(self.certificate))
        with patch.object(manager, "_auto_login") as login:
            with self.assertRaisesRegex(ValueError, "same origin and TLS policy"):
                agent.execute(self.origin)
            login.assert_not_called()
        self.assertEqual(self.primary.observed, [])

    def test_provided_manager_rejects_duplicate_credential_arguments(self):
        manager = AuthManager(bearer_token=TOKEN)
        for duplicate in ({"bearer_token": TOKEN}, {"cookie": COOKIE},
                          {"account": {"username": "fixture_user", "password": "fixture_password"}}):
            with self.subTest(argument=list(duplicate)):
                with self.assertRaises(ValueError):
                    recon.TechReconAgent(auth_manager=manager, **duplicate)
        self.assertEqual(self.primary.observed, [])

    def test_malformed_external_links_do_not_abort_dom_or_spider(self):
        self.primary.extra_html = (
            '<a href="http://[bad">malformed host</a>'
            '<a href="http://127.0.0.1:invalid/foreign">malformed port</a>'
            '<script src="http://[bad"></script>'
            '<a href="/fragment-link#section">valid fragment link</a>'
        )
        result = recon.TechReconAgent(headers=dict(HEADERS))._run_full_recon_internal(self.origin)
        self.assert_all_channels_requested()
        self.assertIn("/inside", result["discovered_paths"])
        self.assertIn("/fragment-link", result["discovered_paths"])
        self.assertEqual(self.secondary.observed, [])

    def test_coordinator_passes_private_ca_and_retains_authenticated_verified_tls(self):
        config = {"recon_options": {"headers": dict(HEADERS), "tls_ca_file": str(self.certificate)}}
        result = self.coordinator_recon(config, target_url=self.tls_origin)
        self.assertTrue(result["recon_http_policy"]["verify_ssl"])
        self.assertTrue(self.tls.observed)
        for request in self.tls.observed:
            self.assert_auth(request, present=request["method"] != "TRACE")
        self.assertIn("/api/schema-discovered", result["discovered_paths"])
        self.assertEqual(self.primary.observed, [])
        self.assertEqual(self.secondary.observed, [])

    def test_coordinator_rejects_untrusted_tls_and_insecure_option_before_http(self):
        for options in ({"headers": dict(HEADERS)}, {"headers": dict(HEADERS), "verify_ssl": False}):
            with self.subTest(options=list(options)):
                state = graph.init_state({"target_url": self.tls_origin, "config": {"recon_options": options}})
                result = graph.run_tech_recon(state)
                self.assertEqual(result["agent_statuses"]["tech_recon"], "failed")
                self.assertTrue(result["error_log"])
                self.assertEqual(self.tls.observed, [])
                self.assert_secrets_absent(result["error_log"])


if __name__ == "__main__":
    unittest.main()
