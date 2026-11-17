"""Real loopback comparisons, never candidate-only or fabricated measurements."""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

from src.agents.param_discovery import ParamDiscoveryAgent, parameter_options_from_config
from src.tools.parameter_verification import verify_parameters


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append((self.path, dict(self.headers)))
        query = parse_qs(urlsplit(self.path).query)
        status, body, extra = 200, b"Base-row", {}
        mode = self.server.mode
        if mode == "normal" and "page" in query:
            body = b"Firstrow" if query["page"] == ["1"] else b"Next-row"
        elif mode == "dynamic":
            body = ("Changing serial " + str(len(self.server.observed))).encode()
        elif mode == "unknown_sensitive" and query:
            body = b"Generic alternate representation for every query"
        elif mode == "echo" and "page" in query:
            body = ("You entered " + query["page"][0]).encode()
        elif mode == "encoded_echo" and "q" in query:
            body = ("Echo " + "".join("\\u%04x" % ord(char) for char in query["q"][0])).encode()
        elif mode == "drift" and len(self.server.observed) > 4:
            body = b"Session state changed permanently"
        elif mode == "value_sensitive" and any(value.startswith("sentinel_") for values in query.values() for value in values):
            body = b"Generic value handling, regardless of the name"
        elif mode == "status_only" and "page" in query:
            status, body = 400, b"Invalid query"
        elif mode == "blocked" or (mode == "candidate_blocked" and "page" in query):
            status = self.server.block_status
        elif mode == "retry_after":
            extra["Retry-After"] = "15"
        elif mode == "redirect":
            status, extra = 302, {"Location": self.server.base + "/other"}
        elif mode == "login":
            body = b'<html><input type="password"></html>'
        elif mode == "oversized":
            body = b"x" * 1000
        elif mode == "challenge":
            body = b"Verify you are human"
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionResetError, BrokenPipeError):
            pass

    def log_message(self, *args):
        pass


class ParameterVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.daemon_threads = True
        cls.server.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.server.observed = []
        self.server.mode = "normal"
        self.server.block_status = 403
        self.records = [{"url": self.server.base + "/search?fixed=keep", "status_code": None,
                         "result_kind": "parameter_candidates", "content_length_change": None,
                         "discovered_params": [{"name": "page", "type": "integer", "method": "GET"}]}]

    def verify(self, **kwargs):
        return verify_parameters(self.server.base, self.records, rate_limit=100, **kwargs)

    def test_known_parameter_verified_with_actual_equal_length_body_changes(self):
        original = deepcopy(self.records)
        result = self.verify()
        self.assertEqual(self.records, original)
        self.assertEqual(len(result["verified_parameters"]), 1)
        self.assertFalse(result["parameter_candidates"])
        item = result["verified_parameters"][0]
        self.assertEqual((item["name"], item["location"], item["method"]), ("page", "query", "GET"))
        self.assertEqual(item["status_code"], 200)
        self.assertEqual(item["content_length_change"], 0)
        self.assertEqual(item["verification"], "verified")
        self.assertEqual(result["stats"]["total_requests"], len(self.server.observed))
        self.assertEqual(result["stats"]["total_requests"], 11)
        self.assertEqual(result["stats"]["bytes_read"], 88)
        self.assertEqual(result["stats"]["responses_received"], 11)
        self.assertEqual(result["stats"]["baseline_requests"], 3)
        self.assertEqual(result["stats"]["control_requests"], 4)
        self.assertEqual(result["stats"]["candidate_requests"], 4)
        self.assertTrue(all(parse_qs(urlsplit(path).query)["fixed"] == ["keep"] for path, _ in self.server.observed))
        for sample in item["verification_evidence"]["samples"]:
            self.assertGreater(sample["response_time"], 0)
            self.assertEqual(sample["content_length"], 8)
            self.assertEqual(len(sample["body_sha256"]), 64)
        # Parameter proof does not promote the enclosing endpoint.
        self.assertEqual(result["param_results"][0]["verification"], "not_checked")
        self.assertIsNone(result["param_results"][0]["status_code"])

    def test_unknown_candidate_and_fallback_stay_unverified(self):
        self.records[0]["discovered_params"].append({"name": "unused", "type": "integer"})
        result = self.verify()
        self.assertEqual(len(result["verified_parameters"]), 1)
        self.assertEqual(result["parameter_candidates"][0]["name"], "unused")
        self.assertEqual(result["parameter_candidates"][0]["verification_reason"], "no_repeatable_response_effect")
        self.assertEqual(result["stats"]["total_requests"], 18)
        self.server.mode = "fallback"
        result = self.verify()
        self.assertFalse(result["verified_parameters"])

    def test_ambiguous_reflections_errors_and_dynamic_controls_are_not_verified(self):
        for mode in ("echo", "dynamic", "unknown_sensitive", "status_only"):
            with self.subTest(mode=mode):
                self.server.mode = mode
                result = self.verify()
                self.assertFalse(result["verified_parameters"])
                self.assertEqual(result["parameter_candidates"][0]["verification"], "inconclusive")

    def test_post_controls_reject_drift_and_value_handling_independent_of_name(self):
        self.server.mode = "drift"
        result = self.verify()
        self.assertFalse(result["verified_parameters"])
        self.assertEqual(result["parameter_candidates"][0]["verification_reason"], "changed_or_value_sensitive_negative_controls")
        self.server.mode = "value_sensitive"
        self.records[0]["discovered_params"] = [{"name": "q", "type": "string"}]
        result = self.verify()
        self.assertFalse(result["verified_parameters"])
        self.assertEqual(result["parameter_candidates"][0]["verification_reason"], "changed_or_value_sensitive_negative_controls")

    def test_encoded_echo_is_not_promoted_to_parameter_proof(self):
        self.server.mode = "encoded_echo"
        self.records[0]["discovered_params"] = [{"name": "q", "type": "string"}]
        result = self.verify()
        self.assertFalse(result["verified_parameters"])
        self.assertEqual(result["parameter_candidates"][0]["verification_reason"], "reflected_input_requires_review")

    def test_blocks_stop_entire_phase_and_do_not_try_next_candidate(self):
        self.records[0]["discovered_params"].append({"name": "unused"})
        for status in (401, 403, 407, 429):
            with self.subTest(status=status):
                self.server.mode, self.server.block_status = "candidate_blocked", status
                self.server.observed = []
                result = self.verify()
                self.assertEqual(result["stop_reason"], f"http_{status}")
                self.assertEqual(result["stats"]["total_requests"], 5)
                self.assertEqual(len(self.server.observed), 5)
                self.assertFalse(result["verified_parameters"])

    def test_retry_redirect_login_challenge_stop_without_redirect_follow(self):
        for mode, reason in (("retry_after", "retry_after"), ("redirect", "redirect_requires_review"),
                             ("login", "login_or_challenge"), ("challenge", "login_or_challenge")):
            with self.subTest(mode=mode):
                self.server.mode = mode
                self.server.observed = []
                result = self.verify()
                self.assertEqual(result["stop_reason"], reason)
                self.assertEqual(result["stats"]["total_requests"], 1)
                self.assertEqual(len(self.server.observed), 1)

    def test_budget_preserves_partial_measurements_without_promotion(self):
        result = self.verify(max_requests=6)
        self.assertEqual(result["stats"]["total_requests"], 6)
        self.assertEqual(result["stop_reason"], "max_requests")
        self.assertEqual(result["verification_status"], "partial")
        self.assertFalse(result["verified_parameters"])
        candidate = result["parameter_candidates"][0]
        self.assertEqual(candidate["status_code"], 200)
        self.assertEqual(len(candidate["verification_evidence"]["samples"]), 2)

    def test_transport_error_counts_attempt_without_invented_status(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=URLError("fixture failure")):
            result = self.verify()
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual(result["stats"]["network_errors"], 1)
        self.assertEqual(result["stats"]["responses_received"], 0)
        self.assertEqual(result["stop_reason"], "transport_error")
        evidence = result["parameter_candidates"][0]["verification_evidence"]["controls"][0]
        self.assertIsNone(evidence["status_code"])
        self.assertIsNone(evidence["content_length"])
        self.assertEqual(evidence["error"], "URLError")

    def test_truncated_bodies_do_not_establish_verification(self):
        self.server.mode = "oversized"
        result = self.verify(max_response_bytes=16)
        self.assertFalse(result["verified_parameters"])
        self.assertEqual(result["stats"]["bytes_read"], 4 * 17)
        self.assertTrue(result["parameter_candidates"][0]["verification_evidence"]["controls"][0]["body_truncated"])

    def test_disabled_upstream_stop_outside_scope_and_unsafe_context_send_nothing(self):
        for options in ({"enabled": False}, {"stop_reason": "upstream_http_403"}):
            result = self.verify(**options)
            self.assertEqual(result["stats"]["total_requests"], 0)
        for change in ({"url": "https://example.invalid/search"}, {"source_method": "POST"},
                       {"source_status_code": 403}, {"source_retry_after": True}, {"source_simulated": True},
                       {"url": self.server.base + "/logout"}, {"source_error": "old network error"},
                       {"source_body_truncated": True}, {"source_body_complete": False}):
            with self.subTest(change=change):
                records = deepcopy(self.records)
                records[0].update(change)
                result = verify_parameters(self.server.base, records, rate_limit=100)
                self.assertEqual(result["stats"]["total_requests"], 0)
        self.assertFalse(self.server.observed)

    def test_existing_parameter_and_sensitive_candidates_are_not_probed(self):
        self.records[0]["discovered_params"] = [{"name": name} for name in ("fixed", "token", "debug", "action", "redirect_uri")]
        result = self.verify()
        self.assertEqual(result["stats"]["total_requests"], 0)
        self.assertEqual(len(result["parameter_candidates"]), 5)

    def test_headers_propagate_but_credentials_and_bodies_not_in_artifact(self):
        secret = "fixture_parameter_secret_84919"
        result = self.verify(headers={"Authorization": "Bearer " + secret})
        self.assertTrue(all(headers["Authorization"] == "Bearer " + secret for _, headers in self.server.observed))
        encoded = json.dumps(result)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("Firstrow", encoded)
        self.assertNotIn('"_body"', encoded)

    def test_adapter_keeps_auth_route_rate_and_stop_guards(self):
        context = {"route": "direct", "auth_matches_operator": True, "http_method": "GET", "rate_limit": .5}
        execution = {"engine": "python_http", "success": True, "verification_context": context}
        config = {"fuzzing_options": {"headers": {"Authorization": "Bearer fixture"}, "rate_limit": 1},
                  "parameter_options": {"max_requests": 12, "rate_limit": 10}}
        options = parameter_options_from_config(config, execution)
        self.assertEqual(options["headers"], config["fuzzing_options"]["headers"])
        self.assertEqual(options["rate_limit"], .5)
        self.assertEqual(options["max_requests"], 12)
        execution["verification_context"] = dict(context, route="proxy")
        self.assertEqual(parameter_options_from_config(config, execution)["stop_reason"], "verification_route_unavailable")
        execution["stop_reason"] = "http_429"
        self.assertEqual(parameter_options_from_config(config, execution)["stop_reason"], "upstream_http_429")

    def test_agent_integrates_verification_and_handles_empty_assembler_components(self):
        agent = ParamDiscoveryAgent(llm=None)
        with patch.object(agent.assembler, "assemble", return_value={"components": {"id_lookup": [], "pagination_sort": [], "business_fields": []}}):
            result = agent.execute(self.server.base, [{"url": self.server.base + "/search"}],
                                   verification_options={"rate_limit": 100})
        self.assertEqual(len(result["verified_parameters"]), 1)
        self.assertGreater(result["stats"]["total_requests"], 0)
        self.assertEqual(result["tools_executed"][0]["selected_tool"], "parameter_http_verifier")
        self.assertTrue(all(row["url"].startswith(self.server.base) for row in result["param_results"]))

    def test_verifier_exception_preserves_candidates_and_redacts_error(self):
        agent = ParamDiscoveryAgent(llm=None)
        secret = "fixture_error_secret_84629"
        with patch("src.agents.param_discovery.verify_parameters", side_effect=RuntimeError("Failure " + secret)):
            result = agent.execute(self.server.base, ["/search"],
                                   verification_options={"headers": {"Authorization": "Bearer " + secret}})
        self.assertEqual(result["verification_status"], "failed")
        self.assertIsNone(result["stats"]["total_requests"])
        self.assertTrue(result["param_results"])
        self.assertTrue(result["parameter_candidates"])
        self.assertFalse(result["verified_parameters"])
        self.assertNotIn(secret, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
