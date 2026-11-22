"""B1 public contracts and policy validation; no network/model calls."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.coordinator.origins import (
    add_observation, canonical_origin, endpoint_observation, normalize_origin_config, origin_state,
)
from src.coordinator.validation import validate_pipeline_input, InputValidationError
from src.tools.origin_scope import OriginCredentialContext, OriginScopePolicy, OriginScopedTransport


A, B = "https://front.example.invalid", "https://api.example.invalid"


def config_for(a=A, b=B):
    rule = {"path": "/shared", "methods": ["GET", "HEAD"], "operation": "read_only"}
    return {"approved_origins": [a, b], "origin_policies": {
        a: {"rules": [deepcopy(rule)], "credential_profile": "frontend"},
        b: {"rules": [deepcopy(rule)]},
    }}


class OriginContractTests(unittest.TestCase):
    def test_unknown_information_stays_null_and_observation_never_verifies(self):
        row = endpoint_observation(A + "/shared?p=1")
        for key in ("method", "source", "source_url", "classification", "confidence", "attempted"):
            self.assertIsNone(row[key])
        self.assertEqual(row["url"], A + "/shared?p=1")
        self.assertEqual(row["verification_status"], "not_verified")

    def test_discovery_does_not_approve_and_same_path_on_two_origins_is_distinct(self):
        state = origin_state(A)
        state["wordlist"] = ["/legacy"]
        for origin in (A, B):
            add_observation(state, endpoint_observation(origin + "/shared", method="POST",
                            source="openapi", source_url=A + "/schema.json", classification="observed"))
        self.assertEqual(state["approved_origins"], [A])
        self.assertEqual(len(state["discovered_origins"]), 2)
        first, second = [state["origin_contexts"][o]["endpoints"][0] for o in (A, B)]
        self.assertNotEqual(first["endpoint_id"], second["endpoint_id"])
        self.assertEqual(first["method"], "POST")
        self.assertEqual(state["wordlist"], ["/legacy"])
        self.assertIsNone(state["origin_contexts"][B]["profile"])

    def test_duplicate_reference_preserves_provenance_without_duplicate_resource(self):
        state = origin_state(A)
        row = endpoint_observation(A + "/shared", source="javascript", source_url=A + "/app.js")
        add_observation(state, row)
        add_observation(state, row)
        self.assertEqual(len(state["origin_contexts"][A]["endpoints"]), 1)
        self.assertEqual(len(state["discovered_origins"][0]["sources"]), 1)
        self.assertEqual(row["source_url"], A + "/app.js")

    def test_observation_cannot_import_credential_fields_or_claim_verification(self):
        state = origin_state(A)
        row = endpoint_observation(A + "/shared")
        row.update(headers={"Authorization": "Bearer fake-private"}, attempted=True,
                   verification_status="verified")
        saved = add_observation(state, row)
        self.assertNotIn("fake-private", json.dumps(state))
        self.assertIsNone(saved["attempted"])
        self.assertEqual(saved["verification_status"], "not_verified")

    def test_origin_canonicalization_preserves_scheme_host_and_nondefault_port(self):
        self.assertEqual(canonical_origin("HTTPS://FRONT.example.invalid:443/app"), A)
        self.assertNotEqual(canonical_origin(A), canonical_origin(A + ":8443"))
        self.assertNotEqual(canonical_origin(A), canonical_origin(A.replace("https:", "http:")))
        self.assertNotEqual(canonical_origin(A), canonical_origin(B))

    def test_invalid_and_sensitive_urls_are_not_public_contract_data(self):
        for url in ("https://user:pass@example.invalid/", A + "/?token=fixture-private",
                    A + "/?%74oken=fixture-private",
                    A + "/#fragment", A + ":0/", "//other.invalid/a", A + "/a\r\n"):
            with self.subTest(kind=url.split(":", 1)[0]), self.assertRaises(ValueError):
                endpoint_observation(url)

    def test_policy_requires_explicit_origin_method_path_and_read_only_operation(self):
        policy = OriginScopePolicy(config_for())
        policy.check(A + "/shared", "GET")
        for url, method, operation in ((B + "/outside", "GET", "read_only"),
                ("https://new.example.invalid/shared", "GET", "read_only"),
                (A + "/shared", "POST", "read_only"), (A + "/shared", None, "read_only"),
                (A + "/shared", "GET", "unknown"), (A + "/shared?p=1", "GET", "read_only")):
            with self.subTest(method=method, operation=operation), self.assertRaises(ValueError):
                policy.check(url, method, operation=operation)

    def test_approved_origin_with_no_rule_is_deny_all(self):
        policy = OriginScopePolicy({"approved_origins": [A]})
        with self.assertRaises(ValueError):
            policy.check(A + "/", "GET")

    def test_ambiguous_paths_and_write_rules_are_rejected(self):
        for path in ("/../shared", "/a/./shared", "//shared", "/%2fshared", "/a;param", "/%252e"):
            cfg = config_for()
            cfg["origin_policies"][A]["rules"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                OriginScopePolicy(cfg)
        for field, value in (("methods", ["POST"]), ("methods", []), ("operation", "write")):
            cfg = config_for()
            cfg["origin_policies"][A]["rules"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                OriginScopePolicy(cfg)

    def test_public_policy_cannot_contain_secrets_or_approve_unknown_policy_origin(self):
        for mutate in (lambda cfg: cfg.update(credentials={}),
                       lambda cfg: cfg["origin_policies"][A].update(headers={}),
                       lambda cfg: cfg["origin_policies"].update({"https://new.invalid": {}})):
            cfg = config_for()
            mutate(cfg)
            with self.assertRaises(ValueError):
                normalize_origin_config(cfg)

    def test_credentials_require_explicit_binding_and_are_detached_private_copies(self):
        policy = OriginScopePolicy(config_for())
        headers = {"Authorization": "Bearer fake-a", "Cookie": "sid=fake-a"}
        context = OriginCredentialContext(policy, {A: {"profile_id": "frontend", "headers": headers}})
        headers.clear()
        self.assertTrue(context.headers_for(A).get("Authorization"))
        returned = context.headers_for(A)
        returned.clear()
        self.assertTrue(context.headers_for(A))
        self.assertEqual(context.headers_for(B), {})
        self.assertNotIn("fake-a", repr(context))
        self.assertNotIn("fake-a", json.dumps(policy.public_config()))
        self.assertNotIn("fake-a", context.redact("fake-a"))
        with self.assertRaises(ValueError):
            OriginCredentialContext(policy, {B: {"profile_id": "frontend", "headers": headers}})
        with self.assertRaises(ValueError):
            OriginScopedTransport(A, policy=OriginScopePolicy(config_for()), credentials=context)

    def test_missing_required_credential_profile_fails_before_dispatch(self):
        transport = OriginScopedTransport(A, policy=OriginScopePolicy(config_for()))
        with patch("src.tools.recon_http.record_http_attempt") as dispatch:
            result = transport.fetch_result(A + "/shared")
        dispatch.assert_not_called()
        self.assertFalse(result["attempted"])

    def test_credential_profile_cannot_override_method_routing_or_send_empty_auth(self):
        policy = OriginScopePolicy(config_for())
        for headers in ({}, {"X-HTTP-Method-Override": "DELETE"}, {"Host": "outside.invalid"},
                        {"Authorization": "Bearer fake\r\nX-Injected: value"},
                        {"Authorization": "Bearer one", "authorization": "Bearer two"}):
            with self.subTest(keys=list(headers)), self.assertRaises(ValueError):
                OriginCredentialContext(policy, {A: {"profile_id": "frontend", "headers": headers}})

    def test_tls_verification_cannot_be_disabled_in_b1_adapter(self):
        with self.assertRaises(TypeError):
            OriginScopedTransport(A, policy=OriginScopePolicy(config_for()), verify_ssl=False)

    def test_policy_and_state_are_independent_copies(self):
        cfg = config_for()
        policy = OriginScopePolicy(cfg)
        state = origin_state(A, cfg)
        cfg["origin_policies"][A]["rules"].clear()
        state["origin_policies"][A]["rules"].clear()
        policy.check(A + "/shared", "GET")
        state["origin_contexts"][A]["context"] = {"name": "frontend"}
        self.assertIsNone(state["origin_contexts"][B]["context"])

    def test_legacy_validation_unchanged_and_new_config_is_public_only(self):
        _, legacy = validate_pipeline_input(A, {"fuzzing_options": {"engine": "python_http"}})
        self.assertNotIn("multi_origin", legacy)
        _, cfg = validate_pipeline_input(A, {"multi_origin": config_for(),
                                            "fuzzing_options": {"engine": "python_http"}})
        self.assertEqual(cfg["multi_origin"]["approved_origins"], [A, B])
        with self.assertRaises(InputValidationError):
            validate_pipeline_input(A, {"multi_origin": {"approved_origins": [B]}})

    def test_coordinator_explicit_multi_origin_fails_closed_before_agents_or_llm(self):
        from src.coordinator import graph
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(graph, "_get_decision_engine") as model, \
                patch.object(graph, "TechReconAgent") as agent:
            result = graph.run_pipeline(A, {"multi_origin": config_for(), "output_dir": directory,
                                            "fuzzing_options": {"engine": "python_http"}})
            model.assert_not_called()
            agent.assert_not_called()
            self.assertEqual(result["pipeline_status"], "failed")
            self.assertEqual(result["stop_reason"], "multi_origin_execution_not_enabled_b1")
            self.assertEqual(result["approved_origins"], [A, B])
            self.assertEqual(result["telemetry"]["http"]["known_requests"], 0)
            self.assertEqual(result["llm_call_count"], 0)
            saved = json.loads(Path(result["artifacts"]["result"]).read_text(encoding="utf-8"))
            self.assertEqual(saved["origin_contexts"], result["origin_contexts"])
