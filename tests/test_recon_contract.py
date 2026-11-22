"""Recon evidence survives Coordinator handoff and checkpoints without live APIs."""

from contextlib import ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from langchain_core.messages import AIMessage
from src.agents.wordlist_gen import WordlistGenAgent, _bounded_recon_context
from src.coordinator import graph
from src.coordinator.telemetry import record_http_attempt, telemetry_session


TARGET = "https://catalog.example.invalid/app"


def fixture_result(status="completed", *, responses=1, errors=None):
    profile = {
        "schema_version": 1, "target_url": TARGET,
        "tech_stack": {"frontend": "React", "backend": "Unknown", "language": "Unknown", "cms": "Unknown"},
        "technology_evidence": [{"category": "frontend", "technology": "React",
                                 "source": "dom_attribute", "classification": "observed"}],
        "architecture": {"type": "decoupled_spa", "classification": "inferred",
                         "primary_backend_api": "https://outside.example.invalid"},
        "paths": [{"url": TARGET + "/items", "path": "/app/items", "origin": "https://catalog.example.invalid",
                   "source": "DOM", "classification": "candidate"}],
        "parameters": [{"name": "filter", "url": TARGET + "/items", "location": "query",
                        "source": "OpenAPI", "classification": "observed"}],
        "forms": [{"action": "/app/items", "method": "GET", "params": ["filter"],
                   "source": "DOM", "classification": "observed"}],
        "api_context": {"schema": {"type": "OpenAPI", "source": TARGET + "/openapi.json",
                                    "operations": [{"path": "/app/items", "method": "GET"}]},
                        "backend_origins": [{"origin": "https://outside.example.invalid",
                                             "classification": "candidate"}]},
    }
    return {
        "tech_stack": deepcopy(profile["tech_stack"]), "discovered_paths": ["/app/items"],
        "js_endpoints": ["/app/items"], "recon_profile": profile,
        "execution": {"status": status, "success": status == "completed", "completed": status == "completed",
                      "partial": status == "partial", "stop_reason": "completed" if status == "completed" else "transport_error",
                      "errors": errors or [], "channels": {"CH-3 JS": {"status": status}},
                      "stats": {"attempted_requests": 1 + len(errors or []), "responses_received": responses,
                                "network_errors": len(errors or [])}},
    }


class ReconContractTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.dict(os.environ, {
            "PYTHON_DOTENV_DISABLED": "1", "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false",
            "DEEPSEEK_API_KEY": "", "OPENAI_API_KEY": "", "LLM_RESPONSE_LOG_FILE": str(self.temp / "llm.jsonl"),
        }))
        self.stack.enter_context(patch("socket.socket.connect", side_effect=AssertionError("Offline contract tests")))
        self.engine = SimpleNamespace(llm=None, make_decision=lambda **kw: {"action": "abort_to_report"},
                                      reflect_on_session=lambda state: None)
        self.stack.enter_context(patch.object(graph, "_get_decision_engine", return_value=self.engine))
        self.stack.enter_context(patch.object(graph, "circuit_breakers", deepcopy(graph.circuit_breakers)))
        self.stack.enter_context(patch.object(graph, "log_decision"))
        self.stack.enter_context(patch.object(graph, "log_pipeline_summary"))

    def state(self):
        return graph.init_state({"target_url": TARGET, "config": {}})

    def test_full_profile_and_operator_target_reach_agent2_without_mutation(self):
        output = fixture_result()
        original = deepcopy(output)
        state = self.state()
        with patch.object(graph.TechReconAgent, "execute", return_value=output):
            graph.run_tech_recon(state)
        with patch.object(graph.WordlistGenAgent, "execute", return_value={"wordlist": ["/app/items"]}) as wordlist:
            graph.run_wordlist_gen(state)
        options = wordlist.call_args.kwargs
        self.assertEqual(options["target_url"], TARGET)
        self.assertEqual(options["recon_profile"], output["recon_profile"])
        self.assertEqual(options["tech_stack"], output["tech_stack"])
        self.assertEqual(options["discovered_paths"], output["discovered_paths"])
        self.assertEqual(options["js_endpoints"], output["js_endpoints"])
        self.assertEqual(state["agent_statuses"]["tech_recon"], "success")
        self.assertEqual(state["recon_profile"]["parameters"][0]["location"], "query")
        self.assertEqual(state["recon_profile"]["forms"][0]["method"], "GET")
        self.assertEqual(output, original)

    def test_partial_measurements_and_errors_are_retained_and_redacted(self):
        secret = "opaque-fixture-access-value"
        errors = [{"channel": "CH-3 JS", "error_type": "timeout", "message": "timeout " + secret} for _ in range(3)]
        output = fixture_result("partial", errors=errors)
        state = self.state()
        state["config"] = {"bearer_token": secret}
        with patch.object(graph.TechReconAgent, "execute", return_value=output):
            graph.run_tech_recon(state)
        self.assertEqual(state["agent_statuses"]["tech_recon"], "partial")
        self.assertEqual(len(state["recon_execution"]["errors"]), 3)
        self.assertEqual(sum(row["count"] for row in state["error_log"]), 3)
        self.assertEqual(state["discovered_paths"], ["/app/items"])
        self.assertEqual(state["recon_execution"]["stats"]["responses_received"], 1)
        self.assertNotIn(secret, json.dumps({k: v for k, v in state.items() if k != "config"}))

    def test_operator_config_does_not_redact_public_recon_evidence(self):
        secret = "opaque-recon-contract-fixture-7138"
        provider_secret = "opaque-provider-fixture-1942"
        proxy_password = "fixture-proxy-pass-9371"
        proxy_url = "http://fixture-proxy-user:" + proxy_password + "@127.0.0.1:3128"
        output = fixture_result()
        output["execution"]["requests"] = [{"url": TARGET, "method": "GET", "status_code": 200}]
        output["subagent_justification"] = "echo " + " ".join((secret, provider_secret, proxy_url, proxy_password))
        original = deepcopy(output)
        state = self.state()
        state["config"] = {
            "headers": {"Authorization": "Bearer " + secret}, "api_key": provider_secret,
            "allowed_origins": ["https://catalog.example.invalid"],
            "auth_origins": ["https://catalog.example.invalid"],
            "wordlist": ["/app/items"], "llm_model": "React",
            "fuzzing_options": {"engine": "python_http", "http_method": "GET", "proxy": proxy_url},
        }
        with patch.object(graph.TechReconAgent, "execute", return_value=output):
            graph.run_tech_recon(state)
        self.assertEqual(state["recon_execution"]["requests"], output["execution"]["requests"])
        self.assertEqual(state["recon_profile"], output["recon_profile"])
        self.assertEqual(state["discovered_paths"], ["/app/items"])
        with patch.object(graph.WordlistGenAgent, "execute", return_value={"wordlist": ["/app/items"]}) as wordlist:
            graph.run_wordlist_gen(state)
        self.assertEqual(wordlist.call_args.kwargs["recon_profile"], output["recon_profile"])
        from src.coordinator.artifacts import RunArtifacts
        saved = RunArtifacts({**state["config"], "artifact_root": str(self.temp)}).save(state)
        self.assertEqual(saved["recon_execution"]["requests"], output["execution"]["requests"])
        for value in (saved, wordlist.call_args.kwargs,
                      {k: v for k, v in state.items() if k != "config"}):
            for token in (secret, provider_secret, proxy_url, proxy_password):
                self.assertNotIn(token, json.dumps(value))
        self.assertEqual(output, original)

    def test_error_summaries_are_idempotent_per_attempt_and_preserve_retries(self):
        state = self.state()
        state["agent_attempts"] = {"tech_recon": 1}
        errors = [{"channel": "CH-3 JS", "error_type": "timeout", "count": 3},
                  {"channel": "CH-6 Schema", "error_type": "parse_error", "count": 1}]
        graph._sync_recon_errors(state, errors)
        graph._sync_recon_errors(state, errors)
        self.assertEqual(sum(row["count"] for row in state["error_log"]), 4)
        state["agent_attempts"]["tech_recon"] = 2
        graph._sync_recon_errors(state, errors[:1])
        self.assertEqual(sum(row["count"] for row in state["error_log"]), 7)
        self.assertEqual({row["attempt"] for row in state["error_log"]}, {1, 2})

    def test_all_timeouts_override_inconsistent_completed_status(self):
        output = fixture_result(errors=[{"channel": "CH-1 Headers", "error_type": "timeout"}], responses=0)
        state = self.state()
        with patch.object(graph.TechReconAgent, "execute", return_value=output):
            graph.run_tech_recon(state)
        self.assertEqual(state["agent_statuses"]["tech_recon"], "failed")
        self.assertFalse(state["recon_execution"]["completed"])
        self.assertEqual(state["recon_execution"]["stop_reason"], "recon_incomplete")

    def test_valid_404_is_not_a_transport_error_or_failed_recon(self):
        output = fixture_result()
        output["status_code"] = 404
        state = self.state()
        with patch.object(graph.TechReconAgent, "execute", return_value=output):
            graph.run_tech_recon(state)
        self.assertEqual(state["agent_statuses"]["tech_recon"], "success")
        self.assertEqual(state["error_log"], [])

    def test_global_telemetry_is_not_added_again_from_recon_stats(self):
        output = fixture_result()
        output["execution"]["stats"]["attempted_requests"] = 20
        state = self.state()
        with telemetry_session():
            record_http_attempt(count=2)
            with patch.object(graph.TechReconAgent, "execute", return_value=output):
                graph.run_tech_recon(state)
            self.assertEqual(state["total_http_requests"], 2)

    def test_partial_and_failed_profile_survive_real_langgraph_checkpoints(self):
        for status, responses in (("partial", 1), ("failed", 0)):
            with self.subTest(status=status):
                output = fixture_result(status, responses=responses,
                                        errors=[{"channel": "CH-3 JS", "error_type": "timeout"}])
                with patch.object(graph.TechReconAgent, "execute", return_value=output):
                    result = graph.run_pipeline(TARGET, {"artifact_root": str(self.temp / status)})
                saved = json.loads(Path(result["artifacts"]["result"]).read_text(encoding="utf-8"))
                self.assertEqual(result, saved)
                self.assertNotEqual(result["pipeline_status"], "completed")
                self.assertEqual(result["agent_statuses"]["tech_recon"], status)
                self.assertEqual(result["recon_profile"], output["recon_profile"])
                self.assertEqual(len(result["recon_execution"]["errors"]), 1)
                checkpoints = list(Path(result["artifacts"]["directory"]).glob("checkpoints/*run_tech_recon.json"))
                self.assertTrue(any(json.loads(p.read_text(encoding="utf-8")).get("recon_profile") for p in checkpoints))

    def test_exception_on_retry_keeps_prior_observations_but_cannot_reuse_success(self):
        state = self.state()
        state["agent_attempts"] = {"tech_recon": 1}
        with patch.object(graph.TechReconAgent, "execute", return_value=fixture_result()):
            graph.run_tech_recon(state)
        state["agent_attempts"]["tech_recon"] = 2
        with patch.object(graph.TechReconAgent, "execute", side_effect=RuntimeError("fixture failure")):
            graph.run_tech_recon(state)
        self.assertEqual(state["agent_statuses"]["tech_recon"], "failed")
        self.assertEqual(state["recon_execution"]["status"], "failed")
        self.assertEqual(state["recon_execution"]["retained_profile_attempt"], 1)
        self.assertEqual(state["recon_profile"]["paths"][0]["classification"], "candidate")

    def test_legacy_results_remain_usable_without_invented_measurement_counts(self):
        state = self.state()
        with patch.object(graph.TechReconAgent, "execute", return_value={"tech_stack": {}, "discovered_paths": ["/"]}):
            graph.run_tech_recon(state)
        self.assertEqual(state["agent_statuses"]["tech_recon"], "success")
        self.assertEqual(state["recon_execution"]["measurement_status"], "legacy_unreported")
        self.assertEqual(state["recon_execution"]["stats"], {})
        self.assertIsNone(state["total_http_requests"])

    def test_failed_retry_without_responses_preserves_prior_profile_with_attempt_label(self):
        state = self.state()
        state["agent_attempts"] = {"tech_recon": 1}
        observed = fixture_result()
        with patch.object(graph.TechReconAgent, "execute", return_value=observed):
            graph.run_tech_recon(state)
        empty = fixture_result("failed", responses=0,
                               errors=[{"channel": "CH-1 Headers", "error_type": "timeout"}])
        empty["tech_stack"], empty["discovered_paths"], empty["js_endpoints"] = {}, [], []
        empty["recon_profile"]["paths"] = []
        for attempt in (2, 3):
            state["agent_attempts"]["tech_recon"] = attempt
            with patch.object(graph.TechReconAgent, "execute", return_value=empty):
                graph.run_tech_recon(state)
            self.assertEqual(state["recon_profile"], observed["recon_profile"])
            self.assertEqual(state["discovered_paths"], observed["discovered_paths"])
            self.assertEqual(state["recon_execution"]["retained_profile_attempt"], 1)
            self.assertEqual(state["recon_execution"]["attempt"], attempt)
            self.assertEqual(state["agent_statuses"]["tech_recon"], "failed")
        self.assertEqual(sum(row["count"] for row in state["error_log"]), 2)

    def test_agent2_existing_prompt_receives_classified_context_with_one_model_call(self):
        profile = fixture_result()["recon_profile"]
        model = SimpleNamespace(invoke=Mock(return_value=AIMessage(content='{"url_hierarchy":{},"naming_convention":"flat"}')))
        agent = WordlistGenAgent(llm=model)
        result = agent._analyze_dev_profile_with_llm(profile["tech_stack"], ["/app/items"],
                                                     target_url=TARGET, recon_profile=profile)
        model.invoke.assert_called_once()
        messages = model.invoke.call_args.args[0]
        prompt = "\n".join(message.content for message in messages)
        for value in (TARGET, "observed", "candidate", "inferred", "filter", "OpenAPI", "decoupled_spa"):
            self.assertIn(value, prompt)
        self.assertEqual(result["classification"], "inferred")
        self.assertEqual(result["recon_context"]["forms"][0]["classification"], "observed")

    def test_agent2_prompt_view_is_bounded_but_full_profile_is_unchanged(self):
        profile = fixture_result()["recon_profile"]
        profile["paths"] = [{"path": "/" + "x" * 1000, "classification": "candidate"} for _ in range(10000)]
        original = deepcopy(profile)
        summary = _bounded_recon_context(profile, TARGET)
        self.assertEqual(summary["counts"]["paths"], 10000)
        self.assertLess(len(json.dumps(summary)), 16000)
        self.assertEqual(profile, original)

    def test_nested_empty_api_schema_cannot_bypass_prompt_node_bound(self):
        nested = {str(n): "" for n in range(16)}
        for _ in range(4):
            nested = {str(n): nested for n in range(16)}
        profile = fixture_result()["recon_profile"]
        profile["api_context"] = {"classification": "observed", "schema": nested}
        summary = _bounded_recon_context(profile, TARGET)
        self.assertLess(len(json.dumps(summary)), 16000)
        self.assertEqual(summary["api_context"]["classification"], "observed")
        self.assertIn("truncated", json.dumps(summary))

    def test_agent2_target_identity_uses_operator_url_not_inferred_backend(self):
        profile = fixture_result()["recon_profile"]
        agent = WordlistGenAgent(llm=SimpleNamespace())
        profile_output = {"recon_context": {"counts": {"paths": 1, "parameters": 1, "forms": 1}}}
        original_cwd = Path.cwd()
        try:
            os.chdir(self.temp)
            with patch.object(agent, "_analyze_dev_profile_with_llm", return_value=profile_output) as analyze, \
                    patch.object(agent, "_run_endpoint_assembler", return_value={"endpoints": [], "metadata": {}}), \
                    patch.object(agent, "_run_sensitive_assembler", return_value={"sensitive_files": [], "metadata": {}}) as sensitive, \
                    patch.object(agent, "_run_parameter_assembler", return_value={"parameters": [], "metadata": {}}):
                result = agent._generate_wordlist_internal(
                    {"target_url": "https://legacy.example.invalid", "backend": "Unknown"}, ["/app/items"],
                    target_url=TARGET, recon_profile=profile,
                )
        finally:
            os.chdir(original_cwd)
        self.assertEqual(result["target_url"], TARGET)
        self.assertEqual(sensitive.call_args.kwargs["target_url"], TARGET)
        self.assertEqual(analyze.call_args.kwargs["recon_profile"], profile)
        self.assertEqual(result["metadata"]["recon_context"]["counts"]["forms"], 1)


if __name__ == "__main__":
    unittest.main()
