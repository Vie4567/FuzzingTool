"""Real LangGraph failure/checkpoint routing with offline dispatch fixtures."""

from contextlib import ExitStack
from copy import deepcopy
import importlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from src.coordinator.artifacts import ArtifactWriteError, RunArtifacts
from src.coordinator.llm_logging import invoke_logged
from src.coordinator.telemetry import current_telemetry, record_http_attempt


class _Response:
    def __init__(self, value=None, error=None):
        self.value, self.error = value, error

    def invoke(self, _input):
        if self.error is not None:
            raise self.error
        return self.value


class PipelineFailureIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.dict(os.environ, {
            "PYTHON_DOTENV_DISABLED": "1", "LANGSMITH_TRACING": "false",
            "LANGCHAIN_TRACING_V2": "false",
            "LLM_RESPONSE_LOG_FILE": str(self.temporary / "llm_responses.jsonl"),
        }))
        self.stack.enter_context(patch("socket.socket.connect", side_effect=AssertionError("Tests must stay offline")))
        self.graph = importlib.import_module("src.coordinator.graph")
        for name in ("circuit_breakers", "llm_limiter", "tarpit_detector"):
            self.stack.enter_context(patch.object(self.graph, name, deepcopy(getattr(self.graph, name))))
        self.stack.enter_context(patch.object(self.graph, "_decision_engine", None))
        self.stack.enter_context(patch.object(self.graph, "log_decision"))
        self.stack.enter_context(patch.object(self.graph, "log_pipeline_summary"))
        self.secret = "fixture-opaque-access-token"
        self.config = {"artifact_root": str(self.temporary / "artifacts"), "token": self.secret}

    def _saved(self):
        results = list((self.temporary / "artifacts").glob("pipeline_*/result.json"))
        self.assertEqual(len(results), 1)
        return json.loads(results[0].read_text(encoding="utf-8"))

    def _assert_artifacts_safe(self):
        files = list((self.temporary / "artifacts").rglob("*.json"))
        self.assertGreater(len(files), 0)
        for file in files:
            self.assertNotIn(self.secret, file.read_text(encoding="utf-8"), str(file))

    def _fixture_agents(self, *, decision_error=None, reflection_error=None):
        # HTTP boundaries are deterministic fixtures here. Actual transport
        # dispatch is covered separately by test_runtime_telemetry.py.
        actions = {"after_tech_recon": "proceed_to_wordlist",
                   "after_wordlist_gen": "proceed_to_fuzzing",
                   "after_fuzzing": "abort_to_report"}

        def decide(**options):
            point = options["decision_point"]
            response = {"action": actions[point], "reasoning": "offline fixture"}
            return invoke_logged(
                _Response(response, decision_error if point == "after_fuzzing" else None),
                "offline input", component="Coordinator", operation=point,
                context={"token": self.secret},
            )

        def reflect(state):
            invoke_logged(_Response({}, reflection_error), "offline reflection",
                          component="Coordinator", operation="reflection", context={"token": self.secret})

        engine = SimpleNamespace(llm=None, make_decision=Mock(side_effect=decide),
                                 reflect_on_session=Mock(side_effect=reflect))
        self.stack.enter_context(patch.object(self.graph, "_get_decision_engine", return_value=engine))

        def recon(*args, **kwargs):
            record_http_attempt(kind="scoped_http", count=2)
            return {"tech_stack": {}, "discovered_paths": ["/fixture"]}

        def fuzz(*args, **kwargs):
            record_http_attempt(kind="python_http", count=1)
            return {"results": [{"url": "https://example.invalid/fixture", "path": "/fixture",
                                 "status_code": 200, "content_length": 2219}],
                    "success": True, "partial": False, "simulated": True,
                    "engine": "offline_fixture", "stop_reason": "completed",
                    "stats": {"total_requests": 1}}

        recon_agent = self.stack.enter_context(patch.object(self.graph, "TechReconAgent", autospec=True))
        recon_agent.return_value.execute.side_effect = recon
        word_agent = self.stack.enter_context(patch.object(self.graph, "WordlistGenAgent", autospec=True))
        word_agent.return_value.execute.return_value = {"wordlist": ["/fixture"]}
        public_options = self.graph.FuzzingAgent._public_options
        fuzz_agent = self.stack.enter_context(patch.object(self.graph, "FuzzingAgent", autospec=True))
        fuzz_agent._public_options.side_effect = public_options
        fuzz_agent.return_value.execute.side_effect = fuzz
        return engine

    def test_graph_build_error_is_saved_before_any_dispatch(self):
        with patch.object(self.graph, "build_coordinator_graph", side_effect=ImportError(self.secret)):
            result = self.graph.run_pipeline("https://example.invalid", self.config)
        self.assertEqual(result["pipeline_status"], "failed")
        self.assertEqual(result["error_log"][-1]["type"], "ImportError")
        self.assertEqual(result["total_http_requests"], 0)
        self.assertEqual(result["llm_call_count"], 0)
        self.assertEqual(result, self._saved())
        self._assert_artifacts_safe()

    def test_eleven_timeouts_are_counted_saved_and_never_successful(self):
        self._fixture_agents()
        errors = [{"url": f"https://example.invalid/p{i}", "status_code": None,
                   "error": "TimeoutError: timed out " + self.secret} for i in range(11)]
        rows = [dict(row, content_length=None) for row in errors]

        def fuzz(**_options):
            record_http_attempt(kind="python_http", count=11)
            # Also test the defensive guard against an inconsistent old engine.
            return {"results": rows, "errors": errors, "success": True,
                    "partial": False, "stop_reason": "completed", "engine": "python_http",
                    "stats": {"total_requests": 11, "responses_received": 0}}

        self.graph.FuzzingAgent.return_value.execute.side_effect = fuzz
        result = self.graph.run_pipeline("https://example.invalid", self.config)
        self.assertEqual(len(result["fuzzing_execution"]["errors"]), 11)
        summaries = [e for e in result["error_log"] if e["agent"] == "fuzzing"]
        self.assertEqual(sum(e["count"] for e in summaries), 11)
        self.assertEqual(summaries[0]["error_type"], "timeout")
        self.assertEqual(result["agent_statuses"]["fuzzing"], "failed")
        self.assertNotEqual(result["pipeline_status"], "completed")
        self.assertEqual(len(result["raw_results"]), 11)
        self.assertEqual(result["total_http_requests"], 13)  # Two Recon fixture calls.
        self.assertEqual(result["llm_call_count"], 3)  # No extra error-summary LLM.
        self.assertEqual(result, self._saved())
        self._assert_artifacts_safe()

    def test_error_summary_is_idempotent_per_attempt_and_additive_across_retries(self):
        state = {"error_log": [], "agent_attempts": {"fuzzing": 1}}
        errors = [{"error": "TimeoutError: timed out"}] * 11
        self.graph._sync_fuzzing_errors(state, errors)
        self.graph._sync_fuzzing_errors(state, errors)
        self.assertEqual(sum(e["count"] for e in state["error_log"]), 11)
        state["agent_attempts"]["fuzzing"] = 2
        self.graph._sync_fuzzing_errors(state, errors[:2])
        self.assertEqual(sum(e["count"] for e in state["error_log"]), 13)
        self.assertEqual([e["attempt"] for e in state["error_log"]], [1, 2])

    def test_ffuf_aggregate_keeps_reported_error_count(self):
        state = {"error_log": []}
        self.graph._sync_fuzzing_errors(state, [
            {"error_type": "transport_error", "error": "ffuf reported request errors", "count": 11},
            {"error_type": "engine_error", "error": "ffuf process failed", "count": 1},
        ])
        counts = {e["error_type"]: e["count"] for e in state["error_log"]}
        self.assertEqual(counts, {"transport_error": 11, "engine_error": 1})

    def test_valid_http_error_statuses_do_not_become_transport_errors(self):
        state = self.graph.init_state({"target_url": "https://example.invalid", "config": {}})
        with patch.object(self.graph, "_get_decision_engine", return_value=SimpleNamespace(llm=None)), \
                patch.object(self.graph.FuzzingAgent, "execute", return_value={
                    "results": [{"status_code": 403}, {"status_code": 404}],
                    "stats": {}, "errors": [], "success": True, "stop_reason": "completed"}):
            self.graph.run_fuzzing(state)
        self.assertEqual(state["error_log"], [])
        self.assertEqual(state["agent_statuses"]["fuzzing"], "success")

    def test_real_graph_invalid_url_persists_and_never_initializes_llm(self):
        with patch.object(self.graph, "_get_decision_engine", side_effect=AssertionError("No LLM for invalid URL")) as engine:
            result = self.graph.run_pipeline("invalid-url", self.config)
        engine.assert_not_called()
        self.assertEqual(result["agent_statuses"]["validate"], "failed")
        self.assertEqual(result["pipeline_status"], "failed")
        self.assertEqual(result["total_http_requests"], 0)
        self.assertEqual(result["llm_call_count"], 0)
        self.assertTrue(result["finished_at"])
        self.assertEqual(result, self._saved())
        self._assert_artifacts_safe()

    def test_decision_failure_keeps_prior_measurements_and_attempt_counters(self):
        engine = self._fixture_agents(decision_error=RuntimeError("decision failed " + self.secret))
        result = self.graph.run_pipeline("https://example.invalid", self.config)
        self.assertEqual(result["pipeline_status"], "failed")
        self.assertEqual(result["raw_results"][0]["content_length"], 2219)
        self.assertEqual(result["agent_statuses"]["fuzzing"], "success")
        self.assertEqual(result["total_http_requests"], 3)
        self.assertEqual(result["llm_call_count"], 3)
        self.assertEqual(result["coordinator_llm_calls"], 3)
        self.assertEqual(result["telemetry"]["llm"]["failed"], 1)
        self.assertEqual(result["telemetry"]["llm"]["succeeded"], 2)
        self.assertEqual(result["telemetry"]["http"]["by_phase"]["run_tech_recon"]["scoped_http"], 2)
        engine.reflect_on_session.assert_not_called()
        self.assertEqual(result, self._saved())
        self._assert_artifacts_safe()

    def test_caught_reflection_failure_is_partial_and_saved(self):
        self._fixture_agents(reflection_error=RuntimeError("reflection failed " + self.secret))
        result = self.graph.run_pipeline("https://example.invalid", self.config)
        self.assertEqual(result["pipeline_status"], "partial")
        self.assertEqual(result["raw_results"][0]["status_code"], 200)
        self.assertEqual(result["error_log"][-1]["agent"], "reflection")
        self.assertEqual(result["audit_log"][-1]["type"], "reflection_failed")
        self.assertEqual(result["total_http_requests"], 3)
        self.assertEqual(result["llm_call_count"], 4)
        self.assertEqual(result["telemetry"]["llm"]["failed"], 1)
        self.assertEqual(result, self._saved())
        self._assert_artifacts_safe()

    def test_keyboard_interrupt_is_saved_then_reraised_with_clean_context(self):
        self._fixture_agents(decision_error=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.graph.run_pipeline("https://example.invalid", self.config)
        result = self._saved()
        self.assertEqual(result["pipeline_status"], "interrupted")
        self.assertEqual(result["raw_results"][0]["content_length"], 2219)
        self.assertEqual(result["total_http_requests"], 3)
        self.assertEqual(result["llm_call_count"], 3)
        self.assertEqual(result["telemetry"]["llm"]["failed"], 1)
        self.assertEqual(result["error_log"][-1]["type"], "KeyboardInterrupt")
        self.assertIsNone(current_telemetry())
        self.assertIsNone(self.graph._active_run.get())
        self._assert_artifacts_safe()

    def test_disk_error_stops_before_dispatch_and_does_not_claim_saved_failure(self):
        original_save = RunArtifacts.save
        saves = []

        def save(artifacts, state, **kwargs):
            saves.append(kwargs)
            if len(saves) == 2:
                raise ArtifactWriteError("simulated disk unavailable")
            return original_save(artifacts, state, **kwargs)

        with patch.object(RunArtifacts, "save", new=save), \
                patch.object(self.graph, "_get_decision_engine") as engine:
            with self.assertRaises(ArtifactWriteError):
                self.graph.run_pipeline("https://example.invalid", self.config)
        engine.assert_not_called()
        self.assertEqual(len(saves), 2)
        saved = self._saved()
        self.assertEqual(saved["pipeline_status"], "running")
        self.assertEqual(saved["total_http_requests"], 0)
        self.assertIsNone(self.graph._active_run.get())
        self._assert_artifacts_safe()


if __name__ == "__main__":
    unittest.main()
