"""Coordinator measurement context and evidence-gated reflection; entirely offline."""
from contextlib import ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from langchain_core.language_models.fake_chat_models import FakeListChatModel

from src.coordinator.decision_engine import DecisionEngine, _bounded_json
from src.coordinator.knowledge_store import KnowledgeStore
from src.coordinator.state import lifecycle_summary, error_count
from src.coordinator.telemetry import telemetry_session


class CoordinatorObservationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.stack.enter_context(patch.dict(os.environ, {
            "PYTHON_DOTENV_DISABLED": "1", "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false",
            "LLM_RESPONSE_LOG_FILE": str(self.directory / "llm.jsonl"),
        }))
        self.stack.enter_context(patch("socket.socket.connect", side_effect=AssertionError("No network in this test")))
        self.state = {
            "session_id": "fixture-session", "target_url": "https://example.invalid",
            "wordlist": [f"/candidate-{i}" for i in range(12)],
            "wordlist_metadata": {"generated_valid_count": 1950, "selected_count": 12},
            "fuzzing_stats": {"planned_requests": 12, "attempted_requests": 11,
                              "responses_received": 0, "network_errors": 11, "remaining_requests": 1},
            "fuzzing_execution": {"engine": "python_http", "stop_reason": "transport_error"},
            "agent_statuses": {"fuzzing": "failed"}, "error_log": [{"count": 11, "error_type": "timeout"}],
            "decision_chain": [{"decision_id": "D1", "decision_point": "after_fuzzing",
                                "action": "abort_to_report", "reasoning": {"analysis": "fixture"}}],
            "audit_log": [], "verified_results": [], "false_positives": [], "verified_parameters": [],
        }

    def engine(self, reflection=None):
        reflection = reflection if reflection is not None else {"lessons_learned": [], "decision_evaluations": []}
        return DecisionEngine(FakeListChatModel(responses=[json.dumps(reflection)]),
                              KnowledgeStore(str(self.directory / "knowledge")))

    def reflect(self, engine):
        with telemetry_session() as telemetry:
            result = engine.reflect_on_session(self.state)
        self.assertEqual(telemetry.snapshot()["llm"]["attempted"], 1)
        self.assertEqual(telemetry.snapshot()["llm"]["succeeded"], 1)
        self.assertEqual(telemetry.snapshot()["http"]["total_requests"], 0)
        return result

    def test_1950_generated_12_selected_11_timeouts_remain_distinct(self):
        engine = self.engine()
        expected = {"generated_count": 1950, "selected_count": 12, "planned_requests": 12,
                    "attempted_requests": 11, "responses_received": 0, "network_errors": 11, "remaining_requests": 1}
        summary = lifecycle_summary(self.state)
        for key, value in expected.items():
            self.assertEqual(summary[key], value)
        context = engine._build_context(self.state, "fuzzing")
        snapshot = engine._snapshot_state(self.state)
        variables = engine._build_decision_prompt_vars(self.state, "after_fuzzing", "fuzzing", "failed", "", 0, {}, [])
        self.assertEqual(context["lifecycle"], summary)
        self.assertEqual(snapshot["lifecycle"], summary)
        self.assertEqual(json.loads(variables["lifecycle_summary"]), summary)
        self.assertEqual(variables["error_count"], 11)
        prompt = engine.decision_prompt.invoke(variables).to_string()
        self.assertIn('"generated_count": 1950', prompt)
        self.assertIn("HTTP 200 chưa phải endpoint", prompt)
        self.assertIn("không phải bằng chứng SharedState bị hỏng", prompt)

    def test_unknown_ffuf_counts_are_not_inferred_from_returned_records(self):
        self.state["fuzzing_execution"]["engine"] = "ffuf_cli"
        self.state["fuzzing_stats"] = {"planned_requests": 12, "attempted_requests": None,
            "responses_received": 8, "response_count_scope": "returned_ffuf_records", "total_responses_received": None,
            "network_errors": None, "remaining_requests": None}
        self.state["raw_results"] = [{"status_code": 200}] * 8
        summary = lifecycle_summary(self.state)
        for key in ("attempted_requests", "responses_received", "network_errors", "remaining_requests"):
            self.assertIsNone(summary[key])
        self.assertEqual(summary["responses_received_lower_bound"], 8)

    def test_legacy_aggregated_error_count(self):
        self.assertEqual(error_count({"error_log": [{"count": 11}, {"error": "legacy"}]}), 12)

    def test_proxy_healthcheck_and_connect_scopes_are_explicit(self):
        self.state["fuzzing_stats"].update(attempted_requests=15, fuzzing_requests=11,
                                          healthcheck_requests=4, proxy_connect_errors=2)
        summary = lifecycle_summary(self.state)
        self.assertEqual(summary["attempted_requests"], 15)
        self.assertEqual(summary["healthcheck_requests"], 4)
        self.assertEqual(summary["proxy_connect_errors"], 2)
        self.assertIn("separate from network_errors", summary["count_scope"])

    def test_missing_or_false_evidence_skips_lessons_but_saves_session_history(self):
        engine = self.engine({"lessons_learned": [
            {"lesson": "WAF blocked all IPs", "evidence": "11 timeout errors"},
            {"lesson": "SharedState broken", "evidence": {"fact": "generated_count", "value": 12}},
            {"lesson": "unknown", "evidence": {"fact": "waf_detected", "value": True}},
        ], "decision_evaluations": [{"decision_id": "D1", "was_correct": True, "retrospective_note": "model opinion"}]})
        output = self.reflect(engine)
        self.assertEqual(output["lessons_learned"], [])
        self.assertEqual(output["lessons_rejected_count"], 3)
        self.assertFalse(engine.knowledge.lessons_file.exists())
        sessions = list(engine.knowledge.sessions_dir.glob("*.json"))
        self.assertEqual(len(sessions), 1)
        saved = json.loads(sessions[0].read_text(encoding="utf-8"))
        self.assertEqual(saved["decisions"][0]["action"], "abort_to_report")
        self.assertEqual(saved["outcomes"]["errors_encountered"], 11)
        outcome = self.state["decision_chain"][0]["outcome"]
        self.assertIsNone(outcome["was_correct_decision"])
        self.assertEqual(outcome["verification_status"], "unverified_model_assessment")

    def test_matching_evidence_persists_only_canonical_observation_not_causal_prose(self):
        engine = self.engine({"lessons_learned": [{"id": "L001", "lesson": "WAF definitely blocked IPs",
            "evidence": {"fact": "network_errors", "value": 11}, "confidence": .99,
            "applicable_when": {"all_targets": True}}], "decision_evaluations": []})
        engine.knowledge.lessons_file.write_text(json.dumps({"lessons": [{"id": "L001", "lesson": "existing",
                                                              "times_validated": 1, "confidence": .5}]}), encoding="utf-8")
        output = self.reflect(engine)
        saved = json.loads(engine.knowledge.lessons_file.read_text(encoding="utf-8"))["lessons"]
        self.assertEqual(saved[0]["times_validated"], 1)
        self.assertEqual(saved[0]["confidence"], .5)
        self.assertEqual(saved[1]["id"], "L002")
        self.assertIn("network_errors = 11", saved[1]["lesson"])
        self.assertNotIn("WAF", saved[1]["lesson"])
        self.assertEqual(saved[1]["applicable_when"], {"session_id": "fixture-session"})
        self.assertEqual(output["lessons_learned"][0]["verification_status"], "verified_observation")

    def test_evidence_type_mismatch_and_unknown_value_are_rejected(self):
        engine = self.engine({"lessons_learned": [
            {"evidence": {"fact": "network_errors", "value": "11"}},
            {"evidence": {"fact": "responses_received", "value": False}},
            {"evidence": {"fact": "fuzzing_requests", "value": None}},
        ], "decision_evaluations": []})
        self.assertEqual(self.reflect(engine)["lessons_learned"], [])

    def test_malformed_lesson_items_are_skipped_without_losing_session(self):
        engine = self.engine({"lessons_learned": [None, "unsupported assertion", {},
                              {"evidence": {"fact": [], "value": 11}}, {"evidence": {"fact": {}, "value": 11}}],
                              "decision_evaluations": [None, "unsupported assessment"]})
        result = self.reflect(engine)
        self.assertEqual(result["lessons_learned"], [])
        self.assertEqual(result["lessons_rejected_count"], 5)
        self.assertEqual(len(list(engine.knowledge.sessions_dir.glob("*.json"))), 1)

    def test_duplicate_lessons_do_not_amplify_observation_count(self):
        evidence = {"fact": "network_errors", "value": 11}
        engine = self.engine({"lessons_learned": [{"evidence": evidence}] * 50, "decision_evaluations": []})
        result = self.reflect(engine)
        self.assertEqual(len(result["lessons_learned"]), 1)
        self.assertEqual(result["lessons_rejected_count"], 49)

    def test_actual_prompt_context_is_bounded_and_contains_no_raw_http_rows(self):
        engine = self.engine()
        self.state["raw_results"] = [{"status_code": 200, "body": "PRIVATE-RAW-HTTP-MARKER" * 1000}] * 10000
        knowledge = {"similar_sessions": [{"nested": {"text": "historical" * 10000}}] * 1000}
        variables = engine._build_decision_prompt_vars(self.state, "after_fuzzing", "fuzzing", "partial", "A" * 100000, 0, knowledge, [])
        prompt = engine.decision_prompt.invoke(variables).to_string()
        self.assertNotIn("PRIVATE-RAW-HTTP-MARKER", prompt)
        self.assertLess(len(prompt), 15000)
        self.state["decision_chain"] = [dict(deepcopy(self.state["decision_chain"][0]), decision_id=f"D{i}",
            reasoning={"analysis": "A" * 10000}) for i in range(100)]
        with patch("src.coordinator.decision_engine.invoke_logged", wraps=__import__(
                "src.coordinator.decision_engine", fromlist=["invoke_logged"]).invoke_logged) as invoke:
            self.reflect(engine)
        supplied = invoke.call_args.args[1]
        rows = json.loads(supplied["decision_chain_summary"])
        self.assertEqual(len(rows), 20)
        self.assertTrue(all(len(row["reasoning"]) <= 300 for row in rows))
        session = json.loads(next(engine.knowledge.sessions_dir.glob("*.json")).read_text(encoding="utf-8"))
        self.assertEqual(len(session["decisions"]), 100)  # Persistence keeps full history.

    def test_wide_nested_knowledge_has_hard_prompt_and_traversal_limits(self):
        class TrackedDict(dict):
            visited = 0

            def items(self):
                for item in super().items():
                    type(self).visited += 1
                    yield item

        value = "\\\"" * 10000
        for _ in range(5):
            value = TrackedDict({f"key_{i}": value for i in range(1000)})
        rendered = _bounded_json(value)
        self.assertLessEqual(len(rendered), 4000)
        self.assertLessEqual(TrackedDict.visited, 110)
        self.assertIsInstance(json.loads(rendered), dict)

    def test_error_prompt_is_bounded_and_redacts_credentials(self):
        engine = self.engine()
        self.state["config"] = {"token": "fixture-secret-token"}
        self.state["tech_stack"] = {f"k{i}": "large-value" * 10000 for i in range(100)}
        variables = engine._build_error_prompt_vars(self.state, "fuzzing", "fixture-secret-token" * 1000, {}, [])
        self.assertLessEqual(len(variables["state_snapshot_at_error"]), 4000)
        self.assertNotIn("fixture-secret-token", variables["error_message"])
        self.assertLessEqual(len(variables["error_message"]), 1200)


if __name__ == "__main__":
    unittest.main()
