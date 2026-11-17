"""Offline persistence/redaction regression tests; no live target or LLM."""

from copy import deepcopy
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.coordinator.artifacts import ArtifactWriteError, RunArtifacts


class PipelineArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = {"artifact_root": self.temporary.name}

    def test_unique_directories_and_atomic_latest_with_per_node_snapshots(self):
        first = RunArtifacts(self.config)
        second = RunArtifacts(self.config)
        self.assertNotEqual(first.directory, second.directory)
        state = {"raw_results": [{"status_code": 200, "content_length": 2219}],
                 "agent_statuses": {"fuzzing": "success"}}
        before = deepcopy(state)
        saved = first.save(state, node="fuzzing")
        self.assertEqual(before, state)
        self.assertEqual(saved, json.loads(first.result_path.read_text(encoding="utf-8")))
        failed = first.record_failure(state, RuntimeError("decision unavailable"), node="llm_decide_fuzzing")
        self.assertEqual(before, state)
        self.assertEqual(failed["raw_results"], state["raw_results"])
        self.assertEqual(failed["agent_statuses"]["fuzzing"], "success")
        self.assertEqual(failed["agent_statuses"]["llm_decide_fuzzing"], "failed")
        self.assertEqual(failed["pipeline_status"], "failed")
        self.assertEqual(2, len(list((first.directory / "checkpoints").glob("*.json"))))
        self.assertEqual(failed, json.loads(first.result_path.read_text(encoding="utf-8")))

    def test_full_state_and_exception_redact_known_secrets(self):
        config = {**self.config,
                  "token": "opaque-token-value",
                  "recon_options": {"custom_headers": {"X-Session": "private-session-value"},
                                    "account": {"username": "private-account-name", "password": "private-account-password"}},
                  "fuzzing_options": {"proxy_profiles": {"proxy1": "http://private-proxy-user:private%20proxy%20password@127.0.0.1:8080"},
                                      "headers": {"Authorization": "Bearer opaque-token-value"}},
                  "api_key": "my-private-key-value"}
        artifacts = RunArtifacts(config)
        state = {"config": config, "param_results": [{"evidence": "private-session-value"}],
                 "proxy_error": "http://private-proxy-user:private%20proxy%20password@127.0.0.1:8080 timed out",
                 "other": "private proxy password",
                 "raw_results": [{"status_code": 403, "content_length": 10}],
                 "error_log": [{"error": "private-account-password, private-account-name"}]}
        saved = artifacts.record_failure(state, RuntimeError("opaque-token-value private-session-value my-private-key-value"), node="param_disc")
        encoded = json.dumps(saved)
        for secret in ("opaque-token-value", "private-session-value", "private-account-name", "private-account-password",
                       "private-proxy-user", "private%20proxy%20password", "private proxy password", "my-private-key-value"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(saved["raw_results"], [{"status_code": 403, "content_length": 10}])
        for file in artifacts.directory.rglob("*.json"):
            self.assertNotIn("opaque-token-value", file.read_text(encoding="utf-8"))

    def test_external_url_userinfo_masked_even_without_config(self):
        artifacts = RunArtifacts(self.config)
        state = {"error": "http://user-name:private@password@localhost:8080 failed"}
        saved = artifacts.save(state)
        self.assertNotIn("private", saved["error"])
        self.assertNotIn("user-name", saved["error"])
        self.assertIn("localhost:8080", saved["error"])

    def test_unknown_objects_cycles_and_nonfinite_numbers_never_use_repr(self):
        class SecretObject:
            def __str__(self):
                raise AssertionError("must not stringify arbitrary object")
            def __repr__(self):
                raise AssertionError("must not repr arbitrary object")

        state = {"value": SecretObject(), SecretObject(): "safe", "nan": math.nan}
        state["cycle"] = state
        saved = RunArtifacts(self.config).save(state)
        self.assertEqual(saved["value"], "[SecretObject]")
        self.assertEqual(saved["cycle"], "[recursive value]")
        self.assertIsNone(saved["nan"])

    def test_replace_failure_keeps_previous_result_and_is_not_silently_swallowed(self):
        artifacts = RunArtifacts(self.config)
        previous = artifacts.save({"raw_results": [1]}, node="fuzzing")
        original_replace = __import__("os").replace

        def replace(source, destination):
            if Path(destination) == artifacts.result_path:
                raise PermissionError("private credential must not be echoed")
            original_replace(source, destination)

        with patch("src.coordinator.artifacts.os.replace", side_effect=replace):
            with self.assertRaises(ArtifactWriteError) as raised:
                artifacts.save({"raw_results": [1, 2]}, node="param_disc")
        self.assertNotIn("private credential", str(raised.exception))
        self.assertEqual(previous, json.loads(artifacts.result_path.read_text(encoding="utf-8")))
        checkpoint = artifacts.directory / "checkpoints" / "0002_param_disc.json"
        self.assertEqual([1, 2], json.loads(checkpoint.read_text(encoding="utf-8"))["raw_results"])
        self.assertEqual([], list(artifacts.directory.rglob(".pending_*.json")))

    def test_directory_failure_is_explicit(self):
        with patch("src.coordinator.artifacts.Path.mkdir", side_effect=PermissionError("secret")):
            with self.assertRaises(ArtifactWriteError) as raised:
                RunArtifacts(self.config)
        self.assertNotIn("secret", str(raised.exception))

    def test_interrupt_state_saved_without_mutating_input(self):
        state = {"raw_results": [{"status_code": 200}], "error_log": None, "agent_statuses": None}
        original = deepcopy(state)
        artifacts = RunArtifacts(self.config)
        result = artifacts.record_failure(state, KeyboardInterrupt(), node="param_disc")
        self.assertEqual(original, state)
        self.assertEqual("interrupted", result["pipeline_status"])
        self.assertEqual("KeyboardInterrupt", result["error_log"][0]["type"])
        self.assertEqual(result, json.loads(artifacts.result_path.read_text(encoding="utf-8")))

    def test_output_dir_is_parent_not_overwritten_run(self):
        artifacts = RunArtifacts({"output_dir": self.temporary.name})
        self.assertEqual(artifacts.directory.parent, Path(self.temporary.name).resolve())
        self.assertTrue(artifacts.directory.name.startswith("pipeline_"))


if __name__ == "__main__":
    unittest.main()
