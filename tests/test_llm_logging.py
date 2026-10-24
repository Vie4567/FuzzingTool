"""Response logging records actual model output while keeping credentials out."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.setdefault("PYTHON_DOTENV_DISABLED", "1")

from src.coordinator.llm_logging import (  # noqa: E402
    invoke_logged,
    response_log_path,
    sanitize_for_log,
)


class FakeLLM:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.inputs = []

    def invoke(self, value):
        self.inputs.append(value)
        if self.error is not None:
            raise self.error
        return self.response


class LLMResponseLoggingTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "nested" / "responses.jsonl"
        self.environment = patch.dict(os.environ, {"LLM_RESPONSE_LOG_FILE": str(self.path)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def records(self):
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()]

    def invoke(self, llm, value="Do not save this prompt", context=None):
        return invoke_logged(llm, value, component="wordlist_gen", operation="pattern_parts", context=context)

    def test_response_and_usage_are_saved_but_prompt_is_not(self):
        response = SimpleNamespace(
            content='{"resources": ["account", "settings"]}',
            response_metadata={"model_name": "test-model", "request_id": "req-123"},
            usage_metadata={"input_tokens": 10, "output_tokens": 12, "total_tokens": 22},
            id="response-456",
        )
        llm = FakeLLM(response)
        result = self.invoke(llm, context={"pattern_id": "api/resource/action", "batch": 2})
        self.assertIs(result, response)
        self.assertEqual(llm.inputs, ["Do not save this prompt"])
        event = self.records()[0]
        self.assertEqual(event["response"]["content"], response.content)
        self.assertEqual(event["response"]["usage_metadata"]["total_tokens"], 22)
        self.assertEqual(event["response"]["response_metadata"]["request_id"], "req-123")
        self.assertEqual(event["component"], "wordlist_gen")
        self.assertEqual(event["operation"], "pattern_parts")
        self.assertEqual(event["context"]["batch"], 2)
        self.assertGreaterEqual(event["duration_seconds"], 0)
        self.assertTrue(event["timestamp"].endswith("+00:00"))
        self.assertNotIn("Do not save this prompt", self.path.read_text(encoding="utf-8"))

    def test_malformed_json_is_saved_before_callers_can_parse_it(self):
        text = '```json\n{"resources": ["account",\ninvalid model output'
        response = SimpleNamespace(content=text)
        self.assertIs(self.invoke(FakeLLM(response)), response)
        self.assertEqual(self.records()[0]["response"]["content"], text)

    def test_full_response_is_not_truncated(self):
        content = "resource-item\n" * 30000
        self.invoke(FakeLLM(SimpleNamespace(content=content)))
        self.assertEqual(self.records()[0]["response"]["content"], content)

    def test_error_is_logged_and_original_exception_reraised(self):
        failure = RuntimeError("upstream unavailable")
        with self.assertRaises(RuntimeError) as caught:
            self.invoke(FakeLLM(error=failure))
        self.assertIs(caught.exception, failure)
        event = self.records()[0]
        self.assertEqual(event["status"], "error")
        self.assertEqual(event["error"], {"type": "RuntimeError", "message": "upstream unavailable"})

    def test_error_cannot_echo_the_request_or_credentials(self):
        prompt = "A private request that should never be saved"
        secret = "llm-key-value-123456"
        with patch.dict(os.environ, {"CUSTOM_API_KEY": secret}):
            failure = RuntimeError(f"Rejected input {prompt}; Authorization: Bearer {secret}")
            with self.assertRaises(RuntimeError):
                self.invoke(FakeLLM(error=failure), prompt)
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn(prompt, text)
        self.assertNotIn(secret, text)
        self.assertIn("REQUEST REDACTED", text)

    def test_nested_credentials_are_removed_including_repeated_values(self):
        password = "opaque-private-password-12345"
        authorization = "Bearer opaque-private-authorization-12345"
        content = json.dumps({"nested": {"password": password, "Authorization": authorization},
                              "echo": f"{password}; {authorization}"})
        response = SimpleNamespace(content=content, response_metadata={"headers": {"set-cookie": "session=secret-cookie"}})
        self.invoke(FakeLLM(response), context={"api_key": "opaque-context-key", "echo": "opaque-context-key"})
        saved = self.path.read_text(encoding="utf-8")
        for secret in (password, authorization, "secret-cookie", "opaque-context-key"):
            self.assertNotIn(secret, saved)
        self.assertIn("[REDACTED]", saved)
        # Credential redaction should leave otherwise valid model JSON usable.
        self.assertEqual(json.loads(self.records()[0]["response"]["content"])["nested"]["password"], "[REDACTED]")

    def test_raw_invalid_json_header_and_jwt_patterns_are_removed(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcml2YXRlLXBlcnNvbiJ9.c2lnbmF0dXJlLXByaXZhdGUtMTIzNDU2"
        text = f'not-json "api_key": "opaque-json-api-key",\nAuthorization: Bearer {jwt}\nCookie: sid=private-cookie\nmore'
        self.invoke(FakeLLM(SimpleNamespace(content=text)))
        saved = self.path.read_text(encoding="utf-8")
        for secret in (jwt, "opaque-json-api-key", "private-cookie"):
            self.assertNotIn(secret, saved)

    def test_environment_credentials_are_removed_when_unlabelled(self):
        secrets = {"CUSTOM_API_KEY": "opaque-unlabelled-api-value", "SOME_TOKEN": "opaque-unlabelled-token-value",
                   "SERVICE_SECRET": "opaque-unlabelled-secret-value", "APP_PASSWORD": "opaque-unlabelled-password-value",
                   "APP_COOKIE": "opaque-unlabelled-cookie-value", "AUTHORIZATION": "opaque-unlabelled-auth-value"}
        with patch.dict(os.environ, secrets):
            self.invoke(FakeLLM(SimpleNamespace(content=" ".join(secrets.values()))))
        saved = self.path.read_text(encoding="utf-8")
        for secret in secrets.values():
            self.assertNotIn(secret, saved)

    def test_nested_credential_object_in_invalid_outer_json_is_redacted(self):
        content = 'invalid prefix {"credentials": {"user": "private-user", "pass": "private-pass"}, "echo": "private-pass"'
        self.invoke(FakeLLM(SimpleNamespace(content=content)))
        saved = self.path.read_text(encoding="utf-8")
        self.assertNotIn("private-user", saved)
        self.assertNotIn("private-pass", saved)

    def test_prompt_credential_echo_is_redacted_without_persisting_prompt(self):
        prompt = '{"headers": {"Authorization": "opaque-authorization-value-123456"}}'
        self.invoke(FakeLLM(SimpleNamespace(content="value: opaque-authorization-value-123456")), prompt)
        saved = self.path.read_text(encoding="utf-8")
        self.assertNotIn("opaque-authorization-value-123456", saved)

    def test_pattern_segments_and_token_usage_are_not_credentials(self):
        value = {"auth_segment": ["auth", "token"], "internal_segment": ["api"],
                 "token_resource": ["tokens"], "usage_metadata": {"total_tokens": 14}}
        self.assertEqual(sanitize_for_log(value), value)
        self.invoke(FakeLLM(SimpleNamespace(content=json.dumps(value))), context={"auth_segment": "auth", "prompt": "private prompt"})
        event = self.records()[0]
        self.assertEqual(json.loads(event["response"]["content"]), value)
        self.assertEqual(event["context"]["auth_segment"], "auth")
        self.assertEqual(event["context"]["prompt"], "[REDACTED]")

    def test_concurrent_appends_produce_complete_unique_json_records(self):
        def one(index):
            return self.invoke(FakeLLM(SimpleNamespace(content=f"batch-{index}")), context={"index": index})
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(one, range(32)))
        events = self.records()
        self.assertEqual(len(events), 32)
        self.assertEqual(len({event["call_id"] for event in events}), 32)
        self.assertEqual({event["context"]["index"] for event in events}, set(range(32)))

    def test_unwritable_log_does_not_change_success_or_failure(self):
        with patch.dict(os.environ, {"LLM_RESPONSE_LOG_FILE": self.directory.name}):
            response = SimpleNamespace(content="actual response")
            self.assertIs(self.invoke(FakeLLM(response)), response)
            error = RuntimeError("original failure")
            with self.assertRaises(RuntimeError) as caught:
                self.invoke(FakeLLM(error=error))
            self.assertIs(caught.exception, error)

    def test_response_path_uses_environment_override(self):
        self.assertEqual(response_log_path(), self.path)


if __name__ == "__main__":
    unittest.main()
