from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import run_coordinator_scan as runner
from src.agents.soft404_filter import soft404_options_from_config
from src.tools.parameter_verification import parameter_options_from_config
from src.tools.recon_http import recon_options_from_config


class CoordinatorScanRunnerTests(unittest.TestCase):
    settings = {"DEEPSEEK_API_KEY": "test-provider-secret", "LLM_MODEL": "test-model"}

    def setUp(self):
        self.network = patch("socket.create_connection", side_effect=AssertionError("No network in runner tests"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.output = runner.ROOT / "output_samples" / "diagnostics" / "runner_config_test"

    def config(self, extra=(), settings=None, token="test-bearer-secret"):
        args = runner.parser().parse_args(["--target", "https://authorized.example", *extra])
        return runner.build_config(args, settings or self.settings, token, self.output)[1]

    def test_auth_scope_tls_and_existing_verification_guards(self):
        config = self.config(token="Bearer test-bearer-secret")
        self.assertEqual(recon_options_from_config(config)["headers"],
                         config["fuzzing_options"]["headers"])
        self.assertEqual(config["headers"]["Authorization"], "Bearer test-bearer-secret")
        self.assertEqual(config["auth_origins"], ["https://authorized.example"])
        self.assertTrue(config["verify_ssl"])
        for builder in (soft404_options_from_config, parameter_options_from_config):
            self.assertNotIn("stop_reason", builder(config))
            self.assertEqual(builder(config)["headers"], config["headers"])
        self.assertTrue(config["run_all_modules"])

    def test_direct_default_ignores_proxy_settings_and_applies_shared_limits(self):
        config = self.config(["--http-max-requests", "200", "--http-rate-limit", "0.5", "--max-retries", "0"],
                             {**self.settings, "FUZZ_PROXY_PROFILES": "invalid secret JSON"})
        fuzz = config["fuzzing_options"]
        self.assertEqual(fuzz["engine"], "python_http")
        self.assertFalse(any(key.startswith("proxy") for key in fuzz))
        self.assertEqual(config["http_max_requests"], 200)
        self.assertEqual(config["max_retries"], 0)
        self.assertEqual(config["http_rate_limit"], 0.5)
        for section in ("fuzzing_options", "parameter_options", "soft404_options"):
            self.assertEqual(config[section]["rate_limit"], 0.5)
        for builder in (soft404_options_from_config, parameter_options_from_config):
            options = builder(config, {"engine": "python_http", "success": True,
                                      "stop_reason": "completed", "verification_context": {
                                          "route": "direct", "auth_matches_operator": True}})
            self.assertNotIn("stop_reason", options)
            self.assertNotIn("proxy_options", options)
            self.assertEqual(options["headers"], config["headers"])

    def test_auto_mode_ignores_manual_credentials_and_preserves_limits(self):
        config = self.config(["--proxy-source", "proxyscrape"],
                             settings={**self.settings, "FUZZ_PROXY_PROFILES": "invalid secret JSON"})
        fuzz = config["fuzzing_options"]
        self.assertNotIn("proxy_profiles", fuzz)
        self.assertNotIn("proxy_profiles_env", fuzz)
        self.assertEqual(fuzz["engine"], "proxy_http")
        self.assertEqual(fuzz["proxy_healthcheck_url"], "https://authorized.example/robots.txt")
        self.assertEqual(fuzz["rate_limit"], 1)
        self.assertEqual(fuzz["threads"], 1)
        self.assertTrue(fuzz["stop_on_block"])
        self.assertTrue(fuzz["stop_on_429"])
        self.assertFalse(fuzz["follow_redirects"])
        for builder in (soft404_options_from_config, parameter_options_from_config):
            self.assertEqual(builder(config)["stop_reason"], "verification_route_unavailable")

    def test_manual_profiles_from_settings_stay_in_memory(self):
        profiles = [{"id": "a", "url": "http://user:proxy-secret@proxy-a.example:3128"},
                    {"id": "b", "url": "http://proxy-b.example:3128"}]
        config = self.config(["--proxy-source", "manual"],
                             {**self.settings, "FUZZ_PROXY_PROFILES": json.dumps(profiles)})
        self.assertEqual(config["fuzzing_options"]["proxy_profiles"], profiles)
        self.assertNotIn("proxy_profiles_env", config["fuzzing_options"])

    def test_bad_settings_rejected_without_exposing_values(self):
        for extra, settings, token in [
            (["--target", "http://authorized.example"], self.settings, "test-bearer-secret"),
            ([], self.settings, "test-bearer-secret\r\nX-Header: value"),
            (["--proxy-source", "manual"], {**self.settings, "FUZZ_PROXY_PROFILES": "proxy-secret"}, "ok"),
            ([], {**self.settings, "DEEPSEEK_BASE_URL": "https://secret-key@elsewhere.example"}, "ok"),
            (["--proxy-source", "proxyscrape", "--proxy-refresh-seconds", "1"], self.settings, "ok"),
            (["--http-max-requests", "0"], self.settings, "ok"),
            (["--http-rate-limit", "nan"], self.settings, "ok"),
            (["--max-retries", "-1"], self.settings, "ok"),
        ]:
            with self.subTest(extra=extra), self.assertRaises(ValueError) as caught:
                self.config(extra, settings, token)
            for secret in ("test-bearer-secret", "proxy-secret", "secret-key"):
                self.assertNotIn(secret, str(caught.exception))

    def test_check_does_not_run_pipeline_or_write_credentials(self):
        stdout = io.StringIO()
        with patch.dict(os.environ), patch.object(runner, "read_settings", return_value=self.settings), \
             patch.object(runner, "getpass", side_effect=AssertionError("check must not read a token")) as prompt, \
             patch("src.coordinator.run_pipeline_supervised") as pipeline, \
             patch.object(Path, "mkdir") as mkdir, redirect_stdout(stdout):
            code = runner.main(["--target", "https://authorized.example", "--check"])
        self.assertEqual(code, 0)
        pipeline.assert_not_called()
        mkdir.assert_not_called()
        prompt.assert_not_called()
        self.assertIn("No target, proxy or LLM requests", stdout.getvalue())
        self.assertIn("proxy rotation=off", stdout.getvalue())
        self.assertNotIn("test-bearer-secret", stdout.getvalue())
        self.assertNotIn(self.settings["DEEPSEEK_API_KEY"], stdout.getvalue())

    def test_live_runner_passes_hidden_token_to_supervisor_without_exposing_it(self):
        stdout = io.StringIO()
        with patch.dict(os.environ), patch.object(runner, "read_settings", return_value=self.settings), \
             patch.object(runner, "getpass", return_value="test-bearer-secret"), \
             patch("src.coordinator.run_pipeline_supervised", return_value={
                 "pipeline_status": "completed", "all_modules_successful": True,
             }) as pipeline, patch.object(Path, "mkdir"), redirect_stdout(stdout):
            code = runner.main(["--target", "https://authorized.example", "--proxy-source", "none"])
        self.assertEqual(code, 0)
        config = pipeline.call_args.args[1]
        self.assertEqual(config["fuzzing_options"]["engine"], "python_http")
        self.assertEqual(config["headers"]["Authorization"], "Bearer test-bearer-secret")
        self.assertNotIn("test-bearer-secret", stdout.getvalue())
        self.assertNotIn(self.settings["DEEPSEEK_API_KEY"], stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
