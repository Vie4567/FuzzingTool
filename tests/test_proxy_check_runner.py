"""Runner preflight and observability tests; no network access is required."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import run_proxy_http_check as runner


PROFILES = json.dumps([
    {"id": "route-a", "url": "http://lab-user:lab-secret@proxy-a.example:3128"},
    {"id": "route-b", "url": "http://proxy-b.example:3128"},
])


class ProxyCheckRunnerTests(unittest.TestCase):
    def setUp(self):
        parent = runner.PROJECT_ROOT / "output_samples" / "diagnostics"
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "run"

    def _run(self, raw, factory):
        stdout = io.StringIO()
        with patch.object(runner, "_proxy_environment_value", return_value=(raw, "test")):
            with patch("socket.create_connection", side_effect=AssertionError("No network in runner tests")):
                with redirect_stdout(stdout):
                    code = runner.main(
                        ["--target", "https://authorized.example", "--output-dir", str(self.output)],
                        agent_factory=factory,
                    )
        return code, stdout.getvalue()

    def test_missing_profiles_stops_before_constructing_agent(self):
        factory = Mock()
        code, stdout = self._run(None, factory)
        self.assertEqual(code, 2)
        factory.assert_not_called()
        result = json.loads((self.output / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["stop_reason"], "missing_proxy_profiles")
        self.assertEqual(result["requests_sent"], 0)
        self.assertIn("requests_sent=0; no network request was made", stdout)
        self.assertIn("PRECHECK BLOCKED", (self.output / "progress.log").read_text(encoding="utf-8"))

    def test_single_profile_cannot_be_presented_as_rotation(self):
        factory = Mock()
        raw = json.dumps([{"id": "single", "url": "http://proxy-a.example:3128"}])
        code, _ = self._run(raw, factory)
        self.assertEqual(code, 2)
        factory.assert_not_called()
        result = json.loads((self.output / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["stop_reason"], "at_least_two_proxy_profiles_required")

    def test_explicit_single_proxy_count_can_run_without_claiming_rotation(self):
        factory = Mock(return_value=Mock(execute=Mock(return_value={
            "success": True, "results": [], "stats": {}, "stop_reason": "completed",
        })))
        raw = json.dumps([{"id": "single", "url": "http://proxy-a.example:3128"}])
        with patch.object(runner, "_proxy_environment_value", return_value=(raw, "test")):
            with redirect_stdout(io.StringIO()):
                code = runner.main(
                    ["--target", "https://authorized.example", "--proxy-count", "1",
                     "--output-dir", str(self.output)], agent_factory=factory,
                )
        self.assertEqual(code, 0)
        self.assertEqual(factory.return_value.execute.call_args.kwargs["proxy_count"], 1)

    def test_manual_healthcheck_profiles_are_pending_but_pass_configuration_preflight(self):
        factory = Mock(return_value=Mock(execute=Mock(return_value={
            "success": True, "results": [], "stats": {}, "stop_reason": "completed",
        })))
        with patch.object(runner, "_proxy_environment_value", return_value=(PROFILES, "test")):
            with patch("socket.create_connection", side_effect=AssertionError("Preflight has no I/O")):
                with redirect_stdout(io.StringIO()):
                    code = runner.main([
                        "--target", "https://authorized.example",
                        "--proxy-healthcheck-url", "https://authorized.example/health",
                        "--max-requests", "5", "--output-dir", str(self.output),
                    ], agent_factory=factory)
        self.assertEqual(code, 0)
        factory.assert_called_once_with(llm=None)
        options = factory.return_value.execute.call_args.kwargs
        self.assertEqual(options["proxy_healthcheck_url"], "https://authorized.example/health")
        self.assertEqual(options["max_requests"], 5)
        preflight = json.loads((self.output / "preflight.json").read_text(encoding="utf-8"))
        self.assertEqual(preflight["status"], "ready")
        self.assertEqual(preflight["profile_ids"], ["route-a", "route-b"])
        self.assertEqual(preflight["requests_sent"], 0)

    def test_live_logger_captures_both_streams_and_restores_settings_after_errors(self):
        loggers = [logging.getLogger(name) for name in (
            "sentinel.fuzzing.http", "sentinel.fuzzing.proxy",
        )]
        original = [(logger.level, logger.propagate, list(logger.handlers)) for logger in loggers]
        try:
            for index, logger in enumerate(loggers):
                logger.setLevel(logging.WARNING if index == 0 else logging.ERROR)
                logger.propagate = index == 0
                logger.addHandler(logging.NullHandler())
            expected = [(logger.level, logger.propagate, list(logger.handlers)) for logger in loggers]
            for fail in (False, True):
                with self.subTest(exception=fail):
                    output = self.output / str(fail)
                    output.mkdir(parents=True)
                    stdout = io.StringIO()
                    caught = False
                    with redirect_stdout(stdout):
                        try:
                            with runner._live_logger(output) as live:
                                self.assertIs(live, loggers[0])
                                live.info("START request=1 profile=route-a")
                                loggers[1].info("PROXY profile=route-a requests=1 seconds=0.1 error_rate=0.0")
                                if fail:
                                    raise RuntimeError("test logger cleanup")
                        except RuntimeError as error:
                            self.assertEqual(str(error), "test logger cleanup")
                            caught = True
                    self.assertEqual(caught, fail)
                    progress = (output / "progress.log").read_text(encoding="utf-8")
                    for captured in (stdout.getvalue(), progress):
                        self.assertEqual(captured.count("START request=1"), 1)
                        self.assertEqual(captured.count("PROXY profile=route-a"), 1)
                    self.assertEqual(
                        [(logger.level, logger.propagate, list(logger.handlers)) for logger in loggers],
                        expected,
                    )
        finally:
            for logger, (level, propagate, handlers) in zip(loggers, original):
                for handler in list(logger.handlers):
                    if handler not in handlers:
                        logger.removeHandler(handler)
                        handler.close()
                logger.setLevel(level)
                logger.propagate = propagate

    def test_automatic_mode_validates_empty_pool_without_reading_manual_credentials(self):
        pool = Mock(profile_ids=[])
        pool.redact.side_effect = lambda text: text

        def execute(**options):
            self.assertEqual(options["engine"], "proxy_http")
            self.assertEqual(options["proxy_source"], "proxyscrape")
            self.assertNotIn("proxy_profiles_env", options)
            self.assertNotIn("proxy_profiles", options)
            self.assertEqual(options["allowed_origins"], ["https://authorized.example"])
            self.assertEqual(options["max_requests"], 23)
            self.assertEqual(options["max_scan_seconds"], 120)
            self.assertEqual(options["rate_limit"], 1)
            self.assertEqual(options["threads"], 1)
            self.assertEqual(options["delay_ms"], 1000)
            self.assertEqual(options["proxy_candidate_limit"], 20)
            self.assertEqual(options["proxy_fetch_timeout_seconds"], 10)
            self.assertEqual(options["proxy_check_timeout_seconds"], 5)
            return {
                "success": False, "engine": "proxy_http", "results": [],
                "health_checks": [], "proxy_pool": {"source": "proxyscrape"},
                "stop_reason": "proxy_pool_empty",
                "stats": {"total_requests": 0, "healthcheck_requests": 0,
                          "fuzzing_requests": 0, "responses_received": 0},
            }

        factory = Mock(return_value=Mock(execute=execute))
        with patch.object(runner, "_proxy_environment_value", side_effect=AssertionError("Auto must not read credentials")):
            with patch.object(runner, "_profile_environment", side_effect=AssertionError("No manual proxy context")):
                with patch.object(runner.ProxyProfilePool, "from_options", return_value=pool):
                    with patch("socket.create_connection", side_effect=AssertionError("Preflight has no I/O")):
                        with redirect_stdout(io.StringIO()):
                            code = runner.main(
                                ["--target", "https://authorized.example", "--proxy-source", "proxyscrape",
                                 "--output-dir", str(self.output)], agent_factory=factory,
                            )
        self.assertEqual(code, 1)
        factory.assert_called_once_with(llm=None)
        preflight = json.loads((self.output / "preflight.json").read_text(encoding="utf-8"))
        self.assertEqual(preflight["status"], "ready")
        self.assertEqual(preflight["reason"], "validated_auto_configuration")
        self.assertEqual(preflight["profile_ids"], [])
        self.assertEqual(preflight["requests_sent"], 0)
        report = (self.output / "report.md").read_text(encoding="utf-8")
        self.assertIn("configuration only", report)
        self.assertIn("stats.proxy_profiles", report)

    def test_proxy_and_shared_budget_cli_options_reach_engine(self):
        pool = Mock(profile_ids=[])
        pool.redact.side_effect = lambda text: text
        factory = Mock(return_value=Mock(execute=Mock(return_value={
            "success": True, "results": [], "stats": {}, "stop_reason": "completed",
        })))
        with patch.object(runner.ProxyProfilePool, "from_options", return_value=pool) as validate:
            with redirect_stdout(io.StringIO()):
                code = runner.main([
                    "--target", "https://authorized.example", "--proxy-source", "proxyscrape",
                    "--proxy-count", "3", "--proxy-candidate-limit", "15",
                    "--proxy-check-timeout", "2.5", "--proxy-fetch-timeout", "8",
                    "--proxy-refresh-seconds", "60", "--proxy-healthcheck-url", "https://authorized.example/health",
                    "--max-requests", "18", "--max-scan-seconds", "90", "--timeout-seconds", "7",
                    "--output-dir", str(self.output),
                ], agent_factory=factory)
        self.assertEqual(code, 0)
        options = factory.return_value.execute.call_args.kwargs
        for key, expected in {
            "proxy_count": 3, "proxy_candidate_limit": 15, "proxy_check_timeout_seconds": 2.5,
            "proxy_fetch_timeout_seconds": 8, "proxy_refresh_seconds": 60,
            "proxy_healthcheck_url": "https://authorized.example/health", "max_requests": 18,
            "max_scan_seconds": 90, "timeout_seconds": 7,
        }.items():
            self.assertEqual(options[key], expected)
        self.assertEqual(validate.call_args.args[0]["proxy_count"], 3)

    def test_auto_real_pool_validation_performs_no_network_or_credential_read(self):
        factory = Mock(return_value=Mock(execute=Mock(return_value={
            "success": False, "results": [], "stats": {}, "stop_reason": "proxy_pool_empty",
        })))
        with patch.object(runner, "_proxy_environment_value", side_effect=AssertionError("No manual credentials")):
            with patch("socket.create_connection", side_effect=AssertionError("Configuration validation must not connect")):
                with redirect_stdout(io.StringIO()):
                    code = runner.main([
                        "--target", "https://authorized.example", "--proxy-source", "proxyscrape",
                        "--proxy-refresh-seconds", "0", "--output-dir", str(self.output),
                    ], agent_factory=factory)
        self.assertEqual(code, 1)
        factory.assert_called_once_with(llm=None)
        preflight = json.loads((self.output / "preflight.json").read_text(encoding="utf-8"))
        self.assertEqual(preflight["status"], "ready")
        self.assertEqual(preflight["profile_ids"], [])
        self.assertEqual(factory.return_value.execute.call_args.kwargs["proxy_refresh_seconds"], 0)

    def test_auto_healthcheck_outside_scope_is_rejected_before_engine(self):
        factory = Mock()
        with patch("socket.create_connection", side_effect=AssertionError("Invalid configuration must not connect")):
            with redirect_stdout(io.StringIO()):
                code = runner.main([
                    "--target", "https://authorized.example", "--proxy-source", "proxyscrape",
                    "--proxy-healthcheck-url", "https://outside.example/health",
                    "--output-dir", str(self.output),
                ], agent_factory=factory)
        self.assertEqual(code, 2)
        factory.assert_not_called()
        preflight = json.loads((self.output / "preflight.json").read_text(encoding="utf-8"))
        self.assertEqual(preflight["reason"], "invalid_proxy_options")
        self.assertEqual(preflight["requests_sent"], 0)

    def test_invalid_cli_bounds_and_conflicting_routes_fail_before_io(self):
        cases = [
            ["--proxy-count", "0"], ["--proxy-count", "9"],
            ["--proxy-candidate-limit", "101"], ["--proxy-check-timeout", "nan"],
            ["--proxy-fetch-timeout", "31"], ["--proxy-refresh-seconds", "29"],
            ["--proxy-refresh-seconds", "inf"], ["--max-requests", "1001"],
            ["--max-scan-seconds", "601"], ["--timeout-seconds", "0"],
            ["--direct", "--proxy-source", "proxyscrape"],
        ]
        factory = Mock()
        with patch.object(runner, "_proxy_environment_value", side_effect=AssertionError("No configuration read")):
            with patch.object(runner, "_output_directory", side_effect=AssertionError("No output mutation")):
                for args in cases:
                    with self.subTest(args=args), redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as error:
                            runner.main(args, agent_factory=factory)
                        self.assertEqual(error.exception.code, 2)
        factory.assert_not_called()

    def test_explicit_direct_does_not_read_proxy_configuration_and_streams_results(self):
        def execute(**options):
            self.assertEqual(options["engine"], "python_http")
            self.assertIn("proxy", options)
            self.assertIsNone(options["proxy"])
            self.assertNotIn("proxy_profiles_env", options)
            self.assertNotIn("proxy_profiles", options)
            self.assertNotIn("allowed_origins", options)
            self.assertEqual(options["target_url"], "https://authorized.example")
            self.assertEqual(options["wordlist"], runner.CHECK_PATHS)
            self.assertEqual(options["max_requests"], 3)
            self.assertEqual(options["rate_limit"], 1)
            self.assertEqual(options["threads"], 1)
            self.assertEqual(options["delay_ms"], 1000)
            self.assertEqual(options["timeout_seconds"], 10)
            self.assertEqual(options["max_scan_seconds"], 45)
            self.assertFalse(options["use_pattern_engine"])
            self.assertEqual(os.environ["PYTHON_DOTENV_DISABLED"], "1")
            live = logging.getLogger("sentinel.fuzzing.http")
            live.info("START request=1 profile=direct path=/robots.txt")
            live.info("RESULT request=1 profile=direct status=200 bytes=7")
            live.info("STOP reason=completed attempted=1 responses=1")
            return {
                "success": True, "engine": "python_http", "stop_reason": "completed",
                "stats": {"total_requests": 1, "responses_received": 1},
                "results": [{"path": "/robots.txt", "status_code": 200,
                             "content_length": 7, "response_time": 0.012, "error": None}],
            }

        factory = Mock(return_value=Mock(execute=execute))
        stdout = io.StringIO()
        with patch.object(runner, "_proxy_environment_value", side_effect=AssertionError("Direct must not read proxies")):
            with patch.object(runner, "_profile_environment", side_effect=AssertionError("No proxy context in direct mode")):
                with patch.object(runner.ProxyProfilePool, "from_options", side_effect=AssertionError("No proxy pool")):
                    with redirect_stdout(stdout):
                        code = runner.main(
                            ["--direct", "--target", "https://authorized.example", "--output-dir", str(self.output)],
                            agent_factory=factory,
                        )
        self.assertEqual(code, 0)
        factory.assert_called_once_with(llm=None)
        self.assertIn("ip_rotation=false", stdout.getvalue())
        progress = (self.output / "progress.log").read_text(encoding="utf-8")
        self.assertLess(progress.index("START request=1"), progress.index("RESULT request=1"))
        self.assertLess(progress.index("RESULT request=1"), progress.index("STOP reason=completed"))
        preflight = json.loads((self.output / "preflight.json").read_text(encoding="utf-8"))
        self.assertEqual(preflight["configuration_source"], "not_used")
        self.assertEqual(preflight["profile_ids"], [])
        result = json.loads((self.output / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["route"], "direct")
        self.assertFalse(result["ip_rotation"])
        self.assertIsNone(result["egress_ip"])
        self.assertEqual(result["egress_ip_verification"], "not_measured")
        self.assertEqual(result["results"][0]["content_length"], 7)
        report = (self.output / "report.md").read_text(encoding="utf-8")
        self.assertIn("IP rotation: disabled", report)
        self.assertIn("| /robots.txt | direct | 200 | 7 |", report)

    def test_direct_runner_error_keeps_unknown_request_counts(self):
        factory = Mock(return_value=Mock(execute=Mock(side_effect=RuntimeError("test transport failure"))))
        with patch.object(runner, "_proxy_environment_value", side_effect=AssertionError("No proxy read")):
            with redirect_stdout(io.StringIO()):
                code = runner.main(
                    ["--direct", "--target", "https://authorized.example", "--output-dir", str(self.output)],
                    agent_factory=factory,
                )
        self.assertEqual(code, 1)
        result = json.loads((self.output / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["stop_reason"], "runner_error")
        self.assertIsNone(result["stats"]["total_requests"])
        self.assertIsNone(result["stats"]["responses_received"])
        self.assertEqual(result["route"], "direct")
        self.assertFalse(result["ip_rotation"])

    def test_direct_default_artifact_prefix(self):
        output = runner._output_directory(None, direct=True)
        self.addCleanup(output.rmdir)
        self.assertTrue(output.name.startswith("http_direct_check_"))

    def test_invalid_profile_never_prints_raw_configuration(self):
        factory = Mock()
        raw = '[{"id": "invalid", "url": "http://lab-secret@broken"}]'
        code, stdout = self._run(raw, factory)
        self.assertEqual(code, 2)
        factory.assert_not_called()
        self.assertNotIn("lab-secret", stdout)
        self.assertNotIn("broken", (self.output / "preflight.json").read_text(encoding="utf-8"))

    def test_valid_run_passes_explicit_scope_and_streams_redacted_measurements(self):
        def execute(**options):
            self.assertEqual(options["engine"], "proxy_http")
            self.assertEqual(options["proxy_profiles_env"], runner.PROFILE_ENV)
            self.assertEqual(options["allowed_origins"], ["https://authorized.example"])
            self.assertFalse(options["use_pattern_engine"])
            self.assertEqual(options["wordlist"], runner.CHECK_PATHS)
            self.assertEqual(options["max_requests"], 3)
            self.assertEqual(options["rate_limit"], 1)
            self.assertEqual(options["max_scan_seconds"], 45)
            live = logging.getLogger("sentinel.fuzzing.http")
            live.info("START request=1 profile=route-a path=/robots.txt")
            live.info("RESULT request=1 profile=route-a status=200 bytes=7")
            logging.getLogger("sentinel.fuzzing.proxy").info(
                "PROXY profile=route-a requests=1 responses=1 seconds=0.012 error_rate=0.0"
            )
            live.info("STOP reason=completed attempted=1 responses=1")
            return {
                "success": True, "engine": "proxy_http", "stop_reason": "completed",
                "stats": {"total_requests": 1, "responses_received": 1},
                "results": [{"path": "/robots.txt", "proxy_profile_id": "route-a", "status_code": 200,
                             "content_length": 7, "response_time": 0.012, "error": None, "egress_ip": None}],
                "warnings": ["Never expose lab-secret or proxy-a.example:3128"],
            }

        factory = Mock(return_value=Mock(execute=execute))
        code, stdout = self._run(PROFILES, factory)
        self.assertEqual(code, 0)
        factory.assert_called_once_with(llm=None)
        self.assertIn("START request=1", stdout)
        self.assertIn("RESULT request=1", stdout)
        self.assertIn("STOP reason=completed", stdout)
        self.assertIn("PROXY profile=route-a requests=1", stdout)
        progress = (self.output / "progress.log").read_text(encoding="utf-8")
        self.assertIn("PROXY profile=route-a requests=1", progress)
        self.assertLess(progress.index("START request=1"), progress.index("RESULT request=1"))
        self.assertLess(progress.index("RESULT request=1"), progress.index("STOP reason=completed"))
        saved = (self.output / "result.json").read_text(encoding="utf-8")
        self.assertNotIn("lab-secret", saved)
        self.assertNotIn("proxy-a.example:3128", saved)
        self.assertIsNone(json.loads(saved)["results"][0]["egress_ip"])
        self.assertIn("profile selection alone does not prove", (self.output / "report.md").read_text(encoding="utf-8"))

    def test_dotenv_setting_is_scoped_without_loading_other_secrets(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch("dotenv.dotenv_values", return_value={runner.PROFILE_ENV: PROFILES, "UNRELATED_SECRET": "hidden"}) as read:
                with patch.object(Path, "is_file", return_value=True):
                    raw, source = runner._proxy_environment_value()
            self.assertEqual(raw, PROFILES)
            self.assertEqual(source, "project_dotenv")
            read.assert_called_once_with(runner.PROJECT_ROOT / ".env", interpolate=False)
            self.assertNotIn("UNRELATED_SECRET", os.environ)
            self.assertNotIn(runner.PROFILE_ENV, os.environ)
            with runner._profile_environment(raw):
                self.assertEqual(os.environ[runner.PROFILE_ENV], PROFILES)
                self.assertNotIn("UNRELATED_SECRET", os.environ)
            self.assertNotIn(runner.PROFILE_ENV, os.environ)

    def test_output_must_stay_in_project_and_must_not_overwrite_artifacts(self):
        with self.assertRaises(ValueError):
            runner._output_directory(str(runner.PROJECT_ROOT.parent / "outside-proxy-check"))
        self.output.mkdir()
        (self.output / "result.json").write_text("existing", encoding="utf-8")
        with self.assertRaises(ValueError):
            runner._output_directory(str(self.output))
        self.assertEqual((self.output / "result.json").read_text(encoding="utf-8"), "existing")

    def test_fresh_process_import_does_not_load_unrelated_dotenv_or_expand_passwords(self):
        isolated_env = Path(self.temporary.name) / ".env"
        profiles = PROFILES.replace("lab-secret", "${UNSET_PROXY_MARKER}")
        isolated_env.write_text(
            "UNRELATED_RUNNER_SECRET=must-stay-in-file\n"
            + "FUZZ_PROXY_PROFILES='" + profiles + "'\n", encoding="utf-8"
        )
        code = """
import os, sys
from pathlib import Path
import dotenv
dotenv.find_dotenv = lambda *args, **kwargs: sys.argv[1]
from scripts import configure_proxy_profiles
from scripts import run_proxy_http_check as runner
assert 'UNRELATED_RUNNER_SECRET' not in os.environ
assert 'FUZZ_PROXY_PROFILES' not in os.environ
runner.PROJECT_ROOT = Path(sys.argv[1]).parent
raw, source = runner._proxy_environment_value()
assert source == 'project_dotenv'
assert '${UNSET_PROXY_MARKER}' in raw
assert 'UNRELATED_RUNNER_SECRET' not in os.environ
with runner._profile_environment(raw):
    assert os.environ['PYTHON_DOTENV_DISABLED'] == '1'
    assert '${UNSET_PROXY_MARKER}' in os.environ['FUZZ_PROXY_PROFILES']
assert 'PYTHON_DOTENV_DISABLED' not in os.environ
print('isolated proxy configuration OK')
"""
        child_env = dict(os.environ)
        for key in ("PYTHON_DOTENV_DISABLED", "FUZZ_PROXY_PROFILES", "UNRELATED_RUNNER_SECRET", "UNSET_PROXY_MARKER"):
            child_env.pop(key, None)
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, str(isolated_env)],
            cwd=runner.PROJECT_ROOT, env=child_env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("isolated proxy configuration OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
