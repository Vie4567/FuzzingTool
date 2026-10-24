"""Real ffuf helper tests, restricted to a local HTTP fixture."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import base64
import json
import os
import socket
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.tools.ffuf_helper import FfufToolHelper, PROJECT_ROOT


class Fixture(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.calls.append(self.path)
        body = b"actual-response"
        status = 200
        if self.path == "/missing":
            status, body = 404, b"not-found"
        elif self.path == "/redirect":
            status, body = 302, b"moved"
        elif self.path == "/rate":
            status, body = 429, b"slow-down"
        elif self.path == "/slow":
            time.sleep(0.5)
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if status == 302:
            self.send_header("Location", "/ok")
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


class FfufHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = FfufToolHelper()
        cls.binary = cls.helper.resolve_binary()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        Fixture.calls.clear()

    def run_ffuf(self, words, **options):
        if not self.binary:
            self.skipTest("ffuf is not installed")
        return self.helper.run(target_url=self.url, wordlist=words, ffuf_binary=self.binary,
                               rate_limit=20, **options)

    def test_real_status_bytes_timing_and_all_statuses(self):
        result = self.run_ffuf(["/ok", "missing", "ok"])
        self.assertTrue(result.success, result.to_dict())
        rows = result.result_data["results"]
        self.assertEqual({row["status_code"] for row in rows}, {200, 404})
        self.assertEqual({row["content_length"] for row in rows}, {15, 9})
        self.assertEqual({row["path"] for row in rows}, {"/ok", "/missing"})
        self.assertEqual({row["input_value"] for row in rows}, {"ok", "missing"})
        # Preserve ffuf's measured duration, including an observed zero.
        self.assertTrue(all(row["response_time"] >= 0 for row in rows))
        for row in rows:
            self.assertEqual(row["response_time"], row["duration_ns"] / 1_000_000_000)
        self.assertTrue(all(row["response_time_kind"] == "time_to_first_byte" for row in rows))
        self.assertFalse(result.result_data["simulated"])
        self.assertIsNone(result.result_data["stats"]["attempted_requests"])
        self.assertEqual(sorted(Fixture.calls), ["/missing", "/ok"])

    def test_redirect_option_is_applied(self):
        result = self.run_ffuf(["redirect"])
        self.assertTrue(result.success, result.to_dict())
        self.assertEqual(result.result_data["results"][0]["status_code"], 302)
        self.assertEqual(Fixture.calls, ["/redirect"])
        Fixture.calls.clear()
        followed = self.run_ffuf(["redirect"], follow_redirects=True)
        self.assertEqual(followed.result_data["results"][0]["status_code"], 200)
        self.assertEqual(Fixture.calls, ["/redirect", "/ok"])

    def test_fixed_filters_keep_raw_observed_counts(self):
        result = self.run_ffuf(["ok", "missing"], match_codes="200", filter_size=0)
        self.assertTrue(result.success, result.to_dict())
        self.assertEqual(len(result.result_data["results"]), 1)
        self.assertEqual(result.result_data["stats"]["responses_received"], 2)
        self.assertEqual(result.result_data["stats"]["matched_responses"], 1)

    def test_stops_on_429_without_repeating_with_native(self):
        with patch("src.tools.http_fuzzing.run_http_fuzzing") as fallback:
            result = self.helper.run(target_url=self.url, wordlist=["rate", "ok", "missing"],
                                     ffuf_binary=self.binary, rate_limit=2)
            fallback.assert_not_called()
        self.assertFalse(result.success)
        self.assertEqual(result.result_data["stop_reason"], "http_429")
        self.assertEqual(result.result_data["results"][0]["status_code"], 429)
        self.assertEqual(Fixture.calls, ["/rate"])

    def test_request_cap_marks_partial_and_unique_outputs(self):
        first = self.run_ffuf(["ok", "missing"], max_requests=1)
        second = self.run_ffuf(["missing"])
        self.assertFalse(first.success)
        self.assertEqual(first.result_data["stop_reason"], "max_requests")
        self.assertNotEqual(first.result_data["output_dir"], second.result_data["output_dir"])
        self.assertEqual(second.result_data["results"][0]["status_code"], 404)

    def test_process_deadline_keeps_completed_responses(self):
        result = self.run_ffuf(["ok", "slow", "missing"], max_scan_seconds=0.2)
        self.assertFalse(result.success)
        self.assertTrue(result.result_data["partial"])
        self.assertEqual(result.result_data["stop_reason"], "max_scan_seconds")
        self.assertEqual(result.result_data["results"][0]["path"], "/ok")
        self.assertEqual(Fixture.calls, ["/ok", "/slow"])
        time.sleep(0.1)
        self.assertEqual(Fixture.calls, ["/ok", "/slow"])

    def test_failed_cli_preserves_flushed_response_without_native_rerun(self):
        if not self.binary:
            self.skipTest("ffuf is not installed")
        record = {"url": self.url + "/ok", "input": {"FUZZ": base64.b64encode(b"ok").decode()},
                  "status": 200, "length": 15, "duration": 123000000}

        def start_process(*args, **kwargs):
            kwargs["stdout"].write(json.dumps(record) + "\n")
            kwargs["stdout"].flush()
            return SimpleNamespace(poll=lambda: 2, wait=lambda timeout: 2)

        with patch("src.tools.ffuf_helper.subprocess.Popen", side_effect=start_process), \
             patch("src.tools.http_fuzzing.run_http_fuzzing") as fallback:
            result = self.run_ffuf(["ok"])
            fallback.assert_not_called()
        self.assertFalse(result.success)
        self.assertTrue(result.result_data["partial"])
        self.assertEqual(result.result_data["results"][0]["input_value"], "ok")
        self.assertEqual(result.result_data["results"][0]["path"], "/ok")
        self.assertEqual(result.result_data["results"][0]["response_time"], 0.123)
        self.assertIsNone(result.result_data["stats"]["attempted_requests"])
        self.assertEqual(Fixture.calls, [])

    def test_missing_executable_explicit_failure(self):
        result = self.helper.run(target_url=self.url, wordlist=["ok"], ffuf_binary="missing-ffuf-binary")
        self.assertFalse(result.success)
        self.assertEqual(Fixture.calls, [])

    def test_native_engine_sends_real_requests(self):
        result = self.helper.run(target_url=self.url, wordlist=["ok", "missing"], engine="python_http", rate_limit=100)
        self.assertTrue(result.success, result.to_dict())
        self.assertEqual(result.result_data["engine"], "python_http")
        self.assertEqual([row["status_code"] for row in result.result_data["results"]], [200, 404])

    def test_native_429_is_partial_failure_with_measured_response(self):
        result = self.helper.run(target_url=self.url, wordlist=["rate", "ok"], engine="python_http", rate_limit=100)
        self.assertFalse(result.success, result.to_dict())
        self.assertTrue(result.result_data["partial"])
        self.assertTrue(result.result_data["stopped_early"])
        self.assertEqual(result.result_data["results"][0]["status_code"], 429)
        self.assertEqual(Fixture.calls, ["/rate"])

    def test_connection_failure_is_not_success_or_fallback(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        with patch("src.tools.http_fuzzing.run_http_fuzzing") as fallback:
            result = self.helper.run(target_url=f"http://127.0.0.1:{port}", wordlist=["ok"],
                                     ffuf_binary=self.binary, timeout_seconds=1, max_scan_seconds=3)
            fallback.assert_not_called()
        self.assertFalse(result.success, result.to_dict())
        self.assertEqual(result.result_data["results"], [])

    def test_logs_and_artifacts_omit_credentials(self):
        result = self.run_ffuf(["ok"], headers={"Authorization": "Bearer unique-test-secret"})
        self.assertTrue(result.success, result.to_dict())
        self.assertNotIn("unique-test-secret", result.result_data["command_executed"])
        directory = Path(result.result_data["output_dir"])
        self.assertNotIn("unique-test-secret", (directory / "results.json").read_text())
        self.assertNotIn("unique-test-secret", (directory / "stderr.log").read_text())

    def test_target_query_is_preserved_but_redacted_from_logs(self):
        if not self.binary:
            self.skipTest("ffuf is not installed")
        result = self.helper.run(target_url=self.url + "?api_key=unique-query-secret", wordlist=["ok"],
                                 ffuf_binary=self.binary, rate_limit=20)
        self.assertTrue(result.success, result.to_dict())
        self.assertEqual(Fixture.calls, ["/ok?api_key=unique-query-secret"])
        self.assertNotIn("unique-query-secret", result.result_data["command_executed"])
        self.assertNotIn("unique-query-secret", result.raw_output)

    def test_rejects_invalid_ranges_and_rotation_before_network(self):
        for options in ({"filter_codes": "not-a-code"}, {"rotate_ip": True},
                        {"headers": {"X-Forwarded-For": "1.2.3.4"}}, {"max_requests": 0}):
            result = self.helper.run(target_url=self.url, wordlist=["ok"], **options)
            self.assertFalse(result.success, result.to_dict())
        self.assertEqual(Fixture.calls, [])

    def test_resolution_is_independent_of_cwd(self):
        old = Path.cwd()
        try:
            os.chdir(PROJECT_ROOT / "src")
            self.assertEqual(self.helper.resolve_binary(), self.binary)
        finally:
            os.chdir(old)

    def test_missing_duration_remains_unknown(self):
        row = self.helper._normalize_result({"status": 200, "length": 0})
        self.assertIsNone(row["response_time"])
        self.assertEqual(row["content_length"], 0)

    def test_query_replacement_is_separate_from_actual_path(self):
        row = self.helper._normalize_result({"url": self.url + "/search?q=term", "input": {"FUZZ": "term"},
                                             "status": 200, "length": 15, "duration": 0})
        self.assertEqual(row["path"], "/search")
        self.assertEqual(row["input_value"], "term")
        self.assertEqual(row["response_time"], 0)


if __name__ == "__main__":
    unittest.main()
