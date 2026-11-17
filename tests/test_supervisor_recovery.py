import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from src.coordinator.artifacts import RunArtifacts
from src.coordinator import supervisor


def measured_state():
    return {
        "pipeline_status": "running", "agent_statuses": {"fuzzing": "success"},
        "error_log": [], "total_http_requests": 7, "llm_call_count": 3,
        "raw_results": [{"url": "http://127.0.0.1/test", "status_code": 200, "content_length": 42}],
        "telemetry": {"http": {"total_requests": 7, "count_complete": True},
                      "llm": {"attempted": 3, "succeeded": 2, "failed": 0}},
    }


class SupervisorRecoveryTests(unittest.TestCase):
    def test_interrupt_and_control_loop_error_preserve_latest_child_checkpoint(self):
        for error in (KeyboardInterrupt(), RuntimeError("join failed")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                class Worker:
                    pid = None
                    exitcode = None
                    alive = False

                    def __init__(self, *, target, args):
                        self.root = Path(args[2])

                    def start(self):
                        self.pid, self.alive = 12345, True
                        child = RunArtifacts({"artifact_root": str(self.root)})
                        child.save({"total_http_requests": 1, "llm_call_count": 1})
                        # Simulate a completed checkpoint whose result update failed.
                        newer = child.directory / "checkpoints" / "0002_fuzzing.json"
                        RunArtifacts._write_json(newer, measured_state())
                        newer_time = child.result_path.stat().st_mtime + 2
                        os.utime(newer, (newer_time, newer_time))

                    def is_alive(self):
                        return self.alive

                    def join(self, timeout=None):
                        raise error

                def terminate(worker):
                    worker.alive, worker.exitcode = False, -1

                with patch.object(supervisor.mp, "get_context", return_value=SimpleNamespace(Process=Worker)), \
                        patch.object(supervisor, "_terminate_owned", side_effect=terminate), \
                        self.assertRaises(type(error)):
                    supervisor.run_pipeline_supervised("http://127.0.0.1:9", {"artifact_root": directory})
                result_file = next(Path(directory).glob("pipeline_*/result.json"))
                result = json.loads(result_file.read_text(encoding="utf-8"))
                self.assertEqual(result["raw_results"], measured_state()["raw_results"])
                self.assertEqual(result["agent_statuses"]["fuzzing"], "success")
                self.assertEqual(result["last_checkpoint_http_requests"], 7)
                self.assertEqual(result["last_checkpoint_llm_calls"], 3)
                self.assertIsNone(result["total_http_requests"])
                self.assertIsNone(result["llm_call_count"])
                self.assertFalse(result["telemetry"]["http"]["count_complete"])
                self.assertFalse(result["telemetry"]["llm"]["count_complete"])
                self.assertEqual(result["pipeline_status"], "interrupted" if isinstance(error, KeyboardInterrupt) else "failed")

    def test_nonzero_worker_exit_cannot_publish_success_even_with_final_output(self):
        with tempfile.TemporaryDirectory() as directory:
            class Worker:
                pid = None
                exitcode = 7

                def __init__(self, *, target, args):
                    self.root = Path(args[2])

                def start(self):
                    self.pid = 12345
                    RunArtifacts._write_json(self.root / "worker_result.json",
                                             dict(measured_state(), pipeline_status="completed"))

                def is_alive(self):
                    return False

            with patch.object(supervisor.mp, "get_context", return_value=SimpleNamespace(Process=Worker)):
                result = supervisor.run_pipeline_supervised("http://127.0.0.1:9", {"artifact_root": directory})
            self.assertEqual(result["pipeline_status"], "failed")
            self.assertEqual(result["stop_reason"], "worker_terminated")
            self.assertEqual(result["supervision"]["worker_exitcode"], 7)
            self.assertEqual(result["raw_results"], measured_state()["raw_results"])
            self.assertEqual(result["last_checkpoint_http_requests"], 7)

    def test_windows_taskkill_failure_still_kills_and_joins_owned_worker(self):
        for error in (subprocess.TimeoutExpired("taskkill", 10), OSError("unavailable")):
            with self.subTest(error=type(error).__name__):
                worker = MagicMock(pid=12345)
                worker.is_alive.side_effect = [True, False]
                with patch.object(supervisor.os, "name", "nt"), \
                        patch.object(supervisor.subprocess, "run", side_effect=error):
                    supervisor._terminate_owned(worker)
                worker.kill.assert_called_once_with()
                worker.join.assert_called_once_with(timeout=3)


if __name__ == "__main__":
    unittest.main()
