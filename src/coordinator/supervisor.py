"""Process isolation for a hard pipeline deadline on Windows and POSIX."""
from datetime import datetime, timezone
import json
import multiprocessing as mp
import os
from pathlib import Path
import subprocess
import time

from .artifacts import RunArtifacts
from .validation import validate_pipeline_input


def _worker(target, config, run_root):
    # Credentials cross a private process argument, never argv or a config file.
    os.chdir(run_root)
    from .graph import run_pipeline
    cfg = dict(config, artifact_root=str(run_root))
    cfg.setdefault("knowledge_store_dir", str(Path(run_root) / "knowledge_store"))
    result = run_pipeline(target, cfg)
    RunArtifacts._write_json(Path(run_root) / "worker_result.json", result)


def _terminate_owned(process):
    if process.is_alive():
        if os.name == "nt":
            # Only our just-created worker PID and descendants (e.g. ffuf).
            try:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired):
                # Keep the direct worker fallback available if taskkill fails.
                process.kill()
        else:
            process.terminate()
        process.join(timeout=3)
        if process.is_alive():
            process.kill()
            process.join(timeout=3)


def _recover_partial(artifacts, initial, exitcode, reason):
    """Recover the latest durable worker state, including interrupted writes.

    A child checkpoint can be newer than its result.json if the second atomic
    write failed. Never replace such evidence with the supervisor's initial
    empty state just because its control loop was interrupted.
    """
    candidates = [artifacts.directory / "worker_result.json"]
    candidates.extend(artifacts.directory.glob("pipeline_*/result.json"))
    candidates.extend(artifacts.directory.glob("pipeline_*/checkpoints/*.json"))
    readable = []
    for path in candidates:
        try:
            readable.append((path.stat().st_mtime_ns, str(path), path))
        except OSError:
            continue
    partial = dict(initial)
    for _, _, path in sorted(readable, reverse=True):
        try:
            candidate = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                partial = candidate
                break
        except (OSError, ValueError):
            continue
    partial["last_checkpoint_http_requests"] = partial.get("total_http_requests")
    partial["last_checkpoint_llm_calls"] = partial.get("llm_call_count")
    partial["total_http_requests"] = None
    partial["llm_call_count"] = None
    partial["supervision"] = {"hard_deadline": True, "worker_exitcode": exitcode,
                              "in_flight_measurements_unknown": True}
    partial["stop_reason"] = reason
    telemetry = partial.get("telemetry")
    if isinstance(telemetry, dict):
        if isinstance(telemetry.get("http"), dict):
            telemetry["http"].update(total_requests=None, count_complete=False)
        if isinstance(telemetry.get("llm"), dict):
            telemetry["llm"]["count_complete"] = False
    return partial


def run_pipeline_supervised(target_url, config=None, *, _worker_target=None):
    """Return a durable public result; stop the owned worker on hard timeout.

    A killed request may have reached its server without a checkpoint. Counts
    then become unknown with a preserved checkpoint lower bound, never zero.
    """
    cfg = config if isinstance(config, dict) else {}
    artifacts = RunArtifacts(cfg)
    initial = {"target_url": target_url, "config": config or {}, "pipeline_status": "running",
               "started_at": datetime.now(timezone.utc).isoformat(), "error_log": [], "agent_statuses": {}}
    artifacts.save(initial, event="supervisor_started")
    try:
        target, normalized = validate_pipeline_input(target_url, config)
    except (ValueError, TypeError) as exc:
        return artifacts.record_failure(initial, exc, node="validate")
    deadline = time.monotonic() + normalized["pipeline_timeout_seconds"]
    process = mp.get_context("spawn").Process(target=_worker_target or _worker,
                                               args=(target, normalized, str(artifacts.directory)))
    timed_out = False
    try:
        process.start()
        while process.is_alive():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_owned(process)
                break
            process.join(timeout=min(.2, remaining))
        output = artifacts.directory / "worker_result.json"
        if output.exists() and not timed_out and process.exitcode == 0:
            result = json.loads(output.read_text(encoding="utf-8"))
            result["supervision"] = {"hard_deadline": True, "worker_exitcode": process.exitcode,
                                     "timeout_seconds": normalized["pipeline_timeout_seconds"]}
            return artifacts.save(result, event="supervisor_completed")
        reason = "pipeline_deadline" if timed_out else "worker_terminated"
        partial = _recover_partial(artifacts, initial, process.exitcode, reason)
        error = TimeoutError(reason) if timed_out else RuntimeError(reason)
        return artifacts.record_failure(partial, error, node="supervisor")
    except BaseException as exc:
        if process.pid:
            _terminate_owned(process)
        reason = "supervisor_interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "supervisor_error"
        partial = _recover_partial(artifacts, initial, process.exitcode, reason)
        artifacts.record_failure(partial, exc, node="supervisor")
        raise
    finally:
        if process.pid:
            _terminate_owned(process)
