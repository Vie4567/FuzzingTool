"""One explicitly selected GET, with bounded stage diagnostics and no pipeline.

Default mode validates configuration only. --run is required for network I/O.
Credentials are accepted interactively, never from command-line arguments.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import importlib.util
import json
import multiprocessing
from pathlib import Path
import queue
import sys
import time
from uuid import uuid4
import warnings


ROOT = Path(__file__).resolve().parents[1]
# Import the stdlib-only module without src/__init__.py loading .env or registry.
_spec = importlib.util.spec_from_file_location(
    "connection_diagnostic_core", ROOT / "src/tools/connection_diagnostics.py"
)
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _worker(options, events):
    try:
        result = core.diagnose_once(**options, progress=lambda value: events.put(("progress", value)))
        events.put(("result", result))
    except Exception as error:
        # Exception text can contain the URL, headers or a server-supplied reason.
        events.put(("error", {"exception_type": type(error).__name__}))


def _save(path, result):
    pending = path.with_name(path.name + ".pending")
    pending.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    pending.replace(path)


def run_diagnostic(options, output_root, *, _worker_target=_worker):
    """Persist progress and bound even OS DNS and HTTP-header drip waits.

    A forced stop retains the last observed counters, marked incomplete. This
    parent never retries, resolves a target or starts a second worker.
    """
    plan = core.validate_options(**options)
    options = {**options, "trace_id": plan["diagnostic_id"]}
    directory = Path(output_root).resolve() / (
        "connection_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid4().hex[:8]
    )
    directory.mkdir(parents=True, exist_ok=False)
    result_path = directory / "result.json"
    _save(directory / "plan.json", plan)
    latest = {
        "diagnostic_id": options.get("trace_id"), "origin": plan["origin"],
        "state": "running", "active_stage": "worker_start", "started_at": _utc(),
        "stages": [], "http": {"attempted_requests": 0, "responses_received": 0,
                                  "status_code": None, "bytes_received": 0, "body_complete": False},
        "counts_complete": False,
        "auth": {"provided": bool(options.get("bearer_token")),
                 "assessment": "not_verified" if options.get("bearer_token") else "not_configured"},
    }
    _save(result_path, latest)
    context = multiprocessing.get_context("spawn")
    events = context.Queue()
    process = context.Process(target=_worker_target, args=(options, events), daemon=True)
    started = time.monotonic()
    deadline = started + float(options.get("timeout_seconds", 8))
    complete, interrupted, worker_error = False, False, None
    try:
        process.start()
        with (directory / "progress.jsonl").open("w", encoding="utf-8") as log:
            while time.monotonic() < deadline:
                try:
                    kind, value = events.get(timeout=min(.05, max(.001, deadline - time.monotonic())))
                except queue.Empty:
                    if not process.is_alive():
                        break
                    continue
                if kind == "error":
                    worker_error = value["exception_type"]
                    break
                latest = value
                latest["counts_complete"] = kind == "result"
                log.write(json.dumps(latest, ensure_ascii=True) + "\n")
                log.flush()
                _save(result_path, latest)
                if kind == "result":
                    complete = True
                    break
                print(f"{_utc()} stage={latest.get('active_stage')} state={latest.get('state')}", flush=True)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
        events.close()
        events.join_thread()
        if not complete:
            reason = ("operator_interrupted" if interrupted else "worker_failed" if worker_error
                      or time.monotonic() < deadline else "diagnostic_deadline")
            latest.update(state="failed", stop_reason=reason, counts_complete=False, finished_at=_utc())
            latest["supervisor"] = {"reason": reason, "exception_type": worker_error,
                                    "last_observed_stage": latest.get("active_stage"),
                                    "inflight_counts_may_be_incomplete": True}
            for stage in latest.get("stages", []):
                if stage.get("status") == "running":
                    stage.update(status="interrupted", finished_at=_utc(), error={"kind": reason})
        latest["supervisor_elapsed_seconds"] = time.monotonic() - started
        latest["artifacts"] = {"directory": str(directory), "result": str(result_path)}
        _save(result_path, latest)
    return latest


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse otherwise echoes unrecognized or malformed argument values.
        self.exit(2, "Invalid diagnostic arguments; use --help.\n")


def _hidden(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument("--url", required=True, help="Exact operator-approved read-only GET endpoint")
    parser.add_argument("--allowed-origin", required=True, help="Exact scheme, host and effective port")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Validate only (default), no DNS/HTTP/token input")
    mode.add_argument("--run", action="store_true", help="Explicitly dispatch at most one GET")
    parser.add_argument("--timeout-seconds", type=float, default=8, help="Total deadline, maximum 8 seconds")
    parser.add_argument("--max-response-bytes", type=int, default=65536)
    parser.add_argument("--tls-ca-file", help="Optional trusted CA bundle; never disables verification")
    parser.add_argument("--bearer-prompt", action="store_true", help="Prompt securely only with --run")
    parser.add_argument("--auth-origin", help="Required exact credential origin when using bearer")
    parser.add_argument("--expect-json-pointer", help="Operator-confirmed protected endpoint contract; expected scalar prompted hidden")
    parser.add_argument("--output-root", default=str(ROOT / "output_samples/diagnostics"))
    args = parser.parse_args(argv)
    if args.expect_json_pointer is not None and not args.bearer_prompt:
        parser.error("Authentication contract requires bearer")
    options = {
        "url": args.url, "allowed_origin": args.allowed_origin, "auth_origin": args.auth_origin,
        "timeout_seconds": args.timeout_seconds, "max_response_bytes": args.max_response_bytes,
        "tls_ca_file": args.tls_ca_file, "trace_id": str(uuid4()),
        "bearer_token": "preflight-placeholder" if args.bearer_prompt else None,
        "expected_json_pointer": args.expect_json_pointer,
        "expected_json_value": "preflight-placeholder" if args.expect_json_pointer is not None else None,
    }
    try:
        plan = core.validate_options(**options)
        if not args.run:
            print(json.dumps({"mode": "check", "network_attempts": 0, "plan": plan}, indent=2, ensure_ascii=True))
            return 0
        if args.bearer_prompt:
            options["bearer_token"] = _hidden("Bearer token (hidden): ").strip()
            if not options["bearer_token"]:
                raise ValueError("Empty token")
        if args.expect_json_pointer is not None:
            options["expected_json_value"] = json.loads(_hidden("Expected JSON scalar (hidden): "))
        result = run_diagnostic(options, args.output_root)
        stage = result.get("active_stage") or next((row["name"] for row in result.get("stages", [])
                                                   if row["status"] in {"failed", "interrupted"}), None)
        print(f"State: {result['state']}; stage: {stage}; stop: {result.get('stop_reason')}")
        print("Auth: " + result.get("auth", {}).get("assessment", "not_verified"))
        print("Result: " + result["artifacts"]["result"])
        return 0 if result["state"] == "completed" else 1
    except (ValueError, OSError, getpass.GetPassWarning):
        print("Diagnostic configuration/input/output failed; no sensitive details logged.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
