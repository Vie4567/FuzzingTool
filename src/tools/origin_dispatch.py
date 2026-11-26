"""B3.1 sequential Python HTTP harness over B2.2 selections and B1 guards.

This is not LangGraph scheduling or a new runtime. Only the supplied B1
transport can dispatch. The full multi-origin pipeline gate stays closed.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import re

from src.coordinator.artifacts import RunArtifacts
from src.coordinator.origins import canonical_origin, endpoint_observation, public_url
from src.coordinator.runtime import current_runtime, PipelineStopped
from src.coordinator.telemetry import telemetry_phase, current_telemetry
from .origin_scope import OriginScopedTransport, OriginScopePolicy


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _plan(state):
    plan, duplicates = [], 0
    contexts = state.get("origin_contexts", {})
    if not isinstance(contexts, dict) or len(contexts) > 32:
        raise ValueError("Invalid origin context plan")
    order = list(dict.fromkeys(state.get("approved_origins", []) + list(contexts)))
    for origin in order:
        if origin not in contexts:
            continue
        entry = contexts[origin]
        if canonical_origin(public_url(origin, origin_only=True)) != origin:
            raise ValueError("Invalid origin context identity")
        wordlist = (entry.get("context") or {}).get("wordlist") or {}
        selected = wordlist.get("selected_ids", [])
        if not isinstance(selected, list) or len(selected) > 10000:
            raise ValueError("Invalid selected candidate IDs")
        seen = set()
        for value in selected:
            identifier = value if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{24}", value) else (
                "invalid_" + sha256(str(type(value).__name__).encode()).hexdigest()[:24])
            key = (origin, identifier)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            plan.append(key)
    if len(plan) > 10000:
        raise ValueError("Selected candidate plan exceeds limit")
    return plan, duplicates


def _candidate(state, origin, identifier, transport, record):
    """Read current state at dispatch time; a stale eligible flag grants nothing."""
    if identifier.startswith("invalid_"):
        raise ValueError("invalid_candidate_id")
    entry = state["origin_contexts"][origin]
    wordlist = entry["context"]["wordlist"]
    if identifier not in wordlist["selected_ids"]:
        raise ValueError("selection_changed")
    matches = [r for r in wordlist["candidates"] if r.get("endpoint_id") == identifier]
    if not matches or any(row != matches[0] for row in matches):
        raise ValueError("missing_or_ambiguous_candidate")
    raw = matches[0]
    url = public_url(raw.get("url"))
    method = raw.get("method")
    identity = endpoint_observation(url, method=method)
    if identity["origin"] != origin or raw.get("origin") != origin or identity["endpoint_id"] != identifier:
        raise ValueError("candidate_identity_changed")
    record["url"] = url
    original = next((r for r in entry["endpoints"] if r.get("endpoint_id") == identifier), None)
    if original and original.get("method") == method and original.get("url") == url:
        record["observed_method"] = method
    if method is None:
        raise ValueError("method_unknown")
    if method not in {"GET", "HEAD"}:
        raise ValueError("method_not_read_only")
    if raw.get("generated") or not raw.get("observed") or not raw.get("selected"):
        raise ValueError("candidate_not_observed_selection")
    if original is None or any(original.get(key) != raw.get(key) for key in
                               ("url", "origin", "method", "evidence_refs", "provenance")):
        raise ValueError("source_contract_changed")
    public = {key: deepcopy(raw[key]) for key in ("url", "origin", "endpoint_id", "method", "evidence_refs")}
    if transport.redact(public) != public:
        raise ValueError("sensitive_candidate")
    refs = public["evidence_refs"]
    if not isinstance(refs, list) or len(refs) > 4096 or not refs or any(
            not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", ref) for ref in refs):
        raise ValueError("invalid_evidence_refs")
    record["evidence_refs"] = deepcopy(refs)
    # A policy edited after selection must agree with the explicit transport
    # policy. Neither source material nor a stale state snapshot can widen it.
    policy = OriginScopePolicy({"approved_origins": state["approved_origins"],
                                "origin_policies": state.get("origin_policies", {})})
    try:
        policy.check(url, method)
    except ValueError:
        raise ValueError("scope_denied") from None
    if policy.public_config() != transport._policy.public_config():
        raise ValueError("policy_snapshot_mismatch")
    try:
        transport.check_dispatch(url, method)
    except ValueError:
        raise ValueError("credential_or_transport_scope_denied") from None
    return public


def _counts(rows):
    counts = {"selected": len(rows), "attempted": sum(r["attempted"] is True for r in rows),
            "responses": sum(r["status_code"] is not None for r in rows),
            "errors": sum(r["attempted"] is True and r["error"] is not None for r in rows),
            "unattempted": sum(r["attempted"] is False for r in rows),
            "timeouts": sum(r.get("timeout", False) for r in rows)}
    if any("recovery_state" in r for r in rows):
        counts.update(attempted_unknown=sum(r["attempted"] is None for r in rows),
                      outcome_unknown=sum(r.get("recovery_state") == "outcome_unknown" for r in rows))
    return counts


def _outcome(rows, global_reason=None):
    counts = _counts(rows)
    reasons = [r["stop_reason"] for r in rows if r["stop_reason"]]
    if not rows:
        return "skipped", "no_selected_candidates"
    if "pending" in reasons:
        return "running", "pending"
    if not counts["unattempted"] and not counts["errors"] and not reasons and not global_reason:
        return "completed", "completed"
    reason = global_reason or (reasons[0] if reasons else
                               "partial_transport_error" if counts["responses"] else "transport_error")
    return ("partial" if counts["responses"] else "failed"), reason


def _publish(state, runtime, writer, transport, call_before, duplicates, *, event):
    all_rows = list(runtime.origin_dispatch_records.values())
    for origin, entry in state["origin_contexts"].items():
        rows = [deepcopy(r) for r in all_rows if r["origin"] == origin]
        status, reason = _outcome(rows)
        context = entry.setdefault("context", {})
        if context is None:
            context = entry["context"] = {"schema_version": 1}
        context["http_dispatch"] = {"engine": "python_http", "status": status,
            "stop_reason": reason, "counts": _counts(rows), "records": rows,
            "origin_budget_used": runtime.origin_requests.get(origin, 0),
            "origin_budget_limit": (runtime.origin_limits or {}).get(origin)}
        entry.setdefault("agent_statuses", {})["fuzzing"] = "success" if status == "completed" else status
        for candidate in (context.get("wordlist") or {}).get("candidates", []):
            measured = runtime.origin_dispatch_records.get((origin, candidate.get("endpoint_id")))
            if measured and measured["attempted"]:
                candidate["attempted"] = True
                # HTTP observation is not endpoint/parameter/Soft404 verification.
            if measured and measured.get("recovery_state") == "outcome_unknown":
                candidate["attempted"] = measured["attempted"]
                candidate["recovery_state"] = "outcome_unknown"
    status, reason = _outcome(all_rows, runtime.stop_reason)
    telemetry = current_telemetry()
    summary = {"engine": "python_http", "status": status, "stop_reason": reason,
        "completed": status == "completed", "partial": status == "partial", "success": status == "completed",
        "counts": _counts(all_rows), "runtime": runtime.snapshot(),
        "http_dispatches_this_call": runtime.requests - call_before,
        "duplicates_suppressed_this_call": duplicates,
        "verification_status": "not_verified", "full_multi_origin_execution_enabled": False}
    state.setdefault("fuzzing_execution", {})["multi_origin"] = summary
    if telemetry is not None:
        state["telemetry"] = telemetry.snapshot()
    state["runtime"] = runtime.snapshot()
    public = writer.save(transport.redact(state), node="b31_dispatch", event=event)
    if runtime.recovery:
        runtime.recovery.checkpoint(public, "b31_dispatch", event)
    return public


def dispatch_selected(state, *, transport, artifact_root=None, engine="python_http"):
    runtime = current_runtime()
    if engine != "python_http":
        raise ValueError("B3.1 only supports the B1 Python HTTP transport")
    if not isinstance(transport, OriginScopedTransport) or runtime is None:
        raise ValueError("B3.1 requires the B1 transport and the existing shared runtime")
    if state.get("origin_contract_version") != 1:
        raise ValueError("B3.1 requires the B1/B2.2 SharedState contract")
    if runtime.origin_limits is None or set(runtime.origin_limits) != set(state["approved_origins"]):
        raise ValueError("Configure per-origin quotas for approved origins before starting the shared runtime")
    if not runtime.origin_dispatch_lock.acquire(blocking=False):
        raise ValueError("An origin dispatch call is already active in this runtime")
    try:
        if not runtime.origin_dispatch_records and not (runtime.recovery and runtime.recovery.restored) and any((entry.get("context") or {}).get("http_dispatch")
                for entry in state.get("origin_contexts", {}).values()):
            raise ValueError("Cross-runtime resume requires separate reconciliation; not enabled in B3.1")
        plan, duplicates = _plan(state)
        writer = RunArtifacts({"artifact_root": artifact_root} if artifact_root else {})
        before = runtime.requests
        new = []
        for key in plan:
            if key in runtime.origin_dispatch_records:
                duplicates += 1
                continue
            origin, identifier = key
            record = {"candidate_id": identifier, "origin": origin, "url": None,
                "observed_method": None, "planned_test_method": None, "execution_method": None,
                "evidence_refs": [], "attempted": False, "status_code": None,
                "retained_body_bytes": None, "bytes_received": 0, "body_complete": False,
                "response_time": None, "error": None, "timeout": False,
                "stop_reason": "pending", "classification": None,
                "verified": None, "verification_status": "not_verified", "recorded_at_utc": _utc()}
            runtime.origin_dispatch_records[key] = record
            new.append(key)
        _publish(state, runtime, writer, transport, before, duplicates, event="dispatch_planned")
        with telemetry_phase("fuzzing"):
            for origin, identifier in new:
                record = runtime.origin_dispatch_records[(origin, identifier)]
                try:
                    row = _candidate(state, origin, identifier, transport, record)
                    record.update(url=row["url"], observed_method=row["method"], evidence_refs=row["evidence_refs"])
                    runtime.check()
                except (ValueError, TypeError, KeyError, PipelineStopped) as exc:
                    # Validation text can include malformed input: persist only a public code.
                    record["stop_reason"] = runtime.stop_reason or "request_guard_rejected"
                    record["guard_error_type"] = type(exc).__name__
                    public_reasons = {"invalid_candidate_id", "selection_changed", "missing_or_ambiguous_candidate",
                        "candidate_identity_changed", "method_unknown", "method_not_read_only", "candidate_not_observed_selection",
                        "source_contract_changed", "sensitive_candidate", "invalid_evidence_refs", "policy_snapshot_mismatch",
                        "scope_denied", "credential_or_transport_scope_denied"}
                    record["rejection_reason"] = str(exc) if str(exc) in public_reasons else "request_guard_rejected"
                    _publish(state, runtime, writer, transport, before, duplicates, event="request_blocked")
                    continue
                before_request = runtime.requests
                try:
                    runtime.recovery_candidate = record
                    measurement = transport.fetch_result(row["url"], timeout=runtime.timeout, method=row["method"])
                except BaseException as exc:
                    record.update(attempted=runtime.requests > before_request,
                        execution_method=row["method"] if runtime.requests > before_request else None,
                        error={"error_type": "dispatch_interrupted", "exception_type": type(exc).__name__, "count": 1},
                        stop_reason="dispatch_interrupted")
                    runtime.stop_reason = runtime.stop_reason or "dispatch_interrupted"
                    for pending in runtime.origin_dispatch_records.values():
                        if pending["stop_reason"] == "pending":
                            pending["stop_reason"] = "upstream_dispatch_interrupted"
                    _publish(state, runtime, writer, transport, before, duplicates, event="dispatch_interrupted")
                    raise
                finally:
                    runtime.recovery_candidate = None
                error = measurement.get("error")
                record.update(attempted=measurement["attempted"], status_code=measurement["status_code"],
                    runtime_sequence=before_request + 1 if measurement["attempted"] else None,
                    execution_method=row["method"] if measurement["attempted"] else None,
                    retained_body_bytes=measurement["content_length"] if measurement["status_code"] is not None else None,
                    bytes_received=measurement["bytes_received"], body_complete=measurement["body_complete"],
                    response_time=measurement["response_time"],
                    error={"error_type": error["error_type"], "exception_type": error["exception_type"], "count": 1} if error else None,
                    timeout=bool(error and ("timeout" in error["exception_type"].lower() or "timed out" in error.get("message", "").lower())),
                    stop_reason=measurement["stop_reason"],
                    classification="observed_response" if measurement["status_code"] is not None else None,
                    recorded_at_utc=_utc())
                if not record["attempted"] and not record["stop_reason"]:
                    record["stop_reason"] = "origin_request_budget" if error and error["exception_type"] == "OriginBudgetExhausted" else "request_guard_rejected"
                _publish(state, runtime, writer, transport, before, duplicates, event="request_measured")
        return _publish(state, runtime, writer, transport, before, duplicates, event="dispatch_finished")
    finally:
        runtime.origin_dispatch_lock.release()
