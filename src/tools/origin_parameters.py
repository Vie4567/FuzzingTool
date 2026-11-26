"""B4.1 multi-origin query-parameter verification over B3.1 observed responses.

Agent 4 consumes endpoints that Agent 3 actually observed (2xx, complete GET
body), joins Agent 1 parameter references, Agent 2 selection metadata and the
static ParameterAssembler vocabulary, and verifies only operator-listed names
(`parameters` on an exact GET read_only rule) with the existing bounded control
comparison of `verify_parameters`. One shared runtime; no new budget per origin.

B4.2A: with a B3.2B journal bound by a parameter-enabled LocalOriginTest, every
probe carries a public unit identity, every dispatched probe is journaled as a
measurement, and each unit result is checkpointed and anchored. Reconcile keeps
only verdicts the journal re-derives; units with reservations but no checkpointed
result are terminal and are never re-sent (at-most-once, not exactly-once).

Not enabled here: Soft404 per origin, full graph routing, non-GET methods,
proxy/ffuf engines, and the production multi-origin gate.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import re
import time
from urllib.parse import urlsplit
from uuid import uuid4

from src.coordinator.artifacts import RunArtifacts
from src.coordinator.origins import canonical_origin, public_url
from src.coordinator.recovery_units import check_checkpoint_rows, check_units, process_epochs
from src.coordinator.runtime import (current_runtime, PipelineStopped, HttpDispatchDeadline,
                                     OriginBudgetExhausted)
from src.coordinator.telemetry import telemetry_phase, current_telemetry
from .origin_scope import OriginScopedTransport, OriginScopePolicy
from .parameter_verification import verify_parameters, _reflection_text

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_TYPES = {"string", "integer", "number", "boolean"}
_DEFAULT_MAX_REQUESTS = 200
_CONTROL = re.compile(r"__sentinel_unknown_[0-9a-f]{32}")
_HEX32, _HEX24 = re.compile(r"[0-9a-f]{32}"), re.compile(r"[0-9a-f]{24}")
_ROLES = {"baseline", "control", "candidate"}
# Unit states that must never be re-measured in the same session.
TERMINAL_UNITS = {"completed", "halted", "interrupted", "no_probes"}


def _utc():
    return datetime.now(timezone.utc).isoformat()


class _DispatchMark(dict):
    """Captures the instant ScopedReconTransport reserves the attempt."""
    at = None

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if key == "attempted" and value:
            self.at = time.perf_counter()


class ParameterProbeTransport(OriginScopedTransport):
    """B1 transport that also admits B4.1 bounded probes; same open() chain."""

    def __init__(self, target_url, *, policy, credentials=None, tls_ca_file=None):
        super().__init__(target_url, policy=policy, credentials=credentials, tls_ca_file=tls_ca_file)
        self.proxy_profile_id = None
        self.dispatched = False
        self.dispatched_at = None
        self.dispatch_deadline = None
        self.stop_reason = None
        self.requests = []
        self.endpoint_ids = {}
        self.endpoint_refs = {}
        self.unit_ids = {}
        self.unit, self.unit_endpoint, self.ordinal = None, None, 0
        self._probe, self._unit_base_body = None, None

    def classify(self, url):
        """(base_url, role, parameter) from the operator policy, never from the caller."""
        try:
            self._policy.check(url, "GET")
            return url, "baseline", None
        except ValueError:
            base, name = self._policy.check_parameter_probe(url, "GET")
            return base, ("control" if _CONTROL.fullmatch(name) else "candidate"), name

    def check_dispatch(self, url, method):
        try:
            self._policy.check(url, method)
            base = url
        except ValueError:
            base, _ = self._policy.check_parameter_probe(url, method)
        # Re-run the exact B1 rule and credential binding on the base endpoint.
        super().check_dispatch(base, method)

    def check_global(self):
        runtime = current_runtime()
        if runtime is not None:
            try:
                runtime.check()
            except PipelineStopped:
                self.stop_reason = self.stop_reason or runtime.stop_reason
        return self.stop_reason

    def begin_unit(self):
        # One unit = one endpoint comparison; identity is fresh per unit.
        self.unit, self.unit_endpoint, self.ordinal = uuid4().hex, None, 0
        self._unit_base_body = None
        return self.check_global()

    def open(self, request, timeout=10, *, cookie_jar=None):
        self.dispatched, self.dispatched_at, self._probe = False, None, None
        if self.stop_reason:
            raise PipelineStopped(self.stop_reason)
        if self.dispatch_deadline is not None and time.monotonic() >= self.dispatch_deadline:
            raise HttpDispatchDeadline("max_duration")
        url = request.full_url if hasattr(request, "full_url") else request
        base, role, parameter = self.classify(url)
        endpoint = self.endpoint_ids.get(base)
        if self.unit is None or endpoint is None or self.unit_endpoint not in (None, endpoint):
            raise ValueError("probe_unit_endpoint_changed")
        probe = {"version": 1, "endpoint_id": endpoint, "unit_id": self.unit,
                 "ordinal": self.ordinal + 1, "role": role, "parameter": parameter}
        runtime = current_runtime()
        if runtime is not None and runtime.recovery is not None:
            runtime.recovery_candidate = {"candidate_id": None, "probe": probe,
                                          "evidence_refs": list(self.endpoint_refs.get(endpoint, []))}
        mark = _DispatchMark()
        try:
            return super().open(request, timeout, cookie_jar=cookie_jar, _measurement=mark)
        finally:
            if runtime is not None:
                runtime.recovery_candidate = None
            self.dispatched = bool(mark.get("attempted"))
            self.dispatched_at = mark.at
            if self.dispatched:
                # Ordinals count reserved requests only; a denied reservation sends nothing.
                self.ordinal += 1
                self.unit_endpoint = endpoint
                self.unit_ids[endpoint] = self.unit
                self._probe = probe

    def failure(self, exc, measured):
        if isinstance(exc, HttpDispatchDeadline):
            return "max_duration"
        if isinstance(exc, OriginBudgetExhausted):
            return "origin_request_budget"
        if isinstance(exc, PipelineStopped):
            runtime = current_runtime()
            return self.stop_reason or (runtime.stop_reason if runtime else None) or "pipeline_stopped"
        if isinstance(exc, ValueError) and not self.dispatched:
            return "request_guard_rejected"
        return "transport_error"

    def record_measurement(self, measured, halt_reason):
        if not self.dispatched or self._probe is None:
            return
        runtime = current_runtime()
        parts = urlsplit(measured["url"])
        probe = self._probe
        body = measured.get("_body")
        reflected = None
        if probe["role"] == "baseline" and self._unit_base_body is None and body is not None:
            self._unit_base_body = body
        if probe["role"] == "candidate" and body is not None and self._unit_base_body is not None:
            value = parts.query.rsplit("=", 1)[-1]
            reflected = _reflection_text(body).count(value) > _reflection_text(self._unit_base_body).count(value)
        global_stop = runtime.stop_reason if runtime else None
        evidence = {"status_code": measured["status_code"], "content_type": measured["content_type"],
                    "content_length": measured["content_length"], "body_complete": measured["body_complete"],
                    "body_truncated": measured["body_truncated"], "body_sha256": measured["body_sha256"],
                    "normalized_sha256": measured["normalized_sha256"], "response_time": measured["response_time"],
                    "error": measured["error"], "value_reflected": reflected,
                    "unit_halt": halt_reason if halt_reason and halt_reason != global_stop else None}
        if runtime is not None and runtime.recovery is not None:
            # Durable before the row exists: every checkpointed row has journal proof.
            runtime.recovery.request_event("measurement", {
                "probe": {"unit_id": probe["unit_id"], "ordinal": probe["ordinal"]},
                **{k: v for k, v in evidence.items() if k != "error"},
                "bytes_received": measured["content_length"],
                "error": {"exception_type": measured["error"]} if measured["error"] else None,
                "stop_reason": global_stop})
        self.requests.append({
            "sequence": len(self.requests) + 1,
            "runtime_sequence": runtime.requests if runtime else None,
            "origin": canonical_origin(measured["url"]), "endpoint_id": probe["endpoint_id"],
            "unit_id": probe["unit_id"], "ordinal": probe["ordinal"], "role": probe["role"],
            "parameter": probe["parameter"],
            "path": parts.path or "/", "query": parts.query, "kind": measured["kind"],
            **evidence, "halt_reason": halt_reason, "recorded_at_utc": _utc()})

    def metrics(self):
        return {}

    def public_settings(self):
        result = super().public_settings()
        result.update(route="direct", probe_policy="b41_operator_listed_parameters")
        return result


def _source_reason(record):
    """Agent 3 HTTP observation that can serve as a comparison baseline."""
    if record.get("recovery_state") == "outcome_unknown":
        return "source_outcome_unknown"
    if record.get("attempted") is not True:
        return "source_not_observed"
    if record.get("error") is not None or record.get("timeout"):
        return "source_error_or_timeout"
    if record.get("classification") != "observed_response":
        return "source_not_observed"
    if record.get("execution_method") != "GET":
        return "source_method_not_get"
    status = record.get("status_code")
    if type(status) is not int or not 200 <= status < 300:
        return "source_not_2xx"
    if record.get("body_complete") is not True:
        return "source_body_incomplete"
    return None


def _rule(policy, url):
    parts = urlsplit(url)
    config = policy.public_config()["origin_policies"].get(canonical_origin(url), {"rules": []})
    return next((r for r in config["rules"] if r["path"] == (parts.path or "/") and r["query"] == parts.query
                 and "GET" in r["methods"]), None)


def _candidates(endpoint, context, wordlist_row, static_names):
    """Merge sources by name; provenance is kept, never collapsed."""
    merged = {}

    def add(name, kind, provenance):
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            return
        row = merged.setdefault(name, {"name": name, "location": "query", "method": "GET",
                                       "type": None, "provenance": []})
        if provenance not in row["provenance"]:
            row["provenance"].append(provenance)
        if kind is not None and row["type"] is None:
            row["type"] = kind

    for param in context.get("parameters", []):
        if (param.get("url") == endpoint["url"] and param.get("method") == "GET"
                and param.get("location", "query") == "query"):
            add(param.get("name"), "string", {
                "source": "agent1_reference", "reference_source": param.get("source"),
                "source_url": param.get("source_url"), "classification": param.get("classification"),
                "evidence_refs": list(param.get("evidence_refs") or [])})
    support = (wordlist_row or {}).get("priority", {}).get("parameter_support")
    for name, kind in static_names:
        add(name, kind if kind in _TYPES else "string", {
            "source": "param_assembler_static", "classification": "inferred", "evidence_refs": []})
    rows = []
    for name in sorted(merged):
        row = merged[name]
        # Observed references outrank inferred static types for test values.
        if any(p["source"] == "agent1_reference" for p in row["provenance"]):
            row["type"] = "string"
        row["type"] = row["type"] or "string"
        row["parameter_id"] = sha256((endpoint["endpoint_id"] + "\n" + name).encode()).hexdigest()[:24]
        row["agent2_parameter_support"] = support
        rows.append(row)
    return rows


def _plan(state, policy, transport, static_names_for):
    plan = []
    for origin in state.get("approved_origins", []):
        entry = state.get("origin_contexts", {}).get(origin) or {}
        context = entry.get("context") or {}
        dispatch = context.get("http_dispatch") or {}
        wordlist = {r.get("endpoint_id"): r for r in (context.get("wordlist") or {}).get("candidates", [])}
        endpoints = {r.get("endpoint_id"): r for r in entry.get("endpoints", [])}
        rows = []
        for record in dispatch.get("records", []):
            identifier = record.get("candidate_id")
            source = endpoints.get(identifier)
            row = {"endpoint_id": identifier, "origin": origin, "url": record.get("url"),
                   "method": record.get("execution_method"),
                   "source_dispatch": {key: deepcopy(record.get(key)) for key in (
                       "candidate_id", "status_code", "runtime_sequence", "evidence_refs", "attempted",
                       "body_complete", "error", "timeout", "stop_reason", "classification")},
                   "provenance": deepcopy(source.get("provenance")) if source is not None else None,
                   "eligible": False, "exclusion_reason": None, "candidates": [],
                   "unit_id": None, "unit_state": None}
            reason = _source_reason(record)
            if reason is None and (source is None or source.get("url") != record.get("url")
                                   or source.get("method") != record.get("observed_method")
                                   or source.get("origin") != origin
                                   or (wordlist.get(identifier) or {}).get("url") != record.get("url")):
                reason = "source_contract_changed"
            if reason is None:
                try:
                    if public_url(record["url"]) != record["url"] or canonical_origin(record["url"]) != origin:
                        raise ValueError
                    policy.check(record["url"], "GET")
                except (ValueError, TypeError, KeyError):
                    reason = "scope_denied"
            rule = _rule(policy, record["url"]) if reason is None else None
            if reason is None:
                row["candidates"] = _candidates(source, context, wordlist.get(identifier),
                                                static_names_for(urlsplit(record["url"]).path or "/"))
                approved = set((rule or {}).get("parameters", []))
                for candidate in row["candidates"]:
                    candidate["selected"] = candidate["name"] in approved
                    candidate["selection_reason"] = ("operator_listed_parameter" if candidate["selected"]
                                                     else "parameter_not_approved_by_operator")
                    candidate.update(verification="not_checked", verification_performed=False,
                                     verification_reason="not_selected" if not candidate["selected"] else "not_measured",
                                     verification_evidence={})
                if not approved:
                    reason = "parameter_probe_not_approved"
                elif not any(c["selected"] for c in row["candidates"]):
                    reason = "no_operator_listed_candidate"
            if reason is None:
                try:
                    transport.check_dispatch(record["url"], "GET")
                except ValueError:
                    reason = "credential_or_transport_scope_denied"
                    for candidate in row["candidates"]:
                        if candidate["selected"]:
                            candidate["verification_reason"] = reason
            row["eligible"], row["exclusion_reason"] = reason is None, reason
            row["unit_state"] = "not_started" if reason is None else None
            rows.append(row)
        plan.append((origin, rows))
    return plan


def _counts(rows, requests):
    candidates = [c for r in rows for c in r["candidates"]]
    return {"endpoints": len(rows), "eligible_endpoints": sum(r["eligible"] for r in rows),
            "candidates": len(candidates), "selected": sum(c["selected"] for c in candidates),
            "verification_attempted": sum(c["verification_performed"] for c in candidates),
            "verified": sum(c["verification"] == "verified" for c in candidates),
            "inconclusive": sum(c["verification"] == "inconclusive" for c in candidates),
            "not_checked": sum(c["verification"] == "not_checked" for c in candidates),
            "http_requests": len(requests),
            "responses": sum(r["status_code"] is not None for r in requests),
            "errors": sum(r["error"] is not None for r in requests)}


def _stats_sum(total, stats):
    for key, value in (stats or {}).items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total[key] = total.get(key, 0) + value
    return total


def verify_origin_parameters(state, *, transport, static_names_for, artifact_root=None, max_requests=None):
    """Verify operator-listed query parameters on Agent 3 observations, per origin.

    Each endpoint is one comparison unit and one `verify_parameters` call. A local
    halt stops the rest of that origin (B4.1 semantics); a global stop stops all.
    With a journal bound, a restored session continues only units that have no
    reservation; terminal units keep their reconciled result and are never re-sent.
    """
    runtime = current_runtime()
    if not isinstance(transport, ParameterProbeTransport) or runtime is None:
        raise ValueError("B4.1 requires the B4.1 probe transport and the existing shared runtime")
    if state.get("origin_contract_version") != 1:
        raise ValueError("B4.1 requires the B1/B3.1 SharedState contract")
    recovery = runtime.recovery
    if recovery is not None and not getattr(recovery, "parameter_probes", False):
        # Only a parameter-enabled LocalOriginTest journal defines probe identity.
        raise ValueError("parameter_recovery_not_supported_b41")
    if runtime.origin_limits is None or set(runtime.origin_limits) != set(state["approved_origins"]):
        raise ValueError("Configure per-origin quotas for approved origins before starting the shared runtime")
    snapshot = OriginScopePolicy({"approved_origins": state["approved_origins"],
                                  "origin_policies": state.get("origin_policies", {})})
    if snapshot.public_config() != transport._policy.public_config():
        raise ValueError("policy_snapshot_mismatch")
    if (state.get("fuzzing_execution") or {}).get("multi_origin") is None:
        raise ValueError("B4.1 requires a completed B3.1 dispatch call")
    cap = _DEFAULT_MAX_REQUESTS if max_requests is None else max_requests
    if type(cap) is not int or not 1 <= cap <= 10000:
        raise ValueError("max_requests must be an integer in 1..10000")
    restored = {o: deepcopy(e["context"]["parameter_discovery"]) for o, e in state.get("origin_contexts", {}).items()
                if "parameter_discovery" in ((e or {}).get("context") or {})}
    if restored:
        if not (recovery is not None and recovery.restored and not getattr(recovery, "parameter_resumed", False)):
            raise ValueError("Parameter verification already recorded; rerun is not enabled in B4.1")
        recovery.parameter_resumed = True
        summary = (state.get("parameter_execution") or {}).get("multi_origin") or {}
        if summary.get("phase_max_requests") != cap:
            raise ValueError("parameter_phase_cap_changed")
    writer = RunArtifacts({"artifact_root": artifact_root} if artifact_root else {})
    before = {"http_dispatches": runtime.requests, "by_origin": dict(runtime.origin_requests)}
    if restored:
        before = {"http_dispatches": summary.get("http_dispatches_before"),
                  "by_origin": {o: s.get("origin_budget_before", 0) for o, s in restored.items()}}
    plan = _plan(state, transport._policy, transport, static_names_for)
    outcomes, halts, stats = {}, {}, {}
    if restored:
        transport.requests = sorted((deepcopy(r) for s in restored.values() for r in s.get("requests", [])),
                                    key=lambda r: r["runtime_sequence"])
        for origin, rows in plan:
            previous = {e["endpoint_id"]: e for e in restored.get(origin, {}).get("endpoints", [])}
            if set(previous) != {r["endpoint_id"] for r in rows}:
                raise ValueError("parameter_resume_plan_changed")
            for index, row in enumerate(rows):
                old = previous[row["endpoint_id"]]
                if (old["url"], old["eligible"], old["exclusion_reason"]) != (row["url"], row["eligible"], row["exclusion_reason"]):
                    raise ValueError("parameter_resume_plan_changed")
                if old.get("unit_state") in TERMINAL_UNITS or not old["eligible"]:
                    rows[index] = old
            section = restored.get(origin, {})
            if section.get("final"):
                outcomes[origin] = {k: section.get(k) for k in ("status", "stop_reason")}
                outcomes[origin].update(stats=section.get("verifier_stats"), final=True)
            if section.get("origin_halt"):
                halts[origin] = section["origin_halt"]
            stats[origin] = dict(section.get("verifier_stats") or {})
    transport.endpoint_ids = {r["url"]: r["endpoint_id"] for _, rows in plan for r in rows if r["eligible"]}
    transport.endpoint_refs = {r["endpoint_id"]: (r["source_dispatch"].get("evidence_refs") or [])
                               for _, rows in plan for r in rows if r["eligible"]}

    def publish(event):
        for origin, rows in plan:
            context = state["origin_contexts"][origin].setdefault("context", {}) or {}
            requests = [deepcopy(r) for r in transport.requests if r["origin"] == origin]
            outcome = outcomes.get(origin, {"status": "pending", "stop_reason": "pending"})
            context["parameter_discovery"] = {
                "schema_version": 1, "stage": "B4.1", "status": outcome["status"],
                "stop_reason": outcome["stop_reason"], "final": bool(outcome.get("final")),
                "origin_halt": halts.get(origin), "endpoints": deepcopy(rows),
                "requests": requests, "counts": _counts(rows, requests),
                "verifier_stats": deepcopy(outcome.get("stats") if outcome.get("final") else stats.get(origin)),
                "origin_budget_used": runtime.origin_requests.get(origin, 0),
                "origin_budget_before": before["by_origin"].get(origin, 0),
                "origin_budget_limit": runtime.origin_limits.get(origin),
                "verification_meaning": "repeatable_response_effect_vs_negative_controls; not business validity"}
            state["origin_contexts"][origin]["context"] = context
            state["origin_contexts"][origin].setdefault("agent_statuses", {})["param_disc"] = (
                "success" if outcome["status"] == "completed" else outcome["status"])
        statuses = [o["status"] for o in outcomes.values()]
        overall = ("running" if len(outcomes) < len(plan) else "completed"
                   if statuses and all(s in {"completed", "skipped"} for s in statuses) else "partial")
        telemetry = current_telemetry()
        state.setdefault("parameter_execution", {})["multi_origin"] = {
            "stage": "B4.1", "engine": "python_http", "status": overall,
            "stop_reason": runtime.stop_reason or next((o["stop_reason"] for o in outcomes.values()
                                                        if o["stop_reason"] not in ("completed", "no_eligible_endpoints")), "completed"),
            "http_dispatches_before": before["http_dispatches"], "http_dispatches_after": runtime.requests,
            "http_dispatches_this_call": runtime.requests - before["http_dispatches"],
            "probe_requests_recorded": len(transport.requests), "phase_max_requests": cap,
            "runtime": runtime.snapshot(), "full_multi_origin_execution_enabled": False,
            "langgraph_integration": "not_enabled_b41",
            "recovery_support": "journaled_b42a" if recovery is not None else "not_bound",
            "resumed": bool(restored)}
        if telemetry is not None:
            state["telemetry"] = telemetry.snapshot()
        state["runtime"] = runtime.snapshot()
        public = writer.save(transport.redact(state), node="b41_parameters", event=event)
        if recovery is not None:
            recovery.checkpoint(public, "b41_parameters", event)
        return public

    current = None
    publish("parameters_resumed" if restored else "parameters_planned")
    try:
        with telemetry_phase("param_disc"):
            for origin, rows in plan:
                if origin in outcomes:
                    continue
                eligible = [r for r in rows if r["eligible"]]
                if not eligible:
                    outcomes[origin] = {"status": "skipped", "stop_reason": "no_eligible_endpoints", "final": True}
                    publish("parameters_origin_skipped")
                    continue
                stats.setdefault(origin, {})
                for row in eligible:
                    if row.get("unit_state") in TERMINAL_UNITS:
                        continue
                    remaining_time = runtime.deadline - time.monotonic()
                    remaining = cap - len(transport.requests)
                    halted = runtime.stop_reason or halts.get(origin) or transport.check_global() or (
                        "max_requests" if remaining < 1 else "pipeline_deadline" if remaining_time < .01 else None)
                    if halted:
                        # Same visible result as B4.1: halted reason, nothing measured here.
                        for candidate in row["candidates"]:
                            if candidate["selected"]:
                                candidate["verification_reason"] = halted
                        row["parameter_verification"] = "not_started"
                        halts.setdefault(origin, halted)
                        continue
                    record = {"url": row["url"], "method": "GET", "source_method": "GET",
                              "source_status_code": row["source_dispatch"]["status_code"],
                              "source_body_complete": True, "source_error": None,
                              "discovered_params": [{"name": c["name"], "type": c["type"], "method": "GET",
                                                     "location": "query"} for c in row["candidates"] if c["selected"]]}
                    transport.stop_reason = None
                    current = row
                    result = verify_parameters(origin + "/", [record], transport=transport,
                                               rate_limit=min(100, runtime.rate), timeout_seconds=min(120, runtime.timeout),
                                               max_requests=max(1, remaining), max_duration_seconds=max(.01, min(3600, remaining_time)),
                                               max_response_bytes=runtime.body_cap)
                    current = None
                    checked = result["param_results"][0]
                    by_name = {c["name"]: c for c in checked.get("parameter_checks", [])}
                    for candidate in row["candidates"]:
                        found = by_name.get(candidate["name"]) if candidate["selected"] else None
                        if found is not None:
                            candidate.update({key: deepcopy(found[key]) for key in (
                                "verification", "verification_performed", "verification_reason",
                                "verification_evidence", "status_code", "content_length_change")})
                    row["parameter_verification"] = checked.get("parameter_verification", "not_started")
                    row["unit_id"] = transport.unit_ids.get(row["endpoint_id"])
                    measured = result["stats"]["total_requests"]
                    row["unit_state"] = ("no_probes" if not measured else
                                         "completed" if result["stop_reason"] == "completed" else "halted")
                    if result["stop_reason"] != "completed":
                        halts.setdefault(origin, result["stop_reason"])
                    _stats_sum(stats[origin], result["stats"])
                    publish("parameters_unit_measured")
                total = sum(r["origin"] == origin for r in transport.requests)
                halt = halts.get(origin)
                status = ("completed" if not halt and total else "skipped" if not halt
                          else "partial" if total else "not_started")
                outcomes[origin] = {"status": status, "stop_reason": halt or "completed",
                                    "stats": stats.get(origin), "final": True}
                publish("parameters_origin_measured")
    except BaseException:
        if current is not None and transport.unit_ids.get(current["endpoint_id"]):
            current["unit_id"] = transport.unit_ids[current["endpoint_id"]]
            current["unit_state"] = "interrupted"
            for candidate in current["candidates"]:
                if candidate["selected"] and candidate["verification"] != "verified":
                    candidate.update(verification="inconclusive", verification_reason="unit_interrupted")
        for origin, _ in plan:
            outcomes.setdefault(origin, {"status": "interrupted", "stop_reason": "upstream_interrupted"})
        publish("parameters_interrupted")
        raise
    return publish("parameters_finished")


# ── B4.2A reconcile: journal is evidence, the fresh operator context is authority ──

def _usable(entry):
    status = entry.get("status_code")
    return (entry.get("body_complete") is True and not entry.get("body_truncated") and not entry.get("error")
            and entry.get("normalized_sha256") is not None and type(status) is int and 200 <= status < 300
            and not entry.get("unit_halt"))


def _signature(entry):
    return (entry.get("status_code"), entry.get("content_type"), entry.get("normalized_sha256"))


def derive_unit_verdicts(entries):
    """Re-derive B4.1 `verified` per parameter from ordered unit measurements only.

    entries: dicts with role, parameter, value and the journaled measurement fields,
    ordered by ordinal. A missing measurement makes the whole unit unusable.
    """
    names = {e["parameter"] for e in entries if e["role"] == "candidate"}
    verdicts = {name: False for name in names}
    controls = entries[:4]
    if ([e["role"] for e in controls] != ["baseline", "baseline", "control", "control"]
            or not all(_usable(e) for e in controls) or len({_signature(e) for e in controls}) != 1):
        return verdicts
    base, index, seen = _signature(controls[0]), 4, set()
    while index < len(entries):
        name = entries[index]["parameter"]
        if entries[index]["role"] != "candidate" or name in seen:
            return {n: False for n in names}  # broken unit structure proves nothing
        seen.add(name)
        samples, post = [], []
        while index < len(entries) and len(samples) < 4 and entries[index]["role"] == "candidate" \
                and entries[index]["parameter"] == name:
            samples.append(entries[index]); index += 1
        while index < len(entries) and len(post) < 3 and entries[index]["role"] in {"baseline", "control"}:
            post.append(entries[index]); index += 1
        verdicts[name] = (
            len(samples) == 4 and len(post) == 3 and all(_usable(e) for e in samples + post)
            and all(e.get("value_reflected") is False for e in samples)
            and samples[0]["value"] == samples[1]["value"] and samples[2]["value"] == samples[3]["value"]
            and samples[0]["value"] != samples[2]["value"]
            and [e["role"] for e in post] == ["baseline", "control", "control"]
            and post[1]["value"] == samples[0]["value"] and post[2]["value"] == samples[2]["value"]
            and all(_signature(e) == base for e in post)
            and _signature(samples[0]) == _signature(samples[1]) and _signature(samples[2]) == _signature(samples[3])
            and any(_signature(e) != base for e in samples))
    return verdicts


def reconcile_probe_recovery(*, local, state, events, reservations, starts, measurements, checkpoints, deny):
    """Validate probe reservations/checkpoints against the journal; mark terminal units.

    Returns outcome-unknown probe sequences. `deny(code)` raises RecoveryDenied.
    """
    from src.coordinator.origins import endpoint_observation
    probes = [r for r in reservations if "probe" in r]
    sections = lambda saved: {o: (e.get("context") or {}).get("parameter_discovery")
                              for o, e in (saved.get("origin_contexts") or {}).items()
                              if (e.get("context") or {}).get("parameter_discovery") is not None}
    if not probes and not any(sections(saved) for _, saved in checkpoints):
        return []
    transport = getattr(local, "probe_transport", None)
    if transport is None:
        deny("recovery_reservation_identity_invalid")
    by_seq = {}
    for row in probes:
        try:
            probe = row["probe"]
            if (set(probe) != {"version", "endpoint_id", "unit_id", "ordinal", "role", "parameter"}
                    or probe["version"] != 1 or not _HEX32.fullmatch(probe["unit_id"])
                    or not _HEX24.fullmatch(probe["endpoint_id"]) or type(probe["ordinal"]) is not int
                    or probe["role"] not in _ROLES or row.get("candidate_id") is not None or row["method"] != "GET"
                    or canonical_origin(row["url"]) != row["origin"]):
                raise ValueError
            transport.check_dispatch(row["url"], "GET")
            base, role, parameter = transport.classify(row["url"])
            if (role, parameter) != (probe["role"], probe["parameter"]):
                raise ValueError
            if endpoint_observation(base, method="GET")["endpoint_id"] != probe["endpoint_id"]:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            deny("recovery_reservation_identity_invalid")
        by_seq[row["sequence"]] = row
    # Replay is decided by identity and epoch, never by URL equality (shared integrity rules).
    units, endpoint_units = check_units(probes, key="probe", owner=lambda r: (r["origin"], r["probe"]["endpoint_id"]),
                                        epochs=process_epochs(events), deny=deny, code="recovery_probe_replay_detected")

    def entry(seq):
        res, measure = by_seq[seq], measurements.get(seq)
        value = urlsplit(res["url"]).query.rsplit("=", 1)[-1] if res["probe"]["role"] != "baseline" else None
        return {"role": res["probe"]["role"], "parameter": res["probe"]["parameter"], "value": value,
                **({k: measure.get(k) for k in ("status_code", "content_type", "normalized_sha256", "body_complete",
                                                "body_truncated", "error", "value_reflected", "unit_halt")}
                   if measure else {"body_complete": None})}

    fields = ("status_code", "content_type", "body_sha256", "normalized_sha256", "body_complete")
    check_checkpoint_rows(checkpoints, probes, measurements, sections, key="probe",
                          identity=("unit_id", "ordinal", "role", "parameter"), fields=fields, deny=deny,
                          missing_code="recovery_parameter_checkpoint_missing")
    current = sections(state)
    if probes and not current:
        deny("recovery_parameter_checkpoint_missing")
    last_cover = checkpoints[-1][0]["reservations"]
    unknown = []
    for origin, section in current.items():
        listed = {r["runtime_sequence"] for r in section.get("requests", [])}
        for endpoint in section.get("endpoints", []):
            unit_id = endpoint_units.get((origin, endpoint["endpoint_id"]))
            claims = [c for c in endpoint.get("candidates", []) if c.get("verification") == "verified"]
            if unit_id is None:
                if claims or endpoint.get("unit_state") in TERMINAL_UNITS - {"no_probes"}:
                    deny("recovery_parameter_verdict_unproven")
                continue
            seqs = [r["sequence"] for r in units[unit_id]]
            complete = (all(s <= last_cover and s in measurements for s in seqs)
                        and endpoint.get("unit_id") == unit_id and endpoint.get("unit_state") in {"completed", "halted"})
            if complete:
                derived = derive_unit_verdicts([entry(s) for s in seqs])
                for candidate in endpoint.get("candidates", []):
                    if candidate.get("selected") and (candidate.get("verification") == "verified") != derived.get(candidate["name"], False):
                        deny("recovery_parameter_verdict_unproven")
                continue
            # Reserved but not proven complete: terminal, never re-sent, never verified.
            missing = [s for s in seqs if s not in measurements]
            endpoint.update(unit_id=unit_id, unit_state="interrupted")
            for candidate in endpoint.get("candidates", []):
                if candidate.get("selected"):
                    candidate.update(verification="inconclusive", verification_evidence={},
                                     verification_performed=any(s in starts for s in seqs),
                                     verification_reason="probe_outcome_unknown" if missing else "unit_interrupted")
        for res in probes:
            seq = res["sequence"]
            if res["origin"] != origin or seq in listed:
                continue
            measure, parts = measurements.get(seq), urlsplit(res["url"])
            row = {"sequence": None, "runtime_sequence": seq, "origin": origin,
                   "endpoint_id": res["probe"]["endpoint_id"], "unit_id": res["probe"]["unit_id"],
                   "ordinal": res["probe"]["ordinal"], "role": res["probe"]["role"], "parameter": res["probe"]["parameter"],
                   "path": parts.path or "/", "query": parts.query, "kind": res["probe"]["role"],
                   "attempted": True if seq in starts else None,
                   **{k: (measure or {}).get(k) for k in fields + ("content_length", "body_truncated", "response_time",
                                                                   "value_reflected", "unit_halt")},
                   "error": ((measure or {}).get("error") or {}).get("exception_type"),
                   "halt_reason": None, "recorded_at_utc": _utc(),
                   "recovery_state": "result_persisted" if measure else "outcome_unknown"}
            section.setdefault("requests", []).append(row)
            if not measure:
                unknown.append(seq)
        section["requests"].sort(key=lambda r: r["runtime_sequence"])
        for index, row in enumerate(section["requests"], 1):
            row["sequence"] = index
        if not section.get("final"):
            section["status"], section["stop_reason"] = "interrupted", "upstream_interrupted"
    for origin, unit_id in endpoint_units.items():
        if origin[0] not in current or not any(e["endpoint_id"] == origin[1] for e in current[origin[0]].get("endpoints", [])):
            deny("recovery_checkpoint_invalid")
    return unknown
