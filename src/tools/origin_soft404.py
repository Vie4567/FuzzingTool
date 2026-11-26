"""B4.2B multi-origin Soft404 (Agent 5) over B3.1 observed responses.

Each origin is classified on its own: controls are operator-approved sibling
missing paths (`soft404_controls` on the endpoint's exact GET rule) on the same
origin, directory, suffix and query. One `verify_soft404` call per comparison
group; one shared runtime. `genuine_distinct` means a distinct successful HTTP
representation, never business validity; endpoints stay `not_verified`.

With a B3.2B journal bound by a soft404-enabled LocalOriginTest, every request
carries a public unit identity and is journaled as a measurement; group and
candidate decisions are journaled before an anchored checkpoint. Reconcile keeps
strong classifications only when re-derived (`rederived`) or rule-checked against
journaled metrics (`metrics_journaled`, not a similarity recomputation); groups
with reservations but no checkpointed result are `interrupted` and never re-sent.

Not enabled here: full graph acceptance (B4.2C), non-GET, proxy/ffuf engines,
the production multi-origin gate.
"""
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
from .origin_parameters import _DispatchMark, _source_reason
from .origin_scope import OriginScopedTransport, OriginScopePolicy
from .soft404 import _group_key, _matching, verify_soft404

SAMPLES, SIMILARITY, DISTINCT = 3, 0.97, 0.80
_DEFAULT_MAX_REQUESTS = 200
_HEX32, _HEX24 = re.compile(r"[0-9a-f]{32}"), re.compile(r"[0-9a-f]{24}")
TERMINAL_GROUPS = {"completed", "halted", "interrupted"}
_CLASSES = {"genuine": "genuine_distinct", "soft_404": "soft_404", "http_404": "http_404",
            "inconclusive": "inconclusive", "not_checked": "not_checked"}
STRONG = {"genuine_distinct", "soft_404", "http_404"}


def _utc():
    return datetime.now(timezone.utc).isoformat()


def group_id(url):
    return sha256("\n".join(map(str, _group_key(url))).encode()).hexdigest()[:24]


class Soft404InconsistentEvidence(ValueError):
    """Journaled metrics disagree with journaled measurements."""


class Soft404ProbeTransport(OriginScopedTransport):
    """B1 transport that also admits operator-approved Soft404 controls; same open() chain."""

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
        self.unit = self.group = None
        self.ordinal = 0
        self._probe = None

    def classify(self, url):
        """(role, endpoint_url or None) from the operator policy, never from the caller."""
        try:
            self._policy.check(url, "GET")
            return "candidate", url
        except ValueError:
            self._policy.check_soft404_control(url, "GET")
            return "control", None

    def check_dispatch(self, url, method):
        try:
            self._policy.check(url, method)
            super().check_dispatch(url, method)
        except ValueError:
            base = self._policy.check_soft404_control(url, method)
            # Credential binding is checked on the approving exact rule.
            super().check_dispatch(base, method)

    def check_global(self):
        runtime = current_runtime()
        if runtime is not None:
            try:
                runtime.check()
            except PipelineStopped:
                self.stop_reason = self.stop_reason or runtime.stop_reason
        return self.stop_reason

    def start_unit(self, group):
        self.unit, self.group, self.ordinal = uuid4().hex, group, 0

    def begin_unit(self):
        return self.check_global()

    def open(self, request, timeout=10, *, cookie_jar=None):
        self.dispatched, self.dispatched_at, self._probe = False, None, None
        if self.stop_reason:
            raise PipelineStopped(self.stop_reason)
        if self.dispatch_deadline is not None and time.monotonic() >= self.dispatch_deadline:
            raise HttpDispatchDeadline("max_duration")
        url = request.full_url if hasattr(request, "full_url") else request
        role, endpoint_url = self.classify(url)
        endpoint = self.endpoint_ids.get(endpoint_url) if endpoint_url else None
        if self.unit is None or group_id(url) != self.group or (role == "candidate" and endpoint is None):
            raise ValueError("soft404_unit_group_changed")
        probe = {"version": 1, "stage": "soft404", "group_id": self.group, "unit_id": self.unit,
                 "ordinal": self.ordinal + 1, "role": role, "endpoint_id": endpoint}
        runtime = current_runtime()
        if runtime is not None and runtime.recovery is not None:
            runtime.recovery_candidate = {"candidate_id": None, "soft404": probe,
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
                self.ordinal += 1
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
        probe, parts = self._probe, urlsplit(measured["url"])
        features = measured.get("features") or {}
        global_stop = runtime.stop_reason if runtime else None
        error = measured.get("error")
        evidence = {"status_code": measured["status_code"], "content_type": measured["content_type"],
                    "content_length": measured["content_length"], "body_complete": measured["body_complete"],
                    "body_truncated": measured["body_truncated"], "body_sha256": measured["body_sha256"],
                    "normalized_sha256": measured.get("normalized_sha256"), "html": features.get("html"),
                    "login_or_challenge": bool(features.get("login_or_challenge")),
                    "response_time": measured["response_time"],
                    "unit_halt": halt_reason if halt_reason and halt_reason != global_stop else None}
        if runtime is not None and runtime.recovery is not None:
            # Durable before the row exists: every checkpointed row has journal proof.
            runtime.recovery.request_event("measurement", {
                "soft404": {"unit_id": probe["unit_id"], "ordinal": probe["ordinal"]}, **evidence,
                "bytes_received": measured["content_length"],
                "error": {"exception_type": error} if error else None, "stop_reason": global_stop})
        self.requests.append({
            "sequence": len(self.requests) + 1, "runtime_sequence": runtime.requests if runtime else None,
            "origin": canonical_origin(measured["url"]), **{k: probe[k] for k in (
                "group_id", "unit_id", "ordinal", "role", "endpoint_id")},
            "path": parts.path or "/", "query": parts.query, **evidence, "error": error,
            "halt_reason": halt_reason, "recorded_at_utc": _utc()})

    def metrics(self):
        return {}

    def public_settings(self):
        result = super().public_settings()
        result.update(route="direct", probe_policy="b42b_operator_approved_soft404_controls")
        return result


# ── classification re-derivation (mirrors soft404.verify_soft404 branches) ──

def _usable(m):
    return (m is not None and m.get("body_complete") is True and not m.get("error") and bool(m.get("content_length"))
            and m.get("normalized_sha256") is not None and not m.get("login_or_challenge")
            and m.get("status_code") in {200, 404, 410})


def _exact(a, b):
    return a.get("body_sha256") == b.get("body_sha256") or a.get("normalized_sha256") == b.get("normalized_sha256")


def _consistent(metric, a, b):
    """Recorded exact flags/length ratio must agree with the two journaled measurements."""
    try:
        length = min(a["content_length"], b["content_length"]) / max(1, a["content_length"], b["content_length"])
        return (metric["exact_body_match"] == (a["body_sha256"] == b["body_sha256"])
                and metric["exact_normalized_match"] == (a["normalized_sha256"] == b["normalized_sha256"])
                and abs(metric["length_ratio"] - length) < 1e-9
                and all(isinstance(metric[k], (int, float)) and 0 <= metric[k] <= 1
                        for k in ("content_similarity", "text_similarity"))
                and (metric["structure_similarity"] is None or 0 <= metric["structure_similarity"] <= 1)
                and isinstance(metric["comparison_limited"], bool))
    except (KeyError, TypeError):
        return False


def derive_group(controls, metrics):
    """(stable, reason, level) for one group's journaled controls."""
    if len(controls) < SAMPLES:
        return False, "insufficient_controls", "rederived"
    if not all(_usable(c) for c in controls):
        return False, "unsafe_or_incomplete_controls", "rederived"
    if len({(c["status_code"], c["content_type"]) for c in controls}) != 1:
        return False, "unstable_control_status_or_type", "rederived"
    if all(_exact(controls[0], c) for c in controls[1:]):
        return True, "stable", "rederived"
    if not isinstance(metrics, list) or len(metrics) != SAMPLES - 1 or not all(
            _consistent(m, controls[0], c) for m, c in zip(metrics, controls[1:])):
        raise Soft404InconsistentEvidence("group_metrics")
    stable = all(_matching(m, SIMILARITY) for m in metrics)
    return stable, "stable" if stable else "unstable_control_content", "metrics_journaled"


def derive_candidate(group, controls, candidate, metrics, root):
    """(classification, reason, level) for one candidate, from journaled evidence only."""
    stable, reason, level = group
    if not stable:
        return "inconclusive", reason, level
    if candidate is None:
        return "not_checked", "not_measured", "rederived"
    if candidate.get("unit_halt") or candidate.get("stop_reason"):
        return "inconclusive", candidate.get("unit_halt") or candidate.get("stop_reason"), "rederived"
    if candidate["status_code"] in {404, 410} and candidate.get("body_complete") and not candidate.get("error"):
        return "http_404", "remeasured_http_" + str(candidate["status_code"]), "rederived"
    if not _usable(candidate) or candidate["status_code"] != 200:
        return "inconclusive", ("candidate_login_or_challenge" if candidate.get("login_or_challenge")
                                else "unsafe_or_incomplete_candidate"), "rederived"
    same_type = all(candidate["content_type"] == c["content_type"] for c in controls)
    if all(_exact(candidate, c) for c in controls):
        if same_type:
            return ("inconclusive", "shared_homepage_or_spa_shell", "rederived") if root else \
                   ("soft_404", "matches_stable_missing_path_controls", "rederived")
        return "inconclusive", "ambiguous_similarity", "rederived"
    if not isinstance(metrics, list) or len(metrics) != len(controls) or not all(
            _consistent(m, candidate, c) for m, c in zip(metrics, controls)):
        raise Soft404InconsistentEvidence("candidate_metrics")
    if same_type and all(_matching(m, SIMILARITY) for m in metrics):
        return (("inconclusive", "shared_homepage_or_spa_shell", "metrics_journaled") if root else
                ("soft_404", "matches_stable_missing_path_controls", "metrics_journaled"))
    if all(not m["comparison_limited"] and m["content_similarity"] <= DISTINCT and m["text_similarity"] <= DISTINCT
           for m in metrics):
        return "genuine_distinct", "distinct_successful_response", "metrics_journaled"
    return "inconclusive", "ambiguous_similarity", "metrics_journaled"


def _root(url):
    parts = urlsplit(url)
    return parts.path in {"", "/"}


def _metric_fields(comparison):
    return {k: comparison.get(k) for k in ("exact_body_match", "exact_normalized_match", "comparison_limited",
                                          "content_similarity", "text_similarity", "structure_similarity",
                                          "length_ratio")}


def _rule(policy, url):
    parts = urlsplit(url)
    config = policy.public_config()["origin_policies"].get(canonical_origin(url), {"rules": []})
    return next((r for r in config["rules"] if r["path"] == (parts.path or "/") and r["query"] == parts.query
                 and "GET" in r["methods"]), None)


def _plan(state, policy, transport):
    plan = []
    for origin in state.get("approved_origins", []):
        entry = state.get("origin_contexts", {}).get(origin) or {}
        context = entry.get("context") or {}
        wordlist = {r.get("endpoint_id"): r for r in (context.get("wordlist") or {}).get("candidates", [])}
        endpoints = {r.get("endpoint_id"): r for r in entry.get("endpoints", [])}
        params = {e["endpoint_id"]: sorted(c["name"] for c in e.get("candidates", []) if c.get("verification") == "verified")
                  for e in (context.get("parameter_discovery") or {}).get("endpoints", [])}
        rows = []
        for record in (context.get("http_dispatch") or {}).get("records", []):
            identifier, source = record.get("candidate_id"), endpoints.get(record.get("candidate_id"))
            row = {"endpoint_id": identifier, "origin": origin, "url": record.get("url"),
                   "source_dispatch": {k: deepcopy(record.get(k)) for k in (
                       "candidate_id", "status_code", "runtime_sequence", "evidence_refs", "attempted",
                       "body_complete", "retained_body_bytes", "error", "timeout", "stop_reason", "classification")},
                   "provenance": deepcopy(source.get("provenance")) if source is not None else None,
                   "parameter_context": {"verified_parameters": params.get(identifier, []), "authority": "context_only"},
                   "eligible": False, "exclusion_reason": None, "group_id": None, "unit_id": None, "unit_state": None,
                   "soft404_classification": "not_checked", "classification_reason": None, "evidence_level": None,
                   "verification_status": "not_verified", "verification_evidence": {}}
            reason = _source_reason(record)
            if reason is None and record.get("status_code") != 200:
                reason = "source_not_http_200"
            if reason is None and (source is None or source.get("url") != record.get("url")
                                   or source.get("method") != record.get("observed_method") or source.get("origin") != origin
                                   or (wordlist.get(identifier) or {}).get("url") != record.get("url")):
                reason = "source_contract_changed"
            if reason is None:
                try:
                    if public_url(record["url"]) != record["url"] or canonical_origin(record["url"]) != origin:
                        raise ValueError
                    policy.check(record["url"], "GET")
                except (ValueError, TypeError, KeyError):
                    reason = "scope_denied"
            if reason is None and not (_rule(policy, record["url"]) or {}).get("soft404_controls"):
                reason = "soft404_controls_not_approved"
            if reason is None:
                try:
                    transport.check_dispatch(record["url"], "GET")
                except ValueError:
                    reason = "credential_or_transport_scope_denied"
            row["eligible"], row["exclusion_reason"] = reason is None, reason
            if reason is None:
                row.update(group_id=group_id(record["url"]), unit_state="not_started")
            else:
                row["classification_reason"] = reason
            rows.append(row)
        plan.append((origin, rows))
    return plan


def _counts(rows, requests):
    classes = [r["soft404_classification"] for r in rows]
    return {"endpoints": len(rows), "eligible_endpoints": sum(r["eligible"] for r in rows),
            **{name: classes.count(name) for name in ("genuine_distinct", "soft_404", "http_404", "inconclusive", "not_checked")},
            "http_requests": len(requests), "responses": sum(r["status_code"] is not None for r in requests),
            "errors": sum(r["error"] is not None for r in requests)}


def _derive_row(row, unit_rows, group_metrics, candidate_metrics):
    controls = [r for r in unit_rows if r["role"] == "control"]
    candidate = next((r for r in unit_rows if r["role"] == "candidate" and r["endpoint_id"] == row["endpoint_id"]), None)
    # Any recorded metric must agree with the measurements, even where digests decide.
    if group_metrics is not None and (len(group_metrics) != len(controls) - 1 or not all(
            _consistent(m, controls[0], c) for m, c in zip(group_metrics, controls[1:]))):
        raise Soft404InconsistentEvidence("group_metrics")
    if candidate_metrics is not None and (candidate is None or len(candidate_metrics) != len(controls[:SAMPLES]) or not all(
            _consistent(m, candidate, c) for m, c in zip(candidate_metrics, controls[:SAMPLES]))):
        raise Soft404InconsistentEvidence("candidate_metrics")
    group = derive_group(controls, group_metrics)
    return derive_candidate(group, controls[:SAMPLES], candidate, candidate_metrics, _root(row["url"]))


def verify_origin_soft404(state, *, transport, artifact_root=None, max_requests=None):
    """Classify Agent 3 observations per origin and comparison group (B4.2B)."""
    runtime = current_runtime()
    if not isinstance(transport, Soft404ProbeTransport) or runtime is None:
        raise ValueError("B4.2B requires the Soft404 probe transport and the existing shared runtime")
    if state.get("origin_contract_version") != 1:
        raise ValueError("B4.2B requires the B1/B3.1 SharedState contract")
    recovery = runtime.recovery
    if recovery is not None and not getattr(recovery, "soft404_probes", False):
        raise ValueError("soft404_recovery_not_supported")
    if runtime.origin_limits is None or set(runtime.origin_limits) != set(state["approved_origins"]):
        raise ValueError("Configure per-origin quotas for approved origins before starting the shared runtime")
    snapshot = OriginScopePolicy({"approved_origins": state["approved_origins"],
                                  "origin_policies": state.get("origin_policies", {})})
    if snapshot.public_config() != transport._policy.public_config():
        raise ValueError("policy_snapshot_mismatch")
    if (state.get("fuzzing_execution") or {}).get("multi_origin") is None:
        raise ValueError("B4.2B requires a completed B3.1 dispatch call")
    cap = _DEFAULT_MAX_REQUESTS if max_requests is None else max_requests
    if type(cap) is not int or not 1 <= cap <= 10000:
        raise ValueError("max_requests must be an integer in 1..10000")
    restored = {o: deepcopy(e["context"]["soft404"]) for o, e in state.get("origin_contexts", {}).items()
                if "soft404" in ((e or {}).get("context") or {})}
    summary = {}
    if restored:
        if not (recovery is not None and recovery.restored and not getattr(recovery, "soft404_resumed", False)):
            raise ValueError("Soft404 classification already recorded; rerun is not enabled")
        recovery.soft404_resumed = True
        summary = (state.get("soft404_execution") or {}).get("multi_origin") or {}
        if summary.get("phase_max_requests") != cap:
            raise ValueError("soft404_phase_cap_changed")
    writer = RunArtifacts({"artifact_root": artifact_root} if artifact_root else {})
    before = {"http_dispatches": runtime.requests, "by_origin": dict(runtime.origin_requests)}
    if restored:
        before = {"http_dispatches": summary.get("http_dispatches_before"),
                  "by_origin": {o: s.get("origin_budget_before", 0) for o, s in restored.items()}}
    plan = _plan(state, transport._policy, transport)
    outcomes, halts, groups = {}, {}, {o: [] for o, _ in plan}
    if restored:
        transport.requests = sorted((deepcopy(r) for s in restored.values() for r in s.get("requests", [])),
                                    key=lambda r: r["runtime_sequence"])
        for origin, rows in plan:
            section = restored.get(origin, {})
            previous = {e["endpoint_id"]: e for e in section.get("endpoints", [])}
            if set(previous) != {r["endpoint_id"] for r in rows}:
                raise ValueError("soft404_resume_plan_changed")
            for index, row in enumerate(rows):
                old = previous[row["endpoint_id"]]
                if (old["url"], old["eligible"], old["exclusion_reason"]) != (row["url"], row["eligible"], row["exclusion_reason"]):
                    raise ValueError("soft404_resume_plan_changed")
                if old.get("unit_state") in TERMINAL_GROUPS or not old["eligible"]:
                    rows[index] = old
            groups[origin] = deepcopy(section.get("groups", []))
            if section.get("final"):
                outcomes[origin] = {k: section.get(k) for k in ("status", "stop_reason")}
                outcomes[origin]["final"] = True
            if section.get("origin_halt"):
                halts[origin] = section["origin_halt"]
    transport.endpoint_ids = {r["url"]: r["endpoint_id"] for _, rows in plan for r in rows if r["eligible"]}
    transport.endpoint_refs = {r["endpoint_id"]: (r["source_dispatch"].get("evidence_refs") or [])
                               for _, rows in plan for r in rows if r["eligible"]}

    def publish(event):
        for origin, rows in plan:
            context = state["origin_contexts"][origin].setdefault("context", {}) or {}
            requests = [deepcopy(r) for r in transport.requests if r["origin"] == origin]
            outcome = outcomes.get(origin, {"status": "pending", "stop_reason": "pending"})
            context["soft404"] = {
                "schema_version": 1, "stage": "B4.2B", "status": outcome["status"],
                "stop_reason": outcome["stop_reason"], "final": bool(outcome.get("final")),
                "origin_halt": halts.get(origin), "endpoints": deepcopy(rows), "groups": deepcopy(groups[origin]),
                "requests": requests, "counts": _counts(rows, requests),
                "thresholds": {"baseline_samples": SAMPLES, "similarity": SIMILARITY, "distinct": DISTINCT},
                "origin_budget_used": runtime.origin_requests.get(origin, 0),
                "origin_budget_before": before["by_origin"].get(origin, 0),
                "origin_budget_limit": runtime.origin_limits.get(origin),
                "classification_meaning": "HTTP representation vs approved missing-path controls; not endpoint validity"}
            state["origin_contexts"][origin]["context"] = context
            state["origin_contexts"][origin].setdefault("agent_statuses", {})["soft404_filter"] = (
                "success" if outcome["status"] == "completed" else outcome["status"])
        statuses = [o["status"] for o in outcomes.values()]
        overall = ("running" if len(outcomes) < len(plan) else "completed"
                   if statuses and all(s in {"completed", "skipped"} for s in statuses) else "partial")
        telemetry = current_telemetry()
        state.setdefault("soft404_execution", {})["multi_origin"] = {
            "stage": "B4.2B", "engine": "python_http", "status": overall,
            "stop_reason": runtime.stop_reason or next((o["stop_reason"] for o in outcomes.values()
                                                        if o["stop_reason"] not in ("completed", "no_eligible_endpoints")), "completed"),
            "http_dispatches_before": before["http_dispatches"], "http_dispatches_after": runtime.requests,
            "http_dispatches_this_call": runtime.requests - before["http_dispatches"],
            "probe_requests_recorded": len(transport.requests), "phase_max_requests": cap,
            "runtime": runtime.snapshot(), "full_multi_origin_execution_enabled": False,
            "langgraph_integration": "not_enabled_b42b",
            "recovery_support": "journaled_b42b" if recovery is not None else "not_bound", "resumed": bool(restored)}
        if telemetry is not None:
            state["telemetry"] = telemetry.snapshot()
        state["runtime"] = runtime.snapshot()
        public = writer.save(transport.redact(state), node="b42b_soft404", event=event)
        if recovery is not None:
            recovery.checkpoint(public, "b42b_soft404", event)
        return public

    current = None
    publish("soft404_resumed" if restored else "soft404_planned")
    try:
        with telemetry_phase("soft404_filter"):
            for origin, rows in plan:
                if origin in outcomes:
                    continue
                eligible = [r for r in rows if r["eligible"]]
                if not eligible:
                    outcomes[origin] = {"status": "skipped", "stop_reason": "no_eligible_endpoints", "final": True}
                    publish("soft404_origin_skipped")
                    continue
                for gid in list(dict.fromkeys(r["group_id"] for r in eligible)):
                    members = [r for r in eligible if r["group_id"] == gid]
                    if any(r.get("unit_state") in TERMINAL_GROUPS for r in members):
                        continue
                    remaining_time = runtime.deadline - time.monotonic()
                    remaining = cap - len(transport.requests)
                    halted = runtime.stop_reason or halts.get(origin) or transport.check_global() or (
                        "max_requests" if remaining < 1 else "pipeline_deadline" if remaining_time < .01 else None)
                    if halted:
                        for row in members:
                            row.update(soft404_classification="not_checked", classification_reason=halted,
                                       evidence_level="rederived")
                        halts.setdefault(origin, halted)
                        continue
                    transport.stop_reason = None
                    transport.start_unit(gid)
                    current = members
                    records = [{"url": r["url"], "method": "GET", "status_code": 200, "body_complete": True,
                                "content_length": r["source_dispatch"].get("retained_body_bytes")} for r in members]
                    result = verify_soft404(origin + "/", records, transport=transport,
                                            rate_limit=min(100, runtime.rate), timeout_seconds=min(120, runtime.timeout),
                                            max_requests=max(1, remaining), max_duration_seconds=max(.01, min(3600, remaining_time)),
                                            max_response_bytes=runtime.body_cap, baseline_samples=SAMPLES,
                                            similarity_threshold=SIMILARITY, distinct_threshold=DISTINCT)
                    unit_rows = [r for r in transport.requests if r["unit_id"] == transport.unit]
                    info = (result["baseline"]["groups"] or [{}])[0]
                    group_metrics = [_metric_fields(c) for c in info.get("control_similarities", [])] or None
                    by_url = {r["url"]: r for bucket in ("verified", "false_positives", "unverified") for r in result[bucket]}
                    controls = [r["runtime_sequence"] for r in unit_rows if r["role"] == "control"]
                    decisions = []
                    for row in members:
                        checked = by_url.get(row["url"], {})
                        evidence = checked.get("verification_evidence") or {}
                        metrics = [_metric_fields(c) for c in evidence.get("comparisons", [])] or None
                        cls = _CLASSES.get(checked.get("verification"), "not_checked")
                        reason = checked.get("verification_reason") or "not_measured"
                        try:
                            derived, _, level = _derive_row(row, unit_rows, group_metrics, metrics)
                        except Soft404InconsistentEvidence:
                            derived, level = None, "inconclusive"
                        if (cls in STRONG or derived in STRONG) and derived != cls:
                            # Defense in depth: never keep a strong class the evidence cannot reproduce.
                            cls, reason, level = "inconclusive", "derivation_mismatch", "inconclusive"
                        candidate = next((r["runtime_sequence"] for r in unit_rows if r["role"] == "candidate"
                                          and r["endpoint_id"] == row["endpoint_id"]), None)
                        row.update(unit_id=transport.unit, soft404_classification=cls, classification_reason=reason,
                                   evidence_level=level, verification_evidence={
                                       "candidate": evidence.get("candidate"), "comparisons": evidence.get("comparisons"),
                                       "baseline_group": gid, "candidate_sequence": candidate, "control_sequences": controls})
                        if candidate is not None:
                            decisions.append({"unit_id": transport.unit, "endpoint_id": row["endpoint_id"],
                                              "candidate_sequence": candidate, "control_sequences": controls,
                                              "metrics": metrics, "classification": cls, "reason": reason})
                    measured = bool(unit_rows)
                    for row in members:
                        row["unit_state"] = ("completed" if result["stop_reason"] == "completed" else "halted") \
                            if measured else row["unit_state"]
                        if not measured:
                            row["unit_id"] = None
                    groups[origin].append({"group_id": gid, "unit_id": transport.unit if measured else None,
                                           "stable": info.get("stable"), "reason": info.get("reason"),
                                           "control_sequences": controls, "control_metrics": group_metrics})
                    if recovery is not None and measured:
                        # Decisions are durable before the anchored unit checkpoint.
                        recovery.append("soft404_group", {"unit_id": transport.unit, "group_id": gid,
                                                          "control_sequences": controls, "control_metrics": group_metrics,
                                                          "stable": info.get("stable"), "reason": info.get("reason")})
                        for decision in decisions:
                            recovery.append("soft404_decision", decision)
                    current = None
                    if result["stop_reason"] != "completed":
                        halts.setdefault(origin, result["stop_reason"])
                    publish("soft404_unit_measured")
                total = sum(r["origin"] == origin for r in transport.requests)
                halt = halts.get(origin)
                status = ("completed" if not halt and total else "skipped" if not halt
                          else "partial" if total else "not_started")
                outcomes[origin] = {"status": status, "stop_reason": halt or "completed", "final": True}
                publish("soft404_origin_measured")
    except BaseException:
        if current is not None and any(r["unit_id"] == transport.unit for r in transport.requests):
            for row in current:
                row.update(unit_id=transport.unit, unit_state="interrupted", soft404_classification="inconclusive",
                           classification_reason="unit_interrupted", evidence_level="interrupted")
        for origin, _ in plan:
            outcomes.setdefault(origin, {"status": "interrupted", "stop_reason": "upstream_interrupted"})
        publish("soft404_interrupted")
        raise
    return publish("soft404_finished")


# ── B4.2B reconcile: journal is evidence, the fresh operator context is authority ──

def reconcile_soft404_recovery(*, local, state, events, reservations, starts, measurements, checkpoints, deny):
    """Validate Soft404 reservations/decisions/checkpoints; mark terminal groups. Returns unknown sequences."""
    from src.coordinator.origins import endpoint_observation
    probes = [r for r in reservations if "soft404" in r]
    sections = lambda saved: {o: (e.get("context") or {}).get("soft404") for o, e in (saved.get("origin_contexts") or {}).items()
                              if (e.get("context") or {}).get("soft404") is not None}
    if not probes and not any(sections(saved) for _, saved in checkpoints):
        return []
    transport = getattr(local, "soft404_transport", None)
    if transport is None:
        deny("recovery_reservation_identity_invalid")
    for row in probes:
        try:
            probe = row["soft404"]
            if (set(probe) != {"version", "stage", "group_id", "unit_id", "ordinal", "role", "endpoint_id"}
                    or probe["version"] != 1 or probe["stage"] != "soft404" or not _HEX32.fullmatch(probe["unit_id"])
                    or not _HEX24.fullmatch(probe["group_id"]) or type(probe["ordinal"]) is not int
                    or probe["role"] not in {"control", "candidate"} or row.get("candidate_id") is not None
                    or row["method"] != "GET" or canonical_origin(row["url"]) != row["origin"]):
                raise ValueError
            transport.check_dispatch(row["url"], "GET")
            role, endpoint_url = transport.classify(row["url"])
            if role != probe["role"] or group_id(row["url"]) != probe["group_id"]:
                raise ValueError
            expected = endpoint_observation(endpoint_url, method="GET")["endpoint_id"] if endpoint_url else None
            if expected != probe["endpoint_id"]:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            deny("recovery_reservation_identity_invalid")
    units, owners = check_units(probes, key="soft404", owner=lambda r: (r["origin"], r["soft404"]["group_id"]),
                                epochs=process_epochs(events), deny=deny, code="recovery_probe_replay_detected")
    fields = ("status_code", "content_type", "body_sha256", "normalized_sha256", "body_complete")
    check_checkpoint_rows(checkpoints, probes, measurements, sections, key="soft404",
                          identity=("group_id", "unit_id", "ordinal", "role", "endpoint_id"), fields=fields,
                          deny=deny, missing_code="recovery_soft404_checkpoint_missing")
    group_events = {e["payload"]["unit_id"]: e["payload"] for e in events if e["event"] == "soft404_group"}
    decisions = {(e["payload"]["unit_id"], e["payload"]["endpoint_id"]): e["payload"] for e in events
                 if e["event"] == "soft404_decision"}
    current = sections(state)
    if probes and not current:
        deny("recovery_soft404_checkpoint_missing")
    last_cover = checkpoints[-1][0]["reservations"]
    by_seq = {r["sequence"]: r for r in probes}

    def measured_row(seq):
        res, m = by_seq[seq], measurements[seq]
        return {**{k: m.get(k) for k in fields + ("content_length", "login_or_challenge", "unit_halt", "stop_reason")},
                "error": (m.get("error") or {}).get("exception_type"), "role": res["soft404"]["role"],
                "endpoint_id": res["soft404"]["endpoint_id"], "runtime_sequence": seq}

    unknown = []
    for origin, section in current.items():
        listed = {r["runtime_sequence"] for r in section.get("requests", [])}
        for endpoint in section.get("endpoints", []):
            unit_id = owners.get((origin, endpoint.get("group_id")))
            strong = endpoint.get("soft404_classification") in STRONG
            if unit_id is None:
                if strong or endpoint.get("unit_state") in TERMINAL_GROUPS:
                    deny("recovery_soft404_classification_unproven")
                continue
            seqs = [r["sequence"] for r in units[unit_id]]
            group_event = group_events.get(unit_id)
            complete = (all(s <= last_cover and s in measurements for s in seqs) and group_event is not None
                        and endpoint.get("unit_id") == unit_id and endpoint.get("unit_state") in {"completed", "halted"})
            if complete:
                rows = [measured_row(s) for s in seqs]
                decision = decisions.get((unit_id, endpoint["endpoint_id"]))
                candidate = next((r for r in rows if r["role"] == "candidate" and r["endpoint_id"] == endpoint["endpoint_id"]), None)
                if candidate is not None and (decision is None or decision["candidate_sequence"] != candidate["runtime_sequence"]
                                              or decision["classification"] != endpoint.get("soft404_classification")):
                    deny("recovery_soft404_classification_unproven")
                if group_event["control_sequences"] != [r["runtime_sequence"] for r in rows if r["role"] == "control"]:
                    deny("recovery_soft404_classification_unproven")
                try:
                    derived, _, level = _derive_row(endpoint, rows, group_event.get("control_metrics"),
                                                    decision.get("metrics") if decision else None)
                except Soft404InconsistentEvidence:
                    deny("recovery_soft404_classification_unproven")
                if (strong or derived in STRONG) and derived != endpoint.get("soft404_classification"):
                    deny("recovery_soft404_classification_unproven")
                if strong and endpoint.get("evidence_level") != level:
                    deny("recovery_soft404_classification_unproven")
                continue
            missing = [s for s in seqs if s not in measurements]
            endpoint.update(unit_id=unit_id, unit_state="interrupted", soft404_classification="inconclusive",
                            classification_reason="probe_outcome_unknown" if missing else "unit_interrupted",
                            evidence_level="interrupted")
        for res in probes:
            seq = res["sequence"]
            if res["origin"] != origin or seq in listed:
                continue
            measure, parts = measurements.get(seq), urlsplit(res["url"])
            row = {"sequence": None, "runtime_sequence": seq, "origin": origin,
                   **{k: res["soft404"][k] for k in ("group_id", "unit_id", "ordinal", "role", "endpoint_id")},
                   "path": parts.path or "/", "query": parts.query, "attempted": True if seq in starts else None,
                   **{k: (measure or {}).get(k) for k in fields + ("content_length", "body_truncated", "html",
                                                                   "login_or_challenge", "response_time", "unit_halt")},
                   "error": ((measure or {}).get("error") or {}).get("exception_type"), "halt_reason": None,
                   "recorded_at_utc": _utc(), "recovery_state": "result_persisted" if measure else "outcome_unknown"}
            section.setdefault("requests", []).append(row)
            if not measure:
                unknown.append(seq)
        section["requests"].sort(key=lambda r: r["runtime_sequence"])
        for index, row in enumerate(section["requests"], 1):
            row["sequence"] = index
        if not section.get("final"):
            section["status"], section["stop_reason"] = "interrupted", "upstream_interrupted"
    for (origin, gid) in owners:
        if origin not in current or not any(e.get("group_id") == gid for e in current[origin].get("endpoints", [])):
            deny("recovery_checkpoint_invalid")
    return unknown
