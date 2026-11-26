"""B5 offline, verified export of a finished B4.2C local multi-origin session.

Reads only: the recovery journal (hash chain + head, under the session's OS lock), every
journal-anchored checkpoint (sha256) and the final `pipeline` checkpoint sealed by
`session_finished`. Report content v1 and its digest are copied verbatim and re-checked; a digest
is never recomputed to make a source valid. The envelope `multi_origin_report_export` v1 adds
journal-derived HTTP accounting (global, per origin, per phase), budget, telemetry, LLM and
recovery statistics, a per-origin endpoint index (identity, method, query variant, provenance)
and an explicit evidence vocabulary. JSON is canonical; Markdown is rendered only from the
envelope. Files are written into a pending directory and published by one atomic rename; an
existing output is never overwritten and a failure leaves no published report.

Not done here: HTTP, LLM, KnowledgeStore, resume or finalize_only (a session must already be
finished), severity, HTML, cross-origin de-duplication, export of sessions without a journal,
server-receipt claims (only lab access logs prove those). Single-target result.json, Report v1,
recovery and the production multi-origin gate are unchanged.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit
from uuid import uuid4

from .llm_logging import sanitize_for_log
from .origin_recovery import RecoveryDenied, RecoveryJournal
from .origin_report import AGENTS, canonical_digest, origin_agent_status, origin_status, resolve

_STRONG = {"genuine_distinct", "soft_404", "http_404"}

SCHEMA = "multi_origin_report_export"
SCHEMA_VERSION = 1
KEYS = ("reserved", "dispatch_started", "response_headers", "measured", "measured_with_error", "timeouts",
        "incomplete_bodies", "attempt_unknown", "outcome_unknown")
KINDS = ("recon", "dispatch", "parameter_probe", "soft404_probe")
_UNKNOWN = "không xác định"
_ABSENT = "—"
ACCOUNTING_MEANING = {
    "reserved": "journal `reserved`: the shared runtime reserved one request slot (budget/quota consumed)",
    "dispatch_started": "journal `dispatch_started`: the transport began opening the request; not proof the server received it",
    "response_headers": "journal `response_headers`: the client received a status line and headers",
    "measured": "journal `measurement`: the request outcome was recorded (response, error or timeout)",
    "measured_with_error": "measured with a transport/read error recorded",
    "timeouts": "measured with a timeout exception type",
    "incomplete_bodies": "measured with a status code but body_complete = false",
    "attempt_unknown": "reserved without dispatch_started: it is unknown whether a request was sent",
    "outcome_unknown": "reserved without measurement: the outcome is unknown (never re-sent)",
    "server_arrivals": "not claimed by the export; only independent lab access logs prove server receipt",
}
VOCABULARY = {
    "observation_classification": {
        "observed": "Agent 1 saw the reference in a collected source document",
        "candidate": "reference shape that Agent 1 could not resolve to a concrete request",
        "inferred": "derived by rule, not seen as such"},
    "dispatch_evidence": {"observed_http": "Agent 3 measured a status code; HTTP observation is not verification"},
    "parameter_verification": {
        "verified": "repeatable response effect vs negative controls; authority context_only, never endpoint verification",
        "inconclusive": "measured without a repeatable effect", "not_checked": "not selected or not measured"},
    "parameter_provenance": {"observed_reference": "named by an Agent 1 reference",
                             "inferred_static": "ParamAssembler vocabulary (inferred)"},
    "soft404_class": {
        "genuine_distinct": "representation differs from approved missing-path controls; not a vulnerability, not business validity",
        "soft_404": "representation matches stable missing-path controls", "http_404": "HTTP 404 response",
        "inconclusive": "no strong class could be derived", "not_checked": "no Soft404 measurement for this endpoint"},
    "soft404_evidence_basis": {
        "rederived": "class re-derived from journaled measurements (status, type, digest, length)",
        "metrics_journaled": "class rests on journaled similarity metrics; similarity is not recomputable from the journal",
        "inconclusive": "evidence was inconsistent or insufficient", "interrupted": "unit interrupted; never re-sent",
        "not_applicable": "class not_checked: the v1 evidence_level label (kept as evidence_level_v1) is not evidence"},
    "endpoint_verification": "always not_verified",
    "severity": "not assessed in B5 (null); no finding or vulnerability is asserted",
}
NOT_CONCLUDED = [
    "business validity of any endpoint (all endpoints remain not_verified)",
    "severity or vulnerability status of any observation (severity is null)",
    "genuine_distinct as a security finding",
    "server receipt of any request (requires independent access logs; available only in the lab verifier)",
    "results of reservations whose outcome is unknown",
    "similarity recomputation after recovery (the journal stores no bodies)",
    "behaviour outside the loopback lab (Internet, real TLS, DNS, proxy, ffuf, provider LLM)",
]
LIMITS = [
    "export accepts only finished sessions with a valid journal, head, anchored checkpoints and session_finished",
    "hash chain and sha256 anchors do not resist an actor with full write access; semantic cross-checks narrow but do not close this",
    "redaction idempotence of the envelope is a guard, not proof that no secret remains",
    "Report v1 totals are kept verbatim: *_requests count section rows (journal reservations) and exclude Recon",
    "Report v1 `executed` means some Agent was invoked globally, not that the origin received a request",
    "recovery is at-most-once, never exactly-once",
    "power-loss durability is not verified",
]


class ExportError(ValueError):
    """Fixed public code only; never include source content."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _deny(code):
    raise ExportError(code)


def _identity(url, method):
    return sha256((url + "\n" + (method or "")).encode()).hexdigest()[:24]


def _origin_of(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _sha(path):
    return sha256(Path(path).read_bytes()).hexdigest()


# ── loading and verification of the source session ──

def _open(directory):
    if not directory.is_dir():
        _deny("export_session_missing")
    for name in ("journal.jsonl", "head.json"):
        if not (directory / name).is_file():
            _deny("export_journal_missing")
    lock = directory / "session.lock"
    if not lock.is_file() or lock.stat().st_size == 0:
        _deny("export_session_lock_missing")  # never create or initialise session files
    journal = RecoveryJournal(directory, resume=True)
    try:
        journal.__enter__()  # OS lock + hash chain + head; never appends
    except RecoveryDenied as exc:
        _deny("export_session_locked" if str(exc) == "recovery_session_locked" else "export_journal_invalid")
    return journal


def _source_hashes(directory, checkpoints):
    hashes = {"journal.jsonl": _sha(directory / "journal.jsonl"), "head.json": _sha(directory / "head.json")}
    for row in checkpoints:
        hashes[row["rel"]] = _sha(row["path"])
    return hashes


def load_verified(directory, root, events):
    """Every check before any envelope field is built; failures are fixed public codes."""
    if not events or events[0]["event"] != "session":
        _deny("export_journal_invalid")
    if events[-1]["event"] != "session_finished":
        _deny("export_session_not_finished")
    if sum(e["event"] == "session_finished" for e in events) != 1 or len(events) < 3 \
            or events[-2]["event"] != "checkpoint":
        _deny("export_session_finished_invalid")
    session = events[0]["payload"]
    checkpoints = []
    for event in events:
        if event["event"] != "checkpoint":
            continue
        data = event["payload"]
        try:
            path = Path(data["path"]).resolve()
        except (KeyError, TypeError, ValueError, OSError):
            _deny("export_checkpoint_invalid")
        if not path.is_relative_to(root):
            _deny("export_path_escape")
        if not path.is_file():
            _deny("export_checkpoint_missing")
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != data.get("sha256"):
            _deny("export_checkpoint_invalid")
        try:
            saved = json.loads(raw)
        except ValueError:
            _deny("export_checkpoint_invalid")
        if not isinstance(saved, dict) or saved.get("session_id") != session.get("session_id"):
            _deny("export_checkpoint_invalid")
        checkpoints.append({"seq": event["seq"], "payload": data, "path": path,
                            "rel": path.relative_to(root).as_posix(), "sha256": data["sha256"], "data": saved})
    final = checkpoints[-1] if checkpoints else None
    status = events[-1]["payload"].get("pipeline_status")
    if (final is None or final["seq"] != events[-2]["seq"] or final["payload"].get("node") != "pipeline"
            or final["payload"].get("event") != status or final["data"].get("pipeline_status") != status):
        _deny("export_session_finished_invalid")
    for row in checkpoints:
        report = row["data"].get("multi_origin_report")
        if report is not None:
            try:
                if canonical_digest(report["content"]) != report["digest"]:
                    _deny("export_report_digest_mismatch")
            except (KeyError, TypeError, ValueError):
                _deny("export_report_digest_mismatch")
    state = final["data"]
    report = state.get("multi_origin_report")
    if not isinstance(report, dict) or not isinstance(report.get("content"), dict):
        _deny("export_report_missing")
    if report.get("schema_version") != 1 or report["content"].get("schema_version") != 1:
        _deny("export_report_schema_unsupported")
    anchored = [r for r in checkpoints if r["payload"].get("node") == "generate_report"
                and r["payload"].get("event") == "checkpoint"]
    if not anchored or anchored[-1]["data"]["multi_origin_report"]["digest"] != report["digest"]:
        _deny("export_report_unanchored")
    reflection = state.get("local_reflection") or {}
    try:
        backed = all(resolve(report["content"], o["report_path"]) == o["value"] for o in reflection["observations"])
    except (KeyError, IndexError, TypeError, ValueError):
        backed = False
    if (not backed or reflection.get("report_digest") != report["digest"] or reflection.get("knowledge_writes") != 0
            or reflection.get("llm_called") is not False or reflection.get("lessons") != []):
        _deny("export_reflection_mismatch")
    gate = {"origin_execution_mode": "not_enabled_b1", "full_multi_origin_execution_enabled": False}
    if state.get("origin_execution_mode") != "not_enabled_b1" or report["content"].get("gate") != gate:
        _deny("export_gate_changed")
    scope = (session.get("authority") or {}).get("config", {}).get("multi_origin") or {}
    approved = [o["origin"] for o in report["content"]["approved_origins"]]
    # Same rule as B3.2B restore: the checkpoint's public policy equals the journal authority.
    if not approved or approved != state.get("approved_origins") or approved != scope.get("approved_origins") \
            or (state.get("config") or {}).get("multi_origin") != scope:
        _deny("export_scope_mismatch")
    return {"session": session, "checkpoints": checkpoints, "final": final, "state": state, "report": report,
            "report_checkpoint": anchored[-1], "approved": approved}


# ── journal accounting ──

def _kind(reservation):
    if reservation.get("probe") is not None:
        return "parameter_probe"
    if reservation.get("soft404") is not None:
        return "soft404_probe"
    return "dispatch" if reservation.get("candidate_id") is not None else "recon"


def journal_accounting(events, approved):
    reservations = [e["payload"] for e in events if e["event"] == "reserved"]
    starts, responses, measures = {}, {}, {}
    for index, row in enumerate(reservations, 1):
        if row.get("sequence") != index or row.get("origin") not in approved \
                or _origin_of(str(row.get("url"))) != row.get("origin"):
            _deny("export_accounting_mismatch" if row.get("sequence") != index else "export_unapproved_dispatch")
    for event in events:
        kind = event["event"]
        if kind not in ("dispatch_started", "response_headers", "measurement"):
            continue
        seq = event["payload"].get("sequence")
        dest = {"dispatch_started": starts, "response_headers": responses, "measurement": measures}[kind]
        if type(seq) is not int or not 1 <= seq <= len(reservations) or seq in dest \
                or (kind != "dispatch_started" and seq not in starts):
            _deny("export_accounting_mismatch")
        dest[seq] = event["payload"]
    rows = []
    for seq, reservation in enumerate(reservations, 1):
        measure = measures.get(seq)
        error = (measure or {}).get("error") or {}
        flags = {"reserved": True, "dispatch_started": seq in starts, "response_headers": seq in responses,
                 "measured": measure is not None, "measured_with_error": bool(measure and measure.get("error")),
                 "timeouts": "timeout" in str(error.get("exception_type") or "").lower(),
                 "incomplete_bodies": bool(measure and measure.get("status_code") is not None
                                           and measure.get("body_complete") is False),
                 "attempt_unknown": seq not in starts, "outcome_unknown": measure is None}
        status = (measure or responses.get(seq) or {}).get("status_code")
        rows.append({"sequence": seq, "origin": reservation["origin"], "phase": str(reservation.get("phase")),
                     "kind": _kind(reservation), "url": reservation.get("url"), "method": reservation.get("method"),
                     "candidate_id": reservation.get("candidate_id"), "status_code": status, "flags": flags})
    return rows


def _bucket(rows):
    return {key: sum(1 for r in rows if r["flags"][key]) for key in KEYS}


def _check_sections(state, approved, rows, report):
    """Agent sections and Report v1 must agree with the journal; nothing is recomputed into validity."""
    by_kind = {(r["origin"], r["kind"]): set() for r in rows}
    for r in rows:
        by_kind[(r["origin"], r["kind"])].add(r["sequence"])
    seq_row = {r["sequence"]: r for r in rows}
    unknown_journal = {}
    for r in rows:
        if r["flags"]["outcome_unknown"] and r["kind"] != "recon":
            unknown_journal.setdefault(r["origin"], []).append(r["sequence"])
    for index, origin in enumerate(approved):
        context = ((state.get("origin_contexts") or {}).get(origin) or {}).get("context") or {}
        v1 = report["content"]["approved_origins"][index]
        for key, kind, field in (("http_dispatch", "dispatch", "records"), ("parameter_discovery", "parameter_probe", "requests"),
                                 ("soft404", "soft404_probe", "requests")):
            section = context.get(key)
            journal = by_kind.get((origin, kind), set())
            if section is None:
                if journal:
                    _deny("export_accounting_mismatch")
                continue
            listed = [r.get("runtime_sequence") for r in section.get(field, []) if r.get("runtime_sequence") is not None]
            if len(listed) != len(set(listed)) or set(listed) != journal:
                _deny("export_accounting_mismatch")
            for row in section.get(field, []):
                seq = row.get("runtime_sequence")
                if seq is None:
                    continue
                proof = seq_row[seq]
                if row.get("status_code") is not None and row.get("status_code") != proof["status_code"]:
                    _deny("export_accounting_mismatch")
                if (row.get("recovery_state") == "outcome_unknown") != proof["flags"]["outcome_unknown"]:
                    _deny("export_accounting_mismatch")  # unknown is never laundered into a measured row
        if sorted(v1.get("outcome_unknown_sequences") or []) != sorted(unknown_journal.get(origin, [])):
            _deny("export_accounting_mismatch")
        # Report v1 rows must equal the anchored final sections they were built from.
        sections = {"dispatch": ("http_dispatch", "records", "candidate_id", ("runtime_sequence", "status_code")),
                    "parameters": ("parameter_discovery", "endpoints", "endpoint_id", ("unit_state",)),
                    "soft404": ("soft404", "endpoints", "endpoint_id",
                                ("soft404_classification", "evidence_level", "unit_state"))}
        for name, (key, field, ident, compared) in sections.items():
            v1_rows = (v1.get(name) or {}).get(field) or []
            src = {r.get(ident): r for r in (context.get(key) or {}).get(field, [])}
            if len(v1_rows) != len(src):
                _deny("export_report_source_mismatch")
            for row in v1_rows:
                source = src.get(row.get(ident))
                if source is None or any(row.get(k) != source.get(k) for k in compared) or row.get("url") != source.get("url"):
                    _deny("export_report_source_mismatch")
                if name == "parameters" and [(c["name"], c["verification"]) for c in row["candidates"]] != \
                        [(c.get("name"), c.get("verification")) for c in source.get("candidates", [])]:
                    _deny("export_report_source_mismatch")


def _check_report_semantics(state, approved, report):
    """Consistent forgeries (content + digest rewritten) must still re-derive from the sections."""
    content = report["content"]
    totals = Counter()
    for index, origin in enumerate(approved):
        v1 = content["approved_origins"][index]
        entry = (state.get("origin_contexts") or {}).get(origin) or {}
        context = entry.get("context") or {}
        for name, key in (("dispatch", "http_dispatch"), ("parameters", "parameter_discovery"), ("soft404", "soft404")):
            if (v1.get(name) is None) != (context.get(key) is None) or \
                    (v1.get(name) is not None and v1[name].get("counts") != context[key].get("counts")):
                _deny("export_report_source_mismatch")
        failures = content["stop"]["contract_failures"]
        for agent in ("fuzzing", "param_disc", "soft404_filter"):
            if agent in failures:
                continue
            if (context.get({"fuzzing": "http_dispatch", "param_disc": "parameter_discovery",
                             "soft404_filter": "soft404"}[agent]) is not None
                    and origin_agent_status(entry, agent, ("absent", None))[0] != v1["agents"][agent]["status"]):
                _deny("export_status_mismatch")
        agents = {a: (v["status"], v["reason"]) for a, v in v1["agents"].items()}
        if origin_status(agents, v1["outcome_unknown_sequences"]) != v1["status"]:
            _deny("export_status_mismatch")
        counts = lambda section: ((v1.get(section) or {}).get("counts") or {})
        totals["dispatch_attempted"] += counts("dispatch").get("attempted", 0)
        totals["dispatch_responses"] += counts("dispatch").get("responses", 0)
        totals["outcome_unknown"] += len(v1["outcome_unknown_sequences"])
        totals["parameter_requests"] += counts("parameters").get("http_requests", 0)
        totals["verified_parameters"] += counts("parameters").get("verified", 0)
        totals["soft404_requests"] += counts("soft404").get("http_requests", 0)
        for row in (v1.get("soft404") or {}).get("endpoints", []):
            cls = row.get("soft404_classification")
            if "soft404_" + str(cls) in content["totals"]:
                totals["soft404_" + cls] += 1
            totals["soft404_strong"] += cls in _STRONG
            if row.get("verification_status") != "not_verified":
                _deny("export_endpoint_promoted")
        for name in ("parameters", "soft404"):
            for row in (v1.get(name) or {}).get("endpoints", []):
                totals["interrupted_units"] += row.get("unit_state") == "interrupted"
                if name == "parameters" and row.get("endpoint_verification_status") != "not_verified":
                    _deny("export_endpoint_promoted")
    if any(content["totals"].get(k) != totals.get(k, 0) for k in content["totals"]):
        _deny("export_report_source_mismatch")
    if state.get("pipeline_status") == "completed" and not (
            all(o["status"] == "completed" for o in content["approved_origins"])
            and all(content["agents"][a]["status"] == "success" for a in AGENTS)
            and content["totals"]["outcome_unknown"] == 0 and content["totals"]["interrupted_units"] == 0
            and content["stop"]["global_stop_reason"] is None and not content["stop"]["contract_failures"]
            and not (state.get("recovery") or {}).get("finalize_only")
            and state.get("all_modules_successful") is True):
        _deny("export_status_mismatch")
    for agent in AGENTS:
        if content["agents"][agent]["status"] != (state.get("agent_statuses") or {}).get(agent):
            _deny("export_status_mismatch")


# ── envelope ──

def _provenance_class(provenance):
    source = provenance.get("source")
    return ("observed_reference" if source == "agent1_reference" else
            "inferred_static" if source == "param_assembler_static" else "other")


def _endpoints(origin, entry, context):
    observations = entry.get("endpoints") or []
    ids = [e.get("endpoint_id") for e in observations]
    if len(ids) != len(set(ids)):
        _deny("export_duplicate_endpoint")
    by_id = {e["endpoint_id"]: e for e in observations}
    wordlist = context.get("wordlist") or {}
    candidates = {}
    for row in wordlist.get("candidates", []):
        if row.get("endpoint_id") in candidates and candidates[row["endpoint_id"]] != row:
            _deny("export_duplicate_endpoint")
        candidates[row.get("endpoint_id")] = row
    selected = set(wordlist.get("selected_ids") or [])
    linked = {}
    for key, field, ident in (("dispatch", "records", "candidate_id"), ("parameters", "endpoints", "endpoint_id"),
                              ("soft404", "endpoints", "endpoint_id")):
        section = context.get({"dispatch": "http_dispatch", "parameters": "parameter_discovery", "soft404": "soft404"}[key])
        rows = {}
        for row in (section or {}).get(field, []):
            if row.get(ident) in rows:
                _deny("export_duplicate_endpoint")
            rows[row.get(ident)] = row
        linked[key] = rows
    extra = sorted({i for rows in linked.values() for i in rows} - set(ids), key=str)
    out = []
    for identifier in ids + extra:
        source = by_id.get(identifier) or candidates.get(identifier)
        if source is None or not isinstance(source.get("url"), str):
            _deny("export_evidence_unresolved")
        url, method = source["url"], source.get("method")
        if _identity(url, method) != identifier:
            _deny("export_endpoint_identity_invalid")
        if _origin_of(url) != origin:
            _deny("export_origin_mixed")
        for rows in linked.values():
            row = rows.get(identifier)
            if row is not None and row.get("url") not in (None, url):
                _deny("export_origin_mixed")
            if row is not None and row.get("verification_status") not in (None, "not_verified"):
                _deny("export_endpoint_promoted")
        provenance = (source.get("provenance") or []) if identifier in by_id else []
        record, params, soft = (linked["dispatch"].get(identifier), linked["parameters"].get(identifier),
                                linked["soft404"].get(identifier))
        dispatch = None if record is None else {
            "runtime_sequence": record.get("runtime_sequence"), "attempted": record.get("attempted"),
            "observed_method": record.get("observed_method"), "execution_method": record.get("execution_method"),
            "status_code": record.get("status_code"), "body_complete": record.get("body_complete"),
            "bytes_received": record.get("bytes_received"), "timeout": record.get("timeout"),
            "error_type": (record.get("error") or {}).get("error_type"), "stop_reason": record.get("stop_reason"),
            "rejection_reason": record.get("rejection_reason"), "recovery_state": record.get("recovery_state"),
            "classification": record.get("classification"),
            "evidence": "observed_http" if record.get("status_code") is not None else None,
            "verification_status": "not_verified"}
        parameters = None if params is None else {
            "endpoint_id": identifier, "eligible": params.get("eligible"), "exclusion_reason": params.get("exclusion_reason"),
            "unit_id": params.get("unit_id"), "unit_state": params.get("unit_state"),
            "candidates": [{"endpoint_id": identifier, "name": c.get("name"), "selected": c.get("selected"),
                            "selection_reason": c.get("selection_reason"), "verification": c.get("verification"),
                            "verification_reason": c.get("verification_reason"),
                            "verification_performed": c.get("verification_performed"),
                            "provenance_classes": sorted({_provenance_class(p) for p in c.get("provenance") or []}),
                            "authority": "context_only"} for c in params.get("candidates", [])]}
        soft404 = None
        if soft is not None:
            context_param = soft.get("parameter_context") or {}
            if context_param.get("authority") != "context_only":
                _deny("export_parameter_authority_changed")
            cls, level = soft.get("soft404_classification"), soft.get("evidence_level")
            evidence = soft.get("verification_evidence") or {}
            soft404 = {"endpoint_id": identifier, "eligible": soft.get("eligible"),
                       "exclusion_reason": soft.get("exclusion_reason"), "group_id": soft.get("group_id"),
                       "unit_id": soft.get("unit_id"), "unit_state": soft.get("unit_state"),
                       "classification": cls, "classification_reason": soft.get("classification_reason"),
                       "evidence_level_v1": level, "evidence_basis": "not_applicable" if cls == "not_checked" else level,
                       "candidate_sequence": evidence.get("candidate_sequence"),
                       "control_sequences": deepcopy(evidence.get("control_sequences")),
                       "parameter_context": {"verified_parameters": sorted(context_param.get("verified_parameters") or []),
                                             "authority": "context_only"},
                       "verification_status": "not_verified"}
        word = candidates.get(identifier)
        out.append({"endpoint_id": identifier, "url": url, "method": method, "has_query": bool(urlsplit(url).query),
                    "source": "agent1_observation" if identifier in by_id else "agent2_wordlist_candidate",
                    "resource_type": source.get("resource_type"), "provenance_count": len(provenance),
                    "provenance": [{k: deepcopy(p.get(k)) for k in ("source", "source_type", "source_url", "classification",
                                                                    "resource_type", "evidence_refs")} for p in provenance],
                    "observation_classes": sorted({p.get("classification") for p in provenance if p.get("classification")}),
                    "wordlist": None if word is None else {"generated": bool(word.get("generated")),
                                                           "selected": identifier in selected},
                    "dispatch": dispatch, "parameters": parameters, "soft404": soft404,
                    "endpoint_verification_status": "not_verified"})
    return out


def _accounting_lists(rows, origins):
    phases = sorted({r["phase"] for r in rows})
    return {
        "total": _bucket(rows),
        "by_phase": [{"phase": p, "kind": sorted({r["kind"] for r in rows if r["phase"] == p}),
                      **_bucket([r for r in rows if r["phase"] == p])} for p in phases],
        "by_kind": [{"kind": k, **_bucket([r for r in rows if r["kind"] == k])} for k in KINDS],
        "by_origin": [{"origin": o, **_bucket([r for r in rows if r["origin"] == o]),
                       "by_phase": [{"phase": p, **_bucket([r for r in rows if r["origin"] == o and r["phase"] == p])}
                                    for p in phases if any(r["origin"] == o and r["phase"] == p for r in rows)]}
                      for o in origins],
        "unknown_sequences": {"attempt_unknown": [r["sequence"] for r in rows if r["flags"]["attempt_unknown"]],
                              "outcome_unknown": [r["sequence"] for r in rows if r["flags"]["outcome_unknown"]]},
    }


def build_envelope(source):
    state, report, session = source["state"], source["report"], source["session"]
    content, approved, events = report["content"], source["approved"], source["events"]
    rows = journal_accounting(events, approved)
    try:
        _check_report_semantics(state, approved, report)
        _check_sections(state, approved, rows, report)
    except (KeyError, TypeError, AttributeError, IndexError):
        _deny("export_source_malformed")
    runtime = state.get("runtime") or {}
    if (runtime.get("http_dispatches") != len(rows)
            or runtime.get("http_dispatches_by_origin") != dict(Counter(r["origin"] for r in rows))):
        _deny("export_accounting_mismatch")
    authority = session.get("authority") or {}
    if authority.get("quotas") != runtime.get("http_origin_max_requests"):
        _deny("export_budget_mismatch")
    config = authority.get("config") or {}
    if config.get("http_max_requests", runtime.get("http_max_requests")) != runtime.get("http_max_requests"):
        _deny("export_budget_mismatch")
    telemetry = state.get("telemetry") or {}
    http = telemetry.get("http") or {}
    complete = http.get("count_complete")
    if (complete is True and http.get("total_requests") != len(rows)) or \
            (complete is False and (http.get("total_requests") is not None or (http.get("known_requests") or 0) > len(rows))) \
            or complete not in (True, False):
        _deny("export_telemetry_mismatch")
    recovery = state.get("recovery") or {}
    summary = recovery.get("accounting")
    total = _bucket(rows)
    if summary is not None and (summary.get("reserved_requests"), summary.get("known_dispatch_starts"),
                                summary.get("attempts_unknown"), summary.get("responses_received"),
                                summary.get("outcome_unknown_requests")) != (
            total["reserved"], total["dispatch_started"], total["attempt_unknown"], total["response_headers"],
            total["outcome_unknown"]):
        _deny("export_recovery_accounting_mismatch")
    llm = telemetry.get("llm") or {}
    if state.get("llm_call_count") != llm.get("attempted"):
        _deny("export_telemetry_mismatch")
    contexts = state.get("origin_contexts") or {}
    origins = []
    limits = runtime.get("http_origin_max_requests") or {}
    for index, origin in enumerate(approved):
        entry = contexts.get(origin) or {}
        context = entry.get("context") or {}
        v1 = content["approved_origins"][index]
        endpoints = _endpoints(origin, entry, context)
        mine = [r for r in rows if r["origin"] == origin]
        classes = Counter((e["soft404"] or {}).get("classification") for e in endpoints if e["soft404"])
        params = [c for e in endpoints if e["parameters"] for c in e["parameters"]["candidates"]]
        urls = Counter(e["url"] for e in endpoints)
        origins.append({
            "origin": origin, "report_path": f"approved_origins[{index}]", "status": v1["status"],
            "v1_executed": v1["executed"], "v1_executed_scope": "some Agent invoked globally (Report v1 semantics)",
            "journal_reservations": len(mine),
            "agents": [{"agent": a, "status": v1["agents"][a]["status"], "reason": v1["agents"][a]["reason"]} for a in AGENTS],
            "accounting": _bucket(mine),
            "budget": {"limit": limits.get(origin), "reserved": len(mine),
                       "remaining": limits[origin] - len(mine) if type(limits.get(origin)) is int else None},
            "recon": deepcopy(v1["recon"]), "wordlist": deepcopy(v1["wordlist"]),
            "halts": {"parameters": (context.get("parameter_discovery") or {}).get("origin_halt"),
                      "soft404": (context.get("soft404") or {}).get("origin_halt")},
            "endpoint_index": {"endpoints": len(endpoints), "agent1_observations": sum(e["source"] == "agent1_observation" for e in endpoints),
                               "wordlist_only": sum(e["source"] == "agent2_wordlist_candidate" for e in endpoints),
                               "provenance_references": sum(e["provenance_count"] for e in endpoints),
                               "urls_with_multiple_methods": sum(1 for n in urls.values() if n > 1),
                               "with_query": sum(e["has_query"] for e in endpoints)},
            "parameter_summary": {"candidates": len(params), "selected": sum(bool(c["selected"]) for c in params),
                                  "verified": sum(c["verification"] == "verified" for c in params),
                                  "inconclusive": sum(c["verification"] == "inconclusive" for c in params),
                                  "not_checked": sum(c["verification"] == "not_checked" for c in params)},
            "soft404_summary": {k: classes.get(k, 0) for k in ("genuine_distinct", "soft_404", "http_404",
                                                                "inconclusive", "not_checked")},
            "outcome_unknown_sequences": list(v1["outcome_unknown_sequences"]),
            "endpoints": endpoints})
    discovered = []
    for index, row in enumerate(content["discovered_only_origins"]):
        if row.get("executed") is not False or any(r["origin"] == row.get("origin") for r in rows):
            _deny("export_unapproved_dispatch")
        discovered.append({"origin": row["origin"], "report_path": f"discovered_only_origins[{index}]", "approved": False,
                           "executed": False, "status": row.get("status"), "endpoints_observed": row.get("endpoints_observed"),
                           "source_references": row.get("source_references"), "journal_reservations": 0})
    lists = _accounting_lists(rows, approved)
    local = state.get("local_origin_execution") or {}
    stops = sorted({e["payload"].get("reason") for e in events if e["event"] == "stop"} - {None})
    bound = [e["payload"].get("reservations") for e in events if e["event"] == "process_bound"]
    envelope = {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "stage": "B5",
        "source": {"session_id": session.get("session_id"), "runtime_id": session.get("runtime_id"),
                   "journal": source["journal_rel"], "journal_events": len(events), "journal_head_hash": events[-1]["hash"],
                   "journal_sha256": source["hashes"]["journal.jsonl"], "head_sha256": source["hashes"]["head.json"],
                   "final_checkpoint": source["final"]["rel"], "final_checkpoint_sha256": source["final"]["sha256"],
                   "report_checkpoint": source["report_checkpoint"]["rel"],
                   "report_checkpoint_sha256": source["report_checkpoint"]["sha256"],
                   "checkpoints_verified": len(source["checkpoints"]), "report_digest": report["digest"],
                   "report_digest_rule": report.get("digest_rule"), "report_schema_version": report["schema_version"],
                   "report_stage": report.get("stage")},
        "session": {"pipeline_status": state.get("pipeline_status"), "stop_reason": state.get("stop_reason"),
                    "runtime_stop_reason": runtime.get("stop_reason"), "global_stop_reason": content["stop"]["global_stop_reason"],
                    "contract_failures": deepcopy(content["stop"]["contract_failures"]),
                    "journal_stop_events": stops, "mode": local.get("mode"), "graph_integration": local.get("graph_integration"),
                    "finalize_only": bool(recovery.get("finalize_only")), "resumed": bool(recovery.get("resumed")),
                    "all_modules_executed": state.get("all_modules_executed"),
                    "all_modules_successful": state.get("all_modules_successful"),
                    "gate": deepcopy(content["gate"]),
                    "decisions": [{"decision_point": d.get("decision_point"), "action": d.get("action"), "reason": d.get("reason"),
                                   "source": d.get("source"), "llm_called": d.get("llm_called")}
                                  for d in state.get("decision_chain") or []],
                    "errors": [{"agent": e.get("agent"), "error_type": e.get("error_type") or e.get("type")}
                               for e in state.get("error_log") or [] if isinstance(e, dict)]},
        "scope": {"approved_origins": list(approved), "discovered_only_origins": [d["origin"] for d in discovered],
                  "origin_policies": deepcopy(state.get("origin_policies"))},
        "agents": [{"agent": a, "status": content["agents"][a]["status"], "invoked": content["agents"][a]["invoked"],
                    "reason": content["agents"][a]["reason"], "report_path": f"agents.{a}"} for a in AGENTS],
        "origins": origins, "discovered_only_origins": discovered,
        "accounting": {"source": "recovery journal events; Recon included", "meaning": ACCOUNTING_MEANING, **lists,
                       "runtime": {"http_dispatches": runtime.get("http_dispatches"), "http_max_requests": runtime.get("http_max_requests"),
                                   "stop_reason": runtime.get("stop_reason")},
                       "telemetry_http": {"total_requests": http.get("total_requests"), "known_requests": http.get("known_requests"),
                                          "count_complete": complete, "count_scope": http.get("count_scope"),
                                          "by_phase": [{"phase": p, "target": (v or {}).get("target")}
                                                       for p, v in sorted((http.get("by_phase") or {}).items())],
                                          "unknown_sources": deepcopy(http.get("unknown_sources") or []),
                                          "process_scope": "final process; restored from journal dispatch starts on resume"},
                       "recovery_accounting": deepcopy(summary),
                       "legacy_report_totals": {**deepcopy(content["totals"]),
                                                "scope": "Report v1 verbatim: *_requests count Agent section rows (journal reservations, "
                                                         "including outcome_unknown) and exclude Recon; not reconciled HTTP"}},
        "budget": {"global": {"limit": runtime.get("http_max_requests"), "reserved": len(rows),
                              "remaining": runtime["http_max_requests"] - len(rows) if type(runtime.get("http_max_requests")) is int else None},
                   "by_origin": [{"origin": o, "limit": limits.get(o), "reserved": sum(r["origin"] == o for r in rows)} for o in approved],
                   "phase_caps": {"parameter_max_requests": authority.get("parameter_max_requests"),
                                  "soft404_max_requests": authority.get("soft404_max_requests")},
                   "http_rate_limit": config.get("http_rate_limit"), "http_timeout_seconds": config.get("http_timeout_seconds"),
                   "pipeline_timeout_seconds": config.get("pipeline_timeout_seconds")},
        "llm": {"attempted": llm.get("attempted"), "succeeded": llm.get("succeeded"), "failed": llm.get("failed"),
                "in_flight": llm.get("in_flight"), "quota_rejections": llm.get("quota_rejections"), "max_calls": llm.get("max_calls"),
                "llm_call_count": state.get("llm_call_count"),
                "decisions_with_llm": sum(bool(d.get("llm_called")) for d in state.get("decision_chain") or []),
                "reflection_llm_called": (state.get("local_reflection") or {}).get("llm_called"),
                "count_scope": llm.get("count_scope")},
        "reflection": {"status": state["local_reflection"].get("status"), "mode": state["local_reflection"].get("mode"),
                       "knowledge_writes": state["local_reflection"].get("knowledge_writes"),
                       "observations": len(state["local_reflection"].get("observations") or []),
                       "report_digest_bound": state["local_reflection"].get("report_digest") == report["digest"]},
        "recovery": {"resumed": bool(recovery.get("resumed")), "status": recovery.get("status"),
                     "finalize_only": bool(recovery.get("finalize_only")), "finalize_basis": deepcopy(recovery.get("finalize_basis")),
                     "processes_bound": len(bound), "process_bound_reservations": bound,
                     "reconciled_events": sum(e["event"] == "reconciled" for e in events),
                     "reused_nodes": deepcopy(recovery.get("reused_nodes") or []),
                     "dispatch_outcome_unknown_sequences": deepcopy(recovery.get("outcome_unknown_sequences") or []),
                     "parameter_outcome_unknown_sequences": deepcopy(recovery.get("parameter_outcome_unknown_sequences") or []),
                     "soft404_outcome_unknown_sequences": deepcopy(recovery.get("soft404_outcome_unknown_sequences") or []),
                     "replay_policy": recovery.get("replay_policy"), "exactly_once_delivery": False},
        "report_v1": {"schema_version": report["schema_version"], "stage": report.get("stage"),
                      "digest": report["digest"], "digest_rule": report.get("digest_rule"), "content": deepcopy(content)},
        "evidence_vocabulary": VOCABULARY, "severity": None, "severity_basis": "not_assessed_b5",
        "not_concluded": NOT_CONCLUDED, "limits": LIMITS,
    }
    envelope["export_digest"] = canonical_digest(envelope)
    return envelope


# ── Markdown (rendered only from the envelope) ──

_PROSE = re.compile(r"([\\`*_{}\[\]<>()#+\-.!|~&])")


def md_text(value):
    """Static prose/labels: every Markdown/HTML metacharacter is backslash-escaped."""
    return _PROSE.sub(r"\\\1", str(value).replace("\r", " ").replace("\n", " "))


def md_code(text):
    """Untrusted data as an inline code span: no HTML, no links; `|` escaped for GFM tables."""
    text = str(text).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    run = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (run + 1)
    pad = " " if text.startswith(("`", " ")) or text.endswith(("`", " ")) or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_cell(value):
    if value is None:
        return _UNKNOWN
    if value is True or value is False:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        return json.dumps(value)
    if isinstance(value, str):
        return md_code(value)
    return md_code(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def _lookup(envelope, path):
    """Absent through a null parent renders as —; a missing key is a programming error."""
    value = envelope
    for part in path.replace("]", "").split("."):
        name, *indexes = part.split("[")
        if value is None:
            return _ABSENT
        if name:
            value = value[name]
        for index in indexes:
            if value is None:
                return _ABSENT
            value = value[int(index)]
    return value


def _cell(envelope, path):
    value = _lookup(envelope, path)
    return _ABSENT if value is _ABSENT else md_cell(value)


def _kv(envelope, rows):
    lines = ["| Trường | Giá trị | Nguồn |", "|---|---|---|"]
    for label, path in rows:
        lines.append(f"| {md_text(label)} | {_cell(envelope, path)} | {md_code(path)} |")
    return lines


def _table(envelope, prefix_paths, keys):
    lines = ["| JSON path | " + " | ".join(md_code(k) for k in keys) + " |", "|" + "---|" * (len(keys) + 1)]
    for path in prefix_paths:
        lines.append(f"| {md_code(path)} | " + " | ".join(_cell(envelope, f"{path}.{k}") for k in keys) + " |")
    return lines


def render_markdown(envelope):
    e, out = envelope, []
    add = out.extend
    out.append("# " + md_text("Báo cáo Multi-Origin — B5 export"))
    out.append("")
    out.append(md_text("Sinh hoàn toàn từ report.json (envelope). Không HTTP, không LLM, không KnowledgeStore. "
                       "Không đánh giá mức độ nghiêm trọng. Endpoint luôn not_verified. "
                       "Giá trị null hiển thị là “không xác định”; — nghĩa là không áp dụng."))
    sections = [
        ("1. Nguồn và toàn vẹn", _kv(e, [(k, f"source.{k}") for k in (
            "session_id", "journal", "journal_events", "journal_head_hash", "final_checkpoint", "final_checkpoint_sha256",
            "report_checkpoint", "checkpoints_verified", "report_digest", "report_schema_version")] + [("export_digest", "export_digest")])),
        ("2. Phiên thực thi", _kv(e, [(k, f"session.{k}") for k in (
            "pipeline_status", "stop_reason", "runtime_stop_reason", "global_stop_reason", "contract_failures", "journal_stop_events",
            "mode", "graph_integration", "finalize_only", "resumed", "all_modules_executed", "all_modules_successful", "gate")]
            + [("severity", "severity"), ("severity_basis", "severity_basis")])),
        ("3. Quyết định", _table(e, [f"session.decisions[{i}]" for i in range(len(e["session"]["decisions"]))],
                                ("decision_point", "action", "reason", "source", "llm_called"))),
        ("4. Phạm vi: origin đã phê duyệt", _table(e, [f"origins[{i}]" for i in range(len(e["origins"]))],
                                                  ("origin", "status", "v1_executed", "journal_reservations", "outcome_unknown_sequences"))),
        ("5. Origin chỉ được phát hiện (không thực thi)", _table(e, [f"discovered_only_origins[{i}]" for i in range(len(e["discovered_only_origins"]))],
                                                               ("origin", "approved", "executed", "status", "endpoints_observed", "journal_reservations"))),
        ("6. Agent (toàn cục)", _table(e, [f"agents[{i}]" for i in range(len(e["agents"]))], ("agent", "status", "invoked", "reason"))),
        ("7. Accounting HTTP từ journal (gồm Recon)", _table(e, ["accounting.total"], KEYS)
            + [""] + _table(e, [f"accounting.by_phase[{i}]" for i in range(len(e["accounting"]["by_phase"]))], ("phase", "kind") + KEYS)
            + [""] + _table(e, [f"accounting.by_origin[{i}]" for i in range(len(e["accounting"]["by_origin"]))], ("origin",) + KEYS)
            + [""] + _kv(e, [("attempt_unknown sequences", "accounting.unknown_sequences.attempt_unknown"),
                             ("outcome_unknown sequences", "accounting.unknown_sequences.outcome_unknown"),
                             ("runtime http_dispatches", "accounting.runtime.http_dispatches"),
                             ("telemetry total_requests", "accounting.telemetry_http.total_requests"),
                             ("telemetry known_requests", "accounting.telemetry_http.known_requests"),
                             ("telemetry count_complete", "accounting.telemetry_http.count_complete"),
                             ("server arrivals", "accounting.meaning.server_arrivals")])
            + [""] + _kv(e, [(f"Report v1 totals: {k}", f"accounting.legacy_report_totals.{k}")
                             for k in sorted(e["accounting"]["legacy_report_totals"])])),
        ("8. Budget", _kv(e, [("global limit", "budget.global.limit"), ("global reserved", "budget.global.reserved"),
                              ("global remaining", "budget.global.remaining"),
                              ("parameter_max_requests", "budget.phase_caps.parameter_max_requests"),
                              ("soft404_max_requests", "budget.phase_caps.soft404_max_requests"),
                              ("http_rate_limit", "budget.http_rate_limit"), ("http_timeout_seconds", "budget.http_timeout_seconds"),
                              ("pipeline_timeout_seconds", "budget.pipeline_timeout_seconds")])
            + [""] + _table(e, [f"budget.by_origin[{i}]" for i in range(len(e["budget"]["by_origin"]))], ("origin", "limit", "reserved"))),
        ("9. LLM và Reflection", _kv(e, [(k, f"llm.{k}") for k in ("attempted", "succeeded", "failed", "max_calls", "llm_call_count",
                                                                    "decisions_with_llm", "reflection_llm_called")]
            + [(f"reflection {k}", f"reflection.{k}") for k in ("status", "knowledge_writes", "observations", "report_digest_bound")])),
        ("10. Recovery", _kv(e, [(k, f"recovery.{k}") for k in (
            "resumed", "status", "finalize_only", "finalize_basis", "processes_bound", "process_bound_reservations", "reconciled_events",
            "reused_nodes", "dispatch_outcome_unknown_sequences", "parameter_outcome_unknown_sequences",
            "soft404_outcome_unknown_sequences", "replay_policy", "exactly_once_delivery")])),
        ("11. Lỗi", _table(e, [f"session.errors[{i}]" for i in range(len(e["session"]["errors"]))], ("agent", "error_type"))),
    ]
    for title, lines in sections:
        add(["", "## " + md_text(title), ""] + lines)
    for i, origin in enumerate(e["origins"]):
        base = f"origins[{i}]"
        add(["", "## " + md_text(f"Origin {i + 1}") + " " + md_code(origin["origin"]), ""])
        add(_table(e, [f"{base}.agents[{j}]" for j in range(len(origin["agents"]))], ("agent", "status", "reason")))
        add([""] + _kv(e, [(f"accounting {k}", f"{base}.accounting.{k}") for k in KEYS]
                       + [(f"budget {k}", f"{base}.budget.{k}") for k in ("limit", "reserved", "remaining")]
                       + [("recon endpoints_observed", f"{base}.recon.endpoints_observed"),
                          ("wordlist candidates", f"{base}.wordlist.candidates"), ("wordlist selected", f"{base}.wordlist.selected"),
                          ("parameter halt", f"{base}.halts.parameters"), ("soft404 halt", f"{base}.halts.soft404")]
                       + [(f"endpoint_index {k}", f"{base}.endpoint_index.{k}") for k in sorted(origin["endpoint_index"])]
                       + [(f"parameters {k}", f"{base}.parameter_summary.{k}") for k in sorted(origin["parameter_summary"])]
                       + [(f"soft404 {k}", f"{base}.soft404_summary.{k}") for k in sorted(origin["soft404_summary"])]))
        endpoints = [f"{base}.endpoints[{j}]" for j in range(len(origin["endpoints"]))]
        add(["", "### " + md_text("Endpoint observations"), ""] + _table(e, endpoints, (
            "endpoint_id", "method", "url", "source", "provenance_count", "observation_classes",
            "dispatch.runtime_sequence", "dispatch.status_code", "dispatch.evidence", "dispatch.recovery_state",
            "endpoint_verification_status")))
        candidates = [f"{base}.endpoints[{j}].parameters.candidates[{k}]" for j, row in enumerate(origin["endpoints"])
                      if row["parameters"] for k in range(len(row["parameters"]["candidates"]))]
        add(["", "### " + md_text("Parameter candidates (context_only)"), ""] + _table(e, candidates, (
            "endpoint_id", "name", "selected", "verification", "verification_reason", "provenance_classes", "authority")))
        soft = [f"{base}.endpoints[{j}].soft404" for j, row in enumerate(origin["endpoints"]) if row["soft404"]]
        add(["", "### " + md_text("Soft404 classifications (không phải lỗ hổng)"), ""] + _table(e, soft, (
            "endpoint_id", "classification", "classification_reason", "evidence_basis", "evidence_level_v1", "unit_state",
            "candidate_sequence", "control_sequences", "parameter_context.verified_parameters", "verification_status")))
    vocab = [(f"{group}.{key}", f"evidence_vocabulary.{group}.{key}") for group, values in sorted(e["evidence_vocabulary"].items())
             if isinstance(values, dict) for key in sorted(values)]
    add(["", "## " + md_text("Mức bằng chứng"), ""] + _kv(e, vocab + [("endpoint_verification", "evidence_vocabulary.endpoint_verification"),
                                                               ("severity", "evidence_vocabulary.severity")]))
    add(["", "## " + md_text("Không kết luận và giới hạn"), ""] + _kv(
        e, [(f"not_concluded {i + 1}", f"not_concluded[{i}]") for i in range(len(e["not_concluded"]))]
        + [(f"limit {i + 1}", f"limits[{i}]") for i in range(len(e["limits"]))]))
    return "\n".join(out) + "\n"


# ── public-content guard and atomic publication ──

def check_public(envelope, markdown, root):
    # The guard runs on the envelope (all data). Markdown is a pure function of the envelope plus static
    # labels and JSON paths; long dotted paths match the redactor's JWT pattern (a false positive of the
    # same family as R8), so Markdown is checked for absolute paths only.
    if sanitize_for_log(envelope) != envelope:
        _deny("export_sensitive_content")
    text = json.dumps(envelope, ensure_ascii=False) + markdown
    if any(p and p in text for p in (str(root), root.as_posix(), str(Path.home()))) \
            or re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", text):
        _deny("export_absolute_path")


def _write_bytes(path, data):
    with open(path, "xb") as stream:  # never overwrite
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _publish(output, files, verify_unchanged):
    parent = output.parent
    if output.exists():
        _deny("export_output_exists")
    if not parent.is_dir():
        _deny("export_output_parent_missing")
    pending = parent / f".pending_export_{uuid4().hex}"
    try:
        pending.mkdir()
    except OSError:
        _deny("export_write_failed")
    try:
        for name, data in files:
            _write_bytes(pending / name, data)
        verify_unchanged()
        os.rename(pending, output)  # one atomic publication; fails if the target appeared
    except ExportError:
        shutil.rmtree(pending, ignore_errors=True)
        raise
    except OSError:
        shutil.rmtree(pending, ignore_errors=True)
        _deny("export_output_exists" if output.exists() else "export_write_failed")
    except BaseException:
        shutil.rmtree(pending, ignore_errors=True)
        raise


def _dumps(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def export_session(recovery_directory, output_directory, *, generated_at=None):
    """Verify a finished session, build the envelope and publish report.json/report.md/manifest.json."""
    directory = Path(recovery_directory).resolve()
    root = directory.parent
    output = Path(output_directory).resolve()
    if output.is_relative_to(directory):
        _deny("export_output_inside_session_state")
    journal = _open(directory)
    try:
        events = journal.events
        try:
            source = load_verified(directory, root, events)
        except ExportError:
            raise
        except (KeyError, TypeError, AttributeError, IndexError, ValueError):
            _deny("export_source_malformed")  # never a traceback with source content
        if any(output.is_relative_to(row["path"].parent.parent) for row in source["checkpoints"]):
            _deny("export_output_inside_session_state")
        before = _source_hashes(directory, source["checkpoints"])
        source.update(events=events, hashes=before, journal_rel=(directory / "journal.jsonl").relative_to(root).as_posix())
        try:
            envelope = build_envelope(source)
        except ExportError:
            raise
        except (KeyError, TypeError, AttributeError, IndexError, ValueError):
            _deny("export_source_malformed")
        markdown = render_markdown(envelope)
        check_public(envelope, markdown, root)
        stamp = generated_at or datetime.now(timezone.utc).isoformat()
        written = {**envelope, "export_meta": {"generated_at_utc": stamp,
                                               "nondeterministic_fields": ["export_meta.generated_at_utc"]}}
        report_json, report_md = _dumps(written), markdown.encode("utf-8")
        manifest = {"schema": SCHEMA + "_manifest", "schema_version": 1, "complete": True,
                    "export_digest": envelope["export_digest"], "report_digest": envelope["source"]["report_digest"],
                    "session_id": envelope["source"]["session_id"],
                    "files": {"report.json": sha256(report_json).hexdigest(), "report.md": sha256(report_md).hexdigest()}}

        def unchanged():
            if _source_hashes(directory, source["checkpoints"]) != before:
                _deny("export_source_changed")
        _publish(output, [("report.json", report_json), ("report.md", report_md), ("manifest.json", _dumps(manifest))],
                 unchanged)
        return {"output": str(output), "export_digest": envelope["export_digest"], "report_digest": envelope["source"]["report_digest"],
                "pipeline_status": envelope["session"]["pipeline_status"], "source_sha256": before}
    finally:
        journal.__exit__(None, None, None)
