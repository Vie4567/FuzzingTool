"""B4.2C deterministic local Report and Reflection over per-origin Agent evidence.

Pure functions: no HTTP, no LLM, no KnowledgeStore, no artifact or journal writes.
One section per approved origin keeps each Agent's own status, evidence level and
provenance references (endpoint IDs, runtime sequences, evidence refs). Discovered-only
origins are listed apart and are never counted as executed. Totals are sums of the
per-origin sections. The digest covers `content` only: canonical JSON without
timestamps, durations, artifact paths, PIDs or recovery bookkeeping.

Not done here (B5): rendering, severity, cross-origin de-duplication, exports,
knowledge persistence; the production multi-origin gate stays closed.
"""
from copy import deepcopy
from hashlib import sha256
import json

AGENTS = ("tech_recon", "wordlist_gen", "fuzzing", "param_disc", "soft404_filter")
_SECTION = {"fuzzing": "http_dispatch", "param_disc": "parameter_discovery", "soft404_filter": "soft404"}
_STRONG = {"genuine_distinct", "soft_404", "http_404"}
DIGEST_RULE = "sha256(json.dumps(content, sort_keys=True, separators=(',', ':'), ensure_ascii=False))"


def canonical_digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode()).hexdigest()


def _section(entry, agent):
    return ((entry or {}).get("context") or {}).get(_SECTION[agent])


def _unknown(entry):
    rows = (_section(entry, "fuzzing") or {}).get("records", [])
    seqs = [r.get("runtime_sequence") for r in rows if r.get("recovery_state") == "outcome_unknown"]
    for agent in ("param_disc", "soft404_filter"):
        seqs += [r.get("runtime_sequence") for r in (_section(entry, agent) or {}).get("requests", [])
                 if r.get("recovery_state") == "outcome_unknown"]
    return sorted(s for s in seqs if type(s) is int)


def origin_agent_status(entry, agent, absent):
    """Status of one Agent at one approved origin, from its own section only.

    `absent` is the (status, reason) to use when the Agent left no section there.
    """
    if agent in ("tech_recon", "wordlist_gen"):
        value = ((entry or {}).get("agent_statuses") or {}).get(agent)
        if value in ("success", "partial", "failed", "skipped", "interrupted"):
            return value, None
        return absent
    section = _section(entry, agent)
    if section is None:
        return absent
    status = section.get("status")
    if agent == "fuzzing":
        rows = section.get("records", [])
        if status == "running" or any(r.get("stop_reason") in ("pending", "upstream_dispatch_interrupted",
                                                                   "dispatch_interrupted") for r in rows):
            return "interrupted", section.get("stop_reason")
        if any(r.get("recovery_state") == "outcome_unknown" for r in rows):
            return "partial", "outcome_unknown"
    else:
        if any(e.get("unit_state") == "interrupted" for e in section.get("endpoints", [])):
            return "interrupted", "unit_interrupted"
        if status in ("pending", "running", "interrupted"):
            return "interrupted", section.get("stop_reason")
        if status == "not_started":
            return "not_started", section.get("stop_reason")
    mapped = {"completed": "success", "partial": "partial", "failed": "failed", "skipped": "skipped"}.get(status)
    return (mapped or "failed"), (None if mapped == "success" else section.get("stop_reason"))


def origin_status(agents, unknown):
    values = [s for s, _ in agents.values()]
    if "failed" in values:
        return "failed"
    if "interrupted" in values:
        return "interrupted"
    if all(v == "success" for v in values):
        return "partial" if unknown else "completed"
    if all(v in ("skipped", "not_started") for v in values):
        return "skipped"
    return "partial"


def global_agent_status(values, invoked, absent):
    if not invoked:
        return absent[0]
    if "interrupted" in values:
        return "interrupted"
    if values and all(v == "success" for v in values):
        return "success"
    if values and all(v in ("success", "skipped") for v in values) and "success" in values:
        return "success"
    if values and all(v == "skipped" for v in values):
        return "skipped"
    if values and all(v in ("failed", "not_started") for v in values) and "failed" in values:
        return "failed"
    if values and all(v == "not_started" for v in values):
        return "not_started"
    return "partial"


def _dispatch(section):
    if section is None:
        return None
    return {"status": section.get("status"), "stop_reason": section.get("stop_reason"),
            "counts": deepcopy(section.get("counts")),
            "records": [{k: deepcopy(r.get(k)) for k in (
                "candidate_id", "url", "runtime_sequence", "attempted", "status_code", "classification",
                "verification_status", "stop_reason", "recovery_state", "evidence_refs")}
                for r in section.get("records", [])]}


def _parameters(section):
    if section is None:
        return None
    return {"status": section.get("status"), "stop_reason": section.get("stop_reason"),
            "origin_halt": section.get("origin_halt"), "counts": deepcopy(section.get("counts")),
            "endpoints": [{"endpoint_id": e.get("endpoint_id"), "url": e.get("url"), "eligible": e.get("eligible"),
                           "exclusion_reason": e.get("exclusion_reason"), "unit_id": e.get("unit_id"),
                           "unit_state": e.get("unit_state"),
                           "source_runtime_sequence": (e.get("source_dispatch") or {}).get("runtime_sequence"),
                           "evidence_refs": deepcopy((e.get("source_dispatch") or {}).get("evidence_refs")),
                           "endpoint_verification_status": "not_verified",
                           "candidates": [{k: deepcopy(c.get(k)) for k in (
                               "name", "selected", "verification", "verification_reason", "verification_performed")}
                               for c in e.get("candidates", [])]}
                          for e in section.get("endpoints", [])]}


def _soft404(section):
    if section is None:
        return None
    return {"status": section.get("status"), "stop_reason": section.get("stop_reason"),
            "origin_halt": section.get("origin_halt"), "counts": deepcopy(section.get("counts")),
            "classification_meaning": section.get("classification_meaning"),
            "endpoints": [{"endpoint_id": e.get("endpoint_id"), "url": e.get("url"), "eligible": e.get("eligible"),
                           "exclusion_reason": e.get("exclusion_reason"), "group_id": e.get("group_id"),
                           "unit_id": e.get("unit_id"), "unit_state": e.get("unit_state"),
                           "soft404_classification": e.get("soft404_classification"),
                           "classification_reason": e.get("classification_reason"),
                           "evidence_level": e.get("evidence_level"),
                           "verification_status": e.get("verification_status"),
                           "parameter_context": deepcopy(e.get("parameter_context")),
                           "source_runtime_sequence": (e.get("source_dispatch") or {}).get("runtime_sequence"),
                           "evidence_refs": deepcopy((e.get("source_dispatch") or {}).get("evidence_refs")),
                           "candidate_sequence": (e.get("verification_evidence") or {}).get("candidate_sequence"),
                           "control_sequences": deepcopy((e.get("verification_evidence") or {}).get("control_sequences"))}
                          for e in section.get("endpoints", [])]}


def build_report(state, *, absent, invoked, global_stop, contract_failures, fixed=None):
    """Deterministic per-origin report. `absent[agent]` / `invoked[agent]` come from the Coordinator.

    `fixed` carries global statuses of single-call Agents (Recon, Wordlist) as the graph recorded them.
    """
    fixed = fixed or {}
    approved = list(state.get("approved_origins") or [])
    contexts = state.get("origin_contexts") or {}
    origins, per_agent = [], {a: [] for a in AGENTS}
    totals = {"dispatch_attempted": 0, "dispatch_responses": 0, "outcome_unknown": 0, "parameter_requests": 0,
              "verified_parameters": 0, "soft404_requests": 0, "soft404_strong": 0, "interrupted_units": 0,
              **{"soft404_" + k: 0 for k in ("genuine_distinct", "soft_404", "http_404", "inconclusive", "not_checked")}}
    for origin in approved:
        entry = contexts.get(origin) or {}
        agents = {}
        for agent in AGENTS:
            if agent in contract_failures:
                agents[agent] = ("failed", contract_failures[agent])
            else:
                agents[agent] = origin_agent_status(entry, agent, absent[agent])
            per_agent[agent].append(agents[agent][0])
        unknown = _unknown(entry)
        dispatch, params, soft = (_dispatch(_section(entry, "fuzzing")), _parameters(_section(entry, "param_disc")),
                                  _soft404(_section(entry, "soft404_filter")))
        counts = (dispatch or {}).get("counts") or {}
        totals["dispatch_attempted"] += counts.get("attempted", 0)
        totals["dispatch_responses"] += counts.get("responses", 0)
        totals["outcome_unknown"] += len(unknown)
        totals["parameter_requests"] += ((params or {}).get("counts") or {}).get("http_requests", 0)
        totals["verified_parameters"] += ((params or {}).get("counts") or {}).get("verified", 0)
        totals["soft404_requests"] += ((soft or {}).get("counts") or {}).get("http_requests", 0)
        for row in (soft or {}).get("endpoints", []):
            cls = row["soft404_classification"]
            if "soft404_" + str(cls) in totals:
                totals["soft404_" + cls] += 1
            totals["soft404_strong"] += cls in _STRONG
        totals["interrupted_units"] += sum(e.get("unit_state") == "interrupted"
                                           for s in (params, soft) for e in (s or {}).get("endpoints", []))
        recon = entry.get("context") or {}
        origins.append({
            "origin": origin, "approved": True, "executed": any(invoked[a] for a in AGENTS),
            "status": origin_status(agents, unknown),
            "agents": {a: {"status": s, "reason": r} for a, (s, r) in agents.items()},
            "skipped_agents": sorted(a for a, (s, _) in agents.items() if s == "skipped"),
            "recon": {"endpoints_observed": len(entry.get("endpoints") or []),
                      "source_documents": [{"url": d.get("url"), "collection_status": d.get("collection_status")}
                                           for d in recon.get("source_documents", [])]},
            "wordlist": {"candidates": len(((recon.get("wordlist") or {}).get("candidates")) or []),
                         "selected": len(((recon.get("wordlist") or {}).get("selected_ids")) or [])},
            "dispatch": dispatch, "parameters": params, "soft404": soft, "outcome_unknown_sequences": unknown})
    discovered = sorted((set(contexts) | {d.get("origin") for d in state.get("discovered_origins") or []
                                          if isinstance(d, dict)}) - set(approved) - {None})
    discovered_only = []
    for origin in discovered:
        entry = contexts.get(origin) or {}
        rows = (_section(entry, "fuzzing") or {}).get("records", [])
        sources = next((d.get("sources", []) for d in state.get("discovered_origins") or []
                        if isinstance(d, dict) and d.get("origin") == origin), [])
        discovered_only.append({"origin": origin, "approved": False, "executed": False, "status": "not_applicable",
                                "endpoints_observed": len(entry.get("endpoints") or []),
                                "source_references": len(sources),
                                "dispatch_attempts": sum(r.get("attempted") is True for r in rows)})
    agents = {}
    for agent in AGENTS:
        if agent in contract_failures:
            agents[agent] = {"status": "failed", "invoked": invoked[agent], "reason": contract_failures[agent]}
        elif agent in fixed and invoked[agent]:
            agents[agent] = {"status": fixed[agent], "invoked": True, "reason": None}
        else:
            agents[agent] = {"status": global_agent_status(per_agent[agent], invoked[agent], absent[agent]),
                             "invoked": invoked[agent], "reason": None if invoked[agent] else absent[agent][1]}
    content = {"schema_version": 1, "stage": "B4.2C", "approved_origins": origins,
               "discovered_only_origins": discovered_only, "agents": agents, "totals": totals,
               "stop": {"global_stop_reason": global_stop, "contract_failures": dict(sorted(contract_failures.items()))},
               "gate": {"origin_execution_mode": state.get("origin_execution_mode"),
                        "full_multi_origin_execution_enabled": False},
               "semantics": {"endpoint_verification": "not_verified; HTTP observation and Soft404 class are not business validity",
                             "parameter_authority": "context_only; a verified parameter never verifies an endpoint",
                             "evidence_levels": ["observed", "inferred", "rederived", "metrics_journaled", "interrupted"]}}
    return {"schema_version": 1, "stage": "B4.2C", "content": content, "digest": canonical_digest(content),
            "digest_rule": DIGEST_RULE}


def resolve(content, path):
    """Resolve 'a.b[0].c' in report content; KeyError/IndexError when absent."""
    value = content
    for part in path.replace("]", "").split("."):
        name, *indexes = part.split("[")
        if name:
            value = value[name]
        for index in indexes:
            value = value[int(index)]
    return value


def build_reflection(report):
    """Observations only where a report path backs the value; no lessons, no knowledge writes."""
    content, rows = report["content"], []

    def observe(kind, path):
        rows.append({"id": f"obs-{len(rows) + 1:03d}", "kind": kind, "report_path": path,
                     "value": deepcopy(resolve(content, path)), "evidence": "multi_origin_report.content"})

    for index, origin in enumerate(content["approved_origins"]):
        observe("approved_origin_status", f"approved_origins[{index}].status")
        if origin["outcome_unknown_sequences"]:
            observe("outcome_unknown_sequences", f"approved_origins[{index}].outcome_unknown_sequences")
    for index, _ in enumerate(content["discovered_only_origins"]):
        observe("discovered_only_not_executed", f"discovered_only_origins[{index}].executed")
    for agent in AGENTS:
        observe("agent_status", f"agents.{agent}.status")
    for key in ("outcome_unknown", "interrupted_units", "verified_parameters", "soft404_strong"):
        observe("total", f"totals.{key}")
    if content["stop"]["global_stop_reason"]:
        observe("global_stop", "stop.global_stop_reason")
    for agent in content["stop"]["contract_failures"]:
        observe("contract_failure", f"stop.contract_failures.{agent}")
    return {"schema_version": 1, "stage": "B4.2C", "mode": "deterministic_local_no_knowledge_write",
            "status": "completed", "llm_called": False, "knowledge_writes": 0, "lessons": [],
            "report_digest": report["digest"], "observations": rows}
