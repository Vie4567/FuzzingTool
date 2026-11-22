"""B2.2 offline candidate generation/selection over the B1/B2.1 contract.

No HTTP client or LLM is called here. Eligibility is a scope snapshot, never
dispatch permission: B3 must recheck runtime, credentials, policy and budgets.
"""
from copy import deepcopy
from datetime import datetime, timezone
import re
from urllib.parse import urlsplit

from src.coordinator.artifacts import RunArtifacts
from src.coordinator.llm_logging import sanitize_for_log
from src.coordinator.origins import canonical_origin, endpoint_observation, add_observation, public_url
from src.tools.origin_scope import OriginScopePolicy
from .endpoint_assembler import EndpointAssembler


_EVIDENCE = ("source", "source_type", "source_url", "source_sha256", "evidence_location",
             "evidence_refs", "classification", "confidence", "confidence_basis", "resource_type")
_TYPES = {"api_reference": 0, "frontend_route": 1, "unknown": 2, "static_asset": 3}


def _clean_endpoint(raw, origin):
    """Project only the public contract; claimed selected/verified flags are ignored."""
    url = public_url(raw["url"])
    if canonical_origin(url) != origin or raw.get("origin") != origin:
        raise ValueError("Endpoint origin mismatch")
    staging = {"origin_contexts": {}, "discovered_origins": []}
    sources = raw.get("provenance") or [{key: raw.get(key) for key in _EVIDENCE}]
    if not isinstance(sources, list) or len(sources) > 256:
        raise ValueError("Invalid provenance")
    for source in sources:
        data = {key: source.get(key) for key in _EVIDENCE}
        data["resource_type"] = data["resource_type"] or "unknown"
        row = endpoint_observation(url, method=raw.get("method"), **data)
        if row["endpoint_id"] != raw.get("endpoint_id"):
            raise ValueError("Endpoint identity mismatch")
        add_observation(staging, row)
    result = staging["origin_contexts"][origin]["endpoints"][0]
    if sanitize_for_log(result) != result:
        raise ValueError("Sensitive endpoint metadata")
    return result


def _public_context(context):
    """Consume B2.1 context without copying arbitrary body/snippet/value fields."""
    context = context or {}
    fields = {
        "parameters": ("name", "location", "url", "method", "source", "source_url", "classification", "evidence_refs"),
        "forms": ("action", "method", "params", "source", "source_url", "classification", "evidence_refs"),
        "source_documents": ("url", "origin", "kind", "method", "status_code", "source_sha256", "collection_status"),
        "unresolved_references": ("url", "origin", "method", "source", "source_type", "source_url", "source_sha256", "evidence_location", "evidence_refs", "reason"),
    }
    output, rejected = {}, 0
    for field, keys in fields.items():
        output[field] = []
        rows = context.get(field, [])
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError("Invalid discovery context size")
        for raw in rows:
            try:
                if not isinstance(raw, dict):
                    raise ValueError("Invalid context record")
                row = {key: deepcopy(raw[key]) for key in keys if key in raw}
                for key in ("url", "action", "source_url"):
                    if row.get(key) is not None:
                        public_url(row[key])
                if field == "unresolved_references" and (row.get("url") is not None or row.get("origin") is not None):
                    raise ValueError("Unresolved destination must stay null")
                if sanitize_for_log(raw) != raw or sanitize_for_log(row) != row:
                    raise ValueError("Sensitive context")
                if row not in output[field]:
                    output[field].append(row)
            except (ValueError, TypeError, KeyError):
                rejected += 1
    return output, rejected


def _support(row, context):
    sources = {p.get("source_url") for p in row["provenance"] if p.get("source_url")}
    direct = any(p.get("source_type") in {"javascript", "openapi"}
                 and p.get("source_sha256") and p.get("evidence_refs") and p.get("evidence_location")
                 for p in row["provenance"])
    parameters = [p for p in context["parameters"]
                  if p.get("url") == row["url"] and p.get("method") == row["method"]]
    forms = [f for f in context["forms"]
             if f.get("action") == row["url"] and f.get("method") == row["method"]]
    tier = 1 if direct and row["method"] is not None else 2
    return {"tier": tier, "reason": "direct_declaration" if tier == 1 else "observed_context",
            "independent_sources": len(sources), "parameter_support": len(parameters),
            "form_support": len(forms)}


def _eligibility(row, policy, approved):
    if row["origin"] not in approved:
        return False, "origin_not_approved"
    if row["method"] is None:
        return False, "method_unknown"
    if row["method"] not in {"GET", "HEAD"}:
        return False, "method_not_read_only"
    try:
        policy.check(row["url"], row["method"])
    except ValueError:
        return False, "exact_scope_denied"
    return True, "scope_method_path_allowed"


def selection_key(row):
    priority = row["priority"]
    return (priority["tier"], _TYPES[row["resource_type"]],
            -priority["independent_sources"], -priority["parameter_support"],
            -priority["form_support"], row["endpoint_id"])


def _tech(profile):
    stack = profile.get("tech_stack", {}) if isinstance(profile, dict) else {}
    return {key: value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9 ._+-]{1,80}", value)
            and sanitize_for_log(value) == value else "Unknown"
            for key, value in ((key, stack.get(key)) for key in ("frontend", "backend", "cms", "language"))}


def generate(state, *, profile_builder, max_wordlist_entries=6, max_generated_per_origin=32,
             allow_generic=False, artifact_root=None):
    """Deterministic Agent 2 entry point. Mutate only the additive wordlist context.

    Generated paths have no observed method and therefore remain review-only.
    Selection is strictly from dispatch_eligible records. No implicit GET, even
    if a policy allows GET for a guessed path. Generic generation is opt-in.
    """
    if state.get("origin_contract_version") != 1:
        raise ValueError("B2.2 requires the B1/B2.1 origin contract")
    for value, lower, upper in ((max_wordlist_entries, 1, 10000), (max_generated_per_origin, 0, 256)):
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError("Invalid candidate limit")
    if type(allow_generic) is not bool:
        raise ValueError("allow_generic must be boolean")
    target = public_url(state["target_url"])
    config = {"approved_origins": state["approved_origins"], "origin_policies": state.get("origin_policies", {})}
    policy = OriginScopePolicy(config)
    contexts = state.get("origin_contexts", {})
    if not isinstance(contexts, dict) or len(contexts) > 32:
        raise ValueError("Invalid origin context size")
    result = {"target_url": target, "origin_contexts": {}, "wordlist_metadata": {},
              "origin_execution_mode": state.get("origin_execution_mode"),
              "generation_mode": "deterministic_discovery", "execution_enabled": False,
              "created_at_utc": datetime.now(timezone.utc).isoformat()}
    all_candidates, rejected = [], 0
    # Recognize credentials supplied anywhere in the input, including reflected
    # values inside otherwise innocently named URLs. Reject, never use a masked URL.
    safe_contexts = sanitize_for_log(state).get("origin_contexts", {})
    for origin, entry in contexts.items():
        if canonical_origin(public_url(origin, origin_only=True)) != origin:
            raise ValueError("Noncanonical context origin")
        rows = entry.get("endpoints", [])
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError("Invalid endpoint context size")
        safe_entry = safe_contexts.get(origin, {})
        safe_context = safe_entry.get("context") or {}
        raw_context = entry.get("context") or {}
        filtered_context = {}
        for field in ("parameters", "forms", "source_documents", "unresolved_references"):
            original_rows, sanitized_rows = raw_context.get(field, []), safe_context.get(field, [])
            if not isinstance(original_rows, list) or not isinstance(sanitized_rows, list):
                raise ValueError("Invalid discovery context")
            filtered_context[field] = [raw for raw, safe in zip(original_rows, sanitized_rows) if raw == safe]
            rejected += len(original_rows) - len(filtered_context[field])
        context, invalid = _public_context(filtered_context)
        rejected += invalid
        staging = {"origin_contexts": {}, "discovered_origins": []}
        for index, raw in enumerate(rows):
            try:
                # Compare the public projection; ignore irrelevant headers/body fields.
                safe_raw = safe_entry.get("endpoints", [])[index]
                if any(raw.get(key) != safe_raw.get(key) for key in ("url", "origin", "method", "provenance") + _EVIDENCE):
                    raise ValueError("Sensitive observation")
                clean = _clean_endpoint(raw, origin)
                for source in clean["provenance"]:
                    add_observation(staging, {"url": clean["url"], "method": clean["method"], **source})
            except (ValueError, TypeError, KeyError, IndexError, AttributeError):
                rejected += 1
        candidates = staging.get("origin_contexts", {}).get(origin, {}).get("endpoints", [])
        for row in candidates:
            observed = any(p.get("source_url") and p.get("source_sha256") and p.get("evidence_refs")
                           and p.get("evidence_location") for p in row["provenance"])
            row.update(observed=bool(observed), generated=False, selected=False,
                       attempted=None, verified=None, verification_status="not_verified",
                       priority=_support(row, context), derivation=None)
        stack = _tech(entry.get("profile"))
        # Only literal read-only API declarations supply semantic assembler input.
        # Never let an asset, POST operation or unresolved expression become an API seed.
        seeds = [row for row in candidates if row["observed"] and row["method"] in {"GET", "HEAD"}
                 and row["resource_type"] == "api_reference"
                 and re.fullmatch(r"/[A-Za-z0-9/_-]*", urlsplit(row["url"]).path)]
        seed_paths = [urlsplit(row["url"]).path for row in seeds]
        generated_paths = []
        if max_generated_per_origin and (seeds or allow_generic):
            profile = profile_builder(stack, seed_paths)
            generated_paths = EndpointAssembler().assemble(profile, observed_urls=seed_paths,
                max_endpoints=max_generated_per_origin, llm=None)["endpoints"]
        observed_urls = {row["url"] for row in candidates}
        for path in generated_paths:
            if not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9/_-]*", path) or "//" in path:
                continue
            url = origin + path
            if url in observed_urls:
                continue
            # Grounding is a naming relationship, never evidence of this new URL.
            supporting = [row for row in seeds if _grounded(path, urlsplit(row["url"]).path)]
            if not supporting and not allow_generic:
                continue
            row = endpoint_observation(url, method=None, source="endpoint_assembler",
                classification="inferred", resource_type="api_reference" if supporting else "unknown")
            row.update(observed=False, generated=True, selected=False, attempted=None, verified=None,
                provenance=[], priority={"tier": 3 if supporting else 4,
                    "reason": "grounded_pattern" if supporting else "generic_pattern",
                    "independent_sources": 0, "parameter_support": 0, "form_support": 0},
                derivation={"generator": "EndpointAssembler", "supporting_endpoint_ids": [r["endpoint_id"] for r in supporting],
                            "supporting_evidence_refs": sorted({ref for r in supporting for ref in r["evidence_refs"]})})
            candidates.append(row)
            observed_urls.add(url)
        for row in candidates:
            row["dispatch_eligible"], row["eligibility_reason"] = _eligibility(row, policy, state["approved_origins"])
            row["selection_reason"] = "selection_limit" if row["dispatch_eligible"] else row["eligibility_reason"]
            if not row["observed"] and not row["generated"]:
                row["selection_reason"] = "missing_source_evidence"
        origin_result = {"candidates": candidates, "selected_ids": [], "tech_stack": stack,
                         "input_context": context}
        result["origin_contexts"][origin] = {"context": {"wordlist": origin_result}}
        all_candidates.extend(candidates)
    ranked = sorted((row for row in all_candidates if row["dispatch_eligible"] and (row["observed"] or row["generated"])), key=selection_key)
    for rank, row in enumerate(ranked[:max_wordlist_entries], 1):
        row.update(selected=True, selection_reason="evidence_priority", selection_rank=rank)
    totals = {name: 0 for name in ("catalog_count", "observed_count", "generated_count", "unattributed_count", "selected_count", "dispatch_eligible_count")}
    for origin, entry in result["origin_contexts"].items():
        wordlist = entry["context"]["wordlist"]
        rows = wordlist["candidates"]
        wordlist["selected_ids"] = [r["endpoint_id"] for r in sorted((r for r in rows if r["selected"]), key=lambda r: r["selection_rank"])]
        counts = {"catalog_count": len(rows), "observed_count": sum(r["observed"] for r in rows),
                  "unattributed_count": sum(not r["observed"] and not r["generated"] for r in rows),
                  "generated_count": sum(r["generated"] for r in rows), "selected_count": sum(r["selected"] for r in rows),
                  "dispatch_eligible_count": sum(r["dispatch_eligible"] for r in rows)}
        wordlist["counts"] = counts
        for key in totals:
            totals[key] += counts[key]
    summary = state.get("discovery_summary", {})
    # Summary is contextual data, never a policy or arbitrary instructions/body.
    summary = {"unique_endpoints_by_type": {k: v for k, v in summary.get("unique_endpoints_by_type", {}).items()
               if k in _TYPES and type(v) is int and v >= 0},
               "unresolved_references": summary.get("unresolved_references") if type(summary.get("unresolved_references")) is int else None}
    result["wordlist_metadata"]["multi_origin"] = {**totals, "schema_version": 1,
        "selection_limit": max_wordlist_entries, "max_generated_per_origin": max_generated_per_origin,
        "allow_generic": allow_generic, "selection_policy": "eligible_only_evidence_priority_v1",
        "source_discovery_summary": summary, "rejected_input_records": rejected,
        "http_dispatches": 0, "llm_invocations": 0, "verification_status": "not_verified",
        "eligibility_scope": "exact origin/path/query/method/read_only; not runtime or credential readiness"}
    artifacts = RunArtifacts({"artifact_root": artifact_root} if artifact_root else {})
    saved = artifacts.save(result, node="b22_wordlist", event="generated")
    # Never silently substitute redacted URLs/provenance for valid candidates.
    if saved["origin_contexts"] != result["origin_contexts"]:
        raise ValueError("Candidate artifact did not preserve the public contract")
    for origin, entry in result["origin_contexts"].items():
        current = state["origin_contexts"][origin]
        if current.get("context") is None:
            current["context"] = {"schema_version": 1}
        current["context"]["wordlist"] = deepcopy(entry["context"]["wordlist"])
    state.setdefault("wordlist_metadata", {})["multi_origin"] = deepcopy(result["wordlist_metadata"]["multi_origin"])
    return saved


def _grounded(path, observed_path):
    observed = [part for part in observed_path.split("/") if part]
    parts = [part for part in path.split("/") if part]
    semantic = {part for part in observed if part not in {"api", "rpc"} and not re.fullmatch(r"v\d+", part)}
    return bool(observed and parts and parts[0] == observed[0] and semantic.intersection(parts))
