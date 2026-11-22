"""B1 public origin contracts. Observations never grant dispatch permission.

No credential values belong here. Multi-origin Agent scheduling is deliberately
not enabled by this contract; the existing single-target fields remain canonical.
"""
from copy import deepcopy
from hashlib import sha256
import math
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .llm_logging import sanitize_for_log


AGENTS = ("tech_recon", "wordlist_gen", "fuzzing", "param_disc", "soft404_filter")


def public_url(value, *, origin_only=False):
    # Lazy import: validation also compiles this optional contract.
    from .validation import validate_url
    url = validate_url(value, "origin contract URL", origin_only=origin_only)
    decoded = unquote(url)
    if sanitize_for_log(url) != url or sanitize_for_log(decoded) != decoded:
        raise ValueError("Sensitive URLs are not accepted in the public origin contract")
    return url


def canonical_origin(value):
    parts = urlsplit(public_url(value))
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _label(value):
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", value)
            or sanitize_for_log(value) != value):
        raise ValueError("Expected a public identifier, not credential material")
    return value


def _path(value):
    # Deliberately conservative exact-path policy. Encoded/ambiguous routing
    # needs a separate server-aware policy, never implicit normalization.
    if (not isinstance(value, str) or not value.startswith("/") or "//" in value
            or any(c in value for c in "%\\;?#")
            or any(c.isspace() or ord(c) < 32 or ord(c) > 126 for c in value)
            or any(part in {".", ".."} for part in value.split("/"))):
        raise ValueError("Scope requires an unambiguous literal absolute path")
    return value


def normalize_origin_config(config):
    """Validate operator-authored PUBLIC policy only; no scope from discovery."""
    if not isinstance(config, dict) or set(config) - {"approved_origins", "origin_policies"}:
        raise ValueError("Unsupported multi_origin contract fields")
    approved = config.get("approved_origins")
    if not isinstance(approved, list) or not 1 <= len(approved) <= 32:
        raise ValueError("approved_origins requires 1..32 explicit origins")
    approved = list(dict.fromkeys(canonical_origin(public_url(o, origin_only=True)) for o in approved))
    policies = config.get("origin_policies", {})
    if not isinstance(policies, dict) or len(policies) > 32:
        raise ValueError("origin_policies must be an origin-keyed mapping")
    normalized = {}
    for origin, policy in policies.items():
        origin = canonical_origin(public_url(origin, origin_only=True))
        if origin not in approved or origin in normalized:
            raise ValueError("Policy origin is unapproved or duplicated")
        if not isinstance(policy, dict) or set(policy) - {"rules", "credential_profile"}:
            raise ValueError("Unsupported origin policy fields")
        profile = policy.get("credential_profile")
        if profile is not None:
            profile = _label(profile)
        rules = policy.get("rules", [])
        if not isinstance(rules, list) or len(rules) > 256:
            raise ValueError("rules must contain at most 256 exact path rules")
        cleaned = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) - {"path", "query", "methods", "operation"}:
                raise ValueError("Unsupported scope rule")
            methods = rule.get("methods")
            if (not isinstance(methods, list) or not methods
                    or any(method not in ("GET", "HEAD") for method in methods)):
                raise ValueError("B1 requires explicit GET/HEAD methods")
            if rule.get("operation") != "read_only":
                raise ValueError("Only explicitly declared read_only operations are supported")
            path, query = _path(rule.get("path")), rule.get("query", "")
            if not isinstance(query, str) or "#" in query:
                raise ValueError("query must be a literal query string")
            full = origin + path + ("?" + query if query else "")
            if public_url(full) != full:
                raise ValueError("Scope URLs must already be canonical")
            cleaned.append({"path": path, "query": query, "methods": sorted(set(methods)),
                            "operation": "read_only"})
        normalized[origin] = {"rules": cleaned, "credential_profile": profile}
    for origin in approved:
        normalized.setdefault(origin, {"rules": [], "credential_profile": None})
    return {"approved_origins": approved, "origin_policies": normalized}


def _context():
    # B1 does not execute Agents or infer their outcomes.
    return {"profile": None, "context": None, "status": None,
            "agent_statuses": {agent: None for agent in AGENTS}, "endpoints": []}


def origin_state(target_url, config=None):
    """Additive SharedState projection; legacy Agent output fields stay intact."""
    primary = canonical_origin(target_url)
    policy = normalize_origin_config(config) if config is not None else {
        "approved_origins": [primary], "origin_policies": {}}
    if primary not in policy["approved_origins"]:
        raise ValueError("Primary target origin must be explicitly approved")
    return {"origin_contract_version": 1, **deepcopy(policy), "discovered_origins": [],
            "origin_contexts": {origin: _context() for origin in policy["approved_origins"]},
            "origin_execution_mode": "not_enabled_b1" if config is not None else "legacy_untracked"}


def endpoint_observation(url, *, method=None, source=None, source_url=None,
                         classification=None, confidence=None, evidence_refs=None,
                         source_type=None, source_sha256=None, evidence_location=None,
                         resource_type="unknown", confidence_basis=None):
    """A reference or declaration is not a successful request or verification."""
    url = public_url(url)
    if method is not None and (not isinstance(method, str) or not re.fullmatch(r"[A-Z]+", method)):
        raise ValueError("method must be an uppercase token or null")
    if classification not in (None, "observed", "candidate", "inferred"):
        raise ValueError("Unknown observation classification")
    if confidence is not None and (type(confidence) not in (int, float)
                                  or not math.isfinite(confidence) or not 0 <= confidence <= 1):
        raise ValueError("confidence must be null or a finite value in [0, 1]")
    if source is not None:
        source = _label(source)
    if source_url is not None:
        source_url = public_url(source_url)
    refs = [] if evidence_refs is None else evidence_refs
    if not isinstance(refs, list) or len(refs) > 32:
        raise ValueError("evidence_refs must be a bounded list of public IDs")
    refs = [_label(ref) for ref in refs]
    if source_type not in (None, "html", "javascript", "form", "openapi", "other"):
        raise ValueError("Unknown discovery source type")
    if resource_type not in ("frontend_route", "static_asset", "api_reference", "unknown"):
        raise ValueError("Unknown resource type")
    if source_sha256 is not None and (not isinstance(source_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", source_sha256)):
        raise ValueError("Invalid source digest")
    if confidence_basis is not None:
        confidence_basis = _label(confidence_basis)
    location = {} if evidence_location is None else evidence_location
    if not isinstance(location, dict) or set(location) - {"line", "column", "offset", "end_offset", "tag", "attribute", "json_pointer"}:
        raise ValueError("Invalid evidence location")
    for key, value in location.items():
        if key in {"line", "column", "offset", "end_offset"}:
            if type(value) is not int or value < (1 if key in {"line", "column"} else 0):
                raise ValueError("Invalid evidence position")
        elif value is not None and (not isinstance(value, str) or len(value) > 8192 or sanitize_for_log(value) != value):
            raise ValueError("Invalid public evidence position")
    identity = sha256((url + "\n" + (method or "")).encode()).hexdigest()[:24]
    return {"endpoint_id": identity, "url": url, "origin": canonical_origin(url),
            "method": method, "source": source, "source_url": source_url,
            "classification": classification, "confidence": confidence, "evidence_refs": refs,
            "source_type": source_type, "source_sha256": source_sha256, "evidence_location": deepcopy(location),
            "resource_type": resource_type, "confidence_basis": confidence_basis,
            "attempted": None, "verification_status": "not_verified"}


def add_observation(state, observation):
    """Keep separate resources per origin. Never mutate approved_origins/policy."""
    # Rebuild the public schema, rejecting arbitrary fields/claimed verification.
    row = endpoint_observation(observation["url"], **{
        key: observation.get(key) for key in
        ("method", "source", "source_url", "classification", "confidence", "evidence_refs",
         "source_type", "source_sha256", "evidence_location", "confidence_basis")},
        resource_type=observation.get("resource_type", "unknown"))
    origin = row["origin"]
    contexts = state.setdefault("origin_contexts", {})
    context = contexts.setdefault(origin, _context())
    existing = next((item for item in context["endpoints"] if item["endpoint_id"] == row["endpoint_id"]), None)
    provenance = {key: deepcopy(row[key]) for key in (
        "source", "source_type", "source_url", "source_sha256", "evidence_location", "evidence_refs",
        "classification", "confidence", "confidence_basis", "resource_type")}
    if existing is not None and "provenance" not in existing:
        # B1 checkpoints predate provenance/resource_type. Preserve their first
        # source rather than rejecting the next observation or replacing it.
        existing.setdefault("resource_type", "unknown")
        existing.setdefault("evidence_refs", [])
        existing["provenance"] = [{key: deepcopy(existing.get(key)) for key in provenance}]
    if existing is None:
        row["provenance"] = [provenance]
        context["endpoints"].append(row)
        existing = row
    elif provenance not in existing["provenance"]:
        existing["provenance"].append(provenance)
        existing["evidence_refs"] = list(dict.fromkeys(existing["evidence_refs"] + row["evidence_refs"]))
        kinds = {p["resource_type"] for p in existing["provenance"]} - {"unknown"}
        existing["resource_type"] = next(iter(kinds)) if len(kinds) == 1 else "unknown"
        if len(kinds) > 1:
            existing["confidence"] = None
            existing["confidence_basis"] = "conflicting_resource_types"
    found = state.setdefault("discovered_origins", [])
    entry = next((entry for entry in found if entry["origin"] == origin), None)
    if entry is None:
        entry = {"origin": origin, "sources": []}
        found.append(entry)
    provenance = {key: row[key] for key in ("source", "source_url", "evidence_refs")}
    if provenance not in entry["sources"]:
        entry["sources"].append(deepcopy(provenance))
    return deepcopy(existing)


def merge_discovery_context(state, discovery):
    """Pure Coordinator handoff. No dispatch, approval or credential mutation."""
    if state.get("origin_contract_version") != 1:
        raise ValueError("Initialize the B1 origin contract before merging discovery")
    rejected = 0
    for observation in discovery.get("observations", []):
        try:
            add_observation(state, observation)
        except (ValueError, TypeError, KeyError):
            rejected += 1  # Never persist rejected URLs or secret-bearing snippets.
    def context_for(url):
        origin = canonical_origin(url)
        entry = state["origin_contexts"].setdefault(origin, _context())
        if entry["context"] is None:
            entry["context"] = {"schema_version": 1, "parameters": [], "forms": [],
                                "source_documents": [], "unresolved_references": []}
        return entry
    for field in ("parameters", "forms", "source_documents", "unresolved_references"):
        for raw in discovery.get(field, []):
            try:
                safe = sanitize_for_log(deepcopy(raw))
                if safe != raw:
                    raise ValueError("Sensitive context")
                # Unknown endpoint origins stay null; group by SOURCE document only.
                url = (raw.get("source_url") if field == "unresolved_references" else
                       raw.get("action") if field == "forms" else raw.get("url"))
                entry = context_for(public_url(url))
                if safe not in entry["context"][field]:
                    entry["context"][field].append(safe)
                if field == "source_documents":
                    statuses = [row["collection_status"] for row in entry["context"][field]]
                    status = "success" if all(s == "completed" for s in statuses) else (
                        "partial" if "completed" in statuses else "failed")
                    entry["agent_statuses"]["tech_recon"] = status
                    entry["status"] = status
            except (ValueError, TypeError, KeyError):
                rejected += 1
    state["discovery_summary"] = discovery_summary(state)
    state["discovery_summary"]["rejected_records"] = rejected
    state["discovery_summary"]["rejection_count_scope"] = "last_merge"
    state["discovery_summary"]["collector_rejected_sensitive_records"] = discovery.get("rejected_sensitive_records", 0)
    return state


def discovery_summary(state):
    counts = {kind: 0 for kind in ("frontend_route", "static_asset", "api_reference", "unknown")}
    unresolved = 0
    for context in state.get("origin_contexts", {}).values():
        for row in context["endpoints"]:
            counts[row.get("resource_type", "unknown")] += 1
        unresolved += len((context.get("context") or {}).get("unresolved_references", []))
    return {"unique_endpoints_by_type": counts, "unresolved_references": unresolved,
            "verification_status": "not_verified"}
