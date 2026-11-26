"""Independent B4.1 stdlib verifier: Agent 4 SharedState/artifacts -> server access logs.

Does not import Coordinator, Agents, transports or scope implementation. It
re-derives scope from the public operator config, re-derives verdict evidence
from what each server actually served, and checks accounting/credentials.
--negative-checks mutates in-memory copies; files on disk are never modified.
Usage: verify_origin_parameter_evidence.py DIR [--expected-cases N] [--negative-checks]
"""
from copy import deepcopy
from html import unescape
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

CONTROL = re.compile(r"__sentinel_unknown_[0-9a-f]{32}")
VALUE = re.compile(r"1|2|true|false|sentinel_[0-9a-f]{32}")
SECRET = "b41-local-only-fake"


def origin_of(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def pair(query, base_query):
    """Return (name, value) appended to base_query, or None for the exact base."""
    if query == base_query:
        return None
    prefix = base_query + "&" if base_query else ""
    if not query.startswith(prefix):
        raise AssertionError("probe query does not extend the approved query")
    extra = query[len(prefix):]
    if extra.count("=") != 1 or "&" in extra:
        raise AssertionError("probe adds more than one query pair")
    return tuple(extra.split("=", 1))


def text(body):
    body = unescape(unquote(body or ""))
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), body)


def check_case(ev):
    errors = []
    def need(cond, message):
        if not cond:
            errors.append(message)
    a, b = ev["origins"]["frontend"], ev["origins"]["gateway"]
    access, config = ev["access"], ev["config_public"]
    after, before = ev["state_after_agent4"], ev["state_before_agent4"]
    need(len(access["unapproved"]) == 0, "unapproved origin received requests")
    need(after.get("origin_execution_mode") == "not_enabled_b1", "production gate changed")
    need(after["approved_origins"] == config["approved_origins"] == before["approved_origins"], "approved_origins changed")
    need(after["origin_policies"] == before["origin_policies"], "origin policy changed during Agent 4")
    summary = after["parameter_execution"]["multi_origin"]
    need(summary["full_multi_origin_execution_enabled"] is False, "full execution flag set")
    total_probes = 0
    rules = {o: config["origin_policies"][o]["rules"] for o in (a, b)}
    for role, origin in (("frontend", a), ("gateway", b)):
        rows = [r for r in access[role] if r["phase"] == "parameters"]
        total_probes += len(rows)
        section = after["origin_contexts"][origin]["context"]["parameter_discovery"]
        sent = section["requests"]
        need(len(sent) == len(rows), f"{role}: {len(sent)} recorded requests vs {len(rows)} server rows")
        need(section["origin_budget_used"] - section["origin_budget_before"] == len(rows), f"{role}: origin budget delta mismatch")
        need(section["counts"]["http_requests"] == len(rows), f"{role}: request counter mismatch")
        expected_identity = "frontend" if role == "frontend" else "anonymous"
        need(all(r["credential_identity"] == expected_identity for r in access[role]), f"{role}: credential identity leak")
        need(all(r["method"] == "GET" for r in rows), f"{role}: non-GET probe")
        served = {}
        for item, row in zip(sent, rows):
            need(item["origin"] == origin == row["origin"], f"{role}: request origin mismatch")
            need((item["path"], item["query"]) == (row["path"], row["query"]), f"{role}: request order/url mismatch")
            if item["status_code"] is None:
                need(item["error"] is not None and row["delay_seconds"] > ev["limits"]["http_timeout_seconds"],
                     f"{role}: missing status without a real timeout")
            else:
                need(item["status_code"] == row["status"], f"{role}: status mismatch")
                if item["body_complete"]:
                    need(item["body_sha256"] == row["body_sha256"], f"{role}: body digest mismatch")
            served[(row["path"], row["query"])] = row
            rule = next((r for r in rules[origin] if r["path"] == row["path"] and r.get("parameters")), None)
            try:
                need(rule is not None, f"{role}: probe path without operator parameters {row['path']}")
                probe = pair(row["query"], (rule or {}).get("query", ""))
                if probe is not None:
                    need((probe[0] in rule["parameters"] or CONTROL.fullmatch(probe[0])) and VALUE.fullmatch(probe[1]),
                         f"{role}: probe outside approved names/values")
            except AssertionError as exc:
                need(False, f"{role}: {exc}")
        observed = {r["candidate_id"]: r for r in before["origin_contexts"][origin]["context"]["http_dispatch"]["records"]}
        endpoints = {e["endpoint_id"]: e for e in before["origin_contexts"][origin]["endpoints"]}
        params = before["origin_contexts"][origin]["context"].get("parameters", [])
        for endpoint in section["endpoints"]:
            need(endpoint["origin"] == origin, f"{role}: endpoint origin mismatch")
            if not endpoint["eligible"]:
                need(all(c["verification"] != "verified" for c in endpoint["candidates"]), f"{role}: excluded endpoint verified")
                continue
            source = observed.get(endpoint["endpoint_id"])
            need(source is not None and source["url"] == endpoint["url"] and source["attempted"] is True
                 and 200 <= (source["status_code"] or 0) < 300, f"{role}: endpoint not observed by Agent 3")
            need(endpoints.get(endpoint["endpoint_id"], {}).get("url") == endpoint["url"], f"{role}: endpoint identity changed")
            path, base_query = urlsplit(endpoint["url"]).path, urlsplit(endpoint["url"]).query
            for c in endpoint["candidates"]:
                if c["verification"] != "verified":
                    continue
                name = c["name"]
                rule = next((r for r in rules[origin] if r["path"] == path and r.get("query", "") == base_query), {})
                need(name in rule.get("parameters", []), f"{role}: verified name not operator-listed")
                need(c["verification_reason"] == "repeatable_response_effect_vs_negative_controls", f"{role}: verified reason")
                need(any(p["source"] == "agent1_reference" and any(q.get("name") == name and q.get("url") == endpoint["url"]
                         for q in params) for p in c["provenance"]), f"{role}: verified candidate lacks Agent 1 provenance")
                evidence = c["verification_evidence"]
                groups = [("controls", 4), ("samples", 4), ("post_controls", 3)]
                rows_by_group = {}
                for group, size in groups:
                    items = evidence.get(group, [])
                    need(len(items) == size, f"{role}: {name} {group} size")
                    matched = []
                    for m in items:
                        parts = urlsplit(m["url"])
                        need(origin_of(m["url"]) == origin and parts.path == path, f"{role}: {name} {group} from another endpoint/origin")
                        row = served.get((parts.path, parts.query))
                        need(row is not None, f"{role}: {name} {group} response not in server log")
                        if row is not None:
                            need(row["status"] == m["status_code"] and 200 <= row["status"] < 300, f"{role}: {name} {group} status")
                            need(row["body_sha256"] == m["body_sha256"], f"{role}: {name} {group} digest")
                            matched.append(row)
                    rows_by_group[group] = matched
                if len(rows_by_group.get("controls", [])) == 4 and len(rows_by_group.get("samples", [])) == 4 \
                        and len(rows_by_group.get("post_controls", [])) == 3:
                    controls, samples, post = rows_by_group["controls"], rows_by_group["samples"], rows_by_group["post_controls"]
                    base_digest = controls[0]["body_sha256"]
                    for row in controls[2:] + post[1:]:
                        probe = pair(row["query"], base_query)
                        need(probe is not None and CONTROL.fullmatch(probe[0]), f"{role}: {name} control is not an unknown-name control")
                    for row in samples:
                        probe = pair(row["query"], base_query)
                        need(probe is not None and probe[0] == name, f"{role}: {name} sample uses another name")
                        if probe is not None:
                            need(text(row["body"]).count(probe[1]) <= text(controls[0]["body"]).count(probe[1]),
                                 f"{role}: {name} verified despite server-side reflection")
                    need(all(r["body_sha256"] == base_digest for r in controls + post), f"{role}: {name} unstable controls")
                    need(samples[0]["body_sha256"] == samples[1]["body_sha256"] and samples[2]["body_sha256"] == samples[3]["body_sha256"],
                         f"{role}: {name} unstable samples")
                    need(any(r["body_sha256"] != base_digest for r in samples), f"{role}: {name} no served difference")
    rows_all = sum(len(v) for v in access.values())
    need(summary["http_dispatches_this_call"] == total_probes, "Agent 4 dispatch delta mismatch")
    need(ev["runtime_after_agent4"]["http_dispatches"] == rows_all, "runtime total vs server rows")
    need(ev["telemetry"]["http"]["known_requests"] == rows_all, "telemetry total vs server rows")
    for role, origin in (("frontend", a), ("gateway", b)):
        need(ev["runtime_after_agent4"]["http_dispatches_by_origin"].get(origin, 0) == len(access[role]), f"{role}: per-origin runtime vs rows")
    expected = ev["scenario"].get("expected_verified")
    if expected is not None:
        actual = sorted(f"{e['origin']}{urlsplit(e['url']).path}?{c['name']}" for o in (a, b)
                        for e in after["origin_contexts"][o]["context"]["parameter_discovery"]["endpoints"]
                        for c in e["candidates"] if c["verification"] == "verified")
        need(actual == expected, "verified set differs from expected lab semantics")
    need(SECRET not in json.dumps(after), "credential value in SharedState")
    return errors


def check_artifacts(ev):
    errors = []
    results = [Path(p) for p in ev["artifact_results"]]
    if not results:
        return ["no artifacts"]
    found = False
    for path in results:
        raw = path.read_text(encoding="utf-8")
        if SECRET in raw:
            errors.append(f"credential value in {path.name}")
        data = json.loads(raw)
        if (data.get("parameter_execution") or {}).get("multi_origin") == ev["state_after_agent4"]["parameter_execution"]["multi_origin"]:
            found = True
            checkpoints = sorted(path.parent.glob("checkpoints/*_b41_parameters.json"))
            if len(checkpoints) < 2:
                errors.append("missing B4.1 checkpoints")
    if not found:
        errors.append("no artifact result matches the Agent 4 summary")
    return errors


def mutations(ev):
    a, b = ev["origins"]["frontend"], ev["origins"]["gateway"]
    def sections(e):
        return [e["state_after_agent4"]["origin_contexts"][o]["context"]["parameter_discovery"] for o in (a, b)]
    def candidates(e, verified):
        return [c for s in sections(e) for x in s["endpoints"] for c in x["candidates"]
                if (c["verification"] == "verified") == verified and c["selected"] and c["verification_performed"]]
    def fake_verified(e):
        c = candidates(e, False)[0]; c.update(verification="verified", verification_reason="repeatable_response_effect_vs_negative_controls")
    def change_origin(e):
        sections(e)[1]["requests"][0]["origin"] = a
    def add_response(e):
        s = sections(e)[1]; extra = deepcopy(s["requests"][-1]); extra["sequence"] += 1; s["requests"].append(extra)
    def lower_counter(e):
        sections(e)[0]["origin_budget_used"] -= 1
    def mix_controls(e):
        frontend = next(c for x in sections(e)[0]["endpoints"] for c in x["candidates"] if c["verification"] == "verified")
        gateway = next(c for x in sections(e)[1]["endpoints"] for c in x["candidates"] if c["verification"] == "verified")
        gateway["verification_evidence"]["controls"] = deepcopy(frontend["verification_evidence"]["controls"])
    return [("fake_verified_parameter", fake_verified), ("changed_request_origin", change_origin),
            ("nonexistent_response_added", add_response), ("attempt_counter_lowered", lower_counter),
            ("controls_mixed_across_origins", mix_controls)]


def main():
    root = Path(sys.argv[1])
    expected = int(sys.argv[sys.argv.index("--expected-cases") + 1]) if "--expected-cases" in sys.argv else None
    cases = sorted(root.glob("b41_*/evidence.json"))
    report = {"cases": [], "negative_checks": []}
    ok = bool(cases) and (expected is None or len(cases) == expected)
    for path in cases:
        ev = json.loads(path.read_text(encoding="utf-8"))
        errors = check_case(ev) + check_artifacts(ev)
        report["cases"].append({"case_id": ev["case_id"], "test": ev["test"], "passed": not errors, "errors": errors})
        ok &= not errors
    if "--negative-checks" in sys.argv:
        main_case = next((json.loads(p.read_text(encoding="utf-8")) for p in cases
                          if "real_chain" in json.loads(p.read_text(encoding="utf-8"))["test"]), None)
        if main_case is None:
            ok = False
            report["negative_checks"].append({"error": "main case missing"})
        else:
            for name, mutate in mutations(main_case):
                copy = deepcopy(main_case)
                mutate(copy)
                errors = check_case(copy)
                report["negative_checks"].append({"mutation": name, "detected": bool(errors), "first_error": errors[:1]})
                ok &= bool(errors)
    report["case_count"], report["expected_cases"], report["passed"] = len(cases), expected, ok
    (root / "independent_verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"case_count": len(cases), "passed": ok,
                      "failed_cases": [c["case_id"] for c in report["cases"] if not c["passed"]],
                      "negative_checks": [(n["mutation"], n["detected"]) for n in report["negative_checks"] if "mutation" in n]}, indent=1))
    for case in report["cases"]:
        for error in case["errors"][:5]:
            print("ERROR", case["case_id"], error)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
