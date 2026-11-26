"""Independent B4.2B stdlib verifier: Soft404 results/journal <-> server access logs.

Does not import Coordinator, Agents, transports, comparator, recovery or scope code. It
re-derives control scope from the public operator config, recomputes similarity from the
bodies the servers actually served (a separate minimal normalizer: the lab bodies carry no
volatile tokens), and checks origin isolation, counters, replay and denied resumes.
--negative-checks mutates in-memory copies; files on disk are never modified.
Usage: verify_origin_soft404_evidence.py DIR [--expected-cases N] [--negative-checks]
"""
from collections import Counter
from copy import deepcopy
from difflib import SequenceMatcher
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
import posixpath
import re
import sys
from urllib.parse import urlsplit

SECRET = "b42b-local-only-fake"
SIMILARITY, DISTINCT = 0.97, 0.80
STRONG = {"genuine_distinct", "soft_404", "http_404"}
CONTROL = re.compile(r"__sentinel_missing_[0-9a-f]{32}")


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.text, self.tags = [], []
    def handle_starttag(self, tag, attrs): self.tags.append(tag)
    def handle_data(self, data):
        if data.strip(): self.text.append(data.strip())


def features(row):
    body = row["body"] or ""
    html = "html" in (row.get("content_type") or "")
    norm = re.sub(r"\s+", " ", body).strip()
    parser = _Text()
    if html:
        parser.feed(norm)
    return {"norm": norm, "text": " ".join(parser.text) if html else norm, "tags": "".join(parser.tags), "html": html,
            "length": len(body.encode()), "sha": row["body_sha256"]}


def ratio(a, b):
    return 1.0 if a == b else 0.0 if not a or not b else SequenceMatcher(None, a, b, autojunk=True).ratio()


def compare(x, y):
    exact = x["sha"] == y["sha"] or x["norm"] == y["norm"]
    return {"exact": exact, "content": 1.0 if exact else ratio(x["norm"], y["norm"]),
            "text": 1.0 if exact else ratio(x["text"], y["text"]),
            "structure": ratio(x["tags"], y["tags"]) if x["html"] and y["html"] else None,
            "length": min(x["length"], y["length"]) / max(1, x["length"], y["length"])}


def matching(c):
    return c["exact"] or (c["content"] >= SIMILARITY and c["text"] >= max(SIMILARITY, .99) and c["length"] >= .97
                          and (c["structure"] is None or c["structure"] >= SIMILARITY))


def usable(row):
    return row is not None and row["status"] in {200, 404, 410} and bool(row["body"]) and not row.get("fault")


def classify(controls, candidate, root):
    """Independent classification from served rows: (class, exact_only)."""
    if len(controls) < 3 or not all(usable(c) for c in controls) or len({(c["status"], c["content_type"]) for c in controls}) != 1:
        return "inconclusive", True
    feats = [features(c) for c in controls]
    pairs = [compare(feats[0], f) for f in feats[1:]]
    if not all(matching(p) for p in pairs):
        return "inconclusive", all(p["exact"] for p in pairs)
    if candidate is None:
        return "not_checked", True
    if candidate["status"] in {404, 410} and not candidate.get("fault"):
        return "http_404", True
    if not usable(candidate) or candidate["status"] != 200:
        return "inconclusive", True
    cand = features(candidate)
    comps = [compare(cand, f) for f in feats]
    same_type = all(candidate["content_type"] == c["content_type"] for c in controls)
    exact = all(p["exact"] for p in pairs) and all(c["exact"] for c in comps)
    if same_type and all(matching(c) for c in comps):
        return ("inconclusive" if root else "soft_404"), exact
    if all(c["content"] <= DISTINCT and c["text"] <= DISTINCT for c in comps):
        return "genuine_distinct", False
    return "inconclusive", exact


def control_allowed(config, origin, path, query):
    parent, name = posixpath.split(path)
    for rule in config["origin_policies"].get(origin, {}).get("rules", []):
        if not rule.get("soft404_controls") or rule.get("query", "") != query:
            continue
        rule_parent, rule_name = posixpath.split(rule["path"])
        suffix = posixpath.splitext(rule_name)[1]
        if (rule_parent or "/") == (parent or "/") and re.fullmatch(CONTROL.pattern + re.escape(suffix), name):
            return True
    return False


def group_of(origin, path, query):
    parent, name = posixpath.split(path or "/")
    suffix = posixpath.splitext(name)[1]
    return (origin, parent or "/", suffix if re.fullmatch(r"(?:\.[a-zA-Z0-9_-]+)?", suffix) and len(suffix) <= 16 else "", query)


def check_sections(case, result, served_rows, errors, journal=None):
    """Shared checks over final per-origin sections against served rows (by runtime sequence)."""
    need = lambda c, m: None if c else errors.append(m)
    ev, config = case["ev"], case["config"]
    decisions = {}
    if journal is not None:
        decisions = {(e["payload"]["unit_id"], e["payload"]["endpoint_id"]): e["payload"] for e in journal if e["event"] == "soft404_decision"}
    for role, origin in (("frontend", ev["origins"]["frontend"]), ("gateway", ev["origins"]["gateway"])):
        section = result["origin_contexts"][origin]["context"].get("soft404")
        if section is None:
            continue
        rows = {r["runtime_sequence"]: r for r in section["requests"]}
        for seq, req in rows.items():
            need(req["origin"] == origin, f"{role}: request from another origin")
            if req["role"] == "control":
                need(control_allowed(config, origin, req["path"], req["query"]), f"{role}: control outside approved scope {req['path']}")
            served = served_rows.get(seq)
            if served is not None and req.get("status_code") is not None:
                need(served["status"] == req["status_code"], f"{role}: measured status differs from server")
                if req.get("body_complete"):
                    need(served["body_sha256"] == req["body_sha256"], f"{role}: measured digest differs from served body")
        for endpoint in section["endpoints"]:
            need(endpoint["verification_status"] == "not_verified", "endpoint marked verified")
            need(endpoint["parameter_context"]["authority"] == "context_only", "Agent 4 context used as authority")
            cls = endpoint["soft404_classification"]
            if endpoint.get("unit_state") == "interrupted":
                need(cls not in STRONG, "interrupted group has a strong classification")
            evidence = endpoint.get("verification_evidence") or {}
            controls = [rows.get(s) for s in evidence.get("control_sequences") or []]
            for c in controls:
                need(c is not None and c["origin"] == origin and group_of(origin, c["path"], c["query"]) ==
                     group_of(origin, urlsplit(endpoint["url"]).path or "/", urlsplit(endpoint["url"]).query),
                     f"{role}: control from another origin/group")
            if cls not in STRONG:
                continue
            cand_seq = evidence.get("candidate_sequence")
            served_controls = [served_rows.get(c["runtime_sequence"]) if c else None for c in controls]
            derived, exact = classify([s for s in served_controls if s], served_rows.get(cand_seq),
                                      urlsplit(endpoint["url"]).path in {"", "/"})
            need(derived == cls, f"{role}: {endpoint['url']} {cls} not reproducible from served bodies ({derived})")
            need(endpoint["evidence_level"] == ("rederived" if exact or cls == "http_404" else "metrics_journaled"),
                 f"{role}: evidence level {endpoint['evidence_level']} does not match evidence")
            if journal is not None:
                decision = decisions.get((endpoint["unit_id"], endpoint["endpoint_id"]))
                need(decision is not None and decision["classification"] == cls and decision["candidate_sequence"] == cand_seq,
                     f"{role}: strong class without matching journaled decision")
                for metric, c in zip((decision or {}).get("metrics") or [], controls):
                    cand = rows.get(cand_seq)
                    if cand and c:
                        need(metric["exact_body_match"] == (cand["body_sha256"] == c["body_sha256"]), "journaled metric contradicts digests")
                        length = min(cand["content_length"], c["content_length"]) / max(1, cand["content_length"], c["content_length"])
                        need(abs(metric["length_ratio"] - length) < 1e-9, "journaled length ratio contradicts lengths")


def check_inprocess(case):
    errors = []
    need = lambda c, m: None if c else errors.append(m)
    ev, access = case["ev"], case["ev"]["access"]
    after, a, b = ev["state_after_agent5"], ev["origins"]["frontend"], ev["origins"]["gateway"]
    need(len(access["unapproved"]) == 0, "unapproved origin contacted")
    need(all(r["credential_identity"] == "anonymous" for r in access["gateway"]), "credential sent to gateway")
    need(after["origin_execution_mode"] == "not_enabled_b1", "production gate changed")
    need(SECRET not in json.dumps(after), "credential value persisted")
    served_rows = {}
    for role, origin in (("frontend", a), ("gateway", b)):
        section = after["origin_contexts"][origin]["context"]["soft404"]
        rows = [r for r in access[role] if r["phase"] == "soft404"]
        need(len(section["requests"]) == len(rows), f"{role}: {len(section['requests'])} recorded vs {len(rows)} served")
        need(section["origin_budget_used"] - section["origin_budget_before"] == len(rows), f"{role}: origin budget delta")
        for req, row in zip(section["requests"], rows):
            need((req["path"], req["query"]) == (row["path"], row["query"]), f"{role}: order/url mismatch")
            served_rows[req["runtime_sequence"]] = row
    total = sum(len(v) for v in access.values())
    need(ev["runtime_after_agent5"]["http_dispatches"] == total, "runtime total vs server rows")
    need(ev["telemetry"]["http"]["known_requests"] == total, "telemetry total vs server rows")
    need(after["soft404_execution"]["multi_origin"]["http_dispatches_this_call"]
         == sum(1 for v in access.values() for r in v if r["phase"] == "soft404"), "Agent 5 dispatch delta")
    check_sections(case, after, served_rows, errors)
    expected = ev["scenario"].get("expected")
    if expected:
        actual = {f"{o}{urlsplit(e['url']).path}": [e["soft404_classification"], e["evidence_level"]]
                  for o in (a, b) for e in after["origin_contexts"][o]["context"]["soft404"]["endpoints"]}
        need(actual == {k: list(v) for k, v in expected.items()}, "classes differ from lab semantics")
    return errors


def check_recovery(case):
    errors = []
    need = lambda c, m: None if c else errors.append(m)
    ev, access = case["ev"], case["access"]
    a, b = ev["origins"]["frontend"], ev["origins"]["gateway"]
    result = case["result"]
    blocked = result is not None and (result.get("recovery") or {}).get("status") == "blocked"
    denied = case["access_before"] is not None and ("resume_denied.json" in case["denials"] or blocked)
    journal = case["before_journal"] if denied else case["journal"]
    prev = None
    for n, row in enumerate(journal, 1):
        check = dict(row); claimed = check.pop("hash")
        need(row["seq"] == n and row["previous"] == prev and digest(check) == claimed, f"journal chain broken at {n}")
        prev = claimed
    if not denied:
        need(case["head"] == {"seq": len(journal), "hash": prev}, "journal head mismatch")
    need(SECRET not in case["raw"], "credential value persisted")
    need(len(access["unapproved"]) == 0, "unapproved origin contacted")
    need(all(r["credential_identity"] == "anonymous" for r in access["gateway"]), "credential sent to gateway")
    reservations = [e["payload"] for e in journal if e["event"] == "reserved"]
    probes = [r for r in reservations if "soft404" in r]
    started = {e["payload"]["sequence"] for e in journal if e["event"] == "dispatch_started"}
    measured = {e["payload"]["sequence"] for e in journal if e["event"] == "measurement"}
    ids = [(r["soft404"]["unit_id"], r["soft404"]["ordinal"]) for r in probes]
    need(len(ids) == len(set(ids)), "Soft404 identity reserved twice (replay)")
    owners = {}
    for r in probes:
        owners.setdefault((r["origin"], r["soft404"]["group_id"]), set()).add(r["soft404"]["unit_id"])
        if r["soft404"]["role"] == "control":
            parts = urlsplit(r["url"])
            need(control_allowed(case["config"], r["origin"], parts.path, parts.query), "reserved control outside approved scope")
    need(all(len(u) == 1 for u in owners.values()), "group measured by a second unit (replay)")
    served_rows = {}
    for role, origin in (("frontend", a), ("gateway", b)):
        expected = [r for r in reservations if r["origin"] == origin and r["sequence"] in started]
        j = 0
        for row in access[role]:
            key = (row["path"], row["query"])
            while j < len(expected) and (urlsplit(expected[j]["url"]).path, urlsplit(expected[j]["url"]).query) != key:
                j += 1
            need(j < len(expected), f"{role}: server row without matching dispatched reservation (replay or fabricated)")
            if j < len(expected):
                served_rows[expected[j]["sequence"]] = row
            j += 1
    if denied:
        need(case["access_before"] == access, "HTTP sent after a denied resume")
        return errors
    if case["before_journal"] is not None:
        old = case["before_journal"]
        need(journal[:len(old)] == old, "pre-resume journal rewritten")
        old_units = {e["payload"]["soft404"]["unit_id"] for e in old if e["event"] == "reserved" and "soft404" in e["payload"]}
        old_unknown = {e["payload"]["sequence"] for e in old if e["event"] == "reserved"} - \
                      {e["payload"]["sequence"] for e in old if e["event"] == "measurement"}
        for e in journal[len(old):]:
            if e["event"] == "reserved" and "soft404" in e["payload"]:
                need(e["payload"]["soft404"]["unit_id"] not in old_units, "group unit reopened after resume (replay)")
            if e["event"] == "measurement":
                need(e["payload"]["sequence"] not in old_unknown, "outcome_unknown request measured after resume")
    if result is None:
        need(False, "no final result")
        return errors
    need(result["origin_execution_mode"] == "not_enabled_b1", "production gate changed")
    need(result["runtime"]["http_dispatches"] == len(reservations), "runtime counter differs from reservations")
    need(result["runtime"]["http_dispatches_by_origin"] == dict(Counter(r["origin"] for r in reservations)), "per-origin counter")
    for origin in (a, b):
        section = result["origin_contexts"][origin]["context"].get("soft404")
        if section is None:
            continue
        need(sorted(r["runtime_sequence"] for r in section["requests"]) == sorted(r["sequence"] for r in probes if r["origin"] == origin),
             "result requests differ from journal reservations")
        for req in section["requests"]:
            if req["runtime_sequence"] not in measured:
                need(req.get("recovery_state") == "outcome_unknown" and req.get("status_code") is None, "unknown outcome reported as measured")
    check_sections(case, result, served_rows, errors, journal=journal)
    return errors


def load(directory):
    ev = json.loads((directory / "evidence.json").read_text(encoding="utf-8"))
    case = {"ev": ev, "dir": directory}
    if ev.get("kind") != "recovery":
        case["config"] = ev["config_public"]
        return case
    load_jsonl = lambda p: [json.loads(l) for l in Path(p).read_text(encoding="utf-8").splitlines() if l]
    case["config"] = ev["settings_public"]["config"]["multi_origin"]
    case["access"] = {role: load_jsonl(path) for role, path in ev["access_files"].items()}
    case["journal"] = load_jsonl(directory / "recovery/journal.jsonl")
    case["head"] = json.loads((directory / "recovery/head.json").read_text(encoding="utf-8"))
    before = directory / "recovery_before_resume/journal.jsonl"
    case["before_journal"] = load_jsonl(before) if before.exists() else None
    access_before = directory / "access_before_resume.json"
    case["access_before"] = json.loads(access_before.read_text(encoding="utf-8")) if access_before.exists() else None
    results = {Path(p).name: json.loads(Path(p).read_text(encoding="utf-8")) for p in ev["results"]}
    case["denials"] = {Path(p).name: json.loads(Path(p).read_text(encoding="utf-8")) for p in ev["denials"]}
    case["result"] = results.get("resume_result.json") or results.get("first_result.json")
    case["raw"] = "".join(Path(p).read_text(encoding="utf-8") for p in ev["results"] + ev["denials"])
    case["raw"] += (directory / "recovery/journal.jsonl").read_text(encoding="utf-8")
    return case


def check(case):
    return check_recovery(case) if case["ev"].get("kind") == "recovery" else check_inprocess(case)


def rehash(c):
    """Consistent rewrite of the final AND pre-resume journal: only semantic checks can catch it."""
    for key in ("journal", "before_journal"):
        rows, prev = c.get(key), None
        for n, row in enumerate(rows or [], 1):
            row["seq"], row["previous"] = n, prev; row.pop("hash", None); row["hash"] = digest(row); prev = row["hash"]
        if key == "journal":
            c["head"] = {"seq": len(rows), "hash": prev}


def both(c, pick):
    """Apply the same journal edit to the final and pre-resume journals."""
    for key in ("journal", "before_journal"):
        for event in c.get(key) or []:
            if pick(event):
                yield key, event


def mutations(inproc, recovery):
    def sec(c, i):
        return c["ev"]["state_after_agent5"]["origin_contexts"][[c["ev"]["origins"]["frontend"], c["ev"]["origins"]["gateway"]][i]]["context"]["soft404"]

    def borrowed_control(c):
        a, b = sec(c, 0), sec(c, 1)
        target = next(e for e in b["endpoints"] if e["soft404_classification"] == "genuine_distinct")
        foreign = next(e for e in a["endpoints"] if (e.get("verification_evidence") or {}).get("control_sequences"))
        # Point a gateway classification at frontend controls (counts untouched: isolation must catch it).
        target["verification_evidence"]["control_sequences"] = deepcopy(foreign["verification_evidence"]["control_sequences"])

    def upgraded_inconclusive(c):
        e = next(e for e in sec(c, 1)["endpoints"] if e["soft404_classification"] == "inconclusive")
        e["soft404_classification"] = "genuine_distinct"

    def extra_control(c):
        s = sec(c, 0); extra = deepcopy(next(r for r in s["requests"] if r["role"] == "control"))
        extra["runtime_sequence"] += 100000; s["requests"].append(extra)

    def lowered_counter(c):
        sec(c, 0)["origin_budget_used"] -= 1

    def removed_decision(c):
        strong = {(e["unit_id"], e["endpoint_id"]) for o in c["result"]["origin_contexts"].values()
                  for e in ((o.get("context") or {}).get("soft404") or {}).get("endpoints", []) if e["soft404_classification"] in STRONG}
        victim = next(e for e in c["journal"] if e["event"] == "soft404_decision" and (e["payload"]["unit_id"], e["payload"]["endpoint_id"]) in strong)
        key_of = (victim["payload"]["unit_id"], victim["payload"]["endpoint_id"])
        for key, event in list(both(c, lambda e: e["event"] == "soft404_decision"
                                    and (e["payload"]["unit_id"], e["payload"]["endpoint_id"]) == key_of)):
            c[key].remove(event)
        rehash(c)

    def tampered_metric(c):
        d = next(e for e in c["journal"] if e["event"] == "soft404_decision" and e["payload"]["metrics"]
                 and e["payload"]["classification"] in STRONG)
        key_of = (d["payload"]["unit_id"], d["payload"]["endpoint_id"])
        for _, event in both(c, lambda e: e["event"] == "soft404_decision"
                             and (e["payload"]["unit_id"], e["payload"]["endpoint_id"]) == key_of):
            event["payload"]["metrics"][0]["length_ratio"] = 0.5
        rehash(c)

    def replayed_server_request(c):
        c["access"]["frontend"].append(deepcopy(next(r for r in c["access"]["frontend"] if "__sentinel_missing_" in r["path"])))

    out = []
    if inproc is not None:
        out += [("control_borrowed_from_other_origin", inproc, borrowed_control), ("inconclusive_upgraded", inproc, upgraded_inconclusive),
                ("control_without_reservation", inproc, extra_control), ("attempt_counter_lowered", inproc, lowered_counter)]
    if recovery is not None:
        out += [("strong_class_decision_removed", recovery, removed_decision), ("journaled_metric_tampered", recovery, tampered_metric),
                ("replayed_server_request", recovery, replayed_server_request)]
    return out


def main():
    root = Path(sys.argv[1])
    expected = int(sys.argv[sys.argv.index("--expected-cases") + 1]) if "--expected-cases" in sys.argv else None
    dirs = sorted(p.parent for p in root.glob("b42[br]_*/evidence.json"))
    report = {"cases": [], "negative_checks": []}
    ok = bool(dirs) and (expected is None or len(dirs) == expected)
    loaded = []
    for d in dirs:
        case = load(d); loaded.append(case)
        errors = check(case)
        report["cases"].append({"case_id": case["ev"]["case_id"], "test": case["ev"]["test"], "passed": not errors, "errors": errors})
        ok &= not errors
    if "--negative-checks" in sys.argv:
        inproc = next((c for c in loaded if c["ev"]["test"] == "test_real_chain_classifies_each_origin_with_its_own_controls"), None)
        recovery = next((c for c in loaded if c["ev"]["test"] == "test_crash_after_group_checkpoint_preserves_classification"), None)
        if inproc is None or recovery is None:
            ok = False; report["negative_checks"].append({"error": "base cases missing"})
        for name, base, mutate in mutations(inproc, recovery):
            copy = deepcopy(base); mutate(copy)
            errors = check(copy)
            report["negative_checks"].append({"mutation": name, "detected": bool(errors), "first_error": errors[:1]})
            ok &= bool(errors)
    report.update(case_count=len(dirs), expected_cases=expected, passed=ok,
                  assurance="strong classes recomputed from served lab bodies; journaled metrics checked for digest/length "
                            "consistency only; hash chain does not resist a writer with full access")
    (root / "independent_verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"case_count": len(dirs), "passed": ok, "failed_cases": [c["test"] for c in report["cases"] if not c["passed"]],
                      "negative_checks": [(n["mutation"], n["detected"], n["first_error"]) for n in report["negative_checks"] if "mutation" in n]}, indent=1))
    for c in report["cases"]:
        for e in c["errors"][:4]:
            print("ERROR", c["test"], e)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
