"""Independent B4.2A stdlib verifier: probe recovery journal <-> results <-> server access logs.

Does not import Coordinator, Agents, transports, recovery or scope code. Re-derives
verdicts from what the servers actually served, checks replay by identity (never by
URL alone), counters, unit states and that denied resumes sent no HTTP.
--negative-checks mutates in-memory copies; files on disk are never modified.
Usage: verify_origin_parameter_recovery_evidence.py DIR [--expected-cases N] [--negative-checks]
"""
from collections import Counter
from copy import deepcopy
from hashlib import sha256
from html import unescape
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

SECRET = "b42a-local-only-fake"


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode()).hexdigest()


def text(body):
    body = unescape(unquote(body or ""))
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), body)


def load_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]


def load_case(directory):
    ev = json.loads((directory / "evidence.json").read_text(encoding="utf-8"))
    case = {"ev": ev, "dir": directory,
            "access": {role: load_jsonl(path) for role, path in ev["access_files"].items()},
            "journal": load_jsonl(directory / "recovery/journal.jsonl"),
            "head": json.loads((directory / "recovery/head.json").read_text(encoding="utf-8")),
            "before_journal": load_jsonl(directory / "recovery_before_resume/journal.jsonl")
            if (directory / "recovery_before_resume/journal.jsonl").exists() else None,
            "access_before": json.loads((directory / "access_before_resume.json").read_text(encoding="utf-8"))
            if (directory / "access_before_resume.json").exists() else None,
            "results": {Path(p).name: json.loads(Path(p).read_text(encoding="utf-8")) for p in ev["results"]},
            "denials": {Path(p).name: json.loads(Path(p).read_text(encoding="utf-8")) for p in ev["denials"]}}
    case["raw"] = "".join(Path(p).read_text(encoding="utf-8") for p in ev["results"] + ev["denials"])
    case["raw"] += (directory / "recovery/journal.jsonl").read_text(encoding="utf-8")
    return case


def final_result(case):
    results = case["results"]
    return results.get("resume_result.json") or results.get("first_result.json")


def derive(entries):
    """B4.1 rule over server-served bodies (raw digests; the lab has no volatile tokens)."""
    usable = lambda e: e["row"] is not None and 200 <= e["row"]["status"] < 300
    sig = lambda e: e["row"]["body_sha256"]
    names = {e["parameter"] for e in entries if e["role"] == "candidate"}
    out = {n: False for n in names}
    controls = entries[:4]
    if [e["role"] for e in controls] != ["baseline", "baseline", "control", "control"] or not all(map(usable, controls)) \
            or len({sig(e) for e in controls}) != 1:
        return out
    base, i = sig(controls[0]), 4
    while i < len(entries):
        name, samples, post = entries[i]["parameter"], [], []
        if entries[i]["role"] != "candidate":
            return {n: False for n in names}
        while i < len(entries) and len(samples) < 4 and entries[i]["role"] == "candidate" and entries[i]["parameter"] == name:
            samples.append(entries[i]); i += 1
        while i < len(entries) and len(post) < 3 and entries[i]["role"] in {"baseline", "control"}:
            post.append(entries[i]); i += 1
        ok = (len(samples) == 4 and len(post) == 3 and all(map(usable, samples + post))
              and all(text(s["row"]["body"]).count(s["value"]) <= text(controls[0]["row"]["body"]).count(s["value"]) for s in samples)
              and samples[0]["value"] == samples[1]["value"] and samples[2]["value"] == samples[3]["value"]
              and samples[0]["value"] != samples[2]["value"]
              and post[1]["value"] == samples[0]["value"] and post[2]["value"] == samples[2]["value"]
              and all(sig(p) == base for p in post)
              and sig(samples[0]) == sig(samples[1]) and sig(samples[2]) == sig(samples[3])
              and any(sig(s) != base for s in samples))
        out[name] = ok
    return out


def check_case(case):
    errors = []
    need = lambda cond, msg: None if cond else errors.append(msg)
    ev, journal = case["ev"], case["journal"]
    a, b = ev["origins"]["frontend"], ev["origins"]["gateway"]
    result = final_result(case)
    blocked = result is not None and (result.get("recovery") or {}).get("status") == "blocked"
    denied = case["access_before"] is not None and ("resume_denied.json" in case["denials"] or blocked)
    if denied:
        # Tamper cases rewrite the journal after the kill; judge what the system wrote.
        journal = case["before_journal"]
        check_head = False
    else:
        check_head = True
    previous = None
    for seq, row in enumerate(journal, 1):
        check = dict(row); claimed = check.pop("hash")
        need(row["seq"] == seq and row["previous"] == previous and digest(check) == claimed, f"journal chain broken at {seq}")
        previous = claimed
    if check_head:
        need(case["head"] == {"seq": len(journal), "hash": previous}, "journal head mismatch")
    need(SECRET not in case["raw"], "credential value persisted")
    need(len(case["access"]["unapproved"]) == 0, "unapproved origin contacted")
    need(all(r["credential_identity"] == "anonymous" for r in case["access"]["gateway"]), "credential sent to gateway")
    need(all(r["credential_identity"] == "frontend" for r in case["access"]["frontend"]), "frontend credential missing")
    reservations = [e["payload"] for e in journal if e["event"] == "reserved"]
    need([r["sequence"] for r in reservations] == list(range(1, len(reservations) + 1)), "reservation sequence gap")
    probes = [r for r in reservations if "probe" in r]
    started = {e["payload"]["sequence"] for e in journal if e["event"] == "dispatch_started"}
    measured = {e["payload"]["sequence"]: e["payload"] for e in journal if e["event"] == "measurement"}
    identities = [(r["probe"]["unit_id"], r["probe"]["ordinal"]) for r in probes]
    need(len(identities) == len(set(identities)), "probe identity reserved twice (replay)")
    units = {}
    for r in probes:
        units.setdefault((r["origin"], r["probe"]["endpoint_id"]), set()).add(r["probe"]["unit_id"])
    need(all(len(u) == 1 for u in units.values()), "endpoint measured by a second unit (replay)")
    for unit in {r["probe"]["unit_id"] for r in probes}:
        ordinals = [r["probe"]["ordinal"] for r in probes if r["probe"]["unit_id"] == unit]
        need(ordinals == list(range(1, len(ordinals) + 1)), "unit ordinals not contiguous")
    # Each server row maps, in order, to a dispatched reservation with the same URL.
    served_by_seq = {}
    for role, origin in (("frontend", a), ("gateway", b)):
        expected = [r for r in reservations if r["origin"] == origin and r["sequence"] in started]
        rows, j = case["access"][role], 0
        for row in rows:
            key = (row["path"], row["query"])
            while j < len(expected) and (urlsplit(expected[j]["url"]).path, urlsplit(expected[j]["url"]).query) != key:
                j += 1
            need(j < len(expected), f"{role}: server row without a matching dispatched reservation (replay or fabricated)")
            if j < len(expected):
                served_by_seq[expected[j]["sequence"]] = row
            j += 1
    if denied:
        # A denied resume is the only acceptable outcome of tampering: it must send nothing.
        need(case["access_before"] == case["access"], "HTTP sent after a denied resume")
        need(result is None or result.get("pipeline_status") == "failed" or "reason" in result, "denial not reported")
        return errors
    if case["before_journal"] is not None:
        old = case["before_journal"]
        need(journal[:len(old)] == old, "pre-resume journal rewritten")
        old_units = {e["payload"]["probe"]["unit_id"] for e in old if e["event"] == "reserved" and "probe" in e["payload"]}
        old_unknown = {e["payload"]["sequence"] for e in old if e["event"] == "reserved"} - \
                      {e["payload"]["sequence"] for e in old if e["event"] == "measurement"}
        for e in journal[len(old):]:
            if e["event"] == "reserved" and "probe" in e["payload"]:
                need(e["payload"]["probe"]["unit_id"] not in old_units, "unit reopened after resume (replay)")
            if e["event"] == "measurement":
                need(e["payload"]["sequence"] not in old_unknown, "outcome_unknown request measured after resume")
    if result is None:
        need(False, "no final result")
        return errors
    need(result.get("origin_execution_mode") == "not_enabled_b1", "production gate changed")
    need(result["runtime"]["http_dispatches"] == len(reservations), "runtime counter differs from reservations")
    need(result["runtime"]["http_dispatches_by_origin"] == dict(Counter(r["origin"] for r in reservations)), "per-origin counter")
    need(sum(len(v) for v in case["access"].values()) <= len(reservations), "more server rows than reservations")
    need(result["agent_statuses"].get("soft404_filter") == "skipped", "Agent 5 executed")
    by_unit = {}
    for r in probes:
        by_unit.setdefault(r["probe"]["unit_id"], []).append(r)
    for origin in (a, b):
        section = result["origin_contexts"][origin]["context"].get("parameter_discovery")
        if section is None:
            need(not any(r["origin"] == origin for r in probes), "probes without a parameter section")
            continue
        need(sorted(r["runtime_sequence"] for r in section["requests"]) == sorted(r["sequence"] for r in probes if r["origin"] == origin),
             f"{origin}: result requests differ from journal probes")
        for row in section["requests"]:
            if row["runtime_sequence"] not in measured:
                need(row.get("recovery_state") == "outcome_unknown" and row.get("status_code") is None,
                     "unknown outcome reported as measured")
        for endpoint in section["endpoints"]:
            unit = endpoint.get("unit_id")
            claims = {c["name"] for c in endpoint["candidates"] if c["verification"] == "verified"}
            if endpoint.get("unit_state") == "interrupted":
                need(not claims, "interrupted unit has a verified parameter")
            if not claims:
                continue
            rows = by_unit.get(unit, [])
            need(rows and all(r["sequence"] in measured for r in rows), "verified without complete journal measurements")
            entries = []
            for r in sorted(rows, key=lambda r: r["probe"]["ordinal"]):
                parts = urlsplit(r["url"])
                entries.append({"role": r["probe"]["role"], "parameter": r["probe"]["parameter"],
                                "value": None if r["probe"]["role"] == "baseline" else parts.query.rsplit("=", 1)[-1],
                                "row": served_by_seq.get(r["sequence"])})
            derived = derive(entries)
            for name in claims:
                need(derived.get(name) is True, f"{origin}: {name} verified but not derivable from served bodies")
    return errors


def rehash(c):
    """Consistent rewrite (attacker with full write access): semantic checks must still fail."""
    prev = None
    for n, row in enumerate(c["journal"], 1):
        row["seq"], row["previous"] = n, prev; row.pop("hash", None); row["hash"] = digest(row); prev = row["hash"]
    c["head"] = {"seq": len(c["journal"]), "hash": prev}


def mutations(case):
    def section(c, index):
        result = final_result(c)
        origin = [c["ev"]["origins"]["frontend"], c["ev"]["origins"]["gateway"]][index]
        return result["origin_contexts"][origin]["context"]["parameter_discovery"]

    def replayed_server_row(c):
        row = next(r for r in c["access"]["frontend"] if r["query"])
        c["access"]["frontend"].append(deepcopy(row))

    def verified_interrupted(c):
        for i in (0, 1):
            for e in section(c, i)["endpoints"]:
                if e.get("unit_state") == "interrupted":
                    for cand in e["candidates"]:
                        if cand["selected"]:
                            cand["verification"] = "verified"; return

    def reopened_unit(c):
        old_units = [e["payload"]["probe"]["unit_id"] for e in c["before_journal"] if e["event"] == "reserved" and "probe" in e["payload"]]
        later = next(e for e in c["journal"][len(c["before_journal"]):] if e["event"] == "reserved" and "probe" in e["payload"])
        later["payload"]["probe"]["unit_id"] = old_units[0]
        rehash(c)

    def counter_reset(c):
        final_result(c)["runtime"]["http_dispatches"] -= 1

    def laundered_unknown(c):
        for i in (0, 1):
            for row in section(c, i)["requests"]:
                if row.get("recovery_state") == "outcome_unknown":
                    row["status_code"] = 200; row["recovery_state"] = "result_persisted"; return

    def dropped_measurement(c):
        verified_units = {e["unit_id"] for i in (0, 1) for e in section(c, i)["endpoints"]
                          if any(x["verification"] == "verified" for x in e["candidates"])}
        seq = next(e["payload"]["sequence"] for e in c["journal"] if e["event"] == "reserved"
                   and e["payload"].get("probe", {}).get("unit_id") in verified_units)
        c["journal"] = [e for e in c["journal"] if not (e["event"] == "measurement" and e["payload"]["sequence"] == seq)]
        rehash(c)

    return [("replayed_server_request", replayed_server_row), ("verified_interrupted_unit", verified_interrupted),
            ("unit_reopened_after_resume", reopened_unit), ("attempt_counter_lowered", counter_reset),
            ("outcome_unknown_laundered", laundered_unknown), ("verified_unit_measurement_dropped", dropped_measurement)]


def main():
    root = Path(sys.argv[1])
    expected = int(sys.argv[sys.argv.index("--expected-cases") + 1]) if "--expected-cases" in sys.argv else None
    cases = sorted(p.parent for p in root.glob("b42a_*/evidence.json"))
    report = {"cases": [], "negative_checks": []}
    ok = bool(cases) and (expected is None or len(cases) == expected)
    loaded = {}
    for directory in cases:
        case = load_case(directory)
        loaded[directory] = case
        errors = check_case(case)
        report["cases"].append({"case_id": case["ev"]["case_id"], "test": case["ev"]["test"], "passed": not errors, "errors": errors})
        ok &= not errors
    if "--negative-checks" in sys.argv:
        base = next((c for c in loaded.values() if c["ev"]["test"] == "test_crash_after_probe_reservation_is_outcome_unknown_not_resent"), None)
        if base is None:
            ok = False; report["negative_checks"].append({"error": "base case missing"})
        else:
            for name, mutate in mutations(base):
                copy = deepcopy(base); mutate(copy)
                errors = check_case(copy)
                report["negative_checks"].append({"mutation": name, "detected": bool(errors), "first_error": errors[:1]})
                ok &= bool(errors)
    report.update(case_count=len(cases), expected_cases=expected, passed=ok)
    (root / "independent_verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"case_count": len(cases), "passed": ok,
                      "failed_cases": [c["test"] for c in report["cases"] if not c["passed"]],
                      "negative_checks": [(n["mutation"], n["detected"], n["first_error"]) for n in report["negative_checks"] if "mutation" in n]}, indent=1))
    for c in report["cases"]:
        for e in c["errors"][:4]:
            print("ERROR", c["test"], e)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
