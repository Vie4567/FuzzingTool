"""Independent B4.2C verifier: full local graph (Agents 1-5, Report, Reflection) evidence.

Stdlib only; never imports `src`. Re-derives from raw evidence: the journal hash chain and head,
checkpoint sha256 anchors, independent server access logs, the Report digest (own canonical rule),
Reflection backing, per-origin isolation, totals, status rules, Agent 4 verdicts from served bodies,
zero-HTTP finalize/already_finished and counters that never decrease. `--negative-checks` corrupts
in-memory copies of loaded evidence and requires every mutation to be detected.

Usage: verify_origin_full_graph_evidence.py <evidence_dir> [--expected-cases N] [--negative-checks]
"""
import argparse
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

AGENTS = ("tech_recon", "wordlist_gen", "fuzzing", "param_disc", "soft404_filter")
SECRETS = ("b42b-local-only-fake",)
STRONG = {"genuine_distinct", "soft_404", "http_404"}


class Failure(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Failure(message)


def canonical(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                             allow_nan=False).encode()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lines(path):
    path = Path(path)
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()] if path.exists() else []


def origin_of(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def resolve(content, path):
    value = content
    for part in path.replace("]", "").split("."):
        name, *indexes = part.split("[")
        if name:
            value = value[name]
        for index in indexes:
            value = value[int(index)]
    return value


# ── loading ──

def load_case(directory):
    evidence = read(directory / "evidence.json")
    case = {"dir": directory, "evidence": evidence, "expect": evidence.get("expect") or {}}
    labels = [p["label"] for p in evidence.get("process_events", []) if "label" in p]
    results = {Path(p).name.split("_result.json")[0]: read(p) for p in evidence.get("results", [])}
    denials = {Path(p).name.split("_denied.json")[0]: read(p) for p in evidence.get("denials", [])}
    order = [l for l in labels if l in results] or sorted(results)
    case["results"], case["denials"] = results, denials
    case["final"] = results[order[-1]] if order else None
    case["final_label"] = order[-1] if order else None
    case["access"] = {role: lines(path) for role, path in evidence.get("access_files", {}).items()}
    journal_path = directory / "recovery" / "journal.jsonl"
    case["journal_raw"] = journal_path.read_bytes() if journal_path.exists() else None
    case["journal"] = lines(journal_path)
    case["head"] = read(directory / "recovery" / "head.json") if (directory / "recovery" / "head.json").exists() else None
    before = directory / "recovery_before_resume" / "journal.jsonl"
    case["journal_before_raw"] = before.read_bytes() if before.exists() else None
    case["journal_before"] = lines(before)
    snapshot = directory / "access_before_resume.json"
    case["access_before"] = read(snapshot) if snapshot.exists() else None
    case["checkpoints"] = []
    for row in case["journal"]:
        if row["event"] == "checkpoint":
            path = Path(row["payload"]["path"])
            raw = path.read_bytes() if path.exists() else b""
            case["checkpoints"].append((row["payload"], raw, json.loads(raw) if raw else None))
    return case


# ── checks (each takes a possibly-mutated case) ──

def check_journal(case):
    previous = None
    for seq, row in enumerate(case["journal"], 1):
        body = {k: v for k, v in row.items() if k != "hash"}
        need(row["seq"] == seq and row["previous"] == previous and canonical(body) == row["hash"], f"journal row {seq} broken")
        previous = row["hash"]
    if case["journal"]:
        need(case["head"] == {"seq": len(case["journal"]), "hash": previous}, "head does not anchor the journal")
    broken = [payload["node"] for payload, raw, _ in case["checkpoints"] if sha256(raw).hexdigest() != payload["sha256"]]
    tampered = case["expect"].get("tampered_checkpoint")
    if tampered:
        # The case corrupted one anchored checkpoint on purpose: the anchor must expose it.
        need(broken == [tampered], f"deliberately tampered checkpoint not exposed ({broken})")
    else:
        need(not broken, f"checkpoint {broken} sha256 mismatch")


def reservations(case, rows=None):
    return [e["payload"] for e in (case["journal"] if rows is None else rows) if e["event"] == "reserved"]


def check_scope_and_accounting(case):
    evidence, final = case["evidence"], case["final"]
    origins = evidence["origins"]
    need(not case["access"].get("unapproved"), "unapproved origin received HTTP")
    need(all(r["credential_identity"] == "frontend" for r in case["access"].get("frontend", [])), "frontend credential mismatch")
    need(all(r["credential_identity"] == "anonymous" for r in case["access"].get("gateway", [])), "credential crossed origins")
    texts = [json.dumps(final or {})] + [raw.decode("utf-8", "replace") for _, raw, _ in case["checkpoints"]]
    texts.append((case["journal_raw"] or b"").decode("utf-8", "replace"))
    need(not any(s in t for s in SECRETS for t in texts), "credential value persisted")
    rows = reservations(case)
    started = {e["payload"]["sequence"] for e in case["journal"] if e["event"] == "dispatch_started"}
    sent = Counter((r["origin"], urlsplit(r["url"]).path, urlsplit(r["url"]).query) for r in rows if r["sequence"] in started)
    for role in ("frontend", "gateway"):
        seen = Counter((origins[role], r["path"], r["query"]) for r in case["access"].get(role, []))
        need(all(n <= sent.get(k, 0) for k, n in seen.items()), f"{role}: server saw a request without a started reservation")
    if final is None or case["legacy"] or case["denied_only"]:
        return
    need(final["runtime"]["http_dispatches"] == len(rows), "runtime counter differs from journal reservations")
    need(final["runtime"]["http_dispatches_by_origin"] == dict(Counter(r["origin"] for r in rows)), "per-origin counter mismatch")
    if case["evidence"]["kind"] == "run":
        need(sum(len(case["access"].get(r, [])) for r in ("frontend", "gateway")) == len(rows), "server rows != reservations")
    need(final.get("origin_execution_mode") == "not_enabled_b1", "production gate changed")
    for key in ("fuzzing_execution", "parameter_execution", "soft404_execution"):
        section = (final.get(key) or {}).get("multi_origin")
        if section:
            need(section.get("full_multi_origin_execution_enabled") is False, f"{key} claims full execution")
    bound = [e["payload"]["reservations"] for e in case["journal"] if e["event"] == "process_bound"]
    need(bound == sorted(bound), "reservation counter decreased across processes")
    if case["journal_before"]:
        need(final["runtime"]["http_dispatches"] >= len(reservations(case, case["journal_before"])), "counter reset after resume")
    for key in ("probe", "soft404"):
        ids = [(r[key]["unit_id"], r[key]["ordinal"]) for r in rows if key in r]
        need(len(ids) == len(set(ids)), f"{key} reservation replayed")
    cands = [(r["origin"], r["candidate_id"]) for r in rows if r.get("candidate_id")]
    need(len(cands) == len(set(cands)), "Agent 3 candidate replayed")


def check_decisions(case):
    chain = case["final"]["decision_chain"]
    points = [d["decision_point"] for d in chain]
    need(len(points) == len(set(points)), "duplicate decision records")
    need(all(d.get("source") == "deterministic_local_test_policy" and d.get("llm_called") is False for d in chain),
         "non-deterministic or LLM decision")


def anchored_section(case, origin, key):
    for payload, _, saved in reversed(case["checkpoints"]):
        section = (((saved or {}).get("origin_contexts") or {}).get(origin) or {}).get("context") or {}
        if key in section:
            return section[key]
    return None


def check_report(case):
    final = case["final"]
    report, reflection = final["multi_origin_report"], final["local_reflection"]
    content = report["content"]
    need(canonical(content) == report["digest"], "report digest does not match content")
    need(reflection["report_digest"] == report["digest"], "reflection is bound to another report")
    need((reflection["knowledge_writes"], reflection["lessons"], reflection["llm_called"]) == (0, [], False),
         "reflection wrote knowledge or used an LLM")
    for row in reflection["observations"]:
        try:
            value = resolve(content, row["report_path"])
        except (KeyError, IndexError, ValueError, TypeError):
            raise Failure(f"reflection observation {row['id']} has no report evidence") from None
        need(value == row["value"], f"reflection observation {row['id']} disagrees with the report")
    approved = case["evidence"]["settings_public"]["config"]["multi_origin"]["approved_origins"]
    need([o["origin"] for o in content["approved_origins"]] == approved, "approved origin list changed")
    unapproved = case["evidence"]["origins"]["unapproved"]
    discovered = {o["origin"]: o for o in content["discovered_only_origins"]}
    need(unapproved in discovered, "discovered-only origin missing")
    need(all(o["executed"] is False and o["dispatch_attempts"] == 0 and o["status"] == "not_applicable"
             for o in discovered.values()), "discovered-only origin counted as executed")
    totals = Counter()
    for origin in content["approved_origins"]:
        name = origin["origin"]
        for key, source_key in (("parameters", "parameter_discovery"), ("soft404", "soft404")):
            section = origin.get(key)
            anchored = anchored_section(case, name, source_key)
            for row in (section or {}).get("endpoints", []):
                need(origin_of(row["url"]) == name, f"{key} endpoint {row['url']} reported under {name}")
                source = next((e for e in (anchored or {}).get("endpoints", []) if e["endpoint_id"] == row["endpoint_id"]), None)
                need(source is not None, f"{key} endpoint without anchored source")
                if key == "soft404":
                    need((row["soft404_classification"], row["evidence_level"], row["unit_state"]) ==
                         (source["soft404_classification"], source["evidence_level"], source["unit_state"]),
                         f"soft404 class/evidence level differs from the anchored checkpoint ({row['url']})")
                    need(row["verification_status"] == "not_verified", "endpoint promoted to verified")
                    need((row.get("parameter_context") or {}).get("authority") == "context_only", "parameter context became authority")
                    totals["soft404_" + str(row["soft404_classification"])] += 1
                    totals["soft404_strong"] += row["soft404_classification"] in STRONG
                else:
                    need(row["endpoint_verification_status"] == "not_verified", "parameter endpoint promoted")
                    claims = {c["name"]: c["verification"] for c in row["candidates"]}
                    need(claims == {c["name"]: c["verification"] for c in source["candidates"]}, "parameter verdict differs from anchor")
                    totals["verified_parameters"] += sum(v == "verified" for v in claims.values())
                totals["interrupted_units"] += row.get("unit_state") == "interrupted"
        totals["outcome_unknown"] += len(origin["outcome_unknown_sequences"])
    for key in ("soft404_strong", "soft404_http_404", "soft404_soft_404", "soft404_genuine_distinct", "soft404_inconclusive",
                "interrupted_units", "outcome_unknown", "verified_parameters"):
        need(content["totals"][key] == totals[key], f"report total {key} is not the sum of origin sections")
    need(content["gate"] == {"origin_execution_mode": "not_enabled_b1", "full_multi_origin_execution_enabled": False},
         "report gate changed")


def check_status(case):
    final, expect = case["final"], case["expect"]
    content = final["multi_origin_report"]["content"]
    statuses = final["agent_statuses"]
    need({a: content["agents"][a]["status"] for a in AGENTS} == {a: statuses[a] for a in AGENTS}, "agent status != report")
    if final["pipeline_status"] == "completed":
        need(all(statuses[a] == "success" for a in AGENTS) and final["all_modules_executed"] and final["all_modules_successful"],
             "completed without five successful Agents")
        need(all(o["status"] == "completed" for o in content["approved_origins"]), "completed with an incomplete origin")
        need(content["totals"]["outcome_unknown"] == 0 and content["totals"]["interrupted_units"] == 0,
             "completed with unknown or interrupted work")
        need(content["stop"]["global_stop_reason"] is None and not content["stop"]["contract_failures"], "completed after a stop")
        need(not (final.get("recovery") or {}).get("finalize_only"), "finalize_only reported completed")
        need(final["local_reflection"]["status"] == "completed", "completed before Reflection")
    if final["all_modules_successful"]:
        need(final["all_modules_executed"], "successful without executed")
    if "pipeline_status" in expect:
        need(final["pipeline_status"] == expect["pipeline_status"], "pipeline status differs from the case expectation")


def check_agent_http(case):
    origins, rows = case["evidence"]["origins"], reservations(case)
    for role in ("frontend", "gateway"):
        access = case["access"].get(role, [])
        need(any(r["query"] and "__sentinel_missing_" not in r["path"] for r in access), f"{role}: no Agent 4 probe at server")
        need(any("__sentinel_missing_" in r["path"] for r in access), f"{role}: no Agent 5 control at server")
        for phase in ("param_disc", "soft404_filter"):
            need(any(r["phase"] == phase and r["origin"] == origins[role] for r in rows), f"{role}: no {phase} reservation")


def check_verdicts(case):
    final, origins = case["final"], case["evidence"]["origins"]
    role_of = {v: k for k, v in origins.items()}
    expected = case["evidence"].get("expected_verdicts") or {}
    for key, verdict in expected.items():
        url, name = key.rsplit("?", 1)
        origin, path = origin_of(url), urlsplit(url).path
        section = final["origin_contexts"][origin]["context"]["parameter_discovery"]
        endpoint = next(e for e in section["endpoints"] if urlsplit(e["url"]).path == path)
        claim = next(c for c in endpoint["candidates"] if c["name"] == name)
        need(("verified" if claim["verification"] == "verified" else "not_verified") == verdict, f"verdict {key}")
        if claim["verification"] == "verified":
            access = case["access"][role_of[origin]]
            plain = {r["body_sha256"] for r in access if r["path"] == path and not r["query"]}
            probed = {r["body_sha256"] for r in access if r["path"] == path and r["query"].startswith(name + "=")}
            need(plain and probed and not probed & plain, f"{key}: server bodies do not show a parameter effect")
    for key, (cls, level) in (case["evidence"].get("expected_classes") or {}).items():
        origin = origin_of(key)
        endpoint = next(e for e in final["origin_contexts"][origin]["context"]["soft404"]["endpoints"]
                        if urlsplit(e["url"]).path == (urlsplit(key).path or "/"))
        if endpoint.get("unit_state") != "interrupted":
            need((endpoint["soft404_classification"], endpoint["evidence_level"]) == (cls, level), f"soft404 class {key}")


def check_recovery(case):
    expect, final = case["expect"], case["final"]
    if expect.get("zero_http_after_resume") or expect.get("already_finished") or expect.get("denied"):
        before = case["access_before"] or {}
        need({k: len(v) for k, v in before.items()} == {k: len(v) for k, v in case["access"].items()},
             "HTTP after the crash point")
    if expect.get("already_finished"):
        need(case["journal_raw"] == case["journal_before_raw"], "already_finished appended to the journal")
        need(final["recovery"]["status"] == "already_finished" and final["recovery"]["graph_invoked"] is False,
             "already_finished re-executed")
    if expect.get("finalize_only"):
        rows = case["journal"]
        marks = [i for i, e in enumerate(rows) if e["event"] == "process_bound" and e["payload"].get("finalize_only")]
        need(marks, "finalize process not journaled")
        end = next((i for i in range(marks[0], len(rows)) if rows[i]["event"] == "session_finished"), len(rows))
        need(not any(e["event"] == "reserved" for e in rows[marks[0]:end]), "finalize reserved a request")
        need(final["pipeline_status"] != "completed", "finalize reported completed")
    if expect.get("denied"):
        text = json.dumps(list(case["denials"].values()) + list(case["results"].values()))
        need(expect["denied"] in text, "expected denial code missing")
    if expect.get("report_digest"):
        need(final["multi_origin_report"]["digest"] == expect["report_digest"], "report digest changed across resume")


def verify(case):
    check_journal(case)
    final = case["final"]
    if case["legacy"]:
        # Three legacy-mode runs share one access log; each result is checked on its own.
        need(not case["access"].get("unapproved"), "unapproved origin received HTTP")
        for path in case["expect"]["legacy_results"]:
            result = read(path)
            need(result["pipeline_status"] != "completed" and not result["all_modules_executed"], "legacy mode completed")
            need(result["origin_execution_mode"] == "not_enabled_b1", "production gate changed")
            need("graph_integration" not in result["local_origin_execution"], "legacy mode labelled as full graph")
        return
    check_scope_and_accounting(case)
    if case["denied_only"]:
        check_recovery(case)
        return
    if case["expect"].get("unmasked_error"):
        need(final["pipeline_status"] == "failed" and "multi_origin_report" not in final, "programming error masked")
        return
    check_decisions(case)
    check_report(case)
    check_status(case)
    if case["expect"].get("agent4_and_agent5_http"):
        check_agent_http(case)
    if final["pipeline_status"] == "completed":
        check_verdicts(case)
    check_recovery(case)


# ── negative mutations on in-memory copies ──

def _rebind(final):
    report = final["multi_origin_report"]
    report["digest"] = canonical(report["content"])
    final["local_reflection"]["report_digest"] = report["digest"]
    for row in final["local_reflection"]["observations"]:
        row["value"] = resolve(report["content"], row["report_path"])


def m_origin_merged(case):
    origins = case["final"]["multi_origin_report"]["content"]["approved_origins"]
    origins[0]["soft404"]["endpoints"].append(origins[1]["soft404"]["endpoints"].pop(0)); _rebind(case["final"])


def m_count_inflated(case):
    case["final"]["multi_origin_report"]["content"]["totals"]["soft404_strong"] += 1; _rebind(case["final"])


def m_decision_duplicated(case):
    chain = case["final"]["decision_chain"]; chain.append(deepcopy(chain[0]))


def m_unbacked_observation(case):
    case["final"]["local_reflection"]["observations"].append(
        {"id": "obs-999", "kind": "lesson", "report_path": "totals.verified_parameters", "value": 999})


def m_status_upgraded(case):
    case["final"].update(pipeline_status="completed", all_modules_executed=True, all_modules_successful=True)


def m_evidence_level_upgraded(case):
    for origin in case["final"]["multi_origin_report"]["content"]["approved_origins"]:
        for row in (origin["soft404"] or {}).get("endpoints", []):
            if row["evidence_level"] == "metrics_journaled":
                row["evidence_level"] = "rederived"; _rebind(case["final"]); return
    raise Failure("no metrics_journaled row to mutate")


def m_counter_reset(case):
    rows = case["journal"]
    last = max(i for i, e in enumerate(rows) if e["event"] == "process_bound")
    case["final"]["runtime"]["http_dispatches"] = sum(e["event"] == "reserved" for e in rows[last:])


def m_parameter_promotes(case):
    for origin in case["final"]["multi_origin_report"]["content"]["approved_origins"]:
        for row in (origin["soft404"] or {}).get("endpoints", []):
            if (row.get("parameter_context") or {}).get("verified_parameters"):
                row["verification_status"] = "verified"; _rebind(case["final"]); return
    raise Failure("no endpoint with a verified parameter")


def negative_checks(cases):
    by_test = {c["evidence"]["test"]: c for c in cases}
    full = by_test.get("test_full_graph_five_agents_report_reflection")
    partial = by_test.get("test_crash_in_agent4_marks_unit_interrupted_never_resent")
    resumed = by_test.get("test_crash_after_agent4_checkpoint_reuses_agent4")
    plan = [("report_origin_merged", full, m_origin_merged), ("report_count_inflated", full, m_count_inflated),
            ("decision_duplicated", full, m_decision_duplicated), ("reflection_unbacked_observation", full, m_unbacked_observation),
            ("status_upgraded_completed", partial, m_status_upgraded), ("evidence_level_upgraded", full, m_evidence_level_upgraded),
            ("counter_reset_after_resume", resumed, m_counter_reset), ("parameter_promotes_endpoint", full, m_parameter_promotes)]
    out = []
    for name, case, mutate in plan:
        if case is None:
            out.append([name, False, ["source case missing"]]); continue
        copy = deepcopy(case)
        try:
            mutate(copy)
            verify(copy)
            out.append([name, False, ["mutation not detected"]])
        except Failure as exc:
            out.append([name, True, [str(exc)]])
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--expected-cases", type=int)
    parser.add_argument("--negative-checks", action="store_true")
    args = parser.parse_args()
    root = Path(args.directory)
    cases, failed = [], []
    for path in sorted(p.parent for p in root.rglob("evidence.json")):
        case = load_case(path)
        case["legacy"] = "legacy_traces" in case["expect"]
        case["denied_only"] = bool(case["expect"].get("denied")) and not case["expect"].get("finalize_only")
        try:
            verify(case)
            cases.append(case)
        except (Failure, KeyError, TypeError, StopIteration) as exc:
            failed.append({"case": path.name, "test": case["evidence"].get("test"), "error": f"{type(exc).__name__}: {exc}"})
            cases.append(case)
    summary = {"case_count": len(cases), "passed": not failed, "failed_cases": failed,
               "tests": sorted(c["evidence"]["test"] for c in cases),
               "verification_level": "integration_verified", "live_verification": "not_verified"}
    if args.expected_cases is not None and len(cases) != args.expected_cases:
        summary["passed"] = False
        summary["failed_cases"].append({"error": f"expected {args.expected_cases} cases, found {len(cases)}"})
    if args.negative_checks:
        summary["negative_checks"] = negative_checks([c for c in cases if c["final"] is not None])
        summary["passed"] = summary["passed"] and all(row[1] for row in summary["negative_checks"])
    text = json.dumps(summary, indent=1, ensure_ascii=False)
    print(text)
    (root / "independent_verification.json").write_text(text, encoding="utf-8")
    sys.exit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
