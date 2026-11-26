"""Independent B5 verifier: offline multi-origin report export evidence.

Stdlib only; never imports `src`. For every exported case it re-derives from raw evidence: the journal
hash chain and head, checkpoint sha256 anchors, the final checkpoint sealed by `session_finished`, the
Report v1 digest (own canonical rule) and its verbatim copy, journal accounting (global, origin, phase,
kind; Recon included), server arrivals from the independent lab access logs (per origin:
response_headers <= arrivals <= dispatch_started; the export itself never claims receipt), per-origin
endpoint identity, method/query variants and provenance against the final checkpoint, parameter and
Soft404 classes and evidence basis, discovered-only origins, severity, secrets and absolute paths, the
export digest and manifest, and every Markdown table cell against the JSON path it names.

Refusals (a case may be refusal-only): each must carry recorded refusal evidence (`outcome`) equal to
its expected public code; the verifier independently re-derives the ineligibility reason from the raw
source (journal presence, hash chain/head, `session_finished`, checkpoint hashes recorded at refusal time
against the journal anchors, report digest) and requires the same code; a session it finds eligible is a
false refusal. No output or pending directory may exist and the source must be unchanged. A case with
neither an export nor a refusal fails. `--negative-checks` corrupts in-memory copies (re-sealing
digests/manifests so only semantic checks can catch them) and requires every detection.

Usage: verify_origin_report_evidence.py <evidence_dir> [--expected-cases N] [--negative-checks]
"""
import argparse
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

SECRETS = ("b42b-local-only-fake", "b5-local-only-fake")
KEYS = ("reserved", "dispatch_started", "response_headers", "measured", "measured_with_error", "timeouts",
        "incomplete_bodies", "attempt_unknown", "outcome_unknown")
STRONG = {"genuine_distinct", "soft_404", "http_404"}
UNKNOWN, ABSENT = "không xác định", "—"


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


def origin_of(url):
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def ident(url, method):
    return sha256((url + "\n" + (method or "")).encode()).hexdigest()[:24]


# ── loading ──

def load_row(row):
    # A refusal may carry a snapshot of journal/head taken when it was judged (a later resume appends).
    current = Path(row["recovery_dir"]) / "journal.jsonl"
    recovery = Path(row.get("source_snapshot") or row["recovery_dir"])
    art = {"row": row, "journal_raw": None, "journal": [], "head": None, "head_raw": None, "checkpoints": [],
           "current_journal_raw": current.read_bytes() if current.is_file() else None}
    if (recovery / "journal.jsonl").is_file():
        art["journal_raw"] = (recovery / "journal.jsonl").read_bytes()
        try:
            art["journal"] = [json.loads(l) for l in art["journal_raw"].decode("utf-8").splitlines() if l.strip()]
        except ValueError:
            art["journal"] = None  # unparseable journal: refusal reason export_journal_invalid
    if (recovery / "head.json").is_file():
        art["head_raw"] = (recovery / "head.json").read_bytes()
        try:
            art["head"] = json.loads(art["head_raw"])
        except ValueError:
            art["head"] = None
    for event in art["journal"] or []:
        if isinstance(event, dict) and event.get("event") == "checkpoint":
            path = Path(event["payload"]["path"])
            raw = path.read_bytes() if path.exists() else b""
            art["checkpoints"].append({"payload": event["payload"], "seq": event["seq"], "raw": raw, "path": path})
    out = Path(row["output_dir"])
    art["output_exists"] = out.exists()
    art["pending"] = list(out.parent.glob(".pending_export_*")) if out.parent.exists() else []
    if row["expect"] == "exported" and out.exists():
        art["json_bytes"] = (out / "report.json").read_bytes()
        art["md_bytes"] = (out / "report.md").read_bytes()
        art["manifest_bytes"] = (out / "manifest.json").read_bytes()
        art["env"] = json.loads(art["json_bytes"])
        art["md"] = art["md_bytes"].decode("utf-8")
        art["manifest"] = json.loads(art["manifest_bytes"])
    return art


def load_case(directory):
    evidence = read(directory / "evidence.json")
    b5 = read(directory / "b5_evidence.json")
    access = {}
    for role, path in evidence.get("access_files", {}).items():
        p = Path(path)
        access[role] = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []
    return {"dir": directory, "evidence": evidence, "b5": b5, "access": access,
            "rows": [load_row(row) for row in b5["exports"]]}


# ── journal re-derivation ──

def check_journal(art):
    previous = None
    for seq, row in enumerate(art["journal"], 1):
        body = {k: v for k, v in row.items() if k != "hash"}
        need(row["seq"] == seq and row["previous"] == previous and canonical(body) == row["hash"], f"journal row {seq} broken")
        previous = row["hash"]
    need(art["head"] == {"seq": len(art["journal"]), "hash": previous}, "head does not anchor the journal")
    for cp in art["checkpoints"]:
        need(sha256(cp["raw"]).hexdigest() == cp["payload"]["sha256"], f"checkpoint {cp['payload']['node']} sha256 mismatch")


def kind_of(reservation):
    if reservation.get("probe") is not None:
        return "parameter_probe"
    if reservation.get("soft404") is not None:
        return "soft404_probe"
    return "dispatch" if reservation.get("candidate_id") is not None else "recon"


def derive(journal):
    reservations = [e["payload"] for e in journal if e["event"] == "reserved"]
    starts, heads, measures = {}, {}, {}
    for e in journal:
        dest = {"dispatch_started": starts, "response_headers": heads, "measurement": measures}.get(e["event"])
        if dest is not None:
            need(e["payload"]["sequence"] not in dest, "duplicate request event")
            dest[e["payload"]["sequence"]] = e["payload"]
    rows = []
    for seq, r in enumerate(reservations, 1):
        need(r["sequence"] == seq, "reservation sequence gap")
        m = measures.get(seq)
        error = (m or {}).get("error") or {}
        rows.append({"sequence": seq, "origin": r["origin"], "phase": str(r.get("phase")), "kind": kind_of(r),
                     "url": r["url"], "candidate_id": r.get("candidate_id"),
                     "flags": {"reserved": True, "dispatch_started": seq in starts, "response_headers": seq in heads,
                               "measured": m is not None, "measured_with_error": bool(m and m.get("error")),
                               "timeouts": "timeout" in str(error.get("exception_type") or "").lower(),
                               "incomplete_bodies": bool(m and m.get("status_code") is not None and m.get("body_complete") is False),
                               "attempt_unknown": seq not in starts, "outcome_unknown": m is None}})
    return rows


def bucket(rows):
    return {k: sum(1 for r in rows if r["flags"][k]) for k in KEYS}


# ── Markdown, independently re-rendered ──

def md_code(text):
    text = str(text).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    run = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (run + 1)
    pad = " " if text.startswith(("`", " ")) or text.endswith(("`", " ")) or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def md_cell(value):
    if value is None:
        return UNKNOWN
    if value is True or value is False:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        return json.dumps(value)
    if isinstance(value, str):
        return md_code(value)
    return md_code(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def lookup(env, path):
    value = env
    for part in path.replace("]", "").split("."):
        name, *indexes = part.split("[")
        if value is None:
            return ABSENT
        if name:
            need(isinstance(value, dict) and name in value, f"markdown names a missing JSON path {path}")
            value = value[name]
        for index in indexes:
            if value is None:
                return ABSENT
            need(isinstance(value, list) and int(index) < len(value), f"markdown names a missing JSON path {path}")
            value = value[int(index)]
    return value


def render(env, path):
    value = lookup(env, path)
    return ABSENT if value is ABSENT else md_cell(value)


def unspan(cell):
    m = re.fullmatch(r"(`+) ?(.*?) ?\1", cell)
    need(m is not None, f"markdown cell is not a code span: {cell[:60]}")
    return m.group(2).replace("\\|", "|")


def split_row(line):
    return [c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]]


def check_markdown(env, md):
    lines, paths, checked = md.splitlines(), set(), 0
    i = 0
    while i < len(lines):
        if not lines[i].startswith("|"):
            i += 1
            continue
        header = split_row(lines[i])
        need(i + 1 < len(lines) and re.fullmatch(r"\|(---\|)+", lines[i + 1]), "malformed markdown table")
        i += 2
        while i < len(lines) and lines[i].startswith("|"):
            cells = split_row(lines[i])
            need(len(cells) == len(header), "markdown row has a different column count")
            if header == ["Trường", "Giá trị", "Nguồn"]:
                path = unspan(cells[2])
                need(cells[1] == render(env, path), f"markdown value differs from JSON at {path}")
                paths.add(path); checked += 1
            elif header[0] == "JSON path":
                path = unspan(cells[0])
                paths.add(path)
                for key, cell in zip(header[1:], cells[1:]):
                    need(cell == render(env, f"{path}.{unspan(key)}"), f"markdown cell differs from JSON at {path}.{unspan(key)}")
                    checked += 1
            else:
                raise Failure("markdown table without JSON-path backing")
            i += 1
    for o, origin in enumerate(env["origins"]):
        for j, row in enumerate(origin["endpoints"]):
            need(f"origins[{o}].endpoints[{j}]" in paths, "markdown dropped an endpoint row")
            if row["soft404"]:
                need(f"origins[{o}].endpoints[{j}].soft404" in paths, "markdown dropped a soft404 row")
            for k, _ in enumerate((row["parameters"] or {}).get("candidates", [])):
                need(f"origins[{o}].endpoints[{j}].parameters.candidates[{k}]" in paths, "markdown dropped a parameter row")
    for name in ("by_phase", "by_origin"):
        for k, _ in enumerate(env["accounting"][name]):
            need(f"accounting.{name}[{k}]" in paths, f"markdown dropped accounting.{name} row")
    need("accounting.total" in paths and checked > 50, "markdown accounting not backed")
    outside = re.sub(r"(`+)(?:(?!\1).)*?\1", "", md)
    need(not re.search(r"(?<!\\)<", outside) and "](" not in outside, "markdown contains raw HTML or a link outside code spans")
    return checked


# ── export checks ──

def walk(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield f"{path}.{k}" if path else k, k, v
            yield from walk(v, f"{path}.{k}" if path else k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}[{i}]")


def check_exported(case, art, *, markdown=True):
    env, row = art["env"], art["row"]
    check_journal(art)
    journal = art["journal"]
    need(journal[-1]["event"] == "session_finished" and journal[-2]["event"] == "checkpoint", "export from an unfinished session")
    final_cp = art["checkpoints"][-1]
    need(final_cp["seq"] == journal[-2]["seq"] and final_cp["payload"]["node"] == "pipeline", "final checkpoint is not sealed")
    final = json.loads(final_cp["raw"])
    report = final["multi_origin_report"]
    need(canonical(report["content"]) == report["digest"], "final report digest does not match its content")
    # manifest and export digest
    need(art["manifest"]["files"]["report.json"] == sha256(art["json_bytes"]).hexdigest(), "manifest does not seal report.json")
    need(art["manifest"]["files"]["report.md"] == sha256(art["md_bytes"]).hexdigest(), "manifest does not seal report.md")
    body = {k: v for k, v in env.items() if k not in ("export_digest", "export_meta")}
    need(canonical(body) == env["export_digest"] == art["manifest"]["export_digest"], "export digest mismatch")
    need(set(env.get("export_meta", {})) <= {"generated_at_utc", "nondeterministic_fields"}, "undeclared nondeterministic metadata")
    # source binding
    src = env["source"]
    need(src["journal_head_hash"] == journal[-1]["hash"], "export bound to another journal")
    need(src["final_checkpoint_sha256"] == final_cp["payload"]["sha256"], "export bound to another final checkpoint")
    need(src["report_digest"] == report["digest"] == env["report_v1"]["digest"] == art["manifest"]["report_digest"],
         "export bound to another report")
    need(env["report_v1"]["content"] == report["content"], "Report v1 content was changed by the export")
    need(src["session_id"] == final["session_id"] == journal[0]["payload"]["session_id"], "session identity mismatch")
    # read-only
    current = {"journal.jsonl": sha256(art["journal_raw"]).hexdigest()}
    need(row["source_sha256_before"] == row["source_sha256_after"], "export changed its source")
    need(row["source_sha256_before"].get("journal.jsonl") == current["journal.jsonl"], "journal changed after export")
    for cp in art["checkpoints"]:
        key = next((k for k in row["source_sha256_before"] if cp["path"].as_posix().endswith(k)), None)
        need(key is not None and row["source_sha256_before"][key] == sha256(cp["raw"]).hexdigest(), "checkpoint changed after export")
    need(row["server_rows_before_export"] == row["server_rows_after_export"], "export sent HTTP")
    # accounting re-derived from the journal
    rows = derive(journal)
    acc = env["accounting"]
    need(acc["total"] == bucket(rows), "accounting total differs from journal")
    phases = sorted({r["phase"] for r in rows})
    need([p["phase"] for p in acc["by_phase"]] == phases, "accounting phases differ from journal")
    for p in acc["by_phase"]:
        need({k: p[k] for k in KEYS} == bucket([r for r in rows if r["phase"] == p["phase"]]), f"phase {p['phase']} differs")
    for k in acc["by_kind"]:
        need({x: k[x] for x in KEYS} == bucket([r for r in rows if r["kind"] == k["kind"]]), f"kind {k['kind']} differs")
    recon = [r for r in rows if r["kind"] == "recon"]
    need(not recon or next(k for k in acc["by_kind"] if k["kind"] == "recon")["reserved"] == len(recon) > 0, "Recon HTTP missing")
    need(acc["unknown_sequences"]["outcome_unknown"] == [r["sequence"] for r in rows if r["flags"]["outcome_unknown"]],
         "outcome_unknown sequences differ")
    need(acc["unknown_sequences"]["attempt_unknown"] == [r["sequence"] for r in rows if r["flags"]["attempt_unknown"]],
         "attempt_unknown sequences differ")
    need(acc["runtime"]["http_dispatches"] == len(rows) == final["runtime"]["http_dispatches"], "runtime counter differs")
    tel = final["telemetry"]["http"]
    need(acc["telemetry_http"]["total_requests"] == tel["total_requests"], "telemetry total changed")
    if tel["count_complete"] is False:
        need(acc["telemetry_http"]["total_requests"] is None, "unknown telemetry reported as a number")
    if any(r["flags"]["outcome_unknown"] for r in rows):
        need(acc["total"]["outcome_unknown"] > 0, "unknown outcome reported as zero")
    approved = final["approved_origins"]
    need([o["origin"] for o in env["origins"]] == approved, "approved origin list changed")
    need([o["origin"] for o in acc["by_origin"]] == approved, "accounting origins changed")
    roles = {v: k for k, v in case["evidence"].get("origins", {}).items()}
    need(not case["access"].get("unapproved"), "unapproved origin received HTTP")
    for o in acc["by_origin"]:
        mine = [r for r in rows if r["origin"] == o["origin"]]
        need({k: o[k] for k in KEYS} == bucket(mine), f"origin accounting differs for {o['origin']}")
        arrivals = case["access"].get(roles.get(o["origin"]), [])
        b = bucket(mine)
        need(b["response_headers"] <= len(arrivals) <= b["dispatch_started"],
             f"{o['origin']}: server arrivals {len(arrivals)} outside [response_headers, dispatch_started]")
        sent = Counter((urlsplit(r["url"]).path, urlsplit(r["url"]).query) for r in mine if r["flags"]["dispatch_started"])
        for key, n in Counter((a["path"], a["query"]) for a in arrivals).items():
            need(n <= sent.get(key, 0), f"{o['origin']}: server arrival without a started reservation")
    for b in env["budget"]["by_origin"]:
        need(b["reserved"] == sum(r["origin"] == b["origin"] for r in rows)
             and b["limit"] == final["runtime"]["http_origin_max_requests"][b["origin"]], "budget differs")
    # per-origin endpoints vs the final checkpoint
    content = report["content"]
    seq_of = {r["sequence"]: r for r in rows}
    for index, origin in enumerate(env["origins"]):
        name = origin["origin"]
        entry = final["origin_contexts"][name]
        context = entry.get("context") or {}
        for e in origin["endpoints"]:
            need(origin_of(e["url"]) == name, f"{e['url']} reported under {name}")
        ids = [e["endpoint_id"] for e in origin["endpoints"]]
        need(len(ids) == len(set(ids)), f"{name}: endpoint counted twice")
        need(origin["endpoint_index"]["endpoints"] == len(ids), f"{name}: endpoint count differs from rows")
        expected = [e["endpoint_id"] for e in entry.get("endpoints", [])]
        linked = {r.get("candidate_id") for r in (context.get("http_dispatch") or {}).get("records", [])} | \
            {e["endpoint_id"] for k in ("parameter_discovery", "soft404") for e in (context.get(k) or {}).get("endpoints", [])}
        need(set(ids) == set(expected) | linked, f"{name}: endpoint set differs from the checkpoint (variant merged or dropped)")
        source = {e["endpoint_id"]: e for e in entry.get("endpoints", [])}
        need({(e["url"], e["method"]) for e in origin["endpoints"] if e["endpoint_id"] in source} ==
             {(e["url"], e["method"]) for e in entry.get("endpoints", [])}, f"{name}: method/query variant lost")
        need(origin["endpoint_index"]["provenance_references"] == sum(len(e.get("provenance") or []) for e in entry.get("endpoints", [])),
             f"{name}: provenance references double-counted")
        params = {e["endpoint_id"]: e for e in (context.get("parameter_discovery") or {}).get("endpoints", [])}
        soft = {e["endpoint_id"]: e for e in (context.get("soft404") or {}).get("endpoints", [])}
        for e in origin["endpoints"]:
            need(origin_of(e["url"]) == name, f"{e['url']} reported under {name}")
            need(e["endpoint_id"] == ident(e["url"], e["method"]), "endpoint identity does not match url+method")
            need(e["endpoint_verification_status"] == "not_verified", "endpoint promoted to verified")
            if e["endpoint_id"] in source:
                need(e["provenance_count"] == len(source[e["endpoint_id"]].get("provenance") or []), "provenance count differs")
            if e["dispatch"] and e["dispatch"]["runtime_sequence"] is not None:
                r = seq_of.get(e["dispatch"]["runtime_sequence"])
                need(r and r["origin"] == name and r["candidate_id"] == e["endpoint_id"], "dispatch row not backed by its reservation")
            if e["parameters"]:
                src_c = {c["name"]: c for c in params[e["endpoint_id"]]["candidates"]}
                for c in e["parameters"]["candidates"]:
                    s = src_c[c["name"]]
                    need(c["verification"] == s["verification"] and c["authority"] == "context_only", "parameter verdict/authority changed")
                    classes = sorted({"observed_reference" if p.get("source") == "agent1_reference" else
                                      "inferred_static" if p.get("source") == "param_assembler_static" else "other"
                                      for p in s.get("provenance") or []})
                    need(c["provenance_classes"] == classes, "parameter provenance class changed")
            if e["soft404"]:
                s = soft[e["endpoint_id"]]
                cls, level = s["soft404_classification"], s["evidence_level"]
                need((e["soft404"]["classification"], e["soft404"]["evidence_level_v1"]) == (cls, level), "soft404 class/level changed")
                need(e["soft404"]["evidence_basis"] == ("not_applicable" if cls == "not_checked" else level), "evidence basis upgraded")
                need(e["soft404"]["verification_status"] == "not_verified", "soft404 endpoint promoted")
        need(origin["status"] == content["approved_origins"][index]["status"], f"{name}: status differs from Report v1")
    # discovered-only
    discovered = [d["origin"] for d in content["discovered_only_origins"]]
    need([d["origin"] for d in env["discovered_only_origins"]] == discovered, "discovered-only list changed")
    for d in env["discovered_only_origins"]:
        need(d["executed"] is False and d["approved"] is False and d["journal_reservations"] == 0
             and not any(r["origin"] == d["origin"] for r in rows), "discovered-only origin counted as executed")
        need(d["origin"] not in approved, "discovered-only origin listed as approved")
    # status, severity, gate
    need(env["session"]["pipeline_status"] == final["pipeline_status"], "pipeline status changed")
    if final["pipeline_status"] == "completed":
        need(all(o["status"] == "completed" for o in env["origins"]) and acc["total"]["outcome_unknown"] == 0
             and not env["session"]["finalize_only"], "completed with incomplete evidence")
    need(env["session"]["gate"] == {"origin_execution_mode": "not_enabled_b1", "full_multi_origin_execution_enabled": False},
         "production gate changed")
    data = {k: v for k, v in env.items() if k != "evidence_vocabulary"}
    need([v for _, k, v in walk(data) if k == "severity"] == [None] and env["severity_basis"] == "not_assessed_b5",
         "severity assigned without evidence")
    # secrets and paths
    blob = art["json_bytes"] + art["md_bytes"] + art["manifest_bytes"]
    need(not any(s.encode() in blob for s in SECRETS), "credential value exported")
    text = blob.decode("utf-8")
    need(not re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", text) and str(case["dir"]) not in text
         and case["dir"].as_posix() not in text, "absolute path exported")
    for _, key, _ in walk(env):
        need(str(key).lower() not in {"authorization", "cookie", "headers", "credentials", "set_cookie"}, "credential field exported")
    return check_markdown(env, art["md"]) if markdown else 0


def chain_ok(art):
    try:
        check_journal({**art, "checkpoints": []})
        return True
    except (Failure, KeyError, TypeError):
        return False


def independent_refusal_reason(art):
    """Why this session is ineligible, re-derived from raw source state; None means it was eligible.

    Order mirrors the exporter's own gate order. Checkpoint validity is judged from the hashes recorded at
    refusal time against the journal anchors (a lab case may restore a tampered file afterwards).
    """
    row, journal = art["row"], art["journal"]
    if art["journal_raw"] is None or art["head_raw"] is None:
        return "export_journal_missing"
    if not journal or art["head"] is None or not chain_ok(art) or journal[0].get("event") != "session":
        return "export_journal_invalid"
    if journal[-1]["event"] != "session_finished":
        return "export_session_not_finished"
    snapshot = row.get("source_sha256_before") or {}
    for cp in art["checkpoints"]:
        key = next((k for k in snapshot if cp["path"].as_posix().endswith(k)), None)
        if key is None or snapshot[key] != cp["payload"]["sha256"]:
            return "export_checkpoint_invalid"
    final = json.loads(art["checkpoints"][-1]["raw"]) if art["checkpoints"] else {}
    report = final.get("multi_origin_report") or {}
    try:
        if canonical(report["content"]) != report["digest"]:
            return "export_report_digest_mismatch"
    except (KeyError, TypeError, ValueError):
        return "export_report_missing"
    return None


def check_refused(art):
    row = art["row"]
    need(row.get("expect") == "refused" and isinstance(row.get("code"), str) and row["code"].startswith("export_"),
         "refusal without a public expected code")
    need(row.get("outcome") == ["refused", row["code"]], "missing or mismatching refusal evidence")
    reason = independent_refusal_reason(art)
    need(reason is not None, "refusal claimed for a session that is eligible for export")
    need(reason == row["code"], f"refusal code {row['code']} differs from the independently derived reason {reason}")
    need(not art["output_exists"], "refused export published an output")
    need(not art["pending"], "refused export left a pending directory")
    need(row["source_sha256_before"] == row["source_sha256_after"], "refused export changed its source")
    need(row["server_rows_before_export"] == row["server_rows_after_export"], "export sent HTTP")
    if art["journal_raw"] is not None:
        need(row["source_sha256_before"].get("journal.jsonl") == sha256(art["journal_raw"]).hexdigest()
             and row["source_sha256_before"].get("head.json") == sha256(art["head_raw"]).hexdigest(),
             "refusal snapshot does not match the journal/head recorded at refusal time")
        current = art["current_journal_raw"]
        if row.get("source_snapshot"):
            # Only append-only growth (e.g. an operator resume) is allowed after the refusal.
            need(current is not None and current.startswith(art["journal_raw"]), "journal rewritten after the refusal")
        else:
            need(current == art["journal_raw"], "journal changed after the refusal")
    for cp in art["checkpoints"]:
        key = next((k for k in row["source_sha256_before"] if cp["path"].as_posix().endswith(k)), None)
        current = sha256(cp["raw"]).hexdigest()
        # Unchanged, or a deliberately tampered lab file restored to its journal anchor afterwards.
        need(key is not None and current in (row["source_sha256_before"][key], cp["payload"]["sha256"]),
             "checkpoint changed after the refusal")
    return reason


def verify_case(case):
    checked = 0
    need(case["rows"], "case has neither an export nor a refusal")
    for art in case["rows"]:
        if art["row"].get("expect") == "exported":
            need(art["row"].get("outcome") in (None, ["exported", None]), "export evidence contradicts its expectation")
            need("env" in art, f"expected export {art['row']['label']} missing")
            checked += check_exported(case, art)
        else:
            case.setdefault("refusal_reasons", []).append(check_refused(art))
    return checked


# ── negative mutations (in-memory copies, re-sealed) ──

def reseal(art, *, md=False):
    env = art["env"]
    env["export_digest"] = canonical({k: v for k, v in env.items() if k not in ("export_digest", "export_meta")})
    art["json_bytes"] = (json.dumps(env, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    if md:
        art["md_bytes"] = art["md"].encode("utf-8")
    art["manifest"]["export_digest"] = env["export_digest"]
    art["manifest"]["report_digest"] = env["source"]["report_digest"]
    art["manifest"]["files"] = {"report.json": sha256(art["json_bytes"]).hexdigest(), "report.md": sha256(art["md_bytes"]).hexdigest()}
    art["manifest_bytes"] = json.dumps(art["manifest"]).encode()


def first(env, predicate):
    for o, origin in enumerate(env["origins"]):
        for j, e in enumerate(origin["endpoints"]):
            if predicate(e):
                return o, j, e
    raise LookupError("mutation target missing")  # never counted as a detection


def m_cross_origin(art):
    # An endpoint of the second origin leaks into the first origin's section (counts kept consistent).
    env = art["env"]
    env["origins"][0]["endpoints"].append(deepcopy(env["origins"][1]["endpoints"][0]))
    env["origins"][0]["endpoint_index"]["endpoints"] += 1


def m_total(art): art["env"]["accounting"]["total"]["reserved"] += 1


def m_recon_dropped(art):
    acc = art["env"]["accounting"]
    recon = next(p for p in acc["by_phase"] if "recon" in p["kind"])
    acc["by_phase"].remove(recon)
    for k in KEYS:
        acc["total"][k] -= recon[k]
    acc["by_kind"] = [k for k in acc["by_kind"] if k["kind"] != "recon"]


def m_unknown_zero(art):
    acc = art["env"]["accounting"]
    acc["total"]["outcome_unknown"] = 0; acc["total"]["attempt_unknown"] = 0
    acc["unknown_sequences"] = {"attempt_unknown": [], "outcome_unknown": []}
    if acc["telemetry_http"]["total_requests"] is None:
        acc["telemetry_http"]["total_requests"] = acc["telemetry_http"]["known_requests"]


def m_discovered(art): art["env"]["discovered_only_origins"][0]["executed"] = True


def m_promote(art):
    _, _, e = first(art["env"], lambda e: e["parameters"] and any(c["verification"] == "verified" for c in e["parameters"]["candidates"]))
    e["endpoint_verification_status"] = "verified"


def m_severity(art):
    _, _, e = first(art["env"], lambda e: (e["soft404"] or {}).get("classification") == "genuine_distinct")
    e["soft404"]["severity"] = "high"


def m_level(art):
    _, _, e = first(art["env"], lambda e: (e["soft404"] or {}).get("classification") in ("inconclusive", "not_checked"))
    e["soft404"]["classification"] = "genuine_distinct"; e["soft404"]["evidence_basis"] = "rederived"


def m_variant_merged(art):
    origin = art["env"]["origins"][0]
    origin["endpoints"].pop(); origin["endpoint_index"]["endpoints"] -= 1


def m_double_count(art):
    origin = art["env"]["origins"][0]
    origin["endpoints"].append(deepcopy(origin["endpoints"][0])); origin["endpoint_index"]["endpoints"] += 1


def m_secret(art):
    _, _, e = first(art["env"], lambda e: e["provenance"])
    e["provenance"][0]["source_url"] = e["provenance"][0]["source_url"] + "?note=" + SECRETS[0]


def m_other_report(art):
    other = sha256(b"another session").hexdigest()
    art["env"]["source"]["report_digest"] = other; art["env"]["report_v1"]["digest"] = other


def m_markdown_number(art):
    lines = art["md"].splitlines()
    i = next(i for i, l in enumerate(lines) if l.startswith("| `accounting.total` |"))
    cells = lines[i].split("|"); cells[2] = f" {int(cells[2]) + 1} "
    lines[i] = "|".join(cells); art["md"] = "\n".join(lines) + "\n"


def m_markdown_row_dropped(art):
    lines = art["md"].splitlines()
    i = next(i for i, l in enumerate(lines) if l.startswith("| `origins[0].endpoints[0]` |"))
    del lines[i]; art["md"] = "\n".join(lines) + "\n"


def m_headers_as_arrivals(art):
    o = art["env"]["accounting"]["by_origin"][0]
    o["response_headers"] = o["dispatch_started"] + 1


def m_source_changed(art):
    cp = art["checkpoints"][-1]; cp["raw"] = cp["raw"] + b" "


def m_unknown_laundered(art):
    # Unknown outcomes reported as measured in every per-origin/per-phase/per-kind view (self-consistent sums).
    acc = art["env"]["accounting"]
    for row in [acc["total"]] + acc["by_phase"] + acc["by_kind"] + acc["by_origin"] + \
            [p for o in acc["by_origin"] for p in o["by_phase"]]:
        row["measured"] += row["outcome_unknown"]; row["outcome_unknown"] = 0
    acc["unknown_sequences"]["outcome_unknown"] = []


MUTATIONS = [  # name, case selector, mutate, markdown check included
    ("endpoint_cross_origin", "full", m_cross_origin, False), ("total_inflated", "full", m_total, False),
    ("recon_http_dropped", "full", m_recon_dropped, False), ("unknown_to_zero", "unknown", m_unknown_zero, False),
    ("discovered_only_executed", "full", m_discovered, False), ("parameter_promotes_endpoint", "full", m_promote, False),
    ("severity_assigned", "full", m_severity, False), ("evidence_level_upgraded", "full", m_level, False),
    ("method_variant_merged", "full", m_variant_merged, False), ("provenance_double_count", "full", m_double_count, False),
    ("secret_injected", "full", m_secret, False), ("export_bound_to_other_report", "full", m_other_report, False),
    ("markdown_unbacked_number", "full", m_markdown_number, True),
    ("markdown_row_dropped", "full", m_markdown_row_dropped, True),
    ("response_headers_counted_as_arrival", "full", m_headers_as_arrivals, False),
    ("source_changed_after_export", "full", m_source_changed, False),
    ("unknown_laundered_as_measured", "unknown", m_unknown_laundered, False),
]


def refusal_negative_checks(cases):
    """Case-level corruptions of refusal evidence; each must make verify_case fail."""
    refused = next(((c, i) for c in cases for i, a in enumerate(c["rows"]) if a["row"].get("expect") == "refused"), None)
    eligible = next(((c, i) for c in cases for i, a in enumerate(c["rows"]) if a["row"].get("expect") == "exported"), None)

    def wrong_code(case, i):
        row = case["rows"][i]["row"]
        code = "export_journal_invalid" if row["code"] != "export_journal_invalid" else "export_session_not_finished"
        row.update(code=code, outcome=["refused", code])

    def evidence_missing(case, i):
        case["rows"][i]["row"].pop("outcome", None)

    def with_report(case, i):
        case["rows"][i]["output_exists"] = True

    def empty(case, i):
        case["rows"] = []

    def false_refusal(case, i):
        art = case["rows"][i]
        art["row"].update(expect="refused", code="export_session_not_finished", outcome=["refused", "export_session_not_finished"])
        art["output_exists"], art["pending"] = False, []

    def source_rewritten(case, i):
        art = case["rows"][i]
        art["current_journal_raw"] = b"x" + (art["current_journal_raw"] or b"")

    plan = [("refusal_wrong_code", refused, wrong_code), ("refusal_evidence_missing", refused, evidence_missing),
            ("refusal_source_rewritten", refused, source_rewritten),
            ("refusal_with_report", refused, with_report), ("empty_case", refused or eligible, empty),
            ("false_refusal_of_eligible_session", eligible, false_refusal)]
    results = []
    for name, target, mutate in plan:
        if target is None:
            results.append([name, False, ["no evidence case for this mutation"]])
            continue
        case = deepcopy(target[0])
        mutate(case, target[1])
        try:
            verify_case(case)
            results.append([name, False, ["mutation not detected"]])
        except Failure as exc:
            results.append([name, True, [str(exc)]])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            results.append([name, False, [f"verifier crashed: {type(exc).__name__}"]])
    return results


def negative_checks(cases):
    def exported(case, predicate):
        for art in case["rows"]:
            if art["row"]["expect"] == "exported" and "env" in art and predicate(art):
                return art
        return None
    results = refusal_negative_checks(cases)
    full = next(((c, a) for c in cases for a in [exported(c, lambda a: a["env"]["session"]["pipeline_status"] == "completed"
                                                          and a["env"]["discovered_only_origins"])] if a), None)
    unknown = next(((c, a) for c in cases for a in [exported(c, lambda a: a["env"]["accounting"]["total"]["outcome_unknown"] > 0)] if a), None)
    for name, selector, mutate, md in MUTATIONS:
        target = full if selector == "full" else unknown
        if target is None:
            results.append([name, False, ["no evidence case for this mutation"]])
            continue
        case, art = target
        copy = deepcopy(art)
        try:
            mutate(copy)
            reseal(copy, md=md)
            check_exported(case, copy, markdown=md)
            results.append([name, False, ["mutation not detected"]])
        except Failure as exc:
            results.append([name, True, [str(exc)]])
        except (KeyError, IndexError, StopIteration, TypeError, LookupError) as exc:
            results.append([name, False, [f"verifier crashed: {type(exc).__name__}"]])
    return results


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_dir")
    parser.add_argument("--expected-cases", type=int)
    parser.add_argument("--negative-checks", action="store_true")
    args = parser.parse_args(argv)
    base = Path(args.evidence_dir).resolve()
    dirs = sorted(p.parent for p in base.rglob("b5_evidence.json"))
    cases, failures, cells = [], [], 0
    for directory in dirs:
        try:
            case = load_case(directory)
            cells += verify_case(case)
            cases.append(case)
        except (Failure, KeyError, IndexError, TypeError, ValueError, OSError) as exc:
            failures.append([directory.name, f"{type(exc).__name__}: {exc}"])
    result = {"case_count": len(dirs), "passed": not failures and bool(dirs), "failed_cases": failures,
              "exports_checked": sum(a["row"]["expect"] == "exported" for c in cases for a in c["rows"]),
              "refusals_checked": sum(len(c.get("refusal_reasons", [])) for c in cases),
              "refusal_reasons": dict(Counter(r for c in cases for r in c.get("refusal_reasons", []))),
              "markdown_cells_checked": cells, "verification_level": "integration_verified", "live_verification": "not_verified"}
    if args.expected_cases is not None and len(dirs) != args.expected_cases:
        result["passed"] = False
        failures.append(["expected_cases", f"found {len(dirs)}, expected {args.expected_cases}"])
    if args.negative_checks:
        result["negative_checks"] = negative_checks(cases)
        if not all(ok for _, ok, _ in result["negative_checks"]):
            result["passed"] = False
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
