"""Shared journal integrity checks for stage-specific probe recovery (B4.2A/B4.2B).

Only integrity rules that both stages use: process epochs, unit ordinal/contiguity/
epoch/ownership, and exact checkpoint-row coverage of journal reservations. Business
reconcile (parameter verdicts, Soft404 classifications) stays in each stage module.
"""


def process_epochs(events):
    """Map reservation sequence -> number of `process_bound` events before it."""
    epoch, epochs = 0, {}
    for event in events:
        if event["event"] == "process_bound":
            epoch += 1
        elif event["event"] == "reserved":
            epochs[event["payload"]["sequence"]] = epoch
    return epochs


def check_units(rows, *, key, owner, epochs, deny, code):
    """Group reservations by unit; replay is decided by identity and epoch, never URL.

    Returns (units: unit_id -> rows, owners: owner -> unit_id).
    """
    units = {}
    for row in rows:
        units.setdefault(row[key]["unit_id"], []).append(row)
    owners = {}
    for unit_id, members in units.items():
        seqs = [r["sequence"] for r in members]
        if [r[key]["ordinal"] for r in members] != list(range(1, len(members) + 1)):
            deny(code)
        if seqs != list(range(seqs[0], seqs[-1] + 1)) or len({epochs.get(s) for s in seqs}) != 1:
            deny(code)
        if len({owner(r) for r in members}) != 1:
            deny(code)
        target = owner(members[0])
        if target in owners:
            deny(code)
        owners[target] = unit_id
    return units, owners


def check_checkpoint_rows(checkpoints, rows, measurements, sections, *, key, identity, fields, deny, missing_code):
    """Every checkpoint lists exactly the reservations up to its counter, matching the journal."""
    by_seq = {r["sequence"]: r for r in rows}
    for data, saved in checkpoints:
        covered = {r["sequence"] for r in rows if r["sequence"] <= data["reservations"]}
        found = sections(saved)
        listed = [r for section in found.values() for r in section.get("requests", [])]
        if covered and not found:
            deny(missing_code)
        if found and sorted(r.get("runtime_sequence") for r in listed) != sorted(covered):
            deny("recovery_checkpoint_invalid")
        for row in listed:
            res, measure = by_seq.get(row["runtime_sequence"]), measurements.get(row["runtime_sequence"])
            if res is None:
                deny("recovery_checkpoint_invalid")
            parts = _split(res["url"])
            if (row["origin"] != res["origin"] or (row["path"], row["query"]) != parts
                    or any(row.get(k) != res[key][k] for k in identity)):
                deny("recovery_checkpoint_invalid")
            if measure is None:
                if row.get("recovery_state") != "outcome_unknown" or row.get("status_code") is not None:
                    deny("recovery_checkpoint_invalid")
            elif any(row.get(k) != measure.get(k) for k in fields):
                deny("recovery_checkpoint_invalid")


def _split(url):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    return parts.path or "/", parts.query
