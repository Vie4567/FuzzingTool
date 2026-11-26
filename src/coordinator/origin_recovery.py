"""Opt-in loopback recovery. Durable reservations, never exactly-once delivery.

The operator supplies policy afresh. The journal is evidence, not authority.
An OS lock owns the session for the entire graph invocation. Each journal line
is fsynced before its atomic head anchor; a torn/missing pair fails closed.
This protects process termination, not arbitrary storage/power-loss guarantees.

B4.2C: decision nodes are reused only when the recorded action re-derives from the
checkpoint of that decision point (`recovery_decision_mismatch` otherwise); a
recomputed Report must match the journal-anchored digest (`recovery_report_mismatch`).
`finalize_only` keeps every integrity check but allows rebuilding Report/Reflection
after a stop/deadline/budget end, with dispatch refused here as one of three layers.
A verified `session_finished` journal returns the recorded result (`already_finished`)
without invoking the graph or appending to the journal.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from threading import RLock
import time

from .artifacts import ArtifactWriteError, RunArtifacts
from .origin_report import canonical_digest
from .runtime import PipelineStopped

DECISION_NODES = {"llm_decide_after_recon": "after_recon", "llm_decide_after_wordlist": "after_wordlist",
                  "llm_decide_after_fuzzing": "after_fuzzing"}


def utc():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class RecoveryDenied(ValueError):
    """Public reason only; never include supplied secrets or untrusted content."""


class RecoveryJournal:
    def __init__(self, directory, *, resume=False):
        self.directory = Path(directory).resolve()
        self.resume = resume
        self.events = []
        self.lock = RLock()
        self.owner = None
        self.runtime = None
        self.broken = False
        self.completed_nodes = set()
        self.reused_nodes = []
        self.restored = False
        # B4.2A: set only by a parameter-enabled LocalOriginTest.
        self.parameter_probes = False
        self.parameter_resumed = False
        # B4.2B: set only by a soft404-enabled LocalOriginTest.
        self.soft404_probes = False
        self.soft404_resumed = False
        # B4.2C: set only by LocalOriginTest(finalize_only=True); never from config/state.
        self.finalize_only = False
        self.decisions = {}
        self.prior_report_digest = None
        self.already_finished = None

    def __enter__(self):
        if self.resume and not self.directory.is_dir():
            raise RecoveryDenied("recovery_session_missing")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.owner = open(self.directory / "session.lock", "a+b")
        try:
            self.owner.seek(0, 2)
            if self.owner.tell() == 0:
                self.owner.write(b"0"); self.owner.flush()
            self.owner.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.owner.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.owner.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.owner.close(); self.owner = None
            raise RecoveryDenied("recovery_session_locked") from None
        try:
            if self.resume:
                self._read()
            elif any((self.directory / name).exists() for name in ("journal.jsonl", "head.json")):
                raise RecoveryDenied("recovery_session_already_exists")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.owner is not None:
            self.owner.close()  # OS releases lock even when the process is killed.
            self.owner = None

    def barrier(self, event, payload):
        """No-op seam for controlled subprocess termination in localhost tests."""

    def append(self, event, payload):
        with self.lock:
            if self.owner is None or self.broken:
                raise ArtifactWriteError("Recovery journal is unavailable")
            row = {"seq": len(self.events) + 1, "previous": self.events[-1]["hash"] if self.events else None,
                   "event": event, "payload": deepcopy(payload), "pid": os.getpid(), "utc": utc()}
            row["hash"] = digest(row)
            try:
                with open(self.directory / "journal.jsonl", "ab") as stream:
                    stream.write((json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n").encode())
                    stream.flush(); os.fsync(stream.fileno())
                RunArtifacts._write_json(self.directory / "head.json", {"seq": row["seq"], "hash": row["hash"]})
            except (OSError, ValueError, TypeError):
                self.broken = True
                if self.runtime: self.runtime.stop_reason = "recovery_persistence_error"
                raise ArtifactWriteError("Cannot durably record recovery event") from None
            self.events.append(row)
        self.barrier(event, payload)
        return row

    def _read(self):
        try:
            raw = (self.directory / "journal.jsonl").read_bytes()
            if not raw.endswith(b"\n"): raise ValueError()
            rows = [json.loads(line) for line in raw.splitlines()]
            previous = None
            for seq, row in enumerate(rows, 1):
                check = dict(row); claimed = check.pop("hash")
                if row["seq"] != seq or row["previous"] != previous or digest(check) != claimed:
                    raise ValueError()
                previous = claimed
            if not rows or rows[0]["event"] != "session": raise ValueError()
            if json.loads((self.directory / "head.json").read_text(encoding="utf-8")) != {
                    "seq": len(rows), "hash": previous}: raise ValueError()
            self.events = rows
        except (OSError, ValueError, KeyError, TypeError):
            raise RecoveryDenied("recovery_journal_invalid") from None

    @staticmethod
    def authority(local, config):
        # Paths to output directories are not HTTP authority. Everything else
        # must match, including deadline/rate/limits and public profile bindings.
        authority = {"target": local.target, "documents": local.documents,
                     "config": {k: v for k, v in config.items() if k not in {"artifact_root", "output_dir"}},
                     "quotas": local.quotas}
        if getattr(local, "parameter_verification", False):
            # Added only when enabled, so B3.2B journals keep their exact authority.
            authority["parameter_verification"] = True
            authority["parameter_max_requests"] = local.parameter_max_requests
        if getattr(local, "soft404_verification", False):
            authority["soft404_verification"] = True
            authority["soft404_max_requests"] = local.soft404_max_requests
        return authority

    def bind(self, local, runtime, state, config):
        self.runtime = runtime
        root = Path(config.get("artifact_root") or config.get("output_dir") or "output_samples/diagnostics").resolve()
        if self.directory.parent != root:
            raise RecoveryDenied("recovery_artifact_root_mismatch")
        authority = self.authority(local, config)
        if local.transport.redact(authority) != authority:
            raise RecoveryDenied("recovery_sensitive_authority")
        # Require re-supply of every bound profile before any recovery HTTP.
        for origin in local.policy.public_config()["approved_origins"]:
            try:
                local.transport._credentials.headers_for(origin)
            except ValueError:
                raise RecoveryDenied("recovery_credentials_required") from None
        if not self.resume:
            self.append("session", {"version": 1, "session_id": state["session_id"],
                "runtime_id": local.runtime_id, "authority": authority,
                "started_wall": time.time(), "started_monotonic": runtime.started,
                "deadline_monotonic": runtime.deadline,
                "deadline_wall": time.time() + runtime.deadline - time.monotonic()})
            state["recovery"] = {"version": 1, "session_id": state["session_id"], "resumed": False,
                "journal": str(self.directory / "journal.jsonl"), "replay_policy": "at_most_once_no_replay_reserved",
                "exactly_once_delivery": False}
        else:
            self._restore(local, runtime, state, authority)
            if self.already_finished is not None:
                return self.already_finished  # verified final result; no journal write, no dispatch binding
        runtime.recovery = self
        self.append("process_bound", {"session_id": state["session_id"], "resume": self.resume,
            "reservations": runtime.requests, **({"finalize_only": True} if self.finalize_only else {})})
        if self.finalize_only:
            local.close_dispatch()
        return None

    def public_summary(self):
        starts = {e["payload"]["sequence"] for e in self.events if e["event"] == "dispatch_started"}
        measured = {e["payload"]["sequence"] for e in self.events if e["event"] == "measurement"}
        reserved = [e["payload"]["sequence"] for e in self.events if e["event"] == "reserved"]
        return {"reserved_requests": len(reserved), "known_dispatch_starts": len(starts),
            "attempts_unknown": len(set(reserved) - starts),
            "responses_received": sum(e["event"] == "response_headers" for e in self.events),
            "outcome_unknown_requests": len(set(reserved) - measured),
            "checkpoint_journal_sequence": len(self.events), "global_stop_reason": self.runtime.stop_reason}

    def _restore(self, local, runtime, state, authority):
        session = self.events[0]["payload"]
        if session.get("version") != 1 or session["authority"] != authority:
            raise RecoveryDenied("recovery_authority_changed")
        wall_elapsed = time.time() - session["started_wall"]
        mono_elapsed = time.monotonic() - session["started_monotonic"]
        if min(wall_elapsed, mono_elapsed) < 0 or abs(wall_elapsed - mono_elapsed) > 2:
            raise RecoveryDenied("recovery_clock_discontinuity")
        checkpoints, reservations, starts, responses, measurements = [], [], {}, {}, {}
        reserved_candidates = set()
        stop, finished = None, None
        for event in self.events:
            kind, data = event["event"], event["payload"]
            if kind == "session_finished":
                if finished is not None: raise RecoveryDenied("recovery_session_finished")
                finished = event
                continue
            if finished is not None: raise RecoveryDenied("recovery_session_finished")
            if kind == "reserved":
                reservations.append(data)
                if data["sequence"] != len(reservations): raise RecoveryDenied("recovery_counter_mismatch")
                if "probe" in data or "soft404" in data:
                    continue  # Stage probe identities are validated by their stage reconcile.
                try:
                    from .origins import canonical_origin, endpoint_observation
                    if canonical_origin(data["url"]) != data["origin"]: raise ValueError()
                    local.transport.check_dispatch(data["url"], data["method"])
                    if data.get("candidate_id") is not None:
                        if endpoint_observation(data["url"], method=data["method"])["endpoint_id"] != data["candidate_id"]:
                            raise ValueError()
                        key = (data["origin"], data["candidate_id"])
                        if key in reserved_candidates:
                            raise ValueError()
                        reserved_candidates.add(key)
                except (KeyError, TypeError, ValueError):
                    raise RecoveryDenied("recovery_reservation_identity_invalid") from None
            elif kind in {"dispatch_started", "response_headers", "measurement"}:
                seq = data["sequence"]
                if type(seq) is not int or not 1 <= seq <= len(reservations):
                    raise RecoveryDenied("recovery_request_sequence_invalid")
                dest = {"dispatch_started": starts, "response_headers": responses, "measurement": measurements}[kind]
                if seq in dest: raise RecoveryDenied("recovery_duplicate_event")
                if kind != "dispatch_started" and seq not in starts:
                    raise RecoveryDenied("recovery_missing_dispatch_evidence")
                if kind == "measurement" and data.get("status_code") != (responses.get(seq) or {}).get("status_code"):
                    raise RecoveryDenied("recovery_response_mismatch")
                dest[seq] = data
            elif kind == "stop": stop = data["reason"]
            elif kind == "checkpoint":
                try:
                    path = Path(data["path"])
                    # Only immutable files created below the session's artifact root.
                    if not path.resolve().is_relative_to(self.directory.parent): raise ValueError()
                    raw = path.read_bytes()
                    if sha256(raw).hexdigest() != data["sha256"]: raise ValueError()
                    saved = json.loads(raw)
                    if saved["session_id"] != session["session_id"]: raise ValueError()
                    if data["reservations"] != len(reservations): raise ValueError()
                    snap = saved.get("runtime", {})
                    if snap.get("http_dispatches") != len(reservations): raise ValueError()
                    # An interrupted dispatcher can checkpoint its global stop
                    # before a separate stop event is committed. Never clear it.
                    if snap.get("stop_reason"):
                        stop = snap["stop_reason"]
                    expected = dict(Counter(r["origin"] for r in reservations))
                    if snap.get("http_dispatches_by_origin") != expected: raise ValueError()
                    if saved.get("config", {}).get("multi_origin") != authority["config"]["multi_origin"]:
                        raise ValueError()
                    for entry in saved.get("origin_contexts", {}).values():
                        for record in ((entry.get("context") or {}).get("http_dispatch") or {}).get("records", []):
                            if record.get("status_code") is not None:
                                seq = record.get("runtime_sequence")
                                proof = measurements.get(seq) or responses.get(seq)
                                if not proof or proof.get("status_code") != record["status_code"]: raise ValueError()
                                if record.get("body_complete") and (seq not in measurements or not measurements[seq]["body_complete"]):
                                    raise ValueError()
                                if seq in measurements and any(record.get(key) != measurements[seq].get(key)
                                        for key in ("bytes_received", "body_complete", "response_time")):
                                    raise ValueError()
                    checkpoints.append((data, saved))
                    if data["event"] == "checkpoint": self.completed_nodes.add(data["node"])
                except (OSError, ValueError, KeyError, TypeError):
                    raise RecoveryDenied("recovery_checkpoint_invalid") from None
        if finished is not None:
            self._finished(session, finished, checkpoints)
            return
        stop = stop or next((r["stop_reason"] for r in list(measurements.values()) + list(responses.values())
                             if r.get("stop_reason")), None)
        # finalize_only (B4.2C D6) may summarize an ended session; normal resume keeps B3.2B denials.
        if stop and not self.finalize_only:
            raise RecoveryDenied("recovery_global_stop")
        expired = time.time() >= session["deadline_wall"] or time.monotonic() >= session["deadline_monotonic"]
        if expired and not self.finalize_only:
            raise RecoveryDenied("recovery_deadline_expired")
        exhausted = len(reservations) >= runtime.max_requests
        if exhausted and not self.finalize_only: raise RecoveryDenied("recovery_budget_exhausted")
        counts = Counter(r["origin"] for r in reservations)
        if any(o not in runtime.origin_limits or n > runtime.origin_limits[o] for o, n in counts.items()):
            raise RecoveryDenied("recovery_origin_counter_mismatch")
        if not {"run_tech_recon", "run_wordlist_gen"} <= self.completed_nodes or not checkpoints:
            raise RecoveryDenied("recovery_discovery_checkpoint_missing")
        recovered = deepcopy(checkpoints[-1][1])
        # Approval is checked against the fresh private context, never loaded as authority.
        if recovered["approved_origins"] != local.policy.public_config()["approved_origins"] or recovered["origin_policies"] != local.policy.public_config()["origin_policies"]:
            raise RecoveryDenied("recovery_scope_mismatch")
        state.clear(); state.update(recovered)
        state["config"] = deepcopy(authority["config"])
        state["config"]["artifact_root"] = str(self.directory.parent)
        runtime.started = session["started_monotonic"]
        runtime.deadline = min(session["deadline_monotonic"], time.monotonic() + session["deadline_wall"] - time.time())
        runtime.requests = len(reservations)
        runtime.origin_requests = dict(counts)
        runtime.origin_reservations = [{k: r[k] for k in ("sequence", "origin", "reserved_at_monotonic")} for r in reservations]
        runtime.next_start = max(runtime.started, reservations[-1]["reserved_at_monotonic"] + 1/runtime.rate) if reservations else runtime.started
        local.runtime_id = session["runtime_id"]
        local.callback_events = deepcopy(state.get("local_origin_execution", {}).get("langgraph_trace", []))
        from src.tools.origin_parameters import reconcile_probe_recovery

        def deny(code):
            raise RecoveryDenied(code)
        probe_unknown = reconcile_probe_recovery(
            local=local, state=state, events=self.events, reservations=reservations, starts=starts,
            measurements=measurements, checkpoints=checkpoints, deny=deny)
        from src.tools.origin_soft404 import reconcile_soft404_recovery
        soft404_unknown = reconcile_soft404_recovery(
            local=local, state=state, events=self.events, reservations=reservations, starts=starts,
            measurements=measurements, checkpoints=checkpoints, deny=deny)
        # Recover every published row. Pending rows have not granted execution;
        # only a matching durable reservation can make their outcome unknown.
        for _, saved in checkpoints:
            for origin, entry in saved.get("origin_contexts", {}).items():
                for row in ((entry.get("context") or {}).get("http_dispatch") or {}).get("records", []):
                    if row["stop_reason"] != "pending":
                        runtime.origin_dispatch_records[(origin, row["candidate_id"])] = deepcopy(row)
        unknown = []
        for reservation in reservations:
            key = (reservation["origin"], reservation.get("candidate_id"))
            if key[1] is None: continue  # Recon is checkpointed; never rerun.
            seq = reservation["sequence"]
            row = runtime.origin_dispatch_records.get(key)
            if row and row.get("runtime_sequence") == seq and seq in measurements:
                continue
            # Headers can be proven without claiming that a body completed.
            measure = measurements.get(seq)
            status = (measure or responses.get(seq) or {}).get("status_code")
            row = {"candidate_id": key[1], "origin": key[0], "url": reservation["url"],
                "observed_method": reservation["method"], "planned_test_method": None,
                "execution_method": reservation["method"] if seq in starts else None,
                "evidence_refs": reservation["evidence_refs"], "runtime_sequence": seq,
                "attempted": True if seq in starts else None, "status_code": status,
                "retained_body_bytes": measure.get("content_length") if measure else None,
                "bytes_received": measure.get("bytes_received") if measure else None,
                "body_complete": measure.get("body_complete") if measure else None,
                "response_time": measure.get("response_time") if measure else None,
                "error": measure.get("error") if measure else None,
                "timeout": bool(measure and "timeout" in (measure.get("error") or {}).get("exception_type", "").lower()),
                "stop_reason": measure.get("stop_reason") if measure else "outcome_unknown",
                "classification": "observed_response" if status is not None else None,
                "verified": None, "verification_status": "not_verified", "recorded_at_utc": utc(),
                "recovery_state": "result_persisted" if measure else "outcome_unknown"}
            runtime.origin_dispatch_records[key] = row
            if not measure: unknown.append(seq)
        from .telemetry import current_telemetry
        telemetry = current_telemetry()
        for phase, count in Counter(reservations[s-1]["phase"] for s in starts).items():
            telemetry.http_attempt(phase=phase, kind="target", count=count)
        if len(starts) < len(reservations):
            telemetry.http_unknown(phase="recovery", source="reserved_without_dispatch_evidence")
        self._verify_decisions(local, state, checkpoints, deny)
        self._verify_reports(checkpoints, deny)
        if self.finalize_only:
            # Preserve the original stop; dispatch is also closed in bind() and refused in reserve().
            runtime.stop_reason = stop
            runtime._durable_stop = stop
        self.restored = True
        state["recovery"] = {"version": 1, "session_id": session["session_id"], "resumed": True,
            "journal": str(self.directory / "journal.jsonl"), "restored_reservations": len(reservations),
            "outcome_unknown_sequences": unknown, "replay_policy": "at_most_once_no_replay_reserved",
            "reused_nodes": [], "exactly_once_delivery": False}
        reconciled = {"reservations": len(reservations), "by_origin": dict(counts),
                      "outcome_unknown_sequences": unknown, "checkpoint": checkpoints[-1][0]["path"]}
        if self.parameter_probes:
            state["recovery"]["parameter_outcome_unknown_sequences"] = probe_unknown
            reconciled["parameter_outcome_unknown_sequences"] = probe_unknown
        if self.soft404_probes:
            state["recovery"]["soft404_outcome_unknown_sequences"] = soft404_unknown
            reconciled["soft404_outcome_unknown_sequences"] = soft404_unknown
        if self.finalize_only:
            basis = {"global_stop": stop, "deadline_expired": expired, "budget_exhausted": exhausted}
            state["recovery"].update(finalize_only=True, finalize_basis=basis)
            reconciled["finalize_only"] = basis
        self.append("reconciled", reconciled)

    def _verify_decisions(self, local, state, checkpoints, deny):
        """D5: each recorded decision must re-derive from its own decision-point checkpoint."""
        latest = {}
        for data, saved in checkpoints:
            if data["event"] == "checkpoint" and data["node"] in DECISION_NODES:
                latest[data["node"]] = saved
        for node, saved in latest.items():
            point = DECISION_NODES[node]
            rows = [d for d in saved.get("decision_chain", []) if isinstance(d, dict) and d.get("decision_point") == point]
            try:
                action, reason = local.decision_for(saved, point, (saved.get("runtime") or {}).get("stop_reason"))
            except (KeyError, TypeError, AttributeError):
                deny("recovery_decision_mismatch")
            if (len(rows) != 1 or rows[0].get("action") != action or rows[0].get("reason") != reason
                    or rows[0].get("llm_called") is not False):
                deny("recovery_decision_mismatch")
            self.decisions[node] = rows[0]
        nodes = {point: node for node, point in DECISION_NODES.items()}
        seen = set()
        for row in state.get("decision_chain", []):
            node = nodes.get(row.get("decision_point")) if isinstance(row, dict) else None
            if node is None or node in seen or self.decisions.get(node) != row:
                deny("recovery_decision_mismatch")
            seen.add(node)
        if seen != set(self.decisions):
            deny("recovery_decision_mismatch")

    def _verify_reports(self, checkpoints, deny):
        """A journal-anchored Report must hash to its digest; the latest one binds the recomputation."""
        for data, saved in checkpoints:
            report = saved.get("multi_origin_report")
            if report is None:
                continue
            try:
                if canonical_digest(report["content"]) != report["digest"]:
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                deny("recovery_report_mismatch")
            if data["node"] == "generate_report" and data["event"] == "checkpoint":
                self.prior_report_digest = report["digest"]

    def _finished(self, session, finished, checkpoints):
        """D7: `session_finished` must directly follow the anchored final `pipeline` checkpoint."""
        if (self.events[-1] is not finished or len(self.events) < 2 or self.events[-2]["event"] != "checkpoint"
                or not checkpoints or checkpoints[-1][0] is not self.events[-2]["payload"]):
            raise RecoveryDenied("recovery_session_finished")
        data, saved = checkpoints[-1]
        status = finished["payload"].get("pipeline_status")
        if data["node"] != "pipeline" or data["event"] != status or saved.get("pipeline_status") != status:
            raise RecoveryDenied("recovery_session_finished")
        def deny(code):
            raise RecoveryDenied(code)
        self._verify_reports(checkpoints, deny)
        self.already_finished = {"result": deepcopy(saved), "checkpoint": data["path"], "sha256": data["sha256"],
                                 "pipeline_status": status, "session_id": session["session_id"],
                                 "journal_sequence": len(self.events)}

    def reserve(self, runtime, origin, request, phase):
        if self.finalize_only:
            raise PipelineStopped("finalize_only_no_dispatch")  # before any journal write or counter change
        if request is None: raise RecoveryDenied("recovery_request_identity_missing")
        self.barrier("before_reservation", request)
        self.append("reserved", {**request, "origin": origin, "phase": phase,
            "sequence": runtime.requests + 1, "reserved_at_monotonic": time.monotonic()})

    def request_event(self, kind, payload=None):
        self.append(kind, {"sequence": self.runtime.requests, **(payload or {})})

    def checkpoint(self, public, node, event):
        path = Path(public["artifacts"]["checkpoint"])
        self.append("checkpoint", {"node": node, "event": event, "path": str(path),
            "sha256": sha256(path.read_bytes()).hexdigest(), "reservations": self.runtime.requests})
        if event == "checkpoint": self.completed_nodes.add(node)

    def reuse(self, state, node):
        if not self.restored:
            return False
        if node in DECISION_NODES:
            record = self.decisions.get(node)
            if record is None:
                return False
            # Route from the verified record; never append a second record on resume.
            state["_last_decision_action"], state["_config_adjustments"] = record["action"], {}
        elif node not in self.completed_nodes or node not in {
                "validate_input", "init_state", "run_tech_recon", "run_wordlist_gen", "run_fuzzing",
                "run_param_discovery", "run_soft404_filter"}:
            return False
        self.reused_nodes.append(node)
        state["recovery"]["reused_nodes"] = list(self.reused_nodes)
        return True
