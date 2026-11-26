---
name: multi-origin-stage
description: Plans, scopes and closes out one staged step of FuzzingTool's multi-origin work (B1, B2.1, B2.2, B3.1, B3.2A, B3.2B, B4.x, B5, B6 full local acceptance, and any later stage). Use when the user asks to start, continue, extend, verify or document a multi-origin stage; to work on origin_scope, origins, origin_wordlist, origin_dispatch, origin_local or origin_recovery as part of a stage; or to judge whether the multi-origin production gate may change. Not for single-target pipeline work, for code-level HTTP guard review (use http-dispatch-invariants), or for how to write the localhost tests (use loopback-lab-tests).
---

# Multi-origin stage workflow

Multi-origin support is delivered in small stages. Each one adds a narrow capability behind a closed production gate and proves it with localhost evidence. This skill keeps a new stage inside that discipline.

## 1. Load the current state (read before deciding anything)

1. Read the latest stage doc first, then the previous one. Their limits and handoff sections define what the next stage owes.

   | Stage | Doc | Main code | Tests (`tests/`) | Evidence env var / verifier |
   |---|---|---|---|---|
   | B1 contract + scope | `docs/multi_origin_b1.md` | `src/coordinator/origins.py`, `src/tools/origin_scope.py` | `test_origin_contract.py`, `test_origin_scope_integration.py` | `B1_EVIDENCE_DIR` |
   | B2.1 recon discovery | `docs/multi_origin_b21.md` | `TechReconAgent.collect_discovery`, `origins.merge_discovery_context` | `test_discovery_context.py`, `test_discovery_http_integration.py` | `B21_EVIDENCE_DIR` |
   | B2.2 wordlist selection | `docs/multi_origin_b22.md` | `src/agents/origin_wordlist.py`, `WordlistGenAgent.generate_from_discovery` | `test_origin_wordlist*.py` | `B22_EVIDENCE_DIR`, `scripts/verify_origin_wordlist_evidence.py` |
   | B3.1 dispatch harness | `docs/multi_origin_b31.md` | `src/tools/origin_dispatch.py` (`dispatch_selected`) | `test_origin_dispatch*.py` | `B31_EVIDENCE_DIR`, `verify_origin_dispatch_evidence.py --negative-checks` |
   | B3.2A graph, Agents 1→3 | `docs/multi_origin_b32a.md` | `src/coordinator/origin_local.py` (`LocalOriginTest`), `graph.py` | `test_origin_graph*.py` | `B32A_EVIDENCE_DIR`, `verify_origin_graph_evidence.py --expected-cases 21 --negative-checks` |
   | B3.2B crash recovery | `docs/multi_origin_b32b.md` | `src/coordinator/origin_recovery.py` (`RecoveryJournal`) | `test_origin_recovery*.py`, `origin_recovery_worker.py` | `B32B_EVIDENCE_DIR`, `verify_origin_recovery_evidence.py --expected-cases 27 --negative-checks` |
   | B4.1 parameters (Agent 4) | `docs/multi_origin_b41.md` | `src/tools/origin_parameters.py`, `OriginScopePolicy.check_parameter_probe` | `test_origin_parameters*.py` | `B41_EVIDENCE_DIR`, `verify_origin_parameter_evidence.py --expected-cases 8 --negative-checks` |
   | B4.2A probe recovery | `docs/multi_origin_b42a.md` | `origin_parameters.reconcile_probe_recovery`/`derive_unit_verdicts`, `LocalOriginTest(parameter_verification=True)` | `test_origin_parameter_recovery*.py`, `origin_parameter_recovery_worker.py` | `B42A_EVIDENCE_DIR`, `verify_origin_parameter_recovery_evidence.py --expected-cases 16 --negative-checks` |
   | B4.2B Soft404 (Agent 5) | `docs/multi_origin_b42b.md` | `src/tools/origin_soft404.py`, `src/coordinator/recovery_units.py`, `OriginScopePolicy.check_soft404_control`, `LocalOriginTest(soft404_verification=True)` | `test_origin_soft404*.py`, `origin_soft404_recovery_worker.py` | `B42B_EVIDENCE_DIR`, `verify_origin_soft404_evidence.py --expected-cases 26 --negative-checks` |
   | B4.2C full local graph (Agents 1→5, Report, Reflection) | `docs/multi_origin_b42c.md` | `src/coordinator/origin_report.py`, `LocalOriginTest(parameter_verification=True, soft404_verification=True)` (`decision_for`, `report`, `reflect`, `finish`, `finalize_only`), `RecoveryJournal._verify_decisions/_verify_reports/_finished` | `test_origin_full_graph*.py`, `origin_full_graph_recovery_worker.py` | `B42C_EVIDENCE_DIR`, `verify_origin_full_graph_evidence.py --expected-cases 21 --negative-checks` |
   | B5 verified export (JSON + Markdown, offline) | `docs/multi_origin_b5.md` | `src/coordinator/origin_export.py` (`export_session`, `build_envelope`, `render_markdown`), `scripts/export_origin_report.py` | `test_origin_report_*.py` (export unit, export HTTP/recovery, verifier) | `B5_EVIDENCE_DIR`, `verify_origin_report_evidence.py --expected-cases 10 --negative-checks` (refusal-only cases allowed; historical B4.2C: `--expected-cases 20`) |
   | B6 full local acceptance (no new code) | `docs/multi_origin_b6.md` | — (acceptance matrix B1→B5, gap analysis) | all of the above | evidence `multi_origin_b6_20261126T063201Z/`; run every verifier with its doc flags. B3.1/B3.2A verifiers fail under `python -I` (they import a sibling). The B1/B2.1 verifiers live in their evidence dirs, not `scripts/`. |

2. Run `git status --short`. Stage work is often uncommitted. Read every modified or untracked file the stage touches before editing it. Never stash, reset or overwrite it.
3. Write down the stage's **in scope** and its **explicitly not done** lists before coding. Each existing stage doc states both.

## 2. Invariants every stage keeps (unless the user explicitly changes them)

- **The production gate stays closed.** `graph.validate_input` raises `InputValidationError` with `stop_reason = "multi_origin_execution_not_enabled_b1"` whenever `multi_origin` is in config and no `LocalOriginTest` is active. `origins.origin_state` reports `origin_execution_mode: "not_enabled_b1"`. Don't rename, remove or weaken this, and don't add a JSON/`SharedState`/env flag that bypasses it.
- **The lab mode is private and loopback only.** `LocalOriginTest` is a Python object passed as `run_pipeline(..., local_origin_test=...)`, and a context can be used once. `loopback_url` accepts literal `127.0.0.1` / `[::1]` URLs only. Every approved origin, document and quota must be explicit. `LocalOriginTest.NODES` and `EXECUTION` list the graph nodes this mode may run. Adding Agent 4/5 (`param_disc`, `filter_404`) is a stage decision, not a side effect.
- **One runtime, one telemetry session.** Never create a runtime per origin or per agent. Per-origin quotas (`http_origin_max_requests`) live inside the shared `RuntimeBudget` and never reset the global budget.
- **Observation is not permission.** Discovered or generated URLs grant nothing. Dispatch rechecks the current state, the `OriginScopePolicy` and the credential binding at send time (see `origin_dispatch._candidate`). Generated candidates with `method=None` stay review-only.
- **Secrets live only in private objects.** `OriginCredentialContext` holds credential headers and must never be serialized into config, `SharedState`, artifacts or logs.
- **Single-target behaviour doesn't change.** `FuzzingAgent.execute()`, `WordlistGenAgent.execute()` and the legacy `SharedState` fields stay canonical.
- **Engines.** Multi-origin dispatch supports `python_http` through the B1 transport only. `ffuf_cli` and `proxy_http` are out of scope unless a stage adds them with their own evidence.
- **Recovery semantics.** Recovery is at-most-once replay, not exactly-once delivery. Never re-send a reserved candidate. Fail closed on a torn or mismatched journal or head.
- **B4.2C local graph.** Status is set only after Reflection; `completed` needs all five Agents `success` at every approved origin, no stop, no `interrupted`/`outcome_unknown`, never in `finalize_only`. Report/Reflection stay deterministic (no LLM, `knowledge_writes = 0`); discovered-only origins are never counted as executed. Decision nodes are reused only after re-derivation from their own checkpoint (`recovery_decision_mismatch`); a recomputed Report must match the anchored digest (`recovery_report_mismatch`). `finalize_only` keeps every integrity check and sends no HTTP (three independent layers); a verified `session_finished` returns `already_finished` without running the graph.
- **B5 export.** Export is offline and read-only: it accepts only finished sessions (journal, head, anchored checkpoints, `session_finished`), never runs resume or `finalize_only`, copies Report v1 verbatim and never re-digests it, and publishes `report.json`, `report.md` and `manifest.json` by one atomic rename without overwrite. Accounting comes from journal events and never claims server receipt; unknown stays `null` or is counted, never 0. `severity` is `null`. Endpoints stay `not_verified`, parameters stay `context_only`, and `genuine_distinct` is not a finding. A new stage must not change Report content v1 or its digest rule without a migration plan (R8: digest before redaction, see `docs/multi_origin_b5.md` §8).

For code that opens, paces or measures HTTP, apply `http-dispatch-invariants`. For the tests, apply `loopback-lab-tests`.

## 3. Implement the stage

- Prefer extending the existing modules and the existing graph nodes over a new graph, runner or scheduler. B3.2A, for example, wired entry points into the existing nodes through `LocalOriginTest` hooks.
- Start each new module with a docstring that names the stage, what it guarantees, and what it deliberately does not enable (see the `origin_*.py` headers).
- Validation errors that reach artifacts use fixed public reason codes, never raw input text (see the `public_reasons` set in `origin_dispatch.dispatch_selected`).
- Every artifact goes through `RunArtifacts`, which handles redaction and atomic writes.

## 4. Evidence and status vocabulary

The stage docs grade claims with exactly these labels:

- `implemented`: the code exists.
- `unit_verified`: unit tests pass.
- `integration_verified`: localhost HTTP tests plus the independent verifier pass.
- `not_verified`: anything outside the lab (Internet, real TLS across origins, DeepSeek, production multi-origin, power-loss durability).

Run order for a stage, from the repo root in an offline PowerShell (the env vars are listed in `CLAUDE.md`):

```powershell
$env:B<NN>_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b<nn>_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_<area>*.py' -v
.\.venv\Scripts\python.exe -B scripts/verify_origin_<area>_evidence.py $env:B<NN>_EVIDENCE_DIR [--expected-cases N] [--negative-checks]
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Use the flags from the table above. `verify_origin_wordlist_evidence.py` takes only the directory.

- A new stage that produces new evidence gets its own stdlib-only verifier in `scripts/`. It must not import `src`, and `--negative-checks` must corrupt **copies** to prove that the verifier detects tampering.
- If the full suite has a failure that already existed before your change, show that it reproduces on clean HEAD before calling it pre-existing. Don't raise timeouts or change dependencies to hide it.

## 5. Close out

- Draft the new stage doc as `docs/multi_origin_<stage>.md`, in Vietnamese, with the same section types as the previous docs: scope/gate, API or contract before and after, state/credentials/artifacts, verification commands with results, and limits plus handoff. Ask before editing an existing stage doc.
- Report the test counts as actually run, the evidence directory, the status label for each claim, and what remains `not_verified`.
- Leave commits to the user.
