# Coordinator MVP Task 4 — measurement context and reflection

Implemented on 2026-11-07; local tests only, no provider or target network calls.

## Cause

Coordinator prompt variables exposed selected wordlist size and returned HTTP
rows without explaining generation/selection/dispatch stages. `_build_context`
was not the input actually formatted into the model prompt. Reflection trusted
model prose and lesson IDs, and defaulted decision correctness to true.

## Changes

- `src/coordinator/state.py`: `lifecycle_summary(state)` derives generated,
  selected, planned, attempted, responses, network errors and remaining counts
  from existing metadata/stats. It never stores a duplicate SharedState copy.
  Health checks and CONNECT rejections have explicit separate counters/scopes.
  ffuf returned rows remain a lower bound; unknown exact counts remain null.
  `error_count(state)` totals aggregate counts and supports legacy error rows.
- `src/coordinator/decision_engine.py`: actual decision prompt variables,
  error snapshots, reflection and session records include the lifecycle summary.
  `_verified_observations` permits only an allowlisted fact/value with exact type
  equality to observed state. Stored text is canonical and session-scoped; model
  causal prose, IDs, confidence and claimed applicability are not persisted as
  verified knowledge. Missing/malformed/false evidence is skipped. Session and
  decision history remain. Decision evaluations stay explicitly unverified.
  Historical prompt context is bounded, reflection sends latest 20 decisions
  with 300-character reasoning. Full HTTP rows are never put into these prompts.
- `src/coordinator/prompts.py`: explains generated != selected != attempted !=
  received, null != zero, and HTTP 200 != verified endpoint. Evidence schema is
  an object with `fact` and `value` from a supplied measured fact catalog.
- `tests/test_coordinator_observations.py`: lifecycle fixture1950/12/11/0/11,
  ffuf unknowns, aggregate errors, healthcheck/CONNECT scope, evidence/type checks,
  unsupported lessons, model-supplied existing IDs, bounded actual prompts,
  preserved session/decision history and exact unchanged model-call count.

## Verification

Command: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_coordinator_observations.py -v`

Initial 8 tests PASS; expanded 11-test run recorded at
`output_samples/diagnostics/coordinator_mvp_20261107/task4_tests.log`.
A twelfth test adds bounded/redacted error prompts in the final full regression.
Full suite and end-to-end evidence are recorded in `coordinator_mvp_progress.md`.

## Cost and limits

No extra HTTP or model invocation, retries, agents or scan stages. Each reflection
test checks one existing model invocation and zero HTTP calls. Summary construction
is constant size apart from existing error/history traversal; persisted raw
measurement artifacts remain complete. Reflection is deliberately conservative:
verified observations describe this session, not transferable causal explanations.
Existing historical knowledge is neither deleted nor retroactively validated.
