# Agent 1 P0 — implementation and verification

Scope: fingerprint evidence, truthful per-channel execution, Coordinator/Agent 2
handoff, and URL/origin correctness. Keep the existing pipeline, dependencies,
TLS/auth/scope policy and shared runtime budgets. No public targets or provider
calls, no commit/push.

## Baseline (2026-11-13)

`python -B -m unittest discover -s tests -v`: **408 tests PASS**, 106.982s.
Evidence: `output_samples/diagnostics/agent1_p0_20261113/tests_before.log`.
Source hashes before this work are in `source_before.json` in that directory.

## Task 1: fingerprint correctness

Files/functions: `src/tools/tech_fingerprints.py` (`header_fingerprint`,
`resolve_technologies`); `src/agents/tech_recon.py` (CH1 wrapper, technology
resolution inside `_run_async`).

The former matcher treated the existence of `Server` as DDoS-Guard and mixed
frontend/CMS/backend into one field. The replacement matches specific header,
cookie-name, body and DOM signatures and attaches `field`, `value`, `source`,
`indicator`, `classification`. Generic Server/cache/CDN evidence is insufficient
to confirm WAF. Multiple conflicting signatures remain ambiguous. Frontend,
backend, CMS and backend language are independent; React does not replace
ASP.NET, and ASP.NET alone cannot establish C# rather than another .NET language.

`tests/test_recon_fingerprints.py`: 25 tests covering negatives, specific vendor
signals, cookie-name boundaries/multiple headers, mixed layers, conflicts,
Unknown, malformed HTML and no credential values in evidence. Pure computation:
zero HTTP/LLM calls. Knowledge JSON and dependencies were not changed.

## Task 2: errors, measurements and completion

Files/functions: `src/tools/recon_http.py` (`open`, `fetch_result`, compatible
`fetch`); `src/tools/recon_records.py` (`ReconRecords`, channel transport);
`src/agents/tech_recon.py` (`_run_async`, `execute`, individual channels).

The old code discarded errors after a successful homepage, counted selected JS
files as analyzed, and lost observed HTTP status when body reading failed.
Now every channel retains actual attempts/responses/network errors/read errors,
errors and outcomes. CH2 explicitly shares CH1's response without adding another
HTTP count. Incomplete input is skipped or partial rather than completed.
HTTP404 is a response; DNS/TLS/reset/timeout without headers is a transport error.
EOF before declared Content-Length and body timeout retain status and received
prefix. `bytes_received` counts the limit-detection byte; `content_length` is the
retained prefix length. Raw headers/bodies are not persisted in request records.

`completed` describes supported collection, not endpoint verification. Mixed
transport outcomes are partial; failure of the initial request yields failed
with one attempt and no follow-up requests. Existing runtime stop reasons win;
no retry, new proxy route or extra request is used for error aggregation.
Optional login requests stay in global telemetry and are explicitly outside the
channel-ledger `count_scope`.

`execute` records the native suite actually executed. Existing model advice is
marked advisory; the justification uses bounded measurements rather than the
entire profile. Failed/stopped Recon does not make narrative model calls.

## Task 3: SharedState and Agent 2 contract

Files/functions: `src/coordinator/graph.py` (`_recon_execution`,
`_sync_recon_errors`, `run_tech_recon`, `run_wordlist_gen`);
`src/coordinator/state.py`; `src/agents/wordlist_gen.py`
(`_bounded_recon_context`, `execute`, `_generate_wordlist_internal`,
`_analyze_dev_profile_with_llm`).

Legacy tech/path/WAF fields remain. `recon_profile` retains target URL,
technology evidence/conflicts, architecture, origin-bearing paths, parameters,
forms and API context. `recon_execution` retains channel measurements and full
sanitized errors. Coordinator maps completed/partial/failed truthfully and
summarizes errors per attempt/channel/type without double-counting a replay.
Retries with no responses retain the earlier profile with its attempt label,
but execution remains failed. Existing global telemetry is not incremented a
second time from Recon statistics.

Agent 2 accepts optional `target_url` and `recon_profile` while retaining its
three original positional arguments. Operator target identity takes precedence
over inferred API hosts. The existing developer-profile call receives bounded
context (including a node budget); no model call is added. Observed declarations,
candidate references and inferred conclusions remain separate, and generated
wordlists/developer profiles do not become verified facts.

`tests/test_recon_contract.py`: 14 tests, including real compiled LangGraph
checkpoints, partial/failed/error/retry cases, legacy compatibility, redaction,
one-call prompt integration and adversarial nested context size.

## Task 4: URLs, scope and provenance

Files/functions: `src/tools/recon_observations.py` (`absolute_url`,
`path_observation`, `target_paths`, `_DOMParser`, `parse_dom`);
`src/agents/tech_recon.py` (JS, crawler, probes, schema and error probe);
`src/tools/registry.py` (CH3 wrapper URL context).

The old code concatenated target subpaths with root resource paths, removed the
question mark from probe queries and stripped origins from JS/sitemap URLs.
Now URL resolution keeps absolute/relative paths and queries, public-resource
probes start at the origin, and GET/OPTIONS/TRACE preserve the target endpoint.
External references remain candidates with their original origin, and never
enter legacy target-only paths. Script source provenance is separate from the
document URL used to resolve fetch references. HTML base origins and form
query/body methods are preserved. Invalid explicit schema servers are rejected,
not silently reassigned to the target. Existing exact-origin/TLS/auth policies
continue to gate all dispatched requests.

The stdlib HTML parser supplies forms/fields consistently without installing
BeautifulSoup. OpenAPI JSON keeps operation/parameter context; unsupported
YAML/GraphQL is explicitly skipped. This does not add an API scan or schema
server request.

`tests/test_recon_p0_integration.py`: 17 tests with local HTTP servers, independent
server request records and a socket guard; plus pure parsing fixtures.

## Verification and reproducible commands

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p "test_recon*.py" -v
.\.venv\Scripts\python.exe -B -u scripts/run_recon_p0_lab.py
```

The lab defaults to a new output directory on each run. It uses actual Recon,
Coordinator and Wordlist nodes, actual localhost HTTP, fixture model responses
and the real checkpoint writer. It never calls a provider or public target.

- Baseline: 408 PASS, 106.982s (`tests_before.log`).
- Intermediate Recon suite: 80 PASS, 29.516s (`tests_recon_first.log`).
- Intermediate full suite: 462 PASS, 121.255s (`tests_after.log`).
- Final full suite: **464/464 PASS**, 119.616s (`tests_final.log`): all 408
  original tests plus 56 new tests (25 fingerprint, 14 contract, 17 integration).

Verified local handoff lab (2026-11-14):
`output_samples/diagnostics/agent1_p0_lab_20261114_verified/`.

| Scenario | Recon status | Attempts | Responses | Network errors | Fixture LLM calls |
|---|---|---:|---:|---:|---:|
| completed | completed | 14 | 14 | 0 | 18 |
| partial | partial | 14 | 13 | 1 | 18 |
| failed | failed | 1 | 0 | 1 | 0 |
| Total | All lab assertions PASS | 29 | 27 | 2 | 36 |

Agent 1 itself uses two fixture-model calls per successful/partial collection,
unchanged from its previous advisory/narrative interfaces; the other calls are
Agent 2's existing generation flow. Provider calls: **0**. External connection
attempts: **0**. Wordlist performs no additional HTTP request. Every scenario's
`server_requests.json`, `model_calls.json`, `result.json`, `evidence.json` and
checkpoints agree. Source hashes match the verified lab manifest except a final
trailing-blank-line cleanup in `tech_recon.py`; `format_verification.json` records
the tested/final hashes and confirms identical Python AST. No behavior changed
after the final suite/lab. Scoped `git diff --check` also passes.

This is an Agent1–Coordinator–Agent2 handoff lab, not a new full five-agent live
scan. Its overall `pipeline_status` correctly stays partial because Fuzzing,
Parameter and Soft404 are not run by this scoped runner. Their regression tests
are included in the full suite. An earlier lab attempt was rejected by existing
validation (`max_iterations=2`); it made no HTTP/provider calls. Only the runner
was corrected to the valid minimum of 5; production validation was unchanged.

## Files changed in this task

- Source: `src/agents/tech_recon.py`, `src/agents/wordlist_gen.py`,
  `src/coordinator/graph.py`, `src/coordinator/state.py`,
  `src/tools/recon_http.py`, `src/tools/registry.py`.
- New helpers: `src/tools/tech_fingerprints.py`, `src/tools/recon_records.py`,
  `src/tools/recon_observations.py`.
- New tests: `tests/test_recon_fingerprints.py`, `tests/test_recon_contract.py`,
  `tests/test_recon_p0_integration.py`.
- New local lab runner: `scripts/run_recon_p0_lab.py`.
- Documentation: this file. Logs/results are under ignored diagnostics folders.

Hashes compared against the task-start snapshot show no deleted source files,
no dependency/lockfile changes and no unrelated source edits. The pre-existing
workspace changes remain; no Git staging/commit/push was performed.

## Remaining scope and limits

- Signature evidence identifies observed indicators, not an independently
  verified production software inventory. Conflicts/insufficient evidence stay
  Unknown; inferred language/architecture is labeled.
- No Neo4j/MCP, browser execution, recursive JS chunk execution, complete
  OpenAPI reference resolution, YAML parser or GraphQL introspection.
- No public-site/provider benchmark or statistical precision/recall claim.
- Standalone Recon without Coordinator runtime retains its previous local
  limits; shared global budget/rate/deadline enforcement applies in Coordinator.
- Legacy externally injected results without execution metadata remain usable
  but explicitly carry `measurement_status=legacy_unreported`; no counts are
  invented for them.

## Acceptance conclusion (2026-11-14)

**The four Agent 1 P0 tasks pass within the verified native Recon scope.** This
conclusion includes independent local HTTP evidence, real Coordinator/Agent2
handoff, retained partial/failed artifacts and the complete regression suite.
It is not a claim that the entire Agent 1 feature roadmap or a production
multi-stack benchmark is complete.

| Requirement | Evidence | Result |
|---|---|---|
| Ordinary Server/CDN not confirmed WAF; layers/evidence/Unknown correct | 25 fingerprint tests + mixed ASP.NET/React local lab | PASS |
| Per-channel counts, partial/failed and retained actual responses | 17 integration tests; lab 14/14/0, 14/13/1, 1/0/1 | PASS |
| Body timeout/limit/early EOF retain status and actual bytes | Integration tests for runtime and legacy transport API | PASS |
| Profile/target/forms/params/API context reach Agent2 and checkpoint | 14 contract tests + actual two-node handoff lab | PASS |
| URL/subpath/query/origin correct; no foreign dispatch or origin reassignment | Fixture server logs, socket guard and URL/schema tests | PASS |
| Auth/TLS/redaction, quotas, retries, deadline/supervisor unchanged | Entire 464-test suite, including original policy/limits tests | PASS |
| No extra measurement-validation HTTP/model calls | Ledger is local computation; lab Wordlist HTTP delta0; Agent1 calls2/2/0 | PASS |

No unresolved blocker was observed for these acceptance cases. Limitations
listed above remain explicit work for later phases; do not describe this as
Neo4j/MCP, full GraphQL/YAML support or a verified public-target deployment.
