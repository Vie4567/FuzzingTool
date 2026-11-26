# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sentinel Pentest / FuzzingTool is a multi-agent pipeline for web pentesting **on authorized targets only**. It runs recon, wordlist generation, HTTP path fuzzing, parameter discovery and soft-404 filtering, then writes a report. An LLM-driven LangGraph coordinator orchestrates the pipeline. Design docs (`Sentinel_Pentest_Design.md`, `docs/*.md`, `knowledge/README.md`) and many docstrings are in Vietnamese. Keep that style when editing them.

## Technology Stack

- CPython **3.12.10** on Windows x64, using the project `.venv`. There is no `pyproject.toml`, linter, type checker or pytest.
- Dependencies: `langgraph`, `langchain`, `langchain-core`, `langchain-openai` and `python-dotenv`, pinned in `requirements.txt` with constraints from `requirements.lock.txt`. The rest is stdlib, including the native HTTP client (`urllib`/`http.client`).
- LLM: an OpenAI-compatible endpoint (DeepSeek by default) through `langchain_openai`, configured in `.env`. See `.env.example` for the variable names.
- Optional CLI binaries: ffuf (`FFUF_PATH`/`PATH`), gobuster, katana, httpx, nmap and arjun. Each wrapper falls back to native code when its binary is missing.

## Architecture

The `run_pipeline(target_url, config)` / `build_coordinator_graph()` pair in `src/coordinator/graph.py` is one compiled `StateGraph`:

```
validate_input → init_state → tech_recon → llm_decide_recon → gen_words → llm_decide_wordlist
→ fuzzing → llm_decide_fuzzing → [param_disc] → filter_404 → report → reflection → END
```

- **Decision nodes** use `DecisionEngine` (`decision_engine.py`, `prompts.py`). It builds context from `SharedState` (`state.py`) and from past runs in `KnowledgeStore` (`knowledge_store/`, gitignored), then returns a `DecisionRecord`. The hard-coded guards in `guards.py` can override it: `CircuitBreaker`, `LLMCallLimiter` and `TarpitDetector`. They are module globals that `run_pipeline` resets.
- **Execution nodes** are wrapped by `_checkpointed`. Each run gets its own directory, written by `RunArtifacts` (`artifacts.py`): `output_samples/diagnostics/pipeline_<UTC>_<id>/result.json` plus numbered `checkpoints/`, all redacted (see `docs/pipeline_artifacts.md`).
- **Runtime (`runtime.py`)** keeps a context-var `RuntimeBudget` that holds:
  - the global HTTP budget, rate limit and cooperative deadline;
  - optional exact per-origin quotas (`http_origin_max_requests`);
  - automatic stops on 401/403/407/429 and `Retry-After`.

  Every target request goes through `before_http()` and `observe_response()`, with timeouts from `cap_http_timeout()`. Use a single runtime per run. Agents and origins never create their own.
- **Telemetry (`telemetry.py`)** counts logical HTTP attempts and LLM starts at the dispatch boundaries. LLM calls go through `invoke_logged` / `invoke_measured`, and responses are logged only after `sanitize_for_log` (`llm_logging.py`).
- **The supervisor (`supervisor.py`)** provides `run_pipeline_supervised`. It runs the pipeline in a worker process, which gives a hard deadline, and recovers partial artifacts if the worker dies.
- **Import order:** `src/coordinator/__init__.py` loads its entry points lazily. Agents import coordinator logging, so the agents-before-coordinator import order must keep working (see `docs/coordinator_environment.md`).

### Multi-origin (staged: B1 → B2.1 → B2.2 → B3.1 → B3.2A → B3.2B → B4.1 → B4.2A → B4.2B → B4.2C full local graph → B5 verified export → B6 full local acceptance; production not ready)

Read the latest `docs/multi_origin_b*.md` before touching this area. The production gate is **closed**. A `multi_origin` config stops before any agent or LLM runs, with `stop_reason=multi_origin_execution_not_enabled_b1` (`graph.py`, `origins.py`).

- **B1, scope:** `src/coordinator/origins.py` holds the public contract (canonical origins and observations). Observations never grant permission to dispatch. `src/tools/origin_scope.py` contains:
  - `OriginScopePolicy`, an exact allow-list of origin + path + method + `read_only`;
  - `OriginCredentialContext`, private in-memory credentials;
  - `OriginScopedTransport`, which reuses the TLS, redirect and budget behaviour of `ScopedReconTransport`.
- **B2.1 / B2.2, discovery:** B2.1 is `TechReconAgent.collect_discovery` and `merge_discovery_context`. B2.2 is `src/agents/origin_wordlist.py`, which selects candidates offline with no HTTP and no LLM.
- **B3.1, dispatch:** `src/tools/origin_dispatch.py` (`dispatch_selected`) is a sequential `python_http` harness. Only the supplied B1 transport can dispatch.
- **B3.2A, local graph:** `src/coordinator/origin_local.py` provides `LocalOriginTest`, a private, single-use context passed as `run_pipeline(..., local_origin_test=...)`. It runs the real graph for Agents 1–3 only, uses deterministic routing, and has no LLM and no proxy. It is **loopback only**: `loopback_url` rejects DNS names, `localhost` and ambiguous IP forms. It is never enabled from JSON config or `SharedState`.
- **B3.2B, recovery:** `src/coordinator/origin_recovery.py` provides `RecoveryJournal`: a hash-chained `journal.jsonl` and `head.json` under a `session.lock` OS lock. Each record is fsynced before the head is replaced. Torn or mismatched state fails closed. Replay is **at-most-once**: reserved candidates are never re-sent, and completed nodes are reused without re-invoking the agent or bumping retry counts.
- **B4.1, parameters:** `src/tools/origin_parameters.py` (`ParamDiscoveryAgent.verify_origin_parameters`) verifies query parameters on endpoints Agent 3 actually observed. Only names listed in an exact GET rule's optional `parameters` field are probed (`OriginScopePolicy.check_parameter_probe`), through `ParameterProbeTransport` and the existing `verify_parameters` controls. Without a parameter-enabled journal it still refuses to run under recovery (`parameter_recovery_not_supported_b41`).
- **B4.2A, probe recovery:** `LocalOriginTest(..., parameter_verification=True, parameter_max_requests=N)` (Python-only) runs Agent 4 after Agent 3 in the local graph; Agent 5 is bypassed, not executed.
  - Each probe reservation carries `probe{endpoint_id, unit_id, ordinal, role, parameter}`, and every dispatched probe journals a `measurement`. Each endpoint is one unit, with its own `verify_parameters` call and an anchored checkpoint.
  - `reconcile_probe_recovery` (in `origin_parameters.py`, called from `RecoveryJournal._restore`) decides replay by identity and process epoch, never by URL. It re-derives `verified` from journal measurements (`derive_unit_verdicts`) and makes units with reservations but no checkpointed result terminal (`interrupted`, never re-sent).
- **B4.2B, Soft404 (Agent 5):** `LocalOriginTest(..., soft404_verification=True, soft404_max_requests=N)` (Python-only) runs `Soft404FilterAgent.verify_origin_soft404` (`src/tools/origin_soft404.py`) through the real `run_soft404_filter` node. With parameter mode on too, Agents 4 and 5 both run.
  - Controls are allowed only by an operator's explicit `"soft404_controls": true` on an exact GET rule (`OriginScopePolicy.check_soft404_control`). They must be in the same origin and parent directory, have the same suffix and query, and be named `__sentinel_missing_<32 hex>`. Each group is one unit and is classified per origin with its own controls.
  - Classes: `genuine_distinct` / `soft_404` / `http_404` / `inconclusive` / `not_checked`. Endpoints stay `not_verified`. Agent 4 results are `context_only`.
  - The journal stores `soft404` identities, measurements (digests, no bodies), `soft404_group` and `soft404_decision`. `reconcile_soft404_recovery` keeps a strong class only if it re-derives it, at evidence level `rederived` or `metrics_journaled`. Similarity is checked against the journaled metrics, not recomputed. Unproven classes are denied, and unfinished groups become `interrupted`.
  - Shared integrity checks live in `src/coordinator/recovery_units.py`, which B4.2A also uses.
- **B4.2C, full local graph:** with both `parameter_verification=True` and `soft404_verification=True`, the same compiled graph runs Agents 1→5, then `generate_report` builds `multi_origin_report` (`src/coordinator/origin_report.py`, pure, per approved origin; discovered-only origins listed apart with `executed: false`; digest = sha256 of canonical `content`, no timestamps) and `post_session_reflection` builds `local_reflection` (deterministic, every observation resolves to a report path, `knowledge_writes = 0`, no LLM).
  - `pipeline_status` is set in `LocalOriginTest.finish` after Reflection; `completed` requires all five Agents `success` at every approved origin, no stop, no `interrupted`/`outcome_unknown`, and is impossible in older local modes and in `finalize_only`. A valid all-origin skip is `skipped`, never success.
  - Decisions are pure (`decision_for`); on resume a decision node is reused only if its record re-derives from that node's own checkpoint (`recovery_decision_mismatch`), so `decision_chain` never duplicates. A recomputed Report must equal the journal-anchored digest (`recovery_report_mismatch`).
  - `LocalOriginTest(..., resume=True, finalize_only=True)` keeps every integrity check, may summarize a session that ended by global stop/deadline/budget, preserves the original stop, and sends no HTTP (Agents not invoked, transports `dispatch_closed`, `RecoveryJournal.reserve` refuses). A verified `session_finished` returns `recovery.status = already_finished` without running the graph or writing the journal.
  - Only listed Agent 4/5 preconditions are contract failures (`CONTRACT_ERRORS` in `origin_local.py`): the Agent becomes `failed`, Agent 5 is `skipped` after an Agent 4 contract failure, and the graph still reaches Report. Resume-integrity errors and programming errors are never caught.
- **B5, verified export:** `src/coordinator/origin_export.py` (`export_session`) and the CLI `scripts/export_origin_report.py <recovery_dir> --output <new dir>` run offline after a session: no HTTP, LLM, KnowledgeStore, graph or journal write.
  - Only finished sessions are accepted: valid journal, head, every anchored checkpoint and `session_finished`. Otherwise there is a fixed `export_*` refusal and no file. Export never runs resume or `finalize_only` itself. Report v1 content and digest are copied verbatim and never re-digested; consistent forgeries are caught by re-deriving totals, statuses and sections against the journal.
  - Output is `report.json` (canonical envelope `multi_origin_report_export` v1, `export_digest`), `report.md` (rendered only from the envelope; every table cell names its JSON path) and `manifest.json`. They are published by one atomic rename and never overwrite.
  - Accounting comes from the journal: `reserved`, `dispatch_started`, `response_headers`, `measured`, `attempt_unknown` and `outcome_unknown`, with Recon included. Server receipt is never claimed; only lab access logs prove it. `severity` is `null`.
  - R8 (Report digest computed before `RunArtifacts` redaction) is proven at the persistence layer and fails closed. It is not fixed at source; see `docs/multi_origin_b5.md` §8.
- **B6, full acceptance (no new code):** `docs/multi_origin_b6.md`. It holds the acceptance matrix B1→B5 on fresh loopback evidence. The local MVP is `integration_verified`; production multi-origin is **not** ready, and the gap list is in §18.
  - Run the verifiers with the flags in each stage doc. `verify_origin_dispatch_evidence.py` and `verify_origin_graph_evidence.py` import a sibling module and fail under `python -I`.
  - The B1 and B2.1 verifiers live only in their evidence directories, not in `scripts/`.

## Module Responsibilities

- `src/agents/`:
  - `TechReconAgent`: recon channels CH-1…CH-7 (headers/cookies, DOM, JS bundles, crawl, framework probe, …).
  - `WordlistGenAgent`: developer-habit profile plus the `endpoint_`, `param_` and `sensitive_assembler` pattern engines.
  - `FuzzingAgent`: engines `python_http`, `ffuf_cli`, `proxy_http` and `loopback_lab`.
  - `ParamDiscoveryAgent`: parameter candidates and verification.
  - `Soft404FilterAgent`: classifies responses against measured controls, never by status or size alone.
  - `BaseAutonomousAgent`: asks the LLM to choose a tool and its options from `ToolRegistry` and records a justification.
- `src/tools/`:
  - Recon transport and observations: `recon_http`, `recon_discovery`, `recon_observations` and `tech_fingerprints`.
  - Native fuzzing: `http_fuzzing`. Proxy pools: `proxy_profiles` and `proxyscrape`.
  - Verification: `parameter_verification`, `verification_http` and `soft404`.
  - Auth: `auth_manager`. Diagnostics: `connection_diagnostics`.
  - CLI wrappers: the `*_helper.py` modules. The registry is `registry.py`.
- `src/coordinator/`: the graph, decisions, guards, runtime, telemetry, artifacts, validation (`InputValidationError`), the knowledge store and the multi-origin modules above.
- `knowledge/`: static JSON and wordlists that agents load at runtime. Put new signatures, paths and patterns here, not in code.
- `scripts/`: runners and the independent evidence verifiers `verify_origin_*_evidence.py`. The verifiers use the stdlib only and must **not** import `src`.

## Development Commands

```powershell
.\.venv\Scripts\python.exe -m pip check          # do not reinstall/upgrade unless asked

# Offline test shell (no .env, no tracing)
$env:PYTHON_DOTENV_DISABLED = "1"; $env:PYTHONIOENCODING = "utf-8"
$env:LANGSMITH_TRACING = "false"; $env:LANGCHAIN_TRACING_V2 = "false"

.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v                              # full suite
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_graph*.py' -v   # group
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_dispatch_http.py' -k test_global_budget_between_origins -v  # one test
# Dotted form (tests.test_x.Class) only works for modules that don't import sibling test modules (no tests/__init__.py)

# Stage evidence (example B3.2B; each stage doc gives its exact --expected-cases)
$env:B32B_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b32b_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_recovery*.py' -v
.\.venv\Scripts\python.exe -B scripts/verify_origin_recovery_evidence.py $env:B32B_EVIDENCE_DIR --expected-cases 27 --negative-checks

# Graph compile / local validation only — no HTTP, no LLM
.\.venv\Scripts\python.exe scripts/run_coordinator_scan.py --target https://<authorized> --check
```

Scripts that send real traffic need explicit authorization from the user and a named target: `run_coordinator_scan.py` without `--check`, `run_proxy_http_check.py`, `run_connection_diagnostic.py`, `import_proxyscrape_candidates.py`, and the root-level `test_recon_real.py`, `test_recon_target.py`, `test_wordlist_real.py` and `test_modules.py`.

## Coding Conventions

- Fail closed. Validate config strictly and raise `ValueError` / `InputValidationError`. Prefer an explicit stop reason over a silent fallback.
- New modules start with a docstring that states the stage, the scope and what the module deliberately does *not* do (see `origin_*.py`).
- Secrets stay in private Python contexts (credential profiles, transports) and never go into `config`, `SharedState`, artifacts or logs. Serialize only through the redaction in `artifacts.py` and `sanitize_for_log`, never with `repr()`.
- Reuse the existing transport, runtime and telemetry instead of adding parallel ones. Don't change single-target behaviour (`FuzzingAgent.execute()`, `WordlistGenAgent.execute()`) while extending multi-origin.
- Type hints are used sparingly. Match the surrounding file, use 3.12 syntax, and keep diffs minimal and local.
- Preserve existing line endings. Some working-copy files are LF while git uses autocrlf.

## Testing Strategy

- Tests use stdlib `unittest` (`TestCase`, `unittest.mock.patch`, `tempfile`, `subTest`). Don't introduce pytest, pytest-mock or Hypothesis; they aren't installed and would change dependencies.
- Everything in `tests/` is offline. HTTP tests start their own `ThreadingHTTPServer` on `127.0.0.1` port 0, and the recovery tests kill and restart a worker (`tests/origin_recovery_worker.py`). Fake the LLM and agents with fixtures.
- Multi-origin work uses three layers: unit tests (`test_origin_*.py`), localhost HTTP integration (`test_origin_*_http.py`, which writes evidence into `$env:B*_EVIDENCE_DIR`), and the independent verifier script (B3.x verifiers add `--negative-checks`).
- Test budgets, quotas, scope rejection and stop reasons, not just the happy path.

## Skill Selection Guidelines

Load only the skill that fits the task, never all of them. The project skills are in `.claude/skills/` and their sources are pinned in `skills-lock.json`. Don't install or remove skills.

**Project skills (written for this repo).** Their boundaries are deliberately separate; load only the one(s) the task touches:

| Task group | Skill |
|---|---|
| Starting, continuing, verifying or documenting a multi-origin stage (B1…B6, accepted locally); any question about the production gate | `multi-origin-stage` |
| Adding/changing/reviewing code that sends, paces, times out, measures or records target HTTP (transports, engines, proxy, ffuf, dispatch, recovery reservations, new threads) | `http-dispatch-invariants` |
| Writing/fixing tests in `tests/` or producing localhost evidence for a change | `loopback-lab-tests` (replaces `write-tests` here) |

A typical stage task uses `multi-origin-stage` to scope, `http-dispatch-invariants` while coding the HTTP path, and `loopback-lab-tests` for the proof — not all three for a single-target bugfix.

**Third-party skills:**

| Task | Use | Caveats for this repo |
|---|---|---|
| Locating code / explaining it | `codebase-research`, `explain-code` | — |
| Bug or failing test | `systematic-debugging` | `find-polluter.sh` assumes JS-style test globs; adapt it to `unittest`. |
| New behaviour | `test-driven-development` | Write the tests in `unittest`. |
| Adding tests to existing code | `loopback-lab-tests` | Don't use `write-tests`: it mandates pytest, `mocker` and `conftest.py`. |
| Planning multi-step work | `writing-plans`, then `executing-plans` | Drop the plan's `git commit` steps unless the user asks for commits. The `executing-plans/scripts/task-*` helpers need the missing `subagent-driven-development` skill and **will fail**. Track progress by hand. |
| Design of a new stage or feature | `brainstorming` | Only for real design work. Its visual companion starts a local Node server, so ask first. It saves specs to `docs/superpowers/specs/` and commits them; ask first. |
| General code review | built-in `code-review`, or `requesting-code-review` | Avoid `python-code-review`: it assumes 3.13+, ruff, pyright and `~/.claude/CLAUDE.md`, none of which exist here. |
| Security review of a diff (scope, transport, credentials, runtime, recovery) | `differential-review` | Have it write its report to the scratchpad, not the repo. |
| API or config footguns (scope policy, quotas, gates) | `sharp-edges` | Read-only. |
| Static analysis of **this repo's source** | `semgrep` | `semgrep` and `jq` aren't installed, and `run-scans.sh` can clone third-party rule repos. Get approval first. |
| Before claiming done | `verification-before-completion` | — |
| Handling review feedback / asking for review | `receiving-code-review`, `requesting-code-review` | — |
| Session handoff | `task-handover` | Writes `.claude/HANDOVER.md`, uncommitted. |

These skills are for **coverage-guided fuzzing campaigns** (libFuzzer, AFL++, C/C++/Rust harnesses, llvm-cov), not for developing this HTTP web fuzzer: `harness-writing`, `fuzzing-obstacles`, `coverage-analysis` and `fuzzing-dictionary`. At most, `fuzzing-dictionary` offers ideas for token extraction into `knowledge/wordlists`. Two more don't fit as-is: `modern-python` would migrate the project to uv, ruff and ty, which conflicts with the pinned pip lock, and `property-based-testing` needs Hypothesis. Use either only if the user explicitly asks. Read a skill's bundled scripts before running them.

## Git Safety

- The working tree often holds uncommitted, in-progress user changes. Never `commit`, `push`, `stash`, `reset`, `checkout -- <file>`, `clean` or rebase unless the user explicitly asks.
- Never overwrite a modified file wholesale without reading it first. Make targeted edits.
- The branch is `feature/fuzzingtool-integration` and `main` is the base. Don't commit `.env`, `logs/`, `output_samples/`, `knowledge_store/` or proxy credentials; they are gitignored for a reason.

## Security Constraints

- Send HTTP traffic, fuzzing or scans only to targets the user has explicitly authorized. Automated runs are limited to loopback (`127.0.0.1` / `[::1]`) labs.
- Don't read or print the values in `.env`. `.env.example` lists the variable names.
- Don't open the multi-origin production gate, enable proxy or LLM paths for multi-origin, or bypass `before_http`, scope policy, quotas or stop-on-401/403/429, unless a stage doc says so and the user asks.
- Don't modify `.venv`, site-packages or the pinned dependencies.

## Definition of Done

1. The targeted tests pass, then the full offline suite: `unittest discover -s tests`.
2. For multi-origin changes, the matching stage's HTTP tests and its `verify_origin_*_evidence.py` both pass, using the exact flags from that stage's doc. `--negative-checks` exists for the dispatch, graph and recovery verifiers, but not for wordlist.
3. If graph wiring or imports changed, `run_coordinator_scan.py --check` (or `test_coordinator_environment.py`) passes.
4. No secrets appear in the new artifacts or logs. Single-target behaviour is unchanged unless that was the goal.
5. Report the real results, including failures and anything skipped. Leave committing to the user.
