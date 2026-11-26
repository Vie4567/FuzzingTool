---
name: loopback-lab-tests
description: Writes and runs FuzzingTool tests in the repo's own style — stdlib unittest, offline, with real ThreadingHTTPServer labs on 127.0.0.1 port 0, independent server access logs, optional evidence directories, faked LLM/agents and owned subprocess workers. Use when adding or fixing tests under tests/, when a change to HTTP, runtime, recovery, scope or graph code needs localhost proof, or when a test must show that no request escaped scope or budget. Not for pytest/Hypothesis setups (not installed), not for traffic to real targets, and not for deciding what a multi-origin stage must prove (use multi-origin-stage).
---

# Loopback lab tests

The suite runs fully offline and uses no third-party test tooling. Integration tests start real local HTTP servers and compare what the server logged against what the tool reported. Match the existing style; don't introduce pytest, pytest-mock, Hypothesis or conftest fixtures.

## Layout and running

- Tests live in `tests/test_*.py`. There is **no `tests/__init__.py`**, and several HTTP tests import sibling test modules (`test_origin_dispatch_http.py` imports `test_discovery_http_integration as b21` and `test_origin_wordlist_http as b22`; `test_http_progress.py` imports `test_proxy_fuzzing`). Run them with `discover`, which puts `tests/` on `sys.path`:

  ```powershell
  .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_dispatch_http.py' -v
  .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_dispatch_http.py' -k test_global_budget_between_origins -v
  ```

  The dotted form `python -m unittest tests.test_x` only works for modules without sibling imports.
- Use the offline env from `CLAUDE.md`: `PYTHON_DOTENV_DISABLED=1` and tracing disabled.
- Pair them: unit tests (`test_<area>.py`, no sockets) plus localhost integration (`test_<area>_http.py` or `*_integration.py`).
- Start each module with a docstring that says what is real and what is excluded, for example `"""B3.1 real localhost chain; no HTTP mocks, public Internet or provider LLM."""`.

## Building a lab server

Follow `tests/test_origin_dispatch_http.py` / `tests/test_origin_recovery_http.py`:

- `ThreadingHTTPServer(('127.0.0.1', 0), Handler)` (port 0 means the OS picks), `server.daemon_threads = True`, and `serve_forever` on a daemon `Thread`. Shut down and `server_close()` in `tearDownClass`.
- Use several servers with roles (for example `frontend`, `gateway`, `unapproved`). Each origin is `f'http://127.0.0.1:{server.server_port}'`. Keep one server unapproved so out-of-scope traffic can be detected.
- The handler appends a row per request under `server.lock`: UTC, monotonic time, origin, path, method, status, fault, phase, and `credential_identity` (`'frontend' | 'anonymous' | 'unexpected'`) instead of raw credential values. For crash tests, write each row to a JSONL file with `flush()` + `os.fsync()`.
- Drive faults per path through `server.faults`: status codes (401/403/429), `retry_after`, `redirect` (Location to the unapproved server, which must never be followed), `timeout`, `disconnect`, partial `body`. A refused connection uses a port that was bound and then closed.
- Count requests from the **server logs**, never from the tool's own counters, then assert that the two agree.

## Isolation rules

- Never use a DNS name, `localhost` or a public IP. Multi-origin lab code accepts only literal loopback (`loopback_url`).
- Where a test needs no network at all, block it: `patch("socket.create_connection", side_effect=AssertionError(...))`, `patch("socket.socket.connect", ...)` or `patch.object(module.socket, "getaddrinfo", ...)`.
- Fake the LLM at the agent boundary. Pass `llm=Mock()` or a small fake class to agents (`FuzzingAgent(llm=...)`, `TechReconAgent(llm=...)`). For graph tests, patch `graph._get_decision_engine` to return a `SimpleNamespace(llm=None, make_decision=...)`. Never call a provider.
- Credentials are obviously fake literals (for example `'Bearer b32b-local-only-fake'`). Assert they never show up in artifacts or logs.
- Configure limits explicitly for each test (`http_max_requests`, `http_rate_limit`, `http_timeout_seconds`, `pipeline_timeout_seconds`, `http_origin_max_requests`). The existing pattern wraps `runtime_session` with `patch.object(..., side_effect=configured)` keyed on `self._testMethodName`.

## Evidence directories

- Each stage test reads an optional env var (`B1_EVIDENCE_DIR`, `B21_…`, `B22_…`, `B31_…`, `B32A_…`, `B32B_…`). If it's unset, use `tempfile.TemporaryDirectory()` plus `addCleanup`. If it's set, write a subdirectory per case (`case_id` or `uuid4().hex[:10]`) for the matching `scripts/verify_origin_*_evidence.py`.
- When reusing another stage's `setUp`, clear its env var (`patch.dict(os.environ, {'B22_EVIDENCE_DIR': ''})`) so evidence doesn't mix.
- Pass `artifact_root` to the run's config inside that directory. Never write into the repo or into existing `output_samples` runs.

## Crash and restart tests

Use an owned worker script (`tests/origin_recovery_worker.py`). The parent:

1. writes a config JSON;
2. starts `subprocess.Popen([sys.executable, '-B', worker, config, mode, label], cwd=<repo root>)`;
3. waits with a bounded loop for a barrier file the worker writes;
4. calls `proc.kill()` (a real kill, not a mocked exception);
5. snapshots the journal, checkpoints and access logs;
6. starts a `resume` worker.

The worker sets the offline env vars itself, patches only its own barrier hook, and bounds every wait (for example 30 s).

## What to assert

- **Scope and safety:** no row on the unapproved server, no redirect followed, credentials only to the bound origin, stop reasons (`http_401`, `http_429`, `retry_after`, `pipeline_deadline`, `http_request_budget`, `origin_request_budget`, `max_duration`).
- **Accounting:** server rows equal telemetry and runtime counts. The global budget and the per-origin quotas both hold. Rate pacing is measured from the servers' monotonic timestamps.
- **Artifacts:** they exist, they are redacted, and their status vocabulary is honest (`observed_response`, `not_verified`).
- Use `subTest` for tables of inputs. Keep the timing margins of the existing tests. Don't loosen them to make a flaky test pass; investigate with `systematic-debugging` instead.
