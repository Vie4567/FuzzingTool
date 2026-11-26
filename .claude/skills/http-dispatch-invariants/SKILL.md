---
name: http-dispatch-invariants
description: Checklist for writing or reviewing any FuzzingTool code that sends, paces, times out, measures or records target HTTP requests — ScopedReconTransport/OriginScopedTransport, http_fuzzing, verification_http, proxy pools, ffuf/CLI wrappers, origin_dispatch, recovery reservations, or a new transport/engine/thread pool. Use when adding or changing an HTTP code path, a timeout, a budget/quota/rate/stop rule, redirect or credential handling, or when asked whether a change can bypass runtime limits or scope. Not for planning a multi-origin stage (use multi-origin-stage) or for writing the test harness itself (use loopback-lab-tests).
---

# HTTP dispatch invariants

Every outbound target request in FuzzingTool shares one cooperative budget, one rate slot, one deadline and one set of stop rules. A new code path that skips any link below silently breaks the guarantees that the tests and stage docs claim. Check each item against the actual diff.

## 1. Reservation before the socket

The chokepoint is `src/coordinator/telemetry.py::record_http_attempt(kind=..., deadline=..., request=...)`. It calls `runtime.before_http()`, which calls `RuntimeBudget.reserve_http()`, and only then counts the attempt in telemetry.

- [ ] Call `record_http_attempt` **before** each network open, once per logical attempt. Retries, healthchecks and proxy-provider fetches are attempts too (`kind="proxy_healthcheck"`, `"proxy_provider"`).
- [ ] Handle the reservation exceptions without counting a dispatch:
  - `PipelineStopped`: the deadline, the budget or an earlier stop.
  - `HttpDispatchDeadline("max_duration")`: the phase's own deadline.
  - `OriginBudgetExhausted("origin_request_budget")`: a local quota denial. It does not stop or reset the global budget.

  See how `http_fuzzing.py` returns before the network open.
- [ ] Only `kind="ffuf_returned_response_lower_bound"` skips the reservation. External CLIs that can't expose a per-request count must call `mark_http_unknown(source)` (see `ffuf_helper.py`). Never invent counts.
- [ ] Don't open sockets with `urlopen`, `requests` or `httpx`, or through a helper that bypasses these functions.

## 2. Timeouts and deadline

- [ ] Wrap HTTP timeouts in `cap_http_timeout(seconds)`, which caps at the runtime's `http_timeout_seconds` and the remaining pipeline time. Use `cap_timeout` only for non-HTTP waits (LLM, subprocess).
- [ ] Call `check_deadline()` inside long loops, especially body-read loops (see `ScopedReconTransport.fetch_result` and `http_fuzzing.py`).
- [ ] Cap bodies at `runtime.body_cap` (`http_max_response_bytes`) and record `body_complete` / `body_truncated` honestly.
- [ ] The deadline is cooperative. A hard wall-clock bound needs `supervisor.run_pipeline_supervised`. Don't claim otherwise.

## 3. Stop rules from responses

- [ ] Pass every response, including `HTTPError` responses and proxy CONNECT failures, to `observe_response(status, headers)`. `RuntimeBudget.response` stops the run on 401/403/407/429 or on any `Retry-After` header.
- [ ] Don't swallow the stop. Callers check `current_runtime().stop_reason` and end the phase instead of continuing.

## 4. Context propagation

`RuntimeBudget`, telemetry, the current phase and the origin are all `ContextVar`s.

- [ ] Threads must inherit that context. `asyncio.to_thread` copies it, and so does `llm_client.py`'s `copy_context()` bridge. A bare `Thread(...)` or a `ThreadPoolExecutor` without `copy_context().run` sees `current_runtime() is None`, so **every limit is skipped**.
- [ ] Never create a second `runtime_session` / `telemetry_session` inside a run (one per pipeline, opened in `graph.run_pipeline`). Run tasks inside `telemetry_phase(name)` so attempts are attributed to the right phase.

## 5. Scope, redirects, TLS, credentials

- [ ] Target traffic goes through `ScopedReconTransport` / `ScopedVerificationTransport` (or openers built the same way) with `ProxyHandler({})`, `_ScopeGuard` and `_NoRedirect` (from `proxy_profiles.py`). Redirects are never followed, and auth headers are never sent off-origin (`allows_auth`).
- [ ] TLS verification stays on. `ScopedReconTransport` rejects `verify_ssl is not True`. A private CA goes through `tls_ca_file`.
- [ ] For multi-origin, use `OriginScopedTransport.open`:
  - it calls `check_dispatch` (exact origin, path, query and method, `GET`/`HEAD` only, `read_only`, credential binding);
  - it rejects request bodies, cookie jars and private headers supplied by the caller;
  - it wraps the dispatch in `http_origin(origin)` so the per-origin quota applies.

  Without an `http_origin` context, a runtime with quotas fails closed. Keep it that way.
- [ ] Credentials come only from `OriginCredentialContext.headers_for(url)` or the transport's private headers. Never read them from config, `SharedState`, discovered content or the LLM.
- [ ] Proxy use is opt-in (`--proxy-source`). Recon always connects directly.

## 6. Recovery-aware dispatch (B3.2B)

When `runtime.recovery` is set, `reserve_http` durably journals the reservation before the request counter moves, and `ScopedReconTransport.open`:

- builds a public request identity and refuses it if redaction would change it;
- calls `recovery.request_event("dispatch_started")`.

- [ ] New dispatch paths in recovery mode must go through this same transport, so the journal stays the single source of truth.
- [ ] A failed journal write means no request is sent.
- [ ] Never re-send a candidate that has a reservation.

## 7. What gets recorded

- [ ] Measurements record what was observed, not inferred: `attempted`, `status_code`, `bytes_received`, `response_time`, `stop_reason` and a typed `error`. An HTTP 200 is `observed_response`, not verified (`verification_status: "not_verified"`).
- [ ] Persist through `RunArtifacts` and `sanitize_for_log` / `transport.redact`. Don't persist raw headers, bodies, credentials, proxy userinfo or arbitrary `repr()` output.
- [ ] Errors that reach artifacts use fixed public codes (as in `origin_dispatch.py`), not exception text that may echo input.

## Reporting a review

For each violated item, give the `file:line`, the concrete bypass (for example "a worker thread without copy_context sends unbudgeted requests"), and the smallest fix. If a localhost test should prove the fix, say which assertion. The test belongs to `loopback-lab-tests`.
