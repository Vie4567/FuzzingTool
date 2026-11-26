"""Per-run counters recorded at dispatch boundaries, never inferred from inputs.

HTTP counts logical outbound attempts (including DNS/TLS/CONNECT failures), not
TCP packets or the CONNECT handshake as a second target request. LLM counts
LangChain model-start events, or public invoke attempts for custom clients
without callbacks. Hidden SDK retries cannot be measured here. Coordinator-
created clients disable SDK retries.
"""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock


_CURRENT = ContextVar("sentinel_run_telemetry", default=None)
_PHASE = ContextVar("sentinel_telemetry_phase", default="unassigned")


class RunTelemetry:
    """Thread-safe shared counters, carried by the current execution context."""

    def __init__(self, max_llm_calls=50):
        if (isinstance(max_llm_calls, bool) or not isinstance(max_llm_calls, int)
                or max_llm_calls < 0):
            raise ValueError("max_llm_calls must be a non-negative integer")
        self.max_llm_calls = max_llm_calls
        self._lock = Lock()
        self._http = Counter()
        self._http_phase = {}
        self._unknown = set()
        self._llm = Counter()
        self._llm_component = {}
        self._llm_phase = {}

    def http_attempt(self, *, phase, kind, count=1):
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("HTTP count must be a non-negative integer")
        with self._lock:
            self._http[kind] += count
            self._http_phase.setdefault(phase, Counter())[kind] += count

    def http_unknown(self, *, phase, source):
        with self._lock:
            self._unknown.add((phase, source))

    def llm_start(self, component, phase):
        with self._lock:
            if self._llm["attempted"] >= self.max_llm_calls:
                self._llm["quota_rejections"] += 1
                from .guards import LLMQuotaExhaustedError
                raise LLMQuotaExhaustedError(
                    f"LLM call limit reached before dispatch: {self.max_llm_calls}"
                )
            self._llm["attempted"] += 1
            self._llm_component.setdefault(component, Counter())["attempted"] += 1
            self._llm_phase.setdefault(phase, Counter())["attempted"] += 1

    def llm_finish(self, component, phase, *, failed):
        outcome = "failed" if failed else "succeeded"
        with self._lock:
            self._llm[outcome] += 1
            self._llm_component[component][outcome] += 1
            self._llm_phase[phase][outcome] += 1

    @staticmethod
    def _llm_counts(counter):
        return {key: counter[key] for key in ("attempted", "succeeded", "failed")}

    def snapshot(self):
        with self._lock:
            known = sum(self._http.values())
            llm = self._llm_counts(self._llm)
            llm.update(
                in_flight=llm["attempted"] - llm["succeeded"] - llm["failed"],
                quota_rejections=self._llm["quota_rejections"],
                max_calls=self.max_llm_calls,
                count_scope="LangChain model-start events; direct custom invoke attempts; includes failures, excludes hidden SDK retries",
                by_component={key: self._llm_counts(value) for key, value in self._llm_component.items()},
                by_phase={key: self._llm_counts(value) for key, value in self._llm_phase.items()},
            )
            return {
                "llm": llm,
                "http": {
                    "total_requests": None if self._unknown else known,
                    "known_requests": known,
                    "count_complete": not self._unknown,
                    "count_scope": "logical_outbound_attempts_including_transport_failures; excludes LLM provider HTTP",
                    "by_kind": dict(self._http),
                    "by_phase": {key: dict(value) for key, value in self._http_phase.items()},
                    "unknown_sources": [{"phase": phase, "source": source}
                                        for phase, source in sorted(self._unknown)],
                },
            }


def current_telemetry():
    return _CURRENT.get()


@contextmanager
def telemetry_session(max_llm_calls=50):
    """Isolate one run; asyncio.to_thread copies this context into crawl workers."""
    telemetry = RunTelemetry(max_llm_calls=max_llm_calls)
    token = _CURRENT.set(telemetry)
    phase_token = _PHASE.set("unassigned")
    try:
        yield telemetry
    finally:
        _PHASE.reset(phase_token)
        _CURRENT.reset(token)


@contextmanager
def telemetry_phase(name):
    token = _PHASE.set(name)
    try:
        yield
    finally:
        _PHASE.reset(token)


def record_http_attempt(*, kind="target", count=1, deadline=None, request=None):
    from .runtime import before_http
    if kind != "ffuf_returned_response_lower_bound":
        before_http(kind, deadline=deadline, request=request, phase=_PHASE.get())
    telemetry = _CURRENT.get()
    if telemetry is not None:
        telemetry.http_attempt(phase=_PHASE.get(), kind=kind, count=count)


def mark_http_unknown(source):
    telemetry = _CURRENT.get()
    if telemetry is not None:
        telemetry.http_unknown(phase=_PHASE.get(), source=source)


def start_llm_call(component):
    from .runtime import check_deadline
    check_deadline()
    telemetry, phase = _CURRENT.get(), _PHASE.get()
    if telemetry is None:
        return None
    telemetry.llm_start(component, phase)
    return telemetry, component, phase


def finish_llm_call(handle, *, failed=False):
    if handle is not None:
        telemetry, component, phase = handle
        telemetry.llm_finish(component, phase, failed=failed)


def invoke_measured(runnable, input_value, *, component):
    """Measure model dispatch, excluding prompt formatting/parser failures.

    LangChain chains contain formatting/parsing work around the model. Model
    callbacks count only actual model starts. Plain injected clients lacking a
    callback interface count their public invoke attempts instead.
    """
    from .runtime import check_deadline
    check_deadline()
    if _CURRENT.get() is None:
        return runnable.invoke(input_value)
    try:
        from langchain_core.runnables import Runnable
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError:
        Runnable = ()
    if not isinstance(runnable, Runnable):
        handle = start_llm_call(component)
        try:
            result = runnable.invoke(input_value)
        except BaseException:
            finish_llm_call(handle, failed=True)
            raise
        finish_llm_call(handle)
        return result

    telemetry, phase = _CURRENT.get(), _PHASE.get()

    class ModelDispatchCounter(BaseCallbackHandler):
        raise_error = True

        def __init__(self):
            self.pending = set()
            self.lock = Lock()

        def _start(self, run_id):
            # Capture the run explicitly even when LangChain dispatches its own
            # callback workers without copying ContextVars.
            with self.lock:
                check_deadline()
                if run_id in self.pending:
                    return
                telemetry.llm_start(component, phase)
                self.pending.add(run_id)

        def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
            self._start(run_id)

        def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
            self._start(run_id)

        def _finish(self, run_id, failed):
            with self.lock:
                if run_id not in self.pending:
                    return
                self.pending.remove(run_id)
                telemetry.llm_finish(component, phase, failed=failed)

        def on_llm_end(self, response, *, run_id, **kwargs):
            self._finish(run_id, False)

        def on_llm_error(self, error, *, run_id, **kwargs):
            self._finish(run_id, True)

        def close(self):
            with self.lock:
                for _run_id in self.pending:
                    telemetry.llm_finish(component, phase, failed=True)
                self.pending.clear()

    callback = ModelDispatchCounter()
    try:
        return runnable.invoke(input_value, config={"callbacks": [callback]})
    finally:
        callback.close()


def sync_state(state):
    """Replace legacy estimates; no-op for standalone calls outside a run."""
    telemetry = _CURRENT.get()
    if telemetry is not None:
        snapshot = telemetry.snapshot()
        state["telemetry"] = snapshot
        state["llm_call_count"] = snapshot["llm"]["attempted"]
        state["coordinator_llm_calls"] = snapshot["llm"]["by_component"].get("Coordinator", {}).get("attempted", 0)
        state["total_http_requests"] = snapshot["http"]["total_requests"]
        state["known_http_requests"] = snapshot["http"]["known_requests"]
    return state
