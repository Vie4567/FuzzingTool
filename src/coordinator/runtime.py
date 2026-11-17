"""Cooperative deadlines and a shared HTTP dispatch budget for one pipeline.

Use run_pipeline_supervised for a hard wall-clock bound, including blocked I/O.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
import time

_CURRENT = ContextVar("coordinator_runtime", default=None)


class PipelineStopped(TimeoutError):
    pass


class HttpDispatchDeadline(TimeoutError):
    """A phase cannot start another request within its own time budget."""
    pass


class RuntimeBudget:
    def __init__(self, config):
        self.started = time.monotonic()
        self.deadline = self.started + config.get("pipeline_timeout_seconds", 600)
        self.max_requests = config.get("http_max_requests", 500)
        self.rate = config.get("http_rate_limit", 2)
        self.timeout = config.get("http_timeout_seconds", 10)
        self.body_cap = config.get("http_max_response_bytes", 2*1024*1024)
        self.requests = 0
        self.next_start = self.started
        self.stop_reason = None
        self.lock = Lock()

    def check(self):
        if not self.stop_reason and time.monotonic() >= self.deadline:
            self.stop_reason = "pipeline_deadline"
        if self.stop_reason:
            raise PipelineStopped(self.stop_reason)

    def reserve_http(self, *, deadline=None):
        with self.lock:
            self.check()
            if self.requests >= self.max_requests:
                self.stop_reason = "http_request_budget"
                self.check()
            wait = max(0, self.next_start - time.monotonic())
            if time.monotonic() + wait >= self.deadline:
                self.stop_reason = "pipeline_deadline"
                self.check()
            if deadline is not None and time.monotonic() + wait >= deadline:
                raise HttpDispatchDeadline("max_duration")
            if wait:
                time.sleep(wait)
            self.check()
            if deadline is not None and time.monotonic() >= deadline:
                raise HttpDispatchDeadline("max_duration")
            self.requests += 1
            self.next_start = time.monotonic() + 1 / self.rate

    def response(self, status, headers=None):
        if status in {401, 403, 407, 429}:
            self.stop_reason = f"http_{status}"
        elif any(str(key).lower() == "retry-after" for key in (headers or {})):
            self.stop_reason = "retry_after"

    def snapshot(self):
        return {"elapsed_seconds": time.monotonic()-self.started,
                "remaining_seconds": max(0, self.deadline-time.monotonic()),
                "http_dispatches": self.requests, "http_max_requests": self.max_requests,
                "stop_reason": self.stop_reason, "deadline_mode": "cooperative; use supervisor for hard deadline"}


def current_runtime():
    return _CURRENT.get()


@contextmanager
def runtime_session(config):
    budget = RuntimeBudget(config)
    token = _CURRENT.set(budget)
    try:
        yield budget
    finally:
        _CURRENT.reset(token)


def check_deadline():
    budget = _CURRENT.get()
    if budget:
        budget.check()


def cap_timeout(seconds):
    budget = _CURRENT.get()
    if budget:
        budget.check()
        return max(.001, min(float(seconds), budget.deadline-time.monotonic()))
    return seconds


def cap_http_timeout(seconds):
    """Apply the operator's shared HTTP limit independently of LLM timeouts."""
    budget = _CURRENT.get()
    return cap_timeout(min(seconds, budget.timeout) if budget else seconds)


def before_http(kind="target", *, deadline=None):
    budget = _CURRENT.get()
    if budget:
        budget.check()
        if kind != "ffuf_returned_response_lower_bound":
            budget.reserve_http(deadline=deadline)
    elif deadline is not None and time.monotonic() >= deadline:
        raise HttpDispatchDeadline("max_duration")


def observe_response(status, headers=None):
    budget = _CURRENT.get()
    if budget:
        budget.response(status, headers)


def snapshot():
    budget = _CURRENT.get()
    return budget.snapshot() if budget else {}
