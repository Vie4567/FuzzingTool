"""Cooperative deadlines and a shared HTTP dispatch budget for one pipeline.

Use run_pipeline_supervised for a hard wall-clock bound, including blocked I/O.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
import time

_CURRENT = ContextVar("coordinator_runtime", default=None)
_HTTP_ORIGIN = ContextVar("coordinator_http_origin", default=None)


class PipelineStopped(TimeoutError):
    pass


class HttpDispatchDeadline(TimeoutError):
    """A phase cannot start another request within its own time budget."""
    pass


class OriginBudgetExhausted(RuntimeError):
    """A local quota denial before dispatch; it does not reset/stop global budget."""
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
        limits = config.get("http_origin_max_requests")
        if limits is not None:
            from .origins import canonical_origin, public_url
            if not isinstance(limits, dict) or not 1 <= len(limits) <= 32:
                raise ValueError("http_origin_max_requests requires explicit origin quotas")
            for origin, limit in limits.items():
                if (canonical_origin(public_url(origin, origin_only=True)) != origin
                        or type(limit) is not int or limit < 0):
                    raise ValueError("Invalid exact origin quota")
        self.origin_limits = dict(limits) if limits is not None else None
        self.origin_requests = {}
        self.origin_reservations = []
        # Same-runtime idempotence; this is not a new runtime or an Agent scheduler.
        self.origin_dispatch_records = {}
        self.origin_dispatch_lock = Lock()
        # Optional private loopback journal; never enabled by JSON config.
        self.recovery = None
        self.recovery_candidate = None
        self._durable_stop = None

    def check(self):
        if not self.stop_reason and time.monotonic() >= self.deadline:
            self.stop_reason = "pipeline_deadline"
        if self.stop_reason:
            if self.recovery and self._durable_stop != self.stop_reason:
                self.recovery.append("stop", {"reason": self.stop_reason})
                self._durable_stop = self.stop_reason
            raise PipelineStopped(self.stop_reason)

    def reserve_http(self, *, deadline=None, origin=None, request=None, phase="unassigned"):
        with self.lock:
            self.check()
            if self.requests >= self.max_requests:
                self.stop_reason = "http_request_budget"
                self.check()
            if self.origin_limits is not None:
                if origin not in self.origin_limits or self.origin_requests.get(origin, 0) >= self.origin_limits[origin]:
                    raise OriginBudgetExhausted("origin_request_budget")
            wait = max(0, self.next_start - time.monotonic())
            if time.monotonic() + wait >= self.deadline:
                self.stop_reason = "pipeline_deadline"
                self.check()
            if deadline is not None and time.monotonic() + wait >= deadline:
                raise HttpDispatchDeadline("max_duration")
            while wait:
                time.sleep(wait)
                self.check()
                if deadline is not None and time.monotonic() >= deadline:
                    raise HttpDispatchDeadline("max_duration")
                # A sleep may return before the monotonic clock reaches its
                # slot (notably coarse Windows clock resolution). Never dispatch early.
                wait = max(0, self.next_start - time.monotonic())
            self.check()
            if deadline is not None and time.monotonic() >= deadline:
                raise HttpDispatchDeadline("max_duration")
            reserved_at = time.monotonic()
            if self.recovery:
                self.recovery.reserve(self, origin, request, phase)
                # Journal persistence consumes time; pacing starts no earlier
                # than the durable reservation timestamp.
                reserved_at = self.recovery.events[-1]["payload"]["reserved_at_monotonic"]
            self.requests += 1
            if origin is not None:
                self.origin_requests[origin] = self.origin_requests.get(origin, 0) + 1
            if self.origin_limits is not None:
                self.origin_reservations.append({"sequence": self.requests, "origin": origin,
                                                 "reserved_at_monotonic": reserved_at})
            self.next_start = reserved_at + 1 / self.rate

    def response(self, status, headers=None):
        if status in {401, 403, 407, 429}:
            self.stop_reason = f"http_{status}"
        elif any(str(key).lower() == "retry-after" for key in (headers or {})):
            self.stop_reason = "retry_after"
        if self.recovery:
            self.recovery.request_event("response_headers", {"status_code": status, "stop_reason": self.stop_reason})
            if self.stop_reason:
                self.recovery.append("stop", {"reason": self.stop_reason})
                self._durable_stop = self.stop_reason

    def snapshot(self):
        return {"elapsed_seconds": time.monotonic()-self.started,
                "remaining_seconds": max(0, self.deadline-time.monotonic()),
                "http_dispatches": self.requests, "http_max_requests": self.max_requests,
                "stop_reason": self.stop_reason, "deadline_mode": "cooperative; use supervisor for hard deadline",
                "http_dispatches_by_origin": dict(self.origin_requests),
                "http_origin_max_requests": dict(self.origin_limits) if self.origin_limits is not None else None,
                "origin_reservations": [dict(row) for row in self.origin_reservations]}


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


def before_http(kind="target", *, deadline=None, request=None, phase="unassigned"):
    budget = _CURRENT.get()
    if budget:
        budget.check()
        if kind != "ffuf_returned_response_lower_bound":
            budget.reserve_http(deadline=deadline, origin=_HTTP_ORIGIN.get(), request=request, phase=phase)
    elif deadline is not None and time.monotonic() >= deadline:
        raise HttpDispatchDeadline("max_duration")


@contextmanager
def http_origin(origin):
    """Private transport context for the shared reservation, never from candidates."""
    token = _HTTP_ORIGIN.set(origin)
    try:
        yield
    finally:
        _HTTP_ORIGIN.reset(token)


def observe_response(status, headers=None):
    budget = _CURRENT.get()
    if budget:
        budget.response(status, headers)


def snapshot():
    budget = _CURRENT.get()
    return budget.snapshot() if budget else {}
