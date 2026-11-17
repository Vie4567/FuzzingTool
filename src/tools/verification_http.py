"""Replay through the completed fuzzing pool, pinned for each comparison unit.

Live pools and credentials stay in the process-local RuntimeBudget, never in
pipeline state/artifacts. Verification freezes pool membership; it cannot fetch
new routes or revive a stopped scan. Direct callers need a runtime session and
a successful fuzzing phase before requesting proxy replay.
"""
import logging
import time
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from src.coordinator.runtime import current_runtime, cap_http_timeout, observe_response, PipelineStopped, HttpDispatchDeadline
from src.coordinator.telemetry import record_http_attempt
from .proxy_profiles import ProxyConnectError, ProxyProfilePool, _origin, _ScopeGuard, _NoRedirect
from .recon_http import ScopedReconTransport, DEFAULT_UA, _PUBLIC_HEADERS, _validate_headers

logger = logging.getLogger("sentinel.verification.proxy")


def _key(target, options):
    # Normalize settings without discovery/I/O. Resolve manual environment
    # profiles now so changed credentials cannot silently reuse an old pool.
    pool = ProxyProfilePool.from_options(options, target)
    return (_origin(target), tuple(sorted(pool._origins)), pool.source,
            tuple(record["profile"] for record in pool._records.values()),
            pool.healthcheck_url, pool.count_limit, pool.candidate_limit,
            pool.fetch_timeout, pool.check_timeout, pool.refresh_seconds)


def forget_proxy_pool(target, options):
    budget = current_runtime()
    if budget is not None:
        getattr(budget, "_verification_proxy_sessions", {}).pop(_key(target, options), None)


def publish_proxy_pool(target, options, pool):
    budget = current_runtime()
    if budget is not None and not budget.stop_reason and pool.profile_ids:
        if not hasattr(budget, "_verification_proxy_sessions"):
            budget._verification_proxy_sessions = {}
        budget._verification_proxy_sessions[_key(target, options)] = {"pool": pool, "stop_reason": None}


class ScopedVerificationTransport(ScopedReconTransport):
    def __init__(self, target_url, *, proxy_options=None, **policy):
        super().__init__(target_url, **policy)
        self.proxy_options = proxy_options
        self.proxy_profile_id = None
        self.dispatched = False
        self.dispatch_deadline = None
        self.dispatched_at = None
        self.stop_reason = None
        self._session = None
        self._opener = None
        self._metrics = {}
        if proxy_options is not None:
            budget = current_runtime()
            self._session = getattr(budget, "_verification_proxy_sessions", {}).get(_key(target_url, proxy_options))
            if self._session is None:
                self.stop_reason = "verification_route_unavailable"
            else:
                pool = self._session["pool"]
                if not self._origins <= pool._origins:
                    raise ValueError("Verification scope exceeds the original proxy scope")
                self.stop_reason = self._session["stop_reason"]

    def begin_unit(self):
        if self._session:
            self.stop_reason = self.stop_reason or self._session["stop_reason"]
        budget = current_runtime()
        if budget:
            try:
                budget.check()
            except PipelineStopped:
                self.stop_reason = self.stop_reason or budget.stop_reason
        if self.stop_reason or self.proxy_options is None:
            return self.stop_reason
        selected = self._session["pool"].next_opener()
        if selected is None:
            self.stop_reason = "proxy_pool_empty"
        else:
            self.proxy_profile_id = selected[0]
            self._opener = self._session["pool"].opener_by_id(
                self.proxy_profile_id, ssl_context=self.ssl_context)
            logger.info("VERIFY_ROUTE profile=%s rotation=per_endpoint", self.proxy_profile_id)
        return self.stop_reason

    def open(self, request, timeout=10, *, cookie_jar=None):
        self.dispatched = False
        self.dispatched_at = None
        if self.stop_reason or (self._session and self._session["stop_reason"]):
            raise PipelineStopped(self.stop_reason or self._session["stop_reason"])
        if cookie_jar is not None:
            raise ValueError("Verification uses explicit operator headers, not mutable cookies")
        request = Request(request) if isinstance(request, str) else request
        self.check_url(request.full_url, credentials=request.data is not None)
        include_auth = self.allows_auth(request.full_url) and request.get_method().upper() != "TRACE"
        extra = _validate_headers(dict(request.header_items()))
        headers = {"User-Agent": "SentinelPentest/1.0 (bounded-http-fuzzing)" if self.proxy_options is not None else DEFAULT_UA}
        if include_auth:
            headers.update(self.headers)
            headers.update(extra)
        else:
            headers.update({k: v for k, v in extra.items() if k.lower() in _PUBLIC_HEADERS})
        outgoing = Request(request.full_url, data=request.data, headers=_validate_headers(headers), method=request.get_method())
        if self.proxy_options is not None:
            if self._opener is None:
                raise ValueError("Select a verification unit before proxy dispatch")
            opener = self._opener
        else:
            opener = build_opener(ProxyHandler({}), _ScopeGuard(self._origins), _NoRedirect(), HTTPSHandler(context=self.ssl_context))
        timeout = cap_http_timeout(timeout)
        record_http_attempt(kind="target", deadline=self.dispatch_deadline)
        self.dispatched = True
        if self.dispatch_deadline is not None:
            timeout = min(timeout, max(.001, self.dispatch_deadline - time.monotonic()))
        budget = current_runtime()
        if budget:
            timeout = min(timeout, max(.001, budget.deadline - time.monotonic()))
        self.dispatched_at = time.perf_counter()
        try:
            response = opener.open(outgoing, timeout=timeout)
        except HTTPError as exc:
            observe_response(exc.code, exc.headers)
            raise
        observe_response(response.code, response.headers)
        return response

    def failure(self, exc, measured):
        if isinstance(exc, HttpDispatchDeadline):
            return "max_duration"
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, ProxyConnectError):
            measured.update(proxy_connect_status=reason.status, proxy_connect_headers={
                k: self._session["pool"].redact(v) for k, v in reason.headers.items()})
            observe_response(reason.status, reason.headers)
            return "proxy_connect_http_" + str(reason.status)
        if isinstance(exc, PipelineStopped):
            return self.stop_reason or (current_runtime().stop_reason if current_runtime() else None) or "pipeline_stopped"
        return "transport_error"

    def record_measurement(self, measured, halt_reason):
        if self._session is None:
            return
        if self.dispatched:
            entry = self._metrics.setdefault(self.proxy_profile_id, {
                "requests": 0, "responses": 0, "errors": 0, "proxy_connect_errors": 0,
                "total_response_time": 0.0})
            entry["requests"] += 1
            entry["responses"] += measured.get("status_code") is not None
            entry["errors"] += bool(measured.get("error") or halt_reason or (measured.get("status_code") or 0) >= 400)
            entry["proxy_connect_errors"] += measured.get("proxy_connect_status") is not None
            entry["total_response_time"] += measured.get("response_time") or 0
        if halt_reason:
            self.stop_reason = self._session["stop_reason"] = halt_reason
            if self.proxy_profile_id and (halt_reason == "transport_error" or measured.get("proxy_connect_status") == 407):
                self._session["pool"].exclude(self.proxy_profile_id, halt_reason)

    def metrics(self):
        if self.proxy_options is None:
            return {}
        profiles = {key: dict(value, error_rate=value["errors"] / value["requests"],
                             avg_response_time=value["total_response_time"] / value["requests"])
                    for key, value in self._metrics.items()}
        return {"proxy_profiles": profiles,
                "proxy_profile_requests": {key: val["requests"] for key, val in profiles.items()},
                "proxy_connect_errors": sum(val["proxy_connect_errors"] for val in profiles.values())}

    def public_settings(self):
        result = super().public_settings()
        result["route"] = "proxy" if self.proxy_options is not None else "direct"
        if self.proxy_options is not None:
            result.update(rotation="round_robin_per_verification_unit", pool_reuse="fuzzing_session",
                          refresh_policy="frozen_during_verification", egress_ip_verification="not_measured")
        return result

    def redact(self, value):
        value = super().redact(value)
        if self._session is None:
            return value
        def clean(item):
            if isinstance(item, str):
                return self._session["pool"].redact(item)
            if isinstance(item, dict):
                return {key: clean(val) for key, val in item.items()}
            if isinstance(item, list):
                return [clean(val) for val in item]
            return item
        return clean(value)
