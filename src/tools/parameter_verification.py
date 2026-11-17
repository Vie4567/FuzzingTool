"""Bounded GET parameter checks with repeated negative controls and evidence.

Verified means a repeatable HTTP response effect for a parameter, not business
validity, an exploitable issue, or proof that an endpoint passes Soft404 checks.
"""

from copy import deepcopy
from hashlib import sha256
from html import unescape
from http.client import IncompleteRead
import logging
import re
import time
from urllib.error import HTTPError
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request
from uuid import uuid4

from src.coordinator.runtime import current_runtime
from .verification_http import ScopedVerificationTransport
from .soft404 import _features, _number, _set_read_timeout


logger = logging.getLogger("sentinel.parameters")
_BLOCKED = {401, 403, 407, 429}
_NETWORK_KEYS = {"headers", "allowed_origins", "auth_origins", "verify_ssl", "tls_ca_file"}
_LIMIT_KEYS = {"rate_limit", "timeout_seconds", "max_requests", "max_duration_seconds", "max_response_bytes"}
_UNSAFE_NAME = re.compile(r"(?:^|[_-])(?:token|password|passwd|secret|auth|session|cookie|admin|debug|delete|remove|action|command|exec|redirect|callback|logout|csrf)(?:$|[_-])", re.I)
_UNSAFE_PATH = re.compile(r"(?:^|/)(?:logout|signout|login|signin|register|auth|oauth|delete|remove|destroy|reset|clear|transfer|checkout|payment)(?:/|$)", re.I)


def parameter_options_from_config(config=None, execution=None):
    """Share replay gates with Soft404, while keeping independent phase budgets."""
    from src.agents.soft404_filter import soft404_options_from_config

    config = dict(config or {})
    nested = config.get("parameter_options", {})
    if not isinstance(nested, dict):
        raise ValueError("parameter_options must be a mapping")
    unknown = set(nested) - _NETWORK_KEYS - _LIMIT_KEYS - {"enabled", "cookie", "bearer_token"}
    if unknown:
        raise ValueError("Unsupported parameter verification option")
    config["soft404_options"] = nested
    return soft404_options_from_config(config, execution)


def _signature(measured):
    return (measured["status_code"], measured["content_type"], measured["normalized_sha256"])


def _public(measured):
    return {key: value for key, value in measured.items() if key != "_body"}


def _query_url(url, name, value):
    parts = urlsplit(url)
    query = parts.query + ("&" if parts.query else "") + urlencode([(name, value)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _reflection_text(body):
    # Common HTML/URL/JSON encodings must not turn an echo into evidence.
    body = unescape(unquote(body))
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), body)


def verify_parameters(target_url, records, *, headers=None, allowed_origins=None,
                      auth_origins=None, verify_ssl=True, tls_ca_file=None,
                      rate_limit=1, timeout_seconds=5, max_requests=60,
                      max_duration_seconds=120, max_response_bytes=262144,
                      enabled=True, stop_reason=None, proxy_options=None):
    """Compare two baselines, two random-name controls and two value pairs.

    Two identical repeats per value must be complete 2xx responses. A fresh
    baseline and unknown-name controls using BOTH test values must still match
    the original baseline after each candidate. At least one value must differ
    from stable negative controls. Reflected input,
    dynamic responses, redirects and incomplete bodies never establish proof.
    Every attempt, including failed opens and control requests, consumes budget.
    With a proxy pool, each endpoint's controls and candidate repeats stay on
    one profile; round-robin selection happens between endpoint checks.
    """
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise ValueError("records must be a list of mappings")
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    rate = _number(rate_limit, "rate_limit", .01, 100)
    timeout = _number(timeout_seconds, "timeout_seconds", .01, 120)
    budget = _number(max_requests, "max_requests", 1, 10000, integer=True)
    duration = _number(max_duration_seconds, "max_duration_seconds", .01, 3600)
    cap = _number(max_response_bytes, "max_response_bytes", 1, 8 * 1024 * 1024, integer=True)
    if proxy_options is not None:
        rate, timeout = min(rate, 10), min(timeout, 30)
    if current_runtime():
        cap = min(cap, current_runtime().body_cap)
    transport = ScopedVerificationTransport(target_url, headers=headers, allowed_origins=allowed_origins,
                                            auth_origins=auth_origins, verify_ssl=verify_ssl,
                                            tls_ca_file=tls_ca_file, proxy_options=proxy_options)
    rows = deepcopy(records)
    stats = {"total_requests": 0, "responses_received": 0, "bytes_read": 0,
             "baseline_requests": 0, "control_requests": 0, "candidate_requests": 0,
             "network_errors": 0}
    result = {"result_kind": "parameter_candidates", "param_results": rows,
              "parameter_candidates": [], "verified_parameters": [], "stats": stats,
              "verification": "not_checked", "verification_performed": False,
              "verification_status": "skipped", "stop_reason": "completed",
              "http_policy": transport.public_settings()}
    halted = ("disabled" if not enabled else str(stop_reason)
              if stop_reason not in (None, "", "completed") else None)
    halted = halted or transport.stop_reason
    if any(row.get("source_status_code", row.get("status_code")) in _BLOCKED or row.get("source_retry_after")
           or any(str(key).lower() == "retry-after" for key in (row.get("headers") or {})) for row in rows):
        halted = halted or "source_blocked"
    if any(row.get("simulated") or row.get("source_simulated") for row in rows):
        halted = halted or "simulated_source"
    candidates_by_row = []
    for row in rows:
        # Candidate containers never become endpoint-validity claims.
        row.update(result_kind="parameter_candidates", verification="not_checked", verification_performed=False)
        row.pop("verification_evidence", None)
        row.pop("verification_reason", None)
        candidate_url = row.get("url") or row.get("path") or ""
        url = urljoin(target_url.rstrip("/") + "/", candidate_url) if isinstance(candidate_url, str) else ""
        candidates, seen = [], set()
        for raw in row.get("discovered_params") or []:
            param = dict(raw) if isinstance(raw, dict) else {"name": raw}
            name = param.get("name")
            if not isinstance(name, str) or name in seen:
                continue
            seen.add(name)
            candidate = {"endpoint": url, "name": name, "location": param.get("location", "query"),
                         "method": str(param.get("method", "GET")).upper(),
                         "type": param.get("type", "string"), "result_kind": "parameter_candidate",
                         "verification": "not_checked", "verification_performed": False,
                         "verification_reason": halted or "not_measured", "status_code": None,
                         "content_length_change": None, "verification_evidence": {}}
            candidates.append(candidate)
        candidates_by_row.append((row, url, candidates))

    start = time.perf_counter()
    deadline, next_start = start + duration, start
    transport.dispatch_deadline = time.monotonic() + duration

    def measure(url, kind):
        nonlocal halted, next_start
        if halted:
            return None
        if stats["total_requests"] >= budget:
            halted = "max_requests"
            return None
        now = time.perf_counter()
        if max(now, next_start) >= deadline:
            halted = "max_duration"
            return None
        if next_start > now:
            time.sleep(next_start - now)
        request_start = time.perf_counter()
        next_start = request_start + 1 / rate
        measured = {"request_id": stats["total_requests"] + 1, "kind": kind, "url": url,
                    "status_code": None, "content_length": None, "content_type": "",
                    "body_complete": False, "body_truncated": False, "response_time": None,
                    "body_sha256": None, "normalized_sha256": None, "error": None,
                    "proxy_profile_id": transport.proxy_profile_id}
        response, raw = None, b""
        transport.dispatched = False
        logger.info("Parameter START request=%s/%s kind=%s profile=%s", measured["request_id"],
                    budget, kind, transport.proxy_profile_id or "direct")
        try:
            try:
                response = transport.open(Request(url, headers={"Accept-Encoding": "identity"}),
                                          timeout=min(timeout, max(.001, deadline - request_start)))
            except HTTPError as exc:
                response = exc
            measured["status_code"] = response.code
            measured["content_type"] = response.headers.get_content_type()
            stats["responses_received"] += 1
            if response.code in _BLOCKED:
                halted = "http_" + str(response.code)
            elif response.headers.get("Retry-After") is not None:
                halted = "retry_after"
            elif 300 <= response.code < 400:
                halted = "redirect_requires_review"
            if not halted:
                read_deadline = min(deadline, (transport.dispatched_at or request_start) + timeout)
                reader = getattr(response, "read1", response.read)
                while len(raw) <= cap:
                    remaining = read_deadline - time.perf_counter()
                    if remaining <= 0:
                        raise TimeoutError("response deadline")
                    _set_read_timeout(response, remaining)
                    chunk = reader(min(65536, cap + 1 - len(raw)))
                    if not chunk:
                        expected = response.headers.get("Content-Length")
                        if expected and expected.isdigit() and len(raw) < int(expected):
                            raise IncompleteRead(b"", int(expected) - len(raw))
                        measured["body_complete"] = True
                        break
                    raw += chunk
                    if len(raw) > cap:
                        measured["body_truncated"] = True
                        break
                measured["content_length"] = len(raw)
                measured["body_sha256"] = sha256(raw).hexdigest()
                encoding = response.headers.get("Content-Encoding", "identity").lower()
                if measured["body_complete"] and encoding in {"", "identity"}:
                    try:
                        body = raw.decode(response.headers.get_content_charset() or "utf-8")
                    except (UnicodeError, LookupError):
                        measured["error"] = "unsupported_text_encoding"
                    else:
                        features = _features(body, url, measured["content_type"])
                        measured["normalized_sha256"] = features["sha256"]
                        measured["_body"] = body
                        if features["login_or_challenge"]:
                            halted = "login_or_challenge"
                elif measured["body_complete"]:
                    measured["error"] = "unsupported_content_encoding"
        except Exception as exc:
            measured["content_length"] = len(raw) if measured["status_code"] is not None else None
            measured["error"] = type(exc).__name__
            halted = transport.failure(exc, measured)
            if halted == "transport_error" and time.perf_counter() >= deadline:
                halted = "max_duration"
            if transport.dispatched and measured.get("proxy_connect_status") is None:
                stats["network_errors"] += 1
        finally:
            if transport.dispatched:
                stats["total_requests"] += 1
                stats[kind + "_requests"] += 1
            if response is not None:
                try:
                    response.close()
                except Exception as exc:
                    if measured["error"] is None:
                        stats["network_errors"] += 1
                    measured["error"] = measured["error"] or type(exc).__name__
                    halted = halted or transport.failure(exc, measured)
            measured["response_time"] = (time.perf_counter() - transport.dispatched_at
                                         if transport.dispatched_at is not None else None)
        if not transport.dispatched:
            # A shared deadline/budget rejection is not a network attempt.
            return None
        stats["bytes_read"] += measured["content_length"] or 0
        transport.record_measurement(measured, halted)
        logger.info("Parameter RESULT profile=%s status=%s connect_status=%s bytes=%s seconds=%.6f error=%s",
                    measured["proxy_profile_id"] or "direct", measured["status_code"],
                    measured.get("proxy_connect_status"), measured["content_length"],
                    measured["response_time"], measured["error"])
        return measured

    def usable(item):
        return (item is not None and item["body_complete"] and not item["body_truncated"] and not item["error"]
                and item["normalized_sha256"] is not None and 200 <= item["status_code"] < 300)

    for row, url, candidates in candidates_by_row:
        if not candidates:
            continue
        try:
            existing_query = {key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
            path = urlsplit(url).path
            valid_url = transport.allows(url) and not urlsplit(url).fragment
        except (ValueError, TypeError):
            valid_url, existing_query, path = False, set(), ""
        eligible = []
        for candidate in candidates:
            reason = halted
            if not reason and not valid_url:
                reason = "invalid_or_out_of_scope_url"
            if not reason and (candidate["method"] != "GET" or candidate["location"] != "query"
                               or str(row.get("source_method", row.get("method", "GET"))).upper() != "GET"
                               or row.get("request_body") is not None or row.get("post_data") is not None):
                reason = "unsupported_request_context"
            if not reason and (row.get("source_error") or row.get("error") or row.get("body_complete") is False
                               or row.get("source_body_complete") is False or row.get("body_truncated")
                               or row.get("source_body_truncated")):
                reason = "source_incomplete_or_error"
            if not reason and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", candidate["name"]):
                reason = "invalid_parameter_name"
            if not reason and (_UNSAFE_NAME.search(candidate["name"]) or _UNSAFE_PATH.search(path)):
                reason = "sensitive_parameter_or_path_requires_review"
            if not reason and candidate["name"] in existing_query:
                reason = "already_in_query"
            if reason:
                candidate["verification_reason"] = reason
            else:
                eligible.append(candidate)
        if not eligible:
            continue
        halted = transport.begin_unit()
        if halted:
            for candidate in eligible:
                candidate["verification_reason"] = halted
            continue
        controls = []
        for kind in ("baseline", "baseline", "control", "control"):
            control_url = url if kind == "baseline" else _query_url(url, "__sentinel_unknown_" + uuid4().hex, "1")
            measured = measure(control_url, kind)
            if measured is not None:
                controls.append(measured)
            if halted:
                break
        control_evidence = [_public(item) for item in controls]
        stable = len(controls) == 4 and all(usable(item) for item in controls) and len({_signature(item) for item in controls}) == 1
        for candidate in eligible:
            candidate["verification_evidence"] = {
                "controls": control_evidence, "samples": [],
                "proxy_profile_id": transport.proxy_profile_id,
                "source_proxy_profile_id": row.get("source_proxy_profile_id", row.get("proxy_profile_id")),
            }
            if halted or not stable:
                candidate.update(verification="inconclusive" if controls else "not_checked",
                                 verification_performed=bool(controls),
                                 verification_reason=halted or "unstable_or_query_sensitive_controls")
                continue
            kind = candidate["type"]
            values = ("1", "2") if kind in {"integer", "number"} else ("false", "true") if kind == "boolean" else ("sentinel_" + uuid4().hex, "sentinel_" + uuid4().hex)
            samples = []
            reflected = False
            for value in values:
                for _ in range(2):
                    measured = measure(_query_url(url, candidate["name"], value), "candidate")
                    if measured is not None:
                        samples.append(measured)
                        body = _reflection_text(measured.get("_body", ""))
                        # Any newly reflected test value needs manual review; an
                        # echo alone does not prove application use of a parameter.
                        reflected |= body.count(value) > _reflection_text(controls[0].get("_body", "")).count(value)
                    if halted:
                        break
                if halted:
                    break
            evidence = candidate["verification_evidence"]
            evidence["samples"] = [_public(item) for item in samples]
            evidence["reflection_detected"] = reflected
            post_controls = []
            if not halted:
                for control_url, control_kind in [(url, "baseline")] + [
                        (_query_url(url, "__sentinel_unknown_" + uuid4().hex, value), "control") for value in values]:
                    measured = measure(control_url, control_kind)
                    if measured is not None:
                        post_controls.append(measured)
                    if halted:
                        break
            evidence["post_controls"] = [_public(item) for item in post_controls]
            candidate["verification_performed"] = bool(samples)
            candidate["verification"] = "inconclusive"
            if samples:
                candidate["status_code"] = samples[0]["status_code"]
                if samples[0]["content_length"] is not None:
                    candidate["content_length_change"] = samples[0]["content_length"] - controls[0]["content_length"]
            if halted:
                reason = halted
            elif len(samples) != 4 or not all(usable(item) for item in samples):
                reason = "incomplete_or_non_success_candidate"
            elif reflected:
                reason = "reflected_input_requires_review"
            elif len(post_controls) != 3 or not all(usable(item) and _signature(item) == _signature(controls[0]) for item in post_controls):
                reason = "changed_or_value_sensitive_negative_controls"
            elif _signature(samples[0]) != _signature(samples[1]) or _signature(samples[2]) != _signature(samples[3]):
                reason = "unstable_candidate_response"
            elif all(_signature(item) == _signature(controls[0]) for item in samples):
                reason = "no_repeatable_response_effect"
            else:
                reason = "repeatable_response_effect_vs_negative_controls"
                candidate["verification"] = "verified"
                candidate["result_kind"] = "verified_parameter"
            candidate["verification_reason"] = reason
        row["verification_performed"] = any(candidate["verification_performed"] for candidate in candidates)
        row["parameter_verification"] = "completed" if not halted else "partial"
    for row, _, candidates in candidates_by_row:
        row["parameter_checks"] = candidates
        for candidate in candidates:
            if halted and candidate["verification_reason"] == "not_measured":
                candidate["verification_reason"] = halted
            result["verified_parameters" if candidate["verification"] == "verified" else "parameter_candidates"].append(candidate)
    result["verification_performed"] = stats["total_requests"] > 0
    result["verification_status"] = "partial" if halted else "completed"
    if not stats["total_requests"]:
        result["verification_status"] = "skipped"
    result["verification"] = "measured" if stats["total_requests"] else "not_checked"
    result["stop_reason"] = halted or "completed"
    stats["wall_time"] = time.perf_counter() - start
    stats["metric_scope"] = "Attempted GET opens, including baselines, random-name controls, candidate repeats and transport errors; bytes count actual reads."
    stats.update(transport.metrics())
    return transport.redact(result)
