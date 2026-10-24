"""A bounded HTTP fallback that records measurements from actual responses only.

The engine deliberately sends requests sequentially, does not follow redirects,
and stops when a server asks it to slow down. An explicit proxy_http mode can
cycle caller-configured routing profiles under one shared request budget.
No third-party dependencies are required.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException, IncompleteRead
import logging
import math
import re
import time
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from src.tools.proxy_profiles import PROXY_OPTION_KEYS, ProxyProfilePool


progress_logger = logging.getLogger("sentinel.fuzzing.http")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_SPOOF_HEADERS = {
    "forwarded", "x-forwarded-for", "x-real-ip", "true-client-ip",
    "cf-connecting-ip", "client-ip", "x-client-ip", "x-originating-ip",
}
_ROTATION_OPTIONS = {
    "rotate_ip", "rotate_ips", "ip_rotation", "rotate_proxy", "rotate_proxies",
    "proxy_rotation", "proxy_pool", "proxies", "proxy_list", "tor",
    "tor_control_port", "spoof_ip", "random_ip",
}


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return result


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    result = _number(value, name, minimum, maximum)
    if not result.is_integer():
        raise ValueError(f"{name} must be an integer")
    return int(result)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("target_url must be an absolute HTTP or HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL credentials are unsupported; use request headers")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    return parts.scheme, parts.hostname.lower(), port


def _prepare_urls(target_url: str, words: Iterable[str]) -> list[tuple[str, str]]:
    if not isinstance(target_url, str) or any(ord(c) < 32 for c in target_url):
        raise ValueError("target_url must be a URL without control characters")
    origin = _origin(target_url)
    parts = urlsplit(target_url)
    if "FUZZ" in parts.scheme or "FUZZ" in parts.netloc:
        raise ValueError("Host or subdomain fuzzing is unsupported; keep the origin fixed")
    if parts.fragment:
        raise ValueError("target_url must not contain a fragment")
    if isinstance(words, (str, bytes)):
        raise ValueError("wordlist must be an iterable of strings")
    result = []
    for word in words:
        if not isinstance(word, str):
            raise ValueError("Every wordlist entry must be a string")
        word = word.strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in word) or "\\" in word:
            raise ValueError("Wordlist entries must not contain controls or backslashes")
        entry_parts = urlsplit(word)
        if entry_parts.scheme or entry_parts.netloc or word.startswith("//"):
            raise ValueError("Wordlist entries must be relative paths or values, not URLs")
        # Query values are encoded as one value. Paths preserve slash separators.
        encoded_path = quote(word.strip("/"), safe="/-._~%")
        if "FUZZ" in target_url:
            path = parts.path.replace("FUZZ", encoded_path)
            query = parts.query.replace("FUZZ", quote(word, safe=""))
        else:
            path = f"{parts.path.rstrip('/')}/{encoded_path}"
            query = parts.query
        url = urlunsplit((parts.scheme, parts.netloc, path or "/", query, ""))
        if _origin(url) != origin:
            raise ValueError("A wordlist entry would escape the target origin")
        result.append((url, word))
    return result


def _retry_after_seconds(raw: str | None) -> float | None:
    if raw is None:
        return None
    try:
        if raw.strip().isdigit():
            return float(raw)
        timestamp = parsedate_to_datetime(raw)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return max(0.0, (timestamp - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def _remaining_length(response: Any) -> int | None:
    remaining = getattr(response, "length", None)
    if remaining is None:
        remaining = getattr(getattr(response, "fp", None), "length", None)
    return remaining


def run_http_fuzzing(target_url: str, wordlist: Iterable[str], **options: Any) -> dict:
    """Send bounded, sequential HTTP requests and return observed measurements.

    HTTP error statuses (including 404/429) are real responses. Transport errors
    have ``status_code=None`` unless response headers were already received.
    ``content_length`` counts body bytes actually read, never Content-Length.
    Rate limiting applies to request starts. Redirects are recorded, not followed.
    All results remain in this raw measurement set, including filtered statuses.

    Key options: rate_limit (default 2/s), delay_ms, timeout_seconds (10),
    max_requests (100), max_duration_seconds (300), max_response_bytes (2 MiB),
    http_method/method, post_data/body, headers and one fixed HTTP(S) proxy.
    By default the engine stops on 429 or three consecutive 403 responses.
    Explicit respect_retry_after=True and stop_on_429=False permit a bounded
    wait before the next candidate in the single-route mode only; no request is
    automatically retried. Explicit engine=proxy_http uses manual profiles or
    ProxyScrape candidates with allowed_origins. Health checks and fuzz requests
    share the same rate, request budget, deadline and blocking stop conditions.
    """
    for key in _ROTATION_OPTIONS:
        if options.get(key):
            raise ValueError("Generic rotation flags are unsupported; choose explicit scoped proxy_http profiles or one fixed proxy")
    controlled_proxy = options.get("engine") == "proxy_http"
    profile_options = PROXY_OPTION_KEYS
    pool = None
    if controlled_proxy:
        pool = ProxyProfilePool.from_options(options, target_url)
        if any(options.get(key) is not None for key in (
            "proxy", "lab_source_ips", "source_address", "source_ip", "ssl_context",
            "verify", "verify_ssl", "insecure",
        )):
            raise ValueError("proxy_http uses explicit routing profiles and standard TLS verification only")
        for key in ("threads", "workers"):
            _integer(options.get(key, 1), key, 1, 1)
        for key in ("stop_on_block", "stop_on_429"):
            if key in options and options[key] is not True:
                raise ValueError("Stopping all proxy profiles on blocking responses cannot be disabled")
        for key in ("block_threshold", "consecutive_403_limit", "max_consecutive_403"):
            if key in options:
                _integer(options[key], key, 3, 3)
    elif any(options.get(key) is not None for key in profile_options):
        raise ValueError("Proxy profiles and allowed_origins require engine=proxy_http")
    if options.get("follow_redirects") or options.get("follow_redirect"):
        raise ValueError("Redirect following is unsupported; redirects are recorded without additional requests")
    if options.get("recursion"):
        raise ValueError("Recursive fuzzing is unsupported by the bounded Python HTTP engine")

    rate = _number(options.get("rate_limit", options.get("rate", 2)), "rate_limit", 0.01, 10 if controlled_proxy else 100)
    delay = _number(options.get("delay_ms", 0), "delay_ms", 0, 300_000) / 1000
    timeout = _number(options.get("timeout_seconds", options.get("timeout", 10)), "timeout_seconds", 0.01, 30 if controlled_proxy else 120)
    max_requests = _integer(options.get("max_requests", 100), "max_requests", 1, 1000 if controlled_proxy else 10_000)
    default_duration = 120 if controlled_proxy else 300
    max_duration = _number(options.get("max_duration_seconds", options.get("max_scan_seconds", default_duration)), "max_duration_seconds", 0.01, 600 if controlled_proxy else 3600)
    max_body = _integer(options.get("max_response_bytes", 2 * 1024 * 1024), "max_response_bytes", 1, 64 * 1024 * 1024)
    block_threshold = _integer(options.get("consecutive_403_limit", options.get("max_consecutive_403", 3)), "consecutive_403_limit", 1, 100)
    max_backoff = _number(options.get("max_retry_after_seconds", 30), "max_retry_after_seconds", 0, 300)
    method = str(options.get("http_method", options.get("method", "GET"))).upper()
    if not re.fullmatch(r"[A-Z]+", method):
        raise ValueError("http_method must contain only HTTP method letters")
    if controlled_proxy and method in {"CONNECT", "TRACE"}:
        raise ValueError("CONNECT and TRACE are unsupported target methods in proxy_http")
    headers = dict(options.get("headers") or {})
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("headers must map strings to strings")
        if key.lower() in _SPOOF_HEADERS:
            raise ValueError("Client-IP spoofing headers are unsupported")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or "\r" in value or "\n" in value:
            raise ValueError("Invalid request header")
        if key.lower() == "host":
            raise ValueError("The Host header must be derived from the target URL")
        if controlled_proxy and key.lower() == "proxy-authorization":
            raise ValueError("Proxy authentication must come from routing profiles only")
    if not any(key.lower() == "user-agent" for key in headers):
        headers["User-Agent"] = "SentinelPentest/1.0 (bounded-http-fuzzing)"
    body = options.get("post_data", options.get("body"))
    if body is not None and not isinstance(body, (str, bytes)):
        raise ValueError("post_data/body must be a string or bytes")
    proxy = options.get("proxy")
    if proxy:
        if not isinstance(proxy, str) or urlsplit(proxy).scheme not in {"http", "https"} or not urlsplit(proxy).hostname:
            raise ValueError("proxy must be a single fixed HTTP(S) proxy URL")
        try:
            urlsplit(proxy).port
        except ValueError as exc:
            raise ValueError("Invalid fixed proxy port") from exc
    # Ignore ambient proxy environment variables unless explicitly configured.
    opener = None if controlled_proxy else build_opener(ProxyHandler({"http": proxy, "https": proxy} if proxy else {}), _NoRedirect())
    urls = _prepare_urls(target_url, wordlist)
    started = time.perf_counter()
    deadline = started + max_duration
    next_start = started
    results: list[dict] = []
    health_checks: list[dict] = []
    attempts: list[dict] = []
    errors: list[dict] = []
    refresh_events: list[dict] = []
    stop_reason = "completed"
    consecutive_403 = 0
    pinned_profile = None
    warnings = []
    if options.get("threads", 1) != 1 or options.get("workers", 1) != 1:
        warnings.append("Python HTTP engine uses one sequential worker")
    for name in ("extensions", "auto_calibrate", "match_codes", "filter_codes", "filter_size", "filter_words", "filter_lines"):
        if options.get(name):
            warnings.append(f"{name} is not applied by this raw Python HTTP measurement engine")

    def budget_available():
        nonlocal stop_reason
        if len(attempts) >= max_requests:
            stop_reason = "max_requests"
            return False
        if time.perf_counter() >= deadline:
            stop_reason = "max_duration"
            return False
        return True

    def measure(url, word, *, profile=None, healthcheck=False):
        """One measured request, including failures, under the shared budget."""
        nonlocal stop_reason, next_start
        if not budget_available():
            return None
        wait = max(0.0, next_start - time.perf_counter())
        if time.perf_counter() + wait >= deadline:
            stop_reason = "max_duration"
            return None
        if wait:
            time.sleep(wait)
        if not budget_available():
            return None
        request_started = time.perf_counter()
        next_start = request_started + max(1 / rate, delay)
        if healthcheck:
            request_body = None
        elif isinstance(body, str):
            request_body = body.replace("FUZZ", word).encode("utf-8")
        else:
            request_body = body
        request_method = "GET" if healthcheck else method
        request_headers = {"User-Agent": "SentinelPentest/1.0 (proxy-healthcheck)"} if healthcheck else headers
        request = Request(url, data=request_body, headers=request_headers, method=request_method)
        parts = urlsplit(url)
        record = {
            "url": url, "path": parts.path or "/", "input": word,
            "status_code": None, "content_length": None, "response_time": None,
            "redirect_url": None, "headers": {}, "error": None,
            "body_complete": False, "body_truncated": False,
            "request_kind": "healthcheck" if healthcheck else "fuzzing",
        }
        request_opener = opener
        if profile is not None:
            profile_id, request_opener = profile
            record.update(proxy_profile_id=profile_id, egress_ip=None,
                          egress_ip_verification="not_measured")
        progress_profile = record.get("proxy_profile_id", "fixed_proxy" if proxy else "direct")
        progress_logger.info(
            "START request=%d/%d profile=%s method=%s path=%s kind=%s",
            len(attempts) + 1, max_requests if pool and pool.managed else min(len(urls), max_requests), progress_profile,
            request_method, pool.redact(parts.path or "/") if pool is not None else parts.path or "/", record["request_kind"],
        )
        response = None
        try:
            try:
                response = request_opener.open(request, timeout=min(
                    pool.check_timeout if healthcheck else timeout,
                    max(0.01, deadline - request_started),
                ))
            except HTTPError as exc:
                response = exc
            record["status_code"] = response.code
            for name in ("Retry-After", "Content-Type", "Content-Encoding", "Content-Length"):
                value = response.headers.get(name)
                if value is not None:
                    record["headers"][name] = pool.redact(value) if pool is not None else value
            location = response.headers.get("Location")
            if location is not None and 300 <= response.code < 400:
                redirect = urljoin(url, location)
                record["redirect_url"] = pool.redact(redirect) if pool is not None else redirect
            record["content_length"] = 0
            while record["content_length"] < max_body:
                if time.perf_counter() >= deadline:
                    raise TimeoutError("Run duration limit reached while reading the response")
                try:
                    chunk = response.read(min(65536, max_body - record["content_length"]))
                except IncompleteRead as exc:
                    # A truncated chunked response may still have delivered bytes.
                    record["content_length"] += len(exc.partial)
                    raise
                if not chunk:
                    remaining = _remaining_length(response)
                    if remaining is not None and remaining > 0:
                        raise IncompleteRead(b"", remaining)
                    record["body_complete"] = True
                    break
                record["content_length"] += len(chunk)
            if record["content_length"] == max_body:
                # Do not read beyond the configured cap to inspect a truncation.
                record["body_complete"] = _remaining_length(response) == 0
                record["body_truncated"] = not record["body_complete"]
        except (URLError, OSError, ValueError, HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            message = f"{type(reason).__name__}: {reason}"
            record["error"] = pool.redact(message) if pool is not None else message
        finally:
            record["response_time"] = time.perf_counter() - request_started
            if response is not None:
                response.close()
        record["response_time_kind"] = "request_start_to_body_read_end"
        attempts.append(record)
        (health_checks if healthcheck else results).append(record)
        progress_logger.info(
            "RESULT request=%d profile=%s status=%s bytes=%s seconds=%.6f error=%s",
            len(attempts), progress_profile, record["status_code"],
            record["content_length"], record["response_time"],
            (record["error"] if pool is not None else "yes") if record["error"] else "none",
        )
        if record["error"] and not healthcheck:
            errors.append({"url": url, "error": record["error"], "status_code": record["status_code"]})
        return record

    def prepare_pool():
        """Refresh and vet pending routes before choosing a fuzzing route."""
        nonlocal stop_reason
        if not budget_available():
            return False
        now = time.perf_counter()
        if pool.refresh_due(now):
            event = pool.refresh(timeout=max(0.01, deadline - now), now=now)
            refresh_events.append(event)
            progress_logger.info("POOL source=%s event=%s candidates=%s healthy=%s error=%s",
                                 pool.source, event.get("event"), event.get("candidate_count", 0),
                                 len(pool.profile_ids), event.get("error"))
            if event.get("error") and not pool.profile_ids:
                stop_reason = "proxy_source_error"
                return False
        while budget_available():
            candidate = pool.next_pending()
            if candidate is None:
                break
            identifier, _ = candidate
            record = measure(pool.healthcheck_url, "", profile=candidate, healthcheck=True)
            if record is None:
                pool.mark_check_stopped(identifier, stop_reason)
                return False
            status = record["status_code"]
            # A target's access restriction is not evidence of a dead proxy.
            # Do not check another route to get around this response.
            if status in {403, 429, 407}:
                stop_reason = {403: "proxy_healthcheck_http_403", 429: "rate_limited_429",
                               407: "proxy_authentication_required"}[status]
                if status == 407:
                    pool.exclude(identifier, stop_reason)
                else:
                    pool.mark_check_stopped(identifier, stop_reason)
                return False
            healthy = status is not None and 200 <= status < 300 and not record["error"] and record["body_complete"]
            reason = None if healthy else "transport_error" if record["error"] else "healthcheck_response_rejected"
            pool.mark_checked(identifier, healthy, reason)
            progress_logger.info("PROXY_CHECK profile=%s healthy=%s status=%s reason=%s",
                                 identifier, healthy, status, reason)
        if stop_reason != "completed":
            return False
        if not pool.profile_ids:
            stop_reason = "proxy_pool_empty"
            return False
        return True

    for url, word in urls:
        if not budget_available():
            break
        selected_profile = None
        if pool is not None:
            if pinned_profile is not None:
                selected_profile = (pinned_profile, pool.opener_by_id(pinned_profile))
            else:
                if pool.managed and not prepare_pool():
                    break
                selected_profile = pool.next_opener()
            if selected_profile is None:
                stop_reason = "proxy_pool_empty"
                break
        record = measure(url, word, profile=selected_profile)
        if record is None:
            break
        status = record["status_code"]
        consecutive_403 = consecutive_403 + 1 if status == 403 else 0
        if pool is not None:
            pinned_profile = record["proxy_profile_id"] if status == 403 else None
        if status == 429:
            raw_retry_after = record["headers"].get("Retry-After")
            pause = _retry_after_seconds(raw_retry_after)
            can_wait = (options.get("respect_retry_after") is True and options.get("stop_on_429") is False
                        and pause is not None and pause <= max_backoff
                        and time.perf_counter() + pause < deadline)
            if can_wait:
                next_start = max(next_start, time.perf_counter() + pause)
            else:
                stop_reason = "rate_limited_429"
                break
        if consecutive_403 >= block_threshold:
            stop_reason = "consecutive_403"
            break
        if controlled_proxy and status == 407:
            stop_reason = "proxy_authentication_required"
            pool.exclude(record["proxy_profile_id"], stop_reason)
            break
        if controlled_proxy and record["error"]:
            stop_reason = "max_duration" if time.perf_counter() >= deadline else "transport_error"
            pool.exclude(record["proxy_profile_id"], stop_reason)
            break

    elapsed = time.perf_counter() - started
    received = [r for r in attempts if r["status_code"] is not None]
    complete = [r for r in received if r["error"] is None]
    stats = {
        "planned_requests": len(urls), "total_requests": len(attempts),
        "attempted_requests": len(attempts), "responses_received": len(received),
        "fuzzing_requests": len(results), "healthcheck_requests": len(health_checks),
        "successful_responses": len(complete), "network_errors": sum(bool(r["error"]) for r in attempts),
        "remaining_requests": len(urls) - len(results),
        "status_codes": dict(Counter(str(r["status_code"]) for r in received)),
        "avg_response_time": sum(r["response_time"] for r in complete) / len(complete) if complete else None,
        "wall_time": elapsed, "stop_reason": stop_reason,
        "potential_block_responses": sum(r["status_code"] in {403, 429} for r in attempts),
        "bytes_read": sum(r["content_length"] or 0 for r in attempts),
        "metric_scope": "All attempted target requests, including proxy health checks; provider fetches are separate. Redirects are not followed. HTTP error statuses are responses; network errors are separate. Length counts body bytes read; time includes reading the body and excludes rate-limit waits.",
    }
    data = {
        "engine": "proxy_http" if controlled_proxy else "python_http", "simulated": False, "results": results,
        "stats": stats, "errors": errors, "warnings": warnings,
        "stop_reason": stop_reason, "completed": len(results) == len(urls) and stop_reason == "completed",
        "settings": {"rate_limit": rate, "delay_ms": delay * 1000, "workers": 1,
                     "timeout_seconds": timeout, "max_requests": max_requests,
                     "max_duration_seconds": max_duration, "max_response_bytes": max_body,
                     "fixed_proxy_configured": bool(proxy), "follow_redirects": False},
    }
    if pool is not None:
        data["settings"].update(proxy_profile_ids=pool.all_profile_ids,
                                routing_policy="round_robin", global_rate_limit=True,
                                proxy_source=pool.source, proxy_count=pool.count_limit,
                                egress_ip_verification="not_measured")
        data["health_checks"] = health_checks
        data["proxy_pool"] = pool.snapshot()
        data["proxy_refresh_events"] = refresh_events
        stats["proxy_source_fetches"] = len(refresh_events)
        stats["proxy_profile_requests"] = dict(Counter(row["proxy_profile_id"] for row in attempts))
        stats["proxy_profiles"] = {}
        for identifier in pool.all_profile_ids:
            rows = [r for r in attempts if r["proxy_profile_id"] == identifier]
            count = len(rows)
            failures = sum(bool(r["error"]) or (r["status_code"] is not None and r["status_code"] >= 400) for r in rows)
            metrics = {
                "requests": count,
                "healthcheck_requests": sum(r["request_kind"] == "healthcheck" for r in rows),
                "fuzzing_requests": sum(r["request_kind"] == "fuzzing" for r in rows),
                "responses": sum(r["status_code"] is not None for r in rows),
                "network_errors": sum(bool(r["error"]) for r in rows),
                "http_errors": sum(r["status_code"] is not None and r["status_code"] >= 400 for r in rows),
                "error_rate": failures / count if count else None,
                "avg_response_time": sum(r["response_time"] for r in rows) / count if count else None,
                "status_codes": dict(Counter(str(r["status_code"]) for r in rows if r["status_code"] is not None)),
            }
            stats["proxy_profiles"][identifier] = metrics
            # Keep the existing START/RESULT/STOP stream stable; detailed
            # summaries are available in JSON and the proxy metrics logger.
            logging.getLogger("sentinel.fuzzing.proxy").info(
                "PROXY profile=%s requests=%d responses=%d seconds=%s error_rate=%s",
                identifier, count, metrics["responses"], metrics["avg_response_time"], metrics["error_rate"],
            )
        data["warnings"].append("Proxy profile selection does not prove distinct public egress IPs; verify using authorized target logs.")
    progress_logger.info(
        "STOP reason=%s attempted=%d responses=%d bytes=%d",
        stop_reason, stats["attempted_requests"], stats["responses_received"], stats["bytes_read"],
    )
    return data
