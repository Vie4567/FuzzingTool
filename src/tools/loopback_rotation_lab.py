"""Real source-address rotation for an isolated, same-machine HTTP lab.

Only 127.0.0.1 / ::1 destinations are accepted. ``localhost`` is rewritten to
127.0.0.1 before connecting, so no hostname lookup can select a remote host.
The operating system must already support the selected loopback addresses;
this module never changes network settings, uses proxies, or follows redirects.
It demonstrates local socket binding, not changing a public Internet address.
"""

from __future__ import annotations

from collections import Counter
from http.client import HTTPConnection, HTTPSConnection, HTTPException, IncompleteRead
from ipaddress import ip_address
from itertools import islice
import re
import time
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

from src.tools.http_fuzzing import _integer, _number, _prepare_urls, _SPOOF_HEADERS


_DISALLOWED_OPTIONS = {
    "proxy", "proxies", "proxy_pool", "proxy_list", "rotation_pool", "rotate_ip",
    "rotate_ips", "ip_rotation", "rotate_proxy", "rotate_proxies", "proxy_rotation",
    "tor", "tor_control_port", "spoof_ip", "random_ip", "source_address",
    "source_ip", "local_address", "ssl_context", "verify", "verify_ssl",
    "insecure", "cert", "key",
}
_CLIENT_IP_HEADERS = _SPOOF_HEADERS | {
    "x-cluster-client-ip", "x-remote-ip", "x-remote-addr", "x-proxyuser-ip",
    "fastly-client-ip", "x-original-forwarded-for", "x-forwarded-host",
}


def _loopback_target(target_url: str) -> tuple[str, str, int, int]:
    if not isinstance(target_url, str) or any(ord(c) < 33 or ord(c) == 127 for c in target_url):
        raise ValueError("target_url must be an HTTP(S) URL without whitespace or controls")
    if "\\" in target_url:
        raise ValueError("Backslashes are unsupported in target_url")
    try:
        parts = urlsplit(target_url)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("Invalid loopback target URL") from exc
    if parts.scheme not in {"http", "https"} or not host:
        raise ValueError("The lab requires an absolute HTTP(S) loopback URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL credentials are unsupported")
    if parts.fragment:
        raise ValueError("target_url must not contain a fragment")
    if host.lower() == "localhost":
        host = "127.0.0.1"
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("The loopback lab accepts only 127.0.0.1, ::1, or localhost; remote targets are prohibited")
    port = port if port is not None else (443 if parts.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("The target port must be between 1 and 65535")
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        netloc += f":{port}"
    normalized = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))
    return normalized, host, port, ip_address(host).version


def _source_addresses(raw: Any, family: int) -> list[str]:
    if raw is None:
        raw = ["127.0.0.2", "127.0.0.3"] if family == 4 else ["::1"]
    if not isinstance(raw, (list, tuple)) or not 1 <= len(raw) <= 8:
        raise ValueError("lab_source_ips must be a list of 1 to 8 literal loopback addresses")
    addresses = []
    for item in raw:
        if not isinstance(item, str) or "%" in item:
            raise ValueError("lab_source_ips must contain literal loopback IP addresses")
        try:
            address = ip_address(item)
        except ValueError as exc:
            raise ValueError("lab_source_ips must contain literal loopback IP addresses") from exc
        if not address.is_loopback or address.version != family:
            raise ValueError("Every source address must be loopback and use the target's IP family")
        addresses.append(str(address))
    return addresses


def run_loopback_rotation_lab(target_url: str, wordlist: Iterable[str], **options: Any) -> dict:
    """Measure bounded HTTP requests while cycling real local source addresses.

    Defaults: four requests, one worker, two requests/second, ten-second request
    timeout, sixty-second scan budget, and a 2 MiB response-body cap. Limits
    cannot exceed 100 requests, ten requests/second, ten seconds per request or
    sixty seconds overall. A 429 or three consecutive 403 responses always stops
    the entire run before selecting another source address. No request retries.
    The scan budget is checked around blocking socket operations; inactivity
    timeouts cannot guarantee cancellation of a peer trickling header bytes.
    """
    target, destination, port, family = _loopback_target(target_url)
    for name in _DISALLOWED_OPTIONS:
        if name in options and options[name] is not None:
            raise ValueError(f"{name} is unsupported in the isolated loopback lab")
    if options.get("engine", "loopback_lab") != "loopback_lab":
        raise ValueError("This engine must be explicitly selected as loopback_lab")
    if options.get("follow_redirects") or options.get("follow_redirect") or options.get("recursion"):
        raise ValueError("The loopback lab never follows redirects or recurses")
    for key in ("threads", "workers"):
        if _integer(options.get(key, 1), key, 1, 1) != 1:
            raise ValueError("The loopback lab uses exactly one worker")
    for key in ("stop_on_block", "stop_on_429"):
        if key in options and options[key] is not True:
            raise ValueError("Stopping the entire lab on blocking responses cannot be disabled")
    for key in ("block_threshold", "consecutive_403_limit", "max_consecutive_403"):
        if key in options:
            _integer(options[key], key, 3, 3)
    rate = _number(options.get("rate_limit", options.get("rate", 2)), "rate_limit", 0.01, 10)
    delay = _number(options.get("delay_ms", 0), "delay_ms", 0, 60_000) / 1000
    timeout = _number(options.get("timeout_seconds", options.get("timeout", 10)), "timeout_seconds", 0.01, 10)
    max_requests = _integer(options.get("max_requests", 4), "max_requests", 1, 100)
    duration = _number(options.get("max_duration_seconds", options.get("max_scan_seconds", 60)), "max_duration_seconds", 0.01, 60)
    body_cap = _integer(options.get("max_response_bytes", 2 * 1024 * 1024), "max_response_bytes", 1, 2 * 1024 * 1024)
    sources = _source_addresses(options.get("lab_source_ips"), family)
    method = str(options.get("http_method", options.get("method", "GET"))).upper()
    if not re.fullmatch(r"[A-Z]+", method) or method in {"CONNECT", "TRACE"}:
        raise ValueError("The lab requires an HTTP method other than CONNECT/TRACE")
    headers = dict(options.get("headers") or {})
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("headers must map strings to strings")
        if key.lower() == "host" or key.lower() in _CLIENT_IP_HEADERS:
            raise ValueError("Host overrides and client-IP spoofing headers are prohibited")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Invalid request header")
    if not any(key.lower() == "user-agent" for key in headers):
        headers["User-Agent"] = "SentinelPentest/1.0 (same-machine-loopback-lab)"
    body = options.get("post_data", options.get("body"))
    if body is not None and not isinstance(body, (str, bytes)):
        raise ValueError("post_data/body must be a string or bytes")
    if body is not None and len(body.encode("utf-8") if isinstance(body, str) else body) > 2 * 1024 * 1024:
        raise ValueError("Request bodies must not exceed 2 MiB")
    if isinstance(wordlist, (str, bytes)):
        raise ValueError("wordlist must be an iterable of strings")
    # Consume at most 101 candidates, including one sentinel to report truncation.
    words = list(islice(wordlist, max_requests + 1))
    if any(not isinstance(word, str) or len(word) > 8192 for word in words):
        raise ValueError("Wordlist entries must be strings of at most 8192 characters")
    urls = _prepare_urls(target, words)
    # Validate all selected URLs before opening any socket.
    for url, word in urls:
        _loopback_target(url)
        if isinstance(body, str):
            # Check replacement length without allocating an arbitrarily large
            # expanded body when FUZZ occurs many times in the template.
            expanded_bytes = (len(body.encode("utf-8"))
                              + body.count("FUZZ") * (len(word.encode("utf-8")) - 4))
            if expanded_bytes > 2 * 1024 * 1024:
                raise ValueError("An expanded request body would exceed 2 MiB")

    warnings = ["Source addresses remain on this machine; public egress IP rotation is unavailable."]
    if len(words) > max_requests:
        warnings.append("Only max_requests+1 candidates were inspected; additional candidates were not consumed.")
    for key in ("match_codes", "filter_codes", "filter_size", "filter_words", "filter_lines", "extensions", "auto_calibrate"):
        if options.get(key):
            warnings.append(f"{key} is not applied; this lab preserves every raw measurement")
    started = time.perf_counter()
    deadline = started + duration
    next_start = started
    results: list[dict] = []
    errors: list[dict] = []
    stop_reason = "completed"
    consecutive_403 = 0

    for url, word in urls:
        if len(results) >= max_requests:
            stop_reason = "max_requests"
            break
        wait = max(0.0, next_start - time.perf_counter())
        if time.perf_counter() + wait >= deadline:
            stop_reason = "max_duration"
            break
        if wait:
            time.sleep(wait)
        request_started = time.perf_counter()
        next_start = request_started + max(1 / rate, delay)
        selected_source = sources[len(results) % len(sources)]
        parts = urlsplit(url)
        record = {"url": url, "path": parts.path or "/", "input": word,
                  "status_code": None, "content_length": None, "response_time": None,
                  "redirect_url": None, "headers": {}, "error": None,
                  "body_complete": False, "body_truncated": False,
                  "selected_source_ip": selected_source, "bound_source_ip": None}
        response = None
        connection = None
        try:
            connection_type = HTTPSConnection if parts.scheme == "https" else HTTPConnection
            connection = connection_type(destination, port,
                                         timeout=min(timeout, max(0.001, deadline - time.perf_counter())),
                                         source_address=(selected_source, 0))
            connection.connect()
            # The value comes from the live OS socket, never a header or assumption.
            record["bound_source_ip"] = connection.sock.getsockname()[0]
            if ip_address(record["bound_source_ip"]) != ip_address(selected_source):
                raise OSError("The operating system did not bind the selected loopback source")
            if time.perf_counter() >= deadline:
                raise TimeoutError("Run duration limit reached before sending the request")
            connection.sock.settimeout(min(timeout, max(0.001, deadline - time.perf_counter())))
            request_body = body.replace("FUZZ", word).encode("utf-8") if isinstance(body, str) else body
            path_and_query = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            connection.request(method, path_and_query, body=request_body, headers=headers)
            response = connection.getresponse()
            record["status_code"] = response.status
            for key in ("Retry-After", "Content-Type", "Content-Encoding", "Content-Length"):
                value = response.getheader(key)
                if value is not None:
                    record["headers"][key] = value
            location = response.getheader("Location")
            if location is not None and 300 <= response.status < 400:
                record["redirect_url"] = urljoin(url, location)
                # The destination of a redirect is evidence only, never contacted.
                try:
                    _loopback_target(record["redirect_url"])
                    record["redirect_blocked"] = False
                except ValueError:
                    record["redirect_blocked"] = True
            record["content_length"] = 0
            # Retain the connected socket even if HTTPResponse takes ownership
            # after Connection: close, so each read shares the global deadline.
            response_socket = connection.sock
            if response_socket is None:
                response_socket = getattr(getattr(response.fp, "raw", None), "_sock", None)
            while record["content_length"] < body_cap:
                if response.length == 0:
                    record["body_complete"] = True
                    break
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    raise TimeoutError("Run duration limit reached while reading the response")
                if response_socket is not None:
                    response_socket.settimeout(min(timeout, remaining))
                try:
                    chunk = response.read1(min(65536, body_cap - record["content_length"]))
                except IncompleteRead as exc:
                    record["content_length"] += len(exc.partial)
                    raise
                if not chunk:
                    if response.length is not None and response.length > 0:
                        raise IncompleteRead(b"", response.length)
                    record["body_complete"] = True
                    break
                record["content_length"] += len(chunk)
            if record["content_length"] == body_cap:
                record["body_complete"] = response.length == 0
                record["body_truncated"] = not record["body_complete"]
        except (OSError, ValueError, HTTPException) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            record["response_time"] = time.perf_counter() - request_started
            record["response_time_kind"] = "request_start_to_body_read_end"
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
        results.append(record)
        if record["error"]:
            errors.append({"url": url, "error": record["error"], "status_code": record["status_code"]})
        status = record["status_code"]
        consecutive_403 = consecutive_403 + 1 if status == 403 else 0
        if status == 429:
            stop_reason = "rate_limited_429"
            break
        if consecutive_403 >= 3:
            stop_reason = "consecutive_403"
            break
        if record["error"]:
            stop_reason = "max_duration" if time.perf_counter() >= deadline else "transport_error"
            break

    received = [row for row in results if row["status_code"] is not None]
    complete = [row for row in received if row["error"] is None]
    stats = {"planned_requests": len(urls), "total_requests": len(results),
             "attempted_requests": len(results), "responses_received": len(received),
             "successful_responses": len(complete), "network_errors": len(errors),
             "remaining_requests": len(urls) - len(results),
             "status_codes": dict(Counter(str(row["status_code"]) for row in received)),
             "avg_response_time": sum(row["response_time"] for row in complete) / len(complete) if complete else None,
             "wall_time": time.perf_counter() - started, "stop_reason": stop_reason,
             "potential_block_responses": sum(row["status_code"] in {403, 429} for row in results),
             "bytes_read": sum(row["content_length"] or 0 for row in results),
             "metric_scope": "Measured same-machine loopback responses only; no redirect requests, retries, or public egress IP changes.",
             "candidate_count_is_lower_bound": len(words) > max_requests}
    return {"engine": "loopback_lab", "simulated": False, "results": results,
            "stats": stats, "errors": errors, "warnings": warnings,
            "stop_reason": stop_reason, "completed": len(results) == len(urls) and stop_reason == "completed",
            "settings": {"rate_limit": rate, "delay_ms": delay * 1000, "workers": 1,
                         "timeout_seconds": timeout, "max_requests": max_requests,
                         "max_duration_seconds": duration, "max_response_bytes": body_cap,
                         "lab_source_ips": sources, "follow_redirects": False,
                         "scope": "same_machine_loopback_only", "public_egress_rotation": False}}
