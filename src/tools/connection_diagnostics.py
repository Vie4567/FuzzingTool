"""One bounded GET with explicit connection phases; independent of the pipeline.

The CLI supervises this function in a child process because getaddrinfo and a
slowly trickling HTTP header cannot reliably be interrupted by socket timeouts.
No credentials, URL path/query, response headers/body or exception text are
included in the public result or progress callback.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import urlsplit
from uuid import UUID, uuid4


DEFAULT_UA = "SentinelPentest/1.0 (bounded-http-fuzzing)"
CORRELATION_HEADER = "X-FuzzingTool-Diagnostic-ID"
STAGE_NAMES = ("dns_resolution", "tcp_connect", "tls_handshake", "request_send",
               "response_headers", "response_body")


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _endpoint(value, *, origin_only=False):
    if (not isinstance(value, str) or not value or len(value) > 8192
            or value != value.strip() or "\\" in value
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)):
        raise ValueError("Endpoint must be an ASCII HTTP(S) URL without whitespace or control characters")
    try:
        parts = urlsplit(value)
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.fragment or "#" in value):
            raise ValueError
        host = parts.hostname.lower()
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        if not 1 <= port <= 65535 or "%" in host:
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9.])?", host):
                raise ValueError
        if origin_only and (parts.path not in {"", "/"} or parts.query or "?" in value):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Invalid endpoint or origin; URL credentials and fragments are forbidden") from None
    return parts, (parts.scheme, host, port)


def _display_origin(origin):
    scheme, host, port = origin
    host = f"[{host}]" if ":" in host else host
    suffix = "" if port == (443 if scheme == "https" else 80) else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate(url, *, allowed_origin, auth_origin=None, bearer_token=None,
              timeout_seconds=8, max_response_bytes=65536, trace_id=None,
              tls_ca_file=None, expected_json_pointer=None, expected_json_value=None):
    parts, origin = _endpoint(url)
    _, allowed = _endpoint(allowed_origin, origin_only=True)
    if origin != allowed:
        raise ValueError("Endpoint is outside the explicitly allowed origin")
    if auth_origin is not None:
        _, auth = _endpoint(auth_origin, origin_only=True)
        if auth != allowed:
            raise ValueError("Auth origin must equal the explicitly allowed origin")
    if bearer_token is not None:
        if (not isinstance(bearer_token, str) or not bearer_token
                or len(bearer_token) > 16384
                or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", bearer_token)):
            raise ValueError("Bearer token must be a nonempty token without whitespace")
        if auth_origin is None:
            raise ValueError("Bearer credentials require an explicit auth origin")
        if origin[0] != "https" and not _loopback(origin[1]):
            raise ValueError("Bearer credentials require HTTPS; HTTP is allowed only for numeric loopback fixtures")
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 8):
        raise ValueError("Diagnostic timeout must be greater than zero and at most 8 seconds")
    if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= 65536:
        raise ValueError("Diagnostic body cap must be between 1 and 65536 bytes")
    if trace_id is not None:
        try:
            trace_id = str(UUID(str(trace_id)))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("Diagnostic ID must be a UUID") from None
    else:
        trace_id = str(uuid4())
    if tls_ca_file is not None:
        if not isinstance(tls_ca_file, (str, Path)) or not Path(tls_ca_file).is_file():
            raise ValueError("TLS CA file must be an existing file")
    if expected_json_pointer is not None:
        if (not isinstance(expected_json_pointer, str) or len(expected_json_pointer) > 512
                or (expected_json_pointer and not expected_json_pointer.startswith("/"))
                or any(ord(char) < 32 for char in expected_json_pointer)
                or re.search(r"~(?:[^01]|$)", expected_json_pointer)):
            raise ValueError("Expected JSON pointer must follow RFC 6901")
        if bearer_token is None:
            raise ValueError("An authentication response contract requires bearer credentials")
        if type(expected_json_value) not in (str, int, float, bool, type(None)):
            raise ValueError("Expected JSON value must be a scalar")
        if isinstance(expected_json_value, float) and not math.isfinite(expected_json_value):
            raise ValueError("Expected JSON value must be finite")
    elif expected_json_value is not None:
        raise ValueError("Expected JSON value requires an expected JSON pointer")
    return parts, origin, trace_id


def validate_options(url, *, allowed_origin, auth_origin=None, bearer_token=None,
                     timeout_seconds=8, max_response_bytes=65536, trace_id=None,
                     tls_ca_file=None, expected_json_pointer=None, expected_json_value=None):
    """Validate offline and return only a public plan; never resolve the host."""
    _, origin, trace_id = _validate(
        url, allowed_origin=allowed_origin, auth_origin=auth_origin, bearer_token=bearer_token,
        timeout_seconds=timeout_seconds, max_response_bytes=max_response_bytes, trace_id=trace_id,
        tls_ca_file=tls_ca_file, expected_json_pointer=expected_json_pointer,
        expected_json_value=expected_json_value)
    return {"diagnostic_id": trace_id, "origin": _display_origin(origin), "method": "GET",
            "user_agent": DEFAULT_UA, "timeout_seconds": timeout_seconds,
            "max_response_bytes": max_response_bytes, "max_requests": 1,
            "max_tcp_attempts": 1, "verify_tls": True, "custom_ca_configured": tls_ca_file is not None,
            "follow_redirects": False, "proxy": False, "retries": 0,
            "auth_configured": bearer_token is not None,
            "auth_contract_configured": expected_json_pointer is not None,
            "auth": _auth_metadata(bearer_token, expected_json_pointer)}


def _auth_metadata(bearer_token, expected_json_pointer):
    configured = expected_json_pointer is not None
    return {"provided": bearer_token is not None, "contract_configured": configured,
            "assessment": "not_configured" if bearer_token is None else "not_verified",
            "verification_status": "not_verified" if configured else "not_configured",
            "verification_performed": False,
            "reason": "server_confirmation_required" if configured else
                      "operator_confirmed_protected_endpoint_contract_missing",
            "server_confirmation_required": bearer_token is not None}


def _error(exc):
    kind = ("timeout" if isinstance(exc, TimeoutError) else
            "dns_resolution_error" if isinstance(exc, socket.gaierror) else
            "tls_certificate_error" if isinstance(exc, ssl.SSLCertVerificationError) else
            "tls_error" if isinstance(exc, ssl.SSLError) else
            "incomplete_body" if isinstance(exc, http.client.IncompleteRead) else
            "http_protocol_error" if isinstance(exc, http.client.HTTPException) else
            "connection_error" if isinstance(exc, OSError) else "diagnostic_error")
    value = {"kind": kind, "exception_type": type(exc).__name__}
    for field in ("errno", "verify_code"):
        number = getattr(exc, field, None)
        if type(number) is int:
            value[field] = number
    return value


def _json_matches(raw, pointer, expected):
    try:
        value = json.loads(raw.decode("utf-8"))
        for part in pointer.split("/")[1:] if pointer else []:
            key = part.replace("~1", "/").replace("~0", "~")
            if isinstance(value, dict):
                value = value[key]
            elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key):
                value = value[int(key)]
            else:
                return False
        return type(value) is type(expected) and value == expected
    except (ValueError, UnicodeError, KeyError, IndexError, TypeError, RecursionError):
        # An unsupported/deep JSON contract is not a transport or body-read
        # failure; the bytes may already have been received completely.
        return False


def diagnose_once(url, *, allowed_origin, auth_origin=None, bearer_token=None,
                  timeout_seconds=8, max_response_bytes=65536, trace_id=None,
                  progress=None, tls_ca_file=None, expected_json_pointer=None,
                  expected_json_value=None):
    """Measure one approved endpoint without redirects, retry or proxy fallback.

    Only the first DNS result is connected. A transport/header/body failure
    preserves the last observed status and counters. The supervisor must enforce
    the total deadline when a platform call cannot be interrupted in-process.
    """
    parts, origin, trace_id = _validate(
        url, allowed_origin=allowed_origin, auth_origin=auth_origin, bearer_token=bearer_token,
        timeout_seconds=timeout_seconds, max_response_bytes=max_response_bytes, trace_id=trace_id,
        tls_ca_file=tls_ca_file, expected_json_pointer=expected_json_pointer,
        expected_json_value=expected_json_value)
    started, deadline = time.monotonic(), time.monotonic() + timeout_seconds
    result = {"diagnostic_id": trace_id, "origin": _display_origin(origin), "method": "GET",
              "user_agent": DEFAULT_UA, "started_at": _utc(), "finished_at": None,
              "elapsed_seconds": 0.0, "state": "running", "active_stage": None,
              "stop_reason": None,
              "stages": [{"name": name, "status": "pending", "started_at": None,
                          "finished_at": None, "duration_seconds": None, "error": None}
                         for name in STAGE_NAMES],
              "counts": {"dns_attempts": 0, "tcp_attempts": 0, "tls_handshakes": 0},
              "http": {"attempted_requests": 0, "responses_received": 0, "status_code": None,
                       "bytes_received": 0, "body_complete": False},
              "auth": _auth_metadata(bearer_token, expected_json_pointer)}
    current = None
    stage_started = None
    sock = connection = response = None

    def emit():
        result["elapsed_seconds"] = time.monotonic() - started
        if progress is not None:
            progress(deepcopy(result))

    def begin(name):
        nonlocal current, stage_started
        current = next(row for row in result["stages"] if row["name"] == name)
        current.update(status="running", started_at=_utc())
        result["active_stage"] = name
        stage_started = time.monotonic()
        emit()

    def finish(status="success", error=None):
        current.update(status=status, finished_at=_utc(),
                       duration_seconds=time.monotonic() - stage_started, error=error)
        emit()

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError()
        return value

    try:
        begin("dns_resolution")
        result["counts"]["dns_attempts"] = 1
        emit()
        addresses = socket.getaddrinfo(origin[1], origin[2], type=socket.SOCK_STREAM)
        remaining()
        if not addresses:
            raise socket.gaierror()
        result["counts"]["resolved_addresses"] = len(addresses)
        finish()

        begin("tcp_connect")
        family, socktype, protocol, _, address = addresses[0]
        sock = socket.socket(family, socktype, protocol)
        sock.settimeout(remaining())
        result["counts"]["tcp_attempts"] = 1
        emit()
        sock.connect(address)
        finish()

        begin("tls_handshake")
        if origin[0] == "https":
            # Keep the verified client policy of create_default_context, but
            # do not enable its SSLKEYLOGFILE environment-driven key logging.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            if tls_ca_file is not None:
                context.load_verify_locations(cafile=tls_ca_file)
            else:
                context.load_default_certs(ssl.Purpose.SERVER_AUTH)
            context.set_alpn_protocols(["http/1.1"])
            sock.settimeout(remaining())
            sock = context.wrap_socket(sock, server_hostname=origin[1], do_handshake_on_connect=False)
            result["counts"]["tls_handshakes"] = 1
            emit()
            sock.do_handshake()
            finish()
            connection = http.client.HTTPSConnection(origin[1], origin[2], context=context)
        else:
            finish("skipped")
            connection = http.client.HTTPConnection(origin[1], origin[2])
        connection.sock = sock
        connection.auto_open = 0

        begin("request_send")
        headers = {"User-Agent": DEFAULT_UA, "Connection": "close", "Accept-Encoding": "identity",
                   CORRELATION_HEADER: trace_id}
        if bearer_token is not None:
            headers["Authorization"] = "Bearer " + bearer_token
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        sock.settimeout(remaining())
        # A failed send can be partial; never claim that the server saw no request.
        result["http"]["attempted_requests"] = 1
        emit()
        connection.request("GET", path, headers=headers)
        finish()

        begin("response_headers")
        sock.settimeout(remaining())
        response = connection.getresponse()
        result["http"].update(responses_received=1, status_code=response.status)
        finish()
        stop = (f"http_{response.status}" if response.status in {401, 403, 407, 429} else
                "retry_after" if response.getheader("Retry-After") is not None else
                "redirect_requires_review" if 300 <= response.status < 400 else None)
        if stop:
            begin("response_body")
            finish("skipped")
            result.update(state="stopped", stop_reason=stop)
            if bearer_token is not None:
                result["auth"]["assessment"] = {
                    401: "rejected_401", 403: "access_denied_403", 407: "proxy_authentication_required_407",
                    429: "rate_limited_429",
                }.get(response.status, "not_verified")
        else:
            begin("response_body")
            raw = bytearray()
            body_updates, last_body_emit, emitted_bytes = 0, time.monotonic(), 0
            while True:
                # read1 closes its file/socket after the declared body length
                # is exhausted. Do not set a timeout on that closed socket.
                if response.length == 0:
                    result["http"]["body_complete"] = True
                    break
                sock.settimeout(remaining())
                if len(raw) >= max_response_bytes:
                    result.update(state="stopped", stop_reason="response_body_limit")
                    break
                chunk = response.read1(min(16384, max_response_bytes - len(raw)))
                if not chunk:
                    if response.length not in (None, 0):
                        raise http.client.IncompleteRead(b"", response.length)
                    result["http"]["body_complete"] = True
                    break
                raw.extend(chunk)
                result["http"]["bytes_received"] = len(raw)
                # A peer can trickle one byte per read. Keep the public log
                # bounded while the in-memory byte count remains exact.
                now = time.monotonic()
                if body_updates < 20 and (body_updates == 0 or len(raw) - emitted_bytes >= 16384
                                          or now - last_body_emit >= .5):
                    emit()
                    body_updates += 1
                    last_body_emit, emitted_bytes = now, len(raw)
            finish("success" if result["http"]["body_complete"] else "partial")
            if result["state"] == "running":
                result.update(state="completed", stop_reason="completed")
            if (bearer_token is not None and expected_json_pointer is not None
                    and 200 <= response.status < 300 and result["http"]["body_complete"]):
                is_json = response.headers.get_content_type() in {"application/json", "application/problem+json"}
                matched = is_json and _json_matches(raw, expected_json_pointer, expected_json_value)
                result["auth"]["assessment"] = "expected_contract_matched" if matched else "expected_contract_not_matched"
                result["auth"]["verification_performed"] = True
    except Exception as exc:
        if current is not None:
            finish("failed", _error(exc))
        result.update(state="failed", stop_reason=(current["name"] if current else "setup") + "_failed")
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        if sock is not None:
            sock.close()
        result.update(finished_at=_utc(), active_stage=None)
        emit()
    return result
