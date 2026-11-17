"""One explicit origin, credential and TLS policy for Recon HTTP requests."""

from __future__ import annotations

import re
import ssl
import time
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener

from src.coordinator.llm_logging import sanitize_for_log
from src.coordinator.telemetry import record_http_attempt
from src.coordinator.runtime import cap_http_timeout, current_runtime, check_deadline, observe_response
from .proxy_profiles import _NoRedirect, _ScopeGuard, _origin


DEFAULT_UA = "SentinelPentest/1.0 (scoped-recon)"
_PUBLIC_HEADERS = {"user-agent", "accept", "accept-encoding", "accept-language", "content-type"}
RECON_OPTION_KEYS = frozenset({"headers", "cookie", "bearer_token", "account",
                             "allowed_origins", "auth_origins", "verify_ssl", "tls_ca_file"})


def recon_options_from_config(config):
    """Only operator configuration supplies credentials and network policy."""
    config = {} if config is None else config
    if not isinstance(config, dict):
        raise ValueError("config must be a mapping")
    options = {}
    # Compatibility with existing authenticated pipeline configurations. Proxy
    # routing options are not implicitly enabled for Recon.
    fuzzing = config.get("fuzzing_options") or {}
    if isinstance(fuzzing, dict):
        options.update({key: fuzzing[key] for key in ("headers", "allowed_origins") if key in fuzzing})
    nested = config.get("recon_options", {})
    if not isinstance(nested, dict):
        raise ValueError("recon_options must be a mapping")
    for source in (config, nested):
        normalized = dict(source)
        if "token" in normalized and "bearer_token" not in normalized:
            normalized["bearer_token"] = normalized["token"]
        if "custom_headers" in normalized and "headers" not in normalized:
            normalized["headers"] = normalized["custom_headers"]
        options.update({key: normalized[key] for key in RECON_OPTION_KEYS if key in normalized})
    return options


def _validate_headers(headers):
    if not isinstance(headers, dict):
        raise ValueError("headers must be a mapping")
    normalized = {}
    for name, value in headers.items():
        if (not isinstance(name, str) or not isinstance(value, str)
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise ValueError("Invalid request header")
        if name.lower() in {"host", "proxy-authorization", "proxy-connection"}:
            raise ValueError("Host and proxy authentication headers are transport-owned")
        normalized[name.lower()] = (name, value)
    return {name: value for name, value in normalized.values()}


class ScopedReconTransport:
    def __init__(self, target_url, *, headers=None, allowed_origins=None,
                 auth_origins=None, verify_ssl=True, tls_ca_file=None):
        if verify_ssl is not True:
            raise ValueError("Recon requires TLS verification; provide tls_ca_file for a private CA")
        target_origin = _origin(target_url)
        self._origins = self._origins_from(allowed_origins, {target_origin}, "allowed_origins")
        self._auth_origins = self._origins_from(auth_origins, {target_origin}, "auth_origins")
        if target_origin not in self._origins:
            raise ValueError("Target origin is outside allowed_origins")
        if not self._auth_origins <= self._origins:
            raise ValueError("auth_origins must be a subset of allowed_origins")
        self.headers = _validate_headers(headers if headers is not None else {})
        self.ssl_context = ssl.create_default_context(cafile=tls_ca_file)

    @staticmethod
    def _origins_from(values, default, name):
        if values is None:
            return frozenset(default)
        if not isinstance(values, (list, tuple)) or (name == "allowed_origins" and not values):
            raise ValueError(f"{name} must be a list of exact HTTP(S) origins")
        return frozenset(_origin(value, origin_only=True) for value in values)

    def allows(self, url):
        try:
            return _origin(url) in self._origins
        except (ValueError, TypeError):
            return False

    def allows_auth(self, url):
        try:
            return _origin(url) in self._auth_origins and self.allows(url)
        except (ValueError, TypeError):
            return False

    def check_url(self, url, *, credentials=False):
        if not self.allows(url):
            raise ValueError("Request origin is outside allowed_origins")
        if credentials and not self.allows_auth(url):
            raise ValueError("Credential destination is outside auth_origins")

    def redact(self, value):
        return sanitize_for_log({"headers": self.headers, "payload": value})["payload"]

    def public_settings(self):
        def display(origin):
            scheme, host, port = origin
            host = f"[{host}]" if ":" in host else host
            return f"{scheme}://{host}:{port}"
        return {"allowed_origins": [display(o) for o in sorted(self._origins)],
                "auth_origins": [display(o) for o in sorted(self._auth_origins)],
                "verify_ssl": True, "follow_redirects": False}

    def open(self, request, timeout=10, *, cookie_jar=None, _measurement=None):
        request = Request(request) if isinstance(request, str) else request
        self.check_url(request.full_url, credentials=request.data is not None)
        method = request.get_method()
        include_auth = self.allows_auth(request.full_url) and method.upper() != "TRACE"
        extra = _validate_headers(dict(request.header_items()))
        headers = {"User-Agent": DEFAULT_UA}
        if include_auth:
            headers.update(self.headers)
            headers.update(extra)
        else:
            headers.update({key: val for key, val in extra.items() if key.lower() in _PUBLIC_HEADERS})
        headers = _validate_headers(headers)
        outgoing = Request(request.full_url, data=request.data, headers=headers, method=method)
        handlers = [ProxyHandler({}), _ScopeGuard(self._origins), _NoRedirect(),
                    HTTPSHandler(context=self.ssl_context)]
        if cookie_jar is not None and include_auth:
            handlers.append(HTTPCookieProcessor(cookie_jar))
        # A separate opener per call avoids mutable cookie/handler state being
        # shared between concurrent crawl workers. Redirects never carry auth.
        opener = build_opener(*handlers)
        timeout = cap_http_timeout(timeout)
        record_http_attempt(kind="target")
        if _measurement is not None:
            _measurement["attempted"] = True
        try:
            # Waiting for the shared rate slot may consume the deadline.
            response = opener.open(outgoing, timeout=cap_http_timeout(timeout))
        except HTTPError as exc:
            observe_response(exc.code, exc.headers)
            raise
        observe_response(response.code, response.headers)
        return response

    def fetch_result(self, url, timeout=10, method="GET"):
        """One measured attempt; keep observed status even if reading the body fails.

        Headers/body are internal parser inputs. Callers persisting this result
        must retain only public measurements, not raw headers or response bodies.
        No retry, redirect or additional network request is performed here.
        """
        started = time.monotonic()
        result = {"url": url, "method": method, "attempted": False,
                  "status_code": None, "headers": {}, "body": "",
                  "body_complete": False, "content_length": 0,
                  "bytes_received": 0, "body_truncated": False,
                  "response_time": None, "error": None, "stop_reason": None}
        response = None
        raw = b""
        try:
            try:
                response = self.open(Request(url, method=method), timeout=timeout, _measurement=result)
            except HTTPError as exc:
                response = exc
            result["status_code"] = response.code
            result["headers"] = dict(response.headers)
            # HTTPMessage is multi-valued: preserve every cookie name for
            # fingerprinting without changing the legacy string header contract.
            cookies = response.headers.get_all("Set-Cookie", [])
            if cookies:
                result["headers"]["Set-Cookie"] = "\n".join(cookies)
            budget = current_runtime()
            if budget and budget.stop_reason:
                result["stop_reason"] = budget.stop_reason
                return result
            if budget:
                from .soft404 import _set_read_timeout
                while len(raw) <= budget.body_cap:
                    check_deadline()
                    _set_read_timeout(response, cap_http_timeout(timeout))
                    chunk = response.read1(min(65536, budget.body_cap + 1 - len(raw)))
                    if not chunk:
                        if getattr(response, "length", None) not in (None, 0):
                            raise ValueError("recon_incomplete_response_body")
                        break
                    raw += chunk
                    result["bytes_received"] += len(chunk)
                if len(raw) > budget.body_cap:
                    result["body_truncated"] = True
                    raw = raw[:budget.body_cap]
                    raise ValueError("recon_response_body_limit")
            else:
                raw = response.read()
                result["bytes_received"] = len(raw)
            result["body_complete"] = True
        except Exception as exc:
            # HTTPResponse.read() reports an incomplete body via this exception
            # when used outside a runtime. Preserve the prefix it actually read.
            partial = getattr(exc, "partial", None)
            if isinstance(partial, bytes):
                raw += partial
                result["bytes_received"] += len(partial)
            budget = current_runtime()
            result["stop_reason"] = budget.stop_reason if budget else None
            error_type = ("pipeline_stopped" if result["stop_reason"] else
                          "response_body_limit" if str(exc) == "recon_response_body_limit" else
                          "response_read_error" if result["status_code"] is not None else
                          "transport_error" if result["attempted"] else "request_rejected")
            result["error"] = {"error_type": error_type, "exception_type": type(exc).__name__,
                               "message": self.redact(f"{type(exc).__name__}: {exc}"), "count": 1}
        finally:
            result["content_length"] = len(raw)  # retained prefix; bytes_received includes cap sentinel
            result["response_time"] = time.monotonic() - started
            if response is not None:
                response.close()
        if response is not None:
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                result["body"] = raw.decode(charset, errors="replace")
            except LookupError:
                result["body"] = raw.decode("utf-8", errors="replace")
        return result

    def fetch(self, url, timeout=10, method="GET"):
        """Backward-compatible tuple API; richer observations use fetch_result."""
        result = self.fetch_result(url, timeout=timeout, method=method)
        body = result["body"]
        if result["status_code"] is None and result["error"]:
            body = result["error"]["message"]
        return result["status_code"], result["headers"], body
