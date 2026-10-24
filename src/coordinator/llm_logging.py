"""Record LLM responses without recording prompts or credentials.

This wrapper belongs around the application ``invoke`` call, before response
parsing. It therefore also records malformed responses that a parser rejects.
The response object and exceptions are returned to the caller unchanged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


_REDACTED = "[REDACTED]"
_WRITE_LOCK = threading.Lock()
_ENV_SECRET = re.compile(
    r"(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|COOKIE|AUTHORIZATION)", re.I
)
_SENSITIVE_KEYS = {
    "apikey", "api_key", "authorization", "proxy_authorization", "cookie", "cookies",
    "set_cookie", "password", "passwd", "pwd", "secret", "token", "credentials",
    "headers", "x_api_key",
}
_REQUEST_KEYS = {"prompt", "prompts", "messages", "request", "request_input", "input"}
_JWT = re.compile(r"(?<![\w-])[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}(?![\w-])")
_API_KEY = re.compile(r"(?<![\w-])(?:sk|pk|api)[-_][A-Za-z0-9_-]{16,}(?![\w-])", re.I)
_AUTH = re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.I)
_JSON_FIELD_START = re.compile(r'"(?P<key>(?:\\.|[^"\\])*)"\s*:\s*')
_QUOTED_FIELD = re.compile(
    r"(?P<prefix>[\"'](?P<key>[^\"'\r\n]+)[\"']\s*:\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^,\s}\]\[{]+)",
    re.S,
)
_HEADER_LINE = re.compile(
    r"(?im)(?P<prefix>\b(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key)\s*:\s*)(?P<value>[^\r\n]+)"
)
_ASSIGNMENT = re.compile(
    r"(?P<prefix>\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|token|secret|password|passwd|cookie|authorization)\s*=\s*)"
    r"(?P<value>[^\s&;,\"'<>]+)", re.I
)


def response_log_path() -> Path:
    """Return the response JSONL path, resolved when a call is logged."""
    return Path(os.getenv("LLM_RESPONSE_LOG_FILE") or "logs/llm_responses.jsonl")


def _sensitive_key(key: Any, *, context: bool = False) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
    credential = normalized in _SENSITIVE_KEYS or normalized.endswith(
        ("_api_key", "_apikey", "_password", "_passwd", "_secret", "_token")
    )
    return credential or (
        context and normalized in _REQUEST_KEYS
    )


def _plain(value: Any, seen: set[int] | None = None) -> Any:
    """Convert metadata without using arbitrary object reprs (which may leak)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    seen = seen if seen is not None else set()
    if id(value) in seen:
        return "[recursive value]"
    seen.add(id(value))
    try:
        if isinstance(value, dict):
            return {str(key): _plain(item, seen) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [_plain(item, seen) for item in value]
        return f"[{type(value).__name__}]"
    finally:
        seen.remove(id(value))


def _credential_json_fields(value: str):
    """Recognize complete credential values even inside malformed outer JSON."""
    decoder = json.JSONDecoder()
    for match in _JSON_FIELD_START.finditer(value):
        try:
            key = json.loads('"' + match.group("key") + '"')
            if not _sensitive_key(key):
                continue
            decoded, end = decoder.raw_decode(value, match.end())
        except (ValueError, TypeError):
            continue
        yield match.end(), end, decoded


class _Redactor:
    def __init__(self, *values: Any):
        self.secrets = {
            value for key, value in os.environ.items()
            if value and _ENV_SECRET.search(key)
        }
        for value in values:
            self._collect(value)

    def _collect(self, value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if _sensitive_key(key):
                    self._collect_strings(item)
                else:
                    self._collect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._collect(item)
        elif isinstance(value, str):
            for match in _AUTH.finditer(value):
                self._collect_strings(match.group(0))
            for match in _JWT.finditer(value):
                self.secrets.add(match.group(0))
                self.secrets.update(part for part in match.group(0).split(".") if len(part) >= 24)
            for match in _HEADER_LINE.finditer(value):
                self._collect_strings(match.group("value"))
            for match in _ASSIGNMENT.finditer(value):
                self._collect_strings(match.group("value"))
            # JSON responses often contain a credential repeated elsewhere.
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                self._collect(parsed)
            for _start, _end, decoded in _credential_json_fields(value):
                self._collect_strings(decoded)
            for match in _QUOTED_FIELD.finditer(value):
                if _sensitive_key(match.group("key")):
                    raw = match.group("value")
                    try:
                        secret = json.loads(raw)
                    except (ValueError, TypeError):
                        secret = raw.strip("\"'")
                    self._collect_strings(secret)

    def _collect_strings(self, value: Any) -> None:
        if isinstance(value, str) and value:
            self.secrets.add(value)
            auth = re.match(r"^(?:Bearer|Basic)\s+(.+)$", value, re.I)
            if auth:
                self.secrets.add(auth.group(1))
        elif isinstance(value, dict):
            for item in value.values():
                self._collect_strings(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._collect_strings(item)

    def text(self, value: str) -> str:
        for secret in sorted(self.secrets, key=len, reverse=True):
            if len(secret) >= 4:
                value = value.replace(secret, _REDACTED)
            else:
                value = re.sub(r"(?<!\w)" + re.escape(secret) + r"(?!\w)", _REDACTED, value)
        value = _JWT.sub(_REDACTED, value)
        value = _AUTH.sub(_REDACTED, value)
        value = _API_KEY.sub(_REDACTED, value)
        parts, previous_end = [], 0
        for start, end, _decoded in _credential_json_fields(value):
            if start < previous_end:
                continue
            parts.extend((value[previous_end:start], json.dumps(_REDACTED)))
            previous_end = end
        if parts:
            value = "".join(parts) + value[previous_end:]
        value = _QUOTED_FIELD.sub(
            lambda match: match.group("prefix") + json.dumps(_REDACTED)
            if _sensitive_key(match.group("key")) else match.group(0), value
        )
        value = _HEADER_LINE.sub(lambda match: match.group("prefix") + _REDACTED, value)
        return _ASSIGNMENT.sub(lambda match: match.group("prefix") + _REDACTED, value)

    def clean(self, value: Any, *, context: bool = False) -> Any:
        if isinstance(value, dict):
            return {
                self.text(str(key)): _REDACTED if _sensitive_key(key, context=context)
                else self.clean(item, context=context)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.clean(item, context=context) for item in value]
        return self.text(value) if isinstance(value, str) else value


def _response_data(response: Any) -> dict[str, Any]:
    if isinstance(response, str):
        return {"content": response}
    if isinstance(response, dict):
        return _plain(response)
    data = {}
    for attr in ("content", "response_metadata", "usage_metadata", "id", "model"):
        item = getattr(response, attr, None)
        if item is not None:
            data[attr] = _plain(item)
    return data or {"content": _plain(response)}


def sanitize_for_log(value: Any) -> Any:
    """Return a JSON-compatible copy with credential values removed.

    Pattern component names such as ``auth_segment`` and ``token_resource`` are
    retained. Only credential fields/values and recognizable secrets are masked.
    """
    data = _plain(value)
    return _Redactor(data).clean(data)


def _append(event: dict[str, Any]) -> None:
    # Observability must never change the success/failure of an actual LLM call.
    try:
        line = json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n"
        with _WRITE_LOCK:
            path = response_log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(line)
    except Exception:
        pass


def _input_texts(value: Any) -> list[str]:
    """Only used to remove an echoed request from an exception message."""
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, dict):
        return [text for item in value.values() for text in _input_texts(item)]
    if isinstance(value, (list, tuple)):
        return [text for item in value for text in _input_texts(item)]
    content = getattr(value, "content", None)
    if content is not None:
        return _input_texts(content)
    messages = getattr(value, "messages", None)
    return _input_texts(messages) if messages is not None else []


def invoke_logged(runnable: Any, input_value: Any, *, component: str,
                  operation: str, context: dict | None = None) -> Any:
    """Invoke once and append its full, sanitized response or error to JSONL.

    Context should contain identifiers/counts for this operation; request inputs
    are never written. Failure to create/write the log is deliberately nonfatal.
    """
    started = time.monotonic()
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "call_id": uuid4().hex,
        "component": component,
        "operation": operation,
    }
    try:
        response = runnable.invoke(input_value)
    except Exception as error:
        try:
            error_message = str(error)
            for text in sorted(_input_texts(input_value), key=len, reverse=True):
                error_message = error_message.replace(text, "[REQUEST REDACTED]")
            redactor = _Redactor(_plain(context), error_message, *_input_texts(input_value))
            event.update({
                "status": "error", "duration_seconds": time.monotonic() - started,
                "context": redactor.clean(_plain(context or {}), context=True),
                "error": {"type": type(error).__name__, "message": error_message},
            })
            _append(redactor.clean(event))
        except Exception:
            pass
        raise
    try:
        data = _response_data(response)
        redactor = _Redactor(data, _plain(context), *_input_texts(input_value))
        event.update({
            "status": "ok", "duration_seconds": time.monotonic() - started,
            "context": redactor.clean(_plain(context or {}), context=True),
            "response": data,
        })
        _append(redactor.clean(event))
    except Exception:
        pass
    return response
