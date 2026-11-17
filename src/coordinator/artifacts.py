"""Atomic, sanitized pipeline checkpoints, including partial/error results.

``output_dir`` and ``artifact_root`` are parent directories. Each invocation gets
its own child directory so a failed retry cannot overwrite an earlier run.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from urllib.parse import quote, unquote
from uuid import uuid4

from .llm_logging import sanitize_for_log


# Preserve the existing public proxy-configuration marker for API consumers.
_REDACTED = "<redacted>"
_PRIVATE_FIELDS = {
    "headers", "custom_headers", "account", "credentials", "authorization",
    "proxy_authorization", "cookie", "cookies", "set_cookie", "token",
    "access_token", "refresh_token", "bearer_token", "password", "passwd",
    "api_key", "apikey", "secret", "proxy", "proxy_profiles", "proxies",
    "proxy_list", "proxy_pool", "body", "post_data", "request_body",
}
_USERINFO = re.compile(r"(?P<scheme>\b[a-z][a-z0-9+.-]*://)(?P<userinfo>[^\s/?#]+)@", re.I)


def _field(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")


def _private(key: str) -> bool:
    field = _field(key)
    return field in _PRIVATE_FIELDS or field.endswith(
        ("_token", "_password", "_secret", "_api_key", "_apikey")
    )


def _plain(value: Any, seen: set[int] | None = None) -> Any:
    """Make JSON-safe copies; never call user object's repr/str for storage."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    seen = set() if seen is None else seen
    if id(value) in seen:
        return "[recursive value]"
    seen.add(id(value))
    try:
        if isinstance(value, dict):
            return {
                key if isinstance(key, str) else f"[{type(key).__name__} key]": _plain(item, seen)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [_plain(item, seen) for item in value]
        return f"[{type(value).__name__}]"
    finally:
        seen.remove(id(value))


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, dict):
        return [text for item in value.values() for text in _strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    return []


def _secrets(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [secret for key, item in value.items()
                for secret in ((_strings(item) + _secrets(item)) if _private(key) else _secrets(item))]
    if isinstance(value, list):
        return [secret for item in value for secret in _secrets(item)]
    if isinstance(value, str):
        result = []
        for match in _USERINFO.finditer(value):
            userinfo = match.group("userinfo")
            result.append(userinfo)
            result.extend(unquote(part) for part in userinfo.split(":", 1) if part)
        return result
    return []


def _mask_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _REDACTED if _private(key) else _mask_fields(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_fields(item) for item in value]
    if isinstance(value, str):
        return _USERINFO.sub(lambda match: match.group("scheme") + _REDACTED + "@", value)
    return value


class ArtifactWriteError(OSError):
    """A run was not safely persisted; callers must report this explicitly."""


class RunArtifacts:
    """Persist a run and every completed/failed node without leaking auth data."""

    def __init__(self, config: dict | None = None):
        self._config = _plain(config or {})
        options = config if isinstance(config, dict) else {}
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            root = Path(options.get("artifact_root") or
                        options.get("output_dir") or "output_samples/diagnostics")
            self.directory = root.resolve() / f"pipeline_{stamp}_{uuid4().hex[:12]}"
        except (OSError, TypeError, ValueError) as error:
            raise ArtifactWriteError(
                f"Invalid pipeline artifact directory ({type(error).__name__})"
            ) from None
        self.result_path = self.directory / "result.json"
        self._sequence = 0
        try:
            (self.directory / "checkpoints").mkdir(parents=True, exist_ok=False)
        except OSError as error:
            raise ArtifactWriteError(
                f"Cannot create pipeline artifact directory ({type(error).__name__})"
            ) from None

    def public_state(self, state: dict) -> dict:
        """Return a detached JSON-compatible result; known secrets are masked everywhere."""
        data = _plain(state)
        secrets = _secrets(self._config) + _secrets(data)
        secrets += [quote(secret, safe="") for secret in secrets if secret]
        return sanitize_for_log({
            "credentials": secrets,
            "payload": _mask_fields(data),
        })["payload"]

    @staticmethod
    def _write_json(path: Path, value: dict) -> None:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent,
                prefix=".pending_", suffix=".json", delete=False,
            ) as stream:
                temporary = Path(stream.name)
                json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except (OSError, TypeError, ValueError) as error:
            # The original OS exception may contain sensitive path components.
            raise ArtifactWriteError(
                f"Cannot persist {path.name} ({type(error).__name__})"
            ) from None
        finally:
            if temporary is not None and temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def save(self, state: dict, *, node: str = "pipeline", event: str = "checkpoint") -> dict:
        """Write node checkpoint then latest result. Disk failures propagate.

        ``result.json`` always contains the last fully written snapshot. If
        updating it fails, the newly written checkpoint may still be available.
        """
        sequence = self._sequence + 1
        safe_node = re.sub(r"[^a-zA-Z0-9_-]", "_", str(node))[:64] or "node"
        checkpoint = self.directory / "checkpoints" / f"{sequence:04d}_{safe_node}.json"
        public = self.public_state(state)
        public["artifacts"] = {
            "directory": str(self.directory),
            "result": str(self.result_path),
            "checkpoint": str(checkpoint),
            "sequence": sequence,
            "event": self.public_state({"event": event})["event"],
            "node": safe_node,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        self._write_json(checkpoint, public)
        self._write_json(self.result_path, public)
        self._sequence = sequence
        return public

    def record_failure(self, state: dict, error: BaseException, *, node: str = "pipeline") -> dict:
        """Save a failure snapshot while preserving prior results and the caller's state."""
        data = _plain(state)
        try:
            message = str(error)
        except Exception:
            message = "Exception message unavailable"
        if not isinstance(data.get("error_log"), list):
            data["error_log"] = []
        data["error_log"].append({
            "agent": node,
            "type": type(error).__name__,
            "error": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if not isinstance(data.get("agent_statuses"), dict):
            data["agent_statuses"] = {}
        data["agent_statuses"][node] = "failed"
        data["pipeline_status"] = "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "failed"
        data["finished_at"] = datetime.now(timezone.utc).isoformat()
        return self.save(data, node=node, event=data["pipeline_status"])
