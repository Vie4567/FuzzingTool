"""Scoped proxy transports and a pool whose health checks belong to the engine.

Construction performs no I/O. Only an explicit refresh fetches the provider's
candidate list; it never probes the target or retries requests on its own.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import os
import re
from urllib.parse import unquote, urlsplit
from urllib.request import BaseHandler, HTTPRedirectHandler, ProxyHandler, build_opener

from . import proxyscrape


PROXY_OPTION_KEYS = frozenset({
    "proxy_profiles", "proxy_profiles_env", "allowed_origins", "proxy_source",
    "proxy_count", "proxy_candidate_limit", "proxy_fetch_timeout_seconds",
    "proxy_refresh_seconds", "proxy_healthcheck_url", "proxy_check_timeout_seconds",
})
OPERATOR_PROXY_OPTIONS = PROXY_OPTION_KEYS | {"engine"}


def _number(value, name, minimum, maximum, *, integer=False):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number") from None
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{name} is outside its supported range")
    if integer and not number.is_integer():
        raise ValueError(f"{name} must be an integer")
    return int(number) if integer else number


def _clean_text(value):
    return (
        isinstance(value, str)
        and bool(value)
        and not any(ord(char) <= 32 or ord(char) == 127 for char in value)
        and "\\" not in value
    )


def _origin(value, *, origin_only=False):
    if not _clean_text(value):
        raise ValueError("An absolute HTTP or HTTPS URL without controls is required")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ValueError("Invalid HTTP origin") from None
    if (
        parts.scheme not in {"http", "https"}
        or not host
        or "%" in host
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or (origin_only and (parts.path not in {"", "/"} or parts.query))
    ):
        raise ValueError("Invalid HTTP origin")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid HTTP origin port")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid HTTP origin hostname") from None
    return parts.scheme, host, port or (443 if parts.scheme == "https" else 80)


class _ScopeGuard(BaseHandler):
    handler_order = 10

    def __init__(self, origins):
        self._origins = origins

    def _check(self, request):
        if _origin(request.full_url) not in self._origins:
            raise ValueError("Request origin is outside allowed_origins")

    def default_open(self, request):
        self._check(request)
        return None

    def http_request(self, request):
        self._check(request)
        return request

    https_request = http_request


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _ExplicitProxy(ProxyHandler):
    """Use the configured proxy even when ambient NO_PROXY matches the target."""

    def __init__(self, endpoint, authorization):
        self._endpoint = endpoint
        self._authorization = authorization
        # This also suppresses urllib's automatic environment proxy handler.
        super().__init__({"http": "explicit", "https": "explicit"})

    def proxy_open(self, request, proxy, protocol):
        # Do not consult proxy_bypass: a failed proxy must never become direct.
        request.remove_header("Proxy-authorization")
        if self._authorization is not None:
            request.add_unredirected_header("Proxy-Authorization", self._authorization)
        # urllib routes HTTPS through HTTP CONNECT and removes proxy auth from
        # the encrypted target request. Its default HTTPSHandler verifies TLS.
        request.set_proxy(self._endpoint, "http")
        return None


class ProxyProfilePool:
    """Round-robin healthy profiles, pending checks and scan-long quarantine."""

    def __init__(self, profiles, origins, secrets, *, source="manual", managed=False,
                 healthcheck_url=None, count_limit=None, candidate_limit=20,
                 fetch_timeout=10.0, check_timeout=5.0, refresh_seconds=300.0):
        self._origins = frozenset(origins)
        self._secrets = sorted({value for value in secrets if value}, key=len, reverse=True)
        self._openers = {}
        self.source = source
        self.managed = managed
        self.healthcheck_url = healthcheck_url
        self.count_limit = count_limit or len(profiles)
        self.candidate_limit = candidate_limit
        self.fetch_timeout = fetch_timeout
        self.check_timeout = check_timeout
        self.refresh_seconds = refresh_seconds
        self._last_refresh = None
        self._cursor = 0
        self._quarantined = set()
        self._records = {}
        self._active, self._pending = [], []
        for profile in profiles:
            identifier = profile[0]
            active = not managed and len(self._active) < self.count_limit
            self._records[identifier] = {
                "profile": profile, "state": "healthy" if active else "pending",
                "reason": None,
            }
            (self._active if active else self._pending).append(identifier)

    @classmethod
    def from_options(cls, options, target_url):
        if not isinstance(options, dict) or options.get("engine") != "proxy_http":
            raise ValueError("Explicit proxy profiles require engine=proxy_http")
        allowed = options.get("allowed_origins")
        if not isinstance(allowed, (list, tuple)) or not 1 <= len(allowed) <= 32:
            raise ValueError("allowed_origins must contain 1 to 32 HTTP origins")
        origins = {_origin(value, origin_only=True) for value in allowed}
        target_origin = _origin(target_url)
        if target_origin not in origins:
            raise ValueError("Target origin is outside allowed_origins")

        source = options.get("proxy_source", "manual")
        if not isinstance(source, str) or source not in {"manual", "proxyscrape"}:
            raise ValueError("proxy_source must be manual or proxyscrape")
        healthcheck = options.get("proxy_healthcheck_url")
        if healthcheck is None and source == "proxyscrape":
            scheme, host, port = target_origin
            authority = f"[{host}]" if ":" in host else host
            if port != (443 if scheme == "https" else 80):
                authority += f":{port}"
            healthcheck = f"{scheme}://{authority}/robots.txt"
        if healthcheck is not None and _origin(healthcheck) not in origins:
            raise ValueError("Proxy health check origin is outside allowed_origins")
        managed = source == "proxyscrape" or healthcheck is not None

        candidate_limit = _number(options.get("proxy_candidate_limit", 20), "proxy_candidate_limit", 1, 100, integer=True)
        fetch_timeout = _number(options.get("proxy_fetch_timeout_seconds", 10), "proxy_fetch_timeout_seconds", 0.01, 30)
        check_timeout = _number(options.get("proxy_check_timeout_seconds", 5), "proxy_check_timeout_seconds", 0.01, 30)
        refresh_seconds = _number(options.get("proxy_refresh_seconds", 300), "proxy_refresh_seconds", 0, 86400)
        if 0 < refresh_seconds < 30:
            raise ValueError("proxy_refresh_seconds must be 0 or at least 30")

        inline = options.get("proxy_profiles")
        environment = options.get("proxy_profiles_env")
        if source == "proxyscrape":
            if inline is not None or environment is not None:
                raise ValueError("proxyscrape mode does not accept manual proxy profiles")
            profiles, secrets = [], []
        elif (inline is not None) == (environment is not None):
            raise ValueError("Provide exactly one of proxy_profiles or proxy_profiles_env")
        if environment is not None:
            if not isinstance(environment, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", environment):
                raise ValueError("proxy_profiles_env must be an environment variable name")
            raw = os.environ.get(environment)
            if raw is None:
                raise ValueError("The proxy profile environment variable is not configured")
            try:
                inline = json.loads(raw)
            except (ValueError, TypeError):
                raise ValueError("The proxy profile environment variable must contain JSON profiles") from None
        if source == "manual":
            if not isinstance(inline, list) or not 1 <= len(inline) <= 8:
                raise ValueError("proxy_profiles must contain 1 to 8 explicit profiles")
            profiles, secrets = cls._parse_profiles(inline, deduplicate=managed)
        count_limit = _number(options.get("proxy_count", 2 if source == "proxyscrape" else len(profiles)), "proxy_count", 1, 8, integer=True)
        return cls(profiles, origins, secrets, source=source, managed=managed,
                   healthcheck_url=healthcheck, count_limit=count_limit,
                   candidate_limit=candidate_limit, fetch_timeout=fetch_timeout,
                   check_timeout=check_timeout, refresh_seconds=refresh_seconds)

    @staticmethod
    def _parse_profiles(inline, *, deduplicate=False):
        profiles, secrets, identifiers, endpoints = [], [], set(), set()
        for entry in inline:
            if not isinstance(entry, dict) or set(entry) != {"id", "url"}:
                raise ValueError("Each proxy profile must contain only id and url")
            identifier, url = entry["id"], entry["url"]
            if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", identifier):
                raise ValueError("Proxy profile IDs must be safe labels of 1 to 32 characters")
            if not _clean_text(url):
                raise ValueError("Proxy URLs must be explicit HTTP endpoints without controls")
            try:
                parts = urlsplit(url)
                host, port = parts.hostname, parts.port
            except ValueError:
                raise ValueError("Invalid proxy HTTP endpoint") from None
            if (
                parts.scheme != "http" or not host or "%" in host
                or port is None or not 1 <= port <= 65535
                or parts.path or "?" in url or "#" in url
            ):
                raise ValueError("Proxy URLs require HTTP, an explicit valid port, and no path, query or fragment")
            try:
                host = host.encode("idna").decode("ascii").lower()
            except UnicodeError:
                raise ValueError("Invalid proxy hostname") from None
            try:
                host = str(ipaddress.ip_address(host))
            except ValueError:
                pass
            endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            authorization = None
            if parts.username is not None or parts.password is not None:
                if parts.username is None or parts.password is None or re.search(r"%(?![0-9A-Fa-f]{2})", parts.username + parts.password):
                    raise ValueError("Proxy credentials must contain a username and password")
                username, password = unquote(parts.username), unquote(parts.password)
                if not username or ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username + password):
                    raise ValueError("Invalid proxy credentials")
                token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                authorization = "Basic " + token
                secrets.extend((parts.username, parts.password, username, password, token, authorization))
            secrets.extend((url, unquote(url), parts.netloc, endpoint))
            if endpoint in endpoints:
                if deduplicate:
                    # Even discarded aliases and their credentials are redacted.
                    continue
                raise ValueError("Proxy profile endpoints must be unique")
            if identifier in identifiers:
                raise ValueError("Proxy profile IDs must be unique")
            profiles.append((identifier, endpoint, authorization))
            identifiers.add(identifier)
            endpoints.add(endpoint)
        return profiles, secrets

    @property
    def profile_ids(self):
        return list(self._active)

    @property
    def all_profile_ids(self):
        return list(self._records)

    def refresh_due(self, now):
        return self.source == "proxyscrape" and (
            self._last_refresh is None or
            (self.refresh_seconds > 0 and now - self._last_refresh >= self.refresh_seconds)
        )

    def refresh(self, timeout, now):
        """Fetch candidates transactionally; never reconnect to excluded profiles."""
        if self.source != "proxyscrape":
            return {"event": "refresh_not_applicable", "source": self.source}
        self._last_refresh = now
        try:
            candidates = proxyscrape.fetch_candidates(
                timeout=min(self.fetch_timeout, timeout), limit=self.candidate_limit,
            )
            # Provider normalization already deduplicates; repeat it here to
            # keep refresh deterministic for alternate injected test providers.
            entries = [{"id": "ps_" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:24], "url": url}
                       for url in candidates[:self.candidate_limit]]
            profiles, secrets = self._parse_profiles(entries, deduplicate=True)
        except Exception as exc:
            # Provider errors may contain an entire hostile response or URL.
            return {"event": "refresh_failed", "source": self.source,
                    "error": type(exc).__name__, "candidate_count": 0,
                    "pending_count": len(self._pending), "healthy_count": len(self._active)}
        self._secrets = sorted(set(self._secrets).union(secrets), key=len, reverse=True)
        new_active, new_pending = [], []
        retained_ids = set()
        for profile in profiles:
            identifier, endpoint, _ = profile
            if endpoint in self._quarantined:
                continue
            retained_ids.add(identifier)
            old = self._records.get(identifier)
            healthy = old is not None and old["state"] == "healthy"
            self._records[identifier] = {"profile": profile,
                                         "state": "healthy" if healthy else "pending", "reason": None}
            (new_active if healthy else new_pending).append(identifier)
        for identifier, record in self._records.items():
            if identifier not in retained_ids and record["state"] != "excluded":
                record.update(state="expired", reason="not_in_latest_provider_list")
        self._active, self._pending = new_active, new_pending
        if self._active:
            self._cursor %= len(self._active)
        return {"event": "refreshed", "source": self.source, "error": None,
                "candidate_count": len(profiles), "pending_count": len(self._pending),
                "healthy_count": len(self._active)}

    def next_pending(self):
        if len(self._active) >= self.count_limit:
            return None
        while self._pending:
            identifier = self._pending.pop(0)
            if self._records[identifier]["state"] != "pending":
                continue
            self._records[identifier]["state"] = "checking"
            return identifier, self.opener_by_id(identifier)
        return None

    def mark_checked(self, identifier, healthy, reason=None):
        record = self._records[identifier]
        if record["state"] == "excluded":
            return
        if not healthy:
            self.exclude(identifier, reason or "health_check_failed")
            return
        if identifier in self._pending:
            self._pending.remove(identifier)
        if identifier not in self._active and len(self._active) < self.count_limit:
            self._active.append(identifier)
        record.update(state="healthy" if identifier in self._active else "standby",
                      reason=None if identifier in self._active else "proxy_count_limit")

    def mark_check_stopped(self, identifier, reason):
        """Finish an interrupted check without declaring the route unhealthy."""
        record = self._records[identifier]
        if record["state"] == "checking":
            record.update(state="stopped", reason=self.redact(reason)[:512])

    def exclude(self, identifier, reason):
        record = self._records[identifier]
        self._quarantined.add(record["profile"][1])
        record.update(state="excluded", reason=self.redact(reason)[:512])
        if identifier in self._active:
            # The cursor describes the next identity, not simply an offset.
            slot = self._active.index(identifier)
            if slot < self._cursor:
                self._cursor -= 1
            self._active.remove(identifier)
        if identifier in self._pending:
            self._pending.remove(identifier)

    def opener_by_id(self, identifier):
        record = self._records[identifier]
        if record["state"] in {"excluded", "expired"}:
            raise ValueError("Proxy profile is unavailable")
        _, endpoint, authorization = record["profile"]
        if identifier not in self._openers:
            self._openers[identifier] = build_opener(
                _ScopeGuard(self._origins), _ExplicitProxy(endpoint, authorization), _NoRedirect()
            )
        return self._openers[identifier]

    def next_opener(self):
        if not self._active:
            return None
        identifier = self._active[self._cursor % len(self._active)]
        self._cursor = (self._cursor + 1) % len(self._active)
        return identifier, self.opener_by_id(identifier)

    def opener_for(self, index):
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ValueError("Proxy profile index must be a nonnegative integer")
        if not self._active:
            raise ValueError("Proxy pool has no healthy profiles")
        identifier = self._active[index % len(self._active)]
        return identifier, self.opener_by_id(identifier)

    def snapshot(self):
        return {
            "source": self.source, "managed": self.managed,
            "count_limit": self.count_limit, "healthy_count": len(self._active),
            "pending_count": len(self._pending),
            "profiles": [{"id": identifier, "state": record["state"], "reason": record["reason"]}
                         for identifier, record in self._records.items()],
        }

    def redact(self, text):
        result = str(text)
        # One pass prevents short credentials from repeatedly editing the
        # replacement marker itself.
        if not self._secrets:
            return result
        return re.sub("|".join(re.escape(secret) for secret in self._secrets), "[redacted]", result)
