"""B1 exact read-only scope and private, origin-bound credential context.

This adapter reuses the existing TLS/redirect/rate/budget transport. It is not
yet connected to multi-origin Agent scheduling (B3); it never creates a runtime.
"""
from copy import deepcopy
from urllib.parse import urlsplit
from urllib.request import Request

from src.coordinator.origins import canonical_origin, normalize_origin_config, public_url, _path
from src.coordinator.llm_logging import sanitize_for_log
from .recon_http import ScopedReconTransport, _validate_headers, _PUBLIC_HEADERS


class OriginScopePolicy:
    def __init__(self, config):
        self._config = normalize_origin_config(config)

    def public_config(self):
        return deepcopy(self._config)

    def check(self, url, method, *, operation="read_only"):
        url = public_url(url)
        parts = urlsplit(url)
        policy = self._config["origin_policies"].get(canonical_origin(url))
        if policy is None or operation != "read_only" or method not in ("GET", "HEAD"):
            raise ValueError("Request denied by origin/method/operation scope")
        path = _path(parts.path or "/")
        if not any(rule["path"] == path and rule["query"] == parts.query
                   and method in rule["methods"] for rule in policy["rules"]):
            raise ValueError("Request denied by exact path/query scope")


class OriginCredentialContext:
    """Runtime-only secret values. Never put this object in config/SharedState."""
    def __init__(self, policy, profiles=None):
        self._policy = policy
        self._headers = {}
        if profiles is not None and not isinstance(profiles, dict):
            raise ValueError("Credential profiles must be an origin-keyed mapping")
        for origin, profile in (profiles or {}).items():
            origin = canonical_origin(public_url(origin, origin_only=True))
            rule = policy.public_config()["origin_policies"].get(origin)
            if (origin in self._headers or not isinstance(profile, dict)
                    or set(profile) != {"profile_id", "headers"} or not rule
                    or rule["credential_profile"] is None
                    or rule["credential_profile"] != profile["profile_id"]):
                raise ValueError("Credential profile is not explicitly bound to this origin")
            headers = _validate_headers(profile["headers"])
            if not headers or any(key.lower() not in {"authorization", "cookie", "x-api-key"} for key in headers):
                raise ValueError("Credential profiles accept only nonempty authentication headers")
            if len(headers) != len(profile["headers"]):
                raise ValueError("Duplicate credential header names")
            for value in headers.values():
                try:
                    value.encode("latin-1")
                except UnicodeError:
                    raise ValueError("Invalid credential header encoding") from None
            self._headers[origin] = headers

    def __repr__(self):
        return "<OriginCredentialContext private>"

    def headers_for(self, url):
        return dict(self._headers.get(canonical_origin(url), {}))

    def redact(self, value):
        return sanitize_for_log({"credentials": self._headers, "payload": value})["payload"]


class OriginScopedTransport(ScopedReconTransport):
    def __init__(self, target_url, *, policy, credentials=None, tls_ca_file=None):
        if not isinstance(policy, OriginScopePolicy):
            raise ValueError("An explicit OriginScopePolicy is required")
        if credentials is None:
            credentials = OriginCredentialContext(policy)
        if not isinstance(credentials, OriginCredentialContext) or credentials._policy is not policy:
            raise ValueError("Credential context belongs to a different scope policy")
        self._policy, self._credentials = policy, credentials
        config = policy.public_config()
        super().__init__(target_url, allowed_origins=config["approved_origins"],
                         auth_origins=list(credentials._headers), verify_ssl=True, tls_ca_file=tls_ca_file)

    def open(self, request, timeout=10, *, cookie_jar=None, _measurement=None):
        request = Request(request) if isinstance(request, str) else request
        self._policy.check(request.full_url, request.get_method())
        origin = canonical_origin(request.full_url)
        binding = self._policy._config["origin_policies"][origin]["credential_profile"]
        if binding is not None and origin not in self._credentials._headers:
            raise ValueError("Required origin credential profile is unavailable")
        if request.data is not None or cookie_jar is not None:
            raise ValueError("B1 disallows request bodies and shared cookie jars")
        supplied = _validate_headers(dict(request.header_items()))
        if any(key.lower() not in _PUBLIC_HEADERS for key in supplied):
            raise ValueError("Private/routing headers must use the origin credential context")
        headers = {**supplied, **self._credentials.headers_for(request.full_url)}
        outgoing = Request(request.full_url, headers=headers, method=request.get_method())
        return super().open(outgoing, timeout, _measurement=_measurement)

    def redact(self, value):
        return self._credentials.redact(value)
