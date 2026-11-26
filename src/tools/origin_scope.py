"""B1 exact read-only scope and private, origin-bound credential context.

This adapter reuses the existing TLS/redirect/rate/budget transport. It is not
yet connected to multi-origin Agent scheduling (B3); it never creates a runtime.
"""
from copy import deepcopy
import posixpath
import re
from urllib.parse import urlencode, urlsplit
from urllib.request import Request

from src.coordinator.origins import canonical_origin, normalize_origin_config, public_url, _path
from src.coordinator.llm_logging import sanitize_for_log
from .recon_http import ScopedReconTransport, _validate_headers, _PUBLIC_HEADERS

# B4.1 probe vocabulary, matching parameter_verification's control/test values.
_PROBE_CONTROL = re.compile(r"__sentinel_unknown_[0-9a-f]{32}")
_PROBE_VALUE = re.compile(r"1|2|true|false|sentinel_[0-9a-f]{32}")


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

    def check_parameter_probe(self, url, method):
        """B4.1: one appended benign query pair on an exact GET rule with `parameters`.

        The name must be operator-listed or a random unknown-name control; the
        value must be one of the bounded test values. Returns (base_url, name).
        """
        url = public_url(url)
        parts = urlsplit(url)
        origin = canonical_origin(url)
        policy = self._config["origin_policies"].get(origin)
        if policy is None or method != "GET" or parts.fragment:
            raise ValueError("Parameter probe denied by origin/method scope")
        path = _path(parts.path or "/")
        for rule in policy["rules"]:
            if rule["path"] != path or "GET" not in rule["methods"] or not rule.get("parameters"):
                continue
            prefix = rule["query"] + "&" if rule["query"] else ""
            if not parts.query.startswith(prefix):
                continue
            extra = parts.query[len(prefix):]
            if extra.count("=") != 1 or "&" in extra:
                continue
            name, value = extra.split("=", 1)
            if ((name in rule["parameters"] or _PROBE_CONTROL.fullmatch(name))
                    and _PROBE_VALUE.fullmatch(value) and urlencode([(name, value)]) == extra):
                return origin + path + ("?" + rule["query"] if rule["query"] else ""), name
        raise ValueError("Parameter probe denied by exact path/query/parameter scope")

    def check_soft404_control(self, url, method):
        """B4.2B: one operator-approved missing sibling of an exact GET rule.

        Allowed only for rules with `soft404_controls`: same origin, parent
        directory and suffix, the rule's exact query, and a name
        `__sentinel_missing_<32 hex><suffix>`. Returns the approving rule URL.
        """
        url = public_url(url)
        parts = urlsplit(url)
        origin = canonical_origin(url)
        policy = self._config["origin_policies"].get(origin)
        if policy is None or method != "GET" or parts.fragment:
            raise ValueError("Soft404 control denied by origin/method scope")
        parent, filename = posixpath.split(_path(parts.path or "/"))
        for rule in policy["rules"]:
            if not rule.get("soft404_controls") or "GET" not in rule["methods"] or rule["query"] != parts.query:
                continue
            rule_parent, rule_name = posixpath.split(rule["path"])
            suffix = posixpath.splitext(rule_name)[1]
            if len(suffix) > 16 or not re.fullmatch(r"(?:\.[a-zA-Z0-9_-]+)?", suffix):
                suffix = ""  # same suffix rule as soft404._group_key
            if (rule_parent or "/") == (parent or "/") and re.fullmatch(
                    r"__sentinel_missing_[0-9a-f]{32}" + re.escape(suffix), filename):
                return origin + rule["path"] + ("?" + rule["query"] if rule["query"] else "")
        raise ValueError("Soft404 control denied by exact directory/suffix/query scope")


class OriginCredentialContext:
    """Runtime-only secret values. Never put this object in config/SharedState."""
    def __init__(self, policy, profiles=None):
        self._policy = policy
        self._headers = {}
        self._profile_ids = {}
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
            self._profile_ids[origin] = profile["profile_id"]

    def __repr__(self):
        return "<OriginCredentialContext private>"

    def headers_for(self, url):
        origin = canonical_origin(url)
        binding = self._policy._config["origin_policies"].get(origin, {}).get("credential_profile")
        if binding != self._profile_ids.get(origin):
            raise ValueError("Origin credential binding is unavailable or changed")
        return dict(self._headers.get(origin, {}))

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

    def check_dispatch(self, url, method):
        """Recheck exact policy and private binding without spending an HTTP attempt."""
        self._policy.check(url, method)
        origin = canonical_origin(url)
        binding = self._policy._config["origin_policies"][origin]["credential_profile"]
        if binding is not None and origin not in self._credentials._headers:
            raise ValueError("Required origin credential profile is unavailable")
        self._credentials.headers_for(url)

    def open(self, request, timeout=10, *, cookie_jar=None, _measurement=None):
        from src.coordinator.runtime import http_origin
        request = Request(request) if isinstance(request, str) else request
        self.check_dispatch(request.full_url, request.get_method())
        origin = canonical_origin(request.full_url)
        if request.data is not None or cookie_jar is not None:
            raise ValueError("B1 disallows request bodies and shared cookie jars")
        supplied = _validate_headers(dict(request.header_items()))
        if any(key.lower() not in _PUBLIC_HEADERS for key in supplied):
            raise ValueError("Private/routing headers must use the origin credential context")
        headers = {**supplied, **self._credentials.headers_for(request.full_url)}
        outgoing = Request(request.full_url, headers=headers, method=request.get_method())
        with http_origin(origin):
            return super().open(outgoing, timeout, _measurement=_measurement)

    def redact(self, value):
        return self._credentials.redact(value)
