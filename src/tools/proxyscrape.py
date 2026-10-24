"""Bounded download and normalization of ProxyScrape's public HTTP candidates.

Downloading a candidate does not establish that it works or has a distinct
egress IP. The HTTP engine validates candidates against its authorized origin.
"""

from __future__ import annotations

import ipaddress
import math
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


SOURCE_URL = (
    "https://api.proxyscrape.com/v4/free-proxy-list/get"
    "?request=display_proxies&proxy_format=protocolipport&format=text&protocol=http"
)
MAX_BYTES = 2_000_000


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_http_proxy_urls(source: str, *, limit: int | None = None) -> list[str]:
    """Keep distinct public, literal-IP HTTP endpoints; discard all credentials."""
    if not isinstance(source, str):
        raise ValueError("Proxy list must be text")
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100):
        raise ValueError("Proxy candidate limit must be between 1 and 100")
    candidates, seen = [], set()
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if any(ord(char) <= 32 or ord(char) == 127 for char in line) or "\\" in line:
            continue
        if "://" not in line:
            line = "http://" + line
        try:
            parts = urlsplit(line)
            host, port = parts.hostname, parts.port
            if (parts.scheme.lower() != "http" or not host or port is None
                    or not 1 <= port <= 65535 or "%" in host
                    or parts.username is not None or parts.password is not None
                    or parts.path or "?" in line or "#" in line):
                continue
            address = ipaddress.ip_address(host)
            # is_global alone accepts multicast on some Python versions.
            if not address.is_global or address.is_multicast or address.is_reserved:
                continue
            host = f"[{address}]" if address.version == 6 else str(address)
            normalized = f"http://{host}:{port}"
        except (ValueError, TypeError):
            continue
        if normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)
            if limit is not None and len(candidates) >= limit:
                break
    return candidates


def fetch_candidates(*, timeout: float = 10.0, limit: int = 20) -> list[str]:
    """Fetch only the fixed HTTPS API, without redirects or ambient proxies."""
    if isinstance(timeout, bool):
        raise ValueError("Proxy fetch timeout must be between 0.01 and 30 seconds")
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        raise ValueError("Proxy fetch timeout must be between 0.01 and 30 seconds") from None
    if not math.isfinite(timeout) or not 0.01 <= timeout <= 30:
        raise ValueError("Proxy fetch timeout must be between 0.01 and 30 seconds")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("Proxy candidate limit must be between 1 and 100")
    request = Request(SOURCE_URL, headers={"User-Agent": "FuzzingTool-ProxyCandidateImporter/2.0"})
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        if response.geturl() != SOURCE_URL or response.status != 200:
            raise ValueError("Proxy provider returned an unexpected response")
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("Proxy list response is unexpectedly large")
    return parse_http_proxy_urls(body.decode("utf-8-sig", errors="replace"), limit=limit)
