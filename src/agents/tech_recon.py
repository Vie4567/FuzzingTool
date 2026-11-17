"""
Tech-Stack Reconnaissance Agent — scoped multi-source observations.

Seven channels, sequenced with bounded concurrency inside probes and crawler:
  CH-1: HTTP Header & Cookie Fingerprinting
  CH-2: DOM Parser & HTML Anchor Extraction
  CH-3: JavaScript Bundle Analysis
  CH-4: Recursive Crawl Spider (async, adaptive depth)
  CH-5: robots.txt, sitemap.xml & Security Files Probe
  CH-6: OpenAPI JSON (YAML/GraphQL explicitly unsupported)
  CH-7: Error Probe — khai thác thông báo lỗi

HTML parsing and transport use the standard library. Evidence records retain
origins and distinguish observations, references and inferences. Completion
describes collection, never independent verification of an endpoint.
"""

import asyncio
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from src.coordinator.logger import (
    agent_logger,
    log_agent_error,
    log_agent_progress,
    log_agent_start,
    log_agent_success,
    COLOR_CYAN,
    COLOR_MAGENTA,
    COLOR_RESET,
)
from src.agents.base_agent import BaseAutonomousAgent
from src.tools.registry import default_registry
from src.tools.recon_http import ScopedReconTransport, _origin
from src.tools.recon_records import ReconRecords
from src.tools.recon_observations import (
    absolute_url, origin_url, path_observation, target_paths, unique_records,
    query_parameters, parse_dom,
)
from src.tools.tech_fingerprints import header_fingerprint, resolve_technologies

logger = logging.getLogger(__name__)


def records_stopped():
    from src.coordinator.runtime import current_runtime
    budget = current_runtime()
    return bool(budget and budget.stop_reason)

# ---------------------------------------------------------------------------
# Attempt optional import of BeautifulSoup for richer DOM parsing
# ---------------------------------------------------------------------------
try:
    from bs4 import BeautifulSoup  # type: ignore
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


# ===========================================================================
# Low-level HTTP helper
# ===========================================================================

def _make_ssl_ctx() -> ssl.SSLContext:
    return ssl.create_default_context()


_SSL_CTX = _make_ssl_ctx()

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
from src.tools.auth_manager import AuthManager


def _fetch_sync(url: str, timeout: int = 10, extra_headers: Optional[dict] = None,
                *, transport=None, method="GET") -> tuple[Optional[int], dict, str]:
    """Đồng bộ: trả (status, headers_dict, body_str). Lỗi → (None, {}, err_msg)."""
    transport = transport or ScopedReconTransport(url, headers=extra_headers)
    return transport.fetch(url, timeout=timeout, method=method)


async def _fetch_async(url: str, timeout: int = 10, extra_headers: Optional[dict] = None,
                       *, transport=None, method="GET") -> tuple[Optional[int], dict, str]:
    """Bất đồng bộ wrapper quanh _fetch_sync (chạy trong thread pool)."""
    return await asyncio.to_thread(_fetch_sync, url, timeout, extra_headers,
                                   transport=transport, method=method)


# ===========================================================================
# CH-1: HTTP Header & Cookie Fingerprinting
# ===========================================================================

def _ch1_header_fingerprint(headers: dict, body: str, fp_data: dict, waf_data: dict) -> dict:
    return header_fingerprint(headers, body, fp_data, waf_data)



# ===========================================================================
# CH-2: DOM Parser & HTML Anchor Extraction
# ===========================================================================

def _ch2_dom_parse(body: str, base_url: str, fp_data: dict) -> dict:
    return parse_dom(body, base_url, fp_data)



# ===========================================================================
# CH-3: JavaScript Bundle Analysis
# ===========================================================================

THIRD_PARTY_IGNORE = {
    "google-analytics.com", "googletagmanager.com", "google.com", "gstatic.com",
    "facebook.com", "facebook.net", "fbcdn.net",
    "twitter.com", "twimg.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "w3.org", "schema.org", "github.com",
    "sentry.io", "datadoghq.com", "mixpanel.com",
}


def _ch3_js_analyze(js_body: str, js_patterns: dict, base_domain: str = "", *, base_url=None, source_url=None) -> dict:
    # Keep the complete source URL; absolute external paths are never reassigned
    # to the target origin. This remains candidate extraction, not verification.
    base_url = base_url or ("https://" + base_domain + "/" if base_domain else "https://unknown.invalid/")
    observations, parameters = [], []
    candidates = []
    for category, data in js_patterns.items():
        if category == "_meta" or not isinstance(data, dict):
            continue
        for pattern in data.get("patterns", []):
            try:
                for match in re.finditer(pattern, js_body):
                    value = match.group(1) if match.lastindex else match.group(0).strip("\"'")
                    if value.startswith(("/", "http://", "https://")):
                        candidates.append(value)
            except re.error:
                continue
    # Quoted URLs retain query parameters lost by older path-only regexes.
    candidates.extend(re.findall(r"[\"']((?:https?://|/)[^\"'<>\s]+)[\"']", js_body))
    for value in candidates:
        row = path_observation(value, base_url, "javascript")
        if row:
            row["source_url"] = source_url or base_url
            observations.append(row)
            parameters.extend(query_parameters(row["url"], "javascript", source_url or base_url))
    observations = unique_records(observations)
    api_origins = sorted({row["origin"] for row in observations
                          if _origin(row["url"]) != _origin(base_url)})
    return {"paths": target_paths(observations, base_url),
            "params": sorted({row["name"] for row in parameters}),
            "api_origins": api_origins, "observations": observations,
            "parameters": unique_records(parameters)}




# ===========================================================================
# CH-4: Recursive Crawl Spider (async)
# ===========================================================================

class _ReconSpider:
    """Crawl đệ quy adaptive-depth theo spider_config.json."""

    SPA_FRAMEWORKS = {"react", "vue_js", "angular", "svelte", "next_js", "nuxt_js"}
    SSR_FRAMEWORKS = {"wordpress", "drupal", "joomla", "django", "laravel", "symfony"}

    def __init__(self, start_url: str, tech_hints: dict, spider_cfg: dict, extra_headers: Optional[dict] = None, *, transport=None):
        self.start_url = start_url
        self.parsed_base = urllib.parse.urlparse(start_url)
        self.base_domain = self.parsed_base.netloc
        self.cfg = spider_cfg
        self.limits = spider_cfg.get("limits", {})
        self.exclusions = spider_cfg.get("exclusion_patterns", [])
        self.priority_paths = spider_cfg.get("priority_paths", [])
        self.extra_headers = extra_headers or {}
        self.transport = transport or ScopedReconTransport(start_url, headers=extra_headers)

        self.max_depth = self._resolve_depth(tech_hints)
        self.max_pages = self._resolve_max_pages(tech_hints)
        self.visited: set = set()
        self.discovered_paths: set = set()
        self.discovered_params: set = set()
        self.observations = []
        self.parameters = []
        self.forms = []
        self.responses_received = 0

        self._sem = asyncio.Semaphore(
            self.limits.get("concurrent_requests", 5)
        )

    def _resolve_depth(self, hints: dict) -> int:
        cms_hints = [h.lower() for h in hints.get("cms_hints", [])]
        if hints.get("api_schema"):
            return 1
        if any(f in cms_hints for f in self.SPA_FRAMEWORKS):
            return 2
        if any(f in cms_hints for f in self.SSR_FRAMEWORKS):
            return 4
        if hints.get("waf_detected"):
            return 1
        return self.limits.get("default_max_depth", 3)

    def _resolve_max_pages(self, hints: dict) -> int:
        cms_hints = [h.lower() for h in hints.get("cms_hints", [])]
        if any(f in cms_hints for f in self.SPA_FRAMEWORKS):
            return self.limits.get("spa_max_pages", 50)
        if any(f in cms_hints for f in self.SSR_FRAMEWORKS):
            return self.limits.get("ssr_max_pages", 250)
        return self.limits.get("default_max_pages", 150)

    def _is_excluded(self, path: str) -> bool:
        path_lower = path.lower()
        return any(ex in path_lower for ex in self.exclusions)

    def _normalize_url(self, href: str, current_url: str) -> Optional[str]:
        href = href.strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        try:
            full = urllib.parse.urldefrag(urllib.parse.urljoin(current_url, href)).url
            parsed = urllib.parse.urlparse(full)
        except ValueError:
            return None
        if not self.transport.allows(full):
            return None  # external
        clean_path = parsed.path
        if self._is_excluded(clean_path):
            return None
        return full

    async def crawl(self, url: str, depth: int = 0):
        if not self.transport.allows(url):
            return
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        self.visited.add(url)
        parsed = urllib.parse.urlparse(url)
        self.discovered_paths.add(parsed.path or "/")

        delay = self.limits.get("request_delay_ms", 300) / 1000.0
        await asyncio.sleep(delay)

        async with self._sem:
            timeout = self.limits.get("request_timeout_ms", 8000) // 1000
            status, headers, body = await _fetch_async(url, timeout=timeout, transport=self.transport)

        if status is not None:
            self.responses_received += 1
            row = path_observation(url, url, "crawler", classification="observed", method="GET")
            row["status_code"] = status
            self.observations.append(row)
        if not body or status is None:
            return

        parsed_dom = _ch2_dom_parse(body, url, {})
        for error in parsed_dom.get("errors", []):
            if hasattr(self.transport, "error"):
                self.transport.error(error["error_type"], error["message"], url=url)
        self.observations.extend(parsed_dom["observations"])
        self.parameters.extend(parsed_dom["parameters"])
        self.forms.extend(parsed_dom["forms"])
        self.discovered_params.update(parsed_dom["params"])
        hrefs = [row["url"] for row in parsed_dom["observations"]
                 if row["url"] not in parsed_dom["script_urls"]]

        new_links = []
        for href in hrefs:
            normalized = self._normalize_url(href, url)
            if normalized and normalized not in self.visited:
                new_links.append(normalized)
                p = urllib.parse.urlparse(normalized).path
                if p:
                    self.discovered_paths.add(p)

        # Ưu tiên priority paths
        new_links.sort(
            key=lambda lnk: any(p in lnk for p in self.priority_paths),
            reverse=True
        )

        tasks = [self.crawl(link, depth + 1) for link in new_links]
        if tasks:
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, Exception) and hasattr(self.transport, "error"):
                    self.transport.error("crawler_error", str(outcome))

    async def run(self) -> dict:
        await self.crawl(self.start_url)
        return {
            "paths": target_paths(self.observations, self.start_url),
            "params": list(self.discovered_params),
            "pages_visited": self.responses_received,
            "pages_selected": len(self.visited),
            "depth_used": self.max_depth,
            "observations": unique_records(self.observations),
            "parameters": unique_records(self.parameters),
            "forms": unique_records(self.forms),
        }


# ===========================================================================
# CH-5: robots.txt, sitemap.xml & Security Files Probe
# ===========================================================================

PROBE_FILES = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/swagger.json",
    "/graphql", "/graphiql",
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/package.json", "/composer.json", "/Gemfile",
    "/.git/config", "/.env",
]


def _parse_robots(content: str) -> list[str]:
    paths = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith(("Allow:", "Disallow:", "Sitemap:")):
            _, _, value = stripped.partition(":")
            value = value.strip()
            if value and value != "/":
                paths.append(value)
    return paths


def _parse_sitemap(content: str) -> list[str]:
    paths = []
    for loc in re.findall(r"<loc>([^<]+)</loc>", content, re.IGNORECASE):
        loc = loc.strip()
        parsed = urllib.parse.urlparse(loc)
        if parsed.path and parsed.path != "/":
            paths.append(parsed.path)
    return paths


async def _ch5_probe(base_url: str, *, transport=None) -> dict:
    result = {"paths": [], "params": [], "has_robots_txt": False, "has_sitemap": False,
              "probe_hits": [], "api_schema_urls": [], "observations": [], "parameters": []}
    base = origin_url(base_url)
    transport = transport or ScopedReconTransport(base_url)
    sem = asyncio.Semaphore(3)

    async def probe(probe_path):
        url = absolute_url(probe_path, base + "/")
        if not url or not transport.allows(url):
            return
        async with sem:
            status, _, body = await _fetch_async(url, timeout=8, transport=transport)
        if status not in (200, 301, 302) or not body:
            return
        lower = body.strip().lower()
        is_html = lower.startswith(("<!doctype html", "<html")) or "<body" in lower[:200]
        values = []
        if probe_path == "/robots.txt":
            if not is_html and any(k in lower for k in ("user-agent", "disallow", "allow")):
                result["has_robots_txt"] = True
                values = _parse_robots(body)
            else:
                return
        elif probe_path in ("/sitemap.xml", "/sitemap_index.xml"):
            if not is_html and any(k in lower for k in ("<loc>", "<urlset", "<sitemap")):
                from html import unescape
                result["has_sitemap"] = True
                values = [unescape(value.strip()) for value in re.findall(r"<loc>([^<]+)</loc>", body, re.I)]
            else:
                return
        elif probe_path in ("/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml", "/api-docs", "/api/swagger.json"):
            if is_html or not any(k in lower for k in ("swagger", "openapi", "paths")):
                return
            result["api_schema_urls"].append(url)
        elif probe_path in ("/graphql", "/graphiql"):
            if is_html and "graphql" not in lower:
                return
            result["api_schema_urls"].append(url)
        elif is_html:
            return
        result["probe_hits"].append(probe_path)
        for value in values:
            row = path_observation(value, url, "robots" if probe_path == "/robots.txt" else "sitemap")
            if row:
                result["observations"].append(row)
                result["parameters"].extend(query_parameters(row["url"], row["source"], url))

    outcomes = await asyncio.gather(*(probe(path) for path in PROBE_FILES), return_exceptions=True)
    for outcome in outcomes:
        if isinstance(outcome, Exception) and hasattr(transport, "error"):
            transport.error("probe_error", str(outcome))
    result["observations"] = unique_records(result["observations"])
    result["paths"] = target_paths(result["observations"], base_url)
    result["params"] = sorted({row["name"] for row in result["parameters"]})
    return result



# ===========================================================================
# CH-6: API Schema Auto-Detection (OpenAPI / GraphQL Introspection)
# ===========================================================================

async def _ch6_api_schema(schema_urls: list[str], *, transport=None) -> dict:
    result = {"paths": [], "params": [], "schema_type": None, "endpoints_count": 0,
              "schema_source": None, "observations": [], "parameters": [], "operations": [],
              "unsupported": []}
    if not schema_urls:
        return result
    transport = transport or ScopedReconTransport(schema_urls[0])
    for schema_url in schema_urls:
        suffix = urllib.parse.urlsplit(schema_url).path.lower()
        if suffix.endswith((".yaml", ".yml", "/graphql", "/graphiql")):
            result["unsupported"].append({"url": schema_url, "reason": "unsupported_schema_format"})
            continue
        status, _, body = await _fetch_async(schema_url, timeout=10, transport=transport)
        if status != 200 or not body:
            continue
        try:
            schema = json.loads(body)
            if not isinstance(schema, dict) or not isinstance(schema.get("paths"), dict):
                raise ValueError("OpenAPI paths must be an object")
            if not (schema.get("openapi") or schema.get("swagger")):
                raise ValueError("Missing OpenAPI/Swagger version")
            server = origin_url(schema_url) + "/"
            if isinstance(schema.get("basePath"), str):
                if not schema["basePath"].startswith("/") or schema["basePath"].startswith("//"):
                    raise ValueError("Invalid Swagger basePath")
                server = absolute_url(schema["basePath"].rstrip("/") + "/", server)
            servers = schema.get("servers", [])
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                server = absolute_url(servers[0].get("url"), schema_url)
                if server is None:
                    raise ValueError("Invalid OpenAPI server URL")
                server = server.rstrip("/") + "/"
            for path, item in schema["paths"].items():
                if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or not isinstance(item, dict):
                    raise ValueError("Invalid OpenAPI path item")
                for method, operation in item.items():
                    if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                        continue
                    if not isinstance(operation, dict):
                        raise ValueError("Invalid OpenAPI operation")
                    row = path_observation(path.lstrip("/"), server, "openapi", method=method.upper())
                    if not row:
                        continue
                    row["source_url"] = schema_url
                    result["observations"].append(row)
                    result["operations"].append({**row, "operation_id": operation.get("operationId"),
                                                 "request_body": operation.get("requestBody", {})})
                    path_params, op_params = item.get("parameters", []), operation.get("parameters", [])
                    if not isinstance(path_params, list) or not isinstance(op_params, list):
                        raise ValueError("OpenAPI parameters must be arrays")
                    for param in path_params + op_params:
                        if isinstance(param, dict) and isinstance(param.get("name"), str):
                            result["parameters"].append({"name": param["name"], "location": param.get("in", "unknown"),
                                "url": row["url"], "method": method.upper(), "source": "openapi", "source_url": schema_url,
                                "classification": "observed", "required": param.get("required", False)})
            result["schema_type"], result["schema_source"] = "OpenAPI", schema_url
        except (ValueError, TypeError, AttributeError) as exc:
            if hasattr(transport, "error"):
                transport.error("schema_parse_error", str(exc), url=schema_url)
            continue
        break
    result["observations"] = unique_records(result["observations"])
    result["paths"] = target_paths(result["observations"], schema_urls[0])
    result["parameters"] = unique_records(result["parameters"])
    result["params"] = sorted({row["name"] for row in result["parameters"]})
    result["endpoints_count"] = len({row["url"] for row in result["observations"]})
    return result



# ===========================================================================
# CH-7: Error Probe — khai thác thông báo lỗi
# ===========================================================================

ERROR_PROBE_PAYLOADS = [
    {"method": "GET",    "suffix": "?id=SENTINEL_PROBE&debug=1"},
    {"method": "GET",    "suffix": "?XDEBUG_SESSION=SENTINEL"},
    {"method": "OPTIONS","suffix": ""},
    {"method": "TRACE",  "suffix": ""},
]

INTERNAL_PATH_RE = re.compile(
    r'(?:/[\w\-./]+\.(?:java|py|php|js|rb|go|cs|ts))', re.IGNORECASE
)

FRAMEWORK_ERROR_SIGS = {
    "Traceback (most recent call last)": "Python",
    "at Object.<anonymous>":            "Node.js",
    "PHPFatal error":                   "PHP",
    "NullPointerException":             "Java",
    "ActionView::Template::Error":      "Rails",
    "Whoa! Something went wrong":       "Laravel",
    "System.Web.HttpException":         "ASP.NET",
}


async def _ch7_error_probe(base_url: str, *, transport=None) -> dict:
    """Gửi request lỗi có chủ ý để khai thác stack trace."""
    result: dict = {
        "paths": [],
        "params": [],
        "internal_paths": [],
        "confirmed_framework": None,
        "allowed_methods": [],
    }
    parsed_target = urllib.parse.urlsplit(base_url)
    transport = transport or ScopedReconTransport(base_url)

    for payload in ERROR_PROBE_PAYLOADS:
        query = parsed_target.query
        if payload["suffix"]:
            query = "&".join(part for part in (query, payload["suffix"].lstrip("?")) if part)
        url = urllib.parse.urlunsplit((parsed_target.scheme, parsed_target.netloc,
                                      parsed_target.path or "/", query, ""))
        status, hdrs, body = await _fetch_async(url, timeout=8, transport=transport, method=payload["method"])
        if status is None:
            continue

        # OPTIONS → lấy Allow header
        if payload["method"] == "OPTIONS":
            allow = hdrs.get("Allow") or hdrs.get("allow") or ""
            if allow:
                result["allowed_methods"] = [m.strip() for m in allow.split(",")]

        # Tìm internal paths trong stack trace
        for m in INTERNAL_PATH_RE.finditer(body):
            ip = m.group(0)
            if ip not in result["internal_paths"]:
                result["internal_paths"].append(ip)
                # Extract dirname as path hint
                parts = ip.rsplit("/", 1)
                if len(parts) > 1 and parts[0]:
                    result["paths"].append(parts[0])

        # Framework từ error signature
        if not result["confirmed_framework"]:
            for sig, fw in FRAMEWORK_ERROR_SIGS.items():
                if sig in body:
                    result["confirmed_framework"] = fw
                    break

    return result


# ===========================================================================
# CMS / Backend resolution helper
# ===========================================================================

def _resolve_cms_backend(tech_stack: dict, cms_hints: list, meta_generator: Optional[str], **options) -> dict:
    return resolve_technologies(tech_stack, cms_hints, meta_generator, **options)



# ===========================================================================
# Aggregator
# ===========================================================================

def _aggregate(channel_results: dict) -> dict:
    """Gộp và dedup kết quả từ tất cả các kênh."""
    all_paths: set = set()
    all_params: set = set()
    source_breakdown: dict = {}

    for ch, data in channel_results.items():
        paths = data.get("paths", [])
        params = data.get("params", [])
        all_paths.update(
            p for p in paths
            if isinstance(p, str)
            and p.startswith("/")
            and not p.startswith("//")   # loại bỏ //external.com/...
        )
        all_params.update(p for p in params if isinstance(p, str) and p)
        source_breakdown[ch] = len(paths)

    return {
        "total_paths_discovered": len(all_paths),
        "total_params_discovered": len(all_params),
        "paths": sorted(all_paths),
        "params": sorted(all_params),
        "source_breakdown": source_breakdown,
    }


# ===========================================================================
# Main Agent Class
# ===========================================================================

class TechReconAgent(BaseAutonomousAgent):
    """
    Tech Recon Agent — Multi-Source Recon Engine (7 kênh).
    Thực hiện recon tự chủ: Gọi tool, lập luận chọn tool & options, giải trình kết quả.
    """

    def __init__(
        self,
        llm=None,
        auth_manager: Optional[AuthManager] = None,
        cookie: Optional[str] = None,
        bearer_token: Optional[str] = None,
        account: Optional[dict] = None,
        headers: Optional[dict] = None,
        allowed_origins: Optional[list] = None,
        auth_origins: Optional[list] = None,
        verify_ssl: bool = True,
        tls_ca_file: Optional[str] = None,
    ):
        super().__init__(agent_name="TechReconAgent", llm=llm, tool_registry=default_registry)
        if auth_manager is not None and any(value is not None for value in (cookie, bearer_token, account)):
            raise ValueError("Configure credentials on auth_manager or on TechReconAgent, not both")
        self.auth_manager = auth_manager or AuthManager(
            cookie=cookie,
            bearer_token=bearer_token,
            account=account,
            custom_headers=headers,
            allowed_origins=allowed_origins,
            auth_origins=auth_origins,
            verify_ssl=verify_ssl,
            tls_ca_file=tls_ca_file,
        )
        self._request_headers = dict(headers or {})
        self._transport_options = {
            "allowed_origins": allowed_origins if allowed_origins is not None else getattr(self.auth_manager, "allowed_origins", None),
            "auth_origins": auth_origins if auth_origins is not None else getattr(self.auth_manager, "auth_origins", None),
            "verify_ssl": verify_ssl,
            "tls_ca_file": tls_ca_file if tls_ca_file is not None else getattr(self.auth_manager, "tls_ca_file", None),
        }
        self._knowledge_dir = Path(__file__).resolve().parents[2] / "knowledge"
        self._fp_data: dict = {}
        self._waf_data: dict = {}
        self._js_patterns: dict = {}
        self._spider_cfg: dict = {}
        self._loaded = False

    def _build_transport(self, target_url):
        # Validate the caller's policy before resolving credentials/auto-login.
        policy = ScopedReconTransport(target_url, headers=self._request_headers, **self._transport_options)
        manager_policy = ScopedReconTransport(
            target_url, allowed_origins=self.auth_manager.allowed_origins,
            auth_origins=self.auth_manager.auth_origins, verify_ssl=self.auth_manager.verify_ssl,
            tls_ca_file=self.auth_manager.tls_ca_file,
        )
        if (policy.public_settings() != manager_policy.public_settings()
                or self._transport_options["tls_ca_file"] != self.auth_manager.tls_ca_file):
            raise ValueError("AuthManager and Recon must use the same origin and TLS policy")
        headers = {**self._request_headers, **self.auth_manager.get_auth_headers(target_url)}
        return ScopedReconTransport(target_url, headers=headers, **self._transport_options)

    def _redact(self, value, transport):
        return self.auth_manager.redact(transport.redact(value))

    def _run_full_recon_internal(self, target_url: str) -> dict:
        """Helper nội bộ chạy 7 kênh recon."""
        return asyncio.run(self._run_async(target_url))

    def _load_knowledge(self):
        if self._loaded:
            return
        kd = self._knowledge_dir

        def _load_json(fname: str) -> dict:
            path = kd / fname
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            return {}

        self._fp_data = _load_json("tech_fingerprints.json")
        self._waf_data = _load_json("waf_signatures.json")
        self._js_patterns = _load_json("js_extraction_patterns.json")
        self._spider_cfg = _load_json("spider_config.json")
        self._loaded = True

    # ------------------------------------------------------------------
    # Async core
    # ------------------------------------------------------------------

    async def _run_async(self, target_url: str, *, transport=None) -> dict:
        self._load_knowledge()
        transport = transport or self._build_transport(target_url)
        records = ReconRecords(transport)
        empty = lambda: {"paths": [], "params": [], "observations": [], "parameters": []}

        async def step(channel, work, default):
            if not records.start(channel):
                return default
            try:
                import inspect
                value = work()
                return await value if inspect.isawaitable(value) else value
            except Exception as exc:
                records.error(channel, "channel_error", str(exc), exception_type=type(exc).__name__)
                return default
            finally:
                records.finish(channel)

        status, headers, body = await step("CH-1 Headers",
            lambda: _fetch_async(target_url, timeout=12, transport=records.for_channel("CH-1 Headers")),
            (None, {}, ""))
        ch1 = _ch1_header_fingerprint(headers, body, self._fp_data, self._waf_data)
        ch2 = {**empty(), "forms": [], "cms_hints": [], "meta_generator": None, "script_urls": []}
        ch3 = {**empty(), "api_origins": [], "files_selected": 0, "files_analyzed": 0}
        ch4 = {**empty(), "forms": [], "pages_visited": 0, "pages_selected": 0, "depth_used": 0}
        ch5 = {**empty(), "has_robots_txt": False, "has_sitemap": False, "probe_hits": [], "api_schema_urls": []}
        ch6 = {**empty(), "schema_type": None, "schema_source": None, "endpoints_count": 0,
               "operations": [], "unsupported": []}
        ch7 = {**empty(), "allowed_methods": [], "internal_paths": [], "confirmed_framework": None}
        if status is not None:
            records.channels["CH-2 DOM"]["shared_response_channel"] = "CH-1 Headers"
            if records.requests and records.requests[0]["body_complete"]:
                ch2 = await step("CH-2 DOM", lambda: _ch2_dom_parse(body, target_url, self._fp_data), ch2)
            else:
                records.channels["CH-2 DOM"]["reason"] = "homepage_body_incomplete"
            for error in ch2.get("errors", []):
                records.error("CH-2 DOM", error["error_type"], error["message"])
            records.finish("CH-2 DOM")

            async def collect_js():
                data = {**empty(), "api_origins": [], "files_selected": 0, "files_analyzed": 0}
                js_urls = [url for url in ch2.get("script_urls", [])
                           if urllib.parse.urlsplit(url).path.endswith(".js")][:20]
                data["files_selected"] = len(js_urls)
                for url in js_urls:
                    if not transport.allows(url) or records.stopped():
                        continue
                    code, _, content = await _fetch_async(url, timeout=15, transport=records.for_channel("CH-3 JS"))
                    if code == 200 and content:
                        if len(content.encode("utf-8")) >= 5_000_000:
                            records.error("CH-3 JS", "js_size_limit", "JavaScript analysis size limit", url=url)
                            continue
                        observed = _ch3_js_analyze(content, self._js_patterns, base_url=target_url, source_url=url)
                        data["files_analyzed"] += 1
                        for key in ("observations", "parameters", "api_origins"):
                            data[key].extend(observed.get(key, []))
                data["observations"] = unique_records(data["observations"])
                data["parameters"] = unique_records(data["parameters"])
                data["paths"] = target_paths(data["observations"], target_url)
                data["params"] = sorted({row["name"] for row in data["parameters"]})
                data["api_origins"] = sorted(set(data["api_origins"]))
                return data

            ch3 = await step("CH-3 JS", collect_js, ch3)
            records.channels["CH-3 JS"].update(files_selected=ch3["files_selected"], files_analyzed=ch3["files_analyzed"])
            ch5 = await step("CH-5 Probe", lambda: _ch5_probe(target_url, transport=records.for_channel("CH-5 Probe")), ch5)
            if ch5["api_schema_urls"]:
                ch6 = await step("CH-6 Schema", lambda: _ch6_api_schema(ch5["api_schema_urls"], transport=records.for_channel("CH-6 Schema")), ch6)
                if ch6["unsupported"] and not ch6["schema_type"] and not records.channels["CH-6 Schema"]["errors"]:
                    records.channels["CH-6 Schema"].update(status="skipped", reason="unsupported_schema_format")
            else:
                records.channels["CH-6 Schema"]["reason"] = "no_schema_candidates"
            early_hints = {"cms_hints": ch2["cms_hints"], "waf_detected": ch1["waf_detected"],
                           "api_schema": bool(ch6.get("schema_type"))}
            spider = _ReconSpider(target_url, early_hints, self._spider_cfg,
                                  transport=records.for_channel("CH-4 Spider"))
            ch4 = await step("CH-4 Spider", spider.run, ch4)
            ch7 = await step("CH-7 Error", lambda: _ch7_error_probe(target_url, transport=records.for_channel("CH-7 Error")), ch7)

        resolved = _resolve_cms_backend(ch1["tech_stack"], ch2["cms_hints"], ch2.get("meta_generator"),
                                       evidence=ch1.get("technology_evidence"), body=body, fp_data=self._fp_data)
        for error in resolved.pop("technology_errors", []):
            if not any(e["channel"] == "CH-2 DOM" and e["error_type"] == error["error_type"] for e in records.errors):
                records.error("CH-2 DOM", error["error_type"], error["message"])
            records.finish("CH-2 DOM")
        evidence = resolved.pop("technology_evidence", [])
        conflicts = resolved.pop("technology_conflicts", [])
        final_tech = {**ch1["tech_stack"], **resolved}
        sources = {"CH-2 DOM": ch2, "CH-3 JS": ch3, "CH-4 Spider": ch4,
                   "CH-5 Probe": ch5, "CH-6 Schema": ch6}
        observations = [row for data in sources.values() for row in data.get("observations", [])]
        if status is not None:
            row = path_observation(target_url, target_url, "homepage", classification="observed", method="GET")
            row["status_code"] = status
            observations.append(row)
        observations = unique_records(observations)
        parameters = unique_records([row for data in sources.values() for row in data.get("parameters", [])])
        forms = unique_records(ch2.get("forms", []) + ch4.get("forms", []))
        paths = target_paths(observations, target_url)
        api_hosts = [origin for origin in ch3.get("api_origins", []) if _origin(origin) != _origin(target_url)]
        is_spa = final_tech.get("frontend", "Unknown") != "Unknown"
        architecture = {"type": "decoupled_spa" if api_hosts and is_spa else "decoupled_api" if api_hosts else
                        "monolithic_spa" if is_spa else "Unknown", "classification": "inferred",
                        "frontend_origin": origin_url(target_url), "backend_api_hosts": api_hosts,
                        "primary_backend_api": None, "is_decoupled": bool(api_hosts),
                        "basis": "frontend signatures and JavaScript origin candidates; not independently verified"}
        if api_hosts:
            candidate = api_hosts[0]
            if transport.allows(candidate) and not records.stopped():
                code, hdrs, _ = await _fetch_async(candidate + "/", timeout=8,
                                                  transport=records.for_channel("CH-1 Headers"))
                architecture["backend_probe"] = {"status_code": code, "url": candidate,
                    "server": hdrs.get("server") or hdrs.get("Server"), "classification": "observed"}
                records.finish("CH-1 Headers")
            else:
                architecture["backend_probe"] = {"status_code": None,
                    "skipped_reason": "outside_allowed_origins" if not transport.allows(candidate) else records.stop_reason}
        api_prefixes = ("/api/", "/v1/", "/v2/", "/v3/", "/auth/", "/service/", "/hub")
        api_paths = [path for path in paths if path.startswith(api_prefixes) or "-service/" in path]
        schema_context = {"type": ch6.get("schema_type"), "source": ch6.get("schema_source"),
                          "endpoints_count": ch6.get("endpoints_count", 0),
                          "operations": ch6.get("operations", []), "unsupported": ch6.get("unsupported", [])}
        api_context = {"schema": schema_context,
                       "backend_origins": [{"origin": host, "classification": "candidate", "source": "javascript"} for host in api_hosts],
                       "backend_paths": api_paths, "path_classification": "inferred"}
        profile = {"schema_version": 1, "target_url": target_url, "tech_stack": final_tech,
                   "technology_evidence": evidence, "technology_conflicts": conflicts,
                   "architecture": architecture, "paths": observations, "parameters": parameters,
                   "forms": forms, "api_context": api_context,
                   "classification_contract": "observed = measured response or declaration; candidate = reference; inferred = heuristic; none means verified endpoint"}
        execution = records.execution()
        result = {"target_url": target_url, "status_code": status, "tech_stack": final_tech,
                  "technology_evidence": evidence, "technology_conflicts": conflicts,
                  "architecture": architecture, "primary_backend_api": architecture["primary_backend_api"],
                  "backend_api_endpoints": api_paths, "frontend_routes": [path for path in paths if path not in api_paths],
                  "meta_generator": ch2.get("meta_generator"), "cms": final_tech.get("cms", "Unknown"),
                  "waf_detected": ch1["waf_detected"], "waf_type": ch1["waf_type"],
                  "waf_evidence": ch1.get("waf_evidence", []), "waf_candidates": ch1.get("waf_candidates", []),
                  "discovered_paths": paths, "discovered_params": sorted({row["name"] for row in parameters}),
                  "js_endpoints": ch3["paths"], "forms": forms,
                  "has_robots_txt": ch5["has_robots_txt"], "has_sitemap": ch5["has_sitemap"], "probe_hits": ch5["probe_hits"],
                  "api_schema": schema_context if ch6.get("schema_type") else None,
                  "allowed_methods": ch7.get("allowed_methods", []), "internal_paths": ch7.get("internal_paths", []),
                  "recon_profile": profile, "execution": execution, "http_policy": transport.public_settings(),
                  "recon_stats": {"total_paths_discovered": len(paths), "total_params_discovered": len({r["name"] for r in parameters}),
                      "backend_endpoints_count": len(api_paths), "frontend_routes_count": len(paths)-len(api_paths),
                      "backend_api_hosts_count": len(api_hosts), "spider_pages_visited": ch4.get("pages_visited", 0),
                      "spider_depth_used": ch4.get("depth_used", 0), "js_files_selected": ch3["files_selected"],
                      "js_files_analyzed": ch3["files_analyzed"],
                      "source_breakdown": {key: len(value.get("paths", [])) for key, value in sources.items()}}}
        result["tech_fingerprint"] = {**final_tech, "waf_detected": ch1["waf_detected"], "waf_type": ch1["waf_type"],
                                      "waf_evasion_hints": ch1.get("waf_evasion_hints", []),
                                      "architecture_type": architecture["type"], "backend_api_hosts": api_hosts}
        return self._redact(result, transport)


    # ------------------------------------------------------------------
    # Public sync entry point
    # ------------------------------------------------------------------

    def execute(self, target_url: str, directive: dict = None) -> dict:
        transport = self._build_transport(target_url)
        log_agent_start("TechReconAgent", self._redact(target_url, transport))
        try:
            result = asyncio.run(self._run_async(target_url, transport=transport))
            execution = result["execution"]
            task = self._redact(directive or {"task_id": "TASK_RECON_001", "target_url": target_url,
                "objective": "Collect scoped HTTP observations and evidence-based technology candidates"}, transport)
            history = [{"selected_tool": "full_7channel_recon_suite",
                        "options": {"target_url": self._redact(target_url, transport), **result["http_policy"]},
                        "status": execution["status"], "tool_selection_reason": "Actual native Recon suite execution",
                        "result_summary": {"stats": execution["stats"], "stop_reason": execution["stop_reason"]}}]
            summary = {"execution_status": execution["status"], "stop_reason": execution["stop_reason"],
                       "stats": execution["stats"], "tech_stack": result["tech_stack"],
                       "paths_count": len(result["discovered_paths"]), "path_sample": result["discovered_paths"][:12],
                       "errors_count": len(execution["errors"]),
                       "evidence_note": "HTTP responses and extracted references do not verify an endpoint."}
            narrative = ""
            # Retain the existing advisory model interfaces without letting a
            # post-execution plan rewrite the operation that actually ran.
            if execution["status"] != "failed" and not records_stopped():
                advice = self.plan_tool_execution(task_directive=task, available_tools=self.tool_registry.list_tools(
                    filter_names=["full_7channel_recon_suite"]), execution_history=history)
                result["advisory_plan"] = self._redact(advice, transport)
                narrative = self.generate_justification(task_directive=task, execution_history=history, extracted_data=summary)
            result["tools_executed"] = history
            result["subagent_justification"] = self._redact(
                f"Recon status={execution['status']}; stop_reason={execution['stop_reason']}; "
                f"attempted={execution['stats']['attempted_requests']}; responses={execution['stats']['responses_received']}. "
                + ("Unverified model/template narrative: " + narrative if narrative else ""), transport)
            message = (f"Recon {execution['status']}: {len(result['discovered_paths'])} candidate paths; "
                       f"{execution['stats']['attempted_requests']} HTTP attempts; "
                       f"{len(execution['errors'])} errors; stop={execution['stop_reason']}")
            if execution["completed"]:
                log_agent_success("TechReconAgent", message, metrics=execution["stats"])
            else:
                log_agent_progress("TechReconAgent", message)
            return result
        except Exception as exc:
            safe_error = RuntimeError(self._redact(str(exc), transport))
            log_agent_error("TechReconAgent", "Recon execution failed", exception=safe_error)
            raise safe_error from None
