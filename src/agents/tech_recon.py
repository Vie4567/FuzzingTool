"""
Tech-Stack Reconnaissance Agent — Multi-Source Recon Engine (7 kênh song song).

Triển khai đầy đủ 7 kênh theo thiết kế:
  CH-1: HTTP Header & Cookie Fingerprinting
  CH-2: DOM Parser & HTML Anchor Extraction
  CH-3: JavaScript Bundle Analysis
  CH-4: Recursive Crawl Spider (async, adaptive depth)
  CH-5: robots.txt, sitemap.xml & Security Files Probe
  CH-6: API Schema Auto-Detection (OpenAPI / GraphQL)
  CH-7: Error Probe — khai thác thông báo lỗi

Không dùng thư viện ngoài (chỉ stdlib + beautifulsoup4 nếu có).
Fallback sang regex nếu bs4 không có sẵn.
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

logger = logging.getLogger(__name__)

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
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_SSL_CTX = _make_ssl_ctx()

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _fetch_sync(url: str, timeout: int = 10) -> tuple[Optional[int], dict, str]:
    """Đồng bộ: trả (status, headers_dict, body_str). Lỗi → (None, {}, err_msg)."""
    req = urllib.request.Request(url, headers={"User-Agent": _DEFAULT_UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            raw = resp.read()
            # Thử decode theo charset trong Content-Type, fallback utf-8
            ctype = resp.headers.get("Content-Type", "")
            charset = "utf-8"
            m = re.search(r"charset=([\w-]+)", ctype)
            if m:
                charset = m.group(1)
            body = raw.decode(charset, errors="ignore")
            return resp.status, dict(resp.headers), body
    except Exception as exc:
        return None, {}, str(exc)


async def _fetch_async(url: str, timeout: int = 10) -> tuple[Optional[int], dict, str]:
    """Bất đồng bộ wrapper quanh _fetch_sync (chạy trong thread pool)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _fetch_sync, url, timeout)


# ===========================================================================
# CH-1: HTTP Header & Cookie Fingerprinting
# ===========================================================================

def _ch1_header_fingerprint(headers: dict, body: str, fp_data: dict, waf_data: dict) -> dict:
    """
    Phân tích headers + cookies để xác định tech stack và WAF.
    Trả về dict: {tech_stack, waf_detected, waf_type, waf_evasion_hints, paths, params}
    """
    result: dict = {
        "tech_stack": {},
        "waf_detected": False,
        "waf_type": None,
        "waf_evasion_hints": [],
        "paths": [],
        "params": [],
    }
    ts = result["tech_stack"]
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Server header
    server_val = headers_lower.get("server", "")
    if server_val:
        ts["web_server"] = server_val
        for key, sigs in fp_data.get("headers", {}).get("Server", {}).items():
            if any(s.lower() in server_val.lower() for s in sigs if s != "*"):
                ts["server_tech"] = key

    # X-Powered-By
    xpb = headers_lower.get("x-powered-by", "")
    if xpb:
        ts["backend_powered_by"] = xpb
        if "PHP" in xpb:
            ts["language"] = "PHP"
        elif "ASP.NET" in xpb:
            ts["language"] = "C#"
            ts["backend"] = "asp_net"
        elif "Express" in xpb:
            ts["language"] = "JavaScript"
            ts["backend"] = "express"

    # X-Generator / X-Drupal-Cache / X-Redirect-By / X-AspNet-Version
    for h_name, fp_group in fp_data.get("headers", {}).items():
        h_val = headers_lower.get(h_name.lower(), "")
        if not h_val:
            continue
        for tech_key, sigs in fp_group.items():
            if sigs == ["*"] or any(s.lower() in h_val.lower() for s in sigs):
                ts[f"header_{h_name.lower().replace('-', '_')}"] = tech_key

    # X-Api-Version → lộ API prefix
    api_ver = headers_lower.get("x-api-version", "")
    if api_ver:
        ts["api_version_header"] = api_ver

    # CORS — lộ internal domain
    cors = headers_lower.get("access-control-allow-origin", "")
    if cors and cors not in ("*", ""):
        ts["cors_origin"] = cors

    # Cookie fingerprint
    cookie_str = headers_lower.get("set-cookie", "")
    for ck_name, ck_tech in fp_data.get("cookies", {}).items():
        if ck_name.lower() in cookie_str.lower():
            ts[f"cookie_{ck_name.lower()}"] = ck_tech

    # WAF detection
    headers_str = str(headers).lower()
    cookie_str_lower = cookie_str.lower()
    for waf_name, sig in waf_data.items():
        if waf_name == "_meta":
            continue
        if not isinstance(sig, dict):
            continue
        matched = False
        for h_key in sig.get("headers", []):
            if h_key.lower() in headers_str:
                matched = True
                break
        if not matched:
            for c_key in sig.get("cookies", []):
                if c_key.lower() in cookie_str_lower:
                    matched = True
                    break
        if not matched:
            for srv_val in sig.get("server_values", []):
                if srv_val.lower() in server_val.lower():
                    matched = True
                    break
        if matched:
            result["waf_detected"] = True
            result["waf_type"] = waf_name
            result["waf_evasion_hints"] = sig.get("evasion_hints", [])
            break

    return result


# ===========================================================================
# CH-2: DOM Parser & HTML Anchor Extraction
# ===========================================================================

def _ch2_dom_parse(body: str, base_url: str, fp_data: dict) -> dict:
    """
    Bóc tách: href, form action/params, data-url, data-api, button formaction,
    meta generator, CMS body patterns.
    Trả về {paths, params, forms, cms_hints, meta_generator}
    """
    result: dict = {
        "paths": set(),
        "params": set(),
        "forms": [],
        "cms_hints": [],
        "meta_generator": None,
    }
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

    def _normalize(href: str) -> Optional[str]:
        """Chuẩn hóa href → path tuyệt đối hoặc None nếu external/vô ích."""
        href = href.strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        if href.startswith("//"):
            href = parsed_base.scheme + ":" + href
        if href.startswith("http"):
            p = urllib.parse.urlparse(href)
            if p.netloc != parsed_base.netloc:
                return None  # external
            return p.path or "/"
        if href.startswith("/"):
            return href.split("?")[0].split("#")[0]
        # relative → resolve
        full = urllib.parse.urljoin(base_url, href)
        p = urllib.parse.urlparse(full)
        if p.netloc != parsed_base.netloc:
            return None
        return p.path or "/"

    if _BS4_AVAILABLE:
        soup = BeautifulSoup(body, "html.parser")

        # Meta generator
        gen_tag = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
        if gen_tag and gen_tag.get("content"):
            result["meta_generator"] = gen_tag["content"]

        # a[href]
        for tag in soup.find_all("a", href=True):
            p = _normalize(tag["href"])
            if p:
                result["paths"].add(p)

        # form[action] + input/select/textarea names
        for form in soup.find_all("form"):
            action = _normalize(form.get("action", "")) or ""
            method = (form.get("method") or "GET").upper()
            params = [
                inp.get("name")
                for inp in form.find_all(["input", "select", "textarea"])
                if inp.get("name")
            ]
            if action:
                result["paths"].add(action)
            result["params"].update(p for p in params if p)
            result["forms"].append({"action": action, "method": method, "params": params})

        # button[formaction]
        for btn in soup.find_all("button", formaction=True):
            p = _normalize(btn["formaction"])
            if p:
                result["paths"].add(p)

        # link[href] — CSS/resources (lấy path)
        for tag in soup.find_all("link", href=True):
            p = _normalize(tag["href"])
            if p and not any(p.endswith(e) for e in (".css", ".ico", ".png", ".jpg")):
                result["paths"].add(p)

        # [data-url], [data-api]
        for attr in ("data-url", "data-api", "data-href", "data-action"):
            for tag in soup.find_all(attrs={attr: True}):
                p = _normalize(tag[attr])
                if p:
                    result["paths"].add(p)

        # script[src] — chỉ lấy path, không extension filter (để CH-3 fetch)
        for tag in soup.find_all("script", src=True):
            p = _normalize(tag["src"])
            if p:
                result["paths"].add(p)

        # DOM attribute fingerprint
        body_text = str(soup)
        for attr_sig, tech in fp_data.get("dom_attributes", {}).items():
            if attr_sig in body_text:
                result["cms_hints"].append(tech)

    else:
        # Fallback: regex-based extraction
        meta_m = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            body, re.IGNORECASE
        )
        if meta_m:
            result["meta_generator"] = meta_m.group(1)

        for href in re.findall(r'href=["\']([^"\'<>\s]+)["\']', body, re.IGNORECASE):
            p = _normalize(href)
            if p:
                result["paths"].add(p)

        for action in re.findall(r'action=["\']([^"\'<>\s]+)["\']', body, re.IGNORECASE):
            p = _normalize(action)
            if p:
                result["paths"].add(p)

        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
            result["params"].add(name)

        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
            p = _normalize(src)
            if p:
                result["paths"].add(p)

    # Body pattern fingerprint (cả 2 path)
    for pattern, tech in fp_data.get("body_patterns", {}).items():
        if pattern in body:
            result["cms_hints"].append(tech)

    result["paths"] = list(result["paths"])
    result["params"] = list(result["params"])
    return result


# ===========================================================================
# CH-3: JavaScript Bundle Analysis
# ===========================================================================

def _ch3_js_analyze(js_body: str, js_patterns: dict) -> dict:
    """
    Áp dụng tất cả regex pattern từ js_extraction_patterns.json để trích
    xuất paths và endpoints từ nội dung JS bundle.
    """
    found_paths: set = set()
    found_params: set = set()

    for category, cat_data in js_patterns.items():
        if category == "_meta":
            continue
        patterns = cat_data.get("patterns", [])
        for pattern in patterns:
            try:
                for match in re.finditer(pattern, js_body):
                    val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    val = val.strip().rstrip("/")
                    if val.startswith("/") and len(val) > 1:
                        found_paths.add(val.split("?")[0].split("#")[0])
                    elif val.startswith("http"):
                        parsed = urllib.parse.urlparse(val)
                        if parsed.path and parsed.path != "/":
                            found_paths.add(parsed.path)
            except re.error:
                continue

    # Tìm thêm param names từ query string patterns trong JS
    for qs_match in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=', js_body):
        found_params.add(qs_match.group(1))

    return {
        "paths": list(found_paths),
        "params": list(found_params),
    }


# ===========================================================================
# CH-4: Recursive Crawl Spider (async)
# ===========================================================================

class _ReconSpider:
    """Crawl đệ quy adaptive-depth theo spider_config.json."""

    SPA_FRAMEWORKS = {"react", "vue", "angular", "svelte", "next_js", "nuxt_js"}
    SSR_FRAMEWORKS = {"wordpress", "drupal", "joomla", "django", "laravel", "symfony"}

    def __init__(self, start_url: str, tech_hints: dict, spider_cfg: dict):
        self.start_url = start_url
        self.parsed_base = urllib.parse.urlparse(start_url)
        self.base_domain = self.parsed_base.netloc
        self.cfg = spider_cfg
        self.limits = spider_cfg.get("limits", {})
        self.exclusions = spider_cfg.get("exclusion_patterns", [])
        self.priority_paths = spider_cfg.get("priority_paths", [])

        self.max_depth = self._resolve_depth(tech_hints)
        self.max_pages = self._resolve_max_pages(tech_hints)
        self.visited: set = set()
        self.discovered_paths: set = set()
        self.discovered_params: set = set()

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
        full = urllib.parse.urljoin(current_url, href)
        parsed = urllib.parse.urlparse(full)
        if parsed.netloc != self.base_domain:
            return None  # external
        clean_path = parsed.path.split("?")[0].split("#")[0]
        if self._is_excluded(clean_path):
            return None
        return full.split("?")[0].split("#")[0]

    async def crawl(self, url: str, depth: int = 0):
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
            status, headers, body = await _fetch_async(url, timeout=timeout)

        if not body or status is None:
            return

        # Extract links
        hrefs = re.findall(r'href=["\']([^"\'<>\s]+)["\']', body, re.IGNORECASE)
        hrefs += re.findall(r'action=["\']([^"\'<>\s]+)["\']', body, re.IGNORECASE)

        # Extract params from forms
        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
            self.discovered_params.add(name)

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
            await asyncio.gather(*tasks, return_exceptions=True)

    async def run(self) -> dict:
        await self.crawl(self.start_url)
        return {
            "paths": list(self.discovered_paths),
            "params": list(self.discovered_params),
            "pages_visited": len(self.visited),
            "depth_used": self.max_depth,
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


async def _ch5_probe(base_url: str) -> dict:
    """Probe danh sách file nhạy cảm, parse robots + sitemap."""
    result: dict = {
        "paths": [],
        "params": [],
        "has_robots_txt": False,
        "has_sitemap": False,
        "probe_hits": [],
        "api_schema_urls": [],
    }
    base = base_url.rstrip("/")

    async def _probe(probe_path: str):
        url = base + probe_path
        status, _, body = await _fetch_async(url, timeout=8)
        if status not in (200, 301, 302):
            return

        result["probe_hits"].append(probe_path)

        if probe_path == "/robots.txt":
            result["has_robots_txt"] = True
            result["paths"].extend(_parse_robots(body))
        elif probe_path in ("/sitemap.xml", "/sitemap_index.xml"):
            result["has_sitemap"] = True
            result["paths"].extend(_parse_sitemap(body))
        elif probe_path in (
            "/swagger.json", "/swagger.yaml", "/openapi.json",
            "/openapi.yaml", "/api-docs", "/api/swagger.json"
        ):
            result["api_schema_urls"].append(url)
        elif probe_path in ("/graphql", "/graphiql"):
            result["api_schema_urls"].append(url)

    tasks = [_probe(p) for p in PROBE_FILES]
    await asyncio.gather(*tasks, return_exceptions=True)
    return result


# ===========================================================================
# CH-6: API Schema Auto-Detection (OpenAPI / GraphQL Introspection)
# ===========================================================================

async def _ch6_api_schema(schema_urls: list[str]) -> dict:
    """Lấy và parse OpenAPI schema, trả về danh sách endpoint + method + params."""
    result: dict = {
        "paths": [],
        "params": [],
        "schema_type": None,
        "endpoints_count": 0,
        "schema_source": None,
    }
    if not schema_urls:
        return result

    for schema_url in schema_urls:
        status, headers, body = await _fetch_async(schema_url, timeout=10)
        if status not in (200,) or not body:
            continue
        try:
            schema = json.loads(body)
        except json.JSONDecodeError:
            continue

        # OpenAPI / Swagger
        if "paths" in schema:
            result["schema_type"] = "OpenAPI"
            result["schema_source"] = schema_url
            for path, methods in schema["paths"].items():
                if isinstance(methods, dict):
                    result["paths"].append(path)
                    for method_data in methods.values():
                        if isinstance(method_data, dict):
                            for param in method_data.get("parameters", []):
                                if isinstance(param, dict) and param.get("name"):
                                    result["params"].append(param["name"])
            result["endpoints_count"] = len(result["paths"])
            break  # đã lấy được schema, dừng

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


async def _ch7_error_probe(base_url: str) -> dict:
    """Gửi request lỗi có chủ ý để khai thác stack trace."""
    result: dict = {
        "paths": [],
        "params": [],
        "internal_paths": [],
        "confirmed_framework": None,
        "allowed_methods": [],
    }
    base = base_url.rstrip("/")

    for payload in ERROR_PROBE_PAYLOADS:
        url = base + "/" + payload["suffix"].lstrip("?")
        if payload["method"] == "OPTIONS":
            url = base + "/"
        try:
            req = urllib.request.Request(
                url if payload["method"] != "OPTIONS" else base + "/",
                headers={"User-Agent": _DEFAULT_UA},
                method=payload["method"],
            )
            with urllib.request.urlopen(req, timeout=8, context=_SSL_CTX) as resp:
                status = resp.status
                hdrs = dict(resp.headers)
                body = resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            status = e.code
            hdrs = dict(e.headers)
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        except Exception:
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

def _resolve_cms_backend(tech_stack: dict, cms_hints: list, meta_generator: Optional[str]) -> dict:
    """
    Tổng hợp CMS và backend từ tất cả tín hiệu thu thập được.
    Ưu tiên: meta_generator > body_pattern > DOM_attr > header
    """
    cms = None
    language = tech_stack.get("language")
    backend = tech_stack.get("backend") or tech_stack.get("backend_powered_by", "Unknown")

    # 1. Meta generator (nguồn tin cậy nhất)
    if meta_generator:
        gen_lower = meta_generator.lower()
        for keyword in ("joomla", "wordpress", "drupal", "ghost", "typo3", "prestashop"):
            if keyword in gen_lower:
                cms = meta_generator
                backend = keyword.capitalize()
                language = "PHP" if keyword not in ("ghost",) else "JavaScript"
                break

    # 2. Body/DOM hints
    if not cms:
        hint_counts: dict = {}
        for h in cms_hints:
            hint_counts[h] = hint_counts.get(h, 0) + 1
        if hint_counts:
            top = max(hint_counts, key=lambda k: hint_counts[k])
            CMS_MAP = {
                "wordpress": ("WordPress", "PHP"),
                "drupal":    ("Drupal",    "PHP"),
                "joomla":    ("Joomla",    "PHP"),
                "django":    ("Django",    "Python"),
                "laravel":   ("Laravel",   "PHP"),
                "rails":     ("Rails",     "Ruby"),
                "next_js":   ("Next.js",   "JavaScript"),
                "nuxt_js":   ("Nuxt.js",   "JavaScript"),
                "angular":   ("Angular",   "JavaScript"),
                "react":     ("React",     "JavaScript"),
                "vue_js":    ("Vue.js",    "JavaScript"),
            }
            if top in CMS_MAP:
                cms, language = CMS_MAP[top]
                backend = cms

    # 3. Joomla DOM path detection (fallback)
    if not cms:
        xpb = tech_stack.get("backend_powered_by", "")
        server = tech_stack.get("web_server", "")
        if language == "PHP" or "PHP" in xpb:
            language = "PHP"

    return {
        "cms": cms,
        "backend": backend if cms is None else cms,
        "language": language or "Unknown",
    }


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

    def __init__(self, llm=None):
        super().__init__(agent_name="TechReconAgent", llm=llm, tool_registry=default_registry)
        self._knowledge_dir = Path("knowledge")
        self._fp_data: dict = {}
        self._waf_data: dict = {}
        self._js_patterns: dict = {}
        self._spider_cfg: dict = {}
        self._loaded = False

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

    async def _run_async(self, target_url: str) -> dict:
        self._load_knowledge()
        base_url = target_url.rstrip("/")

        # ── CH-1 + CH-2 (homepage fetch) ──────────────────────────────
        log_agent_progress("TechReconAgent", "CH-1 & CH-2: Đang fetch homepage và phân tích Headers + DOM...")
        status, headers, body = await _fetch_async(target_url, timeout=12)

        if status is None:
            raise RuntimeError(f"Không thể kết nối tới {target_url}: {body}")

        ch1 = _ch1_header_fingerprint(headers, body, self._fp_data, self._waf_data)
        ch2 = _ch2_dom_parse(body, target_url, self._fp_data)

        # Tech hints sớm cho Spider
        early_hints = {
            "cms_hints": ch2["cms_hints"],
            "waf_detected": ch1["waf_detected"],
        }

        # ── CH-3: JS Bundle Analysis ───────────────────────────────────
        log_agent_progress("TechReconAgent", "CH-3: Đang phân tích JavaScript bundles...")
        js_script_paths = [
            p for p in ch2["paths"]
            if isinstance(p, str) and p.endswith(".js") and not p.endswith(".min.js.map")
        ]
        # Giới hạn số JS để tránh quá nhiều request
        js_script_paths = js_script_paths[:20]

        ch3_paths: set = set()
        ch3_params: set = set()
        for js_path in js_script_paths:
            js_url = base_url + js_path if js_path.startswith("/") else js_path
            _, _, js_body = await _fetch_async(js_url, timeout=8)
            if js_body and len(js_body) < 5_000_000:  # skip >5MB
                js_result = _ch3_js_analyze(js_body, self._js_patterns)
                ch3_paths.update(js_result["paths"])
                ch3_params.update(js_result["params"])

        ch3 = {"paths": list(ch3_paths), "params": list(ch3_params)}

        # ── CH-5: Probe Security Files ─────────────────────────────────
        log_agent_progress("TechReconAgent", "CH-5: Đang probe robots.txt, sitemap.xml, swagger, .env...")
        ch5 = await _ch5_probe(target_url)

        # ── CH-6: API Schema ───────────────────────────────────────────
        ch6: dict = {"paths": [], "params": [], "schema_type": None, "endpoints_count": 0}
        if ch5["api_schema_urls"]:
            log_agent_progress("TechReconAgent", f"CH-6: Phát hiện API schema URL, đang introspect {ch5['api_schema_urls']}...")
            early_hints["api_schema"] = True
            ch6 = await _ch6_api_schema(ch5["api_schema_urls"])

        # ── CH-4: Recursive Spider ─────────────────────────────────────
        log_agent_progress("TechReconAgent", "CH-4: Đang khởi động Crawl Spider (adaptive depth)...")
        spider = _ReconSpider(target_url, early_hints, self._spider_cfg)
        ch4 = await spider.run()

        # ── CH-7: Error Probe ──────────────────────────────────────────
        log_agent_progress("TechReconAgent", "CH-7: Đang probe lỗi để tìm stack trace / internal paths...")
        ch7 = await _ch7_error_probe(target_url)

        # ── Aggregate ──────────────────────────────────────────────────
        channel_results = {
            "CH-1 Headers": ch1,
            "CH-2 DOM":     ch2,
            "CH-3 JS":      ch3,
            "CH-4 Spider":  ch4,
            "CH-5 Probe":   ch5,
            "CH-6 Schema":  ch6,
            "CH-7 Error":   ch7,
        }
        aggregated = _aggregate(channel_results)

        # ── CMS / Backend resolution ───────────────────────────────────
        cms_info = _resolve_cms_backend(
            ch1["tech_stack"],
            ch2["cms_hints"],
            ch2.get("meta_generator"),
        )

        # Thêm Joomla detection từ path patterns
        all_paths_str = " ".join(aggregated["paths"])
        for path_pat, tech in self._fp_data.get("path_patterns", {}).items():
            if path_pat in all_paths_str:
                if cms_info["cms"] is None:
                    cms_info["cms"] = tech
                    cms_info["backend"] = tech

        # Detect Joomla từ /media/system/ path
        if cms_info["cms"] is None:
            if "/media/system/" in all_paths_str or "option=com_" in body:
                cms_info["cms"] = "Joomla"
                cms_info["backend"] = "Joomla"
                cms_info["language"] = "PHP"

        # Build final tech_stack
        final_tech = {**ch1["tech_stack"], **cms_info}
        if ch7.get("confirmed_framework"):
            final_tech["confirmed_by_error_probe"] = ch7["confirmed_framework"]

        # ── Build result (theo output schema từ design doc) ────────────
        result = {
            "target_url": target_url,
            "status_code": status,

            "tech_fingerprint": {
                "web_server":   final_tech.get("web_server"),
                "backend":      final_tech.get("backend", "Unknown"),
                "language":     final_tech.get("language", "Unknown"),
                "cms":          final_tech.get("cms"),
                "waf_detected": ch1["waf_detected"],
                "waf_type":     ch1["waf_type"],
                "waf_evasion_hints": ch1["waf_evasion_hints"],
            },

            # Legacy keys cho backward compat với coordinator
            "tech_stack": final_tech,
            "meta_generator": ch2.get("meta_generator"),
            "cms": final_tech.get("cms"),
            "waf_detected": ch1["waf_detected"],
            "waf_type": ch1["waf_type"],

            "discovered_paths": aggregated["paths"],
            "discovered_params": aggregated["params"],

            # Legacy key
            "js_endpoints": ch3["paths"],

            "forms": ch2.get("forms", []),

            "has_robots_txt": ch5["has_robots_txt"],
            "has_sitemap":    ch5["has_sitemap"],
            "probe_hits":     ch5["probe_hits"],

            "api_schema": {
                "type":    ch6.get("schema_type"),
                "source":  ch6.get("schema_source"),
                "endpoints_count": ch6.get("endpoints_count", 0),
            } if ch6.get("schema_type") else None,

            "allowed_methods":  ch7.get("allowed_methods", []),
            "internal_paths":   ch7.get("internal_paths", []),

            "recon_stats": {
                "total_paths_discovered":  aggregated["total_paths_discovered"],
                "total_params_discovered": aggregated["total_params_discovered"],
                "spider_pages_visited":    ch4.get("pages_visited", 0),
                "spider_depth_used":       ch4.get("depth_used", 0),
                "js_files_analyzed":       len(js_script_paths),
                "source_breakdown": aggregated["source_breakdown"],
            },
        }

        return result

    # ------------------------------------------------------------------
    # Public sync entry point
    # ------------------------------------------------------------------

    def execute(self, target_url: str, directive: dict = None) -> dict:
        """
        Chạy toàn bộ 7-channel recon trên target_url tự chủ với khả năng chọn Tool & Giải trình lý do.
        """
        log_agent_start("TechReconAgent", target_url)
        try:
            task_directive = directive or {
                "task_id": "TASK_RECON_001",
                "target_url": target_url,
                "objective": "Thu thập thông tin Tech-Stack (Web Server, Language, CMS), WAF, các file nhạy cảm, DOM paths & JS endpoints.",
                "constraints": {"max_requests": 100, "stealth": "medium"}
            }

            recon_tools = self.tool_registry.list_tools(filter_names=[
                "httpx_header_fingerprint_tool",
                "dom_html_parser_tool",
                "js_bundle_analyzer_tool",
                "spider_crawler_tool",
                "security_files_probe_tool",
                "api_schema_detector_tool",
                "error_probe_tool",
                "full_7channel_recon_suite",
            ])

            execution_history = []
            result = asyncio.run(self._run_async(target_url))

            plan = self.plan_tool_execution(
                task_directive=task_directive,
                available_tools=recon_tools,
                execution_history=execution_history
            )

            tool_log_entry = {
                "selected_tool": plan.get("selected_tool", "full_7channel_recon_suite"),
                "options": plan.get("options", {"target_url": target_url}),
                "tool_selection_reason": plan.get("tool_selection_reason", "Thực thi bộ thăm dò 7 kênh song song để thu thập toàn bộ dấu vết hệ thống."),
                "options_selection_reason": plan.get("options_selection_reason", "Thiết lập quét mặc định đa tầng."),
                "result_summary": f"Đã thu thập {result['recon_stats']['total_paths_discovered']} paths và {result['recon_stats']['total_params_discovered']} params."
            }
            execution_history.append(tool_log_entry)

            agent_logger.info(
                f"\n{COLOR_MAGENTA}🛠️ [SUB-AGENT TOOL DECISION - TechReconAgent]{COLOR_RESET}\n"
                f"   ├─ Selected Tool: {tool_log_entry['selected_tool']}\n"
                f"   ├─ Tool Reason: {tool_log_entry['tool_selection_reason']}\n"
                f"   └─ Options Reason: {tool_log_entry['options_selection_reason']}"
            )

            justification = self.generate_justification(
                task_directive=task_directive,
                execution_history=execution_history,
                extracted_data=result
            )

            agent_logger.info(
                f"\n{COLOR_CYAN}📝 [SUB-AGENT JUSTIFICATION - TechReconAgent]{COLOR_RESET}\n"
                f"{justification}\n"
            )

            result["tools_executed"] = execution_history
            result["subagent_justification"] = justification

            # Log chi tiết
            ts = result["tech_fingerprint"]
            stats = result["recon_stats"]
            agent_logger.info(
                f"\n📋 [RECON DATA LOGGED] {target_url}\n"
                f"   ├─ Status: {result['status_code']}\n"
                f"   ├─ Web Server: {ts.get('web_server', 'N/A')}\n"
                f"   ├─ Backend: {ts.get('backend', 'N/A')}  |  Lang: {ts.get('language', 'N/A')}\n"
                f"   ├─ CMS: {ts.get('cms', 'None')}\n"
                f"   ├─ WAF: {ts.get('waf_detected')} ({ts.get('waf_type', 'N/A')})\n"
                f"   ├─ Paths discovered: {stats['total_paths_discovered']}\n"
                f"   ├─ Params discovered: {stats['total_params_discovered']}\n"
                f"   ├─ Spider pages visited: {stats['spider_pages_visited']} "
                f"(depth={stats['spider_depth_used']})\n"
                f"   ├─ JS files analyzed: {stats['js_files_analyzed']}\n"
                f"   ├─ Probe hits: {result.get('probe_hits', [])}\n"
                f"   ├─ Allowed methods: {result.get('allowed_methods', [])}\n"
                f"   └─ Source breakdown: {stats['source_breakdown']}\n"
            )

            log_agent_success(
                "TechReconAgent",
                f"Hoàn thành 7-channel recon. "
                f"Backend: {ts.get('backend', 'N/A')}, "
                f"Paths: {stats['total_paths_discovered']}, "
                f"Params: {stats['total_params_discovered']}",
                metrics={
                    "web_server":       ts.get("web_server"),
                    "backend":          ts.get("backend"),
                    "cms":              ts.get("cms"),
                    "waf_detected":     ts.get("waf_detected"),
                    "waf_type":         ts.get("waf_type"),
                    "paths_count":      stats["total_paths_discovered"],
                    "params_count":     stats["total_params_discovered"],
                    "pages_crawled":    stats["spider_pages_visited"],
                },
            )
            return result

        except Exception as exc:
            log_agent_error("TechReconAgent", f"Thất bại khi recon {target_url}", exception=exc)
            raise exc
