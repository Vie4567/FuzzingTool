"""
src/agents/tech_recon.py — Tech-Stack & Context Analyzer (Agent 1).

Thay thế stub bằng implementation đầy đủ theo Sentinel_Pentest_Design.md.

Pipeline 2 Stage:

STAGE A (asyncio.gather — song song):
  CH-1  HTTP Header & Cookie Fingerprinting
  CH-2  DOM Parser & HTML Anchor Extraction
  CH-3  JavaScript Bundle Analysis
  CH-5  Recon Probe Files (robots/sitemap/openapi...)
  CH-6  API Schema Detection (OpenAPI/GraphQL)
  CH-7  Error Probe (chỉ khi aggressive_probe=True)

STAGE B (sau Stage A, depth phụ thuộc kết quả CH-6):
  CH-4  Recursive Crawl Spider

Output contract (tương thích run_tech_recon() hiện tại):
    {
        "tech_stack": {...},
        "discovered_paths": [...],
        "js_endpoints": [...],
        "waf_detected": bool,
        "waf_type": str | None,
    }

Public API: execute(target_url) → dict  (sync wrapper)
Nội bộ:    _execute_async(target_url) → dict
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import random
import re
import time
from contextlib import asynccontextmanager
from http.cookies import SimpleCookie
from collections import Counter, deque
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import httpx
import yaml
from bs4 import BeautifulSoup
from defusedxml import ElementTree

from src.graph_schema import endpoint_uid, normalize_target_url, scoped_uid

logger = logging.getLogger(__name__)

# ─── Knowledge paths ─────────────────────────────────────────────────────────
_KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"


def _load_json(name: str) -> dict:
    path = _KNOWLEDGE_DIR / name
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[TechRecon] Cannot load {name}: {e}")
        return {}


# ─── Recon probe files from Design ──────────────────────────────────────────
RECON_PROBE_FILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/graphiql",
    "/package.json",
    "/composer.json",
    "/Gemfile",
    "/.git/config",
    "/.env",
]

# ─── Error probe payloads from Design ────────────────────────────────────────
ERROR_PROBE_PAYLOADS = [
    {"method": "GET",     "suffix": "?id=SENTINEL_PROBE"},
    {"method": "POST",    "suffix": "/",  "body": "INVALID{{{"},
    {"method": "OPTIONS", "suffix": "/"},
    {"method": "TRACE",   "suffix": "/"},
]

HTML_EXTRACTION_SELECTORS = [
    "a[href]", "form[action]", "form input[name]", "form select[name]",
    "button[formaction]", "script[src]", "link[href]", "[data-url]",
    "[data-api]", "[action]",
]
GRAPHQL_INTROSPECTION = """query SentinelRecon { __schema {
    queryType { name fields { name args { name } } }
    mutationType { name fields { name args { name } } }
} }"""

# ═════════════════════════════════════════════════════════════════════════════
class TechReconAgent:
    """
    Tech-Stack & Context Analyzer — Agent 1.

    Args:
        config: Optional dict override (timeout_s, user_agent, aggressive_probe, ...)
        llm_limiter: LLMCallLimiter instance (nếu None, LLM sẽ không được gọi)
        http_client: Inject httpx.AsyncClient (chủ yếu để test)
    """

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        config: dict | None = None,
        llm_limiter=None,
        http_client: httpx.AsyncClient | None = None,
        mcp_client=None,
        mcp_client_factory=None,
    ):
        self.config = config or {}
        self.llm_limiter = llm_limiter
        self._injected_client = http_client
        self._mcp_client = mcp_client
        self._mcp_client_factory = mcp_client_factory

        # Knowledge (load once at init)
        self._tech_fp    = _load_json("tech_fingerprints.json")
        self._waf_sigs   = _load_json("waf_signatures.json")
        self._js_pats    = _load_json("js_extraction_patterns.json")
        self._spider_cfg = _load_json("spider_config.json")
        self._framework_paths = _load_json("framework_paths.json")
        self._sensitive_files = _load_json("sensitive_files.json")
        self._http_loop = None
        self._last_target_profile = {}
        self.persistence_status = "not_requested"

        # Build flat regex list from js_extraction_patterns.json
        self._js_regexes: list[re.Pattern] = []
        for group_key, group_val in self._js_pats.items():
            if group_key == "_meta":
                continue
            for pat in group_val.get("patterns", []):
                try:
                    self._js_regexes.append(re.compile(pat))
                except re.error as e:
                    logger.warning(f"[CH-3] Invalid regex '{pat}': {e}")

    # ─── Public sync API (backward-compatible) ────────────────────────────────

    def execute(self, target_url: str) -> dict:
        """
        Sync entry point — tương thích với run_tech_recon() trong graph.py.

        Internally delegates to _execute_async().
        Handles the "already in running event loop" case gracefully.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Chạy async core trong thread với event loop riêng.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self._run_in_new_loop, target_url)
                return future.result()
        else:
            return asyncio.run(self._execute_async(target_url))

    def _run_in_new_loop(self, target_url: str) -> dict:
        """Chạy trong thread riêng với event loop mới — tránh nested asyncio.run()."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._execute_async(target_url))
        finally:
            loop.close()

    # ─── Async core ──────────────────────────────────────────────────────────

    async def _execute_async(self, target_url: str) -> dict:
        """Điều phối toàn bộ 7-channel pipeline."""
        normalize_target_url(target_url)
        if not isinstance(self.config.get("aggressive_probe", False), bool):
            raise ValueError("aggressive_probe must be a boolean")
        start_time = time.monotonic()
        limits      = self._spider_cfg.get("limits", {})
        timeout_s   = self.config.get(
            "request_timeout_ms", limits.get("request_timeout_ms", 8000)
        ) / 1000
        ua          = self.config.get("user_agent", self.DEFAULT_USER_AGENT)
        aggressive  = self.config.get("aggressive_probe", False)

        client_kwargs = dict(
            timeout=httpx.Timeout(timeout_s, connect=5.0),
            headers={"User-Agent": ua},
            follow_redirects=False,
            max_redirects=5,
        )
        if self._injected_client:
            client = self._injected_client
            own_client = False
        else:
            client = httpx.AsyncClient(**client_kwargs)
            own_client = True

        try:
            result = await self._run_pipeline(client, target_url, aggressive, start_time)
            await self._persist_profile_best_effort(target_url)
            return result
        finally:
            if own_client:
                await client.aclose()


    @property
    def target_profile(self) -> dict:
        return self._last_target_profile

    async def execute_async(self, target_url: str) -> dict:
        return await self._execute_async(target_url)

    def _limit(self, name):
        return self.config.get(name, self._spider_cfg["limits"][name])

    def _reset_http_state(self, target_url):
        self._target_url = target_url
        self._http_loop = asyncio.get_running_loop()
        self._request_semaphore = asyncio.Semaphore(max(1, int(self._limit("concurrent_requests"))))
        self._pace_lock = asyncio.Lock()
        self._next_request_at = 0.0
        self._get_cache, self._get_locks, self._observations = {}, {}, {}
        self._request_count = self._response_count = self._blocked_count = 0

    @staticmethod
    def _same_origin(left, right):
        def origin(value):
            p = urlparse(value)
            if p.scheme not in {"http", "https"} or p.username or p.password:
                return None
            return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)
        try:
            return origin(left) is not None and origin(left) == origin(right)
        except ValueError:
            return False

    async def _request(self, client, method, url, **kwargs):
        if self._http_loop is not asyncio.get_running_loop():
            self._reset_http_state(url)
        method = method.upper()
        if not self._same_origin(url, self._target_url):
            raise ValueError("Request outside target origin")
        key = (method, url)
        # The homepage and schema responses are shared across channels.
        if method == "GET" and not kwargs:
            async with self._get_locks.setdefault(key, asyncio.Lock()):
                if key not in self._get_cache:
                    self._get_cache[key] = await self._send_request(client, method, url)
                return self._get_cache[key]
        return await self._send_request(client, method, url, **kwargs)

    async def _send_request(self, client, method, url, **kwargs):
        for redirect_count in range(6):
            if not self._same_origin(url, self._target_url):
                raise ValueError("Redirect outside target origin")
            async with self._request_semaphore:
                async with self._pace_lock:
                    while (remaining := self._next_request_at - time.perf_counter()) > 0:
                        await asyncio.sleep(remaining)
                    delay = max(0, self._limit("request_delay_ms"))
                    jitter = random.uniform(0, max(0, self._limit("request_jitter_ms")))
                    self._next_request_at = time.perf_counter() + (delay + jitter) / 1000
                self._request_count += 1
                resp = await client.request(method, url, follow_redirects=False, **kwargs)
                self._response_count += 1
                self._blocked_count += resp.status_code in {403, 429}
                if len(resp.content) > self._limit("max_response_bytes"):
                    raise ValueError("Response exceeds max_response_bytes")
                path = self._normalize_path(str(resp.url), self._target_url)
                if path:
                    self._observations[(path, method)] = resp.status_code
            if resp.status_code not in {301, 302, 303, 307, 308} or "location" not in resp.headers:
                return resp
            if redirect_count == 5:
                raise ValueError("Too many redirects")
            url = urljoin(str(resp.url), resp.headers["location"])
            if resp.status_code == 303 or (resp.status_code in {301, 302} and method == "POST"):
                method, kwargs = "GET", {}

    @staticmethod
    def _channel_data(value):
        if isinstance(value, BaseException):
            return {"paths": [], "params": [], "error": str(value)}
        return value

    async def _run_pipeline(self, client, target_url, aggressive, start_time):
        self._reset_http_state(target_url)
        self._last_target_profile = {}
        channels = {
            "ch6": self._ch6_api_schema, "ch1": self._ch1_headers,
            "ch2": self._ch2_dom, "ch3": self._ch3_js, "ch5": self._ch5_probe,
        }
        if aggressive:
            channels["ch7"] = self._ch7_error_probe
        tasks = {key: asyncio.create_task(fn(client, target_url)) for key, fn in channels.items()}

        async def adaptive_spider():
            dependencies = ("ch1", "ch2", "ch6")
            results = await asyncio.gather(*(tasks[key] for key in dependencies), return_exceptions=True)
            preliminary = self._build_preliminary_profile(
                {key: self._channel_data(value) for key, value in zip(dependencies, results)}, target_url
            )
            self._preliminary_profile = preliminary
            return await self._ch4_spider(
                client, target_url, self._resolve_depth(preliminary, self._spider_cfg["limits"])
            )

        tasks["ch4"] = asyncio.create_task(adaptive_spider())
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        channels = {key: self._channel_data(value) for key, value in zip(tasks, results)}
        for key, value in channels.items():
            if value.get("error"):
                logger.warning("%s failed: %s", key, value["error"])
        if not aggressive:
            channels["ch7"] = {"paths": [], "params": [], "skipped": True}
        preliminary = self._build_preliminary_profile(channels, target_url)
        return self._aggregate_output(channels, preliminary, target_url, time.monotonic() - start_time)


    async def _persist_profile_best_effort(self, target_url):
        self.persistence_status = "not_requested"
        if self._mcp_client is None and self._mcp_client_factory is None:
            return
        try:
            async with asyncio.timeout(self.config.get("mcp_timeout_s", 60)):
                async with self._mcp_session() as client:
                    await self._persist_profile(client, target_url)
            self.persistence_status = "success"
        except Exception as exc:
            self.persistence_status = "failed"
            logger.warning("MCP persistence unavailable; recon result retained: %s", exc)

    @asynccontextmanager
    async def _mcp_session(self):
        resource = self._mcp_client_factory() if self._mcp_client_factory else self._mcp_client
        if inspect.isawaitable(resource):
            resource = await resource
        if hasattr(resource, "__aenter__"):
            async with resource as client:
                yield client
        else:
            yield resource

    async def _persist_profile(self, client, target_url):
        target_url = normalize_target_url(target_url)
        profile = self._last_target_profile
        await client.create_node("Target", {"url": target_url})
        for field in ("web_server", "backend", "frontend", "cms", "language", "waf_type"):
            name = profile.get("tech_fingerprint", {}).get(field)
            if name:
                await client.create_node("Technology", {"name": name, "category": "waf" if field == "waf_type" else field})
                await client.create_relationship("Target", {"url": target_url}, "USES", "Technology", {"name": name})
        for endpoint in self._profile_endpoints(profile, target_url):
            props = {"path": endpoint["path"], "method": endpoint["method"], "_target_url": target_url}
            if "status_code" in endpoint:
                props["status_code"] = endpoint["status_code"]
            uid = endpoint_uid(target_url, endpoint["method"], endpoint["path"])
            await client.create_node("Endpoint", props)
            await client.create_relationship("Target", {"url": target_url}, "HAS_ENDPOINT", "Endpoint", {"_uid": uid})
            for parameter in endpoint["parameters"]:
                props = {**parameter, "_endpoint_uid": uid}
                await client.create_node("Parameter", props)
                await client.create_relationship("Endpoint", {"_uid": uid}, "HAS_PARAM", "Parameter",
                                                 {"_uid": scoped_uid("Parameter", props)})

    def _profile_endpoints(self, profile, target_url):
        records = {}
        def add(path, method="GET", parameters=(), status=None):
            path = self._normalize_path(path, target_url)
            if not path:
                return
            method = method.upper()
            record = records.setdefault((path, method), {"path": path, "method": method, "parameters": {}})
            if status is not None:
                record["status_code"] = status
            for parameter in parameters:
                if isinstance(parameter, str):
                    parameter = {"name": parameter, "location": "unknown"}
                if parameter.get("name"):
                    location = parameter.get("location", "unknown")
                    record["parameters"][(parameter["name"], location)] = {"name": parameter["name"], "location": location}
        schema = profile.get("api_schema") or {}
        for ep in schema.get("endpoints", []) + profile.get("endpoints", []):
            add(ep["path"], ep.get("method", "GET"), ep.get("parameter_details", ep.get("params", [])))
        for form in profile.get("forms", []):
            method = form.get("method", "GET").upper()
            add(form.get("action") or target_url, method,
                [{"name": name, "location": "query" if method == "GET" else "form"} for name in form.get("params", [])])
        for ep in profile.get("observed_endpoints", []):
            add(ep["path"], ep["method"], status=ep.get("status_code"))
        known_paths = {path for path, _ in records}
        for path in profile.get("discovered_paths", []):
            if self._normalize_path(path, target_url) not in known_paths:
                add(path)
        return [{**record, "parameters": list(record["parameters"].values())} for _, record in sorted(records.items())]

    # ─── CH-1: HTTP Header & Cookie Fingerprinting ───────────────────────────

    async def _ch1_headers(self, client: httpx.AsyncClient, url: str) -> dict:
        """CH-1: Phân tích headers, cookies, WAF."""
        result: dict[str, Any] = {
            "paths": [], "params": [],
            "tech_fingerprint": {},
            "waf": {"detected": False, "type": None, "evasion_hints": []},
            "raw_headers": {},
            "source": "CH-1 Headers",
        }
        try:
            resp = await self._request(client, "GET", url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            result["raw_headers"] = dict(resp.headers)

            fp: dict[str, str] = {}

            # ── Match header fingerprints ──
            header_fp = self._tech_fp.get("headers", {})
            for hdr_name, tech_map in header_fp.items():
                val = headers_lower.get(hdr_name.lower(), "")
                if not val:
                    continue
                for tech_key, patterns in tech_map.items():
                    for pat in patterns:
                        if pat == "*" or pat.lower() in val.lower():
                            fp[tech_key] = val
                            break

            # ── Cookie fingerprints ──
            cookies = SimpleCookie()
            for value in resp.headers.get_list("set-cookie"):
                cookies.load(value)
            cookie_names = {name.lower() for name in cookies}
            for cookie_name, tech_key in self._tech_fp.get("cookies", {}).items():
                if cookie_name.lower() in cookie_names:
                    fp[tech_key] = cookie_name

            # ── WAF detection ──
            body_text = ""
            try:
                body_text = resp.text[:4096]
            except Exception:
                pass

            waf_sigs = {k: v for k, v in self._waf_sigs.items() if k != "_meta"}
            for waf_key, sig in waf_sigs.items():
                matched = False
                # Check headers
                for hdr in sig.get("headers", []):
                    if hdr.lower() == "server" and sig.get("server_values"):
                        continue
                    if hdr.lower() in headers_lower:
                        matched = True
                        break
                # Check server value
                if not matched:
                    server_val = headers_lower.get("server", "").lower()
                    for sv in sig.get("server_values", []):
                        if sv.lower() in server_val:
                            matched = True
                            break
                # Check cookies
                if not matched:
                    cookie_str = headers_lower.get("set-cookie", "").lower()
                    for ck in sig.get("cookies", []):
                        if any(name.startswith(ck.lower()) for name in cookie_names):
                            matched = True
                            break
                # Check body patterns
                if not matched:
                    for bp in sig.get("body_patterns", []):
                        if bp.lower() in body_text.lower():
                            matched = True
                            break

                if matched:
                    result["waf"]["detected"] = True
                    result["waf"]["type"] = sig.get("label", waf_key)
                    result["waf"]["evasion_hints"] = sig.get("evasion_hints", [])
                    break

            # ── Parse Link header for API hints ──
            link_hdr = headers_lower.get("link", "")
            if link_hdr:
                for part in link_hdr.split(","):
                    m = re.search(r'<([^>]+)>', part)
                    if m:
                        result["paths"].append(m.group(1))

            result["tech_fingerprint"] = fp

        except Exception as e:
            logger.warning(f"[CH-1] Error fetching {url}: {e}")
            result["error"] = str(e)

        return result

    # ─── CH-2: DOM Parser ────────────────────────────────────────────────────


    def _parse_dom(self, html, document_url):
        soup = BeautifulSoup(html, "html.parser")
        base_tag = soup.find("base", href=True)
        base = urljoin(document_url, base_tag["href"]) if base_tag else document_url
        paths, params, forms, endpoints = set(), set(), [], []
        for selector in HTML_EXTRACTION_SELECTORS:
            for tag in soup.select(selector):
                for attr in ("href", "src", "action", "formaction", "data-url", "data-api"):
                    raw = tag.get(attr)
                    if not raw:
                        continue
                    absolute = urljoin(base, raw)
                    path = self._normalize_path(absolute, document_url)
                    if not path:
                        continue
                    paths.add(path)
                    details = [{"name": name, "location": "query"}
                               for name, _ in parse_qsl(urlparse(absolute).query, keep_blank_values=True)]
                    params.update(p["name"] for p in details)
                    if details and attr not in {"action", "formaction"}:
                        endpoints.append({"path": path, "method": "GET", "parameter_details": details})
        for form in soup.find_all("form"):
            action = self._normalize_path(urljoin(base, form.get("action") or document_url), document_url)
            if not action:
                continue
            names = sorted({tag["name"] for tag in form.find_all(["input", "select", "textarea"])
                            if tag.get("name")})
            method = form.get("method", "GET").upper()
            if method not in {"GET", "POST"}:
                continue
            forms.append({"action": action, "method": method, "params": names})
            paths.add(action)
            params.update(names)
            for button in form.select("button[formaction], input[formaction]"):
                action = self._normalize_path(urljoin(base, button["formaction"]), document_url)
                button_method = button.get("formmethod", method).upper()
                if action and button_method in {"GET", "POST"}:
                    forms.append({"action": action, "method": button_method, "params": names})
                    paths.add(action)
        hints = {}
        for group in ("dom_attributes", "body_patterns"):
            for signature, tech in self._tech_fp[group].items():
                if signature in html:
                    hints[tech] = signature
        return {"paths": sorted(paths), "params": sorted(params), "forms": forms,
                "endpoints": endpoints, "tech_hints": hints}

    async def _ch2_dom(self, client, url):
        response = await self._request(client, "GET", url)
        return self._parse_dom(response.text, str(response.url))

    # ─── CH-3: JavaScript Bundle Analysis ────────────────────────────────────

    async def _ch3_js(self, client: httpx.AsyncClient, url: str) -> dict:
        """CH-3: Phân tích JS (inline + external) để trích xuất endpoints."""
        result: dict[str, Any] = {
            "paths": [], "params": [],
            "js_endpoints": [],
            "source": "CH-3 JS",
        }
        try:
            resp = await self._request(client, "GET", url)
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            found_paths: set[str] = set()

            # Inline scripts
            for script_tag in soup.find_all("script"):
                if not script_tag.get("src"):
                    js_text = script_tag.get_text()
                    found_paths.update(self._extract_js_paths(js_text))

            # External script files (within same origin)
            parsed_base = urlparse(url)
            base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

            external_scripts = []
            for tag in soup.find_all("script", src=True):
                src = tag["src"].strip()
                abs_src = urljoin(url, src)
                if self._same_origin(abs_src, url):
                    external_scripts.append(abs_src)

            for script_url in sorted(set(external_scripts))[:self._limit("max_external_scripts")]:
                try:
                    js_resp = await self._request(client, "GET", script_url)
                    if js_resp.status_code == 200:
                        found_paths.update(self._extract_js_paths(js_resp.text))
                except Exception as e:
                    logger.debug(f"[CH-3] Cannot fetch {script_url}: {e}")

            result["paths"] = list(found_paths)
            result["js_endpoints"] = list(found_paths)

        except Exception as e:
            logger.warning(f"[CH-3] Error: {e}")
            result["error"] = str(e)

        return result

    def _extract_js_paths(self, js_text: str) -> set[str]:
        """Áp dụng tất cả regex từ js_extraction_patterns.json."""
        found: set[str] = set()
        for pattern in self._js_regexes:
            try:
                matches = pattern.findall(js_text)
                for m in matches:
                    val = m if isinstance(m, str) else (m[0] if m else "")
                    val = val.strip().strip("\"'")
                    # Chỉ giữ paths, không giữ absolute URLs ngoài domain
                    if val and (val.startswith("/") or val.startswith("http")):
                        found.add(val)
            except Exception:
                pass
        return found

    # ─── CH-4: Recursive Crawl Spider ────────────────────────────────────────


    async def _ch4_spider(self, client, start_url, effective_depth):
        profile = getattr(self, "_preliminary_profile", {})
        rendering = self._rendering(profile.get("tech_fingerprint", {}))
        pages_key = f"{rendering}_max_pages" if rendering in {"spa", "ssr"} else "default_max_pages"
        max_pages = self._limit(pages_key)
        exclusions = self._spider_cfg["exclusion_patterns"]
        priority = self._spider_cfg["priority_paths"]
        queue = deque([(start_url, 0)])
        queued, visited, paths = {self._normalize_path(start_url, start_url)}, set(), set()
        forms, params, endpoints = [], set(), []

        async def crawl(url, depth):
            try:
                response = await self._request(client, "GET", url)
                data = self._parse_dom(response.text, str(response.url))
                forms.extend(data["forms"])
                params.update(data["params"])
                endpoints.extend(data["endpoints"])
                paths.add(self._normalize_path(str(response.url), start_url))
                soup = BeautifulSoup(response.text, "html.parser")
                links = [urljoin(str(response.url), tag["href"]) for tag in soup.select("a[href]")]
                links.sort(key=lambda link: not any(part in link for part in priority))
                return [(link, depth + 1) for link in links if self._same_origin(link, start_url)
                        and not any(ex.lower() in link.lower() for ex in exclusions)]
            except Exception as exc:
                logger.debug("Spider request failed: %s", exc)
                return []

        while queue and len(visited) < max_pages:
            batch = []
            allowed_depth = effective_depth
            if self._is_blocking_heavily():
                allowed_depth = min(allowed_depth, self._depth_rule("waf_blocking")["depth"])
            while queue and len(batch) < self._limit("concurrent_requests") and len(visited) < max_pages:
                url, depth = queue.popleft()
                path = self._normalize_path(url, start_url)
                if depth > allowed_depth or path in visited:
                    continue
                visited.add(path)
                paths.add(path)
                batch.append(crawl(url, depth))
            results = await asyncio.gather(*batch, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    for link, depth in result:
                        path = self._normalize_path(link, start_url)
                        if path not in queued:
                            queued.add(path)
                            queue.append((link, depth))
        return {"paths": sorted(p for p in paths if p), "params": sorted(params),
                "forms": forms, "endpoints": endpoints, "crawled_count": len(visited),
                "effective_depth": effective_depth, "max_pages": max_pages}

    # ─── CH-5: Recon Probe Files ─────────────────────────────────────────────


    async def _ch5_probe(self, client, url):
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        result = {"paths": [], "params": [], "probe_hits": [], "robots_paths": [], "sitemap_paths": []}
        async def probe(path):
            response = await self._request(client, "GET", origin + path)
            return response if response.status_code in {200, 204} else None
        responses = await asyncio.gather(*(probe(path) for path in RECON_PROBE_FILES), return_exceptions=True)
        sitemaps = deque()
        for path, response in zip(RECON_PROBE_FILES, responses):
            if not isinstance(response, httpx.Response):
                continue
            if path.endswith((".txt", ".xml", ".json", ".yaml")) or path in {"/.env", "/.git/config", "/Gemfile"}:
                if response.text.lstrip().lower().startswith(("<!doctype html", "<html")):
                    continue
            result["probe_hits"].append(path)
            result["paths"].append(path)
            if path == "/robots.txt":
                for line in response.text.splitlines():
                    directive, sep, value = line.partition(":")
                    value = value.split("#", 1)[0].strip()
                    if sep and directive.strip().lower() in {"allow", "disallow", "sitemap"} and value:
                        absolute = urljoin(origin + "/", value)
                        if self._same_origin(absolute, url):
                            result["robots_paths"].append(value)
                            result["paths"].append(absolute)
                            if directive.strip().lower() == "sitemap":
                                sitemaps.append(absolute)
            if "sitemap" in path:
                sitemaps.append(origin + path)
        visited = set()
        while sitemaps and len(visited) < self._limit("max_sitemaps"):
            sitemap = sitemaps.popleft()
            if sitemap in visited or not self._same_origin(sitemap, url):
                continue
            visited.add(sitemap)
            try:
                response = await self._request(client, "GET", sitemap)
                root = ElementTree.fromstring(response.text)
                is_index = root.tag.rsplit("}", 1)[-1] == "sitemapindex"
                for node in root.iter():
                    if node.tag.rsplit("}", 1)[-1] != "loc" or not node.text:
                        continue
                    absolute = urljoin(sitemap, node.text.strip())
                    if not self._same_origin(absolute, url):
                        continue
                    if is_index:
                        sitemaps.append(absolute)
                    else:
                        result["sitemap_paths"].append(absolute)
                        result["paths"].append(absolute)
            except Exception as exc:
                logger.debug("Invalid/unavailable sitemap: %s", exc)
        return result

    # ─── CH-6: API Schema Detection ──────────────────────────────────────────


    @staticmethod
    def _schema_ref(value, document):
        seen = set()
        while isinstance(value, dict) and "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
                return {}
            seen.add(ref)
            resolved = document
            for part in ref[2:].split("/"):
                resolved = resolved.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(resolved, dict) else {}
            value = resolved
        return value if isinstance(value, dict) else {}

    def _openapi_endpoints(self, document, source_url):
        endpoints = []
        default_base = document.get("basePath", "/")
        for raw_path, path_item in document.get("paths", {}).items():
            item = self._schema_ref(path_item, document)
            for method, operation in item.items():
                if method.lower() not in {"get", "post", "put", "delete", "patch", "options", "head", "trace"}:
                    continue
                details = self._schema_ref(operation, document)
                servers = details.get("servers", item.get("servers", document.get("servers", [])))
                base = default_base
                if servers:
                    spec_server = servers[0]
                    base = spec_server.get("url", "/")
                    for variable, definition in spec_server.get("variables", {}).items():
                        base = base.replace("{" + variable + "}", str(definition.get("default", "")))
                    absolute = urljoin(source_url, base)
                    if not self._same_origin(absolute, source_url):
                        continue
                    base = urlparse(absolute).path
                path = self._normalize_path(base.rstrip("/") + "/" + raw_path.lstrip("/"), source_url)
                if not path:
                    continue
                parameters = {}
                for parameter in item.get("parameters", []) + details.get("parameters", []):
                    parameter = self._schema_ref(parameter, document)
                    if parameter.get("name"):
                        location = parameter.get("in", "unknown")
                        parameters[(parameter["name"], location)] = {"name": parameter["name"], "location": location}
                body = self._schema_ref(details.get("requestBody", {}), document)
                for media, content in body.get("content", {}).items():
                    schema = self._schema_ref(content.get("schema", {}), document)
                    location = "form" if media in {"application/x-www-form-urlencoded", "multipart/form-data"} else "body"
                    for name in schema.get("properties", {}):
                        parameters[(name, location)] = {"name": name, "location": location}
                endpoints.append({"path": path, "method": method.upper(),
                                  "params": sorted({name for name, _ in parameters}),
                                  "parameter_details": list(parameters.values()), "tags": details.get("tags", [])})
        return endpoints

    async def _ch6_api_schema(self, client, url):
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        result = {"paths": [], "params": [], "api_schema": None, "schema_type": None, "endpoints": []}
        candidates = [path for path in RECON_PROBE_FILES if "swagger" in path or "openapi" in path or "api-docs" in path]
        for candidate in candidates:
            try:
                response = await self._request(client, "GET", origin + candidate)
                if response.status_code != 200:
                    continue
                document = yaml.safe_load(response.text)
                if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
                    continue
                if not (document.get("openapi") or document.get("swagger")):
                    continue
                endpoints = self._openapi_endpoints(document, str(response.url))
                result.update(schema_type="openapi", endpoints=endpoints,
                              paths=sorted({ep["path"] for ep in endpoints}),
                              params=sorted({p for ep in endpoints for p in ep["params"]}),
                              api_schema={"type": "OpenAPI", "source": candidate,
                                          "version": document.get("openapi", document.get("swagger")),
                                          "endpoints_count": len(endpoints)})
                return result
            except Exception as exc:
                logger.debug("OpenAPI candidate failed: %s", exc)
        for path in ("/graphql", "/graphiql"):
            try:
                response = await self._request(client, "POST", origin + path, json={"query": GRAPHQL_INTROSPECTION})
                if response.status_code != 200:
                    continue
                schema = response.json().get("data", {}).get("__schema")
                if not isinstance(schema, dict) or not isinstance(schema.get("queryType"), dict):
                    continue
                operations, parameters = [], set()
                for kind in ("queryType", "mutationType"):
                    for field in (schema.get(kind) or {}).get("fields", []):
                        if not isinstance(field, dict) or not field.get("name"):
                            continue
                        args = [arg["name"] for arg in field.get("args", []) if isinstance(arg, dict) and arg.get("name")]
                        operations.append({"type": kind, "name": field["name"], "args": args})
                        parameters.update(args)
                if not operations:
                    continue
                result.update(schema_type="graphql", paths=[path], params=sorted(parameters),
                              endpoints=[{"path": path, "method": "POST", "params": sorted(parameters),
                                          "parameter_details": [{"name": name, "location": "graphql"} for name in sorted(parameters)]}],
                              api_schema={"type": "GraphQL", "source": path, "endpoints_count": 1,
                                          "operations": operations})
                return result
            except Exception as exc:
                logger.debug("GraphQL introspection unavailable: %s", exc)
        return result

    # ─── CH-7: Error Probe ────────────────────────────────────────────────────

    async def _ch7_error_probe(self, client: httpx.AsyncClient, url: str) -> dict:
        """CH-7: Khai thác thông báo lỗi để lộ internal paths (aggressive_probe only)."""
        result: dict[str, Any] = {
            "paths": [], "params": [],
            "findings": [],
            "source": "CH-7 Error Probe",
        }
        if self.config.get("aggressive_probe", False) is not True:
            return result
        for payload in ERROR_PROBE_PAYLOADS:
            try:
                probe_url = url.rstrip("/") + payload["suffix"]
                method = payload["method"]
                body = payload.get("body", "")

                if method == "GET":
                    resp = await self._request(client, "GET", probe_url)
                elif method == "POST":
                    resp = await self._request(client, "POST", probe_url, content=body)
                elif method == "OPTIONS":
                    resp = await self._request(client, "OPTIONS", probe_url)
                elif method == "TRACE":
                    resp = await self._request(client, "TRACE", probe_url)
                else:
                    continue

                text = resp.text[:4096]
                findings: dict[str, Any] = {"method": method}

                # Internal paths in stack trace
                int_paths = re.findall(
                    r'(?:/[\w\-./]+\.(?:java|py|php|js|rb|go))', text
                )
                if int_paths:
                    findings["internal_paths"] = int_paths
                    result["paths"].extend(int_paths)

                for signature, language in self._tech_fp.get("error_signatures", {}).items():
                    if signature in text:
                        findings["confirmed_framework"] = language
                        break

                if len(findings) > 1:
                    result["findings"].append(findings)

            except Exception as e:
                logger.debug(f"[CH-7] Error probe failed: {e}")

        return result

    # ─── Aggregation helpers ──────────────────────────────────────────────────


    def _classify(self, detected, category):
        for key, metadata in self._tech_fp["technologies"].items():
            if key in detected and metadata["category"] == category:
                return metadata["label"]
        return None

    def _metadata_for_profile(self, fingerprint):
        labels = {fingerprint.get(key) for key in ("backend", "frontend", "cms")}
        return [metadata for metadata in self._tech_fp["technologies"].values() if metadata["label"] in labels]

    def _rendering(self, fingerprint):
        types = {metadata.get("rendering") for metadata in self._metadata_for_profile(fingerprint)}
        return "spa" if "spa" in types else "ssr" if "ssr" in types else "default"

    def _build_preliminary_profile(self, ch_results, target_url):
        ch1 = ch_results.get("ch1", {})
        detected = set(ch1.get("tech_fingerprint", {})) | set(ch_results.get("ch2", {}).get("tech_hints", {}))
        waf = ch1.get("waf", {})
        headers = {key.lower(): value for key, value in ch1.get("raw_headers", {}).items()}
        fp = {"web_server": headers.get("server"), "backend": self._classify(detected, "backend"),
              "frontend": self._classify(detected, "frontend"), "cms": self._classify(detected, "cms"),
              "waf_detected": waf.get("detected", False), "waf_type": waf.get("type")}
        fp["language"] = next((meta["language"] for meta in self._metadata_for_profile(fp) if meta.get("language")), None)
        return {"target_url": target_url, "tech_fingerprint": fp,
                "api_schema": ch_results.get("ch6", {}).get("api_schema"), "waf": waf}

    def _depth_rule(self, name):
        return next(rule for rule in self._spider_cfg["adaptive_depth"]["rules"] if rule["id"] == name)

    def _is_blocking_heavily(self):
        count = getattr(self, "_response_count", 0)
        rate = getattr(self, "_blocked_count", 0) / count if count else 0
        return rate > self._depth_rule("waf_blocking")["block_rate_threshold"]

    def _resolve_depth(self, profile, limits):
        if profile.get("api_schema"):
            rule = "api_schema"
        elif self._is_blocking_heavily():
            rule = "waf_blocking"
        else:
            rule = self._rendering(profile.get("tech_fingerprint", {}))
        return self._depth_rule(rule)["depth"]

    def _get_framework_paths(self, fingerprint):
        paths = set()
        for metadata in self._metadata_for_profile(fingerprint):
            entry = self._framework_paths.get(metadata.get("wordlist_key"), {})
            for filename in entry.get("wordlists", []):
                filepath = (_KNOWLEDGE_DIR.parent / filename).resolve()
                if not filepath.is_relative_to(_KNOWLEDGE_DIR.resolve()):
                    raise ValueError("Wordlist is outside knowledge directory")
                paths.update(line.strip() for line in filepath.read_text(encoding="utf-8").splitlines()
                             if line.strip() and not line.lstrip().startswith("#"))
        return sorted(paths)

    def _infer_dev_habits(self, paths):
        conventions = {"snake_case": 0, "kebab-case": 0, "camelCase": 0}
        for path in paths:
            conventions["snake_case"] += "_" in path
            conventions["kebab-case"] += "-" in path
            conventions["camelCase"] += bool(re.search(r"[a-z][A-Z]", path))
        dominant = max(conventions, key=conventions.get)
        prefixes = Counter(match.group(0) for path in paths if (match := re.match(r"/api(?:/v\d+)?/", path)))
        segments = [path.rstrip("/").rsplit("/", 1)[-1] for path in paths if path != "/"]
        return {"naming_convention": dominant if conventions[dominant] else "unknown",
                "url_hierarchy_prefix": prefixes.most_common(1)[0][0] if prefixes else None,
                "versioning_style": "path_prefix" if any(re.search(r"/v\d+(?:/|$)", path) for path in paths) else "none",
                "pluralization": "plural" if segments and sum(part.endswith("s") for part in segments) > len(segments) / 2 else "unknown",
                "crud_pattern": "unknown"}

    def _aggregate_output(self, ch_results, preliminary, target_url, elapsed_s):
        paths, params, breakdown = set(), set(), {}
        forms, endpoints = [], []
        for key, data in ch_results.items():
            normalized = {path for raw in data.get("paths", []) if (path := self._normalize_path(raw, target_url))}
            paths.update(normalized)
            params.update(param for param in data.get("params", []) if param)
            breakdown[key] = len(normalized)
            forms.extend(data.get("forms", []))
            endpoints.extend(data.get("endpoints", []))
        ch6 = ch_results.get("ch6", {})
        schema = ch6.get("api_schema")
        if schema:
            schema = {**schema, "endpoints": ch6.get("endpoints", [])}
        fp = dict(preliminary.get("tech_fingerprint", {}))
        for finding in ch_results.get("ch7", {}).get("findings", []):
            if not fp.get("language") and finding.get("confirmed_framework"):
                fp["language"] = finding["confirmed_framework"]
        waf = ch_results.get("ch1", {}).get("waf", {})
        js = {path for raw in ch_results.get("ch3", {}).get("js_endpoints", [])
              if (path := self._normalize_path(raw, target_url))}
        habits = self._infer_dev_habits(sorted(paths))
        if any(ep.get("method") in {"PUT", "PATCH", "DELETE"} for ep in endpoints):
            habits["crud_pattern"] = "restful"
        sensitive = {path for key, group in self._sensitive_files.items() if key != "_meta" for path in group["paths"]}
        self._last_target_profile = {
            "target_url": normalize_target_url(target_url), "tech_fingerprint": fp, "dev_habits": habits,
            "discovered_paths": sorted(paths), "discovered_params": sorted(params), "js_endpoints": sorted(js),
            "forms": forms, "endpoints": endpoints, "api_schema": schema, "waf": waf,
            "framework_default_paths": self._get_framework_paths(fp),
            "sensitive_file_hints": sorted(paths & {self._normalize_path(path, target_url) for path in sensitive}),
            "observed_endpoints": [{"path": path, "method": method, "status_code": status}
                                   for (path, method), status in getattr(self, "_observations", {}).items() if path in paths],
            "recon_stats": {"total_paths_discovered": len(paths), "total_params_discovered": len(params),
                            "source_breakdown": breakdown, "elapsed_seconds": round(elapsed_s, 3),
                            "http_requests": getattr(self, "_request_count", 0),
                            "blocked_responses": getattr(self, "_blocked_count", 0),
                            "crawl_depth": ch_results.get("ch4", {}).get("effective_depth"),
                            "crawl_max_pages": ch_results.get("ch4", {}).get("max_pages"),
                            "channel_errors": {key: value["error"] for key, value in ch_results.items() if value.get("error")}},
        }
        return {"tech_stack": {key: value for key, value in fp.items() if value and key not in {"waf_detected", "waf_type"}},
                "discovered_paths": sorted(paths), "js_endpoints": sorted(js),
                "waf_detected": waf.get("detected", False), "waf_type": waf.get("type")}

    def _normalize_path(self, raw, base_url):
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            absolute = urljoin(base_url, raw.strip())
            if not self._same_origin(absolute, base_url):
                return None
            path = re.sub(r"/+", "/", urlparse(absolute).path)
            return path.rstrip("/") or "/"
        except ValueError:
            return None
