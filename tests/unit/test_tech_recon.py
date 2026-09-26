"""
tests/unit/test_tech_recon.py — Unit tests cho TechReconAgent (Phase 2).

Không gọi internet thật — dùng respx.MockRouter + httpx MockTransport.
Pattern: tạo MockRouter riêng → mock routes → tạo client với transport → inject.

Coverage:
  CH-1: tech fingerprint từ headers, cookies, WAF detection
  CH-2: form discovery, href, DOM hints
  CH-3: inline JS extraction, external JS (same origin)
  CH-4: depth limit, exclusion patterns, max_pages, dedup
  CH-5: robots.txt parsing, sitemap parsing, probe hits
  CH-6: OpenAPI JSON parse, YAML parse, GraphQL fallback
  CH-7: disabled (aggressive_probe=False), enabled
  Aggregator: dedup, path normalization, external URL exclusion
  CH-6 → CH-4 depth: nếu OpenAPI found → depth=1
  Channel exception isolation: một channel fail không crash Agent
"""

from __future__ import annotations

import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from httpx import MockTransport

# Thêm root vào sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.agents.tech_recon import TechReconAgent

# ─── Constants ────────────────────────────────────────────────────────────────
TARGET = "http://test.local/"


# ─── Factory helpers ─────────────────────────────────────────────────────────

def make_agent(config: dict | None = None) -> TechReconAgent:
    cfg = {"aggressive_probe": False, "user_agent": "TestBot/1.0", "request_delay_ms": 0, "request_jitter_ms": 0}
    if config:
        cfg.update(config)
    return TechReconAgent(config=cfg)


def make_router() -> respx.MockRouter:
    """Tạo MockRouter mới cho mỗi test."""
    return respx.MockRouter(assert_all_mocked=False, assert_all_called=False)


def make_client(router: respx.MockRouter) -> httpx.AsyncClient:
    """Tạo AsyncClient với MockTransport từ router."""
    transport = MockTransport(router.async_handler)
    return httpx.AsyncClient(transport=transport, base_url=TARGET)


def html_page(links=(), scripts=(), forms=(), body_extra="") -> str:
    link_tags = "".join(f'<a href="{h}">link</a>' for h in links)
    script_tags = ""
    for s in scripts:
        if s.startswith("inline:"):
            script_tags += f'<script>{s[7:]}</script>'
        else:
            script_tags += f'<script src="{s}"></script>'
    form_tags = ""
    for f in forms:
        inputs = "".join(f'<input name="{p}" />' for p in f.get("params", []))
        form_tags += (
            f'<form action="{f.get("action","/submit")}" '
            f'method="{f.get("method","GET")}">{inputs}</form>'
        )
    return (
        f"<html><head></head><body>"
        f"{link_tags}{script_tags}{form_tags}{body_extra}"
        f"</body></html>"
    )


# ═════════════════════════════════════════════════════════════════════════════
# CH-1: HTTP Header Fingerprinting + WAF
# ═════════════════════════════════════════════════════════════════════════════

class TestCH1HeaderFingerprint:

    @pytest.mark.asyncio
    async def test_server_nginx_detected(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text="<html></html>", headers={"Server": "nginx/1.24.0"}
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch1_headers(client, TARGET)
        assert "nginx" in result["tech_fingerprint"]

    @pytest.mark.asyncio
    async def test_x_powered_by_php(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text="<html></html>", headers={"X-Powered-By": "PHP/8.1.0"}
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch1_headers(client, TARGET)
        assert "php" in result["tech_fingerprint"]

    @pytest.mark.asyncio
    async def test_cloudflare_waf_detected_by_header(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text="<html></html>",
            headers={"cf-ray": "abc123", "Server": "cloudflare"}
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch1_headers(client, TARGET)
        assert result["waf"]["detected"] is True
        assert "Cloudflare" in result["waf"]["type"]

    @pytest.mark.asyncio
    async def test_aws_waf_detected(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text="AWS WAF blocked", headers={"x-amzn-requestid": "req-123"}
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch1_headers(client, TARGET)
        assert result["waf"]["detected"] is True

    @pytest.mark.asyncio
    async def test_no_waf_when_no_signature(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text="<html></html>", headers={"Server": "Apache/2.4"}
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch1_headers(client, TARGET)
        assert result["waf"]["detected"] is False

    @pytest.mark.asyncio
    async def test_evasion_hints_populated_when_waf_detected(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text="<html></html>",
            headers={"cf-ray": "abc", "Server": "cloudflare"}
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch1_headers(client, TARGET)
        assert len(result["waf"]["evasion_hints"]) > 0

    @pytest.mark.asyncio
    async def test_ch1_network_error_does_not_raise(self):
        """Network error → result có error key nhưng không propagate exception."""
        router = make_router()
        router.get(TARGET).mock(side_effect=httpx.ConnectError("timeout"))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch1_headers(client, TARGET)
        assert "error" in result


# ═════════════════════════════════════════════════════════════════════════════
# CH-2: DOM Parser
# ═════════════════════════════════════════════════════════════════════════════

class TestCH2DOM:

    @pytest.mark.asyncio
    async def test_href_extracted(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(links=["/login", "/dashboard", "/api/users"])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch2_dom(client, TARGET)
        assert "/login" in result["paths"]
        assert "/dashboard" in result["paths"]

    @pytest.mark.asyncio
    async def test_form_action_and_params_extracted(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(forms=[{
                "action": "/submit", "method": "POST",
                "params": ["username", "password"]
            }])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch2_dom(client, TARGET)
        assert "/submit" in result["paths"]
        assert "username" in result["params"]
        assert "password" in result["params"]

    @pytest.mark.asyncio
    async def test_form_list_contains_params(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(forms=[{
                "action": "/register", "method": "POST",
                "params": ["email", "phone"]
            }])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch2_dom(client, TARGET)
        forms = result["forms"]
        assert len(forms) == 1
        assert "email" in forms[0]["params"]
        assert forms[0]["method"] == "POST"

    @pytest.mark.asyncio
    async def test_mailto_excluded(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(links=["mailto:admin@example.com", "/contact"])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch2_dom(client, TARGET)
        assert not any("mailto" in p for p in result["paths"])
        assert "/contact" in result["paths"]

    @pytest.mark.asyncio
    async def test_dom_tech_hint_wordpress(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text="<html><body>wp-content/themes/test</body></html>"
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch2_dom(client, TARGET)
        assert "wordpress" in result["tech_hints"]


# ═════════════════════════════════════════════════════════════════════════════
# CH-3: JavaScript Analysis
# ═════════════════════════════════════════════════════════════════════════════

class TestCH3JavaScript:

    @pytest.mark.asyncio
    async def test_inline_fetch_path_extracted(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(scripts=["inline:fetch('/api/users').then(r=>r.json())"])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch3_js(client, TARGET)
        assert "/api/users" in result["js_endpoints"]

    @pytest.mark.asyncio
    async def test_inline_axios_path_extracted(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(scripts=["inline:axios.get('/api/v1/profile')"])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch3_js(client, TARGET)
        assert "/api/v1/profile" in result["js_endpoints"]

    @pytest.mark.asyncio
    async def test_external_js_same_origin_fetched(self):
        js_content = "fetch('/api/orders').then(r=>r.json())"
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(scripts=["/static/app.js"])
        ))
        router.get("http://test.local/static/app.js").mock(return_value=httpx.Response(
            200, text=js_content, headers={"Content-Type": "application/javascript"}
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch3_js(client, TARGET)
        assert "/api/orders" in result["js_endpoints"]

    @pytest.mark.asyncio
    async def test_external_js_different_origin_not_fetched(self):
        """JS từ CDN ngoài không được fetch — không throw khi không có mock."""
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(scripts=["https://cdn.example.com/analytics.js"])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            # Không raise — CDN không được crawl
            result = await agent._ch3_js(client, TARGET)
        assert isinstance(result["js_endpoints"], list)

    @pytest.mark.asyncio
    async def test_route_definition_extracted(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(scripts=["inline:Router.get('/users/:id', handler)"])
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch3_js(client, TARGET)
        assert any("/users" in ep for ep in result["js_endpoints"])


# ═════════════════════════════════════════════════════════════════════════════
# CH-4: Spider
# ═════════════════════════════════════════════════════════════════════════════

class TestCH4Spider:

    @pytest.mark.asyncio
    async def test_depth_1_no_second_level(self):
        """Depth=1: root OK, level-2 không bị crawl."""
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(links=["/level1"])
        ))
        router.get("http://test.local/level1").mock(return_value=httpx.Response(
            200, text=html_page(links=["/level2"])
        ))
        router.get("http://test.local/level2").mock(return_value=httpx.Response(
            200, text="<html></html>"
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch4_spider(client, TARGET, effective_depth=1)
        assert "/level2" not in result["paths"]

    @pytest.mark.asyncio
    async def test_exclusion_logout_skipped(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(links=["/logout", "/profile"])
        ))
        router.get("http://test.local/profile").mock(return_value=httpx.Response(
            200, text="<html></html>"
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch4_spider(client, TARGET, effective_depth=2)
        assert "/logout" not in result["paths"]

    @pytest.mark.asyncio
    async def test_external_domain_not_crawled(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(links=["https://evil.com/exfil", "/safe"])
        ))
        router.get("http://test.local/safe").mock(return_value=httpx.Response(
            200, text="<html></html>"
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch4_spider(client, TARGET, effective_depth=2)
        assert not any("evil.com" in p for p in result["paths"])

    @pytest.mark.asyncio
    async def test_max_pages_respected(self):
        """Spider dừng khi đạt max_pages=2."""
        agent = make_agent()
        agent._spider_cfg["limits"] = dict(agent._spider_cfg.get("limits", {}))
        agent._spider_cfg["limits"]["default_max_pages"] = 2
        agent._spider_cfg["limits"]["request_delay_ms"] = 0
        agent._spider_cfg["limits"]["request_jitter_ms"] = 0

        pages = {
            "/": html_page(links=["/p1", "/p2", "/p3", "/p4"]),
            "/p1": html_page(links=["/p5"]),
            "/p2": html_page(),
            "/p3": html_page(),
            "/p4": html_page(),
        }

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path or "/"
            return httpx.Response(200, text=pages.get(path, "<html></html>"))

        transport = MockTransport(handler=handler)
        async with httpx.AsyncClient(transport=transport, base_url=TARGET) as client:
            result = await agent._ch4_spider(client, TARGET, effective_depth=3)

        assert result["crawled_count"] <= 2

    @pytest.mark.asyncio
    async def test_same_url_not_crawled_twice(self):
        """Dedup: cùng URL không bị crawl lại."""
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(links=["/page", "/page", "/page"])
        ))
        router.get("http://test.local/page").mock(return_value=httpx.Response(
            200, text="<html></html>"
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch4_spider(client, TARGET, effective_depth=2)
        assert result["crawled_count"] <= 3

    @pytest.mark.asyncio
    async def test_image_extensions_excluded(self):
        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(
            200, text=html_page(links=["/banner.jpg", "/logo.png", "/api/data"])
        ))
        router.get("http://test.local/api/data").mock(return_value=httpx.Response(
            200, text="<html></html>"
        ))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch4_spider(client, TARGET, effective_depth=1)
        assert "/banner.jpg" not in result["paths"]
        assert "/logo.png" not in result["paths"]


# ═════════════════════════════════════════════════════════════════════════════
# CH-5: Probe Files
# ═════════════════════════════════════════════════════════════════════════════

class TestCH5ProbeFiles:

    @pytest.mark.asyncio
    async def test_robots_txt_parsed(self):
        robots_body = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Allow: /api/\n"
            "Sitemap: https://test.local/sitemap.xml\n"
        )
        router = make_router()
        router.get("http://test.local/robots.txt").mock(
            return_value=httpx.Response(200, text=robots_body)
        )
        # All other probes → 404
        router.get(url__regex=".*").mock(return_value=httpx.Response(404))
        async with make_client(router) as client:
            agent = make_agent()
            # Patch delay to avoid waiting
            agent._spider_cfg["limits"]["request_delay_ms"] = 0
            agent._spider_cfg["limits"]["request_jitter_ms"] = 0
            result = await agent._ch5_probe(client, TARGET)
        assert "/robots.txt" in result["probe_hits"]
        assert any("/admin/" in p for p in result["robots_paths"])

    @pytest.mark.asyncio
    async def test_sitemap_paths_extracted(self):
        sitemap_body = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://test.local/products</loc></url>
  <url><loc>http://test.local/about</loc></url>
</urlset>"""
        router = make_router()
        router.get("http://test.local/robots.txt").mock(return_value=httpx.Response(404))
        router.get("http://test.local/sitemap.xml").mock(
            return_value=httpx.Response(200, text=sitemap_body)
        )
        router.get(url__regex=".*").mock(return_value=httpx.Response(404))
        async with make_client(router) as client:
            agent = make_agent()
            agent._spider_cfg["limits"]["request_delay_ms"] = 0
            agent._spider_cfg["limits"]["request_jitter_ms"] = 0
            result = await agent._ch5_probe(client, TARGET)
        assert "/sitemap.xml" in result["probe_hits"]
        assert any("products" in p for p in result["paths"])

    @pytest.mark.asyncio
    async def test_404_probes_yield_no_hits(self):
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(404))
        async with make_client(router) as client:
            agent = make_agent()
            agent._spider_cfg["limits"]["request_delay_ms"] = 0
            agent._spider_cfg["limits"]["request_jitter_ms"] = 0
            result = await agent._ch5_probe(client, TARGET)
        assert result["probe_hits"] == []


# ═════════════════════════════════════════════════════════════════════════════
# CH-6: API Schema Detection
# ═════════════════════════════════════════════════════════════════════════════

class TestCH6APISchema:

    @pytest.mark.asyncio
    async def test_openapi_json_parsed(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {
                "/api/users": {
                    "get": {"parameters": [{"name": "page", "in": "query"}]},
                    "post": {},
                },
                "/api/orders": {"get": {}},
            }
        }
        router = make_router()
        router.get("http://test.local/openapi.json").mock(
            return_value=httpx.Response(200, json=spec)
        )
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch6_api_schema(client, TARGET)
        assert result["schema_type"] == "openapi"
        # GET users + POST users + GET orders = 3 endpoint entries
        assert result["api_schema"]["endpoints_count"] == 3
        assert "/api/users" in result["paths"]
        assert "page" in result["params"]

    @pytest.mark.asyncio
    async def test_openapi_yaml_parsed(self):
        spec_yaml = """
openapi: "3.0.0"
info:
  title: YAML Test
paths:
  /api/items:
    get: {}
  /api/items/{id}:
    delete: {}
"""
        router = make_router()
        router.get("http://test.local/openapi.json").mock(return_value=httpx.Response(404))
        router.get("http://test.local/openapi.yaml").mock(
            return_value=httpx.Response(200, text=spec_yaml)
        )
        router.get(url__regex=".*").mock(return_value=httpx.Response(404))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch6_api_schema(client, TARGET)
        assert result["schema_type"] == "openapi"
        assert "/api/items" in result["paths"]

    @pytest.mark.asyncio
    async def test_graphql_get_400_is_not_a_schema(self):
        router = make_router()
        # All OpenAPI probes → 404
        router.get(url__regex=r".*(openapi|swagger|api-docs|v2|v3).*").mock(
            return_value=httpx.Response(404)
        )
        router.get("http://test.local/graphql").mock(
            return_value=httpx.Response(
                400, text='{"errors":[{"message":"Must provide query string"}]}'
            )
        )
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch6_api_schema(client, TARGET)
        assert result["schema_type"] is None

    @pytest.mark.asyncio
    async def test_no_schema_returns_none(self):
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(404))
        async with make_client(router) as client:
            agent = make_agent()
            result = await agent._ch6_api_schema(client, TARGET)
        assert result["api_schema"] is None
        assert result["schema_type"] is None


# ═════════════════════════════════════════════════════════════════════════════
# CH-7: Error Probe
# ═════════════════════════════════════════════════════════════════════════════

class TestCH7ErrorProbe:

    @pytest.mark.asyncio
    async def test_ch7_not_called_when_disabled(self):
        """aggressive_probe=False → _ch7_error_probe không được gọi trong pipeline."""
        agent = make_agent({"aggressive_probe": False})

        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))
        router.post(url__regex=".*").mock(return_value=httpx.Response(200, text=""))
        router.options(url__regex=".*").mock(return_value=httpx.Response(200, text=""))

        with patch.object(agent, "_ch7_error_probe", new_callable=AsyncMock) as mock_ch7:
            async with make_client(router) as client:
                agent._injected_client = client
                await agent._run_pipeline(client, TARGET, aggressive=False, start_time=0)
            mock_ch7.assert_not_called()

    @pytest.mark.asyncio
    async def test_ch7_called_when_enabled(self):
        """aggressive_probe=True → _ch7_error_probe được gọi."""
        agent = make_agent({"aggressive_probe": True})

        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))
        router.post(url__regex=".*").mock(return_value=httpx.Response(200, text=""))
        router.options(url__regex=".*").mock(return_value=httpx.Response(200, text=""))

        dummy_return = {"paths": [], "params": [], "findings": [], "source": "CH-7 Error Probe"}
        with patch.object(agent, "_ch7_error_probe", new_callable=AsyncMock,
                          return_value=dummy_return) as mock_ch7:
            async with make_client(router) as client:
                await agent._run_pipeline(client, TARGET, aggressive=True, start_time=0)
            mock_ch7.assert_called_once()

    @pytest.mark.asyncio
    async def test_ch7_python_traceback_detected(self):
        python_traceback = (
            "Traceback (most recent call last):\n"
            '  File "/app/src/views.py", line 42\n'
            "    raise ValueError\n"
        )
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(500, text=python_traceback))
        router.post(url__regex=".*").mock(return_value=httpx.Response(200, text=""))
        router.options(url__regex=".*").mock(return_value=httpx.Response(200, text=""))
        async with make_client(router) as client:
            agent = make_agent({"aggressive_probe": True})
            result = await agent._ch7_error_probe(client, TARGET)
        assert any(f.get("confirmed_framework") == "Python" for f in result["findings"])
        assert any("/app/src/views.py" in p for p in result["paths"])


# ═════════════════════════════════════════════════════════════════════════════
# Aggregator: Path Normalization & Dedup
# ═════════════════════════════════════════════════════════════════════════════

class TestAggregator:

    def test_normalize_absolute_url_same_origin(self):
        agent = make_agent()
        assert agent._normalize_path("http://test.local/api/users", TARGET) == "/api/users"

    def test_normalize_external_url_returns_none(self):
        agent = make_agent()
        assert agent._normalize_path("https://evil.com/steal", TARGET) is None

    def test_normalize_removes_fragment(self):
        agent = make_agent()
        assert agent._normalize_path("/page#section", TARGET) == "/page"

    def test_normalize_removes_query_string(self):
        agent = make_agent()
        assert agent._normalize_path("/search?q=xss", TARGET) == "/search"

    def test_normalize_double_slash(self):
        agent = make_agent()
        assert agent._normalize_path("/api//users//me", TARGET) == "/api/users/me"

    def test_normalize_trailing_slash_stripped(self):
        agent = make_agent()
        assert agent._normalize_path("/api/users/", TARGET) == "/api/users"

    def test_normalize_root_preserved(self):
        agent = make_agent()
        assert agent._normalize_path("/", TARGET) == "/"

    def test_normalize_mailto_returns_none(self):
        agent = make_agent()
        assert agent._normalize_path("mailto:admin@test.local", TARGET) is None

    def test_normalize_empty_returns_none(self):
        agent = make_agent()
        assert agent._normalize_path("", TARGET) is None

    def test_paths_dedup_across_channels(self):
        """Cùng path từ nhiều channels → chỉ xuất hiện 1 lần trong output."""
        ch_results = {
            "ch1": {"paths": ["/api/login", "/api/users"], "params": []},
            "ch2": {"paths": ["/api/login", "/home"], "params": ["user"]},
            "ch3": {"paths": ["/api/login"], "params": [], "js_endpoints": []},
            "ch4": {"paths": ["/api/login", "/api/orders"], "params": []},
            "ch5": {"paths": [], "params": [], "probe_hits": []},
            "ch6": {"paths": [], "params": [], "api_schema": None, "endpoints": []},
        }
        preliminary = {
            "tech_fingerprint": {},
            "api_schema": None,
            "waf": {"detected": False, "type": None},
            "target_url": TARGET,
        }
        agent = make_agent()
        output = agent._aggregate_output(ch_results, preliminary, TARGET, 1.0)
        assert output["discovered_paths"].count("/api/login") == 1


# ═════════════════════════════════════════════════════════════════════════════
# CH-6 → CH-4 Depth Adaptation
# ═════════════════════════════════════════════════════════════════════════════

class TestDepthAdaptation:

    def test_openapi_detected_sets_depth_1(self):
        agent = make_agent()
        profile = {
            "api_schema": {"type": "OpenAPI", "endpoints_count": 50},
            "tech_fingerprint": {"waf_detected": False, "frontend": None, "backend": None},
        }
        depth = agent._resolve_depth(profile, agent._spider_cfg.get("limits", {}))
        assert depth == 1

    def test_waf_detected_sets_depth_1(self):
        agent = make_agent()
        agent._response_count = 10
        agent._blocked_count = 4
        profile = {
            "api_schema": None,
            "tech_fingerprint": {"waf_detected": True, "frontend": None, "backend": None},
        }
        depth = agent._resolve_depth(profile, agent._spider_cfg.get("limits", {}))
        assert depth == 1

    def test_spa_framework_sets_depth_2(self):
        agent = make_agent()
        profile = {
            "api_schema": None,
            "tech_fingerprint": {"waf_detected": False, "frontend": "React", "backend": None},
        }
        depth = agent._resolve_depth(profile, agent._spider_cfg.get("limits", {}))
        assert depth == 2

    def test_ssr_wordpress_sets_depth_4(self):
        agent = make_agent()
        profile = {
            "api_schema": None,
            "tech_fingerprint": {"waf_detected": False, "frontend": None, "backend": "WordPress"},
        }
        depth = agent._resolve_depth(profile, agent._spider_cfg.get("limits", {}))
        assert depth == 4

    def test_unknown_framework_sets_default_depth(self):
        agent = make_agent()
        profile = {
            "api_schema": None,
            "tech_fingerprint": {"waf_detected": False, "frontend": None, "backend": None},
        }
        limits = agent._spider_cfg.get("limits", {})
        default = limits.get("default_max_depth", 3)
        depth = agent._resolve_depth(profile, limits)
        assert depth == default

    @pytest.mark.asyncio
    async def test_openapi_causes_spider_depth_1(self):
        """E2E: CH-6 finds OpenAPI → _ch4_spider is called with effective_depth=1."""
        spec = {
            "openapi": "3.0.0",
            "paths": {"/api/things": {"get": {}}}
        }
        agent = make_agent()
        ch4_depths: list[int] = []

        async def patched_ch4(client, url, effective_depth):
            ch4_depths.append(effective_depth)
            return {"paths": [], "params": [], "crawled_count": 0, "source": "CH-4 Spider"}

        agent._ch4_spider = patched_ch4

        router = make_router()
        router.get(TARGET).mock(return_value=httpx.Response(200, text="<html></html>"))
        router.get("http://test.local/openapi.json").mock(
            return_value=httpx.Response(200, json=spec)
        )
        router.get(url__regex=".*").mock(return_value=httpx.Response(404))

        async with make_client(router) as client:
            await agent._run_pipeline(client, TARGET, aggressive=False, start_time=0)

        assert ch4_depths == [1], f"Expected depth=[1] but got {ch4_depths}"


# ═════════════════════════════════════════════════════════════════════════════
# Channel Exception Isolation
# ═════════════════════════════════════════════════════════════════════════════

class TestChannelExceptionIsolation:

    @pytest.mark.asyncio
    async def test_ch3_exception_does_not_crash_agent(self):
        """CH-3 raise RuntimeError → Agent vẫn trả output hợp lệ."""
        agent = make_agent()

        async def bad_ch3(client, url):
            raise RuntimeError("JS engine crash")

        agent._ch3_js = bad_ch3

        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))

        async with make_client(router) as client:
            result = await agent._run_pipeline(client, TARGET, aggressive=False, start_time=0)

        assert "discovered_paths" in result
        assert "waf_detected" in result

    @pytest.mark.asyncio
    async def test_all_channels_fail_still_returns_contract(self):
        """Tất cả channel fail → Agent vẫn trả đủ 5 keys."""
        agent = make_agent()

        async def bad_channel(client, url):
            raise ConnectionError("network down")

        agent._ch1_headers   = bad_channel
        agent._ch2_dom       = bad_channel
        agent._ch3_js        = bad_channel
        agent._ch5_probe     = bad_channel
        agent._ch6_api_schema = bad_channel

        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))

        async with make_client(router) as client:
            result = await agent._run_pipeline(client, TARGET, aggressive=False, start_time=0)

        required = {"tech_stack", "discovered_paths", "js_endpoints", "waf_detected", "waf_type"}
        assert required.issubset(result.keys()), f"Missing: {required - result.keys()}"


# ═════════════════════════════════════════════════════════════════════════════
# Output Contract Compatibility
# ═════════════════════════════════════════════════════════════════════════════

class TestOutputContract:

    @pytest.mark.asyncio
    async def test_output_has_required_keys(self):
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))
        router.post(url__regex=".*").mock(return_value=httpx.Response(200, text=""))
        router.options(url__regex=".*").mock(return_value=httpx.Response(200, text=""))

        async with make_client(router) as client:
            agent = make_agent()
            agent._injected_client = client
            result = await agent._execute_async(TARGET)

        required = {"tech_stack", "discovered_paths", "js_endpoints", "waf_detected", "waf_type"}
        assert required.issubset(result.keys()), f"Missing: {required - result.keys()}"

    @pytest.mark.asyncio
    async def test_waf_detected_is_bool(self):
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))
        async with make_client(router) as client:
            agent = make_agent()
            agent._injected_client = client
            result = await agent._execute_async(TARGET)
        assert isinstance(result["waf_detected"], bool)

    @pytest.mark.asyncio
    async def test_discovered_paths_is_sorted_list(self):
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))
        async with make_client(router) as client:
            agent = make_agent()
            agent._injected_client = client
            result = await agent._execute_async(TARGET)
        assert isinstance(result["discovered_paths"], list)
        assert result["discovered_paths"] == sorted(result["discovered_paths"])

    @pytest.mark.asyncio
    async def test_js_endpoints_is_list(self):
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))
        async with make_client(router) as client:
            agent = make_agent()
            agent._injected_client = client
            result = await agent._execute_async(TARGET)
        assert isinstance(result["js_endpoints"], list)

    def test_execute_sync_wrapper_returns_dict(self):
        """execute() sync wrapper trả về dict đúng format mà không raise."""
        router = make_router()
        router.get(url__regex=".*").mock(return_value=httpx.Response(200, text="<html></html>"))

        transport = MockTransport(router.async_handler)
        client = httpx.AsyncClient(transport=transport, base_url=TARGET)

        agent = TechReconAgent(config={"aggressive_probe": False, "request_delay_ms": 0, "request_jitter_ms": 0}, http_client=client)
        result = agent.execute(TARGET)

        required = {"tech_stack", "discovered_paths", "js_endpoints", "waf_detected", "waf_type"}
        assert required.issubset(result.keys())


# ═════════════════════════════════════════════════════════════════════════════
# Config Injection
# ═════════════════════════════════════════════════════════════════════════════

class TestConfigInjection:

    def test_aggressive_probe_defaults_to_false(self):
        agent = TechReconAgent()
        assert agent.config.get("aggressive_probe", False) is False

    def test_config_override_accepted(self):
        agent = TechReconAgent(config={"aggressive_probe": True, "user_agent": "CustomBot/2.0"})
        assert agent.config["aggressive_probe"] is True
        assert agent.config["user_agent"] == "CustomBot/2.0"

    def test_two_instances_no_shared_state(self):
        a = TechReconAgent(config={"aggressive_probe": False})
        b = TechReconAgent(config={"aggressive_probe": True})
        assert a.config["aggressive_probe"] is not b.config["aggressive_probe"]

    def test_js_regexes_loaded_from_knowledge(self):
        """Regex được load từ js_extraction_patterns.json, không empty."""
        agent = make_agent()
        assert len(agent._js_regexes) > 0

    def test_spider_config_loaded(self):
        agent = make_agent()
        assert "limits" in agent._spider_cfg
        assert "request_jitter_ms" in agent._spider_cfg["limits"]
