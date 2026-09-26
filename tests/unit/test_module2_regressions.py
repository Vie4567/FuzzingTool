import asyncio
import json
import time
from unittest.mock import AsyncMock

import httpx
import pytest

from src.agents.tech_recon import TechReconAgent
from src.graph_schema import endpoint_uid, prepare_properties, scoped_uid


TARGET = "https://target.test/"
FAST = {"request_delay_ms": 0, "request_jitter_ms": 0}


def agent(**kwargs):
    return TechReconAgent(config={**FAST, **kwargs})


@pytest.mark.parametrize("script_url", [
    "https://target.test.outside.invalid/a.js", "https://target.test:444/a.js",
    "http://target.test/a.js", "https://target.test@outside.invalid/a.js",
])
async def test_js_origin_requires_matching_scheme_host_and_port(script_url):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, text=f'<script src="{script_url}"></script>')
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await agent()._ch3_js(client, TARGET)
    assert calls == [TARGET]


async def test_redirects_never_leave_target_even_with_injected_follow_redirects():
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://outside.invalid/"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        with pytest.raises(ValueError, match="Redirect outside"):
            await agent()._request(client, "GET", TARGET)
    assert calls == [TARGET]


async def test_all_channels_share_concurrency_limit_and_homepage_cache():
    active = peak = 0
    calls = []
    async def handler(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        calls.append((request.method, str(request.url)))
        await asyncio.sleep(0.005)
        active -= 1
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        recon = agent(concurrent_requests=3)
        recon._injected_client = client
        await recon.execute_async(TARGET)
    assert 1 < peak <= 3
    assert calls.count(("GET", TARGET)) == 1


async def test_request_start_times_are_spaced_globally():
    starts = []
    def handler(request):
        starts.append(time.perf_counter())
        return httpx.Response(200)
    recon = agent(request_delay_ms=25, request_jitter_ms=5)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await asyncio.gather(*(recon._request(client, "GET", TARGET + str(i)) for i in range(4)))
    assert all(right - left >= 0.024 for left, right in zip(starts, starts[1:]))


@pytest.mark.parametrize("channel", ["ch1_headers", "ch2_dom", "ch3_js", "ch4_spider", "ch5_probe", "ch6_api_schema", "ch7_error_probe"])
async def test_each_channel_failure_is_isolated(channel):
    recon = agent(aggressive_probe=True)
    setattr(recon, "_" + channel, AsyncMock(side_effect=RuntimeError("channel failed")))
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(404))) as client:
        recon._injected_client = client
        result = await recon.execute_async(TARGET)
    assert set(result) == {"tech_stack", "discovered_paths", "js_endpoints", "waf_detected", "waf_type"}
    assert channel.split("_")[0] in recon.target_profile["recon_stats"]["channel_errors"]


async def test_graphql_introspection_extracts_query_mutation_and_args():
    calls = []
    def handler(request):
        calls.append(request)
        if request.method == "POST" and request.url.path == "/graphql":
            assert "__schema" in json.loads(request.content)["query"]
            return httpx.Response(200, json={"data": {"__schema": {
                "queryType": {"name": "Query", "fields": [{"name": "users", "args": [{"name": "limit"}]}]},
                "mutationType": {"name": "Mutation", "fields": [{"name": "addUser", "args": [{"name": "name"}]}]},
            }}})
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await agent()._ch6_api_schema(client, TARGET)
    assert result["schema_type"] == "graphql"
    assert result["params"] == ["limit", "name"]
    assert result["endpoints"][0]["method"] == "POST"
    assert len(result["api_schema"]["operations"]) == 2


@pytest.mark.parametrize("response", [
    httpx.Response(200, text="<html>SPA fallback</html>"),
    httpx.Response(200, json={"errors": [{"message": "Introspection disabled"}]}),
    httpx.Response(400, json={"errors": [{"message": "Invalid query"}]}),
])
async def test_non_schema_graphql_responses_do_not_reduce_depth(response):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: response)) as client:
        recon = agent()
        result = await recon._ch6_api_schema(client, TARGET)
    assert result["api_schema"] is None
    profile = recon._build_preliminary_profile({"ch6": result}, TARGET)
    assert recon._resolve_depth(profile, recon._spider_cfg["limits"]) == 3


@pytest.mark.parametrize("key,expected", [("next_js", 2), ("vue_js", 2), ("wordpress", 4), ("django", 4)])
def test_depth_uses_real_classified_profile(key, expected):
    recon = agent()
    profile = recon._build_preliminary_profile({"ch2": {"tech_hints": {key: "found"}}}, TARGET)
    assert recon._resolve_depth(profile, recon._spider_cfg["limits"]) == expected
    rule = recon._depth_rule("spa" if expected == 2 else "ssr")
    rule["depth"] = 7
    assert recon._resolve_depth(profile, recon._spider_cfg["limits"]) == 7


def test_waf_depth_depends_on_measured_block_rate():
    recon = agent()
    profile = {"tech_fingerprint": {"frontend": "React", "waf_detected": True}}
    recon._response_count, recon._blocked_count = 10, 3
    assert recon._resolve_depth(profile, recon._spider_cfg["limits"]) == 2
    recon._blocked_count = 4
    assert recon._resolve_depth(profile, recon._spider_cfg["limits"]) == 1


@pytest.mark.parametrize("fingerprint,limit", [({"frontend": "Vue"}, 2), ({"cms": "WordPress"}, 4)])
async def test_spider_uses_rendering_specific_page_budget(fingerprint, limit):
    recon = agent(spa_max_pages=2, ssr_max_pages=4)
    recon._preliminary_profile = {"tech_fingerprint": fingerprint}
    html = "".join(f'<a href="/page{i}">page</a>' for i in range(10))
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, text=html))) as client:
        result = await recon._ch4_spider(client, TARGET, 4)
    assert result["crawled_count"] == limit


def test_wordlists_are_loaded_and_unknown_framework_has_no_guessed_wordlist():
    recon = agent()
    assert "/manage.py" in recon._get_framework_paths({"backend": "Django"})
    assert "/wp-login.php" in recon._get_framework_paths({"cms": "WordPress"})
    assert recon._get_framework_paths({}) == []


def test_dom_relative_action_missing_action_and_all_selectors():
    result = agent()._parse_dom('''<widget action="custom"></widget><form method="post">
        <input name="id"><textarea name="note"></textarea><select name="mode"></select>
        <button formaction="save">save</button></form><a href="edit?q=1">edit</a>''', TARGET + "admin/")
    assert {"/admin", "/admin/save", "/admin/edit", "/admin/custom"} <= set(result["paths"])
    assert {"id", "note", "mode", "q"} <= set(result["params"])


def test_parameter_locations_methods_and_observed_status_are_preserved():
    profile = {"discovered_paths": ["/submit"], "api_schema": {"endpoints": [{
        "path": "/submit", "method": "POST", "parameter_details": [
            {"name": "id", "location": "query"}, {"name": "id", "location": "header"},
        ],
    }]}, "forms": [{"action": "/submit", "method": "POST", "params": ["id"]}],
        "observed_endpoints": [{"path": "/submit", "method": "POST", "status_code": 201}]}
    records = agent()._profile_endpoints(profile, TARGET)
    assert len(records) == 1
    assert records[0]["method"] == "POST"
    assert records[0]["status_code"] == 201
    assert {p["location"] for p in records[0]["parameters"]} == {"query", "header", "form"}


def test_endpoint_identity_preserves_case_and_parameter_scope():
    upper = endpoint_uid(TARGET, "GET", "/User")
    lower = endpoint_uid(TARGET, "GET", "/user")
    assert upper != lower
    assert lower == endpoint_uid(TARGET, "get", "/user/?x=1")
    assert upper != endpoint_uid("https://other.test", "GET", "/User")
    first = {"name": "id", "location": "query", "_endpoint_uid": upper}
    second = {**first, "_endpoint_uid": lower}
    assert scoped_uid("Parameter", first) != scoped_uid("Parameter", second)
    assert scoped_uid("Parameter", first) != scoped_uid("Parameter", {**first, "location": "header"})
    assert prepare_properties("Parameter", first)["_uid"] == scoped_uid("Parameter", first)


def test_openapi_refs_path_parameters_body_and_server_prefix():
    document = {"openapi": "3.0.0", "servers": [{"url": "/api/v2"}],
                "components": {"parameters": {"Id": {"name": "id", "in": "path"}},
                               "schemas": {"Input": {"properties": {"name": {"type": "string"}}}}},
                "paths": {"/users/{id}": {"parameters": [{"$ref": "#/components/parameters/Id"}],
                    "post": {"parameters": [{"name": "id", "in": "query"}],
                             "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Input"}}}}}}}}
    result = agent()._openapi_endpoints(document, TARGET + "openapi.json")
    assert result[0]["path"] == "/api/v2/users/{id}"
    assert {(p["name"], p["location"]) for p in result[0]["parameter_details"]} == {("id", "path"), ("id", "query"), ("name", "body")}


async def test_sitemap_index_is_followed_without_truncating_long_xml():
    xml = "<urlset>" + " " * 5000 + "<url><loc>https://target.test/deep</loc></url></urlset>"
    pages = {"/sitemap.xml": '<sitemapindex><sitemap><loc>https://target.test/part.xml</loc></sitemap></sitemapindex>', "/part.xml": xml}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, text=pages[req.url.path]) if req.url.path in pages else httpx.Response(404))) as client:
        result = await agent()._ch5_probe(client, TARGET)
    assert "https://target.test/deep" in result["paths"]


async def test_persistence_timeout_keeps_result():
    class SlowMCP:
        async def create_node(self, *args):
            await asyncio.sleep(2)
    recon = agent(mcp_timeout_s=0.01)
    recon._mcp_client = SlowMCP()
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(404))) as client:
        recon._injected_client = client
        result = await recon.execute_async(TARGET)
    assert "discovered_paths" in result
    assert recon.persistence_status == "failed"
