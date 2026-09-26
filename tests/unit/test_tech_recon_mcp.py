"""Unit tests for Phase 3 TechRecon -> MCP persistence boundary."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.agents.tech_recon import TechReconAgent


TARGET = "http://test.local"


class FakeMCPClient:
    def __init__(self):
        self.create_node = AsyncMock()
        self.create_relationship = AsyncMock()


def profile() -> dict:
    return {
        "target_url": TARGET,
        "tech_fingerprint": {
            "backend": "Django",
            "frontend": None,
            "web_server": "nginx",
            "cms": None,
            "language": "Python",
            "waf_type": None,
        },
        "api_schema": {
            "type": "OpenAPI",
            "endpoints": [
                {
                    "path": "/api/users/{id}",
                    "method": "post",
                    "params": ["id", "token"],
                }
            ],
        },
        "forms": [
            {"action": "/login", "method": "POST", "params": ["username"]}
        ],
        "discovered_paths": ["/health"],
    }


@pytest.mark.asyncio
async def test_persistence_maps_nodes_methods_and_parameter_locations():
    client = FakeMCPClient()
    agent = TechReconAgent(mcp_client=client)
    agent._last_target_profile = profile()

    await agent._persist_profile_best_effort(TARGET)

    create_calls = client.create_node.await_args_list
    assert create_calls[0].args == ("Target", {"url": TARGET})
    assert ("Technology", {"name": "Django", "category": "backend"}) in [
        call.args for call in create_calls
    ]
    endpoint_calls = [call.args for call in create_calls if call.args[0] == "Endpoint"]
    assert any(call[1]["path"] == "/api/users/{id}" and call[1]["method"] == "POST" for call in endpoint_calls)

    parameter_calls = [call.args for call in create_calls if call.args[0] == "Parameter"]
    assert any(props["name"] == "username" and props["location"] == "form" and props["_endpoint_uid"] for _, props in parameter_calls)
    assert any(props["name"] == "id" and props["location"] == "unknown" and props["_endpoint_uid"] for _, props in parameter_calls)

    relationships = [call.args for call in client.create_relationship.await_args_list]
    assert any(call[2] == "USES" for call in relationships)
    assert any(call[2] == "HAS_ENDPOINT" for call in relationships)
    assert any(call[2] == "HAS_PARAM" for call in relationships)


@pytest.mark.asyncio
async def test_persistence_failure_does_not_raise():
    client = FakeMCPClient()
    client.create_node.side_effect = RuntimeError("MCP unavailable")
    agent = TechReconAgent(mcp_client=client)
    agent._last_target_profile = profile()

    await agent._persist_profile_best_effort(TARGET)


@pytest.mark.asyncio
async def test_factory_opens_one_session_for_run():
    client = AsyncMock()
    entered = AsyncMock()
    exited = AsyncMock()

    class Session:
        async def __aenter__(self):
            await entered()
            return client

        async def __aexit__(self, exc_type, exc, tb):
            await exited()

    factory = AsyncMock(return_value=Session())
    agent = TechReconAgent(mcp_client_factory=factory)
    agent._last_target_profile = profile()

    await agent._persist_profile_best_effort(TARGET)

    factory.assert_awaited_once()
    entered.assert_awaited_once()
    exited.assert_awaited_once()


@pytest.mark.asyncio
async def test_persistence_runs_after_aggregation_and_output_is_unchanged():
    http_client = AsyncMock()
    agent = TechReconAgent(http_client=http_client, mcp_client=AsyncMock())
    output = {
        "tech_stack": {"backend": "Django"},
        "discovered_paths": ["/health"],
        "js_endpoints": [],
        "waf_detected": False,
        "waf_type": None,
    }
    events = []

    async def aggregate(*args, **kwargs):
        events.append("aggregate")
        agent._last_target_profile = profile()
        return output

    async def persist(*args, **kwargs):
        events.append("persist")

    agent._run_pipeline = aggregate
    agent._persist_profile_best_effort = persist
    result = await agent._execute_async(TARGET)

    assert result is output
    assert events == ["aggregate", "persist"]


def test_mcp_configuration_is_optional():
    without_mcp = TechReconAgent()
    with_mcp = TechReconAgent(mcp_client=FakeMCPClient())
    assert without_mcp._mcp_client is None
    assert with_mcp._mcp_client is not None
