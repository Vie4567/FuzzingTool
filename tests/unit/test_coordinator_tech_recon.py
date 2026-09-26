"""Coordinator regression tests for the Module 2 Agent 1 boundary."""

from unittest.mock import MagicMock, patch

import pytest

from src.coordinator.graph import run_tech_recon


def _state():
    return {
        "target_url": "http://test.local",
        "config": {},
        "agent_statuses": {"tech_recon": "pending"},
        "audit_log": [],
        "error_log": [],
    }


def test_run_tech_recon_preserves_waf_type():
    state = _state()
    result = {
        "tech_stack": {"backend": "Django"},
        "discovered_paths": ["/login"],
        "js_endpoints": [],
        "waf_detected": True,
        "waf_type": "cloudflare",
    }

    agent = MagicMock()
    agent.execute.return_value = result
    with patch("src.coordinator.graph.TechReconAgent", return_value=agent):
        updated = run_tech_recon(state)

    assert updated["waf_detected"] is True
    assert updated["waf_type"] == "cloudflare"
    assert updated["agent_statuses"]["tech_recon"] == "success"


def test_run_tech_recon_injects_shared_limiter_and_default_mcp_factory():
    from src.clients.neo4j_mcp_client import Neo4jMCPClient
    from src.coordinator.graph import llm_limiter
    with patch("src.coordinator.graph.TechReconAgent") as constructor:
        constructor.return_value.execute.return_value = {}
        run_tech_recon(_state())
    assert constructor.call_args.kwargs["llm_limiter"] is llm_limiter
    assert constructor.call_args.kwargs["mcp_client_factory"] is Neo4jMCPClient


def test_run_tech_recon_can_disable_neo4j_for_sample_pipeline():
    state = _state()
    state["config"]["neo4j_enabled"] = False
    with patch("src.coordinator.graph.TechReconAgent") as constructor:
        constructor.return_value.execute.return_value = {}
        run_tech_recon(state)
    assert constructor.call_args.kwargs["mcp_client_factory"] is None
