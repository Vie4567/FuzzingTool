"""Exercise the real MCP handlers with a stateful mock driver."""

import json
import re
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.graph_schema import endpoint_uid
from src.mcp_servers import neo4j_server as server


@pytest.fixture
def graph_driver(monkeypatch):
    nodes = {}
    queries = []
    session = AsyncMock()
    session.__aenter__.return_value = session

    async def run(query, parameters):
        queries.append((query, parameters))
        result = AsyncMock()
        if query.startswith("MERGE (n:"):
            label = re.search(r"MERGE \(n:(\w+)", query).group(1)
            key = (label, parameters["identity"])
            if key not in nodes:
                nodes[key] = {"node_id": str(len(nodes) + 1), "properties": dict(parameters["create_props"])}
            else:
                nodes[key]["properties"].update(parameters["update_props"])
            result.single.return_value = nodes[key]
        else:
            result.single.return_value = {"rel_type": "HAS_PARAM", "rel_id": "r1"}
            result.data.return_value = [{"value": 1}]
        return result

    session.run.side_effect = run
    driver = MagicMock()
    driver.session.return_value = session
    monkeypatch.setattr(server, "_driver", driver)
    return nodes, queries


async def test_target_merge_twice_retains_identity_and_created_at(graph_driver):
    nodes, queries = graph_driver
    first = json.loads(await server.create_node("Target", {"url": "https://a.test/", "created_at": "first"}))
    second = json.loads(await server.create_node("Target", {"url": "https://a.test", "created_at": "later"}))
    assert first["status"] == second["status"] == "ok"
    assert first["data"]["node_id"] == second["data"]["node_id"]
    assert second["data"]["properties"]["created_at"] == "first"
    assert len(nodes) == 1
    assert all(query.startswith("MERGE ") for query, _ in queries)


@pytest.mark.parametrize("label,props", [
    ("Technology", {"name": "Django", "category": "backend"}),
    ("Endpoint", {"_target_url": "https://a.test", "path": "/users", "method": "GET"}),
    ("Parameter", {"_endpoint_uid": "ep1", "name": "id", "location": "query"}),
    ("Finding", {"_endpoint_uid": "ep1", "type": "disclosure", "severity": "low", "description": "trace"}),
])
async def test_every_label_is_idempotent(label, props, graph_driver):
    nodes, _ = graph_driver
    first = json.loads(await server.create_node(label, props))
    second = json.loads(await server.create_node(label, props))
    assert first["status"] == second["status"] == "ok"
    assert first["data"]["node_id"] == second["data"]["node_id"]
    assert len(nodes) == 1


async def test_parameters_are_scoped_and_keep_location(graph_driver):
    nodes, _ = graph_driver
    for endpoint, location in [("ep1", "query"), ("ep1", "header"), ("ep2", "query")]:
        props = {"_endpoint_uid": endpoint, "name": "id", "location": location}
        await server.create_node("Parameter", props)
        await server.create_node("Parameter", props)
    assert len(nodes) == 3


@pytest.mark.parametrize("label,props", [
    ("Target", {}), ("Technology", {}), ("Endpoint", {"path": "/login"}),
    ("Parameter", {"name": "id", "location": "query"}),
    ("Finding", {"type": "xss", "description": "x"}),
])
async def test_missing_identity_is_rejected_before_query(label, props, graph_driver):
    result = json.loads(await server.create_node(label, props))
    assert result["code"] == "VALIDATION_ERROR"
    assert not graph_driver[1]


async def test_relationship_uses_only_unique_keys_and_parent_scope(graph_driver):
    await server.create_relationship("Endpoint", {"_target_url": "https://a.test", "path": "/User", "method": "GET"},
                                     "HAS_PARAM", "Parameter", {"name": "id", "location": "query", "_endpoint_uid": "ep1"})
    query, params = graph_driver[1][-1]
    assert "a._uid" not in query.split(" WHERE ")[0]  # Identity appears in MATCH properties.
    assert "Endpoint {_uid: $left}" in query
    assert "Parameter {_uid: $right}" in query
    assert ") WITH a MATCH (b:" in query
    assert "b._endpoint_uid = a._uid" in query
    assert params["left"] == endpoint_uid("https://a.test", "GET", "/User")


async def test_run_cypher_supports_arbitrary_parameterized_queries(graph_driver):
    result = json.loads(await server.run_cypher("MERGE (t:Target {url: $url}) RETURN 1 AS value", {"url": "https://a.test"}))
    assert result["status"] == "ok"
    assert graph_driver[1][-1][1] == {"url": "https://a.test"}


async def test_subgraph_follows_only_outgoing_edges_and_deduplicates(monkeypatch):
    class Node(dict):
        element_id = "n1"
        labels = {"Target"}
    node = Node(url="https://a.test")
    result = AsyncMock()
    result.single.return_value = {"t": node, "neighbors": [node], "rel_lists": [[], []]}
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.run.return_value = result
    driver = MagicMock()
    driver.session.return_value = session
    monkeypatch.setattr(server, "_driver", driver)
    payload = json.loads(await server.get_subgraph("https://a.test"))
    assert payload["data"]["node_count"] == 1
    assert "]->(n)" in session.run.call_args.args[0]
    assert session.run.call_args.kwargs["parameters"]["rel_types"] == sorted(server.ALLOWED_RELATIONSHIPS)
