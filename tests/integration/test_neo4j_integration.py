"""Live Neo4j integration tests through the real MCP stdio boundary.

Prerequisites:
    docker compose up -d neo4j
    python scripts/init_neo4j.py

No test in this module imports or calls the Neo4j driver. Writes, assertions,
subgraph reads, and cleanup all travel through Neo4jMCPClient -> MCP stdio ->
neo4j_server -> Neo4j.
"""

from __future__ import annotations

import os
import socket
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import pytest
from dotenv import load_dotenv

from src.agents.tech_recon import TechReconAgent
from src.clients.neo4j_mcp_client import MCPToolError, Neo4jMCPClient
from src.graph_schema import endpoint_uid


load_dotenv()
pytestmark = pytest.mark.integration


def _neo4j_port_is_open() -> bool:
    parsed = urlsplit(os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    try:
        with socket.create_connection((parsed.hostname or "localhost", parsed.port or 7687), timeout=1):
            return True
    except OSError:
        return False


if not _neo4j_port_is_open():
    pytest.skip(
        "Neo4j is unavailable. Run: docker compose up -d neo4j",
        allow_module_level=True,
    )


async def _cleanup(client: Neo4jMCPClient, targets: list[str], technologies: list[str]) -> None:
    await client.run_cypher(
        "MATCH (e:Endpoint) WHERE e._target_url IN $targets "
        "OPTIONAL MATCH (e)-[:HAS_PARAM|FLAGGED_AS]->(child) DETACH DELETE child",
        {"targets": targets},
    )
    await client.run_cypher(
        "MATCH (e:Endpoint) WHERE e._target_url IN $targets DETACH DELETE e",
        {"targets": targets},
    )
    await client.run_cypher(
        "MATCH (t:Target) WHERE t.url IN $targets DETACH DELETE t",
        {"targets": targets},
    )
    await client.run_cypher(
        "MATCH (tech:Technology) WHERE tech.name IN $technologies "
        "AND NOT ()-[:USES]->(tech) DETACH DELETE tech",
        {"technologies": technologies},
    )


@pytest.mark.asyncio
async def test_real_mcp_stdio_tools_resource_and_idempotent_graph_round_trip():
    suffix = uuid4().hex
    target_a = f"https://mcp-a-{suffix}.invalid"
    target_b = f"https://mcp-b-{suffix}.invalid"
    technology = f"Django-MCP-{suffix}"
    targets = [target_a, target_b]
    endpoint_a = {"path": "/User", "method": "GET", "_target_url": target_a, "status_code": 200}
    endpoint_b = {"path": "/User", "method": "GET", "_target_url": target_b, "status_code": 403}
    endpoint_a_uid = endpoint_uid(target_a, "GET", "/User")
    endpoint_b_uid = endpoint_uid(target_b, "GET", "/User")

    async with Neo4jMCPClient(timeout_s=30) as client:
        try:
            tools = await client._session.list_tools()
            assert {tool.name for tool in tools.tools} == {
                "create_node", "create_relationship", "run_cypher", "get_subgraph"
            }

            schema = await client.get_graph_schema()
            assert {"Target", "Technology", "Endpoint", "Parameter", "Finding"} <= set(schema["labels"])
            assert "HAS_PARAM" in schema["relationships"]

            for _ in range(2):
                await client.create_node("Target", {"url": target_a})
                await client.create_node("Target", {"url": target_b})
                await client.create_node("Technology", {"name": technology, "category": "backend"})
                await client.create_node("Endpoint", endpoint_a)
                await client.create_node("Endpoint", endpoint_b)
                await client.create_relationship("Target", {"url": target_a}, "USES",
                                                 "Technology", {"name": technology})
                await client.create_relationship("Target", {"url": target_a}, "HAS_ENDPOINT",
                                                 "Endpoint", {"_uid": endpoint_a_uid})
                await client.create_relationship("Target", {"url": target_b}, "HAS_ENDPOINT",
                                                 "Endpoint", {"_uid": endpoint_b_uid})

                parameter = {"name": "id", "location": "query", "_endpoint_uid": endpoint_a_uid}
                created_parameter = await client.create_node("Parameter", parameter)
                await client.create_relationship(
                    "Endpoint", {"_uid": endpoint_a_uid}, "HAS_PARAM", "Parameter",
                    {"_uid": created_parameter["properties"]["_uid"]},
                )

            counts = await client.run_cypher(
                "MATCH (t:Target) WHERE t.url IN $targets "
                "WITH count(t) AS targets "
                "MATCH (e:Endpoint) WHERE e._target_url IN $target_urls "
                "WITH targets, count(e) AS endpoints "
                "MATCH (p:Parameter {_endpoint_uid: $endpoint_uid}) "
                "RETURN targets, endpoints, count(p) AS parameters",
                {"targets": targets, "target_urls": targets, "endpoint_uid": endpoint_a_uid},
            )
            assert counts["records"] == [{"targets": 2, "endpoints": 2, "parameters": 1}]

            links = await client.run_cypher(
                "MATCH (t:Target)-[:HAS_ENDPOINT]->(e:Endpoint) "
                "WHERE t.url IN $targets RETURN t.url AS target, e._target_url AS owner, e.path AS path "
                "ORDER BY target",
                {"targets": targets},
            )
            assert links["records"] == [
                {"target": target_a, "owner": target_a, "path": "/User"},
                {"target": target_b, "owner": target_b, "path": "/User"},
            ]

            subgraph = await client.get_subgraph(target_a, depth=3)
            labels = {label for node in subgraph["nodes"] for label in node["labels"]}
            rel_types = {rel["type"] for rel in subgraph["relationships"]}
            assert {"Target", "Technology", "Endpoint", "Parameter"} <= labels
            assert {"USES", "HAS_ENDPOINT", "HAS_PARAM"} <= rel_types

            with pytest.raises(MCPToolError) as exc_info:
                await client.create_node("Unsupported", {"name": "rejected"})
            assert exc_info.value.code in {"PROTOCOL_ERROR", "VALIDATION_ERROR"}
        finally:
            await _cleanup(client, targets, [technology])


@pytest.mark.asyncio
async def test_tech_recon_persists_through_real_mcp_stdio():
    suffix = uuid4().hex
    target = f"https://agent-{suffix}.invalid"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"server": "nginx"},
                text=(
                    '<html><form action="/login" method="post">'
                    '<input name="username"></form>'
                    '<script>fetch("/api/users")</script></html>'
                ),
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={
                "openapi": "3.0.0",
                "paths": {
                    "/api/users/{id}": {
                        "get": {"parameters": [{"name": "id", "in": "path"}]}
                    }
                },
            })
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        agent = TechReconAgent(
            config={"request_delay_ms": 0, "request_jitter_ms": 0, "max_pages": 4},
            http_client=http_client,
            mcp_client_factory=lambda: Neo4jMCPClient(timeout_s=30),
        )
        result = await agent.execute_async(target)

    assert agent.persistence_status == "success"
    assert "/api/users/{id}" in result["discovered_paths"]

    async with Neo4jMCPClient(timeout_s=30) as client:
        try:
            graph = await client.get_subgraph(target, depth=3)
            endpoints = {
                (node["properties"].get("path"), node["properties"].get("method"))
                for node in graph["nodes"] if "Endpoint" in node["labels"]
            }
            parameters = {
                (node["properties"].get("name"), node["properties"].get("location"))
                for node in graph["nodes"] if "Parameter" in node["labels"]
            }
            assert ("/login", "POST") in endpoints
            assert ("/api/users/{id}", "GET") in endpoints
            assert ("username", "form") in parameters
            assert ("id", "path") in parameters
        finally:
            await _cleanup(client, [target], ["nginx"])
