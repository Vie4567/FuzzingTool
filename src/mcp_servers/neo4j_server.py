"""Neo4j MCP server: four JSON-RPC tools and one schema resource over stdio."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Literal

from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

from src.graph_schema import (
    ALLOWED_LABELS, ALLOWED_RELATIONSHIPS, GRAPH_SCHEMA, RELATIONSHIP_LABELS,
    endpoint_uid as _compute_endpoint_uid, identity_key, normalize_target_url, prepare_properties,
)

load_dotenv()
logger = logging.getLogger(__name__)
mcp = MCPServer("sentinel-neo4j")
_driver = None

Label = Literal["Target", "Technology", "Endpoint", "Parameter", "Finding"]
Relationship = Literal["USES", "HAS_ENDPOINT", "HAS_PARAM", "LINKS_TO", "FLAGGED_AS"]


def _validate_label(label):
    if label not in ALLOWED_LABELS:
        raise ValueError(f"Unsupported label: {label}")


def _validate_relationship(rel_type):
    if rel_type not in ALLOWED_RELATIONSHIPS:
        raise ValueError(f"Unsupported relationship: {rel_type}")


def _validate_identifier(value, name="identifier"):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError(f"Invalid {name}: {value}")


def _get_identity_key(label, properties):
    return identity_key(label, properties)


def _json_default(value):
    if hasattr(value, "iso_format"):
        return value.iso_format()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def _error_response(message, code="ERROR"):
    return json.dumps({"status": "error", "code": code, "message": message})


def _ok_response(data):
    return json.dumps({"status": "ok", "data": data}, default=_json_default)


def _get_neo4j_driver():
    from neo4j import AsyncGraphDatabase
    return AsyncGraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "neo4j")),
        connection_timeout=3, connection_acquisition_timeout=5,
    )


async def _get_driver():
    global _driver
    if _driver is None:
        _driver = _get_neo4j_driver()
    return _driver


def _validated_properties(label, properties, *, lookup=False):
    _validate_label(label)
    for key in properties:
        _validate_identifier(key)
    return prepare_properties(label, properties, lookup=lookup)


@mcp.tool(name="create_node", description=(
    "MERGE a node by its unique identity. Endpoint requires path/method/_target_url; "
    "Parameter requires name/location/_endpoint_uid; Finding requires "
    "type/severity/description/_endpoint_uid. Target requires url; Technology requires name/category."
))
async def create_node(label: Label, properties: dict) -> str:
    try:
        props = _validated_properties(label, properties)
        if label == "Target":
            props.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        key, value = identity_key(label, props)
        create_props = {k: v for k, v in props.items() if k != key and v is not None}
        update_props = {k: v for k, v in create_props.items() if k != "created_at"}
        query = (
            f"MERGE (n:{label} {{{key}: $identity}}) "
            "ON CREATE SET n += $create_props "
            "ON MATCH SET n += $update_props "
            "RETURN elementId(n) AS node_id, properties(n) AS properties"
        )
        driver = await _get_driver()
        async with driver.session() as session:
            result = await session.run(query, parameters={
                "identity": value, "create_props": create_props, "update_props": update_props,
            })
            record = await result.single()
        return _ok_response({"node_id": record["node_id"], "label": label, "properties": record["properties"]})
    except (ValueError, TypeError) as exc:
        return _error_response(str(exc), "VALIDATION_ERROR")
    except Exception as exc:
        logger.warning("create_node failed: %s", exc)
        return _error_response(str(exc), "NEO4J_ERROR")


@mcp.tool(name="create_relationship", description=(
    "MERGE a schema relationship between existing nodes. Keys must uniquely identify nodes: "
    "url for Target, name for Technology, _uid (or all identity properties) for scoped nodes."
))
async def create_relationship(
    from_label: Label, from_key: dict, rel_type: Relationship,
    to_label: Label, to_key: dict, properties: dict | None = None,
) -> str:
    try:
        _validate_relationship(rel_type)
        if RELATIONSHIP_LABELS[rel_type] != (from_label, to_label):
            raise ValueError("Relationship labels do not match the graph schema")
        left = _validated_properties(from_label, from_key, lookup=True)
        right = _validated_properties(to_label, to_key, lookup=True)
        left_key, left_value = identity_key(from_label, left)
        right_key, right_value = identity_key(to_label, right)
        rel_props = dict(properties or {})
        for key in rel_props:
            _validate_identifier(key)
        scope = {
            "HAS_ENDPOINT": " WHERE b._target_url = a.url ",
            "HAS_PARAM": " WHERE b._endpoint_uid = a._uid ",
            "FLAGGED_AS": " WHERE b._endpoint_uid = a._uid ",
            "LINKS_TO": " WHERE a._target_url = b._target_url ",
        }.get(rel_type, " ")
        query = (
            f"MATCH (a:{from_label} {{{left_key}: $left}}) WITH a "
            f"MATCH (b:{to_label} {{{right_key}: $right}})"
            + scope + f"MERGE (a)-[r:{rel_type}]->(b) SET r += $props "
            "RETURN type(r) AS rel_type, elementId(r) AS rel_id"
        )
        driver = await _get_driver()
        async with driver.session() as session:
            result = await session.run(query, parameters={"left": left_value, "right": right_value, "props": rel_props})
            record = await result.single()
        if record is None:
            return _error_response("Nodes not found or relationship crosses endpoint/target scope", "NODE_NOT_FOUND")
        return _ok_response({"rel_type": record["rel_type"], "rel_id": record["rel_id"]})
    except (ValueError, TypeError) as exc:
        return _error_response(str(exc), "VALIDATION_ERROR")
    except Exception as exc:
        logger.warning("create_relationship failed: %s", exc)
        return _error_response(str(exc), "NEO4J_ERROR")


@mcp.tool(name="run_cypher", description=(
    "Execute parameterized Cypher on the local graph. Intended for context queries; "
    "callers may run arbitrary Cypher. Agent 1 writes only through MERGE node/relationship tools."
))
async def run_cypher(query: str, params: dict | None = None) -> str:
    try:
        if not query.strip():
            raise ValueError("Query must not be empty")
        driver = await _get_driver()
        async with driver.session() as session:
            result = await session.run(query, parameters=params or {})
            records = await result.data()
        return _ok_response({"records": records, "count": len(records)})
    except (ValueError, TypeError) as exc:
        return _error_response(str(exc), "VALIDATION_ERROR")
    except Exception as exc:
        logger.warning("run_cypher failed: %s", exc)
        return _error_response(str(exc), "NEO4J_ERROR")


@mcp.tool(name="get_subgraph", description="Read the directed Target subgraph at depth 1-5 (default 2).")
async def get_subgraph(target_url: str, depth: int = 2) -> str:
    try:
        target_url = normalize_target_url(target_url)
        if not isinstance(depth, int) or isinstance(depth, bool) or not 1 <= depth <= 5:
            raise ValueError("depth must be an integer in 1..5")
        # Outgoing traversal cannot jump from a shared Technology to another Target.
        query = (
            "MATCH (t:Target {url: $url}) "
            f"OPTIONAL MATCH path = (t)-[*1..{depth}]->(n) "
            "WHERE all(rel IN relationships(path) WHERE type(rel) IN $rel_types) "
            "AND all(ep IN nodes(path) WHERE NOT ep:Endpoint OR ep._target_url = $url) "
            "RETURN t, collect(DISTINCT n) AS neighbors, collect(relationships(path)) AS rel_lists"
        )
        driver = await _get_driver()
        async with driver.session() as session:
            result = await session.run(query, parameters={
                "url": target_url,
                "rel_types": sorted(ALLOWED_RELATIONSHIPS),
            })
            record = await result.single()
        nodes, rels = {}, {}
        if record:
            for node in [record["t"], *record["neighbors"]]:
                if node is not None:
                    nodes[node.element_id] = {"id": node.element_id, "labels": list(node.labels), "properties": dict(node)}
            for group in record["rel_lists"]:
                for rel in group or []:
                    rels[rel.element_id] = {
                        "id": rel.element_id, "type": rel.type, "start": rel.start_node.element_id,
                        "end": rel.end_node.element_id, "properties": dict(rel),
                    }
        return _ok_response({"target_url": target_url, "depth": depth, "nodes": list(nodes.values()),
                             "relationships": list(rels.values()), "node_count": len(nodes), "relationship_count": len(rels)})
    except (ValueError, TypeError) as exc:
        return _error_response(str(exc), "VALIDATION_ERROR")
    except Exception as exc:
        logger.warning("get_subgraph failed: %s", exc)
        return _error_response(str(exc), "NEO4J_ERROR")


@mcp.resource("sentinel://graph/schema", name="Graph Schema", mime_type="application/json")
async def graph_schema() -> str:
    return json.dumps(GRAPH_SCHEMA, indent=2)


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    try:
        await mcp.run_stdio_async()
    finally:
        if _driver is not None:
            await _driver.close()


if __name__ == "__main__":
    asyncio.run(main())
