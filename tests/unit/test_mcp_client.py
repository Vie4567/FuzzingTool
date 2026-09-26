"""
tests/unit/test_mcp_client.py — Unit tests cho Neo4jMCPClient wrapper.

Test mà KHÔNG spawn MCP subprocess thật.
Mock ClientSession để kiểm tra behavior của wrapper.

Coverage:
  ✓ _ensure_connected raise nếu không ở trong context manager
  ✓ _call_tool parse JSON thành công
  ✓ _call_tool raise MCPToolError khi status == error
  ✓ create_node gọi tool đúng arguments
  ✓ create_relationship gọi tool đúng arguments
  ✓ run_cypher gọi tool đúng arguments
  ✓ get_subgraph gọi tool đúng arguments
  ✓ MCPToolError mang đúng code và message
  ✓ Disconnect sạch ngay cả khi session raise exception
"""

import json
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.clients.neo4j_mcp_client import Neo4jMCPClient, MCPToolError


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_mock_session(tool_response_data: dict | None = None, error: dict | None = None):
    """Tạo mock ClientSession trả về response cụ thể."""
    session = AsyncMock()

    if error:
        payload = json.dumps({"status": "error", "code": error["code"], "message": error["message"]})
    else:
        payload = json.dumps({"status": "ok", "data": tool_response_data or {}})

    content_item = MagicMock()
    content_item.text = payload

    tool_result = MagicMock()
    tool_result.content = [content_item]

    session.call_tool = AsyncMock(return_value=tool_result)
    session.initialize = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)

    return session


def _make_client_with_mock_session(session_mock) -> Neo4jMCPClient:
    """Tạo Neo4jMCPClient với session đã được inject."""
    client = Neo4jMCPClient.__new__(Neo4jMCPClient)
    client._server_script = "fake_server.py"
    client._env = None
    client._session = session_mock
    client._cm = None
    return client


# ─── ensure_connected ─────────────────────────────────────────────────────────

class TestEnsureConnected:
    def test_raises_if_no_session(self):
        """Gọi tool khi không ở trong context → RuntimeError."""
        client = Neo4jMCPClient.__new__(Neo4jMCPClient)
        client._session = None
        client._cm = None

        with pytest.raises(RuntimeError, match="context manager"):
            client._ensure_connected()

    def test_no_raise_if_session_set(self):
        """Có session → không raise."""
        client = Neo4jMCPClient.__new__(Neo4jMCPClient)
        client._session = MagicMock()
        client._ensure_connected()  # không raise


# ─── _call_tool ───────────────────────────────────────────────────────────────

class TestCallTool:
    @pytest.mark.asyncio
    async def test_successful_call_returns_data(self):
        """Khi server trả ok, _call_tool trả về data."""
        session = _make_mock_session(tool_response_data={"node_id": 99})
        client = _make_client_with_mock_session(session)

        result = await client._call_tool("create_node", {"label": "Target", "properties": {}})
        assert result == {"node_id": 99}
        session.call_tool.assert_called_once_with("create_node", {"label": "Target", "properties": {}})

    @pytest.mark.asyncio
    async def test_error_response_raises_mcp_tool_error(self):
        """Khi server trả error, _call_tool raise MCPToolError."""
        session = _make_mock_session(error={"code": "VALIDATION_ERROR", "message": "bad label"})
        client = _make_client_with_mock_session(session)

        with pytest.raises(MCPToolError) as exc_info:
            await client._call_tool("create_node", {})

        err = exc_info.value
        assert err.code == "VALIDATION_ERROR"
        assert "bad label" in err.message

    @pytest.mark.asyncio
    async def test_empty_content_returns_none_data(self):
        """Server trả về content rỗng → data = None."""
        session = AsyncMock()
        tool_result = MagicMock()
        tool_result.content = []
        session.call_tool = AsyncMock(return_value=tool_result)
        session.initialize = AsyncMock()

        client = _make_client_with_mock_session(session)
        result = await client._call_tool("test_tool", {})
        # Khi content rỗng, wrapper trả {"status":"ok","data":None} → .get("data") = None
        assert result is None



# ─── create_node ─────────────────────────────────────────────────────────────

class TestCreateNode:
    @pytest.mark.asyncio
    async def test_create_node_passes_correct_args(self):
        session = _make_mock_session(tool_response_data={"node_id": 1, "label": "Target"})
        client = _make_client_with_mock_session(session)

        await client.create_node("Target", {"url": "https://example.com"})

        session.call_tool.assert_called_once_with(
            "create_node",
            {"label": "Target", "properties": {"url": "https://example.com"}},
        )

    @pytest.mark.asyncio
    async def test_create_node_returns_data(self):
        expected = {"node_id": 42, "label": "Technology", "properties": {"name": "Django"}}
        session = _make_mock_session(tool_response_data=expected)
        client = _make_client_with_mock_session(session)

        result = await client.create_node("Technology", {"name": "Django"})
        assert result == expected


# ─── create_relationship ──────────────────────────────────────────────────────

class TestCreateRelationship:
    @pytest.mark.asyncio
    async def test_passes_correct_args_without_properties(self):
        session = _make_mock_session(tool_response_data={"rel_type": "USES", "rel_id": 5})
        client = _make_client_with_mock_session(session)

        await client.create_relationship(
            from_label="Target",
            from_key={"url": "https://example.com"},
            rel_type="USES",
            to_label="Technology",
            to_key={"name": "Django"},
        )

        call_args = session.call_tool.call_args
        args = call_args[0][1]  # second positional arg = arguments dict
        assert args["from_label"] == "Target"
        assert args["rel_type"] == "USES"
        assert args["to_label"] == "Technology"
        assert "properties" not in args  # không có properties → không truyền

    @pytest.mark.asyncio
    async def test_passes_properties_when_provided(self):
        session = _make_mock_session(tool_response_data={"rel_id": 10})
        client = _make_client_with_mock_session(session)

        await client.create_relationship(
            from_label="Endpoint",
            from_key={"_uid": "abc123"},
            rel_type="HAS_PARAM",
            to_label="Parameter",
            to_key={"name": "id"},
            properties={"discovered_at": "2024-01-01"},
        )

        call_args = session.call_tool.call_args[0][1]
        assert call_args["properties"] == {"discovered_at": "2024-01-01"}


# ─── run_cypher ───────────────────────────────────────────────────────────────

class TestRunCypher:
    @pytest.mark.asyncio
    async def test_run_cypher_passes_query_and_params(self):
        session = _make_mock_session(tool_response_data={"records": [], "count": 0})
        client = _make_client_with_mock_session(session)

        await client.run_cypher(
            "MATCH (t:Target {url: $url}) RETURN t",
            params={"url": "https://example.com"},
        )

        call_args = session.call_tool.call_args[0][1]
        assert call_args["query"] == "MATCH (t:Target {url: $url}) RETURN t"
        assert call_args["params"] == {"url": "https://example.com"}

    @pytest.mark.asyncio
    async def test_run_cypher_without_params(self):
        session = _make_mock_session(tool_response_data={"records": [], "count": 0})
        client = _make_client_with_mock_session(session)

        await client.run_cypher("MATCH (n) RETURN count(n)")

        call_args = session.call_tool.call_args[0][1]
        assert "params" not in call_args


# ─── get_subgraph ────────────────────────────────────────────────────────────

class TestGetSubgraph:
    @pytest.mark.asyncio
    async def test_get_subgraph_default_depth(self):
        session = _make_mock_session(tool_response_data={
            "target_url": "https://example.com",
            "depth": 2,
            "nodes": [],
            "relationships": [],
        })
        client = _make_client_with_mock_session(session)

        await client.get_subgraph("https://example.com")

        call_args = session.call_tool.call_args[0][1]
        assert call_args["target_url"] == "https://example.com"
        assert call_args["depth"] == 2

    @pytest.mark.asyncio
    async def test_get_subgraph_custom_depth(self):
        session = _make_mock_session(tool_response_data={"nodes": [], "relationships": []})
        client = _make_client_with_mock_session(session)

        await client.get_subgraph("https://example.com", depth=3)

        call_args = session.call_tool.call_args[0][1]
        assert call_args["depth"] == 3


# ─── MCPToolError ─────────────────────────────────────────────────────────────

class TestMCPToolError:
    def test_error_message_format(self):
        err = MCPToolError(
            tool_name="create_node",
            code="VALIDATION_ERROR",
            message="Label 'Admin' không được phép",
        )
        assert "create_node" in str(err)
        assert "VALIDATION_ERROR" in str(err)

    def test_error_attributes(self):
        err = MCPToolError("run_cypher", "WRITE_NOT_ALLOWED", "Only READ queries")
        assert err.tool_name == "run_cypher"
        assert err.code == "WRITE_NOT_ALLOWED"
        assert err.message == "Only READ queries"

    def test_is_exception(self):
        err = MCPToolError("tool", "CODE", "msg")
        assert isinstance(err, Exception)


# ─── Disconnect cleanup ───────────────────────────────────────────────────────

class TestDisconnectCleanup:
    @pytest.mark.asyncio
    async def test_disconnect_clears_session(self):
        """Sau _disconnect(), session và cm phải None."""
        session = AsyncMock()
        session.__aexit__ = AsyncMock(return_value=False)

        cm = AsyncMock()
        cm.__aexit__ = AsyncMock(return_value=False)

        client = Neo4jMCPClient.__new__(Neo4jMCPClient)
        client._session = session
        client._cm = cm

        await client._disconnect()

        assert client._session is None
        assert client._cm is None

    @pytest.mark.asyncio
    async def test_disconnect_tolerates_session_error(self):
        """_disconnect() không raise dù session.__aexit__ lỗi."""
        session = AsyncMock()
        session.__aexit__ = AsyncMock(side_effect=RuntimeError("connection lost"))

        client = Neo4jMCPClient.__new__(Neo4jMCPClient)
        client._session = session
        client._cm = None

        # Không raise — disconnect phải luôn sạch
        await client._disconnect()
        assert client._session is None
