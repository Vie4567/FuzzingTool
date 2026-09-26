"""
src/clients/neo4j_mcp_client.py — MCP Client Wrapper cho Neo4j MCP Server.

Wrapper nhỏ, dễ mock khi test, dùng async context manager.

Nguyên tắc:
  - Không gọi Neo4j driver trực tiếp
  - Kết nối MCP Server qua stdio (spawn subprocess)
  - Một agent execution = một MCP session = nhiều tool calls
  - Disconnect sạch khi kết thúc (context manager)
  - Dependency injectable (server_script có thể override khi test)

Ví dụ sử dụng:
    async with Neo4jMCPClient() as client:
        await client.create_node("Target", {"url": "https://example.com"})
        await client.create_relationship(
            from_label="Target",
            from_key={"url": "https://example.com"},
            rel_type="USES",
            to_label="Technology",
            to_key={"name": "Django"},
        )
        data = await client.get_subgraph("https://example.com", depth=2)

Được inject vào TechReconAgent; lỗi persistence không làm mất kết quả recon.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from mcp import ClientSession, StdioServerParameters, stdio_client

logger = logging.getLogger(__name__)


# Đường dẫn mặc định tới server script
_DEFAULT_SERVER_SCRIPT = str(
    Path(__file__).parent.parent / "mcp_servers" / "neo4j_server.py"
)


class Neo4jMCPClient:
    """
    Async context manager wrapping MCP ClientSession cho Neo4j server.

    Mỗi lần `async with Neo4jMCPClient()` tạo một MCP session duy nhất,
    thực hiện nhiều tool calls, rồi disconnect sạch khi thoát context.

    Args:
        server_script: Đường dẫn tới neo4j_server.py (injectable để test)
        env: Optional dict env vars truyền cho server process.
             Nếu None, kế thừa os.environ.
    """

    def __init__(
        self,
        server_script: str | None = None,
        env: dict[str, str] | None = None,
        timeout_s: float = 15,
    ):
        self._server_script = server_script or _DEFAULT_SERVER_SCRIPT
        self._env = env  # None = inherit current process env
        self._timeout_s = timeout_s
        self._stack = None
        self._session: ClientSession | None = None
        self._cm = None  # context manager từ stdio_client

    async def __aenter__(self) -> "Neo4jMCPClient":
        await self._connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._disconnect()

    async def _connect(self) -> None:
        """Khởi động MCP server subprocess và tạo session."""
        # Build env: merge os.environ với override
        server_env = dict(os.environ)
        if self._env:
            server_env.update(self._env)

        params = StdioServerParameters(
            command=sys.executable,
            args=(["-m", "src.mcp_servers.neo4j_server"]
                  if self._server_script == _DEFAULT_SERVER_SCRIPT else [self._server_script]),
            env=server_env,
            cwd=str(Path(__file__).resolve().parents[2]),
        )

        logger.info(f"[Neo4jMCPClient] Connecting to MCP server: {self._server_script}")
        stack = AsyncExitStack()
        try:
            read, write = await stack.enter_async_context(stdio_client(params))
            self._session = await stack.enter_async_context(
                ClientSession(read, write, read_timeout_seconds=self._timeout_s)
            )
            await self._session.initialize()
        except BaseException:
            await stack.aclose()
            self._session = None
            raise
        self._stack = stack
        logger.info("[Neo4jMCPClient] MCP session initialized")

    async def _disconnect(self) -> None:
        """Đóng session và subprocess sạch."""
        stack = getattr(self, "_stack", None)
        if stack is not None:
            try:
                await stack.aclose()
            finally:
                self._stack = None
                self._session = None
                self._cm = None
            return
        try:
            if self._session is not None:
                await self._session.__aexit__(None, None, None)
        except Exception as e:
            logger.warning(f"[Neo4jMCPClient] Error closing session: {e}")
        finally:
            self._session = None

        try:
            if self._cm is not None:
                await self._cm.__aexit__(None, None, None)
        except Exception as e:
            logger.warning(f"[Neo4jMCPClient] Error closing stdio client: {e}")
        finally:
            self._cm = None

        logger.info("[Neo4jMCPClient] Disconnected")

    def _ensure_connected(self) -> None:
        if self._session is None:
            raise RuntimeError(
                "Neo4jMCPClient không ở trong context manager. "
                "Sử dụng: async with Neo4jMCPClient() as client: ..."
            )

    async def _call_tool(self, tool_name: str, arguments: dict) -> Any:
        """Gọi một MCP tool và parse kết quả JSON."""
        self._ensure_connected()
        result = await self._session.call_tool(tool_name, arguments)

        if getattr(result, "is_error", False) is True:
            message = " ".join(getattr(item, "text", "") for item in result.content)
            raise MCPToolError(tool_name, "PROTOCOL_ERROR", message)

        # Lấy text content đầu tiên
        if not result.content:
            return None

        raw_text = result.content[0].text
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            raise MCPToolError(tool_name, "INVALID_RESPONSE", "Expected a JSON result envelope")

        if not isinstance(parsed, dict):
            raise MCPToolError(tool_name, "INVALID_RESPONSE", "Expected a JSON object")

        # Propagate error từ server
        if parsed.get("status") == "error":
            code = parsed.get("code", "ERROR")
            message = parsed.get("message", "Unknown error")
            raise MCPToolError(tool_name=tool_name, code=code, message=message)

        if parsed.get("status") != "ok":
            raise MCPToolError(tool_name, "INVALID_RESPONSE", "Missing result status")
        return parsed.get("data")

    # ── Public API ────────────────────────────────────────────────────────────

    async def create_node(self, label: str, properties: dict) -> dict:
        """
        Tạo hoặc merge node trong Neo4j.

        Returns:
            dict với node_id, label, properties
        """
        return await self._call_tool("create_node", {
            "label": label,
            "properties": properties,
        })

    async def create_relationship(
        self,
        from_label: str,
        from_key: dict,
        rel_type: str,
        to_label: str,
        to_key: dict,
        properties: dict | None = None,
    ) -> dict:
        """
        Tạo hoặc merge relationship giữa 2 nodes.

        Returns:
            dict với rel_type, rel_id
        """
        args: dict = {
            "from_label": from_label,
            "from_key": from_key,
            "rel_type": rel_type,
            "to_label": to_label,
            "to_key": to_key,
        }
        if properties:
            args["properties"] = properties
        return await self._call_tool("create_relationship", args)

    async def run_cypher(self, query: str, params: dict | None = None) -> dict:
        """
        Thực thi Cypher với tham số tách biệt.

        Returns:
            dict với records (list) và count
        """
        args = {"query": query}
        if params:
            args["params"] = params
        return await self._call_tool("run_cypher", args)

    async def get_subgraph(self, target_url: str, depth: int = 2) -> dict:
        """
        Lấy subgraph của Target URL.

        Returns:
            dict với nodes, relationships, counts
        """
        return await self._call_tool("get_subgraph", {
            "target_url": target_url,
            "depth": depth,
        })

    async def get_graph_schema(self) -> dict:
        """Đọc graph schema resource từ MCP server."""
        self._ensure_connected()
        result = await self._session.read_resource("sentinel://graph/schema")
        if result.contents:
            raw = result.contents[0].text
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {"raw": raw}
        return {}


class MCPToolError(Exception):
    """Lỗi trả về từ MCP tool call (status == 'error')."""

    def __init__(self, tool_name: str, code: str, message: str):
        super().__init__(f"[{tool_name}] {code}: {message}")
        self.tool_name = tool_name
        self.code = code
        self.message = message


# ── Factory helper ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def neo4j_mcp_session(
    server_script: str | None = None,
    env: dict[str, str] | None = None,
) -> AsyncIterator[Neo4jMCPClient]:
    """
    Convenience context manager — alias cho Neo4jMCPClient.

    Ví dụ:
        async with neo4j_mcp_session() as client:
            await client.create_node(...)
    """
    async with Neo4jMCPClient(server_script=server_script, env=env) as client:
        yield client
