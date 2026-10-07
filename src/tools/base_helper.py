"""
Base Tool Helper Module — Lớp cơ sở cho các Tool Helpers thực thi công cụ.

ToolHelper chịu trách nhiệm:
1. Đóng gói tham số và quy đổi thành cờ CLI (nếu dùng tool CLI như ffuf, nmap, httpx) hoặc lệnh Python.
2. Thực thi lệnh thật (subprocess / native Python).
3. Thu thập stdout, stderr, status code.
4. Parse và chuẩn hóa kết quả thành định dạng JSON chuẩn (ToolResult).
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolResult:
    """Đại diện cho kết quả thực thi công cụ trả về cho Agent."""

    def __init__(
        self,
        success: bool,
        tool_name: str,
        result_data: Dict[str, Any],
        raw_output: str = "",
        error_message: Optional[str] = None,
        execution_time: float = 0.0,
    ):
        self.success = success
        self.tool_name = tool_name
        self.result_data = result_data
        self.raw_output = raw_output
        self.error_message = error_message
        self.execution_time = execution_time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "result_data": self.result_data,
            "raw_output_snippet": self.raw_output[:500] if self.raw_output else "",
            "error_message": self.error_message,
            "execution_time": self.execution_time,
        }


class BaseToolHelper:
    """Lớp cơ sở cho mọi Tool Helper."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters_schema: Dict[str, Any],
    ):
        self.name = name
        self.description = description
        self.parameters_schema = parameters_schema

    def get_schema(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters_schema": self.parameters_schema,
        }

    def run(self, **kwargs) -> ToolResult:
        """Thực thi công cụ với các tham số do Agent chỉ định."""
        raise NotImplementedError("Subclasses must implement run()")
