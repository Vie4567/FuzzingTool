"""
HTTPX Tool Helper Module — Helper chuyên trách thăm dò HTTP & Tech-Stack bằng HTTPX CLI / Native fallback.
"""

import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.tools.base_helper import BaseToolHelper, ToolResult

logger = logging.getLogger(__name__)


class HttpxToolHelper(BaseToolHelper):
    """Tool Helper chuyên trách đóng gói và thực thi HTTPX CLI."""

    def __init__(self):
        self.knowledge = self._load_knowledge()
        super().__init__(
            name="httpx_probing_tool",
            description="Thăm dò HTTP tốc độ cao (-sc, -title, -td, -server, -location, -favicon, -follow-redirects). Bóc tách Status Code, Title, Web Server và Tech Stack.",
            parameters_schema={
                "target_url": "str (URL mục tiêu)",
                "status_code": "bool (bật -sc)",
                "title": "bool (bật -title)",
                "tech_detect": "bool (bật -td phát hiện Tech Stack)",
                "follow_redirects": "bool (bật -follow-redirects)",
                "favicon": "bool (bật -favicon mmh3 hash)",
            },
        )

    def _load_knowledge(self) -> dict:
        kb_path = Path("knowledge/tools/httpx_knowledge.json")
        if kb_path.exists():
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Không thể đọc httpx_knowledge.json: {e}")
        return {}

    def _build_cli_command(self, target_url: str, kwargs: Dict[str, Any], output_json: str) -> List[str]:
        cmd = ["httpx", "-u", target_url, "-json", "-o", output_json, "-silent"]

        if kwargs.get("status_code", True):
            cmd.append("-sc")
        if kwargs.get("title", True):
            cmd.append("-title")
        if kwargs.get("tech_detect", True):
            cmd.append("-td")
        if kwargs.get("server", True):
            cmd.append("-server")
        if kwargs.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        if kwargs.get("favicon"):
            cmd.append("-favicon")

        return cmd

    def run(self, **kwargs) -> ToolResult:
        start_time = time.time()
        target_url = kwargs.get("target_url", "")
        if not target_url:
            return ToolResult(
                success=False,
                tool_name=self.name,
                result_data={},
                error_message="Thiếu target_url.",
                execution_time=time.time() - start_time,
            )

        httpx_path = shutil.which("httpx")
        if httpx_path:
            output_dir = Path("output_samples")
            output_dir.mkdir(exist_ok=True)
            output_json = output_dir / "httpx_out.json"

            cmd = self._build_cli_command(target_url, kwargs, str(output_json))
            logger.info(f"🚀 [EXECUTING HTTPX CLI COMMAND] -> {' '.join(cmd)}")

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                parsed_res = {}
                if output_json.exists():
                    with open(output_json, "r", encoding="utf-8") as f:
                        parsed_res = json.load(f)

                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    result_data={
                        "engine": "httpx_cli",
                        "command_executed": " ".join(cmd),
                        "status_code": parsed_res.get("status_code"),
                        "title": parsed_res.get("title"),
                        "web_server": parsed_res.get("webserver"),
                        "tech_detected": parsed_res.get("tech", []),
                    },
                    raw_output=proc.stdout,
                    execution_time=time.time() - start_time,
                )
            except Exception as exc:
                logger.warning(f"Lỗi khi chạy binary httpx: {exc}. Chuyển sang Native Probe Fallback.")

        # Native Probe Fallback
        from src.agents.tech_recon import _fetch_sync
        status, headers, body = _fetch_sync(target_url, timeout=10)
        return ToolResult(
            success=True,
            tool_name=self.name,
            result_data={
                "engine": "native_httpx_fallback",
                "status_code": status,
                "server": headers.get("Server"),
                "content_type": headers.get("Content-Type"),
            },
            raw_output=f"Native HTTP Probe executed for {target_url}",
            execution_time=time.time() - start_time,
        )
