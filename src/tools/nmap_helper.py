"""
Nmap Tool Helper Module — Helper chuyên trách quét cổng & dịch vụ bằng Nmap CLI / Native probe fallback.
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


class NmapToolHelper(BaseToolHelper):
    """Tool Helper chuyên trách đóng gói và thực thi Nmap CLI."""

    def __init__(self):
        self.knowledge = self._load_knowledge()
        super().__init__(
            name="nmap_scanning_tool",
            description="Quét cổng, nhận diện phiên bản dịch vụ Web (-sV), kiểm tra SSL/TLS và phát hiện WAF qua NSE scripts (http-enum, http-headers, http-methods, http-waf-detect).",
            parameters_schema={
                "target_url": "str (URL hoặc IP mục tiêu)",
                "ports": "str (cổng quét, ví dụ: '80,443' hoặc '1-65535')",
                "scripts": "str (danh sách NSE script, ví dụ: 'http-enum,http-headers,http-methods')",
                "timing": "str (mức độ thời gian: T0 -> T5, mặc định T3)",
                "version_detection": "bool (bật -sV)",
            },
        )

    def _load_knowledge(self) -> dict:
        kb_path = Path("knowledge/tools/nmap_knowledge.json")
        if kb_path.exists():
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Không thể đọc nmap_knowledge.json: {e}")
        return {}

    def _build_cli_command(self, target_host: str, kwargs: Dict[str, Any], output_xml: str) -> List[str]:
        cmd = ["nmap", target_host]
        ports = kwargs.get("ports", "80,443")
        cmd.extend(["-p", str(ports)])

        timing = kwargs.get("timing", "T3")
        cmd.append(f"-{timing}")

        if kwargs.get("version_detection", True):
            cmd.append("-sV")

        scripts = kwargs.get("scripts")
        if scripts:
            cmd.extend(["--script", str(scripts)])

        cmd.extend(["-oX", output_xml])
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

        # Lấy host từ URL
        host = target_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        nmap_path = shutil.which("nmap")
        if nmap_path:
            output_dir = Path("output_samples")
            output_dir.mkdir(exist_ok=True)
            output_xml = output_dir / "nmap_out.xml"

            cmd = self._build_cli_command(host, kwargs, str(output_xml))
            logger.info(f"🚀 [EXECUTING NMAP CLI COMMAND] -> {' '.join(cmd)}")

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    result_data={
                        "engine": "nmap_cli",
                        "command_executed": " ".join(cmd),
                        "host": host,
                        "raw_output": proc.stdout[:1000],
                    },
                    raw_output=proc.stdout,
                    execution_time=time.time() - start_time,
                )
            except Exception as exc:
                logger.warning(f"Lỗi khi chạy binary nmap: {exc}. Chuyển sang Native Probe Fallback.")

        # Native Probe Fallback
        from src.agents.tech_recon import _fetch_sync
        status, headers, body = _fetch_sync(target_url, timeout=10)
        return ToolResult(
            success=True,
            tool_name=self.name,
            result_data={
                "engine": "native_nmap_fallback",
                "host": host,
                "open_ports": [80 if "http://" in target_url else 443],
                "http_status": status,
                "server_header": headers.get("Server"),
            },
            raw_output=f"Native Nmap Probe executed for {host}",
            execution_time=time.time() - start_time,
        )
