"""
Arjun Tool Helper Module — Helper chuyên trách dò tìm tham số ẩn (Parameter Discovery) bằng Arjun CLI / Native fallback.
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


class ArjunToolHelper(BaseToolHelper):
    """Tool Helper chuyên trách đóng gói và thực thi Arjun CLI."""

    def __init__(self):
        self.knowledge = self._load_knowledge()
        super().__init__(
            name="arjun_param_discovery_tool",
            description="Dò tìm các tham số HTTP GET/POST/JSON ẩn bằng Arjun CLI hoặc Native Engine.",
            parameters_schema={
                "target_url": "str (URL mục tiêu cần tìm tham số)",
                "method": "str (GET, POST, JSON, XML, mặc định: GET)",
                "threads": "int (số luồng song song, mặc định: 5)",
                "delay": "float (độ trễ giữa các request tính bằng giây)",
            },
        )

    def _load_knowledge(self) -> dict:
        kb_path = Path("knowledge/tools/arjun_knowledge.json")
        if kb_path.exists():
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Không thể đọc arjun_knowledge.json: {e}")
        return {}

    def run(self, **kwargs) -> ToolResult:
        start_time = time.time()
        target_url = kwargs.get("target_url", "")
        method = kwargs.get("method", "GET").upper()

        if not target_url:
            return ToolResult(
                success=False,
                tool_name=self.name,
                result_data={},
                error_message="Thiếu target_url.",
                execution_time=time.time() - start_time,
            )

        output_dir = Path("output_samples")
        output_dir.mkdir(exist_ok=True)
        output_json = output_dir / "arjun_out.json"

        arjun_path = shutil.which("arjun")
        if arjun_path:
            cmd = ["arjun", "-u", target_url, "-m", method, "-oJ", str(output_json)]
            threads = kwargs.get("threads")
            if threads:
                cmd.extend(["-t", str(threads)])

            delay = kwargs.get("delay")
            if delay:
                cmd.extend(["-d", str(delay)])

            logger.info(f"🚀 [EXECUTING ARJUN CLI COMMAND] -> {' '.join(cmd)}")

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                parsed_res = {}
                if output_json.exists():
                    with open(output_json, "r", encoding="utf-8") as f:
                        parsed_res = json.load(f)

                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    result_data={
                        "engine": "arjun_cli",
                        "method": method,
                        "discovered_params": parsed_res,
                    },
                    raw_output=proc.stdout,
                    execution_time=time.time() - start_time,
                )
            except Exception as exc:
                logger.warning(f"Lỗi khi chạy binary arjun: {exc}. Fallback sang Native Param Discovery Engine.")

        # Fallback sang Python Param Discovery Engine
        from src.agents.param_discovery import ParamDiscoveryAgent
        engine = ParamDiscoveryAgent()
        res = engine._run_param_discovery_internal(target_url, [target_url])
        return ToolResult(
            success=True,
            tool_name=self.name,
            result_data={
                "engine": "python_arjun_fallback",
                "method": method,
                "param_results": res.get("param_results", []),
            },
            raw_output=f"Native Arjun Fallback executed for {target_url}",
            execution_time=time.time() - start_time,
        )
