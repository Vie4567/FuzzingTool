"""
Katana Tool Helper Module — Helper chuyên trách Crawl & Parse JS bằng Katana CLI / Native fallback.
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


class KatanaToolHelper(BaseToolHelper):
    """Tool Helper chuyên trách đóng gói và thực thi Katana CLI."""

    def __init__(self):
        self.knowledge = self._load_knowledge()
        super().__init__(
            name="katana_crawler_tool",
            description="Crawl liên kết đệ quy & bóc tách API Endpoints từ JS bundles (-js-crawl, -depth, -json).",
            parameters_schema={
                "target_url": "str (URL mục tiêu)",
                "depth": "int (độ sâu quét đệ quy, mặc định: 2)",
                "js_crawl": "bool (bật -js-crawl bóc tách JS bundles)",
            },
        )

    def _load_knowledge(self) -> dict:
        kb_path = Path("knowledge/tools/katana_knowledge.json")
        if kb_path.exists():
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Không thể đọc katana_knowledge.json: {e}")
        return {}

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

        output_dir = Path("output_samples")
        output_dir.mkdir(exist_ok=True)
        output_json = output_dir / "katana_out.json"

        katana_path = shutil.which("katana")
        if katana_path:
            cmd = ["katana", "-u", target_url, "-json", "-o", str(output_json), "-silent"]
            depth = kwargs.get("depth", 2)
            cmd.extend(["-depth", str(depth)])

            if kwargs.get("js_crawl", True):
                cmd.append("-js-crawl")

            logger.info(f"🚀 [EXECUTING KATANA CLI COMMAND] -> {' '.join(cmd)}")

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                parsed_paths = []
                if output_json.exists():
                    with open(output_json, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.strip():
                                try:
                                    item = json.loads(line)
                                    parsed_paths.append(item.get("endpoint", item.get("request", {}).get("endpoint")))
                                except Exception:
                                    pass

                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    result_data={
                        "engine": "katana_cli",
                        "endpoints": [p for p in parsed_paths if p],
                        "total_found": len(parsed_paths),
                    },
                    raw_output=proc.stdout,
                    execution_time=time.time() - start_time,
                )
            except Exception as exc:
                logger.warning(f"Lỗi khi chạy binary katana: {exc}. Fallback sang Native Spider/JS Parser Engine.")

        # Fallback sang Native TechRecon JS Parser
        from src.agents.tech_recon import TechReconAgent
        agent = TechReconAgent()
        res = agent._ch3_js_bundle_analyzer(target_url, [], timeout=10)
        return ToolResult(
            success=True,
            tool_name=self.name,
            result_data={
                "engine": "python_katana_fallback",
                "endpoints": res.get("paths", []),
            },
            raw_output=f"Native Katana JS Fallback executed for {target_url}",
            execution_time=time.time() - start_time,
        )
