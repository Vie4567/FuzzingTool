"""
Gobuster Tool Helper Module — Helper chuyên trách chạy Dò quét Directory/DNS/VHost bằng Gobuster CLI / Native fallback.
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


class GobusterToolHelper(BaseToolHelper):
    """Tool Helper chuyên trách đóng gói và thực thi Gobuster CLI."""

    def __init__(self):
        self.knowledge = self._load_knowledge()
        super().__init__(
            name="gobuster_tool",
            description="Dò quét đường dẫn thư mục (mode dir), tên miền phụ (mode dns) và Virtual Host (mode vhost) bằng Gobuster CLI.",
            parameters_schema={
                "target_url": "str (URL hoặc Domain mục tiêu)",
                "mode": "str ('dir', 'dns', 'vhost', mặc định: 'dir')",
                "wordlist": "list (danh sách từ khóa cần quét)",
                "extensions": "str/list (danh sách extension, ví dụ: 'php,html,js')",
                "threads": "int (số luồng song song, mặc định: 10)",
                "status_codes": "str (danh sách status code, ví dụ: '200,301,302,403')",
            },
        )

    def _load_knowledge(self) -> dict:
        kb_path = Path("knowledge/tools/gobuster_knowledge.json")
        if kb_path.exists():
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Không thể đọc gobuster_knowledge.json: {e}")
        return {}

    def run(self, **kwargs) -> ToolResult:
        start_time = time.time()
        target_url = kwargs.get("target_url", "")
        wordlist = kwargs.get("wordlist", [])
        mode = kwargs.get("mode", "dir")

        if not target_url or not wordlist:
            return ToolResult(
                success=False,
                tool_name=self.name,
                result_data={},
                error_message="Thiếu target_url hoặc wordlist rỗng.",
                execution_time=time.time() - start_time,
            )

        output_dir = Path("output_samples")
        output_dir.mkdir(exist_ok=True)
        wl_path = output_dir / "temp_gobuster_wordlist.txt"
        with open(wl_path, "w", encoding="utf-8") as f:
            for w in wordlist:
                f.write(f"{w.strip('/')}\n")

        gobuster_path = shutil.which("gobuster")
        if gobuster_path:
            cmd = ["gobuster", mode]
            if mode == "dns":
                domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
                cmd.extend(["-d", domain])
            else:
                cmd.extend(["-u", target_url])

            cmd.extend(["-w", str(wl_path), "-q", "-k"])

            exts = kwargs.get("extensions")
            if exts:
                cmd.extend(["-x", ",".join(exts) if isinstance(exts, list) else str(exts)])

            threads = kwargs.get("threads")
            if threads:
                cmd.extend(["-t", str(threads)])

            logger.info(f"🚀 [EXECUTING GOBUSTER CLI COMMAND] -> {' '.join(cmd)}")

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    result_data={
                        "engine": "gobuster_cli",
                        "mode": mode,
                        "command_executed": " ".join(cmd),
                        "total_requests": len(wordlist),
                    },
                    raw_output=proc.stdout,
                    execution_time=time.time() - start_time,
                )
            except Exception as exc:
                logger.warning(f"Lỗi khi chạy binary gobuster: {exc}. Fallback sang Native Engine.")

        # Fallback sang Python Fuzzing Engine
        from src.agents.fuzzer import FuzzingAgent
        engine = FuzzingAgent()
        res = engine._run_fuzzing_internal(target_url, wordlist)
        return ToolResult(
            success=True,
            tool_name=self.name,
            result_data={
                "engine": "python_gobuster_fallback",
                "mode": mode,
                "results": res["results"],
            },
            raw_output=f"Native Gobuster Fallback executed for {len(wordlist)} paths",
            execution_time=time.time() - start_time,
        )
