"""
FFUF Tool Helper Module — Helper chuyên trách chạy Fuzzing bằng FFUF CLI hoặc Python Engine fallback.

Tự động chuyển đổi các options được Agent chọn dựa trên Tri thức FFUF (ffuf_knowledge.json):
  - Lọc theo status code (-mc, -fc), size (-fs), words (-fw), lines (-fl)
  - Tự động hiệu chỉnh Auto-calibration (-ac)
  - Quét extensions (-e .php,.html) & đệ quy (-recursion -recursion-depth)
  - Né tránh WAF: (-rate, -p, -t, -H, -x)
  - Fuzzing POST Data & Parameters (-X POST -d ...)
"""

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.tools.base_helper import BaseToolHelper, ToolResult

logger = logging.getLogger(__name__)


class FfufToolHelper(BaseToolHelper):
    """Tool Helper chuyên trách đóng gói và thực thi công cụ FFUF dựa trên Tri thức FFUF Knowledge Base."""

    def __init__(self):
        # Load FFUF Knowledge Base
        self.knowledge = self._load_ffuf_knowledge()
        super().__init__(
            name="ffuf_fuzzing_tool",
            description=(
                "Thực thi Fuzzing quét đường dẫn/subdomain/parameter bằng lệnh ffuf CLI hoặc Python Engine. "
                "Hỗ trợ đầy đủ cờ CLI: -e (extensions), -ac (auto-calibrate), -mc/-fc (match/filter code), "
                "-fs (filter size), -recursion, -rate, -p (delay), -t (threads), -X (POST method), -d (POST data)."
            ),
            parameters_schema={
                "target_url": "str (bắt buộc, ví dụ: https://example.com/ hoặc chứa từ khóa FUZZ)",
                "wordlist": "list (danh sách từ khóa cần fuzzing)",
                "extensions": "list/str (đuôi mở rộng file, ví dụ: ['.php', '.html', '.bak'])",
                "auto_calibrate": "bool (bật -ac để tự động loại bỏ response ngẫu nhiên)",
                "match_codes": "str/list (status code cần giữ lại, ví dụ: '200,301,302,403')",
                "filter_codes": "str/list (status code cần lọc bỏ, ví dụ: '404')",
                "filter_size": "str/int (lọc loại bỏ theo kích thước response size, ví dụ: 1234)",
                "recursion": "bool (bật quét đệ quy thư mục -recursion)",
                "recursion_depth": "int (độ sâu quét đệ quy, ví dụ: 2)",
                "threads": "int (số luồng song song -t, mặc định: 40)",
                "rate_limit": "int (số request/s -rate, mặc định: 50)",
                "delay_ms": "int (độ trễ giữa các request tính bằng ms -p)",
                "http_method": "str (phương thức HTTP: GET, POST... -X)",
                "post_data": "str (dữ liệu body POST chứa từ khóa FUZZ -d)",
                "headers": "dict (HTTP headers tùy chỉnh -H)",
                "proxy": "str (HTTP proxy -x, ví dụ: http://127.0.0.1:8080)",
                "waf_detected": "bool (bật chế độ né tránh WAF)",
            },
        )

    def _load_ffuf_knowledge(self) -> dict:
        kb_path = Path("knowledge/ffuf_knowledge.json")
        if kb_path.exists():
            try:
                with open(kb_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Không thể đọc file ffuf_knowledge.json: {e}")
        return {}

    def _build_cli_command(
        self,
        target_url: str,
        wordlist_file: str,
        kwargs: Dict[str, Any],
        output_json: str = "output_samples/ffuf_out.json",
    ) -> List[str]:
        """Tự động chuyển đổi các options được Agent suy luận chọn thành câu lệnh CLI ffuf chuẩn."""
        # Check nếu target_url chưa có từ khóa FUZZ
        if "FUZZ" not in target_url:
            url_pattern = f"{target_url.rstrip('/')}/FUZZ"
        else:
            url_pattern = target_url

        cmd = [
            "ffuf",
            "-u", url_pattern,
            "-w", wordlist_file,
            "-of", "json",
            "-o", output_json,
            "-s",  # silent mode
        ]

        # 1. Method & POST Data
        method = kwargs.get("http_method")
        if method and method.upper() != "GET":
            cmd.extend(["-X", method.upper()])

        post_data = kwargs.get("post_data")
        if post_data:
            cmd.extend(["-d", str(post_data)])

        # 2. Extensions & Recursion
        exts = kwargs.get("extensions")
        if exts:
            if isinstance(exts, list):
                ext_str = ",".join(exts)
            else:
                ext_str = str(exts)
            cmd.extend(["-e", ext_str])

        if kwargs.get("recursion"):
            cmd.append("-recursion")
            depth = kwargs.get("recursion_depth", 2)
            cmd.extend(["-recursion-depth", str(depth)])

        # 3. Filtering & Matching
        if kwargs.get("auto_calibrate"):
            cmd.append("-ac")

        mc = kwargs.get("match_codes")
        if mc:
            mc_str = ",".join(map(str, mc)) if isinstance(mc, list) else str(mc)
            cmd.extend(["-mc", mc_str])

        fc = kwargs.get("filter_codes")
        if fc:
            fc_str = ",".join(map(str, fc)) if isinstance(fc, list) else str(fc)
            cmd.extend(["-fc", fc_str])

        fs = kwargs.get("filter_size")
        if fs:
            cmd.extend(["-fs", str(fs)])

        # 4. Rate Limiting, Threads & Delay
        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-t", str(threads)])

        rate = kwargs.get("rate_limit", 50)
        if rate:
            cmd.extend(["-rate", str(rate)])

        delay_ms = kwargs.get("delay_ms", 0)
        if delay_ms > 0:
            cmd.extend(["-p", str(delay_ms / 1000.0)])

        # 5. Headers & Proxy
        headers = kwargs.get("headers")
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        proxy = kwargs.get("proxy")
        if proxy:
            cmd.extend(["-x", str(proxy)])

        return cmd

    def run(self, **kwargs) -> ToolResult:
        start_time = time.time()
        target_url = kwargs.get("target_url", "")
        wordlist = kwargs.get("wordlist", [])
        waf_detected = kwargs.get("waf_detected", False)

        if not target_url or not wordlist:
            return ToolResult(
                success=False,
                tool_name=self.name,
                result_data={},
                error_message="Thiếu target_url hoặc wordlist rỗng.",
                execution_time=time.time() - start_time,
            )

        # Ghi file wordlist tạm thời
        output_dir = Path("output_samples")
        output_dir.mkdir(exist_ok=True)
        wl_path = output_dir / "temp_fuzz_wordlist.txt"
        with open(wl_path, "w", encoding="utf-8") as f:
            for w in wordlist:
                f.write(f"{w.strip('/')}\n")

        # Check binary ffuf trên hệ thống
        ffuf_path = shutil.which("ffuf")
        if ffuf_path:
            output_json = output_dir / "ffuf_results.json"
            cmd = self._build_cli_command(
                target_url=target_url,
                wordlist_file=str(wl_path),
                kwargs=kwargs,
                output_json=str(output_json),
            )

            logger.info(f"🚀 [EXECUTING FFUF CLI COMMAND] -> {' '.join(cmd)}")

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                raw_out = proc.stdout
                parsed_results = []

                if output_json.exists():
                    with open(output_json, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for res in data.get("results", []):
                            parsed_results.append({
                                "url": res.get("url"),
                                "path": res.get("input", {}).get("FUZZ"),
                                "status_code": res.get("status"),
                                "content_length": res.get("length"),
                                "response_time": res.get("duration") / 1e9 if res.get("duration") else 0.1,
                            })

                return ToolResult(
                    success=True,
                    tool_name=self.name,
                    result_data={
                        "engine": "ffuf_cli",
                        "command_executed": " ".join(cmd),
                        "total_requests": len(wordlist),
                        "results": parsed_results,
                    },
                    raw_output=raw_out,
                    execution_time=time.time() - start_time,
                )
            except Exception as exc:
                logger.warning(f"Lỗi khi chạy binary ffuf: {exc}. Chuyển sang Python Fuzzing Engine.")

        # Fallback sang Python Fuzzing Engine nếu không có binary ffuf
        from src.agents.fuzzer import FuzzingAgent
        engine = FuzzingAgent()
        res = engine._run_fuzzing_internal(target_url, wordlist, waf_detected=waf_detected)

        return ToolResult(
            success=True,
            tool_name=self.name,
            result_data={
                "engine": "python_fuzzing_engine",
                "results": res["results"],
                "stats": res["stats"],
            },
            raw_output=f"Python Fuzzing Engine executed {len(wordlist)} requests successfully.",
            execution_time=time.time() - start_time,
        )
