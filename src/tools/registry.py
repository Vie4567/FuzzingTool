"""
Tool Registry Module — Tập hợp các công cụ chuẩn hóa cho các Sub-Agent.

Mỗi Tool có:
- name: Tên duy nhất của công cụ
- description: Mô tả chi tiết tính năng
- parameters_schema: Cấu trúc tham số đầu vào
- func: Hàm Python thực thi công cụ
"""

import json
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class Tool:
    """Đại diện cho một công cụ có thể được Sub-Agent lựa chọn và gọi."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters_schema: Dict[str, Any],
        func: Callable[..., Any],
    ):
        self.name = name
        self.description = description
        self.parameters_schema = parameters_schema
        self.func = func

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Thực thi công cụ và chuẩn hóa kết quả đầu ra."""
        try:
            result = self.func(**kwargs)
            return {
                "success": True,
                "tool_name": self.name,
                "result": result,
                "error": None,
            }
        except Exception as exc:
            logger.error(f"Lỗi khi thực thi tool {self.name}: {exc}")
            return {
                "success": False,
                "tool_name": self.name,
                "result": None,
                "error": str(exc),
            }


class ToolRegistry:
    """Kho đăng ký và quản lý tập hợp các công cụ cho Sub-Agents."""

    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool):
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def list_tools(self, filter_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Trả về danh sách định dạng schema các công cụ phục vụ prompt cho LLM."""
        result = []
        for name, tool in self._tools.items():
            if filter_names is None or name in filter_names:
                result.append({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters_schema": tool.parameters_schema,
                })
        return result

    def execute_tool(self, tool_name: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Gọi thực thi một tool theo tên và tham số."""
        tool = self.get_tool(tool_name)
        if not tool:
            return {
                "success": False,
                "tool_name": tool_name,
                "result": None,
                "error": f"Tool '{tool_name}' không tồn tại trong ToolRegistry.",
            }
        return tool.execute(**options)


# Singleton ToolRegistry instance
default_registry = ToolRegistry()


# ═══════════════════════════════════════════════════════════════
# ĐĂNG KÝ CÁC CÔNG CỤ CHUYÊN DỤNG (RECON, WORDLIST, FUZZ, PARAM, FILTER)
# ═══════════════════════════════════════════════════════════════

def _wrap_ch1(target_url: str, timeout: int = 10) -> dict:
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    # Chạy channel 1 qua execute hoặc internal fetch
    status, headers, body = agent._fetch_sync(target_url, timeout=timeout)
    fp_data = agent._load_json(agent._FINGERPRINTS_FILE)
    waf_data = agent._load_json(agent._WAF_SIGS_FILE)
    ch1_res = agent._ch1_header_fingerprint(headers, body, fp_data, waf_data)
    return {"status_code": status, "ch1_header_fingerprint": ch1_res}

def _wrap_ch2(target_url: str, timeout: int = 10) -> dict:
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    status, headers, body = agent._fetch_sync(target_url, timeout=timeout)
    fp_data = agent._load_json(agent._FINGERPRINTS_FILE)
    ch2_res = agent._ch2_dom_parser(body, target_url, fp_data)
    return {"ch2_dom_parser": ch2_res}

def _wrap_ch3(target_url: str, js_script_paths: list = None, timeout: int = 10) -> dict:
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    ch3_res = agent._ch3_js_bundle_analyzer(target_url, js_script_paths or [], timeout=timeout)
    return {"ch3_js_bundle_analyzer": ch3_res}

def _wrap_ch4(target_url: str, max_depth: int = 2, max_pages: int = 50) -> dict:
    import asyncio
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    spider_cfg = agent._load_json(agent._SPIDER_CFG_FILE)
    if max_depth:
        spider_cfg["max_depth"] = max_depth
    if max_pages:
        spider_cfg["max_pages"] = max_pages
    ch4_res = asyncio.run(agent._ch4_spider_crawl(target_url, spider_cfg))
    return {"ch4_spider_crawl": ch4_res}

def _wrap_ch5(target_url: str, timeout: int = 10) -> dict:
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    sens_data = agent._load_json(agent._SENSITIVE_FILES)
    ch5_res = agent._ch5_security_files_probe(target_url, sens_data, timeout=timeout)
    return {"ch5_security_files_probe": ch5_res}

def _wrap_ch6(target_url: str, discovered_paths: list = None, timeout: int = 10) -> dict:
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    ch6_res = agent._ch6_api_schema_detect(target_url, discovered_paths or [], timeout=timeout)
    return {"ch6_api_schema_detect": ch6_res}

def _wrap_ch7(target_url: str, timeout: int = 10) -> dict:
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    ch7_res = agent._ch7_error_probe(target_url, timeout=timeout)
    return {"ch7_error_probe": ch7_res}

def _wrap_full_recon(target_url: str) -> dict:
    from src.agents.tech_recon import TechReconAgent
    agent = TechReconAgent()
    return agent._run_full_recon_internal(target_url)


def _wrap_wordlist_gen(tech_stack: dict, discovered_paths: list, js_endpoints: list = None) -> dict:
    from src.agents.wordlist_gen import WordlistGenAgent
    agent = WordlistGenAgent()
    return agent._generate_wordlist_internal(tech_stack, discovered_paths, js_endpoints)

def _wrap_fuzzing(target_url: str, wordlist: list, waf_detected: bool = False, waf_type: str = None) -> dict:
    from src.agents.fuzzer import FuzzingAgent
    agent = FuzzingAgent()
    return agent._run_fuzzing_internal(target_url, wordlist, waf_detected, waf_type)

def _wrap_param_disc(target_url: str, discovered_paths: list) -> dict:
    from src.agents.param_discovery import ParamDiscoveryAgent
    agent = ParamDiscoveryAgent()
    return agent._run_param_discovery_internal(target_url, discovered_paths)

def _wrap_soft404_filter(raw_results: list, target_url: str) -> dict:
    from src.agents.soft404_filter import Soft404FilterAgent
    agent = Soft404FilterAgent()
    return agent._run_soft404_filter_internal(raw_results, target_url)


# Register Recon Tools
default_registry.register(Tool(
    name="httpx_header_fingerprint_tool",
    description="Thu thập và phân tích HTTP Headers, Cookies để xác định Web Server, Backend, CMS và chữ ký WAF.",
    parameters_schema={"target_url": "str", "timeout": "int (mặc định 10)"},
    func=_wrap_ch1
))

default_registry.register(Tool(
    name="dom_html_parser_tool",
    description="Trích xuất HTML Meta generator, HTML Anchors, Forms và JS Script paths từ DOM.",
    parameters_schema={"target_url": "str", "timeout": "int (mặc định 10)"},
    func=_wrap_ch2
))

default_registry.register(Tool(
    name="js_bundle_analyzer_tool",
    description="Tải xuống và bóc tách JS files để tìm các bí mật, API endpoints, hidden routes.",
    parameters_schema={"target_url": "str", "js_script_paths": "list", "timeout": "int"},
    func=_wrap_ch3
))

default_registry.register(Tool(
    name="spider_crawler_tool",
    description="Crawl liên kết nội bộ tự động với giới hạn độ sâu (max_depth) và số trang (max_pages).",
    parameters_schema={"target_url": "str", "max_depth": "int", "max_pages": "int"},
    func=_wrap_ch4
))

default_registry.register(Tool(
    name="security_files_probe_tool",
    description="Kiểm tra các file nhạy cảm như robots.txt, sitemap.xml, .git, .env, .well-known.",
    parameters_schema={"target_url": "str", "timeout": "int"},
    func=_wrap_ch5
))

default_registry.register(Tool(
    name="api_schema_detector_tool",
    description="Tự động phát hiện OpenAPI/Swagger, GraphQL endpoints và trích xuất API schema.",
    parameters_schema={"target_url": "str", "discovered_paths": "list"},
    func=_wrap_ch6
))

default_registry.register(Tool(
    name="error_probe_tool",
    description="Thăm dò các đường dẫn lỗi hoặc HTTP method bất thường để khai thác stack traces.",
    parameters_schema={"target_url": "str", "timeout": "int"},
    func=_wrap_ch7
))

default_registry.register(Tool(
    name="full_7channel_recon_suite",
    description="Thực thi đồng thời toàn bộ 7 kênh Reconnaissance để tổng hợp Target Profile đầy đủ.",
    parameters_schema={"target_url": "str"},
    func=_wrap_full_recon
))

default_registry.register(Tool(
    name="wordlist_generator_tool",
    description="Sinh Wordlist đa tầng dựa trên Target Profile (CMS, Backend, Sensitive Files & Mutations).",
    parameters_schema={"tech_stack": "dict", "discovered_paths": "list", "js_endpoints": "list"},
    func=_wrap_wordlist_gen
))

# ═══════════════════════════════════════════════════════════════
# ĐĂNG KÝ CÁC TOOL HELPERS CHUYÊN DỤNG (CLI + NATIVE FALLBACK)
# ═══════════════════════════════════════════════════════════════

from src.tools.ffuf_helper import FfufToolHelper
from src.tools.nmap_helper import NmapToolHelper
from src.tools.httpx_helper import HttpxToolHelper
from src.tools.gobuster_helper import GobusterToolHelper
from src.tools.arjun_helper import ArjunToolHelper
from src.tools.katana_helper import KatanaToolHelper

ffuf_h = FfufToolHelper()
default_registry.register(Tool(
    name=ffuf_h.name,
    description=ffuf_h.description,
    parameters_schema=ffuf_h.parameters_schema,
    func=lambda **kwargs: ffuf_h.run(**kwargs).to_dict()
))

nmap_h = NmapToolHelper()
default_registry.register(Tool(
    name=nmap_h.name,
    description=nmap_h.description,
    parameters_schema=nmap_h.parameters_schema,
    func=lambda **kwargs: nmap_h.run(**kwargs).to_dict()
))

httpx_h = HttpxToolHelper()
default_registry.register(Tool(
    name=httpx_h.name,
    description=httpx_h.description,
    parameters_schema=httpx_h.parameters_schema,
    func=lambda **kwargs: httpx_h.run(**kwargs).to_dict()
))

gobuster_h = GobusterToolHelper()
default_registry.register(Tool(
    name=gobuster_h.name,
    description=gobuster_h.description,
    parameters_schema=gobuster_h.parameters_schema,
    func=lambda **kwargs: gobuster_h.run(**kwargs).to_dict()
))

arjun_h = ArjunToolHelper()
default_registry.register(Tool(
    name=arjun_h.name,
    description=arjun_h.description,
    parameters_schema=arjun_h.parameters_schema,
    func=lambda **kwargs: arjun_h.run(**kwargs).to_dict()
))

katana_h = KatanaToolHelper()
default_registry.register(Tool(
    name=katana_h.name,
    description=katana_h.description,
    parameters_schema=katana_h.parameters_schema,
    func=lambda **kwargs: katana_h.run(**kwargs).to_dict()
))

default_registry.register(Tool(
    name="param_discovery_tool",
    description="Dò tìm các tham số HTTP GET/POST ẩn trên các đường dẫn phản hồi HTTP 200.",
    parameters_schema={"target_url": "str", "discovered_paths": "list"},
    func=_wrap_param_disc
))

default_registry.register(Tool(
    name="soft404_filter_tool",
    description="Lọc bỏ các kết quả Soft 404 (False Positive) dựa trên so sánh tương đồng cấu trúc HTML DOM.",
    parameters_schema={"raw_results": "list", "target_url": "str"},
    func=_wrap_soft404_filter
))

