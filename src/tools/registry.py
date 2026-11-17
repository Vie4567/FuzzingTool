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
            success = not isinstance(result, dict) or result.get("success", True) is not False
            return {
                "success": success,
                "tool_name": self.name,
                "result": result,
                "error": result.get("error_message") if not success else None,
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

def _recon_context(target_url, options):
    from src.agents import tech_recon as recon
    from src.tools.recon_http import recon_options_from_config
    agent = recon.TechReconAgent(**recon_options_from_config(options))
    agent._load_knowledge()
    return recon, agent, agent._build_transport(target_url)


def _wrap_ch1(target_url: str, timeout: int = 10, **options) -> dict:
    recon, agent, transport = _recon_context(target_url, options)
    status, headers, body = transport.fetch(target_url, timeout=timeout)
    result = recon._ch1_header_fingerprint(headers, body, agent._fp_data, agent._waf_data)
    return agent._redact({"status_code": status, "ch1_header_fingerprint": result}, transport)

def _wrap_ch2(target_url: str, timeout: int = 10, **options) -> dict:
    recon, agent, transport = _recon_context(target_url, options)
    _, _, body = transport.fetch(target_url, timeout=timeout)
    return agent._redact({"ch2_dom_parser": recon._ch2_dom_parse(body, target_url, agent._fp_data)}, transport)

def _wrap_ch3(target_url: str, js_script_paths: list = None, timeout: int = 10, **options) -> dict:
    from urllib.parse import urljoin, urlsplit
    recon, agent, transport = _recon_context(target_url, options)
    result = {"paths": [], "params": [], "api_origins": []}
    for path in (js_script_paths or [])[:20]:
        status, _, body = transport.fetch(urljoin(target_url, path), timeout=timeout)
        if status == 200:
            parsed = recon._ch3_js_analyze(body, agent._js_patterns, base_url=target_url,
                                           source_url=urljoin(target_url, path))
            for key in result:
                result[key] = sorted(set(result[key]).union(parsed.get(key, [])))
    return agent._redact({"ch3_js_bundle_analyzer": result}, transport)

def _wrap_ch4(target_url: str, max_depth: int = 2, max_pages: int = 50, **options) -> dict:
    import asyncio
    from copy import deepcopy
    recon, agent, transport = _recon_context(target_url, options)
    spider_cfg = deepcopy(agent._spider_cfg)
    spider_cfg.setdefault("limits", {}).update(default_max_depth=max_depth, default_max_pages=max_pages)
    spider = recon._ReconSpider(target_url, {}, spider_cfg, transport=transport)
    return agent._redact({"ch4_spider_crawl": asyncio.run(spider.run())}, transport)

def _wrap_ch5(target_url: str, timeout: int = 10, **options) -> dict:
    import asyncio
    recon, agent, transport = _recon_context(target_url, options)
    return agent._redact({"ch5_security_files_probe": asyncio.run(recon._ch5_probe(target_url, transport=transport))}, transport)

def _wrap_ch6(target_url: str, discovered_paths: list = None, timeout: int = 10, **options) -> dict:
    import asyncio
    from urllib.parse import urljoin
    recon, agent, transport = _recon_context(target_url, options)
    urls = [urljoin(target_url, path) for path in (discovered_paths or [])]
    return agent._redact({"ch6_api_schema_detect": asyncio.run(recon._ch6_api_schema(urls, transport=transport))}, transport)

def _wrap_ch7(target_url: str, timeout: int = 10, **options) -> dict:
    import asyncio
    recon, agent, transport = _recon_context(target_url, options)
    return agent._redact({"ch7_error_probe": asyncio.run(recon._ch7_error_probe(target_url, transport=transport))}, transport)

def _wrap_full_recon(target_url: str, **options) -> dict:
    import asyncio
    _, agent, transport = _recon_context(target_url, options)
    return asyncio.run(agent._run_async(target_url, transport=transport))


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

def _wrap_soft404_filter(raw_results: list, target_url: str, **options) -> dict:
    from src.agents.soft404_filter import Soft404FilterAgent
    agent = Soft404FilterAgent()
    return agent._run_soft404_filter_internal(raw_results, target_url, **options)


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

