"""
Parameter Discovery Agent — Sinh tham số ứng viên, chưa kiểm chứng bằng HTTP.

Tìm parameter ẩn trên các endpoint HTTP 200 tự chủ:
- Sử dụng ParameterAssembler với LLM component-by-component enrichment để sinh tập tham số theo ngữ cảnh
- Lập luận chọn tool/option & giải trình kết quả.
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.coordinator.logger import (
    log_agent_start,
    log_agent_progress,
    log_agent_success,
    log_agent_error,
    agent_logger,
    COLOR_CYAN,
    COLOR_MAGENTA,
    COLOR_RESET,
)
from src.agents.base_agent import BaseAutonomousAgent
from src.agents.param_assembler import ParameterAssembler
from src.tools.registry import default_registry

logger = logging.getLogger(__name__)


class ParamDiscoveryAgent(BaseAutonomousAgent):
    """Param Discovery Agent — Tìm tham số ẩn tự chủ với Component-by-Component Parameter Assembler."""

    def __init__(self, llm=None):
        super().__init__(agent_name="ParamDiscoveryAgent", llm=llm, tool_registry=default_registry)
        self.assembler = ParameterAssembler()

    def _match_params_for_path(
        self,
        path: str,
        assembled_components: Dict[str, List[str]],
        naming_style: str = "snake_case",
    ) -> List[Dict[str, Any]]:
        """Khớp các tham số tiềm năng phù hợp nhất với một endpoint cụ thể dựa vào ngữ cảnh đường dẫn."""
        path_lower = path.lower()
        matched = []

        id_params = assembled_components.get("id_lookup", ["id", "uuid"])
        biz_params = assembled_components.get("business_fields", ["q", "filter", "category"])
        action_params = assembled_components.get("action_control", ["action", "mode", "view"])
        pag_params = assembled_components.get("pagination_sort", ["page", "limit", "sort"])
        sec_params = assembled_components.get("debug_security", ["debug", "admin", "format"])

        # Trích xuất segment từ path (VD: /api/v1/orders/detail -> segments: api, v1, orders, detail)
        segments = [s for s in path_lower.strip("/").split("/") if s and not re.match(r'^\d+$', s)]

        # 1. Nếu path có chứa search / query / list
        if any(w in path_lower for w in ["search", "find", "query", "list", "catalog", "index", "browse"]):
            matched.append({"name": "q" if "q" in biz_params else biz_params[0], "type": "string", "method": "GET"})
            matched.append({"name": "page" if "page" in pag_params else pag_params[0], "type": "integer", "method": "GET"})
            if "sort" in pag_params:
                matched.append({"name": "sort", "type": "string", "method": "GET"})
            if "filter" in biz_params:
                matched.append({"name": "filter", "type": "string", "method": "GET"})

        # 2. Nếu path trông như resource item detail / get
        elif any(w in path_lower for w in ["detail", "get", "view", "show", "item", "info"]) or re.search(r'/\d+', path):
            matched.append({"name": id_params[0] if id_params else "id", "type": "integer", "method": "GET"})
            matched.append({"name": "format" if "format" in action_params else "view", "type": "string", "method": "GET"})

        # 3. Nếu path liên quan đến auth / login / user
        elif any(w in path_lower for w in ["auth", "login", "register", "token", "oauth", "user"]):
            matched.append({"name": "redirect_uri" if "redirect_uri" in action_params else "redirect", "type": "string", "method": "GET"})
            matched.append({"name": "client_id" if "client_id" in id_params else "token", "type": "string", "method": "GET"})

        # 4. Mặc định cho RESTful resource endpoints
        else:
            # Thử tìm segment danh từ trong path
            res_segment = segments[-1] if segments else "item"
            res_singular = res_segment.rstrip("s")
            specific_id = self.assembler._convert_naming(f"{res_singular}_id", naming_style)

            # Chọn param ID phù hợp
            chosen_id = specific_id if specific_id in id_params else id_params[0]
            matched.append({"name": chosen_id, "type": "integer", "method": "GET"})
            matched.append({"name": pag_params[0] if pag_params else "page", "type": "integer", "method": "GET"})
            if biz_params:
                matched.append({"name": biz_params[0], "type": "string", "method": "GET"})

        # Bổ sung tham số debug / telemetry nếu có
        if sec_params:
            matched.append({"name": sec_params[0], "type": "boolean", "method": "GET"})

        return matched

    def _run_param_discovery_internal(
        self,
        target_url: str,
        endpoints: list,
        tech_stack: dict = None,
        dev_profile: dict = None,
    ) -> dict:
        """
        Thực thi Parameter Discovery sử dụng ParameterAssembler component-by-component:
          1. Sinh tập tham số ứng viên bằng ParameterAssembler (chia thành 5 components).
          2. Khớp các tham số tiềm năng nhất cho từng HTTP 200 endpoint.
        """
        observed_paths = [
            e.get("path", e) if isinstance(e, dict) else e
            for e in endpoints
        ]

        log_agent_progress(
            "ParamDiscoveryAgent",
            f"Đang phân tích {len(endpoints)} endpoints để sinh tham số ứng viên; chưa gửi request kiểm chứng..."
        )

        assembler_res = self.assembler.assemble(
            dev_profile=dev_profile,
            observed_urls=observed_paths,
            tech_stack=tech_stack,
            llm=self.llm,
            max_params=300,
        )

        components = assembler_res.get("components", {})
        param_wordlist = assembler_res.get("parameters", [])
        meta = assembler_res.get("metadata", {})
        naming_style = meta.get("naming_convention", "snake_case")

        param_results = []
        for endpoint in endpoints[:5]:  # Giới hạn 5 endpoints trọng điểm
            path = endpoint.get("path", endpoint) if isinstance(endpoint, dict) else endpoint
            full_url = f"{target_url.rstrip('/')}{path if str(path).startswith('/') else '/' + str(path)}"

            matched_params = self._match_params_for_path(str(path), components, naming_style)

            param_results.append({
                "url": full_url,
                "path": path,
                "discovered_params": matched_params,
                "status_code": None,
                "content_length_change": None,
                "result_kind": "parameter_candidates",
                "verification": "not_checked",
                "verification_performed": False,
            })

        return {
            "result_kind": "parameter_candidates",
            "verification": "not_checked",
            "verification_performed": False,
            "param_results": param_results,
            "assembled_parameter_count": len(param_wordlist),
            "assembled_parameter_sample": param_wordlist[:20],
            "parameter_components": components,
            "assembler_metadata": meta,
        }

    def execute(
        self,
        target_url: str,
        endpoints: list,
        tech_stack: dict = None,
        dev_profile: dict = None,
        directive: dict = None,
    ) -> dict:
        log_agent_start("ParamDiscoveryAgent", target_url, params={"endpoints_count": len(endpoints)})

        try:
            task_directive = directive or {
                "task_id": "TASK_PARAM_001",
                "target_url": target_url,
                "objective": f"Sinh tên tham số ứng viên cho {len(endpoints)} đường dẫn; chưa thực hiện kiểm chứng HTTP.",
                "constraints": {"max_endpoints": 5}
            }

            param_tools = self.tool_registry.list_tools(filter_names=["param_discovery_tool"])
            execution_history = []

            res = self._run_param_discovery_internal(
                target_url=target_url,
                endpoints=endpoints,
                tech_stack=tech_stack,
                dev_profile=dev_profile,
            )

            plan = self.plan_tool_execution(
                task_directive=task_directive,
                available_tools=param_tools,
                execution_history=execution_history
            )

            tool_log_entry = {
                "selected_tool": plan.get("selected_tool", "param_discovery_tool"),
                "options": plan.get("options", {"target_url": target_url}),
                "tool_selection_reason": plan.get(
                    "tool_selection_reason",
                    f"Dự kiến dùng param_discovery_tool cho {len(endpoints)} endpoints; hiện chỉ chạy ParameterAssembler sinh ứng viên."
                ),
                "options_selection_reason": plan.get(
                    "options_selection_reason",
                    "Gợi ý tên tham số theo ngữ cảnh; chưa đo Content-Length hoặc so sánh HTTP response."
                ),
                "result_summary": (
                    f"Đã gợi ý tham số ứng viên cho {len(res['param_results'])} endpoints "
                    f"(ParameterAssembler tạo {res.get('assembled_parameter_count', 0)} tên). Chưa kiểm chứng HTTP."
                )
            }

            agent_logger.info(
                f"\n{COLOR_MAGENTA}[SUB-AGENT TOOL PLAN - ParamDiscoveryAgent; chưa thực thi]{COLOR_RESET}\n"
                f"   ├─ Planned Tool: {tool_log_entry['selected_tool']}\n"
                f"   ├─ Tool Reason: {tool_log_entry['tool_selection_reason']}\n"
                f"   └─ Options Reason: {tool_log_entry['options_selection_reason']}"
            )

            justification = (
                f"[ParamDiscoveryAgent] Đã sinh tham số ứng viên cho {len(res['param_results'])} endpoints "
                f"từ {res.get('assembled_parameter_count', 0)} tên do ParameterAssembler lắp ráp. "
                "Chưa gửi HTTP request kiểm chứng tham số và chưa thực thi công cụ dò tham số. "
                "status_code và content_length_change là null vì chưa đo; mọi ứng viên đều chưa xác minh."
            )

            agent_logger.info(
                f"\n{COLOR_CYAN}📝 [SUB-AGENT JUSTIFICATION - ParamDiscoveryAgent]{COLOR_RESET}\n"
                f"{justification}\n"
            )

            res["planned_tool"] = tool_log_entry
            res["tools_executed"] = []
            res["subagent_justification"] = justification

            log_agent_success(
                "ParamDiscoveryAgent",
                f"Đã sinh tham số ứng viên cho {len(res['param_results'])} endpoints "
                f"({res.get('assembled_parameter_count', 0)} tên được lắp ráp); chưa kiểm chứng HTTP.",
                metrics={
                    "analyzed_endpoints": len(res['param_results']),
                    "assembled_parameters": res.get("assembled_parameter_count", 0),
                }
            )

            return res
        except Exception as e:
            log_agent_error("ParamDiscoveryAgent", f"Thất bại khi tìm tham số ẩn trên {target_url}", exception=e)
            raise e
