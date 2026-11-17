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
from urllib.parse import urljoin, urlsplit

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
from src.tools.parameter_verification import verify_parameters, parameter_options_from_config
from src.coordinator.llm_logging import sanitize_for_log

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

        id_params = assembled_components.get("id_lookup") or ["id", "uuid"]
        biz_params = assembled_components.get("business_fields") or ["q", "filter", "category"]
        action_params = assembled_components.get("action_control") or ["action", "mode", "view"]
        pag_params = assembled_components.get("pagination_sort") or ["page", "limit", "sort"]
        sec_params = assembled_components.get("debug_security") or ["debug", "admin", "format"]

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
            (e.get("url") or e.get("path") or "") if isinstance(e, dict) else str(e)
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
            source = endpoint if isinstance(endpoint, dict) else {}
            reference = (source.get("url") or source.get("path") or "") if source else str(endpoint)
            if not isinstance(reference, str) or not reference:
                continue
            full_url = urljoin(target_url.rstrip("/") + "/", reference)
            path = urlsplit(full_url).path or "/"

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
                "source_status_code": source.get("status_code"),
                "source_method": source.get("http_method", source.get("method", "GET")),
                "source_error": source.get("error"),
                "source_simulated": source.get("simulated", False),
                "source_body_complete": source.get("body_complete"),
                "source_body_truncated": source.get("body_truncated", False),
                "source_proxy_profile_id": source.get("proxy_profile_id"),
                "source_retry_after": any(str(key).lower() == "retry-after" for key in (source.get("headers") or {})),
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
        verification_options: dict = None,
    ) -> dict:
        def redact(value):
            options = verification_options or {}
            proxy = options.get("proxy_options") or {}
            # Profile IDs and routing policy are evidence, not credentials.
            credentials = [row.get("url") for row in proxy.get("proxy_profiles", []) if isinstance(row, dict)]
            return sanitize_for_log({"headers": options.get("headers", {}),
                                     "credentials": credentials, "payload": value})["payload"]

        res = None
        log_agent_start("ParamDiscoveryAgent", redact(target_url), params={"endpoints_count": len(endpoints)})

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
                f"   ├─ Tool Reason: {redact(tool_log_entry['tool_selection_reason'])}\n"
                f"   └─ Options Reason: {redact(tool_log_entry['options_selection_reason'])}"
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

            verification = verify_parameters(
                target_url, res["param_results"],
                **({"enabled": False} if verification_options is None else verification_options),
            )
            res.update(verification)
            if verification["verification_performed"]:
                res["tools_executed"] = [{"selected_tool": "parameter_http_verifier",
                                          "total_requests": verification["stats"]["total_requests"]}]
                res["subagent_justification"] = (
                    f"Đã đo {verification['stats']['total_requests']} HTTP requests, "
                    f"xác minh {len(verification['verified_parameters'])} tham số có ảnh hưởng phản hồi lặp lại; "
                    f"{len(verification['parameter_candidates'])} ứng viên chưa đủ bằng chứng. "
                    "Endpoint vẫn cần kiểm chứng Soft404 riêng."
                )

            log_agent_success(
                "ParamDiscoveryAgent",
                f"Đã sinh tham số ứng viên cho {len(res['param_results'])} endpoints "
                f"({res.get('assembled_parameter_count', 0)} tên được lắp ráp); "
                f"HTTP verification={res['verification_status']}.",
                metrics={
                    "analyzed_endpoints": len(res['param_results']),
                    "assembled_parameters": res.get("assembled_parameter_count", 0),
                }
            )

            return redact(res)
        except Exception as e:
            safe_error = redact(f"{type(e).__name__}: {e}")
            log_agent_error("ParamDiscoveryAgent", f"Thất bại khi tìm tham số ẩn: {safe_error}")
            if res is None:
                raise RuntimeError(safe_error) from None
            # Candidate generation succeeded; keep it reviewable even when a
            # verifier/configuration exception prevents HTTP evidence collection.
            res.update(verification="not_checked", verification_performed=False,
                       verification_status="failed", stop_reason="verification_failed",
                       verified_parameters=[], parameter_candidates=[],
                       stats={"total_requests": None}, error=safe_error)
            for row in res.get("param_results", []):
                for param in row.get("discovered_params", []):
                    res["parameter_candidates"].append({
                        "endpoint": row.get("url"), "name": param.get("name"),
                        "location": param.get("location", "query"), "method": param.get("method", "GET"),
                        "result_kind": "parameter_candidate", "verification": "not_checked",
                        "verification_performed": False, "verification_reason": "verification_failed",
                        "status_code": None, "content_length_change": None,
                    })
            return redact(res)
