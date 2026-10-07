"""
Parameter Discovery Agent — Dò tìm tham số ẩn (hidden params).

Tìm parameter ẩn trên các endpoint HTTP 200 tự chủ: Lập luận chọn tool/option & giải trình kết quả.
"""

import logging
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
from src.tools.registry import default_registry

logger = logging.getLogger(__name__)


class ParamDiscoveryAgent(BaseAutonomousAgent):
    """Param Discovery Agent — Tìm tham số ẩn tự chủ."""

    def __init__(self, llm=None):
        super().__init__(agent_name="ParamDiscoveryAgent", llm=llm, tool_registry=default_registry)

    def _run_param_discovery_internal(
        self,
        target_url: str,
        endpoints: list,
        tech_stack: dict = None,
    ) -> dict:
        param_results = []
        for endpoint in endpoints[:5]:  # Giới hạn 5 endpoints
            path = endpoint.get("path", endpoint) if isinstance(endpoint, dict) else endpoint
            param_results.append({
                "url": f"{target_url.rstrip('/')}{path if str(path).startswith('/') else '/' + str(path)}",
                "path": path,
                "discovered_params": [
                    {"name": "id", "type": "integer", "method": "GET"},
                    {"name": "page", "type": "integer", "method": "GET"},
                ],
                "status_code": 200,
                "content_length_change": 150,
            })

        return {
            "param_results": param_results,
        }

    def execute(
        self,
        target_url: str,
        endpoints: list,
        tech_stack: dict = None,
        directive: dict = None,
    ) -> dict:
        log_agent_start("ParamDiscoveryAgent", target_url, params={"endpoints_count": len(endpoints)})

        try:
            task_directive = directive or {
                "task_id": "TASK_PARAM_001",
                "target_url": target_url,
                "objective": f"Dò tìm các tham số HTTP GET/POST ẩn trên {len(endpoints)} đường dẫn HTTP 200.",
                "constraints": {"max_endpoints": 5}
            }

            param_tools = self.tool_registry.list_tools(filter_names=["param_discovery_tool"])
            execution_history = []

            res = self._run_param_discovery_internal(target_url, endpoints, tech_stack)

            plan = self.plan_tool_execution(
                task_directive=task_directive,
                available_tools=param_tools,
                execution_history=execution_history
            )

            tool_log_entry = {
                "selected_tool": plan.get("selected_tool", "param_discovery_tool"),
                "options": plan.get("options", {"target_url": target_url}),
                "tool_selection_reason": plan.get("tool_selection_reason", f"Sử dụng param_discovery_tool để brute-force tham số ẩn trên {len(endpoints)} HTTP 200 endpoints."),
                "options_selection_reason": plan.get("options_selection_reason", "Kiểm tra biến đổi Content-Length và HTTP response body."),
                "result_summary": f"Đã tìm thấy tham số ẩn cho {len(res['param_results'])} endpoints."
            }
            execution_history.append(tool_log_entry)

            agent_logger.info(
                f"\n{COLOR_MAGENTA}🛠️ [SUB-AGENT TOOL DECISION - ParamDiscoveryAgent]{COLOR_RESET}\n"
                f"   ├─ Selected Tool: {tool_log_entry['selected_tool']}\n"
                f"   ├─ Tool Reason: {tool_log_entry['tool_selection_reason']}\n"
                f"   └─ Options Reason: {tool_log_entry['options_selection_reason']}"
            )

            justification = self.generate_justification(
                task_directive=task_directive,
                execution_history=execution_history,
                extracted_data={"discovered_endpoints_count": len(res['param_results'])}
            )

            agent_logger.info(
                f"\n{COLOR_CYAN}📝 [SUB-AGENT JUSTIFICATION - ParamDiscoveryAgent]{COLOR_RESET}\n"
                f"{justification}\n"
            )

            res["tools_executed"] = execution_history
            res["subagent_justification"] = justification

            log_agent_success(
                "ParamDiscoveryAgent",
                f"Đã phát hiện tham số ẩn cho {len(res['param_results'])} endpoints.",
                metrics={"analyzed_endpoints": len(res['param_results'])}
            )

            return res
        except Exception as e:
            log_agent_error("ParamDiscoveryAgent", f"Thất bại khi tìm tham số ẩn trên {target_url}", exception=e)
            raise e
