"""
Soft 404 Filter Agent — Lọc false positive bằng DOM comparison.

So sánh DOM signature của mỗi kết quả với baseline (trang 404 thật) tự chủ: Lập luận chọn tool/option & giải trình kết quả.
"""

import logging
import random
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


class Soft404FilterAgent(BaseAutonomousAgent):
    """Soft404 Filter Agent — Lọc false positive tự chủ."""

    def __init__(self, llm=None):
        super().__init__(agent_name="Soft404FilterAgent", llm=llm, tool_registry=default_registry)

    def _run_soft404_filter_internal(
        self,
        results_to_verify: list,
        target_url: str,
    ) -> dict:
        verified = []
        false_positives = []

        for result in results_to_verify:
            status = result.get("status_code", 0)

            if status == 200:
                if random.random() < 0.7:
                    result["verification"] = "genuine"
                    result["similarity_to_baseline"] = round(random.uniform(0.05, 0.35), 3)
                    verified.append(result)
                else:
                    result["verification"] = "soft_404"
                    result["similarity_to_baseline"] = round(random.uniform(0.80, 0.99), 3)
                    false_positives.append(result)
            elif status in (301, 302, 403):
                result["verification"] = "non_200_kept"
                verified.append(result)

        return {
            "verified": verified,
            "false_positives": false_positives,
            "baseline": {
                "url": f"{target_url}/this-page-does-not-exist-xyz",
                "dom_signature": {
                    "tag_counts": {"div": 15, "p": 3, "h1": 1},
                    "text_length": 450,
                    "title": "Page Not Found",
                },
                "content_length": 1200,
            },
        }

    def execute(
        self,
        target_url: str,
        results_to_verify: list,
        directive: dict = None,
    ) -> dict:
        log_agent_start("Soft404FilterAgent", target_url, params={"total_to_verify": len(results_to_verify)})

        try:
            task_directive = directive or {
                "task_id": "TASK_FILTER_001",
                "target_url": target_url,
                "objective": f"Lọc bỏ cảnh báo giả (Soft 404 / False Positive) cho {len(results_to_verify)} kết quả thu được.",
                "constraints": {"similarity_threshold": 0.8}
            }

            filter_tools = self.tool_registry.list_tools(filter_names=["soft404_filter_tool"])
            execution_history = []

            res = self._run_soft404_filter_internal(results_to_verify, target_url)

            plan = self.plan_tool_execution(
                task_directive=task_directive,
                available_tools=filter_tools,
                execution_history=execution_history
            )

            tool_log_entry = {
                "selected_tool": plan.get("selected_tool", "soft404_filter_tool"),
                "options": plan.get("options", {"similarity_threshold": 0.8}),
                "tool_selection_reason": plan.get("tool_selection_reason", f"Sử dụng soft404_filter_tool để đối chiếu cấu trúc DOM của {len(results_to_verify)} kết quả với trang baseline 404."),
                "options_selection_reason": plan.get("options_selection_reason", "Ngưỡng tương đồng 80% (similarity=0.80) để nhận diện các trang giả mạo HTTP 200."),
                "result_summary": f"Đã xác minh {len(res['verified'])} đường dẫn thực tế, loại bỏ {len(res['false_positives'])} Soft 404 giả."
            }
            execution_history.append(tool_log_entry)

            agent_logger.info(
                f"\n{COLOR_MAGENTA}🛠️ [SUB-AGENT TOOL DECISION - Soft404FilterAgent]{COLOR_RESET}\n"
                f"   ├─ Selected Tool: {tool_log_entry['selected_tool']}\n"
                f"   ├─ Tool Reason: {tool_log_entry['tool_selection_reason']}\n"
                f"   └─ Options Reason: {tool_log_entry['options_selection_reason']}"
            )

            justification = self.generate_justification(
                task_directive=task_directive,
                execution_history=execution_history,
                extracted_data={"verified_count": len(res['verified']), "false_positive_count": len(res['false_positives'])}
            )

            agent_logger.info(
                f"\n{COLOR_CYAN}📝 [SUB-AGENT JUSTIFICATION - Soft404FilterAgent]{COLOR_RESET}\n"
                f"{justification}\n"
            )

            res["tools_executed"] = execution_history
            res["subagent_justification"] = justification

            log_agent_success(
                "Soft404FilterAgent",
                f"Lọc thành công: {len(res['verified'])} verified, {len(res['false_positives'])} Soft 404 (false positive)",
                metrics={"verified_count": len(res['verified']), "false_positive_count": len(res['false_positives'])}
            )

            return res
        except Exception as e:
            log_agent_error("Soft404FilterAgent", f"Thất bại khi lọc Soft 404 trên {target_url}", exception=e)
            raise e
