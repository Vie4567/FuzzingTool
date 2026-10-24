"""Preserve observed responses until a real Soft 404 comparator is implemented."""

from copy import deepcopy

from src.coordinator.logger import (
    log_agent_start,
    log_agent_skip,
    log_agent_error,
)
from src.agents.base_agent import BaseAutonomousAgent
from src.tools.registry import default_registry


class Soft404FilterAgent(BaseAutonomousAgent):
    """Report the unavailable verification step without inventing evidence."""

    def __init__(self, llm=None):
        super().__init__(agent_name="Soft404FilterAgent", llm=llm, tool_registry=default_registry)

    def _run_soft404_filter_internal(
        self,
        results_to_verify: list,
        target_url: str,
    ) -> dict:
        unverified = deepcopy(results_to_verify)
        for result in unverified:
            result["verification"] = "not_checked"
            result["verification_performed"] = False
            # A previous run's classification is not evidence of this step's work.
            result.pop("similarity_to_baseline", None)

        return {
            "verified": [],
            "false_positives": [],
            "unverified": unverified,
            "baseline": None,
            "verification_performed": False,
            "verification_status": "not_implemented",
        }

    def execute(
        self,
        target_url: str,
        results_to_verify: list,
        directive: dict = None,
    ) -> dict:
        log_agent_start("Soft404FilterAgent", target_url, params={"total_to_verify": len(results_to_verify)})
        try:
            res = self._run_soft404_filter_internal(results_to_verify, target_url)
            justification = (
                f"[Soft404FilterAgent] Bỏ qua xác minh Soft 404 cho {len(results_to_verify)} kết quả: "
                "chưa triển khai bộ so sánh với baseline HTTP/DOM thật. "
                "Không gửi request, không chạy công cụ và không phân loại endpoint. "
                "Giữ nguyên số liệu phản hồi đã quan sát; mọi kết quả đều chưa được xác minh."
            )
            res["tools_executed"] = []
            res["subagent_justification"] = justification
            log_agent_skip("Soft404FilterAgent", justification)
            return res
        except Exception as exc:
            log_agent_error("Soft404FilterAgent", f"Không thể giữ kết quả chưa xác minh cho {target_url}", exception=exc)
            raise
