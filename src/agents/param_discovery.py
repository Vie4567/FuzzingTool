"""
Parameter Discovery Agent — STUB.

Agent 4: Tìm parameter ẩn trên các endpoint HTTP 200.
Sử dụng LLM để suy luận params dựa trên tech stack
và endpoint naming pattern.

⚠️ Đây là stub — trả kết quả giả để test Coordinator end-to-end.
"""

import logging

logger = logging.getLogger(__name__)


class ParamDiscoveryAgent:
    """Stub: Trả kết quả param discovery mẫu."""

    def execute(
        self,
        target_url: str,
        endpoints: list,
        tech_stack: dict = None,
    ) -> dict:
        """
        Tìm hidden parameters trên endpoints.

        Args:
            target_url: URL mục tiêu
            endpoints: Danh sách endpoints HTTP 200 cần phân tích
            tech_stack: Tech stack cho context

        Returns:
            dict với key: param_results
        """
        logger.info(
            f"[ParamDisc STUB] Analyzing {len(endpoints)} endpoints "
            f"on {target_url}"
        )

        param_results = []
        for endpoint in endpoints[:5]:  # Giới hạn 5 endpoints
            path = endpoint.get("path", endpoint) if isinstance(endpoint, dict) else endpoint
            param_results.append({
                "url": f"{target_url.rstrip('/')}{path}",
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
