"""
Fuzzing Agent — STUB.

Agent 3: Hệ thống con fuzzing (Planner → Engine → Analyst).
Sử dụng ffuf làm động cơ quét, tích hợp WAF evasion.

⚠️ Đây là stub — trả kết quả giả để test Coordinator end-to-end.
"""

import logging
import random

logger = logging.getLogger(__name__)


class FuzzingAgent:
    """Stub: Trả kết quả fuzzing mẫu."""

    def execute(
        self,
        target_url: str,
        wordlist: list,
        waf_detected: bool = False,
        waf_type: str = None,
        **config_adjustments,
    ) -> dict:
        """
        Chạy fuzzing trên target.

        Args:
            target_url: URL mục tiêu
            wordlist: Danh sách paths cần quét
            waf_detected: Có WAF không
            waf_type: Loại WAF
            **config_adjustments: Config tùy chỉnh từ Coordinator

        Returns:
            dict với keys: results, stats
        """
        logger.info(
            f"[Fuzzing STUB] Fuzzing {target_url} "
            f"with {len(wordlist)} entries"
        )

        # Sinh kết quả giả: một số 200, nhiều 404, vài 403
        results = []
        status_weights = {200: 0.15, 301: 0.05, 403: 0.10, 404: 0.65, 500: 0.05}

        for path in wordlist:
            roll = random.random()
            cumulative = 0.0
            status = 404

            for code, weight in status_weights.items():
                cumulative += weight
                if roll <= cumulative:
                    status = code
                    break

            results.append({
                "url": f"{target_url.rstrip('/')}{path}",
                "path": path,
                "status_code": status,
                "content_length": random.randint(100, 50000),
                "response_time": round(random.uniform(0.05, 2.0), 3),
                "redirect_url": f"{target_url}/login" if status == 301 else None,
            })

        total_requests = len(wordlist)
        avg_time = sum(r["response_time"] for r in results) / max(len(results), 1)

        return {
            "results": results,
            "stats": {
                "total_requests": total_requests,
                "status_codes": {
                    str(code): sum(1 for r in results if r["status_code"] == code)
                    for code in {200, 301, 403, 404, 500}
                },
                "avg_response_time": round(avg_time, 3),
                "waf_blocks_detected": 0,
            },
        }
