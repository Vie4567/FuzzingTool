"""
Soft 404 Filter Agent — STUB.

Agent 5: Lọc false positive bằng DOM comparison.
So sánh DOM signature của mỗi kết quả với baseline
(trang 404 thật) để loại bỏ soft 404.

⚠️ Đây là stub — trả kết quả giả để test Coordinator end-to-end.
"""

import logging
import random

logger = logging.getLogger(__name__)


class Soft404FilterAgent:
    """Stub: Trả kết quả filter mẫu."""

    def execute(
        self,
        target_url: str,
        results_to_verify: list,
    ) -> dict:
        """
        Lọc false positive từ danh sách kết quả.

        Args:
            target_url: URL mục tiêu
            results_to_verify: Danh sách kết quả cần verify

        Returns:
            dict với keys: verified, false_positives, baseline
        """
        logger.info(
            f"[Soft404 STUB] Verifying {len(results_to_verify)} results "
            f"for {target_url}"
        )

        verified = []
        false_positives = []

        for result in results_to_verify:
            status = result.get("status_code", 0)

            # Chỉ verify các HTTP 200 (các status khác giữ nguyên)
            if status == 200:
                # Giả lập: 70% là thật, 30% là soft 404
                if random.random() < 0.7:
                    result["verification"] = "genuine"
                    result["similarity_to_baseline"] = round(
                        random.uniform(0.05, 0.35), 3
                    )
                    verified.append(result)
                else:
                    result["verification"] = "soft_404"
                    result["similarity_to_baseline"] = round(
                        random.uniform(0.80, 0.99), 3
                    )
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
