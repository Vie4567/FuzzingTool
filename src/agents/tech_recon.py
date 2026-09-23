"""
Tech Recon Agent — STUB.

Agent 1: Phân tích target để xây dựng Target Profile.
7 kênh thu thập: HTTP Headers, HTML Meta, DOM Analysis,
JS Analysis, robots.txt, sitemap.xml, WAF Detection.

⚠️ Đây là stub — trả kết quả giả để test Coordinator end-to-end.
   Agent thật sẽ được phát triển riêng.
"""

import logging

logger = logging.getLogger(__name__)


class TechReconAgent:
    """Stub: Trả kết quả mẫu cho Tech Recon."""

    def execute(self, target_url: str) -> dict:
        """
        Chạy Tech Recon trên target URL.

        Args:
            target_url: URL mục tiêu

        Returns:
            dict với keys: tech_stack, discovered_paths,
                          js_endpoints, waf_detected, waf_type
        """
        logger.info(f"[TechRecon STUB] Scanning {target_url}")

        return {
            "tech_stack": {
                "web_server": "Nginx",
                "backend": "Django",
                "frontend": "React",
                "language": "Python",
            },
            "discovered_paths": [
                "/admin/", "/api/", "/api/v1/", "/api/v2/",
                "/static/", "/media/", "/uploads/",
                "/login/", "/register/", "/dashboard/",
                "/health/", "/docs/", "/swagger/",
            ],
            "js_endpoints": [
                "/api/v1/users", "/api/v1/products",
                "/api/v1/auth/login", "/api/v1/auth/refresh",
            ],
            "waf_detected": False,
            "waf_type": None,
        }
