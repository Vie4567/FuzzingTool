"""
Wordlist Generator Agent — STUB.

Agent 2: Sinh wordlist thông minh dựa trên Target Profile.
Sử dụng LLM để phân tích dev naming convention
và sinh các đường dẫn có khả năng tồn tại cao.

⚠️ Đây là stub — trả kết quả giả để test Coordinator end-to-end.
"""

import logging

logger = logging.getLogger(__name__)


class WordlistGenAgent:
    """Stub: Trả wordlist mẫu."""

    def execute(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
    ) -> dict:
        """
        Sinh wordlist từ Target Profile.

        Args:
            tech_stack: Tech stack đã phát hiện
            discovered_paths: Các paths đã tìm thấy
            js_endpoints: Endpoints trích xuất từ JS

        Returns:
            dict với keys: wordlist, dev_profile, metadata
        """
        logger.info(
            f"[WordlistGen STUB] Generating for "
            f"{tech_stack.get('backend', 'unknown')} stack"
        )

        backend = tech_stack.get("backend", "").lower()

        # Sinh wordlist giả dựa trên backend
        base_paths = [
            "/api/v1/users", "/api/v1/products", "/api/v1/orders",
            "/api/v1/auth/login", "/api/v1/auth/register",
            "/api/v1/auth/refresh", "/api/v1/auth/logout",
            "/api/v2/users", "/api/v2/products",
            "/admin/", "/admin/login/", "/admin/dashboard/",
            "/static/css/", "/static/js/", "/static/img/",
            "/media/uploads/", "/health/", "/status/",
            "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
        ]

        if "django" in backend:
            base_paths.extend([
                "/admin/auth/", "/admin/users/",
                "/api/v1/schema/", "/api/v1/docs/",
                "/__debug__/", "/silk/",
            ])

        return {
            "wordlist": base_paths,
            "dev_profile": {
                "naming_convention": "snake_case",
                "api_versioning": "url_prefix",
                "api_prefix": "/api/v1",
            },
            "metadata": {
                "total_entries": len(base_paths),
                "source": "stub",
                "tech_based_entries": len(base_paths),
            },
        }
