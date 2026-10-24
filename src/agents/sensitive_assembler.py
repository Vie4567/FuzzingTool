"""
Sensitive Files Assembler — Pattern Engine cho Sensitive Files & Backup Fuzzing.

Luồng hoạt động:
  1. Nạp tri thức tĩnh từ `knowledge/sensitive_files.json`.
  2. Phân tích Target Identity: trích xuất domain slugs, app names, host keywords từ target_url.
  3. Component-by-Component LLM Enrichment:
     - Component 1: Config & Environment Secrets (dựa trên framework/backend, database)
     - Component 2: Target & Domain Backup Archives (dựa trên target slugs, domain, database)
     - Component 3: Admin & Internal Management Panels (dựa trên CMS, framework, domain)
     - Component 4: Debug Endpoints, Logs & API Documentation (dựa trên web server, backend)
  4. Cartesian Assembly & Slug Mutations:
     - Lắp ghép target slugs với các extension sao lưu ({slug}.zip, {slug}.sql, {slug}_backup.tar.gz...)
     - Đột biến file (.bak, .old, .save, ~) cho các tệp cấu hình.
  5. Merge & Deduplicate -> Trả về danh sách sensitive paths hoàn chỉnh cho WordlistGenAgent.
"""

import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Set

from src.coordinator.llm_logging import invoke_logged, sanitize_for_log

try:
    from langchain_core.messages import SystemMessage, HumanMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

logger = logging.getLogger(__name__)


class SensitiveFilesAssembler:
    """Engine lắp ráp và làm giàu danh sách Sensitive & Backup Files theo từng thành phần (Component-by-Component)."""

    KNOWLEDGE_FILE = Path("knowledge/sensitive_files.json")

    ARCHIVE_EXTENSIONS = [
        ".zip", ".tar.gz", ".sql", ".sql.gz", ".tar", ".bak", ".old", ".dump", ".7z", ".rar"
    ]

    CONFIG_EXTENSIONS = [
        ".env", ".json", ".yml", ".yaml", ".xml", ".ini", ".conf", ".config", ".properties", ".php", ".py"
    ]

    def __init__(self):
        self._knowledge: Dict[str, Any] = self._load_knowledge()

    def _load_knowledge(self) -> Dict[str, Any]:
        """Nạp danh mục nhạy cảm tĩnh từ knowledge base."""
        if self.KNOWLEDGE_FILE.exists():
            try:
                with open(self.KNOWLEDGE_FILE, "r", encoding="utf-8-sig") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"[SensitiveFilesAssembler] Không đọc được {self.KNOWLEDGE_FILE}: {e}")
        return {}

    # ──────────────────────────────────────────────────────────────────────
    # TARGET SLUG EXTRACTION
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def extract_target_slugs(target_url: str) -> List[str]:
        """Trích xuất các từ khóa định danh từ target_url (domain name, subdomains, path)."""
        slugs = set()
        if not target_url:
            return ["app", "backup", "site", "db"]

        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname or ""
            parts = hostname.split(".")
            # Bỏ TLD phổ biến (com, vn, net, org, edu, gov, ar, io...)
            for p in parts:
                p_clean = re.sub(r'[^a-zA-Z0-9_-]', '', p).lower()
                if p_clean and len(p_clean) > 2 and p_clean not in {"com", "net", "org", "gov", "edu", "mil", "ar", "vn", "io", "co", "www"}:
                    slugs.add(p_clean)

            # Ghép domain + subdomain chính nếu có
            if len(parts) >= 2:
                main_domain = parts[-2]
                if main_domain not in slugs and len(main_domain) > 2:
                    slugs.add(main_domain)

            # Trích xuất từ path nếu có
            path_segments = [s for s in parsed.path.split("/") if s]
            if path_segments:
                slugs.add(path_segments[0].lower())
        except Exception:
            pass

        base_slugs = ["backup", "database", "db", "site", "www", "app", "dump", "old", "web", "data"]
        all_slugs = list(slugs) + [s for s in base_slugs if s not in slugs]
        return all_slugs[:12]

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 1: CONFIG & ENVIRONMENT SECRETS
    # ──────────────────────────────────────────────────────────────────────

    def _generate_config_secrets_with_llm(
        self,
        llm: Any,
        tech_stack: Dict[str, Any],
        business_domain: str,
    ) -> List[str]:
        """Gửi tech stack cho LLM sinh các tệp cấu hình, file bí mật, credentials đặc thù theo framework."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        backend = tech_stack.get("backend", tech_stack.get("cms", "unknown"))
        language = tech_stack.get("language", "unknown")
        database = tech_stack.get("database", "unknown")

        prompt = f"""TARGET CONTEXT:
- Backend / CMS: {backend}
- Programming Language: {language}
- Database: {database}
- Business Domain: {business_domain}

YÊU CẦU: Dựa trên framework "{backend}" và ngôn ngữ "{language}", hãy sinh danh sách các đường dẫn
TỆP CẤU HÌNH NHẠY CẢM, FILE BÍ MẬT & CREDENTIALS (Configuration & Secrets) có khả năng bị lộ.
Bao gồm:
- Framework config files (VD: Laravel: .env, config/app.php; Django: settings.py, local_settings.py; Spring: application.yml, application-prod.properties; Joomla: configuration.php...)
- Cloud & secrets credentials (service-account.json, firebase.json, credentials.yml, auth.json...)
- Database connection strings & local overrides.
Tất cả các path phải bắt đầu bằng "/". Sinh 15-25 paths.

OUTPUT: Chỉ trả về JSON array thuần túy (KHÔNG markdown, KHÔNG giải thích):
["/path/to/file1", "/path/to/file2", ...]"""

        try:
            resp = invoke_logged(llm, [
                SystemMessage(content="Bạn là chuyên gia Penetration Testing & Web Security. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ], component="SensitiveFilesAssembler", operation="generate_component",
                context={"component": "config_secrets"})
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip().startswith("/")]
        except Exception as ex:
            logger.warning(f"[SensitiveFilesAssembler][LLM] Lỗi sinh config_secrets: {sanitize_for_log(str(ex))}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 2: TARGET & DOMAIN BACKUP ARCHIVES
    # ──────────────────────────────────────────────────────────────────────

    def _generate_backup_archives_with_llm(
        self,
        llm: Any,
        target_slugs: List[str],
        business_domain: str,
        database: str,
    ) -> List[str]:
        """Gửi target slugs và database cho LLM sinh các file nén backup, database dump đặc thù."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        prompt = f"""TARGET CONTEXT:
- Target Slugs / Names: {json.dumps(target_slugs[:8])}
- Business Domain: {business_domain}
- Database Engine: {database}

YÊU CẦU: Dựa vào tên target {json.dumps(target_slugs[:5])} và loại database "{database}",
hãy sinh các tên FILE SAO LƯU & DATABASE DUMP (Backup archives & SQL dumps) thường bị quản trị viên
đặt tên và bỏ quên trên web root/subdirectories.
Ví dụ: /{target_slugs[0]}.zip, /{target_slugs[0]}_backup.tar.gz, /{target_slugs[0]}_db.sql, /backup_2024.sql.gz, /dump_{database}.tar.gz...
Tất cả các path phải bắt đầu bằng "/". Sinh 15-25 paths.

OUTPUT: Chỉ trả về JSON array:
["/path/to/backup1.zip", "/path/to/backup2.sql", ...]"""

        try:
            resp = invoke_logged(llm, [
                SystemMessage(content="Bạn là chuyên gia Penetration Testing & Web Security. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ], component="SensitiveFilesAssembler", operation="generate_component",
                context={"component": "backup_archives"})
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip().startswith("/")]
        except Exception as ex:
            logger.warning(f"[SensitiveFilesAssembler][LLM] Lỗi sinh backup_archives: {sanitize_for_log(str(ex))}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 3: ADMIN & INTERNAL MANAGEMENT PANELS
    # ──────────────────────────────────────────────────────────────────────

    def _generate_admin_panels_with_llm(
        self,
        llm: Any,
        tech_stack: Dict[str, Any],
        business_domain: str,
    ) -> List[str]:
        """Gửi CMS và domain cho LLM sinh các trang quản trị nội bộ, database admin và back-office."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        backend = tech_stack.get("backend", tech_stack.get("cms", "unknown"))

        prompt = f"""TARGET CONTEXT:
- Backend / CMS: {backend}
- Business Domain: {business_domain}

YÊU CẦU: Hãy sinh danh sách các ĐƯỜNG DẪN QUẢN TRỊ NỘI BỘ, DATABASE CONSOLES & STAFF PORTALS
(Admin Panels, Management Dashboards, DB Web Tools) thường gặp trong ứng dụng loại này.
Ví dụ: /administrator, /admin-console, /pma, /adminer.php, /backend, /cpanel, /manage, /staff-portal, /internal-dashboard...
Tất cả các path phải bắt đầu bằng "/". Sinh 15-20 paths.

OUTPUT: Chỉ trả về JSON array:
["/admin_path1", "/admin_path2", ...]"""

        try:
            resp = invoke_logged(llm, [
                SystemMessage(content="Bạn là chuyên gia Penetration Testing & Web Security. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ], component="SensitiveFilesAssembler", operation="generate_component",
                context={"component": "admin_panels"})
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip().startswith("/")]
        except Exception as ex:
            logger.warning(f"[SensitiveFilesAssembler][LLM] Lỗi sinh admin_panels: {sanitize_for_log(str(ex))}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 4: DEBUG ENDPOINTS, LOGS & API DOCUMENTATION
    # ──────────────────────────────────────────────────────────────────────

    def _generate_debug_telemetry_with_llm(
        self,
        llm: Any,
        tech_stack: Dict[str, Any],
    ) -> List[str]:
        """Gửi tech stack cho LLM sinh các debug toolbars, error logs, telemetry và schema docs."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        backend = tech_stack.get("backend", tech_stack.get("cms", "unknown"))
        server = tech_stack.get("web_server", "unknown")

        prompt = f"""TARGET CONTEXT:
- Backend: {backend}
- Web Server: {server}

YÊU CẦU: Hãy sinh danh sách các ĐƯỜNG DẪN DEBUG, FILE LOG, TELEMETRY & TÀI LIỆU API (Debug toolbars,
actuators, log files, health checks, OpenAPI/Swagger schemas) có thể bị cấu hình sai và mở công khai.
Ví dụ: /server-status, /actuator/health, /actuator/env, /swagger/v1/swagger.json, /debug/pprof, /storage/logs/laravel.log, /phpinfo.php...
Tất cả các path phải bắt đầu bằng "/". Sinh 15-20 paths.

OUTPUT: Chỉ trả về JSON array:
["/debug_path1", "/debug_path2", ...]"""

        try:
            resp = invoke_logged(llm, [
                SystemMessage(content="Bạn là chuyên gia Penetration Testing & Web Security. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ], component="SensitiveFilesAssembler", operation="generate_component",
                context={"component": "debug_telemetry"})
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip().startswith("/")]
        except Exception as ex:
            logger.warning(f"[SensitiveFilesAssembler][LLM] Lỗi sinh debug_telemetry: {sanitize_for_log(str(ex))}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # ASSEMBLE: CARTESIAN MERGE & MUTATIONS
    # ──────────────────────────────────────────────────────────────────────

    def assemble(
        self,
        target_url: str = "",
        tech_stack: Optional[Dict[str, Any]] = None,
        dev_profile: Optional[Dict[str, Any]] = None,
        llm: Optional[Any] = None,
        max_paths: int = 1500,
    ) -> Dict[str, Any]:
        """
        Lắp ráp danh sách Sensitive & Backup Files qua Component-by-Component LLM Enrichment.

        Returns:
            {
                "sensitive_files": List[str],
                "components": Dict[str, List[str]],
                "metadata": {
                    "total": int,
                    "llm_enriched": bool,
                    "target_slugs": List[str],
                    "enriched_counts": Dict[str, int],
                }
            }
        """
        tech = tech_stack or {}
        profile = dev_profile or {}
        llm_analysis = profile.get("llm_analysis", {})
        business_domain = llm_analysis.get("business_domain", "web application")
        database = tech.get("database", "sql")

        target_slugs = self.extract_target_slugs(target_url)

        components: Dict[str, List[str]] = {}
        enriched_counts: Dict[str, int] = {}

        # ── 1. Nạp baseline từ Knowledge Base ─────────────────────────
        kb_categories = {
            "config_secrets": ["config_files", "secrets_keys", "ci_cd_devops", "package_managers"],
            "backup_archives": ["backup_files"],
            "admin_panels": ["database_admin", "common_admin"],
            "debug_telemetry": ["log_files", "api_testing"],
        }

        for comp_name, kb_keys in kb_categories.items():
            comp_list = []
            for k in kb_keys:
                if k in self._knowledge and isinstance(self._knowledge[k], dict):
                    comp_list.extend(self._knowledge[k].get("paths", []))
            components[comp_name] = comp_list

        # ── 2. Component 1: Config & Secrets (LLM) ───────────────────
        llm_conf = self._generate_config_secrets_with_llm(llm, tech, business_domain)
        components["config_secrets"] = list(dict.fromkeys(components["config_secrets"] + llm_conf))
        enriched_counts["config_secrets"] = len(llm_conf)

        # ── 3. Component 2: Backup Archives (Target Slugs Cartesian + LLM) ──
        # Sinh tổ hợp target_slugs x archive_extensions
        slug_backups = []
        for slug in target_slugs[:6]:
            for ext in self.ARCHIVE_EXTENSIONS:
                slug_backups.append(f"/{slug}{ext}")
                slug_backups.append(f"/{slug}_backup{ext}")
                slug_backups.append(f"/{slug}_db{ext}")
                slug_backups.append(f"/{slug}_dump{ext}")

        llm_backup = self._generate_backup_archives_with_llm(llm, target_slugs, business_domain, database)
        components["backup_archives"] = list(dict.fromkeys(components["backup_archives"] + slug_backups + llm_backup))
        enriched_counts["backup_archives"] = len(llm_backup)

        # ── 4. Component 3: Admin Panels (LLM) ───────────────────────
        llm_admin = self._generate_admin_panels_with_llm(llm, tech, business_domain)
        components["admin_panels"] = list(dict.fromkeys(components["admin_panels"] + llm_admin))
        enriched_counts["admin_panels"] = len(llm_admin)

        # ── 5. Component 4: Debug & Telemetry (LLM) ──────────────────
        llm_debug = self._generate_debug_telemetry_with_llm(llm, tech)
        components["debug_telemetry"] = list(dict.fromkeys(components["debug_telemetry"] + llm_debug))
        enriched_counts["debug_telemetry"] = len(llm_debug)

        # ── 6. Đột biến file (Mutations: .bak, .old, .save) ───────────
        mutations = set()
        for p in components["config_secrets"] + components["backup_archives"]:
            clean = p.rstrip("/")
            if any(clean.endswith(ext) for ext in [".php", ".json", ".xml", ".config", ".env", ".yaml", ".yml", ".py", ".sql"]):
                mutations.add(f"{clean}.bak")
                mutations.add(f"{clean}.old")
                mutations.add(f"{clean}.save")

        # ── 7. Tổng hợp tất cả paths ─────────────────────────────────
        final_set = set()
        for comp_paths in components.values():
            final_set.update(comp_paths)
        final_set.update(mutations)

        # Lọc sạch paths hợp lệ
        valid_paths = sorted([
            p for p in final_set
            if isinstance(p, str) and p.startswith("/") and len(p) > 1
        ])[:max_paths]

        is_llm_enriched = sum(enriched_counts.values()) > 0

        logger.info(
            f"[SensitiveFilesAssembler] Đã assemble {len(valid_paths)} sensitive paths "
            f"(LLM enriched: {is_llm_enriched}, slugs={target_slugs[:4]})"
        )

        return {
            "sensitive_files": valid_paths,
            "components": components,
            "metadata": {
                "total": len(valid_paths),
                "llm_enriched": is_llm_enriched,
                "target_slugs": target_slugs,
                "enriched_counts": enriched_counts,
                "business_domain": business_domain,
            }
        }
