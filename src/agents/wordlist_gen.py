"""
Wordlist Generator Agent Module — Phase 2 Wordlist Generation & Developer Profiling.

Thực hiện:
1. Phân tích 8 chiều thói quen lập trình viên (Developer Habit Profile) bằng LLM.
2. Dự đoán và sinh các endpoints tiềm năng (CRUD, Microservices, Auth) bằng LLM.
3. Lọc qua Anti-Hallucination Filter.
4. Tổng hợp Wordlist đa tầng (Framework/CMS wordlists + Sensitive files + Discovered paths + LLM Predictions).
5. Xuất kết quả ra output_samples/target_profile.json và output_samples/02_wordlist_result.json.
"""

import os
import json
import re
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

# Tự động nạp file .env (hỗ trợ cả khi chưa cài python-dotenv)
try:
    import dotenv
    dotenv.load_dotenv()
except ImportError:
    env_path = Path(".env")
    if env_path.exists():
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

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

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

logger = logging.getLogger(__name__)


class WordlistGenAgent(BaseAutonomousAgent):
    """Wordlist Generator Agent — Phân tích Dev Profile & Sinh Wordlist tự chủ với LLM."""

    def __init__(self, llm=None):
        # Tự động nạp LLM từ biến môi trường nếu không truyền vào
        if llm is None and _LANGCHAIN_AVAILABLE:
            api_key = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
            base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
            model_name = os.getenv("LLM_MODEL", "deepseek-flash")
            temperature = float(os.getenv("LLM_TEMPERATURE", "0.2"))

            if api_key:
                try:
                    llm = ChatOpenAI(
                        api_key=api_key,
                        base_url=base_url if "deepseek" in model_name.lower() or "deepseek" in base_url else None,
                        model=model_name,
                        temperature=temperature,
                    )
                except Exception as ex:
                    logger.warning(f"[WordlistGenAgent] Không thể khởi tạo LLM: {ex}")

        super().__init__(agent_name="WordlistGenAgent", llm=llm, tool_registry=default_registry)

    # ══════════════════════════════════════════════════════════════════════════
    # LLM ANALYSIS: 8 CHIỀU THÓI QUEN LẬP TRÌNH VIÊN (DEVELOPER PROFILING)
    # ══════════════════════════════════════════════════════════════════════════

    def _analyze_dev_profile_with_llm(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
    ) -> dict:
        """Sử dụng LLM phân tích 8 chiều thói quen của developer."""
        combined_paths = list(set((discovered_paths or []) + (js_endpoints or [])))
        sample_paths = combined_paths[:60]  # Lấy mẫu đại diện tránh quá tải token

        # Fallback profile theo rule nếu không có LLM
        fallback_profile = self._build_heuristic_dev_profile(tech_stack, combined_paths)

        if not self.llm:
            return fallback_profile

        prompt_system = (
            "Bạn là Senior Security Architect & Code Auditor chuyên phân tích phong cách lập trình, "
            "thói quen đặt tên và kiến trúc API của team phát triển web (Developer Habit Profiling).\n"
            "Hãy phân tích danh sách các endpoint thực tế và trả về DUY NHẤT một chuỗi JSON chuẩn mô tả "
            "DevProfile theo 8 chiều phân tích."
        )

        prompt_user = f"""
DỮ LIỆU ĐẦU VÀO TỪ RECON:
- Tech Stack: {json.dumps(tech_stack, ensure_ascii=False)}
- Mẫu Endpoints phát hiện được:
{json.dumps(sample_paths, indent=2, ensure_ascii=False)}

YÊU CẦU PHÂN TÍCH 8 CHIỀU:
1. naming_convention: dominant style (kebab-case, snake_case, camelCase, flat) và tỷ lệ.
2. url_hierarchy: phân cấp URL (nested, microservice, resource, flat), tiền tố chung (VD /v1/, /api/).
3. versioning: cách quản lý version (/v1, /v2, query, none).
4. pluralization: số nhiều (users, posts) hay số ít (user, post).
5. crud_pattern: phong cách đặt tên hành động (RESTful, RPC kiểu add-group/get-posts, hay action suffix).
6. microservices_detected: danh sách các microservices (VD: user-service, payment-service, group-service, auth).
7. auth_pattern: cách đặt tên các route xác thực (accounts, verify, login).
8. common_actions: các hành động phổ biến (add, update, delete, get, list, search, cancel).

OUTPUT FORMAT: Trả về JSON theo định dạng sau (KHÔNG CÓ MARKDOWN HAY GIẢI THÍCH):
{{
  "naming_convention": "kebab-case",
  "url_hierarchy": {{
    "style": "microservice-nested",
    "common_prefix": "/v1/",
    "detected_services": ["user-service", "group-service", "payment-service", "identity-service"]
  }},
  "versioning": "v1",
  "pluralization": "mixed",
  "crud_pattern": "action-based",
  "common_actions": ["add", "get", "cancel", "verify", "detail"],
  "business_domain": "Mạng xã hội / Nền tảng dịch vụ",
  "inferred_rules": [
    "Dùng tiền tố /v1/<service-name>/<resource>/<action>",
    "Hành động dùng dấu gạch nối kebab-case"
  ]
}}
"""

        try:
            log_agent_progress("WordlistGenAgent", "🧠 Đang gọi LLM phân tích 8 chiều thói quen Developer Profile...")
            response = self.llm.invoke([
                SystemMessage(content=prompt_system),
                HumanMessage(content=prompt_user),
            ])
            content = response.content.strip()

            # Trích xuất JSON từ phản hồi LLM
            m = re.search(r'\{.*\}', content, re.DOTALL)
            if m:
                llm_data = json.loads(m.group(0))
                dev_profile = {
                    "target_profile": {
                        "backend_stack": tech_stack.get("backend", tech_stack.get("backend_language", "unknown")),
                        "web_server": tech_stack.get("web_server", "unknown"),
                        "language": tech_stack.get("language", "unknown"),
                    },
                    "llm_analysis": llm_data,
                    "naming_convention": llm_data.get("naming_convention", "kebab-case"),
                    "api_versioning": llm_data.get("versioning", "v1"),
                    "common_prefix": llm_data.get("url_hierarchy", {}).get("common_prefix", "/v1/"),
                    "detected_services": llm_data.get("url_hierarchy", {}).get("detected_services", []),
                    "statistics": {
                        "total_observed_paths": len(combined_paths),
                    }
                }
                return dev_profile
        except Exception as ex:
            logger.warning(f"[WordlistGenAgent] LLM Profiling gặp lỗi, sử dụng fallback: {ex}")

        return fallback_profile

    def _build_heuristic_dev_profile(self, tech_stack: dict, paths: list) -> dict:
        """Xây dựng Dev Profile theo thống kê heuristic khi không có LLM."""
        services = set()
        for p in paths:
            m = re.search(r'/v[0-9]+/([a-zA-Z0-9_\-]+-service)', p)
            if m:
                services.add(m.group(1))

        return {
            "target_profile": {
                "backend_stack": tech_stack.get("backend", tech_stack.get("backend_language", "unknown")),
                "web_server": tech_stack.get("web_server", "unknown"),
                "language": tech_stack.get("language", "unknown"),
            },
            "llm_analysis": {
                "naming_convention": "kebab-case",
                "url_hierarchy": {
                    "style": "microservice-nested" if services else "nested",
                    "common_prefix": "/v1/",
                    "detected_services": list(services),
                },
                "versioning": "v1",
                "crud_pattern": "action-based",
            },
            "naming_convention": "kebab-case",
            "api_versioning": "v1",
            "common_prefix": "/v1/",
            "detected_services": list(services),
            "statistics": {
                "total_observed_paths": len(paths),
            }
        }

    # ══════════════════════════════════════════════════════════════════════════
    # LLM PREDICTIVE MUTATION: SINH ENDPOINTS TIỀM NĂNG
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_predicted_endpoints_with_llm(
        self, dev_profile: dict, observed_paths: list
    ) -> List[str]:
        """Sử dụng LLM để suy luận và sinh các endpoints tiềm năng chưa được phát hiện."""
        if not self.llm:
            return []

        sample_paths = observed_paths[:40]
        services = dev_profile.get("detected_services", [])
        naming = dev_profile.get("naming_convention", "kebab-case")

        prompt_system = (
            "Bạn là chuyên gia Penetration Testing & API Fuzzing. "
            "Dựa trên các API endpoints hiện có và thói quen của developer, hãy SUY LUẬN và SINH RA "
            "danh sách các endpoints ẩn có khả năng tồn tại cao (CRUD operations còn thiếu, admin endpoints, "
            "export, import, status, debug, internal services)."
        )

        prompt_user = f"""
THÔNG TIN PHÂN TÍCH:
- Naming Style: {naming}
- Các Microservices đã phát hiện: {json.dumps(services)}
- Mẫu endpoints quan sát được:
{json.dumps(sample_paths, indent=2)}

YÊU CẦU:
1. Với mỗi microservice và resource quan sát được, hãy sinh các endpoints tương ứng còn thiếu:
   Ví dụ: thấy /add-group -> sinh /delete-group, /update-group, /get-members, /leave-group.
   Ví dụ: thấy /matched-profiles -> sinh /block-profile, /report-profile, /profile-settings.
   Ví dụ: thấy /admin/publishers -> sinh /admin/users, /admin/analytics, /admin/logs, /admin/config.
2. BẮT BUỘC tuân thủ đúng quy tắc đặt tên {naming} và cấu trúc tiền tố /v1/...
3. Sinh khoảng 50 - 80 đường dẫn tiềm năng nhất.

OUTPUT FORMAT: Trả về danh sách JSON các đường dẫn (bắt đầu bằng /), KHÔNG CÓ GIẢI THÍCH:
[
  "/v1/group-service/group/delete-group",
  "/v1/group-service/group/update-group",
  "/v1/user-service/users/profile-settings"
]
"""

        try:
            log_agent_progress("WordlistGenAgent", "🔮 Đang dùng LLM suy luận các hidden API & Microservice endpoints...")
            response = self.llm.invoke([
                SystemMessage(content=prompt_system),
                HumanMessage(content=prompt_user),
            ])
            content = response.content.strip()
            m = re.search(r'\[.*\]', content, re.DOTALL)
            if m:
                predicted = json.loads(m.group(0))
                # Anti-hallucination filter
                valid_paths = [p for p in predicted if isinstance(p, str) and p.startswith("/") and " " not in p]
                log_agent_progress("WordlistGenAgent", f"✨ LLM đã suy luận thành công {len(valid_paths)} endpoints tiềm năng!")
                return valid_paths
        except Exception as ex:
            logger.warning(f"[WordlistGenAgent] Lỗi khi sinh predicted endpoints bằng LLM: {ex}")

        return []

    # ══════════════════════════════════════════════════════════════════════════
    # TỔNG HỢP WORDLIST ĐA TẦNG (4 LAYERS)
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_wordlist_internal(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
    ) -> dict:
        """Sinh Wordlist đa tầng tối ưu hoá theo Target Profile."""
        backend = tech_stack.get("backend", tech_stack.get("backend_language", "unknown"))
        cms = tech_stack.get("cms", "unknown")
        all_recon_paths = list(set((discovered_paths or []) + (js_endpoints or [])))

        log_agent_start("WordlistGenAgent", f"Target Profile (Backend: {backend}, Paths: {len(all_recon_paths)})")

        try:
            # 1. Phân tích Developer Profile bằng LLM
            dev_profile = self._analyze_dev_profile_with_llm(tech_stack, discovered_paths, js_endpoints)

            # Lưu file target_profile.json
            output_dir = Path("output_samples")
            output_dir.mkdir(exist_ok=True)
            profile_file = output_dir / "target_profile.json"
            with open(profile_file, "w", encoding="utf-8") as f:
                json.dump(dev_profile, f, indent=2, ensure_ascii=False)
            agent_logger.info(f"💾 [TARGET PROFILE SAVED] -> {profile_file}")

            # 2. Sinh các endpoint tiềm năng bằng LLM (Layer 4 Predictive)
            predicted_paths = self._generate_predicted_endpoints_with_llm(dev_profile, all_recon_paths)

            wordlist_set = set()

            # ── Layer 1: Knowledge Base Wordlists (Theo Framework/Tech) ──────
            knowledge_wl_dir = Path("knowledge/wordlists")
            if knowledge_wl_dir.exists():
                target_keywords = []
                if cms and cms != "unknown":
                    target_keywords.append(str(cms).lower().split()[0])
                if backend and backend != "unknown":
                    target_keywords.append(str(backend).lower().split()[0])
                if tech_stack.get("language"):
                    target_keywords.append(str(tech_stack["language"]).lower())

                for wl_file in knowledge_wl_dir.glob("*.txt"):
                    stem = wl_file.stem.lower()
                    if any(kw in stem for kw in target_keywords):
                        with open(wl_file, encoding="utf-8", errors="ignore") as f:
                            wordlist_set.update(line.strip() for line in f if line.strip() and not line.startswith("#"))

            # ── Layer 2: Sensitive Files & Backup Wordlists ──────────────────
            sensitive_file = Path("knowledge/sensitive_files.json")
            if sensitive_file.exists():
                with open(sensitive_file, encoding="utf-8") as f:
                    sens_data = json.load(f)
                    for category in sens_data.values():
                        if isinstance(category, dict) and "paths" in category:
                            wordlist_set.update(category["paths"])

            # ── Layer 3: Toàn bộ Endpoints thu thập được từ Recon & JS ────────
            for p in all_recon_paths:
                if isinstance(p, str) and p.startswith("/"):
                    wordlist_set.add(p.split("?")[0])

            # ── Layer 4: LLM Predictive Endpoints & Mutations ────────────────
            for p in predicted_paths:
                wordlist_set.add(p)

            # Mutations (Thêm slash, biến thể backup cho file nhạy cảm)
            mutated_paths = set()
            for p in list(wordlist_set):
                clean_p = p.rstrip("/")
                if any(clean_p.endswith(ext) for ext in [".php", ".json", ".xml", ".config", ".env", ".yaml", ".yml"]):
                    mutated_paths.add(clean_p + ".bak")
                    mutated_paths.add(clean_p + ".old")

            wordlist_set.update(mutated_paths)

            final_wordlist = sorted(list(wordlist_set))

            result = {
                "target_url": tech_stack.get("target_url", ""),
                "wordlist": final_wordlist,
                "dev_profile": dev_profile,
                "llm_predicted_count": len(predicted_paths),
                "llm_predicted_sample": predicted_paths[:15],
                "metadata": {
                    "total_entries": len(final_wordlist),
                    "recon_paths_included": len(all_recon_paths),
                    "llm_predicted_paths": len(predicted_paths),
                    "target_profile_file": str(profile_file),
                },
            }
            return result

        except Exception as e:
            log_agent_error("WordlistGenAgent", "Thất bại khi sinh wordlist & Target Profile", exception=e)
            raise e

    def execute(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
        directive: dict = None,
    ) -> dict:
        """Sinh Wordlist tự chủ với giải trình lý do (Autonomous Subagent)."""
        backend = tech_stack.get("backend", tech_stack.get("backend_language", "unknown"))
        cms = tech_stack.get("cms", "unknown")

        try:
            task_directive = directive or {
                "task_id": "TASK_WORDLIST_001",
                "objective": f"Phân tích DevProfile & sinh wordlist đa tầng thích ứng theo {backend}/{cms}.",
                "constraints": {"max_entries": 10000}
            }

            wordlist_tools = self.tool_registry.list_tools(filter_names=["wordlist_generator_tool"])
            execution_history = []

            result = self._generate_wordlist_internal(tech_stack, discovered_paths, js_endpoints)

            plan = self.plan_tool_execution(
                task_directive=task_directive,
                available_tools=wordlist_tools,
                execution_history=execution_history
            )

            tool_log_entry = {
                "selected_tool": plan.get("selected_tool", "wordlist_generator_tool"),
                "options": plan.get("options", {"cms": cms, "backend": backend}),
                "tool_selection_reason": plan.get("tool_selection_reason", "Chọn wordlist_generator_tool kết hợp phân tích LLM 8 chiều và mutation."),
                "options_selection_reason": plan.get("options_selection_reason", "Kích hoạt 4 Layer: Framework, Sensitive files, Recon paths và LLM Predictions."),
                "result_summary": f"Đã sinh {len(result['wordlist'])} wordlist entries (gồm {result['llm_predicted_count']} paths do LLM suy luận)."
            }
            execution_history.append(tool_log_entry)

            justification = self.generate_justification(
                task_directive=task_directive,
                execution_history=execution_history,
                extracted_data={"total_entries": len(result['wordlist']), "predicted": result['llm_predicted_count']}
            )

            result["tools_executed"] = execution_history
            result["subagent_justification"] = justification

            # Ghi kết quả Wordlist ra output_samples/02_wordlist_result.json
            output_file = Path("output_samples/02_wordlist_result.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            log_agent_success(
                "WordlistGenAgent",
                f"Đã sinh {len(result['wordlist'])} wordlist entries (đã lưu vào {output_file}).",
                metrics={
                    "total_entries": len(result['wordlist']),
                    "llm_predictions": result['llm_predicted_count'],
                    "file": str(output_file),
                }
            )
            return result

        except Exception as e:
            log_agent_error("WordlistGenAgent", "Thất bại khi thực thi WordlistGenAgent", exception=e)
            raise e
