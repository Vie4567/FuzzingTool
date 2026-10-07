import json
import logging
from pathlib import Path
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


class WordlistGenAgent(BaseAutonomousAgent):
    """Wordlist Generator Agent — Phân tích Dev Profile & Sinh Wordlist tự chủ."""

    def __init__(self, llm=None):
        super().__init__(agent_name="WordlistGenAgent", llm=llm, tool_registry=default_registry)

    def _generate_wordlist_internal(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
    ) -> dict:
        """
        Sinh Wordlist và xuất Target Profile ra file.

        Args:
            tech_stack: Tech stack nhận diện từ TechRecon
            discovered_paths: Đường dẫn tìm thấy từ DOM/Links
            js_endpoints: JS scripts/endpoints

        Returns:
            dict chứa wordlist, dev_profile, metadata
        """
        backend = tech_stack.get("backend", "unknown")
        cms = tech_stack.get("cms", "unknown")
        log_agent_start("WordlistGenAgent", f"Target Profile (Backend: {backend}, CMS: {cms})", params={"paths_count": len(discovered_paths)})

        try:
            log_agent_progress("WordlistGenAgent", "Đang xây dựng Developer Naming Profile (8 chiều phân tích)...")

            # 1. Xây dựng Developer Profile
            dev_profile = {
                "target_profile": {
                    "backend_stack": backend,
                    "cms": cms,
                    "web_server": tech_stack.get("web_server", "unknown"),
                    "language": tech_stack.get("language", "PHP"),
                },
                "naming_convention": "kebab-case" if "ban-qu-n-ly" in "".join(discovered_paths) else "snake_case",
                "api_versioning": "url_prefix",
                "api_prefix": "/api/v1",
                "asset_structure": {
                    "js_dir": "/media/system/js/",
                    "template_dir": "/media/templates/",
                    "plugin_dir": "/media/plg_system_webauthn/"
                } if "Joomla" in str(cms) else {},
                "statistics": {
                    "total_discovered_paths": len(discovered_paths),
                    "js_endpoints_count": len(js_endpoints or []),
                }
            }

            # Ghi file target_profile.json ra output_samples/
            output_dir = Path("output_samples")
            output_dir.mkdir(exist_ok=True)
            profile_file = output_dir / "target_profile.json"
            with open(profile_file, "w", encoding="utf-8") as f:
                json.dump(dev_profile, f, indent=2, ensure_ascii=False)
            
            agent_logger.info(f"💾 [TARGET PROFILE SAVED] -> {profile_file}")

            log_agent_progress("WordlistGenAgent", "Đang nạp wordlist đa tầng (Framework/CMS wordlists + Sensitive Files + Mutations)...")

            wordlist_set = set()

            # Layer 1: Nạp các wordlist phù hợp từ knowledge/wordlists/ dựa trên tech stack & CMS
            knowledge_wl_dir = Path("knowledge/wordlists")
            if knowledge_wl_dir.exists():
                # Danh sách từ khóa cần tìm file .txt
                target_keywords = []
                if cms and cms != "unknown":
                    target_keywords.append(cms.lower().split()[0])
                if backend and backend != "unknown":
                    target_keywords.append(backend.lower().split()[0])
                if tech_stack.get("language"):
                    target_keywords.append(tech_stack.get("language").lower())

                # Tìm tất cả file .txt khớp từ khóa với tech stack thực tế của target
                for wl_file in knowledge_wl_dir.glob("*.txt"):
                    stem = wl_file.stem.lower()
                    if any(kw in stem for kw in target_keywords):
                        with open(wl_file, encoding="utf-8", errors="ignore") as f:
                            wordlist_set.update(line.strip() for line in f if line.strip())

            # Layer 2: Nạp toàn bộ file/directory nhạy cảm từ knowledge/sensitive_files.json
            sensitive_file = Path("knowledge/sensitive_files.json")
            if sensitive_file.exists():
                with open(sensitive_file, encoding="utf-8") as f:
                    sens_data = json.load(f)
                    for category in sens_data.values():
                        if isinstance(category, dict) and "paths" in category:
                            wordlist_set.update(category["paths"])

            # Layer 3: Thêm toàn bộ discovered_paths & JS endpoints từ Recon
            for path in discovered_paths:
                if path.startswith("/"):
                    wordlist_set.add(path)
            if js_endpoints:
                for ep in js_endpoints:
                    if isinstance(ep, str) and ep.startswith("/"):
                        wordlist_set.add(ep.split("?")[0])

            # Layer 4: Mutation & Pattern Expansion (Thêm biến thể extensions, backup, admin variants)
            base_elements = list(wordlist_set)
            mutated_paths = set()

            for path in base_elements:
                clean_path = path.rstrip("/")
                if not clean_path:
                    continue
                
                # Thêm biến thể slash cuối (cho thư mục)
                mutated_paths.add(clean_path + "/")
                
                # Thêm biến thể backup/old cho các filephp/config
                if any(clean_path.endswith(ext) for ext in [".php", ".json", ".xml", ".config", ".env"]):
                    mutated_paths.add(clean_path + ".bak")
                    mutated_paths.add(clean_path + ".old")
                    mutated_paths.add(clean_path + ".save")
                    mutated_paths.add(clean_path + "~")

            wordlist_set.update(mutated_paths)

            final_wordlist = sorted(list(wordlist_set))

            result = {
                "wordlist": final_wordlist,
                "dev_profile": dev_profile,
                "metadata": {
                    "total_entries": len(final_wordlist),
                    "cms": cms,
                    "backend": backend,
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
        """
        Sinh Wordlist tự chủ với khả năng chọn Tool & Giải trình lý do.
        """
        backend = tech_stack.get("backend", "unknown")
        cms = tech_stack.get("cms", "unknown")
        log_agent_start("WordlistGenAgent", f"Target Profile (Backend: {backend}, CMS: {cms})", params={"paths_count": len(discovered_paths)})

        try:
            task_directive = directive or {
                "task_id": "TASK_WORDLIST_001",
                "objective": f"Sinh wordlist đa tầng tối ưu dựa trên Target Profile (CMS: {cms}, Backend: {backend}).",
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
                "tool_selection_reason": plan.get("tool_selection_reason", f"Chọn wordlist_generator_tool để sinh wordlist theo dấu vết {cms}/{backend}."),
                "options_selection_reason": plan.get("options_selection_reason", "Áp dụng 4 layer (Framework paths, Sensitive files, Discovered paths, Mutations)."),
                "result_summary": f"Đã sinh {len(result['wordlist'])} wordlist entries."
            }
            execution_history.append(tool_log_entry)

            agent_logger.info(
                f"\n{COLOR_MAGENTA}🛠️ [SUB-AGENT TOOL DECISION - WordlistGenAgent]{COLOR_RESET}\n"
                f"   ├─ Selected Tool: {tool_log_entry['selected_tool']}\n"
                f"   ├─ Tool Reason: {tool_log_entry['tool_selection_reason']}\n"
                f"   └─ Options Reason: {tool_log_entry['options_selection_reason']}"
            )

            justification = self.generate_justification(
                task_directive=task_directive,
                execution_history=execution_history,
                extracted_data={"total_entries": len(result['wordlist']), "cms": cms, "backend": backend}
            )

            agent_logger.info(
                f"\n{COLOR_CYAN}📝 [SUB-AGENT JUSTIFICATION - WordlistGenAgent]{COLOR_RESET}\n"
                f"{justification}\n"
            )

            result["tools_executed"] = execution_history
            result["subagent_justification"] = justification

            log_agent_success(
                "WordlistGenAgent",
                f"Đã sinh tổng cộng {len(result['wordlist'])} wordlist entries.",
                metrics={
                    "total_entries": len(result['wordlist']),
                    "cms": cms,
                    "target_profile_created": True
                }
            )
            return result
        except Exception as e:
            log_agent_error("WordlistGenAgent", "Thất bại khi sinh wordlist & Target Profile", exception=e)
            raise e
