"""
Wordlist Generator Agent Module — Phase 2 Wordlist Generation & Developer Profiling.

Thuc hien:
1. Phan tich 8 chieu thoi quen lap trinh vien (Developer Habit Profile) bang LLM.
2. Sinh cac endpoints tiem nang bang EndpointAssembler voi LLM component-by-component enrichment:
   - Phan tich URL patterns -> extract tung thanh phan (service, resource, action, ...)
   - Gui tung phan cho LLM sinh theo context (service cua domain nay la gi? resource nao thuong ton tai?)
   - Merge ket qua va assemble bang cartesian product
3. Tong hop Wordlist da tang (Framework/CMS wordlists + Sensitive files + Discovered paths + Assembler Endpoints).
4. Xuat ket qua ra output_samples/target_profile.json va output_samples/02_wordlist_result.json.
"""

import os
import json
import re
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

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
from src.coordinator.llm_logging import invoke_logged, response_log_path, sanitize_for_log
from src.agents.base_agent import BaseAutonomousAgent
from src.agents.endpoint_assembler import EndpointAssembler
from src.agents.sensitive_assembler import SensitiveFilesAssembler
from src.agents.param_assembler import ParameterAssembler
from src.tools.registry import default_registry

try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

logger = logging.getLogger(__name__)


class WordlistGenAgent(BaseAutonomousAgent):
    """Wordlist Generator Agent — Phan tich Dev Profile & Sinh Wordlist tu chu voi LLM."""

    def __init__(self, llm=None):
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
                    logger.warning(f"[WordlistGenAgent] Khong the khoi tao LLM: {sanitize_for_log(str(ex))}")

        super().__init__(agent_name="WordlistGenAgent", llm=llm, tool_registry=default_registry)

    # ==========================================================================
    # LLM ANALYSIS: 8 CHIEU THOI QUEN LAP TRINH VIEN (DEVELOPER PROFILING)
    # ==========================================================================

    def _analyze_dev_profile_with_llm(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
    ) -> dict:
        """Su dung LLM phan tich 8 chieu thoi quen cua developer."""
        combined_paths = list(dict.fromkeys((discovered_paths or []) + (js_endpoints or [])))
        sample_paths = combined_paths[:60]

        fallback_profile = self._build_heuristic_dev_profile(tech_stack, combined_paths)

        if not self.llm:
            return fallback_profile

        prompt_system = (
            "Ban la Senior Security Architect & Code Auditor chuyen phan tich phong cach lap trinh, "
            "thoi quen dat ten va kien truc API cua team phat trien web (Developer Habit Profiling).\n"
            "Hay phan tich danh sach cac endpoint thuc te va tra ve DUY NHAT mot chuoi JSON chuan mo ta "
            "DevProfile theo 8 chieu phan tich."
        )

        prompt_user = f"""
DU LIEU DAU VAO TU RECON:
- Tech Stack: {json.dumps(tech_stack, ensure_ascii=False)}
- Mau Endpoints phat hien duoc:
{json.dumps(sample_paths, indent=2, ensure_ascii=False)}

YEU CAU PHAN TICH 8 CHIEU:
1. naming_convention: dominant style (kebab-case, snake_case, camelCase, flat).
2. url_hierarchy: phan cap URL, tien to chung (VD /v1/, /api/).
3. versioning: cach quan ly version (/v1, /v2, query, none).
4. pluralization: so nhieu (users) hay so it (user).
5. crud_pattern: RESTful, RPC hay action suffix.
6. microservices_detected: danh sach microservices.
7. auth_pattern: cach dat ten route xac thuc.
8. common_actions: cac hanh dong pho bien.

OUTPUT FORMAT (KHONG CO MARKDOWN HAY GIAI THICH):
{{
  "naming_convention": "kebab-case",
  "url_hierarchy": {{
    "style": "microservice-nested",
    "common_prefix": "/v1/",
    "detected_services": ["user-service", "group-service", "payment-service"]
  }},
  "versioning": "v1",
  "pluralization": "mixed",
  "crud_pattern": "action-based",
  "common_actions": ["add", "get", "cancel", "verify", "detail"],
  "business_domain": "Mang xa hoi / Nen tang dich vu",
  "inferred_rules": [
    "Dung tien to /v1/<service-name>/<resource>/<action>",
    "Hanh dong dung dau gach noi kebab-case"
  ]
}}
"""

        try:
            log_agent_progress("WordlistGenAgent", "Dang goi LLM phan tich 8 chieu thoi quen Developer Profile...")
            response = invoke_logged(self.llm, [
                SystemMessage(content=prompt_system),
                HumanMessage(content=prompt_user),
            ], component="WordlistGenAgent", operation="analyze_dev_profile",
                context={"observed_path_count": len(combined_paths)})
            content = response.content.strip()

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
            logger.warning(f"[WordlistGenAgent] LLM Profiling gap loi, su dung fallback: {sanitize_for_log(str(ex))}")

        return fallback_profile

    def _build_heuristic_dev_profile(self, tech_stack: dict, paths: list) -> dict:
        """Xay dung Dev Profile theo thong ke heuristic khi khong co LLM."""
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

    # ==========================================================================
    # ENDPOINT ASSEMBLER: SINH ENDPOINTS THEO TUNG PHAN (COMPONENT-BY-COMPONENT)
    # ==========================================================================

    def _run_endpoint_assembler(
        self,
        dev_profile: dict,
        all_recon_paths: list,
        max_endpoints: int = 2000,
    ) -> dict:
        """
        Chay EndpointAssembler voi LLM component-by-component enrichment.

        Thay vi goi LLM 1 lan de sinh danh sach endpoint hoan chinh (de hallucination),
        assembler se:
          1. Phan tich cac URL patterns tu observed URLs -> extract parts.
          2. Gui tung phan rieng biet cho LLM theo context:
             - "Business domain nay co service nao?"       -> LLM sinh services
             - "Voi service do, resource nao ton tai?"     -> LLM sinh resources
             - "Voi resource do, action nao bi bo sot?"   -> LLM sinh actions
             - "Sub-resource nao thuong gap?"              -> LLM sinh sub_resources
          3. Merge ket qua LLM vao vocabulary roi assemble bang cartesian product.

        Returns:
            {"endpoints": List[str], "metadata": {"total": int, "llm_enriched": bool, ...}}
        """
        log_agent_progress(
            "WordlistGenAgent",
            "Khoi dong EndpointAssembler voi LLM component-by-component enrichment..."
        )
        assembler = EndpointAssembler()
        result = assembler.assemble(
            dev_profile=dev_profile,
            observed_urls=all_recon_paths,
            max_endpoints=max_endpoints,
            llm=self.llm,
        )

        enriched_info = result.get("metadata", {}).get("llm_enriched_parts", {})
        total = result["metadata"].get("total", 0)
        log_agent_progress(
            "WordlistGenAgent",
            f"Assembler sinh duoc {total} endpoints "
            + (
                f"(LLM bo sung: "
                + ", ".join(f"{k}+{v}" for k, v in enriched_info.items())
                + ")"
                if enriched_info else "(khong co LLM enrichment)"
            )
        )
        return result

    # ==========================================================================
    # SENSITIVE FILES ASSEMBLER: SINH FILE NHAY CAM THEO TUNG PHAN
    # ==========================================================================

    def _run_sensitive_assembler(
        self,
        target_url: str,
        tech_stack: dict,
        dev_profile: dict,
        max_paths: int = 1500,
    ) -> dict:
        """
        Chay SensitiveFilesAssembler voi LLM component-by-component enrichment:
          - config_secrets: LLM sinh cac file cau hinh va credentials theo framework/tech
          - backup_archives: LLM sinh ten backup va database dump theo target slug/domain
          - admin_panels: LLM sinh trang quan tri noi bo va database console
          - debug_telemetry: LLM sinh debug toolbars, error logs va API schema docs
        """
        log_agent_progress(
            "WordlistGenAgent",
            "Khoi dong SensitiveFilesAssembler voi LLM component-by-component enrichment..."
        )
        assembler = SensitiveFilesAssembler()
        result = assembler.assemble(
            target_url=target_url,
            tech_stack=tech_stack,
            dev_profile=dev_profile,
            llm=self.llm,
            max_paths=max_paths,
        )
        enriched_info = result.get("metadata", {}).get("enriched_counts", {})
        total = result.get("metadata", {}).get("total", 0)
        log_agent_progress(
            "WordlistGenAgent",
            f"SensitiveFilesAssembler sinh duoc {total} paths "
            + (
                f"(LLM bo sung: "
                + ", ".join(f"{k}+{v}" for k, v in enriched_info.items())
                + ")"
                if sum(enriched_info.values()) > 0 else "(khong co LLM enrichment)"
            )
        )
        return result

    # ==========================================================================
    # PARAMETER ASSEMBLER: SINH PARAMETER WORDLIST THEO TUNG PHAN
    # ==========================================================================

    def _run_parameter_assembler(
        self,
        dev_profile: dict,
        all_recon_paths: list,
        tech_stack: dict,
        max_params: int = 500,
    ) -> dict:
        """
        Chay ParameterAssembler voi LLM component-by-component enrichment:
          - id_lookup: LLM sinh tham so dinh danh / uuid theo resource va domain
          - pagination_sort: LLM sinh tham so phan trang, sort, date range theo framework
          - business_fields: LLM sinh tham so nghiep vu thuc te theo business domain
          - action_control: LLM sinh tham so dieu khien luong, redirect, format
          - debug_security: LLM sinh tham so debug, admin override, SSRF/LFI injection
        """
        log_agent_progress(
            "WordlistGenAgent",
            "Khoi dong ParameterAssembler voi LLM component-by-component enrichment..."
        )
        assembler = ParameterAssembler()
        result = assembler.assemble(
            dev_profile=dev_profile,
            observed_urls=all_recon_paths,
            tech_stack=tech_stack,
            llm=self.llm,
            max_params=max_params,
        )
        enriched_info = result.get("metadata", {}).get("enriched_counts", {})
        total = result.get("metadata", {}).get("total", 0)
        log_agent_progress(
            "WordlistGenAgent",
            f"ParameterAssembler sinh duoc {total} parameters "
            + (
                f"(LLM bo sung: "
                + ", ".join(f"{k}+{v}" for k, v in enriched_info.items())
                + ")"
                if sum(enriched_info.values()) > 0 else "(khong co LLM enrichment)"
            )
        )
        return result

    # ==========================================================================
    # TONG HOP WORDLIST DA TANG (4 LAYERS)
    # ==========================================================================

    def _generate_wordlist_internal(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
    ) -> dict:
        """Sinh Wordlist da tang toi uu hoa theo Target Profile."""
        backend = tech_stack.get("backend", tech_stack.get("backend_language", "unknown"))
        cms = tech_stack.get("cms", "unknown")
        all_recon_paths = list(dict.fromkeys((discovered_paths or []) + (js_endpoints or [])))

        log_agent_start("WordlistGenAgent", f"Target Profile (Backend: {backend}, Paths: {len(all_recon_paths)})")

        try:
            # 1. Phan tich Developer Profile bang LLM
            dev_profile = self._analyze_dev_profile_with_llm(tech_stack, discovered_paths, js_endpoints)

            output_dir = Path("output_samples")
            output_dir.mkdir(exist_ok=True)
            profile_file = output_dir / "target_profile.json"
            with open(profile_file, "w", encoding="utf-8") as f:
                json.dump(dev_profile, f, indent=2, ensure_ascii=False)
            agent_logger.info(f"[TARGET PROFILE SAVED] -> {profile_file}")

            # 2. EndpointAssembler: sinh endpoints theo tung thanh phan voi LLM enrichment
            assembler_result = self._run_endpoint_assembler(
                dev_profile=dev_profile,
                all_recon_paths=all_recon_paths,
                max_endpoints=2000,
            )
            assembler_endpoints = assembler_result.get("endpoints", [])
            assembler_meta = assembler_result.get("metadata", {})

            # 3. SensitiveFilesAssembler: sinh sensitive & backup files theo tung thanh phan voi LLM enrichment
            target_url = tech_stack.get("target_url", "")
            sensitive_result = self._run_sensitive_assembler(
                target_url=target_url,
                tech_stack=tech_stack,
                dev_profile=dev_profile,
                max_paths=1500,
            )
            sensitive_paths = sensitive_result.get("sensitive_files", [])
            sensitive_meta = sensitive_result.get("metadata", {})

            # 4. ParameterAssembler: sinh parameter wordlist theo tung thanh phan voi LLM enrichment
            parameter_result = self._run_parameter_assembler(
                dev_profile=dev_profile,
                all_recon_paths=all_recon_paths,
                tech_stack=tech_stack,
                max_params=500,
            )
            parameter_wordlist = parameter_result.get("parameters", [])
            parameter_meta = parameter_result.get("metadata", {})

            # Preserve how component candidates become paths separately from the
            # final merged wordlist. These are suggestions, not HTTP findings.
            trace_file = output_dir / "02_pattern_trace.json"
            generation_strategy = "component_by_component_then_template_assembly"
            trace = {
                "generation_strategy": generation_strategy,
                "verification": "candidate_generation_only",
                "llm_response_log_file": str(Path(response_log_path()).resolve()),
                "endpoint_assembly": assembler_meta,
                "sensitive_file_groups": sensitive_result.get("components", {}),
                "parameter_groups": parameter_result.get("components", {}),
                "notes": [
                    "LLM proposes vocabulary per selected semantic slot; templates assemble endpoints.",
                    "Prefix and ID values use observed/profile/knowledge inputs rather than invented LLM IDs.",
                    "Sensitive file and parameter assemblers generate separate candidate groups.",
                    "Legacy llm_predicted_* fields count assembled endpoints, including knowledge-based candidates.",
                ],
            }
            with trace_file.open("w", encoding="utf-8") as stream:
                json.dump(sanitize_for_log(trace), stream, indent=2, ensure_ascii=False)
            log_agent_progress("WordlistGenAgent", f"Pattern trace saved: {trace_file}")

            # Luu parameter wordlist ra file rieng
            param_file = output_dir / "02_parameter_wordlist.txt"
            with open(param_file, "w", encoding="utf-8") as f:
                f.write("\n".join(parameter_wordlist))
            agent_logger.info(f"[PARAMETER WORDLIST SAVED] -> {param_file} ({len(parameter_wordlist)} params)")

            wordlist_set = set()

            # Layer 1: Knowledge Base Wordlists (Theo Framework/Tech)
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

            # Layer 2: Sensitive Files & Backup Wordlists (Component-by-Component LLM Enriched)
            for p in sensitive_paths:
                if isinstance(p, str) and p.startswith("/"):
                    wordlist_set.add(p)

            # Layer 3: Toan bo Endpoints thu thap duoc tu Recon & JS
            for p in all_recon_paths:
                if isinstance(p, str) and p.startswith("/"):
                    wordlist_set.add(p.split("?")[0])

            # Layer 4: Assembler Endpoints (LLM Component-by-Component)
            for p in assembler_endpoints:
                if isinstance(p, str) and p.startswith("/"):
                    wordlist_set.add(p)

            # Mutations
            mutated_paths = set()
            for p in list(wordlist_set):
                clean_p = p.rstrip("/")
                if any(clean_p.endswith(ext) for ext in [".php", ".json", ".xml", ".config", ".env", ".yaml", ".yml"]):
                    mutated_paths.add(clean_p + ".bak")
                    mutated_paths.add(clean_p + ".old")

            wordlist_set.update(mutated_paths)
            final_wordlist = sorted(list(wordlist_set))

            result = {
                "target_url": target_url,
                "wordlist": final_wordlist,
                "parameter_wordlist": parameter_wordlist,
                "parameter_sample": parameter_wordlist[:20],
                "parameter_metadata": parameter_meta,
                "dev_profile": dev_profile,
                "assembler_endpoints_count": len(assembler_endpoints),
                "assembler_sample": assembler_endpoints[:15],
                "assembler_metadata": assembler_meta,
                "generation_strategy": generation_strategy,
                "pattern_trace_file": str(trace_file),
                "sensitive_files_count": len(sensitive_paths),
                "sensitive_sample": sensitive_paths[:15],
                "sensitive_metadata": sensitive_meta,
                "llm_predicted_count": len(assembler_endpoints),
                "llm_predicted_sample": assembler_endpoints[:15],
                "metadata": {
                    "total_entries": len(final_wordlist),
                    "generation_strategy": generation_strategy,
                    "endpoint_candidate_sources": ["observed_paths", "llm_components", "knowledge"],
                    "llm_predicted_paths_is_legacy_alias": True,
                    "recon_paths_included": len(all_recon_paths),
                    "assembler_endpoints": len(assembler_endpoints),
                    "llm_predicted_paths": len(assembler_endpoints),
                    "sensitive_paths_count": len(sensitive_paths),
                    "parameter_entries": len(parameter_wordlist),
                    "llm_enriched": assembler_meta.get("llm_enriched", False) or sensitive_meta.get("llm_enriched", False) or parameter_meta.get("llm_enriched", False),
                    "llm_enriched_parts": assembler_meta.get("llm_enriched_parts", {}),
                    "llm_enriched_sensitive": sensitive_meta.get("enriched_counts", {}),
                    "llm_enriched_params": parameter_meta.get("enriched_counts", {}),
                    "target_profile_file": str(profile_file),
                    "parameter_wordlist_file": str(param_file),
                    "pattern_trace_file": str(trace_file),
                    "llm_response_log_file": str(Path(response_log_path()).resolve()),
                },
            }
            return result

        except Exception as e:
            log_agent_error("WordlistGenAgent", "That bai khi sinh wordlist & Target Profile", exception=e)
            raise e

    def execute(
        self,
        tech_stack: dict,
        discovered_paths: list,
        js_endpoints: list = None,
        directive: dict = None,
    ) -> dict:
        """Sinh Wordlist tu chu voi giai trinh ly do (Autonomous Subagent)."""
        backend = tech_stack.get("backend", tech_stack.get("backend_language", "unknown"))
        cms = tech_stack.get("cms", "unknown")

        try:
            task_directive = directive or {
                "task_id": "TASK_WORDLIST_001",
                "objective": f"Phan tich DevProfile & sinh wordlist da tang thich ung theo {backend}/{cms}.",
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

            assembler_count = result.get("assembler_endpoints_count", result.get("llm_predicted_count", 0))
            param_count = len(result.get("parameter_wordlist", []))
            sensitive_count = result.get("sensitive_files_count", 0)

            tool_log_entry = {
                "selected_tool": plan.get("selected_tool", "wordlist_generator_tool"),
                "options": plan.get("options", {"cms": cms, "backend": backend}),
                "tool_selection_reason": plan.get(
                    "tool_selection_reason",
                    "Chon wordlist_generator_tool ket hop phan tich LLM 8 chieu va component-by-component enrichment cho Endpoints, Sensitive Files va Parameters."
                ),
                "options_selection_reason": plan.get(
                    "options_selection_reason",
                    "Kich hoat 4 Layer: Framework, Sensitive Files Assembler, Recon paths, va Endpoint/Parameter Assemblers."
                ),
                "result_summary": (
                    f"Da sinh {len(result['wordlist'])} wordlist paths "
                    f"(assembler: {assembler_count} endpoints, sensitive: {sensitive_count} paths) "
                    f"va {param_count} parameters."
                )
            }
            execution_history.append(tool_log_entry)

            justification = self.generate_justification(
                task_directive=task_directive,
                execution_history=execution_history,
                extracted_data={
                    "total_entries": len(result['wordlist']),
                    "assembler_endpoints": assembler_count,
                    "sensitive_files": sensitive_count,
                    "parameters_generated": param_count,
                }
            )

            result["tools_executed"] = execution_history
            result["subagent_justification"] = justification

            output_file = Path("output_samples/02_wordlist_result.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

            meta = result.get("metadata", {})
            log_agent_success(
                "WordlistGenAgent",
                f"Da sinh {len(result['wordlist'])} wordlist paths "
                f"(assembler: {assembler_count}, sensitive: {sensitive_count}) "
                f"va {param_count} parameters "
                f"(LLM enriched: {meta.get('llm_enriched', False)}, da luu vao {output_file}).",
                metrics={
                    "total_entries": len(result['wordlist']),
                    "assembler_endpoints": assembler_count,
                    "sensitive_files": sensitive_count,
                    "parameters": param_count,
                    "llm_enriched": meta.get("llm_enriched", False),
                    "file": str(output_file),
                }
            )
            return result

        except Exception as e:
            log_agent_error("WordlistGenAgent", "That bai khi thuc thi WordlistGenAgent", exception=e)
            raise e
