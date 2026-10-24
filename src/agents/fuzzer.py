"""
Fuzzing Agent — Hệ thống con Fuzzing (Planner → Engine → Analyst).

Thực thi Fuzzing đường dẫn với số liệu HTTP thực:
- Nạp tri thức công cụ từ `knowledge/ffuf_knowledge.json`.
- Tích hợp EndpointAssembler: nhận dev_profile → chọn patterns → generate phần → lắp ráp endpoints.
- Tự suy luận chọn tool, chọn options (flags) & giải trình kết quả.
"""

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Optional, List

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
from src.agents.endpoint_assembler import EndpointAssembler
from src.tools.registry import default_registry

logger = logging.getLogger(__name__)


class FuzzingAgent(BaseAutonomousAgent):
    """Fuzzing Agent — Giữ nguyên số liệu đo và báo rõ kết quả một phần/lỗi."""

    def __init__(self, llm=None):
        super().__init__(agent_name="FuzzingAgent", llm=llm, tool_registry=default_registry)
        self.ffuf_knowledge = self._load_knowledge("ffuf_knowledge.json")
        self.principles = self._load_knowledge("agent_operating_principles.json")
        self.assembler = EndpointAssembler()

    def _load_knowledge(self, fname: str) -> dict:
        p = Path(__file__).resolve().parents[2] / "knowledge" / fname
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Không thể đọc file tri thức {fname}: {e}")
        return {}

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 0: ENDPOINT ASSEMBLY (Pattern Engine)
    # ══════════════════════════════════════════════════════════════════════

    def build_pattern_wordlist(
        self,
        dev_profile: dict,
        observed_urls: Optional[List[str]] = None,
        max_endpoints: int = 1500,
        selected_pattern_ids: Optional[List[str]] = None,
    ) -> dict:
        """
        Dùng EndpointAssembler để sinh danh sách endpoint từ dev_profile
        + observed_urls (URLs thật từ recon/JS/fuzzing).

        Luồng:
          0. analyze_observed_urls(): parse URLs thật → extract parts target-specific.
          1. Chọn patterns phù hợp (ưu tiên pattern khớp với URLs thật).
          2. Generate từng phần (prefix, service, resource, action...) — target-specific đứng đầu.
          3. Lắp ráp cartesian product → danh sách endpoints.

        Args:
            dev_profile: Kết quả từ WordlistGenAgent.
            observed_urls: URLs thật đã thu thập (recon, JS extraction, fuzzing results...).
                           Nếu cung cấp, vocabulary sẽ được bổ sung từ URL thật.
            max_endpoints: Giới hạn tổng số endpoints (default 1500).
            selected_pattern_ids: Nếu không None, override lựa chọn pattern tự động.

        Returns:
            {
                "endpoints": List[str],
                "metadata": {..., "target_specific": bool, "url_analysis": {...}}
            }
        """
        ts_label = f"{len(observed_urls)} observed URLs" if observed_urls else "không có observed URLs"
        log_agent_progress(
            "FuzzingAgent",
            f"🧩 [Pattern Engine] Đang lắp ráp endpoints từ dev_profile + {ts_label} "
            f"(max={max_endpoints})..."
        )

        result = self.assembler.assemble(
            dev_profile=dev_profile,
            observed_urls=observed_urls,
            max_endpoints=max_endpoints,
            selected_pattern_ids=selected_pattern_ids,
        )

        url_analysis = result["metadata"].get("url_analysis", {})
        extracted = url_analysis.get("extracted_parts", {})

        agent_logger.info(
            f"\n{COLOR_MAGENTA}🧩 [PATTERN ENGINE - FuzzingAgent]{COLOR_RESET}\n"
            f"   ├─ Patterns used      : {result['metadata']['patterns_used']}\n"
            f"   ├─ Target-specific    : {result['metadata'].get('target_specific', False)}\n"
            f"   ├─ Observed URLs used : {url_analysis.get('url_count', 0)}\n"
            f"   ├─ Extracted services : {extracted.get('service', [])[:5]}\n"
            f"   ├─ Extracted resources: {extracted.get('resource', [])[:5]}\n"
            f"   ├─ Extracted actions  : {extracted.get('action', [])[:5]}\n"
            f"   ├─ Total assembled    : {result['metadata']['total']} endpoints\n"
            f"   └─ Parts vocab sizes  : "
            f"{json.dumps(result['metadata']['parts_counts'], ensure_ascii=False)}"
        )
        return result

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: REAL HTTP ENGINE (compatibility entry point)
    # ══════════════════════════════════════════════════════════════════════

    def _run_fuzzing_internal(
        self,
        target_url: str,
        wordlist: list,
        waf_detected: bool = False,
        waf_type: str = None,
        **config_adjustments,
    ) -> dict:
        from src.tools.http_fuzzing import run_http_fuzzing
        return run_http_fuzzing(target_url, wordlist, **config_adjustments)

    @staticmethod
    def _public_options(options: dict) -> dict:
        """Keep credentials and large wordlists out of logs and LLM explanations."""
        public = dict(options)
        if "wordlist" in public:
            public["wordlist_count"] = len(public.pop("wordlist"))
        if isinstance(public.get("headers"), dict):
            public["headers"] = {key: "<redacted>" for key in public["headers"]}
        for key in ("proxy", "proxy_profiles", "proxy_profiles_env", "proxy_pool", "proxies", "proxy_list",
                    "post_data", "body", "cookie", "token", "api_key", "password"):
            if public.get(key):
                public[key] = "<redacted>"
        return public

    @staticmethod
    def _normalize_options(options: dict) -> dict:
        normalized = dict(options)
        for alias, canonical in {
            "delay_between_requests_ms": "delay_ms",
            "match_status_codes": "match_codes",
            "max_entries_to_use": "max_requests",
            "maxtime": "max_scan_seconds",
            "max_duration_seconds": "max_scan_seconds",
            "timeout": "timeout_seconds",
            "method": "http_method",
            "body": "post_data",
        }.items():
            if alias in normalized:
                normalized.setdefault(canonical, normalized.pop(alias))
        return normalized

    @staticmethod
    def _observed_stats(tool_data: dict, results: list) -> dict:
        """Derive missing response statistics without inventing request totals."""
        stats = dict(tool_data.get("stats") or {})
        responses = [row for row in results if row.get("status_code") is not None]
        times = [row["response_time"] for row in responses
                 if isinstance(row.get("response_time"), (int, float))]
        stats.setdefault("total_requests", tool_data.get("total_requests"))
        stats.setdefault("planned_requests", tool_data.get("planned_requests"))
        stats.setdefault("returned_results", len(results))
        stats.setdefault("matched_responses", len(responses))
        stats.setdefault("status_codes", dict(Counter(str(row["status_code"]) for row in responses)))
        stats.setdefault("avg_response_time", sum(times) / len(times) if times else None)
        stats.setdefault("measurement_scope", "returned_responses")
        return stats

    # ══════════════════════════════════════════════════════════════════════
    # EXECUTE — Entry point chính
    # ══════════════════════════════════════════════════════════════════════

    def execute(
        self,
        target_url: str,
        wordlist: list,
        waf_detected: bool = False,
        waf_type: str = None,
        directive: dict = None,
        dev_profile: dict = None,
        observed_urls: Optional[List[str]] = None,
        use_pattern_engine: bool = True,
        max_pattern_endpoints: int = 1500,
        selected_pattern_ids: Optional[List[str]] = None,
        **config_adjustments,
    ) -> dict:
        """
        Thực thi Fuzzing Agent.

        Args:
            target_url: URL mục tiêu.
            wordlist: Wordlist cơ sở từ WordlistGenAgent.
            waf_detected: Có WAF hay không.
            waf_type: Loại WAF.
            directive: Chỉ thị từ Coordinator (override mặc định).
            dev_profile: Dev profile từ WordlistGenAgent để Pattern Engine dùng.
            observed_urls: URLs thật từ recon/JS/fuzzing cũ để Pattern Engine học vocabulary.
                           Càng nhiều URL thật → vocabulary target-specific càng chính xác.
            use_pattern_engine: Bật/tắt Pattern Engine (lắp ráp endpoint từ patterns).
            max_pattern_endpoints: Giới hạn endpoints sinh ra từ Pattern Engine.
            selected_pattern_ids: Override pattern selection thủ công.
        """
        log_agent_start("FuzzingAgent", target_url, params={
            "wordlist_size": len(wordlist),
            "waf_detected": waf_detected,
            "waf_type": waf_type,
            "use_pattern_engine": use_pattern_engine,
            "config_adjustments": self._public_options(config_adjustments),
        })

        try:
            # ── Phase 0: Pattern Engine ──────────────────────────────────
            pattern_assembly_result = {}
            if use_pattern_engine and dev_profile:
                pattern_assembly_result = self.build_pattern_wordlist(
                    dev_profile=dev_profile,
                    observed_urls=observed_urls,
                    max_endpoints=max_pattern_endpoints,
                    selected_pattern_ids=selected_pattern_ids,
                )
                # Merge pattern endpoints vào wordlist (deduplicate)
                pattern_endpoints = pattern_assembly_result.get("endpoints", [])
                merged_wordlist = list(dict.fromkeys(wordlist + pattern_endpoints))
                log_agent_progress(
                    "FuzzingAgent",
                    f"📦 Merged wordlist: {len(wordlist)} base + "
                    f"{len(pattern_endpoints)} pattern = {len(merged_wordlist)} total"
                )
            else:
                merged_wordlist = wordlist

            # ── Phase 1: LLM suy luận chọn Tool ─────────────────────────
            task_directive = directive or {
                "task_id": "TASK_FUZZ_001",
                "target_url": target_url,
                "objective": (
                    f"Thực thi Fuzzing {len(merged_wordlist)} đường dẫn trên target URL. "
                    f"Trạng thái WAF: {waf_detected} ({waf_type}). "
                    f"Pattern Engine: {'bật' if use_pattern_engine else 'tắt'}."
                ),
                "target_context": {
                    "waf_detected": waf_detected,
                    "waf_type": waf_type,
                    "config_adjustments": self._public_options(config_adjustments),
                    "pattern_engine_used": use_pattern_engine,
                    "pattern_assembly_metadata": pattern_assembly_result.get("metadata", {}),
                },
                "tool_knowledge_reference": self.ffuf_knowledge,
                "operating_principles": self.principles,
            }

            fuzz_tools = self.tool_registry.list_tools(filter_names=["ffuf_fuzzing_tool"])
            execution_history = []

            plan = self.plan_tool_execution(
                task_directive=task_directive,
                available_tools=fuzz_tools,
                execution_history=execution_history
            )

            selected_tool = plan.get("selected_tool", "ffuf_fuzzing_tool")
            if selected_tool != "ffuf_fuzzing_tool":
                raise ValueError(f"Unsupported fuzzing tool: {selected_tool}")
            planned_options = plan.get("options") or {}
            if not isinstance(planned_options, dict):
                raise ValueError("Fuzzing tool options must be an object")
            defaults = self.ffuf_knowledge.get("safe_execution_defaults", {})
            options = {key: value for key, value in defaults.items() if key != "rationale"}
            planned_options = self._normalize_options(planned_options)
            caller_options = self._normalize_options(config_adjustments)
            requested_engine = caller_options.get("engine", planned_options.get("engine", "auto"))
            if requested_engine == "proxy_http":
                if caller_options.get("engine") != "proxy_http":
                    raise ValueError("proxy_http must be explicitly selected by the caller")
                # The LLM cannot invent routing credentials or expand approved scope.
                from src.tools.proxy_profiles import OPERATOR_PROXY_OPTIONS
                for key in OPERATOR_PROXY_OPTIONS:
                    planned_options.pop(key, None)
                proxy_defaults = self.ffuf_knowledge.get("controlled_proxy_mode", {}).get(
                    "safe_execution_defaults", {"max_scan_seconds": 120, "max_requests": 100}
                )
                options.update(proxy_defaults)
            if requested_engine == "loopback_lab":
                lab_defaults = self.ffuf_knowledge.get("local_lab_mode", {}).get(
                    "safe_execution_defaults", {"max_scan_seconds": 60, "max_requests": 4}
                )
                options.update(lab_defaults)
            options.update(planned_options)
            # Explicit caller/coordinator configuration takes precedence over the LLM.
            options.update(caller_options)
            options["target_url"] = target_url
            options["wordlist"] = merged_wordlist
            options["waf_detected"] = waf_detected

            # ── Phase 2: Gọi Tool ────────────────────────────────────────
            tool_execution_res = self.tool_registry.execute_tool(selected_tool, options)
            tool_result = tool_execution_res.get("result")
            if not isinstance(tool_result, dict):
                raise RuntimeError(tool_execution_res.get("error") or "Fuzzing tool returned no result")
            tool_data = tool_result.get("result_data")
            if not isinstance(tool_data, dict) or "results" not in tool_data:
                raise RuntimeError(tool_result.get("error_message") or "Fuzzing tool returned no measurements")
            if tool_data.get("simulated"):
                raise RuntimeError("Simulated fuzzing data is not accepted as HTTP measurements")
            results_list = tool_data["results"]
            if not isinstance(results_list, list):
                raise ValueError("Fuzzing measurements must be a list")
            stats_dict = self._observed_stats(tool_data, results_list)
            success = bool(tool_execution_res.get("success") and tool_result.get("success", True))
            partial = bool(tool_data.get("partial") or tool_data.get("stopped_early") or not success)
            public_options = self._public_options(options)
            request_total = stats_dict.get("total_requests")
            request_label = str(request_total) if request_total is not None else "chưa xác định"

            tool_log_entry = {
                "selected_tool": selected_tool,
                "options": public_options,
                "tool_selection_reason": plan.get(
                    "tool_selection_reason",
                    "Chọn ffuf_fuzzing_tool để đo phản hồi HTTP thực và giới hạn tải gửi tới máy chủ."
                ),
                "options_selection_reason": plan.get(
                    "options_selection_reason",
                    f"Cấu hình rate_limit={options.get('rate_limit', 2)} và delay_ms={options.get('delay_ms', 0)}."
                ),
                "result_summary": (
                    f"Số request thực: {request_label}; thu được {len(results_list)} bản ghi. "
                    f"Trạng thái: {'complete' if success else 'partial/failed'}. HTTP 200 không đồng nghĩa endpoint đã xác minh."
                ),
                "pattern_engine": pattern_assembly_result.get("metadata", {}),
            }
            execution_history.append(tool_log_entry)

            agent_logger.info(
                f"\n{COLOR_MAGENTA}🛠️ [SUB-AGENT TOOL DECISION - FuzzingAgent]{COLOR_RESET}\n"
                f"   ├─ Selected Tool    : {tool_log_entry['selected_tool']}\n"
                f"   ├─ Merged Wordlist  : {len(merged_wordlist)} entries\n"
                f"   ├─ Synthesized Opts : {json.dumps(public_options, ensure_ascii=False)}\n"
                f"   ├─ Tool Reason      : {tool_log_entry['tool_selection_reason']}\n"
                f"   └─ Options Reason   : {tool_log_entry['options_selection_reason']}"
            )

            # ── Phase 3: LLM Justification ───────────────────────────────
            justification = self.generate_justification(
                task_directive=task_directive,
                execution_history=execution_history,
                extracted_data={
                    "http_200_count": stats_dict.get("status_codes", {}).get("200", 0),
                    "total_requests": request_total,
                    "engine": tool_data.get("engine"),
                    "partial": partial,
                    "stop_reason": tool_data.get("stop_reason"),
                    "pattern_endpoints_added": len(
                        pattern_assembly_result.get("endpoints", [])
                    ),
                }
            ) if success else (
                f"Fuzzing dừng với kết quả một phần/lỗi: {tool_data.get('stop_reason') or tool_result.get('error_message')}. "
                f"Giữ nguyên {len(results_list)} bản ghi đo được; không tạo dữ liệu thay thế hoặc xác minh giả."
            )

            agent_logger.info(
                f"\n{COLOR_CYAN}📝 [SUB-AGENT JUSTIFICATION - FuzzingAgent]{COLOR_RESET}\n"
                f"{justification}\n"
            )

            res = {
                "success": success,
                "partial": partial,
                "simulated": False,
                "engine": tool_data.get("engine"),
                "results": results_list,
                "stats": stats_dict,
                "errors": tool_data.get("errors", []),
                "warnings": tool_data.get("warnings", []),
                "stop_reason": tool_data.get("stop_reason"),
                "error_message": tool_result.get("error_message"),
                "tools_executed": execution_history,
                "subagent_justification": justification,
                "pattern_assembly": pattern_assembly_result,
                "merged_wordlist_size": len(merged_wordlist),
            }
            for field in ("health_checks", "proxy_pool", "proxy_refresh_events", "settings"):
                if field in tool_data:
                    res[field] = tool_data[field]

            if not success:
                logger.warning("Fuzzing stopped with partial/failed measurements: %s",
                               tool_result.get("error_message") or tool_data.get("stop_reason"))
                return res
            log_agent_success(
                "FuzzingAgent",
                f"Hoàn thành fuzzing; số request: {request_label}, {len(results_list)} bản ghi phản hồi.",
                metrics={
                    "http_200": stats_dict.get("status_codes", {}).get("200", 0),
                    "http_403": stats_dict.get("status_codes", {}).get("403", 0),
                    "avg_response_time_sec": stats_dict.get("avg_response_time"),
                    "pattern_endpoints": len(pattern_assembly_result.get("endpoints", [])),
                }
            )
            return res

        except Exception as e:
            log_agent_error("FuzzingAgent", f"Lỗi trong quá trình fuzzing {target_url}", exception=e)
            raise e
