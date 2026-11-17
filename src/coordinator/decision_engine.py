"""
LLM Decision Engine — Bộ máy ra quyết định dựa trên LLM.

Thay thế hoàn toàn logic if/else routing cũ (v1.0).
Mỗi quyết định trải qua 5 bước:
    1. Thu thập context từ SharedState
    2. Truy xuất knowledge liên quan từ Knowledge Store
    3. Gọi LLM reasoning (qua LangChain)
    4. Validate decision (guard rails check)
    5. Ghi audit log + DecisionRecord
"""

import json
import re
import logging
from datetime import datetime, timezone
from itertools import islice
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

from .state import SharedState, lifecycle_summary, error_count
from .knowledge_store import KnowledgeStore
from .llm_logging import invoke_logged, sanitize_for_log
from .telemetry import sync_state
from .prompts import (
    COORDINATOR_SYSTEM_PROMPT,
    DECISION_PROMPT_TEMPLATE,
    ERROR_DECISION_PROMPT_TEMPLATE,
    POST_SESSION_REFLECTION_PROMPT,
)

logger = logging.getLogger(__name__)


def _bounded_json(value, *, depth=0):
    """Keep auxiliary historical knowledge bounded before putting it in prompts."""
    remaining = 100
    def bounded(item, level):
        nonlocal remaining
        if remaining <= 0:
            return "[summary truncated]"
        remaining -= 1
        if isinstance(item, str):
            return item[:240]
        if item is None or type(item) in (bool, int, float):
            return item
        if level >= 4:
            return "[summary truncated]"
        if isinstance(item, dict):
            result = {}
            for key, val in islice(item.items(), 8):
                if remaining <= 0:
                    result["[truncated]"] = True
                    break
                result[key[:40] if isinstance(key, str) else "[non-string-key]"] = bounded(val, level + 1)
            return result
        if isinstance(item, list):
            result = []
            for val in islice(item, 5):
                if remaining <= 0:
                    result.append("[truncated]")
                    break
                result.append(bounded(val, level + 1))
            return result
        return "[unsupported value]"
    rendered = json.dumps(bounded(value, depth), ensure_ascii=False)
    if len(rendered) <= 4000:
        return rendered
    # Prefix is already JSON-escaped text; escaping it again is at most 2x.
    return json.dumps({"summary_prefix": rendered[:1800], "truncated": True}, ensure_ascii=False)


def _observed_facts(state):
    """Finite allowlist of measured facts suitable for deterministic reflection."""
    summary = lifecycle_summary(state)
    facts = {key: summary[key] for key in (
        "generated_count", "selected_count", "planned_requests", "attempted_requests",
        "responses_received", "network_errors", "remaining_requests", "fuzzing_requests",
        "healthcheck_requests", "proxy_connect_errors", "responses_received_lower_bound") if summary[key] is not None}
    facts["errors_count"] = error_count(state)
    for key in ("verified_results", "false_positives", "verified_parameters"):
        if isinstance(state.get(key), list):
            facts[key + "_count"] = len(state[key])
    for agent in ("tech_recon", "wordlist_gen", "fuzzing", "param_disc", "soft404_filter"):
        status = state.get("agent_statuses", {}).get(agent)
        if status in {"pending", "running", "success", "partial", "failed", "skipped"}:
            facts["agent_statuses." + agent] = status
    return facts


def _verified_observations(lessons, state):
    """Never promote arbitrary model prose to an observed fact.

    A matched typed scalar permits only a canonical session observation, not
    the model's claimed cause, recommendation, confidence, applicability or ID.
    """
    facts, accepted, seen = _observed_facts(state), [], set()
    for lesson in lessons[:20]:
        evidence = lesson.get("evidence") if isinstance(lesson, dict) else None
        if not isinstance(evidence, dict):
            continue
        key, value = evidence.get("fact"), evidence.get("value")
        if (not isinstance(key, str) or key not in facts or key in seen
                or type(value) is not type(facts[key]) or value != facts[key]):
            continue
        seen.add(key)
        accepted.append({
            "lesson": f"Observed in this session: {key} = {json.dumps(value, ensure_ascii=False)}. No causal explanation is established.",
            "evidence": {"fact": key, "value": value},
            "verification_status": "verified_observation", "kind": "session_observation",
            "applicable_when": {"session_id": state.get("session_id", "")},
            "source_sessions": [state.get("session_id", "")], "confidence": 1.0,
        })
    return accepted


# ═══════════════════════════════════════════════════════════════
# Available actions cho từng decision point
# ═══════════════════════════════════════════════════════════════

AVAILABLE_ACTIONS = {
    "after_validate": [
        {"action": "proceed", "description": "Input hợp lệ, khởi tạo pipeline"},
        {"action": "abort", "description": "Input không hợp lệ, kết thúc"},
    ],
    "after_tech_recon": [
        {"action": "proceed_to_wordlist", "description": "Tiến hành sinh wordlist"},
        {
            "action": "retry_recon",
            "description": "Chạy lại recon (có thể với config khác)",
        },
        {
            "action": "abort_to_report",
            "description": "Dừng pipeline, xuất báo cáo partial",
        },
    ],
    "after_wordlist_gen": [
        {
            "action": "proceed_to_fuzzing",
            "description": "Bắt đầu fuzzing với wordlist sinh ra",
        },
        {
            "action": "use_fallback_wordlist",
            "description": "Dùng base wordlist thay thế",
        },
        {
            "action": "retry_wordlist",
            "description": "Sinh lại wordlist với prompt khác",
        },
        {"action": "abort_to_report", "description": "Dừng pipeline"},
    ],
    "after_fuzzing": [
        {
            "action": "proceed_to_param",
            "description": "Tiến hành tìm hidden params",
        },
        {
            "action": "skip_to_filter",
            "description": "Bỏ qua param discovery, nhảy sang filter",
        },
        {
            "action": "retry_fuzzing",
            "description": "Fuzz lại với config khác",
        },
        {"action": "abort_to_report", "description": "Dừng pipeline"},
    ],
    "after_param_disc": [
        {
            "action": "proceed_to_filter",
            "description": "Tiến hành lọc Soft 404",
        },
        {"action": "abort_to_report", "description": "Dừng pipeline"},
    ],
    "after_soft404_filter": [
        {"action": "generate_report", "description": "Xuất báo cáo cuối cùng"},
        {
            "action": "re_run_filter",
            "description": "Chạy lại filter với ngưỡng khác",
        },
    ],
    "on_error": [
        {"action": "retry", "description": "Chạy lại agent thất bại"},
        {
            "action": "retry_with_adjustment",
            "description": "Chạy lại với config điều chỉnh",
        },
        {
            "action": "skip",
            "description": "Bỏ qua agent, tiếp tục pipeline",
        },
        {
            "action": "abort_to_report",
            "description": "Dừng pipeline, xuất báo cáo",
        },
    ],
}


class DecisionEngine:
    """
    LLM-based Decision Engine cho Coordinator.

    Mỗi quyết định:
        1. Thu thập context từ SharedState
        2. Truy xuất knowledge liên quan
        3. Gọi LLM reasoning
        4. Validate decision (guard rails)
        5. Ghi audit log

    Attributes:
        llm: LangChain LLM instance
        knowledge: KnowledgeStore instance
    """

    def __init__(self, llm: ChatOpenAI, knowledge_store: KnowledgeStore):
        """
        Args:
            llm: LangChain ChatOpenAI (hoặc tương thích)
            knowledge_store: KnowledgeStore instance
        """
        self.llm = llm
        self.knowledge = knowledge_store

        # Build prompt chains
        self.decision_prompt = ChatPromptTemplate.from_messages([
            ("system", COORDINATOR_SYSTEM_PROMPT),
            ("human", DECISION_PROMPT_TEMPLATE),
        ])

        self.error_prompt = ChatPromptTemplate.from_messages([
            ("system", COORDINATOR_SYSTEM_PROMPT),
            ("human", ERROR_DECISION_PROMPT_TEMPLATE),
        ])

        self.reflection_prompt = ChatPromptTemplate.from_messages([
            ("system", COORDINATOR_SYSTEM_PROMPT),
            ("human", POST_SESSION_REFLECTION_PROMPT),
        ])

        self._decision_counter = 0

    # ══════════════════════════════════════════════════════════
    # MAIN: Make Decision
    # ══════════════════════════════════════════════════════════

    def make_decision(
        self,
        state: dict,
        decision_point: str,
        completed_agent: str,
        agent_status: str,
        agent_result_summary: str = "",
        execution_time: float = 0.0,
        error_details: str = "",
    ) -> dict:
        """
        Ra quyết định tại một decision point.

        Quy trình 5 bước:
            1. Build context → 2. Retrieve knowledge →
            3. LLM reason → 4. Validate → 5. Audit

        Args:
            state: SharedState hiện tại
            decision_point: Tên decision point (e.g., "after_tech_recon")
            completed_agent: Agent vừa hoàn thành
            agent_status: "success" hoặc "failed"
            agent_result_summary: Tóm tắt kết quả agent
            execution_time: Thời gian thực thi (giây)
            error_details: Chi tiết lỗi (nếu failed)

        Returns:
            DecisionRecord dict
        """
        self._decision_counter += 1
        decision_id = (
            f"D{decision_point.split('_')[-1]}_{self._decision_counter:03d}"
        )

        # ── BƯỚC 1: Thu thập context ──
        # Lifecycle facts are derived in the actual prompt and audit snapshot.

        # ── BƯỚC 2: Truy xuất knowledge ──
        knowledge_context = self.knowledge.retrieve_knowledge({
            "tech_stack": state.get("tech_stack", {}),
            "waf_type": state.get("waf_type"),
            "waf_detected": state.get("waf_detected", False),
            "decision_point": decision_point,
            "target_characteristics": self._extract_characteristics(state),
            "http_200_count": len([
                r
                for r in state.get("raw_results", [])
                if r.get("status_code") == 200
            ]),
        })

        # ── BƯỚC 3: LLM Reasoning ──
        available_actions = AVAILABLE_ACTIONS.get(decision_point, [])

        if agent_status == "failed":
            prompt = self.error_prompt
            template_vars = self._build_error_prompt_vars(
                state, completed_agent, error_details,
                knowledge_context, available_actions,
            )
        else:
            prompt = self.decision_prompt
            template_vars = self._build_decision_prompt_vars(
                state, decision_point, completed_agent,
                agent_status, agent_result_summary,
                execution_time, knowledge_context, available_actions,
            )

        chain = prompt | self.llm
        raw_response = invoke_logged(
            chain, template_vars, component="Coordinator", operation="decision",
            context={"decision_point": decision_point, "decision_id": decision_id},
        )
        sync_state(state)

        # ── BƯỚC 4: Parse & Validate ──
        decision = self._parse_llm_decision(raw_response.content)
        decision = self._validate_decision(
            decision, decision_point, state
        )

        # ── BƯỚC 5: Build DecisionRecord ──
        decision_record = {
            "decision_id": decision_id,
            "session_id": state.get("session_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision_point": decision_point,
            "trigger": (
                "agent_error"
                if agent_status == "failed"
                else "agent_completed"
            ),
            "agent_completed": completed_agent,
            "agent_status": agent_status,
            "state_snapshot": self._snapshot_state(state),
            "knowledge_context": {
                "similar_sessions_found": len(
                    knowledge_context.get("similar_sessions", [])
                ),
                "relevant_lessons": knowledge_context.get(
                    "relevant_lessons", []
                ),
                "relevant_patterns": knowledge_context.get(
                    "relevant_patterns", []
                ),
            },
            "reasoning": decision.get("reasoning", {}),
            "action": decision["action"],
            "confidence": decision.get("confidence", 0.5),
            "is_knowledge_influenced": len(
                decision.get("reasoning", {}).get(
                    "knowledge_referenced", []
                )
            )
            > 0,
            "next_agent_config_adjustments": decision.get(
                "next_agent_config_adjustments", {}
            ),
            "new_observation": decision.get("new_observation", ""),
            "outcome": None,  # Filled later by reflection
        }

        # ── Ghi audit log ──
        state["decision_chain"].append(decision_record)
        state["audit_log"].append({
            "type": "decision",
            "timestamp": decision_record["timestamp"],
            "decision_id": decision_id,
            "action": decision["action"],
            "reasoning_summary": decision.get("reasoning", {}).get(
                "analysis", ""
            ),
            "confidence": decision.get("confidence", 0.5),
        })

        logger.info(
            f"[Decision {decision_id}] {decision_point} → "
            f"action={decision['action']} "
            f"(confidence={decision.get('confidence', '?')})"
        )
        logger.info(
            f"  Reasoning: "
            f"{decision.get('reasoning', {}).get('analysis', 'N/A')[:200]}"
        )

        return decision_record

    # ══════════════════════════════════════════════════════════
    # POST-SESSION REFLECTION
    # ══════════════════════════════════════════════════════════

    def reflect_on_session(self, state: dict) -> dict:
        """
        Post-session reflection — Rút bài học sau phiên chạy.

        Gọi LLM để phân tích toàn bộ phiên, rút bài học,
        đánh giá các quyết định, và lưu vào Knowledge Store.

        Args:
            state: SharedState sau khi pipeline hoàn thành

        Returns:
            Reflection dict (lessons_learned, decision_evaluations, ...)
        """
        reflection_vars = {
            "lifecycle_summary": json.dumps(lifecycle_summary(state), ensure_ascii=False),
            "observed_facts": json.dumps(_observed_facts(state), ensure_ascii=False),
            "target_url": state.get("target_url", ""),
            "tech_stack": _bounded_json(state.get("tech_stack", {})),
            "waf_info": (
                f"Detected: {state['waf_type']}"
                if state.get("waf_detected")
                else "None"
            ),
            "duration": state.get("finished_at", "?"),
            "agents_list": json.dumps(
                state.get("agent_statuses", {}), ensure_ascii=False
            ),
            "skipped_list": json.dumps(
                [
                    k
                    for k, v in state.get("agent_statuses", {}).items()
                    if v == "skipped"
                ],
                ensure_ascii=False,
            ),
            "verified_count": len(state.get("verified_results", [])),
            "false_positive_count": len(state.get("false_positives", [])),
            "decision_chain_summary": json.dumps(
                [
                    {
                        "id": d["decision_id"],
                        "point": d["decision_point"],
                        "action": d["action"],
                        "reasoning": d.get("reasoning", {}).get(
                            "analysis", ""
                        )[:300],
                    }
                    for d in state.get("decision_chain", [])[-20:]
                ],
                ensure_ascii=False,
            ),
        }

        chain = self.reflection_prompt | self.llm
        response = invoke_logged(
            chain, reflection_vars, component="Coordinator", operation="reflection",
            context={"session_id": state.get("session_id", "")},
        )
        sync_state(state)

        reflection = self._parse_llm_decision(response.content)
        if (not isinstance(reflection, dict)
                or any(not isinstance(reflection.get(key), list)
                       for key in ("lessons_learned", "decision_evaluations"))):
            raise ValueError("Coordinator reflection requires lessons_learned and decision_evaluations lists")

        # Lưu lessons vào Knowledge Store
        proposed = reflection.get("lessons_learned", [])
        new_lessons = _verified_observations(proposed, state)
        reflection["lessons_learned"] = new_lessons
        reflection["lessons_rejected_count"] = len(proposed) - len(new_lessons)
        if new_lessons:
            self.knowledge.save_lessons(new_lessons)

        # Cập nhật decision outcomes
        for eval_item in reflection.get("decision_evaluations", [])[:20]:
            if not isinstance(eval_item, dict):
                continue
            for decision in state.get("decision_chain", []):
                if decision["decision_id"] == eval_item.get("decision_id"):
                    decision["outcome"] = {
                        "was_correct_decision": None,
                        "verification_status": "unverified_model_assessment",
                        "retrospective_note": sanitize_for_log({"credentials": state.get("config", {}),
                            "value": str(eval_item.get("retrospective_note", ""))})["value"][:500],
                    }

        # Lưu session record vào Knowledge Store
        session_record = self._build_session_record(state, new_lessons)
        self.knowledge.save_session(session_record)

        # Ghi audit
        state["audit_log"].append({
            "type": "reflection",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "lessons_count": len(new_lessons),
            "lessons_rejected_count": len(proposed) - len(new_lessons),
            "lessons_summary": [
                l.get("lesson", "") for l in new_lessons
            ],
        })

        state["session_lessons"] = new_lessons

        logger.info(f"[Reflection] Rút ra {len(new_lessons)} bài học mới")
        for lesson in new_lessons:
            logger.info(f"  📝 {lesson.get('lesson', '')[:100]}")

        return reflection

    # ══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ══════════════════════════════════════════════════════════

    def _build_context(self, state: dict, agent: str) -> dict:
        """Xây dựng context dict cho LLM."""
        return {
            "lifecycle": lifecycle_summary(state),
            "tech_stack": state.get("tech_stack", {}),
            "waf_detected": state.get("waf_detected", False),
            "waf_type": state.get("waf_type"),
            "discovered_paths_count": len(
                state.get("discovered_paths", [])
            ),
            "wordlist_size": len(state.get("wordlist", [])),
            "raw_results_count": len(state.get("raw_results", [])),
            "http_200_count": len([
                r
                for r in state.get("raw_results", [])
                if r.get("status_code") == 200
            ]),
            "param_results_count": len(state.get("param_results", [])),
            "verified_count": len(state.get("verified_results", [])),
            "llm_calls_used": state.get("llm_call_count", 0),
            "errors_count": error_count(state),
        }

    def _snapshot_state(self, state: dict) -> dict:
        """Tạo snapshot nhẹ của state cho audit log."""
        return {
            "lifecycle": lifecycle_summary(state),
            "tech_stack": state.get("tech_stack", {}),
            "waf_detected": state.get("waf_detected", False),
            "waf_type": state.get("waf_type"),
            "discovered_paths_count": len(
                state.get("discovered_paths", [])
            ),
            "wordlist_size": len(state.get("wordlist", [])),
            "raw_results_count": len(state.get("raw_results", [])),
            "http_200_count": len([
                r
                for r in state.get("raw_results", [])
                if r.get("status_code") == 200
            ]),
            "param_results_count": len(state.get("param_results", [])),
            "verified_results_count": len(
                state.get("verified_results", [])
            ),
            "llm_calls_used": state.get("llm_call_count", 0),
            "llm_calls_remaining": max(0, state.get("config", {}).get("max_llm_calls", 50) - state.get("llm_call_count", 0)),
            "errors_so_far": error_count(state),
        }

    def _extract_characteristics(self, state: dict) -> list:
        """Trích xuất đặc điểm target cho similarity matching."""
        chars = []
        paths = state.get("discovered_paths", [])

        if any("/api/" in p for p in paths):
            chars.append("has_api_prefix")
        if any("/admin" in p for p in paths):
            chars.append("has_admin_panel")
        if any(
            "_" in p.split("/")[-1] for p in paths if "/" in p
        ):
            chars.append("uses_snake_case")
        if any(
            "-" in p.split("/")[-1] for p in paths if "/" in p
        ):
            chars.append("uses_kebab_case")
        if state.get("waf_detected"):
            chars.append(
                f"waf_{state.get('waf_type', 'unknown').lower()}"
            )

        return chars

    def _build_decision_prompt_vars(
        self, state, decision_point, completed_agent,
        agent_status, result_summary, exec_time,
        knowledge, actions,
    ) -> dict:
        """Build template variables cho decision prompt."""
        return {
            "lifecycle_summary": json.dumps(lifecycle_summary(state), ensure_ascii=False),
            "completed_agent_name": completed_agent,
            "agent_status": agent_status,
            "agent_result_summary": str(result_summary)[:1200],
            "execution_time": exec_time,
            "error_details_if_failed": "",
            "target_url": state.get("target_url", ""),
            "tech_stack_json": _bounded_json(state.get("tech_stack", {})),
            "waf_detected": state.get("waf_detected", False),
            "waf_type": state.get("waf_type", "None"),
            "discovered_paths_count": len(
                state.get("discovered_paths", [])
            ),
            "wordlist_size": len(state.get("wordlist", [])),
            "raw_results_count": len(state.get("raw_results", [])),
            "http_200_count": len([
                r
                for r in state.get("raw_results", [])
                if r.get("status_code") == 200
            ]),
            "param_results_count": len(state.get("param_results", [])),
            "verified_results_count": len(
                state.get("verified_results", [])
            ),
            "error_count": error_count(state),
            "llm_calls_used": state.get("llm_call_count", 0),
            "llm_calls_max": state.get("config", {}).get("max_llm_calls", 50),
            "llm_calls_remaining": max(0, state.get("config", {}).get("max_llm_calls", 50) - state.get("llm_call_count", 0)),
            "total_http_requests": state.get("total_http_requests", 0),
            "elapsed_seconds": 0,
            "circuit_breaker_states": json.dumps(
                state.get("circuit_breaker_state", {})
            ),
            "similar_sessions_summary": _bounded_json(knowledge.get("similar_sessions", [])),
            "relevant_lessons": _bounded_json(knowledge.get("relevant_lessons", [])),
            "relevant_patterns": _bounded_json(knowledge.get("relevant_patterns", [])),
            "available_actions_list": json.dumps(
                actions, ensure_ascii=False
            ),
        }

    def _build_error_prompt_vars(
        self, state, agent, error, knowledge, actions
    ) -> dict:
        """Build template variables cho error decision prompt."""
        return {
            "failed_agent_name": agent,
            "error_message": sanitize_for_log({"credentials": state.get("config", {}),
                                                "value": str(error)})["value"][:1200],
            "error_type": "unknown",
            "retry_count": state.get("retry_counts", {}).get(agent, 0),
            "max_retries": state.get("config", {}).get("max_retries", 2),
            "next_retry_count": (
                state.get("retry_counts", {}).get(agent, 0) + 1
            ),
            "state_snapshot_at_error": _bounded_json(self._snapshot_state(state)),
            "similar_error_knowledge": _bounded_json(knowledge.get("relevant_lessons", [])),
        }

    def _parse_llm_decision(self, raw: str) -> dict:
        """
        Parse JSON decision từ LLM response.

        Tìm JSON object trong response text. Nếu không tìm được,
        trả về fallback decision (abort_to_report).
        """
        json_match = re.search(r"\{[\s\S]+\}", raw)

        if not json_match:
            logger.error(
                "[Decision] LLM không trả về JSON hợp lệ — dùng fallback"
            )
            return {
                "action": "abort_to_report",
                "confidence": 0.3,
                "reasoning": {
                    "analysis": (
                        "LLM response không parse được — "
                        "abort để safety"
                    ),
                    "factors_considered": ["LLM response invalid"],
                    "knowledge_referenced": [],
                    "alternatives_evaluated": [],
                },
            }

        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError as e:
            logger.error(f"[Decision] JSON parse error: {sanitize_for_log(str(e))}")
            return {
                "action": "abort_to_report",
                "confidence": 0.3,
                "reasoning": {
                    "analysis": f"JSON parse error: {e}",
                    "factors_considered": ["JSON invalid"],
                    "knowledge_referenced": [],
                    "alternatives_evaluated": [],
                },
            }

    def _validate_decision(
        self, decision: dict, point: str, state: dict
    ) -> dict:
        """
        Validate quyết định LLM — Guard Rails hardcoded.

        LLM có thể sai, nhưng guard rails không bao giờ sai.

        Checks:
            1. Action phải nằm trong danh sách allowed
            2. Retry count không vượt max_retries đã cấu hình
            3. LLM quota chưa hết max_llm_calls đã cấu hình
        """
        action = decision.get("action", "")
        available = [
            a["action"] for a in AVAILABLE_ACTIONS.get(point, [])
        ]

        # Check 1: Action phải hợp lệ
        if action not in available:
            logger.warning(
                f"[Guard] LLM chose invalid action '{action}' — "
                f"defaulting to first available"
            )
            decision["action"] = (
                available[0] if available else "abort_to_report"
            )
            state["audit_log"].append({
                "type": "guard_rail_override",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": (
                    f"Invalid action '{action}' replaced with "
                    f"'{decision['action']}'"
                ),
                "original_action": action,
            })

        # Check 2: Retry count
        if "retry" in decision.get("action", ""):
            # Lấy agent từ context
            retry_agent = {"retry_recon": "tech_recon", "retry_wordlist": "wordlist_gen", "retry_fuzzing": "fuzzing"}.get(decision.get("action"))
            for agent_name in [retry_agent] if retry_agent else []:
                retries = state["retry_counts"].get(agent_name, 0)
                if retries >= state.get("config", {}).get("max_retries", 2):
                    logger.warning(
                        f"[Guard] LLM wants retry but {agent_name} "
                        f"already retried {retries} times — forcing abort"
                    )
                    decision["action"] = "abort_to_report"
                    state["stop_reason"] = "max_retries"
                    state["audit_log"].append({
                        "type": "guard_rail_override",
                        "timestamp": datetime.now(
                            timezone.utc
                        ).isoformat(),
                        "reason": (
                            f"Max retries ({retries}) exceeded "
                            f"for {agent_name}"
                        ),
                        "original_action": action,
                    })
                    break

        # Check 3: LLM quota
        if state.get("llm_call_count", 0) >= state.get("config", {}).get("max_llm_calls", 50):
            current_action = decision.get("action", "")
            if current_action not in (
                "abort_to_report",
                "generate_report",
                "skip",
            ):
                logger.warning(
                    "[Guard] LLM quota exhausted — forcing report"
                )
                decision["action"] = "abort_to_report"
                state["stop_reason"] = "max_llm_calls"
                state["audit_log"].append({
                    "type": "guard_rail_override",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": "LLM call quota exhausted",
                    "original_action": current_action,
                })

        return decision

    def _build_session_record(
        self, state: dict, lessons: list
    ) -> dict:
        """Build session record cho Knowledge Store."""
        return {
            "session_id": state.get("session_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_url": state.get("target_url", ""),
            "context": {
                "tech_stack": state.get("tech_stack", {}),
                "waf_detected": state.get("waf_detected", False),
                "waf_type": state.get("waf_type"),
                "discovered_paths_count": len(
                    state.get("discovered_paths", [])
                ),
                "target_characteristics": (
                    self._extract_characteristics(state)
                ),
            },
            "decisions": [
                {
                    "point": d["decision_point"],
                    "action": d["action"],
                    "confidence": d.get("confidence", 0),
                    "reasoning": d.get("reasoning", {}).get(
                        "analysis", ""
                    ),
                }
                for d in state.get("decision_chain", [])
            ],
            "outcomes": {
                "lifecycle": lifecycle_summary(state),
                "total_verified_results": len(
                    state.get("verified_results", [])
                ),
                "total_false_positives_filtered": len(
                    state.get("false_positives", [])
                ),
                "total_http_requests": state.get(
                    "total_http_requests", 0
                ),
                "total_llm_calls": state.get("llm_call_count", 0),
                "agents_executed": [
                    k
                    for k, v in state.get(
                        "agent_statuses", {}
                    ).items()
                    if v == "success"
                ],
                "agents_skipped": [
                    k
                    for k, v in state.get(
                        "agent_statuses", {}
                    ).items()
                    if v == "skipped"
                ],
                "errors_encountered": error_count(state),
            },
            "lessons_learned": lessons,
        }
