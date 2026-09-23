"""
Coordinator v2.0 — LLM-Driven LangGraph State Machine.

Sử dụng LLM Decision Engine thay cho hardcoded routing.
12 nodes (9 execution + 3 LLM decision nodes).

Entry point: run_pipeline(target_url, config)

Cấu trúc graph:
    START → validate → init → tech_recon → 🧠D2 → gen_words → 🧠D3
    → fuzzing → 🧠D4 → [param_disc] → filter_404 → report → 🧠reflect → END
"""

import json
import uuid
import logging
from datetime import datetime, timezone

from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END

from .state import SharedState
from .guards import CircuitBreaker, LLMCallLimiter, TarpitDetector
from .decision_engine import DecisionEngine
from .knowledge_store import KnowledgeStore

from ..agents.tech_recon import TechReconAgent
from ..agents.wordlist_gen import WordlistGenAgent
from ..agents.fuzzer import FuzzingAgent
from ..agents.param_discovery import ParamDiscoveryAgent
from ..agents.soft404_filter import Soft404FilterAgent

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# GUARD RAILS (hardcoded safety — không phụ thuộc LLM)
# ═══════════════════════════════════════════════════════════════

circuit_breakers = {
    "tech_recon":   CircuitBreaker(name="tech_recon"),
    "wordlist_gen": CircuitBreaker(name="wordlist_gen"),
    "fuzzing":      CircuitBreaker(name="fuzzing", window_size=200),
    "param_disc":   CircuitBreaker(name="param_disc"),
    "soft404":      CircuitBreaker(name="soft404"),
}
llm_limiter = LLMCallLimiter(max_calls=50)
tarpit_detector = TarpitDetector()


# ═══════════════════════════════════════════════════════════════
# LLM & KNOWLEDGE (initialized lazily in build_coordinator_graph)
# ═══════════════════════════════════════════════════════════════

_decision_engine: DecisionEngine = None
_knowledge_store: KnowledgeStore = None


def _get_decision_engine(config: dict = None) -> DecisionEngine:
    """Lazy initialization cho DecisionEngine."""
    global _decision_engine, _knowledge_store

    if _decision_engine is None:
        config = config or {}
        llm = ChatOpenAI(
            model=config.get("llm_model", "gpt-4o"),
            temperature=config.get("llm_temperature", 0.1),
        )
        _knowledge_store = KnowledgeStore(
            base_dir=config.get("knowledge_store_dir", "knowledge_store")
        )
        _decision_engine = DecisionEngine(
            llm=llm, knowledge_store=_knowledge_store
        )

    return _decision_engine


# ═══════════════════════════════════════════════════════════════
# NODE FUNCTIONS — Agent Execution
# ═══════════════════════════════════════════════════════════════

def validate_input(state: dict) -> dict:
    """Node: Validate URL đầu vào."""
    url = state.get("target_url", "")

    if not url or not url.startswith(("http://", "https://")):
        state["agent_statuses"]["validate"] = "failed"
        state["audit_log"].append({
            "type": "validation_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": f"URL không hợp lệ: '{url}'",
        })
        logger.error(f"[Coordinator] Invalid URL: '{url}'")
    else:
        state["agent_statuses"]["validate"] = "success"
        state["audit_log"].append({
            "type": "validation_passed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": f"URL hợp lệ: {url}",
        })
        logger.info(f"[Coordinator] URL validated: {url}")

    return state


def init_state(state: dict) -> dict:
    """Node: Khởi tạo SharedState đầy đủ + Knowledge context."""
    state["session_id"] = str(uuid.uuid4())
    state["started_at"] = datetime.now(timezone.utc).isoformat()

    state["agent_statuses"] = {
        "validate": state.get("agent_statuses", {}).get("validate", "success"),
        "tech_recon": "pending",
        "wordlist_gen": "pending",
        "fuzzing": "pending",
        "param_disc": "pending",
        "soft404_filter": "pending",
    }
    state["retry_counts"] = {
        k: 0 for k in state["agent_statuses"] if k != "validate"
    }

    # Agent outputs
    state.setdefault("tech_stack", {})
    state.setdefault("discovered_paths", [])
    state.setdefault("js_endpoints", [])
    state.setdefault("waf_detected", False)
    state.setdefault("waf_type", None)
    state.setdefault("dev_profile", None)
    state.setdefault("wordlist", [])
    state.setdefault("wordlist_metadata", {})
    state.setdefault("raw_results", [])
    state.setdefault("fuzzing_stats", {})
    state.setdefault("param_results", [])
    state.setdefault("verified_results", [])
    state.setdefault("false_positives", [])
    state.setdefault("baseline_signature", None)

    # Guard rails
    state["error_log"] = []
    state["llm_call_count"] = 0
    state["coordinator_llm_calls"] = 0
    state["total_http_requests"] = 0
    state["iteration_count"] = 0
    state["circuit_breaker_state"] = {
        k: "closed" for k in circuit_breakers
    }

    # Knowledge & Audit (v2.0)
    state["decision_chain"] = []
    state["audit_log"] = state.get("audit_log", [])
    state["session_lessons"] = []
    state["knowledge_context"] = None

    state["audit_log"].append({
        "type": "session_started",
        "timestamp": state["started_at"],
        "session_id": state["session_id"],
        "target_url": state["target_url"],
    })

    logger.info(
        f"[Coordinator] Session {state['session_id'][:8]}... initialized "
        f"for {state['target_url']}"
    )
    return state


def run_tech_recon(state: dict) -> dict:
    """Node: Agent 1 — Tech Recon."""
    state["agent_statuses"]["tech_recon"] = "running"
    state["audit_log"].append({
        "type": "agent_started",
        "agent": "tech_recon",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        agent = TechReconAgent()
        result = agent.execute(state["target_url"])

        state["tech_stack"] = result.get("tech_stack", {})
        state["discovered_paths"] = result.get("discovered_paths", [])
        state["js_endpoints"] = result.get("js_endpoints", [])
        state["waf_detected"] = result.get("waf_detected", False)
        state["waf_type"] = result.get("waf_type", None)
        state["agent_statuses"]["tech_recon"] = "success"
        circuit_breakers["tech_recon"].record_success()

        logger.info(
            f"[TechRecon] Success — "
            f"stack={state['tech_stack']}, "
            f"paths={len(state['discovered_paths'])}, "
            f"WAF={state['waf_type']}"
        )

    except Exception as e:
        state["agent_statuses"]["tech_recon"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "tech_recon",
            "error": str(e),
        })
        circuit_breakers["tech_recon"].record_failure()
        logger.error(f"[TechRecon] Failed: {e}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "tech_recon",
        "status": state["agent_statuses"]["tech_recon"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def llm_decide_after_recon(state: dict) -> dict:
    """Node: 🧠 LLM quyết định sau Tech Recon (Decision Point D2)."""
    engine = _get_decision_engine(state.get("config"))

    result_summary = (
        f"Tech stack: {json.dumps(state.get('tech_stack', {}))}. "
        f"Paths found: {len(state.get('discovered_paths', []))}. "
        f"WAF: {state.get('waf_type', 'None')}."
    )

    decision = engine.make_decision(
        state=state,
        decision_point="after_tech_recon",
        completed_agent="tech_recon",
        agent_status=state["agent_statuses"]["tech_recon"],
        agent_result_summary=result_summary,
    )

    state["_last_decision_action"] = decision["action"]
    state["_config_adjustments"] = decision.get(
        "next_agent_config_adjustments", {}
    )
    return state


def run_wordlist_gen(state: dict) -> dict:
    """Node: Agent 2 — Wordlist Generator."""
    state["agent_statuses"]["wordlist_gen"] = "running"
    state["audit_log"].append({
        "type": "agent_started",
        "agent": "wordlist_gen",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        agent = WordlistGenAgent()
        result = agent.execute(
            tech_stack=state["tech_stack"],
            discovered_paths=state["discovered_paths"],
            js_endpoints=state.get("js_endpoints", []),
        )

        llm_limiter.record_call()
        state["llm_call_count"] += 1
        state["dev_profile"] = result.get("dev_profile")
        state["wordlist"] = result.get("wordlist", [])
        state["wordlist_metadata"] = result.get("metadata", {})
        state["agent_statuses"]["wordlist_gen"] = "success"
        circuit_breakers["wordlist_gen"].record_success()

        logger.info(
            f"[WordlistGen] Success — "
            f"{len(state['wordlist'])} entries generated"
        )

    except Exception as e:
        state["agent_statuses"]["wordlist_gen"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "wordlist_gen",
            "error": str(e),
        })
        circuit_breakers["wordlist_gen"].record_failure()
        logger.error(f"[WordlistGen] Failed: {e}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "wordlist_gen",
        "status": state["agent_statuses"]["wordlist_gen"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def llm_decide_after_wordlist(state: dict) -> dict:
    """Node: 🧠 LLM quyết định sau Wordlist Generation (Decision Point D3)."""
    engine = _get_decision_engine(state.get("config"))

    result_summary = (
        f"Wordlist size: {len(state.get('wordlist', []))} entries."
    )

    decision = engine.make_decision(
        state=state,
        decision_point="after_wordlist_gen",
        completed_agent="wordlist_gen",
        agent_status=state["agent_statuses"]["wordlist_gen"],
        agent_result_summary=result_summary,
    )

    state["_last_decision_action"] = decision["action"]
    state["_config_adjustments"] = decision.get(
        "next_agent_config_adjustments", {}
    )
    return state


def run_fuzzing(state: dict) -> dict:
    """Node: Agent 3 — Fuzzing & WAF Evasion."""
    state["agent_statuses"]["fuzzing"] = "running"
    config_adj = state.get("_config_adjustments", {})

    state["audit_log"].append({
        "type": "agent_started",
        "agent": "fuzzing",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config_adjustments": config_adj,
    })

    try:
        agent = FuzzingAgent()
        result = agent.execute(
            target_url=state["target_url"],
            wordlist=state["wordlist"],
            waf_detected=state.get("waf_detected", False),
            waf_type=state.get("waf_type"),
            **config_adj,
        )

        state["raw_results"] = result.get("results", [])
        state["fuzzing_stats"] = result.get("stats", {})
        state["total_http_requests"] += result.get(
            "stats", {}
        ).get("total_requests", 0)
        state["agent_statuses"]["fuzzing"] = "success"

        # Tarpit detection
        avg_time = result.get("stats", {}).get(
            "avg_response_time", 0
        )
        tarpit_detector.record_response_time(avg_time)
        if tarpit_detector.is_tarpit_detected():
            state["circuit_breaker_state"]["fuzzing"] = "open"
            state["audit_log"].append({
                "type": "tarpit_detected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            logger.warning("[Fuzzing] Tarpit detected!")

        circuit_breakers["fuzzing"].record_success()

        http_200_count = len([
            r for r in state["raw_results"]
            if r.get("status_code") == 200
        ])
        logger.info(
            f"[Fuzzing] Success — "
            f"{len(state['raw_results'])} results, "
            f"{http_200_count} HTTP 200"
        )

    except Exception as e:
        state["agent_statuses"]["fuzzing"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "fuzzing",
            "error": str(e),
        })
        circuit_breakers["fuzzing"].record_failure()
        logger.error(f"[Fuzzing] Failed: {e}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "fuzzing",
        "status": state["agent_statuses"]["fuzzing"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def llm_decide_after_fuzzing(state: dict) -> dict:
    """Node: 🧠 LLM quyết định sau Fuzzing (Decision Point D4).

    Bao gồm Agent Skip logic — LLM quyết định có nên chạy
    param_disc hay skip trực tiếp sang filter_404.
    """
    engine = _get_decision_engine(state.get("config"))

    http_200s = [
        r
        for r in state.get("raw_results", [])
        if r.get("status_code") == 200
    ]
    result_summary = (
        f"Total results: {len(state.get('raw_results', []))}. "
        f"HTTP 200: {len(http_200s)}. "
        f"HTTP requests sent: {state.get('total_http_requests', 0)}."
    )

    decision = engine.make_decision(
        state=state,
        decision_point="after_fuzzing",
        completed_agent="fuzzing",
        agent_status=state["agent_statuses"]["fuzzing"],
        agent_result_summary=result_summary,
    )

    if decision["action"] == "skip_to_filter":
        state["agent_statuses"]["param_disc"] = "skipped"
        logger.info("[Coordinator] LLM decided to SKIP param_disc")

    state["_last_decision_action"] = decision["action"]
    state["_config_adjustments"] = decision.get(
        "next_agent_config_adjustments", {}
    )
    return state


def run_param_discovery(state: dict) -> dict:
    """Node: Agent 4 — Parameter Discovery."""
    state["agent_statuses"]["param_disc"] = "running"
    state["audit_log"].append({
        "type": "agent_started",
        "agent": "param_disc",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        http_200_endpoints = [
            r
            for r in state.get("raw_results", [])
            if r.get("status_code") == 200
        ]
        agent = ParamDiscoveryAgent()
        result = agent.execute(
            target_url=state["target_url"],
            endpoints=http_200_endpoints,
            tech_stack=state.get("tech_stack", {}),
        )

        llm_limiter.record_call()
        state["llm_call_count"] += 1
        state["param_results"] = result.get("param_results", [])
        state["agent_statuses"]["param_disc"] = "success"
        circuit_breakers["param_disc"].record_success()

        logger.info(
            f"[ParamDisc] Success — "
            f"{len(state['param_results'])} params found"
        )

    except Exception as e:
        state["agent_statuses"]["param_disc"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "param_disc",
            "error": str(e),
        })
        circuit_breakers["param_disc"].record_failure()
        logger.error(f"[ParamDisc] Failed: {e}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "param_disc",
        "status": state["agent_statuses"]["param_disc"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def run_soft404_filter(state: dict) -> dict:
    """Node: Agent 5 — Soft 404 Filter."""
    state["agent_statuses"]["soft404_filter"] = "running"
    state["audit_log"].append({
        "type": "agent_started",
        "agent": "soft404_filter",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        all_results = (
            state.get("raw_results", [])
            + state.get("param_results", [])
        )
        agent = Soft404FilterAgent()
        result = agent.execute(
            target_url=state["target_url"],
            results_to_verify=all_results,
        )

        state["verified_results"] = result.get("verified", [])
        state["false_positives"] = result.get("false_positives", [])
        state["baseline_signature"] = result.get("baseline")
        state["agent_statuses"]["soft404_filter"] = "success"
        circuit_breakers["soft404"].record_success()

        logger.info(
            f"[Soft404] Success — "
            f"{len(state['verified_results'])} verified, "
            f"{len(state['false_positives'])} filtered"
        )

    except Exception as e:
        state["agent_statuses"]["soft404_filter"] = "failed"
        # Fallback: giữ raw results nếu filter lỗi
        state["verified_results"] = state.get("raw_results", [])
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "soft404_filter",
            "error": str(e),
        })
        circuit_breakers["soft404"].record_failure()
        logger.error(f"[Soft404] Failed: {e}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "soft404_filter",
        "status": state["agent_statuses"]["soft404_filter"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def generate_report(state: dict) -> dict:
    """Node: Tổng hợp báo cáo cuối cùng."""
    state["finished_at"] = datetime.now(timezone.utc).isoformat()
    state["audit_log"].append({
        "type": "report_generated",
        "timestamp": state["finished_at"],
        "summary": {
            "verified": len(state.get("verified_results", [])),
            "filtered": len(state.get("false_positives", [])),
            "decisions_made": len(state.get("decision_chain", [])),
        },
    })

    logger.info(
        f"[Report] Generated — "
        f"{len(state.get('verified_results', []))} verified results, "
        f"{len(state.get('decision_chain', []))} decisions made"
    )
    return state


def post_session_reflection(state: dict) -> dict:
    """Node: 🧠 LLM rút bài học → lưu Knowledge Store."""
    engine = _get_decision_engine(state.get("config"))

    try:
        engine.reflect_on_session(state)
    except Exception as e:
        logger.error(f"[Reflection] Failed: {e}")
        state["audit_log"].append({
            "type": "reflection_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        })

    return state


# ═══════════════════════════════════════════════════════════════
# ROUTING FUNCTIONS — Đọc kết quả từ LLM Decision
# ═══════════════════════════════════════════════════════════════

def route_after_validate(state: dict) -> str:
    """Route: Sau validate → init hoặc report."""
    if state.get("agent_statuses", {}).get("validate") == "success":
        return "init_state"
    return "report"


def route_by_llm_decision_recon(state: dict) -> str:
    """Route: LLM decision sau Tech Recon (D2)."""
    action = state.get("_last_decision_action", "abort_to_report")
    return {
        "proceed_to_wordlist": "gen_words",
        "retry_recon": "tech_recon",
        "abort_to_report": "report",
    }.get(action, "report")


def route_by_llm_decision_wordlist(state: dict) -> str:
    """Route: LLM decision sau Wordlist Gen (D3)."""
    action = state.get("_last_decision_action", "abort_to_report")
    return {
        "proceed_to_fuzzing": "fuzzing",
        "use_fallback_wordlist": "fuzzing",
        "retry_wordlist": "gen_words",
        "abort_to_report": "report",
    }.get(action, "report")


def route_by_llm_decision_fuzzing(state: dict) -> str:
    """Route: LLM decision sau Fuzzing (D4)."""
    action = state.get("_last_decision_action", "abort_to_report")
    return {
        "proceed_to_param": "param_disc",
        "skip_to_filter": "filter_404",
        "retry_fuzzing": "fuzzing",
        "abort_to_report": "report",
    }.get(action, "report")


# ═══════════════════════════════════════════════════════════════
# BUILD GRAPH v2.0
# ═══════════════════════════════════════════════════════════════

def build_coordinator_graph() -> StateGraph:
    """
    Xây dựng LLM-Driven State Machine.

    12 nodes:
        - 7 execution nodes (validate, init, 5 agents)
        - 3 LLM decision nodes (D2, D3, D4)
        - 1 report node
        - 1 reflection node
    """
    graph = StateGraph(dict)

    # ── Nodes: Agent execution ──
    graph.add_node("validate_input",    validate_input)
    graph.add_node("init_state",        init_state)
    graph.add_node("tech_recon",        run_tech_recon)
    graph.add_node("gen_words",         run_wordlist_gen)
    graph.add_node("fuzzing",           run_fuzzing)
    graph.add_node("param_disc",        run_param_discovery)
    graph.add_node("filter_404",        run_soft404_filter)
    graph.add_node("report",            generate_report)
    graph.add_node("reflection",        post_session_reflection)

    # ── Nodes: 🧠 LLM Decision Points ──
    graph.add_node("llm_decide_recon",    llm_decide_after_recon)
    graph.add_node("llm_decide_wordlist", llm_decide_after_wordlist)
    graph.add_node("llm_decide_fuzzing",  llm_decide_after_fuzzing)

    # ── Entry ──
    graph.set_entry_point("validate_input")

    # ── Edges ──
    # START → validate → [init | report]
    graph.add_conditional_edges("validate_input", route_after_validate, {
        "init_state": "init_state",
        "report": "report",
    })

    # init → tech_recon
    graph.add_edge("init_state", "tech_recon")

    # tech_recon → 🧠D2 → [gen_words | tech_recon(retry) | report]
    graph.add_edge("tech_recon", "llm_decide_recon")
    graph.add_conditional_edges(
        "llm_decide_recon",
        route_by_llm_decision_recon,
        {
            "gen_words": "gen_words",
            "tech_recon": "tech_recon",
            "report": "report",
        },
    )

    # gen_words → 🧠D3 → [fuzzing | gen_words(retry) | report]
    graph.add_edge("gen_words", "llm_decide_wordlist")
    graph.add_conditional_edges(
        "llm_decide_wordlist",
        route_by_llm_decision_wordlist,
        {
            "fuzzing": "fuzzing",
            "gen_words": "gen_words",
            "report": "report",
        },
    )

    # fuzzing → 🧠D4 → [param_disc | filter_404(skip) | fuzzing(retry) | report]
    graph.add_edge("fuzzing", "llm_decide_fuzzing")
    graph.add_conditional_edges(
        "llm_decide_fuzzing",
        route_by_llm_decision_fuzzing,
        {
            "param_disc": "param_disc",
            "filter_404": "filter_404",
            "fuzzing": "fuzzing",
            "report": "report",
        },
    )

    # param_disc → filter_404
    graph.add_edge("param_disc", "filter_404")

    # filter_404 → report
    graph.add_edge("filter_404", "report")

    # report → reflection → END
    graph.add_edge("report", "reflection")
    graph.add_edge("reflection", END)

    return graph.compile()


# ═══════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def run_pipeline(target_url: str, config: dict = None) -> dict:
    """
    Entry point v2.0 — LLM-Driven Pipeline.

    Args:
        target_url: URL mục tiêu cần quét
        config: Optional config dict
            - llm_model: Model name (default: "gpt-4o")
            - llm_temperature: Temperature (default: 0.1)
            - knowledge_store_dir: Thư mục Knowledge Store

    Returns:
        Final SharedState dict sau khi pipeline hoàn thành
    """
    config = config or {}

    # Reset global state
    global _decision_engine
    _decision_engine = None

    # Reset guard rails
    for cb in circuit_breakers.values():
        cb.reset()
    llm_limiter.reset()
    tarpit_detector.reset()

    initial_state = {
        "target_url": target_url,
        "config": config,
        "session_id": "",
        "started_at": "",
        "finished_at": None,
        "agent_statuses": {},
        "retry_counts": {},
        "tech_stack": {},
        "discovered_paths": [],
        "js_endpoints": [],
        "waf_detected": False,
        "waf_type": None,
        "dev_profile": None,
        "wordlist": [],
        "wordlist_metadata": {},
        "raw_results": [],
        "fuzzing_stats": {},
        "param_results": [],
        "verified_results": [],
        "false_positives": [],
        "baseline_signature": None,
        "llm_call_count": 0,
        "coordinator_llm_calls": 0,
        "total_http_requests": 0,
        "error_log": [],
        "circuit_breaker_state": {},
        "iteration_count": 0,
        "knowledge_context": None,
        "decision_chain": [],
        "audit_log": [],
        "session_lessons": [],
    }

    logger.info(
        f"[Coordinator v2.0] Starting pipeline for {target_url}"
    )

    app = build_coordinator_graph()
    final_state = app.invoke(initial_state)

    logger.info(
        f"[Coordinator v2.0] Pipeline complete — "
        f"Session: {final_state.get('session_id', '?')[:8]}... "
        f"Verified: {len(final_state.get('verified_results', []))} "
        f"Decisions: {len(final_state.get('decision_chain', []))}"
    )

    return final_state
