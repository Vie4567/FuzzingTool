"""
Coordinator v2.0 — LLM-Driven LangGraph State Machine.

Sử dụng LLM Decision Engine thay cho hardcoded routing.
12 nodes (9 execution + 3 LLM decision nodes).

Entry point: run_pipeline(target_url, config)

Cấu trúc graph:
    START → validate → init → tech_recon → 🧠D2 → gen_words → 🧠D3
    → fuzzing → 🧠D4 → [param_disc] → filter_404 → report → 🧠reflect → END
"""

import os
import json
import uuid
import logging
from copy import deepcopy
from contextvars import ContextVar
from contextlib import ExitStack
from functools import wraps
from datetime import datetime, timezone

from .llm_client import DeadlineChatOpenAI as ChatOpenAI
from langgraph.graph import StateGraph, END

from .state import SharedState, lifecycle_summary
from .guards import CircuitBreaker, LLMCallLimiter, TarpitDetector
from .decision_engine import DecisionEngine
from .knowledge_store import KnowledgeStore
from .logger import log_decision, log_agent_skip, log_pipeline_summary
from .llm_logging import sanitize_for_log
from .telemetry import telemetry_session, telemetry_phase, sync_state, current_telemetry
from .artifacts import RunArtifacts, ArtifactWriteError, _secrets
from .validation import validate_pipeline_input, validate_wordlist, InputValidationError
from .runtime import runtime_session, current_runtime, check_deadline, snapshot as runtime_snapshot
from ..tools.recon_http import recon_options_from_config

from ..agents.tech_recon import TechReconAgent
from ..agents.wordlist_gen import WordlistGenAgent
from ..agents.fuzzer import FuzzingAgent
from ..agents.param_discovery import ParamDiscoveryAgent, parameter_options_from_config
from ..agents.soft404_filter import Soft404FilterAgent, soft404_options_from_config

logger = logging.getLogger(__name__)

_active_run = ContextVar("coordinator_active_run", default=None)
_EXECUTION_NODES = {"run_tech_recon": "tech_recon", "run_wordlist_gen": "wordlist_gen",
                    "run_fuzzing": "fuzzing", "run_param_discovery": "param_disc", "run_soft404_filter": "soft404_filter"}


def _local_origin_test():
    run = _active_run.get()
    return run.get("local_origin_test") if run else None


def _output(result, fields, agent):
    if not isinstance(result, dict) or not result:
        raise ValueError(f"{agent} returned an empty or non-object result")
    for key, kind in fields.items():
        if key not in result or not isinstance(result[key], kind):
            raise ValueError(f"{agent} result requires {key} ({kind.__name__})")
    return result


def _sync_fuzzing_errors(state, errors):
    """Summarize this execution once; keep per-request evidence in artifacts.

    Messages and source labels are deliberately fixed: network exception text
    can contain credentials, full URLs or request bodies. A retry has its own
    attempt number; replaying a checkpoint replaces only that attempt's summary.
    """
    attempt = state.get("agent_attempts", {}).get("fuzzing", 1)
    source = "fuzzing_execution.errors"
    counts = {}
    for row in errors:
        row = row if isinstance(row, dict) else {"error": str(row)}
        text = str(row.get("error", row.get("message", ""))).lower()
        if row.get("error_type") in {"llm_justification_error", "engine_error"}:
            kind = row["error_type"]
        elif row.get("proxy_connect_status") is not None:
            kind = "proxy_connect_error"
        elif "timeout" in text or "timed out" in text:
            kind = "timeout"
        elif "gaierror" in text or "name resolution" in text or "getaddrinfo" in text:
            kind = "dns_error"
        elif "refused" in text or "10061" in text:
            kind = "connection_refused"
        elif row.get("status_code") is not None:
            kind = "response_read_error"
        else:
            kind = "transport_error"
        count = row.get("count", 1)
        count = count if type(count) is int and count > 0 else 1
        counts[kind] = counts.get(kind, 0) + count
    messages = {
        "llm_justification_error": "Fuzzing explanation failed; measured HTTP results preserved.",
        "engine_error": "Fuzzing process or output parsing failed; see artifacts.",
        "timeout": "HTTP request timed out.",
        "dns_error": "Target or proxy name resolution failed.",
        "connection_refused": "Target or proxy connection was refused.",
        "proxy_connect_error": "Proxy CONNECT did not establish the tunnel.",
        "response_read_error": "HTTP headers were received but body measurement failed.",
        "transport_error": "HTTP transport failed; see sanitized per-request artifacts.",
    }
    previous = state.setdefault("error_log", [])
    state["error_log"] = [row for row in previous if not (
        row.get("agent") == "fuzzing" and row.get("source") == source
        and row.get("attempt") == attempt)]
    timestamp = datetime.now(timezone.utc).isoformat()
    state["error_log"].extend({
        "agent": "fuzzing", "error_type": kind, "message": messages[kind],
        "error": messages[kind], "count": count, "timestamp": timestamp,
        "source": source, "attempt": attempt,
    } for kind, count in sorted(counts.items()))


def _recon_execution(result):
    """Normalize Recon status without estimating request/response measurements."""
    if "execution" not in result:
        # Older integrations expose only the original two-field contract. Keep
        # that interface usable, while explicitly marking measurement coverage.
        return {"status": "completed", "success": True, "completed": True,
                "partial": False, "stop_reason": "completed", "errors": [],
                "stats": {}, "channels": {}, "measurement_status": "legacy_unreported"}
    execution = deepcopy(result["execution"])
    if (not isinstance(execution, dict)
            or execution.get("status") not in {"completed", "partial", "failed"}
            or not isinstance(execution.get("errors", []), list)
            or not isinstance(execution.get("stats", {}), dict)):
        raise ValueError("Recon execution requires a status, errors list and stats object")
    errors, stats = execution.setdefault("errors", []), execution.setdefault("stats", {})
    status = execution["status"]
    responses, attempts = stats.get("responses_received"), stats.get("attempted_requests")
    network_errors = stats.get("network_errors", 0)
    has_errors = bool(errors) or (type(network_errors) is int and network_errors > 0)
    incomplete = (has_errors or execution.get("success") is False
                  or execution.get("completed") is False or execution.get("partial") is True
                  or execution.get("stop_reason") not in (None, "", "completed"))
    if type(attempts) is int and attempts > 0 and type(responses) is int and responses == 0:
        status = "failed"
    elif status == "completed" and incomplete:
        status = "partial" if type(responses) is int and responses > 0 else "failed"
    execution.update(status=status, success=status == "completed", completed=status == "completed",
                     partial=status == "partial")
    if status != "completed" and execution.get("stop_reason") in (None, "", "completed"):
        execution["stop_reason"] = "recon_incomplete"
    return execution


def _sync_recon_errors(state, errors):
    """Keep occurrence counts once per attempt; detailed evidence stays in Recon."""
    attempt = state.get("agent_attempts", {}).get("tech_recon", 1)
    source = "recon_execution.errors"
    safe = sanitize_for_log({"credentials": state.get("config", {}), "value": errors})["value"]
    counts = {}
    for row in safe:
        row = row if isinstance(row, dict) else {}
        # Never copy arbitrary exception messages/URLs into compact error logs.
        kind = str(row.get("error_type", "recon_error"))[:64]
        channel = str(row.get("channel", "recon"))[:64]
        count = row.get("count", 1)
        count = count if type(count) is int and count > 0 else 1
        counts[(channel, kind)] = counts.get((channel, kind), 0) + count
    state["error_log"] = [row for row in state.setdefault("error_log", []) if not (
        row.get("agent") == "tech_recon" and row.get("source") == source and row.get("attempt") == attempt)]
    timestamp = datetime.now(timezone.utc).isoformat()
    state["error_log"].extend({
        "agent": "tech_recon", "channel": channel, "error_type": kind,
        "message": "Recon channel did not complete; see sanitized execution evidence.",
        "error": "Recon channel did not complete; see sanitized execution evidence.",
        "count": count, "timestamp": timestamp, "source": source, "attempt": attempt,
    } for (channel, kind), count in sorted(counts.items()))


def _apply_decision(state, decision, retry_agent=None):
    if not isinstance(decision, dict) or not isinstance(decision.get("action"), str):
        raise ValueError("Coordinator decision must contain an action")
    action = decision["action"]
    config = state.get("config", {})
    reason = None
    if action.startswith("retry"):
        if not retry_agent or state.get("retry_counts", {}).get(retry_agent, 0) >= config.get("max_retries", 2):
            reason = "max_retries"
        elif retry_agent == "fuzzing" and state.get("fuzzing_execution", {}).get("stop_reason") not in (None, "", "completed"):
            reason = "upstream_stop"
    if state.get("iteration_count", 0) >= config.get("max_iterations", 20):
        reason = "max_iterations"
    budget = current_runtime()
    if budget and budget.stop_reason:
        reason = budget.stop_reason
    if reason:
        action = "abort_to_report"
        state["stop_reason"] = reason
        state["audit_log"].append({"type": "guard_rail_override", "reason": reason,
                                   "original_action": decision["action"], "action": action})
    elif action == "skip_to_filter" and config.get("run_all_modules") and any(
            row.get("status_code") == 200 for row in state.get("raw_results", [])):
        action = "proceed_to_param"
        state["audit_log"].append({"type": "operator_routing", "reason": "run_all_modules",
                                   "original_action": decision["action"], "action": action})
    if action == "abort_to_report":
        state.setdefault("stop_reason", "decision_aborted")
    state["_last_decision_action"] = action
    adjustments = decision.get("next_agent_config_adjustments", {})
    if not isinstance(adjustments, dict):
        raise ValueError("Coordinator configuration adjustments must be an object")
    state["_config_adjustments"] = adjustments


def _checkpointed(node):
    """Keep partial state even if a graph node raises before returning it."""
    @wraps(node)
    def execute(state):
        run = _active_run.get()
        if run is None:
            return node(state)
        run["state"], run["node"] = state, node.__name__
        local = _local_origin_test()
        if local:
            local.enter_node(state, node.__name__)
        sync_state(state)
        run["artifacts"].save(state, node=node.__name__, event="started")
        completed = False
        with telemetry_phase(node.__name__):
            try:
                if local and local.reuse_node(state, node.__name__):
                    # Compiled graph still traverses the same nodes. Their
                    # completed Agent bodies are not invoked or counted again.
                    completed = True
                    return state
                if node.__name__ not in {"validate_input", "init_state", "generate_report"} and (
                        not local or node.__name__ in _EXECUTION_NODES):
                    check_deadline()
                if node.__name__ in _EXECUTION_NODES and not (local and local.continuing_node(node.__name__)
                        and state.get("agent_attempts", {}).get(_EXECUTION_NODES[node.__name__], 0)):
                    agent = _EXECUTION_NODES[node.__name__]
                    attempts = state.setdefault("agent_attempts", {})
                    count = attempts.get(agent, 0)
                    if count > state.get("config", {}).get("max_retries", 2):
                        raise RuntimeError("max_retries")
                    if state.get("iteration_count", 0) >= state.get("config", {}).get("max_iterations", 20):
                        raise RuntimeError("max_iterations")
                    attempts[agent] = count + 1
                    state.setdefault("retry_counts", {})[agent] = count
                    state["iteration_count"] = state.get("iteration_count", 0) + 1
                result = node(state)
                if not isinstance(result, dict):
                    raise ValueError("Coordinator node returned a non-object state")
                run["state"] = result
                completed = True
                return result
            finally:
                if local:
                    local.leave_node(run["state"], node.__name__, completed)
                sync_state(run["state"])
                run["state"]["runtime"] = runtime_snapshot()
                event = "checkpoint" if completed else "interrupted"
                if local and completed:
                    event = local.completion_event(node.__name__)  # B4.2C: finalize skips are not completions
                public = run["artifacts"].save(run["state"], node=node.__name__, event=event)
                if local:
                    local.saved_checkpoint(public, node.__name__, event)
    return execute


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
        model_name = config.get("llm_model") or os.getenv("LLM_MODEL", "DeepSeek-V4.1-Flash")
        temperature = config.get("llm_temperature", float(os.getenv("LLM_TEMPERATURE", "0.1")))

        # Đọc API Key và Base URL (hỗ trợ cả DeepSeek và OpenAI)
        api_key = config.get("api_key") or os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
        base_url = config.get("base_url") or os.getenv("DEEPSEEK_BASE_URL") or os.getenv("OPENAI_API_BASE")

        # Nếu chưa truyền base_url và dùng DeepSeek, đặt mặc định URL API của DeepSeek
        if not base_url and (os.getenv("DEEPSEEK_API_KEY") or "deepseek" in model_name.lower()):
            base_url = "https://api.deepseek.com"

        kwargs = {
            "model": model_name,
            "temperature": temperature,
            # Count one provider attempt per logged invocation; SDK retries
            # would otherwise be invisible to application telemetry.
            "max_retries": 0,
            "timeout": config.get("llm_timeout_seconds", 30),
            "max_tokens": config.get("llm_max_tokens", 4096),
        }
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url

        llm = ChatOpenAI(**kwargs)
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

@_checkpointed
def validate_input(state: dict) -> dict:
    """Node: Validate URL đầu vào."""
    url = state.get("target_url", "")

    try:
        if state.get("_input_validated"):
            config = state["config"]
        else:
            url, config = validate_pipeline_input(url, state.get("config"))
        state["target_url"], state["config"] = url, config
        state["input_wordlist"] = config.get("wordlist", [])
        # B1 adds a public contract without enabling unguarded Agent dispatch.
        # Exact multi-origin policy is not wired through every engine until B3.
        if "multi_origin" in config:
            local = _local_origin_test()
            if local:
                local.validate(state)
            else:
                from .origins import origin_state
                state.update(origin_state(url, config["multi_origin"]))
                state["stop_reason"] = "multi_origin_execution_not_enabled_b1"
                raise InputValidationError("multi_origin execution is unavailable until all dispatch guards are integrated (B3)")
    except (InputValidationError, TypeError, ValueError) as exc:
        state["agent_statuses"]["validate"] = "failed"
        state["audit_log"].append({
            "type": "validation_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": str(exc),
        })
        state.setdefault("error_log", []).append({"agent": "validate", "error": str(exc)})
        logger.error("[Coordinator] Input validation failed: %s", exc)
    else:
        state["agent_statuses"]["validate"] = "success"
        state["audit_log"].append({
            "type": "validation_passed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": f"URL hợp lệ: {url}",
        })
        logger.info(f"[Coordinator] URL validated: {url}")

    return state


@_checkpointed
def init_state(state: dict) -> dict:
    """Node: Khởi tạo SharedState đầy đủ + Knowledge context."""
    state["session_id"] = state.get("session_id") or str(uuid.uuid4())
    state["started_at"] = state.get("started_at") or datetime.now(timezone.utc).isoformat()

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
    state.setdefault("recon_profile", {})
    state.setdefault("recon_execution", {})
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
    state.setdefault("parameter_candidates", [])
    state.setdefault("verified_parameters", [])
    state.setdefault("parameter_stats", {})
    state.setdefault("parameter_verification_status", "not_checked")
    state.setdefault("verified_results", [])
    state.setdefault("unverified_results", [])
    state.setdefault("verification_status", "not_checked")
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
    if _local_origin_test():
        _local_origin_test().initialize(state)
    return state


@_checkpointed
def run_tech_recon(state: dict) -> dict:
    """Node: Agent 1 — Tech Recon."""
    if _local_origin_test():
        state = _local_origin_test().recon(state, TechReconAgent)
        _sync_recon_errors(state, state["recon_execution"].get("errors", []))
        return state
    state["agent_statuses"]["tech_recon"] = "running"
    state["audit_log"].append({
        "type": "agent_started",
        "agent": "tech_recon",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        engine = _get_decision_engine(state.get("config"))
        agent = TechReconAgent(llm=engine.llm if engine else None,
                               **recon_options_from_config(state.get("config")))
        result = agent.execute(state["target_url"])
        _output(result, {"tech_stack": dict, "discovered_paths": list}, "Recon")
        # Collect credential fields from config, not every configuration string.
        # Treating the whole config as credentials also erased public origins,
        # HTTP methods and seed paths from Recon evidence and Agent 2 context.
        result = sanitize_for_log({"credentials": _secrets(state.get("config", {})), "value": result})["value"]
        execution = _recon_execution(result)
        previous = state.get("recon_execution", {})
        responses = execution.get("stats", {}).get("responses_received")
        retain_profile = (bool(state.get("recon_profile")) and execution["status"] == "failed"
                          and type(responses) is int and responses == 0)

        if not retain_profile:
            state["tech_stack"] = result.get("tech_stack", {})
            state["discovered_paths"] = result.get("discovered_paths", [])
            state["js_endpoints"] = result.get("js_endpoints", [])
            state["waf_detected"] = result.get("waf_detected", False)
            state["waf_type"] = result.get("waf_type", None)
        state["recon_http_policy"] = result.get("http_policy", {})
        profile = result.get("recon_profile")
        if state.get("origin_contract_version") == 1 and result.get("discovery_context") is not None:
            from .origins import merge_discovery_context
            merge_discovery_context(state, result["discovery_context"])
        if profile is not None and not isinstance(profile, dict):
            raise ValueError("Recon profile must be an object")
        # Legacy fields remain available; the full structured evidence lives in
        # one canonical profile instead of duplicating forms/schema across state.
        if not retain_profile:
            state["recon_profile"] = deepcopy(profile) if profile is not None else {
                "schema_version": 1, "target_url": state["target_url"],
                "tech_stack": deepcopy(state["tech_stack"]), "paths": [],
                "parameters": [], "forms": [], "api_context": {}, "architecture": {},
                "measurement_status": "legacy_unreported",
            }
        else:
            execution["retained_profile_attempt"] = previous.get("retained_profile_attempt") or previous.get("attempt")
        state["recon_execution"] = execution
        state["recon_execution"]["attempt"] = state.get("agent_attempts", {}).get("tech_recon", 1)
        _sync_recon_errors(state, state["recon_execution"]["errors"])
        # Only transport dispatch telemetry can supply the global count. Outside
        # a runtime session it remains unknown rather than derived from paths.
        if current_telemetry() is None:
            state["total_http_requests"] = None
        else:
            sync_state(state)
        state.setdefault("subagent_justifications", {})["tech_recon"] = result.get("subagent_justification", "")
        execution_status = state["recon_execution"]["status"]
        state["agent_statuses"]["tech_recon"] = "success" if execution_status == "completed" else execution_status
        if execution_status == "completed":
            circuit_breakers["tech_recon"].record_success()
        elif execution_status == "failed":
            circuit_breakers["tech_recon"].record_failure()

        logger.info(
            f"[TechRecon] {execution_status} — "
            f"stack={state['tech_stack']}, "
            f"paths={len(state['discovered_paths'])}, "
            f"WAF={state['waf_type']}"
        )

    except Exception as e:
        state["agent_statuses"]["tech_recon"] = "failed"
        safe_error = sanitize_for_log({"credentials": state.get("config", {}), "value": str(e)})["value"]
        failure = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "channel": "recon", "error_type": "agent_error", "message": safe_error, "count": 1,
        }
        previous = state.get("recon_execution", {})
        state["recon_execution"] = {
            "status": "failed", "success": False, "completed": False, "partial": False,
            "stop_reason": "agent_error", "stats": {}, "channels": {}, "errors": [failure],
            "attempt": state.get("agent_attempts", {}).get("tech_recon", 1),
            "retained_profile_attempt": (previous.get("retained_profile_attempt") or previous.get("attempt"))
                                        if state.get("recon_profile") else None,
        }
        _sync_recon_errors(state, [failure])
        circuit_breakers["tech_recon"].record_failure()
        logger.error(f"[TechRecon] Failed: {safe_error}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "tech_recon",
        "status": state["agent_statuses"]["tech_recon"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


@_checkpointed
def llm_decide_after_recon(state: dict) -> dict:
    """Node: 🧠 LLM quyết định sau Tech Recon (Decision Point D2)."""
    if _local_origin_test():
        return _local_origin_test().decide(state, "after_recon")
    engine = _get_decision_engine(state.get("config"))

    subagent_just = state.get("subagent_justifications", {}).get("tech_recon", "")
    result_summary = (
        f"Tech stack: {json.dumps(state.get('tech_stack', {}))}. "
        f"Paths found: {len(state.get('discovered_paths', []))}. "
        f"WAF: {state.get('waf_type', 'None')}. "
        f"Recon execution: {state.get('recon_execution', {}).get('status', 'legacy_unreported')}; "
        f"stop reason: {state.get('recon_execution', {}).get('stop_reason')}. "
        f"Sub-Agent Justification: {subagent_just}"
    )

    decision = engine.make_decision(
        state=state,
        decision_point="after_tech_recon",
        completed_agent="tech_recon",
        agent_status=state["agent_statuses"]["tech_recon"],
        agent_result_summary=result_summary,
    )

    log_decision(
        decision_point="after_tech_recon (D2)",
        action=decision.get("action", "unknown"),
        reasoning=decision.get("reasoning", "No reasoning provided"),
        adjustments=decision.get("next_agent_config_adjustments")
    )

    _apply_decision(state, decision, "tech_recon")
    return state


@_checkpointed
def run_wordlist_gen(state: dict) -> dict:
    """Node: Agent 2 — Wordlist Generator."""
    if _local_origin_test():
        return _local_origin_test().wordlist(state, WordlistGenAgent)
    state["agent_statuses"]["wordlist_gen"] = "running"
    state["audit_log"].append({
        "type": "agent_started",
        "agent": "wordlist_gen",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        engine = _get_decision_engine(state.get("config"))
        agent = WordlistGenAgent(llm=engine.llm if engine else None)
        result = agent.execute(
            tech_stack=state["tech_stack"],
            discovered_paths=state["discovered_paths"],
            js_endpoints=state.get("js_endpoints", []),
            target_url=state["target_url"],
            recon_profile=state.get("recon_profile", {}),
        )
        _output(result, {"wordlist": list}, "Wordlist")

        state["dev_profile"] = result.get("dev_profile")
        generated, rejected = [], 0
        for entry in result["wordlist"]:
            try:
                generated.extend(validate_wordlist(state["target_url"], [entry]))
            except InputValidationError:
                rejected += 1
        generated = validate_wordlist(state["target_url"], generated, allow_empty=True)
        mode = state.get("config", {}).get("wordlist_mode", "generated")
        provided = state.get("input_wordlist", state.get("config", {}).get("wordlist", []))
        selected = provided if mode == "provided" else provided + generated if mode == "merge" else generated
        state["generated_wordlist"] = generated
        state["wordlist"] = validate_wordlist(state["target_url"], selected)
        count = len(state["wordlist"])
        limit = state.get("config", {}).get("max_wordlist_entries")
        if limit:
            state["wordlist"] = state["wordlist"][:limit]
        state["wordlist_metadata"] = result.get("metadata", {})
        state["wordlist_metadata"].update(selection_mode=mode, generated_valid_count=len(generated),
                                          rejected_generated_entries=rejected, selection_input_count=count,
                                          selected_count=len(state["wordlist"]), selection_limit=limit)
        state.setdefault("subagent_justifications", {})["wordlist_gen"] = result.get("subagent_justification", "")
        state["agent_statuses"]["wordlist_gen"] = "success"
        circuit_breakers["wordlist_gen"].record_success()

        logger.info(
            f"[WordlistGen] Success — "
            f"{len(generated)} valid candidates generated, {len(state['wordlist'])} selected"
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


@_checkpointed
def llm_decide_after_wordlist(state: dict) -> dict:
    """Node: 🧠 LLM quyết định sau Wordlist Generation (Decision Point D3)."""
    if _local_origin_test():
        return _local_origin_test().decide(state, "after_wordlist")
    engine = _get_decision_engine(state.get("config"))

    subagent_just = state.get("subagent_justifications", {}).get("wordlist_gen", "")
    result_summary = (
        f"Lifecycle: {json.dumps(lifecycle_summary(state))}. "
        f"Sub-Agent Justification (unverified model explanation): {str(subagent_just)[:1000]}"
    )

    decision = engine.make_decision(
        state=state,
        decision_point="after_wordlist_gen",
        completed_agent="wordlist_gen",
        agent_status=state["agent_statuses"]["wordlist_gen"],
        agent_result_summary=result_summary,
    )

    log_decision(
        decision_point="after_wordlist_gen (D3)",
        action=decision.get("action", "unknown"),
        reasoning=decision.get("reasoning", "No reasoning provided"),
        adjustments=decision.get("next_agent_config_adjustments")
    )

    _apply_decision(state, decision, "wordlist_gen")
    return state


@_checkpointed
def run_fuzzing(state: dict) -> dict:
    """Node: Agent 3 — Real HTTP fuzzing, preserving partial measurements."""
    if _local_origin_test():
        state = _local_origin_test().fuzzing(state, FuzzingAgent)
        errors = [{**r["error"], "error": r["error"]["exception_type"], "status_code": r["status_code"]}
                  for e in state["origin_contexts"].values()
                  for r in e["context"]["http_dispatch"]["records"] if r["attempted"] and r["error"]]
        _sync_fuzzing_errors(state, errors)
        return state
    state["agent_statuses"]["fuzzing"] = "running"
    config_adj = dict(state.get("_config_adjustments") or {})
    # Manager plans may tune measurement settings, but only operator config can
    # select a transport, provide routing credentials or define approved scope.
    from src.tools.proxy_profiles import OPERATOR_NETWORK_OPTIONS
    for key in OPERATOR_NETWORK_OPTIONS:
        config_adj.pop(key, None)
    config_adj.update(state.get("config", {}).get("fuzzing_options") or {})
    if state.get("config", {}).get("max_wordlist_entries") or state.get("config", {}).get("wordlist_mode") == "provided":
        # The selected work plan is explicit; do not silently append new paths.
        config_adj["use_pattern_engine"] = False
    for key in ("target_url", "wordlist", "waf_detected", "waf_type", "dev_profile", "observed_urls"):
        config_adj.pop(key, None)

    state["audit_log"].append({
        "type": "agent_started",
        "agent": "fuzzing",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "config_adjustments": FuzzingAgent._public_options(config_adj),
    })

    try:
        engine = _get_decision_engine(state.get("config"))
        agent = FuzzingAgent(llm=engine.llm if engine else None)
        result = agent.execute(
            target_url=state["target_url"],
            wordlist=state["wordlist"],
            waf_detected=state.get("waf_detected", False),
            waf_type=state.get("waf_type"),
            dev_profile=state.get("dev_profile"),
            observed_urls=list(dict.fromkeys(state.get("discovered_paths", []) + state.get("js_endpoints", []))),
            **config_adj,
        )
        _output(result, {"results": list, "stats": dict}, "Fuzzing")

        state["raw_results"] = result.get("results", [])
        state["fuzzing_stats"] = result.get("stats", {})
        state.setdefault("subagent_justifications", {})["fuzzing"] = result.get("subagent_justification", "")
        request_count = result.get("stats", {}).get("total_requests")
        previous_count = state.get("total_http_requests")
        state["total_http_requests"] = (
            previous_count + request_count
            if isinstance(previous_count, int) and isinstance(request_count, int)
            else None
        )
        state["fuzzing_execution"] = {
            key: result.get(key) for key in
            ("engine", "success", "completed", "partial", "simulated", "stop_reason", "errors", "warnings", "error_message",
             "verification_context")
        }
        context = state["fuzzing_execution"].get("verification_context")
        if isinstance(context, dict):
            context = dict(context)
            operator_options = state.get("config", {}).get("fuzzing_options") or {}
            context["auth_matches_operator"] = (
                context.get("auth_matches_operator") is True
                and (config_adj.get("headers") or {}) == (operator_options.get("headers") or {})
            )
            context["operator_headers_configured"] = "headers" in operator_options
            state["fuzzing_execution"]["verification_context"] = context
        errors = result.get("errors") or []
        _sync_fuzzing_errors(state, errors)
        successful = (result.get("success", True) and not result.get("partial") and not errors
                      and result.get("completed") is not False
                      and result.get("stop_reason") in (None, "", "completed"))
        if not successful:
            state["fuzzing_execution"].update(success=False, partial=True, completed=False)
        received = any(row.get("status_code") is not None for row in state["raw_results"])
        state["agent_statuses"]["fuzzing"] = "success" if successful else "partial" if received else "failed"

        # Tarpit detection
        avg_time = result.get("stats", {}).get(
            "avg_response_time"
        )
        if isinstance(avg_time, (int, float)):
            tarpit_detector.record_response_time(avg_time)
        if isinstance(avg_time, (int, float)) and tarpit_detector.is_tarpit_detected():
            state["circuit_breaker_state"]["fuzzing"] = "open"
            state["audit_log"].append({
                "type": "tarpit_detected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            logger.warning("[Fuzzing] Tarpit detected!")

        if state["agent_statuses"]["fuzzing"] == "success":
            circuit_breakers["fuzzing"].record_success()
        else:
            circuit_breakers["fuzzing"].record_failure()

        http_200_count = len([
            r for r in state["raw_results"]
            if r.get("status_code") == 200
        ])
        logger.info(
            f"[Fuzzing] {state['agent_statuses']['fuzzing']} — "
            f"{len(state['raw_results'])} results, "
            f"{http_200_count} HTTP 200"
        )

    except Exception as e:
        state["agent_statuses"]["fuzzing"] = "failed"
        state.setdefault("fuzzing_execution", {}).update(success=False, partial=True, completed=False,
                                                        stop_reason="execution_failed")
        safe_error = sanitize_for_log({"credentials": config_adj, "value": str(e)})["value"]
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "fuzzing",
            "error_type": "execution_error", "message": safe_error, "error": safe_error,
            "count": 1, "source": "FuzzingAgent.execute",
            "attempt": state.get("agent_attempts", {}).get("fuzzing", 1),
        })
        circuit_breakers["fuzzing"].record_failure()
        logger.error("[Fuzzing] Failed: %s", safe_error)

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "fuzzing",
        "status": state["agent_statuses"]["fuzzing"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


@_checkpointed
def llm_decide_after_fuzzing(state: dict) -> dict:
    """Node: 🧠 LLM quyết định sau Fuzzing (Decision Point D4).

    Bao gồm Agent Skip logic — LLM quyết định có nên chạy
    param_disc hay skip trực tiếp sang filter_404.
    """
    if _local_origin_test():
        return _local_origin_test().decide(state, "after_fuzzing")
    execution = state.get("fuzzing_execution", {})
    if execution.get("partial") or execution.get("stop_reason") not in (None, "", "completed"):
        # Preserve measured responses without repeating a blocked/limited scan.
        state["_last_decision_action"] = "skip_to_filter"
        state["_config_adjustments"] = {}
        state["agent_statuses"]["param_disc"] = "skipped"
        state["audit_log"].append({
            "type": "fuzzing_stopped",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": execution.get("stop_reason") or execution.get("error_message"),
            "action": "preserve_partial_results",
        })
        return state
    engine = _get_decision_engine(state.get("config"))

    http_200s = [
        r
        for r in state.get("raw_results", [])
        if r.get("status_code") == 200
    ]
    subagent_just = state.get("subagent_justifications", {}).get("fuzzing", "")
    result_summary = (
        f"Lifecycle: {json.dumps(lifecycle_summary(state))}. "
        f"Total results: {len(state.get('raw_results', []))}. "
        f"HTTP 200: {len(http_200s)}. "
        f"Pipeline-wide HTTP attempts (all phases): {state.get('total_http_requests')}. "
        "HTTP 200 is not an endpoint verification. "
        f"Sub-Agent Justification (unverified model explanation): {str(subagent_just)[:1000]}"
    )

    decision = engine.make_decision(
        state=state,
        decision_point="after_fuzzing",
        completed_agent="fuzzing",
        agent_status=state["agent_statuses"]["fuzzing"],
        agent_result_summary=result_summary,
    )

    log_decision(
        decision_point="after_fuzzing (D4)",
        action=decision.get("action", "unknown"),
        reasoning=decision.get("reasoning", "No reasoning provided"),
        adjustments=decision.get("next_agent_config_adjustments")
    )

    if decision["action"] == "skip_to_filter":
        state["agent_statuses"]["param_disc"] = "skipped"
        log_agent_skip("ParamDiscoveryAgent", decision.get("reasoning", "LLM quyết định skip sang filter 404"))

    _apply_decision(state, decision, "fuzzing")
    return state


def _verification_execution_status(result):
    """A returned payload is not proof that HTTP verification ran."""
    declared = result.get("verification_status", "not_checked")
    stop = result.get("stop_reason")
    if declared in {"failed", "partial", "skipped"}:
        return declared, declared, stop
    count = (result.get("stats") or {}).get("total_requests")
    measured = result.get("verification_performed") is True and type(count) is int and count > 0
    if declared == "completed" and measured:
        if stop not in (None, "", "completed"):
            return "partial", "partial", stop
        return "success", declared, stop
    if measured:
        return "partial", "partial", stop or "verification_status_unrecognized"
    # Preserve legacy/unreported declarations for consumers, but never promote
    # them to success. An explicit completed-without-measurements is skipped.
    return "skipped", "skipped" if declared == "completed" else declared, (
        stop if stop not in (None, "", "completed") else "verification_not_performed"
    )


@_checkpointed
def run_param_discovery(state: dict) -> dict:
    """Node: Agent 4 — Parameter Discovery."""
    if _local_origin_test():
        return _local_origin_test().parameters(state, ParamDiscoveryAgent)
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
        execution = dict(state.get("fuzzing_execution") or {})
        if state.get("agent_statuses", {}).get("fuzzing") in {"failed", "partial"}:
            execution.update(success=False, partial=True)
        engine = _get_decision_engine(state.get("config"))
        agent = ParamDiscoveryAgent(llm=engine.llm if engine else None)
        result = agent.execute(
            target_url=state["target_url"],
            endpoints=http_200_endpoints,
            tech_stack=state.get("tech_stack", {}),
            dev_profile=state.get("dev_profile"),
            verification_options=parameter_options_from_config(state.get("config"), execution),
        )
        _output(result, {"param_results": list}, "Parameter")

        state["param_results"] = result.get("param_results", [])
        state["parameter_candidates"] = result.get("parameter_candidates", [])
        state["verified_parameters"] = result.get("verified_parameters", [])
        state["parameter_stats"] = result.get("stats", {})
        agent_status, verification_status, stop_reason = _verification_execution_status(result)
        state["parameter_verification_status"] = verification_status
        state["parameter_stop_reason"] = stop_reason
        state["parameter_http_policy"] = result.get("http_policy", {})
        state.setdefault("subagent_justifications", {})["param_disc"] = result.get("subagent_justification", "")
        count = result.get("stats", {}).get("total_requests", 0)
        previous = state.get("total_http_requests")
        state["total_http_requests"] = previous + count if isinstance(previous, int) and isinstance(count, int) else None
        status = state["parameter_verification_status"]
        state["agent_statuses"]["param_disc"] = agent_status
        if status == "failed":
            state["error_log"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(), "agent": "param_disc",
                "error": sanitize_for_log({"credentials": state.get("config", {}),
                                           "value": result.get("error", "Parameter verification failed")})["value"],
            })
            circuit_breakers["param_disc"].record_failure()
        elif agent_status == "success":
            circuit_breakers["param_disc"].record_success()

        logger.info(
            f"[ParamDisc] {agent_status} — "
            f"{len(state['verified_parameters'])} verified, "
            f"{len(state['parameter_candidates'])} candidates"
        )

    except Exception as e:
        state["agent_statuses"]["param_disc"] = "failed"
        state["verified_parameters"] = []
        state["parameter_verification_status"] = "failed"
        state["parameter_stop_reason"] = "verification_failed"
        state["parameter_stats"] = {"total_requests": None}
        safe_error = sanitize_for_log({"credentials": state.get("config", {}), "value": str(e)})["value"]
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "param_disc",
            "error": safe_error,
        })
        circuit_breakers["param_disc"].record_failure()
        logger.error(f"[ParamDisc] Failed: {safe_error}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "param_disc",
        "status": state["agent_statuses"]["param_disc"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


@_checkpointed
def run_soft404_filter(state: dict) -> dict:
    """Node: Agent 5 — Soft 404 Filter."""
    if _local_origin_test() and _local_origin_test().soft404_verification:
        return _local_origin_test().soft404(state, Soft404FilterAgent)
    state["agent_statuses"]["soft404_filter"] = "running"
    state["audit_log"].append({
        "type": "agent_started",
        "agent": "soft404_filter",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # Parameter evidence has its own result lists; candidate containers are not
    # endpoint measurements and must not force a completed endpoint filter to partial.
    all_results = (state.get("raw_results") or []) + (
        [] if state.get("parameter_verification_status") in {"completed", "partial", "failed", "skipped"}
        else (state.get("param_results") or []))
    try:
        execution = dict(state.get("fuzzing_execution") or {})
        if state.get("agent_statuses", {}).get("fuzzing") in {"failed", "partial"}:
            execution.update(success=False, partial=True)
        # A block/transport stop during Parameter must not be bypassed by the
        # following verification phase.
        if state.get("parameter_verification_status") in {"partial", "failed"}:
            execution.update(success=False, partial=True,
                             stop_reason=state.get("parameter_stop_reason") or "parameter_incomplete")
        agent = Soft404FilterAgent()
        result = agent.execute(
            target_url=state["target_url"],
            results_to_verify=all_results,
            **soft404_options_from_config(state.get("config"), execution),
        )
        _output(result, {"verified": list, "unverified": list}, "Soft404")

        state["verified_results"] = result.get("verified", [])
        state["unverified_results"] = result.get("unverified", [])
        agent_status, verification_status, stop_reason = _verification_execution_status(result)
        state["verification_status"] = verification_status
        state["false_positives"] = result.get("false_positives", [])
        state["baseline_signature"] = result.get("baseline")
        state["soft404_stats"] = result.get("stats", {})
        state["soft404_stop_reason"] = stop_reason
        state["soft404_signals"] = result.get("equal_length_signals", [])
        state.setdefault("subagent_justifications", {})["soft404"] = result.get("subagent_justification", "")
        request_count = result.get("stats", {}).get("total_requests", 0)
        previous_count = state.get("total_http_requests")
        if isinstance(previous_count, int) and isinstance(request_count, int):
            state["total_http_requests"] = previous_count + request_count
        state["agent_statuses"]["soft404_filter"] = agent_status
        if agent_status == "failed":
            state["error_log"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(), "agent": "soft404_filter",
                "error": sanitize_for_log({"credentials": _secrets(state.get("config", {})),
                                           "value": result.get("error", "Soft404 verification failed")})["value"],
            })
            circuit_breakers["soft404"].record_failure()
        elif agent_status == "success":
            circuit_breakers["soft404"].record_success()

        logger.info(
            f"[Soft404] {state['agent_statuses']['soft404_filter']} — "
            f"{len(state['verified_results'])} verified, "
            f"{len(state['unverified_results'])} unverified, "
            f"{len(state['false_positives'])} filtered"
        )

    except Exception as e:
        state["agent_statuses"]["soft404_filter"] = "failed"
        # Keep real measurements, without pretending they passed verification.
        state["verified_results"] = []
        from copy import deepcopy
        state["unverified_results"] = deepcopy(all_results)
        for row in state["unverified_results"]:
            if not isinstance(row, dict):
                continue
            row.update(verification="not_checked", verification_performed=False)
            for key in ("similarity_to_baseline", "verification_evidence", "verification_reason"):
                row.pop(key, None)
        state["false_positives"] = []
        state["baseline_signature"] = None
        state["soft404_stats"] = {"total_requests": None}
        state["soft404_stop_reason"] = "verification_failed"
        state["soft404_signals"] = []
        state.setdefault("subagent_justifications", {})["soft404"] = "Verification failed; results remain unverified."
        state["total_http_requests"] = None
        state["verification_status"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "soft404_filter",
            "error": sanitize_for_log({"credentials": state.get("config", {}), "value": str(e)})["value"],
        })
        circuit_breakers["soft404"].record_failure()
        logger.error(f"[Soft404] Failed: {state['error_log'][-1]['error']}")

    state["audit_log"].append({
        "type": "agent_completed",
        "agent": "soft404_filter",
        "status": state["agent_statuses"]["soft404_filter"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


@_checkpointed
def generate_report(state: dict) -> dict:
    """Node: Tổng hợp báo cáo cuối cùng."""
    if _local_origin_test():
        # B4.2C: per-origin Report; the final pipeline status is set after Reflection.
        _local_origin_test().report(state)
    state["finished_at"] = datetime.now(timezone.utc).isoformat()
    state["audit_log"].append({
        "type": "report_generated",
        "timestamp": state["finished_at"],
        "summary": {
            "verified": len(state.get("verified_results", [])),
            "unverified": len(state.get("unverified_results", [])),
            "verification_status": state.get("verification_status", "not_checked"),
            "filtered": len(state.get("false_positives", [])),
            "verified_parameters": len(state.get("verified_parameters", [])),
            "parameter_candidates": len(state.get("parameter_candidates", [])),
            "decisions_made": len(state.get("decision_chain", [])),
        },
    })

    logger.info(
        f"[Report] Generated — "
        f"{len(state.get('verified_results', []))} verified results, "
        f"{len(state.get('decision_chain', []))} decisions made"
    )
    return state


@_checkpointed
def post_session_reflection(state: dict) -> dict:
    """Node: 🧠 LLM rút bài học → lưu Knowledge Store."""
    if _local_origin_test():
        # B4.2C: deterministic, report-backed; no LLM provider and no KnowledgeStore write.
        return _local_origin_test().reflect(state)
    if state.get("agent_statuses", {}).get("validate") == "failed":
        return state
    try:
        engine = _get_decision_engine(state.get("config"))
        engine.reflect_on_session(state)
    except Exception as e:
        safe_error = sanitize_for_log({"credentials": state.get("config", {}), "value": str(e)})["value"]
        logger.error(f"[Reflection] Failed: {safe_error}")
        state.setdefault("error_log", []).append({"agent": "reflection", "error": safe_error,
                                                 "timestamp": datetime.now(timezone.utc).isoformat()})
        state["audit_log"].append({
            "type": "reflection_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": safe_error,
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

def run_pipeline(target_url: str, config: dict = None, *, local_origin_test=None) -> dict:
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
    config = {} if config is None else config

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
        "session_id": str(uuid.uuid4()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "agent_statuses": {},
        "retry_counts": {},
        "tech_stack": {},
        "recon_profile": {},
        "recon_execution": {},
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
        "parameter_candidates": [],
        "verified_parameters": [],
        "parameter_stats": {},
        "parameter_verification_status": "not_checked",
        "verified_results": [],
        "unverified_results": [],
        "verification_status": "not_checked",
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

    # Create a durable destination before any HTTP/LLM activity. Write failures
    # are explicit errors: a scan must not continue without its checkpoints.
    if local_origin_test is not None:
        from .origin_local import LocalOriginTest
        if type(local_origin_test) is not LocalOriginTest:
            raise ValueError("An explicit localhost-only execution context is required")
    artifact_config = config if isinstance(config, dict) else {}
    if local_origin_test:
        artifact_config = local_origin_test.artifact_config(artifact_config)
    artifacts = RunArtifacts(artifact_config)
    run = {"state": initial_state, "node": "pipeline", "artifacts": artifacts,
           "local_origin_test": local_origin_test}
    token = _active_run.set(run)
    try:
        with telemetry_session(max_llm_calls=50), ExitStack() as contexts:
            initial_state["pipeline_status"] = "running"
            artifacts.save(initial_state, node="pipeline", event="started")
            try:
                if not isinstance(config, dict):
                    raise ValueError("config must be a mapping")
                # A bad input follows the normal validate/report path, without
                # constructing clients or entering runtime/network operations.
                try:
                    normalized_target, normalized_config = validate_pipeline_input(target_url, config)
                except InputValidationError:
                    normalized_config = None
                if normalized_config is not None:
                    if local_origin_test:
                        normalized_config = local_origin_test.configure(normalized_target, normalized_config)
                    initial_state.update(target_url=normalized_target, config=normalized_config, _input_validated=True)
                    current_telemetry().max_llm_calls = 0 if local_origin_test else normalized_config["max_llm_calls"]
                    budget = contexts.enter_context(runtime_session(normalized_config))
                    if local_origin_test and local_origin_test.recovery:
                        recovery = contexts.enter_context(local_origin_test.recovery)
                        finished = recovery.bind(local_origin_test, budget, initial_state, normalized_config)
                        if finished is not None:
                            # B4.2C already_finished: verified result only; no graph, Agent or journal write.
                            return artifacts.save(local_origin_test.finished_result(finished),
                                                  node="pipeline", event="already_finished")
                elif local_origin_test:
                    raise InputValidationError("Invalid localhost graph configuration")
                app = build_coordinator_graph()
                # Each agent execution can be followed by a decision node.
                # Leave room for validate/init/report/reflection so LangGraph's
                # default 25 steps cannot pre-empt our explicit execution limit.
                max_iterations = (normalized_config or {}).get("max_iterations", 20)
                graph_config = {"recursion_limit": 2 * max_iterations + 10}
                if local_origin_test:
                    graph_config["callbacks"] = [local_origin_test.callback]
                final_state = app.invoke(initial_state, config=graph_config)
                run["state"] = final_state
                sync_state(final_state)
                final_state["finished_at"] = datetime.now(timezone.utc).isoformat()
                statuses = set(final_state.get("agent_statuses", {}).values())
                required = set(_EXECUTION_NODES.values())
                final_state["all_modules_executed"] = all(final_state.get("agent_attempts", {}).get(k, 0) > 0 for k in required)
                final_state["all_modules_successful"] = all(final_state.get("agent_statuses", {}).get(k) == "success" for k in required)
                final_state["pipeline_status"] = (
                    "failed" if final_state.get("agent_statuses", {}).get("validate") == "failed"
                    else "partial" if final_state.get("error_log") or final_state.get("stop_reason") or statuses & {"failed", "partial", "pending", "running"}
                    else "completed"
                )
                if local_origin_test:
                    local_origin_test.finish(final_state)
                public = artifacts.save(final_state, node="pipeline", event=final_state["pipeline_status"])
                if local_origin_test and local_origin_test.recovery:
                    local_origin_test.saved_checkpoint(public, "pipeline", final_state["pipeline_status"])
                    local_origin_test.recovery.append("session_finished", {"pipeline_status": final_state["pipeline_status"]})
                start_dt = datetime.fromisoformat(final_state["started_at"])
                finish_dt = datetime.fromisoformat(final_state["finished_at"])
                log_pipeline_summary(
                    session_id=public.get("session_id", "unknown"), target_url=public.get("target_url", ""),
                    duration_sec=max((finish_dt - start_dt).total_seconds(), 0.0),
                    stats={
                        "verified_results": len(public.get("verified_results", [])),
                        "unverified_results": len(public.get("unverified_results", [])),
                        "verification_status": public.get("verification_status", "not_checked"),
                        "false_positives": len(public.get("false_positives", [])),
                        "llm_calls": public.get("llm_call_count", 0),
                        "http_requests": public.get("total_http_requests"),
                        "decisions_made": len(public.get("decision_chain", [])),
                        "agent_statuses": public.get("agent_statuses", {}),
                    },
                )
                return public
            except ArtifactWriteError:
                # Do not mask a disk failure with another save or claim success.
                raise
            except BaseException as exc:
                state = run["state"]
                from .origin_recovery import RecoveryDenied
                if local_origin_test and local_origin_test.recovery and isinstance(exc, RecoveryDenied):
                    # A denied load is not a new empty session. Keep old files
                    # intact and report accounting as unknown, never reset to 0.
                    state["recovery"] = {"status": "blocked", "reason": str(exc),
                        "journal": str(local_origin_test.recovery.directory / "journal.jsonl"),
                        "safe_resume": "not_verified", "exactly_once_delivery": False}
                    state["runtime"] = {"http_dispatches": None, "stop_reason": str(exc)}
                    state["stop_reason"] = str(exc)
                    current_telemetry().http_unknown(phase="recovery", source="reconciliation_denied")
                sync_state(state)
                state["finished_at"] = datetime.now(timezone.utc).isoformat()
                if local_origin_test:
                    local_origin_test.finish(state)
                public = artifacts.record_failure(state, exc, node=run["node"])
                if not isinstance(exc, Exception):
                    raise
                return public
    finally:
        _active_run.reset(token)
