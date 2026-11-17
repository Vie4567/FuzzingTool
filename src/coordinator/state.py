"""
SharedState v2.0 — Cấu trúc trạng thái chia sẻ xuyên suốt pipeline.

Nguồn dữ liệu duy nhất (Single Source of Truth) cho toàn bộ hệ thống.
Mỗi Agent đọc/ghi vào SharedState thông qua Coordinator.
"""

from typing import TypedDict, Optional, Any


def error_count(state: dict) -> int:
    """Count occurrences, including older error rows without a count field."""
    return sum(row.get("count", 1) if isinstance(row, dict)
               and type(row.get("count", 1)) is int and row.get("count", 1) > 0 else 1
               for row in state.get("error_log", []))


def lifecycle_summary(state: dict) -> dict:
    """Derived observation summary; unknown wire counts stay unknown.

    The engine's attempt totals may include proxy health checks. Planned and
    remaining counts describe fuzz candidates; separate counters document that
    scope instead of asserting that selected equals total HTTP dispatches.
    """
    metadata, stats = state.get("wordlist_metadata", {}), state.get("fuzzing_stats", {})
    def count(value):
        return value if type(value) is int and value >= 0 else None

    generated = metadata.get("generated_valid_count", metadata.get("generated_count"))
    selected = metadata.get("selected_count")
    if selected is None and isinstance(state.get("wordlist"), list):
        selected = len(state["wordlist"])
    returned_only = stats.get("response_count_scope") == "returned_ffuf_records" or state.get(
        "fuzzing_execution", {}).get("engine") == "ffuf_cli"
    return {
        "generated_count": count(generated), "selected_count": count(selected),
        "planned_requests": count(stats.get("planned_requests")),
        "attempted_requests": count(stats.get("attempted_requests")),
        "responses_received": count(stats.get("total_responses_received") if returned_only
                                    else stats.get("responses_received")),
        "network_errors": count(stats.get("network_errors")),
        "proxy_connect_errors": count(stats.get("proxy_connect_errors")),
        "remaining_requests": count(stats.get("remaining_requests")),
        "fuzzing_requests": count(stats.get("fuzzing_requests")),
        "healthcheck_requests": count(stats.get("healthcheck_requests")),
        "responses_received_lower_bound": count(stats.get("responses_received")) if returned_only else None,
        "response_count_scope": "returned_ffuf_records_lower_bound" if returned_only else "all_engine_attempts",
        "request_count_source": stats.get("request_count_source", "engine_dispatch_boundary" if stats.get("attempted_requests") is not None else "unknown"),
        "count_scope": "planned/remaining=fuzz candidates; attempted/responses/network_errors=all engine attempts including health checks; proxy CONNECT rejections are separate from network_errors; HTTP200 is not verification",
    }


class SharedState(TypedDict, total=False):
    """
    SharedState v2.0 — Bổ sung knowledge + audit fields.

    Tất cả các field đều optional (total=False) vì state được
    khởi tạo dần trong init_state node.
    """

    # ── META ─────────────────────────────────────────────────
    session_id: str                     # UUID phiên chạy
    target_url: str                     # URL mục tiêu
    started_at: str                     # ISO datetime bắt đầu
    finished_at: Optional[str]          # ISO datetime kết thúc
    config: dict                        # User config (custom options)
    pipeline_status: str               # running | completed | partial | failed
    artifacts: dict                     # Public paths to durable result/checkpoints
    telemetry: dict                     # Actual invocation/transport attempts, completeness
    known_http_requests: int            # Lower bound when native engine totals are unknown

    # ── AGENT STATUS ─────────────────────────────────────────
    agent_statuses: dict                # {agent_name: "pending"|"running"|"success"|"partial"|"failed"|"skipped"}
    retry_counts: dict                  # {agent_name: int}
    agent_attempts: dict                # Actual executions; retries = attempts - 1
    all_modules_executed: bool
    all_modules_successful: bool
    runtime: dict                       # Remaining time and shared dispatch budget
    stop_reason: Optional[str]

    # ── AGENT OUTPUTS ────────────────────────────────────────
    # Agent 1: Tech Recon
    tech_stack: dict                    # {"backend": "Django", "frontend": "React", ...}
    recon_http_policy: dict             # Public origin/TLS policy; never credential values
    recon_profile: dict                # Versioned evidence/context; observed, candidate and inferred stay distinct
    recon_execution: dict              # Last attempt: channel status, actual counters and sanitized errors
    discovered_paths: list              # Các đường dẫn phát hiện được
    js_endpoints: list                  # Endpoints trích xuất từ JS
    waf_detected: bool                  # Có WAF không?
    waf_type: Optional[str]             # Loại WAF (Cloudflare, Akamai, ...)
    dev_profile: Optional[dict]         # Developer profile (naming convention, etc.)

    # Agent 2: Wordlist Generator
    wordlist: list                      # Wordlist đã sinh
    wordlist_metadata: dict             # Metadata (count, source, ...)
    input_wordlist: list                # Validated operator-provided paths
    generated_wordlist: list            # Valid generated candidates before selection

    # Agent 3: Fuzzing
    raw_results: list                   # Kết quả fuzzing thô
    fuzzing_stats: dict                 # Stats (total_requests, avg_time, ...)

    # Agent 4: Parameter Discovery
    param_results: list                 # Endpoint candidate rows, not verified parameters
    parameter_candidates: list          # Names without sufficient HTTP evidence
    verified_parameters: list           # Repeated differential HTTP evidence
    parameter_stats: dict
    parameter_verification_status: str
    parameter_stop_reason: Optional[str]
    parameter_http_policy: dict

    # Agent 5: Soft 404 Filter
    verified_results: list              # Kết quả đã verify (loại soft 404)
    unverified_results: list            # Phản hồi thật chưa có phép kiểm chứng endpoint
    verification_status: str            # not_checked | skipped | partial | completed | failed
    false_positives: list               # Các kết quả bị loại
    baseline_signature: Optional[dict]  # Baseline DOM signature cho comparison
    soft404_stats: dict                 # Measured verification requests, separate from fuzzing
    soft404_stop_reason: Optional[str]
    soft404_signals: list               # Equal length is a hint, never a classification

    # ── GUARD RAILS ──────────────────────────────────────────
    llm_call_count: int                 # Tổng LLM calls (agents + coordinator)
    total_http_requests: Optional[int]  # None nếu chưa có telemetry đầy đủ, không đoán từ wordlist
    fuzzing_execution: dict             # engine/success/partial/stop_reason và lỗi thực thi
    error_log: list                     # Danh sách lỗi
    circuit_breaker_state: dict         # {agent_name: "closed"|"open"|"half_open"}
    iteration_count: int                # Đếm iteration (chống loop vô hạn)

    # ══ MỚI: KNOWLEDGE & AUDIT ═══════════════════════════════
    knowledge_context: Optional[dict]   # Kết quả truy xuất từ Knowledge Store
    decision_chain: list                # List[DecisionRecord] — chuỗi quyết định
    audit_log: list                     # [{type, timestamp, detail, ...}]
    session_lessons: list               # Bài học rút ra SAU phiên
    coordinator_llm_calls: int          # Chỉ đếm LLM calls của Coordinator

    # ── INTERNAL ROUTING ─────────────────────────────────────
    _last_decision_action: str          # Action từ LLM decision gần nhất
    _config_adjustments: dict           # Config adjustments cho agent tiếp theo
