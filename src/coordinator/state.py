"""
SharedState v2.0 — Cấu trúc trạng thái chia sẻ xuyên suốt pipeline.

Nguồn dữ liệu duy nhất (Single Source of Truth) cho toàn bộ hệ thống.
Mỗi Agent đọc/ghi vào SharedState thông qua Coordinator.
"""

from typing import TypedDict, Optional, Any


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

    # ── AGENT STATUS ─────────────────────────────────────────
    agent_statuses: dict                # {agent_name: "pending"|"running"|"success"|"failed"|"skipped"}
    retry_counts: dict                  # {agent_name: int}

    # ── AGENT OUTPUTS ────────────────────────────────────────
    # Agent 1: Tech Recon
    tech_stack: dict                    # {"backend": "Django", "frontend": "React", ...}
    discovered_paths: list              # Các đường dẫn phát hiện được
    js_endpoints: list                  # Endpoints trích xuất từ JS
    waf_detected: bool                  # Có WAF không?
    waf_type: Optional[str]             # Loại WAF (Cloudflare, Akamai, ...)
    dev_profile: Optional[dict]         # Developer profile (naming convention, etc.)

    # Agent 2: Wordlist Generator
    wordlist: list                      # Wordlist đã sinh
    wordlist_metadata: dict             # Metadata (count, source, ...)

    # Agent 3: Fuzzing
    raw_results: list                   # Kết quả fuzzing thô
    fuzzing_stats: dict                 # Stats (total_requests, avg_time, ...)

    # Agent 4: Parameter Discovery
    param_results: list                 # Kết quả tìm param ẩn

    # Agent 5: Soft 404 Filter
    verified_results: list              # Kết quả đã verify (loại soft 404)
    false_positives: list               # Các kết quả bị loại
    baseline_signature: Optional[dict]  # Baseline DOM signature cho comparison

    # ── GUARD RAILS ──────────────────────────────────────────
    llm_call_count: int                 # Tổng LLM calls (agents + coordinator)
    total_http_requests: int            # Tổng HTTP requests
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
