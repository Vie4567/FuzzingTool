# COORDINATOR v2.0 — LLM-Driven Orchestration với Knowledge Base

> **Module:** `src/coordinator/`  
> **Thuộc dự án:** Sentinel Pentest — Multi-Agent Pentest System  
> **Phiên bản:** 2.0 (LLM-Driven)  
> **Cập nhật:** 2026-09-21

---

## 1. Tổng quan

### 1.1. Sự khác biệt giữa v1.0 và v2.0

| Đặc điểm | v1.0 (Hardcoded) | v2.0 (LLM-Driven) |
|-----------|-------------------|--------------------|
| **Routing** | `if/else` cố định | LLM phân tích context → quyết định |
| **Lý do quyết định** | Không có | Mỗi quyết định kèm reasoning |
| **Học từ quá khứ** | Không | Knowledge Store lưu kết quả + bài học từ các lần chạy trước |
| **Audit Trail** | Log đơn giản | Decision Chain đầy đủ, trace được toàn bộ logic |
| **Khả năng thích ứng** | Không — cùng target chạy giống nhau | Có — thích ứng dựa trên kinh nghiệm tích lũy |
| **Agent Skip** | Rule cứng (HTTP 200 count ≤ 2) | LLM cân nhắc nhiều yếu tố + kinh nghiệm quá khứ |

### 1.2. Coordinator v2.0 là gì?

**Coordinator v2.0** vẫn giữ vai trò **"bộ não điều phối"** nhưng giờ đây nó là **một LLM Agent thực sự** — sử dụng prompt, kiến thức tích lũy, và reasoning để ra quyết định thay vì logic `if/else` cứng nhắc.

**Nguyên tắc cốt lõi:**
> *"Mỗi quyết định phải có lý do. Mỗi lần chạy phải để lại kiến thức. Agent không chỉ thực thi — mà phải suy nghĩ."*

### 1.3. Trách nhiệm chính (mở rộng)

| # | Trách nhiệm | Mô tả |
|---|-------------|-------|
| 1 | **State Management** | Duy trì `SharedState` — nguồn dữ liệu duy nhất xuyên suốt pipeline |
| 2 | **LLM-Driven Orchestration** | LLM phân tích state hiện tại + knowledge → ra quyết định agent tiếp theo |
| 3 | **Knowledge Accumulation** | Lưu kết quả, bài học, patterns từ các lần chạy trước → cải thiện quyết định |
| 4 | **Reasoned Decisions** | Mỗi quyết định kèm reasoning (tại sao chọn, tại sao không chọn cái khác) |
| 5 | **Audit Trail** | Ghi lại toàn bộ chuỗi quyết định, có thể trace ngược từ kết quả → lý do |
| 6 | **Error Recovery** | LLM phân tích lỗi + kinh nghiệm → quyết định retry/skip/abort có lý do |
| 7 | **Guard Rails** | Circuit breaker, rate limiter (vẫn giữ hardcoded cho safety) |

### 1.4. Kiến trúc tổng thể v2.0

```
                    ┌──────────────────────────────────────┐
                    │            USER INPUT                │
                    │         (Target URL + Options)       │
                    └──────────────┬───────────────────────┘
                                   │
 ╔═════════════════════════════════▼════════════════════════════════╗
 ║                    C O O R D I N A T O R   v2.0                 ║
 ║                                                                  ║
 ║  ┌────────────────────────────────────────────────────────────┐  ║
 ║  │                   LLM DECISION ENGINE                      │  ║
 ║  │                                                            │  ║
 ║  │  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐   │  ║
 ║  │  │ System   │  │  Knowledge   │  │  Decision Record  │   │  ║
 ║  │  │ Prompt   │  │  Retriever   │  │  + Audit Log      │   │  ║
 ║  │  │          │  │  (RAG-style) │  │                   │   │  ║
 ║  │  └──────────┘  └──────┬───────┘  └───────────────────┘   │  ║
 ║  │                       │                                    │  ║
 ║  │              ┌────────▼────────┐                          │  ║
 ║  │              │ Knowledge Store │  Persistent memory       │  ║
 ║  │              │ (JSON/SQLite)   │  across sessions         │  ║
 ║  │              └─────────────────┘                          │  ║
 ║  └────────────────────────────────────────────────────────────┘  ║
 ║                                                                  ║
 ║  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐    ║
 ║  │ SharedState   │   │ Guard Rails  │   │ LangGraph Engine │    ║
 ║  │ (Runtime)     │   │ (Hardcoded)  │   │ (State Machine)  │    ║
 ║  └──────────────┘   └──────────────┘   └──────────────────┘    ║
 ╚════╤═══╤═══╤═══╤═══╤═══╤═══════════════════════════════════════╝
      │   │   │   │   │   │
       ▼   ▼       ▼            ▼      ▼      ▼
    Agent1 Agent2 FuzzSubsys Agent4 Agent5 Report
```

---

## 2. LLM Decision Engine — Bộ máy ra quyết định

### 2.1. Vòng lặp quyết định (Decision Loop)

Tại mỗi **điểm quyết định** (sau khi một Agent hoàn thành), Coordinator không dùng `if/else` mà thực hiện **LLM Decision Loop**:

```
┌───────────────────────────────────────────────────────────────────────┐
│                     LLM DECISION LOOP                                 │
│                                                                       │
│  ┌─────────────┐                                                     │
│  │ Agent N     │                                                     │
│  │ hoàn thành  │                                                     │
│  └──────┬──────┘                                                     │
│         │                                                             │
│         ▼                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ BƯỚC 1: THU THẬP CONTEXT                                       │ │
│  │                                                                  │ │
│  │  ├── Current SharedState (summary)                              │ │
│  │  ├── Agent N result (success/fail + data)                       │ │
│  │  ├── Guard Rails status (circuit breakers, LLM quota)           │ │
│  │  └── Available next actions (danh sách agents có thể gọi)      │ │
│  └──────────────────────────────┬──────────────────────────────────┘ │
│                                 │                                     │
│                                 ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ BƯỚC 2: TRUY XUẤT KNOWLEDGE                                    │ │
│  │                                                                  │ │
│  │  ├── Tìm các session tương tự trong quá khứ                    │ │
│  │  │   (cùng tech stack, cùng loại WAF, cùng pattern)            │ │
│  │  ├── Lấy bài học đã rút ra (lessons_learned)                   │ │
│  │  └── Lấy decision patterns đã thành công                      │ │
│  └──────────────────────────────┬──────────────────────────────────┘ │
│                                 │                                     │
│                                 ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ BƯỚC 3: LLM REASONING                                          │ │
│  │                                                                  │ │
│  │  System Prompt + Context + Knowledge                            │ │
│  │         │                                                        │ │
│  │         ▼                                                        │ │
│  │  ┌──────────────────────┐                                       │ │
│  │  │   LLM suy nghĩ:     │                                       │ │
│  │  │   - Phân tích tình   │                                       │ │
│  │  │     huống hiện tại   │                                       │ │
│  │  │   - So sánh với      │                                       │ │
│  │  │     kinh nghiệm      │                                       │ │
│  │  │   - Cân nhắc các     │                                       │ │
│  │  │     lựa chọn         │                                       │ │
│  │  │   - Đưa ra quyết     │                                       │ │
│  │  │     định + lý do     │                                       │ │
│  │  └──────────┬───────────┘                                       │ │
│  │             │                                                    │ │
│  │             ▼                                                    │ │
│  │  Output: DecisionRecord (JSON)                                  │ │
│  └──────────────────────────────┬──────────────────────────────────┘ │
│                                 │                                     │
│                                 ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ BƯỚC 4: VALIDATE + GUARD RAILS CHECK                           │ │
│  │                                                                  │ │
│  │  ├── LLM decision hợp lệ? (action trong danh sách allowed?)   │ │
│  │  ├── Circuit breaker cho phép? (hardcoded safety)              │ │
│  │  ├── LLM quota còn không?                                      │ │
│  │  └── Tarpit detected? (hardcoded override)                     │ │
│  └──────────────────────────────┬──────────────────────────────────┘ │
│                                 │                                     │
│                                 ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ BƯỚC 5: GHI AUDIT LOG + THỰC THI                               │ │
│  │                                                                  │ │
│  │  ├── Ghi DecisionRecord vào audit_log                          │ │
│  │  ├── Cập nhật SharedState                                      │ │
│  │  └── Invoke Agent tiếp theo                                    │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### 2.2. Các điểm quyết định (Decision Points)

LLM được gọi tại **5 điểm quyết định** trong pipeline:

| # | Decision Point | Câu hỏi LLM cần trả lời | Lựa chọn khả dĩ |
|---|---------------|--------------------------|------------------|
| D1 | Sau `VALIDATE_INPUT` | "Input có đủ để tiến hành không?" | `proceed` / `abort` |
| D2 | Sau `TECH_RECON` | "Target Profile đủ chất lượng chưa? Tiếp tục hay retry?" | `proceed_to_wordlist` / `retry_recon` / `abort_to_report` |
| D3 | Sau `GEN_WORDS` | "Wordlist có chất lượng không? Tiếp tục hay dùng fallback?" | `proceed_to_fuzz_planner` / `use_fallback_wordlist` / `abort_to_report` |
| D4 | Sau `FUZZ_SUBSYSTEM` | "Các cluster kết quả có đủ endpoint 200 để phân tích param không?" | `proceed_to_param` / `skip_to_report` / `retry_with_different_config` / `abort_to_report` |
| D5 | Sau `PARAM_DISC` | "Param discovery có kết quả đáng chú ý? Tổng hợp báo cáo." | `generate_report` / `abort_to_report` |
| Dx | Khi **bất kỳ Agent lỗi** | "Lỗi gì? Retry có ý nghĩa không? Kinh nghiệm nói gì?" | `retry` / `skip` / `abort` |

---

## 3. Knowledge Store — Bộ nhớ kiến thức

### 3.1. Tại sao cần Knowledge Store?

```
 Lần chạy 1 (ngày 1):                    Lần chạy 5 (ngày 15):
 ┌─────────────────────────┐              ┌─────────────────────────┐
 │ Target: Django app      │              │ Target: Django app (mới)│
 │ WAF: Cloudflare         │              │ WAF: Cloudflare         │
 │                         │              │                         │
 │ Coordinator KHÔNG BIẾT  │              │ Coordinator ĐÃ BIẾT:   │
 │ gì → thử tất cả agents │              │ • Django thường có      │
 │ → param_disc không có   │              │   /admin/, /api/v1/     │
 │   kết quả → lãng phí    │              │ • Cloudflare cần jitter │
 │                         │              │   > 2s mới ổn           │
 │ Kết quả: tốn 25 phút   │              │ • Param disc ít hiệu    │
 └─────────┬───────────────┘              │   quả với static sites  │
           │                              │                         │
           │ ──── LƯU VÀO KNOWLEDGE ────▶ │ Kết quả: chỉ 12 phút   │
           │                              │ (skip param, tăng jitter)│
           └──────────────────────────────└─────────────────────────┘
```

### 3.2. Cấu trúc Knowledge Store

```
knowledge_store/
├── sessions/                      # Kết quả từng phiên
│   ├── 2026-09-20_abc123.json
│   ├── 2026-09-21_def456.json
│   └── ...
├── lessons_learned.json           # Bài học rút ra (tổng hợp)
├── decision_patterns.json         # Patterns quyết định đã thành công
└── tech_stack_profiles.json       # Profile cho từng tech stack đã gặp
```

### 3.3. Schema chi tiết

#### a) Session Record — Kết quả một phiên chạy

```python
class SessionRecord:
    """Kết quả một phiên chạy, lưu vào Knowledge Store."""
    
    schema = {
        "session_id": "uuid",
        "timestamp": "ISO datetime",
        "target_url": "https://example.com",
        "duration_seconds": 720,
        
        # ── CONTEXT (đầu vào) ──
        "context": {
            "tech_stack": {
                "web_server": "Nginx",
                "backend": "Django",
                "frontend": "React",
            },
            "waf_detected": True,
            "waf_type": "Cloudflare",
            "discovered_paths_count": 24,
            "target_characteristics": [
                "has_api_prefix",
                "uses_snake_case",
                "has_admin_panel",
            ],
        },
        
        # ── DECISIONS (chuỗi quyết định) ──
        "decisions": [
            {
                "decision_id": "D2_001",
                "point": "after_tech_recon",
                "action": "proceed_to_wordlist",
                "reasoning": "Recon tìm được 24 paths, tech stack rõ ràng (Django+React). Đủ data cho wordlist generation.",
                "alternatives_considered": [
                    {"action": "retry_recon", "why_rejected": "Đã có đủ data, retry lãng phí LLM call"}
                ],
                "confidence": 0.92,
                "timestamp": "2026-09-21T10:01:15Z",
            },
            {
                "decision_id": "D4_001",
                "point": "after_fuzzing",
                "action": "skip_to_filter",
                "reasoning": "Chỉ có 1 endpoint HTTP 200. Kinh nghiệm từ session abc123 cho thấy param discovery với <3 endpoints thường không tìm được gì mới. Skip để tiết kiệm thời gian.",
                "alternatives_considered": [
                    {"action": "proceed_to_param", "why_rejected": "Kinh nghiệm cho thấy hiệu quả thấp khi ít endpoint"}
                ],
                "confidence": 0.85,
                "knowledge_used": ["session_abc123.decisions.D4_001"],
                "timestamp": "2026-09-21T10:05:30Z",
            },
        ],
        
        # ── OUTCOMES (kết quả) ──
        "outcomes": {
            "total_verified_results": 15,
            "total_false_positives_filtered": 8,
            "total_http_requests": 5200,
            "total_llm_calls": 12,
            "agents_executed": ["tech_recon", "wordlist_gen", "fuzzing", "soft404_filter"],
            "agents_skipped": ["param_disc"],
            "errors_encountered": 0,
        },
        
        # ── LESSONS LEARNED (bài học) ──
        "lessons_learned": [
            {
                "lesson": "Django apps với Cloudflare WAF cần jitter >= 2.0s",
                "evidence": "Với jitter 0.5s, bị block 40%. Sau tăng lên 2.0s, block rate giảm xuống 2%.",
                "applicable_when": {
                    "tech_stack.backend": "Django",
                    "waf_type": "Cloudflare",
                },
                "confidence": 0.90,
            },
            {
                "lesson": "Param discovery không hiệu quả khi endpoint HTTP 200 < 3",
                "evidence": "Trong 5 session với <3 endpoints, param disc chỉ tìm được 0-1 param mới.",
                "applicable_when": {
                    "http_200_count": "< 3",
                },
                "confidence": 0.85,
            },
        ],
    }
```

#### b) Lessons Learned — Bài học tổng hợp

```json
{
    "lessons": [
        {
            "id": "L001",
            "lesson": "Django apps thường có /admin/ panel mặc định",
            "source_sessions": ["abc123", "def456", "ghi789"],
            "times_validated": 3,
            "confidence": 0.95,
            "applicable_when": {
                "tech_stack.backend": ["Django", "Django REST Framework"]
            },
            "recommended_action": "Luôn include /admin/ trong wordlist cho Django targets",
            "created_at": "2026-09-15T10:00:00Z",
            "last_validated": "2026-09-21T10:00:00Z"
        },
        {
            "id": "L002",
            "lesson": "Spring Boot apps có /actuator/* endpoints nhạy cảm",
            "source_sessions": ["jkl012"],
            "times_validated": 1,
            "confidence": 0.70,
            "applicable_when": {
                "tech_stack.backend": ["Spring Boot", "Java"]
            },
            "recommended_action": "Ưu tiên fuzz /actuator/env, /actuator/health, /actuator/configprops",
            "created_at": "2026-09-18T14:00:00Z"
        }
    ]
}
```

#### c) Decision Patterns — Mẫu quyết định đã chứng minh

```json
{
    "patterns": [
        {
            "id": "P001",
            "name": "Skip param_disc cho static sites",
            "condition": {
                "http_200_count": "< 3",
                "tech_stack.frontend": ["React", "Vue.js", "Angular"]
            },
            "recommended_action": "skip_to_filter",
            "success_rate": 0.90,
            "times_used": 4,
            "avg_time_saved_seconds": 180,
            "source_sessions": ["abc123", "def456", "ghi789", "mno345"]
        },
        {
            "id": "P002",
            "name": "Retry recon khi WAF block lần đầu",
            "condition": {
                "waf_detected": true,
                "tech_recon.status": "failed",
                "tech_recon.error_type": "blocked"
            },
            "recommended_action": "retry_recon_with_delay",
            "success_rate": 0.75,
            "times_used": 8,
            "source_sessions": ["pqr678", "stu901"]
        }
    ]
}
```

### 3.4. Knowledge Retrieval — Truy xuất kiến thức

Trước mỗi quyết định, Coordinator truy xuất kiến thức liên quan theo thứ tự ưu tiên:

```
┌─────────────────────────────────────────────────────────────────────┐
│                   KNOWLEDGE RETRIEVAL PIPELINE                      │
│                                                                     │
│  ┌───────────────┐                                                 │
│  │ Current State │  Extracting: tech_stack, waf_type,              │
│  │ (context)     │  discovered_paths_count, decision_point         │
│  └───────┬───────┘                                                 │
│          │                                                          │
│          ▼                                                          │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 1. EXACT MATCH: Tìm session có cùng tech_stack + waf_type   │ │
│  │    → Lấy decisions + lessons từ session đó                   │ │
│  │    → Ưu tiên cao nhất (experience trực tiếp)                 │ │
│  └───────────────────────────────┬───────────────────────────────┘ │
│                                  │                                  │
│                                  ▼                                  │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 2. SIMILAR MATCH: Tìm session có tech_stack.backend giống   │ │
│  │    → Lấy lessons_learned áp dụng được                       │ │
│  │    → Ưu tiên trung bình                                     │ │
│  └───────────────────────────────┬───────────────────────────────┘ │
│                                  │                                  │
│                                  ▼                                  │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 3. PATTERN MATCH: Tìm decision patterns áp dụng được        │ │
│  │    → Lấy recommended_action + success_rate                   │ │
│  │    → Ưu tiên thấp (general patterns)                        │ │
│  └───────────────────────────────┬───────────────────────────────┘ │
│                                  │                                  │
│                                  ▼                                  │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 4. GLOBAL LESSONS: Các bài học áp dụng chung                │ │
│  │    → confidence > 0.80 + times_validated > 2                 │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Output: KnowledgeContext (top 5 relevant items)                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Decision Record & Audit Log

### 4.1. Decision Record Schema

Mỗi quyết định của Coordinator được ghi lại đầy đủ:

```python
class DecisionRecord:
    """
    Bản ghi một quyết định của Coordinator.
    Immutable — không bao giờ sửa sau khi tạo.
    """

    schema = {
        # ── IDENTIFICATION ──
        "decision_id": "D2_001",          # Format: D{point}_{sequence}
        "session_id": "uuid",
        "timestamp": "2026-09-21T10:01:15Z",
        
        # ── DECISION POINT ──
        "decision_point": "after_tech_recon",   # Điểm quyết định
        "trigger": "agent_completed",            # Lý do trigger
        "agent_completed": "tech_recon",         # Agent vừa xong
        "agent_status": "success",               # Kết quả agent
        
        # ── STATE SNAPSHOT ──
        "state_snapshot": {
            "tech_stack": {"backend": "Django", "frontend": "React"},
            "waf_detected": True,
            "waf_type": "Cloudflare",
            "discovered_paths_count": 24,
            "wordlist_size": 0,
            "raw_results_count": 0,
            "llm_calls_used": 3,
            "llm_calls_remaining": 47,
            "errors_so_far": 0,
            "elapsed_seconds": 45,
        },
        
        # ── KNOWLEDGE USED ──
        "knowledge_context": {
            "similar_sessions_found": 2,
            "relevant_lessons": [
                {
                    "id": "L001",
                    "lesson": "Django apps thường có /admin/",
                    "confidence": 0.95,
                },
            ],
            "relevant_patterns": [
                {
                    "id": "P002",
                    "name": "Retry recon khi WAF block",
                    "success_rate": 0.75,
                },
            ],
            "similar_session_decisions": [
                {
                    "session": "abc123",
                    "same_point": "after_tech_recon",
                    "action_taken": "proceed_to_wordlist",
                    "outcome": "success — found 15 endpoints",
                },
            ],
        },
        
        # ── LLM REASONING (core) ──
        "reasoning": {
            "analysis": "Tech recon hoàn thành thành công. Tìm được 24 paths và xác định Django+React stack với Cloudflare WAF. So với session abc123 (cùng Django+Cloudflare), đã có đủ data cho wordlist generation.",
            
            "factors_considered": [
                "Số paths tìm được (24) — đủ lớn để phân tích pattern",
                "Tech stack rõ ràng (Django+React) — LLM sẽ sinh wordlist chính xác",
                "WAF Cloudflare — cần lưu ý cho Agent 3",
                "Kinh nghiệm session abc123 — cùng setup, proceed thành công",
            ],
            
            "alternatives_evaluated": [
                {
                    "action": "retry_recon",
                    "pros": "Có thể tìm thêm paths từ JS chunks",
                    "cons": "Đã có 24 paths, retry tốn thêm 1 LLM call. Session abc123 với 20 paths đã đủ.",
                    "verdict": "REJECTED — diminishing returns",
                },
                {
                    "action": "abort_to_report",
                    "pros": "N/A",
                    "cons": "Không có lý do abort — recon thành công",
                    "verdict": "REJECTED — no reason to abort",
                },
            ],
        },
        
        # ── DECISION ──
        "action": "proceed_to_wordlist",
        "confidence": 0.92,
        "is_knowledge_influenced": True,    # Quyết định có bị ảnh hưởng bởi knowledge?
        
        # ── OUTCOME (cập nhật sau) ──
        "outcome": {
            "next_agent_status": "success",     # Filled after next agent completes
            "was_correct_decision": True,        # Retrospective evaluation
            "outcome_notes": "Wordlist generation thành công, sinh 6,200 entries",
        },
    }
```

### 4.2. Audit Log — Chuỗi quyết định toàn phiên

```python
class AuditLog:
    """
    Nhật ký kiểm toán toàn bộ phiên.
    Cho phép trace ngược: kết quả → quyết định → lý do → kiến thức.
    """
    
    schema = {
        "session_id": "uuid",
        "target_url": "https://example.com",
        "started_at": "2026-09-21T10:00:00Z",
        "finished_at": "2026-09-21T10:12:00Z",
        
        # ── DECISION CHAIN ──
        "decision_chain": [
            # Mỗi entry là một DecisionRecord (xem schema ở trên)
            {"decision_id": "D1_001", "action": "proceed", "reasoning": "..."},
            {"decision_id": "D2_001", "action": "proceed_to_wordlist", "reasoning": "..."},
            {"decision_id": "D3_001", "action": "proceed_to_fuzzing", "reasoning": "..."},
            {"decision_id": "D4_001", "action": "skip_to_filter", "reasoning": "..."},
            {"decision_id": "D6_001", "action": "generate_report", "reasoning": "..."},
        ],
        
        # ── SUMMARY ──
        "total_decisions": 5,
        "decisions_influenced_by_knowledge": 2,
        "decisions_with_retry": 0,
        "agents_skipped_by_llm": ["param_disc"],
        
        # ── GUARD RAIL INTERVENTIONS ──
        "guard_rail_overrides": [
            # Khi hardcoded guard rail override quyết định LLM
            # (ví dụ: LLM muốn tiếp tục nhưng circuit breaker OPEN)
        ],
        
        # ── KNOWLEDGE CONTRIBUTIONS ──
        "new_lessons_generated": [
            {
                "lesson": "...",
                "derived_from_decisions": ["D4_001"],
            },
        ],
    }
```

### 4.3. Traceability — Khả năng truy vết

Audit log cho phép trả lời các câu hỏi:

```
Q: "Tại sao param discovery bị skip?"
   │
   └──▶ Tìm DecisionRecord có action="skip_to_filter"
        │
        └──▶ D4_001: "Chỉ có 1 endpoint HTTP 200. Kinh nghiệm từ session 
             abc123 cho thấy param discovery với <3 endpoints không hiệu quả."
             │
             └──▶ knowledge_used: session_abc123.lessons_learned.L002
                  │
                  └──▶ "Param discovery không hiệu quả khi endpoint HTTP 200 < 3"
                       Evidence: "Trong 5 session, param disc chỉ tìm 0-1 param mới"
```

---

## 5. Coordinator Prompts — Prompt Templates

### 5.1. System Prompt — Vai trò Coordinator

```
SYSTEM PROMPT — COORDINATOR AGENT
══════════════════════════════════

Bạn là Coordinator — bộ não điều phối của hệ thống Sentinel Pentest.

## VAI TRÒ
Bạn quản lý một pipeline dò quét gồm 5 Worker Agents:
  • Agent 1 (Tech Recon):     Phân tích tech stack, DOM, JS, WAF
  • Agent 2 (Wordlist Gen):   Sinh wordlist thông minh dựa trên DevProfile
  • Agent 3 (Fuzzing):        Quét endpoint bằng ffuf + WAF evasion
  • Agent 4 (Param Discovery): Tìm parameter ẩn trên endpoint HTTP 200
  • Agent 5 (Soft 404 Filter): Lọc false positive bằng DOM comparison

## NHIỆM VỤ
Sau khi mỗi Agent hoàn thành (hoặc thất bại), bạn phải:
1. PHÂN TÍCH kết quả và trạng thái hiện tại
2. THAM KHẢO kiến thức từ các lần chạy trước (nếu có)
3. QUYẾT ĐỊNH bước tiếp theo
4. GIẢI THÍCH lý do quyết định
5. ĐÁNH GIÁ các lựa chọn khác và giải thích tại sao không chọn

## QUY TẮC BẮT BUỘC
1. MỌI quyết định PHẢI có reasoning — không bao giờ quyết định không lý do
2. Nếu có kiến thức từ quá khứ LIÊN QUAN, PHẢI tham khảo và trích dẫn
3. LUÔN cân nhắc ít nhất 2 lựa chọn thay thế trước khi quyết định
4. Confidence score PHẢI phản ánh mức độ chắc chắn thực sự (0.0 - 1.0)
5. Nếu confidence < 0.6, PHẢI giải thích tại sao không chắc chắn
6. KHÔNG BAO GIỜ loop vô hạn — mỗi agent tối đa retry 3 lần
7. Nếu guard rail (circuit breaker, LLM quota) can thiệp, TUÂN THỦ ngay

## OUTPUT FORMAT
Trả lời CHÍNH XÁC theo JSON schema dưới đây. KHÔNG thêm text ngoài JSON.
```

### 5.2. Decision Prompt Template — Gọi tại mỗi điểm quyết định

```
USER PROMPT — DECISION REQUEST
═══════════════════════════════

## TRẠNG THÁI HIỆN TẠI

### Agent vừa hoàn thành:
- Agent: {completed_agent_name}
- Status: {agent_status} (success/failed)
- Kết quả tóm tắt: {agent_result_summary}
- Thời gian thực thi: {execution_time}s
{error_details_if_failed}

### SharedState hiện tại:
- Target: {target_url}
- Tech Stack: {tech_stack_json}
- WAF: {waf_detected} ({waf_type})
- Paths đã tìm: {discovered_paths_count}
- Wordlist size: {wordlist_size}
- Raw results: {raw_results_count} (HTTP 200: {http_200_count})
- Param results: {param_results_count}
- Verified results: {verified_results_count}
- Errors: {error_count}

### Tài nguyên:
- LLM calls: {llm_calls_used}/{llm_calls_max} (còn {llm_calls_remaining})
- HTTP requests: {total_http_requests}
- Thời gian đã chạy: {elapsed_seconds}s
- Circuit Breakers: {circuit_breaker_states}

## KIẾN THỨC TỪ QUÁ KHỨ

### Sessions tương tự đã chạy:
{similar_sessions_summary}

### Bài học liên quan:
{relevant_lessons}

### Decision patterns áp dụng được:
{relevant_patterns}

## CÁC HÀNH ĐỘNG KHẢ THI

Bạn có thể chọn MỘT trong các hành động sau:
{available_actions_list}

## YÊU CẦU OUTPUT

Trả về JSON theo format:
```json
{
    "action": "<tên hành động>",
    "confidence": <0.0 - 1.0>,
    "reasoning": {
        "analysis": "<phân tích tình huống hiện tại, 2-4 câu>",
        "factors_considered": ["<yếu tố 1>", "<yếu tố 2>", ...],
        "knowledge_referenced": ["<lesson/pattern ID nếu có>"],
        "alternatives_evaluated": [
            {
                "action": "<hành động thay thế>",
                "pros": "<ưu điểm>",
                "cons": "<nhược điểm>",
                "verdict": "REJECTED — <lý do ngắn>"
            }
        ]
    },
    "next_agent_config_adjustments": {
        "<config_key>": "<new_value nếu cần điều chỉnh>"
    },
    "new_observation": "<quan sát mới rút ra từ quyết định này, nếu có>"
}
```
```

### 5.3. Error Decision Prompt — Khi Agent thất bại

```
USER PROMPT — ERROR DECISION REQUEST
═════════════════════════════════════

⚠️ AGENT THẤT BẠI — CẦN QUYẾT ĐỊNH

### Thông tin lỗi:
- Agent: {failed_agent_name}
- Error: {error_message}
- Error type: {error_type} (timeout/blocked/parse_error/internal/...)
- Retry count hiện tại: {retry_count}/{max_retries}

### Context khi lỗi xảy ra:
{state_snapshot_at_error}

### Kiến thức về lỗi tương tự:
{similar_error_knowledge}

### Các hành động khả thi:
1. "retry" — Chạy lại agent này (retry #{next_retry_count})
2. "retry_with_adjustment" — Chạy lại với config khác (specify trong next_agent_config_adjustments)
3. "skip" — Bỏ qua agent, tiếp tục pipeline với data hiện có
4. "abort_to_report" — Dừng pipeline, xuất báo cáo với kết quả partial

### YÊU CẦU
- Nếu retry, GIẢI THÍCH tại sao nghĩ retry sẽ thành công
- Nếu skip, GIẢI THÍCH impact đến kết quả cuối
- Nếu abort, GIẢI THÍCH tại sao không thể tiếp tục
- Tham khảo kinh nghiệm xử lý lỗi tương tự từ quá khứ
```

### 5.4. Post-Session Reflection Prompt — Rút bài học sau phiên

```
USER PROMPT — POST-SESSION REFLECTION
══════════════════════════════════════

Phiên quét vừa hoàn thành. Hãy rút ra bài học.

### Tổng kết phiên:
- Target: {target_url}
- Tech Stack: {tech_stack}
- WAF: {waf_info}
- Duration: {duration}
- Agents executed: {agents_list}
- Agents skipped: {skipped_list}
- Results: {verified_count} verified, {false_positive_count} filtered

### Chuỗi quyết định đã thực hiện:
{decision_chain_summary}

### YÊU CẦU
Phân tích và trả về JSON:
```json
{
    "lessons_learned": [
        {
            "lesson": "<bài học rút ra>",
            "evidence": "<bằng chứng từ phiên này>",
            "applicable_when": {
                "<condition_key>": "<condition_value>"
            },
            "confidence": <0.0-1.0>
        }
    ],
    "decision_evaluations": [
        {
            "decision_id": "<ID quyết định>",
            "was_correct": true/false,
            "retrospective_note": "<nhận xét hồi tưởng>"
        }
    ],
    "recommendations_for_future": [
        "<đề xuất cho lần chạy sau>"
    ]
}
```
```

---

## 6. State Graph v2.0 — Cập nhật

### 6.1. Sơ đồ tổng thể với LLM Decision Points

```
                           ┌─────────────┐
                           │    START     │
                           └──────┬──────┘
                                  │
                           ┌──────▼──────┐
                           │ VALIDATE    │
                           │ _INPUT      │
                           └──────┬──────┘
                                  │
                           ┌──────▼──────┐
                           │ INIT_STATE  │
                           └──────┬──────┘
                                  │
                           ┌──────▼──────┐
                           │ TECH_RECON  │  Agent 1
                           └──────┬──────┘
                                  │
                        ┌─────────▼─────────┐
                        │  🧠 LLM DECIDE   │  Decision Point D2
                        │  (+ Knowledge)    │
                        └──┬─────────────┬──┘
                      ok   │             │ retry/abort
                           │       ┌─────▼──────┐
                           │       │  ERROR /    │
                           │       │  RETRY      │
                           │       └─────────────┘
                    ┌──────▼──────┐
                    │  GEN_WORDS  │  Agent 2
                    └──────┬──────┘
                           │
                  ┌────────▼────────┐
                  │  🧠 LLM DECIDE │  Decision Point D3
                  │  (+ Knowledge)  │
                  └─┬────────────┬──┘
               ok   │            │ fallback/abort
                    │            └─────────┐
             ┌──────▼──────┐              │
             │   FUZZING   │  Agent 3     │
             └──────┬──────┘              │
                    │                     │
           ┌────────▼────────┐            │
           │  🧠 LLM DECIDE │ D4         │
           │  (+ Knowledge)  │            │
           └─┬──────┬─────┬─┘            │
       param │ skip │  err│              │
             │      │     └───────────────┤
      ┌──────▼──┐   │                    │
      │PARAM_DIS│   │                    │
      │  Agent 4│   │                    │
      └────┬────┘   │                    │
           │        │                    │
    ┌──────▼────────▼─┐                  │
    │   FILTER_404    │ Agent 5          │
    └──────┬──────────┘                  │
           │                             │
    ┌──────▼──────┐                      │
    │ 🧠 LLM     │  D6                  │
    │ DECIDE      │                      │
    └──────┬──────┘                      │
           │                             │
    ┌──────▼──────┐                      │
    │   REPORT    │◄─────────────────────┘
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  🧠 LLM    │  Post-Session Reflection
    │  REFLECT    │  → Rút bài học → Lưu Knowledge Store
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │     END     │
    └─────────────┘
```

### 6.2. SharedState v2.0 — Bổ sung

```python
from typing import TypedDict, Optional


class SharedState(TypedDict):
    """SharedState v2.0 — bổ sung knowledge + audit fields."""
    
    # ── META (giữ nguyên) ─────────────────────────────────────
    session_id: str
    target_url: str
    started_at: str
    finished_at: Optional[str]
    config: dict

    # ── AGENT STATUS (giữ nguyên) ────────────────────────────
    agent_statuses: dict
    retry_counts: dict

    # ── AGENT OUTPUTS (giữ nguyên) ───────────────────────────
    tech_stack: dict
    discovered_paths: list
    js_endpoints: list
    waf_detected: bool
    waf_type: Optional[str]
    dev_profile: Optional[dict]
    wordlist: list
    wordlist_metadata: dict
    raw_results: list
    fuzzing_stats: dict
    param_results: list
    verified_results: list
    false_positives: list
    baseline_signature: Optional[dict]

    # ── GUARD RAILS (giữ nguyên) ─────────────────────────────
    llm_call_count: int
    total_http_requests: int
    error_log: list
    circuit_breaker_state: dict
    iteration_count: int

    # ══ MỚI: KNOWLEDGE & AUDIT ══════════════════════════════
    
    # Knowledge context cho quyết định hiện tại
    knowledge_context: Optional[dict]       # Kết quả truy xuất từ Knowledge Store
    
    # Decision chain — toàn bộ quyết định trong phiên này
    decision_chain: list[dict]              # List[DecisionRecord]
    
    # Audit log — bao gồm cả guard rail interventions
    audit_log: list[dict]                   # [{type, timestamp, detail, ...}]
    
    # Lessons learned — bài học rút ra SAU phiên
    session_lessons: list[dict]             # Populated by post-session reflection
    
    # LLM decision count (khác llm_call_count vì agents cũng gọi LLM)
    coordinator_llm_calls: int              # Chỉ đếm LLM calls của Coordinator
```

---

## 7. Pseudo-code triển khai hoàn chỉnh

### 7.1. `src/coordinator/knowledge_store.py` — Knowledge Store

```python
"""
Knowledge Store — Bộ nhớ kiến thức persistent.
Lưu và truy xuất kiến thức từ các phiên chạy trước.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = Path("knowledge_store")


class KnowledgeStore:
    """
    Quản lý kiến thức tích lũy từ các phiên chạy.
    
    Storage: JSON files (có thể upgrade lên SQLite/Vector DB sau).
    """
    
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else KNOWLEDGE_DIR
        self.sessions_dir = self.base_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        
        self.lessons_file = self.base_dir / "lessons_learned.json"
        self.patterns_file = self.base_dir / "decision_patterns.json"
        self.profiles_file = self.base_dir / "tech_stack_profiles.json"
    
    # ── SAVE ──────────────────────────────────────────────────
    
    def save_session(self, session_record: dict):
        """Lưu kết quả một phiên chạy."""
        session_id = session_record["session_id"]
        date = datetime.now().strftime("%Y-%m-%d")
        filename = f"{date}_{session_id[:8]}.json"
        
        filepath = self.sessions_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(session_record, f, ensure_ascii=False, indent=2)
        
        logger.info(f"[Knowledge] Session saved: {filepath}")
    
    def save_lessons(self, new_lessons: list[dict]):
        """Thêm bài học mới vào kho kiến thức."""
        existing = self._load_json(self.lessons_file, {"lessons": []})
        
        for lesson in new_lessons:
            # Kiểm tra trùng lặp
            existing_ids = {l["id"] for l in existing["lessons"]}
            if lesson.get("id") not in existing_ids:
                lesson["id"] = f"L{len(existing['lessons']) + 1:03d}"
                lesson["created_at"] = datetime.now(timezone.utc).isoformat()
                lesson["times_validated"] = 1
                existing["lessons"].append(lesson)
                logger.info(f"[Knowledge] New lesson: {lesson['id']} — {lesson['lesson'][:80]}")
            else:
                # Cập nhật confidence nếu lesson đã tồn tại
                for existing_lesson in existing["lessons"]:
                    if existing_lesson["id"] == lesson["id"]:
                        existing_lesson["times_validated"] += 1
                        existing_lesson["last_validated"] = \
                            datetime.now(timezone.utc).isoformat()
                        # Tăng confidence dần
                        existing_lesson["confidence"] = min(
                            0.99,
                            existing_lesson["confidence"] + 0.05
                        )
        
        self._save_json(self.lessons_file, existing)
    
    def save_decision_pattern(self, pattern: dict):
        """Lưu một decision pattern mới hoặc cập nhật."""
        existing = self._load_json(self.patterns_file, {"patterns": []})
        
        # Tìm pattern tương tự
        matched = False
        for p in existing["patterns"]:
            if p["name"] == pattern["name"]:
                p["times_used"] += 1
                # Cập nhật success rate (running average)
                old_rate = p["success_rate"]
                p["success_rate"] = (
                    old_rate * (p["times_used"] - 1) + 
                    (1.0 if pattern.get("was_successful") else 0.0)
                ) / p["times_used"]
                p["source_sessions"].append(pattern.get("session_id", "unknown"))
                matched = True
                break
        
        if not matched:
            pattern["id"] = f"P{len(existing['patterns']) + 1:03d}"
            pattern["times_used"] = 1
            existing["patterns"].append(pattern)
        
        self._save_json(self.patterns_file, existing)
    
    # ── RETRIEVE ──────────────────────────────────────────────
    
    def retrieve_knowledge(self, context: dict, max_items: int = 5) -> dict:
        """
        Truy xuất kiến thức liên quan cho quyết định hiện tại.
        
        Args:
            context: {tech_stack, waf_type, decision_point, ...}
            max_items: Số lượng items tối đa trả về
            
        Returns:
            KnowledgeContext dict
        """
        knowledge = {
            "similar_sessions": [],
            "relevant_lessons": [],
            "relevant_patterns": [],
            "total_past_sessions": 0,
        }
        
        # 1. Tìm similar sessions
        knowledge["similar_sessions"] = self._find_similar_sessions(
            context, limit=3
        )
        
        # 2. Tìm relevant lessons
        knowledge["relevant_lessons"] = self._find_relevant_lessons(
            context, limit=5
        )
        
        # 3. Tìm applicable patterns
        knowledge["relevant_patterns"] = self._find_applicable_patterns(
            context, limit=3
        )
        
        # 4. Đếm tổng sessions
        knowledge["total_past_sessions"] = len(
            list(self.sessions_dir.glob("*.json"))
        )
        
        return knowledge
    
    def _find_similar_sessions(self, context: dict, limit: int = 3) -> list:
        """Tìm sessions có context tương tự."""
        sessions = []
        
        for session_file in sorted(
            self.sessions_dir.glob("*.json"), reverse=True
        ):
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    session = json.load(f)
                
                score = self._calculate_similarity(context, session.get("context", {}))
                if score > 0.3:  # Ngưỡng tương đồng tối thiểu
                    sessions.append({
                        "session_id": session["session_id"],
                        "similarity_score": score,
                        "tech_stack": session.get("context", {}).get("tech_stack", {}),
                        "waf_type": session.get("context", {}).get("waf_type"),
                        "outcomes": session.get("outcomes", {}),
                        "decisions_summary": [
                            {
                                "point": d["point"],
                                "action": d["action"],
                                "confidence": d.get("confidence", 0),
                            }
                            for d in session.get("decisions", [])
                        ],
                        "lessons": session.get("lessons_learned", []),
                    })
            except (json.JSONDecodeError, KeyError):
                continue
        
        # Sắp xếp theo similarity score
        sessions.sort(key=lambda x: x["similarity_score"], reverse=True)
        return sessions[:limit]
    
    def _calculate_similarity(self, current: dict, past: dict) -> float:
        """
        Tính similarity score giữa context hiện tại và context quá khứ.
        Score: 0.0 (khác hoàn toàn) → 1.0 (giống hoàn toàn)
        """
        score = 0.0
        weights = {
            "backend_match": 0.35,
            "frontend_match": 0.15,
            "waf_match": 0.25,
            "server_match": 0.10,
            "characteristics_overlap": 0.15,
        }
        
        curr_tech = current.get("tech_stack", {})
        past_tech = past.get("tech_stack", {})
        
        # Backend match (quan trọng nhất)
        if curr_tech.get("backend") and \
           curr_tech["backend"] == past_tech.get("backend"):
            score += weights["backend_match"]
        
        # Frontend match
        if curr_tech.get("frontend") and \
           curr_tech["frontend"] == past_tech.get("frontend"):
            score += weights["frontend_match"]
        
        # WAF match
        if current.get("waf_type") and \
           current["waf_type"] == past.get("waf_type"):
            score += weights["waf_match"]
        elif not current.get("waf_detected") and not past.get("waf_detected"):
            score += weights["waf_match"] * 0.5  # Cả hai đều không có WAF
        
        # Server match
        if curr_tech.get("web_server") and \
           curr_tech["web_server"] == past_tech.get("web_server"):
            score += weights["server_match"]
        
        # Characteristics overlap
        curr_chars = set(current.get("target_characteristics", []))
        past_chars = set(past.get("target_characteristics", []))
        if curr_chars and past_chars:
            overlap = len(curr_chars & past_chars) / max(
                len(curr_chars | past_chars), 1
            )
            score += weights["characteristics_overlap"] * overlap
        
        return round(score, 3)
    
    def _find_relevant_lessons(self, context: dict, limit: int = 5) -> list:
        """Tìm bài học áp dụng được cho context hiện tại."""
        data = self._load_json(self.lessons_file, {"lessons": []})
        relevant = []
        
        for lesson in data["lessons"]:
            applicable = lesson.get("applicable_when", {})
            is_match = True
            
            for key, expected in applicable.items():
                # Traverse nested keys (e.g., "tech_stack.backend")
                actual = context
                for part in key.split("."):
                    actual = actual.get(part, {}) if isinstance(actual, dict) else None
                
                if actual is None:
                    is_match = False
                    break
                
                # Kiểm tra match
                if isinstance(expected, list):
                    if actual not in expected:
                        is_match = False
                        break
                elif isinstance(expected, str) and expected.startswith(("<", ">")):
                    # Numeric comparison (e.g., "< 3")
                    op, val = expected.split()
                    try:
                        if op == "<" and not (float(actual) < float(val)):
                            is_match = False
                        elif op == ">" and not (float(actual) > float(val)):
                            is_match = False
                    except (ValueError, TypeError):
                        is_match = False
                else:
                    if str(actual) != str(expected):
                        is_match = False
                        break
            
            if is_match:
                relevant.append(lesson)
        
        # Sắp xếp theo confidence
        relevant.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return relevant[:limit]
    
    def _find_applicable_patterns(self, context: dict, limit: int = 3) -> list:
        """Tìm decision patterns áp dụng được."""
        data = self._load_json(self.patterns_file, {"patterns": []})
        applicable = []
        
        for pattern in data["patterns"]:
            condition = pattern.get("condition", {})
            matches = True
            
            for key, expected in condition.items():
                actual = context
                for part in key.split("."):
                    actual = actual.get(part, {}) if isinstance(actual, dict) else None
                
                if actual is None:
                    matches = False
                    break
                
                if isinstance(expected, bool):
                    if actual != expected:
                        matches = False
                elif isinstance(expected, list):
                    if actual not in expected:
                        matches = False
                elif isinstance(expected, str) and expected.startswith(("<", ">")):
                    op, val = expected.split()
                    try:
                        if op == "<" and not (float(actual) < float(val)):
                            matches = False
                        elif op == ">" and not (float(actual) > float(val)):
                            matches = False
                    except (ValueError, TypeError):
                        matches = False
                else:
                    if str(actual) != str(expected):
                        matches = False
            
            if matches:
                applicable.append(pattern)
        
        applicable.sort(key=lambda x: x.get("success_rate", 0), reverse=True)
        return applicable[:limit]
    
    # ── HELPERS ───────────────────────────────────────────────
    
    def _load_json(self, filepath: Path, default: dict) -> dict:
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        return default
    
    def _save_json(self, filepath: Path, data: dict):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
```

### 7.2. `src/coordinator/decision_engine.py` — LLM Decision Engine

```python
"""
LLM Decision Engine — Bộ máy ra quyết định dựa trên LLM.
Thay thế hoàn toàn logic if/else routing cũ.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate

from .state import SharedState
from .knowledge_store import KnowledgeStore
from .prompts import (
    COORDINATOR_SYSTEM_PROMPT,
    DECISION_PROMPT_TEMPLATE,
    ERROR_DECISION_PROMPT_TEMPLATE,
    POST_SESSION_REFLECTION_PROMPT,
)

logger = logging.getLogger(__name__)


# ── Available actions cho từng decision point ──
AVAILABLE_ACTIONS = {
    "after_validate": [
        {"action": "proceed", "description": "Input hợp lệ, khởi tạo pipeline"},
        {"action": "abort", "description": "Input không hợp lệ, kết thúc"},
    ],
    "after_tech_recon": [
        {"action": "proceed_to_wordlist", "description": "Tiến hành sinh wordlist"},
        {"action": "retry_recon", "description": "Chạy lại recon (có thể với config khác)"},
        {"action": "abort_to_report", "description": "Dừng pipeline, xuất báo cáo partial"},
    ],
    "after_wordlist_gen": [
        {"action": "proceed_to_fuzzing", "description": "Bắt đầu fuzzing với wordlist sinh ra"},
        {"action": "use_fallback_wordlist", "description": "Dùng base wordlist thay thế"},
        {"action": "retry_wordlist", "description": "Sinh lại wordlist với prompt khác"},
        {"action": "abort_to_report", "description": "Dừng pipeline"},
    ],
    "after_fuzzing": [
        {"action": "proceed_to_param", "description": "Tiến hành tìm hidden params"},
        {"action": "skip_to_filter", "description": "Bỏ qua param discovery, nhảy sang filter"},
        {"action": "retry_fuzzing", "description": "Fuzz lại với config khác"},
        {"action": "abort_to_report", "description": "Dừng pipeline"},
    ],
    "after_param_disc": [
        {"action": "proceed_to_filter", "description": "Tiến hành lọc Soft 404"},
        {"action": "abort_to_report", "description": "Dừng pipeline"},
    ],
    "after_soft404_filter": [
        {"action": "generate_report", "description": "Xuất báo cáo cuối cùng"},
        {"action": "re_run_filter", "description": "Chạy lại filter với ngưỡng khác"},
    ],
    "on_error": [
        {"action": "retry", "description": "Chạy lại agent thất bại"},
        {"action": "retry_with_adjustment", "description": "Chạy lại với config điều chỉnh"},
        {"action": "skip", "description": "Bỏ qua agent, tiếp tục pipeline"},
        {"action": "abort_to_report", "description": "Dừng pipeline, xuất báo cáo"},
    ],
}


class DecisionEngine:
    """
    LLM-based Decision Engine cho Coordinator.
    
    Mỗi quyết định:
    1. Thu thập context từ SharedState
    2. Truy xuất knowledge liên quan
    3. Gọi LLM reasoning
    4. Validate decision
    5. Ghi audit log
    """
    
    def __init__(self, llm: ChatOpenAI, knowledge_store: KnowledgeStore):
        self.llm = llm
        self.knowledge = knowledge_store
        
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
    
    def make_decision(
        self,
        state: SharedState,
        decision_point: str,
        completed_agent: str,
        agent_status: str,
        agent_result_summary: str = "",
        execution_time: float = 0.0,
        error_details: str = "",
    ) -> dict:
        """
        Ra quyết định tại một decision point.
        
        Returns:
            DecisionRecord dict
        """
        self._decision_counter += 1
        decision_id = f"D{decision_point.split('_')[-1]}_{self._decision_counter:03d}"
        
        # ── BƯỚC 1: Thu thập context ──
        context = self._build_context(state, completed_agent)
        
        # ── BƯỚC 2: Truy xuất knowledge ──
        knowledge_context = self.knowledge.retrieve_knowledge({
            "tech_stack": state.get("tech_stack", {}),
            "waf_type": state.get("waf_type"),
            "waf_detected": state.get("waf_detected", False),
            "decision_point": decision_point,
            "target_characteristics": self._extract_characteristics(state),
            "http_200_count": len([
                r for r in state.get("raw_results", [])
                if r.get("status_code") == 200
            ]),
        })
        
        # ── BƯỚC 3: LLM Reasoning ──
        available_actions = AVAILABLE_ACTIONS.get(decision_point, [])
        
        if agent_status == "failed":
            prompt = self.error_prompt
            template_vars = self._build_error_prompt_vars(
                state, completed_agent, error_details,
                knowledge_context, available_actions
            )
        else:
            prompt = self.decision_prompt
            template_vars = self._build_decision_prompt_vars(
                state, decision_point, completed_agent,
                agent_status, agent_result_summary,
                execution_time, knowledge_context, available_actions
            )
        
        chain = prompt | self.llm
        raw_response = chain.invoke(template_vars)
        
        # ── BƯỚC 4: Parse & Validate ──
        decision = self._parse_llm_decision(raw_response.content)
        decision = self._validate_decision(decision, decision_point, state)
        
        # ── BƯỚC 5: Build DecisionRecord ──
        decision_record = {
            "decision_id": decision_id,
            "session_id": state.get("session_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision_point": decision_point,
            "trigger": "agent_error" if agent_status == "failed" else "agent_completed",
            "agent_completed": completed_agent,
            "agent_status": agent_status,
            "state_snapshot": self._snapshot_state(state),
            "knowledge_context": {
                "similar_sessions_found": len(
                    knowledge_context.get("similar_sessions", [])
                ),
                "relevant_lessons": knowledge_context.get("relevant_lessons", []),
                "relevant_patterns": knowledge_context.get("relevant_patterns", []),
            },
            "reasoning": decision.get("reasoning", {}),
            "action": decision["action"],
            "confidence": decision.get("confidence", 0.5),
            "is_knowledge_influenced": len(
                decision.get("reasoning", {}).get("knowledge_referenced", [])
            ) > 0,
            "next_agent_config_adjustments": decision.get(
                "next_agent_config_adjustments", {}
            ),
            "new_observation": decision.get("new_observation", ""),
            "outcome": None,  # Filled later
        }
        
        # ── Ghi audit log ──
        state["decision_chain"].append(decision_record)
        state["audit_log"].append({
            "type": "decision",
            "timestamp": decision_record["timestamp"],
            "decision_id": decision_id,
            "action": decision["action"],
            "reasoning_summary": decision.get("reasoning", {}).get("analysis", ""),
            "confidence": decision.get("confidence", 0.5),
        })
        state["coordinator_llm_calls"] += 1
        
        logger.info(
            f"[Decision {decision_id}] {decision_point} → "
            f"action={decision['action']} "
            f"(confidence={decision.get('confidence', '?')})"
        )
        logger.info(
            f"  Reasoning: {decision.get('reasoning', {}).get('analysis', 'N/A')[:200]}"
        )
        
        return decision_record
    
    def reflect_on_session(self, state: SharedState) -> dict:
        """
        Post-session reflection — Rút bài học sau phiên chạy.
        Gọi LLM để phân tích toàn bộ phiên và rút bài học.
        """
        chain = self.reflection_prompt | self.llm
        
        response = chain.invoke({
            "target_url": state["target_url"],
            "tech_stack": json.dumps(state.get("tech_stack", {})),
            "waf_info": f"{'Detected: ' + state['waf_type'] if state.get('waf_detected') else 'None'}",
            "duration": f"{state.get('finished_at', '?')}",
            "agents_list": json.dumps(state.get("agent_statuses", {})),
            "skipped_list": json.dumps([
                k for k, v in state.get("agent_statuses", {}).items()
                if v == "skipped"
            ]),
            "verified_count": len(state.get("verified_results", [])),
            "false_positive_count": len(state.get("false_positives", [])),
            "decision_chain_summary": json.dumps(
                [
                    {
                        "id": d["decision_id"],
                        "point": d["decision_point"],
                        "action": d["action"],
                        "reasoning": d.get("reasoning", {}).get("analysis", ""),
                    }
                    for d in state.get("decision_chain", [])
                ],
                ensure_ascii=False,
            ),
        })
        
        reflection = self._parse_llm_decision(response.content)
        
        # Lưu lessons vào Knowledge Store
        new_lessons = reflection.get("lessons_learned", [])
        if new_lessons:
            self.knowledge.save_lessons(new_lessons)
        
        # Cập nhật decision outcomes
        for eval_item in reflection.get("decision_evaluations", []):
            for decision in state.get("decision_chain", []):
                if decision["decision_id"] == eval_item.get("decision_id"):
                    decision["outcome"] = {
                        "was_correct_decision": eval_item.get("was_correct", True),
                        "retrospective_note": eval_item.get("retrospective_note", ""),
                    }
        
        # Lưu session record vào Knowledge Store
        session_record = self._build_session_record(state, new_lessons)
        self.knowledge.save_session(session_record)
        
        # Ghi audit
        state["audit_log"].append({
            "type": "reflection",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "lessons_count": len(new_lessons),
            "lessons_summary": [l.get("lesson", "") for l in new_lessons],
        })
        
        state["session_lessons"] = new_lessons
        state["coordinator_llm_calls"] += 1
        
        logger.info(f"[Reflection] Rút ra {len(new_lessons)} bài học mới")
        for lesson in new_lessons:
            logger.info(f"  📝 {lesson.get('lesson', '')[:100]}")
        
        return reflection
    
    # ── HELPER METHODS ────────────────────────────────────────
    
    def _build_context(self, state: SharedState, agent: str) -> dict:
        """Xây dựng context cho LLM."""
        return {
            "tech_stack": state.get("tech_stack", {}),
            "waf_detected": state.get("waf_detected", False),
            "waf_type": state.get("waf_type"),
            "discovered_paths_count": len(state.get("discovered_paths", [])),
            "wordlist_size": len(state.get("wordlist", [])),
            "raw_results_count": len(state.get("raw_results", [])),
            "http_200_count": len([
                r for r in state.get("raw_results", [])
                if r.get("status_code") == 200
            ]),
            "param_results_count": len(state.get("param_results", [])),
            "verified_count": len(state.get("verified_results", [])),
            "llm_calls_used": state.get("llm_call_count", 0),
            "errors_count": len(state.get("error_log", [])),
        }
    
    def _snapshot_state(self, state: SharedState) -> dict:
        """Tạo snapshot nhẹ của state cho audit."""
        return {
            "tech_stack": state.get("tech_stack", {}),
            "waf_detected": state.get("waf_detected", False),
            "waf_type": state.get("waf_type"),
            "discovered_paths_count": len(state.get("discovered_paths", [])),
            "wordlist_size": len(state.get("wordlist", [])),
            "raw_results_count": len(state.get("raw_results", [])),
            "http_200_count": len([
                r for r in state.get("raw_results", [])
                if r.get("status_code") == 200
            ]),
            "param_results_count": len(state.get("param_results", [])),
            "verified_results_count": len(state.get("verified_results", [])),
            "llm_calls_used": state.get("llm_call_count", 0),
            "llm_calls_remaining": 50 - state.get("llm_call_count", 0),
            "errors_so_far": len(state.get("error_log", [])),
        }
    
    def _extract_characteristics(self, state: SharedState) -> list:
        """Trích xuất đặc điểm target cho similarity matching."""
        chars = []
        paths = state.get("discovered_paths", [])
        
        if any("/api/" in p for p in paths):
            chars.append("has_api_prefix")
        if any("/admin" in p for p in paths):
            chars.append("has_admin_panel")
        if any("_" in p.split("/")[-1] for p in paths if "/" in p):
            chars.append("uses_snake_case")
        if any("-" in p.split("/")[-1] for p in paths if "/" in p):
            chars.append("uses_kebab_case")
        if state.get("waf_detected"):
            chars.append(f"waf_{state.get('waf_type', 'unknown').lower()}")
        
        return chars
    
    def _build_decision_prompt_vars(self, state, decision_point, completed_agent,
                                     agent_status, result_summary, exec_time,
                                     knowledge, actions) -> dict:
        """Build template variables cho decision prompt."""
        return {
            "completed_agent_name": completed_agent,
            "agent_status": agent_status,
            "agent_result_summary": result_summary,
            "execution_time": exec_time,
            "error_details_if_failed": "",
            "target_url": state.get("target_url", ""),
            "tech_stack_json": json.dumps(state.get("tech_stack", {}), ensure_ascii=False),
            "waf_detected": state.get("waf_detected", False),
            "waf_type": state.get("waf_type", "None"),
            "discovered_paths_count": len(state.get("discovered_paths", [])),
            "wordlist_size": len(state.get("wordlist", [])),
            "raw_results_count": len(state.get("raw_results", [])),
            "http_200_count": len([r for r in state.get("raw_results", []) if r.get("status_code") == 200]),
            "param_results_count": len(state.get("param_results", [])),
            "verified_results_count": len(state.get("verified_results", [])),
            "error_count": len(state.get("error_log", [])),
            "llm_calls_used": state.get("llm_call_count", 0),
            "llm_calls_max": 50,
            "llm_calls_remaining": 50 - state.get("llm_call_count", 0),
            "total_http_requests": state.get("total_http_requests", 0),
            "elapsed_seconds": 0,
            "circuit_breaker_states": json.dumps(state.get("circuit_breaker_state", {})),
            "similar_sessions_summary": json.dumps(
                knowledge.get("similar_sessions", []), ensure_ascii=False
            ),
            "relevant_lessons": json.dumps(
                knowledge.get("relevant_lessons", []), ensure_ascii=False
            ),
            "relevant_patterns": json.dumps(
                knowledge.get("relevant_patterns", []), ensure_ascii=False
            ),
            "available_actions_list": json.dumps(actions, ensure_ascii=False),
        }
    
    def _build_error_prompt_vars(self, state, agent, error, knowledge, actions) -> dict:
        """Build template variables cho error decision prompt."""
        return {
            "failed_agent_name": agent,
            "error_message": error,
            "error_type": "unknown",
            "retry_count": state.get("retry_counts", {}).get(agent, 0),
            "max_retries": 3,
            "next_retry_count": state.get("retry_counts", {}).get(agent, 0) + 1,
            "state_snapshot_at_error": json.dumps(self._snapshot_state(state), ensure_ascii=False),
            "similar_error_knowledge": json.dumps(
                knowledge.get("relevant_lessons", []), ensure_ascii=False
            ),
        }
    
    def _parse_llm_decision(self, raw: str) -> dict:
        """Parse JSON decision từ LLM response."""
        import re
        json_match = re.search(r'\{[\s\S]+\}', raw)
        if not json_match:
            logger.error("[Decision] LLM không trả về JSON hợp lệ — dùng fallback")
            return {
                "action": "abort_to_report",
                "confidence": 0.3,
                "reasoning": {
                    "analysis": "LLM response không parse được — abort để safety",
                    "factors_considered": ["LLM response invalid"],
                    "knowledge_referenced": [],
                    "alternatives_evaluated": [],
                },
            }
        
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError as e:
            logger.error(f"[Decision] JSON parse error: {e}")
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
    
    def _validate_decision(self, decision: dict, point: str, state: SharedState) -> dict:
        """
        Validate quyết định LLM — Guard Rails hardcoded.
        LLM có thể sai, nhưng guard rails không bao giờ sai.
        """
        action = decision.get("action", "")
        available = [a["action"] for a in AVAILABLE_ACTIONS.get(point, [])]
        
        # Check 1: Action phải nằm trong danh sách allowed
        if action not in available:
            logger.warning(
                f"[Guard] LLM chose invalid action '{action}' — "
                f"defaulting to first available"
            )
            decision["action"] = available[0] if available else "abort_to_report"
            state["audit_log"].append({
                "type": "guard_rail_override",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reason": f"Invalid action '{action}' replaced with '{decision['action']}'",
                "original_action": action,
            })
        
        # Check 2: Retry count
        if "retry" in action:
            agent = decision.get("agent_completed", "")
            retries = state.get("retry_counts", {}).get(agent, 0)
            if retries >= 3:
                logger.warning(
                    f"[Guard] LLM wants retry but {agent} "
                    f"already retried {retries} times — forcing abort"
                )
                decision["action"] = "abort_to_report"
                state["audit_log"].append({
                    "type": "guard_rail_override",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": f"Max retries ({retries}) exceeded for {agent}",
                    "original_action": action,
                })
        
        # Check 3: LLM quota
        if state.get("llm_call_count", 0) >= 50:
            if action not in ["abort_to_report", "generate_report", "skip"]:
                logger.warning("[Guard] LLM quota exhausted — forcing report")
                decision["action"] = "abort_to_report"
                state["audit_log"].append({
                    "type": "guard_rail_override",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "reason": "LLM call quota exhausted",
                    "original_action": action,
                })
        
        return decision
    
    def _build_session_record(self, state: SharedState, lessons: list) -> dict:
        """Build session record cho Knowledge Store."""
        return {
            "session_id": state.get("session_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_url": state.get("target_url", ""),
            "context": {
                "tech_stack": state.get("tech_stack", {}),
                "waf_detected": state.get("waf_detected", False),
                "waf_type": state.get("waf_type"),
                "discovered_paths_count": len(state.get("discovered_paths", [])),
                "target_characteristics": self._extract_characteristics(state),
            },
            "decisions": [
                {
                    "point": d["decision_point"],
                    "action": d["action"],
                    "confidence": d.get("confidence", 0),
                    "reasoning": d.get("reasoning", {}).get("analysis", ""),
                }
                for d in state.get("decision_chain", [])
            ],
            "outcomes": {
                "total_verified_results": len(state.get("verified_results", [])),
                "total_false_positives_filtered": len(state.get("false_positives", [])),
                "total_http_requests": state.get("total_http_requests", 0),
                "total_llm_calls": state.get("llm_call_count", 0),
                "agents_executed": [
                    k for k, v in state.get("agent_statuses", {}).items()
                    if v == "success"
                ],
                "agents_skipped": [
                    k for k, v in state.get("agent_statuses", {}).items()
                    if v == "skipped"
                ],
                "errors_encountered": len(state.get("error_log", [])),
            },
            "lessons_learned": lessons,
        }
```

### 7.3. `src/coordinator/graph.py` — LangGraph State Machine v2.0

```python
"""
Coordinator v2.0 — LLM-Driven LangGraph State Machine.
Sử dụng LLM Decision Engine thay cho hardcoded routing.
"""

import json
import uuid
import logging
from datetime import datetime, timezone

from langchain.chat_models import ChatOpenAI
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

# ─── GUARD RAILS (hardcoded safety) ──────────────────────────
circuit_breakers = {
    "tech_recon":   CircuitBreaker(name="tech_recon"),
    "wordlist_gen": CircuitBreaker(name="wordlist_gen"),
    "fuzzing":      CircuitBreaker(name="fuzzing", window_size=200),
    "param_disc":   CircuitBreaker(name="param_disc"),
    "soft404":      CircuitBreaker(name="soft404"),
}
llm_limiter = LLMCallLimiter(max_calls=50)
tarpit_detector = TarpitDetector()

# ─── LLM & KNOWLEDGE ─────────────────────────────────────────
llm = ChatOpenAI(model="gpt-4o", temperature=0.1)
knowledge_store = KnowledgeStore()
decision_engine = DecisionEngine(llm=llm, knowledge_store=knowledge_store)


# ═══════════════════════════════════════════════════════════════
# NODE FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def validate_input(state: SharedState) -> SharedState:
    """Node: Validate URL."""
    url = state.get("target_url", "")
    if not url or not url.startswith(("http://", "https://")):
        state["agent_statuses"]["validate"] = "failed"
        state["audit_log"].append({
            "type": "validation_failed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": f"URL không hợp lệ: '{url}'",
        })
    else:
        state["agent_statuses"]["validate"] = "success"
        state["audit_log"].append({
            "type": "validation_passed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": f"URL hợp lệ: {url}",
        })
    return state


def init_state(state: SharedState) -> SharedState:
    """Node: Khởi tạo SharedState + Knowledge context."""
    state["session_id"] = str(uuid.uuid4())
    state["started_at"] = datetime.now(timezone.utc).isoformat()
    state["agent_statuses"] = {
        "tech_recon": "pending", "wordlist_gen": "pending",
        "fuzzing": "pending", "param_disc": "pending",
        "soft404_filter": "pending",
    }
    state["retry_counts"] = {k: 0 for k in state["agent_statuses"]}
    state["error_log"] = []
    state["decision_chain"] = []
    state["audit_log"] = []
    state["session_lessons"] = []
    state["llm_call_count"] = 0
    state["coordinator_llm_calls"] = 0
    state["total_http_requests"] = 0
    state["iteration_count"] = 0
    state["circuit_breaker_state"] = {k: "closed" for k in circuit_breakers}
    state["knowledge_context"] = None
    
    state["audit_log"].append({
        "type": "session_started",
        "timestamp": state["started_at"],
        "session_id": state["session_id"],
        "target_url": state["target_url"],
    })
    
    logger.info(f"[Coordinator] Session {state['session_id']} initialized")
    return state


def run_tech_recon(state: SharedState) -> SharedState:
    """Node: Agent 1 — Tech Recon."""
    state["agent_statuses"]["tech_recon"] = "running"
    state["audit_log"].append({
        "type": "agent_started", "agent": "tech_recon",
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
        
    except Exception as e:
        state["agent_statuses"]["tech_recon"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "tech_recon", "error": str(e),
        })
        circuit_breakers["tech_recon"].record_failure()
    
    state["audit_log"].append({
        "type": "agent_completed", "agent": "tech_recon",
        "status": state["agent_statuses"]["tech_recon"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def llm_decide_after_recon(state: SharedState) -> SharedState:
    """Node: 🧠 LLM quyết định sau Tech Recon."""
    result_summary = (
        f"Tech stack: {json.dumps(state.get('tech_stack', {}))}. "
        f"Paths found: {len(state.get('discovered_paths', []))}. "
        f"WAF: {state.get('waf_type', 'None')}."
    )
    
    decision = decision_engine.make_decision(
        state=state,
        decision_point="after_tech_recon",
        completed_agent="tech_recon",
        agent_status=state["agent_statuses"]["tech_recon"],
        agent_result_summary=result_summary,
    )
    
    state["_last_decision_action"] = decision["action"]
    return state


def run_wordlist_gen(state: SharedState) -> SharedState:
    """Node: Agent 2 — Wordlist Generator."""
    state["agent_statuses"]["wordlist_gen"] = "running"
    state["audit_log"].append({
        "type": "agent_started", "agent": "wordlist_gen",
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
        
    except Exception as e:
        state["agent_statuses"]["wordlist_gen"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "wordlist_gen", "error": str(e),
        })
        circuit_breakers["wordlist_gen"].record_failure()
    
    state["audit_log"].append({
        "type": "agent_completed", "agent": "wordlist_gen",
        "status": state["agent_statuses"]["wordlist_gen"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def llm_decide_after_wordlist(state: SharedState) -> SharedState:
    """Node: 🧠 LLM quyết định sau Wordlist Generation."""
    result_summary = f"Wordlist size: {len(state.get('wordlist', []))} entries."
    
    decision = decision_engine.make_decision(
        state=state,
        decision_point="after_wordlist_gen",
        completed_agent="wordlist_gen",
        agent_status=state["agent_statuses"]["wordlist_gen"],
        agent_result_summary=result_summary,
    )
    
    state["_last_decision_action"] = decision["action"]
    return state


def run_fuzzing(state: SharedState) -> SharedState:
    """Node: Agent 3 — Fuzzing & WAF Evasion."""
    state["agent_statuses"]["fuzzing"] = "running"
    config_adj = state.get("_config_adjustments", {})
    
    state["audit_log"].append({
        "type": "agent_started", "agent": "fuzzing",
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
        state["total_http_requests"] += result.get("stats", {}).get("total_requests", 0)
        state["agent_statuses"]["fuzzing"] = "success"
        
        avg_time = result.get("stats", {}).get("avg_response_time", 0)
        tarpit_detector.record_response_time(avg_time)
        if tarpit_detector.is_tarpit_detected():
            state["circuit_breaker_state"]["fuzzing"] = "open"
            state["audit_log"].append({
                "type": "tarpit_detected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        
        circuit_breakers["fuzzing"].record_success()
        
    except Exception as e:
        state["agent_statuses"]["fuzzing"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "fuzzing", "error": str(e),
        })
        circuit_breakers["fuzzing"].record_failure()
    
    state["audit_log"].append({
        "type": "agent_completed", "agent": "fuzzing",
        "status": state["agent_statuses"]["fuzzing"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def llm_decide_after_fuzzing(state: SharedState) -> SharedState:
    """Node: 🧠 LLM quyết định sau Fuzzing — bao gồm Agent Skip logic."""
    http_200s = [r for r in state.get("raw_results", []) if r.get("status_code") == 200]
    result_summary = (
        f"Total results: {len(state.get('raw_results', []))}. "
        f"HTTP 200: {len(http_200s)}. "
        f"HTTP requests sent: {state.get('total_http_requests', 0)}."
    )
    
    decision = decision_engine.make_decision(
        state=state,
        decision_point="after_fuzzing",
        completed_agent="fuzzing",
        agent_status=state["agent_statuses"]["fuzzing"],
        agent_result_summary=result_summary,
    )
    
    if decision["action"] == "skip_to_filter":
        state["agent_statuses"]["param_disc"] = "skipped"
    
    state["_last_decision_action"] = decision["action"]
    return state


def run_param_discovery(state: SharedState) -> SharedState:
    """Node: Agent 4 — Parameter Discovery."""
    state["agent_statuses"]["param_disc"] = "running"
    state["audit_log"].append({
        "type": "agent_started", "agent": "param_disc",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    
    try:
        http_200_endpoints = [
            r for r in state.get("raw_results", [])
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
        
    except Exception as e:
        state["agent_statuses"]["param_disc"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "param_disc", "error": str(e),
        })
        circuit_breakers["param_disc"].record_failure()
    
    state["audit_log"].append({
        "type": "agent_completed", "agent": "param_disc",
        "status": state["agent_statuses"]["param_disc"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def run_soft404_filter(state: SharedState) -> SharedState:
    """Node: Agent 5 — Soft 404 Filter."""
    state["agent_statuses"]["soft404_filter"] = "running"
    state["audit_log"].append({
        "type": "agent_started", "agent": "soft404_filter",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    
    try:
        all_results = state.get("raw_results", []) + state.get("param_results", [])
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
        
    except Exception as e:
        state["agent_statuses"]["soft404_filter"] = "failed"
        state["verified_results"] = state.get("raw_results", [])
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "soft404_filter", "error": str(e),
        })
        circuit_breakers["soft404"].record_failure()
    
    state["audit_log"].append({
        "type": "agent_completed", "agent": "soft404_filter",
        "status": state["agent_statuses"]["soft404_filter"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    return state


def generate_report(state: SharedState) -> SharedState:
    """Node: Tổng hợp báo cáo."""
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
    return state


def post_session_reflection(state: SharedState) -> SharedState:
    """Node: 🧠 LLM rút bài học → lưu Knowledge Store."""
    decision_engine.reflect_on_session(state)
    return state


# ═══════════════════════════════════════════════════════════════
# ROUTING FUNCTIONS — Đọc kết quả từ LLM Decision
# ═══════════════════════════════════════════════════════════════

def route_after_validate(state: SharedState) -> str:
    if state.get("agent_statuses", {}).get("validate") == "success":
        return "init_state"
    return "report"


def route_by_llm_decision_recon(state: SharedState) -> str:
    action = state.get("_last_decision_action", "abort_to_report")
    return {"proceed_to_wordlist": "gen_words", "retry_recon": "tech_recon",
            "abort_to_report": "report"}.get(action, "report")


def route_by_llm_decision_wordlist(state: SharedState) -> str:
    action = state.get("_last_decision_action", "abort_to_report")
    return {"proceed_to_fuzzing": "fuzzing", "use_fallback_wordlist": "fuzzing",
            "retry_wordlist": "gen_words", "abort_to_report": "report"
            }.get(action, "report")


def route_by_llm_decision_fuzzing(state: SharedState) -> str:
    action = state.get("_last_decision_action", "abort_to_report")
    return {"proceed_to_param": "param_disc", "skip_to_filter": "filter_404",
            "retry_fuzzing": "fuzzing", "abort_to_report": "report"
            }.get(action, "report")


# ═══════════════════════════════════════════════════════════════
# BUILD GRAPH v2.0
# ═══════════════════════════════════════════════════════════════

def build_coordinator_graph() -> StateGraph:
    """Xây dựng LLM-Driven State Machine."""
    graph = StateGraph(SharedState)
    
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
    graph.add_conditional_edges("validate_input", route_after_validate, {
        "init_state": "init_state",
        "report": "report",
    })
    
    graph.add_edge("init_state", "tech_recon")
    
    graph.add_edge("tech_recon", "llm_decide_recon")
    graph.add_conditional_edges("llm_decide_recon", route_by_llm_decision_recon, {
        "gen_words": "gen_words",
        "tech_recon": "tech_recon",
        "report": "report",
    })
    
    graph.add_edge("gen_words", "llm_decide_wordlist")
    graph.add_conditional_edges("llm_decide_wordlist", route_by_llm_decision_wordlist, {
        "fuzzing": "fuzzing",
        "gen_words": "gen_words",
        "report": "report",
    })
    
    graph.add_edge("fuzzing", "llm_decide_fuzzing")
    graph.add_conditional_edges("llm_decide_fuzzing", route_by_llm_decision_fuzzing, {
        "param_disc": "param_disc",
        "filter_404": "filter_404",
        "fuzzing": "fuzzing",
        "report": "report",
    })
    
    graph.add_edge("param_disc", "filter_404")
    graph.add_edge("filter_404", "report")
    graph.add_edge("report", "reflection")
    graph.add_edge("reflection", END)
    
    return graph.compile()


# ═══════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def run_pipeline(target_url: str, config: dict = None) -> dict:
    """
    Entry point v2.0 — LLM-Driven Pipeline.
    """
    config = config or {}
    
    initial_state: SharedState = {
        "target_url": target_url,
        "config": config,
        "session_id": "", "started_at": "", "finished_at": None,
        "agent_statuses": {}, "retry_counts": {},
        "tech_stack": {}, "discovered_paths": [], "js_endpoints": [],
        "waf_detected": False, "waf_type": None,
        "dev_profile": None, "wordlist": [], "wordlist_metadata": {},
        "raw_results": [], "fuzzing_stats": {},
        "param_results": [],
        "verified_results": [], "false_positives": [],
        "baseline_signature": None,
        "llm_call_count": 0, "coordinator_llm_calls": 0,
        "total_http_requests": 0, "error_log": [],
        "circuit_breaker_state": {}, "iteration_count": 0,
        "knowledge_context": None, "decision_chain": [],
        "audit_log": [], "session_lessons": [],
    }
    
    app = build_coordinator_graph()
    final_state = app.invoke(initial_state)
    
    return final_state
```

---

## 8. Cấu trúc thư mục v2.0

```
src/coordinator/
├── __init__.py              # Export: build_coordinator_graph, run_pipeline
├── state.py                 # SharedState v2.0 (+ knowledge + audit fields)
├── graph.py                 # LangGraph State Machine v2.0 (LLM decision nodes)
├── decision_engine.py       # 🧠 LLM Decision Engine (core mới)
├── knowledge_store.py       # 📚 Knowledge Store (persistent memory)
├── guards.py                # Guard Rails (CircuitBreaker, LLMLimit, Tarpit)
└── prompts.py               # Tất cả prompt templates

knowledge_store/             # Persistent data directory
├── sessions/                # Kết quả từng phiên (.json)
├── lessons_learned.json     # Bài học tổng hợp
├── decision_patterns.json   # Mẫu quyết định
└── tech_stack_profiles.json # Profiles tech stack đã gặp
```

**Quan hệ phụ thuộc:**

```
graph.py
  ├── imports state.py             (SharedState)
  ├── imports guards.py            (CircuitBreaker, ...)
  ├── imports decision_engine.py   (DecisionEngine) ← MỚI
  ├── imports knowledge_store.py   (KnowledgeStore) ← MỚI  
  └── imports agents/*             (5 Agent classes)

decision_engine.py                 ← MỚI
  ├── imports knowledge_store.py
  ├── imports prompts.py
  └── imports langchain (LLM)

knowledge_store.py                 ← MỚI
  └── standalone (JSON I/O)

guards.py
  └── standalone

state.py
  └── standalone

prompts.py                         ← MỚI
  └── standalone (string templates)
```

---

## 9. Ví dụ Audit Log thực tế

Dưới đây là ví dụ audit log cho một phiên chạy hoàn chỉnh:

```json
{
    "session_id": "a1b2c3d4-...",
    "audit_log": [
        {
            "type": "session_started",
            "timestamp": "2026-09-21T10:00:00Z",
            "target_url": "https://target-django.com"
        },
        {
            "type": "validation_passed",
            "timestamp": "2026-09-21T10:00:01Z",
            "detail": "URL hợp lệ"
        },
        {
            "type": "agent_started",
            "agent": "tech_recon",
            "timestamp": "2026-09-21T10:00:02Z"
        },
        {
            "type": "agent_completed",
            "agent": "tech_recon",
            "status": "success",
            "timestamp": "2026-09-21T10:00:45Z"
        },
        {
            "type": "decision",
            "timestamp": "2026-09-21T10:00:46Z",
            "decision_id": "D2_001",
            "action": "proceed_to_wordlist",
            "reasoning_summary": "Recon tìm được 24 paths, tech stack Django+React rõ ràng. Session abc123 cùng setup đã proceed thành công.",
            "confidence": 0.92
        },
        {
            "type": "agent_started",
            "agent": "wordlist_gen",
            "timestamp": "2026-09-21T10:00:47Z"
        },
        {
            "type": "agent_completed",
            "agent": "wordlist_gen",
            "status": "success",
            "timestamp": "2026-09-21T10:02:30Z"
        },
        {
            "type": "decision",
            "timestamp": "2026-09-21T10:02:31Z",
            "decision_id": "D3_001",
            "action": "proceed_to_fuzzing",
            "reasoning_summary": "Wordlist 6,200 entries, chất lượng tốt (bám sát snake_case pattern). Tiến hành fuzzing.",
            "confidence": 0.95
        },
        {
            "type": "agent_started",
            "agent": "fuzzing",
            "timestamp": "2026-09-21T10:02:32Z",
            "config_adjustments": {"jitter": 2.0}
        },
        {
            "type": "agent_completed",
            "agent": "fuzzing",
            "status": "success",
            "timestamp": "2026-09-21T10:08:00Z"
        },
        {
            "type": "decision",
            "timestamp": "2026-09-21T10:08:01Z",
            "decision_id": "D4_001",
            "action": "skip_to_filter",
            "reasoning_summary": "Chỉ có 1 endpoint HTTP 200. Lesson L002 (confidence 0.85): param discovery không hiệu quả khi <3 endpoints. Skip để tiết kiệm ~3 phút.",
            "confidence": 0.88
        },
        {
            "type": "agent_started",
            "agent": "soft404_filter",
            "timestamp": "2026-09-21T10:08:02Z"
        },
        {
            "type": "agent_completed",
            "agent": "soft404_filter",
            "status": "success",
            "timestamp": "2026-09-21T10:09:30Z"
        },
        {
            "type": "report_generated",
            "timestamp": "2026-09-21T10:09:31Z",
            "summary": {
                "verified": 12,
                "filtered": 5,
                "decisions_made": 4
            }
        },
        {
            "type": "reflection",
            "timestamp": "2026-09-21T10:09:45Z",
            "lessons_count": 2,
            "lessons_summary": [
                "Django+Cloudflare targets benefit from jitter >= 2.0s",
                "snake_case Django apps thường có /api/v1/ prefix cố định"
            ]
        }
    ]
}
```

---

## 10. Tổng kết

| Đặc điểm | v1.0 | v2.0 |
|-----------|------|------|
| **Routing** | Hardcoded `if/else` | 🧠 LLM Decision Engine |
| **Knowledge** | Không | 📚 Knowledge Store (persistent) |
| **Reasoning** | Không | Mỗi quyết định có `reasoning` JSON |
| **Audit** | Log cơ bản | Decision Chain + Guard Rail Overrides |
| **Learning** | Không | Post-session reflection → bài học mới |
| **Nodes** | 9 | 12 (+ 3 LLM decision nodes) |
| **Files** | 3 files | 6 files (+ knowledge_store/) |
| **Guard Rails** | Standalone | Guard Rails **override** LLM khi cần |

> **Coordinator v2.0 = LLM Agent thực sự** — Nó *suy nghĩ* trước khi hành động, *học* từ kinh nghiệm, và *giải thích* mọi quyết định.
