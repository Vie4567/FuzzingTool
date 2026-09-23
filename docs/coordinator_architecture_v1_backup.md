# COORDINATOR — Thiết kế Kiến trúc & Flow Chi tiết

> **Module:** `src/coordinator/`  
> **Thuộc dự án:** Sentinel Pentest — Multi-Agent Pentest System  
> **Phiên bản:** 1.0  
> **Cập nhật:** 2026-09-21

---

## 1. Tổng quan

### 1.1. Coordinator là gì?

**Coordinator** là module trung tâm của hệ thống Sentinel Pentest, đóng vai trò **"bộ não điều phối"** — nó không trực tiếp thực hiện quét hay phân tích, mà **quản lý trạng thái, điều hướng luồng dữ liệu, và ra quyết định** cho toàn bộ pipeline.

### 1.2. Trách nhiệm chính

| # | Trách nhiệm | Mô tả |
|---|-------------|-------|
| 1 | **State Management** | Duy trì `SharedState` — nguồn dữ liệu duy nhất xuyên suốt pipeline |
| 2 | **Flow Orchestration** | Quyết định Agent nào chạy tiếp theo dựa trên kết quả trước đó |
| 3 | **Error Handling** | Bắt lỗi từ Agent, quyết định retry hay skip hay abort |
| 4 | **Guard Rails** | Áp dụng các cơ chế bảo vệ: circuit breaker, rate limit, tarpit detection |
| 5 | **Agent Skip** | Bỏ qua Agent không cần thiết khi target đơn giản |
| 6 | **Lifecycle Control** | Quản lý vòng đời từ START → END, đảm bảo pipeline luôn kết thúc |

### 1.3. Vị trí trong kiến trúc tổng thể

```
                    ┌──────────────────────────────────────┐
                    │            USER INPUT                │
                    │         (Target URL + Options)       │
                    └──────────────┬───────────────────────┘
                                   │
                    ╔══════════════▼═══════════════════════╗
                    ║        C O O R D I N A T O R         ║
                    ║                                       ║
                    ║  ┌─────────────────────────────────┐ ║
                    ║  │      LangGraph State Machine     │ ║
                    ║  │   ┌───────┐  ┌───────┐          │ ║
                    ║  │   │Shared │  │Guard  │          │ ║
                    ║  │   │State  │  │Rails  │          │ ║
                    ║  │   └───────┘  └───────┘          │ ║
                    ║  └─────────────────────────────────┘ ║
                    ╚═══╤═══╤═══╤═══╤═══╤═══╤═════════════╝
                        │   │   │   │   │   │
              ┌─────────┘   │   │   │   │   └──────────┐
              ▼             ▼   │   ▼   │              ▼
         ┌─────────┐  ┌────────┐│┌──────┐│       ┌──────────┐
         │ Agent 1 │  │Agent 2 │││Agent4││       │  REPORT  │
         │Tech Rec.│  │Wordlist│││Param ││       │Generator │
         └─────────┘  └────────┘│└──────┘│       └──────────┘
                                ▼        ▼
                          ┌────────┐┌──────────┐
                          │Agent 3 ││ Agent 5  │
                          │Fuzzing ││Soft 404  │
                          └────────┘└──────────┘
```

---

## 2. Kiến trúc State Graph (LangGraph)

### 2.1. State Graph — Sơ đồ trạng thái đầy đủ

Coordinator được xây dựng trên **LangGraph StateGraph** — một máy trạng thái hữu hạn (Finite State Machine) nơi mỗi node là một bước xử lý và các cạnh (edges) là điều kiện chuyển tiếp.

```
                           ┌─────────────┐
                           │    START     │
                           └──────┬──────┘
                                  │
                           ┌──────▼──────┐
                           │ VALIDATE    │  Validate URL, config
                           │ _INPUT      │
                           └──────┬──────┘
                                  │
                        ┌─────────▼─────────┐
                        │ has valid input?   │
                        └──┬──────────────┬─┘
                      yes  │              │ no
                           │       ┌──────▼──────┐
                           │       │ ERROR_EXIT  │
                           │       └─────────────┘
                    ┌──────▼──────┐
                    │ INIT_STATE  │  Khởi tạo SharedState
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ TECH_RECON  │  Agent 1: Fingerprint + DOM + WAF
                    └──────┬──────┘
                           │
                  ┌────────▼────────┐
                  │ route_after_    │  Conditional Edge
                  │ recon()         │
                  └─┬──────────┬───┘
               ok   │          │ fail
                    │    ┌─────▼──────┐
                    │    │ HANDLE_    │  Ghi log, quyết định retry/abort
                    │    │ RECON_ERR  │
                    │    └─────┬──────┘
                    │          │
                    │    ┌─────▼──────┐
                    │    │ can_retry? │
                    │    └──┬─────┬──┘
                    │   yes │     │ no
                    │    ┌──▼──┐  │
                    │    │RETRY│  │
                    │    │RECON│──┘─────┐
                    │    └─────┘        │
                    │                   │
             ┌──────▼──────┐    ┌──────▼──────┐
             │  GEN_WORDS  │    │   REPORT    │
             │  Agent 2    │    │  (partial)  │
             └──────┬──────┘    └──────┬──────┘
                    │                  │
           ┌────────▼────────┐        │
           │ route_after_    │        │
           │ wordlist()      │        │
           └─┬───────────┬──┘        │
          ok │           │ fail      │
             │           └───────────┤
      ┌──────▼──────┐               │
      │   FUZZING   │  Agent 3      │
      └──────┬──────┘               │
             │                      │
    ┌────────▼────────┐             │
    │ route_after_    │             │
    │ fuzzing()       │             │
    └─┬───────────┬──┘             │
   ok │      fail │                │
      │           └────────────────┤
      │                            │
      │    ┌────────────────┐      │
      ├───▶│ should_skip_   │      │
      │    │ param_disc?    │      │
      │    └──┬──────────┬─┘      │
      │  no   │     skip │        │
      │ ┌─────▼──────┐   │        │
      │ │  PARAM_DISC │   │        │
      │ │  Agent 4    │   │        │
      │ └──────┬──────┘   │        │
      │        │          │        │
      │ ┌──────▼──────┐   │        │
      │ │ FILTER_404  │◄──┘        │
      │ │ Agent 5     │            │
      │ └──────┬──────┘            │
      │        │                   │
      │ ┌──────▼──────┐            │
      └▶│   REPORT    │◄───────────┘
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │     END     │
        └─────────────┘
```

### 2.2. Bảng Node — Mô tả từng trạng thái

| Node | Loại | Mô tả | Input | Output |
|------|------|--------|-------|--------|
| `VALIDATE_INPUT` | Guard | Kiểm tra URL hợp lệ, cấu hình đầy đủ | `target_url`, `config` | `is_valid: bool` |
| `INIT_STATE` | Setup | Tạo `SharedState` trống, ghi nhận timestamp bắt đầu | `target_url` | `SharedState` initialized |
| `TECH_RECON` | Agent Node | Gọi Agent 1: HTTP headers, DOM, JS, WAF detection | `target_url` | `tech_stack`, `discovered_paths`, `waf_*` |
| `GEN_WORDS` | Agent Node | Gọi Agent 2: DevProfile analysis + wordlist sinh | `tech_stack`, `discovered_paths` | `wordlist` (5K-7K entries) |
| `FUZZING` | Agent Node | Gọi Agent 3: ffuf + WAF evasion | `wordlist`, `target_url`, `waf_*` | `raw_results` |
| `PARAM_DISC` | Agent Node | Gọi Agent 4: tìm hidden params trên HTTP 200 endpoints | `raw_results` (filtered 200s) | `param_results` |
| `FILTER_404` | Agent Node | Gọi Agent 5: baseline calibration + DOM comparison | `raw_results` + `param_results` | `verified_results` |
| `REPORT` | Output | Tổng hợp, xuất báo cáo HTML/JSON | `SharedState` (full) | Report file |
| `HANDLE_*_ERR` | Error | Xử lý lỗi từ agent tương ứng | `error_log` | Quyết định retry/skip/abort |
| `ERROR_EXIT` | Terminal | Kết thúc sớm do input không hợp lệ | — | Error report |

### 2.3. Bảng Edge — Điều kiện chuyển tiếp

| Từ Node | Đến Node | Điều kiện | Ghi chú |
|---------|----------|-----------|---------|
| `START` | `VALIDATE_INPUT` | Luôn luôn | Entry point |
| `VALIDATE_INPUT` | `INIT_STATE` | URL hợp lệ | — |
| `VALIDATE_INPUT` | `ERROR_EXIT` | URL không hợp lệ | Kết thúc sớm |
| `INIT_STATE` | `TECH_RECON` | Luôn luôn | — |
| `TECH_RECON` | `GEN_WORDS` | `status == "success"` | Happy path |
| `TECH_RECON` | `HANDLE_RECON_ERR` | `status == "error"` | Error handling |
| `HANDLE_RECON_ERR` | `TECH_RECON` | `retry_count < max_retries` | Retry |
| `HANDLE_RECON_ERR` | `REPORT` | `retry_count >= max_retries` | Abort, báo cáo partial |
| `GEN_WORDS` | `FUZZING` | `len(wordlist) > 0` | — |
| `GEN_WORDS` | `REPORT` | `len(wordlist) == 0` hoặc error | Không sinh được wordlist |
| `FUZZING` | `PARAM_DISC` | `should_skip_param == False` | Đủ endpoint HTTP 200 |
| `FUZZING` | `FILTER_404` | `should_skip_param == True` | Skip param discovery |
| `FUZZING` | `REPORT` | Error hoặc circuit break | — |
| `PARAM_DISC` | `FILTER_404` | Luôn luôn | — |
| `FILTER_404` | `REPORT` | Luôn luôn | — |
| `REPORT` | `END` | Luôn luôn | Terminal |

---

## 3. SharedState — Cấu trúc trạng thái chia sẻ

`SharedState` là **Single Source of Truth** — mọi Agent đều đọc/ghi vào đây thông qua Coordinator.

```python
from typing import TypedDict, Optional
from datetime import datetime
from enum import Enum

class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED  = "failed"
    SKIPPED = "skipped"

class SharedState(TypedDict):
    """
    Trạng thái chia sẻ xuyên suốt pipeline.
    Coordinator là thành phần DUY NHẤT có quyền cập nhật trực tiếp.
    Các Agent trả về kết quả → Coordinator merge vào state.
    """

    # ── META ──────────────────────────────────────────────────
    session_id: str                     # UUID phiên làm việc
    target_url: str                     # URL mục tiêu
    started_at: str                     # ISO timestamp bắt đầu
    finished_at: Optional[str]          # ISO timestamp kết thúc
    config: dict                        # User config (threads, rate, ...)

    # ── AGENT STATUS TRACKING ────────────────────────────────
    agent_statuses: dict                # {agent_name: AgentStatus}
    # Ví dụ: {
    #   "tech_recon": "success",
    #   "wordlist_gen": "running",
    #   "fuzzing": "pending",
    #   "param_disc": "pending",
    #   "soft404_filter": "pending"
    # }

    # ── AGENT 1 OUTPUT: Tech Recon ───────────────────────────
    tech_stack: dict                    # {web_server, backend, frontend, ...}
    discovered_paths: list[str]         # Paths tìm từ DOM + JS
    js_endpoints: list[str]             # API endpoints từ JavaScript chunks
    waf_detected: bool                  # Có WAF không?
    waf_type: Optional[str]             # Loại WAF (Cloudflare, AWS, ...)

    # ── AGENT 2 OUTPUT: Wordlist Generator ───────────────────
    dev_profile: Optional[dict]         # DevProfile JSON (8 chiều phân tích)
    wordlist: list[str]                 # Wordlist sinh ra (5K-7K entries)
    wordlist_metadata: dict             # {total, layers_breakdown, ...}

    # ── AGENT 3 OUTPUT: Fuzzing ──────────────────────────────
    raw_results: list[dict]             # Kết quả thô từ ffuf
    # Mỗi entry: {url, status_code, content_length, redirect_to, ...}
    fuzzing_stats: dict                 # {total_requests, blocked_count, ...}

    # ── AGENT 4 OUTPUT: Parameter Discovery ──────────────────
    param_results: list[dict]           # Params ẩn tìm được
    # Mỗi entry: {endpoint, param_name, injection_point, evidence, ...}

    # ── AGENT 5 OUTPUT: Soft 404 Filter ──────────────────────
    verified_results: list[dict]        # Kết quả đã lọc Soft 404
    false_positives: list[dict]         # Các entry bị loại (để review)
    baseline_signature: Optional[dict]  # Baseline calibration data

    # ── GUARD RAILS ──────────────────────────────────────────
    llm_call_count: int                 # Đếm số lần gọi LLM
    total_http_requests: int            # Đếm tổng HTTP requests
    error_log: list[dict]               # [{timestamp, agent, error, ...}]
    retry_counts: dict                  # {agent_name: retry_count}
    circuit_breaker_state: dict         # {agent_name: "closed"|"open"|"half_open"}
    iteration_count: int                # Đếm số vòng lặp tổng
```

### 3.1. Nguyên tắc cập nhật State

```
 ┌──────────────┐                    ┌──────────────┐
 │   Agent N    │── return result ──▶│ Coordinator  │
 │ (Worker)     │                    │ (Orchestrator)│
 └──────────────┘                    └──────┬───────┘
                                            │
                                     merge vào SharedState
                                            │
                                     ┌──────▼───────┐
                                     │ SharedState   │
                                     │ (updated)     │
                                     └──────────────┘
```

**Quy tắc:**
1. Agent **KHÔNG** trực tiếp sửa `SharedState` — chỉ trả về dict kết quả.
2. Coordinator nhận kết quả, **validate**, rồi mới merge vào state.
3. Mỗi lần merge đều kèm **audit log** (ai sửa, sửa gì, lúc nào).

---

## 4. Conditional Routing — Logic điều hướng

### 4.1. Router Functions

Mỗi Agent node có một **router function** phía sau để quyết định đi tiếp hay xử lý lỗi:

```python
def route_after_recon(state: SharedState) -> str:
    """
    Quyết định đi đâu sau Tech Recon.
    
    Returns:
        "gen_words"       — Recon thành công, tiến hành sinh wordlist
        "handle_recon_err" — Recon thất bại, vào error handler
    """
    if state["agent_statuses"]["tech_recon"] == AgentStatus.SUCCESS:
        # Kiểm tra có đủ data để tiếp tục không
        if state["tech_stack"] and len(state["discovered_paths"]) > 0:
            return "gen_words"
        else:
            # Recon thành công nhưng không tìm được gì → vẫn thử sinh wordlist
            return "gen_words"
    else:
        return "handle_recon_err"


def route_after_wordlist(state: SharedState) -> str:
    """
    Quyết định đi đâu sau Wordlist Generation.
    
    Returns:
        "fuzzing"  — Có wordlist, bắt đầu quét
        "report"   — Wordlist rỗng hoặc lỗi, skip sang báo cáo
    """
    if state["agent_statuses"]["wordlist_gen"] == AgentStatus.SUCCESS:
        if len(state.get("wordlist", [])) > 0:
            return "fuzzing"
    
    # Fallback: nếu wordlist rỗng, thử dùng base wordlist
    if _has_fallback_wordlist():
        state["wordlist"] = _load_base_wordlist()
        return "fuzzing"
    
    return "report"


def route_after_fuzzing(state: SharedState) -> str:
    """
    Quyết định đi đâu sau Fuzzing.
    Agent Skip logic nằm ở đây.
    
    Returns:
        "param_disc"   — Có endpoint HTTP 200, tiến hành tìm param ẩn
        "filter_404"   — Skip param discovery, nhảy thẳng sang filter
        "report"       — Circuit break hoặc lỗi nghiêm trọng
    """
    # Kiểm tra circuit breaker
    if state["circuit_breaker_state"].get("fuzzing") == "open":
        return "report"
    
    if state["agent_statuses"]["fuzzing"] != AgentStatus.SUCCESS:
        return "report"
    
    # Agent Skip: bỏ qua param discovery nếu không có endpoint 200
    http_200_results = [
        r for r in state.get("raw_results", [])
        if r.get("status_code") == 200
    ]
    
    if len(http_200_results) == 0:
        state["agent_statuses"]["param_disc"] = AgentStatus.SKIPPED
        return "filter_404"
    
    # Agent Skip: bỏ qua nếu target quá đơn giản (ít kết quả)
    if len(http_200_results) <= 2:
        state["agent_statuses"]["param_disc"] = AgentStatus.SKIPPED
        return "filter_404"
    
    return "param_disc"


def route_after_param(state: SharedState) -> str:
    """Sau param discovery luôn sang Soft 404 filter."""
    return "filter_404"


def route_after_filter(state: SharedState) -> str:
    """Sau filter luôn sang report."""
    return "report"
```

### 4.2. Sơ đồ quyết định tổng hợp (Decision Tree)

```
route_after_recon:
│
├── status == SUCCESS?
│   ├── YES ──► "gen_words"
│   └── NO  ──► "handle_recon_err"
│                 ├── retry_count < 3?
│                 │   ├── YES ──► retry TECH_RECON
│                 │   └── NO  ──► "report" (partial)
│

route_after_wordlist:
│
├── status == SUCCESS && wordlist > 0?
│   ├── YES ──► "fuzzing"
│   └── NO
│       ├── fallback wordlist tồn tại?
│       │   ├── YES ──► load fallback ──► "fuzzing"
│       │   └── NO  ──► "report"
│

route_after_fuzzing:
│
├── circuit breaker == OPEN?
│   ├── YES ──► "report"
│   └── NO
│       ├── status == SUCCESS?
│       │   ├── YES
│       │   │   ├── endpoint HTTP 200 count > 2?
│       │   │   │   ├── YES ──► "param_disc"
│       │   │   │   └── NO  ──► "filter_404" (skip param)
│       │   └── NO ──► "report"
```

---

## 5. Cơ chế bảo vệ (Guard Rails)

### 5.1. Tổng quan Guard Rails

```
┌───────────────────────────────────────────────────────────┐
│                    GUARD RAILS LAYER                      │
│                                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Circuit      │  │ LLM Call     │  │ Tarpit         │  │
│  │ Breaker      │  │ Limiter      │  │ Detector       │  │
│  │              │  │              │  │                │  │
│  │ Error >80%   │  │ Max 50 calls │  │ Timeout >30s   │  │
│  │ in 100 req   │  │ per session  │  │ 5 lần liên tục │  │
│  └──────────────┘  └──────────────┘  └────────────────┘  │
│                                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Agent Skip   │  │ Max          │  │ Timeout        │  │
│  │ Logic        │  │ Iterations   │  │ Per-Agent      │  │
│  │              │  │              │  │                │  │
│  │ Target đơn   │  │ Max 10 vòng  │  │ 5 min / agent  │  │
│  │ giản → skip  │  │ lặp tổng     │  │ trước khi kill │  │
│  └──────────────┘  └──────────────┘  └────────────────┘  │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

### 5.2. Circuit Breaker — Chi tiết

Circuit Breaker theo pattern 3 trạng thái kinh điển:

```
        ┌────────────────────────────────────┐
        │                                    │
        ▼                                    │
   ┌─────────┐   error_rate > 80%    ┌──────┴────┐
   │ CLOSED  │ ─────────────────────▶│   OPEN    │
   │(bình    │                       │(ngắt toàn │
   │ thường) │                       │ bộ request)│
   └─────────┘                       └──────┬────┘
        ▲                                   │
        │                          sau cooldown_period
        │                                   │
        │    success_count > threshold ┌────▼─────┐
        └──────────────────────────────│HALF_OPEN │
                                       │(thử lại  │
                                       │ 1 request)│
                                       └──────────┘
```

```python
from dataclasses import dataclass, field
from collections import deque
import time

@dataclass
class CircuitBreaker:
    """
    Circuit Breaker cho từng Agent.
    Ngắt Agent khi tỷ lệ lỗi quá cao để tránh lãng phí tài nguyên.
    """
    name: str
    failure_threshold: float = 0.80       # 80% error rate
    window_size: int = 100                 # Cửa sổ 100 request gần nhất
    cooldown_seconds: float = 60.0         # 60s trước khi thử lại
    half_open_max_trials: int = 3          # Số request thử khi HALF_OPEN

    state: str = "closed"
    _results: deque = field(default_factory=lambda: deque(maxlen=100))
    _opened_at: float = 0.0
    _half_open_successes: int = 0

    def record_success(self):
        self._results.append(True)
        if self.state == "half_open":
            self._half_open_successes += 1
            if self._half_open_successes >= self.half_open_max_trials:
                self.state = "closed"
                self._half_open_successes = 0

    def record_failure(self):
        self._results.append(False)
        if self.state == "half_open":
            self.state = "open"
            self._opened_at = time.time()
            return
        if self.state == "closed" and len(self._results) >= 10:
            error_rate = self._results.count(False) / len(self._results)
            if error_rate >= self.failure_threshold:
                self.state = "open"
                self._opened_at = time.time()

    def can_proceed(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.time() - self._opened_at >= self.cooldown_seconds:
                self.state = "half_open"
                self._half_open_successes = 0
                return True
            return False
        # half_open
        return True
```

### 5.3. LLM Call Limiter

```python
class LLMCallLimiter:
    """
    Giới hạn tổng số lần gọi LLM trong một phiên.
    Tránh loop vô hạn hoặc chi phí API bất thường.
    """
    def __init__(self, max_calls: int = 50):
        self.max_calls = max_calls
        self.current_calls = 0

    def can_call(self) -> bool:
        return self.current_calls < self.max_calls

    def record_call(self):
        self.current_calls += 1

    def remaining(self) -> int:
        return max(0, self.max_calls - self.current_calls)

    def is_exhausted(self) -> bool:
        return self.current_calls >= self.max_calls
```

### 5.4. Tarpit Detector

```python
class TarpitDetector:
    """
    Phát hiện server cố tình giữ kết nối (tarpit/honeypot).
    Nếu liên tục timeout → dừng quét, cảnh báo người dùng.
    """
    def __init__(self, timeout_threshold: float = 30.0,
                 consecutive_limit: int = 5):
        self.timeout_threshold = timeout_threshold
        self.consecutive_limit = consecutive_limit
        self._consecutive_timeouts = 0

    def record_response_time(self, response_time: float):
        if response_time > self.timeout_threshold:
            self._consecutive_timeouts += 1
        else:
            self._consecutive_timeouts = 0

    def is_tarpit_detected(self) -> bool:
        return self._consecutive_timeouts >= self.consecutive_limit
```

### 5.5. Agent Skip Logic

```python
def should_skip_agent(state: SharedState, agent_name: str) -> bool:
    """
    Quyết định có bỏ qua agent hay không dựa trên context.
    Coordinator gọi hàm này TRƯỚC khi invoke agent.
    """
    if agent_name == "param_disc":
        # Skip nếu không có endpoint HTTP 200
        http_200s = [r for r in state.get("raw_results", [])
                     if r.get("status_code") == 200]
        if len(http_200s) <= 2:
            return True

    if agent_name == "fuzzing":
        # Skip nếu wordlist rỗng (đã fallback thất bại)
        if len(state.get("wordlist", [])) == 0:
            return True

    if agent_name == "soft404_filter":
        # Skip nếu không có raw results
        all_results = state.get("raw_results", []) + \
                      state.get("param_results", [])
        if len(all_results) == 0:
            return True

    return False
```

---

## 6. Flow Sequences — Các luồng thực thi

### 6.1. Happy Path — Luồng bình thường (mọi Agent thành công)

```
 User          Coordinator       Agent1        Agent2        Agent3        Agent4        Agent5
  │                │                │             │             │             │             │
  │── URL ────────▶│                │             │             │             │             │
  │                │── validate ──▶ │             │             │             │             │
  │                │◀── ok ────────│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── init state ─▶│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── invoke ─────▶│             │             │             │             │
  │                │                │── scan ────▶│             │             │             │
  │                │                │  headers    │             │             │             │
  │                │                │  DOM + JS   │             │             │             │
  │                │                │  WAF check  │             │             │             │
  │                │◀── tech_stack ─│             │             │             │             │
  │                │    + paths     │             │             │             │             │
  │                │── merge ──────▶│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── route: ok ──▶│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── invoke ──────────────────▶ │             │             │             │
  │                │                │             │── DevProfile│             │             │
  │                │                │             │── 5 Layers  │             │             │
  │                │                │             │── wordlist  │             │             │
  │                │◀── wordlist ───────────────── │             │             │             │
  │                │── merge ──────▶│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── invoke ─────────────────────────────────▶│             │             │
  │                │                │             │             │── ffuf      │             │
  │                │                │             │             │── WAF evade │             │
  │                │◀── raw_results ────────────────────────────│             │             │
  │                │── merge ──────▶│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── route: has 200s ──────────────────────────────────────▶│             │
  │                │                │             │             │             │── LLM params│
  │                │                │             │             │             │── inject    │
  │                │◀── param_results ──────────────────────────────────────── │             │
  │                │── merge ──────▶│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── invoke ──────────────────────────────────────────────────────────────▶│
  │                │                │             │             │             │             │── baseline
  │                │                │             │             │             │             │── DOM diff
  │                │◀── verified ───────────────────────────────────────────────────────────│
  │                │── merge ──────▶│             │             │             │             │
  │                │                │             │             │             │             │
  │                │── generate report ──────────▶│             │             │             │
  │◀── report ─────│                │             │             │             │             │
  │                │                │             │             │             │             │
```

### 6.2. Error Recovery Flow — Agent thất bại + Retry

```
 Coordinator              Agent 1              Error Handler
     │                       │                      │
     │── invoke Agent 1 ───▶ │                      │
     │                       │── scan target ──▶    │
     │                       │◀── TIMEOUT ──────    │
     │◀── error: timeout ─── │                      │
     │                                              │
     │── route: error ──────────────────────────── ▶│
     │                                              │── retry_count = 1
     │                                              │── can_retry? YES
     │◀── decision: RETRY ─────────────────────────│
     │                                              │
     │── invoke Agent 1 (retry #1) ──▶│            │
     │                                │── scan ──▶ │
     │                                │◀── OK ──── │
     │◀── tech_stack ────────────────│             │
     │── merge & continue ──────────▶              │
     │                                              │
```

### 6.3. WAF Detected Flow — Adaptive Evasion

```
 Coordinator              Agent 1              Agent 3 (Fuzzing)
     │                       │                      │
     │── invoke Agent 1 ───▶ │                      │
     │◀── waf_detected=true  │                      │
     │    waf_type=Cloudflare│                      │
     │                                              │
     │── merge state ──────▶ │                      │
     │   (waf_detected=true) │                      │
     │                                              │
     │   ... Agent 2 wordlist gen ...               │
     │                                              │
     │── invoke Agent 3 ──────────────────────────▶ │
     │   (pass waf_detected=true)                   │
     │   (pass waf_type="Cloudflare")               │
     │                                              │── enable jitter
     │                                              │── enable header rotation
     │                                              │── reduce rate to 10 req/s
     │                                              │── enable method mutation
     │                                              │
     │◀── raw_results (with evasion stats) ────────│
     │                                              │
```

### 6.4. Agent Skip Flow — Target đơn giản

```
 Coordinator                Agent 3              Agent 5
     │                         │                    │
     │── invoke Agent 3 ─────▶ │                    │
     │◀── raw_results ────────│                    │
     │   (chỉ có 1 endpoint    │                    │
     │    HTTP 200)            │                    │
     │                         │                    │
     │── should_skip_param?    │                    │
     │   http_200_count = 1    │                    │
     │   → YES, SKIP Agent 4  │                    │
     │                         │                    │
     │── mark param_disc =     │                    │
     │   SKIPPED              │                    │
     │                         │                    │
     │── invoke Agent 5 ──────────────────────────▶ │
     │◀── verified_results ───────────────────────── │
     │                         │                    │
     │── REPORT ──────────────▶│                    │
     │                         │                    │
```

---

## 7. Pseudo-code triển khai hoàn chỉnh

### 7.1. `src/coordinator/state.py` — SharedState Definition

```python
"""SharedState definition cho Coordinator."""

from typing import TypedDict, Optional, Annotated
from langgraph.graph.message import add_messages

class SharedState(TypedDict):
    # Meta
    session_id: str
    target_url: str
    started_at: str
    finished_at: Optional[str]
    config: dict

    # Agent tracking
    agent_statuses: dict    # {agent_name: "pending"|"success"|"failed"|"skipped"}
    retry_counts: dict      # {agent_name: int}

    # Agent 1 output
    tech_stack: dict
    discovered_paths: list
    js_endpoints: list
    waf_detected: bool
    waf_type: Optional[str]

    # Agent 2 output
    dev_profile: Optional[dict]
    wordlist: list
    wordlist_metadata: dict

    # Agent 3 output
    raw_results: list
    fuzzing_stats: dict

    # Agent 4 output
    param_results: list

    # Agent 5 output
    verified_results: list
    false_positives: list
    baseline_signature: Optional[dict]

    # Guard rails
    llm_call_count: int
    total_http_requests: int
    error_log: list
    circuit_breaker_state: dict
    iteration_count: int
```

### 7.2. `src/coordinator/guards.py` — Guard Rails

```python
"""Guard Rails: Circuit Breaker, LLM Limiter, Tarpit Detector."""

from dataclasses import dataclass, field
from collections import deque
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: float = 0.80
    window_size: int = 100
    cooldown_seconds: float = 60.0
    half_open_max_trials: int = 3

    state: str = "closed"
    _results: deque = field(default_factory=lambda: deque(maxlen=100))
    _opened_at: float = 0.0
    _half_open_successes: int = 0

    def record_success(self):
        self._results.append(True)
        if self.state == "half_open":
            self._half_open_successes += 1
            if self._half_open_successes >= self.half_open_max_trials:
                self.state = "closed"
                logger.info(f"[CB:{self.name}] Circuit CLOSED — recovered")

    def record_failure(self):
        self._results.append(False)
        if self.state == "half_open":
            self.state = "open"
            self._opened_at = time.time()
            logger.warning(f"[CB:{self.name}] HALF_OPEN → OPEN — still failing")
            return
        if self.state == "closed" and len(self._results) >= 10:
            fail_count = sum(1 for r in self._results if not r)
            error_rate = fail_count / len(self._results)
            if error_rate >= self.failure_threshold:
                self.state = "open"
                self._opened_at = time.time()
                logger.error(
                    f"[CB:{self.name}] Circuit OPEN — "
                    f"error rate {error_rate:.0%} >= {self.failure_threshold:.0%}"
                )

    def can_proceed(self) -> bool:
        if self.state == "closed":
            return True
        if self.state == "open":
            elapsed = time.time() - self._opened_at
            if elapsed >= self.cooldown_seconds:
                self.state = "half_open"
                self._half_open_successes = 0
                logger.info(f"[CB:{self.name}] OPEN → HALF_OPEN after {elapsed:.0f}s cooldown")
                return True
            return False
        return True  # half_open


@dataclass
class LLMCallLimiter:
    max_calls: int = 50
    current_calls: int = 0

    def can_call(self) -> bool:
        return self.current_calls < self.max_calls

    def record_call(self):
        self.current_calls += 1
        if self.current_calls >= self.max_calls:
            logger.warning(f"[LLM Limiter] Đã đạt giới hạn {self.max_calls} lần gọi LLM")

    def remaining(self) -> int:
        return max(0, self.max_calls - self.current_calls)


@dataclass
class TarpitDetector:
    timeout_threshold: float = 30.0
    consecutive_limit: int = 5
    _consecutive_timeouts: int = 0

    def record_response_time(self, response_time: float):
        if response_time > self.timeout_threshold:
            self._consecutive_timeouts += 1
            if self._consecutive_timeouts >= self.consecutive_limit:
                logger.critical(
                    f"[Tarpit] {self._consecutive_timeouts} consecutive timeouts "
                    f"(>{self.timeout_threshold}s) — possible tarpit/honeypot!"
                )
        else:
            self._consecutive_timeouts = 0

    def is_tarpit_detected(self) -> bool:
        return self._consecutive_timeouts >= self.consecutive_limit
```

### 7.3. `src/coordinator/graph.py` — LangGraph State Machine

```python
"""
Coordinator — LangGraph State Machine.
Entry point cho toàn bộ pipeline Sentinel Pentest.
"""

import uuid
import logging
from datetime import datetime, timezone

from langgraph.graph import StateGraph, END

from .state import SharedState
from .guards import CircuitBreaker, LLMCallLimiter, TarpitDetector

# Agent imports (sẽ implement riêng)
from ..agents.tech_recon import TechReconAgent
from ..agents.wordlist_gen import WordlistGenAgent
from ..agents.fuzzer import FuzzingAgent
from ..agents.param_discovery import ParamDiscoveryAgent
from ..agents.soft404_filter import Soft404FilterAgent

logger = logging.getLogger(__name__)


# ─── GUARD RAILS (module-level singletons per session) ────────
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
# NODE FUNCTIONS — Mỗi function là một node trong State Graph
# ═══════════════════════════════════════════════════════════════

def validate_input(state: SharedState) -> SharedState:
    """Node: Validate URL và cấu hình đầu vào."""
    url = state.get("target_url", "")
    
    if not url or not url.startswith(("http://", "https://")):
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "coordinator",
            "error": f"URL không hợp lệ: '{url}'",
            "severity": "critical"
        })
        state["agent_statuses"]["validate"] = "failed"
        return state
    
    state["agent_statuses"]["validate"] = "success"
    logger.info(f"[Coordinator] Input validated: {url}")
    return state


def init_state(state: SharedState) -> SharedState:
    """Node: Khởi tạo SharedState với giá trị mặc định."""
    state["session_id"] = str(uuid.uuid4())
    state["started_at"] = datetime.now(timezone.utc).isoformat()
    state["agent_statuses"] = {
        "tech_recon": "pending",
        "wordlist_gen": "pending",
        "fuzzing": "pending",
        "param_disc": "pending",
        "soft404_filter": "pending",
    }
    state["retry_counts"] = {k: 0 for k in state["agent_statuses"]}
    state["error_log"] = []
    state["llm_call_count"] = 0
    state["total_http_requests"] = 0
    state["iteration_count"] = 0
    state["circuit_breaker_state"] = {k: "closed" for k in circuit_breakers}
    
    logger.info(f"[Coordinator] Session initialized: {state['session_id']}")
    return state


def run_tech_recon(state: SharedState) -> SharedState:
    """Node: Thực thi Agent 1 — Tech-Stack Reconnaissance."""
    state["agent_statuses"]["tech_recon"] = "running"
    logger.info("[Coordinator] Invoking Agent 1: Tech Recon...")
    
    try:
        agent = TechReconAgent()
        result = agent.execute(state["target_url"])
        
        # Merge kết quả vào state
        state["tech_stack"] = result.get("tech_stack", {})
        state["discovered_paths"] = result.get("discovered_paths", [])
        state["js_endpoints"] = result.get("js_endpoints", [])
        state["waf_detected"] = result.get("waf_detected", False)
        state["waf_type"] = result.get("waf_type", None)
        state["agent_statuses"]["tech_recon"] = "success"
        
        circuit_breakers["tech_recon"].record_success()
        logger.info(
            f"[Agent 1] Done — tech_stack={state['tech_stack']}, "
            f"paths={len(state['discovered_paths'])}, "
            f"waf={state['waf_type']}"
        )
        
    except Exception as e:
        state["agent_statuses"]["tech_recon"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "tech_recon",
            "error": str(e),
            "retry": state["retry_counts"]["tech_recon"]
        })
        circuit_breakers["tech_recon"].record_failure()
        logger.error(f"[Agent 1] Failed: {e}")
    
    return state


def run_wordlist_gen(state: SharedState) -> SharedState:
    """Node: Thực thi Agent 2 — Dynamic Wordlist Generator."""
    state["agent_statuses"]["wordlist_gen"] = "running"
    logger.info("[Coordinator] Invoking Agent 2: Wordlist Generator...")
    
    try:
        if not llm_limiter.can_call():
            raise RuntimeError("Đã hết quota LLM calls")
        
        agent = WordlistGenAgent()
        result = agent.execute(
            tech_stack=state["tech_stack"],
            discovered_paths=state["discovered_paths"],
            js_endpoints=state.get("js_endpoints", []),
        )
        
        llm_limiter.record_call()  # Count LLM usage
        
        state["dev_profile"] = result.get("dev_profile", None)
        state["wordlist"] = result.get("wordlist", [])
        state["wordlist_metadata"] = result.get("metadata", {})
        state["agent_statuses"]["wordlist_gen"] = "success"
        
        circuit_breakers["wordlist_gen"].record_success()
        logger.info(f"[Agent 2] Done — wordlist size: {len(state['wordlist'])}")
        
    except Exception as e:
        state["agent_statuses"]["wordlist_gen"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "wordlist_gen",
            "error": str(e)
        })
        circuit_breakers["wordlist_gen"].record_failure()
        logger.error(f"[Agent 2] Failed: {e}")
    
    return state


def run_fuzzing(state: SharedState) -> SharedState:
    """Node: Thực thi Agent 3 — Fuzzing & WAF Evasion."""
    state["agent_statuses"]["fuzzing"] = "running"
    logger.info("[Coordinator] Invoking Agent 3: Fuzzing...")
    
    try:
        agent = FuzzingAgent()
        result = agent.execute(
            target_url=state["target_url"],
            wordlist=state["wordlist"],
            waf_detected=state.get("waf_detected", False),
            waf_type=state.get("waf_type", None),
        )
        
        state["raw_results"] = result.get("results", [])
        state["fuzzing_stats"] = result.get("stats", {})
        state["total_http_requests"] += result.get("stats", {}).get(
            "total_requests", 0
        )
        state["agent_statuses"]["fuzzing"] = "success"
        
        # Kiểm tra tarpit
        avg_time = result.get("stats", {}).get("avg_response_time", 0)
        tarpit_detector.record_response_time(avg_time)
        if tarpit_detector.is_tarpit_detected():
            state["error_log"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent": "fuzzing",
                "error": "TARPIT DETECTED — dừng quét",
                "severity": "critical"
            })
            state["circuit_breaker_state"]["fuzzing"] = "open"
        
        circuit_breakers["fuzzing"].record_success()
        logger.info(f"[Agent 3] Done — results: {len(state['raw_results'])}")
        
    except Exception as e:
        state["agent_statuses"]["fuzzing"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "fuzzing",
            "error": str(e)
        })
        circuit_breakers["fuzzing"].record_failure()
        logger.error(f"[Agent 3] Failed: {e}")
    
    return state


def run_param_discovery(state: SharedState) -> SharedState:
    """Node: Thực thi Agent 4 — Parameter Discovery."""
    state["agent_statuses"]["param_disc"] = "running"
    logger.info("[Coordinator] Invoking Agent 4: Parameter Discovery...")
    
    try:
        if not llm_limiter.can_call():
            raise RuntimeError("Đã hết quota LLM calls")
        
        # Chỉ truyền endpoint HTTP 200
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
        
        state["param_results"] = result.get("param_results", [])
        state["agent_statuses"]["param_disc"] = "success"
        
        circuit_breakers["param_disc"].record_success()
        logger.info(f"[Agent 4] Done — params found: {len(state['param_results'])}")
        
    except Exception as e:
        state["agent_statuses"]["param_disc"] = "failed"
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "param_disc",
            "error": str(e)
        })
        circuit_breakers["param_disc"].record_failure()
        logger.error(f"[Agent 4] Failed: {e}")
    
    return state


def run_soft404_filter(state: SharedState) -> SharedState:
    """Node: Thực thi Agent 5 — Soft 404 Filter."""
    state["agent_statuses"]["soft404_filter"] = "running"
    logger.info("[Coordinator] Invoking Agent 5: Soft 404 Filter...")
    
    try:
        # Gộp tất cả kết quả cần filter
        all_results = state.get("raw_results", []) + \
                      state.get("param_results", [])
        
        agent = Soft404FilterAgent()
        result = agent.execute(
            target_url=state["target_url"],
            results_to_verify=all_results,
        )
        
        state["verified_results"] = result.get("verified", [])
        state["false_positives"] = result.get("false_positives", [])
        state["baseline_signature"] = result.get("baseline", None)
        state["agent_statuses"]["soft404_filter"] = "success"
        
        circuit_breakers["soft404"].record_success()
        logger.info(
            f"[Agent 5] Done — verified: {len(state['verified_results'])}, "
            f"filtered out: {len(state['false_positives'])}"
        )
        
    except Exception as e:
        state["agent_statuses"]["soft404_filter"] = "failed"
        # Nếu filter lỗi, giữ nguyên raw results
        state["verified_results"] = state.get("raw_results", [])
        state["error_log"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "soft404_filter",
            "error": str(e)
        })
        circuit_breakers["soft404"].record_failure()
        logger.error(f"[Agent 5] Failed: {e} — keeping raw results as verified")
    
    return state


def generate_report(state: SharedState) -> SharedState:
    """Node: Tổng hợp và xuất báo cáo."""
    state["finished_at"] = datetime.now(timezone.utc).isoformat()
    
    logger.info("=" * 60)
    logger.info("[Coordinator] PIPELINE COMPLETE — Generating Report")
    logger.info(f"  Session:   {state.get('session_id', 'N/A')}")
    logger.info(f"  Target:    {state.get('target_url', 'N/A')}")
    logger.info(f"  Duration:  {state['started_at']} → {state['finished_at']}")
    logger.info(f"  Agents:    {state.get('agent_statuses', {})}")
    logger.info(f"  Results:   {len(state.get('verified_results', []))} verified")
    logger.info(f"  Filtered:  {len(state.get('false_positives', []))} false positives")
    logger.info(f"  Errors:    {len(state.get('error_log', []))}")
    logger.info(f"  LLM calls: {state.get('llm_call_count', 0)}")
    logger.info(f"  HTTP reqs: {state.get('total_http_requests', 0)}")
    logger.info("=" * 60)
    
    return state


def handle_error(state: SharedState) -> SharedState:
    """Node: Xử lý lỗi tổng quát — quyết định retry hay abort."""
    last_error = state["error_log"][-1] if state["error_log"] else None
    if last_error:
        agent_name = last_error.get("agent", "unknown")
        state["retry_counts"][agent_name] = \
            state["retry_counts"].get(agent_name, 0) + 1
        logger.warning(
            f"[Error Handler] {agent_name} failed "
            f"(retry #{state['retry_counts'][agent_name]})"
        )
    return state


# ═══════════════════════════════════════════════════════════════
# ROUTING FUNCTIONS — Conditional Edges
# ═══════════════════════════════════════════════════════════════

MAX_RETRIES = 3

def route_after_validate(state: SharedState) -> str:
    if state.get("agent_statuses", {}).get("validate") == "success":
        return "init_state"
    return "error_exit"


def route_after_recon(state: SharedState) -> str:
    if state["agent_statuses"]["tech_recon"] == "success":
        return "gen_words"
    return "handle_error"


def route_after_error(state: SharedState) -> str:
    """Quyết định retry hay abort sau khi xử lý lỗi."""
    last_error = state["error_log"][-1] if state["error_log"] else {}
    agent_name = last_error.get("agent", "")
    retries = state["retry_counts"].get(agent_name, 0)
    
    if retries < MAX_RETRIES:
        # Retry agent tương ứng
        route_map = {
            "tech_recon": "tech_recon",
            "wordlist_gen": "gen_words",
            "fuzzing": "fuzzing",
        }
        if agent_name in route_map:
            logger.info(f"[Error Handler] Retrying {agent_name} (#{retries+1})")
            return route_map[agent_name]
    
    # Hết retry → sang report
    logger.warning(f"[Error Handler] {agent_name} exhausted retries — going to report")
    return "report"


def route_after_wordlist(state: SharedState) -> str:
    if state["agent_statuses"]["wordlist_gen"] == "success":
        if len(state.get("wordlist", [])) > 0:
            return "fuzzing"
    return "report"


def route_after_fuzzing(state: SharedState) -> str:
    if state.get("circuit_breaker_state", {}).get("fuzzing") == "open":
        return "report"
    
    if state["agent_statuses"]["fuzzing"] != "success":
        return "handle_error"
    
    # Agent Skip logic
    http_200s = [r for r in state.get("raw_results", [])
                 if r.get("status_code") == 200]
    
    if len(http_200s) <= 2:
        state["agent_statuses"]["param_disc"] = "skipped"
        return "filter_404"
    
    return "param_disc"


def route_after_param(state: SharedState) -> str:
    return "filter_404"


def route_after_filter(state: SharedState) -> str:
    return "report"


# ═══════════════════════════════════════════════════════════════
# BUILD GRAPH — Lắp ráp State Machine
# ═══════════════════════════════════════════════════════════════

def build_coordinator_graph() -> StateGraph:
    """
    Xây dựng LangGraph State Machine cho Coordinator.
    Trả về compiled graph sẵn sàng invoke.
    """
    graph = StateGraph(SharedState)
    
    # ── Thêm Nodes ──
    graph.add_node("validate_input", validate_input)
    graph.add_node("init_state",     init_state)
    graph.add_node("tech_recon",     run_tech_recon)
    graph.add_node("gen_words",      run_wordlist_gen)
    graph.add_node("fuzzing",        run_fuzzing)
    graph.add_node("param_disc",     run_param_discovery)
    graph.add_node("filter_404",     run_soft404_filter)
    graph.add_node("report",         generate_report)
    graph.add_node("handle_error",   handle_error)
    
    # ── Entry Point ──
    graph.set_entry_point("validate_input")
    
    # ── Conditional Edges ──
    graph.add_conditional_edges("validate_input", route_after_validate, {
        "init_state": "init_state",
        "error_exit": "report",    # Báo cáo lỗi và kết thúc
    })
    
    graph.add_edge("init_state", "tech_recon")
    
    graph.add_conditional_edges("tech_recon", route_after_recon, {
        "gen_words":    "gen_words",
        "handle_error": "handle_error",
    })
    
    graph.add_conditional_edges("handle_error", route_after_error, {
        "tech_recon": "tech_recon",
        "gen_words":  "gen_words",
        "fuzzing":    "fuzzing",
        "report":     "report",
    })
    
    graph.add_conditional_edges("gen_words", route_after_wordlist, {
        "fuzzing": "fuzzing",
        "report":  "report",
    })
    
    graph.add_conditional_edges("fuzzing", route_after_fuzzing, {
        "param_disc":   "param_disc",
        "filter_404":   "filter_404",
        "handle_error": "handle_error",
        "report":       "report",
    })
    
    graph.add_conditional_edges("param_disc", route_after_param, {
        "filter_404": "filter_404",
    })
    
    graph.add_conditional_edges("filter_404", route_after_filter, {
        "report": "report",
    })
    
    graph.add_edge("report", END)
    
    # ── Compile ──
    return graph.compile()


# ═══════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def run_pipeline(target_url: str, config: dict = None) -> dict:
    """
    Entry point chính — chạy toàn bộ pipeline Sentinel Pentest.
    
    Args:
        target_url: URL mục tiêu cần quét
        config: Cấu hình tùy chọn (threads, rate, max_llm_calls, ...)
    
    Returns:
        SharedState cuối cùng chứa toàn bộ kết quả
    """
    config = config or {}
    
    initial_state: SharedState = {
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
        "total_http_requests": 0,
        "error_log": [],
        "circuit_breaker_state": {},
        "iteration_count": 0,
    }
    
    # Build & run
    app = build_coordinator_graph()
    final_state = app.invoke(initial_state)
    
    return final_state
```

---

## 8. File Structure — Cấu trúc thư mục Coordinator

```
src/coordinator/
├── __init__.py          # Export: build_coordinator_graph, run_pipeline
├── state.py             # SharedState TypedDict definition
├── graph.py             # LangGraph State Machine + node functions + routing
└── guards.py            # CircuitBreaker, LLMCallLimiter, TarpitDetector
```

**Quan hệ phụ thuộc:**

```
graph.py
  ├── imports state.py       (SharedState)
  ├── imports guards.py      (CircuitBreaker, LLMCallLimiter, TarpitDetector)
  └── imports agents/*       (5 Agent classes)

guards.py
  └── standalone (no internal deps)

state.py
  └── standalone (no internal deps)
```

---

## 9. Cách sử dụng

### 9.1. Sử dụng cơ bản

```python
from src.coordinator.graph import run_pipeline

# Chạy pipeline
result = run_pipeline(
    target_url="https://example.com",
    config={
        "threads": 10,
        "rate": 50,
        "max_llm_calls": 50,
    }
)

# Truy cập kết quả
print(f"Session: {result['session_id']}")
print(f"Verified endpoints: {len(result['verified_results'])}")
print(f"Agent statuses: {result['agent_statuses']}")

for endpoint in result["verified_results"]:
    print(f"  [{endpoint['status_code']}] {endpoint['url']}")
```

### 9.2. Sử dụng nâng cao (custom graph)

```python
from src.coordinator.graph import build_coordinator_graph

# Build graph tùy chỉnh
app = build_coordinator_graph()

# Xem graph visualization
print(app.get_graph().draw_ascii())

# Chạy với streaming (theo dõi từng bước)
for step in app.stream(initial_state):
    node_name = list(step.keys())[0]
    print(f"[Step] {node_name} completed")
```

---

## 10. Tổng kết

| Đặc điểm | Giá trị |
|-----------|---------|
| **Pattern** | LangGraph StateGraph (Finite State Machine) |
| **Nodes** | 9 nodes (validate, init, 5 agents, report, error_handler) |
| **Edges** | 6 conditional edges + 3 direct edges |
| **Guard Rails** | Circuit Breaker, LLM Limiter, Tarpit Detector, Agent Skip |
| **Error Strategy** | Retry (max 3) → Partial Report → END |
| **State** | Single SharedState (TypedDict) — Single Source of Truth |
| **Agent Communication** | Coordinator-mediated (agents không nói chuyện trực tiếp) |

> **Coordinator = "Bộ não" điều phối** — Nó không quét, không phân tích, không sinh wordlist. Nó chỉ **quyết định ai làm gì, khi nào, và xử lý khi mọi thứ sai.**
