"""
Prompt Templates — Tất cả prompt dành cho Coordinator LLM Decision Engine.

4 prompt templates:
    - COORDINATOR_SYSTEM_PROMPT: Vai trò, quy tắc, output format
    - DECISION_PROMPT_TEMPLATE: Decision Point (D1-D5)
    - ERROR_DECISION_PROMPT_TEMPLATE: Khi Agent thất bại
    - POST_SESSION_REFLECTION_PROMPT: Rút bài học cuối phiên
"""

# ═══════════════════════════════════════════════════════════════
# SYSTEM PROMPT — Vai trò Coordinator
# ═══════════════════════════════════════════════════════════════

COORDINATOR_SYSTEM_PROMPT = """Bạn là Coordinator — bộ não điều phối của hệ thống Sentinel Pentest.

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
Trả lời CHÍNH XÁC theo JSON schema được yêu cầu. KHÔNG thêm text ngoài JSON."""


# ═══════════════════════════════════════════════════════════════
# DECISION PROMPT — Gọi tại mỗi điểm quyết định
# ═══════════════════════════════════════════════════════════════

DECISION_PROMPT_TEMPLATE = """## TRẠNG THÁI HIỆN TẠI

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
{{
    "action": "<tên hành động>",
    "confidence": <0.0 - 1.0>,
    "reasoning": {{
        "analysis": "<phân tích tình huống hiện tại, 2-4 câu>",
        "factors_considered": ["<yếu tố 1>", "<yếu tố 2>"],
        "knowledge_referenced": ["<lesson/pattern ID nếu có>"],
        "alternatives_evaluated": [
            {{
                "action": "<hành động thay thế>",
                "pros": "<ưu điểm>",
                "cons": "<nhược điểm>",
                "verdict": "REJECTED — <lý do ngắn>"
            }}
        ]
    }},
    "next_agent_config_adjustments": {{
        "<config_key>": "<new_value nếu cần điều chỉnh>"
    }},
    "new_observation": "<quan sát mới rút ra từ quyết định này, nếu có>"
}}
```"""


# ═══════════════════════════════════════════════════════════════
# ERROR DECISION PROMPT — Khi Agent thất bại
# ═══════════════════════════════════════════════════════════════

ERROR_DECISION_PROMPT_TEMPLATE = """⚠️ AGENT THẤT BẠI — CẦN QUYẾT ĐỊNH

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

Trả về JSON theo format:
```json
{{
    "action": "<tên hành động>",
    "confidence": <0.0 - 1.0>,
    "reasoning": {{
        "analysis": "<phân tích tình huống hiện tại, 2-4 câu>",
        "factors_considered": ["<yếu tố 1>", "<yếu tố 2>"],
        "knowledge_referenced": ["<lesson/pattern ID nếu có>"],
        "alternatives_evaluated": [
            {{
                "action": "<hành động thay thế>",
                "pros": "<ưu điểm>",
                "cons": "<nhược điểm>",
                "verdict": "REJECTED — <lý do ngắn>"
            }}
        ]
    }},
    "next_agent_config_adjustments": {{
        "<config_key>": "<new_value nếu cần điều chỉnh>"
    }},
    "new_observation": "<quan sát mới rút ra>"
}}
```"""


# ═══════════════════════════════════════════════════════════════
# POST-SESSION REFLECTION PROMPT — Rút bài học sau phiên
# ═══════════════════════════════════════════════════════════════

POST_SESSION_REFLECTION_PROMPT = """Phiên quét vừa hoàn thành. Hãy rút ra bài học.

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
{{
    "lessons_learned": [
        {{
            "lesson": "<bài học rút ra>",
            "evidence": "<bằng chứng từ phiên này>",
            "applicable_when": {{
                "<condition_key>": "<condition_value>"
            }},
            "confidence": <0.0-1.0>
        }}
    ],
    "decision_evaluations": [
        {{
            "decision_id": "<ID quyết định>",
            "was_correct": true,
            "retrospective_note": "<nhận xét hồi tưởng>"
        }}
    ],
    "recommendations_for_future": [
        "<đề xuất cho lần chạy sau>"
    ]
}}
```"""
