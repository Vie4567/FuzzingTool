# Coordinator MVP correctness — 2026-11-07 / 2026-11-08

Scope: preserve architecture, agent order, auth/scope/TLS, budgets and supervisor.
No public target or provider API calls; use local HTTP fixtures and offline LLM.
Existing uncommitted changes precede this task. Do not stage/delete them blindly.

## Baseline

Command: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v`

375 tests PASS, 98.600 seconds. Log:
`output_samples/diagnostics/coordinator_mvp_20261107/tests_before.log`.

## Task 1 — HTTP errors into Coordinator

Cause: `run_fuzzing` only added thrown exceptions to `error_log`; returned
per-request errors were omitted and success flags were trusted.

Changes: `graph._sync_fuzzing_errors` creates bounded, typed summaries with
count/timestamp/source/attempt. Reprocessing an attempt is idempotent; retries
retain their own counts. Messages are canonical and contain no URL/token/error
payload. Raw measurements/errors remain in the execution result and checkpoints.
`graph.run_fuzzing` and `FuzzingAgent.execute` reject success with returned errors.
HTTP error responses alone are not transport errors. Fuzzing exceptions use
sanitized messages and preserve prior measurements.

Tests: `tests/test_pipeline_failure_integration.py` covers 11 timeouts,
checkpoint equality, telemetry, secret redaction, retry aggregation and HTTP
403/404 response distinction. First targeted run: 9 PASS (4.203s), command:
`python -B -m unittest discover -s tests -p test_pipeline_failure_integration.py -v`.
`tests/test_fuzzing_integration.py` also checks inconsistent success flags do not
trigger justification calls and a failed LLM explanation preserves HTTP data:
13 PASS (0.970s). The existing explanation is attempted once, never retried here.
CLI aggregate errors carry their reported count; they are not collapsed to one
network failure. Engine/output errors and LLM explanation errors are distinct.

Cost: one linear summary per execution, bounded by error categories per retry;
no extra HTTP/LLM calls or retries. Complete individual errors remain in artifacts.

## Task 2 — Trạng thái thực thi HTTP

Nguyên nhân: engine chỉ kiểm tra đã duyệt hết URL, không kiểm tra lỗi đo;
exception do budget từ chối dispatch lại bị ghi như một request lỗi mạng.

File/hàm: `src/tools/http_fuzzing.py::run_http_fuzzing` (hàm con `measure` và
phần tổng kết); `src/tools/ffuf_helper.py::run`, `_run_cli`;
`src/agents/fuzzer.py::execute`; `src/coordinator/graph.py::run_fuzzing`.

Đã sửa:

- Toàn bộ request lỗi: `success=false`, `completed=false`, `partial=true`,
  `stop_reason=transport_error`; không dùng `completed` để chỉ "đã duyệt hết".
- Có response và lỗi: `partial_transport_error`, giữ tất cả phép đo đã có.
- HTTP 404 vẫn là response hợp lệ ở tầng transport, không phải endpoint đã verify.
- Giữ stop reason do budget, deadline, HTTP 429/403/407 và CONNECT.
- Reservation bị từ chối trước dispatch không tăng engine count hoặc telemetry.
  Thời gian chờ rate limit toàn pipeline không cộng vào response time.
- `remaining_requests` đếm ứng viên chưa thử; `stopped_early` của native thể hiện
  ứng viên còn lại, độc lập với việc kết quả có lỗi hay không.
- ffuf CLI giữ attempted/remaining/exact total responses là unknown/null. Số
  response trong JSON là lower bound có nhãn, không suy từ độ dài wordlist.
  Lỗi ffuf có type/count/source; khi dừng vì lỗi có stop reason cụ thể.

Test thêm trong `test_http_fuzzing.py`: 10 timeout; 8 response + 2 timeout;
10 HTTP404; budget từ chối trước dispatch; deadline/rate-wait; bảo toàn lý do dừng.
`test_ffuf_helper.py` kiểm tra native partial và các bộ đếm CLI unknown.

Lệnh chạy từng file:
`python -B -m unittest discover -s tests -p test_http_fuzzing.py -v`
và tương tự `-p test_ffuf_helper.py`.
Tại mốc Task 2: **23 HTTP tests + 19 helper tests PASS**. Log:
`output_samples/diagnostics/coordinator_mvp_task2_http.log` và
`output_samples/diagnostics/coordinator_mvp_task2_ffuf.log`.

Hiệu năng: tính summary một lần cuối execution, không retry/HTTP/LLM bổ sung;
giữ sequential worker, rate và global budget. Giới hạn: ffuf không cung cấp
attempted count chính xác, không biến unknown thành zero hoặc số tự đoán.

## Task 3 — Root và path normalization

Nguyên nhân: `lstrip('/')` biến `/` thành rỗng rồi loại bỏ. Khi sửa root,
`urlunsplit` còn tự thêm `/` trước FUZZ, gây URL `//` nếu input đã có slash.

File/hàm: `ffuf_helper._normalize_wordlist`, `_path_mode`, `_build_cli_command`,
`_run_cli`; `http_fuzzing._prepare_urls`; `validation.validate_wordlist`;
`graph.run_wordlist_gen`.

Đã giữ `/`, gộp `/admin` và `admin` trước selection limit, kiểm tra URL ngoài
origin/controls/fragments trước khi bỏ slash. Native giữ root đúng một lần;
ffuf ghi slash-prefixed inputs và dựng template tương ứng để không tạo `//`.
Root tương đối với base path đã cấu hình: target `/base` + root cho `/base/`.
Không thay đổi phép thay thế FUZZ trong query/body/header.

Kiểm thử thật cả native và ffuf trên localhost, gồm origin và `/base`, kiểm tra
cả log server và URL trong kết quả. Tests: `test_http_fuzzing.py`,
`test_ffuf_helper.py`, `test_coordinator_limits.py`.

Lệnh: `python -B -m unittest discover -s tests -p <tên_file> -v`.
Mốc Task 3: **24 HTTP + 21 helper + 10 limits tests PASS**. Log
`task3_http_tests.log`, `task3_ffuf_tests.log`, `task3_selection_tests.log` trong
thư mục `output_samples/diagnostics/coordinator_mvp_20261107/`.

Hiệu năng: không thêm giai đoạn quét; root đã chọn nay được gửi đúng một lần,
path trùng không bị gửi lặp. Không có request ngoài origin. Không còn vấn đề
chưa giải quyết trong acceptance criteria của task này.

## Task 4 — Thống kê, context và reflection

Nguyên nhân: prompt dùng wordlist size/returned rows mà thiếu các giai đoạn
generation/selection/dispatch; reflection tin trực tiếp nhận định của LLM.

File/hàm: `state.lifecycle_summary`, `error_count`;
`decision_engine._build_decision_prompt_vars`, `_build_error_prompt_vars`,
`_snapshot_state`, `reflect_on_session`, `_build_session_record`,
`_observed_facts`, `_verified_observations`, `_bounded_json`;
`prompts.py`; `graph.run_wordlist_gen`, `llm_decide_after_wordlist`,
`llm_decide_after_fuzzing`.

Summary lấy dữ liệu từ metadata/stats hiện có, không tạo bản sao bộ đếm trong
SharedState. Phân biệt `generated_count`, `selected_count`, `planned_requests`,
`attempted_requests`, `responses_received`, `network_errors`, `remaining_requests`.
Healthcheck và CONNECT có phạm vi/counter riêng. HTTP response tính khi nhận
headers; lỗi đọc body có thể đồng thời có status và lỗi, không áp đặt công thức
attempted = responses + errors. CLI lower bound được ghi rõ, exact count vẫn null.

Prompt giải thích chênh lệch generated/selected/attempted không phải bằng chứng
SharedState hỏng, HTTP200 không phải endpoint được verify. Không gửi raw HTTP
results; phần knowledge tối đa 100 node và 4.000 ký tự mỗi trường. Reflection
chỉ gửi 20 decision gần nhất, reasoning 300 ký tự; history trên đĩa vẫn đầy đủ.
Error prompt cũng bị giới hạn và che credentials trước khi cắt ngắn.

Bài học chỉ được lưu khi evidence `{fact, value}` thuộc allowlist và khớp đúng
kiểu/giá trị đo được. Nội dung lưu là quan sát chuẩn hóa cho phiên đó; không lưu
nguyên nhân, ID, confidence hay phạm vi áp dụng do LLM tự khẳng định. Evidence
thiếu/sai định dạng bị bỏ qua; session record và decision history vẫn lưu.
Đánh giá đúng/sai của decision từ LLM giữ nhãn chưa xác minh, không mặc định true.

Tests mới: `tests/test_coordinator_observations.py` kiểm tra 1950/12/11/0/11,
unknown CLI, error count, evidence sai/đúng, chống tăng confidence bằng ID cũ,
giới hạn prompt kể cả dict lồng rộng và bảo toàn history.
Lệnh: `python -B -m unittest discover -s tests -p test_coordinator_observations.py -v`.
Mốc đã đo: **11 PASS (0.118s)**; test error prompt bổ sung nằm trong regression cuối.

Hiệu năng: **0 HTTP / 0 LLM bổ sung** để tính summary hoặc kiểm chứng reflection.
Tests reflection xác nhận chỉ một call đã có và zero HTTP. Giới hạn: chỉ lưu
quan sát có căn cứ, không suy ra bài học nhân quả tổng quát; dữ liệu knowledge cũ
không bị xóa hay tự động coi là đã được kiểm chứng lại.

## Task 5 — Regression và lab độc lập

Trước thay đổi: **375 PASS / 98.600s**. Lượt hồi quy đầu sau thay đổi:
**405 PASS / 103.601s**, `tests_after.log`.
Lượt cuối trên source sau sửa: **408/408 PASS, 107.879s**, log
`output_samples/diagnostics/coordinator_mvp_20261107/tests_mvp_final.log`.
Tổng cộng thêm **33 test**. `git diff --check -- src tests scripts docs` PASS
(Git chỉ cảnh báo chuyển LF/CRLF). Thời gian suite trước/sau không phải benchmark
hiệu năng scan vì số test đã tăng. Không kết luận chỉ từ unit tests.

| File test liên quan trực tiếp | Số test trong lượt cuối | Kết quả |
|---|---:|---|
| test_pipeline_failure_integration.py | 10 | PASS |
| test_fuzzing_integration.py | 14 | PASS |
| test_http_fuzzing.py | 24 | PASS |
| test_ffuf_helper.py | 22 | PASS |
| test_coordinator_limits.py | 10 | PASS |
| test_coordinator_observations.py | 12 | PASS |

Các test hiện hữu về timeout LLM, telemetry/quota, supervisor, checkpoints,
scope/auth/TLS và CONNECT/proxy vẫn nằm trong 408 test PASS. Full-suite command:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTHON_DOTENV_DISABLED='1'
$env:LANGSMITH_TRACING='false'
$env:LANGCHAIN_TRACING_V2='false'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Lab script mới `scripts/run_coordinator_mvp_lab.py` chỉ thay model bằng
BaseChatModel fixture. Cả 5 agent, HTTP tools, LangGraph, verifiers, runtime và
artifact writer chạy thật. Socket guard chặn kết nối bên ngoài; cho phép socketpair
loopback nội bộ mà Windows asyncio cần dùng. Mỗi scenario có global budget120,
LLM budget60, retry0. Kết quả riêng, không ghi đè artifacts phiên cũ.

Bằng chứng cuối đã PASS: `output_samples/diagnostics/coordinator_mvp_lab_20261108_final/evidence.json`
và `report.md` cùng thư mục. `source_manifest.json` ghi hash source lúc chạy lab.

| Scenario | Trạng thái | HTTP thật toàn pipeline | Call model fixture |
|---|---|---:|---:|
| Completed | 5/5 module success, xác minh page, lọc fallback | 94 | 30 |
| Partial budget | Root404 một lần, attempted1/remaining2, max_requests | 28 | 22 |
| All timeouts | Fuzzing failed, pipeline partial, 11 errors, count11 | 38 | 22 |
| Tổng lượt kiểm chứng | Các assertion PASS | 160 | 74 |

Mỗi scenario lưu `server_requests.json`, `model_calls.json`, `result.json`,
`evidence.json` và checkpoint của Coordinator. Counter khớp log độc lập; kết quả
trả về khớp JSON đã lưu. Không gọi provider LLM hay website ngoài localhost.
Lượt debug trước đó: 80 HTTP + 68 model fixture; lượt verified ngày 07/11:
160 HTTP + 74 model fixture. Cộng cả ba lượt lab đã chạy: **400 HTTP localhost,
216 model fixture, 0 provider call**. Lượt debug được giữ nguyên và không dùng
để tuyên bố PASS. Regression có traffic fixture riêng, không cộng đoán vào tổng lab.
Sau lab cuối bổ sung che credentials ở log exception FuzzingAgent; test regression
kiểm chứng đường lỗi này, không thay đổi số HTTP/LLM hoặc điều phối của lab.

Chạy lại lab bằng thư mục mới tự sinh:
`python -B -u scripts/run_coordinator_mvp_lab.py`.

Giới hạn kiểm chứng: lab dùng model giả lập, không chứng minh provider/cab.vn/
token/proxy công khai hoạt động. Lab chạy in-process; việc dừng process của
supervisor, timeout LLM, budget và retry được kiểm tra trong regression riêng.
Không coi HTTP404 transport-complete là endpoint hợp lệ hoặc mặc định pipeline
phải completed; bước kiểm chứng có thể còn unverified/partial.

## File thuộc thay đổi MVP này

Không đồng nhất danh sách này với toàn bộ `git diff`: workspace đã có nhiều
thay đổi từ các phiên trước, kể cả `.venv` đang tracked.

- Source (8): `src/agents/fuzzer.py`; `src/tools/http_fuzzing.py`,
  `src/tools/ffuf_helper.py`; `src/coordinator/graph.py`, `validation.py`,
  `state.py`, `decision_engine.py`, `prompts.py`.
- Tests (6): `tests/test_http_fuzzing.py`, `test_ffuf_helper.py`,
  `test_fuzzing_integration.py`, `test_pipeline_failure_integration.py`,
  `test_coordinator_limits.py`, `test_coordinator_observations.py` (mới).
- Script mới: `scripts/run_coordinator_mvp_lab.py`.
- Tài liệu mới: file này và `docs/coordinator_mvp_reflection_progress.md`.
- Logs/evidence nằm trong `output_samples/diagnostics`, không đưa vào source commit.

Không nâng dependency, không đổi pipeline/agent/auth/scope/TLS, không xóa dữ liệu,
không commit/push. Các phần tính lỗi/thống kê/reflection không phát sinh request,
model call, retry hay chuyển proxy bổ sung.

## Kết luận nghiệm thu

**Coordinator đạt MVP theo acceptance criteria của yêu cầu này trong phạm vi
kiểm chứng localhost + model giả lập.** Kết luận dựa trên 408 test PASS và log
độc lập của lab, không chỉ dựa trên unit tests.

| Acceptance | Bằng chứng | Kết quả |
|---|---|---|
| 11 timeout được giữ đủ, error_log count11, không completed | Lab all_timeouts + pipeline failure tests | Đạt |
| 10 timeout / 8 response+2 timeout / 10 HTTP404 | HTTP fixture tests, không retry bổ sung | Đạt |
| Budget/deadline/stop condition không bị che mất | HTTP/ffuf/limits/proxy regression; partial_budget lab | Đạt |
| Root đúng một lần, alias không làm tăng selection count | Native + ffuf thật localhost và root404 lab | Đạt |
| 1950 generated, 12 selected, 11 attempted, 11 lỗi tách biệt | Actual prompt/context/snapshot regression | Đạt |
| Reflection chỉ lưu quan sát có evidence, giữ session/history | Observation tests, mỗi reflection chỉ 1 call đã có | Đạt |
| Partial/failed vẫn có checkpoint và dữ liệu thật | Failure tests + kết quả lab bằng JSON đã lưu | Đạt |
| Đủ 5 module thực thi thành công | completed lab: 94 HTTP khớp server, 30 model calls khớp fixture | Đạt |

Không còn lỗi mở trong phạm vi acceptance đã kiểm chứng. Giới hạn còn lại là
khả năng hoạt động của provider thật/website thật/proxy công khai, số đếm exact
không được ffuf công bố, và tri thức lịch sử chưa kiểm chứng lại. Không dùng kết
luận MVP này để khẳng định đã quét cab.vn thành công hoặc xác thực token hiện tại.
