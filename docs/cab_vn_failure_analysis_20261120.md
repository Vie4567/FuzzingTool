# Phân tích phiên cab.vn ngày 20/11/2026

Ngày kiểm tra: 21/11/2026. Phạm vi: đọc artifacts cũ, sửa lỗi đã tái hiện và kiểm thử localhost. Không gọi cab.vn, không dùng access token thật, không gọi LLM provider, không commit/push.

**Kết luận:** Agent 3 thất bại vì cả 6 request timeout trước khi nhận được HTTP status. Hiện tượng timeout đã xuất hiện trong Recon trước đó. Có ba lỗi phần mềm đã chứng minh và sửa: native helper làm mất các bản ghi đo, redaction che nhầm dữ liệu Recon công khai, và Coordinator có thể báo sai trạng thái kiểm chứng của Agent 4–5. Các sửa đổi này không chứng minh kết nối đến cab.vn đã phục hồi.

## 1. Bằng chứng từ phiên gốc

Nguồn chính: [result.json](../output_samples/diagnostics/coordinator_auth_20261120T034001Z_bac639d4/pipeline_20261120T034023Z_5bd0465baf54/result.json), checkpoint worker trong thư mục `pipeline_20261120T034024Z_4fced5a84791`, audit log và `llm_responses.jsonl` của phiên.

Bản trích xuất không chứa credentials: [failed_session_summary.json](../output_samples/diagnostics/cab_vn_failure_fix_20261121/failed_session_summary.json). File này lưu SHA-256 của result gốc để đối chiếu; không sửa artifacts gốc.

| Giai đoạn | Attempts | HTTP responses | Network errors | Nhận xét |
|---|---:|---:|---:|---|
| Recon | 26 | 21 | 5 | Có thêm 1 lỗi đọc body sau khi đã nhận HTTP 200; lỗi này thuộc 21 responses, không cộng thành request thứ 27 |
| Fuzzing | 6 | 0 | 6 | `transport_error`, `completed=false`, Agent failed |
| Parameter | 0 | 0 | 0 | Không vào execution node, không có `agent_attempts.param_disc` |
| Soft404 | 0 HTTP | 0 | 0 | Node được gọi 1 lần nhưng guard trả `skipped/upstream_transport_error` |

Tổng phiên: **32 HTTP attempts, 20 LLM calls, 0 retries**. Pipeline cuối là `partial`, không phải nghiệm thu thành công toàn bộ module.

Agent 2 tạo 2.057 ứng viên; Coordinator chọn 6: `/robots.txt`, `/sitemap.xml`, `/`, `/.aws/config`, `/.aws/credentials`, `/.circleci/config.yml`. Fuzzing thử đủ 6 trong khoảng 48,216 giây. `fuzzing_execution.errors` giữ 6 timeout và `error_log` tổng hợp count=6, nhưng `raw_results=[]` do lỗi filter được mô tả bên dưới.

Các mốc sau dùng UTC (giờ Việt Nam/Thái Lan cộng 7 giờ):

| Mốc | Bằng chứng |
|---|---|
| 03:40:24 | Recon bắt đầu; request homepage đầu tiên nhận 200, 2.207 byte, khoảng 1,547 giây |
| 03:40:42 | JS chính nhận 200 nhưng lỗi đọc body; đã nhận 1.489.544 byte |
| 03:41:26 | CH-4 Spider gọi lại target root và timeout, không có HTTP status |
| 03:41:34–03:41:58 | Bốn probe CH-7 tiếp tục timeout |
| 03:42:13 | Recon kết thúc partial |
| 03:43:54–03:44:52 | Agent 3 lập kế hoạch rồi thực thi 6 request timeout |
| Sau 03:44:52 | Parameter bị skip; Soft404 không tăng HTTP/LLM counter; Report lưu kết quả partial |

URL/method của một số bản ghi Recon cũ bị che nhầm thành `[REDACTED]`. Việc xác định request homepage/root dựa thêm vào tên kênh, target phiên và call site Recon; không phục hồi hoặc đo lại nội dung đã mất.

**Nguyên nhân trực tiếp:** timeout trong đường gọi mở HTTP connection/response, trước khi parser trả về status. Không có HTTP 401/403/429 trong 6 request này. `TimeoutError` hiện không cung cấp đủ chi tiết để phân biệt DNS, TCP, TLS hay chờ response headers. Không có căn cứ kết luận token hết hạn, IP bị block, User-Agent hoặc TLS là nguyên nhân gốc.

Recon nhận 200 trước đó và Fuzzing timeout sau đó không mâu thuẫn: ngay transport Recon cũng đã timeout ở lần gọi sau. Fixture localhost tái hiện đúng khả năng này: root 200 → server phản hồi chậm → cả Recon và Fuzzing timeout. Đây là bằng chứng về tính hợp lý của chuỗi hành vi, **không phải bằng chứng cab.vn đã dùng cơ chế gây chậm nào cụ thể**.

## 2. Recon và Fuzzing khác nhau ở đâu?

| Thành phần | Recon | Fuzzing trong phiên gốc |
|---|---|---|
| Entry point | `ScopedReconTransport.open/fetch_result`, `src/tools/recon_http.py` | `FuzzingAgent.execute` → `FfufToolHelper.run` → `run_http_fuzzing`, engine `python_http` |
| URL/method | Target homepage và các tài nguyên/probe; GET, OPTIONS, TRACE | 6 URL đã chọn, GET, không request body |
| User-Agent mặc định | `SentinelPentest/1.0 (scoped-recon)` | `SentinelPentest/1.0 (bounded-http-fuzzing)` |
| Auth | Chỉ auth origins được phép; TRACE bỏ credentials | Headers operator được truyền; `auth_matches_operator=true`, `operator_headers_configured=true` |
| TLS | `ssl.create_default_context`, có cấu hình CA | HTTPSHandler mặc định xác minh chứng chỉ hệ thống |
| Kết nối | Tạo opener riêng mỗi request | Dùng lại opener trong lượt chạy; urllib gửi `Connection: close`, không phải connection pool |
| Proxy/redirect | Direct, không lấy proxy môi trường; không theo redirect | Direct, không lấy proxy môi trường; không theo redirect |
| Timeout | Timeout từng kênh được cap bởi runtime HTTP 8 giây | Timeout explicit 8 giây, cap theo runtime/deadline |
| Đọc body | Giữ prefix/status nếu đọc lỗi; đọc có giới hạn, giữ số byte thực | Giữ phép đo status/byte/error; không đưa body đầy đủ vào kết quả |
| Lỗi HTTP | 4xx/5xx là phản hồi HTTP; runtime có stop policy riêng | Cùng nguyên tắc; timeout trước status là transport error |

Cả hai chịu global budget 200 request và tốc độ 0,5 request/giây trong phiên này. Không thay đổi các giá trị này. Timeout socket không phải tổng thời gian của cả kênh: thời gian chờ rate slot và các lần đọc body có thể làm elapsed lớn hơn 8 giây. Lỗi đọc JS sau HTTP 200 khác với 6 timeout không có status của Fuzzing.

TLS context mặc định và context riêng có thể khác chi tiết thương lượng; khác biệt User-Agent cũng tồn tại. Chưa có phép đo trên phiên gốc chứng minh chúng gây lỗi, vì vậy không đổi TLS hoặc giả lập User-Agent khác để thử né cơ chế phía server.

### Cấu hình do LLM đề xuất

`graph.run_fuzzing()` ghép điều chỉnh của Coordinator với cấu hình operator; `FuzzingAgent.execute()` áp dụng caller sau kế hoạch LLM, rồi gán lại `target_url` và wordlist được giao. Engine/proxy/scope/TLS là cấu hình operator. Regression test kiểm tra target, wordlist, rate, timeout, request cap, method và headers của caller giữ ưu tiên.

Trong log phiên gốc:

- LLM đề xuất target `/FUZZ` và danh sách đường dẫn khác; engine vẫn nhận đúng target và 6 đường dẫn Coordinator đã chọn.
- Rate 0,5, timeout 8 giây, method GET, engine `python_http`, auth và request cap explicit không bị kế hoạch LLM thay thế.
- `match_codes=200,204,301,302,307,401,403` có tác động sai ở native helper: lọc mất timeout vì status là null. Đã sửa bằng cách giữ toàn bộ phép đo native.
- `stop_on_errors` và `stop_on_all_errors` không được implementation hỗ trợ; chúng bị bỏ qua, không có warning riêng. Không thể dùng chúng để khẳng định sẽ dừng ngay timeout đầu tiên. Sáu attempts không phải sáu retries.
- Một số điều chỉnh như `wordlist_selection_limit` không phải hợp đồng cấu hình được engine áp dụng. Không coi đề xuất tự do của LLM là cấu hình đã thực thi.

## 3. Sửa đổi tối thiểu và bằng chứng

| File/hàm | Lỗi trước sửa | Sau sửa và kiểm thử |
|---|---|---|
| `src/tools/ffuf_helper.py::FfufToolHelper.run`, tool schema | `_keep_result` áp dụng cả native; `match_codes` xóa status null và filter xóa phép đo 404, trái warning của native engine | Giữ mọi bản ghi native; status filter vẫn chỉ dùng cho ffuf CLI. Hai regression tests trước sửa thất bại, sau sửa giữ đủ 6 timeout hoặc đủ 200/404/timeout |
| `src/coordinator/graph.py::run_tech_recon` | Đưa toàn bộ config vào khóa `credentials` làm origin, GET, seed path và các chuỗi công khai bị coi là secret | Dùng bộ trích secret hiện có `artifacts._secrets(config)`. Giữ public evidence, vẫn che bearer, provider key, URL proxy/password; test kiểm tra cả Agent 2 input và artifact |
| `src/coordinator/graph.py::_verification_execution_status`, `run_param_discovery`, `run_soft404_filter` | Parameter thiếu status có thể thành success; Soft404 failed có thể thành success/skipped; Parameter log luôn ghi Success | Giữ failed/partial. Success chỉ khi completed + performed=True + số request đo được >0 + không có stop bất thường. Có đo nhưng status không xác định → partial. Không đo → skipped. Soft404 failed được ghi error_log/circuit breaker |

Các file test thêm/sửa:

- `tests/test_ffuf_helper.py`: 6 timeout vẫn có 6 bản ghi; 200/404/timeout không bị CLI filter xóa ở native.
- `tests/test_recon_contract.py`: không che nhầm URL/method/profile/path; secrets giả không đi vào SharedState công khai, Agent 2 hoặc artifact.
- `tests/test_fuzzing_integration.py`: tăng kiểm tra caller overrides kế hoạch LLM về target/wordlist/timeout/cap/method.
- `tests/test_post_fuzzing_integration.py` (mới): pipeline thật với HTTP localhost cho Agent 3–5, kiểm tra saved result/checkpoint/budget/auth.
- `tests/test_transport_parity.py` (mới): cùng root, cùng bearer giả, first 200 rồi cả hai transport timeout; server ghi nhận độc lập đúng 3 request.
- `tests/test_coordinator_environment.py`: fixture chỉ trả ứng viên Parameter, không đo HTTP, phải skipped thay vì success.

Không sửa `http_fuzzing.py`, transport Recon, auth origins, TLS, timeout, rate, retry, budget, cơ chế proxy hoặc cấu trúc các Agent. Không thêm HTTP/LLM call vào production flow. Việc giữ bản ghi native chỉ bảo toàn dữ liệu đã đo; không quét lại và không đưa toàn bộ response vào prompt.

## 4. Điều kiện Agent 4–5 chạy hoặc dừng

| Điều kiện | Parameter | Soft404 |
|---|---|---|
| Fuzzing partial hoặc stop reason khác completed | `llm_decide_after_fuzzing` đặt skipped và chọn skip_to_filter; không gọi LLM quyết định thêm | Node được gọi, `soft404_options_from_config` truyền upstream stop; verifier trả skipped trước I/O |
| Fuzzing hoàn tất, có HTTP 200, routing proceed | Nhận các row HTTP 200; chỉ đo khi có ứng viên và scope/auth/route/budget phù hợp | Tạo baseline và đọc lại ứng viên khi upstream không dừng và transport replay hợp lệ |
| LLM muốn skip nhưng `run_all_modules=true`, có HTTP 200 và guard cho phép | `_apply_decision` đổi sang proceed_to_param | Chạy theo pipeline bình thường, vẫn chịu guard |
| Không có HTTP 200, chỉ 404 | LLM có thể skip node hoặc gọi node với endpoints rỗng; cả hai không có kiểm chứng HTTP | Phân loại 404 từ dữ liệu sẵn có, không cần baseline; phase không báo success giả |
| Runtime nhận HTTP 401/403/407/429 hoặc Retry-After | Dừng global runtime; không dùng token khác/refresh/đổi proxy | Không tiếp tục request; nếu chưa vào node thì giữ pending, attempts không tăng |
| Parameter partial/failed | Giữ ứng viên và phép đo đã có | Nhận upstream stop, không tiếp tục để né lỗi giai đoạn trước |
| Hết global request budget/deadline | Không gửi quá giới hạn | Không mở lại budget ở module sau |

Trong các test 401/403/429 và hết budget, `_checkpointed` bắt global stop trước execution của decision tiếp theo; pipeline hiện ghi `failed`, Agent 4–5 còn `pending` với 0 attempts. Đây là "chưa được thực thi do dừng toàn phiên", không phải skipped/success. Artifacts lỗi và checkpoint vẫn lưu. Giữ nguyên hành vi này, không đổi kiến trúc trạng thái.

Trong phiên cab.vn đang xét, Parameter bị skip đúng theo upstream transport stop. Soft404 có attempt node=1 nhưng HTTP=0 là đúng guard. Trường hợp partial có một response hợp lệ cũng vẫn dừng downstream theo chính sách hiện có; dữ liệu được giữ ở unverified, không tự nới guard để đạt completed.

`pipeline_status=completed` khi chỉ có 404 và các verifier skipped có nghĩa luồng đã kết thúc bình thường. Nó không đồng nghĩa mọi module đã kiểm chứng thành công: phải đọc thêm `all_modules_successful`, `agent_attempts` và stats từng phase.

## 5. Kiểm thử và bằng chứng sau sửa

Baseline gần nhất trước task: **471 tests PASS**, log `output_samples/diagnostics/acceptance_readiness_20261120/tests_after_preflight.log`. Bộ tập trung trước lượt bổ sung kiểm tra proxy credentials: **64 PASS, 0 skipped, 15,004 giây**.

Toàn bộ suite cuối cùng: **482/482 PASS, 0 skipped, 135,483 giây**, gồm 11 test mới so với baseline 471. Log: [tests_final.log](../output_samples/diagnostics/cab_vn_failure_fix_20261121/tests_final.log). Một lượt trước bị ngắt khi phiên tương tác tiếp tục, chưa có summary; giữ tại `tests_interrupted_before_summary.log`, không tính là PASS. Sau khi suite ghi `OK`, wrapper in đuôi log ra terminal gặp lỗi encoding cp1252 với ký tự Unicode; đây là lỗi hiển thị của lệnh kiểm tra, không phải lỗi của test suite. Không chạy lại suite chỉ để in log.

Lệnh tái chạy từ thư mục dự án (PowerShell; dùng fixture/mock, không nhập access token):

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:LANGCHAIN_TRACING_V2 = 'false'
$env:PYTHONIOENCODING = 'utf-8'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Tiến trình kiểm thử của task còn loại các biến môi trường API key/access token khỏi môi trường con; không sửa `.env` hoặc môi trường của terminal người dùng.

Bằng chứng localhost được sao lưu từ kết quả/checkpoint thật của các integration tests trước khi thư mục tạm bị dọn. [focused_test_summary.json](../output_samples/diagnostics/cab_vn_failure_fix_20261121/focused_test_summary.json) dẫn đến từng `result_copy`; mỗi thư mục có `independent_server_evidence.json` với số request/path server thực sự thấy và xác nhận auth giả khớp, không lưu bearer. Trường `artifacts` bên trong bản sao vẫn phản ánh đường dẫn tạm tại thời điểm test; dùng `result_copy` để mở bản lưu bền vững.

| Kịch bản localhost | HTTP server ghi nhận | Agent 3 / 4 / 5 | Pipeline |
|---|---:|---|---|
| Thành công `/search` | 15 = Fuzz 1 + Parameter 11 + Soft404 3 | success / success / success | completed; xác minh tham số `filter` và endpoint |
| Timeout toàn bộ | 1 | failed / skipped / skipped | partial; giữ timeout row |
| 200 + timeout | 2 | partial / skipped / skipped | partial; giữ cả hai row |
| Chỉ 404, LLM skip | 1 | success / skipped / skipped | completed, all_modules_successful=false |
| Chỉ 404, LLM proceed | 1 | success / skipped / skipped | completed, all_modules_successful=false |
| HTTP 401 / 403 / 429 | 1 mỗi kịch bản | partial / pending / pending | failed do global stop, không request thứ hai |
| Global budget=1, có 2 ứng viên | 1 | partial / pending / pending | failed, http_request_budget |

Tổng chín kịch bản trên: **24 HTTP requests, 0 LLM calls**, khớp server và telemetry. Test parity riêng: **3 HTTP requests, 0 LLM calls**. Đây là số đo của các kịch bản được nêu, không phải tổng mọi request của toàn bộ test suite. Recon, Wordlist, quyết định LLM và sinh ứng viên Parameter được mock trong integration này; HTTP Agent 3, Parameter verifier và Soft404 verifier là thật. Không gọi đây là nghiệm thu đầy đủ với LLM thật.

## 6. Mức sẵn sàng và phần chưa giải quyết

Các lỗi lưu phép đo, redaction context và trạng thái verifier có bản sửa/test cụ thể; toàn bộ regression suite đã đạt. **Sẵn sàng về phần tích hợp cục bộ cho một phiên kiểm tra HTTP thật có giám sát**, giữ nguyên các giới hạn hiện có. Chưa thể tuyên bố phiên nghiệm thu cab.vn thành công hoặc đã khắc phục nguyên nhân timeout phía mạng/server.

Các giới hạn còn lại:

1. Artifacts cũ không có socket-stage tracing hoặc log server; chưa xác định DNS/TCP/TLS/chờ headers là tầng gây timeout. Cần đối chiếu log phía máy chủ hoặc phép đo hạn chế ở phiên được người vận hành cho phép tiếp theo.
2. Chưa xác minh hiệu lực bearer token bằng endpoint bảo vệ. HTTP 200 ở homepage công khai không chứng minh đăng nhập thành công. Không có refresh token tự động trong lượt sửa này.
3. Test HTTP localhost không thay thế xác minh TLS/network path thực tế đến cab.vn; không có live provider calls trong task.
4. LLM vẫn có thể đề xuất option không được hỗ trợ. Cấu hình operator rõ ràng và artifact thực thi mới là bằng chứng; các kwargs stop_on_errors/stop_on_all_errors chưa được triển khai, không bổ sung tùy tiện trong task này.
5. Các HTML 200 cùng 2.207 byte ở Recon có thể là fallback; chưa đủ cơ sở xem chúng là endpoint hợp lệ khi Soft404 chưa đo baseline.
6. Trước task đã có thay đổi ở `docs/cab_vn_acceptance_readiness.md`, `docs/coordinator_auth_proxy_cli.md`, `scripts/run_coordinator_scan.py`, `tests/test_coordinator_scan_runner.py`; chúng được giữ nguyên, không phải sửa mới của phân tích này.

Không tăng timeout/request budget, không refresh token, không tự động xoay proxy và không bỏ điều kiện dừng để ép pipeline hoàn tất.
