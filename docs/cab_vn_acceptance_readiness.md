# Kiểm tra trước nghiệm thu cab.vn — xác nhận lại 2026-11-20

Phạm vi: đọc mã nguồn, kiểm tra cấu hình cục bộ và regression bằng fixtures/localhost/mock LLM. Không gọi cab.vn, không dùng access token thật, không gọi DeepSeek và không lấy proxy Internet. Chưa có bằng chứng nghiệm thu toàn bộ pipeline trên website thật trong lần kiểm tra này.

Kết luận: mã nguồn có thể chuẩn bị một phiên có giám sát bằng `python_http` trực tiếp, khóa cùng target/auth origin; môi trường còn rủi ro chặn DLL phải theo dõi. Ngày 2026-11-20 đã tái hiện Windows Application Control chặn `ormsgpack.cp312-win_amd64.pyd` khi import Coordinator, với Code Integrity events 3077/3033. Những lần import sau thành công chưa chứng minh chính sách chặn đã được giải quyết. Chưa chứng nhận khả năng truy cập cab.vn, token/API key/model hợp lệ hoặc đủ dữ liệu để cả năm Agent hoàn tất. Những bảo đảm dưới đây áp dụng cho runner và cấu hình được hướng dẫn; không mở rộng kết luận cho mọi cấu hình API hoặc ffuf.

## Pipeline và dữ liệu

| Thành phần | Mã nguồn/luồng đã kiểm tra | Điều cần đối chiếu khi nghiệm thu |
| --- | --- | --- |
| Coordinator | `src/coordinator/graph.py::build_coordinator_graph` nối validate → init → Recon → quyết định → Wordlist → quyết định → Fuzzing → quyết định → Parameter/skip → Soft404 → Report → Reflection | Đây là luồng có điều kiện; stop, skip hoặc lỗi có thể kết thúc sớm. |
| Agent 1 | `run_tech_recon` giữ `recon_profile`, `recon_execution` và trường legacy; `TechReconAgent` thu thập HTTP thật | Xem completed/partial/failed của Recon, evidence, channels và các lỗi; Unknown không được coi là nhận diện chắc chắn. |
| Agent 2 | `run_wordlist_gen` truyền target URL + recon profile; kiểm tra/loại trùng candidate và chọn wordlist | Phân biệt generated/selected; danh sách sinh không chứng minh URL tồn tại. |
| Agent 3 | `run_fuzzing` giữ `raw_results`, `fuzzing_stats`, `fuzzing_execution` và tổng hợp lỗi theo attempt | Chọn `python_http`; đối chiếu attempted/responses/network_errors/remaining. HTTP 200 chưa phải endpoint đã xác minh. |
| Agent 4 | `run_param_discovery` nhận endpoint HTTP200 cần kiểm chứng, lưu candidate và verified riêng | Kiểm chứng GET bằng baseline/control/candidate; không chứng nhận phát hiện mọi body/parameter/API. Thiếu endpoint hoặc upstream dừng có thể skipped. |
| Agent 5 | `run_soft404_filter` giữ verified/unverified/false positives; giữ nguyên raw measurements | Không replay khi upstream chưa hoàn tất, auth/route khác hoặc bị chặn. |
| Report | `generate_report` cập nhật summary/audit/SharedState; artifacts lưu JSON | Không có cam kết core tự sinh Markdown. Reflection cũng có thể lỗi sau khi các module chạy. |

`_checkpointed` và `_apply_decision` giới hạn số lần thực thi/retry/iteration. Runtime dùng ngân sách HTTP chung và deadline; LLM có quota, elapsed timeout và SDK `max_retries=0`. Không thêm retry, request hay LLM call trong các sửa đổi lần này.

`RunArtifacts.save` lưu checkpoint nguyên tử trước/sau node và kết quả lỗi; supervisor có hard deadline, phục hồi snapshot mới nhất. Khi worker chết có request đang chạy, tổng cuối có thể unknown/null, giữ số đếm checkpoint gần nhất. Checkpoint chưa phải API resume để chạy tiếp pipeline.

`run_all_modules=True` chỉ can thiệp skip Parameter trong điều kiện cho phép; không vượt budget/stop. `pipeline_status="completed"` riêng lẻ chưa đủ để nghiệm thu đủ năm Agent, vì có thể có module skipped. Cần cả `all_modules_executed=true`, `all_modules_successful=true` và từng module success.

Giới hạn phụ đã thấy, chưa mở rộng sửa trong đợt này: `use_fallback_wordlist` của Coordinator chỉ route tiếp, không tự cài một wordlist mới; Agent Wordlist có fallback riêng. Circuit breaker/tarpit có ghi trạng thái, nhưng điều kiện chặn chắc chắn trong `_apply_decision` là retry/iteration/runtime guards. Log Parameter có nhãn Success cố định ở một nhánh; dùng JSON trạng thái làm nguồn đối chiếu.

## HTTP, provider, authentication và proxy

- Python 3.12.10 chạy được; ffuf 2.3.0 có tại `output_samples/tools/ffuf/ffuf.exe`. Không cài hoặc nâng dependency.
- Cấu hình cục bộ có `DEEPSEEK_API_KEY`, endpoint `https://api.deepseek.com`, `LLM_MODEL=deepseek-flash`. Chỉ kiểm tra hiện diện/cấu trúc; chưa kiểm chứng dịch vụ/model/quota. Runner chỉ chấp nhận endpoint HTTPS DeepSeek đã quy định. Không có `FUZZ_PROXY_PROFILES` hoặc `TARGET_BEARER_TOKEN` trong settings tại thời điểm kiểm tra; không cần hai biến này cho runner direct với prompt ẩn.
- `python_http` gửi HTTP thật, tuần tự, không redirect, dùng TLS verification, bỏ qua ambient proxy của urllib. Runtime reserve từng dispatch, gồm cả lỗi kết nối. Các lần gọi provider LLM được đếm riêng với HTTP mục tiêu.
- `auto` có thể chọn ffuf vì máy đã có binary. ffuf CLI chưa bảo đảm global wire-request budget/rate hoặc cùng chính sách dừng401/Retry-After; attempted count có thể null. Wrapper chưa đủ cơ sở chứng nhận cùng auth-origin/TLS policy như native. Vì vậy lệnh nghiệm thu dùng rõ `python_http` qua `--proxy-source none`.
- Runner mặc định không proxy. Manual/ProxyScrape chỉ kích hoạt khi chọn rõ; Recon vẫn direct. Không xác minh proxy khỏe hay IP đầu ra trong đợt này.

| Agent | Bearer ở đâu | Scope/redaction |
| --- | --- | --- |
| Recon | `recon_options_from_config` → `_build_transport` | Exact allowed/auth origins, không gửi auth trên TRACE; dữ liệu phản chiếu credentials được che trước prompt/output. |
| Wordlist | Không nhận Authorization | Nhận recon profile đã sanitize và ngữ cảnh có giới hạn. |
| Fuzzing | `config.fuzzing_options.headers` | Native URL preparation giữ đúng target origin; headers được che trong kế hoạch LLM/log. |
| Parameter | `parameter_options_from_config` lấy đúng headers của fuzzing | Yêu cầu `auth_matches_operator`, transport kiểm tra auth origins; credentials không nằm trong input assembler/LLM. |
| Soft404 | `soft404_options_from_config` lấy đúng headers của fuzzing | Cùng replay gates và auth origins; không cần LLM để so sánh. |

Runner ghi bearer ở cả cấu hình chung và fuzzing, với `allowed_origins=auth_origins=[https://cab.vn]`. Không tự suy ra quyền cho `www.cab.vn` hay API subdomain. Fuzzer native chưa có policy `auth_origins` độc lập cho cấu hình API tùy ý; chỉ chứng nhận runner khi target/auth origin bằng nhau. Không chỉ đặt token ở cấu hình Recon rồi giả định Fuzzing sẽ tự nhận.

`RunArtifacts.public_state` che known credentials và các dạng URL-encoded trước checkpoint/final JSON. `invoke_logged` không lưu prompt; response/error được redaction. Runner tắt LangSmith/LangChain tracing. Credential của provider chỉ dùng cho provider, không làm Authorization của website.

HTTP401/403/407/429 hoặc `Retry-After` tạo terminal stop ở `RuntimeBudget.response`; không đổi proxy hay retry để vượt. 401 có thể do hết hạn, sai token/audience hoặc cơ chế auth khác; không tự phân biệt được chỉ bằng status. 403 không chứng minh riêng WAF hay IP block. Ngay cả một probe công khai trả403 cũng có thể dừng phiên trước khi đến đủ năm Agent; giữ nguyên chính sách này.

Không có refresh-token workflow: `AuthManager` hỗ trợ credentials cung cấp trước hoặc form login ban đầu, không có refresh endpoint, cập nhật token trên401 hay replay sau refresh. Cần nhập token mới còn hiệu lực khi tự chạy. HTTP200 của robots/trang công khai không chứng minh token được chấp nhận; cần đối chiếu tài nguyên có yêu cầu đăng nhập thuộc scope.

## Thay đổi tối thiểu trong lần kiểm tra

1. `scripts/run_coordinator_scan.py::{parser,build_config,main}`: thêm `--proxy-source none` làm mặc định; không thêm proxy config ở direct; thêm HTTP budget/rate và retry CLI; `--check` không đọc token hoặc chạy pipeline. Nguyên nhân: runner cũ chỉ dùng proxy_http và tự chọn ProxyScrape.
2. `src/tools/proxy_profiles.py::OPERATOR_NETWORK_OPTIONS`, `src/agents/fuzzer.py::execute`, `src/coordinator/graph.py::run_fuzzing`: chỉ cấu hình người chạy được chọn route/scope/TLS, loại fixed proxy và source/TLS options từ kế hoạch LLM ở cả hai tầng. Nguyên nhân: chặn proxy pool chưa bao phủ fixed proxy, Manager có thể đưa nó trở lại như caller option.
3. `src/agents/fuzzer.py::execute`: che credentials ở nhánh tool trả lỗi bình thường, lý do chọn tool, justification và chuỗi trong response trước khi trả kết quả/log/chuyển cho LLM. Nguyên nhân: nhánh exception đã sanitize nhưng `ToolResult.error_message` trả về bình thường có thể lọt vào info/warning log. Hai regression mới dùng opaque token giả để tái hiện; giữ status, byte length, thời gian, bộ đếm và response header không nhạy cảm, không sửa payload gốc của tool.
4. Tests trong `tests/test_coordinator_scan_runner.py`, `tests/test_fuzzing_integration.py`, `tests/test_proxy_fuzzing.py`: direct mặc định, không đọc token khi check, cùng budget/rate, hidden token forwarding qua supervisor mock, LLM không được tự định tuyến, explicit operator route vẫn giữ và token phản chiếu không lọt vào log/justification.
5. Hướng dẫn đã cập nhật tại [coordinator_auth_proxy_cli.md](coordinator_auth_proxy_cli.md). Không chỉnh `.env`, không thay kiến trúc/Agent, không commit/push. Khi tiếp tục ngày 2026-11-20, các bản vá trên đã có trong HEAD `cf22524`, nhánh `feature/fuzzingtool-integration`, worktree ban đầu sạch.
6. Bổ sung lần xác nhận 2026-11-20: `scripts/run_coordinator_scan.py::check_runtime` import/compile graph thật trước khi hỏi token; thiếu/bị chặn DLL thì exit2, không chạy agent. `test_blocked_runtime_fails_before_token_prompt_or_pipeline` kiểm tra cả check/live với ImportError giả. Nguyên nhân: validation cấu hình trước đây vẫn có thể báo hợp lệ dù process worker không import được LangGraph. Không cài dependency, không thay chính sách Windows; preflight chỉ phát hiện lỗi tại thời điểm/process kiểm tra, không bảo đảm process worker tương lai không bị policy chặn.

## Bằng chứng kiểm tra

- Mốc trước bản vá redaction cuối: 468 tests PASS, 120,239 giây, log `output_samples/diagnostics/acceptance_readiness_20261115/tests.log`.
- Lượt đầu xác nhận 2026-11-20: 461 test entries, **FAILED (1 import error)**, 130,552 giây; module gồm 10 tests Coordinator limits không được nạp do Windows chặn ormsgpack, không phải 461 tests đều PASS. Giữ log tại `output_samples/diagnostics/acceptance_readiness_20261120/tests_final.log`.
- Module limits chạy riêng sau đó: 10/10 PASS. Test runner sau bổ sung preflight: 8/8 PASS. Không dùng hai kết quả riêng này để thay thế yêu cầu full regression.
- Lượt full regression cuối sau bản vá preflight: **471/471 PASS**, 126,120 giây, log [tests_after_preflight.log](../output_samples/diagnostics/acceptance_readiness_20261120/tests_after_preflight.log). Các tests dùng fixtures/localhost/mock LLM; biến credential provider/target không được kế thừa vào process kiểm thử, dotenv/tracing tắt. Không chạy script lab hoặc quét website công khai.
- Cần quản trị viên đánh giá DLL chính thức theo chính sách máy nếu lỗi chặn tái diễn; xem [coordinator_environment.md](coordinator_environment.md). Không dùng `pip check` hoặc `--check` thành công một lần để kết luận Windows sẽ luôn cho phép chạy.

Lệnh regression:

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:LANGCHAIN_TRACING_V2 = 'false'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Trong lần kiểm chứng, stdout/stderr được lưu bằng UTF-8; cấu hình credentials thật trong môi trường process test được bỏ trước khi gọi lệnh này. Các kiểm chứng không tăng HTTP/LLM calls của phiên nghiệm thu: preflight chỉ import/compile, redaction chỉ xử lý dữ liệu đã có, sửa routing không thêm scan/retry. Không thay đổi giới hạn, TLS hoặc scope đã chọn.

## Cách chạy và tiêu chí nghiệm thu

Từ thư mục project, kiểm tra offline:

```powershell
.\.venv\Scripts\python.exe -B -u .\scripts\run_coordinator_scan.py --target https://cab.vn --proxy-source none --http-max-requests 200 --http-rate-limit 0.5 --max-wordlist-entries 6 --max-retries 0 --pipeline-timeout 1200 --llm-timeout 120 --check
```

Lệnh này đã được kiểm tra cục bộ và trả `Configuration valid; Coordinator graph compiled`, không dùng access token. Nếu báo `Coordinator runtime unavailable`, xử lý dependency/policy trước khi nghiệm thu. Chỉ khi muốn thực hiện phiên thật, bỏ `--check` và nhập token ở prompt ẩn. Lượt thật sẽ gọi DeepSeek và gửi HTTP đến target; không được hiểu lệnh check là bằng chứng đã quét.

Runner chọn tối đa 6 đường dẫn từ wordlist merge, nhưng Recon/Parameter/Soft404 cũng tiêu ngân sách 200. Tốc độ tối đa 0,5 request/giây; deadline 1.200 giây; HTTP timeout8 giây; LLM timeout120 giây, quota60 calls, output tối đa8.192 tokens/call. Không retry module với `--max-retries 0`. Giới hạn phase vẫn giữ; không đảm bảo 200 dispatch đủ để hoàn thành năm Agent.

Console in `Artifacts:` và `Result:`. Đọc result/checkpoints và `llm_responses.jsonl`, đối chiếu trạng thái từng Agent, stop reason/error_log, telemetry, lifecycle counts và evidence Parameter/Soft404. Kết quả partial là bằng chứng dừng có kiểm soát, chưa phải nghiệm thu pipeline hoàn tất.
