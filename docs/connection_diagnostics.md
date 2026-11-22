# Chẩn đoán kết nối trước nghiệm thu cab.vn

Cập nhật ngày 21/11/2026. Công cụ chỉ phục vụ một phép kiểm tra kết nối đến URL GET chỉ đọc được người vận hành cho phép; không chạy pipeline, dò đường dẫn, gọi LLM hoặc thay đổi cấu hình Coordinator/Agent.

## Hiện trạng và phạm vi đã bổ sung

Transport hiện tại của Recon (`ScopedReconTransport.fetch_result`) và HTTP Fuzzing (`run_http_fuzzing`) phân biệt được lỗi trước khi nhận status với lỗi đọc body sau khi đã nhận response. Một số exception riêng như `gaierror` hay `SSLCertVerificationError` cung cấp thêm dấu hiệu, nhưng `TimeoutError` từ `urllib.open()` không xác định được nó xảy ra ở DNS, TCP, TLS hay chờ HTTP headers. Artifacts ngày 20/11 không đủ thông tin để phục hồi giai đoạn này.

Hai file độc lập được thêm:

- `src/tools/connection_diagnostics.py`: `validate_options()` chỉ kiểm tra offline; `diagnose_once()` đo từng giai đoạn của một request.
- `scripts/run_connection_diagnostic.py`: CLI mặc định chỉ kiểm tra cấu hình; chế độ `--run` dùng worker riêng và lưu tiến độ/kết quả. Supervisor dừng worker nếu DNS của hệ điều hành hoặc headers nhỏ giọt không trả về kịp deadline.

Không tích hợp probe vào pipeline, không thêm Agent, không thay đổi SharedState/KnowledgeStore/Neo4j hoặc các source file đã sửa ở task trước.

| Stage trong kết quả | Ý nghĩa |
|---|---|
| `dns_resolution` | Gọi resolver hệ điều hành; có thể dùng cache hoặc IP literal, không đồng nghĩa luôn có truy vấn DNS ra mạng |
| `tcp_connect` | Tạo socket và kết nối đến địa chỉ đầu tiên resolver trả về |
| `tls_handshake` | Bắt tay TLS, xác minh CA và hostname; skipped với HTTP localhost |
| `request_send` | Bắt đầu gửi GET; một lỗi tại đây có thể đã gửi một phần request |
| `response_headers` | Chờ parser nhận đầy đủ status và headers; chưa xong thì `responses_received=0` |
| `response_body` | Đọc body có giới hạn; giữ status và số byte đã đọc nếu timeout hoặc dữ liệu bị cắt |

Các stage ghi thời gian UTC, duration, trạng thái, loại exception và mã lỗi số. Không ghi exception message, URL path/query, request/response headers, body, bearer token hoặc giá trị JSON dùng đối chiếu danh tính. Origin đích và diagnostic ID được giữ để đối chiếu. Công cụ không nạp `.env` hoặc registry của Agent và không dùng proxy từ môi trường.

## Giới hạn cố định

- Tối đa **1 GET**, **1 TCP connection attempt**, không retry và không đổi sang địa chỉ DNS thứ hai.
- Deadline tổng mặc định **8 giây**, chỉ cho phép giữ hoặc giảm, tính cả thời gian khởi động worker. Đây là giới hạn tổng chặt hơn timeout socket của phiên cũ; không phải tự nâng timeout. Dọn tiến trình sau khi dừng có thể cần thêm một khoảng ngắn.
- Body tối đa **65.536 byte**; có thể giảm. Tiến độ khi đọc body tối đa 20 cập nhật, không log mỗi byte.
- User-Agent cố định: `SentinelPentest/1.0 (bounded-http-fuzzing)`, giống Python HTTP Fuzzing trong phiên thất bại. Không có option đổi User-Agent.
- TLS luôn `CERT_REQUIRED` và kiểm tra hostname. Có thể chỉ định CA tin cậy bằng `--tls-ca-file`; không có insecure mode. Không bật TLS key logging qua `SSLKEYLOGFILE`.
- Không theo redirect, không xoay proxy, không tự refresh token. 401/403/407/429 hoặc `Retry-After` dừng trước khi đọc body; không gửi request tiếp theo.
- URL phải cùng exact origin với `--allowed-origin` (scheme/host/effective port). Bearer chỉ được gửi đến `--auth-origin` trùng origin này. HTTP không mã hóa chỉ được mang bearer giả ở IP loopback khi kiểm thử.

`http.attempted_requests` đếm lần bắt đầu gửi HTTP, không phải số lần server chắc chắn đã nhận. Lỗi DNS/TCP/TLS có thể có `attempted_requests=0` trong khi đã có network attempt. Không so trực tiếp số này với telemetry pipeline vốn tính logical dispatch từ trước kết nối.

Khi supervisor buộc dừng, `counts_complete=false`, `supervisor.last_observed_stage` là stage cuối đã nhận được từ worker. Số byte/counter trong request đang chạy có thể chưa cập nhật hết; không suy đoán phần chưa quan sát. `result.json` vẫn được lưu.

## Trạng thái xác minh token: not_configured

Chưa tìm thấy endpoint GET chỉ đọc được chủ hệ thống xác nhận yêu cầu đăng nhập và contract JSON hợp lệ trong các nguồn đã kiểm tra. Người vận hành cũng xác nhận chưa có thông tin này. Không dùng đường dẫn từ wordlist, JS hoặc LLM để tự cấu hình bước xác thực.

Bằng chứng:

- `src/tools/auth_manager.py::get_auth_headers()` cung cấp/cache headers trong scope; không chứng minh server chấp nhận bearer. `_auto_login()` trích token từ phản hồi đăng nhập, không phải kiểm chứng tài nguyên bảo vệ.
- Kiểm tra tên khóa `.env`/`.env.example`: không có cấu hình endpoint xác thực/danh tính; không xuất giá trị bí mật.
- `output_samples/diagnostics/cab_vn_authenticated_ffuf_20261021/report.md` và `cab_vn_full_authenticated_20261021/report.md` đã ghi rõ tài nguyên công khai trả 200 không chứng minh token được chấp nhận.
- `cab_vn_full_proxy_authenticated_20261024/report.md`: CONNECT 403, chưa có phản hồi HTTP của target để chứng minh bearer hợp lệ.
- Recon của các phiên đầy đủ 21/10 và 24/10 có `api_schema=null`, `forms=[]`; đường dẫn API/JS chỉ là ứng viên, chưa có protected endpoint contract.
- Phiên 20/11 có `verified_results=[]`, `verified_parameters=[]`, `parameter_verification_status=not_checked`.

Trạng thái được lưu riêng trong [auth_verification_status.json](../output_samples/diagnostics/connection_diagnostics_20261121/auth_verification_status.json): `not_configured`, `verification_performed=false`, lý do `operator_confirmed_protected_endpoint_contract_missing`. Không kiểm thử token thật.

Sau này chỉ cấu hình auth khi có **URL bảo vệ chính xác**, **auth origin được phép**, **JSON pointer và giá trị kỳ vọng đã được phía vận hành xác nhận**, cùng log server để đối chiếu principal. Công cụ có `--bearer-prompt` và `--expect-json-pointer`; cả token lẫn giá trị JSON kỳ vọng đều nhập ẩn khi chạy, không đặt trong command line hoặc file kết quả. Chỉ HTTP200 thì vẫn `not_verified`; khớp contract chỉ là `expected_contract_matched`, vẫn yêu cầu xác nhận phía server. Không tự chạy cặp anonymous/authenticated hoặc làm mới token.

## Cách dùng

Chạy từ `D:\TieuLuan\FuzzingTool`. Lệnh sau **không gọi DNS/HTTP**, không nhập token, không tạo phiên quét:

```powershell
.\.venv\Scripts\python.exe -B scripts\run_connection_diagnostic.py --url https://cab.vn/ --allowed-origin https://cab.vn --check
```

URL `/` trong ví dụ chỉ dùng kiểm tra cấu hình kết nối, **không phải endpoint xác thực**. Chế độ mặc định cũng là check nếu không truyền `--run`.

Chỉ dùng mẫu sau ở lượt được chỉ thị chạy HTTP thật tiếp theo. Nhập endpoint GET chỉ đọc được người vận hành cho phép; không mặc định chọn auth endpoint:

```powershell
$endpoint = Read-Host 'URL GET chi doc da duoc phep'
.\.venv\Scripts\python.exe -B scripts\run_connection_diagnostic.py --url $endpoint --allowed-origin https://cab.vn --timeout-seconds 8 --run
```

Lệnh này không có bearer. Không chạy liên tục hoặc tự lặp lại khi lỗi; mỗi lần chạy là một phép đo độc lập cần được tính vào kế hoạch kiểm thử. Không có request thứ hai để kiểm tra token hay đổi IP sau lỗi.

Console hiển thị stage đang chạy và đường dẫn kết quả. Mỗi lượt có thư mục mới `output_samples/diagnostics/connection_<UTC>_<id>/`, gồm:

- `plan.json`: cấu hình công khai, giới hạn và trạng thái auth.
- `progress.jsonl`: tiến độ có giới hạn, không chứa response content/credentials.
- `result.json`: snapshot cuối, status/byte counts, stage lỗi và lý do dừng.

Mã thoát 0 khi transport/đọc body hoàn tất; **không đồng nghĩa endpoint hợp lệ hoặc token đã xác minh**. Mã 1 khi dừng/lỗi phép đo; mã 2 khi cấu hình/nhập liệu/ghi artifact lỗi.

## Đối chiếu log máy chủ

Request có header **`X-FuzzingTool-Diagnostic-ID: <UUID>`**. Chuyển cho người vận hành server: diagnostic ID, origin, timestamp UTC, endpoint đã phê duyệt và method GET. Không gửi token kèm bằng chứng.

Phía server cần ghi header này trong access log hoặc application log, kèm HTTP status, request/upstream duration và kết quả xác thực/principal nếu kiểm tra auth. Công cụ không tự cấu hình logging của server. Diagnostic ID là dữ liệu phía client, dùng để tương quan chứ không phải bằng chứng xác thực.

Nếu lỗi ở DNS/TCP/TLS, chưa có header HTTP được gửi, nên không thể đòi tìm ID trong access log. Đối chiếu cửa sổ thời gian UTC với log kết nối/TLS/edge/network phù hợp. Không có access log không tự chứng minh IP bị block. Với timeout ở headers, server có thể đã nhận request; dùng ID và thời gian để phân biệt server chưa nhận, xử lý chậm hoặc response không tới client.

## Kiểm thử và giới hạn xác minh

Các tests mới ở `tests/test_connection_diagnostic_runner.py` và `tests/test_connection_diagnostic_tls.py` dùng HTTP/TLS localhost, chứng chỉ lab có sẵn, bearer giả hoặc lỗi DNS/TCP được mock. Bao phủ stage timeout, body thiếu/cap, 401/403/429, redirect/Retry-After, scope/auth, fixed User-Agent, không dùng proxy môi trường, TLS không tin cậy, không key logging, deadline DNS/headers nhỏ giọt, credential redaction, JSON lồng sâu và giới hạn progress.

**Kết quả cuối: 104/104 PASS, 0 skipped, 24,425 giây**, gồm 17 tests mới và 87 regression tests liên quan của Recon/Fuzzing, auth, Coordinator CLI và routing Agent 4–5. Không chạy lại toàn bộ suite trong task này; mốc toàn suite trước task vẫn là 482 PASS. Kết quả tại [tests_related.log](../output_samples/diagnostics/connection_diagnostics_20261121/tests_related.log) và [verification_summary.json](../output_samples/diagnostics/connection_diagnostics_20261121/verification_summary.json).

Ba kịch bản supervisor được lưu bằng chứng độc lập ở `localhost_evidence/`: resolver bị treo được mô phỏng (0 HTTP); headers nhỏ giọt thật (server nhận 1 GET, client chưa nhận đủ headers); thành công thật (1 GET, HTTP200, 109 byte, server thấy cùng diagnostic ID, bearer chỉ là fixture giả). Các bản sao giữ `artifacts` trỏ tới thư mục tạm tại thời điểm test; dùng đường dẫn `result_copy` trong summary để mở bản lưu. CLI `--check` cho origin cab.vn đã chạy offline, kết quả [offline_check.json](../output_samples/diagnostics/connection_diagnostics_20261121/offline_check.json) ghi 0 network attempts và auth not_configured.

Lệnh tái chạy tests mới:

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:LANGCHAIN_TRACING_V2 = 'false'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_connection_diagnostic*.py' -v
```

Giới hạn còn lại: chưa chạy cab.vn; chưa xác minh bearer; chưa đối chiếu log server. Đây là probe riêng dùng cùng User-Agent và TLS verification policy, không thay thế toàn bộ transport/pipeline. Nó thử một địa chỉ DNS thay vì fallback nhiều địa chỉ như urllib; chưa ghi IP/port nguồn hoặc packet capture. Một phép đo thành công không bảo đảm khả năng kết nối ở thời điểm sau. Không tăng timeout hoặc đổi cơ chế bảo vệ để che giấu các giới hạn này.
