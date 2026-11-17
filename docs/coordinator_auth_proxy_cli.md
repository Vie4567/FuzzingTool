# Chạy Coordinator với token và lựa chọn tuyến HTTP

Mặc định runner dùng `python_http` trực tiếp, không lấy danh sách proxy và không xoay proxy. Lựa chọn này cho phép Coordinator kiểm soát từng dispatch trong ngân sách HTTP chung. Proxy chỉ bật khi người chạy chọn rõ `--proxy-source manual` hoặc `proxyscrape`.

Kiểm tra cấu hình cục bộ, không hỏi hoặc dùng access token, không gửi HTTP/LLM:

```powershell
.\.venv\Scripts\python.exe -B -u .\scripts\run_coordinator_scan.py --target https://cab.vn --proxy-source none --http-max-requests 200 --http-rate-limit 0.5 --max-wordlist-entries 6 --max-retries 0 --pipeline-timeout 1200 --llm-timeout 120 --check
```

Khi đã sẵn sàng thực hiện phiên nghiệm thu thật, chạy cùng cấu hình và bỏ `--check`:

```powershell
.\.venv\Scripts\python.exe -B -u .\scripts\run_coordinator_scan.py --target https://cab.vn --proxy-source none --http-max-requests 200 --http-rate-limit 0.5 --max-wordlist-entries 6 --max-retries 0 --pipeline-timeout 1200 --llm-timeout 120
```

Lệnh thứ hai gửi HTTP thật và gọi LLM thật. Nhập token mới còn hiệu lực ở prompt ẩn. Không đặt token trong command history hoặc source. Các Agent cần HTTP (Recon, Fuzzing, Parameter, Soft404) nhận cùng credentials; Agent Wordlist không nhận Authorization. Scope và auth origin trong runner đều là đúng origin mục tiêu (`https://cab.vn`); không tự mở rộng sang `www` hay subdomain API và không theo redirect. Recon không gửi credentials trong TRACE.

Ngân sách 200 tính chung mọi dispatch mục tiêu, tốc độ tối đa 0,5 request/giây; 6 là số ứng viên được chọn, không phải tổng request của pipeline. HTTP timeout 8 giây; LLM tối đa 60 calls, 8.192 output tokens/call; SDK không tự retry. Giới hạn phase riêng vẫn áp dụng. `max-retries=0` tắt việc Coordinator chạy lại module. Ngân sách thấp có thể khiến phiên `partial` trước khi đủ năm Agent; không tăng hoặc bỏ giới hạn tự động.

`--check` chỉ xác minh cấu hình và khả năng import, không xác nhận API key/model/token hoạt động, quyền truy cập hoặc IP có bị chặn. Chưa hỗ trợ refresh token tự động: HTTP 401/403/407/429 hoặc `Retry-After` dừng runtime và lưu kết quả đã đo. 401 không tự chứng minh token hết hạn; cũng có thể sai audience hoặc cơ chế auth. HTTP 200 trên trang công khai không chứng minh đăng nhập thành công.

Điều kiện nghiệm thu đủ pipeline: `pipeline_status="completed"`, `all_modules_executed=true`, `all_modules_successful=true`, năm trạng thái Agent là `success`, telemetry không unknown, và có dữ liệu kiểm chứng Parameter/Soft404 phù hợp. `run_all_modules=True` không bỏ qua stop guards hay ép tạo kết quả khi thiếu ứng viên. Core Report ghi vào JSON/checkpoints, không bảo đảm có `report.md` tự động.

Không chọn engine `auto`/ffuf cho kiểm chứng budget nghiêm ngặt: ffuf có thể có request nội bộ không quan sát được, attempted count có thể `null`.

## Proxy chỉ khi được chọn rõ

Từ PowerShell tại thư mục project:

```powershell
cd D:\TieuLuan\FuzzingTool
.\.venv\Scripts\python.exe -B -u .\scripts\run_coordinator_scan.py --target https://cab.vn --proxy-source proxyscrape --proxy-count 2 --proxy-refresh-seconds 300
```

Khi hiện `Access token (hidden):`, dán access token còn hiệu lực rồi Enter. Ký tự không hiển thị. Có thể dán token trần hoặc `Bearer <token>`; không dán cả `Authorization:`. Runner không nhận token qua tham số dòng lệnh và không lưu token vào file cấu hình. Nó đọc `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `LLM_MODEL` từ `.env`/biến môi trường hiện có để gọi DeepSeek thật.

Thêm `--check` để chỉ validate cấu hình trên máy; bước này không hỏi token, không gửi HTTP hoặc gọi LLM.

Chế độ proxy thủ công đọc `FUZZ_PROXY_PROFILES` từ `.env`/biến môi trường:

```powershell
.\.venv\Scripts\python.exe -B -u .\scripts\run_coordinator_scan.py --target https://cab.vn --proxy-source manual --proxy-count 2
```

Nếu cần nhập proxy thủ công lần đầu, dùng `scripts/configure_proxy_profiles.py --target https://cab.vn`. Tham khảo [cấu hình proxy](proxy_http_authorized_testing.md).

Runner gọi `run_pipeline_supervised()` với `run_all_modules=True`, dùng agent và LLM thật, giữ giới hạn 1 request/giây, 350 dispatch HTTP toàn pipeline, 40 request Fuzzing (gồm kiểm tra proxy), deadline 1.200 giây. Mặc định chọn tối đa 12 đường dẫn: `/robots.txt`, `/sitemap.xml`, rồi wordlist LLM sinh ra. `--max-wordlist-entries` thay đổi số đường dẫn được chọn nhưng không tăng các ngân sách HTTP. `--llm-timeout`, `--pipeline-timeout`, `--proxy-check-timeout` nhận số giây. `--proxy-refresh-seconds 300` làm mới khi Fuzzing còn chạy và đến hạn; không đảm bảo lượt ngắn sẽ có lần làm mới thứ hai.

Console hiện tiến trình các agent; chế độ proxy thêm `POOL`, `PROXY_CHECK`, `START`, `RESULT`, `STOP`. Thư mục riêng `output_samples/diagnostics/coordinator_auth_<UTC timestamp>_<id>/` được in ở dòng `Artifacts:`; đường dẫn kết quả cuối được in ở `Result:`. Bên trong có kết quả/checkpoint của supervisor, log agent trong thư mục worker và `llm_responses.jsonl`. Kiểm tra `pipeline_status`, `agent_statuses`, `all_modules_successful`, số đo và lý do dừng; mã thoát 1 biểu thị chưa hoàn tất thành công toàn bộ module.

**Tuyến proxy:** Fuzzing (`proxy_http`, không gọi ffuf CLI), Parameter và Soft404 dùng chung pool trong một phiên Coordinator. Sau Fuzzing thành công, Parameter xoay giữa endpoint, Soft404 xoay giữa nhóm kiểm chứng của từng endpoint. Baseline, control và candidate thuộc cùng nhóm được ghim vào một proxy để không nhầm khác biệt theo IP với tham số hợp lệ hoặc Soft404. Evidence ghi `proxy_profile_id`; baseline Soft404 được tách theo profile. Recon vẫn kết nối trực tiếp với cùng token và scope.

Parameter/Soft404 dùng lại pool khỏe sau Fuzzing, không lấy danh sách hoặc kiểm tra proxy mới trong giai đoạn kiểm chứng. Cấu hình refresh áp dụng trong Fuzzing; thành viên pool được giữ ổn định khi kiểm chứng. Nếu không có pool cùng phiên/cấu hình, hai module giữ `verification_route_unavailable`, không chuyển sang kết nối trực tiếp. Fuzzing dừng/lỗi thì bước kiểm chứng vẫn bị chặn; `run_all_modules=True` không bỏ qua điều kiện này.

Log thêm `VERIFY_ROUTE profile=...`, `Parameter RESULT profile=...`, `Soft404 RESULT profile=...`. Trong `result.json`, xem `parameter_stats.proxy_profiles`, `soft404_stats.proxy_profiles` để đối chiếu số request, response time và tỷ lệ lỗi mỗi proxy. CONNECT lỗi được ghi riêng ở `proxy_connect_status`, không dùng làm status của website. Bộ đếm phase chỉ tính request thực sự dispatch; ngân sách HTTP toàn pipeline vẫn dùng chung. Pool/credentials chỉ ở bộ nhớ phiên, không được đưa vào checkpoint; không khôi phục tuyến proxy từ JSON cũ.

Pool cần ít nhất hai proxy khỏe mới có thể luân phiên; các profile khác nhau chưa chứng minh IP công khai đầu ra khác nhau. Healthcheck không gửi token. TLS được xác minh, scope chỉ gồm origin mục tiêu, không theo redirect. Coordinator dừng khi nhận 401/403/407/429 hoặc `Retry-After`; lỗi transport Fuzzing cũng có thể dừng sớm. Không dùng proxy tiếp theo để thử vượt các điều kiện dừng này.
