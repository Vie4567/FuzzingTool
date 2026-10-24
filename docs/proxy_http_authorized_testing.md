# Xoay tuyến proxy trong phạm vi kiểm thử được phép

## Chạy trực tiếp khi chưa có proxy

Không cần cài hay cấu hình proxy để gửi request trực tiếp. Dùng `--direct` để chọn rõ chế độ này:

```powershell
.\.venv\Scripts\python.exe -B .\scripts\run_proxy_http_check.py --direct --target https://cab.vn
```

Lệnh trên gửi tối đa ba GET (`robots.txt`, `sitemap.xml`, `favicon.ico`) với một request/giây, một worker, timeout 10 giây và ngân sách phiên 45 giây; không dùng LLM hay theo redirect. Console hiện `START → RESULT → STOP` ngay khi chạy. Chế độ này bỏ qua cấu hình proxy, dùng tuyến mạng hiện tại của máy và **không xoay IP**. Status, byte body và thời gian được đo từ HTTP thật; IP công cộng giữ `null` khi chưa có phép đo độc lập. Gặp 429 hoặc ba 403 liên tiếp thì dừng.

Mỗi lần chạy lưu `progress.log`, `preflight.json`, `result.json` và `report.md` trong thư mục `output_samples/diagnostics/http_direct_check_*` được in trên console. Khi không truyền `--direct`, runner dùng proxy; mặc định là danh sách thủ công, có thể chọn `--proxy-source proxyscrape` để tải ứng viên tự động.

Chế độ `engine="proxy_http"` gửi request HTTP thật lần lượt qua các proxy HTTP trong `ProxyProfilePool`. Nguồn proxy có thể là danh sách thủ công hoặc [ProxyScrape Free Proxy List](https://proxyscrape.com/free-proxy-list). `ffuf_cli` và `python_http` vẫn dùng một proxy cố định; tính năng pool và tự cập nhật thuộc backend `proxy_http`.

Mỗi request chọn một profile theo vòng tròn: `egress-a`, `egress-b`, rồi `egress-a`. Việc chọn hai proxy chỉ tạo ra hai tuyến gửi; chúng có thể dùng chung một IP egress. Tool không suy ra IP công cộng từ hostname của proxy và không gọi dịch vụ kiểm tra IP bên ngoài. `proxy_profile_id` ghi tuyến được chọn, còn `egress_ip` là `null` khi chưa có bằng chứng từ log server hoặc phép đo độc lập.

## Cấu hình proxy và phạm vi

Chọn `engine="proxy_http"` trực tiếp trong lời gọi của người vận hành. Agent không tự bật chế độ này từ kế hoạch của LLM. Cung cấp danh sách origin chính xác trong `allowed_origins`; origin gồm scheme, hostname và port nếu khác port mặc định, không có đường dẫn hay wildcard. Ví dụ `https://cab.vn` không bao gồm `http://cab.vn`, `https://www.cab.vn` hoặc hostname khác.

Chọn `proxy_source="manual"` (mặc định) để cung cấp proxy theo một trong hai cách:

- `proxy_profiles`: danh sách `{"id": "egress-a", "url": "http://proxy-host:port"}`. URL có thể chứa username/password nếu proxy yêu cầu.
- `proxy_profiles_env`: tên biến môi trường chứa JSON danh sách trên. Cách này giữ URL và thông tin đăng nhập ngoài lời gọi agent và ngoài file được commit.

Mỗi pool có 1–8 profile với ID và endpoint riêng biệt. ID là nhãn không chứa bí mật, dài tối đa 32 ký tự gồm chữ, số, dấu chấm, gạch ngang hoặc gạch dưới. URL proxy phải có port cụ thể, không có path, query hay fragment. Chọn ít nhất hai proxy có egress khác nhau nếu thí nghiệm cần thay đổi IP nguồn thực tế.

`proxy_count` giới hạn số proxy được chọn, trong khoảng 1–8. Một profile chỉ là một tuyến proxy, chưa có luân phiên. Chế độ thủ công giữ cách chạy cũ; chỉ thực hiện kiểm tra sức khỏe trước quét khi cung cấp `proxy_healthcheck_url`. Khi bật kiểm tra này, các endpoint trùng được gộp trước khi kiểm tra; ở chế độ thủ công cũ, cấu hình endpoint trùng vẫn bị từ chối. Nếu dùng runner với hai proxy và muốn kiểm tra đủ ba path sau đó, cần ít nhất `--max-requests 5` để chứa cả hai request kiểm tra proxy.

Ví dụ cấu trúc JSON của `FUZZ_PROXY_PROFILES` (thay endpoint mẫu bằng proxy của bạn):

```json
[
  {"id": "egress-a", "url": "http://proxy-a.example:3128"},
  {"id": "egress-b", "url": "http://proxy-b.example:3128"}
]
```

Chỉ hỗ trợ endpoint proxy có scheme `http://`. Đích HTTPS dùng phương thức CONNECT qua proxy rồi xác thực chứng chỉ TLS của server đích. `https://` cho chính endpoint proxy và SOCKS không được hỗ trợ trong backend này. Không tắt xác thực TLS để chạy thí nghiệm.

Đối với proxy có thông tin đăng nhập, dùng một kênh mạng được kiểm soát: kết nối đến endpoint proxy HTTP không được mã hóa. Không đưa URL chứa mật khẩu vào báo cáo, prompt hay log chia sẻ. Tool chỉ công bố ID profile trong các kết quả đo.

## Tự động lấy proxy từ ProxyScrape

Chạy tại thư mục dự án:

```powershell
.\.venv\Scripts\python.exe -B .\scripts\run_proxy_http_check.py --target https://cab.vn --proxy-source proxyscrape --proxy-count 3 --proxy-candidate-limit 20 --proxy-check-timeout 5 --proxy-fetch-timeout 10 --proxy-refresh-seconds 300 --max-requests 23 --max-scan-seconds 120
```

Chế độ này không cần `FUZZ_PROXY_PROFILES` và không đọc thông tin đăng nhập proxy thủ công. Backend tải danh sách HTTP từ API của ProxyScrape, chuẩn hóa địa chỉ, bỏ dòng sai và proxy trùng, rồi kiểm tra ứng viên qua HTTP trước khi đưa vào pool. Cách xử lý danh sách dựa trên [import_proxyscrape_candidates.py](../import_proxyscrape_candidates.py); chạy importer riêng chỉ tạo danh sách ứng viên, còn engine thực hiện kiểm tra hoạt động và quản lý vòng đời pool.

URL kiểm tra mặc định là `<origin>/robots.txt`, ví dụ `https://cab.vn/robots.txt`. Có thể dùng `--proxy-healthcheck-url https://cab.vn/health` nếu có endpoint kiểm tra phù hợp. URL phải nằm trong `allowed_origins`; không tự gọi dịch vụ đo IP ngoài phạm vi. Request kiểm tra dùng GET, không kèm token hoặc body của request fuzzing. Proxy chỉ đạt kiểm tra khi nhận HTTP 2xx, đọc đầy đủ body trong giới hạn cấu hình và không có lỗi transport. Vì vậy nên chọn một URL công khai có phản hồi 2xx đã biết; 404, redirect hoặc body vượt giới hạn đều không đạt. Kết quả đạt xác nhận khả năng nhận phản hồi tại thời điểm kiểm tra, không xác nhận IP đầu ra duy nhất hoặc nội dung response là endpoint hợp lệ.

Pool hoạt động chỉ chứa các proxy đã vượt qua kiểm tra; snapshot vẫn giữ trạng thái ứng viên đang chờ hoặc đã bị loại để đối chiếu. Fuzzing chọn profile theo Round-Robin. Refresh được xem xét giữa các request, theo `proxy_refresh_seconds`; `0` tắt cập nhật định kỳ. Proxy đã bị loại vì lỗi trong phiên không được đưa trở lại khi refresh. Khi hết proxy hoạt động, tool kết thúc với lý do và kết quả đã thu thập, không tự kết nối trực tiếp.

| Tùy chọn engine | Tham số runner | Mặc định / phạm vi |
| --- | --- | --- |
| `proxy_source` | `--proxy-source` | `manual` hoặc `proxyscrape`; mặc định `manual` |
| `proxy_count` | `--proxy-count` | Tự động: 2; thủ công: toàn bộ profile; trong khoảng 1–8 |
| `proxy_candidate_limit` | `--proxy-candidate-limit` | 20; trong khoảng 1–100 ứng viên mỗi lần tải |
| `proxy_check_timeout_seconds` | `--proxy-check-timeout` | 5 giây; 0,01–30 |
| `proxy_fetch_timeout_seconds` | `--proxy-fetch-timeout` | 10 giây; 0,01–30 |
| `proxy_refresh_seconds` | `--proxy-refresh-seconds` | Tự động: 300 giây; 0 hoặc 30–86.400 |
| `proxy_healthcheck_url` | `--proxy-healthcheck-url` | Tự động: `<origin>/robots.txt`; thủ công: không kiểm tra nếu bỏ qua |

Proxy miễn phí có thể ngừng hoạt động hoặc thay đổi chất lượng bất kỳ lúc nào. Một lần kiểm tra đạt không chứng minh proxy an toàn, ổn định lâu dài hay có IP đầu ra khác các proxy còn lại. HTTPS vẫn xác thực chứng chỉ server đích; log công khai ghi ID profile thay vì URL và thông tin đăng nhập proxy.

## Ví dụ gọi agent

Ví dụ dưới đây áp dụng `cab.vn` theo phạm vi mà người vận hành đã xác nhận được phép kiểm thử. Tài liệu và bộ test không chạy website này. Trước khi chạy thực tế, cấp biến `FUZZ_PROXY_PROFILES` cho process từ cấu hình môi trường hoặc kho bí mật của bạn; không ghi giá trị thật vào source, `.env.example` hay báo cáo. Giá trị biến phải là một mảng JSON gồm các profile `id`/`url` như mô tả ở trên.

Chạy tại thư mục dự án bằng PowerShell:

```powershell
@'
import json
import os
from src.agents.fuzzer import FuzzingAgent

if not os.environ.get("FUZZ_PROXY_PROFILES"):
    raise SystemExit("Cần cấp FUZZ_PROXY_PROFILES từ môi trường trước khi chạy")

result = FuzzingAgent(llm=None).execute(
    target_url="https://cab.vn",
    wordlist=["robots.txt", "sitemap.xml", "favicon.ico"],
    use_pattern_engine=False,
    engine="proxy_http",
    proxy_profiles_env="FUZZ_PROXY_PROFILES",
    allowed_origins=["https://cab.vn"],
    threads=1,
    rate_limit=2,
    delay_ms=500,
    max_requests=3,
    timeout_seconds=10,
    max_scan_seconds=120,
)
print(json.dumps(result, ensure_ascii=False, indent=2))
'@ | .\.venv\Scripts\python.exe -B -
```

`llm=None` giúp ví dụ chạy transport mà không gửi dữ liệu đến LLM. Các path trong `wordlist` phải nằm trong phạm vi được cho phép. Có thể dùng URL đích có `FUZZ` ở path hoặc query; origin sau khi thay thế vẫn phải khớp danh sách cho phép. Không tự theo redirect hay quét đệ quy sang phạm vi khác.

Để gọi tự động từ Python, thay `proxy_profiles_env="FUZZ_PROXY_PROFILES"` bằng `proxy_source="proxyscrape", proxy_count=3, proxy_candidate_limit=20`, giữ `allowed_origins` và nâng ngân sách `max_requests` lên 23 để bao gồm các lần kiểm tra proxy. Các tham số ProxyScrape truyền trực tiếp vào cùng `FuzzingAgent.execute`; không cần sửa các module recon hay LLM.

## Tải gửi và điều kiện dừng

Các giới hạn engine áp dụng cho toàn phiên, gộp mọi profile và mọi request kiểm tra proxy lẫn fuzzing:

| Tùy chọn | Mặc định | Giới hạn |
| --- | --- | --- |
| `threads` | 1 | 1 worker |
| `rate_limit` | 2 request/giây | Tối đa 10 request/giây |
| `delay_ms` | 500 ms | Khoảng nghỉ theo cấu hình |
| `max_requests` | 100 | Tối đa 1.000 |
| `timeout_seconds` | 10 giây | Tối đa 30 giây |
| `max_scan_seconds` | 120 giây | Tối đa 600 giây |

Ngân sách thời gian bao gồm cả thời gian tải danh sách ProxyScrape, chờ giữa các request, kiểm tra proxy và fuzzing. Số request tải danh sách được ghi riêng trong `stats.proxy_source_fetches`; giới hạn `max_requests` và tốc độ gửi tới mục tiêu gộp request kiểm tra proxy với request fuzzing. Ngân sách thời gian được kiểm tra quanh thao tác socket. Đây là giới hạn thực thi theo khả năng, không phải cơ chế hủy socket cứng tại đúng thời điểm hết ngân sách; server hoặc proxy gửi dữ liệu nhỏ giọt có thể kéo dài thao tác đang chờ. Hạn chế này cũng áp dụng cho bước tải danh sách: timeout là thời gian socket bất hoạt, không phải thời hạn tuyệt đối cho toàn bộ response.

Runner ngắn giữ một worker và một request/giây. Mặc định thủ công/trực tiếp có ngân sách 3 request và 45 giây; tự động có ngân sách 23 request và 120 giây, trong đó một phần dùng để kiểm tra proxy trước ba path fuzzing cố định. Có thể đặt `--max-requests`, `--timeout-seconds` và `--max-scan-seconds` trong giới hạn engine. Tăng số proxy không tăng tốc độ gửi toàn phiên. Hết ngân sách trong giai đoạn kiểm tra có thể khiến chưa gửi được request fuzzing nào; `health_checks` và các bộ đếm ghi rõ tình huống này.

HTTP 429 đầu tiên hoặc ba HTTP 403 liên tiếp trong fuzzing dừng toàn bộ phiên. Khi mới nhận 403, các request tiếp theo giữ cùng profile cho tới khi hết chuỗi 403 hoặc chạm ngưỡng dừng, không chuyển tuyến để thử vượt chặn. HTTP 407 hoặc lỗi transport khi fuzzing cũng dừng toàn phiên; proxy lỗi bị ghi nhận và loại khỏi pool, không thử lại path qua proxy khác. `Retry-After`, nếu có, được ghi nhận để người vận hành phối hợp lịch kiểm thử. Refresh không khởi động lại phiên đã dừng và không được dùng để vượt giới hạn truy cập.

Trong bước kiểm tra sức khỏe, lỗi kết nối khiến ứng viên bị loại và engine có thể kiểm tra ứng viên tiếp theo trong cùng ngân sách. Nếu bước này nhận HTTP 403/429/407 thì dừng toàn phiên, không thử proxy khác. Lý do dừng tương ứng là `proxy_healthcheck_http_403`, `rate_limited_429` hoặc `proxy_authentication_required`. Kiểm tra sức khỏe và fuzzing dùng chung tốc độ, thời gian và số request tối đa.

## Đối chiếu kết quả cho tiểu luận

Giữ JSON kết quả, ID profile, số request/response thực tế và log server trong cùng thời gian thí nghiệm. Đối chiếu `proxy_profile_id` với IP nguồn mà server đích thực sự ghi nhận. Hai tuyến chỉ được kết luận có egress khác nhau sau khi có bằng chứng này; giữ nguyên `egress_ip=null` nếu chưa quan sát được.

Status, số byte body và thời gian được lấy từ response thật; lỗi kết nối không được thay bằng số liệu thành công giả. HTTP 200 hoặc IP nguồn thay đổi không chứng minh có lỗ hổng. Bộ test cho backend dùng server/proxy localhost để kiểm tra đường đi request, giới hạn origin, số liệu và điều kiện dừng mà không gửi request đến `cab.vn`.

Thí nghiệm không cần proxy Internet có thể dùng [chế độ loopback](loopback_ip_rotation_lab.md).

## Chạy kiểm tra ngắn và quan sát trực tiếp

Runner sau gửi tối đa ba GET tới `robots.txt`, `sitemap.xml` và `favicon.ico`, ở tốc độ chung một request/giây, timeout 10 giây và ngân sách phiên 45 giây. Runner không dùng LLM. Chỉ chạy với origin và đường dẫn nằm trong phạm vi đã được phép:

```powershell
.\.venv\Scripts\python.exe -B .\scripts\run_proxy_http_check.py --target https://cab.vn
```

Ở chế độ thủ công mặc định, runner lấy `FUZZ_PROXY_PROFILES` từ process; nếu key này chưa có trong process thì đọc riêng giá trị đó từ `.env` của dự án, không nạp các key khác và không nội suy biến. Cần ít nhất hai profile hợp lệ, có endpoint khác nhau; dùng rõ `--proxy-count 1` nếu chỉ kiểm tra một proxy. Nếu cấu hình thiếu hoặc sai, runner dừng trước kết nối mạng, ghi `requests_sent=0` và trả exit code 2. Để tải danh sách tự động, chọn rõ `--proxy-source proxyscrape` như phần trên. Chế độ proxy không chuyển sang kết nối trực tiếp khi lỗi.

Console hiện từng sự kiện `START`, `RESULT` và `STOP` trong lúc transport chạy. Khi quản lý pool, có thêm sự kiện tải danh sách `POOL`, kiểm tra ứng viên `PROXY_CHECK` và thống kê cuối phiên `PROXY` theo từng ID. Mỗi phiên tạo thư mục riêng dưới `output_samples/diagnostics/proxy_http_check_*`, in đường dẫn để mở trong IDE và lưu:

- `progress.log`: tiến trình và thống kê proxy giống trên console, chỉ chứa ID profile thay cho URL proxy.
- `preflight.json`: trạng thái kiểm tra cấu hình, nguồn proxy, origin và ID profile. Với ProxyScrape, `ready` chỉ xác nhận cấu hình hợp lệ; danh sách rỗng trước khi tải là bình thường.
- `result.json`: số liệu HTTP, lỗi và lý do dừng; `results` chứa request fuzzing, `health_checks` chứa kiểm tra proxy, `proxy_pool` chứa trạng thái pool và `proxy_refresh_events` chứa kết quả từng lần tải danh sách.
- `report.md`: bảng kết quả ngắn để đối chiếu với access log phía server.

Có thể theo dõi file từ terminal PowerShell thứ hai bằng đường dẫn thư mục mà runner đã in:

```powershell
Get-Content -LiteralPath "output_samples\diagnostics\<thư-mục-phiên>\progress.log" -Wait
```

`egress_ip` vẫn là `null` nếu chưa đối chiếu IP nguồn trong log server đích. Việc thấy các ID profile luân phiên chỉ xác nhận lựa chọn tuyến; chưa chứng minh IP công cộng đã thay đổi. Lỗi proxy, 429 hoặc ba 403 liên tiếp dừng toàn phiên trước khi dùng tuyến tiếp theo.

Đánh giá hiệu năng bằng `stats.proxy_profiles`: số request/response, thời gian và tỷ lệ lỗi theo ID proxy. `error_rate` là số lần gặp lỗi mạng hoặc HTTP từ 400 trở lên chia tổng request; `avg_response_time` là thời gian trung bình của mọi lần thử, gồm cả timeout, và là `null` khi chưa có request. `stats.total_requests` gộp `healthcheck_requests` và `fuzzing_requests`; không tính các request tải danh sách gửi tới ProxyScrape thành request fuzzing của website. Không xem thời gian kiểm tra proxy là thời gian dò endpoint. Các phép đo lỗi kết nối giữ status/body length không có giá trị HTTP thay vì điền số liệu giả.

## Nhập proxy vào cấu hình cục bộ

Khi đã có ít nhất hai proxy HTTP của bạn, chạy helper trong terminal tại thư mục dự án:

```powershell
.\.venv\Scripts\python.exe -B .\scripts\configure_proxy_profiles.py --target https://cab.vn
```

Helper yêu cầu nhập URL cho `egress-a` và `egress-b`, có dạng `http://host:port` hoặc URL có thông tin đăng nhập nếu proxy yêu cầu. Nội dung nhập được ẩn; không cần dán URL chứa mật khẩu vào chat hay câu lệnh. Có thể chọn `--profiles 3` đến `--profiles 8` nếu có thêm proxy.

Helper chỉ kiểm tra cấu trúc endpoint, sự khác nhau của endpoint và origin; không kết nối mạng, không tạo proxy và chưa xác nhận proxy đang hoạt động hoặc có IP đầu ra khác nhau. Khi hợp lệ, helper lưu riêng `FUZZ_PROXY_PROFILES` vào `.env`, giữ các cấu hình khác và in lệnh chạy kiểm tra ngắn. Cấu hình sai hoặc hủy nhập sẽ không ghi file. Sau đó dùng runner ở phần trên để quan sát các request thật.
