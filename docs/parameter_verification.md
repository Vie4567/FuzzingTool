# Kiểm chứng Parameter bằng HTTP

Module sinh tên tham số và bước kiểm chứng HTTP là hai phần riêng biệt. Kết quả
LLM, HTTP 200 của endpoint hoặc thay đổi Content-Length đơn lẻ không phải bằng
chứng một tham số hoạt động.

## Dữ liệu trả về

- `param_results`: các endpoint và tên tham số ứng viên; giữ các trường đo gốc.
  `result_kind=parameter_candidates` và `verification=not_checked` của endpoint
  không đổi chỉ vì một tham số có ảnh hưởng phản hồi.
- `parameter_candidates`: danh sách phẳng các tham số chưa xác minh, gồm tên,
  endpoint, `location=query`, method, trạng thái, lý do và bằng chứng nếu đã đo.
- `verified_parameters`: chỉ chứa tham số có ảnh hưởng HTTP lặp lại so với các
  request đối chứng. `result_kind=verified_parameter`, `verification=verified`.
- `verification_evidence`: status code, số byte thực đọc, thời gian, hash và
  request ID của baseline, đối chứng, thử nghiệm và đối chứng sau thử nghiệm.
  Không lưu response body hoặc header xác thực.
- `stats.total_requests`: mọi lần thực hiện HTTP, gồm baseline, đối chứng,
  request lặp lại và lần kết nối thất bại. Có các bộ đếm riêng cho từng loại.
  Khi lỗi bất ngờ khiến không thể xác định toàn bộ số request, agent trả `null`
  thay vì phỏng đoán.

`verification_status=completed` nghĩa là đã chạy hết lượt kiểm chứng được chọn;
không có nghĩa tất cả ứng viên đã được xác minh. `partial` đi kèm lý do dừng và
bằng chứng đã thu thập. `skipped` nghĩa không gửi request. Khi verifier lỗi bất
ngờ, agent trả `failed` cùng các ứng viên đã sinh và lỗi đã che thông tin bí mật.

## Điều kiện xác minh

Với mỗi endpoint, module gửi hai GET baseline và hai GET có tên tham số ngẫu
nhiên để kiểm tra độ ổn định. Mỗi ứng viên được thử bằng hai giá trị, mỗi giá trị
lặp hai lần. Sau đó gửi lại baseline và hai đối chứng tên ngẫu nhiên dùng đúng
hai giá trị vừa thử để loại ảnh hưởng do thời gian, session hoặc website xử lý
mọi tham số giống nhau.

Chỉ xác minh khi các phản hồi hoàn chỉnh, đều 2xx, cùng một giá trị cho kết quả
lặp lại, ít nhất một giá trị khác baseline và toàn bộ đối chứng trước/sau vẫn
khớp baseline. So sánh cả status, Content-Type và hash toàn bộ nội dung sau chuẩn
hóa có giới hạn (URL phản chiếu, nonce/CSRF, timestamp, trace ID), không dựa riêng
vào độ dài. Trang fallback trả cùng nội dung cho mọi tham số sẽ không được xác minh.

Ứng viên đầu tiên cần 11 request (3 baseline, 4 đối chứng, 4 thử nghiệm); mỗi ứng
viên tiếp theo cùng endpoint cần thêm 7. Tất cả đều nằm trong ngân sách request,
rate và thời gian của phase. Không tự retry hoặc tăng ngân sách.

Nội dung động, phản chiếu giá trị thử (kể cả HTML/URL/JSON unicode escape), chỉ có
lỗi 4xx/5xx, response nén không hỗ trợ, body bị cắt hoặc kết quả không đủ lượt đo
đều giữ trạng thái chưa kết luận. Cách làm này ưu tiên tránh báo sai, vì vậy có
thể bỏ sót tham số thật. `verified` chỉ xác minh ảnh hưởng phản hồi HTTP; không
chứng minh tác dụng nghiệp vụ, lỗ hổng hay endpoint hợp lệ sau lọc Soft404.

## Cấu hình Coordinator

```python
config = {
    "parameter_options": {
        "enabled": True,
        "rate_limit": 1,
        "timeout_seconds": 5,
        "max_requests": 60,
        "max_duration_seconds": 120,
        "max_response_bytes": 262144,
    }
}
```

Coordinator dùng `parameter_options_from_config(config, fuzzing_execution)` để
kế thừa auth, exact-origin scope và TLS của lượt fuzzing trước. Giới hạn rate
không được nhanh hơn cấu hình/runtime fuzzing. Có thể tắt bằng `enabled=False`.
Chỉ request GET/query không có body được hỗ trợ trong phiên bản này; không tự
thử POST/body, tham số nhạy cảm như token/password/action/admin/debug hoặc đường
dẫn đăng nhập, đăng xuất, xóa, thanh toán. Tham số đã có sẵn trong query được giữ
nguyên, không thay thế giá trị và không gắn nhãn là tham số ẩn mới.

Module dừng khi gặp 401/403/407/429, Retry-After, trang login/challenge, redirect,
lỗi kết nối hoặc hết ngân sách. Nếu lượt fuzzing trước đã dừng, dùng proxy không có pool cùng phiên, bind
source IP hoặc thiếu ngữ cảnh xác thực có thể tái sử dụng thì không tự chuyển
sang request trực tiếp. TLS luôn xác minh chứng chỉ; dùng `tls_ca_file` cho CA
lab riêng. Không chuyển tiếp token khi đổi origin hoặc redirect.

Với `fuzzing_options.engine="proxy_http"`, Coordinator tự chuyển pool đã hoàn
tất Fuzzing sang Parameter. Pool chỉ ở bộ nhớ runtime; không khôi phục từ JSON
và không lấy proxy mới khi kiểm chứng. Module xoay round-robin giữa endpoint,
ghim cùng proxy cho toàn bộ baseline/control/candidate/post-control của endpoint
đó. `proxy_profile_id` trong evidence và `stats.proxy_profiles` cho phép đối chiếu
tuyến, số request và độ trễ. `source_proxy_profile_id` giữ tuyến của phép đo gốc.
CONNECT lỗi được tách khỏi HTTP status của mục tiêu; không tự failover hoặc gửi
trực tiếp khi proxy lỗi. Xem [lệnh chạy có token và proxy](coordinator_auth_proxy_cli.md).

Thời gian chờ rate limit chung không tính vào `response_time`; request bị từ
chối trước dispatch vì deadline/ngân sách không làm tăng bộ đếm HTTP.

Gọi `ParamDiscoveryAgent.execute()` trực tiếp mà không truyền
`verification_options` vẫn chỉ sinh ứng viên, không gửi HTTP. Khi gọi trực tiếp
với quyền kiểm thử và chính sách mạng đã xác định, có thể truyền
`verification_options={"enabled": True, "max_requests": 20, "rate_limit": 1}`;
nếu dùng token, truyền `headers` trong cùng mapping thay vì ghi token vào code.

Timeout dùng cho kết nối và đọc body có deadline; urllib vẫn dùng timeout chờ
I/O khi nhận headers, không phải deadline cứng cho mọi kiểu server gửi headers
rất chậm. Không có bằng chứng từ lượt kiểm chứng cục bộ để kết luận về cab.vn.

## Kiểm thử cục bộ

```powershell
$env:PYTHON_DOTENV_DISABLED='1'
$env:LANGSMITH_TRACING='false'
$env:LANGCHAIN_TRACING_V2='false'
.\.venv\Scripts\python.exe -B -m unittest tests.test_parameter_verification tests.test_param_measurement_integrity -q
```

Tests chạy HTTP thật trên loopback: tham số đã biết, tham số không hoạt động,
body khác nhưng cùng độ dài, fallback, dữ liệu động, phản chiếu, đổi trạng thái
giữa lượt đo, kiểm tra đối chứng đúng giá trị, block/redirect, scope, header,
budget, lỗi transport và bảo toàn ứng viên khi verifier lỗi. Không gọi website
bên ngoài hoặc API LLM.
