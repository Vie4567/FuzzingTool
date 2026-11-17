# Lọc Soft404 bằng phản hồi HTTP thực

HTTP 200 chỉ là mã trạng thái. Nhiều URL cùng dài 2.219 byte có thể cùng trả
trang fallback, trang đăng nhập hoặc bộ khung SPA. Kích thước bằng nhau không
đủ chứng minh chúng tồn tại hoặc không tồn tại.

## Phép kiểm tra

`Soft404FilterAgent` dùng `src/tools/soft404.py`, không nhờ LLM quyết định:

1. Chỉ kiểm chứng ứng viên GET có phản hồi thực; bỏ qua số liệu giả lập, lỗi,
   body không đầy đủ và danh sách tham số chỉ mới được suy đoán.
2. Tạo mặc định ba URL ngẫu nhiên khó tồn tại, cùng origin, thư mục và kiểu
   phần mở rộng với ứng viên. Dùng cùng header xác thực và cùng chính sách TLS.
3. Tải lại ứng viên; so sánh status, byte thực đọc, fingerprint nội dung và
   độ tương đồng của nội dung đã chuẩn hóa với nhiều mẫu tham chiếu.
4. Chỉ phân loại khi baseline ổn định. Độ dài là tín hiệu phụ; không tự động
   loại cả nhóm chỉ vì cùng số byte.

Kết quả:

| Danh sách | Ý nghĩa |
| --- | --- |
| `verified` / `verified_results` | Phản hồi thành công khác biệt rõ với baseline; đã qua phép lọc HTTP Soft404. |
| `false_positives` | Phản hồi khớp fallback (`soft_404`) hoặc có bằng chứng HTTP 404/410 (`http_404`). |
| `unverified` / `unverified_results` | Chưa đủ bằng chứng: baseline không ổn định, vùng tương đồng không rõ ràng, login/challenge, redirect, lỗi, giới hạn hoặc không hỗ trợ ngữ cảnh request. |

`genuine` không chứng minh chức năng ứng dụng hoạt động, tham số tồn tại hay có
lỗ hổng. Một route SPA hợp lệ cũng có thể trả cùng app shell với URL không tồn
tại. Homepage trùng shell được giữ chưa xác minh, không tự loại homepage.
Muốn xác nhận route phía trình duyệt cần kiểm tra thêm router/JavaScript.

Với nội dung dài vượt giới hạn so sánh chi tiết, chỉ fingerprint khớp toàn bộ
mới đủ cơ sở kết luận trùng fallback; mẫu đầu/cuối giống nhau không đủ. Những
khác biệt chưa được so sánh đầy đủ được giữ chưa xác minh.

Số liệu gốc `status_code`, `content_length`, `response_time` được giữ nguyên.
Số liệu tải lại nằm trong `verification_evidence`; baseline lưu fingerprint,
hash và phép đo, không lưu body thô hoặc giá trị credential.
`equal_length_signals` chỉ là thống kê nghi vấn, không phải nhãn phân loại.

## Cấu hình Coordinator

```python
config = {
    "fuzzing_options": {
        "headers": {"Authorization": "Bearer " + token},
        "rate_limit": 1,
    },
    "soft404_options": {
        "enabled": True,
        "baseline_samples": 3,
        "max_requests": 60,
        "max_duration_seconds": 120,
        "timeout_seconds": 5,
        "max_response_bytes": 262144,
        "rate_limit": 1,
        "similarity_threshold": 0.97,
        "distinct_threshold": 0.80,
    },
}
```

Ngân sách trên dành riêng cho bước kiểm chứng, bao gồm cả baseline và tải lại
ứng viên. Coordinator cộng số request thực vào tổng nếu tổng trước đó đã biết.
Tốc độ của bước lọc không được cao hơn tốc độ/delay đã cấu hình cho fuzzing.
Khi hết ngân sách, các kết quả còn lại nằm trong `unverified`.

Giới hạn thời gian được kiểm tra trước request và giữa các lần đọc body.
Giai đoạn kết nối/đọc header dùng timeout của urllib; đây chưa phải deadline
cứng cho trường hợp server cố tình kéo dài header bằng từng byte nhỏ.

Header của fuzzing được ưu tiên để giữ đúng ngữ cảnh xác thực. Có thể đặt
`headers`, `cookie`, `bearer_token`, `allowed_origins`, `auth_origins`,
`tls_ca_file` trong `soft404_options` khi cần cấu hình riêng. Nếu không có,
phạm vi/TLS kế thừa cấu hình Recon. Xem [auth, scope và TLS](recon_auth_scope_tls.md).
`verify_ssl=False` không được hỗ trợ; redirect không tự động được theo.

## Các trường hợp không gửi thêm request

- `enabled=False` hoặc không có ứng viên phù hợp.
- Lượt fuzzing trước đã dừng do giới hạn, bị chặn, lỗi hoặc trả kết quả một phần.
- Nguồn là giả lập; ngữ cảnh auto-login không có credential tái sử dụng.
- Lượt trước dùng proxy cố định/source-bound, hoặc `proxy_http` không có pool
  đã hoàn tất Fuzzing trong cùng runtime/cấu hình.
  Bộ lọc giữ kết quả chưa xác minh, không tự chuyển sang kết nối trực tiếp.

`proxy_http` trong Coordinator được hỗ trợ: bộ lọc dùng lại pool của Fuzzing và
xoay giữa endpoint. Baseline và candidate trong cùng nhóm giữ một proxy;
baseline cache được tách theo profile để không so sánh nhầm trang fallback khác
nhau theo IP. Pool không được refresh khi kiểm chứng. `proxy_profile_id` có trong
baseline/evidence, `stats.proxy_profiles` có số request, độ trễ và tỷ lệ lỗi.
CONNECT status được ghi riêng, không thay thế status của website. Thời gian chờ
rate limit không nằm trong `response_time`, và request chưa dispatch không được
đếm khi hết deadline/ngân sách. Xem [lệnh chạy Coordinator](coordinator_auth_proxy_cli.md).

Khi đang kiểm chứng, gặp dấu hiệu chặn, 401/403/407/429, `Retry-After`, lỗi mạng
hoặc hết ngân sách thì dừng request tiếp theo. Không xoay proxy hoặc retry để
vượt qua điều kiện dừng. Thay đổi cấu hình do LLM đề xuất không mở rộng scope,
thay credential hoặc mở lại bước lọc sau khi lượt quét bị chặn.

FuzzingAgent lưu thêm `verification_context` công khai: loại đường kết nối,
method, rate/delay thực dùng và việc header có khớp cấu hình người chạy hay
không. Không lưu giá trị credential ở trường này. Coordinator dùng ngữ cảnh
này để tránh tải lại sai route hoặc nhanh hơn lượt fuzzing. Kết quả cũ không
có ngữ cảnh, route chưa biết, header bị kế hoạch thay đổi hoặc request không
phải GET sẽ được giữ chưa xác minh, không tự chuyển thành GET trực tiếp.

## Nhóm 18 phản hồi cũ trên cab.vn

Nguồn: `output_samples/diagnostics/cab_vn_full_proxy_authenticated_20261024/`.
18 phản hồi 2.219 byte nằm trong telemetry **Recon**, bao gồm homepage; artifact
không có body, hash hay baseline. Bước fuzzing của lượt đó dừng ở proxy CONNECT
403 trước khi gửi request fuzzing đến đích. Không thể phân loại lại 18 phản hồi
đó chỉ từ file metadata, cũng không tự chạy lại traffic sau điều kiện dừng này.

## Kiểm thử

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:LANGCHAIN_TRACING_V2 = 'false'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_soft404*.py' -v
```

Test dùng máy chủ HTTP/HTTPS localhost và credential giả: fallback 2.219 byte,
trang thật cùng độ dài, 404 thường, nội dung động, auth, scope, TLS, redirect,
lỗi/giới hạn và việc giữ nguyên phép đo gốc.
