# Auth, phạm vi origin và TLS của Recon

Coordinator truyền cấu hình của người chạy vào `TechReconAgent` qua
`config["recon_options"]`. Cả bảy kênh Recon và quá trình auto-login dùng
`ScopedReconTransport`: homepage, JavaScript, spider, probe file, API schema,
error probe và probe backend phát hiện từ JavaScript đều chịu cùng chính sách.

## Cấu hình Coordinator

```python
from getpass import getpass
from src.coordinator import run_pipeline

target = "https://web.lab.example"
token = getpass("Access token: ").strip()
if not token:
    raise SystemExit("Access token is required")

result = run_pipeline(target, config={
    "recon_options": {
        "bearer_token": token,
        "allowed_origins": [target],
        "auth_origins": [target],
        "verify_ssl": True,
    },
})
```

Đây là cấu hình xác thực **cho Recon**. Các module khác tiếp tục dùng cấu hình
của chúng; thay đổi này không bổ sung khả năng xác thực cho module chưa hỗ trợ.
`run_pipeline` vẫn chạy pipeline với các module/LLM theo cấu hình hiện có.

Các trường được hỗ trợ:

| Trường | Ý nghĩa |
| --- | --- |
| `bearer_token` | Token thô; transport thêm tiền tố `Bearer `. |
| `cookie` | Giá trị header Cookie do người chạy cung cấp. |
| `headers` | Header bổ sung, ví dụ `Authorization`, `X-Api-Key`. |
| `account` | `username`, `password`, tùy chọn `login_url` cho auto-login. |
| `allowed_origins` | Danh sách origin được gửi request; mặc định chỉ origin mục tiêu. |
| `auth_origins` | Danh sách origin được nhận credential; mặc định chỉ origin mục tiêu. |
| `verify_ssl` | Mặc định `True`. `False` bị từ chối trước khi gửi request. |
| `tls_ca_file` | Đường dẫn PEM CA tin cậy của lab nếu dùng CA riêng. |

`token` là alias của `bearer_token`; `custom_headers` là alias của `headers`.
Khi cùng có alias và tên chính, tên chính được ưu tiên.
Thứ tự ưu tiên theo từng trường: `recon_options` → config cấp ngoài →
`fuzzing_options.headers` / `fuzzing_options.allowed_origins` cũ.
Các tùy chọn proxy, engine và thay đổi cấu hình do LLM đề xuất không được dùng
để mở rộng phạm vi, thay credential hoặc tắt TLS của Recon.

## Phân biệt phạm vi mạng và phạm vi gửi credential

Origin được xác định bằng **scheme + hostname + port**. Không hỗ trợ wildcard;
`https://web.lab.example` khác `http://web.lab.example` và khác cổng `8443`.
Đây là giới hạn theo origin, không phải theo tiền tố đường dẫn.

`auth_origins` phải là tập con của `allowed_origins`. Ví dụ muốn Recon thăm dò
backend riêng nhưng chỉ gửi token tới frontend:

```python
recon_options = {
    "headers": {"Authorization": "Bearer " + token},
    "allowed_origins": ["https://web.lab.example", "https://api.lab.example"],
    "auth_origins": ["https://web.lab.example"],
}
```

Chỉ thêm backend vào `auth_origins` khi credential đó được phép gửi đến backend.
URL backend phát hiện từ JavaScript ngoài `allowed_origins` được ghi nhận với
`skipped_reason="outside_allowed_origins"`, không tự động gọi đến.

Redirect không được tự động theo, kể cả redirect cùng origin hoặc HTTP → HTTPS.
Sử dụng URL đích cuối cùng trong cấu hình. Header xác thực luôn được bỏ khỏi
request TRACE vì phương thức này có thể phản chiếu request.
Recon bỏ qua proxy từ môi trường; cấu hình `proxy_http` của fuzzing không tự
động áp dụng sang Recon.

## TLS và auto-login

TLS kiểm tra cả chuỗi chứng chỉ và hostname. Nếu lab dùng CA riêng, truyền
`tls_ca_file`; không dùng `verify_ssl=False`. Chứng chỉ không tin cậy làm request
thất bại, không tự thử lại bằng kết nối bỏ kiểm tra chứng chỉ.

Auto-login cũng dùng phạm vi và CA của Recon, bao gồm tải form, tải script tìm
login và gửi username/password. Form action ngoài `auth_origins` bị chặn trước
khi gửi credential. Nếu không lấy được cookie/token, Recon báo lỗi xác thực
thay vì âm thầm tiếp tục dưới trạng thái chưa đăng nhập. Luồng SSO hoặc login
cần tự theo redirect chưa được hỗ trợ; có thể cung cấp cookie/token đã lấy.

Một `AuthManager` được gắn với một origin mục tiêu. Nếu truyền manager riêng
vào `TechReconAgent`, cấu hình origin/CA phải thống nhất; cấu hình mâu thuẫn bị
từ chối trước auto-login. Đặt cookie/token/account trên manager đó, không đồng
thời đặt trên agent.

Kết quả Recon có `http_policy`; Coordinator giữ bản công khai tại
`recon_http_policy`. Token, cookie, thông tin account và header tùy chỉnh được
che trong kết quả/log Recon, dữ liệu đưa vào prompt của Recon và config trả về
từ `run_pipeline`. Config gốc của người gọi không bị sửa.

## Kiểm thử cục bộ

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:LANGCHAIN_TRACING_V2 = 'false'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_recon*.py' -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_auth_manager_scope.py' -v
```

Các test dùng HTTP/HTTPS server localhost và credential giả của fixture. Chúng
kiểm tra request thực nhận ở server, phân tách origin, redirect, TLS không tin
cậy/CA riêng, auto-login và đường truyền cấu hình qua Coordinator; không gọi
website bên ngoài hay API LLM.
