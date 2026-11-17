# Môi trường Coordinator đã kiểm thử

Mốc kiểm tra: **2026-10-27**, CPython **3.12.10**, Windows x64.
`requirements.txt` khóa năm dependency trực tiếp và nạp constraint từ
`requirements.lock.txt`. File khóa chứa đủ 45 dependency runtime, gồm cả
dependency gián tiếp; không chứa pip, credential hoặc đường dẫn máy cá nhân.

Kết quả xác nhận: **199/199 test đạt** trong `.venv` hiện tại và trong một
venv sạch cài từ wheel PyPI theo bộ khóa. `pip check` đạt ở cả hai môi trường;
phiên bản của cả 45 package khớp file khóa. Đây là kiểm thử offline/localhost,
không phải một lần quét website hoặc gọi LLM thật.

Các phiên bản chính:

| Package | Phiên bản |
| --- | --- |
| langchain | 1.4.6 |
| langchain-core | 1.6.12 |
| langchain-openai | 1.7.2 |
| langgraph | 1.2.16 |
| langgraph-checkpoint | 4.3.0 |
| ormsgpack | 1.13.0 |
| python-dotenv | 1.2.4 |

Đây là bộ phiên bản đã kiểm tra trên nền tảng trên, chưa phải xác nhận tương
thích cho mọi phiên bản Python hoặc hệ điều hành khác. File khóa giữ phiên bản;
không thay thế chính sách Windows về việc cho phép nạp DLL.

## Nguyên nhân và cách xử lý

Nhật ký `Microsoft-Windows-CodeIntegrity/Operational` ngày 2026-10-24 có sự
kiện 3077/3033 chặn `ormsgpack.cp312-win_amd64.pyd`. `pip check` chỉ kiểm tra
quan hệ dependency nên vẫn có thể báo thành công khi Windows chặn DLL.

Khi kiểm tra lại ngày 2026-10-27, import trực tiếp `ormsgpack 1.13.0` và graph
đã thành công trước khi thay đổi dependency. Không đủ bằng chứng để kết luận
vì sao Windows đã ngừng chặn. Vì vậy giữ nguyên bộ phiên bản đang hoạt động,
không hạ phiên bản hoặc sửa chính sách Windows.

Test mới phát hiện thêm lỗi vòng import: agent nạp logging của Coordinator,
Coordinator lại nạp graph và agent chưa khởi tạo xong. `except ImportError`
cũ che lỗi rồi giữ `run_pipeline`/`build_coordinator_graph` ở giá trị `None`.
Coordinator hiện nạp hai entry point khi được truy cập. Thứ tự import agent
trước Coordinator hoạt động; lỗi dependency thật vẫn được truyền nguyên vẹn
cho người gọi.

## Cài đặt và kiểm tra

Tại thư mục dự án, dùng môi trường hiện có:

```powershell
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements.txt
.\.venv\Scripts\python.exe -m pip check

$env:PYTHON_DOTENV_DISABLED = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:LANGSMITH_TRACING = "false"
$env:LANGCHAIN_TRACING_V2 = "false"

.\.venv\Scripts\python.exe -B -c "import ormsgpack; from src.coordinator import run_pipeline, build_coordinator_graph; assert callable(run_pipeline) and callable(build_coordinator_graph); print('Coordinator import OK')"
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_coordinator_environment.py -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Các biến môi trường trên áp dụng cho terminal kiểm thử hiện tại. Mở terminal
mới khi muốn chạy tool với cấu hình `.env` bình thường.

Bốn test môi trường kiểm tra entry point, thứ tự import agent trước
Coordinator trong process mới, việc truyền lỗi DLL bị chặn, và compile/invoke
graph thật qua các giai đoạn tới báo cáo/reflection. Agent và LLM dùng fixture,
kết nối ra ngoài bị chặn trong test này, dữ liệu tạm nằm ngoài source. Bộ test
trong `tests/` sử dụng fixture/localhost; không dùng các script `test_*real.py`
ở thư mục gốc để xác nhận môi trường offline.

Khi tạo môi trường mới, dùng CPython 3.12 x64 đã cài và cài từ chính
`requirements.txt`; không cài riêng phiên bản mới nhất của LangGraph/LangChain.
Môi trường `.venv` hiện tại tham chiếu Python gốc tại
`output_samples/diagnostics/environment_setup/python.3.12.10/tools` theo
`pyvenv.cfg`. Giữ thư mục Python gốc này khi dọn output, hoặc tạo lại venv từ
một bản Python được cài ở vị trí ổn định.

## Nếu Windows lại chặn DLL

Đọc lỗi import nguyên bản và sự kiện Code Integrity:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3077, 3033
    StartTime = (Get-Date).AddDays(-2)
} -MaxEvents 10 | Select-Object TimeCreated, Id, Message
```

Nếu lỗi là chính sách ký mã, cần quản trị viên máy đánh giá wheel chính thức
theo chính sách đang áp dụng. Nguồn package:
[ormsgpack trên PyPI](https://pypi.org/project/ormsgpack/1.13.0/).
Không thay đổi Defender/Application Control, giả lập module hoặc nuốt lỗi
import để báo môi trường hoạt động. `Unblock-File` không giải quyết yêu cầu ký
mã; file bị chặn đã kiểm tra không có stream `Zone.Identifier`.

## Cập nhật bộ khóa

Thử phiên bản mới trong venv riêng. Cập nhật cả năm pin trực tiếp và toàn bộ
dependency runtime tương ứng trong file khóa. Chỉ chấp nhận sau khi `pip check`,
test môi trường Coordinator và toàn bộ `tests/` đạt, đồng thời cài lại được từ
hai file requirements trong venv sạch. Ghi lại Python, nền tảng và ngày kiểm
tra. Không đưa `.venv`, wheel, log hoặc output kiểm thử vào commit.
