# Bộ đếm runtime và kết quả lỗi

`run_pipeline()` tạo telemetry riêng cho mỗi lần chạy và cập nhật trước/sau mỗi
node. Không cộng một LLM call chỉ vì đã chạy một module.

- `llm_call_count`: số lần model bắt đầu thực thi, gồm lần lỗi. Với LangChain,
  đếm callback model-start, không tính lỗi định dạng prompt xảy ra trước khi gọi
  model; lỗi parser sau response không biến một lần model thành hai lần gọi.
- `coordinator_llm_calls`: phần thuộc quyết định và reflection của Coordinator.
- `telemetry.llm`: attempted/succeeded/failed/in_flight, quota_rejections và
  phân nhóm theo component/phase. Quota 50 được kiểm tra trước khi dispatch;
  client do Coordinator tạo đặt `max_retries=0`. Runnable tự cung cấp có retry
  nội bộ cần tự công bố/instrument retry đó; không suy đoán số HTTP của provider.
- `total_http_requests`: lần thử gửi HTTP của các transport được hỗ trợ, gồm
  baseline, control, Parameter, Soft404, proxy healthcheck và fetch ProxyScrape.
  Lỗi DNS/TLS/CONNECT vẫn là một lần thử. Không cộng CONNECT handshake thành
  một request mục tiêu bổ sung, không gộp HTTP của LLM vào bộ đếm này.
- `telemetry.http.by_kind` phân biệt request mục tiêu, proxy healthcheck và
  provider; `by_phase` cho biết node phát sinh. Bộ đếm không chứng minh server
  đã nhận request: khi lỗi mạng, chỉ biết transport đã thử gửi.
- Với ffuf CLI, tổng request kể cả lỗi chưa được công cụ xuất đầy đủ:
  `total_http_requests=null`, `count_complete=false`; `known_http_requests`
  và `unknown_sources` giữ phần đo được/lý do thiếu. Không lấy số từ wordlist.

Các bộ đếm riêng `fuzzing_stats`, `parameter_stats`, `soft404_stats` được giữ
để đối chiếu; không cộng lại chúng vào telemetry đã đếm tại transport.

Coordinator trả và lưu `pipeline_status`:

- `completed`: graph hoàn thành không có bước lỗi/một phần.
- `partial`: đã tới cuối nhưng có bước lỗi, dữ liệu chưa đủ hoặc reflection lỗi.
- `failed`: lỗi validation, khởi tạo graph hoặc exception làm graph dừng.
- `interrupted`: Ctrl+C/SystemExit; lưu trước khi ném lại tín hiệu ngắt.

Xem `artifacts.result` trong giá trị trả về để mở JSON. Chi tiết lưu checkpoint,
che token và giới hạn khi lỗi ổ đĩa/mất điện ở [pipeline_artifacts.md](pipeline_artifacts.md).
Kiểm chứng tham số và cách cấu hình ở [parameter_verification.md](parameter_verification.md).

Kiểm tra cục bộ:

```powershell
$env:PYTHON_DOTENV_DISABLED='1'
$env:LANGSMITH_TRACING='false'
$env:LANGCHAIN_TRACING_V2='false'
.\.venv\Scripts\python.exe -B -m unittest tests.test_runtime_telemetry tests.test_parameter_pipeline tests.test_pipeline_failure_integration -q
```

Test HTTP dùng server loopback; LLM là fake model/runnable để kiểm bộ đếm,
không phải số liệu hiệu năng từ API thật. Các subprocess helper cũ không được
pipeline hiện tại dispatch cần được bổ sung hook nếu tích hợp thêm sau này.
