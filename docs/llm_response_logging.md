# Response LLM và cách kiểm tra wordlist theo pattern

Mỗi lời gọi LLM trong source được ghi qua `invoke_logged()` ở tầng ứng dụng, nên không phụ thuộc SDK dùng `httpx` hay `httpx2`. File mặc định: `logs/llm_responses.jsonl`; có thể đổi bằng biến `LLM_RESPONSE_LOG_FILE`.

Mỗi dòng có tên module, thao tác, context của phần đang sinh, thời gian thực thi và response đầy đủ trước khi parse JSON. Lỗi gọi LLM cũng được ghi; JSON sai định dạng vẫn còn trong response để đối chiếu việc fallback. Không lưu prompt, request headers hoặc API key; dữ liệu nhạy cảm được che trước khi ghi. Số bản ghi là số lần gọi ở tầng ứng dụng, không phải tổng HTTP request bao gồm retry nội bộ SDK. Lỗi ghi log không làm gián đoạn kết quả LLM.

Với endpoint, LLM sinh vocabulary riêng cho các slot ngữ nghĩa mà pattern đã chọn sử dụng, ví dụ `service`, `resource`, `action`, `sub_resource`. Prefix và ID lấy từ dữ liệu quan sát/profile/knowledge; không yêu cầu LLM đoán ID thật. Sau đó chương trình điền các phần vào template. File tĩnh vẫn có thể xuất hiện nguyên vẹn từ Recon hoặc nhóm sensitive files, nhưng không được dùng làm resource để sinh đường dẫn kiểu `detail-manifest.json`.

`output_samples/02_pattern_trace.json` cho biết:

- `endpoint_assembly.selected_patterns`: pattern, template và danh sách slot.
- `endpoint_assembly.llm_part_items`: giá trị LLM sinh và vượt qua kiểm tra cho từng slot.
- `endpoint_assembly.part_vocabularies` và `slot_sources`: vocabulary sau merge và nguồn của từng giá trị.
- `endpoint_assembly.pattern_results`: số lượng, mẫu endpoint và giá trị dùng cho từng pattern.
- Các nhóm riêng của sensitive files và parameters.

Các endpoint lắp ráp là **ứng viên**, chưa được xác minh HTTP. Các trường cũ `llm_predicted_*` được giữ để tương thích và đếm endpoint lắp ráp; không có nghĩa toàn bộ endpoint do LLM sinh trực tiếp.

Để chạy lại riêng Module Wordlist từ Recon đã lưu và thu response thật, không gửi request tới website:

```powershell
.\.venv\Scripts\python.exe -u -B scripts\run_wordlist_check.py --recon output_samples\diagnostics\cab_vn_full_authenticated_20261021\01_recon_result.json --output output_samples\diagnostics\wordlist_patterns_new
```

Runner đọc cấu hình DeepSeek hiện có, dùng thư mục output mới và giữ nguyên output các lần chạy trước. Response của các lần chạy cũ đã bị bỏ đi trước khi có logging sẽ không được dựng lại.
