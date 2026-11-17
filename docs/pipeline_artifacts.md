# Lưu kết quả và lỗi của Coordinator

`RunArtifacts` ghi một thư mục mới cho mỗi lượt chạy; không ghi đè lượt chạy trước.
`config["artifact_root"]` hoặc `config["output_dir"]` là **thư mục cha**, mặc định
`output_samples/diagnostics`. Nếu có cả hai, `artifact_root` được ưu tiên.

```text
output_samples/diagnostics/pipeline_<UTC timestamp>_<random id>/
  result.json
  checkpoints/
    0001_pipeline.json
    0002_validate_input.json
    ...
```

`result.json` chứa trạng thái mới nhất được ghi hoàn chỉnh. Mỗi checkpoint giữ
trạng thái tại một bước để đối chiếu kết quả trước khi lỗi xảy ra. Trường
`artifacts` cung cấp đường dẫn, số thứ tự, tên bước, sự kiện và thời điểm lưu.
Timestamps trong tên thư mục và JSON dùng UTC.

Khi lỗi, giữ nguyên kết quả đã thu thập và thêm `error_log`, trạng thái bước lỗi,
`pipeline_status` (`failed` hoặc `interrupted`), `finished_at`. Khi dừng bằng
Ctrl+C, Coordinator lưu trạng thái trước khi trả lại tín hiệu ngắt. Việc tắt tiến
trình cưỡng bức hoặc mất điện có thể chỉ để lại checkpoint trước đó.

Dữ liệu lưu là bản sao đã che token, headers, cookies, account, khóa API,
cấu hình proxy và request body. Những giá trị bí mật đã biết cũng được che nếu
xuất hiện trong thông báo lỗi hoặc kết quả lồng nhau. URL proxy không giữ
username/password. Không dùng `repr()` của đối tượng tùy ý để tạo JSON.

Mỗi JSON được ghi vào file tạm cùng thư mục, flush/fsync, rồi thay thế atomically.
Nếu không thể tạo/ghi file, `ArtifactWriteError` được trả ra rõ ràng; không coi
đó là đã lưu thành công. Nếu chỉ cập nhật `result.json` thất bại, checkpoint mới
có thể vẫn còn; `result.json` trước đó không bị ghi dở.

Kiểm tra cục bộ utility:

```powershell
./.venv/Scripts/python.exe -B -m unittest discover -s tests -p test_pipeline_artifacts.py -v
```

Các test không truy cập website hay API LLM; bao phủ việc giữ kết quả trước lỗi,
che bí mật trong lỗi/kết quả, ngắt tiến trình, dữ liệu không tuần tự hóa trực tiếp
được và lỗi ghi đĩa.
