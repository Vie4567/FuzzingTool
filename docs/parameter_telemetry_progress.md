# Tiến độ: kiểm chứng Parameter và telemetry

Cập nhật: 2026-11-03. Phạm vi: source, kiểm thử cục bộ; không gọi cab.vn hoặc API LLM thật.

## Mục tiêu và cách tiếp tục

1. **Parameter — hoàn tất:** ứng viên tách khỏi `verified_parameters`; baseline/control trước và sau phép thử, hai giá trị lặp lại; kế thừa auth/scope/TLS/rate/stop. 18 test Parameter và integrity đã qua.
2. **Telemetry — đã triển khai:** đếm ở model-start/HTTP dispatch, bao gồm lỗi; ffuf thiếu tổng thì giữ `null` và lower bound; bỏ cộng LLM theo module. 123 test telemetry và transport liên quan đã qua.
3. **Lưu kết quả — hoàn tất:** checkpoint trước/sau node, `result.json` nguyên tử và che bí mật; 8 test artifact utility và 6 test tích hợp lỗi decision/reflection/interrupt/ghi file đã qua.
4. **Tích hợp và kiểm thử — hoàn tất:** Coordinator đã nối cả ba phần. Test pipeline localhost đối chiếu 24 HTTP request với server và 6 LLM invocation giả lập, không cộng trùng. Toàn bộ **325 test PASS**, không skip, 49.537 giây.

## Điểm xuất phát

- Soft404, auth/scope/TLS và CONNECT đã có thay đổi chưa commit; phải giữ nguyên.
- Bản kiểm thử Soft404 trước đó ghi nhận 280 test thành công; chưa chạy lại trong lượt này.
- Parameter hiện mới sinh ứng viên; chưa gửi request kiểm chứng.
- Coordinator đang cộng LLM theo module và để tổng HTTP không xác định khi chạy Recon.
- `run_pipeline` chưa có cơ chế lưu kết quả khi graph phát sinh lỗi.

## Phân công và file dự kiến

- Parameter: `src/tools/parameter_verification.py`, `src/agents/param_discovery.py`, test fixture và tài liệu cấu hình.
- Telemetry: `src/coordinator/telemetry.py`, hook `invoke_logged`, transport HTTP và test bộ đếm.
- Artifact: `src/coordinator/artifacts.py`, test che bí mật/lỗi ghi file.
- Tích hợp: `src/coordinator/graph.py`, state, test pipeline và cập nhật tài liệu này.

## Kiểm thử / bàn giao

- 28 test hồi quy `test_param_measurement_integrity`, `test_soft404_coordinator`, `test_coordinator_environment`, `test_recon_auth_integration`: PASS.
- `tests.test_parameter_pipeline`: 2 test PASS; lưu JSON trùng kết quả trả về, 24 request thực tế, 6 LLM giả lập; 403 ở Parameter ngăn Soft404 gửi tiếp. Lần đầu fixture gọi sai tên argument, đã sửa fixture và chạy lại thành công.
- Đã xử lý verifier trả `failed`: giữ ứng viên, đánh dấu bước failed và ghi error_log; bước Soft404 không tiếp tục sau lỗi/block Parameter.
- Lượt suite đầu: 325 test, 1 lỗi tương thích marker che proxy; sửa marker về `<redacted>`, không giảm che bí mật. Lượt cuối: **325/325 PASS**. Log: `output_samples/diagnostics/parameter_telemetry_completion_20261103/tests_full_final.log`; kết quả máy đọc: `validation.json`.
- Fixture lưu riêng: `local_fixture_result.json`, 18 request kiểm chứng + 1 request block 403 = 19; telemetry khớp server, LLM=0. Báo cáo: `output_samples/diagnostics/parameter_telemetry_completion_20261103/report.md`.
- **Không còn bước bắt buộc của yêu cầu này.** Phạm vi mở rộng sau nếu cần: POST/body, transport kiểm chứng qua proxy; hiện giữ chưa kiểm chứng thay vì chuyển route. Không có kết luận mới về cab.vn.
- Khi tiếp tục: kiểm tra diff các file trên và test mới; không lặp lại scan Internet hoặc dùng token cũ. Chưa commit/push.
