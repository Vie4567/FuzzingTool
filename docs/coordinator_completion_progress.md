# Hoàn thiện Coordinator — tiến độ 2026-11-03

## Cập nhật kiểm thử cab.vn ngày 04/11/2026

Đã chạy Coordinator thật, giữ nguyên source/lockfile. Lượt mới **partial**, 37 lần dispatch HTTP (Recon 26, Fuzzing 11), 20/20 LLM thành công; Fuzzing 11/11 timeout, Parameter skipped, Soft404 vào node nhưng skipped/upstream_incomplete với 0 request. 35/35 regression test cục bộ bổ sung PASS. Xem [báo cáo mới](../output_samples/diagnostics/cab_vn_coordinator_20261104/report.md) và [checklist](../output_samples/diagnostics/cab_vn_coordinator_20261104/criteria_checklist.md). Kết luận hoàn thành ngày 03/11 bên dưới chỉ ở phạm vi lab đã nêu, không thay thế kết quả cab.vn mới.

Các việc cần sửa theo bằng chứng live (chưa sửa trong lượt chỉ chạy/đánh giá): tổng hợp lỗi transport lên Coordinator (`error_log=[]` nhưng nested có 11 timeout, stop_reason/error_message `completed` gây hiểu nhầm); bảo toàn hoặc giải thích việc `/` bị bỏ khiến 12 selected còn 11 attempted; đưa generated/selected/attempted counts vào context để LLM không kết luận sai chênh lệch 1.950/12 là state corruption. Chưa xác định được timeout do mạng/server hay cơ chế lọc; không suy diễn nguyên nhân từ văn bản LLM và không tự đổi IP/né điều kiện dừng.

## Trạng thái cuối: đã hoàn thành bốn hạng mục yêu cầu

- Validator URL/config/wordlist và lựa chọn wordlist đã hoàn thiện, kèm test kiểu dữ liệu, engine, scope/TLS/credentials, encoding, file và alias.
- Deadline process + timeout tổng thời gian từng lời gọi LLM đã triển khai. Test phản hồi nhỏ giọt, hủy kết nối, worker treo và phục hồi checkpoint đạt.
- Bộ đếm agent_attempts/retry_counts/iteration_count hoạt động tại nơi thực thi; guard dùng cấu hình, giới hạn bước LangGraph không chặn sớm retry hợp lệ.
- Full suite cuối: **356/356 PASS**, 0 lỗi/skip. Báo cáo: [report.md](../output_samples/diagnostics/coordinator_completion_20261103/report.md); log và `validation.json` cùng thư mục.
- Lượt thật `coordinator_real_lab_20261103_verified`: **completed**, 5/5 module thành công, **94 HTTP** khớp server độc lập, **28/28 DeepSeek calls** thành công; xác minh `page`, loại `/missing-page` là fallback, không có error. 21:18:19–21:21:26 UTC+7 ngày 03/11/2026.
- Bằng chứng: [evidence.json](../output_samples/diagnostics/coordinator_real_lab_20261103_verified/evidence.json), [result.json](../output_samples/diagnostics/coordinator_real_lab_20261103_verified/result.json), server log, LLM responses, source SHA256. Đây là lab cục bộ thật + LLM API thật, chưa phải một lượt toàn pipeline mới trên cab.vn. Chỉ chọn hai đường dẫn để fuzz, giữ nguyên 2.581 ứng viên được sinh để đối chiếu.
- Hướng dẫn sử dụng: [coordinator_configuration.md](coordinator_configuration.md). Không commit/push.

## Điểm tiếp tục cho yêu cầu sau

Không còn công việc bắt buộc đang chạy của bốn hạng mục trên. Giữ nguyên nhiều thay đổi chưa commit từ các phần trước; không dùng `git add .` vì `.venv` đang được Git theo dõi và có nhiều thay đổi môi trường.

Giới hạn đã ghi trong báo cáo: ffuf không có bộ đếm toàn bộ traffic nội bộ; dùng native HTTP để kiểm chứng global budget chính xác. Direct `run_pipeline` còn globals, nên dùng supervisor cho deadline và các phiên đồng thời. Lab cho thấy nhận diện WAF `ddos_guard` sai, và nội dung giải trình LLM chưa hiểu rõ generated_count so với selected_count; cần cải thiện ở bước sau, không dùng văn bản LLM làm ground truth.

## Nhật ký trước khi hoàn tất (giữ để truy vết)

1. **Đầu vào (đã triển khai, đang review):** `validation.py`, URL/config/wordlist, file UTF8, provided/merge/generated, selection budget, giữ config gốc.
2. **Runtime (đã triển khai, đang review):** `runtime.py`, `llm_client.py`, timeout LLM co theo thời gian còn lại, shared HTTP budget/rate; `supervisor.py` process riêng, hard deadline/kill process tree trên Windows, unknown in-flight counts khi kill.
3. **Điều phối (đã triển khai):** graph tăng agent_attempts/retry_counts/iteration_count đúng lượt thực thi, guard retry/iteration, output schema tối thiểu, không gắn completed khi abort/pending; `all_modules_executed`/`all_modules_successful`.
4. **Bằng chứng (chưa đạt toàn pipeline):** `scripts/run_coordinator_lab.py`, toàn bộ agent/Coordinator thật, DeepSeek thật, HTTP lab có server log độc lập. Lượt đầu `coordinator_real_lab_20261103` lỗi timeout ở quyết định sau wordlist. Lượt `coordinator_real_lab_20261103_final` chạy đủ 5 module thành công, 94 HTTP khớp server, 31 LLM (28 thành công/3 lỗi), xác minh `page` và loại fallback; reflection timeout nên pipeline `partial`. Không coi lượt này là bằng chứng toàn pipeline thành công.

## Ghi nhận kiểm thử trước lượt cuối

- Source đang có nhiều thay đổi chưa commit từ Recon/Soft404/Parameter/telemetry; phải bảo toàn.
- Bộ test trước: 325 PASS. Lượt cab.vn gần nhất chỉ HTTP engine + Soft404 (11 request), không phải Coordinator end-to-end.
- Lượt full suite trước: 336 test, 1 failure do test so config nội bộ chưa chuẩn hóa với config gốc. Đã cập nhật test: config người gọi giữ nguyên, config nội bộ thêm defaults. Sau đó 45 test limits/LLM/proxy/auth PASS; 17 test HTTP limits/query/native PASS; 9 test supervisor/limits PASS.
- Đã sửa recursion_limit của LangGraph theo max_iterations, regression 11 lần chạy/10 retry vượt ngưỡng 25 bước mặc định. Đã sửa đường dẫn knowledge không phụ thuộc cwd, timeout HTTP dùng giới hạn chung, query trong wordlist không bị biến thành `%3F`.
- Timeout LLM theo tổng thời gian thực đã hoàn tất sau review: SDK timeout ban đầu chỉ theo socket I/O, phản hồi nhỏ giọt có thể vượt giới hạn. Supervisor recovery cũng đã review/test PASS.
- Đã chạy full suite cuối, real lab trên source cuối và kiểm tra credential trong artifacts. Lệnh full suite: `.\.venv\Scripts\python.exe -B output_samples/diagnostics/coordinator_completion_20261103/run_tests.py` (file có main guard để Windows multiprocessing spawn hoạt động).

Sau mỗi phần cập nhật file này: file đã sửa, lệnh test/kết quả, hạn chế và bước tiếp theo. Không commit/push nếu chưa được yêu cầu.
