# Proxy cho Parameter và Soft404 — hoàn tất 2026-11-07

## Phạm vi đã làm

- `verification_http.py` cung cấp transport kiểm chứng có scope/auth/TLS và pool riêng của runtime.
- Fuzzing chỉ chuyển pool khi hoàn tất, không có lỗi; lượt Fuzzing mới hủy pool cũ cùng cấu hình. Pool/credentials không đưa vào state hay checkpoint.
- Parameter xoay giữa endpoint và ghim baseline/control/candidate/post-control vào một proxy. Soft404 xoay giữa endpoint, tách cache baseline theo profile.
- Chỉ hỗ trợ kế thừa `proxy_http` trong cùng phiên/cấu hình; fixed proxy, source-bound, pool thiếu, upstream dừng và ngữ cảnh auth không khớp vẫn bị chặn. Recon giữ tuyến trực tiếp.
- Không discovery/healthcheck mới trong kiểm chứng: dùng pool đã có, không refresh thành viên khi đang so sánh. Proxy lỗi hoặc HTTP/CONNECT chặn không dẫn tới failover/direct fallback.
- Evidence lưu profile đo hiện tại và profile nguồn. Metrics theo proxy gồm số request, phản hồi, độ trễ và tỷ lệ lỗi; CONNECT status tách khỏi website status.
- Budget chung kiểm tra deadline phase ngay tại bước cấp quyền dispatch; request bị từ chối chưa tăng bộ đếm. `response_time` bắt đầu sau khi chờ rate limit.
- CLI và tài liệu đã cập nhật, không cần thêm option mới ngoài cấu hình Fuzzing proxy hiện có.

## Kiểm chứng

`python -B -m unittest discover -s tests -p 'test_*.py' -q`: **375 test đạt**, 101,580 giây, exit code 0.

Log đầy đủ: [proxy_verification_full_suite.log](../output_samples/diagnostics/proxy_verification_full_suite.log).

14 test mới ở [test_proxy_verification.py](../tests/test_proxy_verification.py) dùng socket HTTP/proxy/CONNECT/TLS thật trên loopback. Đối chiếu IP nguồn `127.0.0.2`/`127.0.0.3`, baseline khác theo tuyến, auth, TLS CA, scope, redirect, lỗi chặn/transport, cô lập pool, ngân sách và deadline. Test handoff chạy FuzzingAgent → ParameterAgent → Soft404Agent; phần sinh ứng viên được cố định, HTTP verifier chạy thật. ProxyScrape discovery được thay bằng danh sách proxy lab, không gọi Internet.

Đây là bằng chứng tích hợp cục bộ; không phải lượt quét mới hoặc bằng chứng proxy công khai hoạt động với cab.vn.

## Cách dùng

Xem [lệnh Coordinator có token và proxy](coordinator_auth_proxy_cli.md). Hai module tự dùng pool sau Fuzzing thành công. Nếu Fuzzing dừng/lỗi, giữ kết quả chưa kiểm chứng và lý do upstream; không bỏ điều kiện dừng để ép hoàn thành pipeline.
