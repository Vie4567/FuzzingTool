# B3.2B — Crash recovery cho chế độ multi-origin localhost

B3.2B bổ sung journal bền vững và reconciliation vào `LocalOriginTest` của B3.2A.
Coordinator vẫn dùng compiled LangGraph và topology cũ. Không mở production gate,
không gọi Agent 4–5, không thêm Agent, không dùng LLM hoặc proxy.

## Phạm vi bảo đảm

Có thể tiếp tục phần dispatch **chưa reserve** sau khi Recon và Wordlist đã có
checkpoint hoàn chỉnh. Runtime của tiến trình mới được phục hồi từ journal trước
bất kỳ HTTP nào: giữ session/runtime identity, quota đã tiêu thụ, slot rate limit,
deadline gốc và kết quả đã đo. Không tạo runtime theo origin hoặc Agent.

Không chạy lại Recon/Wordlist đã hoàn thành. Graph vẫn đi qua các node tương ứng;
wrapper dùng kết quả checkpoint và ghi `recovery.reused_nodes`, không gọi lại thân
Agent, không tăng `agent_attempts` hoặc retry count. Agent 3 chỉ tiếp tục những
candidate chưa có reservation; candidate đã có phép đo hoặc outcome chưa xác định
đều bị loại khỏi việc gửi lại. Khi checkpoint Agent 3 đã hoàn thành, Agent 3 cũng
không được gọi lại. Decisions là routing xác định của lab, không phải LLM production.

Đây là **at-most-once replay policy**, không phải exactly-once HTTP delivery.
`dispatch_started` chứng minh client đã bắt đầu lượt dispatch, không chứng minh
server đã nhận request. Chỉ access log độc lập trong lab xác nhận phía server.

## Contract và lifecycle

`recovery_directory` là tham số của private Python context, không phải quyền lấy
từ config JSON, SharedState hoặc discovery. Directory chứa:

- `session.lock`: khóa hệ điều hành, giữ suốt invocation; Windows dùng
  `msvcrt.locking`, POSIX dùng `flock`. Không dùng PID file làm khóa.
- `journal.jsonl`: các event có sequence, previous hash, SHA-256, PID, UTC và payload.
- `head.json`: anchor sequence/hash cuối, ghi bằng atomic writer hiện có.

Mỗi append ghi/flush/fsync journal trước khi thay head. Không gửi HTTP nếu ghi
reservation thất bại. Journal/head dở dang hoặc không khớp bị từ chối; không bỏ qua
dòng lỗi hoặc tự chọn checkpoint cũ hơn để tiếp tục.

| Event/trạng thái | Ý nghĩa |
| --- | --- |
| Candidate pending, chưa có `reserved` | Chưa có bằng chứng tiêu thụ quota; có thể đánh giá lại để dispatch |
| `reserved` | Quota global và origin đã tiêu thụ bền vững, kể cả khi process chưa gửi HTTP |
| `dispatch_started` | Bắt đầu dispatch phía client; chưa phải xác nhận delivery |
| `response_headers` | Status thực nhận, kèm stop reason nếu có; không lưu headers nhạy cảm |
| `measurement` | Metadata HTTP/body thực đo đã persist; không lưu body/raw headers |
| `checkpoint` | Tham chiếu checkpoint immutable của writer hiện có, hash, node/event và reservation count |
| `outcome_unknown` khi reconciliation | Có reservation nhưng thiếu phép đo hoàn chỉnh; không replay |
| `reconciled` / `process_bound` | Counter, checkpoint nguồn, PID tiếp tục và session identity |
| `stop` / `session_finished` | Phiên không được tiếp tục HTTP |

SharedState thêm public `recovery`: journal reference, session ID, replay policy,
reservation đã restore, các sequence outcome unknown, node được tái sử dụng và
`accounting`. `accounting` phân biệt reserved requests, known dispatch starts,
attempts unknown, responses received và unresolved outcomes. Không lưu token,
cookie hoặc profile secret. Existing origin/candidate/evidence identity giữ nguyên.

Nếu crash sau reservation nhưng trước dispatch evidence, `record.attempted=null`,
status/body bytes/duration chưa biết cũng null. `total_http_requests=null` và
telemetry giữ known lower bound. Budget vẫn tính reservation đó. Nếu đã lưu headers,
status được giữ nhưng body chưa persist vẫn null. Không tự tạo lỗi mạng, bytes hoặc
verified endpoint cho một outcome chưa biết. Summary có `attempted_unknown` và
`outcome_unknown` khi có record recovery; các trường legacy vẫn giữ nguyên.

## Điều kiện resume và fail-closed

Operator phải cung cấp lại context mới, cùng exact origins/path/query/method,
document plan, quota/rate/deadline/limits và public credential bindings. Secret
profile được cấp lại qua runtime riêng, không đọc từ checkpoint. Secret values
không được lưu hoặc hash vào journal; việc token mới thực sự hợp lệ không được
chứng minh bằng matching profile ID.

Reconciliation kiểm tra hash-chain/head, checkpoint hashes/session/counters,
identity của reservation và dữ liệu response đối chiếu với measurement. Policy
được lấy từ context operator vừa cấp; checkpoint chỉ là dữ liệu và bằng chứng.
Mỗi dispatch mới vẫn qua scope/credential guard B1 và kiểm chứng candidate B3.1.

Từ chối tiếp tục khi:

- Journal/checkpoint thiếu, hỏng, bị thay đổi hoặc counters không khớp.
- Scope, binding, document plan hoặc giới hạn thay đổi; credential profile cần
  thiết chưa được cấp lại.
- Chưa có checkpoint hoàn chỉnh của Recon và Wordlist. Không tự chạy lại để bù.
- Có global stop, HTTP 401/403/407/429, Retry-After, hết budget hoặc hết deadline.
  Chỉ headers mang stop reason cũng đủ chặn, kể cả crash trước event `stop`.
- Session đã kết thúc, process khác đang giữ khóa hoặc clock có discontinuity.

Deadline dùng mốc monotonic gốc cùng UTC expiry; lấy giới hạn sớm hơn, không cộng
lại thời lượng pipeline. Chênh lệch elapsed giữa hai clock quá 2 giây bị từ chối.
Quy tắc này fail-closed khi clock/host thay đổi; không hứa resume sau reboot.
Khi load bị từ chối, artifact mới ghi lý do và accounting unknown, không báo quota
đã trở về zero. Journal/checkpoint gốc được giữ nguyên.

## Cách sử dụng trong lab

Dùng `LocalOriginTest` như B3.2A, bổ sung `recovery_directory=artifact_root / "recovery"`
cho lần đầu. Recovery directory phải nằm trực tiếp dưới artifact root.
Sau crash, tạo **context mới** với cùng cấu hình được operator cung cấp, cấp lại
private profiles và đặt `resume=True`, rồi gọi `run_pipeline()` như trước.

```python
local = LocalOriginTest(
    frontend_url,
    scope=operator_scope,
    documents=operator_document_plan,
    origin_max_requests=operator_quotas,
    credential_profiles=private_local_profiles,
    recovery_directory=artifact_root / "recovery",
    resume=True,  # chỉ khi operator chủ động yêu cầu tiếp tục session bị gián đoạn
)
result = run_pipeline(frontend_url, unchanged_config, local_origin_test=local)
```

Không có auto-restart. Session đã hoàn tất không thể resume. Pipeline toàn phần
vẫn partial/failed, `all_modules_executed=false`, `all_modules_successful=false`.
HTTP response chỉ là observed response; verification vẫn not_verified.

## Kiểm chứng

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGCHAIN_TRACING_V2 = 'false'
$env:LANGSMITH_TRACING = 'false'
$env:B32B_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b32b_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_recovery*.py' -v
.\.venv\Scripts\python.exe -B scripts/verify_origin_recovery_evidence.py $env:B32B_EVIDENCE_DIR --expected-cases 27 --negative-checks
```

Lab có ba HTTP servers độc lập với process chạy Coordinator. Worker chạy graph
thật, bị parent kill bằng `Popen.kill()` rồi khởi động process mới. Barrier được
patch riêng trong test worker, có thời hạn chờ; không có fault switch trong config
production. Server tự flush/fsync access logs, không lấy số request từ tool.

27 integration cases bao phủ trước/sau reservation, server receive, headers,
measurement, checkpoint, gateway, body streaming, quota/deadline, corruption,
scope/binding, khóa concurrent resume và stop guards. 11 unit tests kiểm tra
durability/anchor/private context/counter unknown và global stop chỉ có trong checkpoint. Verifier chỉ dùng stdlib,
không import dispatcher/runtime/Agents, và từ chối 4 mutations bắt buộc.

Kết quả đầy đủ, commands, source hashes, baseline và các giới hạn nghiệm thu nằm
trong [báo cáo B3.2B](../output_samples/diagnostics/multi_origin_b32b_20261124T021501Z/report.md).

## Giới hạn và phần việc B4

- Safe resume chỉ cho phần dispatch sau checkpoint Recon/Wordlist, trong lab
  literal-loopback, Python HTTP, sequential. Không hỗ trợ resume Recon dở dang.
- Không có bằng chứng Internet, DeepSeek, production multi-origin, distributed
  lock, network filesystem hoặc power-loss durability. Hash chain phát hiện sửa
  dữ liệu thông thường; không thay thế MAC/signature chống kẻ có quyền sửa toàn bộ
  journal, anchor và checkpoint cùng lúc. Cần bảo vệ quyền ghi thư mục bằng OS.
- Không benchmark quy mô lớn; journal fsync/checkpoint hash tăng disk I/O nhưng
  không tăng HTTP/LLM calls, retry hoặc budget.
- Không xác nhận đã sửa lỗi LLM timeout chập chờn trước đây chỉ từ một lần suite PASS.
- B4 vẫn cần verification Parameter/Soft404 riêng từng origin và baseline không
  trộn; recovery cho hai Agent này chưa triển khai. Production gate vẫn đóng.
