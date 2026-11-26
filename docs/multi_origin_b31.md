# B3.1 — Multi-Origin HTTP Dispatch, Shared Budget & Origin Telemetry

B3.1 nối **harness** Agent 1 → Agent 2 → Agent 3 bằng Python HTTP thật, dùng
contract B1/B2.1/B2.2 và một runtime chung. Full multi-origin LangGraph gate vẫn
`not_enabled_b1`; không gọi Agent 4–5. `FuzzingAgent.execute()` một target giữ
nguyên. Không hỗ trợ multi-origin `ffuf_cli` hoặc `proxy_http` trong entry point này.

## Cách gọi và trách nhiệm của operator

```python
# Các object/config dưới đây được tạo theo B1/B2.1, không lấy từ HTML/JS/LLM.
# Mở MỘT runtime trước cả Recon; không tạo lại runtime cho Agent 3/từng origin.
with telemetry_session(), runtime_session({
    **existing_limits,
    "http_origin_max_requests": {frontend_origin: 8, gateway_origin: 8},
}):
    # Agent 1 collect_discovery với document plan và OriginScopedTransport đã duyệt.
    # merge_discovery_context(shared_state, discovery) như B2.1.
    wordlist_agent.generate_from_discovery(shared_state, max_wordlist_entries=3,
                                          artifact_root=artifact_root)
    result = fuzzing_agent.dispatch_selected(
        shared_state,
        transport=origin_scoped_transport,
        engine="python_http",
        artifact_root=artifact_root,
    )
```

Đây là API tích hợp, không phải lệnh bật full pipeline. Ví dụ dùng các biến đã
cấu hình rõ ràng; không tự phê duyệt hostname/path nào. Xem HTTP test bên dưới
để chạy ví dụ hoàn chỉnh, chỉ localhost, không cần token hoặc LLM thật.

`http_origin_max_requests` bắt buộc cho harness B3.1: mapping chính xác toàn bộ
approved origins sang số nguyên không âm. Quota 0 hợp lệ; thiếu origin bị chặn.
Origin gồm scheme/hostname/port, không gộp subdomain. Quota tính **mọi attempt
trong runtime qua B1 transport, gồm Recon**, không chỉ request Agent 3.
Global HTTP budget/rate/deadline vẫn là giới hạn chung; per-origin quota không
reset hoặc thay thế chúng. Runtime một target không cấu hình quota mới giữ cách
dispatch cũ. Transport không gắn origin trong runtime có quota sẽ fail-closed.

## Contract trước/sau

Input giữ nguyên:

```text
approved_origins / discovered_origins / origin_policies
origin_contexts[origin].endpoints
origin_contexts[origin].context.wordlist.candidates
origin_contexts[origin].context.wordlist.selected_ids
```

Harness đọc lại candidate ngay trước request, kiểm tra identity URL đầy đủ/query,
origin, method, source observation/provenance/evidence refs, selection và policy
exact path/query/method/read_only. Policy trong state phải khớp policy explicit
của transport. `dispatch_eligible` cũ không cấp quyền gửi HTTP.

Chỉ declaration observed, selected, có nguồn và method GET/HEAD được xem xét.
POST/PUT/PATCH/DELETE, method null, generated candidate, origin không approved
và candidate bị sửa identity/source bị từ chối. Không lấy headers/body từ
candidate. Không đổi User-Agent, TLS, redirect, proxy, token hay retry policy.

Output thêm vào cùng SharedState:

```text
origin_contexts[origin].context.http_dispatch
  engine / status / stop_reason
  counts: selected, attempted, responses, errors, unattempted, timeouts
  origin_budget_used / origin_budget_limit
  records[]:
    candidate_id, origin, url, evidence_refs
    observed_method, planned_test_method, execution_method
    attempted, runtime_sequence, status_code, response_time
    bytes_received, retained_body_bytes, body_complete
    error, timeout, stop_reason, rejection_reason (nếu bị chặn)
    classification, verified, verification_status, recorded_at_utc
fuzzing_execution.multi_origin
  status / stop_reason / completed / partial / success
  counts / runtime / http_dispatches_this_call / duplicates_suppressed_this_call
  verification_status / full_multi_origin_execution_enabled=false
```

`agent_statuses.fuzzing` riêng origin đổi thành success/partial/failed/skipped;
không gán trạng thái hoàn thành cho toàn pipeline. Candidate chỉ đổi
`attempted=true` sau attempt thực. `verified=null`, `verification_status=not_verified`
vẫn giữ nguyên; HTTP 200/302/404 chỉ là `observed_response`.

`selected` đếm ID duy nhất trong kế hoạch; `attempted` là dispatch bắt đầu tại
reservation của transport, gồm lỗi DNS/TCP/TLS/timeout; response chỉ tính khi có
HTTP status thực. Lỗi trước dispatch không tiêu thụ quota và nằm trong unattempted.
`errors` đếm attempt có lỗi transport/đọc body; HTTP 4xx hợp lệ không bị tính như
lỗi mạng. Body không lưu trong ledger; số byte là phần thực đọc/giữ lại, không
phải Content-Length suy đoán. Thời gian dùng phép đo transport hiện có, bao gồm
thời gian chờ slot rate; có thể bằng 0 ở request localhost ngắn hơn độ phân giải
đồng hồ. Không dùng con số này làm latency TCP/TLS riêng biệt.

Runtime snapshot thêm `http_dispatches_by_origin`, `http_origin_max_requests`,
`origin_reservations` (sequence/origin/monotonic timestamp). Dữ liệu này nối
ledger với các lần reservation và dùng đối chiếu pacing; không chứa credentials.
Monotonic timestamp chỉ so sánh trong cùng tiến trình/phiên.

## Trạng thái, credentials và lưu bằng chứng

- Hết toàn bộ candidates và không lỗi/stop: completed ở tầng dispatch.
- Có phản hồi nhưng còn candidate bị chặn/lỗi/stop: partial; không mất response.
- Không có response và bị lỗi/stop: failed. Không selected: skipped.
- Hết per-origin quota: `origin_request_budget`; origin khác còn quota có thể
  chạy nếu **global** runtime chưa dừng. Hết global: `http_request_budget` chặn tất cả.
- 401/403/407/429 và Retry-After: stop toàn runtime theo policy hiện có. Không
  đổi origin để đi tiếp. Redirect được ghi nhận nhưng không follow.
- TLS verification bắt buộc; proxy môi trường bị vô hiệu theo B1 transport.
- Credential values chỉ ở `OriginCredentialContext` riêng của runtime; binding
  phải khớp origin/profile hiện tại. Thiếu hoặc bị đổi binding sẽ chặn trước HTTP.
  Approved origin không mặc nhiên nhận credentials; không dùng cookie jar chung.
- Artifact writer hiện có lưu sanitized state lúc lập kế hoạch, sau mỗi kết quả
  hoặc chặn, khi interrupted và khi kết thúc. Không lưu raw headers/body hay text
  lỗi có thể chứa secret. Mỗi lần gọi tạo thư mục riêng; dữ liệu origin trước
  vẫn còn khi origin sau lỗi. Giữ provenance qua candidate ID/evidence refs và
  observation đã có trong state, không chép lại toàn bộ nguồn vào từng event.

Ledger trong runtime chống lặp `(origin, candidate_id)` kể cả đổi thứ tự hoặc gọi
lại harness. Không retry những record đã thử hoặc đã bị chặn. Chạy đồng thời hai
lần harness trên một runtime bị từ chối. Resume checkpoint với **runtime mới**
bị từ chối; chưa có cơ chế phục hồi counters qua tiến trình mới trong B3.1.

## Kiểm thử và mức bằng chứng

Chạy từ repository root trong PowerShell, không dùng `.env`, không HTTP Internet:

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:B31_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b31_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $env:B31_EVIDENCE_DIR -Force | Out-Null
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_dispatch*.py' -v 2>&1 |
    Tee-Object -FilePath (Join-Path $env:B31_EVIDENCE_DIR 'tests.log')
.\.venv\Scripts\python.exe -B scripts/verify_origin_dispatch_evidence.py $env:B31_EVIDENCE_DIR --negative-checks
```

Verifier dùng stdlib và bộ kiểm chứng nguồn B2.2 độc lập, không import dispatcher,
không gọi HTTP/LLM. Nó đối chiếu HTML/JS/OpenAPI được server thực trả về, observation,
selection, ledger, log riêng ba server, telemetry, checkpoint/result và credentials
đã che. `--negative-checks` sửa bản sao artifacts để chứng minh sai method/status/
counter/request ngoài scope đều bị phát hiện; không sửa bản gốc.

Lượt nghiệm thu B3.1: [report](../output_samples/diagnostics/multi_origin_b31_20261123T043151Z/report.md),
[independent verification](../output_samples/diagnostics/multi_origin_b31_20261123T043151Z/full/independent_verification.json).
36 tests mới PASS; full suite 614 tests, 613 PASS và một lỗi LLM timeout có sẵn,
đã tái hiện trên clean HEAD 6cea1d6. Không nâng timeout/dependency để che lỗi.
Mức B3.1: **implemented, unit_verified, integration_verified**; Internet/TLS thực
đa origin ngoài lab và full pipeline **not_verified**. Không suy ra endpoint đã
được giám định hợp lệ từ HTTP 200 lab.

## Bàn giao B3.2/B4 và method cho generated candidates

B3.2 cần thiết kế phục hồi ledger/counters nguyên tử khi tiến trình mới nhận
checkpoint, scheduling và xử lý ngắt giữa reserve/send/save, cũng như evidence
cho engine khác nếu sau này cần. B4 cần guard Parameter/Soft404 và baseline riêng
origin trước khi mở full graph. Đây là công việc chưa triển khai trong B3.1.

Đề xuất task riêng cho generated candidates, **chưa cấp quyền hay triển khai**:

| Trường | Nguồn và ý nghĩa |
|---|---|
| observed_method | Method có bằng chứng nguồn; null vẫn là null. |
| planned_test_method | Chỉ từ kế hoạch operator đã duyệt, không lấy từ LLM/candidate; B3.1 luôn null. |
| execution_method | Method thực đã gửi; null nếu chưa attempt. |

Kế hoạch tương lai nên có approval ID, candidate ID, exact origin/path/query,
method, operation=read_only, credential profile ID (không value), hạn dùng và
quota. Approval không sửa observed_method hoặc provenance. Ngay trước dispatch
phải giao scope plan với scope runtime và kiểm tra approval còn hiệu lực; thiếu
bất kỳ phần nào thì fail-closed. Cần test âm tính cho approval giả/hết hạn/sai
identity, query thay đổi, endpoint đổi trạng thái và chống replay; HTTP localhost
chứng minh planned GET không bị ghi thành observed GET. Không tự cho GET trên
mọi generated path và không dùng đề xuất này để chạy candidates trong B3.1.
