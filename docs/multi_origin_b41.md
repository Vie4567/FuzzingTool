# B4.1 — Multi-Origin Parameter Discovery & Verification (Agent 4)

B4.1 cho Agent 4 (`ParamDiscoveryAgent`) tiêu thụ **phản hồi HTTP mà Agent 3 đã
thực sự quan sát** (B3.1) và kiểm chứng query parameter theo từng origin bằng
phép so sánh đối chứng có giới hạn đã có sẵn trong `verify_parameters`. Một
runtime chung, không tạo budget mới theo origin. Gate production vẫn
`not_enabled_b1`; không tích hợp Agent 4/5 vào LangGraph (B4.2); không gọi
Agent 5; không recovery cho probe tham số.

## Gate và phạm vi

- Entry point Python: `ParamDiscoveryAgent.verify_origin_parameters(state, transport=..., artifact_root=..., max_requests=None)`
  → `src/tools/origin_parameters.verify_origin_parameters`. Không có cờ JSON/SharedState/env.
- Bắt buộc: runtime chung đang mở, `http_origin_max_requests` khớp đúng approved origins,
  `origin_contract_version=1`, đã có `fuzzing_execution.multi_origin` (B3.1),
  policy snapshot trong state trùng policy của transport, chưa có kết quả B4.1 trước đó.
- Fail-closed (ValueError, không HTTP): runtime đang gắn recovery journal
  (`parameter_recovery_not_supported_b41`), rerun trên cùng state, thiếu quota, policy bị mở rộng.
- `execute()` một origin và `verify_parameters` không truyền `transport` giữ nguyên hành vi cũ.

## Phê duyệt của operator: `parameters` trên rule GET chính xác

B1 so khớp query chính xác nên không thể probe tham số nếu không có phê duyệt riêng.
B4.1 thêm trường tùy chọn vào rule (chỉ xuất hiện khi khai báo):

```json
{"path": "/v1/products", "methods": ["GET"], "operation": "read_only",
 "parameters": ["category", "sort"]}
```

- 1..32 tên duy nhất, dạng `[A-Za-z_][A-Za-z0-9_.-]{0,63}`, không prefix `__sentinel_`, rule phải có GET.
- `OriginScopePolicy.check(...)` B1 **không đổi**. Probe đi qua
  `check_parameter_probe(url, method)`: GET, đúng path và query gốc của rule, nối thêm
  **đúng một** cặp; tên thuộc danh sách hoặc control `__sentinel_unknown_<32 hex>`;
  giá trị chỉ thuộc `1|2|true|false|sentinel_<32 hex>`.
- `ParameterProbeTransport` (kế thừa `OriginScopedTransport`) chấp nhận URL chính xác
  hoặc probe hợp lệ, rồi chạy lại rule B1 và credential binding trên URL gốc. Mọi request
  vẫn qua `OriginScopedTransport.open` → `http_origin` → `ScopedReconTransport.open`
  (`record_http_attempt`, `cap_http_timeout`, `observe_response`, `_NoRedirect`, TLS).
- Tên nhạy cảm/đường dẫn nhạy cảm (`debug`, `token`, `redirect`, `logout`, …) vẫn bị
  `verify_parameters` loại dù operator liệt kê (`sensitive_parameter_or_path_requires_review`).

## Contract Agent 3 → Agent 4

Đầu vào: `origin_contexts[origin].context.http_dispatch.records` (B3.1). Endpoint đủ điều kiện:

| Điều kiện | Lý do loại |
|---|---|
| `recovery_state != outcome_unknown` | `source_outcome_unknown` |
| `attempted is True` | `source_not_observed` |
| không error/timeout | `source_error_or_timeout` |
| `classification == observed_response` | `source_not_observed` |
| `execution_method == GET` | `source_method_not_get` |
| status 2xx, body complete | `source_not_2xx`, `source_body_incomplete` |
| URL/method/origin khớp endpoint B2.1 và candidate B2.2 | `source_contract_changed` |
| rule B1 chính xác cho GET | `scope_denied` |
| rule có `parameters` và có ứng viên được liệt kê | `parameter_probe_not_approved`, `no_operator_listed_candidate` |
| credential binding khả dụng | `credential_or_transport_scope_denied` |

Ứng viên được gộp theo tên, giữ provenance:
`agent1_reference` (parameter Agent 1 cùng URL + GET + query, kèm `evidence_refs`),
`param_assembler_static` (ParameterAssembler không LLM, `classification=inferred`),
`agent2_parameter_support` (metadata ưu tiên B2.2). Chỉ tên được operator liệt kê mới `selected`.
Hai origin cùng `/search` là hai endpoint/ID riêng; không chuyển API URL thành frontend URL.

## Phương pháp kiểm chứng (tái sử dụng `verify_parameters`)

Mỗi endpoint: 2 baseline + 2 control tên ngẫu nhiên. Mỗi ứng viên: 2 giá trị × 2 lần lặp
+ 3 post-control (baseline mới + control tên ngẫu nhiên với chính hai giá trị thử).
`verified` chỉ khi: control ổn định, mẫu lặp ổn định, ít nhất một giá trị khác control,
post-control vẫn bằng baseline, **không reflection**. HTTP 200, reflection, fallback,
nhiễu hoặc endpoint nhạy với mọi query đều không phải bằng chứng.
`verified` nghĩa là *repeatable response effect vs negative controls*, không phải hợp lệ nghiệp vụ.

## SharedState và artifacts

`origin_contexts[origin].context.parameter_discovery` (schema_version 1): `endpoints`
(identity, `source_dispatch`, provenance, eligible/exclusion_reason, candidates với
selected/selection_reason/verification/verification_reason/verification_evidence:
controls/samples/post_controls/reflection_detected), `requests` (mọi attempt thật:
path, query, kind, status, digest, error, response_time, runtime_sequence), `counts`,
`origin_budget_before/used/limit`, `status`, `stop_reason`. `agent_statuses.param_disc`
theo origin. Tổng hợp ở `parameter_execution.multi_origin`
(`langgraph_integration=not_enabled_b41`, `recovery_support=not_supported_b41`).
Unknown giữ `null`/`not_checked`; timeout giữ `status_code=null`. Checkpoints
`*_b41_parameters.json` qua `RunArtifacts` (đã che credentials).

## Kiểm chứng localhost

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'; $env:LANGSMITH_TRACING = 'false'; $env:LANGCHAIN_TRACING_V2 = 'false'
$env:B41_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b41_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_parameters*.py' -v
.\.venv\Scripts\python.exe -B scripts/verify_origin_parameter_evidence.py $env:B41_EVIDENCE_DIR --expected-cases 8 --negative-checks
```

Lab: ba server 127.0.0.1 (frontend có credential giả, gateway, origin chưa approved).
Agent 1 tải 3 tài liệu thật, Agent 2 chọn 10 endpoint, Agent 3 dispatch 10 GET, rồi
Agent 4 tiêu thụ chính SharedState đó. Server ghi log khi nhận request (trước mọi delay),
kèm body đã phục vụ để verifier tự tính lại khác biệt và reflection.

Ca chính (81 probe: frontend 33, gateway 48; runtime 13 → 94):

| Origin | Endpoint | Tham số | Kết quả |
|---|---|---|---|
| frontend | /account/orders (cần credential) | status | verified |
| frontend | /search (HTML phản chiếu) | q | inconclusive — reflected_input_requires_review |
| frontend | /app (SPA fallback 200) | tab | inconclusive — no_repeatable_response_effect |
| frontend | /missing (404), /slow (timeout) | — | loại: source_not_2xx, source_error_or_timeout |
| gateway | /search (JSON xử lý q) | q | verified |
| gateway | /v1/products | category / sort / debug / page | verified / no effect / sensitive / không được duyệt |
| gateway | /v1/echo (JSON phản chiếu) | term | inconclusive — reflected |
| gateway | /v1/noise (body ngẫu nhiên) | seed | inconclusive — unstable controls |
| gateway | /v1/strict (đổi phản hồi với mọi query) | mode | inconclusive — query-sensitive controls |

Các ca khác: global budget giữa verification (`http_request_budget`, gateway 0 probe),
quota frontend cạn cục bộ (`origin_request_budget`, gateway hoàn tất, không global stop),
429 + Retry-After trên probe dừng mọi origin, timeout probe được đếm và giữ origin còn lại,
thiếu credential binding → 0 attempt frontend, input Agent 3 bị sửa/giả `verified`/bản ghi
origin chưa approved không phải authority, runtime có recovery journal và rerun bị từ chối
không HTTP.

Verifier `scripts/verify_origin_parameter_evidence.py` (stdlib, không import `src`)
đối chiếu SharedState trước/sau, access log, budget toàn cục/theo origin, telemetry,
credential identity, scope tái suy ra từ config công khai, nguồn Agent 1–3 của từng
tham số verified, và tự tính verdict từ body server đã phục vụ. `--negative-checks`
sửa bản sao trong bộ nhớ: giả verified, đổi origin của request, thêm response không
tồn tại, giảm bộ đếm attempt, trộn control giữa hai origin — cả 5 đều bị phát hiện.

## Nghiệm thu và regression (2026-11-25)

Diagnostic: `output_samples/diagnostics/multi_origin_b41_20261125T144608Z/` (HEAD `6cea1d6`,
`source_hashes_b41.txt`, `workspace_snapshot.txt`, `flaky_investigation/`). Không commit.

| Lần chạy | Mã nguồn | Kết quả |
|---|---|---|
| Baseline trong repo (lúc preflight) | trước B4.1* | 682/682 OK |
| Baseline snapshot nguyên trạng (155 hash khớp), thiếu ffuf | trước B4.1 | 682: 668 PASS, 2 FAIL, 12 skip, cả 14 đều do thiếu binary ffuf |
| Sau B4.1 | B4.1 | 697/697 OK |
| Nghiệm thu cuối | B4.1 đã chốt | **696/697, FAIL `test_http_fuzzing.test_rate_limit_applies_to_request_starts` (0,1792 < 0,18)** |
| Regression lại | B4.1 đã chốt (hash không đổi) | 697/697 OK |
| Baseline snapshot có ffuf | trước B4.1 | 682/682 OK |

\* Lần chạy này bắt đầu trước khi sửa file nhưng còn đang chạy lúc 21:25 thì file bị sửa;
vì vậy dùng snapshot nguyên trạng làm baseline đối chiếu.

Stage verifier trên evidence mới (cùng diagnostic): B4.1 8/8 case + 5/5 mutation;
B3.1 36 test, 4/4 mutation; B3.2A 21/21 case, 4/4; B3.2B 27/27 case, 4/4.

**Test đo thời gian chập chờn (đã có bằng chứng, không phải lỗi chức năng):** test đo
`perf_counter()` lúc handler server chạy, không đo lúc client bắt đầu request.
Harness ngoài repo chạy đúng test method, mỗi lần một process, và đo thêm thời điểm
client gọi `OpenerDirector.open`:

| Lượt | Mã nguồn | FAIL | Server Δ min–max (s) | Client Δ min (s) |
|---|---|---|---|---|
| 20 tuần tự | hiện tại | 2/20 | 0,1790–0,2177 | 0,2001 |
| 20 tuần tự | snapshot | 0/20 | 0,1817–0,2213 | 0,2002 |
| 50 xen kẽ | hiện tại | 1/50 | 0,1787–0,2240 | 0,2002 |
| 50 xen kẽ | snapshot | 0/50 | 0,1834–0,2196 | 0,2001 |

Ở mọi lượt, server Δ = client Δ + (độ trễ request 2 − độ trễ request 1), sai lệch 0.
Client luôn bắt đầu cách nhau ≥ 0,2 s nên rate limiter đúng. Mọi lần FAIL đều có độ trễ
request đầu ~21–22 ms trong khi request sau ~1 ms. Outlier độ trễ request đầu xuất hiện
với tần suất như nhau ở hai phiên bản (>10 ms: 27/50 so với 31/50). 3/70 so với 0/70
không khác biệt có ý nghĩa (Fisher hai phía p ≈ 0,245). `http_fuzzing.py`, `runtime.py`,
`telemetry.py` và file test giống hệt bản trước B4.1. Chưa quan sát được lần FAIL trên
snapshot trong 70 lượt; nguồn gốc ~20 ms của request đầu (trước khi handler chạy) chưa
được xác định đến tầng hệ điều hành. Không nới ngưỡng, không skip, không sửa rate limiter.
Đề xuất sửa test tối thiểu (lúc đó chưa áp dụng): đo thời điểm client bắt đầu, hoặc gửi một
request làm nóng kết nối trước cặp đo.

### Sửa test đo thời gian (phương án 1, đã áp dụng)

Chỉ sửa `tests/test_http_fuzzing.py::test_rate_limit_applies_to_request_starts`, thêm import
`http.client` và `unittest.mock.patch`. Test bọc `http.client.HTTPConnection.connect`, gọi
xuyên tới hàm gốc nên vẫn là HTTP localhost thật, để ghi thời điểm socket bắt đầu kết nối
sau bước chờ rate limit. Test cũng kiểm tra access log server có đúng `/one`, `/two` và có
đúng 2 lần connect. Ngưỡng giữ nguyên 0,18 s. Không sửa production code hay rate limiter:
9 file production có hash trùng trước khi sửa (`flaky_fix/production_hashes_before_fix.txt`).

| Kiểm chứng (`flaky_fix/`) | Kết quả |
|---|---|
| Negative check: `time.sleep` không chờ, chỉ trong process harness | 2/2 FAIL, Δ 0,0019 s và 0,0143 s |
| Negative check: chỉ chờ một nửa | 2/2 FAIL, Δ 0,1065 s và 0,1016 s |
| 50 lần tuần tự, test đã sửa | 50/50 PASS; Δ client 0,200117–0,201313 s |
| Cùng 50 lần đó, thước đo cũ (server arrival) | 0,1757–0,2254 s; 4 lần < 0,18 (test cũ sẽ FAIL) |
| `test_http_fuzzing.py` | 24/24 OK |
| Full regression sau khi sửa (15:28–15:37 UTC) | **697/697 OK** |

Lịch sử 696/697 ở bảng trên được giữ nguyên.

## Giới hạn và bàn giao B4.2

- Mức B4.1: **implemented, unit_verified, integration_verified** trong lab loopback HTTP.
  Giai đoạn đóng ngày 2026-11-25 sau khi sửa test đo thời gian và full regression 697/697 OK.
  Internet, TLS đa origin thật, DeepSeek, production multi-origin: **not_verified**.
- Recovery: **không hỗ trợ** cho probe tham số; có recovery journal thì từ chối trước HTTP.
  Probe không ghi reservation identity vào journal B3.2B; không replay `outcome_unknown`.
  > Ghi chú (2026-11-25): giới hạn này của B4.1 được xử lý trong lab loopback ở **B4.2A**
  > (identity probe, measurement trong journal, reconcile at-most-once, integration_verified) — xem
  > [multi_origin_b42a.md](multi_origin_b42a.md). Nhận định và nghiệm thu B4.1 ở trên giữ nguyên;
  > khi không có journal bật parameter, hành vi fail-closed của B4.1 vẫn áp dụng.
  B4.2 cần reservation/reconcile cho probe trước khi cho resume.
- LangGraph: chưa thêm `param_disc` vào `LocalOriginTest.NODES`; chưa gọi Agent 5.
- Một lỗi transport/redirect trên một endpoint dừng phần còn lại của origin đó (hành vi
  thận trọng sẵn có của `verify_parameters`); origin khác vẫn chạy nếu không có global stop.
- Deadline phase trong `ParameterProbeTransport` kiểm tra trước reservation; thời gian chờ
  rate slot có thể vượt deadline phase tối đa một khoảng 1/rate (deadline pipeline vẫn chặn).
- Chỉ query parameter với GET; không body, header, path parameter, POST/PUT/PATCH/DELETE.
- B4.2: Soft404 theo origin với baseline riêng, tích hợp Agent 4–5 vào graph local,
  recovery cho probe, rồi mới xét mở gate.
