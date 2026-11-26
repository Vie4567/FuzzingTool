# B4.2A — Parameter Probe Recovery (Agent 4 + B3.2B journal)

Trạng thái: **thiết kế đã duyệt (D1–D7 có điều chỉnh); phần implementation và nghiệm thu
được cập nhật ở cuối tài liệu.** Đánh số: B4.2A = Parameter Probe Recovery, B4.2B =
Multi-Origin Soft404, B4.2C = Full Local Graph Integration.

## 1. Kiến trúc trước B4.2A (audit, trích source)

- Journal B3.2B: hash-chain + fsync trước head (`origin_recovery.py:84-120`). `reserved` ghi
  trong `reserve_http` trước khi counter tăng (`runtime.py:96-101`); `dispatch_started`,
  `measurement` ghi trong `ScopedReconTransport.open/fetch_result` (`recon_http.py:138-151`,
  `:232-237`); `response_headers`/`stop` ở `runtime.py:114-117`.
- Reconcile (`origin_recovery.py:169-318`): `check_dispatch` exact cho mọi reservation (`:189`),
  `(origin, candidate_id)` duy nhất (`:193-196`), checkpoint chỉ kiểm `http_dispatch` (`:231-241`),
  `candidate_id=None` bị coi là recon và bỏ qua (`:281`), reuse tối đa tới `run_fuzzing` (`:335-341`).
- Recovery chỉ gắn qua `LocalOriginTest` (`origin_recovery.py:130-157`); `NODES` không có Agent 4/5
  (`origin_local.py:64-66`); `decide(after_fuzzing)` luôn `abort_to_report`; `run_param_discovery`
  không có local hook (`graph.py:916`).
- B4.1 từ chối khi có journal (`origin_parameters.py:280-282`); probe dùng `transport.open` tự đọc body
  (`parameter_verification.py:177`), không có `measurement`; checkpoint `b41_parameters` không neo
  journal (`origin_parameters.py:335`); tên control và giá trị thử ngẫu nhiên (`parameter_verification.py:303,323,345`).

## 2. Điểm chưa tương thích và rủi ro

| # | Vấn đề | Mức độ |
|---|---|---|
| R1 | Probe `candidate_id=None` bị coi là recon; baseline probe bị bỏ qua, có thể gửi lặp sau resume | Nghiêm trọng (tiềm ẩn, đang bị guard chặn) |
| R2 | Verdict trong checkpoint được nạp mà journal không chứng minh | Cao |
| R3 | Probe đo xong vẫn thành `outcome_unknown` vì không có `measurement` | Cao |
| R4 | Uniqueness `(origin, candidate_id)` không hợp với ~11 request/endpoint; probe query bị exact check từ chối | Trung bình (fail-closed) |
| R5 | Trần phase reset khi resume | Trung bình |
| R6 | Local halt bị hiểu là global stop | Trung bình (fail-closed) |
| R7 | Ghép unit dở dang với probe mới cho verdict sai | Cao nếu thiết kế sai |

## 3. Thiết kế cuối cùng

### 3.1 Probe identity và phân biệt lặp có chủ đích với replay

Mỗi probe reservation mang `probe = {version:1, endpoint_id, unit_id, ordinal, role, parameter}`:
`unit_id` là 32 hex mới cho mỗi lần đo một endpoint (một unit), `ordinal` tăng 1 cho mỗi request
**đã được reservation** trong unit, `role ∈ {baseline, control, candidate}`, `parameter` là tên
probe (null với baseline). `candidate_id=None` giữ nguyên nhánh B3.1.

- Lặp **có chủ đích** của B4.1 (2 baseline, 2 lần mỗi giá trị, post-baseline) cùng URL/query
  nhưng khác `ordinal` trong cùng unit → hợp lệ. URL/query trùng **không** phải bằng chứng replay.
- **Replay** được xác định bằng identity và epoch tiến trình (số `process_bound` trước reservation):
  `(unit_id, ordinal)` trùng; ordinal không liên tục 1..k; reservation của unit không liền mạch;
  unit kéo dài qua hai epoch (mở lại sau resume); hoặc **unit thứ hai cho cùng endpoint**.
  Tất cả → `RecoveryDenied` trước mọi HTTP.
- Identity được kiểm lại với context operator vừa cấp: loopback, `check_parameter_probe`/exact rule,
  credential binding; role phải khớp URL (baseline = URL gốc; control = tên `__sentinel_unknown_*`;
  candidate = tên được liệt kê).

### 3.2 Measurement và verdict

`record_measurement` ghi `measurement` cho mỗi probe đã dispatch: `status_code`, `content_type`,
`content_length`, `body_complete`, `body_truncated`, `body_sha256`, `normalized_sha256`,
`response_time`, `error` (chỉ exception type), `value_reflected` (candidate: số lần giá trị xuất hiện
trong body > trong baseline đầu unit; null nếu không đo được), `stop_reason` (**chỉ global stop**),
`unit_halt` (local halt). Không lưu body/header.

Verdict được **suy ra lại** từ journal theo đúng quy tắc B4.1 (4 control ổn định → mỗi ứng viên
4 sample usable, không reflection, cặp lặp ổn định, giá trị khác nhau, ít nhất một khác control,
3 post-control bằng control với đúng hai giá trị thử). `verified` trong checkpoint chỉ được giữ khi
verdict suy ra cũng là `verified` và mọi sequence liên quan có measurement khớp; mọi bất đồng →
`recovery_parameter_verdict_unproven`. Không khôi phục verdict từ số lượng measurement.

### 3.3 Nguồn có thẩm quyền khi reconcile

1. Context operator vừa cấp (policy, credentials, quotas, limits, cờ parameter) — authority.
2. Journal hash-chain + head — sự kiện đã xảy ra (reservation, dispatch, headers, measurement, checkpoint).
3. Checkpoint — dữ liệu dẫn xuất, chỉ dùng khi hash khớp journal và từng dòng request/verdict khớp journal.

SharedState hoặc một checkpoint đơn lẻ không bao giờ là bằng chứng đủ. Mỗi checkpoint
`b41_parameters` phải liệt kê **đúng** các probe reservation tới thời điểm checkpoint (không thiếu, không thừa).

### 3.4 Trạng thái

| Trạng thái | Phạm vi | Ý nghĩa | Resume |
|---|---|---|---|
| global stop | runtime | 401/403/407/429, Retry-After, budget, deadline | Chặn resume |
| local halt (`unit_halt`) | unit/origin | redirect, login/challenge, transport error trong probe | Origin không đo thêm (giữ B4.1) |
| `interrupted` | unit | có reservation nhưng kết quả unit chưa có checkpoint hợp lệ | Unit là trạng thái cuối, không gửi lại |
| `inconclusive` | ứng viên | thiếu bằng chứng hoặc bằng chứng không đạt | — |
| `outcome_unknown` | request | có reservation nhưng thiếu measurement | Không replay |
| `completed` / `halted` | unit | kết quả đã checkpoint và khớp journal | Giữ verdict hợp lệ |
| `not_started` | unit | không có reservation | Được chạy khi resume (nếu origin chưa halt) |

Ứng viên của unit `interrupted` → `inconclusive` với `probe_outcome_unknown` (có sequence thiếu
measurement) hoặc `unit_interrupted`; không bao giờ `verified`. Trần phase còn lại = trần operator
trừ số probe reservation trong journal. Budget, deadline, quota lấy từ journal, không reset.

### 3.5 Tích hợp graph tối thiểu (D7)

Chỉ qua `LocalOriginTest(..., parameter_verification=True)` (Python private, không có cờ JSON):
`run_param_discovery` thêm hook local; `decide(after_fuzzing)` → `proceed_to_param` khi không có
stop; `run_soft404_filter` được **bỏ qua không thực thi** (Agent 5 không chạy, `skipped`). Mặc định
tắt → B3.2A/B3.2B không đổi hành vi. Authority recovery chỉ thêm khóa `parameter_verification`
khi bật → journal B3.2B cũ vẫn tương thích. Gate production giữ `not_enabled_b1`.

### 3.6 Fail-closed bổ sung

Recovery có probe reservation nhưng context không bật parameter; identity probe sai schema/scope/
binding; replay theo §3.1; checkpoint parameter thiếu/thừa request hoặc lệch measurement; verdict
không chứng minh được; journal có probe nhưng state khôi phục không có `parameter_discovery`.

### 3.7 Điều chỉnh khi implementation

- Trần phase là tham số **private** `LocalOriginTest(parameter_max_requests=...)` và nằm trong
  recovery authority. Không thêm khóa config công khai vì `validation.py` từ chối khóa lạ; contract
  config và gate không đổi. Đổi trần khi resume → `recovery_authority_changed`.
- Agent 4 gọi `verify_parameters` **từng endpoint** để mỗi unit có checkpoint `parameters_unit_measured`.
  Đã kiểm chứng B4.1 vẫn dừng phần còn lại của origin sau local halt (bằng chứng B4.1: sau
  `transport_error` chỉ có 5 request `/v1/products`) và giữ nguyên ngữ nghĩa này.
- Lab dùng case ID ngắn vì đường dẫn checkpoint lồng nhau vượt MAX_PATH Windows; khi không ghi được
  checkpoint, pipeline fail-closed (`ArtifactWriteError`) — đúng thiết kế.

## 4. Kế hoạch kiểm thử

- Unit (không socket): identity/uniqueness/epoch, role-URL, suy verdict (verified, reflected,
  unstable, no effect, thiếu sample), checkpoint thiếu/thừa/lệch, trạng thái unit, trần phase.
- Integration (loopback, kill thật): crash trước reservation probe, sau reservation, sau server nhận,
  sau headers, sau measurement trước checkpoint, sau checkpoint unit, giữa hai origin, sau checkpoint
  node; 429 trong probe; trần phase; journal giả mạo nhất quán (rehash) bị phát hiện.
- Independent verifier (stdlib): journal ↔ checkpoint ↔ access log; không replay theo identity;
  verdict tái suy từ body server; counters; negative mutations.

## 5. File và hàm đã thay đổi (so với snapshot trước B4.2A, 160 file đã băm)

| File | Thay đổi |
|---|---|
| `src/tools/recon_http.py` (+3) | `ScopedReconTransport.open`: chép `probe` công khai vào identity reservation |
| `src/tools/origin_parameters.py` (+397/−51) | `ParameterProbeTransport`: `classify`, `check_global`, `begin_unit` (unit mới), `open` (identity + ordinal theo reservation), `record_measurement` (journal `measurement` trước khi tạo dòng, `value_reflected`, `unit_halt`); `verify_origin_parameters` gọi theo endpoint, neo checkpoint, resume, giữ trần phase; mới `derive_unit_verdicts`, `reconcile_probe_recovery`, `TERMINAL_UNITS` |
| `src/coordinator/origin_recovery.py` (+28/−6) | `authority` thêm khóa parameter khi bật; `_restore` chuyển probe reservation sang reconcile; `reuse` thêm `run_param_discovery`; `parameter_outcome_unknown_sequences` |
| `src/coordinator/origin_local.py` (+53/−6) | `parameter_verification`, `parameter_max_requests`; `_LoopbackProbeTransport`; hook `parameters`; `decide(after_fuzzing)` → `proceed_to_param`; bypass Agent 5; `continuing_node` cho Agent 4 |
| `src/coordinator/graph.py` (+2) | hook local đầu `run_param_discovery`; topology không đổi |

Mới: `tests/test_origin_parameter_recovery.py` (9 unit), `tests/test_origin_parameter_recovery_http.py`
(16 integration), `tests/origin_parameter_recovery_worker.py`, `scripts/verify_origin_parameter_recovery_evidence.py`.
Không sửa test/verifier của B3.1–B4.1, `validation.py`, dependencies.

## 6. Contract trước / sau

| Mục | Trước | Sau |
|---|---|---|
| Probe reservation | `candidate_id=None`, không identity riêng | thêm `probe{version, endpoint_id, unit_id, ordinal, role, parameter}` |
| Probe measurement | không có | `measurement` (status, content type, length, body digests, complete/truncated, thời gian, exception type, `value_reflected`, `stop_reason` global, `unit_halt`) |
| Checkpoint Agent 4 | không neo journal | neo journal ở planned/resumed/unit/origin/finished/interrupted |
| Endpoint row | — | `unit_id`, `unit_state` |
| Request row | metadata đo | + `unit_id`, `ordinal`, `role`, `parameter`, `value_reflected`, `unit_halt`, `recovery_state` khi khôi phục |
| Section | status/stop | + `final`, `origin_halt` |
| `parameter_execution.multi_origin` | `recovery_support=not_supported_b41` | `recovery_support=not_bound|journaled_b42a`, `resumed`; `langgraph_integration=local_parameter_stage_b42a` khi chạy trong graph local |
| Có journal mà không bật parameter | `parameter_recovery_not_supported_b41` | giữ nguyên (fail-closed) |
| Journal B3.2B cũ | — | authority không đổi khi tắt → resume B3.2B như trước |

## 7. Acceptance criteria và bằng chứng

| # | Tiêu chí | Bằng chứng |
|---|---|---|
| 1 | Không gửi lại probe đã có reservation | integration: reserved, server-received, headers, measurement; verifier: ánh xạ tuần tự server↔reservation, identity duy nhất, không mở lại unit |
| 2 | Không `verified` từ unit dở dang/bằng chứng thiếu | integration: measurement-trước-checkpoint → `unit_interrupted`; unit: thiếu measurement/sample, reflection null; verifier: tái suy từ body server |
| 3 | Bộ đếm không reset | runtime = số reservation = per-origin; trần phase 15 giữ; đổi trần → từ chối |
| 4 | Fail-closed trước HTTP | global stop, authority đổi, verdict giả (rehash), xoá measurement (rehash), relabel identity (rehash) → 0 request mới |
| 5 | Credential/scope | gateway luôn anonymous; không secret trong journal/result; unapproved 0 request |
| 6 | Unknown giữ null | `outcome_unknown` status null; verifier phát hiện "laundering" |
| 7 | Regression | xem §8 |

## 8. Kết quả nghiệm thu (diagnostic `output_samples/diagnostics/multi_origin_b42a_20261125T162822Z/`)

HEAD `6cea1d6`, không commit. `source_hashes_start.txt` = `source_hashes_end.txt` (không đổi trong lúc chạy).

| Bước | Kết quả |
|---|---|
| Baseline trước B4.2A (15:54–16:01 UTC, source chưa sửa) | **697/697 OK** |
| B4.2A unit + integration | **25/25 OK** (9 + 16) |
| Verifier B4.2A `--expected-cases 16 --negative-checks` | **16/16 case PASS; 6/6 mutation bị phát hiện** (replayed server request, verified interrupted unit, unit reopened after resume [rehash], counter lowered, outcome_unknown laundered, verified-unit measurement dropped [rehash]) |
| B3.1 tests / verifier | 36/36 OK; integration_verified, 4/4 mutation |
| B3.2A tests / verifier | 30/30 OK; 21/21 case, 4/4 mutation |
| B3.2B tests / verifier | 38/38 OK; 27/27 case, 4/4 mutation |
| B4.1 tests / verifier | 15/15 OK; 8/8 case, 5/5 mutation |
| Full regression trên source cuối | **722/722 OK** (697 + 25) |

Gate: `validate_input` giống hệt bản trước B4.2A; `origin_execution_mode=not_enabled_b1` trong mọi
kết quả local. Single-origin: `run_param_discovery` chỉ rẽ nhánh khi có `LocalOriginTest`.

## 9. Mức nghiệm thu

**B4.2A: implemented, unit_verified, integration_verified** trong lab loopback (Python HTTP, tuần tự,
kill tiến trình thật). **not_verified:** Internet/TLS đa origin thật, DeepSeek, production multi-origin,
mất điện/reboot, nhiều process ghi đồng thời ngoài khóa OS, exactly-once delivery (không tuyên bố).

## 10. Giới hạn còn tồn tại

- At-most-once: unit đã có reservation nhưng chưa có checkpoint hợp lệ là trạng thái cuối
  (`inconclusive`); kết quả đo xong nhưng chưa checkpoint không được nâng thành `verified`.
- Một endpoint chỉ được đo bởi một unit mỗi session; không có "đo lại".
- Hash chain không chống kẻ có toàn quyền ghi; các kiểm tra ngữ nghĩa (identity, verdict tái suy,
  checkpoint↔journal) phát hiện các giả mạo đã thử, không phải mọi giả mạo khả dĩ.
- Agent 5 chỉ bị bỏ qua; routing đầy đủ, Soft404 theo origin chưa có. Chỉ query/GET.
- `docs/multi_origin_b41.md` vẫn ghi "recovery: không hỗ trợ" cho B4.1 (đúng với B4.1; chưa sửa).

## 11. Điều kiện bàn giao B4.2B (Multi-Origin Soft404)

Dùng chung runtime/journal; Agent 5 cần identity, measurement và checkpoint neo journal theo cùng
mẫu, baseline Soft404 riêng từng origin, verdict tái suy được từ journal, và bypass Agent 5 trong
`LocalOriginTest` được thay bằng hook thật. Gate giữ `not_enabled_b1` cho tới B4.2C.
