# B4.2B — Multi-Origin Soft404 (Agent 5)

Trạng thái: **đã triển khai và nghiệm thu — `integration_verified` trong lab loopback**
(D1–D7, quyết định D2/D5/D6; mục 4–12). Production gate vẫn `not_enabled_b1`. Đánh số: B4.2A Parameter Probe Recovery (xong), **B4.2B Soft404**,
B4.2C Full Local Graph Integration.

## 1. Kiến trúc Agent 5 trước B4.2B (audit)

- Node `run_soft404_filter` (`graph.py:1002`): input `raw_results` single-origin (+ `param_results`
  khi Agent 4 chưa có trạng thái, `:1013`); options `soft404_options_from_config` (`:1029`); output
  `verified_results`/`unverified_results`/`false_positives`/`baseline_signature`/`soft404_stats`.
- Gating `soft404_filter.py:19-98`: dừng khi upstream stop/partial/simulated; cần
  `verification_context.route == direct` và `auth_matches_operator`.
- Comparator `verify_soft404` (`soft404.py:207-518`): nhóm theo `_group_key = (scheme, netloc,
  parent, suffix, query)` (`:172-180`); 3 control `__sentinel_missing_<hex><suffix>` cùng thư mục cha
  (`:200-204`); control ổn định (`:455-464`); candidate đo lại một lần (`:476`); `http_404`,
  `soft_404`, `inconclusive` (root/ambiguous), `genuine` (`:488-508`); halt toàn cục trong một lần gọi.

## 2. Vấn đề multi-origin (audit)

1. `ScopedVerificationTransport` (`soft404.py:237-239`) không đặt `http_origin` (quota theo origin
   → `OriginBudgetExhausted`, `runtime.py:76`), không gửi identity (`verification_http.py:114` →
   `recovery_request_identity_missing`, `origin_recovery.py:342`), không bind credential theo origin.
2. URL control nằm ngoài scope exact B1.
3. Root detection theo `target_url` (`soft404.py:500`); gating theo `verification_context` single-target.
4. Halt toàn cục trong một lần gọi; control của nhóm đo lúc gặp candidate đầu tiên → reservation
   không liền mạch nếu gom nhiều nhóm.
5. `genuine`/`soft_404` theo similarity cần body; journal chỉ có digest.

## 3. Thiết kế cuối cùng

### D1 — Transport
`verify_soft404(..., transport=None)` nhận transport được truyền vào (không có thì giữ nguyên
`ScopedVerificationTransport`). `Soft404ProbeTransport` (`src/tools/origin_soft404.py`) kế thừa
`OriginScopedTransport` (`http_origin`, credential binding, `_NoRedirect`, TLS, reservation trước socket).

### D2 — `soft404_controls` (operator, mặc định không cấp)
Rule GET exact có thể khai báo `"soft404_controls": true` (chỉ chấp nhận `true`; vắng = không cấp).
`OriginScopePolicy.check_soft404_control(url, method)` chỉ cho phép GET tới
`<thư mục cha của rule>/__sentinel_missing_<32 hex><suffix của rule>` với **đúng query của rule**,
cùng origin. `check()` B1, `check_parameter_probe()` B4.1 không đổi. Endpoint chỉ được phân loại khi
**chính rule của nó** có `soft404_controls`. Discovery, SharedState, checkpoint, Agent 4 không là authority.

### D3 — Theo origin, theo nhóm
Một lần `verify_soft404` cho một nhóm (control + candidate cùng `_group_key`) của một origin, với
`target_url = origin + "/"` (root theo origin, không đổi comparator). Local halt dừng origin đó;
global stop dừng tất cả. Trần phase private `soft404_max_requests`. Kết quả riêng theo origin ở
`origin_contexts[o].context.soft404`.

### D4 — Ngữ nghĩa
`soft404_classification ∈ {genuine_distinct, soft_404, http_404, inconclusive, not_checked}`;
endpoint giữ `verification_status = not_verified`. `genuine_distinct` = representation khác biệt,
không phải endpoint hợp lệ nghiệp vụ. Agent 4 chỉ là `parameter_context` (tham khảo), không nâng
phân loại. Dữ liệu: *observed* (Agent 3 + phép đo lại), *inferred* (phân loại), *context*.

### D5 — Journal và mức bằng chứng
Identity reservation `soft404 = {version:1, stage:"soft404", group_id, unit_id, ordinal, role,
endpoint_id}` (role `control`|`candidate`; `endpoint_id` null với control; key khác `probe` của B4.2A).
`measurement` cho mỗi request đã dispatch (status, type, length, body/normalized digest, complete,
truncated, html, login/challenge, exception type, global stop, `unit_halt`) — không lưu body.
Sau mỗi nhóm: `soft404_group` (control sequences, stable, reason, control metrics) và
`soft404_decision` cho mỗi candidate đã đo (sequences, metrics, classification) **trước** checkpoint neo journal.

Mức bằng chứng:

| Mức | Khi nào |
|---|---|
| `rederived` | Kết luận suy lại hoàn toàn từ measurement trong journal: control không dùng được, status/type không ổn định, `http_404`, candidate không dùng được, khớp digest chính xác (normalized/body) với mọi control, halt |
| `metrics_journaled` | Kết luận cần similarity: kiểm tra quy tắc ngưỡng trên **metric đã ghi**, đối chiếu cờ exact với digest và `length_ratio` với độ dài đo được. **Không** phải tính lại similarity từ body |
| `inconclusive` | Bằng chứng không đạt điều kiện comparator |
| `interrupted` | Nhóm có reservation nhưng thiếu measurement/decision/checkpoint hợp lệ — trạng thái cuối, không gửi lại |

Khi reconcile: phân loại mạnh (`genuine_distinct`, `soft_404`, `http_404`) chỉ giữ khi suy lại đúng
lớp đó; mọi bất đồng → `recovery_soft404_classification_unproven`. Lúc chạy bình thường, wrapper
cũng suy lại để gắn mức bằng chứng; nếu bất đồng với comparator → hạ `inconclusive`
(`derivation_mismatch`). Digest khớp không thay thế các điều kiện khác (usable, same type, root).

### D6 — Helper dùng chung tối thiểu
Chỉ tách các kiểm tra toàn vẹn chung (epoch tiến trình; ordinal liên tục, liền mạch, một epoch,
một unit mỗi khóa; dòng checkpoint ↔ journal đúng phủ và đúng trường). Logic nghiệp vụ Parameter
và Soft404 giữ riêng. Mã lỗi và ngữ nghĩa B4.2A không đổi.

### D7 — Graph local tối thiểu
`LocalOriginTest(..., soft404_verification=True, soft404_max_requests=N)` (Python-only): hook thật
trong `run_soft404_filter`; `decide(after_fuzzing)` → `proceed_to_param` khi bật Agent 4, ngược lại
`skip_to_filter`. Authority recovery thêm khóa chỉ khi bật. Gate `not_enabled_b1`. Nghiệm thu toàn
graph thuộc B4.2C.

## 4. Hợp đồng trước / sau

| Mục | Trước B4.2B | Sau B4.2B |
|---|---|---|
| `verify_soft404` | Luôn tự tạo `ScopedVerificationTransport` | Thêm `transport=None`. Nếu truyền transport thì transport đó quyết định network policy. Truyền kèm headers, allowed_origins, auth_origins, `verify_ssl≠True`, `tls_ca_file` hoặc proxy sẽ báo `ValueError`. Không truyền transport thì giữ hành vi cũ |
| Rule scope B1 | `method/path/query/read_only/credential_profile/parameters` | Thêm khóa `soft404_controls`. Chỉ nhận `true` và chỉ cho rule GET. Không khai báo nghĩa là không cấp |
| `OriginScopePolicy` | `check`, `check_parameter_probe` | Thêm `check_soft404_control(url, method)`. Hai hàm cũ không đổi |
| Recovery identity | Chép `probe` (B4.2A) | Chép `probe` và `soft404` |
| Journal events | B3.2B và `measurement` của probe | Thêm `measurement` cho soft404, `soft404_group`, `soft404_decision` |
| `LocalOriginTest` | Agents 1–3, thêm Agent 4 khi bật `parameter_verification` | Thêm `soft404_verification`, `soft404_max_requests` (chỉ đặt được trong Python). Agent 5 chạy thật qua hook `run_soft404_filter` |
| Production gate | `multi_origin_execution_not_enabled_b1` | Không đổi (`graph.py:355`, `origins.py:134`) |

## 5. File và hàm thay đổi

File mới:
- `src/tools/origin_soft404.py` (671 dòng). Gồm `Soft404ProbeTransport` (`classify`, `check_dispatch`, `open`, `record_measurement`), `group_id`, `derive_group`, `derive_candidate`, `_consistent`, `_derive_row`, `_plan`, `verify_origin_soft404` và `reconcile_soft404_recovery`.
- `src/coordinator/recovery_units.py` (73 dòng, theo D6). Gồm `process_epochs`, `check_units` và `check_checkpoint_rows`.
- `scripts/verify_origin_soft404_evidence.py` (412 dòng). Chỉ dùng stdlib, không import `src`.
- Test: `tests/test_origin_soft404.py` (16 test), `tests/test_origin_soft404_http.py` (9 test), `tests/test_origin_soft404_recovery_http.py` (17 test) và worker `tests/origin_soft404_recovery_worker.py`.

File sửa (chỉ thêm, ở mức tối thiểu):
- `src/tools/soft404.py`: thêm tham số `transport`.
- `src/coordinator/origins.py`: validate `soft404_controls`.
- `src/tools/origin_scope.py`: thêm `check_soft404_control`.
- `src/tools/recon_http.py`: thêm identity `soft404`.
- `src/tools/origin_parameters.py`: `reconcile_probe_recovery` chuyển sang dùng helper D6, giữ nguyên mã lỗi và thứ tự kiểm tra.
- `src/coordinator/origin_recovery.py`: cờ `soft404_probes`, authority, gọi `reconcile_soft404_recovery`, thêm `run_soft404_filter` vào danh sách node reuse.
- `src/coordinator/origin_local.py`: chế độ soft404, `decide`, hook `soft404`.
- `src/coordinator/graph.py`: thêm 2 dòng hook trong `run_soft404_filter`.
- `src/agents/soft404_filter.py`: thêm `verify_origin_soft404`.

## 6. Tiêu chí nghiệm thu và bằng chứng

| # | Tiêu chí | Bằng chứng | Mức |
|---|---|---|---|
| 1 | Control phải cùng origin, cùng thư mục cha, cùng suffix và query, tên sentinel 32 hex, method GET. Chỉ được phép khi rule có `soft404_controls` | `Soft404ScopeTests` (4 test). Verifier kiểm scope control. Mutation `control_borrowed_from_other_origin` | integration_verified |
| 2 | Không trộn origin hay nhóm; mỗi origin dùng control riêng | `test_real_chain_classifies_each_origin_with_its_own_controls`. Verifier kiểm cô lập origin và nhóm | integration_verified |
| 3 | Reservation có trước socket. Quota theo origin chỉ dừng origin đó. Global budget hoặc 429 dừng mọi origin. Timeout vẫn được đếm | `test_origin_quota_exhaustion_is_local`, `test_global_budget_stops_mid_classification`, `test_429_on_control_stops_all_origins`, `test_control_timeout_is_counted_and_preserves_other_origin`. Verifier đối chiếu log server với counter. Mutation `attempt_counter_lowered`, `control_without_reservation` | integration_verified |
| 4 | Thiếu credential binding thì fail-closed trước khi có attempt | `test_missing_credential_binding_fails_closed_before_attempt`, `test_transport_rechecks_binding_on_approving_rule` | integration_verified |
| 5 | Agent 3, Agent 4 và SharedState không phải authority. Parameter đã verified không nâng endpoint lên verified | `test_tampered_agent3_input_is_not_authority`, `test_parameter_verified_is_context_only` (`parameter_context.authority = context_only`, `verification_status = not_verified`) | integration_verified |
| 6 | Phân loại khớp comparator thật; gán đúng mức `rederived` hoặc `metrics_journaled` | `Soft404DerivationParityTests` (6 test, so với `verify_soft404` thật). Verifier tính lại similarity từ body server bằng normalizer riêng. Mutation `inconclusive_upgraded` | integration_verified |
| 7 | Metric bị sửa phải bị từ chối, kể cả khi digest đã đủ để quyết định | `test_tampered_metric_is_rejected_even_when_digests_decide`, `test_consistently_tampered_metric_is_rejected`. Mutation `journaled_metric_tampered` | integration_verified |
| 8 | Recovery at-most-once: không gửi lại reservation. Nhóm chưa có checkpoint thành `interrupted`. Nhóm đã có checkpoint giữ phân loại | Các case kill/restart `test_crash_*` (7 case) và `test_decisions_without_checkpoint_do_not_restore_classification` trong `test_origin_soft404_recovery_http.py`. Mutation `replayed_server_request`, `strong_class_decision_removed` | integration_verified |
| 9 | Từ chối resume thiếu ngữ cảnh soft404, từ chối rerun và đổi phase cap. Cap không bị reset khi resume | `test_resume_without_soft404_context_is_denied`, `test_recovery_without_soft404_context_and_rerun_fail_closed`, `test_phase_cap_is_not_reset_on_resume` | integration_verified |
| 10 | B4.2A không đổi sau D6 | B4.2A 25/25. Verifier 16 case, 6 mutation | integration_verified |
| 11 | Single-origin và B3.1–B4.2A giữ nguyên | Full regression 764/764. 5 verifier của các stage trước đều PASS | integration_verified |
| 12 | Gate vẫn đóng | `validate_input` không đổi; test gate nằm trong regression | unit_verified |

Phân loại kỳ vọng trong lab (khớp với verifier):

| Origin | Path | Phân loại | Mức |
|---|---|---|---|
| A | `/` | inconclusive (root) | rederived |
| A | `/promo` | soft_404 | rederived |
| A | `/help` | genuine_distinct | metrics_journaled |
| A | `/docs/legacy` | soft_404 | metrics_journaled |
| B | `/promo` | genuine_distinct | metrics_journaled |
| B | `/v1/products` | genuine_distinct | metrics_journaled |
| B | `/v1/ghost` | http_404 | rederived |
| B | `/v2/items` | inconclusive | metrics_journaled |
| B | `/v1/secret` | not_checked (rule không có `soft404_controls`) | — |

Số request Soft404: origin A 10, origin B 12, tổng 22.

## 7. Kết quả kiểm thử (nghiệm thu cuối, 2026-11-25 17:33–17:54 UTC)

| Bước | Kết quả |
|---|---|
| Baseline trước khi sửa code (16:56–17:06 UTC) | 722/722 OK |
| B4.2B (`test_origin_soft404*.py`) | 42/42 OK (16 unit, 9 in-process, 17 recovery), exit 0 |
| Verifier B4.2B (`--expected-cases 26 --negative-checks`) | 26/26 case PASS, phát hiện 7/7 mutation, exit 0 |
| B3.1 | 36/36 OK. Verifier PASS, 4/4 mutation |
| B3.2A | 30/30 OK. Verifier 21/21 case, 4/4 mutation |
| B3.2B | 38/38 OK. Verifier 27/27 case, 4/4 mutation |
| B4.1 | 15/15 OK. Verifier 8/8 case, 5/5 mutation |
| B4.2A | 25/25 OK. Verifier 16/16 case, 6/6 mutation |
| Full regression | 764/764 OK (722 + 42). 0 FAIL, 0 ERROR, 0 SKIPPED, exit 0 |
| Hash source (`src`, `tests`, `scripts`) đầu và cuối nghiệm thu | 142 file, giống hệt nhau |
| `git status` đầu và cuối nghiệm thu | 50 mục, giống hệt nhau (40 mục có từ trước B4.2B và 10 mục của B4.2B) |

Mutation của verifier B4.2B: `control_borrowed_from_other_origin`, `inconclusive_upgraded`, `control_without_reservation`, `attempt_counter_lowered`, `strong_class_decision_removed`, `journaled_metric_tampered`, `replayed_server_request`. Mutation sửa trên **bản sao** evidence. Journal được băm lại cho nhất quán, nên mutation chỉ bị bắt nhờ kiểm tra ngữ nghĩa chứ không nhờ hash.

Ghi chú quy trình: code được viết trước test, theo thiết kế đã duyệt, tức là lệch TDD. Phần bù gồm test parity với comparator thật và tiêm lỗi có kiểm soát: 4/4 lỗi làm test đỏ, khôi phục code thì 16/16 xanh. Quá trình này phát hiện và sửa một lỗ hổng: khi digest đã đủ để quyết định, metric đã ghi không được kiểm tra nhất quán. Hiện `_derive_row` kiểm mọi metric trước khi suy lại.

## 8. Mức bằng chứng và giới hạn đảm bảo

- `rederived`: kết luận suy lại hoàn toàn từ measurement trong journal (status, type, digest, độ dài).
- `metrics_journaled`: kết luận dựa vào similarity. Recovery chỉ kiểm quy tắc ngưỡng trên metric đã ghi, đối chiếu cờ exact với digest và `length_ratio` với độ dài. Journal không lưu body nên **không tính lại được similarity từ journal**. Chỉ verifier trong lab tính lại được, từ body do server trả.
- Hash chain phát hiện được sửa đổi lẻ tẻ và torn write. Nó **không** chống được người có toàn quyền ghi, vì người đó có thể ghi lại cả chuỗi lẫn `head.json`. Các mutation "nhất quán" bị bắt nhờ kiểm tra ngữ nghĩa và đối chiếu log server trong lab, không phải nhờ hash.
- Recovery là at-most-once, không phải exactly-once.

## 9. Giới hạn còn lại (`not_verified`)

- Internet, TLS thật giữa các origin, proxy, ffuf, DeepSeek hoặc LLM thật, multi-origin production.
- Độ bền khi mất điện. Mới chỉ kiểm khi kill tiến trình.
- Chỉ chạy trong lab loopback. Graph local chỉ tích hợp tới mức test cần (`langgraph_integration = local_soft404_stage_b42b`). Nghiệm thu toàn graph Agents 1→5 kèm report và reflection thuộc B4.2C.
- `genuine_distinct` chỉ là phân loại representation, không xác nhận endpoint hợp lệ về nghiệp vụ. Endpoint vẫn `not_verified`.
- Một phiên đã phân loại không được chạy lại (fail-closed).

## 10. Đường dẫn bằng chứng

Thư mục `output_samples/diagnostics/multi_origin_b42b_20261125T173300Z/` (gitignored), HEAD `6cea1d6`, gồm:
- `acceptance.log`, `b42b_tests.log`, `b42b_verifier.log`;
- `b42b/`: 26 case và `independent_verification.json`;
- `B31|B32A|B32B|B41|B42A_{tests,verifier}.log` cùng thư mục evidence tương ứng;
- `full_regression.log`, `source_hashes_{start,end}.txt`, `git_status_{start,end}.txt`.

Lệnh tái lập:

```powershell
$env:B42B_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b42b_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_soft404*.py' -v
.\.venv\Scripts\python.exe -B scripts/verify_origin_soft404_evidence.py $env:B42B_EVIDENCE_DIR --expected-cases 26 --negative-checks
```

## 11. Kết luận nghiệm thu

B4.2B đạt **`integration_verified`** trong lab loopback:
- 42/42 test pass;
- verifier 26/26 case, phát hiện 7/7 mutation;
- 5 verifier của các stage trước PASS trên evidence mới;
- full regression 764/764;
- source không đổi trong lúc nghiệm thu;
- gate `not_enabled_b1` giữ nguyên.

Mọi thứ ngoài lab vẫn `not_verified`.

## 12. Điều kiện bàn giao sang B4.2C

B4.2C (Full Local Graph Integration) chưa bắt đầu. Đầu vào đã sẵn có:
- Agent 4 và Agent 5 chạy được riêng lẻ và kết hợp (`localhost_agents_1_to_5`) qua hook `LocalOriginTest`.
- Recovery hỗ trợ cả `probe` lẫn `soft404`.

B4.2C cần làm và chứng minh:
- Chạy graph local đầy đủ tới `report` rồi `reflection`, kết quả theo từng origin, report không trộn origin.
- Quyết định có thay `decide()` tất định bằng route khác hay không (vẫn không dùng LLM thật).
- Kiểm crash/resume xuyên suốt Agent 4 → Agent 5 → report, giữ at-most-once và các mã từ chối hiện có.
- Giữ gate `not_enabled_b1`. Mở production là một quyết định riêng, nằm ngoài B4.2C.
