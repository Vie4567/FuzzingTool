# B5 — Evidence & Report: export báo cáo Multi-Origin đã kiểm chứng

Trạng thái: **đã triển khai và nghiệm thu — `integration_verified` trong lab loopback** (lần nghiệm thu 2, mục 11–12).
Lần nghiệm thu 1 **FAIL** ở verifier lịch sử. Kết quả đó được giữ nguyên, không ghi đè (mục 11).
Production gate vẫn `not_enabled_b1`. `full_multi_origin_execution_enabled` vẫn `False`. B6 chưa bắt đầu.

## 1. Thiết kế cuối cùng

Ba quyết định đã duyệt:

1. **Giữ nguyên Report content v1 và digest lịch sử.** `origin_report.build_report` không đổi. B5 là một lớp
   export độc lập, chỉ đọc, chạy **sau** phiên.
2. **JSON (canonical) và Markdown.** Không có HTML.
3. **Verified export chỉ nhận phiên có journal, final checkpoint và `session_finished` hợp lệ.** Một phiên bị crash
   phải được operator hoàn tất trước (resume hoặc `finalize_only`). Export không bao giờ tự gọi hai bước này.
   Phiên không có journal bị từ chối (`export_journal_missing`). `result.json` của pipeline single-origin và của các
   mode cũ vẫn được ghi như trước, vì B5 không đổi graph hay `RunArtifacts`.

Luồng:

```
recovery/journal.jsonl + head.json ─┐  (OS lock session.lock, chỉ đọc)
checkpoints được neo sha256 ────────┼─► load_verified ─► build_envelope ─► render_markdown ─► check_public
checkpoint `pipeline` + session_finished ┘      (fail-closed, mã public cố định)
                                                   ─► .pending_export_<uuid>/ {report.json, report.md, manifest.json}
                                                   ─► kiểm lại hash nguồn ─► os.rename → <output>/ (một lần, không ghi đè)
```

Export không gửi HTTP, không gọi LLM, không ghi KnowledgeStore, không chạy graph hay Agent, và không ghi journal.
Module `origin_export.py` không import `src.tools`, `src.agents` hay SDK LLM. Có test chạy subprocess để kiểm điều này.

## 2. Evidence/data contracts (nguồn của từng phần)

| Phần export | Nguồn | Kiểm tra trước khi xuất |
|---|---|---|
| `source.*` | journal (hash chain, head), checkpoint `pipeline` cuối, checkpoint `generate_report` mới nhất | chain và head (`RecoveryJournal._read`); sha256 của **mọi** checkpoint được neo; checkpoint nằm dưới session root; `session_finished` là sự kiện cuối, đứng ngay sau checkpoint `pipeline` có cùng `pipeline_status` |
| `report_v1` | `multi_origin_report` của checkpoint cuối, **nguyên văn** | `canonical(content) == digest` ở mọi checkpoint; digest cuối bằng digest của checkpoint `generate_report`; Reflection được report chống lưng; schema v1 |
| ngữ nghĩa v1 | sections theo origin trong checkpoint cuối | totals v1 bằng tổng các section; `counts` v1 bằng `counts` của section; trạng thái Agent theo origin tái suy được (`origin_agent_status`), trạng thái origin tái suy được (`origin_status`); quy tắc `completed`; mỗi dòng v1 khớp dòng section (class, `evidence_level`, `unit_state`, verdict) |
| `accounting` | sự kiện journal `reserved` / `dispatch_started` / `response_headers` / `measurement` | sequence liên tục; mỗi sự kiện tham chiếu một reservation, không trùng, headers/measurement phải sau start; origin ∈ approved; tập `runtime_sequence` của từng section = tập reservation cùng loại và cùng origin; `status_code` khớp; `outcome_unknown` khớp **hai chiều**; `runtime`, telemetry và `recovery.accounting` khớp journal |
| `origins[].endpoints[]` | `origin_contexts[o].endpoints` (Agent 1), wordlist, dispatch, parameter, soft404 | `endpoint_id == sha256(url+"\n"+method)[:24]`; không trùng; URL thuộc đúng origin; dòng liên kết cùng URL; không dòng nào `verified`; `parameter_context.authority == context_only` |
| `budget` | `authority` trong sự kiện `session` + runtime snapshot | quota trong authority bằng `http_origin_max_requests`; `http_max_requests` khớp |
| `llm`, `reflection` | `telemetry.llm`, `local_reflection` | `llm_call_count == telemetry.llm.attempted` |
| `recovery` | `state.recovery`, các sự kiện `process_bound` / `reconciled` / `stop` | `recovery.accounting` bằng số đếm journal |

## 3. Export schema (`multi_origin_report_export` v1)

`report.json` (JSON có `sort_keys`, UTF-8):

- `schema`, `schema_version = 1`, `stage = "B5"`.
- `source`: `session_id`, `runtime_id`, `journal` (đường dẫn tương đối), `journal_events`, `journal_head_hash`,
  `journal_sha256`, `head_sha256`, `final_checkpoint`, `final_checkpoint_sha256`, `report_checkpoint`,
  `report_checkpoint_sha256`, `checkpoints_verified`, `report_digest`, `report_digest_rule`, `report_schema_version`.
  Mọi đường dẫn đều tương đối với session root, kiểu POSIX.
- `session`: `pipeline_status`, `stop_reason`, `runtime_stop_reason`, `global_stop_reason`, `contract_failures`,
  `journal_stop_events`, `mode`, `graph_integration`, `finalize_only`, `resumed`, `all_modules_*`, `gate`,
  `decisions[]`, `errors[]` (chỉ `agent` và `error_type`, không có message).
- `scope`: `approved_origins`, `discovered_only_origins`, `origin_policies` (contract public).
- `agents[]`: trạng thái toàn cục của v1 kèm `report_path`.
- `origins[]` (thứ tự phê duyệt): `status`, `v1_executed` + `v1_executed_scope`, `journal_reservations`, `agents[]`,
  `accounting`, `budget{limit, reserved, remaining}`, `recon`, `wordlist`, `halts`, `endpoint_index`,
  `parameter_summary`, `soft404_summary`, `outcome_unknown_sequences`, `endpoints[]`.
  - `endpoints[]`: `endpoint_id`, `url`, `method`, `has_query`, `source` (`agent1_observation` |
    `agent2_wordlist_candidate`), `resource_type`, `provenance_count`, `provenance[]`, `observation_classes`,
    `wordlist`, `dispatch` (gồm `observed_method/execution_method`, `error_type`, `timeout`, `rejection_reason`,
    `recovery_state`, `evidence = observed_http|null`), `parameters` (candidate kèm `provenance_classes`,
    `authority = context_only`), `soft404` (`classification`, `evidence_level_v1`, `evidence_basis`, các sequence
    của candidate/control), `endpoint_verification_status = not_verified`.
- `discovered_only_origins[]`: `approved: false`, `executed: false`, `journal_reservations: 0`.
- `accounting`: `meaning`, `total`, `by_phase[]`, `by_kind[]` (`recon`, `dispatch`, `parameter_probe`,
  `soft404_probe`), `by_origin[]` (kèm `by_phase`), `unknown_sequences`, `runtime`, `telemetry_http`,
  `recovery_accounting`, `legacy_report_totals` (v1 nguyên văn kèm `scope`).
- `budget`, `llm`, `reflection`, `recovery`, `report_v1{schema_version, stage, digest, digest_rule, content}`.
- `evidence_vocabulary`, `severity: null`, `severity_basis: "not_assessed_b5"`, `not_concluded[]`, `limits[]`.
- `export_digest = sha256(canonical(envelope − export_digest − export_meta))`.
- `export_meta{generated_at_utc, nondeterministic_fields}`: trường duy nhất không xác định, đã được khai báo.

`manifest.json`: `complete: true`, `export_digest`, `report_digest`, `session_id`, sha256 của `report.json` và `report.md`.
Mọi map theo origin hay phase đều là **list**, vì URL origin chứa dấu `.` và `:`, không dùng làm JSON path được.

## 4. JSON và Markdown

- JSON là nguồn canonical. Markdown là `render_markdown(envelope)`, hàm thuần trên envelope. Lần export thứ hai
  cho ra `report.md` giống từng byte, `report.json` chỉ khác ở `export_meta`.
- Mọi giá trị trong Markdown nằm trong bảng có nguồn:
  - bảng `| Trường | Giá trị | Nguồn |` (cột Nguồn là JSON path);
  - hoặc bảng hàng `| JSON path | <key>… |`.
  
  Không có số liệu trong văn xuôi. `null` hiển thị là "không xác định"; "—" nghĩa là không áp dụng (cha là null).
- Escape:
  - Dữ liệu luôn nằm trong inline code span, fence dài hơn chuỗi backtick dài nhất bên trong, nên không render HTML
    hay link.
  - `|` được escape cho GFM table; xuống dòng bị thay bằng khoảng trắng.
  - Nhãn tĩnh được backslash-escape toàn bộ ký tự `\`*_{}[]<>()#+-.!|~&`.
  - Test dùng dữ liệu `<script>…|[x](javascript:…)` cùng ảnh và backtick để kiểm.

## 5. Accounting semantics

| Trường | Sự kiện journal | Ý nghĩa |
|---|---|---|
| `reserved` | `reserved` | runtime dùng một slot budget/quota |
| `dispatch_started` | `dispatch_started` (ghi ngay trước `opener.open`) | transport bắt đầu mở request. **Không** chứng minh server đã nhận |
| `response_headers` | `response_headers` | client nhận được status line và headers |
| `measured` | `measurement` (ghi trong `finally`, gồm cả lỗi và timeout) | đã ghi được kết quả |
| `measured_with_error` / `timeouts` / `incomplete_bodies` | trường của `measurement` | lỗi transport/đọc; `exception_type` chứa "timeout"; có status nhưng `body_complete = false` |
| `attempt_unknown` | reserved, không có start | không biết request đã được gửi hay chưa |
| `outcome_unknown` | reserved, không có measurement | không biết kết quả (không bao giờ gửi lại) |
| server arrivals | — | export **không** khẳng định. Chỉ access log độc lập trong lab chứng minh được; verifier kiểm `response_headers ≤ arrivals ≤ dispatch_started` theo origin |

Tên `received_http` trong bản thiết kế đã bị **bỏ**, vì journal không chứng minh server nhận request. Report v1
`totals` vẫn giữ nguyên văn trong `legacy_report_totals`, với chú thích rằng các `*_requests` đếm dòng của section
(tức reservation, gồm cả `outcome_unknown`) và không gồm Recon. Số liệu đã đối chiếu của B5 là `accounting.*`.

## 6. Evidence levels

Có hai thang riêng, không bao giờ trộn:

- quan sát: `observed` / `candidate` / `inferred` (Agent 1), `observed_http` (Agent 3), `observed_reference` /
  `inferred_static` (nguồn tên tham số);
- cơ sở của lớp Soft404: `rederived`, `metrics_journaled`, `inconclusive`, `interrupted`. Khi lớp là `not_checked`,
  `evidence_basis = not_applicable` (nhãn v1 vẫn giữ ở `evidence_level_v1`, xử lý R7 ở tầng hiển thị).

Tham số `verified` luôn là `context_only`. Endpoint luôn là `not_verified`. `genuine_distinct` là phân loại
representation, không phải lỗ hổng. `severity` là `null`.

## 7. Redaction và integrity

- Envelope được dựng **theo allow-list**: từng trường được sao chép tường minh, không deepcopy state. Credential,
  headers, cookie, body, message lỗi và `config` không bao giờ được xuất.
- Guard: `sanitize_for_log(envelope) == envelope`; không có đường dẫn tuyệt đối (ký tự ổ đĩa, session root, home).
  Vi phạm thì từ chối `export_sensitive_content` / `export_absolute_path` và không ghi file. Idempotence của
  redaction **không** chứng minh rằng không còn bí mật. Nó chỉ là một lớp chặn.
- Markdown chỉ được kiểm đường dẫn tuyệt đối. Lý do: regex JWT của redactor (`≥12 ký tự` × 3, nối bằng `.`) khớp
  chính các JSON path dài, ví dụ `evidence_vocabulary.dispatch_evidence.observed_http`. Đây là dương tính giả cùng
  họ với R8. Markdown là hàm thuần của envelope đã qua guard.
- Không bao giờ tính lại digest để hợp thức hóa: report có digest lệch thì bị từ chối (`export_report_digest_mismatch`).
- Ghi file: thư mục `.pending_export_<uuid>` (file mở bằng `xb`, có fsync), kiểm lại hash nguồn
  (`export_source_changed`), sau đó `os.rename` một lần. Output đã tồn tại thì `export_output_exists`. Lỗi giữa chừng
  thì xóa pending và trả `export_write_failed`, không để lại report nào. Output không được nằm trong thư mục recovery
  hay thư mục checkpoint.

Mã từ chối: `export_session_missing`, `export_journal_missing`, `export_session_lock_missing`,
`export_session_locked`, `export_journal_invalid`, `export_session_not_finished`, `export_session_finished_invalid`,
`export_checkpoint_missing`, `export_checkpoint_invalid`, `export_path_escape`, `export_report_missing`,
`export_report_schema_unsupported`, `export_report_digest_mismatch`, `export_report_unanchored`,
`export_reflection_mismatch`, `export_gate_changed`, `export_scope_mismatch`, `export_report_source_mismatch`,
`export_status_mismatch`, `export_endpoint_promoted`, `export_accounting_mismatch`, `export_unapproved_dispatch`,
`export_budget_mismatch`, `export_telemetry_mismatch`, `export_recovery_accounting_mismatch`,
`export_duplicate_endpoint`, `export_evidence_unresolved`, `export_endpoint_identity_invalid`, `export_origin_mixed`,
`export_parameter_authority_changed`, `export_source_malformed`, `export_sensitive_content`, `export_absolute_path`,
`export_output_exists`, `export_output_parent_missing`, `export_output_inside_session_state`, `export_write_failed`,
`export_source_changed`.

## 8. Kết quả kiểm thử R8

**Đã chứng minh, ở tầng persistence.** Đây không phải lỗi của lớp export.

Nguyên nhân: `build_report` tính digest trên content **trong bộ nhớ, trước khi redact**. Sau đó
`RunArtifacts.public_state` mới redact cả state, kể cả `multi_origin_report`, khi ghi checkpoint
([artifacts.py:134-142](../src/coordinator/artifacts.py#L134-L142)). Có hai cơ chế làm đổi giá trị hợp lệ:

- (a) Mọi chuỗi con có độ dài ≥ 4 trùng với một giá trị credential đều bị thay, không xét ranh giới từ
  ([llm_logging.py:161-166](../src/coordinator/llm_logging.py#L161-L166));
- (b) Các pattern tổng quát, ví dụ `_API_KEY` (`api_` cộng ≥16 ký tự), `_JWT` (ba đoạn ≥12 ký tự nối bằng `.`)
  ([llm_logging.py:34-35](../src/coordinator/llm_logging.py#L34-L35)).

Test: `RedactionTests.test_r8_redaction_after_digest_changes_report_content` trong `tests/test_origin_report_export.py`.
- (a) Credential `Bearer help` làm `/help` trong report bị thay, nên `canonical(content) ≠ digest`: **tái hiện được**.
- (b) Tên tham số `api_version_identifier_v2` bị redact, digest lệch: **tái hiện được**.
- (c) Exporter gặp report như vậy thì từ chối `export_report_digest_mismatch`, không ghi file và không tính lại digest:
  **PASS**.
- (d) Dữ liệu lab bình thường với credential giả `Bearer b5-local-only-fake` không bị đổi: **PASS**.

Phạm vi thực tế:
- Trong vocabulary hiện có (`knowledge/`) **không có** tên nào khớp các pattern `(sk|pk|api)[-_]…{16,}`.
- URL đã bị `public_url` chặn từ trước.
- Vì vậy R8 **chưa được chứng minh trên graph thật**. Khả năng xảy ra phụ thuộc giá trị credential của operator
  (credential ngắn hoặc trùng chuỗi trong path, tên tham số).
- Hậu quả là fail-closed, không lộ dữ liệu:
  - recovery từ chối `recovery_report_mismatch`;
  - export từ chối `export_report_digest_mismatch`;
  - còn report của phiên **không có** journal thì digest đã lưu sẽ lệch mà không bị phát hiện.

Cũng trong họ này: regex `_JWT` khớp các JSON path dài của chính Markdown (mục 7), nên guard `sanitize_for_log`
chỉ áp lên envelope.

Phương án sửa tương thích ngược (**chưa triển khai**, vì cần duyệt riêng; nó sửa `origin_report`/`origin_local`, là các
module đã nghiệm thu):

1. Tính digest trên `RunArtifacts.public_state(content)`. Với mọi content mà redaction không làm đổi (toàn bộ evidence
   lịch sử hiện có), digest giữ nguyên nên tương thích ngược. Chỉ các trường hợp vốn đã hỏng mới có digest khác.
2. Hoặc từ chối sớm: trong `LocalOriginTest.report`, nếu `public_state(content) != content` thì raise một mã public
   (ví dụ `report_content_redaction_conflict`) trước khi ghi checkpoint.
3. Không nới redactor: (a) và (b) là hành vi bảo vệ bí mật có chủ đích.

## 9. File và hàm

Chỉ thêm file mới. **Không sửa file nào có sẵn.** 145 file `.py` có sẵn trùng hash với baseline (mục 11).

| File (mới) | Nội dung |
|---|---|
| `src/coordinator/origin_export.py` | `ExportError`, `load_verified`, `journal_accounting`, `_check_report_semantics`, `_check_sections`, `_endpoints`, `build_envelope`, `md_text`, `md_code`, `md_cell`, `render_markdown`, `check_public`, `_publish`, `export_session` |
| `scripts/export_origin_report.py` | CLI offline (mục 13) |
| `scripts/verify_origin_report_evidence.py` | verifier độc lập, chỉ stdlib, không import `src`: `check_exported`, `check_markdown`, `independent_refusal_reason`, `check_refused`, `verify_case`, `refusal_negative_checks`, `negative_checks` (23 mutation) |
| `tests/test_origin_report_export.py` | 27 unit test (không socket); session tổng hợp với journal hash-chain thật, checkpoint neo sha256, report do `build_report` dựng |
| `tests/test_origin_report_export_http.py` | 10 test: graph thật trên lab loopback (5 chạy trong process, 5 kill/restart worker), lưu snapshot journal tại thời điểm refusal |
| `tests/test_origin_report_verifier.py` | 4 test: verifier chạy dạng subprocess trên evidence tổng hợp (refusal-only, các mutation refusal, snapshot chỉ cho ghi tiếp append-only, negative checks) |
| `docs/multi_origin_b5.md` | tài liệu này |

Không đổi: graph, Agent, runtime, telemetry, recovery, `origin_report.py` (Report v1), `artifacts.py`, single-target pipeline,
dependencies. Công cụ nghiệm thu (không thuộc repo) lưu trong thư mục evidence:
`acceptance_tools_run2/{acceptance_run2.ps1, source_manifest.py, historical_export.py}` và
`acceptance_tools_run1_acceptance.ps1`.

## 10. Acceptance criteria và evidence

| # | Nhóm tiêu chí | Bằng chứng | Mức |
|---|---|---|---|
| 1 | Schema, tương thích ngược | `report_v1` = content và digest của checkpoint cuối, đúng nguyên văn (unit + HTTP + verifier); 16 phiên B4.2C lịch sử export được mà Report v1 không đổi | integration_verified |
| 2 | Tổng hợp theo origin | `test_per_origin_identity_variants_and_provenance`; verifier: endpoint đúng origin, mutation `endpoint_cross_origin` | integration_verified |
| 3 | Identity, provenance, biến thể | GET và HEAD, query variant thành dòng riêng; 2 provenance chỉ đếm 1 endpoint; mutation `method_variant_merged`, `provenance_double_count` | integration_verified |
| 4 | Accounting | journal: reserved/started/headers/measured/attempt_unknown/outcome_unknown theo tổng, origin, phase, kind, **có Recon**; verifier tính lại từ journal và kiểm `response_headers ≤ arrivals(log server) ≤ dispatch_started` | integration_verified |
| 5 | Parameter và Soft404 | verdict, `context_only`, class và `evidence_basis` khớp checkpoint; mutation `parameter_promotes_endpoint`, `evidence_level_upgraded`, `severity_assigned` | integration_verified |
| 6 | Partial, interrupted, unknown | các case 429, quota-halt, crash Agent 4 và Agent 5 rồi resume: unknown vẫn là `null` hoặc được đếm, không thành 0; mutation `unknown_to_zero`, `unknown_laundered_as_measured` | integration_verified |
| 7 | Nhất quán với recovery | phiên crash bị từ chối (`export_session_not_finished`) cho tới khi operator resume hoặc finalize; finalize sau crash và sau global stop export được và không bao giờ `completed` | integration_verified |
| 8 | Redaction | allow-list; credential giả không xuất hiện trong JSON, MD hay manifest; R8 (mục 8); mutation `secret_injected` | integration_verified (R8: unit) |
| 9 | Export và lỗi ghi | `xb` + pending + rename; `export_output_exists`, lỗi giữa chừng không để lại gì, `export_source_changed`, checkpoint bị sửa thì bị từ chối | unit_verified + integration_verified |
| 10 | Verifier độc lập | 10/10 case B5 và 20/20 case lịch sử, mỗi ô Markdown đối chiếu với JSON path | integration_verified |
| 11 | Negative mutation | 23/23 trên cả hai bộ evidence (mục 12) | integration_verified |
| 12 | Regression và verifier cũ | 842/842; 7 verifier stage cũ PASS (mục 11) | integration_verified |
| — | 0 HTTP / LLM / KnowledgeStore | export chạy khi `socket.connect`, `create_connection`, decision engine và các writer KnowledgeStore đều bị patch để ném lỗi; số dòng log server trước và sau export bằng nhau; test subprocess xác nhận module không import `src.tools`/`src.agents`/SDK LLM | integration_verified |
| — | Nguồn không đổi | hash journal, head và mọi checkpoint trước và sau mỗi export bằng nhau; 1.742 file evidence B4.2C không đổi | integration_verified |

## 11. Baseline và final regression

Thư mục evidence: `output_samples/diagnostics/multi_origin_b5_20261126T024125Z/` (gitignored), HEAD `6cea1d6`.

**Baseline**, trước khi ghi file B5 nào vào repo (02:41–03:01 UTC):
- 801/801 OK, exit 0 (`baseline.log`);
- 145 file `.py` (`source_hashes_baseline.txt`) giống hệt manifest cuối của B4.2C, và băm lại sau baseline vẫn giống.

**Lần nghiệm thu 1** (03:08–03:48 UTC, `acceptance.log`, giữ nguyên):

| Bước | Kết quả |
|---|---|
| Test B5 | 37/37 OK (27 unit + 10 HTTP/recovery) |
| Verifier B5 | 10/10 case, 17/17 mutation, exit 0 |
| Export lịch sử | 16 export + 4 refusal đúng kỳ vọng, exit 0 |
| Verifier lịch sử | **FAIL, exit 1** |
| B3.1 / B3.2A / B3.2B / B4.1 / B4.2A / B4.2B / B4.2C | 36 / 30 / 38 / 15 / 25 / 42 / 37 OK; verifier PASS |
| Full regression | 838/838 OK, 0 FAIL, 0 ERROR, 0 skipped, exit 0 |
| `run_coordinator_scan.py --check` | exit 0, không gửi request |
| `source_unchanged=True` | **không có giá trị**: `source_hashes_start/end.txt` rỗng (0 byte), vì lệnh `bash -c … sha256sum` gọi từ PowerShell không sinh output. Xem `acceptance_run1_notes.txt` |

Lỗi verifier lịch sử:
- 4 case B4.2C không có `session_finished`: hai case forged decision/report, `test_finalize_never_bypasses_integrity` và
  `test_unexpected_agent4_error_is_not_masked`.
- Export đã từ chối đúng (`export_session_not_finished`). Nhưng verifier có quy tắc "mỗi case phải có ít nhất một
  export", nên báo `case without an exported report` và không kiểm refusal nào (`refusals_checked: 0`).
- Nguyên nhân: quy tắc đó viết cho test B5, không đúng với case lịch sử chỉ có refusal. Không phải lỗi production export.

Một manifest độc lập được ghi bằng Git Bash lúc 03:43 UTC (`source_hashes_0343_gitbash.txt`), và băm lại lúc 03:48 cho
kết quả giống. Nó **không** chứng minh source không đổi trong khoảng trước 03:43 của lần 1.

**Sửa sau lần 1**, chỉ chạm các file B5:
- verifier: hỗ trợ refusal-only (mục 12);
- `tests/test_origin_report_verifier.py`: TDD, 3 test **đỏ** với verifier cũ, tái hiện đúng lỗi, rồi xanh;
- test HTTP B5: lưu snapshot journal/head tại thời điểm refusal. Lý do: khi chạy thử trên evidence lần 1, verifier mới
  phát hiện các case "từ chối rồi resume" không còn tái suy được lý do, vì journal đã được ghi tiếp sau đó.

Production export không đổi.

**Lần nghiệm thu 2**, chính thức (03:53–04:15 UTC, `rerun2_20261126T035347Z/acceptance.log`). Log là byte gốc qua
`Start-Process`; manifest dùng Python stdlib, fail khi rỗng hoặc sai số file:

| Bước | Kết quả |
|---|---|
| Manifest đầu | 151 file (145 có sẵn = baseline, cộng 6 file B5), exit 0 |
| Test B5 (`test_origin_report_*.py`) | **41/41 OK** (27 + 10 + 4), exit 0 |
| Verifier B5 `--expected-cases 10 --negative-checks` | PASS: 11 export, 3 refusal, 7.924 ô Markdown, 23/23 mutation |
| Export lịch sử B4.2C | 16 export + 4 refusal, tất cả khớp kỳ vọng; **1.742 file evidence B4.2C không đổi** |
| Verifier lịch sử `--expected-cases 20 --negative-checks` | PASS: 16 export, 4 refusal (cả 4 đều `export_session_not_finished`, tự tái suy được), 11.831 ô Markdown, 23/23 mutation |
| Verifier 7 stage cũ trên evidence lần 1 | đều exit 0 (B3.1, B3.2A 21, B3.2B 27, B4.1 8, B4.2A 16, B4.2B 26, B4.2C 21 case; kèm negative checks) |
| Full regression | **842/842 OK**, 0 FAIL, 0 ERROR, 0 skipped, exit 0 (838 + 4 test verifier mới) |
| `run_coordinator_scan.py --check` | exit 0: "No target, proxy or LLM requests were sent" |
| Manifest cuối và phép so | 151 = 151, `source_unchanged=true` (cả hai manifest không rỗng, parse đầy đủ, giống hệt) |
| `git status` | 63 mục = 57 lúc bắt đầu B5 + 6 file mới; không mục có sẵn nào bị mất |

Evidence tái sử dụng: test và evidence của 7 stage cũ **không chạy lại** ở lần 2. Lý do:
- source và verifier của chúng không đổi (145 file có sẵn trùng hash baseline ở cả hai manifest của lần 2);
- evidence lần 1 của chúng được verify lại chỉ đọc ở lần 2, đều PASS;
- full regression lần 2 vẫn chạy toàn bộ test của chúng.

Case `test_legacy_local_modes_keep_routing_and_never_complete` của B4.2C (3 run dùng chung một access log) **không** được
export lịch sử, vì không gán được số arrival cho từng session. Nó được liệt kê trong `historical_summary.json`.

## 12. Independent verifier và negative mutations

`scripts/verify_origin_report_evidence.py <evidence_dir> [--expected-cases N] [--negative-checks]`: chỉ stdlib,
không import `src`.

**Export.** Verifier tự tính lại từ dữ liệu gốc:
- hash chain và head; sha256 của mọi checkpoint; checkpoint `pipeline` được `session_finished` niêm phong;
- digest của Report v1 (theo quy tắc canonical của chính nó) và việc bản trong export là nguyên văn;
- manifest và `export_digest`;
- accounting theo tổng, phase, kind và origin từ sự kiện journal, có Recon;
- `response_headers ≤ arrivals ≤ dispatch_started` cho từng origin, dựa trên log server độc lập; mọi arrival theo
  (path, query) phải có reservation đã start;
- budget và telemetry (`null` vẫn là `null`);
- tập endpoint bằng tập trong checkpoint; identity `sha256(url+"\n"+method)`; biến thể method/query; số provenance;
- verdict tham số và `context_only`; class Soft404 và `evidence_basis`;
- discovered-only không được thực thi;
- `severity` luôn `null`; không có secret hay đường dẫn tuyệt đối; không có field credential;
- **mọi ô** của mọi bảng Markdown khớp giá trị render lại từ JSON path nó ghi; không thiếu dòng nào; không có HTML hay
  link ngoài code span.

**Refusal** (case chỉ có refusal được chấp nhận):
- phải có bằng chứng `outcome == ["refused", code]`, và `code` khớp kỳ vọng ghi từ fixture hoặc trạng thái nguồn;
- verifier **tự tái suy** lý do ineligible theo đúng thứ tự gate của exporter: journal/head có không, chain, sự kiện
  `session`, `session_finished`, hash checkpoint ghi lúc refusal so với anchor trong journal, digest report. Lý do phải
  trùng `code`. Nếu nó thấy session đủ điều kiện thì đó là **refusal giả**;
- không có output, không có thư mục pending, hash nguồn trước = sau;
- journal hiện tại bằng snapshot lúc refusal, hoặc chỉ là bản ghi tiếp (append-only) của snapshot khi refusal có
  `source_snapshot` (ví dụ operator resume sau đó);
- checkpoint không đổi, hoặc là file lab cố ý bị sửa rồi được khôi phục về đúng anchor;
- case không có export lẫn refusal thì FAIL.

**Negative mutations**, áp lên bản sao trong bộ nhớ, có niêm phong lại digest và manifest cho nhất quán. **23/23 bị phát
hiện trên cả evidence B5 và evidence lịch sử** (`rerun2_*/b5_verifier.out.log`, `historical_verifier.out.log`):

| Nhóm | Mutation |
|---|---|
| Có từ lần 1 (17) | `endpoint_cross_origin`, `total_inflated`, `recon_http_dropped`, `unknown_to_zero`, `discovered_only_executed`, `parameter_promotes_endpoint`, `severity_assigned`, `evidence_level_upgraded`, `method_variant_merged`, `provenance_double_count`, `secret_injected`, `export_bound_to_other_report`, `markdown_unbacked_number`, `markdown_row_dropped`, `response_headers_counted_as_arrival`, `source_changed_after_export`, `unknown_laundered_as_measured` |
| Mới, cho refusal (6) | `refusal_wrong_code`, `refusal_evidence_missing`, `refusal_source_rewritten`, `refusal_with_report`, `empty_case`, `false_refusal_of_eligible_session` |

Trong quá trình phát triển, mutation `unknown_laundered_as_measured` từng được tính là "phát hiện" chỉ vì helper chọn
mục tiêu ném `Failure` khi không tìm thấy target. Lỗi này đã sửa: target thiếu được tính là verifier lỗi, không phải
phát hiện.

## 13. Hướng dẫn CLI

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
# <recovery_dir> là thư mục có journal.jsonl, head.json, session.lock (session root = thư mục cha)
.\.venv\Scripts\python.exe -B scripts/export_origin_report.py <recovery_dir> --output <thư_mục_mới>
```

- Exit `0`: đã export, stdout là JSON `{exported, output, export_digest, report_digest, pipeline_status}`.
- Exit `2`: bị từ chối, stdout `{exported: false, code}`.
- Exit `3`: `export_write_failed`.
- Không có `--output` thì mặc định là `<session root>/b5_export_<UTC>`.
- Phiên bị crash: chạy resume hoặc `finalize_only` trước (do operator quyết định), rồi mới export.

Tái lập kiểm chứng:

```powershell
$env:B5_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b5_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_report_*.py' -v
.\.venv\Scripts\python.exe -B -I scripts/verify_origin_report_evidence.py $env:B5_EVIDENCE_DIR --expected-cases 10 --negative-checks
```

## 14. Report thực tế từ lab

Gốc: `output_samples/diagnostics/multi_origin_b5_20261126T024125Z/rerun2_20261126T035347Z/b5/`.

- **Completed** (`test_export_completed_full_graph`): `b42c_b2f26605_e7189a/export_first/report.json`, `report.md`
  (393 dòng) và `manifest.json`.
  - accounting: 66 reserved / 66 started / 66 headers / 66 measured / 0 unknown;
  - theo kind: Recon 2, dispatch 9, parameter 33, soft404 22;
  - Report v1 legacy: 9 + 33 + 22 = 64 (không tính Recon);
  - budget: origin 1 dùng 37/80, origin 2 dùng 29/80; telemetry 66; gate `not_enabled_b1`.
- **Partial, sau crash ở Agent 4 rồi resume** (`test_export_after_crash_in_agent4_and_resume`):
  `b42c_10be01ac_a96965/export_resumed/`.
  - 57 reserved / 56 started / 56 headers; `attempt_unknown = outcome_unknown = 1`;
  - parameter: 24 reserved, 23 started (Report v1 ghi `parameter_requests = 24`);
  - telemetry `total_requests = null`, Markdown hiện "không xác định";
  - origin 1 `interrupted`.
- Export của 16 phiên B4.2C lịch sử: `rerun2_20261126T035347Z/historical/<case>/export/`.

Log nghiệm thu:
- `rerun2_20261126T035347Z/acceptance.log` và các file `*.out.log` / `*.err.log`;
- `source_manifest_{start,end}.txt`;
- `historical/historical_summary.json`;
- của lần 1: `acceptance.log`, `acceptance_run1_notes.txt`, `differential_review.md`.

## 15. Giới hạn còn tồn tại

- Ngoài lab vẫn `not_verified`: Internet, TLS thật, DNS, proxy, ffuf, LLM thật, production multi-origin.
- Export chỉ nhận phiên có journal đã hoàn tất.
  - Phiên không có journal (mode cũ không bật recovery, single-target) không có verified export. `result.json` của chúng
    vẫn được ghi như trước.
  - Phiên bị crash cần operator resume hoặc `finalize_only` trước.
- Hash chain và sha256 không chống được người có toàn quyền ghi. Các phép tái suy ngữ nghĩa thu hẹp khoảng hở này.
  Riêng việc server có nhận request hay không thì chỉ log lab độc lập chứng minh được, và export không khẳng định điều đó.
- Guard redaction chỉ là một lớp chặn, không phải bằng chứng tuyệt đối rằng không còn secret. Markdown chỉ được kiểm
  đường dẫn tuyệt đối (vì dương tính giả của regex JWT).
- R8 còn ở tầng nguồn: chưa sửa, có phương án ở mục 8. Phiên không có journal có thể lưu report có digest lệch mà
  không bị phát hiện.
- Report v1 `executed` vẫn nghĩa là "có Agent được gọi ở mức toàn cục". Export hiển thị kèm `journal_reservations`
  của từng origin.
- Trạng thái toàn cục của v1 (ví dụ success + skipped thành success, partial có `reason = null`) được giữ nguyên văn.
- Có một TOCTOU nhỏ giữa lần kiểm hash cuối và `os.rename`. Nó được giảm nhờ giữ OS lock của session suốt quá trình
  export. Một tiến trình không tôn trọng lock nằm ngoài mô hình đe dọa.
- POSIX: `os.rename` có thể ghi đè lên một thư mục *rỗng*. Đã có kiểm tra `exists()` trước dưới lock, nhưng chưa test
  trên POSIX.
- Case B4.2C legacy dùng chung access log không được export lịch sử.
- Không có severity, HTML, khử trùng lặp giữa origin hay ghi KnowledgeStore.

## 16. Kết luận nghiệm thu và bàn giao B6

B5 đạt **`integration_verified`** trong lab loopback ở lần nghiệm thu 2:
- 41/41 test B5;
- verifier B5 10/10 case và verifier lịch sử 20/20 case (16 export, 4 refusal tự tái suy được);
- 23/23 mutation trên cả hai bộ evidence;
- 7 verifier stage cũ PASS;
- full regression 842/842;
- `--check` exit 0;
- manifest 151 file trước và sau giống hệt;
- gate `not_enabled_b1` và `full_multi_origin_execution_enabled = False` không đổi (verifier kiểm trên mọi export).

Lần nghiệm thu 1 FAIL ở verifier lịch sử. Lỗi đó, nguyên nhân và cách sửa được ghi ở mục 11 và 12.

**Điều kiện bàn giao sang B6.** B6 chưa bắt đầu. Đầu vào sẵn có:
- envelope `multi_origin_report_export` v1 (JSON canonical, có digest và manifest);
- Markdown có nguồn ở từng ô;
- accounting đã đối chiếu journal;
- verifier độc lập.

B6 cần quyết định riêng:
1. Có render HTML từ envelope hay không.
2. Mô hình severity cùng chính sách bằng chứng tối thiểu. B5 cố ý để `null`.
3. Khử trùng lặp giữa origin, chỉ khi có quy tắc tường minh.
4. Ghi KnowledgeStore có provenance.
5. Quyết định LLM có guard cho multi-origin.
6. Supervisor có hard deadline và recovery dựa trên journal.
7. Sửa R8 ở tầng nguồn (mục 8), cần duyệt vì chạm `origin_report`/`origin_local`.
8. Content v2, nếu muốn sửa ngữ nghĩa `executed` hay trạng thái toàn cục (cần kế hoạch chuyển digest).

Trước production multi-origin vẫn thiếu đúng các điều kiện đã liệt kê ở B4.2C §14.
