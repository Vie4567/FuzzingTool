# B4.2C — Full Local Graph Integration

Trạng thái: **đã triển khai và nghiệm thu — `integration_verified` trong lab loopback** (mục 8–13).
Production gate vẫn `not_enabled_b1`. `full_multi_origin_execution_enabled` vẫn `False`.

## 1. Thiết kế cuối cùng (D1–D9, đã điều chỉnh theo quyết định của operator)

- **D1 — Mode.** `LocalOriginTest(parameter_verification=True, soft404_verification=True)` là đồ thị local đầy đủ
  Agent 1→5 → Report → Reflection. Giữ nhãn `mode = localhost_agents_1_to_5` (tương thích B4.2B), thêm
  `local_origin_execution.graph_integration = local_full_graph_b42c`. Không thêm cờ JSON/SharedState/env.
- **D2 — Report.** `src/coordinator/origin_report.py`, hàm thuần (không HTTP, không LLM). Section riêng cho từng
  origin **đã phê duyệt**; origin chỉ được phát hiện nằm ở `discovered_only_origins` với `executed: false`.
  Mọi tổng là phép cộng từ section theo origin. Không gộp endpoint giữa origin. Digest = sha256 của JSON chuẩn hóa
  (`sort_keys`, `separators=(",", ":")`, `ensure_ascii=False`) trên `content`, và `content` không chứa timestamp,
  thời gian đáp ứng, đường dẫn artifact, PID hay trạng thái recovery biến động.
- **D3 — Reflection.** Deterministic, không LLM, không KnowledgeStore. Mỗi observation trỏ tới một đường dẫn trong
  `multi_origin_report.content` cùng giá trị tại đó. `lessons = []`, `knowledge_writes = 0`.
- **D4 — Trạng thái.** Agent: `success | partial | failed | skipped | interrupted | not_started`.
  `skipped` (hợp lệ, ví dụ không có tham số đủ điều kiện) **không** là success. Origin, theo ưu tiên:
  `failed > interrupted > partial > skipped > completed`; `completed` chỉ khi cả năm Agent của origin đều `success`
  và không có `outcome_unknown`. `pipeline_status` chỉ được chốt sau Report và Reflection; `completed` chỉ khi mọi
  điều kiện ở mục 5 đều đạt.
- **D5 — Quyết định khi resume.** Node `llm_decide_*` có checkpoint hợp lệ được reuse. Hành động được tính lại bằng
  hàm thuần trên **checkpoint của chính decision point đó** (không dùng state cuối phiên), so với record đã ghi;
  lệch → `recovery_decision_mismatch`. Không ghi record mới khi reuse.
- **D6 — `finalize_only`.** `LocalOriginTest(..., resume=True, finalize_only=True)`: kiểm đầy đủ authority, journal,
  checkpoint, reconcile; cho phép tổng hợp cả khi phiên đã global stop/hết deadline/hết budget; **0 HTTP mới**
  được chặn bằng ba lớp độc lập (không chạy Agent; transport đóng; journal từ chối reservation), không chỉ dựa vào
  `runtime.stop_reason`. Giữ lý do dừng gốc; kết quả không bao giờ là `completed`.
- **D7 — Phiên đã kết thúc.** Journal có `session_finished` hợp lệ (sự kiện cuối, sau checkpoint `pipeline` khớp
  sha256 và `pipeline_status`) → trả về kết quả đã kiểm toàn vẹn, `recovery.status = already_finished`, không invoke
  graph/Agent, không ghi journal. Checkpoint `pipeline` có mà thiếu `session_finished` → chạy lại Report (Agent reuse);
  digest phải khớp digest đã lưu, lệch → `recovery_report_mismatch`.
- **D8 — Lỗi contract.** Chỉ các precondition đã liệt kê của Agent 4/5 (trước mọi reservation) là `contract_failure`:
  Agent → `failed`, mã public cố định; lỗi ở Agent 4 → Agent 5 `skipped` (`upstream_contract_failure`) → Report.
  Lỗi integrity resume (`*_resume_plan_changed`, `*_phase_cap_changed`, rerun), `ArtifactWriteError`,
  `RecoveryDenied` và lỗi lập trình **không** bị bắt.
- **D9 — Nhãn.** `langgraph_integration = local_full_graph_b42c` ở mode đầy đủ; reflection local không còn nhãn
  `localhost_three_agent_scope`. Gate không đổi.

Mã từ chối mới: `recovery_decision_mismatch`, `recovery_report_mismatch`. Mọi mã B3.2B–B4.2B giữ nguyên ngữ nghĩa.

Ghi chú triển khai so với thiết kế: (1) sau global stop, cạnh tĩnh `param_disc → filter_404` đưa vào Agent 5 và
`check_deadline()` của `_checkpointed` từng làm cả graph thành `failed` (mất Report) — ở mode đầy đủ, Agent kế tiếp
được ghi `not_started` (không gọi Agent, không HTTP) rồi đi tiếp tới Report; (2) để giữ nguyên nghiệm thu B3.2A,
từ vựng `not_started` cho Agent bị dừng bởi global stop chỉ áp dụng ở mode đầy đủ, các mode cũ vẫn `skipped`.

## 2. Topology và routing

Cùng một `StateGraph` (`graph.py:build_coordinator_graph`), không có graph/runner mới:

```
validate_input → init_state → tech_recon → llm_decide_recon → gen_words → llm_decide_wordlist
→ fuzzing → llm_decide_fuzzing ─┬─ proceed_to_param → param_disc → filter_404 ─┐
                                ├─ skip_to_filter ─────────────────→ filter_404 ┤→ report → reflection → END
                                └─ abort_to_report ─────────────────────────────┘
```

| Mode (`LocalOriginTest`) | after_fuzzing (có response, không stop) | Agent 4 | Agent 5 | `completed` khả dĩ |
|---|---|---|---|---|
| mặc định (B3.2A) | `abort_to_report` (`local_three_agent_only`) | không | không | không |
| `parameter_verification` (B4.2A) | `proceed_to_param` | chạy | bypass | không |
| `soft404_verification` (B4.2B) | `skip_to_filter` | không | chạy | không |
| cả hai (B4.2C) | `proceed_to_param` | chạy | chạy | có, khi đủ điều kiện mục 5 |

- `decision_for(state, point, stop)` (`origin_local.py:441`) là hàm thuần; `decide` (`:463`) chỉ ghi record.
  Không response sau Fuzzing ở mode 4/5 → `no_target_responses`. Không có retry (`max_retries = 0`).
- Global stop trong Agent 4 → Agent 5 `not_started` (`reuse_node`, `origin_local.py:263`) → Report.
- Lỗi contract Agent 4 → Agent 5 `skipped` (`upstream_contract_failure`) → Report (`_contract`, `:382`).
- Local halt (quota origin) chỉ dừng origin đó; global stop/budget/deadline dừng mọi origin.

## 3. Contract bàn giao giữa năm Agent

| Từ → Đến | Dữ liệu | Authority |
|---|---|---|
| A1 → A2 | `origin_contexts[o].endpoints` (observation, provenance), `context.{parameters, forms, source_documents}` | Quan sát; không cấp quyền |
| A2 → A3 | `context.wordlist.candidates` (`method=None` = chỉ review) | `OriginScopePolicy` kiểm lại lúc gửi |
| A3 → A4/A5 | `context.http_dispatch.records` (`runtime_sequence`, `status_code`, `evidence_refs`) | Đối chiếu lại endpoint, wordlist, policy |
| A4 → A5 | `context.parameter_discovery.endpoints[*].candidates[verification]` | `context_only`; không nâng endpoint |
| A1–A5 → Report | Các section trên + `recovery.*_outcome_unknown_sequences` | Report chỉ đọc; không tạo verdict |

Mức bằng chứng giữ nguyên: *observed* (A3, đo lại), *inferred* (tham số static, phân loại), `rederived`,
`metrics_journaled`, `interrupted`. Endpoint luôn `not_verified`; `genuine_distinct` không phải xác nhận nghiệp vụ.

## 4. Report và Reflection contract

`state.multi_origin_report = {schema_version, stage, content, digest, digest_rule, status, mode}`
(`origin_report.py:build_report`, gọi từ `generate_report` qua `LocalOriginTest.report`, `origin_local.py:506`).

- `content.approved_origins[]`: mỗi origin đã phê duyệt có `status`, `agents{status, reason}`, `skipped_agents`,
  `recon`, `wordlist`, `dispatch.records[]`, `parameters.endpoints[]`, `soft404.endpoints[]`,
  `outcome_unknown_sequences`. Mỗi endpoint giữ `endpoint_id`, `url`, `unit_id`, `unit_state`, `evidence_refs`,
  `source_runtime_sequence`; Soft404 giữ `soft404_classification`, `evidence_level`, `candidate_sequence`,
  `control_sequences`, `parameter_context`.
- `content.discovered_only_origins[]`: `approved: false`, `executed: false`, `status: not_applicable`,
  `dispatch_attempts` (phải = 0). Không bao giờ được tính như origin đã thực thi.
- `content.totals`: chỉ là tổng của các section theo origin. `content.stop`: `global_stop_reason`,
  `contract_failures`. `content.gate`: `not_enabled_b1`, `full_multi_origin_execution_enabled: false`.
- Digest: `sha256(json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False))`. `content`
  không chứa timestamp, `response_time`, đường dẫn artifact, PID, cờ `finalize_only` hay trạng thái recovery.

`state.local_reflection` (`build_reflection`, `LocalOriginTest.reflect`, `origin_local.py:532`):
`mode = deterministic_local_no_knowledge_write`, `llm_called: false`, `knowledge_writes: 0`, `lessons: []`,
`report_digest`, `observations[] = {id, kind, report_path, value}` với `value == resolve(content, report_path)`.
Không gọi `_get_decision_engine`, không ghi KnowledgeStore (lab thay cả hai bằng stub ném lỗi).

## 5. Pipeline status và `all_modules_*`

Agent: `success | partial | failed | skipped | interrupted | not_started`. Một Agent mà mọi origin đều `skipped`
là `skipped` (không phải success). Origin: `failed > interrupted > partial > skipped > completed`; `completed` chỉ khi
cả năm Agent của origin `success` và không có `outcome_unknown`.

- `all_modules_executed`: cả năm Agent có attempt (chạy thật hoặc reuse từ checkpoint có journal) **và** trạng thái
  thuộc `{success, partial, failed, interrupted}` (skipped/not_started không tính là đã thực thi).
- `all_modules_successful`: `all_modules_executed`, cả năm `success`, không `interrupted`/`outcome_unknown`.
- `pipeline_status` chỉ chốt trong `finish` sau Reflection (`origin_local.py:561`). `completed` khi đủ: mode đầy đủ,
  không `finalize_only`, Reflection `completed` và gắn đúng digest, không stop runtime/stop_reason, `error_log` rỗng,
  không contract failure, `all_modules_successful`, mọi origin đã phê duyệt `completed`, totals unknown = interrupted
  = 0. Ngược lại `partial` (có response) hoặc `failed`. Các mode cũ không thể `completed`.

## 6. Recovery, finalize-only và already_finished

- **Quyết định (D5):** `_verify_decisions` (`origin_recovery.py:399`) tính lại hành động trên checkpoint của chính
  decision node (runtime stop trong snapshot của checkpoint đó), so với record; chuỗi quyết định đã khôi phục phải
  khớp đúng các record đã kiểm, không trùng. `reuse` (`:473`) đặt `_last_decision_action` từ record, không ghi thêm.
- **Report (D7):** `_verify_reports` (`:426`) đòi `digest == canonical(content)` ở mọi checkpoint; digest của
  checkpoint `generate_report` mới nhất ràng buộc lần tính lại trong `report()` → lệch: `recovery_report_mismatch`.
- **finalize_only (D6):** cùng `_restore` đầy đủ (authority, clock, hash chain, sha256 checkpoint, counter, scope,
  reconcile probe/soft404, quyết định, report). Chỉ ba điều kiện `recovery_global_stop`, `recovery_deadline_expired`,
  `recovery_budget_exhausted` được nới cho chế độ này; mọi lỗi integrity vẫn từ chối. 0 HTTP nhờ ba lớp độc lập:
  (1) node Agent không được gọi (`finalize_skipped`, không ghi là checkpoint hoàn tất); (2) cả ba transport
  `dispatch_closed` → `finalize_only_no_dispatch`; (3) `RecoveryJournal.reserve` ném `PipelineStopped` trước mọi
  ghi journal. Lý do dừng gốc được giữ (`runtime.stop_reason`); không có thì `finalize_only`. Không bao giờ `completed`.
- **already_finished (D7):** `session_finished` phải là sự kiện cuối, đứng ngay sau checkpoint `pipeline` có cùng
  `pipeline_status` (`_finished`, `:440`). Kết quả trả về là checkpoint đó (đã kiểm sha256), `recovery.status =
  already_finished`, `graph_invoked/agents_invoked/journal_appended = false`. Journal không bị ghi thêm.
- Không tuyên bố exactly-once: replay vẫn là at-most-once; hash chain không chống người có toàn quyền ghi.

## 7. File và hàm thay đổi

File mới:
- `src/coordinator/origin_report.py`: `canonical_digest`, `origin_agent_status`, `origin_status`, `global_agent_status`,
  `build_report`, `resolve`, `build_reflection` (thuần, không import transport/runtime).
- `scripts/verify_origin_full_graph_evidence.py` (stdlib, không import `src`).
- Test: `tests/test_origin_full_graph.py` (16 unit), `tests/test_origin_full_graph_http.py` (7 HTTP in-process,
  graph thật), `tests/test_origin_full_graph_recovery_http.py` (14 subprocess kill/restart), worker
  `tests/origin_full_graph_recovery_worker.py`.

File sửa (chỉ thêm, tối thiểu):
- `src/coordinator/origin_local.py`: `CONTRACT_ERRORS`, `_closed`, tham số `finalize_only`, `full_graph`,
  `close_dispatch`, `finished_result`, `completion_event`, `reuse_node`, `leave_node`, `_default_stop`,
  `_agent_status`, `_contract`, `soft404`, `parameters`, `decision_for`, `decide`, `_fill`, `_absent`, `report`,
  `reflect`, `_completed`, `finish`.
- `src/coordinator/origin_recovery.py`: `DECISION_NODES`, cờ `finalize_only`/`decisions`/`prior_report_digest`/
  `already_finished`, `bind` trả kết quả đã kết thúc, `_restore` (session_finished, nới finalize), `_verify_decisions`,
  `_verify_reports`, `_finished`, `reserve` (từ chối khi finalize), `reuse` (decision node).
- `src/coordinator/graph.py`: `_checkpointed` dùng `completion_event` (`:260`); `generate_report` gọi
  `local.report` (`:1111`); `post_session_reflection` gọi `local.reflect` (`:1140`); `run_pipeline` trả
  `already_finished` sau `bind` (`:1408`).
- `src/coordinator/state.py`: chú thích `multi_origin_report`, `local_reflection`.

Không đổi: `origin_dispatch.py`, `origin_parameters.py`, `origin_soft404.py`, `runtime.py`, `telemetry.py`,
`supervisor.py`, `validation.py`, các Agent và đường single-target.

## 8. Tiêu chí nghiệm thu và bằng chứng

| # | Tiêu chí | Bằng chứng | Mức |
|---|---|---|---|
| 1 | Graph đầy đủ Agent 1→5 → Report → Reflection; Agent 4 và 5 gửi HTTP thật trên cả hai origin | `test_full_graph_five_agents_report_reflection`: trace LangGraph đúng 12 node; journal 66 reservation (recon 2, dispatch 9, Agent 4 33, Agent 5 22), server log 37 + 29 = 66; verdict Agent 4 và lớp Agent 5 khớp kỳ vọng; `completed`. Verifier `check_agent_http` | integration_verified |
| 2 | Routing/state của mode cũ và mới | `test_decision_table_per_mode`, `test_legacy_local_modes_keep_routing_and_never_complete`; B3.2A/B4.2A/B4.2B nguyên vẹn | integration_verified |
| 3 | Global stop và local halt | `test_global_429_in_agent4_stops_all_origins_and_reports` (Agent 5 0 request, `not_started`), `test_origin_quota_halt_is_local_and_reported` | integration_verified |
| 4 | Budget/deadline xuyên pipeline, không reset | `test_global_budget_spans_all_agents_without_reset`; recovery: `process_bound` không giảm, counter ≥ trước crash; mutation `counter_reset_after_resume` | integration_verified |
| 5 | Crash/restart xuyên A3–A5, Report, Reflection, kết quả cuối, phiên đã kết thúc | 9 case `test_crash_*`/`test_finished_*` (kill thật); 0 HTTP sau crash từ checkpoint A5 trở đi (log server); `already_finished` không ghi journal | integration_verified |
| 6 | Toàn vẹn checkpoint/journal | `test_consistently_forged_decision_is_rejected` (`recovery_decision_mismatch`), `test_consistently_forged_report_is_rejected` (`recovery_report_mismatch`), `test_finalize_never_bypasses_integrity` (`recovery_checkpoint_invalid`) | integration_verified |
| 7 | Origin và credential isolation | Mọi case: origin chưa phê duyệt 0 request; frontend chỉ nhận credential của nó, gateway `anonymous`; không có giá trị credential trong result/checkpoint/journal | integration_verified |
| 8 | Report/Reflection integrity | Unit `ReportContractTests`, `ReflectionTests`; verifier tính lại digest, đối chiếu từng endpoint với checkpoint có neo journal, totals = tổng section, mọi observation trỏ đúng giá trị, `knowledge_writes = 0` | integration_verified |
| 9 | Verifier độc lập | `verify_origin_full_graph_evidence.py --expected-cases 21 --negative-checks`: 21/21 | integration_verified |
| 10 | 8 negative mutation | 8/8 phát hiện (mục 10) | integration_verified |
| 11 | Regression và verifier cũ | Full 801/801; B3.1–B4.2B test và verifier đều PASS (mục 9) | integration_verified |
| — | finalize_only 0 HTTP kể cả còn budget; already_finished không chạy lại | `test_finalize_with_budget_remaining_sends_nothing`, `test_finalize_after_global_stop_preserves_stop_with_zero_http`, `test_finished_session_returns_already_finished_without_execution` | integration_verified |
| — | Lỗi contract vs lỗi lập trình | `test_contract_failure_in_agent4_skips_agent5_and_reports`, `test_unexpected_agent4_error_is_not_masked`, unit `test_contract_failure_only_for_listed_preconditions` | integration_verified |
| — | Gate đóng | `origin_execution_mode = not_enabled_b1`, `full_multi_origin_execution_enabled = False` ở mọi section; `validate_input` không đổi | integration_verified |

## 9. Baseline và final regression

Thư mục `output_samples/diagnostics/multi_origin_b42c_20261126T005830Z/` (gitignored), HEAD `6cea1d6`.

| Bước | Kết quả |
|---|---|
| Baseline trước khi sửa source (00:58–01:11 UTC) | 764/764 OK, exit 0; hash 139 file `src/tests/scripts` không đổi trong lúc chạy |
| B4.2C (`test_origin_full_graph*.py`) | 37/37 OK (16 unit, 7 HTTP, 14 subprocess recovery), exit 0 |
| Verifier B4.2C | 21/21 case, 8/8 mutation, exit 0 |
| B3.1 | 36/36 OK; verifier PASS, 4/4 mutation |
| B3.2A | 30/30 OK; verifier 21/21 case, 4/4 mutation |
| B3.2B | 38/38 OK; verifier 27/27 case, 4/4 mutation |
| B4.1 | 15/15 OK; verifier 8/8 case, 5/5 mutation |
| B4.2A | 25/25 OK; verifier 16/16 case, 6/6 mutation |
| B4.2B | 42/42 OK; verifier 26/26 case, 7/7 mutation |
| Full regression (bản source cuối) | 801/801 OK (764 + 37), 0 FAIL, 0 ERROR, 0 SKIPPED, exit 0 |
| `run_coordinator_scan.py --check` | exit 0, không gửi request |
| Hash source đầu/cuối nghiệm thu | giống hệt (`source_unchanged=true`) |
| `git status` | 50 mục trước triển khai → 57 (7 file mới của B4.2C); không mục có sẵn nào bị mất |

Ghi chú quy trình (trung thực): unit test viết trước và chạy đỏ (module chưa tồn tại) rồi mới viết code; test
HTTP/recovery được soạn song song với code, không hoàn toàn TDD. Trong lúc phát triển, test đã bắt 3 lỗi thật:
toán tử ưu tiên khi tính discovered-only (unit), global stop ở Agent 4 làm graph `failed` (HTTP), và `stop_reason`
của finalize khi không có stop gốc (recovery). Hai test B3.2A đỏ khi từ vựng `not_started` áp dụng cho mọi mode; đã
giới hạn về mode đầy đủ để giữ hành vi cũ — không sửa test cũ, không nới ngưỡng.

## 10. Independent verifier và negative mutations

`scripts/verify_origin_full_graph_evidence.py` tự tính: hash chain + head, sha256 mọi checkpoint, khớp log server với
reservation đã dispatch (theo origin/path/query), không replay identity, counter không giảm, digest Report, ràng buộc
Reflection, cô lập origin, so endpoint với checkpoint neo journal, totals, quy tắc `completed`, verdict Agent 4 từ
body server (body có tham số ≠ body gốc), 0 HTTP sau crash/finalize/already_finished, journal không đổi sau
already_finished. Case cố ý làm hỏng checkpoint khai báo `tampered_checkpoint`; verifier đòi đúng checkpoint đó bị lộ.
Mutation sửa **bản sao trong bộ nhớ** của evidence (digest được tính lại cho nhất quán, nên chỉ kiểm tra ngữ nghĩa mới
bắt được):

| Mutation | Phát hiện bởi |
|---|---|
| `report_origin_merged` | endpoint của gateway nằm dưới section frontend |
| `report_count_inflated` | `totals.soft404_strong` ≠ tổng section |
| `decision_duplicated` | record quyết định trùng |
| `reflection_unbacked_observation` | observation không khớp giá trị trong report |
| `status_upgraded_completed` | `completed` khi chưa đủ năm Agent `success` |
| `evidence_level_upgraded` | lớp/mức bằng chứng lệch checkpoint có neo journal |
| `counter_reset_after_resume` | counter runtime ≠ số reservation trong journal |
| `parameter_promotes_endpoint` | endpoint bị nâng thành `verified` |

## 11. Giới hạn còn tồn tại (`not_verified`)

- Internet, TLS thật giữa origin, DNS name, proxy, ffuf, LLM thật, production multi-origin.
- Độ bền khi mất điện (chỉ kiểm khi kill tiến trình). Hash chain không chống người có toàn quyền ghi; giả mạo nhất quán
  chỉ bị bắt bởi tính lại ngữ nghĩa (quyết định, digest report) và log server trong lab.
- Crash *bên trong* phần tính Report/Reflection không có ghi bền nào để làm barrier; được phủ bằng crash ở checkpoint
  liền trước/sau (A5, Report, Reflection, `pipeline`, `session_finished`).
- Quyết định được tính lại từ checkpoint của chính decision node; nếu kẻ giả mạo sửa nhất quán cả dữ kiện lẫn hành động
  trong checkpoint đó thì chỉ log server/journal reservation mới bắt được.
- Supervisor (hard deadline) vẫn không nhận `LocalOriginTest`. Recovery là at-most-once, không exactly-once.
- `genuine_distinct` không xác nhận endpoint hợp lệ nghiệp vụ; endpoint luôn `not_verified`.
- `finalize_only` không bao giờ cho `completed`, kể cả khi bằng chứng đầy đủ (dùng resume thường để hoàn tất).
- `origin_contexts` của origin chưa phê duyệt vẫn giữ trạng thái công cụ cũ (`wordlist_gen`); chỉ Report tách riêng.

## 12. Đường dẫn evidence

`output_samples/diagnostics/multi_origin_b42c_20261126T005830Z/`: `acceptance.log`, `baseline.log`,
`b42c_tests.log`, `b42c_verifier.log`, `b42c/` (21 case + `independent_verification.json`),
`B31|B32A|B32B|B41|B42A|B42B_{tests,verifier}.log` cùng thư mục evidence tương ứng, `full_regression.log`,
`coordinator_check.log`, `source_hashes_{baseline,start,end}.txt`, `git_status_{start,acceptance_start,end}.txt`.

```powershell
$env:B42C_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b42c_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_full_graph*.py' -v
.\.venv\Scripts\python.exe -B scripts/verify_origin_full_graph_evidence.py $env:B42C_EVIDENCE_DIR --expected-cases 21 --negative-checks
```

## 13. Kết luận nghiệm thu

B4.2C đạt **`integration_verified`** trong lab loopback: 37/37 test; verifier 21/21 case và 8/8 mutation; sáu
verifier của các stage trước PASS trên evidence mới; full regression 801/801; source không đổi trong lúc nghiệm thu;
gate `not_enabled_b1` và `full_multi_origin_execution_enabled = False` giữ nguyên. Mọi thứ ngoài lab vẫn `not_verified`.

## 14. Điều kiện bàn giao sang B5

B5 chưa bắt đầu. Đầu vào sẵn có: `multi_origin_report` (contract `schema_version 1`, digest chuẩn hóa) và
`local_reflection` như hợp đồng dữ liệu tối thiểu. B5 cần quyết định: render (HTML/MD), mức độ nghiêm trọng, khử trùng
lặp giữa origin, xuất file, ghi KnowledgeStore có provenance, quyết định LLM có guard cho multi-origin, supervisor dựa
trên journal. Trước khi xem xét production multi-origin vẫn thiếu: quyết định mở gate riêng, DNS/chống rebinding, TLS
thật, kho credential bảo mật, hard deadline có recovery theo journal, độ bền mất điện, chính sách proxy/ffuf, phép thử
trên target được ủy quyền và quy trình phê duyệt theo origin.
