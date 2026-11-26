# B6 — Full Acceptance: Multi-Origin FuzzingTool MVP (local)

Trạng thái: **nghiệm thu xong**.

- **MVP Multi-Origin localhost: ĐẠT** (`integration_verified` trong lab loopback).
- **Multi-Origin production: CHƯA ĐẠT** (`not_verified`; gate vẫn `not_enabled_b1`).

B6 chỉ nghiệm thu: không sửa source, test hay verifier của repo, và không triển khai tính năng mới.

## 1. Mục tiêu và phạm vi

Mục tiêu là nghiệm thu toàn bộ luồng multi-origin trong lab loopback có kiểm soát:
- cấu hình và gate;
- Coordinator và một LangGraph;
- năm Agent;
- runtime, budget và telemetry;
- scope và credential isolation;
- recovery (crash, resume, finalize, already-finished);
- Report và Reflection;
- export JSON/Markdown.

Ngoài phạm vi: HTML, severity, khử trùng lặp giữa origin, KnowledgeStore/LLM Decision Engine mới, Supervisor recovery,
sửa R8, Report v2, Agent hay graph mới, mở gate, Internet, LLM thật.

Evidence B6: `output_samples/diagnostics/multi_origin_b6_20261126T063201Z/` (gitignored), HEAD `6cea1d6`,
06:32–07:07 UTC.

## 2. Kiến trúc cuối cùng (đối chiếu source)

- **Một Coordinator, một graph.**
  - `build_coordinator_graph` tạo **một** `StateGraph(dict)` duy nhất trong `src/`
    ([graph.py:1217](../src/coordinator/graph.py#L1217)) và compile một lần ([graph.py:1295](../src/coordinator/graph.py#L1295)).
  - Graph có 12 node ([graph.py:1220-1233](../src/coordinator/graph.py#L1220-L1233)): `validate_input`, `init_state`,
    `tech_recon`, `gen_words`, `fuzzing`, `param_disc`, `filter_404`, `report`, `reflection`, và `llm_decide_{recon,wordlist,fuzzing}`.
  - Test B4.2C ghi lại trace LangGraph thật từ callback (12 node đúng thứ tự). Không có pipeline giả lập.
- **Gate.** `validate_input` chặn mọi config `multi_origin` khi không có `LocalOriginTest`
  (`stop_reason = multi_origin_execution_not_enabled_b1`, [graph.py:350-358](../src/coordinator/graph.py#L350-L358)).
  - `full_multi_origin_execution_enabled` chỉ xuất hiện trong `src/` với giá trị `False` (6 chỗ).
  - Không file nào trong `src/` hay `scripts/` dựng `LocalOriginTest`; nó chỉ được tạo trong `tests/`.
- **Routing.**
  - Mọi node Agent và node quyết định đều có nhánh `LocalOriginTest` trước nhánh LLM. Ví dụ quyết định ở
    [graph.py:561-564](../src/coordinator/graph.py#L561-L564), Agent ở [graph.py:455-460](../src/coordinator/graph.py#L455-L460).
  - Ở mode local, quyết định là hàm thuần `decision_for` (`deterministic_local_test_policy`, `llm_called: false`).
  - **Routing bằng LLM cho multi-origin chưa được kiểm chứng (`not_verified`).** Lab thay `_get_decision_engine` bằng stub ném
    lỗi nếu bị gọi.
- **Hạ tầng.** Một `RuntimeBudget` và một telemetry session cho mỗi run; quota theo origin nằm trong cùng budget.
  `RecoveryJournal` (hash chain + head + checkpoint sha256). Report v1 và Reflection tất định. Export offline của B5.

## 3. Vai trò của Coordinator và năm Agent (multi-origin)

| Thành phần | Vai trò | Entry (mode local) |
|---|---|---|
| Coordinator | validate/gate, init, routing tất định, `_checkpointed`, Report, Reflection, `finish` | `run_pipeline(..., local_origin_test=)` |
| Agent 1 Tech Recon | thu tài liệu đã duyệt, observation có provenance theo origin | `TechReconAgent.collect_discovery` |
| Agent 2 Wordlist | chọn candidate offline theo origin, không HTTP | `WordlistGenAgent.generate_from_discovery` |
| Agent 3 Fuzzing | dispatch tuần tự `python_http` qua transport B1 | `FuzzingAgent.dispatch_selected` |
| Agent 4 Parameter | probe query parameter do operator liệt kê, kết quả `context_only` | `ParamDiscoveryAgent.verify_origin_parameters` |
| Agent 5 Soft404 | so representation với control missing-path theo origin | `Soft404FilterAgent.verify_origin_soft404` |

## 4. Data contracts

Contract theo các stage doc, được kiểm lại bằng verifier trên evidence B6:
- A1→A2: `origin_contexts[o].endpoints` có `provenance` (observation không cấp quyền).
- A2→A3: `context.wordlist.{candidates, selected_ids}` (`method=None` chỉ để review).
- A3→A4/A5: `context.http_dispatch.records` (`runtime_sequence`, `status_code`, `evidence_refs`).
- A4→A5: `parameter_context` có `authority = context_only`.
- A1–A5→Report: `multi_origin_report` v1 (digest canonical).
- Report→Export: `multi_origin_report_export` v1.

Identity là `endpoint_id = sha256(url + "\n" + method)[:24]`, trong đó URL đã gồm query.

## 5. Acceptance matrix B1 → B5 (evidence mới trong B6)

Nhãn theo bộ từ vựng của dự án. `live_verified`: **không có chức năng nào**.

| Stage / chức năng | Test B6 | Verifier B6 (evidence mới) | Nhãn |
|---|---|---|---|
| B1 contract + scope + credential isolation | 17 + 9 OK | `verify_b1_evidence.py`: 9 case, 9 HTTP, 0 LLM, exit 0 | integration_verified |
| B2.1 recon discovery | 27 OK | `verify_b21_discovery_evidence.py`: 5 case, 15 attempt / 14 response, exit 0 | integration_verified |
| B2.2 wordlist selection | 25 OK | `verify_origin_wordlist_evidence.py`: Agent 2 gửi 0 HTTP, exit 0 (không có negative checks theo thiết kế) | integration_verified |
| B3.1 dispatch | 36 OK | 4/4 mutation, exit 0 (sau khi sửa lệnh chạy, mục 11) | integration_verified |
| B3.2A graph Agents 1→3 | 30 OK | 21/21 case, 4/4 mutation, exit 0 (sau khi sửa lệnh chạy) | integration_verified |
| B3.2B crash recovery | 38 OK | 27/27 case, 4/4 mutation | integration_verified |
| B4.1 parameters | 15 OK | 8/8 case, 5/5 mutation | integration_verified |
| B4.2A probe recovery | 25 OK | 16/16 case, 6/6 mutation | integration_verified |
| B4.2B Soft404 | 42 OK | 26/26 case, 7/7 mutation | integration_verified |
| B4.2C full local graph | 37 OK | 21/21 case, 8/8 mutation | integration_verified |
| B5 export | 41 OK | 10/10 case (11 export, 3 refusal), 23/23 mutation | integration_verified |
| B5 export trên phiên B4.2C **mới** của B6 | — | 20/20 case (16 export, 4 refusal), 11.831 ô Markdown, 23/23 mutation | integration_verified |
| R8 digest/redaction | unit (B5) | — | **known defect** (unit_verified tái hiện; fail-closed) |
| LLM routing, Internet, TLS, DNS, proxy/ffuf, supervisor, power loss | — | — | not_verified |

Verifier B1 và B2.1 không nằm trong `scripts/`, chỉ có trong thư mục evidence của stage đó. Doc B2.1 nhắc tới
`verify_discovery_evidence.py`. B6 chép hai script này nguyên văn sang `acceptance_tools/` (stdlib, không import `src`).

## 6. Kết quả end-to-end (B4.2C chạy lại trong B6, export bằng B5)

Số liệu từ `B42C/` và `B42C_export/`, đối chiếu với access log server độc lập:

| Case | pipeline | reserved / started / headers / unknown | theo kind (Recon / dispatch / param / soft404) | server frontend + gateway / unapproved |
|---|---|---|---|---|
| completed (5 Agent, Report, Reflection) | completed | 66 / 66 / 66 / 0 | 2 / 9 / 33 / 22 | 37 + 29 = 66 / 0 |
| global stop 429 ở Agent 4 | partial | 16 / 16 / 16 / 0 | 2 / 9 / 5 / 0 | 10 + 6 / 0 |
| hết quota origin | partial | 41 / 41 / 41 / 0 | 2 / 9 / 18 / 12 | 12 (= quota 12) + 29 / 0 |
| crash trong Agent 4, rồi resume | partial (interrupted) | 57 / 56 / 56 / 1 | 2 / 9 / 24 / 22 | 27 + 29 = 56 / 0 |
| finalize-only (còn budget) | partial | 13 / 12 / 12 / 1 | 2 / 9 / 2 / 0 | 6 + 6 / 0 |
| already-finished | completed | 66 / 66 / 66 / 0 | 2 / 9 / 33 / 22 | 37 + 29 / 0; journal không bị ghi thêm (verifier B4.2C) |

Các điểm đã kiểm chứng:
- Cả năm Agent chạy trong cùng một phiên; Agent 4 và Agent 5 gửi HTTP localhost thật.
- Origin chưa duyệt nhận 0 request; credential chỉ tới frontend, gateway luôn `anonymous`.
- Report và Reflection gắn đúng digest; export JSON/MD thành công.
- Các phiên không đủ điều kiện bị từ chối đúng chính sách: 4 case forged, programming error và tampered đều trả
  `export_session_not_finished`.

Quan sát về tính tái lập (không phải defect): số request trước global stop thay đổi giữa các lần chạy. Lần B4.2C có
27 reservation, lần B6 có 16. Nguyên nhân:
- B2.2 phá hòa thứ tự candidate bằng `endpoint_id` ([origin_wordlist.py:112](../src/agents/origin_wordlist.py#L112));
- `endpoint_id` là hash của URL có port lab ngẫu nhiên;
- nên Agent 4 khi thì bắt đầu ở `/promo`, khi thì ở `/help`.

Các bất biến vẫn giữ: mọi origin dừng, Agent 5 gửi 0 request, accounting khớp log.

## 7. HTTP accounting và origin isolation

- Một runtime cho mỗi run: `runtime.http_dispatches` = số `reserved` trong journal = tổng theo origin = tổng theo
  phase/kind (có Recon). Verifier B4.2C, B5 và các stage khác đều kiểm.
- Theo từng origin: `response_headers ≤ arrivals (log server) ≤ dispatch_started`. Mỗi arrival theo (path, query) đều có
  reservation đã start. Export không bao giờ khẳng định server đã nhận request.
- Telemetry: `total_requests = null` khi có reservation chưa start (case crash), và không bao giờ bị thay bằng 0.
- LLM: `max_llm_calls = 0` ở mode local; telemetry `attempted = 0` ở mọi export.

## 8. Recovery verification

- At-most-once: B3.2B, B4.2A, B4.2B, B4.2C đều PASS (identity không bị reserve hai lần; counter không giảm qua các
  process; `exactly_once_delivery: false`). **Không tuyên bố exactly-once.**
- Không reset budget hay deadline (`process_bound` tăng dần; mutation `counter_reset_after_resume`).
- Không mất provenance; decision record không trùng (`recovery_decision_mismatch`); report giả mạo nhất quán bị từ chối
  (`recovery_report_mismatch`).
- Không tạo verdict từ bằng chứng thiếu (`interrupted`, `outcome_unknown`). Không nâng tham số thành endpoint verified.
  `genuine_distinct` không phải lỗ hổng. `metrics_journaled` không bị nâng thành `rederived` (mutation
  `evidence_level_upgraded` ở B4.2C và B5).
- `finalize_only`: 0 HTTP và không bao giờ `completed`. `already_finished`: không chạy graph, không ghi journal.
- Export: hash journal, head và checkpoint trước = sau. Cây evidence B4.2C cũ (7.128 file, gồm 1.742 file `b42c/`) và
  cây evidence B5 đã nghiệm thu (924 file) **không đổi** trong suốt B6.

## 9. JSON và Markdown report mẫu (B6)

- Completed: `B5/b42c_b2f26605_a2bea1/export_first/{report.json, report.md, manifest.json}`.
- Từ B4.2C chạy lại trong B6:
  - completed: `B42C_export/b42c_1269085d_70ff77/export/`;
  - crash trong Agent 4: `B42C_export/b42c_b295cdc1_767e7b/export/`;
  - finalize-only: `B42C_export/b42c_939dd465_ec0338/export/`.

## 10. Independent verifier và negative checks

Tổng số mutation bị phát hiện trên evidence B6:

| Verifier | Mutation |
|---|---|
| B3.1 | 4/4 |
| B3.2A | 4/4 |
| B3.2B | 4/4 |
| B4.1 | 5/5 |
| B4.2A | 6/6 |
| B4.2B | 7/7 |
| B4.2C | 8/8 |
| B5 (evidence test) | 23/23 |
| B5 (trên B4.2C mới) | 23/23 |
| B5 (evidence lịch sử của B5, verify lại chỉ đọc) | 23/23 (20/20 case) |

B2.2 không có negative checks theo thiết kế. B1 và B2.1 dùng verifier gốc của stage, không có cờ negative.

## 11. Full regression và lỗi harness

| Bước | Kết quả |
|---|---|
| Full regression | **842/842 OK**, 0 FAIL, 0 ERROR, 0 skipped, exit 0 |
| `run_coordinator_scan.py --check` | exit 0: "No target, proxy or LLM requests were sent" |
| Verifier B3.1, B3.2A (lần đầu) | **exit 1** (`ModuleNotFoundError: verify_origin_wordlist_evidence`) |

Lỗi của verifier B3.1 và B3.2A ở lần đầu là lỗi của harness B6, không phải lỗi hệ thống.
- Script nghiệm thu gọi mọi verifier với `python -I`. Isolated mode bỏ `scripts/` khỏi `sys.path`, nên lần import module
  cùng thư mục bị lỗi.
- Lệnh chuẩn trong doc của hai stage này không có `-I`.
- Hai verifier được chạy lại đúng cờ của doc trên **cùng** evidence: exit 0, ghi thêm vào `acceptance.log` (dòng
  `*_verifier_rerun_no_isolation_exit=0`).
- Log lỗi gốc (`B31_verifier.err.log`, `B32A_verifier.err.log`) được giữ nguyên.

## 12. Source và evidence integrity

- Manifest source (Python stdlib, fail khi rỗng hoặc sai số file): `source_manifest_start.txt` có 151 file, trùng manifest
  cuối của B5. `source_manifest_end.txt` cũng 151 file. Phép so cho `source_unchanged=true`. Không có file nào bị
  sửa trong B6.
- Manifest cây evidence cũ, trước và sau: B4.2C 7.128 = 7.128, B5 rerun2 924 = 924, đều `tree_unchanged=true`.
- `git status` 64 mục, trùng lúc bắt đầu.
- Phân loại bằng chứng:
  - **Mới**: test và evidence của mọi stage B1 → B5, export B4.2C mới, full regression, `--check`, các manifest.
  - **Tái sử dụng (chỉ đọc)**: evidence lịch sử của B5 (16 export, 4 refusal từ phiên B4.2C gốc), được verify lại với
    23/23 mutation.

## 13. Known defects

1. **R8.** Digest của Report v1 được tính trước khi `RunArtifacts` redact, nên content lưu trên đĩa có thể lệch digest.
   - Đã tái hiện ở unit test (B5 `test_r8_redaction_after_digest_changes_report_content`). Test này chạy trong
     regression B6 và PASS.
   - Export từ chối `export_report_digest_mismatch`; recovery từ chối `recovery_report_mismatch`. Không có bước nào tính
     lại digest.
   - Chưa tái hiện trên graph thật, vì `knowledge/` không có tên nào khớp pattern.
   - R8 **không chặn** tiêu chí nghiệm thu nào trong lab. Phiên không có journal có thể mang report có digest lệch mà
     không bị phát hiện.
   - Đề xuất task riêng sau B6, theo phương án tương thích ngược ở `multi_origin_b5.md` §8.
2. **Tài liệu.** Verifier của B1 và B2.1 chỉ có trong thư mục evidence (không có trong `scripts/`). Doc B1, B2.1, B2.2
   và B3.2B không ghi nhãn trạng thái chuẩn. Không ảnh hưởng tới kết quả.
3. **Tính tái lập theo port** (mục 6). Thứ tự probe và số request trước stop phụ thuộc port lab. Không phải lỗi an
   toàn, nhưng nên lưu ý khi so số liệu giữa các lần chạy.

## 14. Danh sách `not_verified`

- LLM thật và routing bằng LLM trong multi-origin. Internet. TLS thật giữa origin. DNS và chống rebinding (lab chỉ
  nhận IP loopback literal).
- Proxy và ffuf cho multi-origin (chỉ `python_http`).
- Supervisor hard deadline cho `LocalOriginTest`. Độ bền khi mất điện (mới chỉ kiểm kill process).
- Hash chain không chống được người có toàn quyền ghi. Giả mạo nhất quán chỉ bị bắt nhờ tái suy ngữ nghĩa và log server
  trong lab.
- Comparator Soft404: `metrics_journaled` dựa vào similarity đã ghi; journal không lưu body nên không tính lại được.
  Chỉ verifier trong lab tính lại được từ body server.
- Case B4.2C legacy (3 run dùng chung một access log) không được nghiệm thu export.
- Production multi-origin, tức gate mở, credential store bảo mật, phê duyệt theo origin, target được ủy quyền thật.

## 15. Tái lập lab nghiệm thu

```powershell
$E = 'output_samples/diagnostics/multi_origin_b6_<UTC>'
$T = (Resolve-Path 'output_samples/diagnostics/multi_origin_b6_20261126T063201Z/acceptance_tools').Path
powershell -NoProfile -ExecutionPolicy Bypass -File "$T\acceptance_b6.ps1" -E $E -Tools $T -ExpectedFiles 151
# Verifier B3.1/B3.2A: chạy theo cờ của doc (không -I), ví dụ:
.\.venv\Scripts\python.exe -B scripts/verify_origin_dispatch_evidence.py "$E/B31" --negative-checks
.\.venv\Scripts\python.exe -B scripts/verify_origin_graph_evidence.py "$E/B32A" --expected-cases 21 --negative-checks
```

Script `acceptance_b6.ps1` còn mang lỗi `-I` cho B3.1/B3.2A. Nó được giữ nguyên làm bằng chứng của lần chạy này;
khi tái lập, dùng hai lệnh trên.

## 16. Đường dẫn evidence

`output_samples/diagnostics/multi_origin_b6_20261126T063201Z/` gồm:
- `acceptance.log`, `*.out.log`, `*.err.log`;
- `B1`, `B21`, `B22`, `B31`, `B32A`, `B32B`, `B41`, `B42A`, `B42B`, `B42C`, `B5/`;
- `B42C_export/` (kèm `historical_summary.json`);
- `source_manifest_{start,end}.txt`, `prior_b42c_tree_{start,end}.txt`, `prior_b5_tree_{start,end}.txt`;
- `git_status_{start,end}.txt`, `acceptance_tools/`.

Các stage trước có evidence riêng: `multi_origin_b42c_20261126T005830Z/`, `multi_origin_b5_20261126T024125Z/`.

## 17. Kết luận MVP Local Multi-Origin

**ĐẠT — `integration_verified` trong lab loopback.**

Lý do:
- cả năm Agent, Report, Reflection và export chạy trên graph thật;
- mọi stage B1 → B5 có test và verifier PASS trên evidence mới (B3.1 và B3.2A sau khi sửa lệnh chạy của harness);
- full regression 842/842;
- `--check` exit 0;
- source và evidence cũ không đổi;
- gate `not_enabled_b1` và `full_multi_origin_execution_enabled = False`.

Kết luận này chỉ áp dụng cho deterministic local routing trên loopback.

## 18. Production readiness gap analysis

**Multi-Origin production: CHƯA ĐẠT.** Không có chức năng nào `live_verified` hay `production_ready`. Những gì còn thiếu:

1. Quyết định mở gate riêng, kèm quy trình phê duyệt theo từng origin và target được ủy quyền thật.
2. DNS name và chống rebinding; TLS thật giữa origin.
3. Kho credential bảo mật thay cho profile trong bộ nhớ.
4. Routing và decision bằng LLM có guard, được kiểm chứng cho multi-origin.
5. Supervisor hard deadline có recovery theo journal; độ bền khi mất điện.
6. Chính sách proxy/ffuf có evidence riêng.
7. Sửa R8 ở tầng nguồn.
8. Chống giả mạo khi kẻ tấn công có toàn quyền ghi (ký hoặc lưu journal ngoài host).
9. Các quyết định B5 để lại: HTML, severity, khử trùng lặp, KnowledgeStore có provenance.
10. Phép thử trên target thật được ủy quyền.

Giai đoạn tiếp theo chưa được khởi động.
