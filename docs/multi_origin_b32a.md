# B3.2A — Coordinator/LangGraph, Agent 1 → Agent 2 → Agent 3

B3.2A tích hợp các entry points B2.1/B2.2/B3.1 vào **những node Coordinator đã
có**, chạy bằng compiled LangGraph thật. Không tạo graph khác hoặc gọi ba Agent
tuần tự từ runner. Chế độ này chỉ dành cho HTTP localhost tests; full multi-origin
pipeline vẫn fail-closed, chưa gọi Parameter/Soft404 đa origin.

## Gate và phạm vi

API `run_pipeline(..., local_origin_test=LocalOriginTest(...))` yêu cầu một context
riêng tạo bằng Python, dùng một lần. Không có cờ JSON/SharedState để bật chế độ.
Context giữ private credential profiles và transport; không serialize nó vào
state/checkpoint/LLM. Chạy `run_pipeline()` bình thường với `multi_origin` vẫn bị
chặn tại validation như B1.

Chỉ chấp nhận IP loopback literal (127.x.x.x hoặc ::1); hostname DNS, `localhost`,
IP ngoài loopback, numeric shorthand và IPv4-mapped IPv6 đều bị chặn. Exact
scheme/host/port/path/query/method/read_only và credential binding của B1 được
kiểm lại. Loopback cũng được kiểm tại transport trước mỗi request. Approved
origins và document plan phải do operator cấu hình, discovery không cấp scope.

Yêu cầu `fuzzing_options={"engine":"python_http"}`, `max_retries=0`,
`run_all_modules=False`; proxy/ffuf, cấu hình token/headers/provider trong config
chung không được chấp nhận. Credentials giả cho lab chỉ được bind riêng từng
origin trong private context. Không tự đổi User-Agent, TLS, redirect hoặc IP.

## API tích hợp

```python
from src.coordinator.graph import run_pipeline
from src.coordinator.origin_local import LocalOriginTest

# URL/port thực của các server loopback đang chạy; scope/documents do test tạo.
local = LocalOriginTest(
    frontend_url,
    scope=approved_scope,       # B1 approved_origins + exact origin_policies
    documents=document_plan,   # [{url, kind: html/javascript/openapi, document_url?}]
    origin_max_requests={frontend_origin: 8, gateway_origin: 8},
    credential_profiles=fake_local_profiles,  # runtime only; có thể bỏ nếu anonymous
)
result = run_pipeline(frontend_url, {
    "multi_origin": approved_scope,
    "fuzzing_options": {"engine": "python_http"},
    "max_retries": 0,
    "max_wordlist_entries": 3,
    "http_max_requests": 8,
    "http_rate_limit": 10,
    "http_timeout_seconds": 1,
    "pipeline_timeout_seconds": 15,
    "artifact_root": artifact_root,
}, local_origin_test=local)
```

Ví dụ dùng các biến do lab cung cấp; không tự tạo approval cho URL bất kỳ. Không
truyền token thật và không dùng context này để nghiệm thu Internet. Hệ thống
tạo đúng một runtime trong `run_pipeline`; quotas được đặt trước Recon, không
tạo runtime theo Agent/origin. Không đặt một runtime mới giữa các node.

## Graph và SharedState

Topology 12 node hiện hữu giữ nguyên. Nhánh lab chạy:

```text
validate_input → init_state → tech_recon → llm_decide_recon
              → gen_words → llm_decide_wordlist
              → fuzzing → llm_decide_fuzzing → report → reflection → END
```

- `tech_recon`: `collect_discovery()` theo explicit document plan rồi
  `merge_discovery_context()`; giữ execution/errors và ngữ cảnh B2.1.
- `gen_words`: `generate_from_discovery()` đọc chính `origin_contexts`, lưu
  catalog/selected IDs theo B2.2; không gửi HTTP.
- `fuzzing`: `dispatch_selected()` dùng transport/runtime chung; giữ ledger
  và `context.http_dispatch` của B3.1, không flatten gateway vào frontend.
- Decision nodes vẫn được graph thực thi, nhưng ở chế độ này là routing xác
  định dựa trên trạng thái/budget. Không dùng LLM hoặc giả danh quyết định LLM:
  `source=deterministic_local_test_policy`, `llm_called=false`. Budget LLM hiệu
  dụng bằng 0, dù schema config legacy có minimum 1.
- Global stop tại Recon/dispatch đi thẳng về report; deadline cũng được kiểm
  ở decision node để không tiếp tục Agent khi đã hết hạn.
- `reflection` ghi lý do skipped; không gọi provider hoặc ghi KnowledgeStore.

SharedState thêm `local_origin_execution` với mode, runtime_id, node_trace,
langgraph_trace, agent_artifacts, status/stop_reason và `full_pipeline_enabled=false`.
`node_trace` ghi tại wrapper checkpoint; `langgraph_trace` lấy từ callbacks của
LangGraph thực, không tự dự đoán node sequence. File checkpoint started/checkpoint
ở mỗi node giữ state trước/sau. Artifact riêng Agent 2/3 có reference trong state.

Các trường B1–B3.1 giữ nguyên: `origin_contexts`, discovery/provenance,
`wordlist_metadata.multi_origin`, `fuzzing_execution.multi_origin`, telemetry và
runtime reservations. Counter theo origin tính cả Recon và dispatch, không đếm
generation thành HTTP. Candidate attempted/verified giữ đúng semantics B3.1.

`local_origin_execution.status=completed` chỉ mô tả ba Agent trong lab. Toàn
pipeline vẫn `partial`, `all_modules_executed=false`, `all_modules_successful=false`,
Agent 4–5 `skipped`. Nếu không có response và bị lỗi, full result là failed.
Kết quả HTTP chỉ observed; verified vẫn null/not_verified.

Không gọi lại node đã đi qua trong cùng context. Context không tái sử dụng được.
Nạp checkpoint và gọi graph khi không có private context bị production gate chặn;
không reset quota để resume. B3.2A **không hỗ trợ recovery qua runtime/process mới**.

## Pacing và tương thích một origin

Baseline B3.2A tái hiện test pacing B3.1 thất bại. Phép tái hiện unit cho thấy
`sleep()` thức sớm 3 ms cho phép reservation ở 0,097s thay vì 0,100s. Runtime hiện
chờ lại phần còn thiếu cho tới slot monotonic thật, tiếp tục kiểm deadline, rồi
mới tăng counter. Không tăng rate/timeout/budget, không nới ngưỡng test.

Đây là sửa runtime chung cần thiết để giữ global rate limit; đường Agent một
origin và toàn bộ graph topology/LLM routing production không đổi. Các guard
scope/TLS/redirect/auth cũ tiếp tục được regression suite kiểm tra.

## Chạy test và verifier

PowerShell tại repository root:

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:LANGCHAIN_TRACING_V2 = 'false'
$env:B32A_EVIDENCE_DIR = Join-Path $PWD ('output_samples/diagnostics/b32a_local_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
New-Item -ItemType Directory -Path $env:B32A_EVIDENCE_DIR -Force | Out-Null
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_graph*.py' -v 2>&1 |
    Tee-Object -FilePath (Join-Path $env:B32A_EVIDENCE_DIR 'tests.log')
.\.venv\Scripts\python.exe -B scripts/verify_origin_graph_evidence.py $env:B32A_EVIDENCE_DIR --negative-checks --expected-cases 21
```

30 tests mới: 9 unit, 21 graph/HTTP cases (gồm ca gate production phải nhận 0 HTTP).
Lượt nghiệm thu cuối chạy **644/644 regression tests PASS**; verifier graph
21/21 và verifier B3.1 23/23 PASS, mỗi bộ từ chối đủ 4 negative mutations.
Tests tự mở ba server với cổng ngẫu nhiên; không cần Internet, API key hay token.
LLM/provider không được gọi, số mock LLM decisions cũng bằng 0. Agent method spies
chỉ ghi input/output/runtime identity rồi gọi nguyên hàm thật, không mock HTTP.

Verifier dùng stdlib và helper source-evidence B2.2, không import Coordinator,
Agent, dispatcher/runtime hoặc scope implementation. Nó đối chiếu callbacks →
node checkpoints → observation/selection → ledger → access logs độc lập, budgets,
credential labels và result/checkpoint. `--expected-cases 21` ngăn một lượt bị
gián đoạn với thiếu cases được dùng thay nghiệm thu đầy đủ. Negative checks sửa
bản sao artifacts về agent status, origin, request thiếu hoặc request lặp và
phải bị từ chối. Bản gốc không bị sửa.

[Báo cáo và test summary](../output_samples/diagnostics/multi_origin_b32a_20261123T165959Z/report.md)
là nguồn kết quả nghiệm thu; không suy ra toàn suite PASS từ riêng unit tests.
Lỗi `test_async_call_cancels_transport_and_next_call_still_works` đã có bằng chứng
trên clean HEAD từ B3.1; không sửa hay nâng timeout test này trong B3.2A.

## Giới hạn và bàn giao

- Chỉ `implemented/unit_verified/integration_verified` trong phạm vi lab;
  Internet, DeepSeek production, full pipeline đa origin chưa được kiểm chứng.
- HTTP localhost không thay cho HTTPS đa origin; TLS verification vẫn bật theo
  B1 nhưng chưa thêm live TLS test trong B3.2A.
- B3.2B cần recovery, reconcile checkpoint/ledger/counters sau crash và chặn
  duplicate qua process mới trước khi hỗ trợ resume.
- B4 cần Parameter/Soft404 theo origin, credential/scope/stop và baseline riêng
  trước khi mở full multi-origin execution. Chưa gọi hai Agent này trong lab.
- Generated method=null vẫn review-only; không cấp planned GET trong task này.
- Graph drawing `get_graph()` trên phiên bản LangGraph hiện tại có thể ném lỗi
  root-channel update với graph có vòng retry. Test đọc builder topology và
  callback execution thực; không đổi graph/schema/dependency để né lỗi drawing.
- Chưa benchmark workload lớn hoặc supervisor hard-kill/restart cho local mode.
  Artifacts giữ evidence trước/sau node, không hứa exactly-once qua crash.
