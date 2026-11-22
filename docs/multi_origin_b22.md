# B2.2 — Multi-Origin Context-Aware Wordlist Generation & Selection

B2.2 bổ sung sinh/chọn candidates **offline** cho Agent 2 từ contract B2.1.
Chưa bật scheduling multi-origin, chưa dispatch candidates và không thay gate
`multi_origin_execution_not_enabled_b1`. `WordlistGenAgent.execute()` một target
và các assembler cũ giữ nguyên. Entry point mới chưa được nối vào full pipeline;
việc nối và kiểm tra lại trước dispatch thuộc B3.

## API và dữ liệu bàn giao

```python
result = agent.generate_from_discovery(
    shared_state,
    max_wordlist_entries=6,       # tổng số selected của tất cả origin
    max_generated_per_origin=32, # giới hạn generation CPU; không phải HTTP budget
    allow_generic=False,        # mặc định không giữ pattern thiếu căn cứ theo origin
    artifact_root="output_samples/diagnostics/b22_local",
)
```

`shared_state` phải có contract B1 (`origin_contract_version=1`), target_url,
approved_origins, origin_policies, origin_contexts và discovery_summary từ B2.1.
Policy thiếu path/method vẫn fail-closed; discovered không biến thành approved.

Agent đọc trực tiếp:

- `origin_contexts[origin].endpoints`: URL/query/method/ID/resource type và provenance.
- `context.parameters`, `forms`: metadata hỗ trợ lựa chọn đúng URL và method.
- `context.source_documents`: metadata tài liệu đã thu thập, không response body.
- `context.unresolved_references`: giữ null destination, không dựng host/baseURL.
- `discovery_summary`: chỉ projection counts/type hợp lệ; không dùng làm policy.

Kết quả được ghi vào **cùng contract hiện có**:

```text
origin_contexts[origin].context.wordlist
  candidates[]
  selected_ids[]
  counts
  tech_stack
  input_context
wordlist_metadata.multi_origin
```

`result.origin_contexts` chỉ là projection phần wordlist đã tạo, không phải bản
sao đầy đủ discovery. Hàm bàn giao phần này vào SharedState sau khi lưu artifact
thành công; không ghi đè `endpoints`, approval, discovery hoặc `wordlist` legacy.
Không dùng result projection để thay toàn bộ SharedState.

## Identity và trạng thái

Endpoint ID tiếp tục theo hợp đồng B1: hash của URL đầy đủ + method. Cùng path
trên hai origin là hai tài nguyên; GET/POST/unknown method là variants riêng.
Trùng URL/method được gộp nguồn, không mất provenance/query. Credentials hoặc
URLs chứa dữ liệu nhạy cảm bị loại với rejection count, không đổi thành URL
`[REDACTED]`. Thông tin policy/execution do nội dung nguồn tự khai không được tin.

| Field | Nghĩa trong B2.2 |
|---|---|
| observed | Có provenance của declaration với source URL, hash, vị trí và evidence refs. Không khẳng định endpoint tồn tại. |
| generated | URL mới do EndpointAssembler sinh; classification inferred. |
| selected | Được chọn vào top-K toàn phiên; không phải đã dispatch. |
| dispatch_eligible | Đáp ứng policy exact origin/path/query/method/read_only tại lần đánh giá. Không chứng minh runtime/credentials sẵn sàng. |
| attempted | null: Agent 2 không thử HTTP tới candidates. |
| verified | null; verification_status=not_verified. Chỉ bước kiểm chứng thực tế được cập nhật. |
| classification | Giữ observed/candidate/inferred từ nguồn cho declaration; inferred cho pattern. |
| derivation | Generator và IDs/evidence refs hỗ trợ pattern, tách khỏi direct provenance. |

Reference B1 cũ thiếu bằng chứng vẫn nằm trong catalog nhưng không bị gán
observed/generated hoặc được chọn; `unattributed_count` ghi riêng.
`catalog_count = observed_count + generated_count + unattributed_count`.

Generated paths chưa có bằng chứng method nên luôn method=null, chưa eligible
và chưa selected trong B2.2. Ngay cả khi policy cho phép GET ở path đó cũng
**không tự suy ra method**. POST/PUT/PATCH/DELETE được giữ nguyên trong catalog,
không dùng làm seed GET hoặc chuyển thành executable wordlist.

## Generation và selection

Generation tái sử dụng `EndpointAssembler.assemble(..., llm=None)` và heuristic
profile builder hiện có. Chỉ các literal API references có bằng chứng, method
GET/HEAD, path phù hợp mới làm seed. Assets, dynamic references và mutating
operations không đi vào semantic API slots. Tech-stack chỉ lấy từ `profile`
đúng origin; thiếu giữ Unknown, không lấy frontend stack áp sang gateway.

Một pattern được gọi là grounded khi có quan hệ prefix/semantic path segment
với API seed cùng origin; `derivation` giữ IDs nguồn. Đây là heuristic về cách
đặt tên, không phải bằng chứng URL mới tồn tại. Generic pattern chỉ được giữ khi
operator bật `allow_generic`; vẫn có method=null và không dùng quota selected.

Priority có thể giải thích:

1. Declaration có URL/method rõ ràng, bằng chứng JavaScript/OpenAPI.
2. Declaration từ context khác; form, parameter và số nguồn độc lập hỗ trợ xếp hạng.
3. Pattern có quan hệ tên với seed của origin đó.
4. Generic pattern được cho phép.

Trong cùng tier: ưu tiên API reference, frontend route, unknown rồi asset;
sau đó số source URL độc lập, parameter support, form support; cuối cùng ID ổn
định để phá hòa. Không cắt catalog theo alphabet trước khi xếp hạng.

Selector chỉ chọn candidates eligible và có nguồn xác định, với một K chung.
Scope denied, method unknown, mutating method, unapproved origin và thiếu
provenance được giữ cùng lý do loại. Tier 3/4 hiện chưa đủ điều kiện method,
được lưu để review thay vì tự cấp GET để lấp đầy K. Không hứa selected luôn bằng K.

`counts` riêng mỗi origin và `wordlist_metadata.multi_origin` ghi observed,
generated, unattributed, catalog, dispatch_eligible và selected. `http_dispatches`
và `llm_invocations` của chức năng này bằng 0; không cộng generated vào telemetry
HTTP. Approval/credential readiness vẫn cần được B3 đánh giá lại.

## Artifact và bảo mật

Tái sử dụng RunArtifacts: mỗi lần gọi có thư mục UUID riêng, result.json và
checkpoint. Mọi candidate có origin identity; cùng `/users` và những lần chạy
lại không ghi đè nhau. Không đổi tên file theo path endpoint.

Chế độ này không gọi LLM, không tạo prompt và không gửi raw HTML/JS/body.
Tests truyền mock LLM và xác nhận 0 invocation. B2.1 context chỉ là dữ liệu,
không được điều khiển policy, method hay hướng dẫn thực thi. Các field body,
headers, credentials hoặc instructions ngoài schema không được sao chép vào
candidate artifact. Giá trị credentials đã biết trong input cũng được kiểm tra
khi bị phản chiếu vào URL/provenance. Legacy LLM mode không thay đổi bởi B2.2.

## Kiểm chứng localhost và so sánh

Tests dùng fixture HTTP B2.1 với ba server độc lập: frontend, gateway và origin
chưa approved. Agent 1 tải 4 tài liệu thực; Agent 2 tiêu thụ state thực từ collector,
không nhận danh sách endpoint hardcode thay thế. Lab phê duyệt thêm một số path
GET để **đánh giá eligibility**, nhưng không dispatch tới chúng.

So sánh K=6 và K=3 là **selection ablation**: cùng catalog, nguồn, scope và K;
baseline dùng alphabet-then-truncate như selection legacy, context-aware dùng
priority mới. Không chạy lại toàn bộ legacy LLM generation và không gọi HTTP để
so sánh discovery. Mọi metric được tính lại từ cùng artifact, gồm provenance giữ
lại, API refs giữ lại, duplicates, sai origin, selected/eligible và LLM cost.
Chỉ được kết luận về lựa chọn top-K trong lab này, không kết luận về endpoint
tồn tại hoặc tỷ lệ phát hiện thực tế.

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:B22_EVIDENCE_DIR = Join-Path $PWD 'output_samples/diagnostics/b22_reproduce'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin_wordlist*.py' -v
.\.venv\Scripts\python.exe -B scripts/verify_origin_wordlist_evidence.py $env:B22_EVIDENCE_DIR
```

Verifier chỉ dùng stdlib: đối chiếu access logs, source body/hash/position,
Agent 1 observations, SharedState, candidate origin/method/provenance, lựa chọn,
counts, result và checkpoint. Không gọi parser của dự án, HTTP hoặc LLM.
Artifacts nghiệm thu: `output_samples/diagnostics/multi_origin_b22_20261122T123520Z/`.

## Handoff B3 — chưa triển khai

B3 đọc candidates/selected_ids theo exact origin từ context.wordlist, giữ ID,
URL/query, method và provenance. Phải kiểm tra lại scope và credential binding,
runtime budget/deadline/rate/TLS/redirect/điều kiện dừng trước mỗi dispatch.
Không dùng dispatch_eligible snapshot để bỏ qua guard hoặc mở gate.

Chỉ dispatcher được cập nhật attempted; HTTP response chưa đồng nghĩa verified.
Parameters/Soft404 phải kiểm chứng đúng origin. Method unknown và unresolved
destinations chưa thể dispatch; cần thêm bằng chứng hoặc cấu hình riêng được
thiết kế/kiểm thử, không tự mặc định GET. Không flatten các origins vào wordlist
legacy hoặc dùng profile của origin A cho B.

Giới hạn: chưa có LLM enrichment đa origin, chưa đánh giá Internet, chưa xác minh
HTTP candidates hoặc full LangGraph multi-origin. Primary stack trong trường
legacy không tự chuyển vào origin profile nếu chưa có liên kết có bằng chứng.
