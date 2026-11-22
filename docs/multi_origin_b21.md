# B2.1 — Multi-Origin Recon & Shared Discovery Context

B2.1 mở rộng **thu thập và bàn giao context của Agent 1**, chưa chạy toàn bộ
pipeline multi-origin. Gate `multi_origin_execution_not_enabled_b1` giữ nguyên.
Không có thay đổi Agent 2–5, budget, retry, TLS, proxy hay auth bindings.

## API thu thập có kế hoạch

`TechReconAgent.collect_discovery(target_url, resources, transport=...)` yêu cầu
`OriginScopedTransport` của B1 và một runtime chung đang hoạt động. Không gọi LLM.
Mỗi resource có `url`, `kind` (`html`, `javascript`, `openapi`) và tùy chọn
`document_url` dùng làm base URL cho JavaScript. Method tải tài liệu luôn GET.
Danh sách tối đa 64 tài liệu được kiểm tra toàn bộ scope trước HTTP đầu tiên;
URL trùng cùng khai báo chỉ được tải một lần, khai báo mâu thuẫn bị từ chối.

Parser tái sử dụng DOM/form extraction mà crawler hiện có đang dùng, CH-3 và
CH-6 OpenAPI JSON. CH-6 đọc response đã thu thập, không gửi GET thứ hai. Luồng
bảy kênh/crawler cũ vẫn tồn tại; chế độ mới không tự crawl thêm links, tải assets,
probe API root hay thực thi các operation lấy từ form/schema/JS. Caller phải đưa
mọi tài liệu cần tải vào plan và policy B1. References không phải request queue.

Không tạo runtime theo origin. Mỗi request vẫn qua B1 scope/credentials/TLS và
bộ đếm/rate limit hiện có. HTTP 401/403/429, budget và deadline được giữ nguyên.
Lỗi một tài liệu không được retry; dữ liệu các tài liệu đã nhận được vẫn được lưu.

## Trích xuất và giới hạn phân tích

- HTML: anchor/link/script/media, data-api và các URL attributes hiện có; form
  action, method và tên input; query parameters. Tôn trọng HTML base href.
- JavaScript: fetch, axios verb calls và axios/request với object config literal;
  URL literal, relative URL, REST/RPC và prefix /api, /v1…
- Method được khai báo rõ ràng mới được ghi nhận. `fetch(url)` chưa khai báo
  method giữ null; form giữ method theo parser HTML hiện có, gồm default GET.
- Không constant-fold biến, nối chuỗi, template interpolation hay điều kiện.
  Dynamic references có `url=null`, `origin=null`, `classification=inferred`,
  `confidence=null`; không lấy fragment rồi dựng thành endpoint hoàn chỉnh.
- Axios relative URL có baseURL chưa resolve được giữ unresolved. Không suy diễn
  endpoint của một custom client từ chuỗi còn thiếu ngữ cảnh.
- URL khác origin không mặc nhiên là API. Phân loại gồm frontend_route,
  static_asset, api_reference, unknown. Prefix là heuristic có ghi lý do.
- Không thực thi JS, không browser/Network/HAR capture, không tự tải source map.
  Không parse source map, YAML, GraphQL hoặc runtime-generated routes. TS/TSX
  chưa có kiểm chứng riêng; không tuyên bố hỗ trợ phân tích đầy đủ ngôn ngữ này.
- Parser JS là bộ đọc literal bảo thủ, không phải AST/semantic engine hoàn chỉnh.
  Có giới hạn 5 MB và 250.000 tokens. Regex knowledge cũ không còn được dùng để
  cắt fragment từ biểu thức động thành URL hoàn chỉnh.
- Inline JavaScript trong HTML không thuộc document collector hiện tại; cần
  bổ sung có bằng chứng riêng nếu muốn hỗ trợ, không suy đoán từ kết quả hiện có.

## Contract trước / sau

Giữ `origin_contract_version=1`, `recon_profile.schema_version=1` và trường legacy.
Các trường mới đều bổ sung; B1 checkpoints thiếu provenance/resource_type vẫn
merge được. Primary tech_stack vẫn ở legacy recon_profile; không sao chép
frontend stack thành backend stack cho API origin. `profile` chưa đủ bằng chứng
ở từng origin giữ null.

Mỗi endpoint observation nay có:

| Trường | Ý nghĩa |
|---|---|
| url, origin, method | URL đầy đủ/query và method nếu biết. |
| source, source_type, source_url | Nguồn và tài liệu cung cấp bằng chứng. |
| source_sha256 | SHA-256 của nội dung nguồn sau decode và encode UTF-8; không phải digest tùy ý của endpoint. |
| evidence_location | HTML tag/attribute/line/column; JS offset/end_offset/line/column; OpenAPI JSON pointer. |
| evidence_refs | ID ổn định theo source URL + digest + location. |
| resource_type | frontend_route/static_asset/api_reference/unknown. |
| classification | observed/candidate/inferred của thông tin, không phải trạng thái HTTP endpoint. |
| confidence, confidence_basis | Mức hỗ trợ cho phân loại từ quy tắc trích xuất; không phải xác suất endpoint tồn tại. Unknown giữ null. |
| attempted, verification_status | Khai báo không chứng minh đã thử HTTP; giữ null / not_verified. |
| provenance | Tất cả nguồn của cùng URL + method, không ghi đè nguồn trước. |

Hai origin cùng `/users` có ID riêng. Cùng URL nhưng GET/POST hoặc method chưa
biết là các request variants riêng, không đoán method để gộp. Cùng URL/method
xuất hiện nhiều nguồn thì gộp một endpoint, hợp nhất provenance/evidence_refs.
Resource kinds mâu thuẫn thì unknown/null, giữ cả hai bằng chứng.

`merge_discovery_context(state, result['discovery_context'])` là hàm bàn giao
thuần dữ liệu dùng bởi Coordinator khi state có contract B1; không gửi HTTP,
không đổi approval. Cấu hình pipeline vẫn bị gate trước khi chạy multi-origin.

`origin_contexts[origin]` chứa:

- `endpoints`: endpoint variants đã chuẩn hóa, có provenance.
- `context.parameters`: tên/location/method/URL/source, không mất query/schema/form context.
- `context.forms`: form declarations, không phải lệnh submit.
- `context.source_documents`: metadata HTTP tài liệu thực tải và collection_status.
- `context.unresolved_references`: group theo **source origin**, endpoint URL/origin
  vẫn null; group không khẳng định đích thuộc source origin.
- `status`, `agent_statuses.tech_recon`: kết quả thu thập tài liệu ở origin đó;
  không khẳng định endpoint đã được kiểm chứng hoặc cả pipeline thành công.

`discovery_summary` ghi unique endpoint variants theo loại, unresolved count và
rejected count của lần merge. Rejections do credentials ở collector được giữ
riêng. URL chứa credentials được loại trước redaction để không biến URL đã che
thành một candidate mới. Các contexts không nhận headers/token/cookie.

## Kiểm chứng và cách tái hiện localhost

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:B21_EVIDENCE_DIR = Join-Path $PWD 'output_samples/diagnostics/b21_local_tests'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_discovery*.py' -v
```

Lab dùng ba server 127.0.0.1/port động: frontend cung cấp HTML/JS, gateway cung
cấp OpenAPI JSON, origin thứ ba chưa được approved. Fake bearer/cookie chỉ gắn
frontend. Mỗi case có server access logs, nội dung thực đã được server phục vụ,
HTTP metadata của Agent, SharedState/checkpoint/result và cấu hình đã che secrets.

Ca thành công gửi 4 GET (3 frontend, 1 gateway schema). Từ 19 observations tạo
16 endpoint variants: 3 frontend routes, 4 assets, 8 API references, 1 unknown URL;
thêm 1 dynamic reference có URL/origin null. `/users` GET có 2 nguồn (JS/OpenAPI),
`/rpc/save` POST có 3 nguồn (form/JS/OpenAPI), không endpoint nào bị tự thực thi.
Ba parameter declarations: q (query literal), title (form body), page (OpenAPI).

Artifacts nghiệm thu tại
`output_samples/diagnostics/multi_origin_b21_20261122T073851Z/`.
`verify_discovery_evidence.py` chỉ dùng stdlib để đối chiếu metadata/log/body
nguồn/provenance/state độc lập, không gọi lại HTTP hoặc parser của dự án.
Tests có mock được ghi là unit; lab dùng HTTP thật là integration. Internet và
full multi-origin pipeline vẫn not_verified.

## Handoff cho B2.2 — đề xuất, chưa triển khai

1. Đọc `origin_contexts` theo exact origin; phân biệt discovery với approval.
   Sinh wordlist không được tự thêm origin vào policy.
2. Ưu tiên literal API references có evidence và giữ origin, URL/query, method,
   endpoint_id, evidence_refs trong candidate output. Context primary tech_stack
   chỉ áp dụng primary origin; origin khác Unknown khi chưa có bằng chứng.
3. Dùng parameter names/forms/schema declarations làm ngữ cảnh; POST/body là
   context, không đổi thành GET fuzzing hoặc lệnh submit. Unknown method không
   tự promote thành request có quyền thực thi.
4. Frontend routes và static assets là nguồn ngữ cảnh riêng; không nối tên API
   vào frontend hoặc sinh wordlist generic cho mọi origin giống nhau.
5. Unresolved references chỉ phục vụ nhận biết thiếu dữ liệu. Không để LLM điền
   base URL/host cho biến, không promote inferred thành observed/verified.
6. Giữ bounded prompt summary, provenance refs và đánh dấu candidates do LLM
   sinh; không đưa body/raw JS/credentials vào prompt. Không cần thêm LLM call để
   kiểm tra số liệu. Chưa cấu hình hay gọi DeepSeek trong B2.1.
7. Test B2.2 bằng mock LLM và context từ lab thật đã lưu; đối chiếu candidates
   theo origin/method, không request thêm endpoint. Dispatch/budget thuộc B3.
