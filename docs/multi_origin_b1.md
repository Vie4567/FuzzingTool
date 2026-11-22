# B1 — Multi-Origin Contract & Scope

## Phạm vi đã triển khai

B1 thêm contract công khai, scope GET/HEAD chính xác và credential context riêng
trong bộ nhớ. Adapter HTTP dùng lại `ScopedReconTransport`, cùng runtime, bộ đếm,
rate limit, TLS verification và chính sách không follow redirect hiện có.

**B1 chưa chạy pipeline năm Agent trên nhiều origin.** Khi nhận cấu hình
`multi_origin`, Coordinator lưu contract rồi dừng trước Agent/LLM với
`multi_origin_execution_not_enabled_b1`. Đây là fail-closed có chủ đích cho tới B3.
`validate_pipeline_input` chỉ xác nhận cấu hình hợp lệ, không chứng nhận khả năng
thực thi. Runner CLI chưa có tùy chọn bật điều phối multi-origin.

Cấu hình cũ không có `multi_origin` đi qua luồng cũ. Không chuyển đổi ngầm
`allowed_origins`/`auth_origins`, không tái sử dụng token, không sửa các Agent,
retry/deadline hay bộ đếm budget. Cơ chế auth legacy trong config nội bộ hiện có
không được di chuyển sang kho credentials mới trong B1.

## Contract

`SharedState` bổ sung các trường tùy chọn:

| Trường | Ý nghĩa |
|---|---|
| `origin_contract_version` | Phiên bản contract mới, hiện là 1. |
| `approved_origins` | Origin được operator khai báo; discovery không sửa danh sách này. |
| `discovered_origins` | Origin và nguồn phát hiện, không phải quyền truy cập. |
| `origin_policies` | Rules công khai và ID credential profile; không chứa secret values. |
| `origin_contexts` | Mapping origin → profile, context, status, agent_statuses, endpoints. |
| `origin_execution_mode` | `not_enabled_b1`; helper legacy có nhãn `legacy_untracked`. |

Các trường cũ như `target_url`, `tech_stack`, `recon_profile`, `wordlist` và
`raw_results` giữ nguyên. B1 không tự đồng bộ kết quả Agent vào context mới;
profile/context/status chưa quan sát là null, không ghi success giả.

`endpoint_observation()` giữ URL đầy đủ và query, canonical origin, HTTP method
nếu biết, source/source_url, classification, confidence, evidence_refs và ID theo
URL + method. `method`, `confidence`, `attempted` chưa biết là null. Nhãn
`observed` có thể chỉ là khai báo trong schema; `verification_status` vẫn là
`not_verified`. Hai origin cùng `/shared` có ID khác nhau.

`add_observation()` cập nhật discovery và context; không thay đổi approval/rules.
Các URL userinfo, fragment, malformed hoặc chứa dấu hiệu credential bị từ chối;
không làm mất query bằng cách âm thầm chuyển thành đường dẫn khác. Không đưa dữ
liệu cá nhân hoặc secret vào các trường công khai/ID/evidence reference.

## Policy công khai (ví dụ chỉ dành cho localhost)

```json
{
  "multi_origin": {
    "approved_origins": ["http://127.0.0.1:8000", "http://127.0.0.1:8001"],
    "origin_policies": {
      "http://127.0.0.1:8000": {
        "credential_profile": "frontend",
        "rules": [{"path": "/shared", "query": "", "methods": ["GET"], "operation": "read_only"}]
      },
      "http://127.0.0.1:8001": {
        "rules": [{"path": "/shared", "query": "page=1", "methods": ["GET"], "operation": "read_only"}]
      }
    }
  }
}
```

Đây không phải cấu hình đã cấp phép cho bất kỳ website Internet nào.

- So khớp chính xác scheme/hostname/effective port; default port được chuẩn hóa.
  `localhost` không đồng nghĩa `127.0.0.1`, subdomain không được tự mở scope.
- Rules chỉ hỗ trợ GET/HEAD và `operation=read_only` do operator xác nhận.
  Không có rule tương ứng thì deny. POST/PUT/PATCH/DELETE/OPTIONS/TRACE bị chặn.
- Path và query so khớp chính xác; không wildcard, prefix hay tự thêm query.
  B1 từ chối percent-encoded/ambiguous paths, dot segments, backslash và semicolon.
- GET không tự chứng minh thao tác chỉ đọc; operator phải xác nhận semantics.
- Không follow redirect ngay cả khi đích cũng đã được approved.

## Credentials

`OriginScopePolicy(public_config)` và `OriginCredentialContext(policy, profiles)`
là API riêng; profiles là mapping **exact origin** → `{profile_id, headers}`.
Profile ID phải trùng binding trong policy. Headers chỉ nhận Authorization,
Cookie hoặc X-API-Key; không cho header đổi method/routing. Headers được copy;
không dùng chung CookieJar. Không có binding thì origin không nhận credentials;
có binding nhưng thiếu profile thì fail-closed trước dispatch.

Chỉ truyền credential context trực tiếp cho `OriginScopedTransport` trong bộ nhớ.
Không đưa context hay header values vào config, SharedState, prompt, checkpoint
hoặc JSON. Public contract chỉ lưu profile ID. Không có cơ chế fallback sang
credentials của origin khác. Adapter không nhận token qua CLI, không gọi login
hoặc refresh token.

## Kiểm thử và bằng chứng

```powershell
$env:PYTHON_DOTENV_DISABLED = '1'
$env:LANGSMITH_TRACING = 'false'
$env:B1_EVIDENCE_DIR = Join-Path $PWD 'output_samples/diagnostics/b1_local_tests'
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_origin*.py' -v
```

Test tạo ba HTTP server trên `127.0.0.1` với port động: frontend, gateway và origin
chưa duyệt. Token/cookie đều là fixture giả. `*_access.json` do server ghi độc lập;
chỉ lưu credential identity/presence, không giá trị. `evidence.json` giữ cấu hình,
UTC, diagnostic ID, HTTP metadata, telemetry/runtime và đường dẫn SharedState
checkpoint/result đã che dữ liệu. So sánh số kết nối, access log và dispatch thật.

Các ca phủ discovery không cấp scope, credential isolation, hai origin cùng path,
scheme/hostname/port/path/query/method, redirect, body/cookie-jar bypass, HTTP 401
và budget chung. Unit tests kiểm tra Coordinator fail-closed không gọi Agent/LLM.

Log và kết quả lượt triển khai:
`output_samples/diagnostics/multi_origin_b1_20261122T071446Z/`.
Baseline, targeted tests, full regression và các lượt lỗi được giữ riêng.
Kết luận local chỉ áp dụng contract/transport B1, không phải full pipeline.

## Phần chưa triển khai

- B2: thu thập context và sinh wordlist theo origin; nhập Network/HAR.
- B3: nối policy vào mọi dispatch của Agent/engine, điều phối nhiều origin,
  per-origin budget và trạng thái thực thi, bảo toàn budget chung.
- Không triển khai per-origin verification orchestration, Report/Reflection mới,
  Neo4j/MCP hoặc nghiệm thu Internet trong B1.
- Kiểm chứng Internet: `not_verified`. B1 không chứng minh bearer thật được chấp
  nhận, cũng không chứng minh endpoint hợp lệ chỉ vì HTTP 200.
