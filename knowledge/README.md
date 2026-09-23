# Knowledge Base — Sentinel Pentest System

Thư mục `knowledge/` chứa toàn bộ dữ liệu tĩnh mà các Agent nạp khi khởi động. Tách khỏi code để dễ cập nhật mà không cần sửa logic.

## Cấu trúc

| File | Dùng bởi | Mô tả |
|------|----------|-------|
| [`framework_paths.json`](./framework_paths.json) | CH-5 Probe + Wordlist Layer-1 | Đường dẫn mặc định của 20+ framework & CMS |
| [`sensitive_files.json`](./sensitive_files.json) | Wordlist Layer-4.5 | File nhạy cảm, backup, log, git leak, secrets |
| [`waf_signatures.json`](./waf_signatures.json) | CH-1 WAF Detection | Chữ ký nhận dạng WAF/CDN từ headers, cookies, body |
| [`js_extraction_patterns.json`](./js_extraction_patterns.json) | CH-3 JS Bundle Analysis | Regex trích xuất endpoint từ JavaScript |
| [`tech_fingerprints.json`](./tech_fingerprints.json) | CH-1 + CH-2 | Nhận dạng tech stack từ headers, cookies, DOM |
| [`spider_config.json`](./spider_config.json) | CH-4 Crawl Spider | Cấu hình adaptive depth, limits, exclusions |

## Nguyên tắc sử dụng

```python
import json
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"

def load_knowledge(filename: str) -> dict:
    """Nạp file knowledge tại runtime, không hardcode trong code."""
    path = KNOWLEDGE_DIR / filename
    with open(path, encoding="utf-8") as f:
        return json.load(f)

# Ví dụ sử dụng trong Tech Recon Agent
framework_paths = load_knowledge("framework_paths.json")
waf_sigs        = load_knowledge("waf_signatures.json")
js_patterns     = load_knowledge("js_extraction_patterns.json")
spider_cfg      = load_knowledge("spider_config.json")
sensitive_files = load_knowledge("sensitive_files.json")
tech_prints     = load_knowledge("tech_fingerprints.json")
```

## Adaptive Depth — Giải thích

`max_depth` **không hardcode** bằng 3. Spider đọc `spider_config.json` và chọn depth theo loại target:

| Loại trang | Depth | Lý do |
|-----------|-------|-------|
| Phát hiện OpenAPI/GraphQL schema | 1 | Schema đã đủ endpoint |
| SPA (React/Vue/Angular) | 2 | Link HTML ít, CH-3 JS mới là nguồn chính |
| SSR (WordPress/Django/Laravel) | 4 | Nhiều link HTML, crawl sâu hơn |
| Không xác định | 3 | Mặc định an toàn |
| WAF block mạnh (>30% 403/429) | 1 | Giảm footprint để tránh bị ban |

## Cập nhật Knowledge

Khi phát hiện framework mới hoặc WAF mới:
1. Thêm entry vào file JSON tương ứng
2. **Không cần sửa code** của bất kỳ Agent nào
3. Agent tự nạp lại khi khởi động
