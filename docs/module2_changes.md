# Module 2 - Nhận diện ngữ cảnh và tech-stack

## 1. Trạng thái

Module 2 đã hoàn tất trong phạm vi Agent 1 của Sentinel Pentest. `TechReconAgent`
không còn là stub: agent thực hiện reconnaissance qua 7 kênh, tổng hợp target
profile, trả output tương thích `SharedState`, sau đó ghi dữ liệu nền vào Neo4j
thông qua MCP JSON-RPC 2.0 trên stdio.

Neo4j persistence là bước cộng thêm và không nằm trên critical path. Khi MCP hoặc
Neo4j tạm thời không khả dụng, agent ghi warning, đặt trạng thái persistence là
`failed`, nhưng vẫn trả kết quả recon cho Coordinator.

## 2. Kiến trúc đã triển khai

### 2.1. Recon engine 7 kênh

- CH-1: fingerprint HTTP header/cookie và nhận diện WAF từ knowledge JSON.
- CH-2: phân tích DOM, link, form, method và parameter bằng BeautifulSoup.
- CH-3: phân tích JavaScript inline/external; chỉ tải tài nguyên cùng origin.
- CH-4: spider đệ quy với adaptive depth, page limit, exclusion và priority path
  lấy từ `knowledge/spider_config.json`.
- CH-5: probe `robots.txt`, sitemap và security/API files.
- CH-6: phát hiện OpenAPI JSON/YAML và thực hiện GraphQL introspection thật;
  schema thu được được dùng để giảm crawl depth và trích endpoint/parameter.
- CH-7: error probe chỉ chạy khi `aggressive_probe=True`.

Các request dùng chung semaphore và bộ điều tiết delay/jitter toàn cục. Các kênh
được chạy bất đồng bộ bằng `asyncio.gather(..., return_exceptions=True)`; lỗi một
kênh không làm hỏng toàn bộ Agent. CH-4 chờ kết quả cần thiết từ CH-1/CH-2/CH-6
để chọn depth nhưng vẫn được cô lập lỗi như các kênh khác.

Aggregator chuẩn hóa và deduplicate path, giữ method/status của endpoint, phân
biệt parameter theo `(name, location)`, đồng thời tạo target profile nội bộ gồm
tech fingerprint, dev habits, API schema, discovered paths/params và recon stats.
Output trả về Coordinator giữ nguyên 5 field:

```python
{
    "tech_stack": dict,
    "discovered_paths": list,
    "js_endpoints": list,
    "waf_detected": bool,
    "waf_type": str | None,
}
```

### 2.2. Neo4j và MCP

`src/mcp_servers/neo4j_server.py` là MCP server thật, giao tiếp qua stdio và expose:

- Tool `create_node`
- Tool `create_relationship`
- Tool `run_cypher`
- Tool `get_subgraph`
- Resource `sentinel://graph/schema`

`src/clients/neo4j_mcp_client.py` quản lý một MCP session theo async context
manager. Client được inject vào Agent 1; Agent không gọi Neo4j driver trực tiếp
và không dùng global singleton.

Mọi node/relationship write đều dùng `MERGE`. Identity hiện hành:

- `Target`: URL chuẩn hóa.
- `Technology`: tên technology.
- `Endpoint`: SHA-256 của target URL, HTTP method và path phân biệt hoa/thường.
- `Parameter`: SHA-256 của endpoint UID, name và location.
- `Finding`: SHA-256 của endpoint UID, type và description.

Các identity theo scope ngăn `/login` của hai target bị trộn và ngăn parameter
trùng lặp giữa các lần quét. Script `scripts/init_neo4j.py` tạo 5 uniqueness
constraints cùng 2 indexes bằng câu lệnh idempotent.

### 2.3. LangGraph integration

`run_tech_recon` vẫn là node Agent 1 trong Coordinator LangGraph. Node truyền
`LLMCallLimiter` dùng chung và MCP dependency vào `TechReconAgent`, sau đó ánh xạ
kết quả về `SharedState`, bao gồm bản sửa propagation cho `waf_type`.

Routing, field của `SharedState`, `DecisionEngine` và `KnowledgeStore` không bị
thay đổi. MCP persistence được đặt bên trong Agent 1 theo kiến trúc yêu cầu, vì
vậy không cần thêm Graph Writer thành một LangGraph node riêng.

## 3. File thay đổi

### Source và knowledge

- `src/agents/tech_recon.py`: implementation 7-channel Agent 1 và MCP persistence.
- `src/coordinator/graph.py`: inject limiter/MCP và ghi đầy đủ output vào state.
- `src/graph_schema.py`: schema, normalization và scoped identity dùng chung.
- `src/clients/neo4j_mcp_client.py`: MCP stdio client wrapper.
- `src/mcp_servers/neo4j_server.py`: 4 MCP tools và graph schema resource.
- `knowledge/spider_config.json`: adaptive rules và request limits.
- `knowledge/tech_fingerprints.json`: metadata công nghệ và error signatures.

### Hạ tầng

- `docker-compose.yml`: Neo4j 5 Community tại cổng 7474/7687.
- `scripts/init_neo4j.py`: khởi tạo và xác minh constraints/indexes.
- `.env.example`: mẫu cấu hình Neo4j và LLM provider.
- `requirements.txt`: MCP, Neo4j, HTTP/parser và test dependencies.
- `pytest.ini`, `.gitignore`: cấu hình test và file local.

### Tests

- `tests/unit/test_tech_recon.py`: unit test từng kênh recon.
- `tests/unit/test_module2_regressions.py`: scope, concurrency, GraphQL, adaptive
  crawl, normalization và failure isolation regressions.
- `tests/unit/test_tech_recon_mcp.py`: mapping/lifecycle/best-effort persistence.
- `tests/unit/test_mcp_client.py`: MCP client protocol wrapper.
- `tests/unit/test_neo4j_server.py`: schema và validation helpers.
- `tests/unit/test_neo4j_handlers.py`: tool handlers với stateful mock driver.
- `tests/unit/test_coordinator_tech_recon.py`: Coordinator wiring và `waf_type`.
- `tests/integration/test_neo4j_integration.py`: Neo4j thật qua MCP stdio, không
  gọi Neo4j driver trực tiếp từ test.

## 4. Kết quả kiểm chứng

- Neo4j 5 Community đã chạy `healthy` bằng Docker Compose tại 7474/7687.
- `scripts/init_neo4j.py` đã tạo và xác minh 5 uniqueness constraints, 2 indexes;
  chạy lặp không tạo schema trùng.
- Integration test đã đi qua toàn bộ đường
  `TechReconAgent -> MCP Client -> stdio -> MCP Server -> Neo4j -> get_subgraph`.
- Smoke run kiểm tra được 1 Target, 13 Endpoint, 4 Parameter, tổng 21 node và
  20 relationship; chạy lặp giữ nguyên số lượng.
- Kết quả test gần nhất: `200 passed` (198 unit + 2 live integration).

Lệnh xác minh:

```powershell
docker compose up -d neo4j
.venv\Scripts\python.exe scripts\init_neo4j.py
.venv\Scripts\python.exe -m pytest tests -q -o addopts= -p no:cacheprovider
```

## 5. Ranh giới với module khác

- Agent 2 đọc context từ Neo4j thuộc bước triển khai Module 3.
- Agent 1 không tạo `Finding` vì recon không kết luận lỗ hổng; schema và MCP tool
  đã hỗ trợ label này cho các module quét/giám định về sau.
- ScanTool MCP Server thuộc Module 4/5.
- GraphQL đã introspect query/mutation và arguments. Việc flatten toàn bộ nested
  input, union/interface chuyên sâu là khả năng mở rộng, không ảnh hưởng output
  contract hoặc tiêu chí hoàn thành Module 2.
