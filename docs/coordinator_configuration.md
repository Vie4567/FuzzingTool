# Cấu hình và kiểm chứng Coordinator

Coordinator kiểm tra đầu vào trước khi tạo LLM client hoặc gửi request tới mục tiêu. Với Windows, dùng `run_pipeline_supervised()` từ một file Python có khối `if __name__ == "__main__"`: mỗi phiên chạy có process và thư mục kết quả riêng. Không chạy ví dụ này qua Python stdin vì `multiprocessing` sử dụng cơ chế `spawn`.

## Đầu vào được kiểm tra

- **URL:** HTTP(S), hostname/IP và port hợp lệ; không có userinfo, fragment, dấu cách, ký tự điều khiển hoặc backslash. Coordinator nhận URL cụ thể, không nhận template `FUZZ`. URL được chuẩn hóa trước khi chuyển tới các module.
- **Config:** chỉ nhận các khóa được hỗ trợ, đúng kiểu và khoảng giá trị. `NaN`, vô cực, boolean thay cho số, alias mâu thuẫn và cấu hình không được engine hỗ trợ đều bị từ chối. Native HTTP chạy một worker tuần tự; cấu hình nhiều luồng hoặc bộ lọc chỉ dành cho ffuf phải dùng engine phù hợp.
- **Auth/scope/TLS:** kiểm tra headers, origin được phép, origin được gửi credentials, URL đăng nhập và CA file. Không tắt xác minh TLS. Redirect được ghi nhận, không tự động theo sang URL khác.
- **Wordlist:** nhận `list[str]` tối đa 100.000 phần tử, hoặc `wordlist_file` UTF-8/UTF-8 BOM tối đa 8 MiB; không nhận đồng thời cả hai. Không cho phép phần tử rỗng, ký tự điều khiển, URL khác origin hoặc fragment. URL cùng origin được đổi thành đường dẫn. Loại trùng và giữ thứ tự xuất hiện đầu tiên. File wordlist bỏ dòng trống.

Config của bên gọi được giữ nguyên; Coordinator dùng một bản sao đã chuẩn hóa. Thông báo validation nêu tên trường và yêu cầu, không in giá trị token hoặc mật khẩu. Schema và giới hạn đầy đủ nằm trong [validation.py](../src/coordinator/validation.py).

## Chọn wordlist đưa vào fuzzing

| Cấu hình | Hành vi |
| --- | --- |
| Không có wordlist đầu vào | Mặc định `wordlist_mode="generated"`: sử dụng kết quả Module 3. |
| Có `wordlist` hoặc `wordlist_file` | Mặc định `wordlist_mode="provided"`: fuzz các đường dẫn người dùng cung cấp. |
| `wordlist_mode="merge"` | Đặt wordlist đầu vào trước, nối danh sách sinh ra sau, rồi loại trùng. |
| `max_wordlist_entries` | Giới hạn 1–10.000 đường dẫn được chọn sau khi kiểm tra và loại trùng. Không đặt thì không có giới hạn chọn bổ sung này. |

`provided` và `merge` cần wordlist đầu vào. `generated` không nhận thêm wordlist đầu vào để tránh bỏ qua dữ liệu mà người dùng đã cung cấp. Module sinh wordlist vẫn được thực thi trong pipeline ở cả ba chế độ; `provided` điều khiển danh sách dùng để fuzz, không có nghĩa là tắt LLM.

Các trường `input_wordlist`, `generated_wordlist`, `wordlist` và `wordlist_metadata` cho phép đối chiếu đầu vào, kết quả sinh, danh sách được chọn và số ứng viên sinh bị loại. Khi chọn `provided` hoặc đặt `max_wordlist_entries`, bước fuzzing không tự nối thêm pattern endpoint ngoài danh sách đã chọn.

## Thời gian và ngân sách thực thi

| Khóa | Mặc định | Ý nghĩa |
| --- | ---: | --- |
| `pipeline_timeout_seconds` | 600 | Deadline toàn phiên; khoảng 0,05–7.200 giây. |
| `llm_timeout_seconds` | 30 | Giới hạn một lời gọi LLM; khoảng 0,01–300 giây, được thu nhỏ theo thời gian còn lại của pipeline. |
| `llm_max_tokens` | 4.096 | Giới hạn output của một lời gọi LLM; khoảng 256–32.768. |
| `max_llm_calls` | 50 | Quota cho toàn bộ agent, quyết định Coordinator và reflection; khoảng 1–500. |
| `max_retries` | 2 | Số lần chạy lại tối đa **cho từng module**, không tính lần đầu; khoảng 0–10. |
| `max_iterations` | 20 | Tổng số lượt thực thi module, kể cả chạy lại; khoảng 5–100. |
| `http_rate_limit` | 2 | Tốc độ dispatch HTTP chung, tính bằng request/giây; khoảng 0,01–100. |
| `http_max_requests` | 500 | Ngân sách dispatch HTTP chung; khoảng 1–10.000. |
| `http_timeout_seconds` | 10 | Timeout I/O HTTP chung; khoảng 0,01–120 giây. |
| `http_max_response_bytes` | 2 MiB | Giới hạn body của transport dùng ngân sách runtime; các module vẫn có giới hạn body riêng. |
| `run_all_modules` | `false` | Cho phép chạy bước Parameter khi LLM đề nghị bỏ qua nhưng fuzzing có phản hồi HTTP 200 phù hợp; không vô hiệu hóa điều kiện dừng. |

`run_pipeline_supervised()` kiểm soát deadline từ process cha và dừng worker khi hết hạn. Thời gian trả kết quả có thể dài hơn deadline do dừng process, thu hồi tài nguyên và lưu checkpoint. Trên Windows, supervisor cố dừng cả cây process của worker; nếu `taskkill /T` thất bại thì fallback dừng worker trực tiếp, không bảo đảm đã dừng mọi process con còn sót lại.

`run_pipeline()` trực tiếp sử dụng các điểm kiểm tra deadline trong code; không thể bảo đảm ngắt mọi thao tác đồng bộ bị kẹt. Chọn supervisor nếu cần deadline toàn phiên hoặc nhiều phiên đồng thời. Không gọi song song nhiều `run_pipeline()` trong cùng process vì decision engine và circuit breaker hiện còn trạng thái toàn cục.

Timeout HTTP là giới hạn từng thao tác I/O, không phải cam kết tổng thời gian một response có thể gửi dữ liệu nhỏ giọt. Deadline process là lớp chặn cuối. Timeout LLM được thực thi trong [llm_client.py](../src/coordinator/llm_client.py); SDK đặt `max_retries=0`, không âm thầm thử lại bên dưới telemetry.

Lời gọi LLM dùng deadline theo tổng thời gian và đóng transport sau khi hủy, kể cả khi server trả dữ liệu nhỏ giọt. Với endpoint chính thức `api.deepseek.com`, `llm_max_tokens` được gửi bằng trường `max_tokens` theo [Chat Completions API của DeepSeek](https://api-docs.deepseek.com/api/create-chat-completion/); endpoint OpenAI giữ trường `max_completion_tokens`. Output chạm giới hạn vẫn có thể không đủ JSON hợp lệ; hãy kiểm tra response và lỗi parse trong log.

Các giới hạn chung kết hợp với giới hạn riêng của module; giá trị nhỏ hơn có thể dừng phiên trước. HTTP 401/403/407/429 hoặc `Retry-After` được ghi nhận là điều kiện dừng runtime. `run_all_modules` không cho phép tiếp tục để vượt qua những phản hồi này.

**Giới hạn ffuf:** process ffuf có thể phát sinh request nội bộ mà Coordinator không quan sát được. Khi không đo được chính xác, `total_http_requests` là `null`, `known_http_requests` là mức tối thiểu đã biết. Không coi `http_max_requests` hoặc `http_rate_limit` chung là bảo đảm chặn toàn bộ traffic nội bộ của ffuf. Dùng `python_http` cho kiểm chứng ngân sách request chung; nếu dùng ffuf, cấu hình thêm giới hạn riêng của engine và kiểm tra log của nó.

## Bộ đếm và trạng thái kết quả

- `agent_attempts[agent]`: số lượt thực sự bắt đầu thực thi module; lỗi khi thực thi vẫn tính một lượt.
- `retry_counts[agent]`: số lượt chạy lại đã thực hiện, bằng `agent_attempts[agent] - 1`. Một đề nghị retry bị guard từ chối không tăng bộ đếm.
- `iteration_count`: tổng số lượt thực thi năm module. Validate, quyết định LLM, report và reflection không phải lượt module.
- `telemetry.llm`: số lời gọi đã bắt đầu, thành công, thất bại, đang chạy và số lần bị quota từ chối. HTTP của nhà cung cấp LLM được tách khỏi bộ đếm HTTP mục tiêu.
- `telemetry.http`: số dispatch logic, gồm cả lỗi kết nối; không suy ra từ số dòng wordlist hoặc số endpoint tìm được.

Ví dụ `max_retries=2` cho phép một module bắt đầu tối đa ba lần. Giới hạn `max_iterations`, quota LLM, deadline và điều kiện dừng HTTP vẫn có thể chặn sớm hơn. Giới hạn bước LangGraph được tính theo `max_iterations`, tránh giới hạn mặc định của thư viện chặn sớm một cấu hình retry hợp lệ.

Mỗi phiên có `pipeline_status` và trạng thái riêng từng module. `completed` chỉ được ghi khi không còn lỗi, điều kiện dừng hoặc module đang chờ/chạy/lỗi/một phần. `partial` giữ lại kết quả đã thu thập khi pipeline không hoàn tất sạch. `failed` biểu thị lỗi validation hoặc lỗi làm kết thúc pipeline.

`all_modules_executed=true` và `all_modules_successful=true` không tự chứng minh toàn pipeline đã hoàn thành: reflection vẫn có thể timeout và khiến `pipeline_status="partial"`. Khi đánh giá, kiểm tra cả ba trường cùng `error_log`, `stop_reason` và telemetry.

## Chạy từ PowerShell trên Windows

Lưu ví dụ dưới thành `run_authorized_scan.py` tại thư mục gốc repository. Ví dụ đọc cấu hình DeepSeek từ `.env`/biến môi trường đã có; không đưa API key vào lệnh terminal hoặc source. `TARGET_BEARER_TOKEN` là tùy chọn, chỉ cấu hình trên máy nếu mục tiêu cần xác thực.

```python
import argparse
import os
from pathlib import Path

from dotenv import dotenv_values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="URL thuộc phạm vi được phép kiểm thử")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    env = {**dotenv_values(root / ".env"), **os.environ}
    key = env.get("DEEPSEEK_API_KEY")
    if not key:
        raise SystemExit("Thiếu DEEPSEEK_API_KEY trong môi trường hoặc .env")

    os.environ.update(
        PYTHON_DOTENV_DISABLED="1",
        LANGSMITH_TRACING="false",
        LANGCHAIN_TRACING_V2="false",
    )
    headers = {}
    if env.get("TARGET_BEARER_TOKEN"):
        headers["Authorization"] = "Bearer " + env["TARGET_BEARER_TOKEN"].strip()

    config = {
        "api_key": key,
        "base_url": env.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com",
        "llm_model": env.get("LLM_MODEL") or "deepseek-chat",
        "artifact_root": str(root / "output_samples" / "diagnostics"),
        "pipeline_timeout_seconds": 900,
        "llm_timeout_seconds": 120,
        "max_retries": 1,
        "max_iterations": 10,
        "max_llm_calls": 60,
        "http_max_requests": 250,
        "http_rate_limit": 1,
        "http_timeout_seconds": 5,
        "wordlist": ["/robots.txt", "/sitemap.xml"],
        "wordlist_mode": "provided",
        "run_all_modules": True,
        "fuzzing_options": {
            "engine": "python_http",
            "threads": 1,
            "rate_limit": 1,
            "max_requests": 2,
            "timeout_seconds": 5,
            "headers": headers,
            "auto_calibrate": False,
            "recursion": False,
            "follow_redirects": False,
        },
        "parameter_options": {"enabled": True, "max_requests": 100, "rate_limit": 1},
        "soft404_options": {"enabled": True, "max_requests": 20, "rate_limit": 1},
    }
    from src.coordinator import run_pipeline_supervised
    result = run_pipeline_supervised(args.target, config)
    print("Pipeline:", result.get("pipeline_status"))
    print("Module:", result.get("agent_statuses"))
    print("Kết quả:", result["artifacts"]["result"])


if __name__ == "__main__":
    main()
```

```powershell
.\.venv\Scripts\python.exe -B .\run_authorized_scan.py https://your-authorized-target.example
```

Thay URL ví dụ bằng mục tiêu được phép kiểm thử. Chọn đường dẫn trong `wordlist` phù hợp với mục tiêu; hai tài nguyên công khai trong ví dụ không bảo đảm có đủ dữ liệu để xác minh Parameter hoặc chứng minh toàn bộ module thành công.

## Kết quả, lỗi và bằng chứng chạy thật

`result["artifacts"]["result"]` trỏ tới `result.json` đã che credentials. Thư mục `checkpoints/` lưu trạng thái tại các giai đoạn. Khi dùng supervisor sẽ có checkpoint ở cả process cha và worker; đường dẫn trả về là kết quả công khai của supervisor. Mỗi lần chạy tạo thư mục mới, không ghi đè phiên trước.

Khi timeout, worker thoát bất thường hoặc bị ngắt, supervisor phục hồi checkpoint mới nhất còn đọc được. Nếu request có thể đã được gửi sau checkpoint cuối, tổng HTTP/LLM được ghi `null`; `last_checkpoint_http_requests` và `last_checkpoint_llm_calls` giữ số đo cuối đã lưu. Không coi các giá trị này là tổng cuối cùng. Lỗi ghi file được báo ra, không tiếp tục quét rồi tuyên bố đã lưu thành công.

Để kiểm chứng pipeline bằng HTTP và LLM thật trên lab cục bộ:

```powershell
.\.venv\Scripts\python.exe -B .\scripts\run_coordinator_lab.py
```

Runner khởi tạo HTTP server lab, gọi Coordinator và năm agent thật, sử dụng API DeepSeek theo cấu hình cục bộ. Không dùng model giả hoặc số đo HTTP dựng sẵn. Wordlist đưa vào fuzzing được giới hạn ở hai đường dẫn chuẩn của lab; danh sách do LLM sinh được giữ để đối chiếu. Đây là kiểm chứng luồng tích hợp, không phải benchmark quét toàn bộ wordlist hay bằng chứng quét thành công trên `cab.vn`.

Đối chiếu các file trong thư mục runner in ra:

- `evidence.json`: các điều kiện kiểm chứng và `success` tổng hợp.
- `result.json`: trạng thái, dữ liệu của module, bộ đếm, lỗi và đường dẫn checkpoint.
- `server_requests.json`: log request độc lập từ HTTP server lab để đối chiếu telemetry.
- `llm_responses.jsonl`: response/lỗi thực tế của LLM theo component và lời gọi.

Chỉ kết luận lượt chạy đạt khi `evidence.json` có `success=true`, pipeline `completed`, đủ năm module thực thi thành công, số request khớp server, tham số chuẩn được xác minh và trang fallback được lọc. Một lượt `partial` vẫn là bằng chứng kiểm thử lỗi, nhưng chưa phải bằng chứng hoàn thành sạch toàn pipeline.
