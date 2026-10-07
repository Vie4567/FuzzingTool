"""
Test Runner & Mock Data Generator cho từng Module / Agent.

Cho phép chạy từng module đơn lẻ hoặc nối tầng (pipeline step-by-step).
Mỗi module khi chạy sẽ tự động đọc dữ liệu đầu vào từ file JSON của module trước (hoặc dùng dữ liệu mới),
sau đó ghi kết quả đầu ra thành file JSON riêng trong thư mục `output_samples/`.
"""

import json
import os
from pathlib import Path

from src.agents.tech_recon import TechReconAgent
from src.agents.wordlist_gen import WordlistGenAgent
from src.agents.fuzzer import FuzzingAgent
from src.agents.param_discovery import ParamDiscoveryAgent
from src.agents.soft404_filter import Soft404FilterAgent

OUTPUT_DIR = Path("output_samples")
OUTPUT_DIR.mkdir(exist_ok=True)

DEFAULT_TARGET = "https://www.casarosada.gob.ar/"

# File paths lưu trữ kết quả mẫu
FILE_M1 = OUTPUT_DIR / "01_recon_result.json"
FILE_M2 = OUTPUT_DIR / "02_wordlist_result.json"
FILE_M3 = OUTPUT_DIR / "03_fuzzing_result.json"
FILE_M4 = OUTPUT_DIR / "04_param_disc_result.json"
FILE_M5 = OUTPUT_DIR / "05_soft404_result.json"


def save_json(file_path: Path, data: dict):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  [Saved] -> {file_path}")


def load_json(file_path: Path) -> dict:
    if not file_path.exists():
        raise FileNotFoundError(f"Chưa có file dữ liệu mẫu: {file_path}. Vui lòng chạy module trước đó!")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ═══════════════════════════════════════════════════════════════
# MODULE EXECUTIONS
# ═══════════════════════════════════════════════════════════════

def run_module_1(target_url: str = DEFAULT_TARGET) -> dict:
    """Module 1: Tech Recon Agent."""
    print(f"\n[1/5] Running Tech Recon Agent for: {target_url}...")
    agent = TechReconAgent()
    result = agent.execute(target_url)
    
    # Bổ sung target_url vào result để các module sau tham chiếu
    result["target_url"] = target_url
    
    save_json(FILE_M1, result)
    return result


def run_module_2() -> dict:
    """Module 2: Wordlist Generator Agent."""
    print("\n[2/5] Running Wordlist Generator Agent...")
    recon_data = load_json(FILE_M1)
    
    agent = WordlistGenAgent()
    result = agent.execute(
        tech_stack=recon_data.get("tech_stack", {}),
        discovered_paths=recon_data.get("discovered_paths", []),
        js_endpoints=recon_data.get("js_endpoints", []),
    )
    result["target_url"] = recon_data.get("target_url", DEFAULT_TARGET)
    
    save_json(FILE_M2, result)
    return result


def run_module_3() -> dict:
    """Module 3: Fuzzing Agent."""
    print("\n[3/5] Running Fuzzing Agent...")
    recon_data = load_json(FILE_M1)
    wordlist_data = load_json(FILE_M2)
    
    target_url = recon_data.get("target_url", DEFAULT_TARGET)
    wordlist = wordlist_data.get("wordlist", [])
    
    agent = FuzzingAgent()
    result = agent.execute(
        target_url=target_url,
        wordlist=wordlist,
        waf_detected=recon_data.get("waf_detected", False),
        waf_type=recon_data.get("waf_type", None),
    )
    result["target_url"] = target_url
    
    save_json(FILE_M3, result)
    return result


def run_module_4() -> dict:
    """Module 4: Parameter Discovery Agent."""
    print("\n[4/5] Running Parameter Discovery Agent...")
    recon_data = load_json(FILE_M1)
    fuzzing_data = load_json(FILE_M3)
    
    target_url = recon_data.get("target_url", DEFAULT_TARGET)
    raw_results = fuzzing_data.get("results", [])
    
    # Lọc lấy các endpoints HTTP 200 từ fuzzing
    endpoints_200 = [r for r in raw_results if r.get("status_code") == 200]
    
    # Nếu không có HTTP 200 nào, lấy tạm 2 kết quả mẫu để test
    if not endpoints_200:
        endpoints_200 = raw_results[:2] if raw_results else [{"path": "/api/v1/users", "status_code": 200}]

    agent = ParamDiscoveryAgent()
    result = agent.execute(
        target_url=target_url,
        endpoints=endpoints_200,
        tech_stack=recon_data.get("tech_stack", {}),
    )
    result["target_url"] = target_url
    
    save_json(FILE_M4, result)
    return result


def run_module_5() -> dict:
    """Module 5: Soft 404 Filter Agent."""
    print("\n[5/5] Running Soft 404 Filter Agent...")
    recon_data = load_json(FILE_M1)
    fuzzing_data = load_json(FILE_M3)
    
    target_url = recon_data.get("target_url", DEFAULT_TARGET)
    raw_results = fuzzing_data.get("results", [])
    
    agent = Soft404FilterAgent()
    result = agent.execute(
        target_url=target_url,
        results_to_verify=raw_results,
    )
    result["target_url"] = target_url
    
    save_json(FILE_M5, result)
    return result


def run_all():
    """Chạy toàn bộ từ m1 -> m5."""
    run_module_1()
    run_module_2()
    run_module_3()
    run_module_4()
    run_module_5()
    print("\n[OK] Completed pipeline and saved data to output_samples/")


if __name__ == "__main__":
    import sys
    
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    
    if arg == "m1":
        run_module_1()
    elif arg == "m2":
        run_module_2()
    elif arg == "m3":
        run_module_3()
    elif arg == "m4":
        run_module_4()
    elif arg == "m5":
        run_module_5()
    elif arg == "all":
        run_all()
    else:
        print("Cú pháp sử dụng:")
        print("  python test_modules.py all  : Chạy toàn bộ 5 module theo thứ tự")
        print("  python test_modules.py m1   : Chạy Module 1 (Tech Recon)")
        print("  python test_modules.py m2   : Chạy Module 2 (Wordlist Gen)")
        print("  python test_modules.py m3   : Chạy Module 3 (Fuzzing)")
        print("  python test_modules.py m4   : Chạy Module 4 (Param Discovery)")
        print("  python test_modules.py m5   : Chạy Module 5 (Soft 404 Filter)")
