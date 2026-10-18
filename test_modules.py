"""
Test Runner & Mock Data Generator cho từng Module / Agent.

Cho phép chạy từng module đơn lẻ hoặc nối tầng (pipeline step-by-step).
Mỗi module khi chạy sẽ tự động đọc dữ liệu đầu vào từ file JSON của module trước (hoặc dùng dữ liệu mới),
sau đó ghi kết quả đầu ra thành file JSON riêng trong thư mục `output_samples/`.
"""

import sys
import subprocess
from pathlib import Path

# Tự động chuyển sang môi trường .venv nếu chạy bằng Python toàn cục bị thiếu thư viện
_venv_py = Path(".venv") / "Scripts" / "python.exe"
if _venv_py.exists() and Path(sys.executable).resolve() != _venv_py.resolve():
    try:
        import langchain_core
    except ImportError:
        res = subprocess.run([str(_venv_py)] + sys.argv, check=False)
        sys.exit(res.returncode)

import json
import os

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
    """Module 3: Fuzzing Agent (với Pattern Engine từ dev_profile + observed URLs)."""
    print("\n[3/5] Running Fuzzing Agent (+ Pattern Engine)...")
    recon_data = load_json(FILE_M1)
    wordlist_data = load_json(FILE_M2)

    # Nếu target là kiến trúc Decoupled, ưu tiên fuzzing trên primary_backend_api
    target_url = recon_data.get("primary_backend_api") or recon_data.get("target_url", DEFAULT_TARGET)
    wordlist = wordlist_data.get("wordlist", [])

    # Dev profile từ WordlistGenAgent (chứa naming_convention, detected_services,...)
    dev_profile = wordlist_data.get("dev_profile", {})

    # Observed URLs từ recon: discovered_paths + js_endpoints (để Pattern Engine học vocab)
    observed_urls = list(set(
        recon_data.get("discovered_paths", []) +
        recon_data.get("js_endpoints", [])
    ))

    agent = FuzzingAgent()
    result = agent.execute(
        target_url=target_url,
        wordlist=wordlist,
        waf_detected=recon_data.get("waf_detected", False),
        waf_type=recon_data.get("waf_type", None),
        dev_profile=dev_profile,
        observed_urls=observed_urls,
        use_pattern_engine=True,
        max_pattern_endpoints=1500,
    )
    result["target_url"] = target_url

    save_json(FILE_M3, result)
    return result


def run_module_4() -> dict:
    """Module 4: Parameter Discovery Agent."""
    print("\n[4/5] Running Parameter Discovery Agent...")
    recon_data = load_json(FILE_M1)
    fuzzing_data = load_json(FILE_M3)
    
    # Nếu target là kiến trúc Decoupled, ưu tiên khám phá param trên primary_backend_api
    target_url = recon_data.get("primary_backend_api") or recon_data.get("target_url", DEFAULT_TARGET)
    raw_results = fuzzing_data.get("results", [])
    
    # Lọc lấy các endpoints HTTP 200 từ fuzzing
    endpoints_200 = [r for r in raw_results if r.get("status_code") == 200]
    
    # Nếu không có HTTP 200 nào, lấy tạm 2 kết quả mẫu để test
    if not endpoints_200:
        endpoints_200 = raw_results[:2] if raw_results else [{"path": "/v1/user-service/users/profile", "status_code": 200}]

    dev_profile = {}
    if FILE_M2.exists():
        try:
            dev_profile = load_json(FILE_M2).get("dev_profile", {})
        except Exception:
            pass

    agent = ParamDiscoveryAgent()
    result = agent.execute(
        target_url=target_url,
        endpoints=endpoints_200,
        tech_stack=recon_data.get("tech_stack", {}),
        dev_profile=dev_profile,
    )
    result["target_url"] = target_url
    
    save_json(FILE_M4, result)
    return result


def run_module_5() -> dict:
    """Module 5: Soft 404 Filter Agent."""
    print("\n[5/5] Running Soft 404 Filter Agent...")
    recon_data = load_json(FILE_M1)
    fuzzing_data = load_json(FILE_M3)
    
    target_url = recon_data.get("primary_backend_api") or recon_data.get("target_url", DEFAULT_TARGET)
    raw_results = fuzzing_data.get("results", [])
    
    agent = Soft404FilterAgent()
    result = agent.execute(
        target_url=target_url,
        results_to_verify=raw_results,
    )
    result["target_url"] = target_url
    
    save_json(FILE_M5, result)
    return result


def run_all(target_url: str = None, token: str = None, cookie: str = None):
    """Chạy toàn bộ từ m1 -> m5 hoặc từ m2 -> m5 nếu m1 đã có dữ liệu."""
    if target_url:
        run_module_1(target_url=target_url, token=token, cookie=cookie)
    elif not FILE_M1.exists():
        run_module_1()
    run_module_2()
    run_module_3()
    run_module_4()
    run_module_5()
    print("\n[OK] Completed pipeline and saved data to output_samples/")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test runner for Sentinel Agents")
    parser.add_argument("mode", nargs="?", default="all", choices=["m1", "m2", "m3", "m4", "m5", "all", "pipeline"], help="Module to run")
    parser.add_argument("--url", default=None, help="Target URL override")
    parser.add_argument("--token", default=None, help="Bearer token for authenticated recon/fuzzing")
    parser.add_argument("--cookie", default=None, help="Cookie header")
    args = parser.parse_args()

    mode = args.mode
    if mode == "m1":
        run_module_1(target_url=args.url or DEFAULT_TARGET, token=args.token, cookie=args.cookie)
    elif mode == "m2":
        run_module_2()
    elif mode == "m3":
        run_module_3()
    elif mode == "m4":
        run_module_4()
    elif mode == "m5":
        run_module_5()
    elif mode in ("all", "pipeline"):
        run_all(target_url=args.url, token=args.token, cookie=args.cookie)

