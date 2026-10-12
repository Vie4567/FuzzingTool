"""
Test Wordlist Generation Agent with real Recon data and LLM.
"""

import sys
import os
import json
from pathlib import Path

sys.path.insert(0, ".")
from src.agents.wordlist_gen import WordlistGenAgent

print("[*] ========================================================")
print("[*] KHỞI ĐỘNG PHASE 2: WORDLIST GENERATION VỚI LLM")
print("[*] ========================================================\n")

# 1. Đọc dữ liệu đầu ra từ Phase 1 (Recon Result)
recon_file = Path("output_samples/01_recon_result.json")
if not recon_file.exists():
    print(f"[!] Không tìm thấy file {recon_file}. Hãy chạy Phase Recon trước!")
    sys.exit(1)

with open(recon_file, encoding="utf-8") as f:
    recon_data = json.load(f)

target_url = recon_data.get("target_url", "https://cab.vn/")
tech_stack = recon_data.get("tech_stack", {})
tech_stack["target_url"] = target_url
discovered_paths = recon_data.get("discovered_paths", [])
js_endpoints = recon_data.get("js_scripts", [])

print(f"[*] Target: {target_url}")
print(f"[*] Tech Stack đầu vào: {json.dumps(tech_stack, ensure_ascii=False)}")
print(f"[*] Số lượng đường dẫn thu thập từ Recon: {len(discovered_paths)}")
print(f"[*] Đang khởi tạo WordlistGenAgent và kết nối LLM (DeepSeek / OpenAI)...\n")

# 2. Khởi tạo Agent và thực thi
agent = WordlistGenAgent()
result = agent.execute(
    tech_stack=tech_stack,
    discovered_paths=discovered_paths,
    js_endpoints=js_endpoints
)

# 3. In kết quả
dev_profile = result.get("dev_profile", {})
llm_analysis = dev_profile.get("llm_analysis", {})

print("\n=== KẾT QUẢ PHÂN TÍCH DEVELOPER PROFILE (8 CHIỀU) TỪ LLM ===")
print(f"[*] Naming Style chủ đạo: {dev_profile.get('naming_convention')}")
print(f"[*] Cấu trúc phân cấp: {llm_analysis.get('url_hierarchy', {}).get('style', 'nested')}")
print(f"[*] Tiền tố chung: {llm_analysis.get('url_hierarchy', {}).get('common_prefix', '/v1/')}")
print(f"[*] Các Microservices phát hiện: {llm_analysis.get('url_hierarchy', {}).get('detected_services', [])}")
print(f"[*] CRUD / Action Pattern: {llm_analysis.get('crud_pattern')}")
print(f"[*] Quy tắc suy luận (Inferred Rules): {json.dumps(llm_analysis.get('inferred_rules', []), indent=2, ensure_ascii=False)}")

print("\n=== MẪU ENDPOINTS TIỀM NĂNG DO LLM SUY LUẬN (LAYER 4 PREDICTIVE) ===")
predicted_sample = result.get("llm_predicted_sample", [])
for ep in predicted_sample:
    print(f"  -> [LLM Predicted] {ep}")

metadata = result.get("metadata", {})
print("\n=== TỔNG KẾT TỔNG HỢP WORDLIST ĐA TẦNG ===")
print(f"[*] Tổng số lượng từ điển sau khi kết hợp 4 tầng: {metadata.get('total_entries')} paths")
print(f"[*] Số path từ Recon gốc: {metadata.get('recon_paths_included')}")
print(f"[*] Số path do LLM suy luận mới: {metadata.get('llm_predicted_paths')}")
print(f"[*] File Target Profile: {metadata.get('target_profile_file')}")
print("[+] ĐÃ XUẤT KẾT QUẢ ĐẦY ĐỦ VÀO: output_samples/02_wordlist_result.json")
