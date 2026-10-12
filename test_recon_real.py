import sys
import os
import json
import argparse

sys.path.insert(0, '.')
from src.agents.tech_recon import TechReconAgent

parser = argparse.ArgumentParser(description="Run TechReconAgent with optional Auth")
parser.add_argument("--url", default="https://ktxhcm.edu.vn/", help="Target URL")
parser.add_argument("--cookie", default=os.getenv("TARGET_COOKIE", None), help="Manual Cookie (Cách 2)")
parser.add_argument("--token", default=os.getenv("TARGET_TOKEN", None), help="Bearer Token (Cách 2)")
parser.add_argument("--username", default=os.getenv("TARGET_USERNAME", None), help="Account username (Cách 3)")
parser.add_argument("--password", default=os.getenv("TARGET_PASSWORD", None), help="Account password (Cách 3)")
parser.add_argument("--login-url", default=os.getenv("TARGET_LOGIN_URL", None), help="Custom login URL (Cách 3)")
args, _ = parser.parse_known_args()

account_cfg = None
if args.username and args.password:
    account_cfg = {
        "username": args.username,
        "password": args.password,
        "login_url": args.login_url or ""
    }

agent = TechReconAgent(
    cookie=args.cookie,
    bearer_token=args.token,
    account=account_cfg
)
result = agent.execute(args.url)

print('=== RECON RESULT ===')
print('Status:', result['status_code'])
print('Tech Fingerprint:')
print(json.dumps(result['tech_fingerprint'], indent=2, ensure_ascii=False))
print('Meta Generator:', result['meta_generator'])
stats = result['recon_stats']
print('Paths discovered:', stats['total_paths_discovered'])
print('Params discovered:', stats['total_params_discovered'])
print('Spider pages:', stats['spider_pages_visited'])
print('JS files analyzed:', stats['js_files_analyzed'])
print('Probe hits:', result['probe_hits'])
print('Source breakdown:', stats['source_breakdown'])
print('Sample paths:', result['discovered_paths'][:10])
print('Sample params:', result['discovered_params'][:10])
print('Allowed methods:', result['allowed_methods'])

# Lưu toàn bộ 100% dữ liệu ra file output_samples/01_recon_result.json
os.makedirs("output_samples", exist_ok=True)
output_path = "output_samples/01_recon_result.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print(f"\n[+] ĐÃ LƯU 100% KẾT QUẢ ĐẦY ĐỦ VÀO: {output_path}")
