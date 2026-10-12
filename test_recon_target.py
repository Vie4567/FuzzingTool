"""
Test Recon script for target analysis.
"""
import urllib.request
import ssl
import json
import re
import os
import sys
import argparse

# Nạp AuthManager hỗ trợ Cách 2 & Cách 3
sys.path.insert(0, ".")
from src.tools.auth_manager import AuthManager

# Cấu hình đối số dòng lệnh hoặc tham số chạy
parser = argparse.ArgumentParser(description="Test Recon with optional Authentication")
parser.add_argument("--url", default="https://cab.vn/", help="Target URL")
parser.add_argument("--cookie", default=os.getenv("TARGET_COOKIE", None), help="Manual Cookie (Cách 2)")
parser.add_argument("--token", default=os.getenv("TARGET_TOKEN", None), help="Bearer Token (Cách 2)")
parser.add_argument("--username", default=os.getenv("TARGET_USERNAME", None), help="Account username (Cách 3)")
parser.add_argument("--password", default=os.getenv("TARGET_PASSWORD", None), help="Account password (Cách 3)")
parser.add_argument("--login-url", default=os.getenv("TARGET_LOGIN_URL", None), help="Custom login URL (Cách 3)")
args, _ = parser.parse_known_args()

target_url = args.url
cookie_input = args.cookie
token_input = args.token

account_input = None
if args.username and args.password:
    account_input = {
        "username": args.username,
        "password": args.password,
        "login_url": args.login_url or ""
    }

# Khởi tạo AuthManager:
# 1. Ưu tiên cookie/token nếu có (Cách 2)
# 2. Nếu không có cookie thì dùng account để auto-login (Cách 3)
# 3. Mặc định không truyền gì -> chạy unauthenticated (Black-box)
auth_mgr = AuthManager(
    cookie=cookie_input,
    bearer_token=token_input,
    account=account_input
)

auth_headers = auth_mgr.get_auth_headers(target_url)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch(url):
    req_headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    # Tự động gộp auth headers nếu có
    req_headers.update(auth_headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return r.status, dict(r.headers), r.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8', errors='ignore')
        except Exception:
            body = ""
        return e.code, dict(e.headers), body
    except Exception as e:
        return None, {}, str(e)

print(f"[*] Starting Recon test for target: {target_url}")
if auth_headers:
    print(f"[*] [AUTH ENABLED] Using Authenticated Headers: {list(auth_headers.keys())}")
else:
    print("[*] [AUTH DISABLED] Running in default Unauthenticated mode")
print()

status, headers, body = fetch(target_url)
_, _, robots = fetch(target_url + "robots.txt")
_, _, sitemap = fetch(target_url + "sitemap.xml")

with open('knowledge/tech_fingerprints.json', encoding='utf-8') as f:
    fingerprints = json.load(f)

with open('knowledge/waf_signatures.json', encoding='utf-8') as f:
    waf_sigs = json.load(f)

tech_stack = {}

# 1. Header Analysis
server = headers.get('Server') or headers.get('server')
if server:
    tech_stack['web_server'] = server

x_powered = headers.get('X-Powered-By') or headers.get('x-powered-by')
if x_powered:
    tech_stack['backend_language'] = x_powered

# 2. Cookie Analysis
cookies = headers.get('Set-Cookie') or headers.get('set-cookie') or ""
detected_cookies = []
for cookie_name, tech in fingerprints.get('cookies', {}).items():
    if cookie_name in cookies:
        detected_cookies.append(f"{cookie_name} ({tech})")

# 3. HTML Meta Generator & Body patterns
meta_generator = None
gen_match = re.search(r'<meta\s+name=[\"\']generator[\"\']\s+content=[\"\']([^\"\']+)[\"\']', body, re.IGNORECASE)
if gen_match:
    meta_generator = gen_match.group(1)
    tech_stack['cms_generator'] = meta_generator

body_detected = []
for pattern, tech in fingerprints.get('body_patterns', {}).items():
    if pattern in body:
        body_detected.append(tech)

# 4. JS Script tags extraction & Deep Bundle Analysis (CH-3)
script_srcs = re.findall(r'<script[^>]+src=[\"\']([^\"\']+)[\"\']', body, re.IGNORECASE)

# 5. Extract links, paths, query parameters & forms
discovered_paths = set()
discovered_params = set()

# Bóc tách hrefs và query parameters từ HTML
for match in re.finditer(r'href=[\"\'](/[^\"\'\s>]+)[\"\']', body):
    raw_href = match.group(1)
    if raw_href.startswith(('//', 'http:', 'https:')):
        continue
    # Tách path và query string
    if '?' in raw_href:
        path_part, query_part = raw_href.split('?', 1)
        discovered_paths.add(path_part)
        for param in re.findall(r'([a-zA-Z0-9_\-\[\]]+)=', query_part):
            discovered_params.add(param)
    else:
        clean_path = raw_href.split('#')[0]
        if clean_path:
            discovered_paths.add(clean_path)

# CH-3: Bóc tách sâu API endpoints & Route ẩn trong tất cả các file JavaScript
print(f"[*] Đang phân tích sâu {len(script_srcs)} file JavaScript bundles...")
for s_path in script_srcs:
    js_url = s_path if s_path.startswith("http") else urllib.parse.urljoin(target_url, s_path)
    _, _, js_body = fetch(js_url)
    if js_body and len(js_body) < 10_000_000:
        # Bóc tách các API endpoint dạng /v1/..., /api/..., service router
        js_endpoints = re.findall(r'[\"\'`](/(?:api|v[0-9]|auth|[a-zA-Z0-9_\-]+-service)/[a-zA-Z0-9_\-/]+)[\"\'`]', js_body)
        for ep in js_endpoints:
            clean_ep = ep.split("?")[0].rstrip("/")
            if len(clean_ep) > 3:
                discovered_paths.add(clean_ep)
        # Bóc tách các tham số query trong JS
        for p in re.findall(r'[\?&]([a-zA-Z0-9_\-]+)=', js_body):
            if len(p) < 30:
                discovered_params.add(p)

# Bóc tách form actions & form inputs (input, select, textarea)
forms = []
for form_match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
    form_attrs, form_inner = form_match.groups()
    action_match = re.search(r'action=[\"\']([^\"\']*)[\"\']', form_attrs, re.IGNORECASE)
    method_match = re.search(r'method=[\"\']([^\"\']*)[\"\']', form_attrs, re.IGNORECASE)
    action = action_match.group(1) if action_match else "/"
    method = method_match.group(1).upper() if method_match else "GET"
    
    input_names = re.findall(r'<input\b[^>]*name=[\"\']([^\"\']+)[\"\']', form_inner, re.IGNORECASE)
    textarea_names = re.findall(r'<textarea\b[^>]*name=[\"\']([^\"\']+)[\"\']', form_inner, re.IGNORECASE)
    select_names = re.findall(r'<select\b[^>]*name=[\"\']([^\"\']+)[\"\']', form_inner, re.IGNORECASE)
    
    all_fields = list(set(input_names + textarea_names + select_names))
    for f in all_fields:
        discovered_params.add(f)
        
    forms.append({
        "action": action,
        "method": method,
        "fields": all_fields
    })

# 6. Phân tích phân bổ Naming Convention thực tế từ discovered paths
naming_stats = {
    "kebab-case": 0,
    "snake_case": 0,
    "camelCase": 0,
    "flat_or_single_word": 0,
}
for p in discovered_paths:
    segments = [s for s in p.strip("/").split("/") if s]
    for seg in segments:
        if "-" in seg and "_" not in seg:
            naming_stats["kebab-case"] += 1
        elif "_" in seg and "-" not in seg:
            naming_stats["snake_case"] += 1
        elif re.search(r'[a-z][A-Z]', seg):
            naming_stats["camelCase"] += 1
        else:
            naming_stats["flat_or_single_word"] += 1

total_named_segments = sum(naming_stats.values()) or 1
naming_distribution = {k: f"{(v / total_named_segments) * 100:.1f}% ({v})" for k, v in naming_stats.items()}

# 7. WAF Detection Check
waf_detected = False
waf_type = None
headers_str = str(headers).lower()
cookies_str = cookies.lower()
body_str = body.lower()

for waf_name, sig in waf_sigs.items():
    if isinstance(sig, dict):
        for h_key in sig.get('headers', {}):
            if h_key.lower() in headers_str:
                waf_detected = True
                waf_type = waf_name
        for c_key in sig.get('cookies', []):
            if c_key.lower() in cookies_str:
                waf_detected = True
                waf_type = waf_name

sorted_all_paths = sorted(list(discovered_paths))
sorted_all_params = sorted(list(discovered_params))

results = {
    "target_url": target_url,
    "status_code": status,
    "tech_stack": tech_stack,
    "detected_cookies": detected_cookies,
    "body_signatures": list(set(body_detected)),
    "meta_generator": meta_generator,
    "waf_detected": waf_detected,
    "waf_type": waf_type,
    "naming_convention_analysis": {
        "dominant_style": max(naming_stats, key=naming_stats.get),
        "distribution": naming_distribution,
    },
    "statistics": {
        "total_paths": len(sorted_all_paths),
        "total_params": len(sorted_all_params),
        "total_forms": len(forms),
        "total_js_scripts": len(script_srcs),
    },
    "discovered_paths": sorted_all_paths,          # In/lưu đầy đủ 100% tất cả paths
    "discovered_params": sorted_all_params,        # In/lưu đầy đủ 100% tất cả params
    "forms": forms,                                # Danh sách form & method & fields
    "js_scripts": sorted(list(set(script_srcs))),  # In/lưu đầy đủ 100% tất cả file JS
    "has_robots_txt": "Disallow" in robots or "User-agent" in robots,
}

print("=== RECON RESULTS SUMMARY ===")
print(f"[*] Target: {target_url} (HTTP {status})")
print(f"[*] Tech Stack: {json.dumps(tech_stack)}")
print(f"[*] WAF: {waf_type if waf_detected else 'None'}")
print(f"[*] Total Paths Found: {len(sorted_all_paths)}")
print(f"[*] Total Params Found: {len(sorted_all_params)}")
print(f"[*] Naming Analysis: {naming_distribution}")
print(f"[*] Sample 10 Paths: {sorted_all_paths[:10]}")
print(f"[*] All Discovered Params: {sorted_all_params}")

# Lưu kết quả đầy đủ ra file output_samples/01_recon_result.json
import os
os.makedirs("output_samples", exist_ok=True)
output_path = "output_samples/01_recon_result.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"\n[+] ĐÃ LƯU ĐẦY ĐỦ 100% TOÀN BỘ ({len(sorted_all_paths)} paths, {len(sorted_all_params)} params, {len(script_srcs)} JS) VÀO: {output_path}")
