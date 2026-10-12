"""
Test Recon script for target analysis.
"""
import urllib.request
import ssl
import json
import re

target_url = "https://ktxhcm.edu.vn/"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return r.status, dict(r.headers), r.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return None, {}, str(e)

print(f"[*] Starting Recon test for target: {target_url}\n")

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

# 4. JS Script tags extraction
script_srcs = re.findall(r'<script[^>]+src=[\"\']([^\"\']+)[\"\']', body, re.IGNORECASE)

# 5. Extract links, paths, query parameters & forms
discovered_paths = set()
discovered_params = set()

# Bóc tách hrefs và query parameters
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
