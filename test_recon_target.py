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

# 5. Extract links/paths
discovered_paths = set()
for match in re.finditer(r'href=[\"\'](/[^\"\'\s>]+)[\"\']', body):
    path = match.group(1)
    if not path.startswith(('//', 'http:', 'https:')):
        discovered_paths.add(path)

# 6. WAF Detection Check
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

results = {
    "target_url": target_url,
    "status_code": status,
    "tech_stack": tech_stack,
    "detected_cookies": detected_cookies,
    "body_signatures": list(set(body_detected)),
    "meta_generator": meta_generator,
    "waf_detected": waf_detected,
    "waf_type": waf_type,
    "js_scripts_found": len(script_srcs),
    "sample_js_scripts": script_srcs[:5],
    "discovered_paths_count": len(discovered_paths),
    "sample_discovered_paths": sorted(list(discovered_paths))[:10],
    "has_robots_txt": "Disallow" in robots or "User-agent" in robots,
}

print("=== RECON RESULTS SUMMARY ===")
print(json.dumps(results, indent=2, ensure_ascii=False))
