import sys
sys.path.insert(0, '.')
from src.agents.tech_recon import TechReconAgent
import json

agent = TechReconAgent()
result = agent.execute('https://ktxhcm.edu.vn/')

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
