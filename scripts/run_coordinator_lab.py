"""All real agents + real configured DeepSeek API against a local HTTP lab.

No monkeypatches, fake model, generated HTTP measurements or target credentials.
"""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class LabHandler(BaseHTTPRequestHandler):
    server_version = 'CoordinatorLab/1.0'

    def do_GET(self):
        p = urlsplit(self.path)
        q = parse_qs(p.query)
        content_type = 'text/html'
        status = 200
        if p.path == '/':
            body = b'<html><title>Catalog lab</title><a href="/api/search">Search</a><script src="/app.js"></script><form action="/api/search" method="GET"><input name="page"></form></html>'
        elif p.path == '/api/search':
            content_type = 'application/json'
            group = {'1': 'first', '2': 'second'}.get(q.get('page', [''])[0], 'all')
            body = json.dumps({'catalog': group, 'items': ['alpha', 'beta'], 'service': 'catalog'}, sort_keys=True).encode()
        elif p.path == '/app.js':
            content_type, body = 'application/javascript', b'fetch("/api/search?page=1"); const api="/api/search";'
        elif p.path == '/robots.txt':
            content_type, body = 'text/plain', b'User-agent: *\nAllow: /api/search\n'
        elif p.path == '/sitemap.xml':
            content_type, body = 'application/xml', b'<urlset><url><loc>/api/search</loc></url></urlset>'
        elif p.path in {'/swagger.json', '/openapi.json'}:
            content_type = 'application/json'
            body = json.dumps({'openapi': '3.0.0', 'info': {'title': 'Catalog Lab', 'version': '1'},
                'paths': {'/api/search': {'get': {'parameters': [{'name': 'page', 'in': 'query', 'schema': {'type': 'integer'}}], 'responses': {'200': {'description': 'catalog'}}}}}}).encode()
        else:
            body = b'<html><title>Application shell</title><div id="root">Missing resource fallback</div></html>'
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)
        with self.server.event_lock:
            self.server.events.append({'method': self.command, 'path': self.path, 'status_code': status,
                                       'body_bytes': len(body), 'received_at': datetime.now(timezone.utc).isoformat()})

    do_HEAD = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir')
    parser.add_argument('--llm-timeout', type=float, default=120, help='Total elapsed seconds allowed for one LLM call')
    parser.add_argument('--pipeline-timeout', type=float, default=900, help='Hard deadline in seconds for the owned pipeline process')
    args = parser.parse_args()
    from dotenv import dotenv_values
    secrets = {**dotenv_values(ROOT / '.env'), **os.environ}
    key = secrets.get('DEEPSEEK_API_KEY')
    provider = secrets.get('DEEPSEEK_BASE_URL') or 'https://api.deepseek.com'
    if not key or urlsplit(provider).scheme != 'https' or urlsplit(provider).netloc != 'api.deepseek.com':
        raise SystemExit('Configure a DeepSeek key and the authorized HTTPS api.deepseek.com provider locally.')
    output = Path(args.output_dir).resolve() if args.output_dir else ROOT / 'output_samples/diagnostics' / ('coordinator_real_lab_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid4().hex[:8])
    output.mkdir(parents=True, exist_ok=False)
    os.environ.update(PYTHON_DOTENV_DISABLED='1', LANGSMITH_TRACING='false', LANGCHAIN_TRACING_V2='false',
                      LLM_RESPONSE_LOG_FILE=str(output / 'llm_responses.jsonl'))
    server = ThreadingHTTPServer(('127.0.0.1', 0), LabHandler)
    server.events, server.event_lock = [], threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f'http://127.0.0.1:{server.server_port}'
    config = {
        'api_key': key, 'base_url': provider, 'llm_model': secrets.get('LLM_MODEL') or 'deepseek-chat',
        'artifact_root': str(output), 'knowledge_store_dir': str(output / 'knowledge_store'),
        'pipeline_timeout_seconds': args.pipeline_timeout, 'llm_timeout_seconds': args.llm_timeout, 'llm_max_tokens': 8192, 'max_llm_calls': 60,
        'max_retries': 1, 'max_iterations': 10, 'run_all_modules': True,
        'http_max_requests': 250, 'http_rate_limit': 20, 'http_timeout_seconds': 5,
        'wordlist': ['/api/search', '/missing-page'], 'wordlist_mode': 'merge', 'max_wordlist_entries': 2,
        'fuzzing_options': {'engine': 'python_http', 'threads': 1, 'rate_limit': 20, 'delay_ms': 0,
                            'max_requests': 2, 'timeout_seconds': 5, 'max_scan_seconds': 20,
                            'headers': {}, 'auto_calibrate': False, 'recursion': False, 'follow_redirects': False},
        'parameter_options': {'enabled': True, 'rate_limit': 20, 'max_requests': 100, 'max_duration_seconds': 60},
        'soft404_options': {'enabled': True, 'rate_limit': 20, 'max_requests': 20, 'max_duration_seconds': 30},
    }
    print('Artifacts:', output, flush=True)
    print('Real Coordinator + real LLM; target:', target, flush=True)
    try:
        from src.coordinator import run_pipeline_supervised
        result = run_pipeline_supervised(target, config)
        (output / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        (output / 'server_requests.json').write_text(json.dumps(server.events, indent=2), encoding='utf-8')
        counts = result.get('telemetry', {}).get('llm', {})
        verified = result.get('verified_parameters', [])
        checks = {
            'pipeline_completed': result.get('pipeline_status') == 'completed',
            'all_real_modules_executed': result.get('all_modules_executed') is True,
            'all_modules_successful': result.get('all_modules_successful') is True,
            'real_llm_responses': counts.get('succeeded', 0) > 0 and counts.get('failed', 0) == 0,
            'http_counter_matches_server': result.get('total_http_requests') == len(server.events),
            'known_parameter_verified': any(p.get('name') == 'page' for p in verified),
            'fallback_filtered': any(p.get('url', '').endswith('/missing-page') for p in result.get('false_positives', [])),
        }
        summary = {'checks': checks, 'success': all(checks.values()), 'http_requests_observed': len(server.events),
                   'llm': counts, 'agent_statuses': result.get('agent_statuses'), 'pipeline_status': result.get('pipeline_status'),
                   'wordlist_selection': result.get('wordlist_metadata'), 'result': str(output / 'result.json')}
        (output / 'evidence.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({'success': summary['success'], 'checks': checks, 'http_requests': len(server.events),
                          'llm_calls': result.get('llm_call_count'), 'output': str(output)}, ensure_ascii=False), flush=True)
        return 0 if summary['success'] else 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == '__main__':
    raise SystemExit(main())
