"""Shared Coordinator HTTP limits reach real sockets, independent of module defaults."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import unittest

from src.coordinator.runtime import runtime_session
from src.coordinator.telemetry import telemetry_session
from src.tools.recon_http import ScopedReconTransport
from src.tools.http_fuzzing import run_http_fuzzing


class SlowHeaders(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/slow':
            time.sleep(.3)
        try:
            self.send_response(200)
            self.send_header('Content-Length', '10')
            self.end_headers()
            self.wfile.write(b'abcdefghij')
        except OSError:
            pass

    def log_message(self, *args):
        pass


class CoordinatorHttpLimitsTests(unittest.TestCase):
    def test_shared_timeout_caps_recon_and_native_dispatch(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), SlowHeaders)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = f'http://127.0.0.1:{server.server_port}'
        try:
            for engine in ('recon', 'fuzzing'):
                with self.subTest(engine=engine), runtime_session({'http_timeout_seconds': .04, 'http_rate_limit': 100}), telemetry_session() as t:
                    started = time.monotonic()
                    if engine == 'recon':
                        status, _, error = ScopedReconTransport(target).fetch(target + '/slow', timeout=5)
                        self.assertIsNone(status)
                        self.assertIn('timed out', error)
                    else:
                        result = run_http_fuzzing(target, ['slow'], timeout_seconds=5)
                        self.assertIsNone(result['results'][0]['status_code'])
                        self.assertIn('timed out', result['results'][0]['error'])
                    self.assertLess(time.monotonic()-started, .25)
                    self.assertEqual(t.snapshot()['http']['total_requests'], 1)
            with runtime_session({'http_max_response_bytes': 3}):
                result = run_http_fuzzing(target, ['body'])
                self.assertEqual(result['results'][0]['content_length'], 3)
                self.assertTrue(result['results'][0]['body_truncated'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
