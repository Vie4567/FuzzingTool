import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
import unittest
from openai import APIStatusError

from src.coordinator.llm_client import DeadlineChatOpenAI
from src.coordinator.telemetry import telemetry_session, invoke_measured
from src.coordinator.runtime import runtime_session, PipelineStopped


class SlowAPI(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.requests += 1
        self.server.observed.append({'path': self.path, 'authorization': self.headers.get('Authorization')})
        incoming = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        mode = incoming['messages'][-1]['content']
        if mode == 'redirect' and self.path == '/v1/chat/completions' and self.server.redirect_to:
            self.send_response(307)
            self.send_header('Location', self.server.redirect_to)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        payload = json.dumps({'id': 'fixture', 'object': 'chat.completion',
            'created': 1, 'model': 'fixture', 'choices': [{'index': 0,
                'message': {'role': 'assistant', 'content': 'ok'}, 'finish_reason': 'stop'}]}).encode()
        if mode == 'slow':
            time.sleep(1.5)
        if mode == 'drip':
            payload += b' ' * 2000
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            if mode == 'drip':
                for offset in range(0, len(payload), 20):
                    self.wfile.write(payload[offset:offset+20])
                    self.wfile.flush()
                    time.sleep(.025)
            else:
                self.wfile.write(payload)
        except OSError:
            self.server.disconnected.set()

    def log_message(self, *args):
        pass


@contextmanager
def local_api(timeout=.6):
    server = ThreadingHTTPServer(('127.0.0.1', 0), SlowAPI)
    server.requests = 0
    server.observed = []
    server.redirect_to = None
    server.disconnected = threading.Event()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        model = DeadlineChatOpenAI(model='fixture', api_key='fixture',
            base_url=f'http://127.0.0.1:{server.server_port}/v1', timeout=timeout, max_retries=0)
        yield server, model
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


class LLMTimeoutTests(unittest.TestCase):
    def test_provider_redirect_does_not_replay_prompt_or_credentials(self):
        with local_api(timeout=2) as (first, model), local_api(timeout=2) as (other, _):
            for destination in ('/redirected', f'http://127.0.0.1:{other.server_port}/redirected'):
                with self.subTest(destination=destination):
                    first.redirect_to = destination
                    first.requests = other.requests = 0
                    first.observed.clear()
                    other.observed.clear()
                    with telemetry_session() as telemetry:
                        with self.assertRaises(APIStatusError) as caught:
                            invoke_measured(model, 'redirect', component='Coordinator')
                        self.assertEqual(caught.exception.status_code, 307)
                        self.assertEqual(telemetry.snapshot()['llm']['attempted'], 1)
                        self.assertEqual(telemetry.snapshot()['llm']['failed'], 1)
                    self.assertEqual(first.requests, 1)
                    self.assertEqual(first.observed, [{'path': '/v1/chat/completions',
                                                      'authorization': 'Bearer fixture'}])
                    self.assertEqual(other.requests, 0)
                    self.assertEqual(other.observed, [])

    def test_token_limit_uses_provider_specific_field_without_network(self):
        for base, key in [('https://api.deepseek.com', 'max_tokens'),
                          ('https://api.openai.com/v1', 'max_completion_tokens')]:
            model = DeadlineChatOpenAI(model='fixture', api_key='fixture', base_url=base, max_tokens=512)
            payload = model._get_request_payload('fixture')
            self.assertEqual(payload[key], 512)
            self.assertEqual(len(set(payload) & {'max_tokens', 'max_completion_tokens'}), 1)

    def test_sdk_timeout_is_real_http_and_no_hidden_retry(self):
        with local_api() as (server, model):
            with runtime_session({'pipeline_timeout_seconds': 5}), telemetry_session() as telemetry:
                with self.assertRaises(Exception) as caught:
                    invoke_measured(model, 'slow', component='Coordinator')
                self.assertIn('Timeout', type(caught.exception).__name__)
                self.assertEqual(telemetry.snapshot()['llm']['attempted'], 1)
                self.assertEqual(telemetry.snapshot()['llm']['failed'], 1)
            self.assertEqual(server.requests, 1)

    def test_dripping_body_cannot_extend_deadline_and_connection_is_closed(self):
        with local_api() as (server, model):
            start = time.monotonic()
            with runtime_session({'pipeline_timeout_seconds': 5}), telemetry_session() as telemetry:
                with self.assertRaises(TimeoutError):
                    invoke_measured(model, 'drip', component='Coordinator')
                self.assertLess(time.monotonic() - start, 1.3)
                self.assertEqual(telemetry.snapshot()['llm']['attempted'], 1)
                self.assertEqual(telemetry.snapshot()['llm']['failed'], 1)
                self.assertEqual(telemetry.snapshot()['llm']['in_flight'], 0)
            self.assertTrue(server.disconnected.wait(1), 'Timed out client must close its connection')
            self.assertEqual(server.requests, 1)

    def test_pipeline_remaining_time_caps_model_call(self):
        with local_api(timeout=3) as (server, model):
            start = time.monotonic()
            with runtime_session({'pipeline_timeout_seconds': .6}) as budget:
                with self.assertRaises(PipelineStopped):
                    model.invoke('drip')
                self.assertEqual(budget.stop_reason, 'pipeline_deadline')
            self.assertLess(time.monotonic() - start, 1.3)
            self.assertTrue(server.disconnected.wait(1))
            self.assertEqual(server.requests, 1)

    def test_successive_calls_and_sync_call_inside_async_loop_reuse_model_safely(self):
        with local_api(timeout=2) as (server, model), telemetry_session() as telemetry:
            for _ in range(2):
                self.assertEqual(invoke_measured(model, 'fast', component='Coordinator').content, 'ok')

            async def nested_sync_call():
                return invoke_measured(model, 'fast', component='Coordinator')

            self.assertEqual(asyncio.run(nested_sync_call()).content, 'ok')
            self.assertEqual(server.requests, 3)
            self.assertEqual(telemetry.snapshot()['llm']['succeeded'], 3)
            self.assertEqual(telemetry.snapshot()['llm']['in_flight'], 0)

    def test_async_call_cancels_transport_and_next_call_still_works(self):
        with local_api() as (server, model):
            async def calls():
                with self.assertRaises(TimeoutError):
                    await model.ainvoke('drip')
                self.assertEqual((await model.ainvoke('fast')).content, 'ok')
            asyncio.run(calls())
            self.assertTrue(server.disconnected.wait(1))
            self.assertEqual(server.requests, 2)
