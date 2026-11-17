"""Counters follow real local dispatch and model callbacks, including failures."""

import asyncio
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.setdefault("PYTHON_DOTENV_DISABLED", "1")

from src.coordinator.guards import LLMQuotaExhaustedError
from src.coordinator.llm_logging import invoke_logged
from src.coordinator.telemetry import (
    current_telemetry, mark_http_unknown, record_http_attempt, sync_state,
    telemetry_phase, telemetry_session,
)
from src.tools.ffuf_helper import FfufToolHelper
from src.tools.http_fuzzing import run_http_fuzzing
from src.tools.recon_http import ScopedReconTransport


class _Target(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.calls.append(self.path)
        status = 429 if self.path == "/rate" else 404 if self.path == "/missing" else 200
        body = b"local measurement"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RuntimeTelemetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)

    def setUp(self):
        _Target.calls.clear()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.logs = patch.dict(os.environ, {
            "LLM_RESPONSE_LOG_FILE": str(Path(self.directory.name) / "llm.jsonl"),
            "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false",
        })
        self.logs.start()
        self.addCleanup(self.logs.stop)

    def invoke(self, runnable, value="local", component="test"):
        return invoke_logged(runnable, value, component=component, operation="fixture")

    def test_success_failed_attempt_and_quota_are_distinct(self):
        client = SimpleNamespace(invoke=lambda value: "done")
        failing = SimpleNamespace(invoke=lambda value: (_ for _ in ()).throw(TimeoutError("fixture")))
        with telemetry_session(max_llm_calls=2) as stats:
            self.invoke(client, component="Coordinator")
            with self.assertRaises(TimeoutError):
                self.invoke(failing)
            with self.assertRaises(LLMQuotaExhaustedError):
                self.invoke(client)
            state = sync_state({"llm_call_count": 99})
        self.assertEqual(state["llm_call_count"], 2)
        self.assertEqual(state["coordinator_llm_calls"], 1)
        self.assertEqual(stats.snapshot()["llm"]["succeeded"], 1)
        self.assertEqual(stats.snapshot()["llm"]["failed"], 1)
        self.assertEqual(stats.snapshot()["llm"]["quota_rejections"], 1)
        self.assertEqual(stats.snapshot()["llm"]["in_flight"], 0)

    def test_langchain_chain_counts_model_not_prompt_or_parser_errors(self):
        from langchain_core.language_models.fake_chat_models import FakeListChatModel
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.runnables import RunnableLambda

        model = FakeListChatModel(responses=["not-json"])
        prompt = ChatPromptTemplate.from_template("{required_input}")
        parse = RunnableLambda(lambda message: json.loads(message.content))
        with telemetry_session() as stats:
            with self.assertRaises(KeyError):
                self.invoke(prompt | model, {})
            self.assertEqual(stats.snapshot()["llm"]["attempted"], 0)
            with self.assertRaises(ValueError):
                self.invoke(prompt | model | parse, {"required_input": "hello"})
            self.assertEqual(stats.snapshot()["llm"]["attempted"], 1)
            self.assertEqual(stats.snapshot()["llm"]["succeeded"], 1)

    def test_langchain_failed_model_and_quota_prevent_provider_dispatch(self):
        from langchain_core.language_models.fake_chat_models import FakeListChatModel

        class FailingModel(FakeListChatModel):
            attempts: int = 0

            def _call(self, *args, **kwargs):
                self.attempts += 1
                raise TimeoutError("provider fixture")

        model = FailingModel(responses=["unused"])
        with telemetry_session(max_llm_calls=1) as stats:
            with self.assertRaises(TimeoutError):
                self.invoke(model)
            with self.assertRaises(LLMQuotaExhaustedError):
                self.invoke(model)
        self.assertEqual(model.attempts, 1)
        self.assertEqual(stats.snapshot()["llm"]["attempted"], 1)
        self.assertEqual(stats.snapshot()["llm"]["failed"], 1)
        self.assertEqual(stats.snapshot()["llm"]["in_flight"], 0)

    def test_recon_success_http_error_and_out_of_scope(self):
        transport = ScopedReconTransport(self.url)
        with telemetry_session() as stats, telemetry_phase("tech_recon"):
            self.assertEqual(transport.fetch(self.url + "/ok")[0], 200)
            self.assertEqual(transport.fetch(self.url + "/missing")[0], 404)
            self.assertIsNone(transport.fetch("https://example.invalid")[0])
        self.assertEqual(_Target.calls, ["/ok", "/missing"])
        self.assertEqual(stats.snapshot()["http"]["total_requests"], 2)
        self.assertEqual(stats.snapshot()["http"]["by_phase"]["tech_recon"]["target"], 2)

    def test_transport_failure_still_counts_attempt_without_fake_response(self):
        transport = ScopedReconTransport(self.url)
        opener = SimpleNamespace(open=lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("fixture")))
        with patch("src.tools.recon_http.build_opener", return_value=opener):
            with telemetry_session() as stats:
                self.assertIsNone(transport.fetch(self.url)[0])
        self.assertEqual(stats.snapshot()["http"]["total_requests"], 1)
        self.assertEqual(_Target.calls, [])

    def test_async_crawl_workers_preserve_context_and_thread_safe_counts(self):
        transport = ScopedReconTransport(self.url)

        async def crawl():
            return await asyncio.gather(*[
                asyncio.to_thread(transport.fetch, self.url + f"/page-{index}")
                for index in range(8)
            ])

        with telemetry_session() as stats, telemetry_phase("tech_recon"):
            responses = asyncio.run(crawl())
        self.assertEqual(len(_Target.calls), 8)
        self.assertTrue(all(status == 200 for status, _, _ in responses))
        self.assertEqual(stats.snapshot()["http"]["total_requests"], 8)

    def test_native_engine_counts_dispatched_not_planned_or_aggregates(self):
        with telemetry_session() as stats, telemetry_phase("fuzzing"):
            result = run_http_fuzzing(self.url, ["ok", "rate", "never"], rate_limit=100)
        self.assertEqual(result["stats"]["total_requests"], 2)
        self.assertEqual(stats.snapshot()["http"]["total_requests"], 2)
        self.assertEqual(_Target.calls, ["/ok", "/rate"])

    def test_proxy_healthcheck_shares_total_but_has_separate_kind(self):
        with telemetry_session() as stats:
            result = run_http_fuzzing(
                self.url, ["ok"], engine="proxy_http", rate_limit=10,
                proxy_profiles=[{"id": "local", "url": self.url}],
                allowed_origins=[self.url], proxy_healthcheck_url=self.url + "/health",
            )
        self.assertEqual(result["stats"]["total_requests"], 2)
        self.assertEqual(stats.snapshot()["http"]["by_kind"], {"proxy_healthcheck": 1, "target": 1})
        self.assertEqual(len(_Target.calls), 2)

    def test_loopback_engine_counts_socket_attempts(self):
        from src.tools.loopback_rotation_lab import run_loopback_rotation_lab
        with telemetry_session() as stats:
            result = run_loopback_rotation_lab(self.url, ["ok"], lab_source_ips=["127.0.0.1"])
        self.assertEqual(result["stats"]["total_requests"], 1)
        self.assertEqual(stats.snapshot()["http"]["total_requests"], 1)
        self.assertEqual(_Target.calls, ["/ok"])

    def test_langgraph_worker_preserves_run_context(self):
        from langgraph.graph import StateGraph, END
        graph = StateGraph(dict)

        def node(state):
            with telemetry_phase("inside_graph"):
                ScopedReconTransport(self.url).fetch(self.url + "/node")
                self.invoke(SimpleNamespace(invoke=lambda value: "fake-model"))
                return sync_state(state)

        graph.add_node("node", node)
        graph.set_entry_point("node")
        graph.add_edge("node", END)
        with telemetry_session() as stats:
            result = graph.compile().invoke({})
        self.assertEqual(result["total_http_requests"], 1)
        self.assertEqual(result["llm_call_count"], 1)
        self.assertEqual(stats.snapshot()["http"]["by_phase"], {"inside_graph": {"target": 1}})

    def test_provider_download_is_separate_from_target(self):
        from src.tools.proxyscrape import fetch_candidates, SOURCE_URL
        response = SimpleNamespace(status=200, geturl=lambda: SOURCE_URL, read=lambda size: b"8.8.8.8:8080\n")
        class ResponseContext:
            def __enter__(self):
                return response

            def __exit__(self, *args):
                return False

        opener = SimpleNamespace(open=lambda *args, **kwargs: ResponseContext())
        with patch("src.tools.proxyscrape.build_opener", return_value=opener):
            with telemetry_session() as stats:
                self.assertEqual(fetch_candidates(), ["http://8.8.8.8:8080"])
        self.assertEqual(stats.snapshot()["http"]["by_kind"], {"proxy_provider": 1})
        self.assertEqual(_Target.calls, [])

    def test_ffuf_is_unknown_with_returned_response_lower_bound(self):
        helper = FfufToolHelper()
        row = {"url": self.url + "/ok", "status": 200, "length": 17,
               "input": {"FUZZ": base64.b64encode(b"ok").decode()}, "duration": 1000}

        def start_process(*args, **kwargs):
            kwargs["stdout"].write(json.dumps(row) + "\n")
            kwargs["stdout"].flush()
            return SimpleNamespace(poll=lambda: 2, wait=lambda timeout: 2)

        with patch("src.tools.ffuf_helper.PROJECT_ROOT", Path(self.directory.name)), \
                patch.object(helper, "resolve_binary", return_value="fixture-ffuf"), \
                patch("src.tools.ffuf_helper.subprocess.Popen", side_effect=start_process):
            with telemetry_session() as stats:
                result = helper.run(target_url=self.url, wordlist=["ok", "missing"], engine="ffuf_cli")
        self.assertFalse(result.success)
        self.assertIsNone(stats.snapshot()["http"]["total_requests"])
        self.assertEqual(stats.snapshot()["http"]["known_requests"], 1)
        self.assertFalse(stats.snapshot()["http"]["count_complete"])
        self.assertEqual(_Target.calls, [])

    def test_unknown_count_retains_known_lower_bound_and_nested_runs_are_isolated(self):
        with telemetry_session() as outer:
            record_http_attempt(count=3)
            with telemetry_session() as inner:
                self.assertIs(current_telemetry(), inner)
                record_http_attempt(count=2)
                mark_http_unknown("fixture")
            self.assertIs(current_telemetry(), outer)
            state = sync_state({})
        self.assertEqual(state["total_http_requests"], 3)
        self.assertEqual(inner.snapshot()["http"]["known_requests"], 2)
        self.assertIsNone(inner.snapshot()["http"]["total_requests"])
        self.assertIsNone(current_telemetry())
        self.assertEqual(sync_state({"llm_call_count": 5}), {"llm_call_count": 5})


if __name__ == "__main__":
    unittest.main()
