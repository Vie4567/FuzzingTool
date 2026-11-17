"""Reproducible offline Coordinator MVP lab: real agents/HTTP, fixture model.

Only the model constructor is replaced. The normal LangGraph, planners, parsers,
tools, verifiers, budgets, telemetry and artifact writers execute unchanged.
This is not evidence of live provider availability or a successful cab.vn scan.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
from unittest.mock import patch
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class LabHandler(BaseHTTPRequestHandler):
    server_version = "CoordinatorMVPLab/1.0"

    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path.startswith("/__mvp_timeout__/"):
            # A real accepted HTTP request with deliberately no response headers.
            # Record receipt independently before the client's timeout expires.
            with self.server.event_lock:
                self.server.events.append({"method": self.command, "path": self.path,
                    "status_code": None, "body_bytes": 0, "response_withheld": True,
                    "received_at": datetime.now(timezone.utc).isoformat()})
            time.sleep(.2)
            self.close_connection = True
            return
        status, content_type = 200, "text/html"
        if parsed.path == "/":
            # Root is intentionally a real HTTP404 with useful public HTML.
            # Recon still parses the response; fuzzing must keep '/' exactly once
            # and classify 404 as a response rather than a network failure.
            status = 404
            body = (b'<html><title>Catalog lab index moved</title><a href="/api/search">Search</a>'
                    b'<script src="/app.js"></script><form action="/api/search" method="GET">'
                    b'<input name="page"></form></html>')
        elif parsed.path == "/api/search":
            content_type = "application/json"
            group = {"1": "first", "2": "second"}.get(query.get("page", [""])[0], "all")
            body = json.dumps({"catalog": group, "items": ["alpha", "beta"],
                               "service": "catalog"}, sort_keys=True).encode()
        elif parsed.path == "/app.js":
            content_type, body = "application/javascript", b'fetch("/api/search?page=1");'
        elif parsed.path == "/robots.txt":
            content_type, body = "text/plain", b"User-agent: *\nAllow: /api/search\n"
        elif parsed.path == "/sitemap.xml":
            content_type, body = "application/xml", b"<urlset><url><loc>/api/search</loc></url></urlset>"
        elif parsed.path in {"/swagger.json", "/openapi.json"}:
            content_type = "application/json"
            body = json.dumps({"openapi": "3.0.0", "info": {"title": "Catalog Lab", "version": "1"},
                "paths": {"/api/search": {"get": {"parameters": [{"name": "page", "in": "query",
                    "schema": {"type": "integer"}}], "responses": {"200": {"description": "catalog"}}}}}}).encode()
        else:
            body = b'<html><title>Application shell</title><div id="root">Missing resource fallback</div></html>'
        with self.server.event_lock:
            self.server.events.append({"method": self.command, "path": self.path,
                "status_code": status, "body_bytes": len(body),
                "received_at": datetime.now(timezone.utc).isoformat()})
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET

    def log_message(self, *_args):
        pass


class FixtureModel:
    """Deterministic text responses only; never manufactures HTTP measurements."""
    def __init__(self):
        self.calls = []

    def respond(self, value):
        from langchain_core.messages import AIMessage
        call = {"index": len(self.calls) + 1, "kind": "unrecognized", "status": "failed"}
        self.calls.append(call)
        messages = value.to_messages() if hasattr(value, "to_messages") else value
        system = str(messages[0].content)
        human = "\n".join(str(message.content) for message in messages[1:])
        if "Developer Habit Profiling" in system:
            kind = "developer_profile"
            answer = {"naming_convention": "snake_case", "url_hierarchy": {
                "style": "resource", "common_prefix": "/api/", "detected_services": []},
                "versioning": "none", "pluralization": "singular", "crud_pattern": "RESTful",
                "common_actions": ["search"], "business_domain": "catalog", "inferred_rules": []}
        elif "JSON array" in system:
            kind, answer = "component_candidates", []
        elif "DANH SÁCH CÔNG CỤ CÓ SẴN" in system:
            kind = "tool_plan"
            names = {"TechReconAgent": "full_7channel_recon_suite", "WordlistGenAgent": "wordlist_generator_tool",
                     "FuzzingAgent": "ffuf_fuzzing_tool", "ParamDiscoveryAgent": "param_discovery_tool"}
            tool = next(tool for agent, tool in names.items() if agent in system)
            answer = {"selected_tool": tool, "options": {}, "is_task_complete": True,
                      "tool_selection_reason": "Offline lab fixture selects the existing module tool.",
                      "options_selection_reason": "Keep explicit operator limits and scope."}
        elif "Justification Report" in system:
            kind, answer = "justification", "Offline fixture: use the measured artifacts as evidence."
        elif "Phiên quét vừa hoàn thành" in human:
            kind = "reflection"
            answer = {"lessons_learned": [], "decision_evaluations": [], "recommendations_for_future": []}
        elif "Coordinator" in system and "- Agent:" in human:
            kind = "coordinator_decision"
            agent = re.search(r"- Agent:\s*(\w+)", human).group(1)
            action = {"tech_recon": "proceed_to_wordlist", "wordlist_gen": "proceed_to_fuzzing",
                      "fuzzing": "proceed_to_param"}[agent]
            answer = {"action": action, "confidence": 1.0,
                      "reasoning": {"analysis": "Fixed lab route; actual results remain measured by tools.",
                                    "factors_considered": ["operator fixture"], "alternatives_evaluated": []},
                      "next_agent_config_adjustments": {}}
        else:
            raise AssertionError("Unrecognized fixture model prompt; refusing provider fallback")
        call.update(kind=kind, status="succeeded")
        return AIMessage(content=answer if isinstance(answer, str) else json.dumps(answer))


@contextmanager
def working_directory(directory):
    previous = Path.cwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous)


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_scenario(directory, *, limited=False, all_timeouts=False):
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.outputs import ChatGeneration, ChatResult
    from src.coordinator import graph

    class LabChatModel(BaseChatModel):
        fixture: Any

        @property
        def _llm_type(self):
            return "offline_coordinator_mvp_fixture"

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            return ChatResult(generations=[ChatGeneration(message=self.fixture.respond(messages))])

    directory.mkdir(parents=True, exist_ok=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    server.events, server.event_lock = [], threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{server.server_port}"
    model = FixtureModel()
    real_connect = socket.socket.connect
    real_socketpair = socket.socketpair
    ipc_context = threading.local()
    internal_ipc_connections = []
    denied_connections = []

    def local_only(sock, address):
        # On Windows asyncio builds its internal wakeup socketpair using a
        # temporary loopback TCP listener. Permit only that scoped IPC call.
        if (getattr(ipc_context, "active", False) and isinstance(address, tuple)
                and address[0] in {"127.0.0.1", "::1"}):
            internal_ipc_connections.append(address[0])
            return real_connect(sock, address)
        if not isinstance(address, tuple) or address[:2] != ("127.0.0.1", server.server_port):
            denied_connections.append(str(address))
            raise AssertionError("Only this lab's loopback HTTP server is allowed")
        return real_connect(sock, address)

    def local_socketpair(*args, **kwargs):
        ipc_context.active = True
        try:
            return real_socketpair(*args, **kwargs)
        finally:
            ipc_context.active = False

    selected_paths = ([f"/__mvp_timeout__/{index}" for index in range(11)] if all_timeouts
                      else ["/", "/api/search", "/missing-page"] if limited
                      else ["/api/search", "/missing-page"])
    config = {
        "api_key": "offline-fixture-not-a-provider-key", "llm_model": "offline-fixture",
        "artifact_root": str(directory), "knowledge_store_dir": str(directory / "knowledge_store"),
        "pipeline_timeout_seconds": 90, "llm_timeout_seconds": 5, "max_llm_calls": 60,
        "max_retries": 0, "max_iterations": 5, "run_all_modules": True,
        "http_max_requests": 120, "http_rate_limit": 100, "http_timeout_seconds": 2,
        "wordlist": selected_paths, "wordlist_mode": "merge", "max_wordlist_entries": len(selected_paths),
        "fuzzing_options": {"engine": "python_http", "threads": 1, "rate_limit": 100, "delay_ms": 0,
            "max_requests": 1 if limited else len(selected_paths),
            "timeout_seconds": .05 if all_timeouts else 2, "max_scan_seconds": 10,
            "headers": {}, "auto_calibrate": False, "recursion": False, "follow_redirects": False},
        "parameter_options": {"enabled": True, "rate_limit": 100, "max_requests": 80, "max_duration_seconds": 30},
        "soft404_options": {"enabled": True, "rate_limit": 100, "max_requests": 15, "max_duration_seconds": 15},
    }
    try:
        with working_directory(directory), patch.dict(os.environ, {"LLM_RESPONSE_LOG_FILE": str(directory / "llm_responses.jsonl")}), \
                patch.object(graph, "ChatOpenAI", return_value=LabChatModel(fixture=model)), \
                patch.object(socket, "socketpair", new=local_socketpair), \
                patch.object(socket.socket, "connect", new=local_only):
            result = graph.run_pipeline(target, config)
        events = list(server.events)
        stats = result.get("fuzzing_stats", {})
        raw = result.get("raw_results", [])
        checks = {
            "http_counter_matches_independent_server": result.get("total_http_requests") == len(events),
            "global_request_budget_respected": len(events) <= 120,
            "mock_llm_counter_matches_independent_model": result.get("llm_call_count") == len(model.calls),
            "mock_llm_budget_respected": len(model.calls) <= 60,
            "no_external_connection_attempts": not denied_connections,
            "selected_matches_operator_limit": result.get("wordlist_metadata", {}).get("selected_count") == len(selected_paths),
            "planned_matches_selected": stats.get("planned_requests") == len(selected_paths),
            "attempted_matches_actual_fuzz_records": stats.get("attempted_requests") == len(raw),
            "responses_match_actual_fuzz_records": stats.get("responses_received") == sum(row.get("status_code") is not None for row in raw),
            "final_checkpoint_equals_returned_state": json.loads(Path(result["artifacts"]["result"]).read_text(encoding="utf-8")) == result,
        }
        if all_timeouts:
            fuzzing_errors = result.get("fuzzing_execution", {}).get("errors", [])
            summaries = [row for row in result.get("error_log", []) if row.get("agent") == "fuzzing"]
            checks.update(
                pipeline_not_completed=result.get("pipeline_status") != "completed",
                fuzzing_failed=result.get("agent_statuses", {}).get("fuzzing") == "failed",
                transport_stop_preserved=result.get("fuzzing_execution", {}).get("stop_reason") == "transport_error",
                execution_not_completed=result.get("fuzzing_execution", {}).get("completed") is False,
                attempted_eleven=stats.get("attempted_requests") == 11,
                received_no_fuzz_responses=stats.get("responses_received") == 0,
                eleven_network_errors=stats.get("network_errors") == 11,
                all_individual_errors_saved=len(fuzzing_errors) == 11,
                summary_error_count_eleven=sum(row.get("count", 1) for row in summaries) == 11,
                all_requests_independently_received=sum(row.get("response_withheld", False) for row in events) == 11,
                remaining_zero=stats.get("remaining_requests") == 0,
            )
        else:
            checks.update(no_fuzz_network_errors=stats.get("network_errors") == 0)
        if limited:
            checks.update(pipeline_partial=result.get("pipeline_status") == "partial",
                          root_fuzzed_exactly_once=sum(row.get("path") == "/" for row in raw) == 1,
                          root_404_is_response=any(row.get("path") == "/" and row.get("status_code") == 404 and not row.get("error") for row in raw),
                          fuzzing_not_success=result.get("agent_statuses", {}).get("fuzzing") != "success",
                          request_stop_preserved=result.get("fuzzing_execution", {}).get("stop_reason") == "max_requests",
                          attempted_one=stats.get("attempted_requests") == 1,
                          remaining_two=stats.get("remaining_requests") == 2)
        elif not all_timeouts:
            checks.update(pipeline_completed=result.get("pipeline_status") == "completed",
                          all_real_modules_executed=result.get("all_modules_executed") is True,
                          all_real_modules_successful=result.get("all_modules_successful") is True,
                          known_parameter_verified=any(p.get("name") == "page" for p in result.get("verified_parameters", [])),
                          fallback_filtered=any(p.get("url", "").endswith("/missing-page") for p in result.get("false_positives", [])),
                          attempted_two=stats.get("attempted_requests") == 2,
                          remaining_zero=stats.get("remaining_requests") == 0)
        save(directory / "result.json", result)
        save(directory / "server_requests.json", events)
        save(directory / "model_calls.json", model.calls)
        evidence = {"success": all(checks.values()), "checks": checks, "target": target,
                    "pipeline_status": result.get("pipeline_status"), "agent_statuses": result.get("agent_statuses"),
                    "http_requests_observed": len(events), "http_requests_reported": result.get("total_http_requests"),
                    "mock_llm_invocations_observed": len(model.calls), "llm_calls_reported": result.get("llm_call_count"),
                    "external_provider_llm_calls": 0, "external_http_connection_attempts": len(denied_connections),
                    "internal_asyncio_ipc_connections": len(internal_ipc_connections),
                    "fuzzing_stats": stats, "wordlist_metadata": result.get("wordlist_metadata"),
                    "limitations": ["LLM responses are deterministic fixtures, not provider responses.",
                                    "In-process Coordinator; supervisor lifecycle is verified by the regression suite.",
                                    "No evidence of cab.vn reachability, token acceptance or public-proxy availability."],
                    "result": str(directory / "result.json")}
        save(directory / "evidence.json", evidence)
        return evidence
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    os.environ.update(PYTHON_DOTENV_DISABLED="1", LANGSMITH_TRACING="false", LANGCHAIN_TRACING_V2="false")
    output = Path(args.output_dir).resolve() if args.output_dir else ROOT / "output_samples/diagnostics" / (
        "coordinator_mvp_lab_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid4().hex[:8])
    output.mkdir(parents=True, exist_ok=False)
    print("Offline MVP lab artifacts:", output, flush=True)
    completed = run_scenario(output / "completed")
    limited = run_scenario(output / "partial_budget", limited=True)
    timeouts = run_scenario(output / "all_timeouts", all_timeouts=True)
    scenarios = [completed, limited, timeouts]
    summary = {"success": all(scenario["success"] for scenario in scenarios),
               "completed_scenario": completed["checks"], "partial_scenario": limited["checks"],
               "all_timeouts_scenario": timeouts["checks"],
               "total_http_requests": sum(scenario["http_requests_observed"] for scenario in scenarios),
               "total_mock_llm_invocations": sum(scenario["mock_llm_invocations_observed"] for scenario in scenarios),
               "external_provider_llm_calls": 0, "output": str(output)}
    save(output / "evidence.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
