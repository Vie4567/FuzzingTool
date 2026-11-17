"""Offline Agent 1 -> Coordinator -> Agent 2 evidence with real localhost HTTP.

Executes the existing Coordinator nodes, transport, parsers, Wordlist Generator,
shared limits and checkpoint writer. Only LLM output is a deterministic fixture.
This scoped handoff lab is not a full five-agent LangGraph completion claim.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


def _save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def run_scenario(directory, scenario):
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.outputs import ChatGeneration, ChatResult

    from scripts.run_coordinator_mvp_lab import FixtureModel, working_directory
    from src.coordinator import graph
    from src.coordinator.artifacts import RunArtifacts
    from src.coordinator.runtime import runtime_session
    from src.coordinator.telemetry import sync_state, telemetry_session
    from test_recon_p0_integration import local_recon_fixture

    class LabModel(BaseChatModel):
        fixture: Any

        @property
        def _llm_type(self):
            return "offline_recon_p0_fixture"

        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            message = self.fixture.respond(messages)
            return ChatResult(generations=[ChatGeneration(message=message)])

    directory.mkdir(parents=True, exist_ok=False)
    model = FixtureModel()
    config = {
        "artifact_root": str(directory), "knowledge_store_dir": str(directory / "knowledge_store"),
        "pipeline_timeout_seconds": 60, "http_max_requests": 40,
        "http_rate_limit": 100, "http_timeout_seconds": 1,
        "http_max_response_bytes": 256 * 1024, "max_llm_calls": 40,
        "max_retries": 0, "max_iterations": 5, "max_wordlist_entries": 5,
        "fuzzing_options": {"engine": "python_http"},
    }
    mode = {"completed": "completed", "partial": "disconnect_js", "failed": "disconnect_home"}[scenario]
    with local_recon_fixture(mode) as fixture:
        state = {"target_url": fixture.target, "config": config,
                 "agent_statuses": {}, "audit_log": [], "error_log": [],
                 "pipeline_status": "partial", "lab_scope": "Agent1-Coordinator-Agent2 only"}
        artifacts = RunArtifacts(config)
        active = {"artifacts": artifacts, "state": state, "node": "lab"}
        token = graph._active_run.set(active)
        try:
            with working_directory(directory), \
                    patch.dict(os.environ, {"LLM_RESPONSE_LOG_FILE": str(directory / "llm_responses.jsonl")}), \
                    patch.object(graph, "_get_decision_engine", return_value=SimpleNamespace(llm=LabModel(fixture=model))), \
                    patch.object(graph, "circuit_breakers", deepcopy(graph.circuit_breakers)), \
                    telemetry_session(max_llm_calls=config["max_llm_calls"]), runtime_session(config):
                state = graph.validate_input(state)
                if state["agent_statuses"].get("validate") != "success":
                    raise AssertionError("Offline lab configuration did not pass existing validation")
                state = graph.init_state(state)
                state = graph.run_tech_recon(state)
                before_wordlist = len(fixture.primary.events)
                if state["agent_statuses"]["tech_recon"] in {"success", "partial"}:
                    state = graph.run_wordlist_gen(state)
                else:
                    state["agent_statuses"]["wordlist_gen"] = "skipped"
                state = graph.generate_report(state)
                sync_state(state)
                saved = artifacts.save(state, node="agent1_handoff_lab", event="finished")
        finally:
            graph._active_run.reset(token)

        events = list(fixture.primary.events)
        profile = saved.get("recon_profile", {})
        execution = saved.get("recon_execution", {})
        stats = execution.get("stats", {})
        counts = saved.get("wordlist_metadata", {}).get("recon_context", {})
        checks = {
            "expected_recon_status": execution.get("status") == scenario,
            "agent_status_agrees_with_recon": saved["agent_statuses"]["tech_recon"] == (
                "success" if scenario == "completed" else scenario),
            "http_attempts_match_server": stats.get("attempted_requests") == len(events),
            "http_responses_match_server": stats.get("responses_received") == sum(e["status_code"] is not None for e in events),
            "network_errors_match_server": stats.get("network_errors") == sum(e["status_code"] is None for e in events),
            "global_telemetry_matches_server": saved.get("total_http_requests") == len(events),
            "global_http_budget_preserved": len(events) <= config["http_max_requests"],
            "model_count_matches_fixture": saved.get("llm_call_count") == len(model.calls),
            "model_budget_preserved": len(model.calls) <= config["max_llm_calls"],
            "wordlist_did_not_make_http_calls": before_wordlist == len(events),
            "no_external_connection_attempts": not fixture.rejected,
            "no_foreign_origin_requests": not fixture.secondary.events,
            "ordinary_server_not_waf": saved.get("waf_detected") is False,
            "target_preserved_in_profile": profile.get("target_url") == fixture.target,
            "final_artifact_matches_returned_state": json.loads(Path(saved["artifacts"]["result"]).read_text(encoding="utf-8")) == saved,
            "checkpoint_exists": Path(saved["artifacts"]["checkpoint"]).is_file(),
        }
        if scenario == "failed":
            checks.update(
                homepage_failure_stops_after_one_attempt=len(events) == 1,
                wordlist_skipped=saved["agent_statuses"]["wordlist_gen"] == "skipped",
                failed_errors_retained=bool(execution.get("errors")),
            )
        else:
            checks.update(
                backend_not_overwritten=saved.get("tech_stack", {}).get("backend", "").lower() in {"asp.net", "asp_net"},
                frontend_preserved=saved.get("tech_stack", {}).get("frontend", "").lower() == "react",
                language_remains_unknown=saved.get("tech_stack", {}).get("language") == "Unknown",
                technology_evidence_retained=bool(profile.get("technology_evidence")),
                form_fields_preserved=any({"term", "category", "note"} <= set(form.get("params", [])) for form in profile.get("forms", [])),
                schema_parameter_preserved=any(row.get("name") == "page" for row in profile.get("parameters", [])),
                wordlist_executed=saved["agent_statuses"]["wordlist_gen"] == "success",
                target_passed_to_wordlist=counts.get("target_url") == fixture.target,
                candidate_classification_preserved=counts.get("classification") == "candidate_generation_only",
            )
        if scenario == "partial":
            checks.update(partial_errors_retained=bool(execution.get("errors")),
                          partial_not_success=execution.get("success") is False)
        _save(directory / "result.json", saved)
        _save(directory / "server_requests.json", events)
        _save(directory / "model_calls.json", model.calls)
        evidence = {
            "success": all(checks.values()), "scenario": scenario, "checks": checks,
            "http_requests_observed": len(events), "http_requests_reported": saved.get("total_http_requests"),
            "fixture_llm_calls_observed": len(model.calls), "llm_calls_reported": saved.get("llm_call_count"),
            "external_provider_llm_calls": 0, "external_connection_attempts": len(fixture.rejected),
            "recon_execution": execution, "agent_statuses": saved["agent_statuses"],
            "limits": config, "result": str(directory / "result.json"),
            "limitations": ["Two existing Coordinator execution nodes only; not the full five-agent graph.",
                            "LLM responses are fixtures; all target HTTP requests use the local fixture.",
                            "Lab bounds public probes and crawler through the shared test fixture."],
        }
        _save(directory / "evidence.json", evidence)
        return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    os.environ.update(PYTHON_DOTENV_DISABLED="1", LANGSMITH_TRACING="false", LANGCHAIN_TRACING_V2="false")
    output = Path(args.output_dir).resolve() if args.output_dir else ROOT / "output_samples/diagnostics" / (
        "agent1_p0_lab_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid4().hex[:8])
    output.mkdir(parents=True, exist_ok=False)
    print("Offline Agent 1 P0 lab artifacts:", output, flush=True)
    results = [run_scenario(output / scenario, scenario) for scenario in ("completed", "partial", "failed")]
    source_paths = ["src/agents/tech_recon.py", "src/tools/recon_http.py", "src/tools/tech_fingerprints.py",
                    "src/tools/recon_records.py", "src/tools/recon_observations.py", "src/tools/registry.py",
                    "src/coordinator/graph.py", "src/coordinator/state.py", "src/agents/wordlist_gen.py",
                    "tests/test_recon_p0_integration.py", "scripts/run_recon_p0_lab.py"]
    _save(output / "source_manifest.json", {name: sha256((ROOT / name).read_bytes()).hexdigest()
                                           for name in source_paths if (ROOT / name).is_file()})
    summary = {"success": all(row["success"] for row in results),
               "total_http_requests": sum(row["http_requests_observed"] for row in results),
               "total_fixture_llm_calls": sum(row["fixture_llm_calls_observed"] for row in results),
               "external_provider_llm_calls": 0,
               "scenarios": [{"scenario": row["scenario"], "success": row["success"],
                              "failed_checks": [key for key, value in row["checks"].items() if not value]}
                             for row in results], "output": str(output)}
    _save(output / "evidence.json", summary)
    report = ["# Agent 1 P0 localhost handoff lab", "", "Existing Coordinator nodes: TechRecon -> WordlistGen.",
              "Real local HTTP; fixture model; this is not a full five-agent pipeline run.", "",
              "| Scenario | PASS | HTTP | Fixture LLM calls |", "|---|---|---:|---:|"]
    report.extend(f"| {row['scenario']} | {row['success']} | {row['http_requests_observed']} | {row['fixture_llm_calls_observed']} |" for row in results)
    report.extend(["", "See evidence.json, per-scenario server_requests.json, model_calls.json, result.json and node checkpoints.",
                   "No public target or provider API calls. Sources are hashed in source_manifest.json."])
    (output / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
