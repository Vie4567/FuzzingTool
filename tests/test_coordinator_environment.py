"""Compile and run the real Coordinator graph without API calls or target traffic.

Only the five agents and decision engine are fixtures. LangGraph imports,
compilation, routing, state propagation, reporting and the public entry point
are exercised so a missing/blocked runtime dependency cannot silently pass.
"""

from contextlib import ExitStack
from copy import deepcopy
import importlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class CoordinatorEnvironmentTests(unittest.TestCase):
    def _run_fresh_python(self, script, *args):
        # A fresh interpreter catches import-order bugs hidden by sys.modules
        # from tests collected earlier. Block traffic before project imports.
        offline_guard = (
            "import socket\n"
            "def deny_connection(*args, **kwargs):\n"
            "    raise AssertionError('Import smoke tests must stay offline')\n"
            "socket.socket.connect = deny_connection\n"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", offline_guard + script, *args],
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "PYTHON_DOTENV_DISABLED": "1",
                 "PYTHONIOENCODING": "utf-8", "LANGSMITH_TRACING": "false",
                 "LANGCHAIN_TRACING_V2": "false"},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", timeout=45,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_agent_first_import_preserves_public_entry_points(self):
        for module in ("src.agents.base_agent", "src.agents.endpoint_assembler"):
            with self.subTest(first_import=module):
                self._run_fresh_python("""
import importlib
import sys
importlib.import_module(sys.argv[1])
from src.coordinator import build_coordinator_graph, run_pipeline
assert callable(build_coordinator_graph)
assert callable(run_pipeline)
assert callable(build_coordinator_graph().invoke)
""", module)

    def test_blocked_dependency_import_is_reported_instead_of_none(self):
        self._run_fresh_python("""
import importlib.abc
import sys

class BlockNativeDependency(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'ormsgpack':
            raise ImportError('Native dependency blocked: offline regression fixture')

sys.meta_path.insert(0, BlockNativeDependency())
try:
    from src.coordinator import build_coordinator_graph
    build_coordinator_graph()
except ImportError as exc:
    assert 'Native dependency blocked: offline regression fixture' in str(exc), str(exc)
else:
    raise AssertionError('The original dependency ImportError must reach the caller')
""")

    def test_public_entry_points_are_callable(self):
        with patch.dict(os.environ, {"PYTHON_DOTENV_DISABLED": "1"}):
            coordinator = importlib.import_module("src.coordinator")
        self.assertTrue(callable(coordinator.build_coordinator_graph))
        self.assertTrue(callable(coordinator.run_pipeline))

    def test_compiled_pipeline_reaches_report_and_reflection_offline(self):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {
                "PYTHON_DOTENV_DISABLED": "1",
                "LANGSMITH_TRACING": "false",
                "LANGCHAIN_TRACING_V2": "false",
            }))
            stack.enter_context(patch(
                "socket.socket.connect",
                side_effect=AssertionError("The Coordinator smoke test must stay offline"),
            ))
            coordinator = importlib.import_module("src.coordinator")
            graph = importlib.import_module("src.coordinator.graph")
            self.assertTrue(callable(coordinator.run_pipeline))
            temporary = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            target = "http://127.0.0.1:9"
            events = []
            decisions = []
            sample_response = {
                "url": target + "/fixture",
                "path": "/fixture",
                "status_code": 200,
                "content_length": 7,
                "response_time": 0.01,
            }
            actions = {
                "after_tech_recon": "proceed_to_wordlist",
                "after_wordlist_gen": "proceed_to_fuzzing",
                "after_fuzzing": "proceed_to_param",
            }

            def decide(**kwargs):
                decisions.append(kwargs["decision_point"])
                return {"action": actions[kwargs["decision_point"]],
                        "reasoning": "Offline test fixture"}

            def reflect(state):
                events.append("reflection")
                self.assertIsNotNone(state["finished_at"])
                self.assertEqual(state["audit_log"][-1]["type"], "report_generated")

            engine = SimpleNamespace(llm=None, make_decision=Mock(side_effect=decide),
                                     reflect_on_session=Mock(side_effect=reflect))
            stack.enter_context(patch.object(graph, "_get_decision_engine", return_value=engine))
            # run_pipeline resets globals; restore them after this isolated test.
            stack.enter_context(patch.object(graph, "_decision_engine", None))
            for name in ("circuit_breakers", "llm_limiter", "tarpit_detector"):
                stack.enter_context(patch.object(graph, name, deepcopy(getattr(graph, name))))
            stack.enter_context(patch.object(graph, "log_decision"))
            stack.enter_context(patch.object(graph, "log_pipeline_summary"))
            compile_graph = stack.enter_context(patch.object(
                graph, "build_coordinator_graph", wraps=graph.build_coordinator_graph,
            ))
            public_options = graph.FuzzingAgent._public_options
            fixtures = {
                "TechReconAgent": {"tech_stack": {"server": "fixture"},
                                   "discovered_paths": ["/fixture"]},
                "WordlistGenAgent": {"wordlist": ["/fixture"], "metadata": {"count": 1}},
                "FuzzingAgent": {"results": [sample_response], "success": True,
                                 "partial": False, "simulated": True,
                                 "engine": "offline_test_fixture", "stop_reason": "completed",
                                 "stats": {"total_requests": 1, "avg_response_time": 0.01}},
                "ParamDiscoveryAgent": {"param_results": []},
                "Soft404FilterAgent": {"verified": [], "unverified": [sample_response],
                                       "verification_performed": False,
                                       "verification_status": "not_implemented"},
            }
            agents = {}
            for name, payload in fixtures.items():
                agent = stack.enter_context(patch.object(graph, name, autospec=True))

                def execute(*args, _name=name, _payload=payload, **kwargs):
                    events.append(_name)
                    return deepcopy(_payload)

                agent.return_value.execute.side_effect = execute
                agents[name] = agent.return_value
                if name == "FuzzingAgent":
                    agent._public_options.side_effect = public_options

            result = coordinator.run_pipeline(target, config={
                "knowledge_store_dir": str(temporary / "knowledge"),
                "fuzzing_options": {"engine": "python_http", "max_requests": 1},
            })

            compile_graph.assert_called_once_with()
            self.assertEqual(events, list(fixtures) + ["reflection"])
            self.assertEqual(decisions, list(actions))
            self.assertEqual(result["error_log"], [])
            self.assertEqual(result["agent_statuses"], {
                "validate": "success", "tech_recon": "success",
                "wordlist_gen": "success", "fuzzing": "success",
                "param_disc": "skipped", "soft404_filter": "skipped",
            })
            self.assertEqual(result["wordlist"], ["/fixture"])
            self.assertEqual(result["raw_results"], [sample_response])
            self.assertEqual(result["unverified_results"], [sample_response])
            self.assertEqual(result["verification_status"], "not_implemented")
            self.assertTrue(result["session_id"])
            self.assertTrue(result["finished_at"])
            self.assertEqual(result["audit_log"][-1]["type"], "report_generated")
            self.assertEqual(agents["FuzzingAgent"].execute.call_args.kwargs["wordlist"],
                             ["/fixture"])
            self.assertEqual(agents["ParamDiscoveryAgent"].execute.call_args.kwargs["endpoints"],
                             [sample_response])
            engine.reflect_on_session.assert_called_once()


if __name__ == "__main__":
    unittest.main()
