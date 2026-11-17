"""
Coordinator v2.0 — LLM-Driven Orchestration module.

Export chính:
    - build_coordinator_graph: Xây dựng LangGraph State Machine
    - run_pipeline: Entry point chạy toàn bộ pipeline
"""

def __getattr__(name):
    if name == "run_pipeline_supervised":
        from .supervisor import run_pipeline_supervised
        return run_pipeline_supervised
    # Agents import coordinator logging while their own modules are loading.
    # Loading graph here eagerly would import those partially initialized agents
    # and could permanently replace the public entry points with None.
    if name in {"build_coordinator_graph", "run_pipeline"}:
        from . import graph

        # Preserve the original ImportError if a runtime dependency is missing
        # or Windows blocks a native extension; never silently return None.
        return getattr(graph, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

from .logger import (
    log_agent_start,
    log_agent_progress,
    log_agent_success,
    log_agent_error,
    log_agent_skip,
    log_decision,
    log_pipeline_summary,
    setup_agent_logger,
)

__all__ = [
    "build_coordinator_graph",
    "run_pipeline",
    "run_pipeline_supervised",
    "log_agent_start",
    "log_agent_progress",
    "log_agent_success",
    "log_agent_error",
    "log_agent_skip",
    "log_decision",
    "log_pipeline_summary",
    "setup_agent_logger",
]
