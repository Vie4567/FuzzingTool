"""Private, single-use loopback execution context for existing graph nodes.

B3.2B optionally reconciles a durable session before this context can dispatch.
B4.2A optionally (`parameter_verification=True`, Python only) runs Agent 4 after
Agent 3 so probe recovery can be tested; Agent 5 is bypassed unless B4.2B
`soft404_verification=True` runs it. B4.2C: with both enabled the same compiled
graph runs Agents 1-5, a deterministic per-origin Report and a deterministic
Reflection (no LLM, no KnowledgeStore). Decisions are pure functions of the
state at their own decision point; a resume reuses journal-proven decisions.
`finalize_only=True` (resume only) rebuilds Report/Reflection from proven
evidence with zero new HTTP. Not a production gate, scheduler or LLM provider.
Secret profiles remain here and in the B1 transport, never in the SharedState config.
"""
from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
from threading import Lock
from urllib.parse import urlsplit
from uuid import uuid4

from langchain_core.callbacks import BaseCallbackHandler

from .origins import canonical_origin, origin_state, merge_discovery_context, public_url
from .origin_report import (AGENTS, build_reflection, build_report, global_agent_status,
                            origin_agent_status)
from .runtime import current_runtime, PipelineStopped
from ..tools.origin_scope import OriginScopePolicy, OriginScopedTransport, OriginCredentialContext
from ..tools.origin_parameters import ParameterProbeTransport
from ..tools.origin_soft404 import Soft404ProbeTransport

# B4.2C D8: only these preconditions (raised before any publish/reservation) are contract
# failures. Resume-integrity errors, reruns and programming errors are never caught.
CONTRACT_ERRORS = {
    "param_disc": {
        "B4.1 requires the B1/B3.1 SharedState contract": "parameter_contract_origin_state_missing",
        "Configure per-origin quotas for approved origins before starting the shared runtime":
            "parameter_contract_quota_mismatch",
        "policy_snapshot_mismatch": "parameter_contract_policy_snapshot_mismatch",
        "B4.1 requires a completed B3.1 dispatch call": "parameter_contract_dispatch_missing"},
    "soft404_filter": {
        "B4.2B requires the B1/B3.1 SharedState contract": "soft404_contract_origin_state_missing",
        "Configure per-origin quotas for approved origins before starting the shared runtime":
            "soft404_contract_quota_mismatch",
        "policy_snapshot_mismatch": "soft404_contract_policy_snapshot_mismatch",
        "B4.2B requires a completed B3.1 dispatch call": "soft404_contract_dispatch_missing"}}
_SECTION_KEY = {"param_disc": "parameter_discovery", "soft404_filter": "soft404"}
_EXECUTED = {"success", "partial", "failed", "interrupted"}


def loopback_url(url):
    url = public_url(url)
    try:
        address = ipaddress.ip_address(urlsplit(url).hostname)
    except ValueError:
        raise ValueError("Local graph requires literal loopback IPs; DNS names are denied") from None
    if not address.is_loopback or getattr(address, "ipv4_mapped", None) is not None:
        raise ValueError("Local graph requires literal loopback IPs")
    return url


def _closed(transport):
    # B4.2C finalize_only: an independent layer from runtime.stop_reason and the journal.
    if getattr(transport, "dispatch_closed", False):
        raise ValueError("finalize_only_no_dispatch")


class _LoopbackTransport(OriginScopedTransport):
    def check_dispatch(self, url, method):
        _closed(self)
        loopback_url(url)
        return super().check_dispatch(url, method)


class _LoopbackProbeTransport(ParameterProbeTransport):
    def check_dispatch(self, url, method):
        _closed(self)
        loopback_url(url)
        return super().check_dispatch(url, method)


class _LoopbackSoft404Transport(Soft404ProbeTransport):
    def check_dispatch(self, url, method):
        _closed(self)
        loopback_url(url)
        return super().check_dispatch(url, method)


class _GraphTrace(BaseCallbackHandler):
    """Record actual LangGraph callback events, not a predicted node sequence."""
    raise_error = True

    def __init__(self, owner):
        self.owner, self.pending = owner, {}

    def on_chain_start(self, serialized, inputs, *, run_id, **kwargs):
        node = (kwargs.get("metadata") or {}).get("langgraph_node")
        if node and kwargs.get("name") == node:
            self.pending[run_id] = node
            self.owner.callback_events.append(self.owner.event(node, "start"))

    def on_chain_end(self, outputs, *, run_id, **kwargs):
        node = self.pending.pop(run_id, None)
        if node:
            self.owner.callback_events.append(self.owner.event(node, "end"))

    def on_chain_error(self, error, *, run_id, **kwargs):
        node = self.pending.pop(run_id, None)
        if node:
            self.owner.callback_events.append(self.owner.event(node, "error"))


class LocalOriginTest:
    """Local compiled Coordinator tests; recovery requires a fresh private context."""
    NODES = {"validate_input", "init_state", "run_tech_recon", "llm_decide_after_recon",
             "run_wordlist_gen", "llm_decide_after_wordlist", "run_fuzzing",
             "llm_decide_after_fuzzing", "generate_report", "post_session_reflection"}
    EXECUTION = {"run_tech_recon": "tech_recon", "run_wordlist_gen": "wordlist_gen", "run_fuzzing": "fuzzing"}

    def __init__(self, target_url, *, scope, documents, origin_max_requests, credential_profiles=None,
                 recovery_directory=None, resume=False, parameter_verification=False, parameter_max_requests=200,
                 soft404_verification=False, soft404_max_requests=200, finalize_only=False):
        self.target = loopback_url(target_url)
        self.policy = OriginScopePolicy(scope)
        for origin in self.policy.public_config()["approved_origins"]:
            loopback_url(origin)
        if canonical_origin(self.target) not in self.policy.public_config()["approved_origins"]:
            raise ValueError("Target is not approved")
        if not isinstance(documents, list) or not 1 <= len(documents) <= 64:
            raise ValueError("Local graph needs an explicit document plan")
        self.documents = deepcopy(documents)
        for row in self.documents:
            if not isinstance(row, dict) or set(row) - {"url", "kind", "document_url"}:
                raise ValueError("Invalid local document plan")
            if row.get("kind") not in {"html", "javascript", "openapi"}:
                raise ValueError("Invalid local document kind")
            self.policy.check(loopback_url(row.get("url")), "GET")
            if "document_url" in row:
                loopback_url(row["document_url"])
        # Validate quotas without creating a second runtime/session.
        if (not isinstance(origin_max_requests, dict)
                or set(origin_max_requests) != set(self.policy.public_config()["approved_origins"])
                or any(type(n) is not int or not 0 <= n <= 10000 for n in origin_max_requests.values())):
            raise ValueError("Explicit nonnegative quotas required for every approved origin")
        self.quotas = dict(origin_max_requests)
        self._profiles = deepcopy(credential_profiles or {})
        credentials = OriginCredentialContext(self.policy, self._profiles)
        self.transport = _LoopbackTransport(self.target, policy=self.policy, credentials=credentials)
        self.runtime_id = uuid4().hex
        self._runtime, self._used, self._visited = None, False, set()
        self._lock = Lock()
        self.callback_events = []
        self.callback = _GraphTrace(self)
        from .origin_recovery import RecoveryJournal
        if resume and recovery_directory is None:
            raise ValueError("Resume requires an explicit recovery directory")
        self.recovery = RecoveryJournal(recovery_directory, resume=resume) if recovery_directory is not None else None
        if type(parameter_verification) is not bool:
            raise ValueError("parameter_verification must be a boolean")
        if type(parameter_max_requests) is not int or not 1 <= parameter_max_requests <= 10000:
            raise ValueError("parameter_max_requests must be an integer in 1..10000")
        if type(soft404_verification) is not bool:
            raise ValueError("soft404_verification must be a boolean")
        if type(soft404_max_requests) is not int or not 1 <= soft404_max_requests <= 10000:
            raise ValueError("soft404_max_requests must be an integer in 1..10000")
        if type(finalize_only) is not bool:
            raise ValueError("finalize_only must be a boolean")
        if finalize_only and not (resume and self.recovery is not None):
            raise ValueError("finalize_only requires resume with an explicit recovery directory")
        self.finalize_only = finalize_only
        self._skipped = {}  # node -> non-completion label (finalize_skipped | global_stop_skipped)
        if self.recovery is not None:
            self.recovery.finalize_only = finalize_only
        self.parameter_verification = parameter_verification
        self.parameter_max_requests = parameter_max_requests
        self.soft404_verification = soft404_verification
        self.soft404_max_requests = soft404_max_requests
        self.full_graph = parameter_verification and soft404_verification
        self.soft404_transport = None
        if soft404_verification:
            # Same policy and private credentials; controls need explicit soft404_controls.
            self.NODES = self.NODES | {"llm_decide_after_fuzzing", "run_soft404_filter"}
            self.EXECUTION = {**self.EXECUTION, "run_soft404_filter": "soft404_filter"}
            self.soft404_transport = _LoopbackSoft404Transport(self.target, policy=self.policy, credentials=credentials)
            if self.recovery is not None:
                self.recovery.soft404_probes = True
        self.probe_transport = None
        if parameter_verification:
            # Same policy and private credential context; probes add no authority.
            self.NODES = self.NODES | {"run_param_discovery", "llm_decide_after_fuzzing", "run_soft404_filter"}
            self.EXECUTION = {**self.EXECUTION, "run_param_discovery": "param_disc"}
            self.probe_transport = _LoopbackProbeTransport(self.target, policy=self.policy, credentials=credentials)
            if self.recovery is not None:
                self.recovery.parameter_probes = True

    def close_dispatch(self):
        """finalize_only: every transport refuses dispatch, whatever the budget or stop state."""
        for transport in (self.transport, self.probe_transport, self.soft404_transport):
            if transport is not None:
                transport.dispatch_closed = True

    def finished_result(self, finished):
        """D7: the journal-verified final result of a finished session; nothing is re-executed."""
        result = deepcopy(finished["result"])
        result.pop("artifacts", None)
        result["recovery"] = {**(result.get("recovery") or {}), "status": "already_finished",
                              "final_checkpoint": finished["checkpoint"], "final_checkpoint_sha256": finished["sha256"],
                              "journal_sequence": finished["journal_sequence"], "graph_invoked": False,
                              "agents_invoked": False, "journal_appended": False, "exactly_once_delivery": False}
        return result

    def completion_event(self, node):
        # A finalize-skipped node is never recorded as a completed (reusable) node.
        return self._skipped.get(node, "checkpoint")

    def artifact_config(self, config):
        # Profile IDs/origin labels are public contract data, not secret values.
        return {**config, "credentials": [p["headers"] for p in self._profiles.values()]}

    def configure(self, target, config):
        with self._lock:
            if self._used:
                raise ValueError("Local graph context is single-use; recovery requires a fresh context")
            self._used = True
        allowed = {"multi_origin", "artifact_root", "output_dir", "pipeline_timeout_seconds",
                   "llm_timeout_seconds", "max_retries", "max_iterations", "max_llm_calls",
                   "http_rate_limit", "http_max_requests", "http_timeout_seconds", "http_max_response_bytes",
                   "run_all_modules", "llm_max_tokens", "max_wordlist_entries", "fuzzing_options", "wordlist_mode"}
        if (target != self.target or set(config) - allowed
                or config.get("multi_origin") != self.policy.public_config()
                or config.get("fuzzing_options") != {"engine": "python_http"}
                or config.get("wordlist_mode") != "generated"
                or config.get("max_retries") != 0 or config.get("run_all_modules")):
            raise ValueError("Local graph requires explicit Python HTTP scope, zero retries, no proxy/auth/provider config")
        return {**config, "http_origin_max_requests": dict(self.quotas)}

    def event(self, node, event):
        runtime = current_runtime()
        return {"node": node, "event": event, "runtime_id": self.runtime_id,
                "http_dispatches": runtime.requests if runtime else None,
                "utc": datetime.now(timezone.utc).isoformat()}

    def enter_node(self, state, node):
        runtime = current_runtime()
        if not self._used or runtime is None or node not in self.NODES or node in self._visited:
            raise ValueError("Local graph node replay or unsupported execution denied")
        if self._runtime is None:
            self._runtime = runtime
        if self._runtime is not runtime or runtime.origin_limits != self.quotas:
            raise ValueError("Local graph runtime identity or quota changed")
        self._visited.add(node)
        mode = ("localhost_agents_1_to_5" if self.soft404_verification and self.parameter_verification
                else "localhost_agents_1_3_5" if self.soft404_verification
                else "localhost_agents_1_to_4" if self.parameter_verification else "localhost_three_agents")
        local = state.setdefault("local_origin_execution", {"mode": mode,
            "runtime_id": self.runtime_id, "node_trace": [], "agent_artifacts": {},
            "llm_mode": "disabled_deterministic_routing", "full_pipeline_enabled": False})
        if local["runtime_id"] != self.runtime_id:
            raise ValueError("Checkpoint belongs to another local run")
        if self.full_graph:
            local["graph_integration"] = "local_full_graph_b42c"
        local["node_trace"].append(self.event(node, "started"))

    def reuse_node(self, state, node):
        if self.parameter_verification and not self.soft404_verification and node == "run_soft404_filter":
            return True  # Agent 5 is not part of B4.2A: bypassed, never executed or counted.
        if self.recovery and self.recovery.reuse(state, node):
            return True
        skips = (state.get("local_origin_execution") or {}).get("routing_skips") or {}
        if node == "run_soft404_filter" and skips.get("soft404_filter"):
            state["agent_statuses"]["soft404_filter"] = "skipped"  # D8: upstream contract failure
            return True
        if self.finalize_only and node in self.EXECUTION:
            # D6: never invoke an Agent; its section (if any) was reconciled from the journal.
            agent = self.EXECUTION[node]
            state["agent_statuses"][agent] = ("interrupted" if state.get("agent_attempts", {}).get(agent)
                                              else "not_started")
            self._skipped[node] = "finalize_skipped"
            return True
        if self.full_graph and node in self.EXECUTION:
            try:
                current_runtime().check()
            except PipelineStopped:
                # A global stop (e.g. 429 in Agent 4) reaches Agent 5 through the static edge: do not
                # start it, keep the stop, and continue to Report instead of failing the whole graph.
                state["agent_statuses"][self.EXECUTION[node]] = "not_started"
                self._skipped[node] = "global_stop_skipped"
                return True
        return False

    def continuing_node(self, node):
        return bool(self.recovery and self.recovery.restored
                    and node in {"run_fuzzing", "run_param_discovery", "run_soft404_filter"})

    def saved_checkpoint(self, public, node, event):
        if self.recovery and self.recovery.runtime:
            self.recovery.checkpoint(public, node, event)

    def leave_node(self, state, node, completed):
        skips = (state.get("local_origin_execution") or {}).get("routing_skips") or {}
        label = ("bypassed_not_enabled" if self.parameter_verification and not self.soft404_verification
                 and node == "run_soft404_filter"
                 else self._skipped[node] if node in self._skipped
                 else "skipped_upstream_contract_failure" if node == "run_soft404_filter" and skips.get("soft404_filter")
                 else "checkpoint" if completed else "interrupted")
        state["local_origin_execution"]["node_trace"].append(self.event(node, label))
        if self.recovery:
            state["local_origin_execution"]["langgraph_trace"] = deepcopy(self.callback_events)
        if not completed and node in self.EXECUTION:
            state["agent_statuses"][self.EXECUTION[node]] = "failed"

    def validate(self, state):
        if state["config"]["multi_origin"] != self.policy.public_config():
            raise ValueError("Local graph policy changed")
        state.update(origin_state(state["target_url"], state["config"]["multi_origin"]))

    def initialize(self, state):
        for agent in ("param_disc", "soft404_filter"):
            state["agent_statuses"][agent] = "skipped"
        state.update(all_modules_executed=False, all_modules_successful=False)
        self._origin_statuses(state)
        return state

    @staticmethod
    def _origin_statuses(state):
        for entry in state["origin_contexts"].values():
            for agent in ("param_disc", "soft404_filter"):
                entry["agent_statuses"][agent] = "skipped"
            # A three-agent stage can never mark the full origin pipeline completed.
            entry["status"] = "partial" if any(entry["agent_statuses"].get(k) in {"success", "partial", "failed"}
                    for k in ("tech_recon", "wordlist_gen", "fuzzing")) else "pending"

    def recon(self, state, agent_class):
        state["agent_statuses"]["tech_recon"] = "running"
        result = agent_class(llm=None).collect_discovery(state["target_url"], self.documents, transport=self.transport)
        merge_discovery_context(state, result["discovery_context"])
        for key in ("tech_stack", "recon_profile", "discovered_paths"):
            state[key] = deepcopy(result[key])
        state["recon_execution"] = deepcopy(result["execution"])
        state["recon_http_policy"] = result["http_policy"]
        state["agent_statuses"]["tech_recon"] = "success" if result["execution"]["status"] == "completed" else result["execution"]["status"]
        self._origin_statuses(state)
        return state

    def wordlist(self, state, agent_class):
        state["agent_statuses"]["wordlist_gen"] = "running"
        result = agent_class(llm=None).generate_from_discovery(state,
            max_wordlist_entries=state["config"].get("max_wordlist_entries", 6),
            artifact_root=state["config"].get("artifact_root") or state["config"].get("output_dir"))
        state["local_origin_execution"]["agent_artifacts"]["wordlist_gen"] = result["artifacts"]
        state["agent_statuses"]["wordlist_gen"] = "success"
        for entry in state["origin_contexts"].values():
            if (entry.get("context") or {}).get("wordlist") is not None:
                entry["agent_statuses"]["wordlist_gen"] = "success"
        self._origin_statuses(state)
        return state

    def fuzzing(self, state, agent_class):
        state["agent_statuses"]["fuzzing"] = "running"
        result = agent_class(llm=None).dispatch_selected(state, transport=self.transport,
            artifact_root=state["config"].get("artifact_root") or state["config"].get("output_dir"))
        state["local_origin_execution"]["agent_artifacts"]["fuzzing"] = result["artifacts"]
        status = state["fuzzing_execution"]["multi_origin"]["status"]
        state["agent_statuses"]["fuzzing"] = "success" if status == "completed" else status
        self._origin_statuses(state)
        return state

    def _default_stop(self):
        if self.finalize_only:
            return "finalize_only"  # only when no original stop reason was recorded
        if self.full_graph:
            return "local_full_graph_incomplete"
        if self.soft404_verification:
            return "local_soft404_stage_only"
        return "local_parameter_stage_only" if self.parameter_verification else "local_three_agent_only"

    def _agent_status(self, state, agent):
        """Global status from per-origin sections; an all-skipped Agent is `skipped`, never success."""
        values = [origin_agent_status(state["origin_contexts"].get(o) or {}, agent, ("not_started", None))[0]
                  for o in state.get("approved_origins", [])]
        return global_agent_status(values, True, ("not_started", None))

    def _contract(self, state, agent, run):
        """D8: a listed precondition failure (before any reservation) fails the Agent, not the graph."""
        runtime, key = current_runtime(), _SECTION_KEY[agent]
        before = runtime.requests
        try:
            return run()
        except ValueError as exc:
            code = CONTRACT_ERRORS[agent].get(str(exc))
            if (code is None or runtime.requests != before
                    or any(key in ((e or {}).get("context") or {}) for e in state.get("origin_contexts", {}).values())):
                raise
        local = state["local_origin_execution"]
        local.setdefault("contract_failures", {})[agent] = code
        if agent == "param_disc" and self.soft404_verification:
            local.setdefault("routing_skips", {})["soft404_filter"] = "upstream_contract_failure"
        state["agent_statuses"][agent] = "failed"
        execution = "parameter_execution" if agent == "param_disc" else "soft404_execution"
        state.setdefault(execution, {})["multi_origin"] = {
            "stage": "B4.2C", "status": "failed", "stop_reason": code, "contract_failure": True,
            "http_dispatches_this_call": 0, "full_multi_origin_execution_enabled": False,
            "langgraph_integration": "local_full_graph_b42c" if self.full_graph else "local_contract_failure"}
        state.setdefault("audit_log", []).append({"type": "agent_contract_failure", "agent": agent, "reason": code})
        state.setdefault("error_log", []).append({"agent": agent, "error_type": "contract_failure", "error": code})
        return None

    def soft404(self, state, agent_class):
        """B4.2B Agent 5 on the same runtime, policy and private credentials."""
        if not self.soft404_verification:
            raise ValueError("Local graph Soft404 stage is not enabled")
        state["agent_statuses"]["soft404_filter"] = "running"
        result = self._contract(state, "soft404_filter", lambda: agent_class(llm=None).verify_origin_soft404(
            state, transport=self.soft404_transport,
            artifact_root=state["config"].get("artifact_root") or state["config"].get("output_dir"),
            max_requests=self.soft404_max_requests))
        if result is None:
            return state
        state["local_origin_execution"]["agent_artifacts"]["soft404_filter"] = result["artifacts"]
        state["soft404_execution"]["multi_origin"]["langgraph_integration"] = (
            "local_full_graph_b42c" if self.full_graph else "local_soft404_stage_b42b")
        state["agent_statuses"]["soft404_filter"] = self._agent_status(state, "soft404_filter")
        return state

    def parameters(self, state, agent_class):
        """B4.2A Agent 4 on the same runtime, policy and private credentials."""
        if not self.parameter_verification:
            raise ValueError("Local graph parameter stage is not enabled")
        state["agent_statuses"]["param_disc"] = "running"
        result = self._contract(state, "param_disc", lambda: agent_class(llm=None).verify_origin_parameters(
            state, transport=self.probe_transport,
            artifact_root=state["config"].get("artifact_root") or state["config"].get("output_dir"),
            max_requests=self.parameter_max_requests))
        if result is None:
            return state
        state["local_origin_execution"]["agent_artifacts"]["param_disc"] = result["artifacts"]
        state["parameter_execution"]["multi_origin"]["langgraph_integration"] = (
            "local_full_graph_b42c" if self.full_graph else "local_parameter_stage_b42a")
        state["agent_statuses"]["param_disc"] = self._agent_status(state, "param_disc")
        return state

    def decision_for(self, state, point, stop, *, finalize=False):
        """Pure routing on the state of this decision point (B4.2C D5); no HTTP, no LLM."""
        if finalize:
            return "abort_to_report", stop or "finalize_only"
        dispatch = (state.get("fuzzing_execution") or {}).get("multi_origin") or {}
        responses = (dispatch.get("counts") or {}).get("responses")
        if point == "after_recon" and not stop and state["agent_statuses"]["tech_recon"] != "failed":
            return "proceed_to_wordlist", None
        if point == "after_wordlist" and not stop and state["wordlist_metadata"]["multi_origin"]["selected_count"]:
            return "proceed_to_fuzzing", None
        if point == "after_fuzzing" and self.parameter_verification and not stop and responses:
            return "proceed_to_param", None
        if point == "after_fuzzing" and self.soft404_verification and not stop and responses:
            return "skip_to_filter", None
        reason = stop or dispatch.get("stop_reason")
        if reason == "completed":
            reason = None
        default = ("no_selected_candidates" if point == "after_wordlist" else "no_target_responses"
                   if point == "after_fuzzing" and (self.parameter_verification or self.soft404_verification)
                   else "local_three_agent_only")
        return "abort_to_report", reason or default

    def decide(self, state, point):
        try:
            current_runtime().check()
        except PipelineStopped:
            pass  # Route to report without another HTTP/LLM attempt.
        action, reason = self.decision_for(state, point, current_runtime().stop_reason, finalize=self.finalize_only)
        if action == "abort_to_report":
            state["stop_reason"] = reason
        state["_last_decision_action"], state["_config_adjustments"] = action, {}
        state["decision_chain"].append({"decision_point": point, "action": action,
            "source": "deterministic_local_test_policy", "llm_called": False, "reason": reason})
        return state

    def _fill(self, state):
        statuses = state.setdefault("agent_statuses", {})
        for agent in AGENTS:
            if statuses.get(agent) in (None, "pending"):
                statuses[agent] = "skipped"
        for entry in state.get("origin_contexts", {}).values():
            for agent in AGENTS:
                if entry.setdefault("agent_statuses", {}).get(agent) in (None, "pending"):
                    entry["agent_statuses"][agent] = "skipped"
        return statuses

    def _absent(self, state):
        """(status, reason) for an Agent that left no section at an origin, and whether it ran at all."""
        local = state.get("local_origin_execution") or {}
        skips = local.get("routing_skips") or {}
        enabled = {"tech_recon", "wordlist_gen", "fuzzing"} | ({"param_disc"} if self.parameter_verification else set()) \
            | ({"soft404_filter"} if self.soft404_verification else set())
        attempts = state.get("agent_attempts") or {}
        runtime = current_runtime()
        stop = runtime.stop_reason if runtime else None
        absent, invoked = {}, {}
        for agent in AGENTS:
            invoked[agent] = bool(attempts.get(agent))
            absent[agent] = (("skipped", "not_enabled_in_mode") if agent not in enabled
                             else ("skipped", skips[agent]) if agent in skips
                             else ("not_started", "finalize_only") if self.finalize_only
                             else ("not_started", stop) if stop and self.full_graph  # legacy modes keep "skipped"
                             else ("skipped", state.get("stop_reason") or "routing_skipped"))
        return absent, invoked

    def report(self, state):
        """B4.2C Report node: deterministic per-origin contract; statuses are derived from evidence."""
        statuses = self._fill(state)
        absent, invoked = self._absent(state)
        local = state.get("local_origin_execution") or {}
        runtime = current_runtime()
        built = build_report(state, absent=absent, invoked=invoked,
                             global_stop=runtime.stop_reason if runtime else None,
                             contract_failures=dict(local.get("contract_failures") or {}),
                             fixed={a: statuses.get(a) for a in ("tech_recon", "wordlist_gen")})
        prior = getattr(self.recovery, "prior_report_digest", None) if self.recovery else None
        if prior is not None and built["digest"] != prior:
            from .origin_recovery import RecoveryDenied
            raise RecoveryDenied("recovery_report_mismatch")
        content = built["content"]
        for agent in AGENTS:
            statuses[agent] = content["agents"][agent]["status"]
        for row in content["approved_origins"]:
            entry = state["origin_contexts"].setdefault(row["origin"], {})
            entry["agent_statuses"] = {a: v["status"] for a, v in row["agents"].items()}
            entry["status"] = row["status"]
        state["multi_origin_report"] = {**built, "status": "completed",
                                        "mode": {"graph_integration": "local_full_graph_b42c" if self.full_graph else None,
                                                 "finalize_only": self.finalize_only}}
        return state

    def reflect(self, state):
        """B4.2C Reflection node: report-backed observations only; no LLM, no KnowledgeStore."""
        report = state.get("multi_origin_report")
        if report is None:
            reflection = {"schema_version": 1, "stage": "B4.2C", "mode": "deterministic_local_no_knowledge_write",
                          "status": "skipped", "reason": "report_missing", "llm_called": False,
                          "knowledge_writes": 0, "lessons": [], "report_digest": None, "observations": []}
        else:
            reflection = build_reflection(report)
        state["local_reflection"] = reflection
        state.setdefault("audit_log", []).append({"type": "reflection_local_deterministic", "status": reflection["status"],
            "observations": len(reflection["observations"]), "knowledge_writes": 0, "llm_called": False})
        return state

    def _completed(self, state, statuses):
        """`completed` only when every condition holds; never in finalize_only."""
        report, reflection = state.get("multi_origin_report"), state.get("local_reflection") or {}
        runtime = current_runtime()
        if (report is None or self.finalize_only or not self.full_graph or reflection.get("status") != "completed"
                or reflection.get("report_digest") != report.get("digest")
                or (runtime is not None and runtime.stop_reason) or state.get("stop_reason")
                or state.get("error_log") or statuses.get("validate") == "failed"
                or (state.get("recovery") or {}).get("status") == "blocked"):
            return False
        content = report["content"]
        return (state.get("all_modules_successful") is True and not content["stop"]["contract_failures"]
                and all(o["status"] == "completed" for o in content["approved_origins"])
                and content["totals"]["outcome_unknown"] == 0 and content["totals"]["interrupted_units"] == 0)

    def finish(self, state):
        if self.recovery and self.recovery.runtime and self.recovery.owner and not self.recovery.broken:
            if state.get("recovery", {}).get("status") != "blocked":
                state.setdefault("recovery", {})["accounting"] = self.recovery.public_summary()
        statuses = self._fill(state)
        attempts = state.get("agent_attempts") or {}
        report = state.get("multi_origin_report")
        executed = report is not None and all(attempts.get(a) and statuses.get(a) in _EXECUTED for a in AGENTS)
        successful = executed and all(statuses.get(a) == "success" for a in AGENTS) and not (
            report["content"]["totals"]["outcome_unknown"] or report["content"]["totals"]["interrupted_units"])
        state.update(all_modules_executed=bool(executed), all_modules_successful=bool(successful))
        runtime = current_runtime()
        local = state.get("local_origin_execution")
        completed = local is not None and self._completed(state, statuses)
        if local is not None:
            response_count = state.get("recon_execution", {}).get("stats", {}).get("responses_received", 0)
            response_count += state.get("fuzzing_execution", {}).get("multi_origin", {}).get("counts", {}).get("responses", 0)
            local["status"] = "completed" if all(statuses.get(k) == "success" for k in self.EXECUTION.values()) else "partial" if response_count else "failed"
            local["stop_reason"] = None if completed else (runtime.stop_reason or state.get("stop_reason") or self._default_stop())
            local["langgraph_trace"] = deepcopy(self.callback_events)
            state["pipeline_status"] = "completed" if completed else "partial" if response_count else "failed"
        state["stop_reason"] = None if completed else (
            (runtime.stop_reason if runtime else None) or state.get("stop_reason") or self._default_stop())
        return state
