"""Classify Soft 404 using measured controls, never HTTP status/size alone."""

from collections import Counter

from src.agents.base_agent import BaseAutonomousAgent
from src.coordinator.llm_logging import sanitize_for_log
from src.coordinator.logger import log_agent_start, log_agent_success, log_agent_error
from src.tools.recon_http import recon_options_from_config
from src.tools.registry import default_registry
from src.tools.soft404 import verify_soft404
from src.tools.proxy_profiles import PROXY_OPTION_KEYS


_NETWORK_KEYS = {"headers", "allowed_origins", "auth_origins", "verify_ssl", "tls_ca_file"}
_LIMIT_KEYS = {"rate_limit", "timeout_seconds", "max_requests", "max_duration_seconds",
               "max_response_bytes", "baseline_samples", "similarity_threshold", "distinct_threshold"}


def soft404_options_from_config(config=None, execution=None):
    """Use operator configuration; never restart a stopped or differently routed scan."""
    config = {} if config is None else config
    auth = recon_options_from_config(config)
    execution_provided = execution is not None
    execution = execution or {}
    context = execution.get("verification_context") or {}
    fuzz = config.get("fuzzing_options") or {}
    replay_proxy = (isinstance(fuzz, dict) and fuzz.get("engine") == "proxy_http"
                    and execution.get("engine") == "proxy_http" and context.get("route") == "proxy"
                    and not any(fuzz.get(key) for key in ("proxy", "lab_source_ips", "source_ip", "source_address")))
    nested = config.get("soft404_options", {})
    if not isinstance(nested, dict):
        raise ValueError("soft404_options must be a mapping")
    unknown = set(nested) - _NETWORK_KEYS - _LIMIT_KEYS - {"enabled", "cookie", "bearer_token"}
    if unknown:
        raise ValueError("Unsupported Soft404 configuration option")
    options = {key: value for key, value in auth.items() if key in _NETWORK_KEYS}
    # Actual fuzzing auth takes priority over unrelated Recon defaults.
    if isinstance(fuzz, dict) and "headers" in fuzz:
        options["headers"] = fuzz["headers"]
    elif execution_provided:
        # No operator fuzz headers means the original scan was anonymous.
        options["headers"] = {}
    options.update({key: value for key, value in nested.items() if key in _NETWORK_KEYS | _LIMIT_KEYS | {"enabled"}})
    headers = dict(options.get("headers") or {})
    for key, option, prefix in (("Cookie", "cookie", ""), ("Authorization", "bearer_token", "Bearer ")):
        inherit_auth = not execution_provided and "headers" not in nested and not (isinstance(fuzz, dict) and "headers" in fuzz)
        value = nested.get(option, auth.get(option) if inherit_auth else None)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"{option} must be a string")
            headers = {name: item for name, item in headers.items() if name.lower() != key.lower()}
            if value:
                headers[key] = prefix + value
    options["headers"] = headers
    if replay_proxy:
        # Private configuration stays in memory; the transport resolves only
        # the completed pool belonging to this runtime session.
        options["proxy_options"] = {key: value for key, value in fuzz.items()
                                    if key in PROXY_OPTION_KEYS | {"engine"}}
    # Verification starts no faster than the preceding configured scan.
    if isinstance(fuzz, dict):
        scan_rate = fuzz.get("rate_limit", fuzz.get("rate"))
        delay = fuzz.get("delay_ms", fuzz.get("delay_between_requests_ms", 0))
        requested_rate = float(options.get("rate_limit", 1))
        if scan_rate is not None:
            requested_rate = min(requested_rate, float(scan_rate))
        if delay:
            requested_rate = min(requested_rate, 1000 / float(delay))
        options["rate_limit"] = requested_rate
    if context:
        runtime_rate = context.get("rate_limit")
        runtime_delay = context.get("delay_ms")
        if runtime_rate is not None:
            options["rate_limit"] = min(float(options.get("rate_limit", 1)), float(runtime_rate))
        if runtime_delay:
            options["rate_limit"] = min(float(options.get("rate_limit", 1)), 1000 / float(runtime_delay))
    prior_stop = execution.get("stop_reason")
    if prior_stop not in (None, "", "completed"):
        options["stop_reason"] = "upstream_" + str(prior_stop)
    elif execution.get("partial") or execution.get("success") is False:
        options["stop_reason"] = "upstream_incomplete"
    elif execution.get("simulated"):
        options["stop_reason"] = "simulated_source"
    elif not replay_proxy and (context.get("route") in {"proxy", "source_bound"} or execution.get("engine") in {"proxy_http", "loopback_lab"} or (isinstance(fuzz, dict) and (
            fuzz.get("engine") in {"proxy_http", "loopback_lab"} or fuzz.get("proxy") or fuzz.get("lab_source_ips")
            or fuzz.get("source_ip") or fuzz.get("source_address")))):
        options["stop_reason"] = "verification_route_unavailable"
    elif not replay_proxy and execution_provided and (context.get("route") != "direct" or execution.get("engine") not in {"python_http", "ffuf_cli"}):
        options["stop_reason"] = "verification_context_unavailable"
    elif execution_provided and context.get("auth_matches_operator") is not True:
        options["stop_reason"] = "authentication_context_unavailable"
    elif context.get("http_method", "GET") != "GET" or context.get("request_has_body") or context.get("headers_templated"):
        options["stop_reason"] = "request_context_not_replayable"
    elif not execution_provided and auth.get("account") and not any(
            key.lower() not in {"user-agent", "accept", "accept-encoding", "accept-language", "content-type"}
            for key in headers):
        options["stop_reason"] = "authentication_context_unavailable"
    return options


class Soft404FilterAgent(BaseAutonomousAgent):
    """Run the deterministic comparator without involving an LLM."""

    def __init__(self, llm=None):
        super().__init__(agent_name="Soft404FilterAgent", llm=llm, tool_registry=default_registry)

    def verify_origin_soft404(self, shared_state, *, transport, artifact_root=None, max_requests=None):
        """B4.2B harness: classify Agent 3 observations per origin; no LLM, gate stays closed."""
        from src.tools.origin_soft404 import verify_origin_soft404
        return verify_origin_soft404(shared_state, transport=transport, artifact_root=artifact_root,
                                     max_requests=max_requests)

    def _run_soft404_filter_internal(self, results_to_verify: list, target_url: str, **options) -> dict:
        return verify_soft404(target_url, results_to_verify, **options)

    def execute(self, target_url: str, results_to_verify: list, directive: dict = None, **options) -> dict:
        def redact(value):
            return sanitize_for_log({"headers": options.get("headers", {}), "payload": value})["payload"]

        log_agent_start("Soft404FilterAgent", redact(target_url), params={"total_to_verify": len(results_to_verify)})
        try:
            result = self._run_soft404_filter_internal(results_to_verify, target_url, **options)
            counts = Counter(row.get("content_length") for row in results_to_verify
                             if isinstance(row, dict) and row.get("status_code") == 200
                             and isinstance(row.get("content_length"), int))
            result["equal_length_signals"] = [
                {"status_code": 200, "content_length": length, "count": count,
                 "meaning": "Suspicious repetition only; size is not proof of Soft404 or validity"}
                for length, count in sorted(counts.items()) if count > 1
            ]
            stats = result.get("stats", {})
            result["tools_executed"] = [{
                "selected_tool": "soft404_comparator",
                "result_summary": {"verified": len(result["verified"]),
                                   "filtered": len(result["false_positives"]),
                                   "unverified": len(result["unverified"]),
                                   "requests": stats.get("total_requests", 0)},
            }] if result.get("verification_performed") else []
            justification = (
                f"Soft404: {len(result['verified'])} phản hồi khác biệt với baseline; "
                f"{len(result['false_positives'])} phản hồi không tồn tại/fallback; "
                f"{len(result['unverified'])} chưa đủ bằng chứng. "
                f"Request kiểm chứng: {stats.get('total_requests', 0)}. "
                f"Trạng thái: {result.get('verification_status')}; dừng: {result.get('stop_reason')}. "
                "HTTP 200 hoặc độ dài bằng nhau không tự chứng minh endpoint hợp lệ."
            )
            result["subagent_justification"] = justification
            log_agent_success("Soft404FilterAgent", redact(justification))
            return result
        except Exception as exc:
            safe = RuntimeError(redact(str(exc)))
            log_agent_error("Soft404FilterAgent", "Không thể xác minh Soft404", exception=safe)
            raise safe from None
