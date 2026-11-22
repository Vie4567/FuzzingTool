"""Run the real Coordinator with a hidden bearer token and explicit routing.

Direct Python HTTP is the default. With an explicitly selected proxy source,
Parameter/Soft404 reuse the completed fuzzing pool. Recon connects directly.
"""

import argparse
from datetime import datetime, timezone
from getpass import getpass, GetPassWarning
import json
import logging
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
from uuid import uuid4
import warnings


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--target", required=True, help="Authorized HTTPS target")
    cli.add_argument("--proxy-source", choices=("none", "proxyscrape", "manual"), default="none",
                     help="none: direct python_http (default); proxy rotation requires explicit opt-in")
    cli.add_argument("--proxy-count", type=int, default=2, choices=range(1, 9), metavar="1..8")
    cli.add_argument("--proxy-refresh-seconds", type=float, default=300)
    cli.add_argument("--proxy-check-timeout", type=float, default=5)
    cli.add_argument("--max-wordlist-entries", type=int, default=12)
    cli.add_argument("--pipeline-timeout", type=float, default=1200)
    cli.add_argument("--llm-timeout", type=float, default=120)
    cli.add_argument("--http-max-requests", type=int, default=350, help="Shared target HTTP dispatch budget")
    cli.add_argument("--http-rate-limit", type=float, default=1, help="Shared target requests per second")
    cli.add_argument("--max-retries", type=int, default=1, help="Maximum retries per module")
    cli.add_argument("--check", action="store_true", help="Validate locally only; no HTTP/LLM calls")
    return cli


def read_settings():
    from dotenv import dotenv_values
    return {**dotenv_values(ROOT / ".env"), **os.environ}


class RuntimePreflightError(RuntimeError):
    pass


def check_runtime():
    """Import/compile the actual graph without invoking agents or providers."""
    try:
        from src.coordinator import build_coordinator_graph
        build_coordinator_graph()
    except (ImportError, OSError) as exc:
        # Do not echo arbitrary import errors that may include private values.
        raise RuntimePreflightError(
            f"Coordinator runtime unavailable ({type(exc).__name__}). "
            "Check dependencies and Windows Application Control; no requests were sent."
        ) from None


def build_config(args, settings, token, output):
    """Use Coordinator's validator; never serialize the private configuration."""
    from src.coordinator.validation import validate_pipeline_input, validate_url

    target = validate_url(args.target)
    parts = urlsplit(target)
    if parts.scheme != "https":
        raise ValueError("This authenticated runner requires an HTTPS target")
    origin = f"{parts.scheme}://{parts.netloc}"
    provider = settings.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com"
    if provider.rstrip("/") not in {"https://api.deepseek.com", "https://api.deepseek.com/v1"}:
        raise ValueError("Configure DEEPSEEK_BASE_URL with the official HTTPS DeepSeek endpoint")
    if not settings.get("DEEPSEEK_API_KEY"):
        raise ValueError("Missing DEEPSEEK_API_KEY in .env or environment")
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if not token or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in token):
        raise ValueError("Enter a nonempty access token without whitespace")
    headers = {"Authorization": "Bearer " + token}
    fuzz = {
        "engine": "python_http" if args.proxy_source == "none" else "proxy_http",
        "http_method": "GET", "headers": dict(headers),
        "threads": 1, "rate_limit": args.http_rate_limit, "delay_ms": 0,
        "timeout_seconds": 8, "max_requests": 40, "max_scan_seconds": 300,
        "auto_calibrate": False, "recursion": False, "follow_redirects": False,
        "stop_on_block": True, "stop_on_429": True,
    }
    if args.proxy_source != "none":
        fuzz.update({
            "allowed_origins": [origin], "proxy_source": args.proxy_source, "proxy_count": args.proxy_count,
            "proxy_candidate_limit": 20, "proxy_fetch_timeout_seconds": 10,
            "proxy_check_timeout_seconds": args.proxy_check_timeout,
            "proxy_refresh_seconds": args.proxy_refresh_seconds,
            "proxy_healthcheck_url": origin + "/robots.txt",
        })
    if args.proxy_source == "manual":
        raw = settings.get("FUZZ_PROXY_PROFILES")
        if not raw:
            raise ValueError("Configure FUZZ_PROXY_PROFILES in .env or environment for manual mode")
        try:
            fuzz["proxy_profiles"] = json.loads(raw)
        except (TypeError, ValueError):
            raise ValueError("FUZZ_PROXY_PROFILES must contain a valid JSON profile list") from None
    config = {
        "api_key": settings["DEEPSEEK_API_KEY"], "base_url": provider,
        "llm_model": settings.get("LLM_MODEL") or "deepseek-chat",
        "headers": headers, "allowed_origins": [origin], "auth_origins": [origin], "verify_ssl": True,
        "artifact_root": str(output), "knowledge_store_dir": str(output / "knowledge_store"),
        "pipeline_timeout_seconds": args.pipeline_timeout, "llm_timeout_seconds": args.llm_timeout,
        "llm_max_tokens": 8192, "max_llm_calls": 60, "max_retries": args.max_retries, "max_iterations": 10,
        "run_all_modules": True, "http_max_requests": args.http_max_requests, "http_rate_limit": args.http_rate_limit,
        "http_timeout_seconds": 8, "http_max_response_bytes": 2 * 1024 * 1024,
        "wordlist": ["/robots.txt", "/sitemap.xml"], "wordlist_mode": "merge",
        "max_wordlist_entries": args.max_wordlist_entries, "fuzzing_options": fuzz,
        "parameter_options": {"enabled": True, "rate_limit": args.http_rate_limit, "max_requests": 180,
                              "timeout_seconds": 8, "max_duration_seconds": 360},
        "soft404_options": {"enabled": True, "rate_limit": args.http_rate_limit, "max_requests": 80,
                            "timeout_seconds": 8, "max_duration_seconds": 180},
    }
    return validate_pipeline_input(target, config)


def main(argv=None):
    args = parser().parse_args(argv)
    os.environ.update(PYTHON_DOTENV_DISABLED="1", LANGSMITH_TRACING="false", LANGCHAIN_TRACING_V2="false")
    output = ROOT / "output_samples" / "diagnostics" / (
        "coordinator_auth_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid4().hex[:8]
    )
    try:
        settings = read_settings()
        check_runtime()
        # Local validation does not need, read or validate a real target token.
        token = "configuration-check-placeholder"
        if not args.check:
            # Fail instead of echoing the token if the terminal cannot hide input.
            with warnings.catch_warnings():
                warnings.simplefilter("error", GetPassWarning)
                token = getpass("Access token (hidden): ")
        target, config = build_config(args, settings, token, output)
    except (EOFError, GetPassWarning):
        print("Use an interactive terminal that supports hidden token input.", flush=True)
        return 2
    except RuntimePreflightError as exc:
        print(str(exc), flush=True)
        return 2
    except (ValueError, OSError) as exc:
        print(f"Configuration error: {exc}", flush=True)
        return 2
    print(f"Target: {target}; auth=Bearer; TLS verification=on", flush=True)
    print(f"HTTP budget={config['http_max_requests']}; rate={config['http_rate_limit']}/s; max retries={config['max_retries']}", flush=True)
    if args.proxy_source == "none":
        print("Routes: Recon/Fuzzing/Parameter/Soft404=direct; Fuzzing engine=python_http; proxy rotation=off.", flush=True)
    else:
        print(f"Fuzzing proxy source={args.proxy_source}; requested pool size={args.proxy_count}", flush=True)
        print("Routes: Recon=direct; Fuzzing=rotating proxy_http; Parameter/Soft404=reused proxy pool, rotation per endpoint.", flush=True)
        print("Proxy availability and distinct public egress IPs have not been verified yet.", flush=True)
    if args.check:
        print("Configuration valid; Coordinator graph compiled. No target, proxy or LLM requests were sent; token acceptance is untested.", flush=True)
        return 0
    output.mkdir(parents=True, exist_ok=False)
    os.environ["LLM_RESPONSE_LOG_FILE"] = str(output / "llm_responses.jsonl")
    print(f"Artifacts: {output}", flush=True)
    print("Starting real Coordinator and LLM; existing request limits and stop conditions apply.", flush=True)
    from src.coordinator import run_pipeline_supervised
    try:
        result = run_pipeline_supervised(target, config)
    except KeyboardInterrupt:
        print(f"Interrupted. Check supervisor checkpoints/results under: {output}", flush=True)
        return 130
    print("Pipeline:", result.get("pipeline_status"), flush=True)
    print("Modules:", json.dumps(result.get("agent_statuses", {}), ensure_ascii=False), flush=True)
    print("HTTP attempts:", result.get("total_http_requests"), "LLM calls:", result.get("llm_call_count"), flush=True)
    print("Result:", result.get("artifacts", {}).get("result", str(output)), flush=True)
    return 0 if result.get("pipeline_status") == "completed" and result.get("all_modules_successful") is True else 1


if __name__ in {"__main__", "__mp_main__"}:
    # Windows spawn reimports this file in the worker; configure its console too.
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", stream=sys.stdout)
    logging.getLogger("sentinel").propagate = False  # Already has its own console/file handlers.
    logging.getLogger("httpx").setLevel(logging.WARNING)

if __name__ == "__main__":
    raise SystemExit(main())
