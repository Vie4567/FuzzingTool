"""Run bounded HTTP checks through manual or ProxyScrape proxies, or --direct.

ProxyScrape candidates are checked by the HTTP engine before use. No LLM is
constructed, and unavailable proxies never fall back to a direct connection.
Use --direct to deliberately run without a proxy or IP rotation.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import logging
import math
import os
from pathlib import Path
import sys
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Package initialization normally loads .env. Keep proxy credentials literal
# and read only the setting this runner needs, including ${...} in passwords.
_proxy_dotenv_state = os.environ.get("PYTHON_DOTENV_DISABLED")
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
try:
    from src.tools.proxy_profiles import ProxyProfilePool, _origin
finally:
    if _proxy_dotenv_state is None:
        os.environ.pop("PYTHON_DOTENV_DISABLED", None)
    else:
        os.environ["PYTHON_DOTENV_DISABLED"] = _proxy_dotenv_state


PROFILE_ENV = "FUZZ_PROXY_PROFILES"
CHECK_PATHS = ["robots.txt", "sitemap.xml", "favicon.ico"]
BANGKOK = timezone(timedelta(hours=7))


def _proxy_environment_value():
    """Read this setting only; do not load .env into the process environment."""
    if PROFILE_ENV in os.environ:
        return os.environ[PROFILE_ENV], "process_environment"
    dotenv_path = PROJECT_ROOT / ".env"
    if dotenv_path.is_file():
        from dotenv import dotenv_values

        value = dotenv_values(dotenv_path, interpolate=False).get(PROFILE_ENV)
        if value is not None:
            return value, "project_dotenv"
    return None, "missing"


@contextmanager
def _profile_environment(value):
    original = os.environ.get(PROFILE_ENV)
    dotenv_state = os.environ.get("PYTHON_DOTENV_DISABLED")
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    if value is not None:
        os.environ[PROFILE_ENV] = value
    try:
        yield
    finally:
        if original is None:
            os.environ.pop(PROFILE_ENV, None)
        else:
            os.environ[PROFILE_ENV] = original
        if dotenv_state is None:
            os.environ.pop("PYTHON_DOTENV_DISABLED", None)
        else:
            os.environ["PYTHON_DOTENV_DISABLED"] = dotenv_state


@contextmanager
def _direct_environment():
    """Avoid loading .env without inspecting or changing proxy configuration."""
    dotenv_state = os.environ.get("PYTHON_DOTENV_DISABLED")
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    try:
        yield
    finally:
        if dotenv_state is None:
            os.environ.pop("PYTHON_DOTENV_DISABLED", None)
        else:
            os.environ["PYTHON_DOTENV_DISABLED"] = dotenv_state


class _BangkokFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created, BANGKOK).strftime(
            "%Y-%m-%d %H:%M:%S +07:00"
        )


@contextmanager
def _live_logger(output_dir):
    loggers = [logging.getLogger(name) for name in (
        "sentinel.fuzzing.http", "sentinel.fuzzing.proxy",
    )]
    original_settings = [(logger.level, logger.propagate) for logger in loggers]
    formatter = _BangkokFormatter("[%(asctime)s] %(message)s")
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(output_dir / "progress.log", encoding="utf-8"),
    ]
    for handler in handlers:
        handler.setFormatter(formatter)
    for logger in loggers:
        for handler in handlers:
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    try:
        yield loggers[0]
    finally:
        for logger, (old_level, old_propagate) in zip(loggers, original_settings):
            for handler in handlers:
                logger.removeHandler(handler)
            logger.setLevel(old_level)
            logger.propagate = old_propagate
        for handler in handlers:
            handler.close()


def _output_directory(raw, *, direct=False):
    if raw:
        candidate = Path(raw)
        candidate = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
    else:
        stamp = datetime.now(BANGKOK).strftime("%Y%m%d_%H%M%S")
        candidate = PROJECT_ROOT / "output_samples" / "diagnostics" / (
            f"{'http_direct_check' if direct else 'proxy_http_check'}_{stamp}_{uuid4().hex[:8]}"
        )
    candidate = candidate.resolve()
    if candidate == PROJECT_ROOT or not candidate.is_relative_to(PROJECT_ROOT):
        raise ValueError("--output-dir must be a directory inside the project")
    artifacts = ("progress.log", "preflight.json", "result.json", "report.md")
    if any((candidate / name).exists() for name in artifacts):
        raise ValueError("Output artifacts already exist; choose a new --output-dir")
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def _target_origin(target):
    scheme, host, port = _origin(target, origin_only=True)
    host = f"[{host}]" if ":" in host else host
    suffix = "" if port == (443 if scheme == "https" else 80) else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _redact(value, pool):
    if pool is None:
        return value
    if isinstance(value, str):
        return pool.redact(value)
    if isinstance(value, dict):
        return {key: _redact(item, pool) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, pool) for item in value]
    return value


def _write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_report(output_dir, origin, preflight, result):
    stats = result.get("stats") or {}
    direct = preflight.get("route") == "direct"
    lines = [
        "# Direct HTTP check" if direct else "# Proxy HTTP check",
        "", f"Target origin: `{origin}`", "",
        "Route: `direct`; proxy: none; IP rotation: disabled." if direct
        else "Route: `proxy_http`; selected proxy profiles are recorded below.", "",
        f"Preflight: `{preflight['status']}`; reason: `{preflight['reason']}`.",
        f"Proxy source: `{preflight.get('proxy_source', 'not_used')}`. "
        "Preflight validates configuration only; availability is measured during execution.",
        f"Attempted requests: {stats.get('total_requests', 0)}; "
        f"responses: {stats.get('responses_received', 0)}; "
        f"stop reason: `{result.get('stop_reason')}`.", "",
        f"Health-check requests: {stats.get('healthcheck_requests', 0)}; "
        f"fuzzing requests: {stats.get('fuzzing_requests', stats.get('total_requests', 0))}. "
        "Both use the same request, time, and rate limits.", "",
        "| Path | Route | HTTP status | Body bytes read | Seconds | Error |" if direct
        else "| Path | Proxy profile | HTTP status | Body bytes read | Seconds | Error |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]
    for row in result.get("results", []):
        elapsed = row.get("response_time")
        elapsed = f"{elapsed:.6f}" if isinstance(elapsed, (int, float)) else "null"
        # Error detail is retained in JSON; keep the table compact and safe.
        lines.append(
            f"| {row.get('path')} | {'direct' if direct else row.get('proxy_profile_id')} | "
            f"{row.get('status_code')} | {row.get('content_length')} | {elapsed} | "
            f"{'yes' if row.get('error') else 'no'} |"
        )
    measurement_note = (
        "Direct connection uses the machine's normal network route; no IP rotation is performed. "
        "`egress_ip` remains `null` because the public source IP was not independently measured."
        if direct else
        "`egress_ip` remains `null`: profile selection alone does not prove "
        "a change of public source IP. Compare the target server's access logs."
    )
    lines.extend([
        "", measurement_note,
        "No LLM, redirect following, or automatic retry is used." if direct
        else "No LLM, redirect following, automatic retry, or direct fallback is used.",
        "Live events: `progress.log`. Measurements and errors: `result.json`.", "",
    ])
    if result.get("proxy_pool") is not None:
        lines.extend([
            "Pool lifecycle: `result.json` → `proxy_pool`; refresh outcome: `proxy_refresh_events`.",
            "Per-profile request counts, response times, and error rates: "
            "`result.json` → `stats.proxy_profiles`. Health-check records: `health_checks`.", "",
        ])
    (output_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def _bounded_number(kind, minimum, maximum):
    def convert(raw):
        try:
            value = kind(raw)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError("A valid number is required") from None
        if not minimum <= value <= maximum or not math.isfinite(value):
            raise argparse.ArgumentTypeError(f"Value must be between {minimum} and {maximum}")
        return value
    return convert


def _refresh_seconds(raw):
    value = _bounded_number(float, 0, 86400)(raw)
    if value != 0 and value < 30:
        raise argparse.ArgumentTypeError("Refresh must be 0 (disabled) or between 30 and 86400 seconds")
    return value


def main(argv=None, *, agent_factory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="https://cab.vn", help="Exact authorized HTTP(S) origin")
    parser.add_argument("--direct", action="store_true", help="Explicit direct connection without proxy or IP rotation")
    parser.add_argument("--proxy-source", choices=("manual", "proxyscrape"), default="manual", help="Manual profiles (default) or automatic ProxyScrape discovery")
    parser.add_argument("--proxy-count", type=_bounded_number(int, 1, 8), help="Maximum selected proxies (1 disables rotation)")
    parser.add_argument("--proxy-candidate-limit", type=_bounded_number(int, 1, 100), default=20, help="Maximum automatic candidates checked per refresh")
    parser.add_argument("--proxy-check-timeout", type=_bounded_number(float, 0.01, 30), default=5, help="Proxy health-check timeout in seconds")
    parser.add_argument("--proxy-fetch-timeout", type=_bounded_number(float, 0.01, 30), default=10, help="ProxyScrape list download timeout in seconds")
    parser.add_argument("--proxy-refresh-seconds", type=_refresh_seconds, help="Automatic refresh interval; 0 disables refresh (auto default 300)")
    parser.add_argument("--proxy-healthcheck-url", help="Health-check URL within the target origin; auto defaults to /robots.txt")
    parser.add_argument("--max-requests", type=_bounded_number(int, 1, 1000), help="Shared health-check + fuzzing request budget; default manual/direct 3, auto 23")
    parser.add_argument("--timeout-seconds", type=_bounded_number(float, 0.01, 30), default=10, help="Fuzzing request timeout")
    parser.add_argument("--max-scan-seconds", type=_bounded_number(float, 0.01, 600), help="Whole-session time budget; default manual/direct 45, auto 120")
    parser.add_argument("--output-dir", help="New artifact directory inside the project")
    args = parser.parse_args(argv)
    if args.direct and args.proxy_source != "manual":
        parser.error("--direct cannot be combined with --proxy-source proxyscrape")
    automatic = not args.direct and args.proxy_source == "proxyscrape"
    max_requests = args.max_requests if args.max_requests is not None else (23 if automatic else 3)
    max_scan_seconds = args.max_scan_seconds if args.max_scan_seconds is not None else (120 if automatic else 45)
    try:
        origin = _target_origin(args.target)
        output_dir = _output_directory(args.output_dir, direct=args.direct)
    except (ValueError, OSError):
        parser.error("Invalid target origin or output directory; use an HTTP(S) origin and a new project directory")

    with _live_logger(output_dir) as live:
        live.info("Artifacts: %s", output_dir)
        engine = "python_http" if args.direct else "proxy_http"
        live.info("PRECHECK target=%s engine=%s route=%s paths=%s rate=1/s max_requests=%s no_llm=true", origin, engine, "direct" if args.direct else "proxy_http", ",".join(CHECK_PATHS), max_requests)
        raw, configuration_source = (
            (None, "proxyscrape") if automatic else
            (None, "not_used") if args.direct else _proxy_environment_value()
        )
        preflight = {
            "status": "blocked", "reason": "missing_proxy_profiles",
            "target_origin": origin, "allowed_origins": [origin],
            "configuration_source": configuration_source, "profile_ids": [],
            "proxy_source": "not_used" if args.direct else args.proxy_source,
            "requests_sent": 0,
        }
        if args.direct:
            preflight.update(status="ready", reason="explicit_direct", route="direct", engine=engine, ip_rotation=False)
        pool = None
        environment = _direct_environment() if args.direct or automatic else _profile_environment(raw)
        with environment:
            options = {"engine": "python_http", "proxy": None} if args.direct else {
                "engine": "proxy_http", "proxy_source": args.proxy_source, "allowed_origins": [origin],
                "proxy_check_timeout_seconds": args.proxy_check_timeout,
                "proxy_fetch_timeout_seconds": args.proxy_fetch_timeout,
                "proxy_candidate_limit": args.proxy_candidate_limit,
            }
            if not args.direct:
                if not automatic:
                    options["proxy_profiles_env"] = PROFILE_ENV
                if args.proxy_count is not None:
                    options["proxy_count"] = args.proxy_count
                if args.proxy_healthcheck_url is not None:
                    options["proxy_healthcheck_url"] = args.proxy_healthcheck_url
                if args.proxy_refresh_seconds is not None:
                    options["proxy_refresh_seconds"] = args.proxy_refresh_seconds
            if not args.direct and (automatic or raw):
                try:
                    pool = ProxyProfilePool.from_options(options, origin)
                    preflight["profile_ids"] = pool.profile_ids if automatic else pool.all_profile_ids
                    if automatic:
                        preflight.update(status="ready", reason="validated_auto_configuration")
                    elif len(preflight["profile_ids"]) < 2 and args.proxy_count != 1:
                        preflight["reason"] = "at_least_two_proxy_profiles_required"
                    else:
                        preflight.update(status="ready", reason="validated")
                except (ValueError, TypeError):
                    preflight["reason"] = "invalid_proxy_options" if automatic else "invalid_proxy_profiles"
            _write_json(output_dir / "preflight.json", preflight)
            if preflight["status"] != "ready":
                live.info("PRECHECK BLOCKED reason=%s requests_sent=0; no network request was made", preflight["reason"])
                result = {
                    "success": False, "engine": "proxy_http", "results": [],
                    "stop_reason": preflight["reason"], "requests_sent": 0,
                    "stats": {"total_requests": 0, "responses_received": 0},
                    "egress_ip": None, "egress_ip_verification": "not_measured",
                }
                exit_code = 2
            else:
                if args.direct:
                    live.info("PRECHECK READY route=direct proxy=none ip_rotation=false; start bounded HTTP check")
                else:
                    live.info("PRECHECK READY source=%s profiles=%s; configuration validated, availability not yet measured", args.proxy_source, ",".join(preflight["profile_ids"]) or "pending_discovery")
                sentinel = logging.getLogger("sentinel")
                old_level = sentinel.level
                try:
                    if agent_factory is None:
                        from src.agents.fuzzer import FuzzingAgent
                        agent_factory = FuzzingAgent
                    sentinel.setLevel(logging.WARNING)
                    result = agent_factory(llm=None).execute(
                        target_url=origin, wordlist=CHECK_PATHS.copy(), use_pattern_engine=False,
                        **options, threads=1, rate_limit=1, delay_ms=1000,
                        max_requests=max_requests, timeout_seconds=args.timeout_seconds,
                        max_scan_seconds=max_scan_seconds,
                    )
                    result = _redact(result, pool)
                    exit_code = 0 if result.get("success") else 1
                except Exception as exc:
                    # A failure outside transport may occur after an attempt;
                    # do not invent a zero request count for this case.
                    result = {
                        "success": False, "engine": engine, "results": [],
                        "stop_reason": "runner_error", "error": pool.redact(str(exc)) if pool else str(exc),
                        "stats": {"total_requests": None, "responses_received": None},
                    }
                    live.info("RUNNER ERROR type=%s; see redacted result.json", type(exc).__name__)
                    exit_code = 1
                finally:
                    sentinel.setLevel(old_level)
            if args.direct:
                result.update(route="direct", ip_rotation=False, egress_ip=None, egress_ip_verification="not_measured")
            _write_json(output_dir / "result.json", result)
            _write_report(output_dir, origin, preflight, result)
            live.info("SAVED report=%s result=%s", output_dir / "report.md", output_dir / "result.json")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
