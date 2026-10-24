"""Execute bounded real HTTP fuzzing and preserve measured ffuf metrics."""

import base64
import json
import logging
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from src.tools.base_helper import BaseToolHelper, ToolResult
from src.tools.proxy_profiles import PROXY_OPTION_KEYS

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FfufToolHelper(BaseToolHelper):
    """Use ffuf or native HTTP; never substitute simulated results."""

    def __init__(self):
        self.knowledge = self._load_ffuf_knowledge()
        super().__init__(
            name="ffuf_fuzzing_tool",
            description="Real HTTP discovery with measured status, size and time, bounded rates and block detection.",
            parameters_schema={
                "target_url": "str: absolute HTTP(S) URL, optionally containing FUZZ",
                "wordlist": "list[str]: relative paths or FUZZ replacement values",
                "engine": "auto (default), ffuf_cli, python_http, proxy_http (scoped manual/ProxyScrape pool), or loopback_lab",
                "lab_source_ips": "list[str]: loopback source addresses, used only by loopback_lab; no public egress rotation",
                "proxy_profiles": "list[dict]: caller-provided {id, url} HTTP proxy profiles; proxy_http only, never logged",
                "proxy_profiles_env": "str: environment variable containing proxy profile JSON; alternative to proxy_profiles",
                "proxy_source": "manual (default) or proxyscrape; explicit caller configuration, proxy_http only",
                "proxy_count": "int: active pool size, 1..8; ProxyScrape default 2",
                "proxy_candidate_limit": "int: candidates per ProxyScrape refresh, 1..100, default 20",
                "proxy_check_timeout_seconds": "float: health check timeout, 0.01..30, default 5",
                "proxy_fetch_timeout_seconds": "float: ProxyScrape download timeout, 0.01..30, default 10",
                "proxy_refresh_seconds": "float: refresh interval, 0 disables periodic refresh or 30..86400; default 300",
                "proxy_healthcheck_url": "str: health-check URL inside allowed_origins; auto defaults to target /robots.txt; requests share scan budget",
                "allowed_origins": "list[str]: exact approved HTTP(S) origins required by proxy_http, no wildcard or redirects",
                "ffuf_binary": "str: executable, otherwise FFUF_PATH/PATH/project tools",
                "extensions": "list/str: ffuf -e extensions",
                "auto_calibrate": "bool: ffuf -ac, adds requests and filters responses",
                "match_codes": "str/list: codes/ranges or all (default)",
                "filter_codes": "str/list: excluded status codes/ranges",
                "filter_size": "str/int: excluded sizes/ranges",
                "filter_words": "str/int: excluded word counts/ranges",
                "filter_lines": "str/int: excluded line counts/ranges",
                "recursion": "bool: ffuf recursive discovery, default false",
                "recursion_depth": "int: maximum depth, default 1",
                "threads": "int: concurrency, default 1",
                "rate_limit": "float: requests/second, default 2",
                "delay_ms": "float: delay between requests",
                "timeout_seconds": "float: per-request timeout, default 10",
                "max_scan_seconds": "float: scan deadline, default 120",
                "max_requests": "int: maximum inputs, default 100",
                "follow_redirects": "bool: ffuf -r, default false",
                "http_method": "str: method, default GET",
                "post_data": "str: request body",
                "headers": "dict: HTTP headers",
                "proxy": "str: one fixed HTTP/SOCKS proxy",
                "stop_on_block": "bool: stop on HTTP 429/repeated 403, default true",
                "block_threshold": "int: consecutive 403 limit, default 3",
                "stop_on_errors": "bool: ffuf -se, default true",
                "stop_on_all_errors": "bool: ffuf -sa, default true",
            },
        )

    def _load_ffuf_knowledge(self) -> dict:
        try:
            return json.loads((PROJECT_ROOT / "knowledge/ffuf_knowledge.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Could not read ffuf knowledge: %s", exc)
            return {}

    @staticmethod
    def resolve_binary(explicit: Optional[str] = None) -> Optional[str]:
        configured = explicit or os.environ.get("FFUF_PATH")
        if configured:
            candidate = Path(configured).expanduser()
            if not candidate.is_absolute():
                candidate = PROJECT_ROOT / candidate
            if candidate.is_file():
                return str(candidate.resolve())
            located = shutil.which(str(configured))
            if located:
                return str(Path(located).resolve())
            raise ValueError("Configured ffuf executable does not exist.")
        located = shutil.which("ffuf")
        if located:
            return str(Path(located).resolve())
        for filename in ("ffuf.exe", "ffuf"):
            candidate = PROJECT_ROOT / "output_samples/tools/ffuf" / filename
            if candidate.is_file():
                return str(candidate.resolve())
        return None

    @staticmethod
    def _positive(value: Any, label: str) -> float:
        number = float(value)
        if not math.isfinite(number) or number <= 0:
            raise ValueError(f"{label} must be a positive finite number.")
        return number

    @staticmethod
    def _csv(value: Any) -> str:
        return ",".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value)

    def _build_cli_command(self, target_url: str, wordlist_file: str, kwargs: Dict[str, Any],
                           output_json: str = "output_samples/ffuf_out.json") -> List[str]:
        binary = self.resolve_binary(kwargs.get("ffuf_binary"))
        if not binary:
            raise ValueError("ffuf executable is not available.")
        headers = kwargs.get("headers") or {}
        has_keyword = "FUZZ" in target_url or "FUZZ" in str(kwargs.get("post_data", ""))
        has_keyword = has_keyword or any("FUZZ" in f"{key}:{value}" for key, value in headers.items())
        parsed = urlsplit(target_url)
        url_pattern = target_url if has_keyword else urlunsplit((parsed.scheme, parsed.netloc,
                      parsed.path.rstrip("/") + "/FUZZ", parsed.query, ""))
        timeout = self._positive(kwargs.get("timeout_seconds", kwargs.get("timeout", 10)), "timeout_seconds")
        maxtime = self._positive(kwargs.get("max_scan_seconds", kwargs.get("max_duration_seconds", 120)), "max_scan_seconds")
        threads = self._positive(kwargs.get("threads", 1), "threads")
        rate = self._positive(kwargs.get("rate_limit", 2), "rate_limit")
        cmd = [binary, "-u", url_pattern, "-w", wordlist_file, "-of", "json", "-o", output_json,
               "-json", "-noninteractive", "-mc", "all", "-t", str(math.ceil(threads)),
               "-rate", str(max(1, math.floor(rate))), "-timeout", str(math.ceil(timeout)),
               "-maxtime", str(math.ceil(maxtime))]
        # Collect all statuses before applying user filters so they cannot hide blocking.
        if kwargs.get("follow_redirects", False):
            cmd.append("-r")
        if kwargs.get("stop_on_all_errors", True):
            cmd.append("-sa")
        else:
            if kwargs.get("stop_on_block", True):
                cmd.append("-sf")
            if kwargs.get("stop_on_errors", True):
                cmd.append("-se")
        method = str(kwargs.get("http_method", "GET")).upper()
        if method != "GET":
            cmd.extend(["-X", method])
        if kwargs.get("post_data") is not None:
            cmd.extend(["-d", str(kwargs["post_data"])])
        if kwargs.get("extensions"):
            cmd.extend(["-e", self._csv(kwargs["extensions"])])
        if kwargs.get("recursion"):
            cmd.extend(["-recursion", "-recursion-depth", str(int(kwargs.get("recursion_depth", 1)))])
        if kwargs.get("auto_calibrate"):
            cmd.append("-ac")
        delay_ms = float(kwargs.get("delay_ms", 0))
        if not math.isfinite(delay_ms) or delay_ms < 0:
            raise ValueError("delay_ms must be a nonnegative finite number.")
        delay = max(delay_ms / 1000, 1 / rate if rate < 1 else 0)
        if delay:
            cmd.extend(["-p", str(delay)])
        for name, value in headers.items():
            if any(char in f"{name}{value}" for char in "\r\n\x00"):
                raise ValueError("HTTP headers cannot contain CR, LF or NUL.")
            cmd.extend(["-H", f"{name}: {value}"])
        if kwargs.get("proxy"):
            cmd.extend(["-x", str(kwargs["proxy"])])
        return cmd

    @staticmethod
    def _sanitized_command(cmd: List[str]) -> str:
        redacted = list(cmd)
        for index, token in enumerate(cmd[:-1]):
            if token in ("-H", "-d", "-x", "-b"):
                redacted[index + 1] = "<redacted>"
            elif token == "-u":
                url = urlsplit(cmd[index + 1])
                redacted[index + 1] = urlunsplit((url.scheme, url.netloc.rsplit("@", 1)[-1], url.path,
                                                 "<redacted>" if url.query else "", ""))
        return subprocess.list2cmdline(redacted)

    @staticmethod
    def _normalize_wordlist(wordlist: Any, path_mode: bool) -> List[str]:
        if isinstance(wordlist, (str, bytes)) or not isinstance(wordlist, (list, tuple)):
            raise ValueError("wordlist must be a list of strings.")
        entries = []
        for entry in wordlist:
            if not isinstance(entry, str) or any(char in entry for char in "\r\n\x00"):
                raise ValueError("Wordlist entries must be strings without CR, LF or NUL.")
            value = entry.strip()
            if path_mode:
                value = value.lstrip("/")
                if value.startswith(("http://", "https://")):
                    raise ValueError("Use relative paths in a path wordlist.")
            if value:
                entries.append(value)
        return list(dict.fromkeys(entries))

    @staticmethod
    def _normalize_result(result: dict, streamed: bool = False) -> dict:
        input_value = result.get("input", {}).get("FUZZ")
        if streamed and isinstance(input_value, str):
            try:
                input_value = base64.b64decode(input_value, validate=True).decode("utf-8", errors="replace")
            except ValueError:
                pass
        duration = result.get("duration")
        url = result.get("url")
        path = (urlsplit(url).path or "/") if isinstance(url, str) else None
        return {"url": url, "path": path, "input_value": input_value, "status_code": result.get("status"),
                "content_length": result.get("length"),
                "response_time": duration / 1_000_000_000 if isinstance(duration, (int, float)) else None,
                "response_time_kind": "time_to_first_byte", "duration_ns": duration,
                "words": result.get("words"), "lines": result.get("lines"),
                "content_type": result.get("content-type"), "redirect_location": result.get("redirectlocation"),
                "engine": "ffuf_cli", "simulated": False}

    def _in_ranges(self, number: Any, specification: Any) -> bool:
        for item in self._csv(specification).split(","):
            if item.strip() == "all":
                return True
            bounds = item.strip().split("-", 1)
            if number is not None and int(bounds[0]) <= number <= int(bounds[-1]):
                return True
        return False

    def _keep_result(self, result: dict, options: dict) -> bool:
        if not self._in_ranges(result.get("status_code"), options.get("match_codes") or "all"):
            return False
        for field, option in (("status_code", "filter_codes"), ("content_length", "filter_size"),
                              ("words", "filter_words"), ("lines", "filter_lines")):
            if options.get(option) is not None and self._in_ranges(result.get(field), options[option]):
                return False
        return True

    def run(self, **kwargs) -> ToolResult:
        started = time.monotonic()
        execution_started = False
        selected_engine = None
        try:
            rotation_options = {"rotate_ip", "rotate_ips", "ip_rotation", "rotate_proxy", "rotate_proxies",
                                "proxy_rotation", "proxy_pool", "proxies", "proxy_list", "tor",
                                "tor_control_port", "spoof_ip", "random_ip"}
            if any(kwargs.get(key) for key in rotation_options):
                raise ValueError("Generic rotation flags are unsupported; choose explicit scoped proxy_http profiles or one fixed proxy.")
            spoof_headers = {"forwarded", "x-forwarded-for", "x-real-ip", "true-client-ip", "cf-connecting-ip",
                             "client-ip", "x-client-ip", "x-originating-ip"}
            if any(str(key).lower() in spoof_headers for key in (kwargs.get("headers") or {})):
                raise ValueError("Client-IP spoofing headers are unsupported.")
            target = kwargs.get("target_url", "")
            parsed = urlsplit(target)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("target_url must be an absolute HTTP(S) URL.")
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError("Use a target URL without credentials or fragments.")
            if any(ord(character) < 32 for character in target):
                raise ValueError("target_url cannot contain control characters.")
            path_mode = "FUZZ" not in target and "FUZZ" not in str(kwargs.get("post_data", ""))
            path_mode = path_mode and not any("FUZZ" in f"{key}:{value}" for key, value in (kwargs.get("headers") or {}).items())
            wordlist = self._normalize_wordlist(kwargs.get("wordlist", []), path_mode)
            if not wordlist:
                raise ValueError("wordlist is empty after normalization.")
            # Validate range syntax before sending any request.
            for key in ("match_codes", "filter_codes", "filter_size", "filter_words", "filter_lines"):
                if kwargs.get(key) is not None:
                    self._in_ranges(0, kwargs[key])
            engine = kwargs.get("engine", "auto")
            if engine not in ("auto", "ffuf", "ffuf_cli", "python", "python_http", "native", "loopback_lab", "proxy_http"):
                raise ValueError("Unsupported engine.")
            if kwargs.get("lab_source_ips") is not None and engine != "loopback_lab":
                raise ValueError("lab_source_ips requires engine=loopback_lab; other engines do not rotate source IPs.")
            if engine != "proxy_http" and any(kwargs.get(key) is not None for key in PROXY_OPTION_KEYS):
                raise ValueError("Proxy profile options require engine=proxy_http")
            binary = None if engine in ("python", "python_http", "native", "loopback_lab", "proxy_http") else self.resolve_binary(kwargs.get("ffuf_binary"))
            if not binary:
                if engine in ("ffuf", "ffuf_cli"):
                    raise ValueError("ffuf executable is not available.")
                native_options = {key: value for key, value in kwargs.items() if key not in ("target_url", "wordlist", "engine")}
                if "block_threshold" in native_options:
                    native_options.setdefault("consecutive_403_limit", native_options.pop("block_threshold"))
                if engine == "loopback_lab":
                    from src.tools.loopback_rotation_lab import run_loopback_rotation_lab
                    selected_engine, execution_started = "loopback_lab", True
                    data = run_loopback_rotation_lab(target, wordlist, **native_options)
                else:
                    from src.tools.http_fuzzing import run_http_fuzzing
                    selected_engine, execution_started = "proxy_http" if engine == "proxy_http" else "python_http", True
                    if engine == "proxy_http":
                        native_options["engine"] = "proxy_http"
                    data = run_http_fuzzing(target, wordlist, **native_options)
                data["results"] = [row for row in data.get("results", []) if self._keep_result(row, kwargs)]
                for row in data["results"]:
                    row.setdefault("input_value", row.get("input"))
                data.setdefault("stats", {})["matched_responses"] = sum(row.get("status_code") is not None for row in data["results"])
                data["stats"]["returned_results"] = len(data["results"])
                data["stopped_early"] = not data.get("completed", False)
                data["partial"] = data["stopped_early"] or bool(data.get("errors"))
                data["stats"].update(partial=data["partial"], stopped_early=data["stopped_early"])
                success = not data["partial"]
                return ToolResult(success, self.name, data, execution_time=time.monotonic() - started,
                                  error_message=None if success else data.get("stop_reason") or "HTTP scan returned errors or partial results.")
            selected_engine, execution_started = "ffuf_cli", True
            return self._run_cli(target, wordlist, binary, kwargs, started)
        except (ValueError, OSError, TypeError) as exc:
            data = {"engine": selected_engine, "simulated": False, "results": [], "errors": [str(exc)],
                    "completed": False, "partial": execution_started, "stopped_early": execution_started,
                    "stop_reason": "execution_error" if execution_started else "invalid_configuration",
                    "stats": {"attempted_requests": None, "total_requests": None, "returned_results": 0,
                              "matched_responses": 0, "metric_scope": "No complete measurement payload is available."}}
            return ToolResult(False, self.name, data,
                              error_message=str(exc), execution_time=time.monotonic() - started)

    def _run_cli(self, target: str, wordlist: List[str], binary: str, options: dict, started: float) -> ToolResult:
        raw_cap = self._positive(options.get("max_requests", 100), "max_requests")
        if not raw_cap.is_integer():
            raise ValueError("max_requests must be an integer.")
        cap = int(raw_cap)
        selected = wordlist[:cap]
        parent_dir = PROJECT_ROOT / "output_samples/fuzzing_runs"
        parent_dir.mkdir(parents=True, exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix="ffuf_", dir=parent_dir))
        wordlist_path = run_dir / "wordlist.txt"
        wordlist_path.write_text("\n".join(selected) + "\n", encoding="utf-8")
        output_json = run_dir / "results.json"
        command = self._build_cli_command(target, str(wordlist_path), {**options, "ffuf_binary": binary}, str(output_json))
        safe_command = self._sanitized_command(command)
        logger.info("Executing real HTTP fuzzing: %s", safe_command)
        maxtime = self._positive(options.get("max_scan_seconds", options.get("max_duration_seconds", 120)), "max_scan_seconds")
        deadline = time.monotonic() + maxtime
        stop_reason, raw_results, consecutive_forbidden = None, [], 0
        threshold = int(self._positive(options.get("block_threshold", options.get("consecutive_403_limit",
                                       options.get("max_consecutive_403", 3))), "block_threshold"))
        stdout_path, stderr_path = run_dir / "stdout.jsonl", run_dir / "stderr.log"
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, cwd=str(PROJECT_ROOT))
            with stdout_path.open("r", encoding="utf-8", errors="replace") as live:
                while True:
                    for line in live:
                        try:
                            response = json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(response, dict) or "status" not in response:
                            continue
                        raw_results.append(response)
                        status = response.get("status")
                        consecutive_forbidden = consecutive_forbidden + 1 if status == 403 else 0
                        if options.get("stop_on_block", True) and (status == 429 or consecutive_forbidden >= threshold):
                            stop_reason = "http_429" if status == 429 else "repeated_http_403"
                    if stop_reason or time.monotonic() >= deadline:
                        stop_reason = stop_reason or "max_scan_seconds"
                        if proc.poll() is None:
                            proc.terminate()
                        break
                    if proc.poll() is not None:
                        break
                    time.sleep(0.05)
            try:
                returncode = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                returncode = proc.wait(timeout=5)
        from_file, errors = False, []
        if output_json.exists():
            try:
                document = json.loads(output_json.read_text(encoding="utf-8"))
                raw_results, from_file = document["results"], True
                # ffuf's retained config/commandline can contain credentials.
                output_json.write_text(json.dumps({"results": raw_results}, ensure_ascii=False, indent=2), encoding="utf-8")
            except (ValueError, KeyError, TypeError) as exc:
                errors.append(f"Invalid ffuf output: {exc}")
        elif not stop_reason:
            errors.append("ffuf did not create its result file.")
        if not from_file:
            # A terminated process may have flushed additional completed records.
            raw_results = []
            for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and "status" in row:
                    raw_results.append(row)
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        for value in list((options.get("headers") or {}).values()) + [options.get("post_data"), options.get("proxy"), target]:
            if value:
                stderr_text = stderr_text.replace(str(value), "<redacted>")
        stderr_text = re.sub(r"(?m)^\s*::\s*(?:URL|Header|Data|Proxy|ReplayProxy)\s*:.*$",
                             " :: Request configuration: <redacted>", stderr_text)
        stderr_path.write_text(stderr_text, encoding="utf-8")
        if returncode != 0 and not stop_reason:
            errors.append(f"ffuf exited with code {returncode}.")
        reported_errors = [int(count) for count in re.findall(r"Errors:\s*(\d+)", stderr_text)]
        network_errors = max(reported_errors) if reported_errors else None
        if network_errors:
            errors.append(f"ffuf reported {network_errors} request errors.")
        lower_stderr = stderr_text.lower()
        if not stop_reason and any(term in lower_stderr for term in ("maxtime", "maximum time", "time limit")):
            stop_reason = "max_scan_seconds"
        if not stop_reason and any(term in lower_stderr for term in ("stopping", "too many", "spurious", "[err]", "[error]")):
            stop_reason = "ffuf_stopped_or_reported_errors"
        observed = [self._normalize_result(row, streamed=not from_file) for row in raw_results]
        results = [row for row in observed if self._keep_result(row, options)]
        partial = bool(stop_reason or errors or len(selected) < len(wordlist))
        if len(selected) < len(wordlist) and not stop_reason:
            stop_reason = "max_requests"
        statuses = sorted({row["status_code"] for row in observed if row["status_code"] is not None})
        stats = {"total_requests": None, "attempted_requests": None,
                 "request_count_source": "not_exposed_by_ffuf_json", "planned_requests": len(selected),
                 "response_count_scope": "returned_ffuf_records",
                 "request_budget_scope": "input_entries",
                 "returned_count": len(observed), "responses_received": len(observed),
                 "returned_results": len(results), "matched_responses": len(results), "network_errors": network_errors,
                 "status_codes": {str(code): sum(row["status_code"] == code for row in observed) for code in statuses},
                 "partial": partial, "stopped_early": bool(stop_reason), "stop_reason": stop_reason}
        data = {"engine": "ffuf_cli", "simulated": False, "results": results, "stats": stats,
                "total_requests": None, "planned_requests": len(selected), "errors": errors,
                "partial": partial, "stopped_early": bool(stop_reason), "stop_reason": stop_reason,
                "command_executed": safe_command, "returncode": returncode, "output_dir": str(run_dir),
                "measurement_notes": ["ffuf response_time is time to first response byte in seconds.",
                                      "ffuf JSON exposes returned matches, not total wire requests including redirects, calibration or retries."]}
        if options.get("auto_calibrate"):
            data["measurement_notes"].append("Auto-calibration may remove responses before live block monitoring.")
        if any(options.get(key) for key in ("extensions", "recursion", "auto_calibrate", "follow_redirects")):
            data["measurement_notes"].append("max_requests caps input entries; extensions, recursion, calibration and redirects can add HTTP requests. The scan deadline still applies.")
        success = returncode == 0 and not partial
        data["completed"] = success
        return ToolResult(success, self.name, data, raw_output=stderr_text[:2000],
                          error_message=None if success else stop_reason or "; ".join(errors),
                          execution_time=time.monotonic() - started)
