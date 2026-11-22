"""Validate Coordinator inputs before any provider or target network activity."""
from copy import deepcopy
import ipaddress
import math
from pathlib import Path
import re
from urllib.parse import quote, urlsplit, urlunsplit, unquote

from src.tools.recon_http import RECON_OPTION_KEYS, _validate_headers, ScopedReconTransport


class InputValidationError(ValueError):
    pass


def _fail(field, requirement):
    # Field names/constraints only: input values may contain credentials.
    raise InputValidationError(f"{field}: {requirement}") from None


def number(value, field, minimum, maximum, integer=False):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or isinstance(value, float) and not math.isfinite(value)):
        _fail(field, "must be a finite number")
    if integer and not isinstance(value, int):
        _fail(field, "must be an integer")
    if not minimum <= value <= maximum:
        _fail(field, f"must be between {minimum} and {maximum}")
    return value


def validate_url(value, field="target_url", origin_only=False):
    if not isinstance(value, str) or not value or len(value) > 8192:
        _fail(field, "must be a nonempty HTTP(S) URL, at most 8192 characters")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        _fail(field, "whitespace, controls and backslashes are not allowed")
    if re.search(r"%(?![0-9a-fA-F]{2})", value) or re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", value, re.I):
        _fail(field, "invalid or control-character URL encoding")
    try:
        p = urlsplit(value)
        host, port = p.hostname, p.port
        if p.scheme not in {"http", "https"} or not host or p.username is not None or p.password is not None:
            raise ValueError()
        if p.fragment or "#" in value or (port is not None and not 1 <= port <= 65535):
            raise ValueError()
        if p.netloc.endswith(":") or "%" in host:
            raise ValueError()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
            # Do not reinterpret malformed IPv4 or legacy numeric addresses as
            # DNS names: resolvers disagree about octal, shorthand and integers.
            if re.fullmatch(r"[0-9.]+", host) or re.fullmatch(r"0[xX][0-9a-fA-F]+", host):
                raise ValueError()
            if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                                      for part in host.rstrip(".").split(".")):
                raise ValueError()
        if origin_only and (p.path not in {"", "/"} or p.query):
            raise ValueError()
        host = f"[{host}]" if ":" in host else host
        netloc = host + (f":{port}" if port is not None and port != (443 if p.scheme == "https" else 80) else "")
        return urlunsplit((p.scheme, netloc, quote(p.path, safe="/:@!$&'()*+,;=-._~%"),
                           quote(p.query, safe="/?@:!$&'()*+,;=-._~%"), ""))
    except (ValueError, UnicodeError):
        _fail(field, "requires a valid HTTP(S) host/port, without userinfo or fragment")


def validate_wordlist(target_url, entries, *, allow_empty=False):
    if not isinstance(entries, list) or len(entries) > 100000:
        _fail("wordlist", "must be a list of at most 100000 strings")
    target = urlsplit(validate_url(target_url))
    result = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, str) or not entry or len(entry) > 8192:
            _fail("wordlist entry", "must be a nonempty string of at most 8192 characters")
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in entry) or "\\" in entry:
            _fail("wordlist entry", "whitespace, controls and backslashes are not allowed")
        if re.search(r"%(?![0-9a-fA-F]{2})", entry) or re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", entry, re.I):
            _fail("wordlist entry", "invalid or control-character encoding")
        try:
            p = urlsplit(entry)
            if p.scheme:
                p = urlsplit(validate_url(entry, "wordlist URL"))
                if (p.scheme, p.netloc) != (target.scheme, target.netloc):
                    _fail("wordlist URL", "must use the target origin")
                entry = urlunsplit(("", "", p.path or "/", p.query, ""))
            elif p.netloc or entry.startswith("//") or "#" in entry:
                _fail("wordlist entry", "network-path URLs and fragments are not allowed")
        except ValueError:
            _fail("wordlist entry", "malformed URL/path")
        # Keep the caller's first spelling for compatibility, but path aliases
        # must not inflate selection counts before engine normalization.
        canonical = entry.lstrip("/") or "/"
        if canonical not in seen:
            result.append(entry)
            seen.add(canonical)
    if not result and not allow_empty:
        _fail("wordlist", "must contain at least one entry")
    return result


_TOP = set(RECON_OPTION_KEYS) | {
    "token", "custom_headers", "llm_model", "llm_temperature", "api_key", "base_url",
    "knowledge_store_dir", "artifact_root", "output_dir", "recon_options", "fuzzing_options",
    "parameter_options", "soft404_options", "wordlist", "wordlist_file", "wordlist_mode",
    "max_wordlist_entries", "pipeline_timeout_seconds", "llm_timeout_seconds", "max_retries",
    "max_iterations", "max_llm_calls", "http_rate_limit", "http_max_requests",
    "http_timeout_seconds", "http_max_response_bytes", "run_all_modules", "llm_max_tokens",
    "multi_origin",
}
_BOOLS = {"enabled", "auto_calibrate", "recursion", "follow_redirects", "follow_redirect",
          "stop_on_block", "stop_on_errors", "stop_on_all_errors", "stop_on_429",
          "respect_retry_after", "use_pattern_engine", "run_all_modules", "verify_ssl"}
_NUMBERS = {
    "rate_limit": (.01, 100), "rate": (.01, 100), "delay_ms": (0, 300000),
    "timeout_seconds": (.01, 120), "timeout": (.01, 120), "max_duration_seconds": (.01, 3600),
    "max_scan_seconds": (.01, 3600), "max_retry_after_seconds": (0, 300),
    "proxy_check_timeout_seconds": (.01, 30), "proxy_fetch_timeout_seconds": (.01, 30),
    "proxy_refresh_seconds": (0, 86400), "similarity_threshold": (0, 1), "distinct_threshold": (0, 1),
}
_INTS = {"max_requests": (1, 10000), "threads": (1, 256), "workers": (1, 256),
         "recursion_depth": (1, 20), "max_response_bytes": (1, 64*1024*1024),
         "block_threshold": (1, 100), "consecutive_403_limit": (1, 100), "max_consecutive_403": (1, 100),
         "proxy_count": (1, 8), "proxy_candidate_limit": (1, 100), "baseline_samples": (2, 10),
         "max_pattern_endpoints": (1, 10000)}
_FUZZ = (set(_BOOLS) - {"enabled", "run_all_modules", "verify_ssl"}
         | set(_NUMBERS) - {"similarity_threshold", "distinct_threshold"}
         | set(_INTS) - {"baseline_samples"}) | {
    "engine", "headers", "http_method", "method", "post_data", "body", "proxy",
    "proxy_source", "proxy_profiles", "proxy_profiles_env", "proxy_healthcheck_url", "allowed_origins",
    "ffuf_binary", "extensions", "match_codes", "filter_codes", "filter_size", "filter_words",
    "filter_lines", "lab_source_ips", "selected_pattern_ids",
}
_VERIFY = {"headers", "allowed_origins", "auth_origins", "verify_ssl", "tls_ca_file", "cookie", "bearer_token",
           "enabled", "rate_limit", "timeout_seconds", "max_requests", "max_duration_seconds", "max_response_bytes"}


def _mapping(options, field, allowed):
    if not isinstance(options, dict):
        _fail(field, "must be an object")
    if any(not isinstance(k, str) for k in options) or set(options) - allowed:
        _fail(field, "contains unsupported option(s); consult the Coordinator configuration schema")
    for key, value in options.items():
        label = f"{field}.{key}"
        if key in _BOOLS:
            if not isinstance(value, bool):
                _fail(label, "must be boolean")
        elif key in _NUMBERS:
            number(value, label, *_NUMBERS[key])
        elif key in _INTS:
            number(value, label, *_INTS[key], integer=True)
        elif key in {"headers", "custom_headers"}:
            try:
                _validate_headers(value)
                if len({name.lower() for name in value}) != len(value):
                    raise ValueError()
                for header_value in value.values():
                    header_value.encode("latin-1")
            except (TypeError, ValueError, UnicodeError):
                _fail(label, "invalid HTTP headers")
        elif key in {"allowed_origins", "auth_origins"}:
            if not isinstance(value, list) or len(value) > 32 or (key == "allowed_origins" and not value):
                _fail(label, "must be a list of at most 32 exact origins")
            options[key] = [validate_url(v, label, origin_only=True).rstrip("/") for v in value]
        elif key == "account":
            _mapping(value, label, {"username", "password", "login_url"})
            if not all(isinstance(value.get(k), str) and value[k] for k in ("username", "password")):
                _fail(label, "requires username and password strings")
        elif key == "proxy_profiles":
            if not isinstance(value, list) or not value:
                _fail(label, "must contain explicit proxy profiles")
        elif key == "extensions":
            if not isinstance(value, (str, list)):
                _fail(label, "must be a string or a list of extension strings")
            parts = value.split(",") if isinstance(value, str) else value
            if any(not isinstance(v, str) or not re.fullmatch(r"\.?[A-Za-z0-9][A-Za-z0-9._-]{0,63}", v) for v in parts):
                _fail(label, "contains invalid extension(s)")
        elif key in {"match_codes", "filter_codes", "filter_size", "filter_words", "filter_lines"}:
            if value is not None and not isinstance(value, (str, int, list)):
                _fail(label, "must be a string, integer or list")
            values = value if isinstance(value, list) else [value]
            if any(v is not None and (isinstance(v, bool) or not isinstance(v, (str, int))) for v in values):
                _fail(label, "invalid filter/extension value")
        elif key in {"lab_source_ips", "selected_pattern_ids"}:
            if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
                _fail(label, "must be a list of strings")
        elif key == "tls_ca_file" and value is not None:
            try:
                if not isinstance(value, str) or not value:
                    raise ValueError()
                path = Path(value).expanduser().resolve()
                if not path.is_file():
                    raise ValueError()
                # The isolated worker has a different cwd; preserve the exact CA.
                options[key] = str(path)
            except (OSError, ValueError, RuntimeError):
                _fail(label, "must name an existing CA certificate file")
        elif value is not None and not isinstance(value, str):
            _fail(label, "must be a string")
        if isinstance(value, str) and any(ord(char) < 32 or ord(char) == 127 for char in value) and key not in {"body", "post_data"}:
            _fail(label, "controls are not allowed")
        if key in {"cookie", "bearer_token", "token"} and value is not None:
            try:
                value.encode("latin-1")
            except UnicodeError:
                _fail(label, "must be encodable as an HTTP header")


def validate_pipeline_input(target_url, config=None):
    target = validate_url(target_url)
    if "FUZZ" in target:
        _fail("target_url", "Coordinator expects a concrete target URL, not a FUZZ template")
    if config is None:
        config = {}
    if not isinstance(config, dict) or any(not isinstance(k, str) for k in config) or set(config) - _TOP:
        _fail("config", "must be an object containing supported Coordinator options")
    c = deepcopy(config)
    if "multi_origin" in c:
        from .origins import normalize_origin_config, canonical_origin
        try:
            c["multi_origin"] = normalize_origin_config(c["multi_origin"])
            if canonical_origin(target) not in c["multi_origin"]["approved_origins"]:
                raise ValueError()
        except (ValueError, TypeError):
            _fail("multi_origin", "requires a public explicit origin policy including the primary target")
    defaults = {"pipeline_timeout_seconds": 600, "llm_timeout_seconds": 30, "max_retries": 2,
                "max_iterations": 20, "max_llm_calls": 50, "http_rate_limit": 2,
                "http_max_requests": 500, "http_timeout_seconds": 10,
                "http_max_response_bytes": 2*1024*1024, "run_all_modules": False, "llm_max_tokens": 4096}
    for key, value in defaults.items():
        c.setdefault(key, value)
    limits = {"pipeline_timeout_seconds": (.05, 7200), "llm_timeout_seconds": (.01, 300),
              "http_rate_limit": (.01, 100), "http_timeout_seconds": (.01, 120), "llm_temperature": (0, 2)}
    ints = {"max_retries": (0, 10), "max_iterations": (5, 100), "max_llm_calls": (1, 500),
            "http_max_requests": (1, 10000), "http_max_response_bytes": (1, 64*1024*1024),
            "max_wordlist_entries": (1, 10000), "llm_max_tokens": (256, 32768)}
    for key in limits:
        if key in c:
            number(c[key], key, *limits[key])
    for key in ints:
        if key in c:
            number(c[key], key, *ints[key], integer=True)
    if not isinstance(c["run_all_modules"], bool):
        _fail("run_all_modules", "must be boolean")
    for key in ("llm_model", "api_key", "base_url", "knowledge_store_dir", "artifact_root", "output_dir"):
        if key in c and (not isinstance(c[key], str) or not c[key].strip() or any(ord(x) < 32 for x in c[key])):
            _fail(key, "must be a nonempty string without controls")
    if "base_url" in c:
        c["base_url"] = validate_url(c["base_url"], "base_url")
        if urlsplit(c["base_url"]).query:
            _fail("base_url", "LLM API base URLs must not contain a query")
    for key in ("knowledge_store_dir", "artifact_root", "output_dir"):
        if key in c:
            try:
                path = Path(c[key]).expanduser().resolve()
                if any(parent.exists() and not parent.is_dir() for parent in (path, *path.parents)):
                    raise ValueError()
                c[key] = str(path)
            except (OSError, ValueError, RuntimeError):
                _fail(key, "must name a directory or a creatable directory path")
    legacy = {k: c[k] for k in set(RECON_OPTION_KEYS) | {"token", "custom_headers"} if k in c}
    _mapping(legacy, "config", set(RECON_OPTION_KEYS) | {"token", "custom_headers"})
    c.update(legacy)
    for key, allowed in (("recon_options", set(RECON_OPTION_KEYS) | {"token", "custom_headers"}),
                         ("fuzzing_options", _FUZZ), ("parameter_options", _VERIFY),
                         ("soft404_options", _VERIFY | {"baseline_samples", "similarity_threshold", "distinct_threshold"})):
        if key in c:
            _mapping(c[key], key, allowed)
    from src.tools.recon_http import recon_options_from_config
    auth = recon_options_from_config(c)
    # Validate TLS, origin sets and header shape without network/auto-login.
    try:
        ScopedReconTransport(target, **{k: auth[k] for k in ("headers", "allowed_origins", "auth_origins", "verify_ssl", "tls_ca_file") if k in auth})
    except (ValueError, OSError, TypeError):
        _fail("recon_options", "invalid scope, auth origin, headers or TLS CA configuration")
    for section in ("parameter_options", "soft404_options"):
        v = c.get(section, {})
        if "max_response_bytes" in v:
            number(v["max_response_bytes"], section + ".max_response_bytes", 1, 8*1024*1024, integer=True)
        try:
            ScopedReconTransport(target, **{k: v.get(k, auth.get(k)) for k in ("headers", "allowed_origins", "auth_origins", "tls_ca_file")},
                                 verify_ssl=v.get("verify_ssl", True))
        except (ValueError, OSError, TypeError):
            _fail(section, "invalid scope, auth origin, headers or TLS CA configuration")
        if section == "soft404_options" and v.get("distinct_threshold", .8) >= v.get("similarity_threshold", .97):
            _fail(section, "distinct_threshold must be smaller than similarity_threshold")
    if auth.get("account", {}).get("login_url"):
        login = validate_url(auth["account"]["login_url"], "account.login_url")
        allowed = auth.get("auth_origins", [urlunsplit((*urlsplit(target)[:2], "", "", ""))])
        if urlunsplit((*urlsplit(login)[:2], "", "", "")) not in allowed:
            _fail("account.login_url", "must be within auth_origins")
    fuzz = c.get("fuzzing_options", {})
    for alias, canonical in (("rate", "rate_limit"), ("workers", "threads"),
                             ("timeout", "timeout_seconds"), ("method", "http_method"),
                             ("body", "post_data"), ("max_duration_seconds", "max_scan_seconds"),
                             ("max_consecutive_403", "consecutive_403_limit")):
        if alias in fuzz:
            if canonical in fuzz and fuzz[canonical] != fuzz[alias]:
                _fail("fuzzing_options", f"conflicting {alias}/{canonical} options")
            fuzz.setdefault(canonical, fuzz.pop(alias))
    if fuzz.get("engine", "auto") not in {"auto", "python_http", "proxy_http", "ffuf_cli", "loopback_lab"}:
        _fail("fuzzing_options.engine", "unsupported engine")
    engine = fuzz.get("engine", "auto")
    if engine in {"auto", "ffuf_cli"} or "ffuf_binary" in fuzz:
        from src.tools.ffuf_helper import FfufToolHelper
        try:
            binary = FfufToolHelper.resolve_binary(fuzz.get("ffuf_binary"))
        except (ValueError, OSError, TypeError):
            _fail("fuzzing_options.ffuf_binary", "configured executable does not exist")
        if engine == "ffuf_cli" and not binary:
            _fail("fuzzing_options.engine", "ffuf_cli requires an installed ffuf executable")
        if engine == "auto":
            engine = "ffuf_cli" if binary else "python_http"
    if fuzz.get("follow_redirects") or fuzz.get("follow_redirect"):
        _fail("fuzzing_options", "Coordinator records redirects without following them")
    if engine in {"python_http", "proxy_http", "loopback_lab"} and fuzz.get("recursion"):
        _fail("fuzzing_options.recursion", "not supported by the selected engine")
    if engine in {"python_http", "proxy_http", "loopback_lab"}:
        if fuzz.get("threads", 1) != 1:
            _fail("fuzzing_options.threads", "selected engine supports one sequential worker")
        for key in ("extensions", "auto_calibrate", "filter_codes", "filter_size", "filter_words", "filter_lines"):
            if fuzz.get(key):
                _fail("fuzzing_options." + key, "not applied by the selected raw HTTP engine")
        if fuzz.get("match_codes") not in (None, "all", ["all"]):
            _fail("fuzzing_options.match_codes", "raw HTTP engines collect all status codes")
    from src.tools.http_fuzzing import _SPOOF_HEADERS
    if any(key.lower() in _SPOOF_HEADERS for key in fuzz.get("headers", {})):
        _fail("fuzzing_options.headers", "client-IP spoofing headers are unsupported")
    for key in ("match_codes", "filter_codes", "filter_size", "filter_words", "filter_lines"):
        raw = fuzz.get(key)
        if raw is None:
            continue
        terms = raw if isinstance(raw, list) else str(raw).split(",")
        for term in terms:
            if key == "match_codes" and str(term) == "all":
                continue
            if not re.fullmatch(r"\d+(?:-\d+)?", str(term)):
                _fail("fuzzing_options." + key, "must contain numeric values/ranges")
            values = [int(part) for part in str(term).split("-")]
            if values[0] > values[-1] or (key.endswith("codes") and any(n < 100 or n > 599 for n in values)):
                _fail("fuzzing_options." + key, "invalid numeric range")
    if fuzz.get("proxy"):
        try:
            proxy = urlsplit(fuzz["proxy"])
            if proxy.scheme not in {"http", "https", "socks5"} or not proxy.hostname or proxy.path not in {"", "/"} or proxy.query or proxy.fragment:
                raise ValueError()
            if proxy.port is not None and not 1 <= proxy.port <= 65535:
                raise ValueError()
            if fuzz["proxy"].endswith(":") or any(char.isspace() for char in fuzz["proxy"]):
                raise ValueError()
            authority = proxy.netloc.rsplit("@", 1)[-1]
            validate_url("http://" + authority, "fuzzing_options.proxy", origin_only=True)
            if proxy.username is not None or proxy.password is not None:
                if not proxy.username or proxy.password is None or re.search(r"%(?![0-9A-Fa-f]{2})", proxy.username + proxy.password):
                    raise ValueError()
                decoded = unquote(proxy.username + proxy.password)
                if any(ord(char) < 32 or ord(char) == 127 for char in decoded):
                    raise ValueError()
            if engine != "ffuf_cli" and proxy.scheme == "socks5":
                raise ValueError()
        except ValueError:
            _fail("fuzzing_options.proxy", "invalid proxy URL for selected engine")
    if "http_method" in fuzz or "method" in fuzz:
        method = fuzz.get("http_method", fuzz.get("method"))
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            _fail("fuzzing_options.http_method", "unsupported HTTP method")
    from src.tools.proxy_profiles import PROXY_OPTION_KEYS
    if engine == "proxy_http":
        from src.tools.proxy_profiles import ProxyProfilePool
        try:
            if fuzz.get("proxy_healthcheck_url") is not None:
                fuzz["proxy_healthcheck_url"] = validate_url(fuzz["proxy_healthcheck_url"], "fuzzing_options.proxy_healthcheck_url")
            pool = ProxyProfilePool.from_options(fuzz, target)
            for record in pool._records.values():
                validate_url("http://" + record["profile"][1], "fuzzing_options.proxy_profiles", origin_only=True)
            if fuzz.get("threads", 1) != 1 or fuzz.get("workers", 1) != 1 or fuzz.get("stop_on_429", True) is not True:
                raise ValueError()
            if fuzz.get("proxy") or fuzz.get("stop_on_block", True) is not True:
                raise ValueError()
            if "lab_source_ips" in fuzz:
                raise ValueError()
            for k in ("block_threshold", "consecutive_403_limit", "max_consecutive_403"):
                if k in fuzz and fuzz[k] != 3:
                    raise ValueError()
            number(fuzz.get("rate_limit", 2), "proxy rate", .01, 10)
            number(fuzz.get("timeout_seconds", 10), "proxy timeout", .01, 30)
            number(fuzz.get("max_requests", 100), "proxy budget", 1, 1000, integer=True)
            number(fuzz.get("max_scan_seconds", 120), "proxy duration", .01, 600)
        except (TypeError, ValueError):
            _fail("fuzzing_options", "invalid proxy pool/worker/stop configuration")
    elif any(k in fuzz for k in PROXY_OPTION_KEYS):
        _fail("fuzzing_options", "proxy profile configuration requires proxy_http")
    if engine == "loopback_lab":
        from src.tools.loopback_rotation_lab import _loopback_target, _source_addresses, _CLIENT_IP_HEADERS
        try:
            _, _, _, family = _loopback_target(target)
            _source_addresses(fuzz.get("lab_source_ips"), family)
            if fuzz.get("proxy") or any(key.lower() in _CLIENT_IP_HEADERS for key in fuzz.get("headers", {})):
                raise ValueError()
            if any(fuzz.get(key, True) is not True for key in ("stop_on_block", "stop_on_429")):
                raise ValueError()
            if any(fuzz[key] != 3 for key in ("block_threshold", "consecutive_403_limit") if key in fuzz):
                raise ValueError()
            for key, default, minimum, maximum in (("rate_limit", 2, .01, 10), ("timeout_seconds", 10, .01, 10),
                    ("max_scan_seconds", 60, .01, 60), ("delay_ms", 0, 0, 60000),
                    ("max_requests", 4, 1, 100), ("max_response_bytes", 2*1024*1024, 1, 2*1024*1024)):
                number(fuzz.get(key, default), "loopback " + key, minimum, maximum)
            if len((fuzz.get("post_data") or "").encode("utf-8")) > 2*1024*1024:
                raise ValueError()
        except (TypeError, ValueError):
            _fail("fuzzing_options", "invalid loopback target, source, limits or stop configuration")
    elif "lab_source_ips" in fuzz:
        _fail("fuzzing_options.lab_source_ips", "requires loopback_lab")
    if "wordlist" in c and "wordlist_file" in c:
        _fail("wordlist", "choose wordlist or wordlist_file, not both")
    if "wordlist_file" in c:
        try:
            if not isinstance(c["wordlist_file"], str):
                raise ValueError()
            path = Path(c["wordlist_file"])
            if not path.is_file() or path.stat().st_size > 8*1024*1024:
                raise ValueError()
            c["wordlist"] = [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
            c.pop("wordlist_file")
        except (ValueError, OSError, UnicodeError):
            _fail("wordlist_file", "requires a readable UTF-8 file of at most 8 MiB")
    if "wordlist" in c:
        c["wordlist"] = validate_wordlist(target, c["wordlist"])
    c.setdefault("wordlist_mode", "provided" if "wordlist" in c else "generated")
    if not isinstance(c["wordlist_mode"], str) or c["wordlist_mode"] not in {"provided", "merge", "generated"}:
        _fail("wordlist_mode", "must be provided, merge or generated")
    if c["wordlist_mode"] in {"provided", "merge"} and "wordlist" not in c:
        _fail("wordlist_mode", "provided/merge requires an input wordlist")
    if c["wordlist_mode"] == "generated" and "wordlist" in c:
        _fail("wordlist_mode", "generated mode must not silently ignore an input wordlist")
    return target, c
