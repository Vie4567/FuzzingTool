"""Bounded HTTP comparison against independent nonexistent sibling controls.

Classification describes the observed HTTP representation, not the existence of
a route in a browser application. Original fuzzing measurements are never replaced.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from difflib import SequenceMatcher
from hashlib import sha256
from html import escape, unescape
from html.parser import HTMLParser
from http.client import IncompleteRead
import logging
import math
import posixpath
import re
import time
from urllib.error import HTTPError
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from urllib.request import Request
from uuid import uuid4

from .verification_http import ScopedVerificationTransport
from src.coordinator.runtime import current_runtime


logger = logging.getLogger("sentinel.soft404")
_BLOCKED = {401, 403, 407, 429}
_STALE = {"verification", "verification_performed", "verification_reason",
          "verification_evidence", "similarity_to_baseline"}
_CHALLENGE = re.compile(
    r"access\s+denied|verify\s+(?:that\s+)?you\s+are\s+human|checking\s+your\s+browser|"
    r"(?:g-recaptcha|hcaptcha|cf-chl-|cloudflare\s+ray\s+id)|too\s+many\s+requests|"
    r"rate\s+limit\s+exceeded|enable\s+javascript\s+and\s+cookies", re.I)
_TRACE_UUID = re.compile(r"""(\b(?:request[_-]?id|correlation[_-]?id|trace[_-]?id)["']?\s*[:=]\s*["']?)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b""", re.I)
_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_NONCE = re.compile(r"(\b(?:nonce|data-nonce|data-csrf(?:-token)?)\s*=\s*)([\"'])(.*?)\2", re.I | re.S)
_CSRF_INPUT = re.compile(r"<input\b[^>]*(?:csrf|xsrf|authenticity_token)[^>]*>", re.I | re.S)
_CSRF_META = re.compile(r"<meta\b[^>]*(?:csrf|xsrf)[^>]*>", re.I | re.S)
_VALUE = re.compile(r"(\bvalue\s*=\s*)([\"'])(.*?)\2", re.I | re.S)
_CONTENT = re.compile(r"(\bcontent\s*=\s*)([\"'])(.*?)\2", re.I | re.S)


class _HTMLFeatures(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.text, self.hidden = [], [], 0
        self.password = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        self.tags.append("<" + tag + " " + " ".join(sorted(name for name, _ in attrs)) + ">")
        if tag == "input" and any(name == "type" and str(value).lower() == "password" for name, value in attrs):
            self.password = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        self.tags.append("</" + tag + ">")
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def _number(value, name, minimum, maximum, *, integer=False):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a number") from None
    if not math.isfinite(value) or not minimum <= value <= maximum or (integer and not value.is_integer()):
        raise ValueError(f"{name} is outside its supported range")
    return int(value) if integer else value


def _features(body, url, content_type):
    """Normalize only request reflections and well identified volatile tokens."""
    parts = urlsplit(url)
    request_path = parts.path + (("?" + parts.query) if parts.query else "")
    normalized = body
    values = {url, request_path, parts.path}
    for value in sorted(values, key=len, reverse=True):
        if len(value) <= 1:
            continue
        for variant in {value, escape(value), quote(value, safe=""), value.replace("/", "\\/")}:
            normalized = re.sub(r"(?<![\w/%.-])" + re.escape(variant) + r"(?![\w/%.-])",
                                "__REQUEST_PATH__", normalized)
    normalized = _TRACE_UUID.sub(r"\1__TRACE_ID__", normalized)
    normalized = _TIMESTAMP.sub("__TIMESTAMP__", normalized)
    normalized = _NONCE.sub(lambda m: m.group(1) + m.group(2) + "__NONCE__" + m.group(2), normalized)
    normalized = _CSRF_INPUT.sub(lambda m: _VALUE.sub(lambda v: v.group(1) + v.group(2) + "__CSRF__" + v.group(2), m.group(0)), normalized)
    normalized = _CSRF_META.sub(lambda m: _CONTENT.sub(lambda v: v.group(1) + v.group(2) + "__CSRF__" + v.group(2), m.group(0)), normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    html = "html" in content_type or bool(re.match(r"\s*(?:<!doctype\s+html|<html\b)", body, re.I))
    parser = _HTMLFeatures()
    if html:
        parser.feed(normalized)
    visible = re.sub(r"\s+", " ", " ".join(parser.text)).strip() if html else normalized
    return {
        "normalized": normalized,
        "text": visible,
        "structure": "".join(parser.tags),
        "html": html,
        "sha256": sha256(normalized.encode("utf-8")).hexdigest(),
        "login_or_challenge": bool(parser.password or _CHALLENGE.search(unescape(body))),
    }


def _ratio(left, right):
    # Bounds keep SequenceMatcher's work independent of large response bodies.
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    limit = 12000
    left = left[:limit] + left[-limit:] if len(left) > limit * 2 else left
    right = right[:limit] + right[-limit:] if len(right) > limit * 2 else right
    return SequenceMatcher(None, left, right, autojunk=True).ratio()


def _compare(left, right):
    a, b = left["features"], right["features"]
    exact = left["body_sha256"] == right["body_sha256"] or a["sha256"] == b["sha256"]
    length = min(left["content_length"], right["content_length"]) / max(1, left["content_length"], right["content_length"])
    return {
        "exact_body_match": left["body_sha256"] == right["body_sha256"],
        "exact_normalized_match": a["sha256"] == b["sha256"],
        "comparison_limited": any(len(value) > 24000 for value in
                                  (a["normalized"], b["normalized"], a["text"], b["text"], a["structure"], b["structure"])),
        "content_similarity": 1.0 if exact else _ratio(a["normalized"], b["normalized"]),
        "text_similarity": 1.0 if exact else _ratio(a["text"], b["text"]),
        "structure_similarity": _ratio(a["structure"], b["structure"]) if a["html"] and b["html"] else None,
        "length_ratio": length,
    }


def _matching(comparison, threshold):
    return comparison["exact_body_match"] or comparison["exact_normalized_match"] or (not comparison["comparison_limited"] and
        comparison["content_similarity"] >= threshold
        and comparison["text_similarity"] >= max(threshold, 0.99)
        and comparison["length_ratio"] >= 0.97
        and (comparison["structure_similarity"] is None or comparison["structure_similarity"] >= threshold)
    )


def _public_measurement(row):
    return {key: value for key, value in row.items() if key != "features"}


def _candidate_url(target_url, record):
    candidate = record.get("url")
    if candidate is None:
        path = record.get("path")
        if not isinstance(path, str) or not path:
            return None
        candidate = urljoin(target_url.rstrip("/") + "/", path)
    if not isinstance(candidate, str):
        return None
    return candidate


def _group_key(url):
    parts = urlsplit(url)
    path = parts.path or "/"
    parent, filename = posixpath.split(path)
    suffix = posixpath.splitext(filename)[1]
    if len(suffix) > 16 or not re.fullmatch(r"(?:\.[a-zA-Z0-9_-]+)?", suffix):
        suffix = ""
    return (parts.scheme, parts.netloc, parent or "/", suffix,
            parts.query)


def _set_read_timeout(response, seconds):
    """Update the underlying urllib socket for the remaining read budget."""
    pending, visited = [response], set()
    while pending:
        obj = pending.pop()
        if id(obj) in visited:
            continue
        visited.add(id(obj))
        if callable(getattr(obj, "settimeout", None)):
            obj.settimeout(seconds)
            return
        for attr in ("fp", "raw", "_sock", "sock"):
            child = getattr(obj, attr, None)
            if child is not None:
                pending.append(child)


def _control_url(candidate, key):
    parts = urlsplit(candidate)
    name = "__sentinel_missing_" + uuid4().hex + key[3]
    path = key[2].rstrip("/") + "/" + name
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def verify_soft404(target_url, records, *, headers=None, allowed_origins=None,
                   auth_origins=None, verify_ssl=True, tls_ca_file=None,
                   rate_limit=1, timeout_seconds=5, max_requests=60,
                   max_duration_seconds=120, max_response_bytes=262144,
                   baseline_samples=3, similarity_threshold=0.97,
                   distinct_threshold=0.80, enabled=True, stop_reason=None, proxy_options=None):
    """Re-measure GET candidates and compare with scoped sibling controls.

    ``genuine`` means a distinct successful HTTP representation, not proof of a
    valid SPA route. Equal byte lengths alone never establish a classification.
    """
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        raise ValueError("records must be a list of mappings")
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    rate = _number(rate_limit, "rate_limit", .01, 100)
    timeout = _number(timeout_seconds, "timeout_seconds", .01, 120)
    budget = _number(max_requests, "max_requests", 1, 10000, integer=True)
    duration = _number(max_duration_seconds, "max_duration_seconds", .01, 3600)
    cap = _number(max_response_bytes, "max_response_bytes", 1, 8 * 1024 * 1024, integer=True)
    controls = _number(baseline_samples, "baseline_samples", 2, 5, integer=True)
    threshold = _number(similarity_threshold, "similarity_threshold", .9, 1)
    distinct = _number(distinct_threshold, "distinct_threshold", 0, .9)
    if distinct >= threshold:
        raise ValueError("distinct_threshold must be below similarity_threshold")
    if proxy_options is not None:
        rate, timeout = min(rate, 10), min(timeout, 30)
    runtime = current_runtime()
    if runtime:
        cap = min(cap, runtime.body_cap)
    transport = ScopedVerificationTransport(target_url, headers=headers, allowed_origins=allowed_origins,
                                     auth_origins=auth_origins, verify_ssl=verify_ssl, tls_ca_file=tls_ca_file,
                                     proxy_options=proxy_options)
    copied = deepcopy(records)
    for row in copied:
        for field in _STALE:
            row.pop(field, None)
        row.update(verification="not_checked", verification_performed=False)
    result = {
        "verified": [], "false_positives": [], "unverified": [],
        "baseline": {"groups": []}, "verification_performed": False,
        "verification_status": "skipped", "stop_reason": "completed",
        "http_policy": transport.public_settings(),
        "stats": {"total_requests": 0, "responses_received": 0, "bytes_read": 0,
                  "baseline_requests": 0, "candidate_requests": 0, "network_errors": 0},
    }
    halted = None
    if not enabled:
        halted = "disabled"
    elif stop_reason not in (None, "", "completed"):
        halted = str(stop_reason)
    elif any(row.get("status_code") in _BLOCKED or any(
            str(name).lower() == "retry-after" for name in (row.get("headers") or {})
            ) for row in copied):
        halted = "source_blocked"
    elif any(row.get("simulated") is True for row in copied):
        halted = "source_simulated"
    halted = halted or transport.stop_reason
    if halted:
        result["stop_reason"] = halted
        for row in copied:
            row["verification_reason"] = halted
        result["unverified"] = copied
        result["stats"].update(transport.metrics())
        return transport.redact(result)

    start = time.perf_counter()
    deadline, next_start = start + duration, start
    transport.dispatch_deadline = time.monotonic() + duration
    groups = {}
    stats = result["stats"]

    def classify(row, classification, reason, *, evidence=None, performed=False):
        row.update(verification=classification, verification_reason=reason,
                   verification_performed=performed)
        if evidence is not None:
            row["verification_evidence"] = evidence
        bucket = "verified" if classification == "genuine" else "false_positives" if classification in {"soft_404", "http_404"} else "unverified"
        result[bucket].append(row)

    def measure(url, kind):
        nonlocal next_start, halted
        if halted:
            return None
        if stats["total_requests"] >= budget:
            halted = "max_requests"
            return None
        now = time.perf_counter()
        if max(now, next_start) >= deadline:
            halted = "max_duration"
            return None
        if next_start > now:
            time.sleep(next_start - now)
        request_start = time.perf_counter()
        next_start = request_start + 1 / rate
        response = None
        raw = b""
        measured = {
            "url": url, "request_kind": kind,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "status_code": None, "content_length": None, "response_time": None,
            "body_complete": False, "body_truncated": False, "content_type": "",
            "content_encoding": "", "body_sha256": None, "error": None,
            "proxy_profile_id": transport.proxy_profile_id,
        }
        logger.info("Soft404 START request=%d/%d profile=%s kind=%s path=%s", stats["total_requests"] + 1, budget,
                    transport.proxy_profile_id or "direct", kind, transport.redact(urlsplit(url).path))
        try:
            try:
                response = transport.open(Request(url, headers={"Accept-Encoding": "identity"}, method="GET"),
                                          timeout=min(timeout, max(.01, deadline - request_start)))
            except HTTPError as exc:
                response = exc
            measured["status_code"] = response.code
            stats["responses_received"] += 1
            measured["content_type"] = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            measured["content_encoding"] = response.headers.get("Content-Encoding", "").strip().lower()
            measured["content_length"] = 0
            if response.code in _BLOCKED:
                halted = "http_" + str(response.code)
            elif response.headers.get("Retry-After") is not None:
                halted = "retry_after"
            if halted:
                measured["error"] = halted
            else:
                while len(raw) <= cap:
                    remaining_time = deadline - time.perf_counter()
                    if remaining_time <= 0:
                        raise TimeoutError("Soft404 duration limit reached")
                    _set_read_timeout(response, min(timeout, remaining_time))
                    try:
                        # read1 returns available bytes after one socket read;
                        # read(n) can wait indefinitely on a slow trickle.
                        read = getattr(response, "read1", response.read)
                        chunk = read(min(65536, cap + 1 - len(raw)))
                    except IncompleteRead as exc:
                        raw += exc.partial
                        raise
                    if not chunk:
                        remaining = getattr(response, "length", getattr(getattr(response, "fp", None), "length", None))
                        if remaining is not None and remaining > 0:
                            raise IncompleteRead(b"", remaining)
                        measured["body_complete"] = True
                        break
                    raw += chunk
                    if len(raw) > cap:
                        measured["body_truncated"] = True
                        break
                measured["content_length"] = len(raw)
                measured["body_sha256"] = sha256(raw).hexdigest()
                if measured["body_complete"] and raw and measured["content_encoding"] in {"", "identity"}:
                    charset = response.headers.get_content_charset() or "utf-8"
                    try:
                        text = raw.decode(charset)
                    except (LookupError, UnicodeDecodeError):
                        measured["error"] = "unsupported_text_encoding"
                    else:
                        measured["features"] = _features(text, url, measured["content_type"])
                        measured["normalized_sha256"] = measured["features"]["sha256"]
                        if measured["features"]["login_or_challenge"]:
                            halted = "login_or_challenge"
        except Exception as exc:
            measured["content_length"] = len(raw) if measured["status_code"] is not None else None
            measured["error"] = type(exc).__name__
            halted = transport.failure(exc, measured)
            if halted == "transport_error" and time.perf_counter() >= deadline:
                halted = "max_duration"
            if transport.dispatched and measured.get("proxy_connect_status") is None:
                stats["network_errors"] += 1
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception as exc:
                    if not measured["error"]:
                        stats["network_errors"] += 1
                    measured["error"] = measured["error"] or type(exc).__name__
                    halted = "transport_error"
            measured["response_time"] = (time.perf_counter() - transport.dispatched_at
                                         if transport.dispatched_at is not None else None)
        if transport.dispatched:
            stats["total_requests"] += 1
            stats[kind + "_requests"] += 1
        else:
            transport.record_measurement(measured, halted)
            return None
        transport.record_measurement(measured, halted)
        stats["bytes_read"] += measured["content_length"] or 0
        logger.info("Soft404 RESULT profile=%s status=%s connect_status=%s bytes=%s seconds=%.6f error=%s",
                    transport.proxy_profile_id or "direct", measured["status_code"], measured.get("proxy_connect_status"),
                    measured["content_length"], measured["response_time"], measured["error"])
        return measured

    def usable(measured):
        return (measured is not None and measured.get("body_complete")
                and not measured.get("error") and bool(measured.get("content_length"))
                and measured.get("features") is not None
                and not measured["features"]["login_or_challenge"]
                and measured["status_code"] in {200, 404, 410})

    for row in copied:
        if halted:
            classify(row, "not_checked", halted)
            continue
        if row.get("result_kind") == "parameter_candidates":
            classify(row, "not_checked", "parameter_candidates_not_http_evidence")
            continue
        if row.get("error") or row.get("body_complete") is False or row.get("body_truncated"):
            classify(row, "not_checked", "source_incomplete_or_error")
            continue
        if str(row.get("http_method", row.get("method", "GET"))).upper() != "GET":
            classify(row, "not_checked", "unsupported_method")
            continue
        if any(row.get(key) is not None for key in ("post_data", "request_body")):
            classify(row, "not_checked", "unsupported_request_body")
            continue
        if row.get("status_code") != 200:
            classify(row, "not_checked", "source_not_http_200")
            continue
        try:
            url = _candidate_url(target_url, row)
            if not url or not transport.allows(url):
                raise ValueError("outside scope")
            key = _group_key(url)
        except (ValueError, TypeError):
            classify(row, "not_checked", "invalid_or_out_of_scope_url")
            continue
        halted = transport.begin_unit()
        if halted:
            classify(row, "not_checked", halted)
            continue
        cache_key = (transport.proxy_profile_id, key)
        group = groups.get(cache_key)
        if group is None:
            group = {"id": "baseline_" + str(len(groups) + 1), "candidate_context": url,
                     "proxy_profile_id": transport.proxy_profile_id,
                     "stable": False, "reason": "insufficient_controls", "samples": []}
            groups[cache_key] = group
            private_controls = []
            for _ in range(controls):
                measured = measure(_control_url(url, key), "baseline")
                if measured is None:
                    break
                private_controls.append(measured)
                group["samples"].append(_public_measurement(measured))
                if halted:
                    break
            group["private_controls"] = private_controls
            if len(private_controls) == controls:
                if not all(usable(item) for item in private_controls):
                    group["reason"] = "unsafe_or_incomplete_controls"
                elif len({(item["status_code"], item["content_type"]) for item in private_controls}) != 1:
                    group["reason"] = "unstable_control_status_or_type"
                else:
                    comparisons = [_compare(private_controls[0], item) for item in private_controls[1:]]
                    group["control_similarities"] = comparisons
                    group["stable"] = all(_matching(item, threshold) for item in comparisons)
                    group["reason"] = "stable" if group["stable"] else "unstable_control_content"
            result["baseline"]["groups"].append({name: val for name, val in group.items() if name != "private_controls"})
        evidence = {"baseline_group": group["id"], "original_status_code": row.get("status_code"),
                    "proxy_profile_id": transport.proxy_profile_id,
                    "source_proxy_profile_id": row.get("proxy_profile_id"),
                    "original_content_length": row.get("content_length")}
        if halted:
            classify(row, "inconclusive", halted, evidence=evidence)
            continue
        if not group["stable"]:
            classify(row, "inconclusive", group["reason"], evidence=evidence)
            continue
        candidate = measure(url, "candidate")
        if candidate is None:
            classify(row, "not_checked", halted or "not_measured", evidence=evidence)
            continue
        evidence["candidate"] = _public_measurement(candidate)
        evidence["source_changed"] = {
            "status_code": candidate["status_code"] != row.get("status_code"),
            "content_length": candidate["content_length"] != row.get("content_length"),
        }
        if halted:
            classify(row, "inconclusive", halted, evidence=evidence, performed=True)
            continue
        if candidate["status_code"] in {404, 410} and candidate["body_complete"] and not candidate["error"]:
            classify(row, "http_404", "remeasured_http_" + str(candidate["status_code"]), evidence=evidence, performed=True)
            continue
        if not usable(candidate) or candidate["status_code"] != 200:
            reason = "candidate_login_or_challenge" if candidate.get("features", {}).get("login_or_challenge") else "unsafe_or_incomplete_candidate"
            classify(row, "inconclusive", reason, evidence=evidence, performed=True)
            continue
        comparisons = [_compare(candidate, control) for control in group["private_controls"]]
        evidence["comparisons"] = comparisons
        row["similarity_to_baseline"] = max(item["content_similarity"] for item in comparisons)
        same_type = all(candidate["content_type"] == control["content_type"] for control in group["private_controls"])
        if same_type and all(_matching(item, threshold) for item in comparisons):
            root = urlsplit(url).path in {"", "/"} or url.rstrip("/") == target_url.rstrip("/")
            classify(row, "inconclusive" if root else "soft_404",
                     "shared_homepage_or_spa_shell" if root else "matches_stable_missing_path_controls",
                     evidence=evidence, performed=True)
        elif all(not item["comparison_limited"] and item["content_similarity"] <= distinct
                 and item["text_similarity"] <= distinct for item in comparisons):
            classify(row, "genuine", "distinct_successful_response", evidence=evidence, performed=True)
        else:
            classify(row, "inconclusive", "ambiguous_similarity", evidence=evidence, performed=True)

    result["verification_performed"] = stats["total_requests"] > 0
    result["verification_status"] = "partial" if halted or result["unverified"] else "completed"
    if not stats["total_requests"]:
        result["verification_status"] = "skipped"
    result["stop_reason"] = halted or "completed"
    stats["wall_time"] = time.perf_counter() - start
    stats["metric_scope"] = "Fresh baseline and candidate GET requests; original measurements remain unchanged. Body lengths count bytes actually read."
    stats.update(transport.metrics())
    return transport.redact(result)
