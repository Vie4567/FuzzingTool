"""Passive, bounded literal discovery. No JS execution, constant folding or I/O."""
from bisect import bisect_right
from hashlib import sha256
import json
import re
from urllib.parse import urlsplit


def content_id(body):
    return sha256(body.encode("utf-8")).hexdigest()


def resource_kind(url, *, hint=None):
    path = urlsplit(url).path.lower()
    if re.search(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|ts|tsx)$", path):
        return "static_asset", .9, "asset_extension"
    if hint in {"http_call", "openapi", "api_attribute"}:
        return "api_reference", 1.0, "explicit_" + hint
    if re.match(r"/(?:api|v[0-9]+|rpc)(?:/|$)", path):
        return "api_reference", .6, "route_prefix_hint"
    if hint == "navigation":
        return "frontend_route", .9, "navigation_declaration"
    return "unknown", None, None


def annotate(row, *, source_type, source_url, digest, location, hint=None):
    kind, confidence, basis = resource_kind(row["url"], hint=hint)
    row.update(source_type=source_type, source_url=source_url, source_sha256=digest,
               evidence_location=location, resource_type=kind,
               confidence=confidence, confidence_basis=basis,
               verification_status="not_verified")
    key = json.dumps([source_url, digest, location], sort_keys=True)
    row["evidence_refs"] = ["ev_" + sha256(key.encode()).hexdigest()[:24]]
    return row


_LEX = re.compile(
    r"(?P<space>\s+)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|"
    r'''(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|'''
    r"(?P<name>[A-Za-z_$][\w$]*)|(?P<punct>.)", re.S)


def _literal(tokens):
    if len(tokens) != 1 or tokens[0][0] != "string":
        return None
    raw = tokens[0][1]
    if "${" in raw:
        return None
    if "\\" not in raw:
        return raw[1:-1]
    try:
        return json.loads(raw) if raw.startswith('"') else None
    except ValueError:
        return None


def _split(tokens):
    """Split top-level comma-separated arguments/properties only."""
    parts, start, depth = [], 0, 0
    for i, token in enumerate(tokens):
        value = token[1] if token[0] != "string" else ""
        if value in ("(", "[", "{"):
            depth += 1
        elif value in (")", "]", "}"):
            depth -= 1
        elif value == "," and depth == 0:
            parts.append(tokens[start:i])
            start = i + 1
    return parts + [tokens[start:]]


def _properties(tokens):
    if not tokens or tokens[0][1] != "{" or tokens[-1][1] != "}":
        return {}
    result = {}
    for part in _split(tokens[1:-1]):
        if not part:
            continue
        if len(part) < 3 or part[1][1] != ":":
            return {}  # spread/computed properties can override an apparent literal
        key = _literal(part[:1]) if part[0][0] == "string" else part[0][1]
        if key in result:
            return {}
        result[key] = part[2:]
    return result


def extract_javascript(body, base_url, source_url):
    from .recon_observations import path_observation, query_parameters, target_paths, unique_records
    # Cap work explicitly rather than executing JS or guessing unresolved URLs.
    if len(body.encode("utf-8")) > 5_000_000:
        raise ValueError("JavaScript discovery size limit")
    tokens = []
    for match in _LEX.finditer(body):
        if match.lastgroup not in {"space", "comment"}:
            if len(tokens) >= 250000:
                raise ValueError("JavaScript discovery token limit")
            tokens.append((match.lastgroup, match.group(), match.start(), match.end()))
    digest = content_id(body)
    lines = [0] + [m.end() for m in re.finditer("\n", body)]
    observations, unresolved, parameters, covered = [], [], [], set()

    def emit(value, method, token, *, hint=None, reason=None):
        offset = token[2]
        index = bisect_right(lines, offset) - 1
        location = {"offset": offset, "end_offset": token[3], "line": index + 1,
                    "column": offset - lines[index] + 1}
        row = path_observation(value, base_url, "javascript", method=method) if value is not None else None
        if row is None:
            key = json.dumps([source_url, digest, location], sort_keys=True)
            unresolved.append({"url": None, "origin": None, "method": method,
                "source": "javascript", "source_type": "javascript", "source_url": source_url,
                "source_sha256": digest, "evidence_location": location,
                "evidence_refs": ["ev_" + sha256(key.encode()).hexdigest()[:24]],
                "resource_type": "unknown", "classification": "inferred", "confidence": None,
                "confidence_basis": None, "reason": reason or "unresolved_url_expression",
                "attempted": None, "verification_status": "not_verified"})
            return
        annotate(row, source_type="javascript", source_url=source_url, digest=digest, location=location, hint=hint)
        observations.append(row)
        for param in query_parameters(row["url"], "javascript", source_url, method=method):
            param.update(evidence_refs=row["evidence_refs"], evidence_location=location)
            parameters.append(param)

    i = 0
    while i < len(tokens):
        name = tokens[i][1]
        opening, explicit, options_call = None, None, False
        if name == "fetch" and i + 1 < len(tokens) and tokens[i + 1][1] == "(":
            opening = i + 1
        elif name == "axios":
            if i + 1 < len(tokens) and tokens[i + 1][1] == "(":
                opening, options_call = i + 1, True
            elif i + 3 < len(tokens) and tokens[i + 1][1] == "." and tokens[i + 3][1] == "(":
                verb = tokens[i + 2][1]
                if verb in {"get", "post", "put", "patch", "delete", "head", "options", "request"}:
                    opening, options_call = i + 3, verb == "request"
                    explicit = verb.upper() if not options_call else None
        if opening is None:
            i += 1
            continue
        depth, end = 1, opening + 1
        while end < len(tokens) and depth:
            if tokens[end][0] != "string":
                depth += int(tokens[end][1] == "(") - int(tokens[end][1] == ")")
            if depth:
                end += 1
        if depth:
            covered.update(range(i, len(tokens)))
            emit(None, explicit, tokens[i], reason="incomplete_call")
            break
        args = _split(tokens[opening + 1:end])
        props = _properties(args[0] if options_call else args[1] if len(args) > 1 else [])
        method = explicit or _literal(props.get("method", []))
        method = method.upper() if isinstance(method, str) and re.fullmatch(r"[A-Za-z]+", method) else None
        value = _literal(props.get("url", [])) if options_call else _literal(args[0])
        reason = None
        if name == "axios" and value is not None and not value.startswith(("http://", "https://")):
            if "baseURL" in props or any(t[0] == "name" and t[1] == "baseURL" for t in tokens):
                value, reason = None, "axios_base_url_not_resolved"
        span = (tokens[i][0], tokens[i][1], tokens[i][2], tokens[end][3])
        emit(value, method, span, hint="http_call", reason=reason)
        covered.update(range(i, end + 1))
        i = end + 1

    for i, token in enumerate(tokens):
        if i in covered or token[0] != "string":
            continue
        value = _literal([token])
        raw = token[1][1:-1]
        if not raw.startswith(("/", "http://", "https://", "./", "../", "api/", "v1/")):
            continue
        adjacent_concat = ((i and tokens[i-1][1] == "+") or (i + 1 < len(tokens) and tokens[i+1][1] == "+"))
        if adjacent_concat or value is None:
            emit(None, None, token)
            continue
        key = tokens[i-2][1].strip("\"'") if i > 1 and tokens[i-1][1] == ":" else None
        emit(value, None, token, hint="navigation" if key in {"route", "path"} else None)
    observations = unique_records(observations)
    api_origins = sorted({row["origin"] for row in observations
                          if row["resource_type"] == "api_reference" and row["origin"] !=
                          (urlsplit(base_url).scheme + "://" + urlsplit(base_url).netloc)})
    return {"paths": target_paths(observations, base_url), "observations": observations,
            "params": sorted({row["name"] for row in parameters}), "parameters": unique_records(parameters),
            "api_origins": api_origins, "unresolved_references": unresolved}
