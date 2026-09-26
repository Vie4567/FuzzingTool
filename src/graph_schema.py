"""Graph identities shared by the recon writer and MCP server (no I/O)."""

import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit


ALLOWED_LABELS = frozenset({"Target", "Technology", "Endpoint", "Parameter", "Finding"})
RELATIONSHIP_LABELS = {
    "USES": ("Target", "Technology"),
    "HAS_ENDPOINT": ("Target", "Endpoint"),
    "HAS_PARAM": ("Endpoint", "Parameter"),
    "LINKS_TO": ("Endpoint", "Endpoint"),
    "FLAGGED_AS": ("Endpoint", "Finding"),
}
ALLOWED_RELATIONSHIPS = frozenset(RELATIONSHIP_LABELS)


def normalize_target_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not supported")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port and parsed.port != default_port:
        host += f":{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path.rstrip("/"), parsed.query, ""))


def normalize_endpoint_path(path: str) -> str:
    path = path.split("?", 1)[0].split("#", 1)[0]
    return re.sub(r"/+", "/", "/" + path.strip("/")) or "/"


def _digest(parts: list[str]) -> str:
    raw = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def endpoint_uid(target_url: str, method: str, path: str) -> str:
    return _digest([normalize_target_url(target_url), method.upper(), normalize_endpoint_path(path)])


def scoped_uid(label: str, properties: dict) -> str:
    parent = properties.get("_endpoint_uid")
    if not parent:
        raise ValueError(f"{label} requires _endpoint_uid")
    fields = ("name", "location") if label == "Parameter" else ("type", "description")
    if any(not isinstance(properties.get(key), str) or not properties[key] for key in fields):
        raise ValueError(f"{label} requires {', '.join(fields)}")
    return _digest([label, parent, *(properties[key] for key in fields)])


def prepare_properties(label: str, properties: dict, *, lookup: bool = False) -> dict:
    """Validate identity before a write; lookups may use an existing unique UID."""
    if label not in ALLOWED_LABELS:
        raise ValueError(f"Unsupported label: {label}")
    props = dict(properties)
    if lookup and label in {"Endpoint", "Parameter", "Finding"} and props.get("_uid"):
        return {"_uid": props["_uid"]}
    if label == "Target":
        props["url"] = normalize_target_url(props.get("url", ""))
    elif label == "Technology":
        if not isinstance(props.get("name"), str) or not props["name"].strip():
            raise ValueError("Technology requires name")
        props["name"] = props["name"].strip()
    elif label == "Endpoint":
        if not props.get("_target_url") or not props.get("path"):
            raise ValueError("Endpoint requires _target_url and path")
        props["_target_url"] = normalize_target_url(props["_target_url"])
        props["path"] = normalize_endpoint_path(props["path"])
        props["method"] = props.get("method", "GET").upper()
        if not re.fullmatch(r"[A-Z]+", props["method"]):
            raise ValueError("Invalid HTTP method")
        props["_uid"] = endpoint_uid(props["_target_url"], props["method"], props["path"])
    else:
        props["_uid"] = scoped_uid(label, props)
    return props


def identity_key(label: str, properties: dict) -> tuple[str, str]:
    key = {"Target": "url", "Technology": "name"}.get(label, "_uid")
    value = properties.get(key)
    if not value:
        raise ValueError(f"{label} requires identity {key}")
    return key, value


GRAPH_SCHEMA = {
    "version": "2.0",
    "labels": {
        "Target": {"properties": ["url", "created_at"], "identity": "url"},
        "Technology": {"properties": ["name", "category"], "identity": "name"},
        "Endpoint": {
            "properties": ["path", "method", "status_code", "_uid", "_target_url"],
            "identity": "SHA256 JSON tuple (_target_url, method, case-sensitive normalized path)",
        },
        "Parameter": {
            "properties": ["name", "location", "_uid", "_endpoint_uid"],
            "identity": "SHA256 JSON tuple (Parameter, _endpoint_uid, name, location)",
        },
        "Finding": {
            "properties": ["type", "severity", "description", "_uid", "_endpoint_uid"],
            "identity": "SHA256 JSON tuple (Finding, _endpoint_uid, type, description)",
        },
    },
    "relationships": {
        rel: f"(:{labels[0]})-[:{rel}]->(:{labels[1]})"
        for rel, labels in RELATIONSHIP_LABELS.items()
    },
    "identity_rules": {
        "idempotency": "All node/relationship tools use MERGE and unique identities",
        "endpoint_scope": "Endpoint identity includes Target; path+method alone is not globally unique",
        "unknown_status": "status_code is omitted until an HTTP response was observed",
    },
}
