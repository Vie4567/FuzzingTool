"""Conservative, offline technology fingerprints with inspectable evidence.

Evidence entries contain ``field``, ``value``, ``source``, ``indicator`` and
``classification``. ``observed`` means a specific signature was observed, not
that the remote software was independently verified. ``inferred`` identifies a
documented derivation (for example WordPress -> PHP); ``candidate`` never sets
a resolved technology field. Indicators contain signature names, never cookie
values, response bodies or authentication headers. Conflicting evidence leaves
the field Unknown and is retained for inspection.

The legacy ``web_server`` field remains an observed Server header, not a claim
that an arbitrary Server string identifies a known product. ``language`` is the
backend language: a frontend framework never establishes the backend language.
No requests, provider calls or optional dependencies are used here.
"""

from __future__ import annotations

from html.parser import HTMLParser
import re


UNKNOWN = "Unknown"
_FIELDS = ("frontend", "backend", "cms", "language")
_FRONTENDS = {"react": "React", "vue_js": "Vue.js", "angular": "Angular",
              "next_js": "Next.js", "nuxt_js": "Nuxt.js", "svelte": "Svelte",
              "gatsby": "Gatsby"}
_BACKENDS = {"asp_net": ("asp_net", None), "express": ("express", "JavaScript"),
             "node_express": ("express", "JavaScript"), "django": ("django", "Python"),
             "laravel": ("laravel", "PHP"), "rails": ("rails", "Ruby"),
             "symfony": ("symfony", "PHP"), "flask": ("flask", "Python"),
             "fastapi": ("fastapi", "Python"), "spring_boot": ("spring_boot", "Java")}
_CMS = {"wordpress": ("WordPress", "PHP"), "drupal": ("Drupal", "PHP"),
        "joomla": ("Joomla", "PHP"), "ghost": ("Ghost", "JavaScript"),
        "typo3": ("TYPO3", "PHP"), "prestashop": ("PrestaShop", "PHP")}
_ALIASES = {"vue": "vue_js", "vue.js": "vue_js", "next.js": "next_js",
            "nuxt.js": "nuxt_js", "asp.net": "asp_net", "node.js": "node",
            "ruby on rails": "rails"}
_LANGUAGES = {"php": "PHP", "python": "Python", "ruby": "Ruby", "java": "Java",
              "javascript": "JavaScript", "node": "JavaScript"}

# These signals identify a provider/CDN, or are shared by unrelated products.
# They are retained as candidates but cannot prove the presence of a WAF.
_WEAK_WAF_HEADERS = {"server", "x-cache", "x-cdn", "x-check-cacheable",
                     "cf-ray", "cf-cache-status", "cf-request-id", "cf-edge-cache",
                     "x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop",
                     "x-akamai-transformed", "akamai-grn", "x-akamai-request-id",
                     "x-azure-ref", "x-ms-ref", "x-f5-lburi", "x-cnection"}
_WEAK_WAF_COOKIES = {"__cfduid", "awsalb", "awsalbcors", "akamaiedge", "bigipserver", "ts", "ts01"}
_COOKIE_PREFIXES = {"visid_incap", "incap_ses", "nlbi_", "wfvt_", "bigipserver", "ts01"}
_WEAK_WAF_BODIES = {"ray id", "request blocked", "access denied", "reference #",
                    "request unsuccessful", "the requested url was rejected",
                    "noyb", "not acceptable", "your access to this site has been limited"}
_WAF_SERVER_PRODUCTS = {"ddos_guard", "sucuri", "imperva"}


def _entry(field, value, source, indicator, classification="observed"):
    return {"field": field, "value": value, "source": source,
            "indicator": indicator, "classification": classification}


def _unique(entries):
    result, seen = [], set()
    for entry in entries:
        key = tuple(entry.get(key) for key in ("field", "value", "source", "indicator", "classification"))
        if key not in seen:
            result.append(entry)
            seen.add(key)
    return result


def _matches(text, signature):
    """Match a literal signature without matching it inside an unrelated word."""
    if not isinstance(signature, str) or not signature or signature == "*":
        return False
    left = r"(?<![a-z0-9_])" if signature[0].isalnum() else ""
    right = r"(?![a-z0-9_])" if signature[-1].isalnum() else ""
    return re.search(left + re.escape(signature) + right, text, re.I) is not None


def _headers(headers):
    values = {}
    # Supports multi-valued dictionaries and HTTPMessage.get_all, without
    # flattening Set-Cookie values into one potentially misleading substring.
    for name in headers:
        if not isinstance(name, str):
            continue
        raw = headers.get_all(name) if hasattr(headers, "get_all") else headers[name]
        raw = raw if isinstance(raw, (list, tuple)) else [raw]
        values.setdefault(name.lower(), []).extend(value for value in raw if isinstance(value, str))
    return values


def _cookie_names(values):
    names = set()
    for value in values:
        names.update(match.group(1).lower() for match in re.finditer(
            r"(?:^|[,;\r\n])\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=", value))
    return names


def _technology(key, source, indicator, classification="observed"):
    key = _ALIASES.get(str(key).lower(), str(key).lower())
    if key in _FRONTENDS:
        return [_entry("frontend", _FRONTENDS[key], source, indicator, classification)]
    if key in _BACKENDS or key in _CMS:
        field = "backend" if key in _BACKENDS else "cms"
        value, language = (_BACKENDS if field == "backend" else _CMS)[key]
        evidence = [_entry(field, value, source, indicator, classification)]
        if language:
            evidence.append(_entry("language", language, source,
                                   indicator + "; language_of=" + key,
                                   "candidate" if classification == "candidate" else "inferred"))
        return evidence
    if key in _LANGUAGES:
        return [_entry("language", _LANGUAGES[key], source, indicator, classification)]
    # A servlet session identifies the Java ecosystem, not Spring specifically.
    if key == "java_spring":
        return [_entry("language", "Java", source, indicator + "; servlet_session", "inferred")]
    return []


def _resolve(evidence):
    result, conflicts = {}, []
    for field in _FIELDS:
        matches = [item for item in evidence if item["field"] == field
                   and item["classification"] in {"observed", "inferred"}]
        values = sorted({item["value"] for item in matches})
        result[field] = values[0] if len(values) == 1 else UNKNOWN
        if len(values) > 1:
            conflicts.append({"field": field, "values": values, "resolution": UNKNOWN})
    result["technology_evidence"] = _unique(evidence)
    result["technology_conflicts"] = conflicts
    return result


def header_fingerprint(headers, body, fp_data, waf_data):
    """Return CH1-compatible findings with signature evidence, not guessed WAFs."""
    values = _headers(headers)
    cookies = _cookie_names(values.get("set-cookie", []))
    evidence = []
    stack = {}
    server_values = values.get("server", [])
    if server_values:
        # This legacy display field is explicitly a measured header. Software
        # identity is separately backed by a configured signature below.
        stack["web_server"] = server_values[0]
        evidence.append(_entry("web_server", server_values[0], "header", "server"))
    if values.get("x-powered-by"):
        stack["backend_powered_by"] = values["x-powered-by"][0]
    for header, groups in fp_data.get("headers", {}).items():
        observed = values.get(header.lower(), [])
        if not observed or not isinstance(groups, dict):
            continue
        matches = []
        for key, signatures in groups.items():
            for signature in signatures:
                if signature == "*" or any(_matches(value, signature) for value in observed):
                    matches.append(key)
                    indicator = header.lower() + ":" + signature
                    evidence.extend(_technology(key, "header", indicator))
                    if header.lower() == "server":
                        evidence.append(_entry("server_tech", key, "header", indicator))
                    break
        distinct = sorted(set(matches))
        if len(distinct) == 1:
            stack["header_" + header.lower().replace("-", "_")] = distinct[0]
            if header.lower() == "server":
                stack["server_tech"] = distinct[0]
    for name, key in fp_data.get("cookies", {}).items():
        if name.lower() in cookies:
            stack["cookie_" + name.lower()] = key
            # csrftoken is used independently of Django too. A generic cookie
            # name must not establish a framework without corroboration.
            evidence.extend(_technology(key, "cookie_name", name,
                                        "candidate" if name.lower() == "csrftoken" else "observed"))
    if values.get("x-api-version"):
        stack["api_version_header"] = values["x-api-version"][0]
    if values.get("access-control-allow-origin") and values["access-control-allow-origin"][0] != "*":
        stack["cors_origin"] = values["access-control-allow-origin"][0]
    resolved = _resolve(evidence)
    stack.update({field: resolved[field] for field in _FIELDS})

    waf_evidence, waf_candidates = [], []
    for vendor, signatures in waf_data.items():
        if vendor == "_meta" or not isinstance(signatures, dict):
            continue
        for name in signatures.get("headers", []):
            name_lower = name.lower()
            # In particular, a generic Server or X-Cache header does not even
            # identify the vendor. Never search header *values* for a key name.
            if name_lower in {"server", "x-cache", "x-cdn", "x-check-cacheable"}:
                continue
            if name_lower in values:
                classification = "candidate" if name_lower in _WEAK_WAF_HEADERS else "observed"
                item = _entry("waf", vendor, "header_name", name_lower, classification)
                (waf_candidates if classification == "candidate" else waf_evidence).append(item)
        for name in signatures.get("cookies", []):
            lower = name.lower()
            present = lower in cookies or (lower in _COOKIE_PREFIXES and any(cookie.startswith(lower) for cookie in cookies))
            if present:
                classification = "candidate" if lower in _WEAK_WAF_COOKIES else "observed"
                item = _entry("waf", vendor, "cookie_name", name, classification)
                (waf_candidates if classification == "candidate" else waf_evidence).append(item)
        for signature in signatures.get("server_values", []):
            if any(_matches(value, signature) for value in server_values):
                classification = "observed" if vendor in _WAF_SERVER_PRODUCTS else "candidate"
                item = _entry("waf", vendor, "header", "server:" + signature, classification)
                (waf_candidates if classification == "candidate" else waf_evidence).append(item)
        for signature in signatures.get("body_patterns", []):
            if signature.lower() not in _WEAK_WAF_BODIES and _matches(body or "", signature):
                waf_evidence.append(_entry("waf", vendor, "body_signature", signature))
    vendors = sorted({item["value"] for item in waf_evidence})
    # Multiple vendor indicators are retained instead of choosing whichever
    # happened to occur first in a JSON file.
    waf_type = vendors[0] if len(vendors) == 1 else None
    return {"tech_stack": stack, "technology_evidence": resolved["technology_evidence"],
            "technology_conflicts": resolved["technology_conflicts"],
            "waf_detected": bool(waf_evidence), "waf_type": waf_type,
            "waf_status": "detected" if waf_type else "conflicting" if vendors else "unknown",
            "waf_evidence": _unique(waf_evidence), "waf_candidates": _unique(waf_candidates),
            "waf_evasion_hints": waf_data.get(waf_type, {}).get("evasion_hints", []) if waf_type else [],
            "paths": [], "params": []}


class _HTMLIndicators(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.attributes = []
        self.generators = []

    def handle_starttag(self, tag, attrs):
        self.attributes.extend((name.lower(), value or "") for name, value in attrs)
        properties = dict(attrs)
        if tag.lower() == "meta" and (properties.get("name") or "").lower() == "generator":
            self.generators.append(properties.get("content") or "")


def _dom_match(signature, attrs):
    """Match known DOM markers as attributes, not prose or cookie values."""
    for name, value in attrs:
        if signature in {"__next", "__nuxt", "__GATSBY"}:
            if name == "id" and value.lower() == signature.lower():
                return True
        elif signature.endswith("-") and "=" not in signature:
            if name.startswith(signature.lower()):
                return True
        elif signature in {"ng-version", "ng-app", "data-reactroot"}:
            if name == signature.lower():
                return True
        elif "=" in signature:
            attr, prefix = signature.split("=", 1)
            if name == attr.lower() and any(word.startswith(prefix) for word in value.split()):
                return True
    return False


def resolve_technologies(tech_stack, cms_hints=None, meta_generator=None, *, evidence=None, body="", fp_data=None):
    """Resolve independent layers from actual signatures, retaining ambiguity.

    Plain legacy hints lack their origin and cannot establish a detection. When
    original HTML and knowledge are supplied, exact matched DOM/body/meta
    indicators supply the evidence. Existing scalar tech_stack values are not
    promoted into facts without their evidence (callers may still retain them as
    legacy raw fields).
    """
    fp_data = fp_data or {}
    collected = [dict(item) for item in (evidence or []) if isinstance(item, dict)
                 and all(isinstance(item.get(key), str) for key in
                         ("field", "value", "source", "indicator", "classification"))]
    parser = _HTMLIndicators()
    parse_errors = []
    try:
        parser.feed(body or "")
        parser.close()
    except (AssertionError, ValueError):
        # HTMLParser can reject malformed marked sections. Keep the header and
        # DOM observations gathered so far, and let the caller report partial
        # CH2 processing without disclosing response content in the error.
        parse_errors.append({"error_type": "html_parse_error",
                             "message": "HTML fingerprint parsing did not complete"})
    for signature, technology in fp_data.get("dom_attributes", {}).items():
        if _dom_match(signature, parser.attributes):
            collected.extend(_technology(technology, "dom_attribute", signature))
    # ng-app is an attribute marker even when present in the legacy body group.
    for signature, technology in fp_data.get("body_patterns", {}).items():
        matched = _dom_match(signature, parser.attributes) if signature == "ng-app" else _matches(body or "", signature)
        if matched:
            # A generic word in arbitrary prose is not a framework signature.
            classification = "candidate" if signature.lower() in {"django", "svelte"} else "observed"
            collected.extend(_technology(technology, "body_signature", signature, classification))
    generators = parser.generators + ([meta_generator] if isinstance(meta_generator, str) else [])
    for generator in generators:
        for key in _CMS:
            if _matches(generator, key):
                collected.extend(_technology(key, "meta_generator", key))
    for hint in cms_hints or []:
        if isinstance(hint, str):
            collected.extend(_technology(hint, "legacy_hint", "unattributed:" + hint.lower(), "candidate"))
    result = _resolve(_unique(collected))
    result["technology_errors"] = parse_errors
    return result
