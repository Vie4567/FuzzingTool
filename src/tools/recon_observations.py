"""URL and HTML observations, with origin and provenance kept intact."""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit, urldefrag, parse_qs

from .recon_http import _origin
from .recon_discovery import annotate, content_id


def absolute_url(value, base_url):
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.startswith(("#", "javascript:", "mailto:", "tel:")) or "\\" in value:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        url = urldefrag(urljoin(base_url, value)).url
        _origin(url)
        parsed = urlsplit(url)
        if parsed.username is not None or parsed.password is not None:
            return None
        return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))
    except (ValueError, TypeError):
        return None


def origin_url(url):
    scheme, host, port = _origin(url)
    host = f"[{host}]" if ":" in host else host
    suffix = "" if (scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
    return f"{scheme}://{host}{suffix}"


def path_observation(value, base_url, source, *, classification="candidate", method=None):
    url = absolute_url(value, base_url)
    if url is None:
        return None
    row = {"url": url, "origin": origin_url(url), "path": urlsplit(url).path,
           "source": source, "source_url": base_url, "classification": classification}
    if method:
        row["method"] = method
    return row


def target_paths(observations, target_url):
    """Legacy path-only consumers must never receive another origin's path."""
    target = _origin(target_url)
    return sorted({row["path"] for row in observations if _origin(row["url"]) == target})


def unique_records(records):
    import json
    seen, result = set(), []
    for row in records:
        key = json.dumps(row, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            result.append(row)
            seen.add(key)
    return result


def query_parameters(url, source, source_url, method="GET"):
    return [{"name": name, "location": "query", "url": url, "method": method,
             "source": source, "source_url": source_url, "classification": "candidate"}
            for name in parse_qs(urlsplit(url).query, keep_blank_values=True)]


class _DOMParser(HTMLParser):
    def __init__(self, base_url, body=""):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.resolution_base = base_url
        self.base_seen = False
        self.observations, self.parameters, self.forms, self.scripts = [], [], [], []
        self.form = None
        self.meta_generator = None
        self.digest = content_id(body)
        self.tag = None

    def _path(self, value, method=None, *, hint=None, attribute=None, source_type="html"):
        row = path_observation(value, self.resolution_base, "dom", method=method)
        if row:
            line, column = self.getpos()
            annotate(row, source_type=source_type, source_url=self.base_url, digest=self.digest,
                     location={"line": line, "column": column + 1, "tag": self.tag, "attribute": attribute}, hint=hint)
            self.observations.append(row)
            for param in query_parameters(row["url"], "dom", self.base_url, method=method):
                param.update(evidence_refs=row["evidence_refs"], evidence_location=row["evidence_location"])
                self.parameters.append(param)
        return row

    def handle_starttag(self, tag, attrs):
        self.tag = tag
        attrs = dict(attrs)
        if tag == "base" and not self.base_seen:
            base = absolute_url(attrs.get("href"), self.base_url)
            if base:
                self.resolution_base, self.base_seen = base, True
        if tag == "meta" and (attrs.get("name") or "").lower() == "generator":
            self.meta_generator = attrs.get("content")
        if tag in {"a", "link"}:
            self._path(attrs.get("href"), hint="navigation" if tag == "a" else None, attribute="href")
        if tag == "script":
            row = self._path(attrs.get("src"), attribute="src")
            if row:
                self.scripts.append(row["url"])
        if tag in {"img", "source", "video", "audio"}:
            self._path(attrs.get("src"), attribute="src")
        for attr in ("data-url", "data-api", "data-href", "data-action", "formaction"):
            self._path(attrs.get(attr), hint="api_attribute" if attr == "data-api" else None, attribute=attr)
        if tag == "form":
            method = (attrs.get("method") or "GET").upper()
            row = self._path(attrs.get("action") or self.base_url, method, attribute="action", source_type="form")
            self.form = {"action": row["url"] if row else "", "method": method, "params": [],
                         "source": "dom", "source_url": self.base_url,
                         "classification": "observed" if row else "candidate"}
            if row:
                self.form.update(evidence_refs=row["evidence_refs"], evidence_location=row["evidence_location"])
            self.forms.append(self.form)
        if tag in {"input", "select", "textarea", "button"} and attrs.get("name"):
            name = attrs["name"]
            if self.form is not None:
                if name not in self.form["params"]:
                    self.form["params"].append(name)
                method = self.form["method"]
                parameter = {"name": name, "location": "query" if method == "GET" else "body",
                                        "url": self.form["action"], "method": method, "source": "html_form",
                                        "source_url": self.base_url, "classification": self.form["classification"]}
                if self.form["action"]:
                    line, column = self.getpos()
                    annotate(parameter, source_type="form", source_url=self.base_url, digest=self.digest,
                             location={"line": line, "column": column + 1, "tag": tag, "attribute": "name"})
                self.parameters.append(parameter)
            else:
                self.parameters.append({"name": name, "location": "unknown", "url": self.base_url,
                                        "source": "html_input", "classification": "candidate"})

    def handle_endtag(self, tag):
        if tag == "form":
            self.form = None


def parse_dom(body, base_url, fp_data):
    parser = _DOMParser(base_url, body)
    errors = []
    try:
        parser.feed(body)
        parser.close()
    except (AssertionError, ValueError):
        errors.append({"error_type": "html_parse_error", "message": "HTML parsing did not complete"})
    # Hints drive crawl depth only. Technology resolution independently checks
    # exact evidence, so these strings cannot establish a backend/CMS by itself.
    hints = [tech for pattern, tech in fp_data.get("body_patterns", {}).items() if pattern in body]
    hints += [tech for attr, tech in fp_data.get("dom_attributes", {}).items() if attr in body]
    observations = unique_records(parser.observations)
    return {"paths": target_paths(observations, base_url),
            "params": sorted({r["name"] for r in parser.parameters}),
            "forms": parser.forms, "cms_hints": hints, "meta_generator": parser.meta_generator,
            "observations": observations, "parameters": unique_records(parser.parameters),
            "script_urls": list(dict.fromkeys(parser.scripts)), "errors": errors}
