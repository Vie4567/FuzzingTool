"""
Endpoint Assembler — Pattern Engine cho Phase Fuzzing.

Luồng hoạt động:
  1. Nạp api_url_patterns.json (thư viện patterns + part vocabularies).
  2. Nhận dev_profile từ WordlistGenAgent + observed_urls (URLs thật từ recon/JS/fuzzing).
  3. analyze_observed_urls(): parse URL thật → extract từng phần (prefix, service,
     resource, action, sub_resource) → tạo target-specific vocabulary.
  4. _select_patterns(): chọn patterns phù hợp với dev_profile.
  5. _generate_parts(): merge target-specific vocab (ưu tiên) + generic vocab (bổ sung).
     Nếu có LLM: gọi _generate_parts_with_llm() để bổ sung từng phần theo business context
     (gửi riêng service → LLM sinh services, resource → LLM sinh resources, ...).
  6. _assemble_for_pattern(): cartesian product từng phần → danh sách endpoints.
  7. Trả về list[str] endpoints để FuzzingAgent sử dụng.
"""

import json
import itertools
import logging
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlsplit

from src.coordinator.llm_logging import invoke_logged

try:
    from langchain_core.messages import SystemMessage, HumanMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

logger = logging.getLogger(__name__)


class EndpointAssembler:
    """
    Engine lắp ráp endpoints từ pattern templates + dev_profile.

    Sử dụng:
        assembler = EndpointAssembler()
        endpoints = assembler.assemble(dev_profile, max_endpoints=2000)
    """

    KNOWLEDGE_FILE = Path("knowledge/api_url_patterns.json")

    def __init__(self):
        self._knowledge: Dict[str, Any] = self._load_knowledge()

    # ──────────────────────────────────────────────────────────────────────
    # KHỞI TẠO & NẠP TRI THỨC
    # ──────────────────────────────────────────────────────────────────────

    def _load_knowledge(self) -> Dict[str, Any]:
        if self.KNOWLEDGE_FILE.exists():
            try:
                with open(self.KNOWLEDGE_FILE, "r", encoding="utf-8-sig") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"[EndpointAssembler] Không đọc được {self.KNOWLEDGE_FILE}: {e}")
        return {}

    # ──────────────────────────────────────────────────────────────────────
    # BƯỚC 0 (MỚI): PHÂN TÍCH URL THẬT → EXTRACT PARTS
    # ──────────────────────────────────────────────────────────────────────

    # Token nào không phải segment nghiệp vụ (lọc bỏ khi classify)
    _SKIP_TOKENS: Set[str] = {
        "api", "v1", "v2", "v3", "v4", "v5",
        "admin", "internal", "gateway", "webhook",
        "auth", "authentication", "oauth", "sso",
        "actuator", "management", "health", "debug",
        "me", "current", "query",
    }

    # Regex nhận ra token trông giống ID động (số, UUID, placeholder)
    _ID_PATTERN = re.compile(
        r'^(\{.+\}|\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$',
        re.IGNORECASE
    )

    # Token trông giống một "action" (verb prefix/suffix)
    _ACTION_VERBS = {
        "get", "list", "add", "create", "update", "edit", "delete", "remove",
        "cancel", "verify", "confirm", "login", "logout", "register", "refresh",
        "search", "export", "import", "download", "upload", "sync", "fetch",
        "follow", "unfollow", "like", "unlike", "block", "unblock", "join",
        "leave", "invite", "share", "report", "archive", "restore", "send",
        "reset", "change", "enable", "disable", "approve", "reject", "batch",
    }

    # Extensions của static assets — bỏ qua khi classify
    _STATIC_EXTENSIONS = {
        ".css", ".js", ".ts", ".jsx", ".tsx",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".zip", ".tar", ".gz",
        ".map", ".min.js", ".min.css",
    }

    def _is_static_asset(self, token: str) -> bool:
        """Trả về True nếu token trông như file static asset (có extension tĩnh)."""
        lower = token.lower()
        # Files remain in the original recon wordlist, never in semantic API slots.
        return "." in lower or any(lower.endswith(ext) for ext in self._STATIC_EXTENSIONS)

    def _classify_token(self, token: str, position: int, total_segments: int) -> str:

        """
        Phân loại một URL segment vào bucket part tương ứng.

        Logic phân loại theo vị trí và hình dạng token:
          - pos 0 → prefix (nếu là version pattern)
          - pos 1 → service (nếu có '-service' suffix hoặc tên service known)
          - pos cuối → action (nếu là verb)
          - giữa → resource (danh từ)
          - ID pattern → id_param
        """
        # Static asset → bỏ qua hoàn toàn
        if self._is_static_asset(token):
            return "skip"
        if not self._valid_part_value("resource", token) and not self._ID_PATTERN.match(token):
            return "skip"

        # ID động
        if self._ID_PATTERN.match(token):
            return "id_param"

        # Version/prefix ở đầu
        if position == 0 and re.match(r'^v\d+$', token, re.IGNORECASE):
            return "prefix"

        # Service segment (có "-service", "-svc", "-api" hoặc ở vị trí 1 sau version)
        if re.search(r'-(service|svc|api|srv)$', token, re.IGNORECASE):
            return "service"

        # Token là verb thuần túy → action
        base = token.replace("-", "").replace("_", "").lower()
        for verb in self._ACTION_VERBS:
            if base == verb or base.startswith(verb) or base.endswith(verb):
                return "action"

        # Token ở vị trí cuối và không phải danh từ rõ ràng → action
        if position == total_segments - 1 and token.lower() in self._SKIP_TOKENS:
            return "action"

        # Mặc định: resource (danh từ)
        return "resource"

    def analyze_observed_urls(
        self,
        observed_urls: List[str],
        min_freq: int = 1,
    ) -> Dict[str, Any]:
        """
        Parse các URLs thật đã thu thập (recon, JS extraction, fuzzing kết quả)
        để trích xuất vocabulary target-specific cho từng phần.

        Args:
            observed_urls: Danh sách path strings (VD: ["/v1/user-service/users/login", ...])
            min_freq: Chỉ giữ lại token xuất hiện >= min_freq lần.

        Returns:
            {
                "extracted_parts": {
                    "prefix": List[str],      # /v1, /v2, /api/v1...
                    "service": List[str],     # user-service, group-service...
                    "resource": List[str],    # users, orders, posts...
                    "action": List[str],      # login, add, cancel...
                    "sub_resource": List[str],
                    "id_param": List[str],
                },
                "detected_prefixes": List[str],   # prefix nổi bật nhất
                "pattern_scores": Dict[str, int], # pattern_id → số URL match
                "url_count": int,
            }
        """
        bucket_counters: Dict[str, Counter] = {
            "prefix": Counter(),
            "service": Counter(),
            "resource": Counter(),
            "action": Counter(),
            "sub_resource": Counter(),
            "id_param": Counter(),
        }
        pattern_hit_counter: Counter = Counter()
        all_patterns = self._knowledge.get("patterns", {})

        valid_urls = []
        for raw in observed_urls or []:
            if not isinstance(raw, str):
                continue
            parsed = urlsplit(raw)
            path = parsed.path if parsed.scheme in ("http", "https") else raw
            if path.startswith("/") and not path.startswith("//"):
                valid_urls.append(path)

        for url in valid_urls:
            # Loại bỏ query string và fragment
            clean = url.split("?")[0].split("#")[0].rstrip("/")
            segments = [s for s in clean.split("/") if s]
            if not segments:
                continue

            # Bỏ qua URLs trông như static assets (tất cả segments đều là file)
            if self._is_static_asset(segments[-1]):
                continue

            # ── Nhận dạng prefix (version) ─────────────────────────────
            prefix_str = ""
            seg_start = 0

            # Tách "api" prefix nếu có
            if segments[0].lower() == "api" and len(segments) > 1:
                seg_start = 1
                if re.match(r'^v\d+$', segments[1], re.IGNORECASE):
                    prefix_str = "/api/" + segments[1]
                    seg_start = 2
                else:
                    prefix_str = "/api"
            elif re.match(r'^v\d+$', segments[0], re.IGNORECASE):
                prefix_str = "/" + segments[0]
                seg_start = 1

            if prefix_str:
                bucket_counters["prefix"][prefix_str] += 1

            business_segs = segments[seg_start:]
            n = len(business_segs)

            # ── Score từng pattern: xem URL khớp pattern nào nhất ──────
            matched_pattern = self._score_url_against_patterns(
                business_segs, all_patterns
            )
            if matched_pattern:
                pattern_hit_counter[matched_pattern] += 1

            # ── Phân loại từng business segment ────────────────────────
            assigned_resource = False
            for i, seg in enumerate(business_segs):
                if seg.lower() in self._SKIP_TOKENS:
                    continue

                bucket = self._classify_token(seg, i, n)

                # Bỏ qua static asset tokens
                if bucket == "skip":
                    continue

                # Nếu đã có resource, token tiếp theo (không phải id/action) → sub_resource
                if bucket == "resource" and assigned_resource and i > 0:
                    bucket = "sub_resource"

                if bucket == "resource":
                    assigned_resource = True

                bucket_counters[bucket][seg] += 1

        # Lọc theo min_freq và trả về list sorted by frequency
        extracted = {}
        for bucket, counter in bucket_counters.items():
            extracted[bucket] = [
                token for token, cnt in counter.most_common()
                if cnt >= min_freq
            ]

        detected_prefixes = extracted.get("prefix", [])

        logger.info(
            f"[EndpointAssembler] URL Analysis: {len(valid_urls)} URLs → "
            f"prefix={len(extracted['prefix'])}, service={len(extracted['service'])}, "
            f"resource={len(extracted['resource'])}, action={len(extracted['action'])}"
        )

        return {
            "extracted_parts": extracted,
            "detected_prefixes": detected_prefixes,
            "pattern_scores": dict(pattern_hit_counter.most_common()),
            "url_count": len(valid_urls),
        }

    def _score_url_against_patterns(
        self,
        business_segs: List[str],
        all_patterns: Dict[str, Any],
    ) -> Optional[str]:
        """
        Thử khớp danh sách business segments với từng pattern để xác định
        pattern nào có khả năng tạo ra URL này nhất.
        Trả về pattern_id khớp nhất hoặc None.
        """
        n = len(business_segs)
        best: Optional[str] = None
        best_score = -1

        # Heuristic score dựa trên số lượng segment của pattern
        for pid, p in all_patterns.items():
            template_parts = p.get("parts", [])
            template_len = len([part for part in template_parts if part != "prefix"])
            if "service" in template_parts and not (
                business_segs and re.search(r"-(service|svc|api|srv)$", business_segs[0], re.IGNORECASE)
            ):
                continue
            if "id_param" in template_parts and not any(self._ID_PATTERN.match(seg) for seg in business_segs):
                continue
            score = 0

            # Chiều dài phù hợp → cộng điểm
            if template_len == n:
                score += 3
            elif abs(template_len - n) == 1:
                score += 1

            # Nếu segment cuối trông như action → ưu tiên pattern có action
            if n > 0 and "action" in template_parts:
                last = business_segs[-1]
                base = last.replace("-", "").replace("_", "").lower()
                if any(base.startswith(v) or base.endswith(v) or base == v
                       for v in self._ACTION_VERBS):
                    score += 2

            # Service segment detected
            if n > 1 and re.search(r'-(service|svc|api|srv)$', business_segs[0], re.IGNORECASE):
                if "service" in template_parts:
                    score += 2

            if score > best_score:
                best_score = score
                best = pid

        return best if best_score > 0 else None

    # ──────────────────────────────────────────────────────────────────────
    # BƯỚC 1: CHỌN PATTERNS THEO DEV_PROFILE + URL ANALYSIS
    # ──────────────────────────────────────────────────────────────────────

    def _select_patterns(
        self,
        dev_profile: Dict[str, Any],
        url_analysis: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Dựa vào dev_profile (crud_pattern, url_hierarchy.style) và
        url_analysis (pattern_scores từ URL thật) để chọn
        tập pattern IDs phù hợp nhất.
        """
        all_patterns = self._knowledge.get("patterns", {})
        hints = self._knowledge.get("profile_hints", {})

        # Xác định crud_pattern từ profile
        llm_analysis = dev_profile.get("llm_analysis", {})
        crud_pattern = llm_analysis.get("crud_pattern", "default")
        url_style = llm_analysis.get("url_hierarchy", {}).get("style", "")

        candidate_ids: List[str] = []

        # Ưu tiên patterns xuất hiện nhiều trong URL thật
        if url_analysis and url_analysis.get("pattern_scores"):
            for pid in url_analysis["pattern_scores"].keys():
                if pid not in candidate_ids:
                    candidate_ids.append(pid)

        if crud_pattern in hints:
            for pid in hints[crud_pattern]:
                if pid not in candidate_ids:
                    candidate_ids.append(pid)
        if "microservice" in url_style and "microservice" in hints:
            for pid in hints["microservice"]:
                if pid not in candidate_ids:
                    candidate_ids.append(pid)

        if len(candidate_ids) < 3:
            for pid in hints.get("default", []):
                if pid not in candidate_ids:
                    candidate_ids.append(pid)

        observed_services = (url_analysis or {}).get("extracted_parts", {}).get("service", [])
        profile_services = dev_profile.get("detected_services") or llm_analysis.get("url_hierarchy", {}).get("detected_services", [])
        flat_without_services = "flat" in str(url_style).lower() and not (observed_services or profile_services)
        selected = []
        for pid in candidate_ids:
            if pid in all_patterns:
                p = dict(all_patterns[pid])
                # A flat frontend route is not evidence of a microservice hierarchy.
                if flat_without_services and "service" in p.get("parts", []):
                    continue
                p["id"] = pid
                selected.append(p)

        selected.sort(key=lambda x: x.get("confidence_score", 0), reverse=True)

        logger.info(
            f"[EndpointAssembler] Đã chọn {len(selected)} patterns: "
            f"{[p['id'] for p in selected]}"
        )
        return selected

    # ──────────────────────────────────────────────────────────────────────
    # BƯỚC 2a: LLM ENRICHMENT — SINH TỪNG PHẦN THEO CONTEXT
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _valid_part_value(part: str, value: Any) -> bool:
        if not isinstance(value, str) or value != value.strip():
            return False
        if part == "prefix":
            return value == "" or bool(re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", value))
        if part == "id_param":
            return bool(re.fullmatch(
                r"(?:\{[A-Za-z_][A-Za-z0-9_]*\}|\d+|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})",
                value,
            )) or value in ("me", "current")
        # Slots contain one semantic segment, not whole endpoints, files or URLs.
        return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,99}", value))

    def _generate_parts_with_llm(
        self,
        llm: Any,
        dev_profile: Dict[str, Any],
        url_analysis: Optional[Dict[str, Any]],
        selected_patterns: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        """Request one vocabulary per semantic slot used by selected templates."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return {}
        analysis = dev_profile.get("llm_analysis", {})
        extracted = (url_analysis or {}).get("extracted_parts", {})
        needed = {part for pattern in selected_patterns for part in pattern.get("parts", [])}
        descriptions = {
            "service": "service/module names, such as user-service or payments",
            "resource": "resource/entity nouns, such as users or orders",
            "action": "operation verbs, such as search or verify-email",
            "sub_resource": "nested resource nouns, such as comments or members",
            "auth_segment": "identity/authentication route segments, such as auth or accounts",
            "internal_segment": "internal diagnostics route segments, such as actuator or management",
            "batch_action": "batch/export operation names, such as export or bulk-update",
            "event": "webhook event names, such as completed or payment-success",
        }
        enriched: Dict[str, List[str]] = {}
        for part, description in descriptions.items():
            if part not in needed:
                continue
            relevant = [pattern for pattern in selected_patterns if part in pattern.get("parts", [])]
            pattern_ids = [pattern["id"] for pattern in relevant]
            context = {
                "business_domain": analysis.get("business_domain", "web application"),
                "naming_convention": dev_profile.get("naming_convention", analysis.get("naming_convention", "kebab-case")),
                "crud_pattern": analysis.get("crud_pattern", "unknown"),
                "inferred_rules": analysis.get("inferred_rules", []),
                "observed_parts": extracted,
                "already_generated_parts": enriched,
                "selected_patterns": [{"id": pattern["id"], "template": pattern.get("template", "")} for pattern in relevant],
            }
            prompt = (
                "TARGET CONTEXT:\n" + json.dumps(context, ensure_ascii=False) +
                f"\nGenerate 10-20 additional {description} for ONLY the '{part}' slot. "
                "Return one JSON array of unique strings. Each string must be a single URL segment. "
                "Do not return full endpoints, URLs, files, query strings, slashes, IDs or explanations. "
                "Follow the observed naming convention and business context."
            )
            enriched[part] = []
            try:
                response = invoke_logged(
                    llm,
                    [SystemMessage(content="Generate contextual API pattern components. Return only a JSON array."),
                     HumanMessage(content=prompt)],
                    component="EndpointAssembler", operation="generate_part",
                    context={"part": part, "pattern_ids": pattern_ids},
                )
                content = response.content
                if not isinstance(content, str):
                    raise ValueError("LLM component response must be text")
                content = content.strip()
                if content.startswith("```"):
                    content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content).strip()
                items = json.loads(content)
                if not isinstance(items, list):
                    raise ValueError("LLM component response must be an array")
                enriched[part] = list(dict.fromkeys(
                    item for item in items if self._valid_part_value(part, item)
                ))[:40]
            except Exception as exc:
                logger.warning("[EndpointAssembler][LLM] Invalid %s response; using observed/profile/knowledge values (%s)", part, type(exc).__name__)
        return enriched

    def _generate_parts(
        self,
        dev_profile: Dict[str, Any],
        url_analysis: Optional[Dict[str, Any]] = None,
        llm_enriched_parts: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, List[str]]:
        """Merge validated observed, LLM, profile and knowledge values, retaining sources."""
        vocab = self._knowledge.get("part_vocabularies", {})
        analysis = dev_profile.get("llm_analysis", {})
        extracted = (url_analysis or {}).get("extracted_parts", {})
        llm_parts = llm_enriched_parts or {}
        naming = dev_profile.get("naming_convention", analysis.get("naming_convention", "kebab-case"))
        parts: Dict[str, List[str]] = {}
        sources: Dict[str, Dict[str, List[str]]] = {}

        def add(part, source, values):
            parts.setdefault(part, [])
            sources.setdefault(part, {})
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, (list, tuple, set)):
                return
            for raw in values:
                if not self._valid_part_value(part, raw):
                    continue
                value = raw if part in ("prefix", "id_param") else self._apply_naming(raw, naming)
                if not self._valid_part_value(part, value):
                    continue
                if value not in parts[part]:
                    parts[part].append(value)
                source_list = sources[part].setdefault(value, [])
                if source not in source_list:
                    source_list.append(source)

        hierarchy = analysis.get("url_hierarchy", {})
        common_prefix = dev_profile.get("common_prefix", hierarchy.get("common_prefix"))
        version = dev_profile.get("api_versioning", analysis.get("versioning"))
        no_version = version is None or str(version).lower() in ("", "none", "unknown", "null", "n/a")
        explicit_bare = no_version and not common_prefix
        # Bare routes must survive empty-string handling when versioning is absent.
        if explicit_bare:
            add("prefix", "profile", [""])
        add("prefix", "observed", extracted.get("prefix", []))
        if isinstance(common_prefix, str):
            add("prefix", "profile", [common_prefix.rstrip("/")])
        if not no_version:
            clean_version = str(version).strip("/")
            if re.fullmatch(r"v?\d+(?:[._-]\d+)*", clean_version):
                add("prefix", "profile", ["/" + clean_version, "/api/" + clean_version])
        if not parts.get("prefix"):
            add("prefix", "knowledge", [""])

        definitions = {
            "service": ("services", "generic"),
            "resource": ("resources", None),
            "action": ("actions", None),
            "sub_resource": ("sub_resources", "generic"),
            "auth_segment": ("auth_segments", "common"),
            "internal_segment": ("internal_segments", "common"),
            "batch_action": ("batch_actions", "common"),
            "id_param": ("id_params", "common"),
            "event": ("events", "common"),
        }
        for part, (category, group) in definitions.items():
            add(part, "observed", extracted.get(part, []))
            add(part, "llm", llm_parts.get(part, []))
            if part == "service":
                add(part, "profile", dev_profile.get("detected_services") or hierarchy.get("detected_services", []))
            elif part == "action":
                add(part, "profile", analysis.get("common_actions", []))
            elif part == "auth_segment":
                profile_auth = analysis.get("auth_pattern")
                if profile_auth and str(profile_auth).lower() not in ("none", "none-detected", "unknown"):
                    add(part, "profile", profile_auth)
            category_values = vocab.get(category, {})
            if isinstance(category_values, dict):
                if group:
                    add(part, "knowledge", category_values.get(group, []))
                else:
                    for values in category_values.values():
                        add(part, "knowledge", values)
        self._part_sources = {
            part: [{"value": value, "sources": source_map[value]} for value in parts[part]]
            for part, source_map in sources.items()
        }
        return parts

    def _apply_naming(self, token: Any, naming: str) -> str:
        """Chuyển đổi token theo naming_convention."""
        if not isinstance(token, str):
            token = str(token) if token is not None else ""
        if naming == "snake_case":
            return token.replace("-", "_")
        if naming == "camelCase":
            parts = token.replace("_", "-").split("-")
            return parts[0] + "".join(p.capitalize() for p in parts[1:])
        # Mặc định giữ nguyên (kebab-case hoặc flat)
        return token

    # ──────────────────────────────────────────────────────────────────────
    # BƯỚC 3: LẮP RÁP ENDPOINTS THEO TỪNG PATTERN
    # ──────────────────────────────────────────────────────────────────────

    def _assemble_for_pattern(
        self,
        pattern: Dict[str, Any],
        parts: Dict[str, List[str]],
        max_per_pattern: int = 200,
    ) -> List[str]:
        """Bounded products with an initial pass covering every slot vocabulary."""
        template = pattern.get("template", "")
        keys = pattern.get("parts", [])
        self._last_pattern_values = {key: [] for key in keys}
        if max_per_pattern <= 0 or not template:
            return []
        slots = [parts.get(key, []) for key in keys]
        if not keys or any(not values for values in slots):
            return []
        # A diagonal pass prevents earlier observed values from excluding every LLM
        # value in a later vocabulary when the Cartesian product exceeds the budget.
        coverage = (tuple(values[index % len(values)] for values in slots)
                    for index in range(max(map(len, slots))))
        combinations = itertools.chain(coverage, itertools.product(*slots))
        assembled = []
        seen = set()
        for combo in combinations:
            try:
                endpoint = template.format(**dict(zip(keys, combo)))
            except (KeyError, ValueError):
                continue
            endpoint = re.sub(r"/{2,}", "/", "/" + endpoint.lstrip("/"))
            if endpoint in seen:
                continue
            seen.add(endpoint)
            assembled.append(endpoint)
            for key, value in zip(keys, combo):
                if value not in self._last_pattern_values[key]:
                    self._last_pattern_values[key].append(value)
            if len(assembled) >= max_per_pattern:
                break
        return assembled

    def assemble(
        self,
        dev_profile: Dict[str, Any],
        observed_urls: Optional[List[str]] = None,
        max_endpoints: int = 2000,
        selected_pattern_ids: Optional[List[str]] = None,
        min_url_freq: int = 1,
        llm: Any = None,
    ) -> Dict[str, Any]:
        """
        Sinh toàn bộ danh sách endpoints từ patterns + dev_profile + observed URLs.

        Luồng mới (component-by-component LLM enrichment):
          Bước 0: Phân tích URL thật → extract parts (service, resource, action, ...)
          Bước 1: Chọn patterns phù hợp với dev_profile.
          Bước 2: Nếu có LLM → gọi _generate_parts_with_llm() để sinh TỪNG PHẦN riêng
                  theo context (VD: "domain thương mại điện tử → service nào?",
                  "service cart → resource nào?", "resource orders → action nào?").
                  Merge kết quả LLM vào vocabulary trước khi assemble.
          Bước 3: Cartesian product các parts → endpoints.

        Args:
            dev_profile: Kết quả phân tích từ WordlistGenAgent._analyze_dev_profile_with_llm().
            observed_urls: Danh sách URL paths thật đã thu thập (recon, JS, fuzzing).
                           Nếu cung cấp, sẽ được phân tích để tạo target-specific vocabulary.
            max_endpoints: Giới hạn tổng số endpoints sinh ra.
            selected_pattern_ids: Nếu cung cấp, override lựa chọn pattern tự động.
            min_url_freq: Ngưỡng tần suất tối thiểu khi extract token từ URL thật.
            llm: LLM instance (ChatOpenAI hoặc tương tự). Nếu cung cấp, sẽ dùng để
                 bổ sung vocabulary cho từng phần theo context trước khi assemble.

        Returns:
            {
                "endpoints": List[str],
                "metadata": {
                    "total": int,
                    "patterns_used": List[str],
                    "parts_counts": Dict[str, int],
                    "url_analysis": {...},       # kết quả phân tích URL thật
                    "target_specific": bool,     # có dùng URL thật không
                    "llm_enriched": bool,        # có dùng LLM enrichment không
                    "llm_enriched_parts": {...}, # số items LLM thêm vào từng phần
                }
            }
        """
        if not self._knowledge:
            logger.warning("[EndpointAssembler] Không có knowledge, trả về danh sách rỗng.")
            return {"endpoints": [], "metadata": {"total": 0, "patterns_used": [], "parts_counts": {}}}

        # ── Bước 0: Phân tích URL thật (nếu có) ─────────────────────────
        url_analysis: Optional[Dict[str, Any]] = None
        if observed_urls:
            url_analysis = self.analyze_observed_urls(observed_urls, min_freq=min_url_freq)
            logger.info(
                f"[EndpointAssembler] URL Analysis xong: "
                f"{url_analysis['url_count']} URLs → "
                f"extracted services={url_analysis['extracted_parts'].get('service', [])[:5]}, "
                f"resources={url_analysis['extracted_parts'].get('resource', [])[:5]}, "
                f"actions={url_analysis['extracted_parts'].get('action', [])[:5]}"
            )

        # ── Bước 1: Chọn patterns ────────────────────────────────────────
        if selected_pattern_ids:
            all_patterns = self._knowledge.get("patterns", {})
            patterns = []
            for pid in selected_pattern_ids:
                if pid in all_patterns:
                    p = dict(all_patterns[pid])
                    p["id"] = pid
                    patterns.append(p)
        else:
            patterns = self._select_patterns(dev_profile, url_analysis=url_analysis)

        # ── Bước 2: LLM Component-by-Component Enrichment (nếu có LLM) ──
        # Thay vì gửi 1 context lớn để sinh endpoint hoàn chỉnh, ta gửi từng phần
        # (service, resource, action) riêng để LLM bổ sung theo business context.
        llm_enriched_parts: Dict[str, List[str]] = {}
        if llm:
            logger.info(
                "[EndpointAssembler] Bắt đầu LLM component-by-component enrichment "
                f"(domain: {dev_profile.get('llm_analysis', {}).get('business_domain', 'unknown')})..."
            )
            llm_enriched_parts = self._generate_parts_with_llm(
                llm=llm,
                dev_profile=dev_profile,
                url_analysis=url_analysis,
                selected_patterns=patterns,
            )
            logger.info(
                f"[EndpointAssembler] LLM enrichment xong: "
                + ", ".join(f"{k}+{len(v)}" for k, v in llm_enriched_parts.items())
            )

        # ── Bước 3: Generate parts (merge: URL thật + LLM enriched + generic) ─
        parts = self._generate_parts(
            dev_profile,
            url_analysis=url_analysis,
            llm_enriched_parts=llm_enriched_parts,
        )

        # ── Bước 4: Lắp ráp (cartesian product) ─────────────────────────
        all_endpoints: List[str] = []
        max_per_pattern = max(50, max_endpoints // max(len(patterns), 1))
        patterns_used = []
        pattern_results = []

        for pattern in patterns:
            if len(all_endpoints) >= max_endpoints:
                break
            remaining = max_endpoints - len(all_endpoints)
            chunk = self._assemble_for_pattern(
                pattern=pattern,
                parts=parts,
                max_per_pattern=min(max_per_pattern, remaining),
            )
            all_endpoints.extend(chunk)
            patterns_used.append(pattern["id"])
            pattern_results.append({
                "pattern_id": pattern["id"], "template": pattern.get("template", ""),
                "parts": pattern.get("parts", []), "count": len(chunk), "sample": chunk[:10],
                "used_values": self._last_pattern_values,
            })
            logger.info(
                f"[EndpointAssembler] Pattern '{pattern['id']}' → {len(chunk)} endpoints"
            )

        # ── Bước 5: Deduplicate + sort ───────────────────────────────────
        all_endpoints = sorted(set(all_endpoints))[:max_endpoints]

        metadata = {
            "total": len(all_endpoints),
            "patterns_used": patterns_used,
            "parts_counts": {k: len(v) for k, v in parts.items()},
            "url_analysis": url_analysis or {},
            "target_specific": url_analysis is not None and url_analysis.get("url_count", 0) > 0,
            "llm_enriched": any(llm_enriched_parts.values()),
            "llm_enriched_parts": {k: len(v) for k, v in llm_enriched_parts.items()},
            "selected_patterns": [{"id": pattern["id"], "template": pattern.get("template", ""),
                                   "parts": pattern.get("parts", [])} for pattern in patterns],
            "part_vocabularies": parts,
            "llm_part_items": llm_enriched_parts,
            "slot_sources": getattr(self, "_part_sources", {}),
            "pattern_results": pattern_results,
        }

        logger.info(
            f"[EndpointAssembler] Hoàn thành: {len(all_endpoints)} endpoints "
            f"từ {len(patterns_used)} patterns "
            f"(target-specific={'yes' if metadata['target_specific'] else 'no'}, "
            f"llm-enriched={'yes' if metadata['llm_enriched'] else 'no'})."
        )

        return {"endpoints": all_endpoints, "metadata": metadata}

    # ──────────────────────────────────────────────────────────────────────
    # HELPERS TIỆN ÍCH
    # ──────────────────────────────────────────────────────────────────────

    def list_patterns(self) -> List[Dict[str, Any]]:
        """Liệt kê tất cả patterns có trong knowledge base."""
        patterns = self._knowledge.get("patterns", {})
        return [
            {
                "id": pid,
                "label": p.get("label", pid),
                "description": p.get("description", ""),
                "template": p.get("template", ""),
                "parts": p.get("parts", []),
                "confidence_score": p.get("confidence_score", 0),
            }
            for pid, p in patterns.items()
        ]

    def get_pattern_examples(self, pattern_id: str) -> List[str]:
        """Trả về examples của một pattern cụ thể."""
        return self._knowledge.get("patterns", {}).get(pattern_id, {}).get("examples", [])
