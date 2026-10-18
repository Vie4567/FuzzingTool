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
        return any(lower.endswith(ext) for ext in self._STATIC_EXTENSIONS)

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

        valid_urls = [
            u for u in (observed_urls or [])
            if isinstance(u, str) and u.startswith("/")
        ]

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
            template_len = len(template_parts)
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

        selected = []
        for pid in candidate_ids:
            if pid in all_patterns:
                p = dict(all_patterns[pid])
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

    def _generate_parts_with_llm(
        self,
        llm: Any,
        dev_profile: Dict[str, Any],
        url_analysis: Optional[Dict[str, Any]],
        selected_patterns: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        """
        Gọi LLM RIÊNG BIỆT cho từng phần URL (service, resource, action, sub_resource)
        để bổ sung vocabulary theo business context thay vì sinh endpoint hoàn chỉnh.

        Quy trình:
          1. Tổng hợp context: business_domain, naming_convention, observed_services,
             observed_resources, observed_actions, các URL patterns đang dùng.
          2. Gửi LLM request cho phần SERVICE: "Domain X thường có những service/module nào?"
          3. Gửi LLM request cho phần RESOURCE: "Với các service trên, resource nào thường tồn tại?"
          4. Gửi LLM request cho phần ACTION: "Với các resource trên, action nào thường bị bỏ sót?"
          5. Trả về dict {"service": [...], "resource": [...], "action": [...], ...}
        """
        if not llm or not _LANGCHAIN_AVAILABLE:
            return {}

        llm_analysis = dev_profile.get("llm_analysis", {})
        business_domain = llm_analysis.get("business_domain", "web application")
        naming = dev_profile.get("naming_convention",
                                  llm_analysis.get("naming_convention", "kebab-case"))
        crud_pattern = llm_analysis.get("crud_pattern", "RESTful")
        inferred_rules = llm_analysis.get("inferred_rules", [])

        # Lấy những gì đã extract được từ URL thật làm seed context
        extracted = (url_analysis or {}).get("extracted_parts", {})
        observed_services = extracted.get("service", [])[:15]
        observed_resources = extracted.get("resource", [])[:20]
        observed_actions = extracted.get("action", [])[:15]
        observed_prefixes = extracted.get("prefix", [])[:5]

        # Các pattern đang được sử dụng (để biết phần nào cần sinh)
        parts_needed: Set[str] = set()
        for p in selected_patterns:
            parts_needed.update(p.get("parts", []))

        llm_enriched: Dict[str, List[str]] = {}

        sys_prompt = (
            "Bạn là chuyên gia Penetration Testing và API Security với kinh nghiệm phân tích "
            "cấu trúc API của nhiều loại ứng dụng web. Nhiệm vụ của bạn là dự đoán các "
            "thành phần URL còn ẩn/chưa được phát hiện dựa trên context của target. "
            "Luôn tuân thủ naming convention và chỉ trả về JSON array thuần túy, không giải thích."
        )

        # ── BƯỚC 1: Sinh SERVICE candidates theo domain ──────────────────
        if "service" in parts_needed:
            logger.info("[EndpointAssembler][LLM] Đang sinh service vocabulary theo context...")
            prompt_service = f"""TARGET CONTEXT:
- Business Domain: {business_domain}
- Naming Convention: {naming} (VD: user-service, payment-service)
- CRUD/Action Pattern: {crud_pattern}
- URL Prefix đã phát hiện: {json.dumps(observed_prefixes)}
- Services đã phát hiện từ URL thật: {json.dumps(observed_services)}
- Inferred Rules: {json.dumps(inferred_rules)}

YÊU CẦU: Dựa trên business domain "{business_domain}" và các services đã biết, hãy sinh thêm
các service/module names khác có khả năng tồn tại cao trong hệ thống này.
Tập trung vào các microservice phổ biến của domain này mà CHƯA có trong danh sách đã biết.
Bắt buộc tuân thủ naming convention: {naming}.
Sinh 10-15 services.

OUTPUT: JSON array (KHÔNG markdown, KHÔNG giải thích):
["service-name-1", "service-name-2", ...]"""
            try:
                resp = llm.invoke([
                    SystemMessage(content=sys_prompt),
                    HumanMessage(content=prompt_service),
                ])
                m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
                if m:
                    items = json.loads(m.group(0))
                    llm_enriched["service"] = [
                        s for s in items
                        if isinstance(s, str) and s and " " not in s
                    ]
                    logger.info(f"[EndpointAssembler][LLM] service: +{len(llm_enriched['service'])} items")
            except Exception as ex:
                logger.warning(f"[EndpointAssembler][LLM] Lỗi sinh service: {ex}")

        # ── BƯỚC 2: Sinh RESOURCE candidates theo services ───────────────
        if "resource" in parts_needed:
            logger.info("[EndpointAssembler][LLM] Đang sinh resource vocabulary theo context...")
            all_services = list(dict.fromkeys(
                observed_services + llm_enriched.get("service", [])
            ))[:12]
            prompt_resource = f"""TARGET CONTEXT:
- Business Domain: {business_domain}
- Naming Convention: {naming}
- Services/Modules đã xác định: {json.dumps(all_services)}
- Resources đã phát hiện từ URL thật: {json.dumps(observed_resources)}

YÊU CẦU: Với các services trên trong context "{business_domain}", hãy sinh thêm các
resource names (danh từ số nhiều thường gặp trong API) còn thiếu/ẩn.
Mỗi resource đại diện cho một loại dữ liệu/entity trong hệ thống.
Tập trung vào resources có khả năng bị misconfigure hoặc expose thông tin nhạy cảm.
Tuân thủ naming convention: {naming}. Sinh 15-20 resources.

OUTPUT: JSON array:
["resource-name-1", "resource-name-2", ...]"""
            try:
                resp = llm.invoke([
                    SystemMessage(content=sys_prompt),
                    HumanMessage(content=prompt_resource),
                ])
                m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
                if m:
                    items = json.loads(m.group(0))
                    llm_enriched["resource"] = [
                        r for r in items
                        if isinstance(r, str) and r and " " not in r
                    ]
                    logger.info(f"[EndpointAssembler][LLM] resource: +{len(llm_enriched['resource'])} items")
            except Exception as ex:
                logger.warning(f"[EndpointAssembler][LLM] Lỗi sinh resource: {ex}")

        # ── BƯỚC 3: Sinh ACTION candidates theo resources + pattern ──────
        if "action" in parts_needed:
            logger.info("[EndpointAssembler][LLM] Đang sinh action vocabulary theo context...")
            all_resources = list(dict.fromkeys(
                observed_resources + llm_enriched.get("resource", [])
            ))[:12]
            prompt_action = f"""TARGET CONTEXT:
- Business Domain: {business_domain}
- Naming Convention: {naming}
- CRUD/Action Pattern: {crud_pattern}
- Resources đã xác định: {json.dumps(all_resources)}
- Actions đã phát hiện từ URL thật: {json.dumps(observed_actions)}
- Inferred Rules: {json.dumps(inferred_rules)}

YÊU CẦU: Với các resources trên trong hệ thống "{business_domain}", hãy sinh thêm các
action names (động từ/verb) có khả năng tồn tại cao mà chưa được phát hiện.
Đặc biệt chú ý đến:
- Admin actions thường bị bỏ sót (approve, reject, ban, restore, ...)
- Data export/import actions (export, download, bulk-delete, ...)
- Auth-related actions ẩn (verify-otp, reset-password, refresh-token, ...)
- Business-specific actions của domain "{business_domain}"
Tuân thủ naming convention: {naming} và CRUD pattern: {crud_pattern}. Sinh 15-20 actions.

OUTPUT: JSON array:
["action-name-1", "action-name-2", ...]"""
            try:
                resp = llm.invoke([
                    SystemMessage(content=sys_prompt),
                    HumanMessage(content=prompt_action),
                ])
                m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
                if m:
                    items = json.loads(m.group(0))
                    llm_enriched["action"] = [
                        a for a in items
                        if isinstance(a, str) and a and " " not in a
                    ]
                    logger.info(f"[EndpointAssembler][LLM] action: +{len(llm_enriched['action'])} items")
            except Exception as ex:
                logger.warning(f"[EndpointAssembler][LLM] Lỗi sinh action: {ex}")

        # ── BƯỚC 4: Sinh SUB_RESOURCE candidates ────────────────────────
        if "sub_resource" in parts_needed:
            logger.info("[EndpointAssembler][LLM] Đang sinh sub_resource vocabulary theo context...")
            all_resources = list(dict.fromkeys(
                observed_resources + llm_enriched.get("resource", [])
            ))[:10]
            prompt_sub = f"""TARGET CONTEXT:
- Business Domain: {business_domain}
- Resources chính: {json.dumps(all_resources)}
- Naming Convention: {naming}

YÊU CẦU: Với các resource chính trên, hãy sinh các sub-resource names thường xuất hiện
trong nested URL patterns (VD: /users/{{id}}/orders, /groups/{{id}}/members).
Sinh 8-12 sub-resources phổ biến trong hệ thống "{business_domain}".

OUTPUT: JSON array:
["sub-resource-1", "sub-resource-2", ...]"""
            try:
                resp = llm.invoke([
                    SystemMessage(content=sys_prompt),
                    HumanMessage(content=prompt_sub),
                ])
                m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
                if m:
                    items = json.loads(m.group(0))
                    llm_enriched["sub_resource"] = [
                        s for s in items
                        if isinstance(s, str) and s and " " not in s
                    ]
                    logger.info(f"[EndpointAssembler][LLM] sub_resource: +{len(llm_enriched['sub_resource'])} items")
            except Exception as ex:
                logger.warning(f"[EndpointAssembler][LLM] Lỗi sinh sub_resource: {ex}")

        return llm_enriched

    # ──────────────────────────────────────────────────────────────────────
    # BƯỚC 2b: GENERATE TỪNG PHẦN THEO DEV_PROFILE (merge static + LLM)
    # ──────────────────────────────────────────────────────────────────────

    def _generate_parts(
        self,
        dev_profile: Dict[str, Any],
        url_analysis: Optional[Dict[str, Any]] = None,
        llm_enriched_parts: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, List[str]]:
        """
        Tạo danh sách giá trị cho từng phần (part vocabulary) theo thứ tự ưu tiên:
          1. Target-specific: trích xuất từ URL thật (url_analysis.extracted_parts)
          2. LLM-enriched: các giá trị do LLM sinh theo context (llm_enriched_parts)
          3. Profile-based: detected_services, common_actions từ LLM dev_profile
          4. Generic fallback: vocabulary mặc định trong knowledge base
        """
        vocab = self._knowledge.get("part_vocabularies", {})
        llm_analysis = dev_profile.get("llm_analysis", {})
        naming = dev_profile.get("naming_convention",
                                  llm_analysis.get("naming_convention", "kebab-case"))

        # Lấy parts đã extract từ URL thật (nếu có)
        extracted = (url_analysis or {}).get("extracted_parts", {})
        # LLM-enriched parts (component-by-component generation)
        llm_parts = llm_enriched_parts or {}

        def _to_string_items(val) -> List[str]:
            if isinstance(val, str):
                return [val]
            elif isinstance(val, (list, set, tuple)):
                res = []
                for x in val:
                    res.extend(_to_string_items(x))
                return res
            elif isinstance(val, dict):
                res = []
                for k, v in val.items():
                    if isinstance(v, str):
                        res.append(v)
                    elif isinstance(v, (list, set, tuple)):
                        res.extend(_to_string_items(v))
                    elif isinstance(k, str):
                        res.append(k)
                return res
            elif val is not None:
                return [str(val)]
            return []

        def _merge_unique(*lists) -> List[str]:
            """Merge nhiều list, loại trùng, ép kiểu string an toàn, giữ thứ tự."""
            seen: Set[str] = set()
            result = []
            for lst in lists:
                for raw_item in (lst or []):
                    for item in _to_string_items(raw_item):
                        clean_item = str(item).strip()
                        if clean_item and clean_item not in seen:
                            seen.add(clean_item)
                            result.append(clean_item)
            return result

        # ── Prefix ──────────────────────────────────────────────────────
        common_prefix = dev_profile.get(
            "common_prefix",
            llm_analysis.get("url_hierarchy", {}).get("common_prefix", "/v1/")
        )
        versioning = dev_profile.get(
            "api_versioning",
            llm_analysis.get("versioning", "v1")
        )
        clean_prefix = common_prefix.rstrip("/") if common_prefix else f"/{versioning}"
        profile_prefixes = list({clean_prefix, f"/{versioning}", f"/api/{versioning}", "/api"})
        prefix_candidates = _merge_unique(
            extracted.get("prefix", []),   # 1. từ URL thật
            url_analysis.get("detected_prefixes", []) if url_analysis else [],
            profile_prefixes,               # 2. từ profile
        )

        # ── Services ────────────────────────────────────────────────────
        detected_services = dev_profile.get(
            "detected_services",
            llm_analysis.get("url_hierarchy", {}).get("detected_services", [])
        )
        generic_services = vocab.get("services", {}).get("generic", [])
        service_candidates = _merge_unique(
            extracted.get("service", []),         # 1. từ URL thật
            llm_parts.get("service", []),          # 2. LLM enriched theo context
            detected_services,                      # 3. từ profile
            generic_services[:8],                  # 4. generic fallback
        )

        # ── Resources ───────────────────────────────────────────────────
        generic_resources: List[str] = []
        for domain_resources in vocab.get("resources", {}).values():
            generic_resources.extend(domain_resources)
        resource_candidates = _merge_unique(
            [self._apply_naming(r, naming) for r in extracted.get("resource", [])],          # 1. thật
            [self._apply_naming(r, naming) for r in llm_parts.get("resource", [])],          # 2. LLM enriched
            [self._apply_naming(r, naming) for r in generic_resources],                       # 3. generic
        )

        # ── Actions ─────────────────────────────────────────────────────
        profile_actions = llm_analysis.get("common_actions", [])
        generic_actions: List[str] = []
        for action_list in vocab.get("actions", {}).values():
            generic_actions.extend(action_list)
        action_candidates = _merge_unique(
            [self._apply_naming(a, naming) for a in extracted.get("action", [])],            # 1. thật
            [self._apply_naming(a, naming) for a in llm_parts.get("action", [])],            # 2. LLM enriched
            [self._apply_naming(a, naming) for a in profile_actions],                        # 3. profile
            [self._apply_naming(a, naming) for a in generic_actions],                        # 4. generic
        )

        # ── Sub-resources ────────────────────────────────────────────────
        generic_sub = vocab.get("sub_resources", {}).get("generic", [])
        sub_resource_candidates = _merge_unique(
            [self._apply_naming(s, naming) for s in extracted.get("sub_resource", [])],     # 1. thật
            [self._apply_naming(s, naming) for s in llm_parts.get("sub_resource", [])],     # 2. LLM enriched
            [self._apply_naming(s, naming) for s in generic_sub],                            # 3. generic
        )

        # ── Auth segments ────────────────────────────────────────────────
        profile_auth = llm_analysis.get("auth_pattern", None)
        auth_defaults = vocab.get("auth_segments", {}).get("common", ["auth"])
        auth_candidates_raw = []
        if profile_auth:
            if isinstance(profile_auth, str):
                words = re.findall(r'[a-zA-Z0-9_\-]+', profile_auth)
                matched = [w for w in words if any(k in w.lower() for k in ("auth", "account", "token", "login", "oauth"))]
                auth_candidates_raw.extend(matched if matched else [profile_auth])
            else:
                auth_candidates_raw.extend(_to_string_items(profile_auth))
        auth_segment_candidates = _merge_unique(
            auth_candidates_raw,
            auth_defaults,
        )

        # ── Internal segments ────────────────────────────────────────────
        internal_segment_candidates = vocab.get("internal_segments", {}).get("common", ["internal"])

        # ── Batch actions ────────────────────────────────────────────────
        batch_action_candidates = vocab.get("batch_actions", {}).get("common", ["export"])

        # ── ID params ────────────────────────────────────────────────────
        id_param_candidates = _merge_unique(
            extracted.get("id_param", []),
            vocab.get("id_params", {}).get("common", ["{id}", "1"]),
        )

        # ── Events (webhook) ────────────────────────────────────────────
        event_candidates = vocab.get("events", {}).get("common", ["success", "completed"])

        return {
            "prefix": prefix_candidates,
            "service": service_candidates,
            "resource": resource_candidates,
            "action": action_candidates,
            "sub_resource": sub_resource_candidates,
            "auth_segment": auth_segment_candidates,
            "internal_segment": internal_segment_candidates,
            "batch_action": batch_action_candidates,
            "id_param": id_param_candidates,
            "event": event_candidates,
        }

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
        """
        Lắp ráp các tổ hợp endpoint cho một pattern cụ thể.
        Chia nhỏ từng slot theo `pattern["parts"]` rồi cartesian product.
        """
        template: str = pattern.get("template", "")
        part_keys: List[str] = pattern.get("parts", [])

        # Giới hạn số giá trị mỗi phần để tránh tổ hợp bùng nổ
        budget_per_part = max(1, int(max_per_pattern ** (1.0 / max(len(part_keys), 1))))
        budget_per_part = min(budget_per_part, 15)  # hard limit

        slots: List[List[str]] = []
        for key in part_keys:
            candidates = parts.get(key, [key])[:budget_per_part]
            if not candidates:
                candidates = [key]  # fallback: dùng tên phần làm giá trị
            slots.append(candidates)

        assembled: List[str] = []
        for combo in itertools.product(*slots):
            # Tạo dict mapping key → value cho combo này
            fill = dict(zip(part_keys, combo))

            try:
                endpoint = template.format(**fill)
                # Chuẩn hoá double-slash
                while "//" in endpoint:
                    endpoint = endpoint.replace("//", "/")
                if not endpoint.startswith("/"):
                    endpoint = "/" + endpoint
                assembled.append(endpoint)
            except KeyError:
                pass  # bỏ qua nếu template có key không có trong fill

            if len(assembled) >= max_per_pattern:
                break

        return assembled

    # ──────────────────────────────────────────────────────────────────────
    # ENTRY POINT CHÍNH
    # ──────────────────────────────────────────────────────────────────────

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
            "llm_enriched": bool(llm_enriched_parts),
            "llm_enriched_parts": {k: len(v) for k, v in llm_enriched_parts.items()},
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
