"""
Parameter Assembler — Pattern Engine cho Parameter Fuzzing & Discovery.

Luồng hoạt động:
  1. Nhận dev_profile (naming_convention, business_domain, resources, actions)
     + observed_urls + tech_stack.
  2. Phân tích ngữ cảnh: trích xuất target entities, resources và actions.
  3. Component-by-Component LLM Enrichment:
     - Component 1: Identification & Filter params (id, uuid, slug, entity_id...)
     - Component 2: Pagination, Range & Sorting params (page, limit, sort, order, from, to...)
     - Component 3: Domain & Business Entity fields (dựa trên business_domain + services)
     - Component 4: Action & Control params (action, mode, step, redirect, callback...)
     - Component 5: Debug, Admin & Hidden params (debug, admin, role, file, test...)
  4. Naming Convention Conversion (snake_case, camelCase, kebab-case theo DevProfile).
  5. Assemble & Deduplicate -> Trả về danh sách parameters hoàn chỉnh cho ParamDiscoveryAgent & Arjun.
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

try:
    from langchain_core.messages import SystemMessage, HumanMessage
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False

logger = logging.getLogger(__name__)


class ParameterAssembler:
    """Engine lắp ráp và làm giàu Parameter Wordlist theo từng thành phần (Component-by-Component)."""

    # Baseline vocabularies theo từng component
    _BASELINE_COMPONENTS: Dict[str, List[str]] = {
        "id_lookup": [
            "id", "uuid", "uid", "code", "slug", "key", "token", "ref", "reference",
            "no", "num", "hash", "guid", "account_id", "user_id", "item_id",
        ],
        "pagination_sort": [
            "page", "p", "page_number", "page_no", "page_size", "limit", "offset",
            "size", "count", "per_page", "cursor", "start", "max", "rows",
            "sort", "order", "dir", "sort_by", "order_by", "direction", "asc", "desc",
            "from", "to", "start_date", "end_date", "since", "until", "range",
        ],
        "domain_generic": [
            "q", "query", "search", "keyword", "term", "filter", "tag", "category",
            "type", "status", "state", "group", "scope", "view", "tab", "lang",
            "locale", "country", "currency", "price_min", "price_max", "title", "name",
        ],
        "action_control": [
            "action", "act", "do", "cmd", "command", "op", "operation", "mode", "step",
            "stage", "event", "trigger", "method", "callback", "redirect", "redirect_uri",
            "return_url", "next", "url", "source", "channel", "format", "output",
        ],
        "debug_security": [
            "debug", "dbg", "test", "testing", "dev", "dry_run", "verbose", "trace",
            "internal", "admin", "is_admin", "adm", "role", "superuser", "sudo",
            "root", "access_token", "api_key", "secret", "auth", "password", "pass",
            "user", "username", "file", "path", "template", "include", "doc", "view_source",
            "show_all", "disable_waf", "bypass", "impersonate", "as_user",
        ],
    }

    def __init__(self):
        pass

    # ──────────────────────────────────────────────────────────────────────
    # UTILS: NAMING CONVENTION CONVERTER
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _convert_naming(name: str, style: str) -> str:
        """Chuyển đổi tên param sang naming convention mục tiêu (camelCase, snake_case, kebab-case)."""
        clean = re.sub(r'[^a-zA-Z0-9_\-]', '', name)
        words = re.split(r'[-_]', clean)
        words = [w for w in words if w]
        if not words:
            return name

        style_lower = (style or "").lower()
        if "camel" in style_lower:
            return words[0].lower() + "".join(w.capitalize() for w in words[1:])
        elif "kebab" in style_lower:
            return "-".join(w.lower() for w in words)
        else:
            # Mặc định snake_case
            return "_".join(w.lower() for w in words)

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 1: ID & LOOKUP PARAMS
    # ──────────────────────────────────────────────────────────────────────

    def _generate_id_lookup_with_llm(
        self,
        llm: Any,
        domain: str,
        resources: List[str],
        naming: str,
    ) -> List[str]:
        """Gửi resources & domain cho LLM sinh các tham số định danh và lookup (ID/UUID/slug)."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        prompt = f"""TARGET CONTEXT:
- Business Domain: {domain}
- Resources/Entities đã phát hiện: {json.dumps(resources[:15])}
- Naming Convention: {naming} (VD: user_id, order_id hoặc userId, orderId)

YÊU CẦU: Hãy sinh danh sách các tham số ĐỊNH DANH và TRA CỨU (Identification & Lookup parameters)
tương ứng với các resources trên và các entities phổ biến của domain "{domain}".
Bao gồm: primary keys, foreign keys, unique slugs, hash codes, tracking tokens (ví dụ: product_id, sku, order_no, tracking_code...).
Bắt buộc tuân thủ naming convention: {naming}.
Sinh 15-25 parameter names.

OUTPUT: Chỉ trả về JSON array thuần túy (KHÔNG markdown, KHÔNG giải thích):
["param1", "param2", ...]"""

        try:
            resp = llm.invoke([
                SystemMessage(content="Bạn là chuyên gia API Security Testing. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ])
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip() and " " not in p]
        except Exception as ex:
            logger.warning(f"[ParameterAssembler][LLM] Lỗi sinh id_lookup params: {ex}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 2: PAGINATION, RANGE & SORTING PARAMS
    # ──────────────────────────────────────────────────────────────────────

    def _generate_pagination_sort_with_llm(
        self,
        llm: Any,
        tech_stack: Dict[str, Any],
        naming: str,
    ) -> List[str]:
        """Gửi tech stack cho LLM sinh các tham số phân trang, lọc khoảng và sắp xếp."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        backend = tech_stack.get("backend", tech_stack.get("cms", "web framework"))
        prompt = f"""TARGET CONTEXT:
- Backend / Framework: {backend}
- Naming Convention: {naming}

YÊU CẦU: Với backend framework "{backend}", các lập trình viên thường dùng những tham số nào
để thực hiện:
1. Phân trang (pagination: page, per_page, limit, offset, cursor, slice...)
2. Sắp xếp (sorting: sort_by, order, dir, sort_order, order_field...)
3. Lọc khoảng thời gian / giá trị (range: date_from, date_to, start, end, min, max...)
Bắt buộc tuân thủ naming convention: {naming}.
Sinh 15-20 parameter names.

OUTPUT: Chỉ trả về JSON array:
["param1", "param2", ...]"""

        try:
            resp = llm.invoke([
                SystemMessage(content="Bạn là chuyên gia API Security Testing. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ])
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip() and " " not in p]
        except Exception as ex:
            logger.warning(f"[ParameterAssembler][LLM] Lỗi sinh pagination_sort params: {ex}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 3: DOMAIN & BUSINESS ENTITY FIELD PARAMS
    # ──────────────────────────────────────────────────────────────────────

    def _generate_business_fields_with_llm(
        self,
        llm: Any,
        domain: str,
        services: List[str],
        resources: List[str],
        naming: str,
    ) -> List[str]:
        """Gửi business domain + services cho LLM sinh các tham số nghiệp vụ thực tế."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        prompt = f"""TARGET CONTEXT:
- Business Domain: {domain}
- Services/Modules: {json.dumps(services[:10])}
- Core Resources: {json.dumps(resources[:15])}
- Naming Convention: {naming}

YÊU CẦU: Trong nghiệp vụ "{domain}", khi người dùng hoặc frontend gửi query hoặc submit form/JSON data,
những tham số nghiệp vụ nào (business fields, filter criteria, search facets, attributes) thường xuyên xuất hiện?
Ví dụ:
- E-commerce: coupon_code, discount, shipping_method, payment_type, in_stock, brand, rating...
- Fintech/Banking: account_number, amount, currency, beneficiary, transaction_type, otp...
- Media/CMS: author_id, publish_status, tag_id, keyword, section, category_slug...
Bắt buộc tuân thủ naming convention: {naming}.
Sinh 25-35 parameter names.

OUTPUT: Chỉ trả về JSON array:
["param1", "param2", ...]"""

        try:
            resp = llm.invoke([
                SystemMessage(content="Bạn là chuyên gia API Security Testing. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ])
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip() and " " not in p]
        except Exception as ex:
            logger.warning(f"[ParameterAssembler][LLM] Lỗi sinh business_fields params: {ex}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 4: ACTION & CONTROL WORKFLOW PARAMS
    # ──────────────────────────────────────────────────────────────────────

    def _generate_action_control_with_llm(
        self,
        llm: Any,
        domain: str,
        actions: List[str],
        naming: str,
    ) -> List[str]:
        """Gửi danh sách actions cho LLM sinh các tham số điều khiển luồng (action dispatch, mode, redirect)."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        prompt = f"""TARGET CONTEXT:
- Business Domain: {domain}
- Observed Actions: {json.dumps(actions[:15])}
- Naming Convention: {naming}

YÊU CẦU: Dựa vào các hành động đã biết và domain "{domain}", hãy sinh danh sách các tham số
ĐIỀU KHIỂN LUỒNG và DISPATCH (Workflow control, command switches, redirect targets, event triggers).
Ví dụ: action, cmd, operation, mode, step, callback_url, return_to, redirect_uri, format, output, view, method...
Bắt buộc tuân thủ naming convention: {naming}.
Sinh 15-25 parameter names.

OUTPUT: Chỉ trả về JSON array:
["param1", "param2", ...]"""

        try:
            resp = llm.invoke([
                SystemMessage(content="Bạn là chuyên gia API Security Testing. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ])
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip() and " " not in p]
        except Exception as ex:
            logger.warning(f"[ParameterAssembler][LLM] Lỗi sinh action_control params: {ex}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # COMPONENT 5: DEBUG, ADMIN & HIDDEN PRIVILEGE PARAMS
    # ──────────────────────────────────────────────────────────────────────

    def _generate_debug_security_with_llm(
        self,
        llm: Any,
        tech_stack: Dict[str, Any],
        naming: str,
    ) -> List[str]:
        """Gửi tech stack cho LLM sinh các tham số ẩn, debug, bypass quyền và tiêm nhiễm file/url."""
        if not llm or not _LANGCHAIN_AVAILABLE:
            return []

        backend = tech_stack.get("backend", tech_stack.get("cms", "web application"))
        prompt = f"""TARGET CONTEXT:
- Tech Stack / Backend: {backend}
- Naming Convention: {naming}

YÊU CẦU: Với công nghệ "{backend}", các lập trình viên thường để sót hoặc cấu hình các tham số ẨN,
DEBUG, ADMIN OVERRIDE hoặc tham số có nguy cơ bảo mật cao nào (hidden parameters, privilege escalation,
debug switches, SSRF/LFI vectors)?
Ví dụ: debug, test, dev, admin, is_admin, role, superuser, impersonate, file, path, template, include, url, token, secret, raw...
Bắt buộc tuân thủ naming convention: {naming}.
Sinh 20-30 parameter names.

OUTPUT: Chỉ trả về JSON array:
["param1", "param2", ...]"""

        try:
            resp = llm.invoke([
                SystemMessage(content="Bạn là chuyên gia API Security Testing. Chỉ trả về JSON array thuần túy."),
                HumanMessage(content=prompt),
            ])
            m = re.search(r'\[.*?\]', resp.content.strip(), re.DOTALL)
            if m:
                items = json.loads(m.group(0))
                return [p.strip() for p in items if isinstance(p, str) and p.strip() and " " not in p]
        except Exception as ex:
            logger.warning(f"[ParameterAssembler][LLM] Lỗi sinh debug_security params: {ex}")
        return []

    # ──────────────────────────────────────────────────────────────────────
    # ASSEMBLE: CARTESIAN MERGE & WORDLIST FORMATION
    # ──────────────────────────────────────────────────────────────────────

    def assemble(
        self,
        dev_profile: Optional[Dict[str, Any]] = None,
        observed_urls: Optional[List[str]] = None,
        tech_stack: Optional[Dict[str, Any]] = None,
        llm: Optional[Any] = None,
        max_params: int = 500,
    ) -> Dict[str, Any]:
        """
        Lắp ráp Parameter Wordlist qua Component-by-Component LLM Enrichment.

        Returns:
            {
                "parameters": List[str],
                "components": Dict[str, List[str]],
                "metadata": {
                    "total": int,
                    "llm_enriched": bool,
                    "naming_convention": str,
                    "enriched_counts": Dict[str, int],
                }
            }
        """
        profile = dev_profile or {}
        llm_analysis = profile.get("llm_analysis", {})
        domain = llm_analysis.get("business_domain", "web application")
        naming = profile.get("naming_convention", llm_analysis.get("naming_convention", "snake_case"))
        tech = tech_stack or profile.get("target_profile", {})

        # Trích xuất resources & services & actions từ dev_profile hoặc observed_urls
        services = profile.get("detected_services", [])
        if not services and isinstance(llm_analysis.get("url_hierarchy"), dict):
            services = llm_analysis.get("url_hierarchy", {}).get("detected_services", [])

        actions = llm_analysis.get("common_actions", [])

        # Extract thêm resources từ observed_urls nếu có
        extracted_resources: Set[str] = set()
        for u in (observed_urls or []):
            if isinstance(u, str):
                parts = [p for p in u.split("?")[0].strip("/").split("/") if p]
                for p in parts:
                    if not re.search(r'\d+', p) and len(p) > 2 and not p.endswith((".css", ".js", ".png", ".jpg")):
                        extracted_resources.add(p)
        resources_list = list(extracted_resources)[:20]

        components: Dict[str, List[str]] = {}
        enriched_counts: Dict[str, int] = {}

        # 1. Component: ID & Lookup
        base_id = [self._convert_naming(p, naming) for p in self._BASELINE_COMPONENTS["id_lookup"]]
        # Thêm entity-specific id: user_id, product_id...
        for res in resources_list[:10]:
            clean_res = res.rstrip("s")  # singularize
            base_id.append(self._convert_naming(f"{clean_res}_id", naming))
            base_id.append(self._convert_naming(f"{clean_res}_uuid", naming))
            base_id.append(self._convert_naming(f"{clean_res}_code", naming))

        llm_id = self._generate_id_lookup_with_llm(llm, domain, resources_list, naming)
        components["id_lookup"] = list(dict.fromkeys(base_id + [self._convert_naming(p, naming) for p in llm_id]))
        enriched_counts["id_lookup"] = len(llm_id)

        # 2. Component: Pagination & Sort
        base_pag = [self._convert_naming(p, naming) for p in self._BASELINE_COMPONENTS["pagination_sort"]]
        llm_pag = self._generate_pagination_sort_with_llm(llm, tech, naming)
        components["pagination_sort"] = list(dict.fromkeys(base_pag + [self._convert_naming(p, naming) for p in llm_pag]))
        enriched_counts["pagination_sort"] = len(llm_pag)

        # 3. Component: Business Fields
        base_biz = [self._convert_naming(p, naming) for p in self._BASELINE_COMPONENTS["domain_generic"]]
        llm_biz = self._generate_business_fields_with_llm(llm, domain, services, resources_list, naming)
        components["business_fields"] = list(dict.fromkeys(base_biz + [self._convert_naming(p, naming) for p in llm_biz]))
        enriched_counts["business_fields"] = len(llm_biz)

        # 4. Component: Action & Control
        base_act = [self._convert_naming(p, naming) for p in self._BASELINE_COMPONENTS["action_control"]]
        llm_act = self._generate_action_control_with_llm(llm, domain, actions, naming)
        components["action_control"] = list(dict.fromkeys(base_act + [self._convert_naming(p, naming) for p in llm_act]))
        enriched_counts["action_control"] = len(llm_act)

        # 5. Component: Debug & Security
        base_sec = [self._convert_naming(p, naming) for p in self._BASELINE_COMPONENTS["debug_security"]]
        llm_sec = self._generate_debug_security_with_llm(llm, tech, naming)
        components["debug_security"] = list(dict.fromkeys(base_sec + [self._convert_naming(p, naming) for p in llm_sec]))
        enriched_counts["debug_security"] = len(llm_sec)

        # Hợp nhất tất cả components (theo thứ tự ưu tiên khám phá)
        combined_params: List[str] = []
        for cat in ["id_lookup", "business_fields", "action_control", "debug_security", "pagination_sort"]:
            for p in components.get(cat, []):
                if p not in combined_params:
                    combined_params.append(p)

        final_params = combined_params[:max_params]
        is_llm_enriched = sum(enriched_counts.values()) > 0

        logger.info(
            f"[ParameterAssembler] Đã assemble {len(final_params)} parameters "
            f"(LLM enriched: {is_llm_enriched}, naming={naming})"
        )

        return {
            "parameters": final_params,
            "components": components,
            "metadata": {
                "total": len(final_params),
                "llm_enriched": is_llm_enriched,
                "naming_convention": naming,
                "enriched_counts": enriched_counts,
                "business_domain": domain,
            }
        }
