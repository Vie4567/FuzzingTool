"""
Authentication Manager Module.
Hỗ trợ 2 chế độ xác thực cho Recon và Fuzzing:
- Cách 2: Cung cấp sẵn Cookie hoặc Bearer Token (Manual Session / Token).
- Cách 3: Tự động đăng nhập qua Account credentials (username, password, optional login_url).
- Mặc định: Không truyền gì -> Black-box testing (Unauthenticated).
"""

import urllib.request
import urllib.parse
import ssl
import re
import http.cookiejar
import logging
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger(__name__)

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Common login path candidates when login_url is not specified
COMMON_LOGIN_PATHS = [
    "/login",
    "/admin",
    "/administrator",
    "/signin",
    "/user/login",
    "/auth/login",
    "/wp-login.php",
    "/index.php?option=com_users&view=login",
]


class AuthManager:
    """
    Quản lý ngữ cảnh xác thực (Authentication Context).
    """

    def __init__(
        self,
        cookie: Optional[str] = None,
        bearer_token: Optional[str] = None,
        account: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        verify_ssl: bool = False,
    ):
        """
        Args:
            cookie: Chuỗi Cookie đã đăng nhập (VD: 'PHPSESSID=...; token=...')
            bearer_token: JWT / Bearer Token
            account: Dict chứa {"username": "...", "password": "...", "login_url": "..."}
            custom_headers: Các header tùy chỉnh khác
            timeout: Timeout cho HTTP request
            verify_ssl: Bật/tắt kiểm tra chứng chỉ SSL
        """
        # Chuẩn hóa nếu người dùng truyền nhầm Token vào trường Cookie
        # VD: --cookie "Authorization=Bearer eyJ..." hoặc --cookie "Bearer eyJ..." hoặc --cookie "eyJ..."
        cleaned_cookie = cookie.strip() if cookie else None
        detected_token = bearer_token.strip() if bearer_token else None

        if cleaned_cookie and not detected_token:
            if "bearer " in cleaned_cookie.lower():
                m = re.search(r'bearer\s+([a-zA-Z0-9_\-\.]+)', cleaned_cookie, re.I)
                if m:
                    detected_token = m.group(1)
                    cleaned_cookie = None
            elif cleaned_cookie.startswith("eyJ"):
                detected_token = cleaned_cookie
                cleaned_cookie = None

        self.cookie = cleaned_cookie
        self.bearer_token = detected_token
        self.account = account if (account and account.get("username") and account.get("password")) else None
        self.custom_headers = custom_headers or {}
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # SSL context
        self.ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

        # Cookie jar for auto-login
        self.cookie_jar = http.cookiejar.CookieJar()
        self._cached_auth_headers: Optional[Dict[str, str]] = None

    def get_auth_headers(self, base_url: str = "") -> Dict[str, str]:
        """
        Lấy các header xác thực đã giải quyết:
        1. Ưu tiên Cách 2: Nếu có cookie hoặc bearer_token -> trả về ngay.
        2. Nếu không có nhưng có account -> thực hiện Cách 3: Auto-login.
        3. Mặc định: Trả về {} (không xác thực).
        """
        if self._cached_auth_headers is not None:
            return dict(self._cached_auth_headers)

        headers = dict(self.custom_headers)

        # ── Cách 2: Cung cấp Cookie hoặc Bearer Token trực tiếp ──────────────
        if self.cookie or self.bearer_token:
            if self.cookie:
                headers["Cookie"] = self.cookie
                logger.info(f"[AuthManager] Sử dụng Cookie thủ công: {self.cookie[:30]}...")
            if self.bearer_token:
                headers["Authorization"] = f"Bearer {self.bearer_token}"
                logger.info(f"[AuthManager] Sử dụng Bearer Token: {self.bearer_token[:20]}...")
            self._cached_auth_headers = headers
            return headers

        # ── Cách 3: Tự động Login từ Account credentials ──────────────────────
        if self.account:
            login_headers = self._auto_login(base_url)
            headers.update(login_headers)
            self._cached_auth_headers = headers
            return headers

        # ── Mặc định: Không truyền gì (Black-box unauthenticated) ─────────────
        self._cached_auth_headers = headers
        return headers

    def _auto_login(self, base_url: str) -> Dict[str, str]:
        """
        Thực hiện quy trình đăng nhập tự động:
        1. Xác định Login URL (từ account hoặc tự động dò tìm form đăng nhập).
        2. Gửi GET để thu thập cookie ban đầu và bóc tách form fields (CSRF token, v.v.).
        3. Điền username, password và submit POST.
        4. Trích xuất Session Cookie thu được.
        """
        username = self.account.get("username", "")
        password = self.account.get("password", "")
        specified_login_url = self.account.get("login_url", "")

        target_login_url = None
        base_clean = base_url.rstrip("/")

        if specified_login_url:
            if specified_login_url.startswith("http"):
                target_login_url = specified_login_url
            else:
                target_login_url = f"{base_clean}/{specified_login_url.lstrip('/')}"
        else:
            # Tự động tìm form login trên trang chủ hoặc các path phổ biến
            target_login_url = self._find_login_url(base_clean)

        if not target_login_url:
            logger.warning("[AuthManager] Không tìm thấy URL đăng nhập phù hợp.")
            return {}

        logger.info(f"[AuthManager] Đang thực hiện Auto-Login vào: {target_login_url} (User: {username})")

        # Cookie processor & opener
        cookie_handler = urllib.request.HTTPCookieProcessor(self.cookie_jar)
        opener = urllib.request.build_opener(
            cookie_handler,
            urllib.request.HTTPSHandler(context=self.ssl_ctx)
        )

        try:
            # Bước 1: GET trang đăng nhập để lấy cookies ban đầu & bóc tách form
            req_get = urllib.request.Request(
                target_login_url,
                headers={"User-Agent": _DEFAULT_UA}
            )
            with opener.open(req_get, timeout=self.timeout) as resp:
                get_body = resp.read().decode("utf-8", errors="ignore")
                final_get_url = resp.geturl()

            form_data, post_action = self._extract_login_form(get_body, final_get_url, username, password)
            if not form_data:
                logger.warning("[AuthManager] Không trích xuất được form đăng nhập.")
                return {}

            # Bước 2: POST credentials
            encoded_data = urllib.parse.urlencode(form_data).encode("utf-8")
            req_post = urllib.request.Request(
                post_action,
                data=encoded_data,
                headers={
                    "User-Agent": _DEFAULT_UA,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": target_login_url,
                }
            )

            # Đọc body phản hồi
            post_body = post_resp.read().decode("utf-8", errors="ignore")
            auth_res = {}

            # Kiểm tra xem phản hồi có trả về JSON Token không (API JWT / OAuth)
            try:
                res_json = json.loads(post_body)
                token = (
                    res_json.get("token") or
                    res_json.get("access_token") or
                    res_json.get("jwt") or
                    res_json.get("accessToken") or
                    res_json.get("id_token") or
                    (res_json.get("data") and isinstance(res_json["data"], dict) and res_json["data"].get("token"))
                )
                if token:
                    logger.info(f"[AuthManager] ✅ Auto-Login thành công qua API! Thu được Bearer Token: {token[:20]}...")
                    auth_res["Authorization"] = f"Bearer {token}"
            except Exception:
                pass

            # Bước 3: Lấy chuỗi Cookie đã lưu trong CookieJar
            # Lọc phân biệt giữa Session Cookies thực sự và Tracking Cookies (_ga, g_state, _fbp, ...)
            TRACKING_COOKIE_PREFIXES = ("_ga", "_gid", "_gat", "_fbp", "__utm", "g_state", "ajs_")
            session_cookies = []
            all_cookies = []

            for cookie in self.cookie_jar:
                cookie_pair = f"{cookie.name}={cookie.value}"
                all_cookies.append(cookie_pair)
                # Kiểm tra xem có phải cookie phiên thực sự không
                if not any(cookie.name.startswith(pfx) for pfx in TRACKING_COOKIE_PREFIXES):
                    session_cookies.append(cookie_pair)

            if session_cookies:
                cookie_str = "; ".join(session_cookies)
                logger.info(f"[AuthManager] ✅ Auto-Login thành công! Thu được Session Cookie phiên: {cookie_str[:40]}...")
                auth_res["Cookie"] = "; ".join(all_cookies)
            elif all_cookies:
                logger.warning(
                    "[AuthManager] ⚠️ Chỉ phát hiện Tracking/SSO Cookies (_ga, g_state...), không tìm thấy Session Cookie phiên. "
                    "Hệ thống đích có thể lưu Token trong LocalStorage (JWT). Hãy truyền trực tiếp qua --token."
                )
                auth_res["Cookie"] = "; ".join(all_cookies)

            if auth_res:
                return auth_res
            else:
                logger.warning("[AuthManager] Đã gửi thông tin login nhưng không nhận được Set-Cookie hay Token.")
                return {}

        except Exception as e:
            logger.error(f"[AuthManager] Lỗi khi thực hiện Auto-Login: {e}")
            return {}

    def _find_login_url(self, base_clean: str) -> Optional[str]:
        """Dò tìm URL đăng nhập từ trang chủ, router hoặc HTTP redirect."""
        # 1. Thử quét trang chủ xem có form password hoặc link login không
        try:
            req = urllib.request.Request(base_clean, headers={"User-Agent": _DEFAULT_UA})
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as r:
                home_body = r.read().decode("utf-8", errors="ignore")
                if 'type="password"' in home_body.lower() or "type='password'" in home_body.lower():
                    return base_clean
                # Tìm thẻ a có href chứa login / signin / auth
                for m in re.finditer(r'href=[\"\']([^\"\']*(?:login|signin|dang-nhap|auth)[^\"\']*)[\"\']', home_body, re.I):
                    candidate = m.group(1)
                    return urllib.parse.urljoin(base_clean, candidate)
                # Tìm trong router JS bundle (cho SPA như React/Vue/Angular)
                for js_path in re.findall(r'<script[^>]+src=[\"\']([^\"\']+)[\"\']', home_body, re.I):
                    js_url = urllib.parse.urljoin(base_clean, js_path)
                    try:
                        req_js = urllib.request.Request(js_url, headers={"User-Agent": _DEFAULT_UA})
                        with urllib.request.urlopen(req_js, timeout=4, context=self.ssl_ctx) as js_r:
                            js_content = js_r.read().decode("utf-8", errors="ignore")
                            for route in re.findall(r'[\"\'](/(?:login|signin|auth)[a-zA-Z0-9_\-]*)[\"\']', js_content):
                                return urllib.parse.urljoin(base_clean, route)
                    except Exception:
                        pass
        except Exception:
            pass

        # 2. Thử truy cập trang bảo vệ như /admin để bắt Redirect Location
        try:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            no_redir_opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=self.ssl_ctx))
            resp = no_redir_opener.open(f"{base_clean}/admin", timeout=4)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get("Location")
                if loc:
                    return urllib.parse.urljoin(base_clean, loc)
        except Exception:
            pass

        # 3. Thử lần lượt các URL phổ biến
        for path in COMMON_LOGIN_PATHS:
            cand_url = f"{base_clean}{path}"
            try:
                req = urllib.request.Request(cand_url, headers={"User-Agent": _DEFAULT_UA})
                with urllib.request.urlopen(req, timeout=4, context=self.ssl_ctx) as r:
                    if r.status in (200, 301, 302):
                        return cand_url
            except Exception:
                continue

        return f"{base_clean}/login"

    def _extract_login_form(
        self, html: str, page_url: str, username: str, password: str
    ) -> Tuple[Dict[str, str], str]:
        """
        Bóc tách form chứa input password, bảo lưu các hidden field (CSRF tokens)
        và điền username/password.
        """
        # Tìm tất cả form trong html
        form_matches = re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
        target_form = None
        target_attrs = ""

        for m in form_matches:
            attrs, inner = m.groups()
            if re.search(r'type=[\"\']password[\"\']', inner, re.IGNORECASE):
                target_form = inner
                target_attrs = attrs
                break

        if not target_form:
            # Fallback: lấy form đầu tiên nếu có
            m_first = re.search(r'<form\b([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL)
            if m_first:
                target_attrs, target_form = m_first.groups()
            else:
                return {}, page_url

        # Xác định Action URL
        action_match = re.search(r'action=[\"\']([^\"\']*)[\"\']', target_attrs, re.IGNORECASE)
        action_val = action_match.group(1).strip() if action_match else ""
        if not action_val:
            action_url = page_url
        else:
            action_url = urllib.parse.urljoin(page_url, action_val)

        # Trích xuất tất cả input tags
        inputs = re.findall(r'<input\b([^>]*)>', target_form, re.IGNORECASE)
        form_data: Dict[str, str] = {}
        username_field = None
        password_field = None

        for inp in inputs:
            name_m = re.search(r'name=[\"\']([^\"\']+)[\"\']', inp, re.IGNORECASE)
            val_m = re.search(r'value=[\"\']([^\"\']*)[\"\']', inp, re.IGNORECASE)
            type_m = re.search(r'type=[\"\']([^\"\']+)[\"\']', inp, re.IGNORECASE)

            if not name_m:
                continue

            name = name_m.group(1)
            val = val_m.group(1) if val_m else ""
            inp_type = type_m.group(1).lower() if type_m else "text"

            if inp_type == "password":
                password_field = name
            elif inp_type in ("text", "email") or not inp_type:
                # Tìm trường username
                if any(k in name.lower() for k in ("user", "login", "email", "account", "name", "id")):
                    username_field = name
                elif not username_field:
                    username_field = name
            else:
                # Giữ nguyên hidden fields (CSRF tokens, viewstate, return, v.v.)
                form_data[name] = val

        # Gán username và password
        if username_field:
            form_data[username_field] = username
        else:
            form_data["username"] = username

        if password_field:
            form_data[password_field] = password
        else:
            form_data["password"] = password

        return form_data, action_url
