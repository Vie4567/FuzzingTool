"""Origin-bound authentication for Recon using its verified, scoped transport."""

import http.cookiejar
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Dict, Tuple

from src.coordinator.llm_logging import sanitize_for_log
from src.tools.recon_http import ScopedReconTransport

logger = logging.getLogger(__name__)
_DEFAULT_UA = "SentinelPentest/1.0 (scoped-recon-auth)"
COMMON_LOGIN_PATHS = [
    "/login", "/admin", "/administrator", "/signin", "/user/login",
    "/auth/login", "/wp-login.php", "/index.php?option=com_users&view=login",
]


def _origin_key(url):
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


class AuthManager:
    """Resolve credentials for one target origin; never log credential values.

    A manager is bound on the first get_auth_headers(base_url) call. Reusing it
    for a different origin is rejected, even when that origin is network-allowed.
    A new manager is required for a different target session.
    """

    def __init__(
        self,
        cookie: Optional[str] = None,
        bearer_token: Optional[str] = None,
        account: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        verify_ssl: bool = True,
        allowed_origins=None,
        auth_origins=None,
        tls_ca_file=None,
    ):
        if verify_ssl is not True:
            raise ValueError("Authentication requires TLS certificate verification; use tls_ca_file for a private CA")
        if cookie is not None and not isinstance(cookie, str):
            raise ValueError("cookie must be a string")
        if bearer_token is not None and not isinstance(bearer_token, str):
            raise ValueError("bearer_token must be a string")
        if custom_headers is not None and not isinstance(custom_headers, dict):
            raise ValueError("custom_headers must be a dictionary")
        if account is not None and (
            not isinstance(account, dict)
            or not all(isinstance(account.get(key), str) and account[key] for key in ("username", "password"))
        ):
            raise ValueError("account requires nonempty username and password strings")
        cleaned_cookie = cookie.strip() if cookie else None
        detected_token = bearer_token.strip() if bearer_token else None
        if cleaned_cookie and not detected_token:
            if "bearer " in cleaned_cookie.lower():
                match = re.search(r"bearer\s+([a-zA-Z0-9_\-\.]+)", cleaned_cookie, re.I)
                if match:
                    detected_token, cleaned_cookie = match.group(1), None
            elif cleaned_cookie.startswith("eyJ"):
                detected_token, cleaned_cookie = cleaned_cookie, None
        self.cookie = cleaned_cookie
        self.bearer_token = detected_token
        self.account = dict(account) if account is not None else None
        self.custom_headers = dict(custom_headers or {})
        self.timeout = timeout
        self.verify_ssl = True
        self.tls_ca_file = tls_ca_file
        self.allowed_origins = allowed_origins
        self.auth_origins = auth_origins
        self.ssl_ctx = ssl.create_default_context(cafile=tls_ca_file)
        self.cookie_jar = http.cookiejar.CookieJar()
        self._cached_auth_headers = None
        self._transport = None
        self._bound_origin = None
        self._base_url = None

    def _supplied_headers(self):
        headers = dict(self.custom_headers)
        for key, value in (("Cookie", self.cookie),
                           ("Authorization", "Bearer " + self.bearer_token if self.bearer_token else None)):
            if value:
                headers = {name: item for name, item in headers.items() if name.lower() != key.lower()}
                headers[key] = value
        return headers

    def redact(self, value):
        """Mask caller and resolved credentials without attempting a login."""
        return sanitize_for_log({
            "headers": {**self._supplied_headers(), **(self._cached_auth_headers or {})},
            "credentials": self.account,
            "payload": value,
        })["payload"]

    def _bind(self, base_url):
        if not base_url:
            if self._base_url is None:
                raise ValueError("base_url is required to scope authentication")
            base_url = self._base_url
        if self._transport is None:
            transport = ScopedReconTransport(
                base_url, headers=self._supplied_headers(),
                allowed_origins=self.allowed_origins, auth_origins=self.auth_origins,
                verify_ssl=True, tls_ca_file=self.tls_ca_file,
            )
            transport.check_url(base_url, credentials=bool(self._supplied_headers() or self.account))
            self._transport = transport
            self._base_url = base_url
            self._bound_origin = _origin_key(base_url)
            self.ssl_ctx = transport.ssl_context
        else:
            self._transport.check_url(base_url)
            if _origin_key(base_url) != self._bound_origin:
                raise ValueError("Authentication manager is bound to a different target origin")
        return self._transport

    def get_auth_headers(self, base_url: str = "") -> Dict[str, str]:
        """Return copies of scoped headers; failed account login is explicit."""
        if not base_url and self._transport is None and not (self._supplied_headers() or self.account):
            return {}
        self._bind(base_url)
        if self._cached_auth_headers is not None:
            return dict(self._cached_auth_headers)
        headers = self._supplied_headers()
        if self.cookie or self.bearer_token:
            logger.info("[AuthManager] Using caller-supplied authentication headers")
        elif self.account:
            resolved = self._auto_login(self._base_url)
            if not resolved:
                raise RuntimeError("Automatic login did not produce scoped authentication credentials")
            headers.update(resolved)
        self._cached_auth_headers = dict(headers)
        return dict(headers)

    def _open(self, url, *, method="GET", data=None, headers=None, timeout=None):
        # Auth discovery, login forms and submission all remain inside credential
        # scope, which may be stricter than the network scope used by Recon.
        self._transport.check_url(url, credentials=True)
        request = urllib.request.Request(url, data=data, method=method,
                                         headers={"User-Agent": _DEFAULT_UA, **(headers or {})})
        return self._transport.open(request, timeout=self.timeout if timeout is None else timeout,
                                    cookie_jar=self.cookie_jar)

    def _auto_login(self, base_url: str) -> Dict[str, str]:
        self._bind(base_url)
        username, password = self.account["username"], self.account["password"]
        specified = self.account.get("login_url", "")
        try:
            target = urllib.parse.urljoin(base_url.rstrip("/") + "/", specified) if specified else self._find_login_url(base_url)
            if not target:
                return {}
            with self._open(target) as response:
                page = response.read().decode("utf-8", errors="ignore")
                page_url = response.geturl()
            data, action = self._extract_login_form(page, page_url, username, password)
            if not data:
                logger.warning("[AuthManager] No usable login form found")
                return {}
            with self._open(action, method="POST", data=urllib.parse.urlencode(data).encode("utf-8"),
                            headers={"Content-Type": "application/x-www-form-urlencoded"}) as response:
                body = response.read().decode("utf-8", errors="ignore")
            result = {}
            try:
                parsed = json.loads(body)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict):
                token = next((parsed.get(key) for key in ("token", "access_token", "jwt", "accessToken", "id_token")
                              if isinstance(parsed.get(key), str) and parsed[key]), None)
                if token is None and isinstance(parsed.get("data"), dict):
                    token = parsed["data"].get("token")
                if isinstance(token, str) and token:
                    result["Authorization"] = "Bearer " + token
            # Apply CookieJar's domain/path/Secure rules to the bound target,
            # rather than copying every cookie collected from a login origin.
            cookie_request = urllib.request.Request(self._base_url)
            self.cookie_jar.add_cookie_header(cookie_request)
            cookie_value = cookie_request.get_header("Cookie")
            if cookie_value:
                names = [piece.split("=", 1)[0].strip() for piece in cookie_value.split(";")]
                tracking = ("_ga", "_gid", "_gat", "_fbp", "__utm", "g_state", "ajs_")
                if any(not name.startswith(tracking) for name in names):
                    result["Cookie"] = cookie_value
            if result:
                logger.info("[AuthManager] Received scoped authentication credentials")
            else:
                logger.warning("[AuthManager] Login response contained no usable authentication credentials")
            return result
        except urllib.error.HTTPError as exc:
            exc.close()
            logger.warning("[AuthManager] Login stopped on HTTP response %s", exc.code)
            return {}
        except Exception as exc:
            # Server messages/URLs may echo credentials; report only the type.
            logger.warning("[AuthManager] Login failed (%s)", type(exc).__name__)
            return {}

    def _find_login_url(self, base_url: str) -> Optional[str]:
        """Discover only inside credential scope, never follow redirects."""
        try:
            with self._open(base_url) as response:
                body = response.read().decode("utf-8", errors="ignore")
            if re.search(r"type=[\"']password[\"']", body, re.I):
                return base_url
            links = re.findall(r"href=[\"']([^\"']*(?:login|signin|dang-nhap|auth)[^\"']*)[\"']", body, re.I)
            for link in links:
                candidate = urllib.parse.urljoin(base_url, link)
                if self._transport.allows_auth(candidate):
                    return candidate
            scripts = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", body, re.I)
            for path in scripts:
                url = urllib.parse.urljoin(base_url, path)
                if not self._transport.allows_auth(url):
                    continue
                try:
                    with self._open(url, timeout=min(4, self.timeout)) as response:
                        script = response.read().decode("utf-8", errors="ignore")
                    routes = re.findall(r"[\"'](/(?:login|signin|auth)[a-zA-Z0-9_\-]*)[\"']", script)
                    if routes:
                        return urllib.parse.urljoin(base_url, routes[0])
                except urllib.error.HTTPError as exc:
                    exc.close()
                except Exception:
                    pass
        except urllib.error.HTTPError as exc:
            exc.close()
        except Exception:
            pass
        for path in COMMON_LOGIN_PATHS:
            candidate = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                with self._open(candidate, timeout=min(4, self.timeout)) as response:
                    body = response.read().decode("utf-8", errors="ignore")
                    if re.search(r"type=[\"']password[\"']", body, re.I):
                        return candidate
            except urllib.error.HTTPError as exc:
                # A redirect is only recorded. Its destination is never fetched
                # implicitly, including HTTP->HTTPS or SSO/login redirects.
                exc.close()
            except Exception:
                continue
        return None

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
