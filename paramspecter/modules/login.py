"""
modules/login.py
Automated form-based login: detects login form, extracts CSRF tokens,
POSTs credentials, injects session cookies.
"""

import re
from typing import Dict, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..utils import fetch_with_retry, log, log_section, col, C


class FormLoginHandler:
    CSRF_FIELD_RE = re.compile(
        r"csrf|token|nonce|_wpnonce|authenticity_token|__RequestVerificationToken",
        re.I,
    )

    def __init__(self, session, login_url: str, username: str, password: str,
                 user_field: str = "username", pass_field: str = "password",
                 timeout: int = 15):
        self.session    = session
        self.login_url  = login_url
        self.username   = username
        self.password   = password
        self.user_field = user_field
        self.pass_field = pass_field
        self.timeout    = timeout

    def login(self) -> None:
        log_section("FORM LOGIN")
        log("AUTH", f"Fetching login page: {col(self.login_url, C.CYAN)}", C.CYAN)

        get_resp, err = fetch_with_retry(
            self.session, self.login_url,
            timeout=self.timeout, allow_redirects=True,
        )
        if get_resp is None:
            self._die(f"Could not reach login page: {err}")

        soup = BeautifulSoup(get_resp.text, "html.parser")
        action_url, method, hidden = self._parse_login_form(soup, get_resp.url)

        log("AUTH", f"Form action : {col(action_url, C.CYAN)}", C.CYAN)
        if hidden:
            log("AUTH", f"CSRF fields : {col(', '.join(hidden.keys()), C.YELLOW)}", C.YELLOW)

        payload: Dict[str, str] = {
            self.user_field: self.username,
            self.pass_field: self.password,
        }
        payload.update(hidden)

        log("AUTH",
            f"Submitting  : {col(self.user_field, C.WHITE)}=<user>  "
            f"{col(self.pass_field, C.WHITE)}=<redacted>  "
            f"method={col(method.upper(), C.WHITE)}",
            C.CYAN)

        if method.upper() == "GET":
            post_resp, err = fetch_with_retry(
                self.session, action_url, method="GET", params=payload,
                timeout=self.timeout, allow_redirects=True,
            )
        else:
            post_resp, err = fetch_with_retry(
                self.session, action_url, method="POST", data=payload,
                timeout=self.timeout, allow_redirects=True,
            )

        if post_resp is None:
            self._die(f"Login POST failed: {err}")

        self._validate(post_resp)

        cookie_names = [c.name for c in self.session.cookies]
        if cookie_names:
            log("AUTH", col(f"Session cookies injected: {', '.join(cookie_names)}", C.GREEN), C.GREEN)
        else:
            log("AUTH", col("WARNING: No cookies received after login", C.YELLOW), C.YELLOW)

    def _parse_login_form(self, soup, page_url: str) -> Tuple[str, str, Dict[str, str]]:
        form = None
        for candidate in soup.find_all("form"):
            if candidate.find("input", {"type": "password"}):
                form = candidate
                break
        if form is None:
            form = soup.find("form")

        if form is None:
            log("AUTH", col("No <form> found on login page; will POST directly to --login-url", C.YELLOW), C.YELLOW)
            return self.login_url, "POST", {}

        raw_action = form.get("action", "").strip() or page_url
        action_url = urljoin(page_url, raw_action)
        method     = form.get("method", "POST").strip()

        hidden: Dict[str, str] = {}
        for inp in form.find_all("input", {"type": "hidden"}):
            name  = inp.get("name", "").strip()
            value = inp.get("value", "")
            if name and self.CSRF_FIELD_RE.search(name):
                hidden[name] = value

        for inp in form.find_all("input", {"type": "hidden"}):
            name  = inp.get("name", "").strip()
            value = inp.get("value", "")
            if name and name not in hidden:
                hidden[name] = value

        return action_url, method, hidden

    def _validate(self, resp) -> None:
        final_url = resp.url
        if not (200 <= resp.status_code < 300):
            self._die(
                f"Login returned HTTP {resp.status_code} (expected 2xx). Final URL: {final_url}"
            )
        login_path = urlparse(self.login_url).path.rstrip("/")
        final_path = urlparse(final_url).path.rstrip("/")
        if login_path and final_path == login_path:
            self._die(
                f"Server redirected back to the login page after POST.\n"
                f"  Login URL : {self.login_url}\n"
                f"  Final URL : {final_url}\n"
                f"  This usually means the credentials were rejected."
            )
        if resp.text and re.search(
            rf'(?:name|id)\s*=\s*["\']?{re.escape(self.pass_field)}["\']?',
            resp.text, re.I
        ):
            log("AUTH", col("WARNING: Password field found in response — login may have failed", C.YELLOW), C.YELLOW)
            return
        log("AUTH",
            col(f"Login appears successful  (HTTP {resp.status_code}, landed on: {final_url})", C.GREEN + C.BOLD),
            C.GREEN)

    @staticmethod
    def _die(msg: str) -> None:
        import sys
        from ..utils.helpers import _log_lock
        with _log_lock:
            print(f"\n  {col('AUTH ERROR:', C.RED + C.BOLD)}  {col(msg, C.RED)}\n")
        sys.exit(1)
