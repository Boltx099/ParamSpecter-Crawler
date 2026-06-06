"""
utils/http.py
HTTP helpers: fetch_with_retry (exponential backoff),
fetch_with_playwright (headless JS rendering + full XHR interception),
SPA auto-detection, curl_cffi Chrome TLS fingerprint spoofing,
resume/checkpoint helpers.

TLS fingerprint spoofing (curl_cffi):
  pip install curl-cffi
  Bypasses Cloudflare, Akamai, DataDome and other WAFs that block
  Python requests by its TLS fingerprint. Falls back to requests
  transparently if curl_cffi is not installed.

SPA auto-detection:
  If a page returns 200 but the HTML body is nearly empty (<500 chars
  of visible text), ParamSpecter automatically retries with Playwright
  if available. This handles React/Vue/Angular apps without requiring
  --playwright to be set manually.
"""

import os, re, time, random, threading
from typing import Optional, List, Set, Tuple, Dict
from urllib.parse import urlparse

from .constants import _RETRYABLE_STATUS
from .helpers import vlog, random_ua, log, C, col

# -----------------------------------------------------------------
#  HTTP BACKEND — curl_cffi (preferred) or requests (fallback)
# -----------------------------------------------------------------
try:
    from curl_cffi import requests as _cffi_requests
    CURL_CFFI_AVAILABLE = True
    # Chrome versions to rotate between for TLS fingerprint diversity
    _CHROME_IMPERSONATE = [
        "chrome120", "chrome119", "chrome116", "chrome110",
        "chrome107", "chrome104", "chrome101", "chrome99",
    ]
    _EDGE_IMPERSONATE = ["edge101", "edge99"]
    _ALL_IMPERSONATE  = _CHROME_IMPERSONATE + _EDGE_IMPERSONATE
    log("HTTP", col("curl_cffi available — Chrome TLS fingerprint active", C.GREEN), C.GREEN)
except ImportError:
    CURL_CFFI_AVAILABLE = False
    import requests as _std_requests

try:
    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# -----------------------------------------------------------------
#  SESSION FACTORY
# -----------------------------------------------------------------

def make_session(impersonate: str = "chrome120",
                 rotate_impersonate: bool = False) -> object:
    """
    Return a requests-compatible session.
    Uses curl_cffi with Chrome TLS fingerprint if available,
    falls back to standard requests.Session() otherwise.
    """
    if CURL_CFFI_AVAILABLE:
        imp = random.choice(_ALL_IMPERSONATE) if rotate_impersonate else impersonate
        session = _cffi_requests.Session(impersonate=imp)
        # curl_cffi session doesn't persist impersonate per-request,
        # store it so fetch_with_retry can rotate if needed
        session._impersonate        = imp
        session._rotate_impersonate = rotate_impersonate
        return session
    else:
        return _std_requests.Session()


def _is_cffi_session(session) -> bool:
    return CURL_CFFI_AVAILABLE and hasattr(session, "_impersonate")


# -----------------------------------------------------------------
#  SPA DETECTION
# -----------------------------------------------------------------
# Patterns that indicate a page is a client-side rendered SPA
_SPA_INDICATORS = re.compile(
    r'<div\s+id=["\'](?:root|app|__next|__nuxt|application)["\']'
    r'|window\.__NEXT_DATA__'
    r'|window\.__NUXT__'
    r'|ng-version='
    r'|data-reactroot'
    r'|<script[^>]+type=["\']module["\']',
    re.I,
)

_MIN_CONTENT_CHARS = 500   # fewer visible chars than this → likely SPA

def is_spa_response(html: str) -> bool:
    """
    Return True if the HTML looks like an empty SPA shell that
    needs JS execution to render real content.
    """
    if not html:
        return False
    # Strip tags and whitespace to count visible text
    visible = re.sub(r"<[^>]+>", " ", html)
    visible = re.sub(r"\s+", " ", visible).strip()
    if len(visible) < _MIN_CONTENT_CHARS:
        return True
    if _SPA_INDICATORS.search(html):
        return True
    return False


# -----------------------------------------------------------------
#  RETRY / HTTP
# -----------------------------------------------------------------

def fetch_with_retry(session, url: str, method: str = "GET",
                     data=None, max_retries: int = 3,
                     timeout: int = 10, rotate_ua: bool = False,
                     proxies=None, **kwargs) -> Tuple[Optional[object], Optional[str]]:
    """
    Fetch a URL with exponential backoff.
    Rotates TLS impersonation profile on 403/429 when using curl_cffi
    so each retry looks like a different Chrome version to WAFs.
    """
    headers = {}
    if rotate_ua:
        headers["User-Agent"] = random_ua()

    is_cffi = _is_cffi_session(session)
    delay   = 1.0
    err     = None

    for attempt in range(max_retries + 1):
        try:
            # Rotate Chrome impersonation on retries (WAF evasion)
            if is_cffi and attempt > 0 and session._rotate_impersonate:
                new_imp = random.choice(_ALL_IMPERSONATE)
                session.impersonate = new_imp
                vlog("HTTP", f"Rotating TLS fingerprint → {new_imp}", C.CYAN)

            resp = session.request(
                method, url, data=data, headers=headers,
                timeout=timeout, proxies=proxies,
                allow_redirects=True, **kwargs
            )

            # Retryable status codes (429, 503, 502 etc.)
            if resp.status_code in _RETRYABLE_STATUS and attempt < max_retries:
                retry_after = float(resp.headers.get("Retry-After", delay * 2))
                retry_after = min(retry_after, 60)
                vlog("RETRY", f"HTTP {resp.status_code} on {url[:60]}, "
                     f"waiting {retry_after:.1f}s", C.YELLOW)
                time.sleep(retry_after)
                delay = min(delay * 2, 30)
                continue

            # Cloudflare challenge page detection
            if resp.status_code == 403 and _is_cf_block(resp):
                if attempt < max_retries:
                    vlog("HTTP", col(
                        f"Cloudflare block detected on {url[:50]} — "
                        f"{'rotating fingerprint' if is_cffi else 'install curl-cffi to bypass'}",
                        C.YELLOW), C.YELLOW)
                    time.sleep(delay + random.uniform(1, 3))
                    delay = min(delay * 2, 15)
                    continue

            return resp, None

        except Exception as e:
            err = str(e)
            # Connection errors
            if "ConnectionError" in type(e).__name__ or "Timeout" in type(e).__name__:
                err = f"{type(e).__name__}: {str(e)[:80]}"
            if "TooManyRedirects" in type(e).__name__:
                return None, "TooManyRedirects"

        if attempt < max_retries:
            jitter = random.uniform(0, 0.3) * delay
            vlog("RETRY", f"Attempt {attempt+1}/{max_retries} failed "
                 f"for {url[:60]}: {err}", C.YELLOW)
            time.sleep(delay + jitter)
            delay = min(delay * 2, 30)

    return None, err


def _is_cf_block(resp) -> bool:
    """Detect Cloudflare / WAF block pages."""
    server = resp.headers.get("server", "").lower()
    ct     = resp.headers.get("content-type", "").lower()
    if "cloudflare" in server:
        return True
    if resp.status_code in (403, 503) and "text/html" in ct:
        body_lower = resp.text[:2000].lower()
        if any(s in body_lower for s in (
            "cloudflare", "cf-ray", "ray id", "attention required",
            "ddos protection", "checking your browser", "just a moment",
            "enable javascript", "security check",
        )):
            return True
    return False


# -----------------------------------------------------------------
#  PLAYWRIGHT — full XHR/Fetch/WebSocket interception
# -----------------------------------------------------------------
_pw_local = threading.local()

# Resource types to intercept for API endpoint discovery
_INTERCEPT_TYPES = {"xhr", "fetch", "websocket", "eventsource"}

# Extensions to block (images, fonts, media) to speed up rendering
_BLOCK_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".ogg", ".wav",
}


def _get_thread_context(pw_browser, extra_headers: Dict = None):
    """Get or create a per-thread Playwright browser context."""
    if not hasattr(_pw_local, "context") or _pw_local.context is None:
        _pw_local.context = pw_browser.new_context(
            user_agent=random_ua(),
            ignore_https_errors=True,
            extra_http_headers=extra_headers or {},
            java_script_enabled=True,
            # Realistic viewport
            viewport={"width": 1366, "height": 768},
            # Pass as real Chrome
            locale="en-US",
        )
    return _pw_local.context


def fetch_with_playwright(pw_browser, url: str, timeout: int = 15,
                          xhr_queue: List = None,
                          cookies: Dict = None,
                          extra_headers: Dict = None) -> Tuple[str, str]:
    """
    Fetch a URL using headless Chromium.
    Intercepts ALL XHR/Fetch/WebSocket requests and adds them to xhr_queue
    for the crawler to process as additional endpoints.

    Also:
    - Blocks image/font/media resources for speed
    - Waits for network to be idle (SPA content fully rendered)
    - Captures dynamically inserted <script> src URLs
    - Returns (html, final_url)
    """
    ctx  = _get_thread_context(pw_browser, extra_headers)
    page = ctx.new_page()

    intercepted_urls:  List[str]         = []
    intercepted_reqs:  List[Dict]        = []   # {url, method, post_data, headers}

    # ── Resource blocking via route (the only way to actually abort in Playwright) ──
    def _on_route(route, request):
        ext = os.path.splitext(urlparse(request.url).path)[-1].lower()
        if ext in _BLOCK_EXTENSIONS:
            try:
                route.abort()
            except Exception:
                pass
            return
        try:
            route.continue_()
        except Exception:
            pass

    page.route("**/*", _on_route)

    # ── Request observation — capture API call metadata (no abort here) ──
    def _on_request(request):
        rtype = request.resource_type
        rurl  = request.url
        parsed = urlparse(rurl)
        # Capture API calls
        if rtype in _INTERCEPT_TYPES:
            if parsed.path and len(parsed.path) > 1:
                intercepted_urls.append(rurl)
                try:
                    intercepted_reqs.append({
                        "url":       rurl,
                        "method":    request.method,
                        "post_data": request.post_data or "",
                        "headers":   dict(request.headers),
                        "type":      rtype,
                    })
                except Exception:
                    pass

    # ── Response interception — capture inline JS endpoint strings ──
    def _on_response(response):
        ct = response.headers.get("content-type", "")
        if "javascript" in ct or "json" in ct:
            try:
                body = response.text()
                # Extract API paths from JS/JSON responses
                for m in re.finditer(r'["\'](/(?:api|v\d+|graphql|rest|gql)[^\s"\'<>]{0,200})["\']', body):
                    path = m.group(1)
                    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    intercepted_urls.append(base + path)
            except Exception:
                pass

    page.on("request",  _on_request)
    page.on("response", _on_response)

    # Inject cookies if provided
    if cookies:
        ctx.add_cookies([
            {"name": k, "value": v, "domain": urlparse(url).netloc, "path": "/"}
            for k, v in cookies.items()
        ])

    html      = ""
    final_url = url
    try:
        page.goto(url, wait_until="networkidle", timeout=timeout * 1000)

        # Scroll to bottom to trigger lazy-loaded content
        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(800)
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(500)
        except Exception:
            pass

        html      = page.content()
        final_url = page.url

        # Also grab any dynamically added script src URLs
        try:
            script_srcs = page.evaluate(
                "Array.from(document.querySelectorAll('script[src]')).map(s => s.src)"
            )
            for src in (script_srcs or []):
                if src and src.startswith("http"):
                    intercepted_urls.append(src)
        except Exception:
            pass

    except Exception as e:
        vlog("PW", f"Playwright error on {url[:60]}: {e}", C.YELLOW)
    finally:
        try:
            page.close()
        except Exception:
            pass

    if xhr_queue is not None:
        # Deduplicate before adding
        seen = set()
        for u in intercepted_urls:
            if u not in seen:
                seen.add(u)
                xhr_queue.append(u)

        # Also store full request objects for deep fuzz
        if hasattr(xhr_queue, '_requests'):
            xhr_queue._requests.extend(intercepted_reqs)

    return html, final_url


# -----------------------------------------------------------------
#  AUTO-UPGRADE TO PLAYWRIGHT
# -----------------------------------------------------------------

def fetch_auto(session, url: str, pw_browser=None,
               timeout: int = 10, rotate_ua: bool = False,
               proxies=None, xhr_queue: List = None,
               cookies: Dict = None) -> Tuple[Optional[object], str, bool]:
    """
    Smart fetch: tries requests/curl_cffi first.
    If the response looks like an empty SPA shell and Playwright
    is available, automatically retries with headless Chrome.

    Returns (resp_or_None, html, used_playwright).
    """
    resp, err = fetch_with_retry(
        session, url, timeout=timeout,
        rotate_ua=rotate_ua, proxies=proxies,
    )

    if resp is None:
        return None, "", False

    html           = resp.text
    used_playwright = False

    # Auto-upgrade to Playwright if SPA detected
    if is_spa_response(html) and pw_browser is not None and PLAYWRIGHT_AVAILABLE:
        vlog("AUTO", col(
            f"SPA detected on {url[:60]} — retrying with Playwright", C.CYAN
        ), C.CYAN)
        try:
            pw_html, _ = fetch_with_playwright(
                pw_browser, url,
                timeout=timeout + 5,
                xhr_queue=xhr_queue,
                cookies=cookies,
            )
            if pw_html and len(pw_html) > len(html):
                html            = pw_html
                used_playwright = True
                vlog("AUTO", col(
                    f"Playwright got {len(pw_html):,} chars vs {len(resp.text):,} from requests",
                    C.GREEN
                ), C.GREEN)
        except Exception as e:
            vlog("AUTO", f"Playwright upgrade failed: {e}", C.YELLOW)

    return resp, html, used_playwright


# -----------------------------------------------------------------
#  CHECKPOINT
# -----------------------------------------------------------------
_CHECKPOINT_LOCK = threading.Lock()

def save_checkpoint(path: str, visited: Set[str]) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for url in sorted(visited):
                f.write(url + "\n")
        os.replace(tmp, path)
    except Exception as e:
        log("CKPT", f"Checkpoint save failed: {e}", C.YELLOW)

def load_checkpoint(path: str) -> Set[str]:
    if not path or not os.path.isfile(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        urls = {line.strip() for line in f if line.strip()}
    log("CKPT", f"Resumed {len(urls)} previously visited URLs from {path}", C.GREEN)
    return urls
