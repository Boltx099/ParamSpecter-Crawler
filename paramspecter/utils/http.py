"""
utils/http.py
HTTP helpers: fetch_with_retry (exponential backoff),
fetch_with_playwright (headless JS rendering + XHR interception),
resume/checkpoint helpers.
"""

import os, re, time, random, threading
from typing import Optional, List, Set
from urllib.parse import urlparse

import requests

from .constants import _RETRYABLE_STATUS
from .helpers import vlog, random_ua, log, C

try:
    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# -----------------------------------------------------------------
#  RETRY / HTTP
# -----------------------------------------------------------------
def fetch_with_retry(session, url, method="GET", data=None, max_retries=3,
                     timeout=10, rotate_ua=False, proxies=None, **kwargs):
    headers = {}
    if rotate_ua:
        headers["User-Agent"] = random_ua()
    delay = 1.0
    for attempt in range(max_retries + 1):
        try:
            resp = session.request(
                method, url, data=data, headers=headers,
                timeout=timeout, proxies=proxies, **kwargs
            )
            if resp.status_code in _RETRYABLE_STATUS and attempt < max_retries:
                retry_after = float(resp.headers.get("Retry-After", delay * 2))
                retry_after = min(retry_after, 60)
                vlog("RETRY", f"HTTP {resp.status_code} on {url[:60]}, waiting {retry_after:.1f}s", C.YELLOW)
                time.sleep(retry_after)
                delay = min(delay * 2, 30)
                continue
            return resp, None
        except requests.exceptions.ConnectionError as e:
            err = f"ConnectionError: {e}"
        except requests.exceptions.Timeout:
            err = "Timeout"
        except requests.exceptions.TooManyRedirects:
            return None, "TooManyRedirects"
        except Exception as e:
            err = str(e)
        if attempt < max_retries:
            jitter = random.uniform(0, 0.3) * delay
            vlog("RETRY", f"Attempt {attempt+1}/{max_retries} failed for {url[:60]}: {err}", C.YELLOW)
            time.sleep(delay + jitter)
            delay = min(delay * 2, 30)
    return None, err


# -----------------------------------------------------------------
#  PLAYWRIGHT
# -----------------------------------------------------------------
_pw_local = threading.local()

def _get_thread_context(pw_browser):
    if not hasattr(_pw_local, "context") or _pw_local.context is None:
        _pw_local.context = pw_browser.new_context(
            user_agent=random_ua(),
            ignore_https_errors=True,
        )
    return _pw_local.context

def fetch_with_playwright(pw_browser, url, timeout=10, xhr_queue=None):
    ctx = _get_thread_context(pw_browser)
    page = ctx.new_page()
    intercepted: List[str] = []

    def _on_request(request):
        if request.resource_type in ("xhr", "fetch"):
            req_url = request.url
            parsed = urlparse(req_url)
            if parsed.path and len(parsed.path) > 1:
                intercepted.append(req_url)

    page.on("request", _on_request)
    try:
        page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
        html = page.content()
        final_url = page.url
    finally:
        page.close()

    if xhr_queue is not None:
        xhr_queue.extend(intercepted)
    return html, final_url


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
