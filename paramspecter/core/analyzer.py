"""
core/analyzer.py
Page analysis: JSAnalyzer, analyze_page(), RobotsTxtHandler.
"""

import re, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from ..utils import (
    fetch_with_retry, random_ua, normalize_url,
    SECRET_PATTERNS, PATTERNS, SOCIAL_DOMAINS,
    TECH_SIGNATURES, WAF_SIGNATURES, CAPTCHA_PATTERNS,
    SECURITY_HEADERS, INTERESTING_HEADER_LEAKS,
    content_hash, vlog, C,
)
from urllib.robotparser import RobotFileParser


# -----------------------------------------------------------------
#  ROBOTS.TXT
# -----------------------------------------------------------------
class RobotsTxtHandler:
    _SITEMAP_DEPTH_LIMIT = 3

    def __init__(self, base_url, ua, session):
        self.rp = RobotFileParser()
        self.ua = ua
        self.disallowed_paths: List[str] = []
        self.sitemaps: List[str] = []
        self.crawl_delay: Optional[float] = None

        robots_url = urljoin(base_url, "/robots.txt")
        self.rp.set_url(robots_url)
        try:
            resp, _ = fetch_with_retry(session, robots_url, timeout=8)
            if resp and resp.status_code == 200:
                # Parse already-fetched content — avoids a second network request
                # that rp.read() would otherwise make.
                self.rp.parse(resp.text.splitlines())
                for line in resp.text.splitlines():
                    ll = line.strip().lower()
                    if ll.startswith("disallow:"):
                        p = line.split(":", 1)[1].strip()
                        if p:
                            self.disallowed_paths.append(p)
                    elif ll.startswith("sitemap:"):
                        self.sitemaps.append(line.split(":", 1)[1].strip())
                    elif ll.startswith("crawl-delay:"):
                        try:
                            self.crawl_delay = float(line.split(":", 1)[1].strip())
                        except Exception:
                            pass
        except Exception:
            pass

    def allowed(self, url) -> bool:
        try:
            return self.rp.can_fetch(self.ua, url)
        except Exception:
            return True

    def extract_sitemap_urls(self, session, depth: int = 0) -> List[str]:
        if depth > self._SITEMAP_DEPTH_LIMIT:
            return []
        urls: List[str] = []
        for sm in list(self.sitemaps):  # iterate a copy so recursion is safe
            try:
                resp, _ = fetch_with_retry(session, sm, timeout=10)
                if not resp or resp.status_code != 200:
                    continue
                text = resp.text
                nested = re.findall(r"<sitemap>\s*<loc>(.*?)</loc>", text, re.I | re.S)
                if nested and depth < self._SITEMAP_DEPTH_LIMIT:
                    # Recurse with the nested sitemap index entries
                    saved = self.sitemaps
                    self.sitemaps = nested
                    try:
                        urls.extend(self.extract_sitemap_urls(session, depth + 1))
                    finally:
                        self.sitemaps = saved
                else:
                    found = re.findall(r"<loc>(.*?)</loc>", text, re.I)
                    urls.extend(found)
            except Exception:
                pass
        return urls


# -----------------------------------------------------------------
#  JS ANALYZER
# -----------------------------------------------------------------
class JSAnalyzer:
    EP_PATTERN = re.compile(
        r"""['"`](/(?:api|v\d+|admin|auth|user|account|graphql|rest|internal|hidden|debug|config|manage)[^\s'"`<>]*)['"`]""",
        re.I
    )
    INTERESTING_VARS = re.compile(
        r"""(?:const|let|var)\s+(\w+)\s*=\s*['"`]([^'"`\n]{6,})['"`]""", re.I
    )
    DYNAMIC_IMPORT_PATTERNS = [
        re.compile(r'import\s*\(\s*["\x27]([^"\x27]+\.js[^"\x27]*)["\x27]\s*\)', re.I),
        re.compile(r'require\.ensure\s*\(\s*\[([^\]]+)\]', re.I),
        re.compile(r'chunkFilename\s*:\s*["\x27]([^"\x27]+)["\x27]', re.I),
        re.compile(r'__webpack_require__\.p\s*\+\s*["\x27]([^"\x27]+\.js)["\x27]', re.I),
        re.compile(r'["\x27]([/.][\\w./-]+\.chunk\.js)["\x27]', re.I),
    ]

    def __init__(self, session, rotate_ua=False):
        self.session = session
        self.rotate_ua = rotate_ua

    def analyze(self, js_src_list: List[str], page_url: str,
                inline_scripts: List[str] = None):
        endpoints: Set[str] = set()
        secrets: List[Dict] = []
        sourcemaps: List[str] = []

        for inline_text in (inline_scripts or []):
            self._scan_js(inline_text, page_url, endpoints, secrets, sourcemaps)

        # Collect all JS URLs to fetch (including dynamic imports discovered later)
        fetched_js: Set[str] = set()
        js_queue: List[str] = list(js_src_list)
        # First pass: resolve all URLs before fetching
        to_fetch: List[tuple] = []  # (full_url, norm)
        while js_queue:
            js_url = js_queue.pop(0)
            full_url = urljoin(page_url, js_url)
            norm = full_url.split("?")[0].split("#")[0]
            if norm in fetched_js:
                continue
            fetched_js.add(norm)
            to_fetch.append((full_url, norm))

        # Fetch all JS files concurrently
        _lock = __import__("threading").Lock()

        def _fetch_and_scan(args):
            full_url, norm = args
            resp, err = fetch_with_retry(self.session, full_url, timeout=8,
                                         rotate_ua=self.rotate_ua)
            if not resp or resp.status_code != 200:
                return []
            text = resp.text
            local_ep: Set[str] = set()
            local_sec: List[Dict] = []
            local_sm: List[str] = []
            self._scan_js(text, full_url, local_ep, local_sec, local_sm)

            new_chunks = []
            for pat in self.DYNAMIC_IMPORT_PATTERNS:
                for m in pat.finditer(text):
                    chunk_path = m.group(1)
                    if chunk_path.startswith("data:") or (
                        chunk_path.startswith("http") and
                        urlparse(chunk_path).netloc != urlparse(page_url).netloc
                    ):
                        continue
                    chunk_norm = urljoin(full_url, chunk_path).split("?")[0]
                    with _lock:
                        if chunk_norm not in fetched_js:
                            fetched_js.add(chunk_norm)
                            new_chunks.append((urljoin(full_url, chunk_path), chunk_norm))
            return [(local_ep, local_sec, local_sm, new_chunks)]

        # Iterative concurrent fetch — handles dynamic chunks too
        pending = list(to_fetch)
        while pending:
            max_workers = min(10, max(1, len(pending)))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_fetch_and_scan, item): item for item in pending}
                next_round = []
                for fut in as_completed(futures):
                    results = fut.result()
                    for local_ep, local_sec, local_sm, new_chunks in results:
                        endpoints.update(local_ep)
                        secrets.extend(local_sec)
                        sourcemaps.extend(local_sm)
                        next_round.extend(new_chunks)
            pending = next_round

        return list(endpoints), secrets, sourcemaps

    def _scan_js(self, text: str, source_url: str,
                 endpoints: set, secrets: list, sourcemaps: list):
        for m in self.EP_PATTERN.finditer(text):
            ep = m.group(1).split("?")[0]
            if 1 < len(ep) < 200:
                endpoints.add(ep)

        for pat, label in SECRET_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                if len(val) > 6:
                    secrets.append({"type": label, "value": val[:80], "source": source_url})

        for m in self.INTERESTING_VARS.finditer(text):
            vname, vval = m.group(1), m.group(2)
            if any(kw in vname.lower() for kw in
                   ["url", "host", "endpoint", "base", "api", "key", "secret", "token"]):
                secrets.append({"type": f"JS var: {vname}", "value": vval[:80], "source": source_url})

        for m in PATTERNS["sourcemap"].finditer(text):
            sourcemaps.append(urljoin(source_url, m.group(1)))

        for m in PATTERNS["jwt"].finditer(text):
            secrets.append({"type": "JWT token", "value": m.group(0)[:80], "source": source_url})


# -----------------------------------------------------------------
#  SOURCE MAP EXPLOITER
# -----------------------------------------------------------------
class SourceMapExploiter:
    """
    Download .map files, reconstruct original pre-minified source,
    then scan it for secrets and API endpoints that were stripped
    from the production bundle.

    Source maps often contain:
    - Hardcoded API keys in original TypeScript/JSX before minification
    - Internal endpoint paths removed from bundle
    - Business logic comments with security notes
    - Developer TODO/FIXME mentioning security issues
    """

    def __init__(self, session, rotate_ua: bool = False):
        self.session    = session
        self.rotate_ua  = rotate_ua

    def exploit(self, sourcemap_urls: List[str], base_url: str) -> Dict:
        """
        Process a list of source map URLs.
        Returns {
            "secrets":   [...],   # secrets found in original source
            "endpoints": [...],   # endpoints found in original source
            "sources":   [...]    # original source file names
        }
        """
        from ..utils.http import fetch_with_retry

        all_secrets:   List[Dict] = []
        all_endpoints: List[str]  = []
        all_sources:   List[str]  = []
        seen_secrets:  set        = set()

        for sm_url in sourcemap_urls:
            try:
                resp, err = fetch_with_retry(
                    self.session, sm_url, timeout=10, rotate_ua=self.rotate_ua
                )
                if not resp or resp.status_code != 200:
                    continue

                data = json.loads(resp.text)
            except Exception:
                continue

            sources         = data.get("sources", [])
            sources_content = data.get("sourcesContent", [])

            for i, content in enumerate(sources_content):
                if not content:
                    continue

                source_name = sources[i] if i < len(sources) else f"source_{i}"
                all_sources.append(source_name)

                # Skip minified/vendor files
                if any(skip in source_name for skip in (
                    "node_modules", "webpack/runtime", "webpack/bootstrap",
                    "polyfill", "vendor", "chunk-vendors",
                )):
                    continue

                # Scan for secrets in original source
                for pat, label in SECRET_PATTERNS:
                    for m in pat.finditer(content):
                        val = m.group(1) if m.lastindex else m.group(0)
                        if len(val) < 6:
                            continue
                        key = (label, val[:20])
                        if key not in seen_secrets:
                            seen_secrets.add(key)
                            all_secrets.append({
                                "type":   f"[SourceMap] {label}",
                                "value":  val[:80],
                                "source": f"{sm_url}#{source_name}",
                            })

                # Extract API endpoints from original source
                ep_pattern = re.compile(
                    r'["\']('
                    r'(?:/api/|/v\d+/|/graphql|/rest/|/gql)'
                    r'[a-zA-Z0-9/_\-\.]{1,150}'
                    r')["\']'
                )
                for m in ep_pattern.finditer(content):
                    ep = m.group(1)
                    if ep not in all_endpoints:
                        all_endpoints.append(ep)

                # Look for security-relevant comments
                comment_pattern = re.compile(
                    r'(?:TODO|FIXME|HACK|XXX|NOTE|SECURITY|VULN|BUG|DANGER|WARN)[^\n]{0,200}',
                    re.I,
                )
                for m in comment_pattern.finditer(content):
                    comment = m.group(0).strip()
                    if any(kw in comment.lower() for kw in (
                        "auth", "password", "secret", "key", "token", "admin",
                        "bypass", "skip", "disable", "todo", "fixme", "hack",
                    )):
                        all_secrets.append({
                            "type":   "[SourceMap] Security Comment",
                            "value":  comment[:120],
                            "source": f"{sm_url}#{source_name}",
                        })

        return {
            "secrets":   all_secrets,
            "endpoints": list(set(all_endpoints)),
            "sources":   all_sources,
        }


# -----------------------------------------------------------------
#  PAGE ANALYZER
# -----------------------------------------------------------------
def analyze_page(url: str, resp, soup, raw_html: str, js_analyzer: JSAnalyzer) -> Dict:
    data: Dict[str, Any] = {
        "url": url,
        "status": resp.status_code,
        "content_type": resp.headers.get("Content-Type", ""),
        "content_length": len(resp.content),
        "content_hash": content_hash(raw_html),
        "redirect_chain": [r.url for r in resp.history] if resp.history else [],
        "title": "", "meta_desc": "", "meta_robots": "",
        "links": [], "external_links": [], "social_links": [],
        "emails": [], "phones": [], "ips": [], "internal_ips": [],
        "subdomains": [], "js_src": [], "js_urls": [],
        "js_endpoints": [], "js_secrets": [], "sourcemaps": [],
        "html_comments": [], "forms": [], "input_fields": [],
        "params": [], "technologies": [], "waf": [],
        "cookies": {}, "security_headers": {}, "leaked_headers": {},
        "captcha_detected": False, "interesting": [],
        "internal_paths": [],
        "openapi_specs": [],
    }

    if soup:
        t = soup.find("title")
        if t:
            data["title"] = t.get_text(strip=True)
        m = soup.find("meta", attrs={"name": re.compile("description", re.I)})
        if m:
            data["meta_desc"] = m.get("content", "")
        mr = soup.find("meta", attrs={"name": re.compile("robots", re.I)})
        if mr:
            data["meta_robots"] = mr.get("content", "")

    for h in SECURITY_HEADERS:
        v = resp.headers.get(h)
        if v:
            data["security_headers"][h] = v

    for h in INTERESTING_HEADER_LEAKS:
        v = resp.headers.get(h)
        if v:
            data["leaked_headers"][h] = v

    for ck in resp.cookies:
        flags = []
        if not ck.has_nonstandard_attr("HttpOnly"):
            flags.append("NO_HTTPONLY")
        if not ck.has_nonstandard_attr("Secure"):
            flags.append("NO_SECURE")
        if not ck.has_nonstandard_attr("SameSite"):
            flags.append("NO_SAMESITE")
        data["cookies"][ck.name] = {"value": ck.value[:40], "flags": flags}

    if soup:
        base_domain = urlparse(url).netloc
        seen_links: Set[str] = set()
        for tag in soup.find_all("a", href=True):
            raw_href = tag["href"].strip()
            if not raw_href or raw_href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            norm = normalize_url(raw_href, url)
            if not norm or norm in seen_links:
                continue
            seen_links.add(norm)
            nd = urlparse(norm).netloc
            if nd == base_domain or nd.endswith("." + base_domain):
                data["links"].append(norm)
            else:
                data["external_links"].append(norm)
                if any(sd in norm for sd in SOCIAL_DOMAINS):
                    data["social_links"].append(norm)

    data["emails"]        = list(set(PATTERNS["email"].findall(raw_html)))
    data["phones"]        = list(set(PATTERNS["phone"].findall(raw_html)))
    data["ips"]           = list(set(PATTERNS["ipv4"].findall(raw_html)))
    data["internal_ips"]  = list(set(PATTERNS["internal_ip"].findall(raw_html)))
    data["subdomains"]    = list(set(PATTERNS["subdomain"].findall(raw_html)))
    data["js_src"]        = list(set(PATTERNS["js_src"].findall(raw_html)))
    data["js_urls"]       = list(set(PATTERNS["js_url"].findall(raw_html)))
    data["html_comments"] = [c.strip() for c in PATTERNS["comment"].findall(raw_html) if c.strip()]
    data["openapi_specs"] = list(set(urljoin(url, m) for m in PATTERNS["openapi"].findall(raw_html)))

    combined = raw_html + str(resp.headers)
    for cp in CAPTCHA_PATTERNS:
        if cp.search(combined):
            data["captcha_detected"] = True
            break

    data["internal_paths"] = list(set(re.findall(
        r'(?:src|href|action|data-url|data-src)=["\']([^"\'<>]{2,})["\']', raw_html
    )))

    if soup:
        for form in soup.find_all("form"):
            inputs = [
                {
                    "tag": i.name,
                    "name": i.get("name", ""),
                    "type": i.get("type", "text"),
                    "value": i.get("value", "")[:50],
                    "placeholder": i.get("placeholder", ""),
                }
                for i in form.find_all(["input", "textarea", "select", "button"])
            ]
            data["forms"].append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "enctype": form.get("enctype", ""),
                "inputs": inputs,
                "input_count": len(inputs),
            })
            data["input_fields"].extend(inputs)

    param_set: Set[str] = set()
    for u in [url] + data["links"] + data["external_links"]:
        for k in parse_qs(urlparse(u).query, keep_blank_values=True):
            param_set.add(k)
    data["params"] = sorted(param_set)

    check_text = raw_html + str(resp.headers)
    for tech, sigs in TECH_SIGNATURES.items():
        if any(s.search(check_text) for s in sigs):
            data["technologies"].append(tech)

    waf_text = str(resp.headers) + raw_html[:3000]
    for waf_name, sig in WAF_SIGNATURES.items():
        if sig.search(waf_text):
            data["waf"].append(waf_name)

    inline_scripts: List[str] = []
    if soup:
        for tag in soup.find_all("script", src=False):
            txt = tag.get_text()
            if txt and len(txt.strip()) > 20:
                inline_scripts.append(txt)

    ep, sec, sm = js_analyzer.analyze(data["js_src"], url, inline_scripts)
    data["js_endpoints"] = sorted(ep)
    data["sourcemaps"]   = sm

    # Collect secrets from JS analysis + raw HTML scan, deduplicating by (type, value[:40])
    seen_secret_keys: Set[tuple] = set()
    deduped_secrets: List[Dict] = []

    def _add_secret(s: Dict):
        key = (s.get("type", ""), s.get("value", "")[:40])
        if key not in seen_secret_keys:
            seen_secret_keys.add(key)
            deduped_secrets.append(s)

    for s in sec:
        _add_secret(s)

    for pat, label in SECRET_PATTERNS:
        for m in pat.finditer(raw_html):
            val = m.group(1) if m.lastindex else m.group(0)
            if len(val) > 6:
                _add_secret({"type": label, "value": val[:80], "source": url})

    data["js_secrets"] = deduped_secrets

    if data["internal_ips"]:
        data["interesting"].append(f"Internal IPs: {data['internal_ips']}")
    if data["js_secrets"]:
        data["interesting"].append(f"{len(data['js_secrets'])} possible secret(s) found")
    if data["sourcemaps"]:
        data["interesting"].append(f"Source maps: {data['sourcemaps']}")
    if data["html_comments"]:
        data["interesting"].append(f"{len(data['html_comments'])} HTML comment(s)")
    if data["captcha_detected"]:
        data["interesting"].append("CAPTCHA detected")
    if data["openapi_specs"]:
        data["interesting"].append(f"OpenAPI spec(s) found: {data['openapi_specs']}")
    for cookie_name, cookie_info in data["cookies"].items():
        if cookie_info["flags"]:
            data["interesting"].append(f"Cookie '{cookie_name}' missing flags: {cookie_info['flags']}")
    if "X-Powered-By" in data["leaked_headers"]:
        data["interesting"].append(f"Tech leak: X-Powered-By: {data['leaked_headers']['X-Powered-By']}")

    return data
