"""
core/crawler.py
ParamSpecter — orchestrates all phases: crawl, subdomain, fuzz, param.
"""

import json, os, queue, re, signal, sys, tempfile, threading, time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from ..utils import (
    VERBOSITY, C, col, status_color, log, log_section, vlog, ts,
    validate_output_dir, validate_file_arg,
    normalize_url, is_same_domain, content_hash, random_ua,
    load_wordlist, load_scope_file, url_in_scope,
    fetch_with_retry, fetch_with_playwright, PLAYWRIGHT_AVAILABLE,
    save_checkpoint, load_checkpoint,
    CRAWLABLE_MIME, SKIP_EXTENSIONS, SECURITY_HEADERS,
    BUILTIN_DIRS, BUILTIN_PARAMS, BUILTIN_SUBDOMAINS,
)
from ..utils.helpers import _log_lock
from .analyzer import JSAnalyzer, analyze_page, RobotsTxtHandler
from .stats import CrawlStats, CrawlQueue, TokenBucket, ProxyManager, _HOST_BUCKET_LIMIT
from ..modules.login import FormLoginHandler
from ..modules.dirhunt import DirectoryHunter
from ..modules.subdomain import SubdomainHunter
from ..modules.paramfuzz import ParamFuzzer, load_payload_file
from ..output.reporter import save_results, export_targets


class ParamSpecter:
    def __init__(self, args):
        self.args           = args
        self.start_url      = args.url.rstrip("/")
        self.max_pages      = args.max_pages
        self.delay          = args.delay
        self.depth          = args.depth
        self.threads        = args.threads
        self.timeout        = args.timeout
        self.same_domain    = not args.follow_external
        self.respect_robots = not args.ignore_robots
        self.rotate_ua      = args.rotate_ua
        self.strategy       = getattr(args, "strategy", "bfs")
        self.ua             = args.user_agent or random_ua()
        self.output         = args.output
        self.mode           = args.mode
        self.base_domain    = urlparse(self.start_url).netloc
        self.max_retries    = getattr(args, "max_retries", 3)
        self.smart_fuzz     = getattr(args, "smart_fuzz", False)

        self.output_dir = validate_output_dir(getattr(args, "output_dir", None) or ".")
        self.scope_entries: List[str] = load_scope_file(getattr(args, "scope_file", None))
        self.custom_payloads: Dict[str, List[str]] = load_payload_file(getattr(args, "payload_file", None))

        cli_rate = getattr(args, "rate_limit", None)
        self._host_rate = float(cli_rate) if cli_rate else max(1.0, self.threads * 0.8)

        # ---- Session ----
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

        if getattr(args, "cookies", None):
            for pair in args.cookies.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

        if getattr(args, "headers", None):
            for pair in args.headers:
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    self.session.headers[k.strip()] = v.strip()

        if getattr(args, "login_url", None):
            FormLoginHandler(
                session    = self.session,
                login_url  = args.login_url,
                username   = args.login_user,
                password   = args.login_pass,
                user_field = getattr(args, "login_user_field", "username"),
                pass_field = getattr(args, "login_pass_field", "password"),
                timeout    = self.timeout,
            ).login()

        proxy_list = []
        if getattr(args, "proxies", None):
            proxy_list = [p.strip() for p in args.proxies.split(",") if p.strip()]
        self.proxy_mgr = ProxyManager(proxy_list) if proxy_list else None

        # ---- Checkpoint ----
        self._checkpoint_file = getattr(args, "resume_file", None) or \
            os.path.join(self.output_dir,
                         f"paramspecter_{self.base_domain.replace('.','_')}_checkpoint.txt")
        _resume = getattr(args, "resume", False)

        # ---- Crawl state ----
        self.crawl_queue = CrawlQueue(strategy=self.strategy)
        self.crawl_queue.put((self.start_url, 0))
        self.visited: Set[str]        = load_checkpoint(self._checkpoint_file) if _resume else set()
        self.visited_hashes: Set[str] = set()
        self.visited_lock             = threading.Lock()
        self.results: List[Dict]      = []
        self.results_lock             = threading.Lock()

        # ---- Aggregated findings ----
        self.all_emails:     Set[str]   = set()
        self.all_phones:     Set[str]   = set()
        self.all_links:      Set[str]   = set()
        self.all_subdomains: Set[str]   = set()
        self.all_techs:      Set[str]   = set()
        self.all_wafs:       Set[str]   = set()
        self.all_params:     Set[str]   = set()
        self.all_secrets:    List[Dict] = []
        self.all_openapi:    Set[str]   = set()
        self.all_forms:      int        = 0
        self.all_interesting: List[str] = []
        self.missing_sec_headers: Dict[str, int] = defaultdict(int)

        self.fuzz_hits:      List[Dict] = []
        self.param_hits:     List[Dict] = []
        self.subdomain_hits: List[Dict] = []
        self.dir_hits:       List[Dict] = []

        self.stats       = CrawlStats()
        self._stop_event = threading.Event()

        # ---- robots.txt ----
        self.robots = None
        if self.respect_robots:
            log("ROBOTS", "Fetching robots.txt ...", C.CYAN)
            self.robots = RobotsTxtHandler(self.start_url, self.ua, self.session)
            if self.robots.disallowed_paths:
                log("ROBOTS", f"Disallowed: {len(self.robots.disallowed_paths)} paths", C.YELLOW)
            if self.robots.sitemaps:
                log("ROBOTS", f"Sitemaps: {', '.join(self.robots.sitemaps[:3])}", C.CYAN)
                for su in self.robots.extract_sitemap_urls(self.session)[:50]:
                    norm = normalize_url(su)
                    if norm:
                        self.crawl_queue.put((norm, 1), priority=1)
            if self.robots.crawl_delay and self.delay < self.robots.crawl_delay:
                self.delay = self.robots.crawl_delay
                log("ROBOTS", f"Honoring crawl-delay: {self.delay}s", C.YELLOW)

        # ---- Rate limiter ----
        self._host_buckets: Dict[str, TokenBucket] = {}
        self._host_buckets_lock = threading.Lock()

        self.js_analyzer = JSAnalyzer(self.session, rotate_ua=self.rotate_ua)

        # ---- Playwright ----
        self.use_playwright = getattr(args, "playwright", False)
        self._pw_instance   = None
        self.pw_browser     = None
        if self.use_playwright:
            if not PLAYWRIGHT_AVAILABLE:
                log("PW", col("playwright not installed -- falling back to requests", C.YELLOW), C.YELLOW)
                self.use_playwright = False
            else:
                try:
                    from playwright.sync_api import sync_playwright
                    self._pw_instance = sync_playwright().__enter__()
                    self.pw_browser   = self._pw_instance.chromium.launch(headless=True)
                    log("PW", col("Playwright headless Chromium ready", C.GREEN), C.GREEN)
                except Exception as e:
                    log("PW", col(f"Failed to launch Playwright: {e} -- falling back", C.YELLOW), C.YELLOW)
                    self.use_playwright = False

        # ---- JSONL streaming handle ----
        self._jsonl_fh = None

        signal.signal(signal.SIGINT, self._handle_sigint)
        self.start_time = datetime.now()

    # ------------------------------------------------------------------
    #  INTERNALS
    # ------------------------------------------------------------------
    def _host_bucket(self, url: str) -> TokenBucket:
        host = urlparse(url).netloc
        with self._host_buckets_lock:
            if host not in self._host_buckets:
                if len(self._host_buckets) >= _HOST_BUCKET_LIMIT:
                    evict_key = next(iter(self._host_buckets))
                    del self._host_buckets[evict_key]
                self._host_buckets[host] = TokenBucket(
                    rate=self._host_rate, capacity=self._host_rate * 2
                )
            return self._host_buckets[host]

    def _handle_sigint(self, sig, frame):
        if self._stop_event.is_set():
            log("STOP", col("Force exit.", C.RED), C.RED)
            sys.exit(1)
        with _log_lock:
            print(f"\n{col('─'*65, C.YELLOW)}")
            print(f"  {col('>> SCAN INTERRUPTED -- saving partial results...', C.BOLD+C.YELLOW)}")
            print(col('─'*65, C.YELLOW))
        self._stop_event.set()

    # ------------------------------------------------------------------
    #  CRAWL WORKER
    # ------------------------------------------------------------------
    def _crawl_worker(self):
        from ..utils.http import _pw_local

        while not self._stop_event.is_set():
            try:
                url, depth = self.crawl_queue.get(timeout=3)
            except queue.Empty:
                break

            with self.visited_lock:
                if url in self.visited:
                    self.crawl_queue.task_done()
                    continue
                self.visited.add(url)
                if len(self.visited) % 50 == 0:
                    threading.Thread(
                        target=save_checkpoint,
                        args=(self._checkpoint_file, set(self.visited)),
                        daemon=True
                    ).start()

            with self.results_lock:
                if self.stats.pages_crawled >= self.max_pages:
                    self.crawl_queue.task_done()
                    break

            if self.robots and not self.robots.allowed(url):
                vlog("SKIP", col(url, C.GRAY), C.GRAY)
                self.crawl_queue.task_done()
                continue

            proxies = self.proxy_mgr.next() if self.proxy_mgr else None
            self._host_bucket(url).acquire()

            xhr_endpoints: List[str] = []
            resp = None
            err  = None

            if self.use_playwright and self.pw_browser is not None:
                try:
                    pw_html, final_url = fetch_with_playwright(
                        self.pw_browser, url, timeout=self.timeout,
                        xhr_queue=xhr_endpoints,
                    )
                    resp, err = fetch_with_retry(
                        self.session, url, timeout=self.timeout,
                        rotate_ua=self.rotate_ua, proxies=proxies,
                        max_retries=1, allow_redirects=True,
                    )
                    if resp is not None and pw_html:
                        resp._content = pw_html.encode("utf-8", errors="replace")
                        resp.encoding  = "utf-8"
                except Exception as e:
                    log("PW", col(f"Playwright failed for {url}: {e} -- falling back", C.YELLOW), C.YELLOW)
                    resp, err = fetch_with_retry(
                        self.session, url, timeout=self.timeout,
                        rotate_ua=self.rotate_ua, proxies=proxies,
                        max_retries=self.max_retries, allow_redirects=True,
                    )
            else:
                resp, err = fetch_with_retry(
                    self.session, url, timeout=self.timeout,
                    rotate_ua=self.rotate_ua, proxies=proxies,
                    max_retries=self.max_retries, allow_redirects=True,
                )

            with self.results_lock:
                self.stats.requests_sent += 1

            if resp is None:
                with self.results_lock:
                    self.results.append({"url": url, "status": None, "error": err})
                    self.stats.pages_failed += 1
                    count = self.stats.pages_crawled
                log(f"[{count:>4}]", f"{col('FAIL', C.RED)}  {col(url, C.GRAY)}  ({err})", C.RED)
                self.crawl_queue.task_done()
                time.sleep(self.delay)
                continue

            self.stats.status_codes[resp.status_code] += 1

            ct   = resp.headers.get("Content-Type", "")
            mime = ct.split(";")[0].strip().lower()
            raw  = ""
            soup = None
            if mime in CRAWLABLE_MIME or "html" in mime:
                try:
                    raw  = resp.text
                    soup = BeautifulSoup(raw, "html.parser")
                except Exception:
                    pass

            chash = content_hash(raw)
            with self.visited_lock:
                if chash in self.visited_hashes and len(raw) > 200:
                    vlog("DUPE", col(url, C.GRAY), C.GRAY)
                    self.crawl_queue.task_done()
                    time.sleep(self.delay)
                    continue
                self.visited_hashes.add(chash)

            pd = analyze_page(url, resp, soup, raw, self.js_analyzer)

            with self.results_lock:
                self.stats.pages_crawled += 1
                count = self.stats.pages_crawled

            redir_info = f"  -> {resp.url}" if resp.history else ""
            q_depth    = self.crawl_queue.qsize()
            if VERBOSITY.level >= 1:
                with _log_lock:
                    print(
                        f"  {ts()}  {col(f'[{count:>4}]', C.CYAN)}  {status_color(resp.status_code)}  "
                        f"{col(url[:72], C.WHITE)}{col(redir_info, C.YELLOW)}"
                        f"  {col(f'[q:{q_depth}]', C.GRAY)}"
                    )
                    if pd.get("interesting"):
                        for item in pd["interesting"][:3]:
                            print(f"  {ts()}  {col('  [*] FIND', C.RED+C.BOLD)}  {col(item, C.YELLOW)}")
                    if pd["emails"]:
                        print(f"  {ts()}  {col('     +', C.GREEN)}  Emails: {col(', '.join(pd['emails']), C.GREEN)}")
                    if pd["waf"]:
                        print(f"  {ts()}  {col('     W', C.YELLOW)}  WAF: {col(', '.join(pd['waf']), C.YELLOW)}")
                    if pd["forms"]:
                        print(f"  {ts()}  {col('     F', C.GRAY)}  Forms:{len(pd['forms'])} Inputs:{len(pd['input_fields'])}")
                    if pd["params"]:
                        print(f"  {ts()}  {col('     P', C.YELLOW)}  Params: {col(str(pd['params'][:5]), C.YELLOW)}")
                    if pd["js_endpoints"]:
                        print(f"  {ts()}  {col('     J', C.CYAN)}  JS endpoints: {len(pd['js_endpoints'])}")
                    if pd["js_secrets"]:
                        print(f"  {ts()}  {col('     !', C.RED+C.BOLD)}  Secrets: {len(pd['js_secrets'])} possible secret(s)")
                    if pd["captcha_detected"]:
                        print(f"  {ts()}  {col('    [C]', C.MAGENTA)}  CAPTCHA detected")
                    if pd.get("openapi_specs"):
                        print(f"  {ts()}  {col('    [A]', C.BLUE)}  OpenAPI specs: {pd['openapi_specs']}")

            # JSONL streaming write
            if self._jsonl_fh is not None:
                try:
                    self._jsonl_fh.write(json.dumps(pd, ensure_ascii=False) + "\n")
                    self._jsonl_fh.flush()
                except Exception:
                    pass

            with self.results_lock:
                self.results.append(pd)
                self.all_emails.update(pd["emails"])
                self.all_phones.update(pd["phones"])
                self.all_links.update(pd["links"])
                self.all_subdomains.update(pd["subdomains"])
                self.all_techs.update(pd["technologies"])
                self.all_wafs.update(pd["waf"])
                self.all_params.update(pd["params"])
                self.all_openapi.update(pd.get("openapi_specs", []))

                _seen_secret_keys = {
                    (s.get("type", ""), s.get("value", "")[:40])
                    for s in self.all_secrets
                }
                for s in pd["js_secrets"]:
                    key = (s.get("type", ""), s.get("value", "")[:40])
                    if key not in _seen_secret_keys:
                        _seen_secret_keys.add(key)
                        self.all_secrets.append(s)

                self.all_forms      += len(pd["forms"])
                self.all_interesting.extend(pd["interesting"])
                self.stats.emails_found  = len(self.all_emails)
                self.stats.secrets_found = len(self.all_secrets)
                self.stats.forms_found   = self.all_forms
                self.stats.params_found  = len(self.all_params)

                for sh in SECURITY_HEADERS:
                    if sh not in pd["security_headers"]:
                        self.missing_sec_headers[sh] += 1

            # Queue new links
            if depth < self.depth and not self._stop_event.is_set() \
                    and ("html" in mime or mime in CRAWLABLE_MIME):
                for link in pd["links"]:
                    if self._stop_event.is_set():
                        break
                    with self.visited_lock:
                        if link not in self.visited:
                            in_scope = (
                                url_in_scope(link, self.scope_entries, self.base_domain)
                                if (self.scope_entries or not self.same_domain)
                                else is_same_domain(link, self.base_domain)
                            )
                            if in_scope:
                                self.crawl_queue.put((link, depth + 1), priority=depth + 1)
                                self.stats.links_found += 1

            # XHR endpoints from Playwright
            if xhr_endpoints and not self._stop_event.is_set():
                new_api = 0
                for ep_url in xhr_endpoints:
                    norm_ep = normalize_url(ep_url, url)
                    if not norm_ep:
                        continue
                    in_scope = (
                        url_in_scope(norm_ep, self.scope_entries, self.base_domain)
                        if (self.scope_entries or not self.same_domain)
                        else is_same_domain(norm_ep, self.base_domain)
                    )
                    if in_scope:
                        with self.visited_lock:
                            if norm_ep not in self.visited:
                                self.crawl_queue.put((norm_ep, depth + 1), priority=depth + 1)
                                self.stats.links_found += 1
                                new_api += 1
                if new_api:
                    vlog("PW", col(f"Queued {new_api} XHR/fetch endpoint(s) from {url[:60]}", C.CYAN), C.CYAN)

            time.sleep(self.delay)
            self.crawl_queue.task_done()

    # ------------------------------------------------------------------
    #  PHASE RUNNERS
    # ------------------------------------------------------------------
    def run_crawl(self):
        _barrier = threading.Barrier(self.threads + 1, timeout=3600)

        def _wrapper():
            try:
                self._crawl_worker()
            finally:
                try:
                    _barrier.wait()
                except threading.BrokenBarrierError:
                    pass

        workers = [threading.Thread(target=_wrapper, daemon=True) for _ in range(self.threads)]
        for w in workers:
            w.start()
        try:
            _barrier.wait()
        except threading.BrokenBarrierError:
            pass

        if self._stop_event.is_set():
            drained = 0
            while True:
                try:
                    self.crawl_queue._q.get_nowait()
                    self.crawl_queue._q.task_done()
                    drained += 1
                except queue.Empty:
                    break
            if drained:
                log("STOP", f"Drained {drained} pending URLs from queue", C.YELLOW)

        for w in workers:
            w.join(timeout=3)

    def run_dir_hunt(self, base_url=None):
        a    = self.args
        wl   = load_wordlist(getattr(a, "wordlist", None), BUILTIN_DIRS)
        exts = [e.strip() for e in a.extensions.split(",")] if a.extensions else [""]
        mc   = set(int(c) for c in a.match_codes.split(",")) if a.match_codes else None
        hc   = set(int(c) for c in a.hide_codes.split(","))  if a.hide_codes  else {404}

        DirectoryHunter(
            base_url or self.start_url, wl, exts,
            a.threads, a.timeout, self.session, a.delay,
            mc, hc, self.dir_hits, self._stop_event,
            rotate_ua=self.rotate_ua, proxy_mgr=self.proxy_mgr,
            recursive=getattr(a, "recursive", False),
            max_depth=getattr(a, "recursive_depth", 2),
        ).run()

    def run_param_fuzz(self, target_url=None):
        a  = self.args
        pl = load_wordlist(getattr(a, "param_wordlist", None), BUILTIN_PARAMS)
        ParamFuzzer(
            target_url or self.start_url, pl,
            a.threads, a.timeout, self.session, a.delay,
            self.param_hits, self._stop_event,
            getattr(a, "param_method", "GET"),
            rotate_ua=self.rotate_ua, proxy_mgr=self.proxy_mgr,
            smart_fuzz=self.smart_fuzz,
            deep_fuzz=getattr(a, "deep_fuzz", False),
            custom_payloads=self.custom_payloads,
        ).run()

    def run_subdomain_hunt(self):
        a  = self.args
        wl = load_wordlist(getattr(a, "sub_wordlist", None), BUILTIN_SUBDOMAINS)
        parts = self.base_domain.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else self.base_domain
        SubdomainHunter(
            root_domain, wl, a.threads, a.timeout,
            self.session, self.subdomain_hits, self._stop_event,
        ).run()

    # ------------------------------------------------------------------
    #  MAIN ENTRY
    # ------------------------------------------------------------------
    def run(self):
        mode = self.mode

        # Open JSONL stream
        ts_str  = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_pfx = f"paramspecter_{self.base_domain.replace('.', '_')}_{ts_str}"
        pfx = os.path.join(self.output_dir, base_pfx)

        if self.output == "jsonl":
            jsonl_path = f"{pfx}.jsonl"
            try:
                self._jsonl_fh = open(jsonl_path, "w", encoding="utf-8")
            except OSError as e:
                log("SAVE", col(f"Cannot open JSONL stream: {e}", C.RED), C.RED)

        if mode in ("crawl", "full"):
            log_section("PHASE 1 -- CRAWLING")
            t0 = time.monotonic()
            self.run_crawl()
            self.stats.record_phase("crawl", time.monotonic() - t0)

        if not self._stop_event.is_set() and mode in ("subdomain", "full"):
            log_section("PHASE 2 -- SUBDOMAIN ENUMERATION")
            t0 = time.monotonic()
            self.run_subdomain_hunt()
            self.stats.subdomains_found = len(self.subdomain_hits)
            self.stats.record_phase("subdomain", time.monotonic() - t0)

        if not self._stop_event.is_set() and mode in ("fuzz", "full"):
            log_section("PHASE 3 -- DIRECTORY HUNTING")
            t0 = time.monotonic()
            targets = {self.start_url}
            if mode == "full" and self.results:
                for r in self.results:
                    p = urlparse(r.get("url", "")).path.rsplit("/", 1)[0]
                    targets.add(self.start_url.rstrip("/") + (p or ""))
            for t in list(targets)[:5]:
                if self._stop_event.is_set():
                    break
                self.run_dir_hunt(base_url=t)
            self.stats.dir_hits = len(self.dir_hits)
            self.stats.record_phase("fuzz", time.monotonic() - t0)

        if not self._stop_event.is_set() and mode in ("param", "full"):
            log_section("PHASE 4 -- PARAMETER FUZZING")
            t0 = time.monotonic()
            targets = [self.start_url]
            if mode == "full":
                param_urls = [r["url"] for r in self.results
                              if r.get("params") and r.get("status") and r["status"] < 400]
                if param_urls:
                    targets = param_urls[:10]
            for t in targets:
                if self._stop_event.is_set():
                    break
                self.run_param_fuzz(target_url=t)
            self.stats.record_phase("param", time.monotonic() - t0)

        # Close JSONL
        if self._jsonl_fh is not None:
            try:
                self._jsonl_fh.close()
            except Exception:
                pass
            self._jsonl_fh = None

        self.print_summary()
        pfx = save_results(self)

        if getattr(self.args, "export_targets", False):
            t_path, sql_path = export_targets(self, pfx)
            self._print_tool_hints(t_path, sql_path)

        # Cleanup Playwright
        if self.pw_browser is not None:
            try:
                from ..utils.http import _pw_local
                if hasattr(_pw_local, "context") and _pw_local.context is not None:
                    _pw_local.context.close()
                    _pw_local.context = None
                self.pw_browser.close()
            except Exception:
                pass
        if self._pw_instance is not None:
            try:
                self._pw_instance.__exit__(None, None, None)
            except Exception:
                pass

    def _print_tool_hints(self, t_path: str, sql_path: str) -> None:
        sep = col("─" * 65, C.YELLOW)
        print(f"\n{sep}")
        print(f"  {col('NEXT STEPS  (--export-targets)', C.BOLD+C.YELLOW)}")
        print(sep)
        if t_path:
            print(f"  {col('Run nuclei:', C.CYAN)}")
            print(f"    {col(f'nuclei -l {t_path} -t ~/nuclei-templates/', C.WHITE)}")
        if sql_path:
            print(f"  {col('Run sqlmap:', C.CYAN)}")
            print(f"    {col(f'sqlmap -m {sql_path} --batch --dbs', C.WHITE)}")
        print(sep + "\n")

    # ------------------------------------------------------------------
    #  SUMMARY
    # ------------------------------------------------------------------
    def print_summary(self):
        dur         = self.stats.elapsed()
        interrupted = "  (INTERRUPTED)" if self._stop_event.is_set() else ""
        print(f"\n{col('='*65, C.RED)}")
        print(col(f"  SCAN COMPLETE{interrupted}", C.BOLD+C.WHITE))
        print(col("="*65, C.RED))

        rows = [
            ("Target",             self.start_url),
            ("Mode",               self.mode),
            ("Strategy",           self.strategy),
            ("Pages crawled",      self.stats.pages_crawled),
            ("Pages failed",       self.stats.pages_failed),
            ("Total requests",     self.stats.requests_sent),
            ("Avg req/s",          self.stats.avg_rps()),
            ("Links found",        len(self.all_links)),
            ("Emails",             len(self.all_emails)),
            ("Subdomains (crawl)", len(self.all_subdomains)),
            ("Subdomains (hunt)",  len(self.subdomain_hits)),
            ("URL Params",         len(self.all_params)),
            ("Forms found",        self.all_forms),
            ("Secrets found",      len(self.all_secrets)),
            ("OpenAPI specs",      len(self.all_openapi)),
            ("Dir hits",           len(self.dir_hits)),
            ("Param hits",         len(self.param_hits)),
            ("Technologies",       ", ".join(self.all_techs) or "None"),
            ("WAF",                ", ".join(self.all_wafs)  or "None"),
            ("Duration",           dur),
        ]
        for label, val in rows:
            sev_col = C.RED if label in ("Secrets found", "Pages failed") and val else C.CYAN
            print(f"  {col(label + ':', sev_col):<32} {val}")

        if self.stats.phase_times:
            print(f"\n  {col('Phase Timing:', C.CYAN)}")
            for phase, secs in self.stats.phase_times.items():
                print(f"    {col(phase, C.WHITE):<16} {secs}s")

        if self.stats.status_codes:
            print(f"\n  {col('HTTP Status Breakdown:', C.CYAN)}")
            for code in sorted(self.stats.status_codes):
                bar = "#" * min(self.stats.status_codes[code], 35)
                print(f"    {status_color(code)}  {bar}  ({self.stats.status_codes[code]})")

        if self.all_emails:
            print(f"\n  {col('Emails:', C.CYAN)}")
            for e in sorted(self.all_emails):
                print(f"    {col(e, C.GREEN)}")

        if self.all_params:
            print(f"\n  {col('URL Parameters Discovered:', C.CYAN)}")
            for p in sorted(self.all_params):
                print(f"    {col('?'+p, C.YELLOW)}")

        if self.all_openapi:
            print(f"\n  {col('OpenAPI / Swagger Specs:', C.CYAN)}")
            for spec in sorted(self.all_openapi):
                print(f"    {col(spec, C.BLUE)}")

        if self.all_secrets:
            print(f"\n  {col('[!] Possible Secrets Found:', C.RED+C.BOLD)}")
            seen_vals: Set[str] = set()
            for s in self.all_secrets:
                key = s.get("value", "")[:30]
                if key in seen_vals:
                    continue
                seen_vals.add(key)
                print(f"    {col('['+s.get('type','?')+']', C.YELLOW)}  {col(s.get('value','')[:60], C.RED)}")
                print(f"    {col('Source: '+s.get('source',''), C.GRAY)}")

        if self.subdomain_hits:
            print(f"\n  {col('Subdomains Found:', C.CYAN)}")
            for h in sorted(self.subdomain_hits, key=lambda x: x["subdomain"]):
                ip_str = ", ".join(h.get("ips", [])) or "no-ip"
                st_str = status_color(h.get("status")) if h.get("status") else col("no-http", C.GRAY)
                print(f"    {col(h['subdomain'], C.CYAN):<50} {ip_str:<20} {st_str}  [{h.get('method','')}]")

        if self.dir_hits:
            print(f"\n  {col('Directory / File Hits:', C.CYAN)}")
            for h in self.dir_hits:
                print(f"    {status_color(h['status'])}  {h['url']}  [{h['size']}B]")

        if self.param_hits:
            print(f"\n  {col('Interesting Parameters:', C.CYAN)}")
            for h in self.param_hits:
                refl = col(" [REFLECTED]", C.RED+C.BOLD) if h.get("reflected") else ""
                cwe  = col(f"  [{h.get('cwe','')}]", C.GRAY) if h.get("cwe") else ""
                print(f"    {status_color(h['status'])}  ?{col(h['param'], C.YELLOW)}"
                      f"  delta:{h['size_diff']}B{refl}{cwe}")

        if self.all_interesting:
            print(f"\n  {col('[*] Interesting Findings:', C.MAGENTA)}")
            seen: Set[str] = set()
            for item in self.all_interesting:
                if item not in seen:
                    seen.add(item)
                    print(f"    {col('-', C.YELLOW)} {item}")

        if self.missing_sec_headers:
            print(f"\n  {col('Missing Security Headers:', C.YELLOW)}")
            for h, c in sorted(self.missing_sec_headers.items(), key=lambda x: -x[1]):
                print(f"    {col(h, C.RED)}: {c} page(s)")

        print(f"{col('='*65, C.RED)}\n")
