"""
modules/dirhunt.py
Directory and file enumeration with wildcard/soft-404 detection,
response-size deduplication, and optional recursion.
"""

import os, queue, random, statistics, threading, time
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from ..utils import fetch_with_retry, log, vlog, col, status_color, C, random_ua


class DirectoryHunter:
    def __init__(self, base_url: str, wordlist: List[str], extensions: List[str],
                 threads: int, timeout: int, session, delay: float,
                 match_codes: Optional[Set[int]], hide_codes: Set[int],
                 hits_out: List[Dict], stop_event: threading.Event = None,
                 rotate_ua: bool = False, proxy_mgr=None, max_retries: int = 2,
                 recursive: bool = False, max_depth: int = 2):
        self.base_url    = base_url.rstrip("/")
        self.wordlist    = wordlist
        self.extensions  = extensions
        self.threads     = threads
        self.timeout     = timeout
        self.session     = session
        self.delay       = delay
        self.match_codes = match_codes
        self.hide_codes  = hide_codes
        self.hits_out    = hits_out
        self.stop_event  = stop_event or threading.Event()
        self.rotate_ua   = rotate_ua
        self.proxy_mgr   = proxy_mgr
        self.max_retries = max_retries
        self.recursive   = recursive
        self.max_depth   = max_depth

        self._lock            = threading.Lock()
        self._hits: List[Dict] = []
        self._seen_urls: Set[str] = set()
        self._baseline_len: int = 0
        self._baseline_stdev: int = 0
        self._wildcard: bool = False

    def _detect_wildcard(self):
        prefixes = ["ps_wc1", "ps_wc2", "ps_wc3", "ps_wc4", "ps_wc5"]
        sizes = []
        for pfx in prefixes:
            probe = f"{self.base_url}/{pfx}_{random.randint(10000,99999)}_notexist"
            resp, _ = fetch_with_retry(self.session, probe, timeout=self.timeout,
                                       rotate_ua=self.rotate_ua, max_retries=1,
                                       allow_redirects=False)
            if resp and resp.status_code not in (404, 400, 410):
                sizes.append(len(resp.content))

        if len(sizes) >= 4:
            self._wildcard = True
            self._baseline_len = int(statistics.mean(sizes))
            self._baseline_stdev = int(statistics.stdev(sizes)) if len(sizes) > 1 else 50
            log("DIR", col(
                f"Wildcard detected ({len(sizes)}/5 probes hit) "
                f"baseline={self._baseline_len}B stdev={self._baseline_stdev}B",
                C.YELLOW), C.YELLOW)
        else:
            self._wildcard = False
            self._baseline_stdev = 0

    def _is_wildcard_response(self, size: int) -> bool:
        if not self._wildcard or self._baseline_len == 0:
            return False
        threshold = max(32, self._baseline_stdev * 2) if self._baseline_stdev else max(32, int(self._baseline_len * 0.03))
        return abs(size - self._baseline_len) < threshold

    def _worker(self, q: queue.Queue, total: int, done_ctr: List[int]):
        while not self.stop_event.is_set():
            try:
                url = q.get(timeout=1)
            except queue.Empty:
                break
            try:
                proxies = self.proxy_mgr.next() if self.proxy_mgr else None
                resp, err = fetch_with_retry(
                    self.session, url, timeout=self.timeout,
                    rotate_ua=self.rotate_ua, proxies=proxies,
                    max_retries=self.max_retries, allow_redirects=False
                )
                with self._lock:
                    done_ctr[0] += 1
                    pct = int(done_ctr[0] / total * 100)

                if resp:
                    code = resp.status_code
                    sz   = len(resp.content)

                    if self._is_wildcard_response(sz):
                        q.task_done()
                        time.sleep(self.delay)
                        continue

                    show = True
                    if self.match_codes and code not in self.match_codes:
                        show = False
                    if code in self.hide_codes:
                        show = False

                    if show:
                        with self._lock:
                            if url in self._seen_urls:
                                show = False
                            else:
                                self._seen_urls.add(url)

                    if show:
                        redir = resp.headers.get("Location", "")
                        log(f"DIR  {pct:>3}%",
                            f"{status_color(code)}  {col(url, C.WHITE)}  "
                            f"{col(f'[{sz}B]', C.GRAY)}"
                            f"{col(' -> ' + redir, C.YELLOW) if redir else ''}",
                            C.CYAN)
                        hit = {"url": url, "status": code, "size": sz, "redirect": redir}
                        with self._lock:
                            self._hits.append(hit)
                            self.hits_out.append(hit)
            except Exception as e:
                vlog("DIR", col(f"Worker error: {e}", C.RED), C.RED)
            finally:
                time.sleep(self.delay)
                q.task_done()

    def _enumerate(self, base: str, depth: int = 0):
        if depth > self.max_depth or self.stop_event.is_set():
            return

        log("DIR", f"Enumerating {col(base, C.CYAN)} (depth {depth})", C.CYAN)
        self._detect_wildcard()

        probes = [
            f"{base.rstrip('/')}/{w.strip('/')}{e}"
            for w in self.wordlist
            for e in self.extensions
        ]
        total = len(probes)
        q: queue.Queue = queue.Queue()
        for p in probes:
            q.put(p)

        done_ctr = [0]
        workers = [
            threading.Thread(target=self._worker, args=(q, total, done_ctr), daemon=True)
            for _ in range(min(self.threads, total or 1))
        ]
        for w in workers:
            w.start()
        q.join()

        if self.recursive and depth < self.max_depth and not self.stop_event.is_set():
            with self._lock:
                new_dirs = [
                    h["url"] for h in self._hits
                    if h["status"] in (200, 301, 302, 403)
                    and not os.path.splitext(urlparse(h["url"]).path)[1]
                    and h["url"] != base
                ]
            for nd in new_dirs:
                self._enumerate(nd, depth + 1)

    def run(self) -> List[Dict]:
        log("DIR", f"Starting directory hunt on {col(self.base_url, C.CYAN)}", C.CYAN)
        log("DIR", f"Wordlist: {col(len(self.wordlist), C.BOLD)} words  "
                   f"Extensions: {col(self.extensions, C.BOLD)}  "
                   f"Recursive: {col(self.recursive, C.BOLD)}", C.CYAN)
        self._enumerate(self.base_url)
        if self.stop_event.is_set():
            log("DIR", col("Directory hunt stopped by user", C.YELLOW), C.YELLOW)
        else:
            log("DIR", f"Done -- {col(len(self._hits), C.BOLD+C.GREEN)} hits found", C.GREEN)
        return self._hits
