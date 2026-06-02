"""
modules/subdomain.py
Subdomain discovery: DNS brute-force, crt.sh cert transparency, DNS record analysis.
"""

import queue, socket, threading
from typing import Dict, List, Optional, Set

from bs4 import BeautifulSoup

from ..utils import fetch_with_retry, log, log_section, vlog, col, status_color, C, random_ua

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class SubdomainHunter:
    CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

    def __init__(self, domain: str, wordlist: List[str], threads: int,
                 timeout: int, session, results_out: List[Dict],
                 stop_event: threading.Event = None):
        self.domain      = domain.lstrip("*.").lower()
        self.wordlist    = wordlist
        self.threads     = threads
        self.timeout     = timeout
        self.session     = session
        self.results_out = results_out
        self.stop_event  = stop_event or threading.Event()
        self._found: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    def _resolve(self, fqdn: str) -> Optional[List[str]]:
        try:
            if DNS_AVAILABLE:
                answers = dns.resolver.resolve(fqdn, "A", lifetime=self.timeout)
                return [str(r) for r in answers]
            else:
                ip = socket.gethostbyname(fqdn)
                return [ip]
        except Exception:
            return None

    def _brute_worker(self, q: queue.Queue, total: int, done_counter: List[int]):
        while not self.stop_event.is_set():
            try:
                word = q.get(timeout=1)
            except queue.Empty:
                break
            try:
                fqdn = f"{word}.{self.domain}"
                ips = self._resolve(fqdn)
                with self._lock:
                    done_counter[0] += 1
                    pct = int(done_counter[0] / total * 100)
                if ips:
                    entry = {"subdomain": fqdn, "ips": ips, "method": "brute-force", "status": None}
                    with self._lock:
                        if fqdn not in self._found:
                            self._found[fqdn] = entry
                            log(f"SUB {pct:>3}%",
                                f"{col('[+]', C.GREEN+C.BOLD)}  {col(fqdn, C.CYAN)}  "
                                f"{col('->', C.GRAY)}  {col(', '.join(ips), C.GREEN)}",
                                C.GREEN)
            except Exception as e:
                vlog("SUB", col(f"Worker error: {e}", C.RED), C.RED)
            finally:
                q.task_done()

    def _run_brute(self):
        log_section("SUBDOMAIN BRUTE-FORCE")
        log("SUB", f"Wordlist: {col(len(self.wordlist), C.BOLD)} entries against {col(self.domain, C.CYAN)}", C.CYAN)

        wildcard_ip = self._resolve(f"this-should-not-exist-12345.{self.domain}")
        if wildcard_ip:
            log("SUB", col(f"WARNING: Wildcard DNS detected ({wildcard_ip})", C.YELLOW), C.YELLOW)

        q: queue.Queue = queue.Queue()
        for w in self.wordlist:
            q.put(w.strip())
        total = q.qsize()
        done_counter = [0]

        workers = [
            threading.Thread(target=self._brute_worker, args=(q, total, done_counter), daemon=True)
            for _ in range(min(self.threads, total or 1))
        ]
        for w in workers:
            w.start()
        q.join()

    def _run_crtsh(self):
        log_section("CERT TRANSPARENCY (crt.sh)")
        url = self.CRTSH_URL.format(domain=self.domain)
        log("CRT", f"Querying {col('crt.sh', C.CYAN)} for {col(self.domain, C.BOLD)} ...", C.CYAN)
        try:
            resp, err = fetch_with_retry(self.session, url, timeout=20)
            if not resp or resp.status_code != 200:
                log("CRT", col("crt.sh query failed or no results", C.YELLOW), C.YELLOW)
                return
            entries = resp.json()
            seen: Set[str] = set()
            for entry in entries:
                names_raw = entry.get("name_value", "")
                for name in names_raw.splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if not name.endswith(self.domain) or name in seen:
                        continue
                    seen.add(name)
                    ips = self._resolve(name) or []
                    record = {"subdomain": name, "ips": ips, "method": "crt.sh", "status": None}
                    with self._lock:
                        if name not in self._found:
                            self._found[name] = record
                            status = col(f"[{', '.join(ips)}]", C.GREEN) if ips else col("[no A record]", C.GRAY)
                            log("CRT", f"{col('[+]', C.GREEN+C.BOLD)}  {col(name, C.CYAN)}  {status}", C.GREEN)
            log("CRT", f"crt.sh returned {col(len(seen), C.BOLD)} unique names", C.CYAN)
        except Exception as e:
            log("CRT", col(f"Error: {e}", C.RED), C.RED)

    def _run_dns_records(self):
        if not DNS_AVAILABLE:
            log("DNS", col("dnspython not installed -- skipping DNS record enumeration", C.YELLOW), C.YELLOW)
            return
        log_section("DNS RECORD ANALYSIS")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=self.timeout)
                vals = [str(r) for r in answers]
                log("DNS", f"{col(rtype, C.YELLOW)}  {col(self.domain, C.CYAN)}  ->  {col(', '.join(vals[:3]), C.WHITE)}", C.CYAN)
            except Exception:
                pass

    def _probe_http(self):
        log_section("HTTP PROBE ON DISCOVERED SUBDOMAINS")
        items = list(self._found.values())
        if not items:
            log("PROBE", "No subdomains to probe", C.GRAY)
            return

        def probe(entry):
            sub = entry["subdomain"]
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                resp, _ = fetch_with_retry(self.session, url, timeout=self.timeout,
                                           rotate_ua=True, allow_redirects=True, max_retries=1)
                if resp:
                    entry["status"] = resp.status_code
                    entry["http_url"] = url
                    title = ""
                    try:
                        soup = BeautifulSoup(resp.text, "html.parser")
                        t = soup.find("title")
                        if t:
                            title = t.get_text(strip=True)[:80]
                    except Exception:
                        pass
                    entry["title"] = title
                    log("PROBE",
                        f"{status_color(resp.status_code)}  {col(url, C.CYAN)}"
                        f"  {col(title, C.GRAY) if title else ''}",
                        C.CYAN)
                    break

        probe_q: queue.Queue = queue.Queue()
        for entry in items:
            probe_q.put(entry)

        def _probe_worker():
            while not self.stop_event.is_set():
                try:
                    entry = probe_q.get(timeout=1)
                except queue.Empty:
                    break
                try:
                    probe(entry)
                finally:
                    probe_q.task_done()

        workers = [threading.Thread(target=_probe_worker, daemon=True)
                   for _ in range(min(50, len(items)))]
        for w in workers:
            w.start()
        probe_q.join()

    def run(self) -> List[Dict]:
        self._run_brute()
        self._run_crtsh()
        self._run_dns_records()
        self._probe_http()

        results = list(self._found.values())
        self.results_out.extend(results)

        log_section("SUBDOMAIN SUMMARY")
        log("SUB", f"Total unique subdomains found: {col(len(results), C.BOLD+C.GREEN)}", C.GREEN)
        for r in sorted(results, key=lambda x: x["subdomain"]):
            status_str = status_color(r.get("status")) if r.get("status") else col("no-http", C.GRAY)
            ip_str = col(", ".join(r.get("ips", [])), C.GREEN)
            log("  +",
                f"{col(r['subdomain'], C.CYAN)}  {ip_str}  {status_str}  "
                f"{col(r.get('method', ''), C.GRAY)}", C.GREEN)
        return results
