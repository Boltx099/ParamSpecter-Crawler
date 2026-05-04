#!/usr/bin/env python3
"""
ParamSpecter v2.0 - Advanced Recon Crawler for Bug Bounty & Security Research
For authorized and educational use only.

Modes:
  crawl   - Recursive crawler (default)
  fuzz    - Wordlist-based directory/endpoint bruteforce
  param   - Wordlist-based parameter discovery/fuzzing
  full    - All three phases combined
"""

import requests, re, sys, json, csv, time, os, argparse, threading, queue
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from urllib.robotparser import RobotFileParser
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────
class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; WHITE = "\033[97m"
    GRAY = "\033[90m"; BOLD = "\033[1m"; RESET = "\033[0m"

def color(text, *codes): return "".join(codes) + str(text) + C.RESET

BANNER = f"""
{C.RED}{C.BOLD}
  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗███████╗██████╗ ███████╗███████╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝███████║██████╔╝███████║██╔████╔██║█████╗  ██████╔╝█████╗  █████╗     ██║   █████╗  ██████╔╝
  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══╝  ██╔══╝     ██║   ██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║███████╗███████╗   ██║   ███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.GRAY}  ParamSpecter v2.0 - Advanced Recon Crawler | Wordlist Edition
{C.BOLD}{C.CYAN}  Created by Boltx{C.RESET}
{C.RED}{'─'*90}{C.RESET}
"""

# ─────────────────────────────────────────────────────────────
#  BUILT-IN WORDLISTS  (used when no -w / -pw file is given)
# ─────────────────────────────────────────────────────────────
BUILTIN_DIRS = [
    "admin","login","dashboard","api","v1","v2","v3","backup","config","test",
    "upload","uploads","files","static","assets","images","js","css","includes",
    "src","lib","vendor","wp-admin","wp-content","wp-login.php",
    ".git","phpinfo.php","info.php","server-status","robots.txt","sitemap.xml",
    "crossdomain.xml","security.txt",".well-known","actuator",
    "swagger","swagger-ui","swagger.json","openapi.json","graphql","console",
    "debug","manage","management","metrics","health","status","monitor",
    "register","signup","logout","profile","account","user","users","panel",
    "portal","hidden","old","dev","development","staging","prod","internal",
    "private","secret","db","database","sql","phpmyadmin","adminer",
    "setup","install","update","cron","shell","tmp","temp","cache",
    "log","logs","error","errors","dump","export","import","download",
    "search","report","data","feed","rss","sitemap",
]

BUILTIN_PARAMS = [
    "id","user","username","name","email","pass","password","token","key",
    "api_key","apikey","secret","auth","session","sid","uid","uuid",
    "ref","redirect","url","next","return","returnurl","callback","continue",
    "dest","destination","path","file","filename","dir","folder",
    "page","p","q","query","search","s","keyword","lang","locale","country",
    "format","type","mode","view","action","cmd","exec","command","code",
    "data","payload","input","output","target","host","domain","ip","port",
    "hash","sig","signature","nonce","state","scope","grant","access",
    "refresh","order","sort","limit","offset","start","end","from","to",
    "date","time","timestamp","created","updated","category","tag","status",
    "filter","include","exclude","fields","expand","depth","version","v",
    "debug","test","verbose","trace","log",
]

BUILTIN_EXTENSIONS = ["", ".php", ".html", ".asp", ".aspx", ".jsp",
                      ".json", ".txt", ".bak", ".old", ".xml"]

# ─────────────────────────────────────────────────────────────
#  DETECTION PATTERNS
# ─────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    re.compile(r'(?i)(?:api[_\-]?key|apikey|token|secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{8,})'),
    re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)'),
    re.compile(r'(AKIA[0-9A-Z]{16})'),
]

PATTERNS = {
    "email":     re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I),
    "phone":     re.compile(r"(?:\+?\d[\d\s\-().]{7,}\d)"),
    "ipv4":      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "subdomain": re.compile(r"https?://([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+)", re.I),
    "comment":   re.compile(r"<!--(.*?)-->", re.DOTALL),
    "js_src":    re.compile(r'<script[^>]*\ssrc=["\'](.*?)["\']', re.I),
    "js_url":    re.compile(r"""(?:['"` ])(https?://[^\s'"` <>]+)(?:['"` ])"""),
    "aws_key":   re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_key":   re.compile(r'(?:api[_\-]?key|apikey|token|secret)["\']?\s*[:=]\s*["\'\w\-]{8,}', re.I),
}

SOCIAL_DOMAINS = {"facebook.com","twitter.com","x.com","linkedin.com","instagram.com",
                  "github.com","youtube.com","tiktok.com","t.me","discord.gg"}

TECH_SIGNATURES = {
    "WordPress":  [re.compile(r"wp-content|wp-includes|WordPress", re.I)],
    "Joomla":     [re.compile(r"Joomla|/components/com_", re.I)],
    "Drupal":     [re.compile(r"Drupal|/sites/default/files", re.I)],
    "React":      [re.compile(r"react(?:\.min)?\.js|__REACT|_reactRootContainer", re.I)],
    "Angular":    [re.compile(r"ng-version|angular(?:\.min)?\.js", re.I)],
    "Vue":        [re.compile(r"vue(?:\.min)?\.js|__vue__", re.I)],
    "jQuery":     [re.compile(r"jquery(?:\.min)?\.js|jQuery", re.I)],
    "Bootstrap":  [re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I)],
    "Cloudflare": [re.compile(r"cloudflare|cf-ray", re.I)],
    "AWS":        [re.compile(r"amazonaws\.com|x-amz-", re.I)],
    "PHP":        [re.compile(r"\.php|X-Powered-By: PHP", re.I)],
    "ASP.NET":    [re.compile(r"__VIEWSTATE|ASP\.NET|X-Powered-By: ASP", re.I)],
    "Django":     [re.compile(r"csrfmiddlewaretoken|Django", re.I)],
    "Laravel":    [re.compile(r"laravel_session|Laravel", re.I)],
    "Nginx":      [re.compile(r"nginx", re.I)],
    "Apache":     [re.compile(r"Apache", re.I)],
}

WAF_SIGNATURES = {
    "Cloudflare WAF": re.compile(r"cloudflare|cf-ray|__cfduid|attention required", re.I),
    "Sucuri WAF":     re.compile(r"sucuri|cloudproxy", re.I),
    "ModSecurity":    re.compile(r"mod_security|modsecurity|NOYB", re.I),
    "Incapsula":      re.compile(r"incapsula|visid_incap", re.I),
    "Akamai":         re.compile(r"akamai|akamaighhost", re.I),
    "Barracuda":      re.compile(r"barracuda", re.I),
}

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")

# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────
def normalize_url(url, parent=""):
    try:
        full = urljoin(parent, url)
        p = urlparse(full)
        if p.scheme not in ("http","https"): return None
        return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", p.query, ""))
    except: return None

def status_color(code):
    if code is None:  return color("ERR", C.RED)
    if code < 300:    return color(code, C.GREEN)
    if code < 400:    return color(code, C.YELLOW)
    if code < 500:    return color(code, C.RED)
    return color(code, C.RED, C.BOLD)

def log(prefix, msg, col=C.WHITE):
    ts = color(datetime.now().strftime("%H:%M:%S"), C.GRAY)
    print(f"  {ts}  {color(prefix, col)}  {msg}")

def load_wordlist(path):
    """Load a wordlist file (one word per line). Returns a list of strings."""
    if not path: return []
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        print(color(f"  [!] Wordlist not found: {path}", C.RED)); sys.exit(1)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    log("+WL", f"Loaded {color(len(words), C.BOLD)} words from {path}", C.GREEN)
    return words

# ─────────────────────────────────────────────────────────────
#  ROBOTS.TXT
# ─────────────────────────────────────────────────────────────
class RobotsTxtChecker:
    def __init__(self, base_url, ua):
        self.rp = RobotFileParser(); self.ua = ua
        self.disallowed_paths = []; self.sitemaps = []
        robots_url = urljoin(base_url, "/robots.txt")
        self.rp.set_url(robots_url)
        try:
            self.rp.read()
            resp = requests.get(robots_url, timeout=8, headers={"User-Agent": ua})
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        p = line.split(":",1)[1].strip()
                        if p: self.disallowed_paths.append(p)
                    elif line.lower().startswith("sitemap:"):
                        self.sitemaps.append(line.split(":",1)[1].strip())
        except: pass

    def allowed(self, url):
        try:    return self.rp.can_fetch(self.ua, url)
        except: return True

# ─────────────────────────────────────────────────────────────
#  JS ANALYSIS
# ─────────────────────────────────────────────────────────────
def analyze_js_files(js_src_list, page_url, session):
    deep_ep = set(); secrets = set()
    ep_pat = re.compile(r'["\'/]((?:api|v\d+|admin|auth|graphql)[a-zA-Z0-9_/.\-]*)', re.I)
    for js in js_src_list:
        try:
            r = session.get(urljoin(page_url, js), timeout=5)
            if r.status_code != 200: continue
            for m in ep_pat.finditer(r.text): deep_ep.add(m.group(1))
            for pat in SECRET_PATTERNS:
                for m in pat.finditer(r.text):
                    try:    secrets.add(m.group(1))
                    except: secrets.add(m.group(0))
        except: continue
    return deep_ep, secrets

# ─────────────────────────────────────────────────────────────
#  PAGE ANALYSIS
# ─────────────────────────────────────────────────────────────
def analyze_page(url, resp, soup, raw_html, session):
    data = {
        "url": url, "status": resp.status_code,
        "content_type": resp.headers.get("Content-Type",""),
        "server": resp.headers.get("Server",""),
        "redirect_chain": [r.url for r in resp.history] if resp.history else [],
        "title":"", "meta_desc":"",
        "links":[], "external_links":[], "social_links":[],
        "emails":[], "phones":[], "ips":[], "subdomains":[],
        "js_src":[], "js_urls":[], "js_endpoints":[],
        "html_comments":[], "forms":[], "input_fields":[],
        "params":[], "sensitive_hints":[], "technologies":[], "waf":[],
        "secrets":[], "cookies": dict(resp.cookies), "security_headers":{},
    }

    if soup:
        t = soup.find("title")
        if t: data["title"] = t.get_text(strip=True)
        m = soup.find("meta", attrs={"name": re.compile("description",re.I)})
        if m: data["meta_desc"] = m.get("content","")

    for h in ["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
              "X-Content-Type-Options","Referrer-Policy","Permissions-Policy",
              "X-XSS-Protection","X-Powered-By"]:
        v = resp.headers.get(h)
        if v: data["security_headers"][h] = v

    if soup:
        bd = urlparse(url).netloc
        for tag in soup.find_all("a", href=True):
            norm = normalize_url(tag["href"], url)
            if norm:
                if urlparse(norm).netloc == bd: data["links"].append(norm)
                else:
                    data["external_links"].append(norm)
                    if any(sd in norm for sd in SOCIAL_DOMAINS): data["social_links"].append(norm)

    data["emails"]     = list(set(PATTERNS["email"].findall(raw_html)))
    data["phones"]     = list(set(PATTERNS["phone"].findall(raw_html)))
    data["ips"]        = list(set(PATTERNS["ipv4"].findall(raw_html)))
    data["subdomains"] = list(set(PATTERNS["subdomain"].findall(raw_html)))
    data["js_src"]     = list(set(PATTERNS["js_src"].findall(raw_html)))
    data["js_urls"]    = list(set(PATTERNS["js_url"].findall(raw_html)))
    data["html_comments"] = [c.strip() for c in PATTERNS["comment"].findall(raw_html) if c.strip()]

    if PATTERNS["aws_key"].search(raw_html): data["sensitive_hints"].append("Possible AWS Access Key found")
    if PATTERNS["api_key"].search(raw_html): data["sensitive_hints"].append("Possible API key / secret found")

    if soup:
        for form in soup.find_all("form"):
            inputs = [{"tag":i.name,"name":i.get("name",""),"type":i.get("type","text"),"value":i.get("value","")}
                      for i in form.find_all(["input","textarea","select"])]
            data["forms"].append({"action":form.get("action",""),"method":form.get("method","GET").upper(),
                                   "enctype":form.get("enctype",""),"inputs":inputs})
            data["input_fields"].extend(inputs)

    param_set = set()
    for u in [url] + data["links"] + data["external_links"]:
        for k in parse_qs(urlparse(u).query, keep_blank_values=True): param_set.add(k)
    data["params"] = sorted(param_set)

    combined = raw_html + str(resp.headers)
    for tech, sigs in TECH_SIGNATURES.items():
        if any(s.search(combined) for s in sigs): data["technologies"].append(tech)
    wc = str(resp.headers) + raw_html[:3000]
    for waf, sig in WAF_SIGNATURES.items():
        if sig.search(wc): data["waf"].append(waf)

    dep, sec = analyze_js_files(data["js_src"], url, session)
    dep.update(re.findall(r'/(?:api|v\d+|admin|auth|graphql)[a-zA-Z0-9_/.\-]*', raw_html))
    data["js_endpoints"] = sorted(dep)
    data["secrets"]      = list(sec)
    return data

# ─────────────────────────────────────────────────────────────
#  DIRECTORY FUZZER
# ─────────────────────────────────────────────────────────────
class DirFuzzer:
    """
    Probes base_url/word[ext] for every word+extension combo.
    Reports non-hidden status codes. Thread-safe.
    """
    def __init__(self, base_url, wordlist, extensions, threads, timeout,
                 session, delay, match_codes, hide_codes, hits_out):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist
        self.extensions = extensions
        self.threads = threads
        self.timeout = timeout
        self.session = session
        self.delay = delay
        self.match_codes = set(match_codes) if match_codes else None
        self.hide_codes  = set(hide_codes)  if hide_codes  else {404}
        self.hits_out = hits_out           # shared list
        self._q = queue.Queue()
        self._lock = threading.Lock()
        self._done = 0; self._total = 0; self._hits = []

    def run(self):
        probes = [f"{self.base_url}/{w.strip('/')}{e}"
                  for w in self.wordlist for e in self.extensions]
        self._total = len(probes)
        for p in probes: self._q.put(p)
        log("FUZZ", f"Starting dir fuzz → {color(self._total, C.BOLD)} probes on {self.base_url}", C.CYAN)
        workers = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.threads)]
        for w in workers: w.start()
        self._q.join()
        for w in workers: w.join(timeout=1)
        log("FUZZ", f"Done — {color(len(self._hits), C.BOLD+C.GREEN)} hits found.", C.GREEN)
        return self._hits

    def _worker(self):
        while True:
            try: url = self._q.get(timeout=2)
            except queue.Empty: break
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                code = r.status_code
                with self._lock: self._done += 1; pct = int(self._done/self._total*100)
                show = True
                if self.match_codes and code not in self.match_codes: show = False
                if code in self.hide_codes: show = False
                if show:
                    sz = len(r.content)
                    redir = f"  → {r.headers.get('Location','')}" if code in (301,302,303,307,308) else ""
                    log(f"FUZZ {pct:>3}%",
                        f"{status_color(code)}  {color(url, C.WHITE)}  "
                        f"{color(f'[{sz}B]',C.GRAY)}{color(redir,C.YELLOW)}", C.CYAN)
                    hit = {"url":url,"status":code,"size":sz,"redirect":r.headers.get("Location","")}
                    with self._lock:
                        self._hits.append(hit)
                        self.hits_out.append(hit)
            except: pass
            finally:
                time.sleep(self.delay)
                self._q.task_done()

# ─────────────────────────────────────────────────────────────
#  PARAMETER FUZZER
# ─────────────────────────────────────────────────────────────
class ParamFuzzer:
    """
    Wordlist-driven parameter discovery.
    Sends target_url?param=FUZZ for each param name.
    Flags responses that differ from the baseline (status or body size).
    Supports GET and POST.
    """
    FUZZ_VAL = "paramspecter1337"

    def __init__(self, target_url, param_list, threads, timeout, session,
                 delay, hits_out, method="GET"):
        self.target_url = target_url
        self.param_list = param_list
        self.threads = threads
        self.timeout = timeout
        self.session = session
        self.delay = delay
        self.hits_out = hits_out
        self.method = method.upper()
        self._q = queue.Queue()
        self._lock = threading.Lock()
        self._done = 0; self._total = len(param_list); self._hits = []
        self._base_code = 0; self._base_len = 0

    def _baseline(self):
        try:
            r = self.session.get(self.target_url, timeout=self.timeout)
            self._base_code = r.status_code
            self._base_len  = len(r.content)
            log("PARAM", f"Baseline → HTTP {self._base_code}  size={self._base_len}B", C.GRAY)
        except: log("PARAM","Baseline failed",C.RED)

    def run(self):
        self._baseline()
        for p in self.param_list: self._q.put(p.strip())
        log("PARAM", f"Starting param fuzz → {color(self._total, C.BOLD)} params "
                     f"via {self.method} on {self.target_url}", C.CYAN)
        workers = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.threads)]
        for w in workers: w.start()
        self._q.join()
        for w in workers: w.join(timeout=1)
        log("PARAM", f"Done — {color(len(self._hits), C.BOLD+C.GREEN)} interesting params found.", C.GREEN)
        return self._hits

    def _worker(self):
        while True:
            try: param = self._q.get(timeout=2)
            except queue.Empty: break
            try:
                if self.method == "GET":
                    sep = "&" if "?" in self.target_url else "?"
                    url = f"{self.target_url}{sep}{param}={self.FUZZ_VAL}"
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                else:
                    url = self.target_url
                    r = self.session.post(url, data={param: self.FUZZ_VAL},
                                          timeout=self.timeout, allow_redirects=False)

                code = r.status_code; sz = len(r.content)
                diff = abs(sz - self._base_len)
                interesting = (code != self._base_code) or (diff > 50)

                with self._lock:
                    self._done += 1
                    pct = int(self._done/self._total*100)

                if interesting:
                    flag = color("★ INTERESTING", C.GREEN+C.BOLD)
                    log(f"PARAM {pct:>3}%",
                        f"{status_color(code)}  "
                        f"{color('?'+param+'=...', C.YELLOW)}  "
                        f"{color(f'[sz:{sz}B Δ{diff}B]', C.GRAY)}  {flag}", C.CYAN)
                    hit = {"param":param,"url":url,"status":code,"size":sz,
                           "size_diff":diff,"interesting":True}
                    with self._lock:
                        self._hits.append(hit)
                        self.hits_out.append(hit)
            except: pass
            finally:
                time.sleep(self.delay)
                self._q.task_done()

# ─────────────────────────────────────────────────────────────
#  MAIN CRAWLER / ORCHESTRATOR
# ─────────────────────────────────────────────────────────────
class ParamSpecter:
    def __init__(self, args):
        self.args = args
        self.start_url      = args.url.rstrip("/")
        self.max_pages      = args.max_pages
        self.delay          = args.delay
        self.depth          = args.depth
        self.threads        = args.threads
        self.timeout        = args.timeout
        self.same_domain    = not args.follow_external
        self.respect_robots = not args.ignore_robots
        self.ua             = args.user_agent or DEFAULT_UA
        self.output         = args.output
        self.mode           = args.mode
        self.base_domain    = urlparse(self.start_url).netloc

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.ua})
        if getattr(args,"cookies",None):
            for pair in args.cookies.split(";"):
                if "=" in pair:
                    k,v = pair.strip().split("=",1)
                    self.session.cookies.set(k.strip(), v.strip())
        if getattr(args,"headers",None):
            for pair in args.headers:
                if ":" in pair:
                    k,v = pair.split(":",1)
                    self.session.headers[k.strip()] = v.strip()

        # Crawl state
        self.visited = set(); self.visited_lock = threading.Lock()
        self.url_queue = queue.Queue(); self.url_queue.put((self.start_url,0))
        self.results = []; self.results_lock = threading.Lock()
        self.page_count = 0; self.count_lock = threading.Lock()

        # Aggregates
        self.all_emails=set(); self.all_phones=set(); self.all_links=set()
        self.all_subdomains=set(); self.all_techs=set(); self.all_wafs=set()
        self.all_params=set(); self.all_secrets=set()

        # Wordlist results
        self.fuzz_hits = []; self.param_hits = []

        # Robots
        self.robots = None
        if self.respect_robots:
            log("ROBOTS","Fetching robots.txt ...",C.CYAN)
            self.robots = RobotsTxtChecker(self.start_url, self.ua)
            if self.robots.disallowed_paths:
                log("ROBOTS",f"Disallowed: {len(self.robots.disallowed_paths)} paths",C.YELLOW)
            if self.robots.sitemaps:
                log("ROBOTS",f"Sitemaps: {', '.join(self.robots.sitemaps)}",C.CYAN)

        self.start_time = datetime.now()

    # ─────────────────────── crawl ──────────────────────────
    def _fetch(self, url):
        try: return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except: return None

    def _crawl_worker(self):
        while True:
            try: url, depth = self.url_queue.get(timeout=3)
            except queue.Empty: break

            with self.visited_lock:
                if url in self.visited: self.url_queue.task_done(); continue
                self.visited.add(url)

            with self.count_lock:
                if self.page_count >= self.max_pages:
                    self.url_queue.task_done(); break
                self.page_count += 1; count = self.page_count

            if self.robots and not self.robots.allowed(url):
                log("SKIP", url, C.GRAY); self.url_queue.task_done(); continue

            resp = self._fetch(url)
            if resp is None:
                log(f"[{count:>4}]", f"{color('FAIL',C.RED)}  {url}", C.RED)
                with self.results_lock: self.results.append({"url":url,"status":None,"error":"failed"})
                self.url_queue.task_done(); continue

            ct = resp.headers.get("Content-Type",""); raw=""; soup=None
            if "text/html" in ct:
                try: raw=resp.text; soup=BeautifulSoup(raw,"html.parser")
                except: pass

            pd = analyze_page(url, resp, soup, raw, self.session)

            print(f"  {color(datetime.now().strftime('%H:%M:%S'),C.GRAY)}  "
                  f"{color(f'[{count:>4}]',C.CYAN)}  {status_color(resp.status_code)}  "
                  f"{color(url[:80],C.WHITE)}")
            if pd.get("secrets"):    log("     !",f"Secrets: {len(pd['secrets'])}",C.RED)
            if pd["emails"]:         log("     +",f"Emails: {color(', '.join(pd['emails']),C.GREEN)}",C.GRAY)
            if pd["sensitive_hints"]:
                for h in pd["sensitive_hints"]: log("     !",color(h,C.RED+C.BOLD),C.RED)
            if pd["waf"]:            log("     W",f"WAF: {color(', '.join(pd['waf']),C.YELLOW)}",C.GRAY)
            if pd["forms"]:          log("     F",f"Forms:{len(pd['forms'])} Inputs:{len(pd['input_fields'])}",C.GRAY)
            if pd["params"]:         log("     P",f"Params: {color(str(pd['params']),C.YELLOW)}",C.YELLOW)
            if pd["js_endpoints"]:   log("     J",f"JS endpoints: {len(pd['js_endpoints'])}",C.CYAN)

            with self.results_lock:
                self.results.append(pd)
                self.all_emails.update(pd["emails"]); self.all_phones.update(pd["phones"])
                self.all_links.update(pd["links"]);   self.all_subdomains.update(pd["subdomains"])
                self.all_techs.update(pd["technologies"]); self.all_wafs.update(pd["waf"])
                self.all_params.update(pd["params"]); self.all_secrets.update(pd["secrets"])

            if depth < self.depth and "text/html" in ct:
                for link in pd["links"]:
                    with self.visited_lock:
                        if link not in self.visited:
                            if not self.same_domain or urlparse(link).netloc == self.base_domain:
                                self.url_queue.put((link, depth+1))

            time.sleep(self.delay)
            self.url_queue.task_done()

    def run_crawl(self):
        workers = [threading.Thread(target=self._crawl_worker, daemon=True)
                   for _ in range(self.threads)]
        for w in workers: w.start()
        self.url_queue.join()
        for w in workers: w.join(timeout=1)

    # ─────────────────────── dir fuzz ───────────────────────
    def run_fuzz(self, base_url=None):
        a = self.args
        wl   = load_wordlist(a.wordlist) if a.wordlist else BUILTIN_DIRS
        exts = [e.strip() for e in a.extensions.split(",")] if a.extensions else [""]
        mc   = [int(c) for c in a.match_codes.split(",")] if a.match_codes else None
        hc   = [int(c) for c in a.hide_codes.split(",")]  if a.hide_codes  else [404]
        DirFuzzer(base_url or self.start_url, wl, exts,
                  a.threads, a.timeout, self.session, a.delay,
                  mc, hc, self.fuzz_hits).run()

    # ─────────────────────── param fuzz ─────────────────────
    def run_param_fuzz(self, target_url=None):
        a = self.args
        pl = load_wordlist(a.param_wordlist) if a.param_wordlist else BUILTIN_PARAMS
        ParamFuzzer(target_url or self.start_url, pl,
                    a.threads, a.timeout, self.session, a.delay,
                    self.param_hits, a.param_method).run()

    # ─────────────────────── orchestrate ────────────────────
    def run(self):
        mode = self.mode

        if mode in ("crawl","full"):
            print(f"\n{color('─'*90,C.RED)}")
            print(color("  ▶  PHASE 1 — CRAWLING", C.BOLD+C.CYAN))
            print(color('─'*90,C.RED))
            self.run_crawl()

        if mode in ("fuzz","full"):
            print(f"\n{color('─'*90,C.RED)}")
            print(color("  ▶  PHASE 2 — DIRECTORY FUZZING", C.BOLD+C.CYAN))
            print(color('─'*90,C.RED))
            targets = {self.start_url}
            if mode == "full" and self.results:
                for r in self.results:
                    p = urlparse(r.get("url","")).path.rsplit("/",1)[0]
                    targets.add(self.start_url.rstrip("/") + (p or ""))
            for t in list(targets)[:5]: self.run_fuzz(base_url=t)

        if mode in ("param","full"):
            print(f"\n{color('─'*90,C.RED)}")
            print(color("  ▶  PHASE 3 — PARAMETER FUZZING", C.BOLD+C.CYAN))
            print(color('─'*90,C.RED))
            targets = [self.start_url]
            if mode == "full":
                param_urls = [r["url"] for r in self.results
                              if r.get("params") and r.get("status") and r["status"] < 400]
                if param_urls: targets = param_urls[:10]
            for t in targets: self.run_param_fuzz(target_url=t)

        self.print_summary(); self.save_results()

    # ─────────────────────── summary ────────────────────────
    def print_summary(self):
        dur = (datetime.now()-self.start_time).seconds
        print(f"\n{color('='*90,C.RED)}")
        print(color("  SCAN COMPLETE", C.BOLD+C.WHITE))
        print(color('='*90,C.RED))

        for label,val in [
            ("Target",       self.start_url),
            ("Mode",         self.mode),
            ("Pages crawled",len(self.results)),
            ("Links found",  len(self.all_links)),
            ("Emails",       len(self.all_emails)),
            ("Subdomains",   len(self.all_subdomains)),
            ("URL Params",   len(self.all_params)),
            ("Secrets",      len(self.all_secrets)),
            ("Dir hits",     len(self.fuzz_hits)),
            ("Param hits",   len(self.param_hits)),
            ("Technologies", ", ".join(self.all_techs) or "None"),
            ("WAF",          ", ".join(self.all_wafs)  or "None"),
            ("Duration",     f"{dur}s"),
        ]:
            print(f"  {color(label+':',C.CYAN):<30} {val}")

        sc = defaultdict(int)
        for r in self.results: sc[r.get("status") or "ERR"] += 1
        if sc:
            print(f"\n  {color('HTTP Status Breakdown:',C.CYAN)}")
            for code in sorted(sc, key=str):
                bar = "█"*min(sc[code],40)
                print(f"    {status_color(code)}  {bar}  ({sc[code]})")

        if self.all_emails:
            print(f"\n  {color('Emails:',C.CYAN)}")
            for e in sorted(self.all_emails): print(f"    {color(e,C.GREEN)}")

        if self.all_params:
            print(f"\n  {color('URL Parameters Discovered:',C.CYAN)}")
            for p in sorted(self.all_params): print(f"    {color('?'+p,C.YELLOW)}")

        if self.all_secrets:
            print(f"\n  {color('Possible Secrets:',C.RED+C.BOLD)}")
            for s in sorted(self.all_secrets): print(f"    {color(s,C.RED)}")

        if self.fuzz_hits:
            print(f"\n  {color('Dir Fuzz Hits:',C.CYAN)}")
            for h in self.fuzz_hits:
                print(f"    {status_color(h['status'])}  {h['url']}  [{h['size']}B]")

        if self.param_hits:
            print(f"\n  {color('Interesting Params Found:',C.CYAN)}")
            for h in self.param_hits:
                print(f"    {status_color(h['status'])}  ?{color(h['param'],C.YELLOW)}  "
                      f"[sz:{h['size']}B Δ{h['size_diff']}B]")

        miss = defaultdict(int)
        for r in self.results:
            for h in ["Strict-Transport-Security","Content-Security-Policy",
                      "X-Frame-Options","X-Content-Type-Options"]:
                if h not in r.get("security_headers",{}): miss[h]+=1
        if miss:
            print(f"\n  {color('Missing Security Headers:',C.YELLOW)}")
            for h,c in miss.items(): print(f"    {color(h,C.RED)}: {c} page(s)")

        print(f"{color('='*90,C.RED)}\n")

    # ─────────────────────── save ────────────────────────────
    def save_results(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pfx = f"paramspecter_{self.base_domain.replace('.','_')}_{ts}"

        if self.output in ("json","both"):
            fname = f"{pfx}.json"
            with open(fname,"w",encoding="utf-8") as f:
                json.dump({
                    "meta":{
                        "target":self.start_url,"mode":self.mode,
                        "crawled_at":self.start_time.isoformat(),
                        "total_pages":len(self.results),
                        "emails":list(self.all_emails),"phones":list(self.all_phones),
                        "subdomains":list(self.all_subdomains),"technologies":list(self.all_techs),
                        "waf":list(self.all_wafs),"params":list(self.all_params),
                        "secrets":list(self.all_secrets),
                    },
                    "pages":self.results,"fuzz_hits":self.fuzz_hits,"param_hits":self.param_hits,
                }, f, indent=2, ensure_ascii=False)
            log("SAVED",f"JSON → {fname}",C.GREEN)

        if self.output in ("csv","both"):
            fname = f"{pfx}.csv"
            fields=["url","status","title","server","technologies","waf","emails","phones",
                    "ips","subdomains","params","forms","html_comments","sensitive_hints",
                    "redirect_chain","social_links","security_headers","secrets","js_endpoints"]
            with open(fname,"w",newline="",encoding="utf-8") as f:
                w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore"); w.writeheader()
                for r in self.results:
                    row=dict(r)
                    for k in ["emails","phones","ips","subdomains","params","technologies","waf",
                              "html_comments","sensitive_hints","redirect_chain","social_links",
                              "secrets","js_endpoints"]:
                        if isinstance(row.get(k),list): row[k]=" | ".join(str(i) for i in row[k])
                    row["forms"]=len(r.get("forms",[])); row["security_headers"]=str(r.get("security_headers",{}))
                    w.writerow(row)
            log("SAVED",f"CSV  → {fname}",C.GREEN)

            if self.fuzz_hits:
                ff=f"{pfx}_fuzz.csv"
                with open(ff,"w",newline="",encoding="utf-8") as f:
                    w=csv.DictWriter(f,fieldnames=["url","status","size","redirect"]); w.writeheader(); w.writerows(self.fuzz_hits)
                log("SAVED",f"CSV  → {ff}",C.GREEN)

            if self.param_hits:
                pf=f"{pfx}_params.csv"
                with open(pf,"w",newline="",encoding="utf-8") as f:
                    w=csv.DictWriter(f,fieldnames=["param","url","status","size","size_diff","interesting"]); w.writeheader(); w.writerows(self.param_hits)
                log("SAVED",f"CSV  → {pf}",C.GREEN)

# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────
def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="ParamSpecter v2.0 — Wordlist Edition",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # ── Core ──────────────────────────────────────────────────
    p.add_argument("url", help="Target URL  e.g. https://example.com")
    p.add_argument("--mode", choices=["crawl","fuzz","param","full"], default="crawl",
                   help=("crawl  → recursive link crawler\n"
                         "fuzz   → wordlist directory/endpoint bruteforce\n"
                         "param  → wordlist parameter discovery\n"
                         "full   → all three phases combined"))

    # ── Crawl ─────────────────────────────────────────────────
    p.add_argument("-m","--max-pages",   type=int,   default=50,   help="Max pages  (default: 50)")
    p.add_argument("-d","--delay",       type=float, default=0.2,  help="Request delay s (default: 0.2)")
    p.add_argument("-D","--depth",       type=int,   default=3,    help="Crawl depth  (default: 3)")
    p.add_argument("-t","--threads",     type=int,   default=10,   help="Threads  (default: 10)")
    p.add_argument("--timeout",          type=int,   default=10,   help="Timeout s (default: 10)")
    p.add_argument("-o","--output",      choices=["json","csv","both"], default="both")
    p.add_argument("--follow-external",  action="store_true", help="Follow external links")
    p.add_argument("--ignore-robots",    action="store_true", help="Ignore robots.txt")
    p.add_argument("-u","--user-agent",  default=None, help="Custom User-Agent")
    p.add_argument("--cookies",          default=None, help='Cookie string: "a=1; b=2"')
    p.add_argument("--headers",          nargs="*",   help='Extra headers: "X-Foo: bar"')

    # ── Wordlist ──────────────────────────────────────────────
    p.add_argument("-w","--wordlist",
                   default=None,
                   help=("Directory/endpoint wordlist path  (fuzz / full)\n"
                         "Built-in list used when omitted."))
    p.add_argument("-pw","--param-wordlist",
                   default=None,
                   help=("Parameter name wordlist path  (param / full)\n"
                         "Built-in list used when omitted."))
    p.add_argument("-x","--extensions",
                   default="",
                   help=('Extensions appended during dir fuzz, comma-sep.\n'
                         'e.g. ".php,.html,.bak"   (default: none)'))
    p.add_argument("--match-codes",
                   default=None,
                   help="Only display these status codes, comma-sep  e.g. 200,301,403")
    p.add_argument("--hide-codes",
                   default="404",
                   help="Hide these status codes  (default: 404)")
    p.add_argument("--param-method",
                   choices=["GET","POST"], default="GET",
                   help="HTTP method for param fuzzing  (default: GET)")

    args = p.parse_args()

    print(f"  {color('WARNING:', C.RED+C.BOLD)} Only test targets you own or have written authorisation to test.\n")
    print(f"  {color('Target     :', C.CYAN)} {args.url}")
    print(f"  {color('Mode       :', C.CYAN)} {args.mode}")
    print(f"  {color('Threads    :', C.CYAN)} {args.threads}")
    print(f"  {color('Delay      :', C.CYAN)} {args.delay}s")
    if args.mode in ("fuzz","full"):
        wl = args.wordlist or f"[built-in {len(BUILTIN_DIRS)} dirs]"
        print(f"  {color('Dir WL     :', C.CYAN)} {wl}")
        print(f"  {color('Extensions :', C.CYAN)} {args.extensions or 'none'}")
    if args.mode in ("param","full"):
        pwl = args.param_wordlist or f"[built-in {len(BUILTIN_PARAMS)} params]"
        print(f"  {color('Param WL   :', C.CYAN)} {pwl}")
        print(f"  {color('Method     :', C.CYAN)} {args.param_method}")
    print(f"\n{color('='*90, C.RED)}\n")

    ParamSpecter(args).run()

if __name__ == "__main__":
    main()
