#!/usr/bin/env python3
"""
ParamSpecter v4.0 -- Advanced Recon Crawler
Advanced Web Crawler for Security Research & Bug Bounty
For authorized and educational use ONLY.

Modes:
  crawl     -- Recursive BFS/DFS crawler with deep analysis
  fuzz      -- Wordlist-based directory/endpoint bruteforce
  param     -- Wordlist-based parameter discovery & fuzzing
  subdomain -- DNS brute-force + cert transparency subdomain enumeration
  full      -- All phases combined

New in v4.0:
  - SubdomainHunter  : DNS brute-force, crt.sh cert transparency, DNS record analysis
  - DirectoryHunter  : Recursive dir enumeration, wildcard detection, size-based dedup
  - Accuracy fixes   : canonical URL normalisation, fragment stripping, mime-type gating,
                       redirect-chain dedup, anchor/mailto filtering, param dedup
"""

import requests, re, sys, json, csv, time, os, argparse
import threading, queue, hashlib, random, signal, textwrap, socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode, quote
from urllib.robotparser import RobotFileParser
from datetime import datetime
from collections import defaultdict
from typing import Optional, Set, Dict, List, Any, Tuple
from dataclasses import dataclass, field

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# -----------------------------------------------------------------
#  ANSI COLORS
# -----------------------------------------------------------------
class C:
    RED     = "\033[91m"; LRED   = "\033[31m"
    GREEN   = "\033[92m"; LGREEN = "\033[32m"
    YELLOW  = "\033[93m"; ORANGE = "\033[33m"
    BLUE    = "\033[94m"; LBLUE  = "\033[34m"
    MAGENTA = "\033[95m"; LMAG   = "\033[35m"
    CYAN    = "\033[96m"; LCYAN  = "\033[36m"
    WHITE   = "\033[97m"; GRAY   = "\033[90m"
    BOLD    = "\033[1m";  DIM    = "\033[2m"
    UNDER   = "\033[4m";  RESET  = "\033[0m"

def col(text, *codes):
    return "".join(codes) + str(text) + C.RESET

def status_color(code):
    if code is None: return col("ERR", C.RED, C.BOLD)
    if code == 200:  return col(code, C.GREEN)
    if code < 300:   return col(code, C.CYAN)
    if code < 400:   return col(code, C.YELLOW)
    if code == 403:  return col(code, C.ORANGE)
    if code == 404:  return col(code, C.GRAY)
    if code < 500:   return col(code, C.RED)
    return col(code, C.RED, C.BOLD)

BANNER = f"""
{C.RED}{C.BOLD}
  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝███████║██████╔╝███████║██╔████╔██║█████╗  ██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║███████╗╚██████╗   ██║   ███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{C.RESET}{C.GRAY}  ParamSpecter v4.0 -- Advanced Recon Crawler | Security Edition
{C.BOLD}{C.CYAN}  Created by Boltx  
{C.RED}{'─'*90}{C.RESET}
"""


# -----------------------------------------------------------------
#  USER-AGENT POOL
# -----------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]

# MIME types worth crawling into
CRAWLABLE_MIME = {"text/html", "text/plain", "application/xhtml+xml", "application/xml"}

# Extensions to skip entirely (binary / media)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".webm", ".ogg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dll", ".so", ".bin",
}


# -----------------------------------------------------------------
#  BUILT-IN WORDLISTS
# -----------------------------------------------------------------
BUILTIN_DIRS = [
    # CMS / Frameworks
    "admin","administrator","login","dashboard","panel","portal","console","manage",
    "management","backend","cms","wp-admin","wp-content","wp-login.php","wp-json",
    "wp-includes","joomla","drupal","typo3","laravel","symfony","rails",
    # API
    "api","v1","v2","v3","v4","rest","graphql","gql","swagger","swagger-ui",
    "swagger.json","openapi.json","openapi.yaml","api-docs","redoc","rpc",
    # Dev / Debug
    "dev","development","staging","test","testing","debug","debugbar","phpinfo.php",
    "info.php","server-status","server-info",".git","git","actuator","metrics",
    "health","healthz","ready","livez","status","monitor","trace",
    # Sensitive files
    ".env",".env.local",".env.production","config","configuration","settings",
    "database","db","sql","phpmyadmin","adminer","backup","backups",
    ".htaccess",".htpasswd","web.config","crossdomain.xml","clientaccesspolicy.xml",
    "security.txt",".well-known","robots.txt","sitemap.xml",
    # Upload / Storage
    "upload","uploads","files","file","media","images","img","static","assets",
    "public","private","storage","data","downloads","export","import",
    # Auth
    "auth","oauth","oauth2","sso","logout","register","signup","forgot",
    "reset","verify","token","session","callback","profile","account","user","users",
    # Infra
    "nginx","apache","grafana","prometheus","kibana","elastic",
    "jenkins","ci","cd","pipeline","k8s","docker","terraform",
    # Old / Hidden
    "old","new","bak","backup","archive","temp","tmp","cache","hidden",
    "internal","secret","legacy","deprecated","_old","_backup",
    # Common endpoints
    "search","query","feed","rss","atom","sitemap","download","report","reports",
    "log","logs","audit","error","errors","exception","exceptions",
    # Extra
    "app","web","src","lib","vendor","includes","modules","plugins",
    "themes","templates","views","cgi-bin","scripts","bin","tools","utils",
]

BUILTIN_PARAMS = [
    "id","uid","uuid","user_id","userid","username","user","name","email","account",
    "token","api_key","apikey","key","secret","auth","password","pass","hash",
    "session","sid","csrf","nonce","state","code","grant","access_token",
    "refresh_token","bearer","jwt",
    "redirect","redirect_uri","redirect_url","return","returnurl","next","url","dest",
    "destination","continue","callback","back","goto","forward","ref","referer",
    "file","filename","path","dir","folder","document","doc","template","include",
    "src","source","load","read","open",
    "q","query","search","s","keyword","keywords","term","terms","find","filter",
    "category","tag","type","status","sort","order","orderby","page","p","limit",
    "offset","start","end","from","to","per_page","size","count","max",
    "data","payload","body","content","input","output","value","val","param",
    "params","field","fields","columns","expand","include","exclude","format",
    "cmd","command","exec","execute","action","op","operation","method","func",
    "function","handler","event","hook","job","task","run","do",
    "host","domain","ip","port","uri","endpoint","server","service","target",
    "debug","test","verbose","trace","log","mode","version","v","lang","locale",
    "country","timezone","currency",
    "date","time","timestamp","created","updated","expires","start_date","end_date",
]

BUILTIN_EXTENSIONS = ["", ".php", ".html", ".asp", ".aspx", ".jsp",
                      ".json", ".xml", ".txt", ".bak", ".old", ".config",
                      ".yml", ".yaml", ".env"]

# Subdomain wordlist
BUILTIN_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","vpn","ssh",
    "dev","development","staging","test","testing","uat","qa","sandbox","demo",
    "api","api2","v1","v2","rest","graphql","ws","websocket","socket",
    "admin","administrator","panel","dashboard","portal","manage","manager",
    "app","apps","web","backend","frontend","static","assets","cdn","media",
    "img","images","files","upload","uploads","download","downloads","store",
    "shop","blog","forum","wiki","docs","support","help","status","monitor",
    "metrics","grafana","kibana","prometheus","jenkins","ci","gitlab","git",
    "jira","confluence","redmine","sonar","nexus","artifactory","registry",
    "db","database","mysql","postgres","mongo","redis","elastic","search",
    "internal","intranet","private","corp","office","employees","staff",
    "proxy","gateway","router","firewall","lb","loadbalancer",
    "auth","login","sso","oauth","id","identity","account","accounts",
    "old","legacy","backup","archive","temp","tmp","new","beta","alpha",
    "mobile","m","ios","android","wap",
    "ns","ns1","ns2","dns","dns1","dns2","mx","mx1","mx2",
    "autodiscover","autoconfig","cpanel","whm","plesk","ftp2",
    "secure","encrypted","vpn2","remote2","access","connect",
    "chat","im","meet","conference","video","voip",
    "pay","payment","billing","invoice","shop2","store2","checkout",
    "news","press","media2","assets2","cdn2","dl","update","updates",
]


# -----------------------------------------------------------------
#  DETECTION PATTERNS
# -----------------------------------------------------------------
SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})'), "API Key"),
    (re.compile(r'(?i)(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\']?([a-zA-Z0-9_\-+/=]{8,})'), "Secret/Token"),
    (re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)'), "Bearer Token"),
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Access Key"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API Key"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "GitHub PAT"),
    (re.compile(r'(sk-[a-zA-Z0-9]{48})'), "OpenAI Key"),
    (re.compile(r'(?i)-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'), "Private Key"),
    (re.compile(r'(?i)(?:jdbc|mysql|postgres|mongodb|redis)://[^\s"\'<>]+'), "DB Connection String"),
    (re.compile(r'(?i)(?:slack|discord|telegram).*(?:token|webhook)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})'), "Chat Token"),
]

PATTERNS = {
    "email":       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I),
    "phone":       re.compile(r"(?:\+?\d[\d\s\-().]{7,}\d)"),
    "ipv4":        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv6":        re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "subdomain":   re.compile(r"https?://([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+)", re.I),
    "comment":     re.compile(r"<!--(.*?)-->", re.DOTALL),
    "js_src":      re.compile(r'<script[^>]*\ssrc=["\'](.*?)["\']', re.I),
    "js_url":      re.compile(r"""(?:['"`])(https?://[^\s'"`<>]{10,})(?:['"`])"""),
    "aws_key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_key":     re.compile(r'(?:api[_\-]?key|apikey|secret)\s*[:=]\s*["\'\\w\-]{8,}', re.I),
    "sourcemap":   re.compile(r'//# sourceMappingURL=(.+\.map)'),
    "endpoints":   re.compile(r"""['"`](/(?:api|v\d+|admin|auth|user|graphql|rest)[^\s'"`<>]*)['"`]""", re.I),
    "jwt":         re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
    "uuid":        re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    "internal_ip": re.compile(r'\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b'),
}

SOCIAL_DOMAINS = {"facebook.com","twitter.com","x.com","linkedin.com","instagram.com",
                  "github.com","youtube.com","tiktok.com","t.me","discord.gg","reddit.com"}

TECH_SIGNATURES = {
    "WordPress":  [re.compile(r"wp-content|wp-includes|WordPress", re.I)],
    "Joomla":     [re.compile(r"Joomla|/components/com_", re.I)],
    "Drupal":     [re.compile(r"Drupal|/sites/default/files", re.I)],
    "React":      [re.compile(r"react(?:\.min)?\.js|__REACT|_reactRootContainer|react-dom", re.I)],
    "Next.js":    [re.compile(r"__next|_next/static|next\.config", re.I)],
    "Nuxt.js":    [re.compile(r"__nuxt|_nuxt/|nuxt\.config", re.I)],
    "Angular":    [re.compile(r"ng-version|angular(?:\.min)?\.js|ng-app", re.I)],
    "Vue.js":     [re.compile(r"vue(?:\.min)?\.js|__vue__|v-app|data-v-", re.I)],
    "jQuery":     [re.compile(r"jquery(?:\.min)?\.js|jQuery", re.I)],
    "Bootstrap":  [re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I)],
    "Tailwind":   [re.compile(r"tailwind(?:css)?|tw-", re.I)],
    "Cloudflare": [re.compile(r"cloudflare|cf-ray|__cfduid", re.I)],
    "AWS":        [re.compile(r"amazonaws\.com|x-amz-|CloudFront", re.I)],
    "GCP":        [re.compile(r"googleapis\.com|storage\.cloud\.google", re.I)],
    "PHP":        [re.compile(r"\.php|X-Powered-By: PHP|PHPSESSID", re.I)],
    "ASP.NET":    [re.compile(r"__VIEWSTATE|ASP\.NET|\.aspx|X-AspNet", re.I)],
    "Django":     [re.compile(r"csrfmiddlewaretoken|Django|djdt", re.I)],
    "Laravel":    [re.compile(r"laravel_session|Laravel|X-Powered-By: PHP", re.I)],
    "Express.js": [re.compile(r"X-Powered-By: Express", re.I)],
    "FastAPI":    [re.compile(r"FastAPI|openapi\.json|/docs", re.I)],
    "Spring":     [re.compile(r"X-Application-Context|Spring", re.I)],
    "GraphQL":    [re.compile(r"graphql|__schema|__typename", re.I)],
    "Nginx":      [re.compile(r"nginx", re.I)],
    "Apache":     [re.compile(r"Apache|mod_", re.I)],
    "IIS":        [re.compile(r"IIS|ASP\.NET|Microsoft-IIS", re.I)],
}

WAF_SIGNATURES = {
    "Cloudflare":  re.compile(r"cloudflare|cf-ray|Attention Required|DDoS protection", re.I),
    "AWS WAF":     re.compile(r"x-amzn-RequestId|awselb|aws-waf", re.I),
    "Akamai":      re.compile(r"akamai|akamaighhost|Ref.*akamai", re.I),
    "Sucuri":      re.compile(r"sucuri|cloudproxy|X-Sucuri", re.I),
    "Incapsula":   re.compile(r"incapsula|visid_incap|X-CDN: Incapsula", re.I),
    "ModSecurity": re.compile(r"mod_security|modsec|NOYB", re.I),
    "Imperva":     re.compile(r"imperva|X-Iinfo", re.I),
    "F5 BIG-IP":   re.compile(r"bigip|F5|TS[a-zA-Z0-9]{8}", re.I),
    "Barracuda":   re.compile(r"barracuda|barra", re.I),
    "Fortinet":    re.compile(r"fortiweb|FORTIWAFSID", re.I),
}

CAPTCHA_PATTERNS = [
    re.compile(r"captcha|recaptcha|hcaptcha|turnstile|arkose", re.I),
    re.compile(r"g-recaptcha|data-sitekey", re.I),
]

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
    "Permissions-Policy", "X-XSS-Protection",
]

INTERESTING_HEADER_LEAKS = [
    "X-Powered-By", "Server", "X-AspNet-Version", "X-Backend-Server",
    "X-Forwarded-For", "X-Real-IP", "X-Debug-Token",
]


# -----------------------------------------------------------------
#  LOGGING
# -----------------------------------------------------------------
_log_lock = threading.Lock()

def ts():
    return col(datetime.now().strftime("%H:%M:%S"), C.GRAY)

def log(prefix, msg, pcolor=C.WHITE):
    with _log_lock:
        print(f"  {ts()}  {col(prefix, pcolor)}  {msg}")

def log_section(title):
    with _log_lock:
        print(f"\n{col('─'*60, C.RED)}")
        print(f"  {col('>> ' + title, C.BOLD+C.CYAN)}")
        print(col('─'*60, C.RED))


# -----------------------------------------------------------------
#  URL HELPERS  (accuracy improvements)
# -----------------------------------------------------------------
def normalize_url(url: str, parent: str = "") -> Optional[str]:
    """
    Resolve, normalize, and canonicalize a URL.
    - Strips fragments (#...)
    - Skips mailto:, javascript:, tel:, data: schemes
    - Strips default ports (80 for http, 443 for https)
    - Lowercases scheme and host
    - Normalizes duplicate slashes in path
    - Skips binary/media extensions
    """
    try:
        full = urljoin(parent, url.strip())
        p = urlparse(full)

        if p.scheme not in ("http", "https"):
            return None

        # Strip fragment
        path = p.path or "/"
        # Collapse consecutive slashes but keep leading slash
        path = re.sub(r"/{2,}", "/", path)
        # Remove trailing slash except root
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        # Check extension
        ext = os.path.splitext(path.split("?")[0])[1].lower()
        if ext in SKIP_EXTENSIONS:
            return None

        # Strip default ports
        host = p.hostname or ""
        port = p.port
        if (p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host

        # Sort query params for consistent dedup
        if p.query:
            params = sorted(parse_qs(p.query, keep_blank_values=True).items())
            query = urlencode(params, doseq=True)
        else:
            query = ""

        return urlunparse((p.scheme.lower(), netloc.lower(), path, "", query, ""))
    except Exception:
        return None


def is_same_domain(url: str, base_domain: str) -> bool:
    """True if url host equals base_domain or is a subdomain of it."""
    try:
        host = urlparse(url).hostname or ""
        return host == base_domain or host.endswith("." + base_domain)
    except Exception:
        return False


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def load_wordlist(path: Optional[str], default: List[str]) -> List[str]:
    if not path:
        return default
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        print(col(f"  [!] Wordlist not found: {path}", C.RED))
        sys.exit(1)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    log("+WL", f"Loaded {col(len(words), C.BOLD)} words from {col(path, C.CYAN)}", C.GREEN)
    return words


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
            return resp, None
        except requests.exceptions.ConnectionError as e:
            err = f"ConnectionError: {e}"
        except requests.exceptions.Timeout:
            err = "Timeout"
        except requests.exceptions.TooManyRedirects:
            err = "TooManyRedirects"
        except Exception as e:
            err = str(e)
        if attempt < max_retries:
            jitter = random.uniform(0, 0.3) * delay
            time.sleep(delay + jitter)
            delay = min(delay * 2, 16)
    return None, err


# -----------------------------------------------------------------
#  ROBOTS.TXT + SITEMAP
# -----------------------------------------------------------------
class RobotsTxtHandler:
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
                self.rp.read()
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

    def extract_sitemap_urls(self, session) -> List[str]:
        urls = []
        for sm in self.sitemaps:
            try:
                resp, _ = fetch_with_retry(session, sm, timeout=10)
                if resp and resp.status_code == 200:
                    found = re.findall(r"<loc>(.*?)</loc>", resp.text, re.I)
                    urls.extend(found)
            except Exception:
                pass
        return urls


# -----------------------------------------------------------------
#  JS ANALYZER
# -----------------------------------------------------------------
class JSAnalyzer:
    EP_PATTERN = re.compile(
        r"""['"` ](/(?:api|v\d+|admin|auth|user|account|graphql|rest|internal|hidden|debug|config|manage)[^\s'"` <>]*)['"` ]""",
        re.I
    )
    INTERESTING_VARS = re.compile(
        r"""(?:const|let|var)\s+(\w+)\s*=\s*['"`]([^'"`\n]{6,})['"`]""", re.I
    )

    def __init__(self, session, rotate_ua=False):
        self.session = session
        self.rotate_ua = rotate_ua

    def analyze(self, js_src_list: List[str], page_url: str):
        endpoints: Set[str] = set()
        secrets: List[Dict] = []
        sourcemaps: List[str] = []

        for js_url in js_src_list:
            full_url = urljoin(page_url, js_url)
            resp, err = fetch_with_retry(self.session, full_url, timeout=8,
                                         rotate_ua=self.rotate_ua)
            if not resp or resp.status_code != 200:
                continue

            text = resp.text

            for m in self.EP_PATTERN.finditer(text):
                ep = m.group(1).split("?")[0]
                if 1 < len(ep) < 200:
                    endpoints.add(ep)

            for pat, label in SECRET_PATTERNS:
                for m in pat.finditer(text):
                    val = m.group(1) if m.lastindex else m.group(0)
                    if len(val) > 6:
                        secrets.append({"type": label, "value": val[:80], "source": full_url})

            for m in self.INTERESTING_VARS.finditer(text):
                vname, vval = m.group(1), m.group(2)
                if any(kw in vname.lower() for kw in
                       ["url", "host", "endpoint", "base", "api", "key", "secret", "token"]):
                    secrets.append({"type": f"JS var: {vname}", "value": vval[:80], "source": full_url})

            for m in PATTERNS["sourcemap"].finditer(text):
                sourcemaps.append(urljoin(full_url, m.group(1)))

            for m in PATTERNS["jwt"].finditer(text):
                secrets.append({"type": "JWT token", "value": m.group(0)[:80], "source": full_url})

        return list(endpoints), secrets, sourcemaps


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
    }

    # Meta
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

    # Security headers
    for h in SECURITY_HEADERS:
        v = resp.headers.get(h)
        if v:
            data["security_headers"][h] = v

    # Leaked headers
    for h in INTERESTING_HEADER_LEAKS:
        v = resp.headers.get(h)
        if v:
            data["leaked_headers"][h] = v

    # Cookies
    for ck in resp.cookies:
        flags = []
        if not ck.has_nonstandard_attr("HttpOnly"):
            flags.append("NO_HTTPONLY")
        if not ck.has_nonstandard_attr("Secure"):
            flags.append("NO_SECURE")
        if not ck.has_nonstandard_attr("SameSite"):
            flags.append("NO_SAMESITE")
        data["cookies"][ck.name] = {"value": ck.value[:40], "flags": flags}

    # Links -- improved: skip anchor-only, mailto, tel, javascript hrefs
    if soup:
        base_domain = urlparse(url).netloc
        seen_links: Set[str] = set()
        for tag in soup.find_all("a", href=True):
            raw_href = tag["href"].strip()
            # skip non-navigable hrefs
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

    # Pattern extraction
    data["emails"]        = list(set(PATTERNS["email"].findall(raw_html)))
    data["phones"]        = list(set(PATTERNS["phone"].findall(raw_html)))
    data["ips"]           = list(set(PATTERNS["ipv4"].findall(raw_html)))
    data["internal_ips"]  = list(set(PATTERNS["internal_ip"].findall(raw_html)))
    data["subdomains"]    = list(set(PATTERNS["subdomain"].findall(raw_html)))
    data["js_src"]        = list(set(PATTERNS["js_src"].findall(raw_html)))
    data["js_urls"]       = list(set(PATTERNS["js_url"].findall(raw_html)))
    data["html_comments"] = [c.strip() for c in PATTERNS["comment"].findall(raw_html) if c.strip()]

    # Captcha detection
    combined = raw_html + str(resp.headers)
    for cp in CAPTCHA_PATTERNS:
        if cp.search(combined):
            data["captcha_detected"] = True
            break

    # Internal paths
    data["internal_paths"] = list(set(re.findall(
        r'(?:src|href|action|data-url|data-src)=["\']([ ^"\'<>]{2,})["\']', raw_html
    )))

    # Forms
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

    # URL params -- deduplicated across all links
    param_set: Set[str] = set()
    for u in [url] + data["links"] + data["external_links"]:
        for k in parse_qs(urlparse(u).query, keep_blank_values=True):
            param_set.add(k)
    data["params"] = sorted(param_set)

    # Technology fingerprinting
    check_text = raw_html + str(resp.headers)
    for tech, sigs in TECH_SIGNATURES.items():
        if any(s.search(check_text) for s in sigs):
            data["technologies"].append(tech)

    # WAF fingerprinting
    waf_text = str(resp.headers) + raw_html[:3000]
    for waf_name, sig in WAF_SIGNATURES.items():
        if sig.search(waf_text):
            data["waf"].append(waf_name)

    # JS analysis
    ep, sec, sm = js_analyzer.analyze(data["js_src"], url)
    data["js_endpoints"] = sorted(ep)
    data["js_secrets"]   = sec
    data["sourcemaps"]   = sm

    # Inline secret scanning
    for pat, label in SECRET_PATTERNS:
        for m in pat.finditer(raw_html):
            val = m.group(1) if m.lastindex else m.group(0)
            if len(val) > 6:
                data["js_secrets"].append({"type": label, "value": val[:80], "source": url})

    # Interesting
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
    for cookie_name, cookie_info in data["cookies"].items():
        if cookie_info["flags"]:
            data["interesting"].append(f"Cookie '{cookie_name}' missing flags: {cookie_info['flags']}")
    if "X-Powered-By" in data["leaked_headers"]:
        data["interesting"].append(f"Tech leak: X-Powered-By: {data['leaked_headers']['X-Powered-By']}")

    return data


# -----------------------------------------------------------------
#  CRAWL QUEUE
# -----------------------------------------------------------------
class CrawlQueue:
    def __init__(self, strategy="bfs"):
        self.strategy = strategy
        if strategy == "bfs":
            self._q = queue.Queue()
        elif strategy == "dfs":
            self._q = queue.LifoQueue()
        else:
            self._q = queue.PriorityQueue()
        self._lock = threading.Lock()

    def put(self, item, priority=0):
        if self.strategy == "priority":
            self._q.put((priority, item))
        else:
            self._q.put(item)

    def get(self, timeout=3):
        if self.strategy == "priority":
            _, item = self._q.get(timeout=timeout)
            return item
        return self._q.get(timeout=timeout)

    def task_done(self):
        self._q.task_done()

    def join(self):
        self._q.join()

    def qsize(self):
        return self._q.qsize()


# -----------------------------------------------------------------
#  PROXY MANAGER
# -----------------------------------------------------------------
class ProxyManager:
    def __init__(self, proxy_list: List[str]):
        self.proxies = proxy_list
        self._idx = 0
        self._lock = threading.Lock()

    def next(self) -> Optional[Dict]:
        if not self.proxies:
            return None
        with self._lock:
            p = self.proxies[self._idx % len(self.proxies)]
            self._idx += 1
        return {"http": p, "https": p}


# -----------------------------------------------------------------
#  STATS
# -----------------------------------------------------------------
@dataclass
class CrawlStats:
    pages_crawled:    int = 0
    pages_failed:     int = 0
    links_found:      int = 0
    emails_found:     int = 0
    secrets_found:    int = 0
    forms_found:      int = 0
    params_found:     int = 0
    fuzz_hits:        int = 0
    param_hits:       int = 0
    subdomains_found: int = 0
    dir_hits:         int = 0
    status_codes:     Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    start_time:       datetime = field(default_factory=datetime.now)

    def elapsed(self) -> str:
        secs = int((datetime.now() - self.start_time).total_seconds())
        return f"{secs // 60}m{secs % 60}s"


# -----------------------------------------------------------------
#  SUBDOMAIN HUNTER  (v4.0 new feature)
# -----------------------------------------------------------------
class SubdomainHunter:
    """
    Discovers subdomains via three methods:
      1. DNS brute-force against a wordlist
      2. Certificate Transparency logs (crt.sh)
      3. DNS record types: A, AAAA, MX, NS, TXT, CNAME
    """

    CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"

    def __init__(self, domain: str, wordlist: List[str], threads: int,
                 timeout: int, session, results_out: List[Dict]):
        self.domain      = domain.lstrip("*.").lower()
        self.wordlist    = wordlist
        self.threads     = threads
        self.timeout     = timeout
        self.session     = session
        self.results_out = results_out
        self._found: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    # -- DNS brute-force --
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
        while True:
            try:
                word = q.get(timeout=2)
            except queue.Empty:
                break
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
            q.task_done()

    def _run_brute(self):
        log_section("SUBDOMAIN BRUTE-FORCE")
        log("SUB", f"Wordlist: {col(len(self.wordlist), C.BOLD)} entries against {col(self.domain, C.CYAN)}", C.CYAN)

        # Wildcard detection -- resolves a random non-existent name
        wildcard_ip = self._resolve(f"this-should-not-exist-12345.{self.domain}")
        if wildcard_ip:
            log("SUB", col(f"WARNING: Wildcard DNS detected ({wildcard_ip}) -- results may include false positives", C.YELLOW), C.YELLOW)

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

    # -- Certificate Transparency --
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
                    if not name.endswith(self.domain):
                        continue
                    if name in seen:
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

    # -- DNS record types --
    def _run_dns_records(self):
        if not DNS_AVAILABLE:
            log("DNS", col("dnspython not installed -- skipping DNS record enumeration", C.YELLOW), C.YELLOW)
            return
        log_section("DNS RECORD ANALYSIS")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=self.timeout)
                vals = [str(r) for r in answers]
                log("DNS", f"{col(rtype, C.YELLOW)}  {col(self.domain, C.CYAN)}  ->  {col(', '.join(vals[:3]), C.WHITE)}", C.CYAN)
            except Exception:
                pass

    # -- HTTP probe discovered subdomains --
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
                                           rotate_ua=True, allow_redirects=True,
                                           max_retries=1)
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

        workers = []
        for entry in items:
            t = threading.Thread(target=probe, args=(entry,), daemon=True)
            workers.append(t)
            t.start()
        for t in workers:
            t.join(timeout=self.timeout + 2)

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


# -----------------------------------------------------------------
#  DIRECTORY HUNTER  (v4.0 new feature)
# -----------------------------------------------------------------
class DirectoryHunter:
    """
    Accurate directory and file enumeration with:
    - Wildcard / soft-404 detection (baseline comparison)
    - Response size deduplication (catches catch-all pages)
    - Configurable match/hide status codes
    - Recursive mode (enumerate discovered directories)
    - Extension probing per word
    - Thread-safe hit accumulation
    """

    def __init__(self, base_url: str, wordlist: List[str], extensions: List[str],
                 threads: int, timeout: int, session, delay: float,
                 match_codes: Optional[Set[int]], hide_codes: Set[int],
                 hits_out: List[Dict], rotate_ua: bool = False,
                 proxy_mgr=None, max_retries: int = 2,
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
        self.rotate_ua   = rotate_ua
        self.proxy_mgr   = proxy_mgr
        self.max_retries = max_retries
        self.recursive   = recursive
        self.max_depth   = max_depth

        self._lock       = threading.Lock()
        self._hits: List[Dict] = []
        self._seen_urls: Set[str] = set()

        # For soft-404/wildcard detection
        self._baseline_len: int = 0
        self._wildcard: bool = False

    # -- Baseline / wildcard --
    def _detect_wildcard(self):
        """
        Request two random non-existent paths.
        If both return non-404 with similar size, assume wildcard responses.
        """
        rand1 = f"{self.base_url}/paramspecter_random_9x7z_{random.randint(10000,99999)}"
        rand2 = f"{self.base_url}/paramspecter_random_2q8w_{random.randint(10000,99999)}"
        sizes = []
        for url in (rand1, rand2):
            resp, _ = fetch_with_retry(self.session, url, timeout=self.timeout,
                                       rotate_ua=self.rotate_ua, max_retries=1,
                                       allow_redirects=False)
            if resp and resp.status_code not in (404, 400, 410):
                sizes.append(len(resp.content))
        if len(sizes) == 2:
            self._wildcard = True
            # Use average size as baseline to detect wildcard matches
            self._baseline_len = sum(sizes) // 2
            log("DIR", col(
                f"Wildcard/catch-all detected (baseline ~{self._baseline_len}B) -- using size filter",
                C.YELLOW), C.YELLOW)
        else:
            self._wildcard = False

    def _is_wildcard_response(self, size: int) -> bool:
        if not self._wildcard or self._baseline_len == 0:
            return False
        # If size is within 5% of baseline, treat as wildcard
        diff = abs(size - self._baseline_len)
        return diff < max(50, int(self._baseline_len * 0.05))

    # -- Worker --
    def _worker(self, q: queue.Queue, total: int, done_ctr: List[int]):
        while True:
            try:
                url = q.get(timeout=2)
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
                    sz = len(resp.content)

                    # Skip if wildcard match
                    if self._is_wildcard_response(sz):
                        q.task_done()
                        time.sleep(self.delay)
                        continue

                    # Apply filters
                    show = True
                    if self.match_codes and code not in self.match_codes:
                        show = False
                    if code in self.hide_codes:
                        show = False

                    # Size-based dedup: skip if we already have a hit with identical size
                    # at the same base path (catches parameterised catch-alls)
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
            except Exception:
                pass
            finally:
                time.sleep(self.delay)
                q.task_done()

    def _enumerate(self, base: str, depth: int = 0):
        if depth > self.max_depth:
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

        # Recursive: go into discovered directories
        if self.recursive and depth < self.max_depth:
            with self._lock:
                new_dirs = [
                    h["url"] for h in self._hits
                    if h["status"] in (200, 301, 302, 403)
                    and not os.path.splitext(urlparse(h["url"]).path)[1]  # no extension = directory
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
        log("DIR", f"Done -- {col(len(self._hits), C.BOLD+C.GREEN)} hits found", C.GREEN)
        return self._hits


# -----------------------------------------------------------------
#  PARAMETER FUZZER
# -----------------------------------------------------------------
class ParamFuzzer:
    FUZZ_VALUES = [
        "paramspecter1337",
        "1",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "{{7*7}}",
    ]

    def __init__(self, target_url, param_list, threads, timeout, session,
                 delay, hits_out, method="GET", rotate_ua=False,
                 proxy_mgr=None, smart_fuzz=False):
        self.target_url = target_url
        self.param_list = param_list
        self.threads    = threads
        self.timeout    = timeout
        self.session    = session
        self.delay      = delay
        self.hits_out   = hits_out
        self.method     = method.upper()
        self.rotate_ua  = rotate_ua
        self.proxy_mgr  = proxy_mgr
        self.smart_fuzz = smart_fuzz
        self._q         = queue.Queue()
        self._lock      = threading.Lock()
        self._done = 0
        self._hits: List[Dict] = []
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
        log("PARAM", f"Starting param fuzz -> {col(total, C.BOLD)} tests via {self.method}", C.CYAN)
        workers = [
            threading.Thread(target=self._worker, args=(total,), daemon=True)
            for _ in range(min(self.threads, total or 1))
        ]
        for w in workers:
            w.start()
        self._q.join()
        log("PARAM", f"Done -- {col(len(self._hits), C.BOLD+C.GREEN)} interesting params found", C.GREEN)
        return self._hits

    def _worker(self, total: int):
        while True:
            try:
                param, fuzz_val = self._q.get(timeout=2)
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
                        flag = col("* INTERESTING " + " ".join(reasons), C.GREEN+C.BOLD)
                        log(f"PARAM {pct:>3}%",
                            f"{status_color(code)}  "
                            f"{col('?'+param+'='+fuzz_val[:20], C.YELLOW)}  {flag}", C.CYAN)
                        hit = {
                            "param": param, "payload": fuzz_val,
                            "url": self.target_url, "status": code,
                            "size": sz, "size_diff": diff,
                            "reflected": reflected, "interesting": True
                        }
                        with self._lock:
                            self._hits.append(hit)
                            self.hits_out.append(hit)
            except Exception:
                pass
            finally:
                time.sleep(self.delay)
                self._q.task_done()


# -----------------------------------------------------------------
#  MAIN CRAWLER
# -----------------------------------------------------------------
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

        # Session
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

        # Proxy manager
        proxy_list = []
        if getattr(args, "proxies", None):
            proxy_list = [p.strip() for p in args.proxies.split(",") if p.strip()]
        self.proxy_mgr = ProxyManager(proxy_list) if proxy_list else None

        # Crawl state
        self.crawl_queue = CrawlQueue(strategy=self.strategy)
        self.crawl_queue.put((self.start_url, 0))
        self.visited: Set[str]        = set()
        self.visited_hashes: Set[str] = set()
        self.visited_lock             = threading.Lock()
        self.results: List[Dict]      = []
        self.results_lock             = threading.Lock()

        # Aggregates
        self.all_emails:     Set[str]   = set()
        self.all_phones:     Set[str]   = set()
        self.all_links:      Set[str]   = set()
        self.all_subdomains: Set[str]   = set()
        self.all_techs:      Set[str]   = set()
        self.all_wafs:       Set[str]   = set()
        self.all_params:     Set[str]   = set()
        self.all_secrets:    List[Dict] = []
        self.all_forms:      int        = 0
        self.all_interesting: List[str] = []
        self.missing_sec_headers: Dict[str, int] = defaultdict(int)

        # Fuzz/subdomain results
        self.fuzz_hits:      List[Dict] = []
        self.param_hits:     List[Dict] = []
        self.subdomain_hits: List[Dict] = []
        self.dir_hits:       List[Dict] = []

        # Stats
        self.stats = CrawlStats()
        self._stop_event = threading.Event()

        # Robots
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

        # JS Analyzer
        self.js_analyzer = JSAnalyzer(self.session, rotate_ua=self.rotate_ua)

        signal.signal(signal.SIGINT, self._handle_sigint)
        self.start_time = datetime.now()

    def _handle_sigint(self, sig, frame):
        log("STOP", col("CTRL+C received -- finishing active requests...", C.YELLOW), C.RED)
        self._stop_event.set()

    # ---- crawl worker ----
    def _crawl_worker(self):
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

            with self.results_lock:
                if self.stats.pages_crawled >= self.max_pages:
                    self.crawl_queue.task_done()
                    break
                self.stats.pages_crawled += 1
                count = self.stats.pages_crawled

            if self.robots and not self.robots.allowed(url):
                log("SKIP", col(url, C.GRAY), C.GRAY)
                self.crawl_queue.task_done()
                continue

            proxies = self.proxy_mgr.next() if self.proxy_mgr else None
            resp, err = fetch_with_retry(
                self.session, url, timeout=self.timeout,
                rotate_ua=self.rotate_ua, proxies=proxies,
                max_retries=self.max_retries, allow_redirects=True
            )

            if resp is None:
                log(f"[{count:>4}]", f"{col('FAIL', C.RED)}  {col(url, C.GRAY)}  ({err})", C.RED)
                with self.results_lock:
                    self.results.append({"url": url, "status": None, "error": err})
                    self.stats.pages_failed += 1
                self.crawl_queue.task_done()
                time.sleep(self.delay)
                continue

            self.stats.status_codes[resp.status_code] += 1

            # Gate on content type -- only parse HTML/text
            ct = resp.headers.get("Content-Type", "")
            raw = ""
            soup = None
            mime = ct.split(";")[0].strip().lower()
            if mime in CRAWLABLE_MIME or "html" in mime:
                try:
                    raw = resp.text
                    soup = BeautifulSoup(raw, "html.parser")
                except Exception:
                    pass

            # Content dedup
            chash = content_hash(raw)
            with self.visited_lock:
                if chash in self.visited_hashes and len(raw) > 200:
                    log(f"[{count:>4}]", f"{col('DUPE', C.GRAY)}  {col(url, C.GRAY)}", C.GRAY)
                    self.crawl_queue.task_done()
                    time.sleep(self.delay)
                    continue
                self.visited_hashes.add(chash)

            pd = analyze_page(url, resp, soup, raw, self.js_analyzer)

            # Print result
            redir_info = f"  -> {resp.url}" if resp.history else ""
            with _log_lock:
                print(f"  {ts()}  {col(f'[{count:>4}]', C.CYAN)}  {status_color(resp.status_code)}  "
                      f"{col(url[:75], C.WHITE)}{col(redir_info, C.YELLOW)}")
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

            # Aggregate
            with self.results_lock:
                self.results.append(pd)
                self.all_emails.update(pd["emails"])
                self.all_phones.update(pd["phones"])
                self.all_links.update(pd["links"])
                self.all_subdomains.update(pd["subdomains"])
                self.all_techs.update(pd["technologies"])
                self.all_wafs.update(pd["waf"])
                self.all_params.update(pd["params"])
                self.all_secrets.extend(pd["js_secrets"])
                self.all_forms += len(pd["forms"])
                self.all_interesting.extend(pd["interesting"])
                self.stats.emails_found  = len(self.all_emails)
                self.stats.secrets_found = len(self.all_secrets)
                self.stats.forms_found   = self.all_forms
                self.stats.params_found  = len(self.all_params)

                for sh in SECURITY_HEADERS:
                    if sh not in pd["security_headers"]:
                        self.missing_sec_headers[sh] += 1

            # Enqueue new links
            if depth < self.depth and ("html" in mime or mime in CRAWLABLE_MIME):
                for link in pd["links"]:
                    with self.visited_lock:
                        if link not in self.visited:
                            if not self.same_domain or is_same_domain(link, self.base_domain):
                                self.crawl_queue.put((link, depth + 1), priority=depth + 1)
                                self.stats.links_found += 1

            time.sleep(self.delay)
            self.crawl_queue.task_done()

    def run_crawl(self):
        workers = [threading.Thread(target=self._crawl_worker, daemon=True)
                   for _ in range(self.threads)]
        for w in workers:
            w.start()
        self.crawl_queue.join()
        for w in workers:
            w.join(timeout=1)

    # ---- directory hunt ----
    def run_dir_hunt(self, base_url=None):
        a = self.args
        wl   = load_wordlist(getattr(a, "wordlist", None), BUILTIN_DIRS)
        exts = [e.strip() for e in a.extensions.split(",")] if a.extensions else [""]
        mc   = set(int(c) for c in a.match_codes.split(",")) if a.match_codes else None
        hc   = set(int(c) for c in a.hide_codes.split(","))  if a.hide_codes  else {404}
        recursive = getattr(a, "recursive", False)
        max_rdepth = getattr(a, "recursive_depth", 2)

        DirectoryHunter(
            base_url or self.start_url, wl, exts,
            a.threads, a.timeout, self.session, a.delay,
            mc, hc, self.dir_hits,
            rotate_ua=self.rotate_ua, proxy_mgr=self.proxy_mgr,
            recursive=recursive, max_depth=max_rdepth,
        ).run()

    # ---- param fuzz ----
    def run_param_fuzz(self, target_url=None):
        a  = self.args
        pl = load_wordlist(getattr(a, "param_wordlist", None), BUILTIN_PARAMS)
        ParamFuzzer(
            target_url or self.start_url, pl,
            a.threads, a.timeout, self.session, a.delay,
            self.param_hits, getattr(a, "param_method", "GET"),
            rotate_ua=self.rotate_ua, proxy_mgr=self.proxy_mgr,
            smart_fuzz=self.smart_fuzz,
        ).run()

    # ---- subdomain hunt ----
    def run_subdomain_hunt(self):
        a  = self.args
        wl = load_wordlist(getattr(a, "sub_wordlist", None), BUILTIN_SUBDOMAINS)
        # Extract root domain (strip leading www/subdomain for brute-force target)
        parts = self.base_domain.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else self.base_domain
        SubdomainHunter(
            root_domain, wl, a.threads,
            a.timeout, self.session, self.subdomain_hits,
        ).run()

    # ---- orchestrate ----
    def run(self):
        mode = self.mode

        if mode in ("crawl", "full"):
            log_section("PHASE 1 -- CRAWLING")
            self.run_crawl()

        if mode in ("subdomain", "full"):
            log_section("PHASE 2 -- SUBDOMAIN ENUMERATION")
            self.run_subdomain_hunt()
            self.stats.subdomains_found = len(self.subdomain_hits)

        if mode in ("fuzz", "full"):
            log_section("PHASE 3 -- DIRECTORY HUNTING")
            targets = {self.start_url}
            if mode == "full" and self.results:
                for r in self.results:
                    p = urlparse(r.get("url", "")).path.rsplit("/", 1)[0]
                    targets.add(self.start_url.rstrip("/") + (p or ""))
            for t in list(targets)[:5]:
                self.run_dir_hunt(base_url=t)
            self.stats.dir_hits = len(self.dir_hits)

        if mode in ("param", "full"):
            log_section("PHASE 4 -- PARAMETER FUZZING")
            targets = [self.start_url]
            if mode == "full":
                param_urls = [r["url"] for r in self.results
                              if r.get("params") and r.get("status") and r["status"] < 400]
                if param_urls:
                    targets = param_urls[:10]
            for t in targets:
                self.run_param_fuzz(target_url=t)

        self.print_summary()
        self.save_results()

    # ---- summary ----
    def print_summary(self):
        dur = self.stats.elapsed()
        print(f"\n{col('='*60, C.RED)}")
        print(col("  SCAN COMPLETE", C.BOLD+C.WHITE))
        print(col("="*60, C.RED))

        rows = [
            ("Target",           self.start_url),
            ("Mode",             self.mode),
            ("Strategy",         self.strategy),
            ("Pages crawled",    self.stats.pages_crawled),
            ("Pages failed",     self.stats.pages_failed),
            ("Links found",      len(self.all_links)),
            ("Emails",           len(self.all_emails)),
            ("Subdomains (crawl)", len(self.all_subdomains)),
            ("Subdomains (hunt)", len(self.subdomain_hits)),
            ("URL Params",       len(self.all_params)),
            ("Forms found",      self.all_forms),
            ("Secrets found",    len(self.all_secrets)),
            ("Dir hits",         len(self.dir_hits)),
            ("Param hits",       len(self.param_hits)),
            ("Technologies",     ", ".join(self.all_techs) or "None"),
            ("WAF",              ", ".join(self.all_wafs)  or "None"),
            ("Duration",         dur),
        ]
        for label, val in rows:
            sev_col = C.RED if label in ("Secrets found", "Pages failed") and val else C.CYAN
            print(f"  {col(label + ':', sev_col):<32} {val}")

        # HTTP breakdown
        if self.stats.status_codes:
            print(f"\n  {col('HTTP Status Breakdown:', C.CYAN)}")
            for code in sorted(self.stats.status_codes):
                bar = "#" * min(self.stats.status_codes[code], 35)
                print(f"    {status_color(code)}  {bar}  ({self.stats.status_codes[code]})")

        # Emails
        if self.all_emails:
            print(f"\n  {col('Emails:', C.CYAN)}")
            for e in sorted(self.all_emails):
                print(f"    {col(e, C.GREEN)}")

        # Params
        if self.all_params:
            print(f"\n  {col('URL Parameters Discovered:', C.CYAN)}")
            for p in sorted(self.all_params):
                print(f"    {col('?'+p, C.YELLOW)}")

        # Secrets
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

        # Subdomain hits
        if self.subdomain_hits:
            print(f"\n  {col('Subdomains Found:', C.CYAN)}")
            for h in sorted(self.subdomain_hits, key=lambda x: x["subdomain"]):
                ip_str  = ", ".join(h.get("ips", [])) or "no-ip"
                st_str  = status_color(h.get("status")) if h.get("status") else col("no-http", C.GRAY)
                print(f"    {col(h['subdomain'], C.CYAN):<50} {ip_str:<20} {st_str}  [{h.get('method','')}]")

        # Dir hits
        if self.dir_hits:
            print(f"\n  {col('Directory / File Hits:', C.CYAN)}")
            for h in self.dir_hits:
                print(f"    {status_color(h['status'])}  {h['url']}  [{h['size']}B]")

        # Param hits
        if self.param_hits:
            print(f"\n  {col('Interesting Parameters:', C.CYAN)}")
            for h in self.param_hits:
                refl = col(" [REFLECTED]", C.RED+C.BOLD) if h.get("reflected") else ""
                print(f"    {status_color(h['status'])}  ?{col(h['param'], C.YELLOW)}"
                      f"  delta:{h['size_diff']}B{refl}")

        # Interesting findings
        if self.all_interesting:
            print(f"\n  {col('[*] Interesting Findings:', C.MAGENTA)}")
            seen: Set[str] = set()
            for item in self.all_interesting:
                if item not in seen:
                    seen.add(item)
                    print(f"    {col('-', C.YELLOW)} {item}")

        # Missing security headers
        if self.missing_sec_headers:
            print(f"\n  {col('Missing Security Headers:', C.YELLOW)}")
            for h, c in sorted(self.missing_sec_headers.items(), key=lambda x: -x[1]):
                print(f"    {col(h, C.RED)}: {c} page(s)")

        print(f"{col('='*60, C.RED)}\n")

    # ---- save ----
    def save_results(self):
        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        pfx = f"paramspecter_{self.base_domain.replace('.','_')}_{ts_str}"

        meta = {
            "target": self.start_url, "mode": self.mode, "strategy": self.strategy,
            "crawled_at": self.start_time.isoformat(),
            "duration": self.stats.elapsed(),
            "total_pages": self.stats.pages_crawled,
            "emails": list(self.all_emails),
            "phones": list(self.all_phones),
            "subdomains_crawl": list(self.all_subdomains),
            "subdomains_hunt": [h["subdomain"] for h in self.subdomain_hits],
            "technologies": list(self.all_techs),
            "waf": list(self.all_wafs),
            "params": list(self.all_params),
            "secrets_count": len(self.all_secrets),
            "missing_security_headers": dict(self.missing_sec_headers),
        }

        if self.output in ("json", "both", "jsonl"):
            fname = f"{pfx}.json"
            with open(fname, "w", encoding="utf-8") as f:
                json.dump({
                    "meta": meta,
                    "pages": self.results,
                    "secrets": self.all_secrets,
                    "fuzz_hits": self.fuzz_hits,
                    "dir_hits": self.dir_hits,
                    "param_hits": self.param_hits,
                    "subdomain_hits": self.subdomain_hits,
                }, f, indent=2, ensure_ascii=False)
            log("SAVED", f"JSON -> {col(fname, C.CYAN)}", C.GREEN)

            if self.output == "jsonl":
                fl = f"{pfx}.jsonl"
                with open(fl, "w", encoding="utf-8") as f:
                    for r in self.results:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")
                log("SAVED", f"JSONL -> {col(fl, C.CYAN)}", C.GREEN)

        if self.output in ("csv", "both"):
            fname = f"{pfx}.csv"
            fields = ["url","status","title","content_type","technologies","waf","emails","phones",
                      "ips","internal_ips","subdomains","params","forms","html_comments",
                      "redirect_chain","social_links","security_headers",
                      "leaked_headers","js_endpoints","sourcemaps","captcha_detected",
                      "content_length","content_hash"]
            with open(fname, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                for r in self.results:
                    row = dict(r)
                    for k in ["emails","phones","ips","internal_ips","subdomains","params",
                              "technologies","waf","html_comments","redirect_chain",
                              "social_links","js_endpoints","sourcemaps"]:
                        if isinstance(row.get(k), list):
                            row[k] = " | ".join(str(i) for i in row[k])
                    row["forms"] = len(r.get("forms", []))
                    row["security_headers"] = str(r.get("security_headers", {}))
                    row["leaked_headers"]   = str(r.get("leaked_headers", {}))
                    w.writerow(row)
            log("SAVED", f"CSV  -> {col(fname, C.CYAN)}", C.GREEN)

            if self.dir_hits:
                df = f"{pfx}_dirs.csv"
                with open(df, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=["url","status","size","redirect"])
                    w.writeheader()
                    w.writerows(self.dir_hits)
                log("SAVED", f"CSV  -> {col(df, C.CYAN)}", C.GREEN)

            if self.param_hits:
                pf = f"{pfx}_params.csv"
                with open(pf, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=["param","payload","url","status","size","size_diff","reflected"])
                    w.writeheader()
                    w.writerows(self.param_hits)
                log("SAVED", f"CSV  -> {col(pf, C.CYAN)}", C.GREEN)

            if self.all_secrets:
                sf = f"{pfx}_secrets.csv"
                with open(sf, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=["type","value","source"])
                    w.writeheader()
                    w.writerows(self.all_secrets)
                log("SAVED", f"CSV  -> {col(sf, C.CYAN)}", C.GREEN)

            if self.subdomain_hits:
                subf = f"{pfx}_subdomains.csv"
                with open(subf, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=["subdomain","ips","method","status","http_url","title"],
                                       extrasaction="ignore")
                    w.writeheader()
                    for h in self.subdomain_hits:
                        row = dict(h)
                        row["ips"] = ", ".join(h.get("ips", []))
                        w.writerow(row)
                log("SAVED", f"CSV  -> {col(subf, C.CYAN)}", C.GREEN)


# -----------------------------------------------------------------
#  CLI
# -----------------------------------------------------------------
def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="ParamSpecter v4.0 -- Advanced Recon Crawler",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python ParamSpecter.py https://example.com --mode crawl
          python ParamSpecter.py https://example.com --mode full -t 20 -d 5
          python ParamSpecter.py https://example.com --mode subdomain
          python ParamSpecter.py https://example.com --mode subdomain --sub-wordlist /path/to/subs.txt
          python ParamSpecter.py https://example.com --mode fuzz -w /path/to/wordlist.txt -x .php,.html --recursive
          python ParamSpecter.py https://example.com --mode param --smart-fuzz
          python ParamSpecter.py https://example.com --strategy dfs --rotate-ua --proxies http://127.0.0.1:8080
        """)
    )

    # Core
    p.add_argument("url", help="Target URL  e.g. https://example.com")
    p.add_argument("--mode",
                   choices=["crawl", "fuzz", "param", "subdomain", "full"],
                   default="crawl",
                   help=("crawl     -> recursive crawler\n"
                         "fuzz      -> directory hunting\n"
                         "param     -> parameter discovery\n"
                         "subdomain -> subdomain enumeration\n"
                         "full      -> all phases"))

    # Crawl
    p.add_argument("-m","--max-pages",    type=int,   default=100, help="Max pages (default: 100)")
    p.add_argument("-d","--delay",        type=float, default=0.2,  help="Request delay s (default: 0.2)")
    p.add_argument("-D","--depth",        type=int,   default=4,    help="Crawl depth (default: 4)")
    p.add_argument("-t","--threads",      type=int,   default=10,   help="Threads (default: 10)")
    p.add_argument("--timeout",           type=int,   default=10,   help="Timeout s (default: 10)")
    p.add_argument("--max-retries",       type=int,   default=3,    help="Max retries per URL (default: 3)")
    p.add_argument("-o","--output",       choices=["json","csv","both","jsonl"], default="both")
    p.add_argument("--follow-external",   action="store_true", help="Follow external links")
    p.add_argument("--ignore-robots",     action="store_true", help="Ignore robots.txt")
    p.add_argument("--rotate-ua",         action="store_true", help="Rotate User-Agent per request")
    p.add_argument("--strategy",          choices=["bfs","dfs","priority"], default="bfs",
                   help="Crawl queue strategy (default: bfs)")

    # Identity
    p.add_argument("-u","--user-agent",   default=None, help="Custom User-Agent string")
    p.add_argument("--cookies",           default=None, help='Cookie string: "a=1; b=2"')
    p.add_argument("--headers",           nargs="*",    help='Extra headers: "X-Custom: value"')
    p.add_argument("--proxies",           default=None, help="Comma-sep proxies: http://127.0.0.1:8080,...")

    # Wordlists
    p.add_argument("-w","--wordlist",        default=None, help="Dir/endpoint wordlist (fuzz/full)")
    p.add_argument("-pw","--param-wordlist", default=None, help="Parameter wordlist (param/full)")
    p.add_argument("-sw","--sub-wordlist",   default=None, help="Subdomain wordlist (subdomain/full)")

    # Directory hunting
    p.add_argument("-x","--extensions",      default="",
                   help='Extensions for dir fuzz e.g. ".php,.html,.bak"')
    p.add_argument("--match-codes",   default=None,  help="Show only these codes e.g. 200,301,403")
    p.add_argument("--hide-codes",    default="404", help="Hide these codes (default: 404)")
    p.add_argument("--recursive",     action="store_true",
                   help="Recursively enumerate discovered directories")
    p.add_argument("--recursive-depth", type=int, default=2,
                   help="Max recursion depth for directory hunting (default: 2)")

    # Param fuzzing
    p.add_argument("--param-method", choices=["GET","POST"], default="GET")
    p.add_argument("--smart-fuzz",   action="store_true",
                   help="Test multiple payloads per param (SQLi, XSS, SSRF...)")

    args = p.parse_args()

    # Print config
    print(f"  {col('WARNING:', C.RED+C.BOLD)} Only test targets you own or have written authorisation to test.\n")
    print(f"  {col('Target        :', C.CYAN)} {args.url}")
    print(f"  {col('Mode          :', C.CYAN)} {args.mode}")
    print(f"  {col('Strategy      :', C.CYAN)} {args.strategy}")
    print(f"  {col('Threads       :', C.CYAN)} {args.threads}")
    print(f"  {col('Depth         :', C.CYAN)} {args.depth}")
    print(f"  {col('Delay         :', C.CYAN)} {args.delay}s")
    print(f"  {col('Max Pages     :', C.CYAN)} {args.max_pages}")
    print(f"  {col('Max Retry     :', C.CYAN)} {args.max_retries}")
    print(f"  {col('Rotate UA     :', C.CYAN)} {args.rotate_ua}")
    print(f"  {col('Recursive Dir :', C.CYAN)} {args.recursive} (depth {args.recursive_depth})")
    if args.proxies:
        print(f"  {col('Proxies       :', C.CYAN)} {args.proxies}")
    if args.smart_fuzz:
        print(f"  {col('Smart Fuzz    :', C.CYAN)} ON (multi-payload mode)")
    if not DNS_AVAILABLE:
        print(f"  {col('DNS lib       :', C.YELLOW)} dnspython not installed (pip install dnspython) -- using socket fallback")
    print(f"\n{col('='*60, C.RED)}\n")

    ParamSpecter(args).run()


if __name__ == "__main__":
    main()
