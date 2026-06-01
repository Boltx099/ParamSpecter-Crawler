#!/usr/bin/env python3
"""
ParamSpecter v6.0 -- Advanced Recon Crawler
Advanced Web Crawler for Security Research & Bug Bounty
For authorized and educational use ONLY.

Modes:
  crawl     -- Recursive BFS/DFS crawler with deep analysis
  fuzz      -- Wordlist-based directory/endpoint bruteforce
  param     -- Wordlist-based parameter discovery & fuzzing
  subdomain -- DNS brute-force + cert transparency subdomain enumeration
  full      -- All phases combined

New in v6.0:
  - Retry with exponential backoff on transient errors (ConnectionReset, 503, 429)
  - Input validation & sanitisation on URL and file arguments
  - Configurable output verbosity (--quiet / --verbose)
  - Per-phase timing & request-rate telemetry in the summary
  - OpenAPI / Swagger endpoint auto-discovery during crawl
  - robots.txt sitemap depth cap to prevent infinite sitemap chains
  - tqdm progress bars for fuzz, param, and subdomain phases
  - JSONL streaming writes (never buffer the full results list in RAM)
  - CWE cross-reference on deep-fuzz findings
  - Graceful degrade when optional deps (playwright, dnspython, tqdm) absent
"""

import requests, re, sys, json, csv, time, os, argparse
import threading, queue, hashlib, random, signal, textwrap, socket, statistics, tempfile
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

try:
    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from tqdm import tqdm as _tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


# -----------------------------------------------------------------
#  VERBOSITY LEVEL  (set once in main(), read everywhere)
# -----------------------------------------------------------------
class _Verbosity:
    level: int = 1   # 0=quiet, 1=normal, 2=verbose

VERBOSITY = _Verbosity()


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

# -----------------------------------------------------------------
#  BANNER
# -----------------------------------------------------------------

_SPIDER_ART = [
    '                        /\\  .-"""-  /\\',
    '                       //\\\\/  ,,,  \\//\\\\',
    '                       |/\\| ,;;;;;, |/\\|',
    '                       //\\\\\\;-"""-;///\\\\',
    '                      //  \\/   .   \\/  \\\\',
    '                     (| ,-_| \\ | / |_-, |)',
    '                       //`__\\.-.-./__`\\\\',
    '                      // /.-(() ())-.\\  \\\\',
    '                     (\\ |)   \'---\'   (| /)',
    "                      ` (|           |) `",
    '                        \\)           (/v',
]

BANNER = (
    C.RED + C.BOLD +
    "\n"
    "  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗\n"
    "  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n"
    "  ██████╔╝███████║██████╔╝███████║██╔████╔██║█████╗  ██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝\n"
    "  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗\n"
    "  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║███████╗╚██████╗   ██║   ███████╗██║  ██║\n"
    "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
    "\n" +
    "\n".join(_SPIDER_ART) + "\n" +
    C.RESET +
    C.GRAY  + "\n  ParamSpecter v6.0 -- Advanced Recon Crawler | Security Edition\n" +
    C.BOLD  + C.CYAN + "  Created by Boltx\n" +
    C.RED   + "─" * 90 + C.RESET + "\n"
)

def print_banner():
    print(BANNER)


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

# HTTP status codes that are transient / server-side and worth retrying
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


# -----------------------------------------------------------------
#  INPUT VALIDATION
# -----------------------------------------------------------------
def validate_url(url: str) -> str:
    """
    Validate that *url* is an absolute HTTP/HTTPS URL.
    Raises SystemExit with a clear message on failure.
    """
    try:
        p = urlparse(url)
    except Exception:
        print(col(f"  [!] Invalid URL: {url!r}", C.RED))
        sys.exit(1)
    if p.scheme not in ("http", "https"):
        print(col(f"  [!] URL must begin with http:// or https://, got: {url!r}", C.RED))
        sys.exit(1)
    if not p.netloc:
        print(col(f"  [!] URL has no host: {url!r}", C.RED))
        sys.exit(1)
    return url


def validate_file_arg(path: Optional[str], label: str) -> Optional[str]:
    """Return *path* if it exists and is readable, else exit with an error."""
    if path is None:
        return None
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        print(col(f"  [!] {label} not found: {path}", C.RED))
        sys.exit(1)
    if not os.access(path, os.R_OK):
        print(col(f"  [!] {label} is not readable: {path}", C.RED))
        sys.exit(1)
    return path


def validate_output_dir(path: str) -> str:
    """Create *path* if it doesn't exist; exit if it cannot be created or is not writable."""
    path = os.path.expanduser(path)
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        print(col(f"  [!] Cannot create output directory {path!r}: {e}", C.RED))
        sys.exit(1)
    if not os.access(path, os.W_OK):
        print(col(f"  [!] Output directory is not writable: {path}", C.RED))
        sys.exit(1)
    return path


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
    "js_url":      re.compile(r"""(?:['\"`])(https?://[^\s'"`<>]{10,})(?:['\"`])"""),
    "aws_key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_key":     re.compile(r'(?:api[_\-]?key|apikey|secret)\s*[:=]\s*["\'\\w\-]{8,}', re.I),
    "sourcemap":   re.compile(r'//# sourceMappingURL=(.+\.map)'),
    "endpoints":   re.compile(r"""['\"`](/(?:api|v\d+|admin|auth|user|graphql|rest)[^\s'"`<>]*)['\"`]""", re.I),
    "jwt":         re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
    "uuid":        re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    "internal_ip": re.compile(r'\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b'),
    # NEW: OpenAPI / Swagger spec file locations often referenced in HTML
    "openapi":     re.compile(r'(?:href|src|url)\s*=\s*["\']((?:[^"\']*/)(?:swagger|openapi)[^"\'\s]*\.(?:json|yaml))["\']', re.I),
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

# CWE references for deep-fuzz findings (NEW in v6.0)
_CWE_MAP: Dict[str, str] = {
    "SQLi":            "CWE-89 (SQL Injection)",
    "XSS":             "CWE-79 (Cross-site Scripting)",
    "PathTraversal":   "CWE-22 (Path Traversal)",
    "SSRF":            "CWE-918 (SSRF)",
    "OpenRedirect":    "CWE-601 (Open Redirect)",
    "HeaderInjection": "CWE-113 (HTTP Response Splitting)",
    "IDOR":            "CWE-639 (IDOR)",
}


# -----------------------------------------------------------------
#  LOGGING
# -----------------------------------------------------------------
_log_lock = threading.Lock()

def ts():
    return col(datetime.now().strftime("%H:%M:%S"), C.GRAY)

def log(prefix, msg, pcolor=C.WHITE, min_level: int = 1):
    """Print a log line if VERBOSITY.level >= min_level."""
    if VERBOSITY.level < min_level:
        return
    with _log_lock:
        print(f"  {ts()}  {col(prefix, pcolor)}  {msg}")

def log_section(title):
    if VERBOSITY.level < 1:
        return
    with _log_lock:
        print(f"\n{col('─'*60, C.RED)}")
        print(f"  {col('>> ' + title, C.BOLD+C.CYAN)}")
        print(col('─'*60, C.RED))

def vlog(prefix, msg, pcolor=C.WHITE):
    """Verbose-only log (level 2)."""
    log(prefix, msg, pcolor, min_level=2)


# -----------------------------------------------------------------
#  URL HELPERS
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

        path = p.path or "/"
        path = re.sub(r"/{2,}", "/", path)
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        ext = os.path.splitext(path.split("?")[0])[1].lower()
        if ext in SKIP_EXTENSIONS:
            return None

        host = p.hostname or ""
        port = p.port
        if (p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443):
            netloc = host
        elif port:
            netloc = f"{host}:{port}"
        else:
            netloc = host

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


_VOLATILE_PATTERNS = [
    re.compile(r"csrfmiddlewaretoken\b[^>]{0,80}value=[\"'][^\"']{10,64}[\"']", re.I),
    re.compile(r"name=[\"'](?:_token|authenticity_token|csrf_token)[\"'][^>]*value=[\"'][^\"']{10,}[\"']", re.I),
    re.compile(r"(?<=[=:\"])" r"(?:nonce|_csrf|xsrf)[^\"\s&]{16,}", re.I),
    re.compile(r"(?<!\d)\d{13}(?!\d)"),
    re.compile(r"(?<=[=\"'])([0-9a-f]{40,64})(?=[\"'\s&]|$)", re.I),
]

def content_hash(text: str) -> str:
    """Hash page content after stripping volatile dynamic tokens for stable dedup."""
    stripped = text
    for pat in _VOLATILE_PATTERNS:
        stripped = pat.sub("", stripped)
    return hashlib.sha256(stripped.encode("utf-8", errors="ignore")).hexdigest()[:16]


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def load_wordlist(path: Optional[str], default: List[str]) -> List[str]:
    if not path:
        return default
    path = validate_file_arg(path, "Wordlist")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    log("+WL", f"Loaded {col(len(words), C.BOLD)} words from {col(path, C.CYAN)}", C.GREEN)
    return words


# -----------------------------------------------------------------
#  RETRY / HTTP
# -----------------------------------------------------------------
def fetch_with_retry(session, url, method="GET", data=None, max_retries=3,
                     timeout=10, rotate_ua=False, proxies=None, **kwargs):
    """
    Send an HTTP request with exponential back-off retry.

    Retries on:
      - Network-level exceptions (ConnectionError, Timeout, ConnectionReset)
      - HTTP 429, 500, 502, 503, 504 (transient server errors)

    Respects the Retry-After header on 429 responses.
    Returns (response, None) on success, (None, error_string) on exhausted retries.
    """
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
            # Transient server errors -- retry with back-off
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
#  PLAYWRIGHT FETCH  (per-thread context, XHR interception)
# -----------------------------------------------------------------
_pw_local = threading.local()

def _get_thread_context(pw_browser):
    """Return (or lazily create) a browser context for the calling thread."""
    if not hasattr(_pw_local, "context") or _pw_local.context is None:
        _pw_local.context = pw_browser.new_context(
            user_agent=random_ua(),
            ignore_https_errors=True,
        )
    return _pw_local.context


def fetch_with_playwright(pw_browser, url, timeout=10, xhr_queue=None):
    """
    Fetch *url* using a headless Chromium page owned by the calling thread.
    Each thread gets its own BrowserContext via _get_thread_context.
    Intercepted XHR/fetch URLs are appended to xhr_queue if provided.
    Returns (html, final_url) or raises on failure.
    """
    ctx = _get_thread_context(pw_browser)
    page = ctx.new_page()
    intercepted: List[str] = []

    def _on_request(request):
        rtype = request.resource_type
        if rtype in ("xhr", "fetch"):
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
#  ROBOTS.TXT + SITEMAP
# -----------------------------------------------------------------
class RobotsTxtHandler:
    # Cap how many sitemap hops we follow to prevent sitemap-index loops
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

    def extract_sitemap_urls(self, session, depth: int = 0) -> List[str]:
        """
        Recursively follow sitemap-index files up to _SITEMAP_DEPTH_LIMIT levels.
        Returns a flat list of page <loc> URLs.
        """
        if depth > self._SITEMAP_DEPTH_LIMIT:
            return []
        urls: List[str] = []
        for sm in self.sitemaps:
            try:
                resp, _ = fetch_with_retry(session, sm, timeout=10)
                if not resp or resp.status_code != 200:
                    continue
                text = resp.text
                # Sitemap index: contains <sitemap><loc> entries
                nested = re.findall(r"<sitemap>\s*<loc>(.*?)</loc>", text, re.I | re.S)
                if nested and depth < self._SITEMAP_DEPTH_LIMIT:
                    old_sitemaps = self.sitemaps
                    self.sitemaps = nested
                    urls.extend(self.extract_sitemap_urls(session, depth + 1))
                    self.sitemaps = old_sitemaps
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

        fetched_js: Set[str] = set()
        js_queue: List[str] = list(js_src_list)

        while js_queue:
            js_url = js_queue.pop(0)
            full_url = urljoin(page_url, js_url)
            norm = full_url.split("?")[0].split("#")[0]
            if norm in fetched_js:
                continue
            fetched_js.add(norm)

            resp, err = fetch_with_retry(self.session, full_url, timeout=8,
                                         rotate_ua=self.rotate_ua)
            if not resp or resp.status_code != 200:
                continue

            text = resp.text
            self._scan_js(text, full_url, endpoints, secrets, sourcemaps)

            for pat in self.DYNAMIC_IMPORT_PATTERNS:
                for m in pat.finditer(text):
                    chunk_path = m.group(1)
                    if chunk_path.startswith("data:") or (
                        chunk_path.startswith("http") and
                        urlparse(chunk_path).netloc != urlparse(page_url).netloc
                    ):
                        continue
                    chunk_norm = urljoin(full_url, chunk_path).split("?")[0]
                    if chunk_norm not in fetched_js:
                        js_queue.append(chunk_path)

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
        "openapi_specs": [],   # NEW in v6.0
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

    # NEW: OpenAPI / Swagger spec discovery
    data["openapi_specs"] = list(set(
        urljoin(url, m) for m in PATTERNS["openapi"].findall(raw_html)
    ))

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
    data["js_secrets"]   = sec
    data["sourcemaps"]   = sm

    for pat, label in SECRET_PATTERNS:
        for m in pat.finditer(raw_html):
            val = m.group(1) if m.lastindex else m.group(0)
            if len(val) > 6:
                data["js_secrets"].append({"type": label, "value": val[:80], "source": url})

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
        raw = self._q.get(timeout=timeout)
        if self.strategy == "priority":
            return raw[1]
        return raw

    def task_done(self):
        self._q.task_done()

    def join(self):
        self._q.join()

    def qsize(self):
        return self._q.qsize()


# -----------------------------------------------------------------
#  TOKEN BUCKET RATE LIMITER (per-host)
# -----------------------------------------------------------------
class TokenBucket:
    """
    Classic token-bucket rate limiter.
    Allows `rate` tokens per second with a burst capacity of `capacity`.
    Thread-safe.
    """
    def __init__(self, rate: float, capacity: float = None):
        self.rate     = rate
        self.capacity = capacity or rate
        self._tokens  = self.capacity
        self._last    = time.monotonic()
        self._lock    = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Block until a token is available or timeout expires."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            wait = min(1.0 / max(self.rate, 0.001), deadline - time.monotonic())
            if wait <= 0:
                return False
            time.sleep(wait)


_HOST_BUCKET_LIMIT = 512


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
    requests_sent:    int = 0       # NEW: total HTTP requests (all phases)
    status_codes:     Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    start_time:       datetime = field(default_factory=datetime.now)
    # Per-phase timing (NEW in v6.0)
    phase_times:      Dict[str, float] = field(default_factory=dict)

    def elapsed(self) -> str:
        secs = int((datetime.now() - self.start_time).total_seconds())
        return f"{secs // 60}m{secs % 60}s"

    def avg_rps(self) -> str:
        """Average requests per second over the whole scan."""
        secs = max(1, int((datetime.now() - self.start_time).total_seconds()))
        return f"{self.requests_sent / secs:.1f}"

    def record_phase(self, name: str, elapsed_s: float) -> None:
        self.phase_times[name] = round(elapsed_s, 1)


# -----------------------------------------------------------------
#  SUBDOMAIN HUNTER
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

    def _brute_worker(self, q: queue.Queue, total: int, done_counter: List[int],
                      pbar=None):
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
                if pbar:
                    pbar.update(1)
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
            log("SUB", col(f"WARNING: Wildcard DNS detected ({wildcard_ip}) -- results may include false positives", C.YELLOW), C.YELLOW)

        q: queue.Queue = queue.Queue()
        for w in self.wordlist:
            q.put(w.strip())
        total = q.qsize()
        done_counter = [0]

        pbar = None
        if TQDM_AVAILABLE and VERBOSITY.level >= 1:
            pbar = _tqdm(total=total, desc="Subdomains", unit="word",
                         leave=False, dynamic_ncols=True)

        workers = [
            threading.Thread(target=self._brute_worker, args=(q, total, done_counter, pbar), daemon=True)
            for _ in range(min(self.threads, total or 1))
        ]
        for w in workers:
            w.start()
        q.join()
        if pbar:
            pbar.close()

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

        probe_threads = min(50, len(items))
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
                   for _ in range(probe_threads)]
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


# -----------------------------------------------------------------
#  DIRECTORY HUNTER
# -----------------------------------------------------------------
class DirectoryHunter:
    """
    Accurate directory and file enumeration with wildcard/soft-404 detection,
    response-size deduplication, recursive mode, and optional progress bars.
    """

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

        self._lock       = threading.Lock()
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
        if self._baseline_stdev == 0:
            threshold = max(32, int(self._baseline_len * 0.03))
        else:
            threshold = max(32, self._baseline_stdev * 2)
        return abs(size - self._baseline_len) < threshold

    def _worker(self, q: queue.Queue, total: int, done_ctr: List[int], pbar=None):
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

                if pbar:
                    pbar.update(1)

                if resp:
                    code = resp.status_code
                    sz = len(resp.content)

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
        pbar = None
        if TQDM_AVAILABLE and VERBOSITY.level >= 1:
            pbar = _tqdm(total=total, desc=f"Dir [{depth}]", unit="path",
                         leave=False, dynamic_ncols=True)

        workers = [
            threading.Thread(target=self._worker, args=(q, total, done_ctr, pbar), daemon=True)
            for _ in range(min(self.threads, total or 1))
        ]
        for w in workers:
            w.start()
        q.join()
        if pbar:
            pbar.close()

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


# -----------------------------------------------------------------
#  PARAMETER FUZZER
# -----------------------------------------------------------------
class DeepFuzzCheck:
    """Base class for deep-fuzz vulnerability checks."""
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
        r"\[boot loader\]|"
        r"\[extensions\]|"
        r"daemon:x:\d+",
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
        r"ami-[0-9a-f]{8,17}|"
        r"instance-id|"
        r"placement/availability-zone|"
        r"iam/security-credentials|"
        r"computeMetadata|"
        r'"compute":\s*\{|'
        r"latest/meta-data",
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

    _CANARY = "https://evil.paramspecter.test"

    PAYLOADS = [
        _CANARY,
        f"//{_CANARY.split('//')[1]}",
        f"////{_CANARY.split('//')[1]}",
        f"https:////{_CANARY.split('//')[1]}",
    ]

    _CANARY_HOST = urlparse(_CANARY).netloc

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
        f"host_inject:{_CANARY_HOST}",
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
                               timeout=timeout, proxies=proxies,
                               allow_redirects=False)
            triggered, evidence = self.detect(f"host_inject:{self._CANARY_HOST}", resp, 0)
            return triggered, evidence
        except Exception as e:
            return False, str(e)


class IDORCheck(DeepFuzzCheck):
    LABEL    = "IDOR"
    SEVERITY = "HIGH"
    PAYLOADS = ["__idor_probe__"]

    _OWNER_PATTERNS = re.compile(
        r'"(?:user(?:name|_?id)?|email|account|owner|author)"'
        r'\s*:\s*"([^"]{3,})"',
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
        probes = [base_int + 1, base_int - 1, base_int + 100, 0]
        for probe_val in probes:
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
                    findings.append((
                        True,
                        f"Status changed {baseline_code}→{code} for id={probe_val}",
                        str(probe_val),
                    ))
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


# -----------------------------------------------------------------
#  CUSTOM PAYLOAD LOADER
# -----------------------------------------------------------------
def load_payload_file(path: Optional[str]) -> Dict[str, List[str]]:
    """
    Load a custom payload file for --deep-fuzz.
    Format: LABEL:payload  (one per line, # = comment)
    """
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
#  RESUME / CHECKPOINT HELPERS
# -----------------------------------------------------------------
_CHECKPOINT_LOCK = threading.Lock()

def save_checkpoint(path: str, visited: Set[str]) -> None:
    """Atomically write visited URLs to a checkpoint file."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for url in sorted(visited):
                f.write(url + "\n")
        os.replace(tmp, path)
    except Exception as e:
        log("CKPT", col(f"Checkpoint save failed: {e}", C.YELLOW), C.YELLOW)


def load_checkpoint(path: str) -> Set[str]:
    """Load previously visited URLs from a checkpoint file."""
    if not path or not os.path.isfile(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        urls = {line.strip() for line in f if line.strip()}
    log("CKPT", f"Resumed {col(len(urls), C.BOLD+C.GREEN)} previously visited URLs from {col(path, C.CYAN)}", C.GREEN)
    return urls


# -----------------------------------------------------------------
#  SCOPE HELPERS
# -----------------------------------------------------------------
def load_scope_file(path: Optional[str]) -> List[str]:
    if not path:
        return []
    path = validate_file_arg(path, "Scope file")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        entries = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    log("+SC", f"Loaded {col(len(entries), C.BOLD)} scope entries from {col(path, C.CYAN)}", C.GREEN)
    return entries


def url_in_scope(url: str, scope_entries: List[str], base_domain: str) -> bool:
    if not scope_entries:
        return is_same_domain(url, base_domain)
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    for entry in scope_entries:
        entry = entry.lstrip("*.")
        if host == entry or host.endswith("." + entry):
            return True
    return False


# Deep-fuzz check registry
_DEEP_FUZZ_CHECKS: List[DeepFuzzCheck] = [
    SQLiCheck(),
    XSSCheck(),
    PathTraversalCheck(),
    SSRFCheck(),
    OpenRedirectCheck(),
    HeaderInjectionCheck(),
    IDORCheck(),
]


class ParamFuzzer:
    """
    Wordlist-based parameter discovery and vulnerability fuzzing.
    Supports normal, --smart-fuzz, and --deep-fuzz modes.
    """

    FUZZ_VALUES = [
        "paramspecter1337",
        "1",
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "{{7*7}}",
    ]

    _SLEEP_EXTRA_TIMEOUT = 8

    def __init__(self, target_url, param_list, threads, timeout, session,
                 delay, hits_out, stop_event: threading.Event = None,
                 method="GET", rotate_ua=False, proxy_mgr=None,
                 smart_fuzz=False, deep_fuzz=False,
                 custom_payloads: Dict[str, List[str]] = None):
        self.target_url     = target_url
        self.param_list     = param_list
        self.threads        = threads
        self.timeout        = timeout
        self.session        = session
        self.delay          = delay
        self.hits_out       = hits_out
        self.stop_event     = stop_event or threading.Event()
        self.method         = method.upper()
        self.rotate_ua      = rotate_ua
        self.proxy_mgr      = proxy_mgr
        self.smart_fuzz     = smart_fuzz or deep_fuzz
        self.deep_fuzz      = deep_fuzz
        self.custom_payloads = custom_payloads or {}
        self._q             = queue.Queue()
        self._lock          = threading.Lock()
        self._done          = 0
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
        log("PARAM",
            f"Starting param fuzz -> {col(total, C.BOLD)} tests via {self.method}{extra}",
            C.CYAN)

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
            total_hits = len(self._hits) + len(self._deep_hits)
            log("PARAM",
                f"Done -- {col(len(self._hits), C.BOLD+C.GREEN)} basic  "
                f"{col(len(self._deep_hits), C.BOLD+C.RED)} deep findings  "
                f"({col(total_hits, C.BOLD)} total)",
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
                                    f"{status_color(code)}  "
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
            f"{col(len(params), C.BOLD)} params × "
            f"{col(len(active_checks), C.BOLD)} checks = "
            f"{col(total, C.BOLD+C.MAGENTA)} probes",
            C.MAGENTA)

        dq: "queue.Queue[Tuple[str, DeepFuzzCheck, str]]" = queue.Queue()
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
                sev_str = col(f"[{h['severity']}]",
                              DeepFuzzCheck._SEV_COLOR.get(h['severity'], C.WHITE))
                cwe_str = col(f"  [{h.get('cwe', '')}]", C.GRAY) if h.get("cwe") else ""
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
            if _sleep_re.search(payload)
            else self.timeout
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
                     f"{col(check.LABEL, C.GRAY)}  {col(param, C.GRAY)}",
                     C.GRAY)

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

        sev_str = col(f"[{check.SEVERITY}]",
                      DeepFuzzCheck._SEV_COLOR.get(check.SEVERITY, C.WHITE))
        cwe_str = col(f"  [{check.cwe()}]", C.GRAY) if check.cwe() else ""
        with _log_lock:
            print(
                f"  {ts()}  {col(f'DEEP {pct:>3}%', C.MAGENTA)}  "
                f"{sev_str}  {col(check.LABEL, C.MAGENTA+C.BOLD)}  "
                f"param={col(param, C.YELLOW)}  "
                f"payload={col(repr(str(payload)[:30]), C.WHITE)}{cwe_str}\n"
                f"  {' '*12}evidence: {col(evidence[:100], C.RED)}"
            )


# -----------------------------------------------------------------
#  FORM LOGIN HANDLER
# -----------------------------------------------------------------
class FormLoginHandler:
    """
    Automated form-based login: GETs the login page, extracts CSRF tokens,
    POSTs credentials, injects cookies into the shared session.
    """

    CSRF_FIELD_RE = re.compile(
        r"csrf|token|nonce|_wpnonce|authenticity_token|__RequestVerificationToken",
        re.I,
    )

    def __init__(self, session: requests.Session, login_url: str,
                 username: str, password: str,
                 user_field: str = "username", pass_field: str = "password",
                 timeout: int = 15):
        self.session    = session
        self.login_url  = login_url
        self.username   = username
        self.password   = password
        self.user_field = user_field
        self.pass_field = pass_field
        self.timeout    = timeout

    def login(self) -> None:
        log_section("FORM LOGIN")
        log("AUTH", f"Fetching login page: {col(self.login_url, C.CYAN)}", C.CYAN)

        get_resp, err = fetch_with_retry(
            self.session, self.login_url,
            timeout=self.timeout, allow_redirects=True,
        )
        if get_resp is None:
            self._die(f"Could not reach login page: {err}")

        soup = BeautifulSoup(get_resp.text, "html.parser")
        action_url, method, hidden = self._parse_login_form(soup, get_resp.url)

        log("AUTH", f"Form action : {col(action_url, C.CYAN)}", C.CYAN)
        if hidden:
            names = ", ".join(hidden.keys())
            log("AUTH", f"CSRF fields : {col(names, C.YELLOW)}", C.YELLOW)

        payload: Dict[str, str] = {
            self.user_field: self.username,
            self.pass_field: self.password,
        }
        payload.update(hidden)

        log("AUTH",
            f"Submitting  : {col(self.user_field, C.WHITE)}=<user>  "
            f"{col(self.pass_field, C.WHITE)}=<redacted>  "
            f"method={col(method.upper(), C.WHITE)}",
            C.CYAN)

        if method.upper() == "GET":
            post_resp, err = fetch_with_retry(
                self.session, action_url,
                method="GET", params=payload,
                timeout=self.timeout, allow_redirects=True,
            )
        else:
            post_resp, err = fetch_with_retry(
                self.session, action_url,
                method="POST", data=payload,
                timeout=self.timeout, allow_redirects=True,
            )

        if post_resp is None:
            self._die(f"Login POST failed: {err}")

        self._validate(post_resp)

        cookie_names = [c.name for c in self.session.cookies]
        if cookie_names:
            log("AUTH",
                col(f"Session cookies injected: {', '.join(cookie_names)}", C.GREEN),
                C.GREEN)
        else:
            log("AUTH",
                col("WARNING: No cookies received after login — session may not be established", C.YELLOW),
                C.YELLOW)

    def _parse_login_form(self, soup, page_url: str) -> Tuple[str, str, Dict[str, str]]:
        form = None
        for candidate in soup.find_all("form"):
            if candidate.find("input", {"type": "password"}):
                form = candidate
                break
        if form is None:
            form = soup.find("form")

        if form is None:
            log("AUTH",
                col("No <form> found on login page; will POST directly to --login-url", C.YELLOW),
                C.YELLOW)
            return self.login_url, "POST", {}

        raw_action = form.get("action", "").strip() or page_url
        action_url = urljoin(page_url, raw_action)
        method     = form.get("method", "POST").strip()

        hidden: Dict[str, str] = {}
        for inp in form.find_all("input", {"type": "hidden"}):
            name  = inp.get("name", "").strip()
            value = inp.get("value", "")
            if name and self.CSRF_FIELD_RE.search(name):
                hidden[name] = value

        for inp in form.find_all("input", {"type": "hidden"}):
            name  = inp.get("name", "").strip()
            value = inp.get("value", "")
            if name and name not in hidden:
                hidden[name] = value

        return action_url, method, hidden

    def _validate(self, resp: requests.Response) -> None:
        final_url = resp.url
        if not (200 <= resp.status_code < 300):
            self._die(
                f"Login returned HTTP {resp.status_code} "
                f"(expected 2xx).  Final URL: {final_url}"
            )

        login_path  = urlparse(self.login_url).path.rstrip("/")
        final_path  = urlparse(final_url).path.rstrip("/")
        if login_path and final_path == login_path:
            self._die(
                f"Server redirected back to the login page after POST.\n"
                f"  Login URL : {self.login_url}\n"
                f"  Final URL : {final_url}\n"
                f"  This usually means the credentials were rejected or the\n"
                f"  --login-user-field / --login-pass-field names are wrong."
            )

        if resp.text and re.search(
            rf'(?:name|id)\s*=\s*["\']?{re.escape(self.pass_field)}["\']?',
            resp.text, re.I
        ):
            log("AUTH",
                col("WARNING: Password field found in response body — login may have failed "
                    "(form re-rendered).  Check credentials and field names.", C.YELLOW),
                C.YELLOW)
            return

        log("AUTH",
            col(f"Login appears successful  (HTTP {resp.status_code}, "
                f"landed on: {final_url})", C.GREEN + C.BOLD),
            C.GREEN)

    @staticmethod
    def _die(msg: str) -> None:
        with _log_lock:
            print(f"\n  {col('AUTH ERROR:', C.RED + C.BOLD)}  {col(msg, C.RED)}\n")
        sys.exit(1)


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

        self.output_dir = validate_output_dir(getattr(args, "output_dir", None) or ".")

        self.scope_entries: List[str] = load_scope_file(getattr(args, "scope_file", None))
        self.custom_payloads: Dict[str, List[str]] = load_payload_file(getattr(args, "payload_file", None))

        cli_rate = getattr(args, "rate_limit", None)
        self._host_rate = float(cli_rate) if cli_rate else max(1.0, self.threads * 0.8)

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

        if getattr(args, "login_url", None):
            FormLoginHandler(
                session     = self.session,
                login_url   = args.login_url,
                username    = args.login_user,
                password    = args.login_pass,
                user_field  = getattr(args, "login_user_field", "username"),
                pass_field  = getattr(args, "login_pass_field", "password"),
                timeout     = self.timeout,
            ).login()

        proxy_list = []
        if getattr(args, "proxies", None):
            proxy_list = [p.strip() for p in args.proxies.split(",") if p.strip()]
        self.proxy_mgr = ProxyManager(proxy_list) if proxy_list else None

        self._checkpoint_file = getattr(args, "resume_file", None) or \
            os.path.join(self.output_dir, f"paramspecter_{self.base_domain.replace('.','_')}_checkpoint.txt")
        _resume = getattr(args, "resume", False)

        self.crawl_queue = CrawlQueue(strategy=self.strategy)
        self.crawl_queue.put((self.start_url, 0))
        self.visited: Set[str]        = load_checkpoint(self._checkpoint_file) if _resume else set()
        self.visited_hashes: Set[str] = set()
        self.visited_lock             = threading.Lock()
        self.results: List[Dict]      = []
        self.results_lock             = threading.Lock()

        self.all_emails:     Set[str]   = set()
        self.all_phones:     Set[str]   = set()
        self.all_links:      Set[str]   = set()
        self.all_subdomains: Set[str]   = set()
        self.all_techs:      Set[str]   = set()
        self.all_wafs:       Set[str]   = set()
        self.all_params:     Set[str]   = set()
        self.all_secrets:    List[Dict] = []
        self.all_openapi:    Set[str]   = set()   # NEW
        self.all_forms:      int        = 0
        self.all_interesting: List[str] = []
        self.missing_sec_headers: Dict[str, int] = defaultdict(int)

        self.fuzz_hits:      List[Dict] = []
        self.param_hits:     List[Dict] = []
        self.subdomain_hits: List[Dict] = []
        self.dir_hits:       List[Dict] = []

        self.stats = CrawlStats()
        self._stop_event = threading.Event()

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

        self._host_buckets: Dict[str, TokenBucket] = {}
        self._host_buckets_lock = threading.Lock()

        self.js_analyzer = JSAnalyzer(self.session, rotate_ua=self.rotate_ua)

        self.use_playwright = getattr(args, "playwright", False)
        self._pw_instance   = None
        self.pw_browser     = None

        if self.use_playwright:
            if not PLAYWRIGHT_AVAILABLE:
                log("PW", col("playwright not installed -- falling back to requests. "
                              "Run: pip install playwright && playwright install chromium", C.YELLOW), C.YELLOW)
                self.use_playwright = False
            else:
                try:
                    self._pw_instance = sync_playwright().__enter__()
                    self.pw_browser   = self._pw_instance.chromium.launch(headless=True)
                    log("PW", col("Playwright headless Chromium ready", C.GREEN), C.GREEN)
                except Exception as e:
                    log("PW", col(f"Failed to launch Playwright: {e} -- falling back to requests", C.YELLOW), C.YELLOW)
                    self.use_playwright = False
                    self._pw_instance   = None
                    self.pw_browser     = None

        # JSONL streaming file handle (opened once, closed in save_results)
        self._jsonl_fh = None

        signal.signal(signal.SIGINT, self._handle_sigint)
        self.start_time = datetime.now()

    def _host_bucket(self, url: str) -> TokenBucket:
        host = urlparse(url).netloc
        with self._host_buckets_lock:
            if host not in self._host_buckets:
                if len(self._host_buckets) >= _HOST_BUCKET_LIMIT:
                    evict_key = next(iter(self._host_buckets))
                    del self._host_buckets[evict_key]
                self._host_buckets[host] = TokenBucket(
                    rate=self._host_rate,
                    capacity=self._host_rate * 2
                )
            return self._host_buckets[host]

    def _handle_sigint(self, sig, frame):
        if self._stop_event.is_set():
            log("STOP", col("Force exit.", C.RED), C.RED)
            sys.exit(1)
        with _log_lock:
            print(f"\n{col('─' * 65, C.YELLOW)}")
            print(f"  {col('>> SCAN INTERRUPTED -- saving partial results...', C.BOLD + C.YELLOW)}")
            print(col('─' * 65, C.YELLOW))
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
            bucket = self._host_bucket(url)
            bucket.acquire()

            xhr_endpoints: List[str] = []
            resp = None
            err  = None
            pw_html: Optional[str] = None

            if self.use_playwright and self.pw_browser is not None:
                try:
                    pw_html, final_url = fetch_with_playwright(
                        self.pw_browser, url,
                        timeout=self.timeout,
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
                    log("PW", col(f"Playwright failed for {url}: {e} -- falling back to requests", C.YELLOW), C.YELLOW)
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

            # Track total requests sent
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
            q_depth = self.crawl_queue.qsize()
            if VERBOSITY.level >= 1:
                with _log_lock:
                    print(f"  {ts()}  {col(f'[{count:>4}]', C.CYAN)}  {status_color(resp.status_code)}  "
                          f"{col(url[:72], C.WHITE)}{col(redir_info, C.YELLOW)}"
                          f"  {col(f'[q:{q_depth}]', C.GRAY)}")
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

            # JSONL streaming: write page record immediately (never buffer all in RAM)
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
                    (s.get("type",""), s.get("value","")[:40])
                    for s in self.all_secrets
                }
                for s in pd["js_secrets"]:
                    key = (s.get("type",""), s.get("value","")[:40])
                    if key not in _seen_secret_keys:
                        _seen_secret_keys.add(key)
                        self.all_secrets.append(s)
                self.all_forms += len(pd["forms"])
                self.all_interesting.extend(pd["interesting"])
                self.stats.emails_found  = len(self.all_emails)
                self.stats.secrets_found = len(self.all_secrets)
                self.stats.forms_found   = self.all_forms
                self.stats.params_found  = len(self.all_params)

                for sh in SECURITY_HEADERS:
                    if sh not in pd["security_headers"]:
                        self.missing_sec_headers[sh] += 1

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

    def run_crawl(self):
        _barrier = threading.Barrier(self.threads + 1, timeout=3600)

        def _worker_wrapper():
            try:
                self._crawl_worker()
            finally:
                try:
                    _barrier.wait()
                except threading.BrokenBarrierError:
                    pass

        workers = [threading.Thread(target=_worker_wrapper, daemon=True)
                   for _ in range(self.threads)]
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
            mc, hc, self.dir_hits, self._stop_event,
            rotate_ua=self.rotate_ua, proxy_mgr=self.proxy_mgr,
            recursive=recursive, max_depth=max_rdepth,
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
            root_domain, wl, a.threads,
            a.timeout, self.session, self.subdomain_hits,
            self._stop_event,
        ).run()

    def run(self):
        mode = self.mode

        # Open JSONL streaming file up-front so crawl worker can write to it
        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_pfx = f"paramspecter_{self.base_domain.replace('.','_')}_{ts_str}"
        pfx = os.path.join(self.output_dir, base_pfx)
        if self.output in ("jsonl",):
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

        # Close JSONL stream
        if self._jsonl_fh is not None:
            try:
                self._jsonl_fh.close()
            except Exception:
                pass
            self._jsonl_fh = None

        self.print_summary()
        self.save_results(pfx)
        self._export_targets_paths: Tuple[str, str] = ("", "")
        if getattr(self.args, "export_targets", False):
            self._export_targets_paths = self.export_targets(pfx)
            self._print_tool_hints()

        if self.pw_browser is not None:
            try:
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

    def _print_tool_hints(self) -> None:
        t_path, sql_path = self._export_targets_paths
        sep = col("─" * 65, C.YELLOW)
        print(f"\n{sep}")
        print(f"  {col('NEXT STEPS  (--export-targets)', C.BOLD + C.YELLOW)}")
        print(sep)
        if t_path:
            print(f"  {col('Run nuclei:', C.CYAN)}")
            print(f"    {col(f'nuclei -l {t_path} -t ~/nuclei-templates/', C.WHITE)}")
        if sql_path:
            print(f"  {col('Run sqlmap:', C.CYAN)}")
            print(f"    {col(f'sqlmap -m {sql_path} --batch --dbs', C.WHITE)}")
        print(sep + "\n")

    def print_summary(self):
        dur = self.stats.elapsed()
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

        # Per-phase timing (NEW)
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
                ip_str  = ", ".join(h.get("ips", [])) or "no-ip"
                st_str  = status_color(h.get("status")) if h.get("status") else col("no-http", C.GRAY)
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

    def save_results(self, pfx: str):
        save_checkpoint(self._checkpoint_file, self.visited)

        meta = {
            "target": self.start_url, "mode": self.mode, "strategy": self.strategy,
            "crawled_at": self.start_time.isoformat(),
            "duration": self.stats.elapsed(),
            "interrupted": self._stop_event.is_set(),
            "total_pages": self.stats.pages_crawled,
            "total_requests": self.stats.requests_sent,
            "avg_rps": self.stats.avg_rps(),
            "phase_times": self.stats.phase_times,
            "emails": list(self.all_emails),
            "phones": list(self.all_phones),
            "subdomains_crawl": list(self.all_subdomains),
            "subdomains_hunt": [h["subdomain"] for h in self.subdomain_hits],
            "technologies": list(self.all_techs),
            "waf": list(self.all_wafs),
            "params": list(self.all_params),
            "openapi_specs": list(self.all_openapi),
            "secrets_count": len(self.all_secrets),
            "missing_security_headers": dict(self.missing_sec_headers),
        }

        if self.output in ("json", "both"):
            fname = f"{pfx}.json"
            payload = {
                "meta": meta,
                "pages": self.results,
                "secrets": self.all_secrets,
                "fuzz_hits": self.fuzz_hits,
                "dir_hits": self.dir_hits,
                "param_hits": self.param_hits,
                "subdomain_hits": self.subdomain_hits,
            }
            try:
                fd, tmp_path = tempfile.mkstemp(suffix=".json.tmp",
                                                dir=os.path.dirname(fname) or ".")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                os.replace(tmp_path, fname)
            except Exception as e:
                log("SAVE", col(f"Atomic write failed ({e}), trying direct write", C.YELLOW), C.YELLOW)
                with open(fname, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
            log("SAVED", f"JSON -> {col(fname, C.CYAN)}", C.GREEN)

        if self.output == "jsonl":
            # JSONL was streamed during crawl; write a separate meta file
            meta_fname = f"{pfx}_meta.json"
            try:
                with open(meta_fname, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2, ensure_ascii=False)
                log("SAVED", f"JSONL meta -> {col(meta_fname, C.CYAN)}", C.GREEN)
            except Exception as e:
                log("SAVE", col(f"Meta write failed: {e}", C.RED), C.RED)

        if self.output in ("csv", "both"):
            fname = f"{pfx}.csv"
            fields = ["url","status","title","content_type","technologies","waf","emails","phones",
                      "ips","internal_ips","subdomains","params","forms","html_comments",
                      "redirect_chain","social_links","security_headers",
                      "leaked_headers","js_endpoints","sourcemaps","captcha_detected",
                      "content_length","content_hash","openapi_specs"]
            _tmp_csv = fname + ".tmp"
            with open(_tmp_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                w.writeheader()
                for r in self.results:
                    row = dict(r)
                    for k in ["emails","phones","ips","internal_ips","subdomains","params",
                              "technologies","waf","html_comments","redirect_chain",
                              "social_links","js_endpoints","sourcemaps","openapi_specs"]:
                        if isinstance(row.get(k), list):
                            row[k] = " | ".join(str(i) for i in row[k])
                    row["forms"] = len(r.get("forms", []))
                    row["security_headers"] = str(r.get("security_headers", {}))
                    row["leaked_headers"]   = str(r.get("leaked_headers", {}))
                    w.writerow(row)
            os.replace(_tmp_csv, fname)
            log("SAVED", f"CSV  -> {col(fname, C.CYAN)}", C.GREEN)

            def _write_csv_atomic(path, fieldnames, rows, extra_fn=None):
                tmp = path + ".tmp"
                try:
                    with open(tmp, "w", newline="", encoding="utf-8") as f:
                        wtr = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                        wtr.writeheader()
                        if extra_fn:
                            for row in rows:
                                wtr.writerow(extra_fn(dict(row)))
                        else:
                            wtr.writerows(rows)
                    os.replace(tmp, path)
                    log("SAVED", f"CSV  -> {col(path, C.CYAN)}", C.GREEN)
                except Exception as e:
                    log("SAVE", col(f"Failed writing {path}: {e}", C.RED), C.RED)
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass

            if self.dir_hits:
                _write_csv_atomic(f"{pfx}_dirs.csv", ["url","status","size","redirect"], self.dir_hits)
            if self.param_hits:
                _write_csv_atomic(f"{pfx}_params.csv",
                    ["param","payload","url","status","size","size_diff","reflected","cwe"], self.param_hits)
            if self.all_secrets:
                _write_csv_atomic(f"{pfx}_secrets.csv", ["type","value","source"], self.all_secrets)
            if self.subdomain_hits:
                def _fix_sub(row):
                    row["ips"] = ", ".join(row.get("ips", []) if isinstance(row.get("ips"), list) else [row.get("ips","")])
                    return row
                _write_csv_atomic(f"{pfx}_subdomains.csv",
                    ["subdomain","ips","method","status","http_url","title"],
                    self.subdomain_hits, extra_fn=_fix_sub)

        self._save_html_report(pfx)

    def _save_html_report(self, pfx: str) -> None:
        html_path = f"{pfx}_report.html"

        def _esc(s):
            return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

        def _rows(items, fields):
            rows = ""
            for item in items:
                rows += "<tr>" + "".join(f"<td>{_esc(item.get(f,''))}</td>" for f in fields) + "</tr>\n"
            return rows

        def _th(fields):
            return "<tr>" + "".join(f"<th>{_esc(f)}</th>" for f in fields) + "</tr>"

        secrets_html = ""
        for s in self.all_secrets:
            secrets_html += (
                f"<tr><td><span class='badge badge-red'>{_esc(s.get('type','?'))}</span></td>"
                f"<td><code>{_esc(s.get('value','')[:80])}</code></td>"
                f"<td>{_esc(s.get('source',''))}</td></tr>\n"
            )

        param_hits_html = _rows(self.param_hits, ["param","url","status","size_diff","reflected","payload","cwe"])
        dir_hits_html   = _rows(self.dir_hits,   ["url","status","size","redirect"])
        sub_hits_html   = ""
        for h in self.subdomain_hits:
            sub_hits_html += (
                f"<tr><td>{_esc(h.get('subdomain',''))}</td>"
                f"<td>{_esc(', '.join(h.get('ips',[])))}</td>"
                f"<td>{_esc(h.get('status',''))}</td>"
                f"<td>{_esc(h.get('method',''))}</td></tr>\n"
            )

        openapi_html = ""
        for spec in sorted(self.all_openapi):
            openapi_html += f"<tr><td><a href='{_esc(spec)}' target='_blank' style='color:#80c8ff'>{_esc(spec)}</a></td></tr>\n"

        tech_badges = " ".join(f"<span class='badge badge-blue'>{_esc(t)}</span>" for t in sorted(self.all_techs))
        waf_badges  = " ".join(f"<span class='badge badge-yellow'>{_esc(w)}</span>" for w in sorted(self.all_wafs))
        param_list  = " ".join(f"<span class='badge badge-gray'>?{_esc(p)}</span>" for p in sorted(self.all_params)[:80])

        phase_timing_html = ""
        if self.stats.phase_times:
            phase_timing_html = "<div class='section'><h2>Phase Timing</h2><table><thead><tr><th>Phase</th><th>Duration (s)</th></tr></thead><tbody>"
            for phase, secs in self.stats.phase_times.items():
                phase_timing_html += f"<tr><td>{_esc(phase)}</td><td>{secs}</td></tr>"
            phase_timing_html += "</tbody></table></div>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ParamSpecter v6.0 Report — {_esc(self.start_url)}</title>
<style>
  :root{{--red:#e74c3c;--green:#2ecc71;--blue:#3498db;--yellow:#f39c12;--gray:#95a5a6;--dark:#1a1a2e;--card:#16213e;--text:#e0e0e0}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--dark);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:20px}}
  h1{{color:var(--red);font-size:1.8rem;margin-bottom:4px}}
  h2{{color:var(--blue);font-size:1.1rem;margin:20px 0 8px;border-bottom:1px solid #333;padding-bottom:4px}}
  .meta{{color:var(--gray);font-size:.85rem;margin-bottom:20px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}}
  .card{{background:var(--card);border-radius:8px;padding:16px;text-align:center;border:1px solid #2a2a4a}}
  .card .num{{font-size:2rem;font-weight:700;color:var(--red)}}
  .card .lbl{{font-size:.8rem;color:var(--gray);margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:16px}}
  th{{background:#0f3460;color:var(--text);padding:8px;text-align:left}}
  td{{padding:7px 8px;border-bottom:1px solid #222;word-break:break-all}}
  tr:hover td{{background:#1e2a45}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;margin:2px}}
  .badge-red{{background:#5c1a1a;color:#ff8080}}
  .badge-blue{{background:#1a3a5c;color:#80c8ff}}
  .badge-yellow{{background:#5c4a1a;color:#ffd080}}
  .badge-gray{{background:#2a2a2a;color:#aaa}}
  code{{background:#0d1117;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.82rem}}
  .warn{{background:#5c3a1a;border:1px solid var(--yellow);border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:.9rem}}
  .section{{background:var(--card);border-radius:8px;padding:16px;margin-bottom:16px;border:1px solid #2a2a4a}}
</style>
</head>
<body>
<h1>⚡ ParamSpecter v6.0 — Scan Report</h1>
<p class="meta">Target: <strong>{_esc(self.start_url)}</strong> &nbsp;|&nbsp;
Mode: {_esc(self.mode)} &nbsp;|&nbsp;
Duration: {_esc(self.stats.elapsed())} &nbsp;|&nbsp;
Requests: {self.stats.requests_sent} ({self.stats.avg_rps()} req/s) &nbsp;|&nbsp;
Generated: {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>

<div class="warn">⚠️ For authorized security testing only. Do not use against targets without explicit written permission.</div>

<div class="grid">
  <div class="card"><div class="num">{self.stats.pages_crawled}</div><div class="lbl">Pages Crawled</div></div>
  <div class="card"><div class="num">{len(self.all_params)}</div><div class="lbl">URL Params</div></div>
  <div class="card"><div class="num">{len(self.all_emails)}</div><div class="lbl">Emails</div></div>
  <div class="card"><div class="num">{len(self.all_secrets)}</div><div class="lbl">Possible Secrets</div></div>
  <div class="card"><div class="num">{len(self.dir_hits)}</div><div class="lbl">Dir Hits</div></div>
  <div class="card"><div class="num">{len(self.param_hits)}</div><div class="lbl">Param Hits</div></div>
  <div class="card"><div class="num">{len(self.subdomain_hits)}</div><div class="lbl">Subdomains</div></div>
  <div class="card"><div class="num">{self.all_forms}</div><div class="lbl">Forms Found</div></div>
  <div class="card"><div class="num">{len(self.all_openapi)}</div><div class="lbl">OpenAPI Specs</div></div>
  <div class="card"><div class="num">{self.stats.requests_sent}</div><div class="lbl">Total Requests</div></div>
</div>

<div class="section">
  <h2>Technologies Detected</h2>
  <p>{tech_badges or '<span style="color:var(--gray)">None detected</span>'}</p>
  <h2 style="margin-top:12px">WAF Detected</h2>
  <p>{waf_badges or '<span style="color:var(--gray)">None detected</span>'}</p>
</div>

<div class="section">
  <h2>URL Parameters Discovered</h2>
  <p>{param_list or '<span style="color:var(--gray)">None</span>'}</p>
</div>

{phase_timing_html}

{"<div class='section'><h2>OpenAPI / Swagger Specs (" + str(len(self.all_openapi)) + ")</h2><table><thead><tr><th>URL</th></tr></thead><tbody>" + openapi_html + "</tbody></table></div>" if self.all_openapi else ""}

{"<div class='section'><h2>⚠️ Possible Secrets (" + str(len(self.all_secrets)) + ")</h2><table><thead>" + _th(["Type","Value","Source"]) + "</thead><tbody>" + secrets_html + "</tbody></table></div>" if self.all_secrets else ""}

{"<div class='section'><h2>Emails Found</h2><p>" + " ".join(f"<span class='badge badge-gray'>{_esc(e)}</span>" for e in sorted(self.all_emails)) + "</p></div>" if self.all_emails else ""}

{"<div class='section'><h2>Directory / File Hits (" + str(len(self.dir_hits)) + ")</h2><table><thead>" + _th(["URL","Status","Size","Redirect"]) + "</thead><tbody>" + dir_hits_html + "</tbody></table></div>" if self.dir_hits else ""}

{"<div class='section'><h2>Parameter Hits (" + str(len(self.param_hits)) + ")</h2><table><thead>" + _th(["Param","URL","Status","Size Delta","Reflected","Payload","CWE"]) + "</thead><tbody>" + param_hits_html + "</tbody></table></div>" if self.param_hits else ""}

{"<div class='section'><h2>Subdomains Found (" + str(len(self.subdomain_hits)) + ")</h2><table><thead>" + _th(["Subdomain","IPs","Status","Method"]) + "</thead><tbody>" + sub_hits_html + "</tbody></table></div>" if self.subdomain_hits else ""}

<div class="section">
  <h2>Missing Security Headers</h2>
  {"<table><thead>" + _th(["Header","Pages Missing"]) + "</thead><tbody>" + "".join(f"<tr><td>{_esc(h)}</td><td>{c}</td></tr>" for h,c in sorted(self.missing_sec_headers.items(), key=lambda x:-x[1])) + "</tbody></table>" if self.missing_sec_headers else "<p style='color:var(--gray)'>All checked</p>"}
</div>

</body></html>"""

        try:
            tmp = html_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(html)
            os.replace(tmp, html_path)
            log("SAVED", f"HTML -> {col(html_path, C.CYAN)}", C.GREEN)
        except Exception as e:
            log("SAVE", col(f"HTML report failed: {e}", C.YELLOW), C.YELLOW)

    def export_targets(self, pfx: str) -> Tuple[str, str]:
        """Build targets.txt and sqlmap_targets.txt from crawl results."""
        candidates: Dict[str, Set[str]] = {}

        def _register(url_str: str) -> None:
            if not url_str:
                return
            parsed = urlparse(url_str)
            if not parsed.query:
                return
            params = set(parse_qs(parsed.query, keep_blank_values=True).keys())
            if not params:
                return
            candidates[url_str] = params

        for page in self.results:
            status = page.get("status") or 0
            if status < 400:
                _register(page.get("url", ""))
            for link in page.get("links", []):
                _register(link)

        for hit in self.param_hits:
            _register(hit.get("url", ""))

        INJECTABLE_NAMES: Set[str] = {
            "id", "uid", "user_id", "userid", "item_id", "itemid",
            "product_id", "productid", "product", "item", "cat",
            "category", "category_id", "page_id", "post_id", "article_id",
            "order_id", "orderid", "pid", "sid", "tid", "cid", "nid",
            "news_id", "blog_id", "entry_id", "record_id", "row_id",
        }

        _NUMERIC_VAL_RE = re.compile(r"^\d+$")
        confirmed_urls: Set[str] = {h.get("url", "") for h in self.param_hits if h.get("url")}

        def _is_sqlmap_candidate(url_str: str, param_names: Set[str]) -> bool:
            if url_str in confirmed_urls:
                return True
            if param_names & INJECTABLE_NAMES:
                return True
            qs = parse_qs(urlparse(url_str).query, keep_blank_values=True)
            for vals in qs.values():
                if any(_NUMERIC_VAL_RE.match(v) for v in vals):
                    return True
            return False

        t_path   = f"{pfx}_targets.txt"
        sql_path = f"{pfx}_sqlmap_targets.txt"

        all_targets   = sorted(candidates.keys())
        sqlmap_targets = sorted(
            url for url, params in candidates.items()
            if _is_sqlmap_candidate(url, params)
        )

        def _write_txt_atomic(path: str, lines: List[str]) -> None:
            tmp = path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + ("\n" if lines else ""))
                os.replace(tmp, path)
                log("SAVED", f"TXT  -> {col(path, C.CYAN)}  ({len(lines)} URLs)", C.GREEN)
            except Exception as e:
                log("SAVE", col(f"Failed writing {path}: {e}", C.RED), C.RED)
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

        _write_txt_atomic(t_path,   all_targets)
        _write_txt_atomic(sql_path, sqlmap_targets)

        return t_path, sql_path


# -----------------------------------------------------------------
#  CLI
# -----------------------------------------------------------------
def main():
    print_banner()
    p = argparse.ArgumentParser(
        description="ParamSpecter v6.0 -- Advanced Recon Crawler",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:

          Basic crawl (bypass robots for full coverage):
            python ParamSpecter.py https://example.com --ignore-robots

          Subdomain enumeration:
            python ParamSpecter.py https://example.com --mode subdomain
            python ParamSpecter.py https://example.com --mode subdomain --sub-wordlist subs.txt

          Directory hunting (recursive, with extensions):
            python ParamSpecter.py https://example.com --mode fuzz --recursive
            python ParamSpecter.py https://example.com --mode fuzz -w dirs.txt -x .php,.html,.bak --recursive-depth 3

          Parameter fuzzing (smart = 6 payloads per param):
            python ParamSpecter.py https://example.com/search --mode param --smart-fuzz

          Deep vulnerability scan (SQLi / XSS / LFI / SSRF / redirect / header / IDOR):
            python ParamSpecter.py https://example.com/search --mode param --deep-fuzz
            python ParamSpecter.py https://example.com/search --mode param --deep-fuzz --param-method POST
            python ParamSpecter.py https://example.com/search --mode param --deep-fuzz --payload-file my_payloads.txt

          Full recon in one shot:
            python ParamSpecter.py https://example.com --mode full -t 20 --ignore-robots

          Multi-domain scope file:
            python ParamSpecter.py https://example.com --mode full --scope-file scope.txt

          Rate limiting (max 5 req/s per host):
            python ParamSpecter.py https://example.com --rate-limit 5

          Resume an interrupted scan:
            python ParamSpecter.py https://example.com --resume
            python ParamSpecter.py https://example.com --resume --resume-file /tmp/my_checkpoint.txt

          Save all output to a specific directory:
            python ParamSpecter.py https://example.com --output-dir /tmp/scans/example/

          Deep crawl with UA rotation and Burp proxy:
            python ParamSpecter.py https://example.com --depth 6 -t 15 --rotate-ua --proxies http://127.0.0.1:8080

          Crawl and export nuclei + sqlmap target lists:
            python ParamSpecter.py https://example.com --export-targets
            python ParamSpecter.py https://example.com --mode full --export-targets --ignore-robots

          Authenticated crawl with session cookie:
            python ParamSpecter.py https://example.com --cookies "session=abc123; auth=xyz" --headers "X-API-Key: key"

          Authenticated crawl via automated form login:
            python ParamSpecter.py https://example.com --login-url https://example.com/login \\
              --login-user admin@example.com --login-pass hunter2

          Quiet mode (suppress per-page output, only show findings and summary):
            python ParamSpecter.py https://example.com --quiet

          Verbose mode (show retry/skip/dupe messages):
            python ParamSpecter.py https://example.com --verbose

          Ctrl+C once = graceful stop (saves partial results)
          Ctrl+C twice = force quit immediately
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
    p.add_argument("--export-targets",    action="store_true",
                   help=(
                       "After the scan, write two target-list files:\n"
                       "  <pfx>_targets.txt     -- all parameterised URLs (nuclei-ready)\n"
                       "  <pfx>_sqlmap_targets.txt -- injectable-looking subset (sqlmap-ready)\n"
                       "  Prints ready-to-run nuclei and sqlmap command lines at the end."
                   ))
    p.add_argument("--follow-external",   action="store_true", help="Follow external links")
    p.add_argument("--ignore-robots",     action="store_true", help="Ignore robots.txt")
    p.add_argument("--rotate-ua",         action="store_true", help="Rotate User-Agent per request")
    p.add_argument("--strategy",          choices=["bfs","dfs","priority"], default="bfs",
                   help="Crawl queue strategy (default: bfs)")
    p.add_argument("--playwright",         action="store_true",
                   help="Use headless Chromium (Playwright) for JS rendering + XHR interception")

    # Identity
    p.add_argument("-u","--user-agent",   default=None, help="Custom User-Agent string")
    p.add_argument("--cookies",           default=None, help='Cookie string: "a=1; b=2"')
    p.add_argument("--headers",           nargs="*",    help='Extra headers: "X-Custom: value"')
    p.add_argument("--proxies",           default=None, help="Comma-sep proxies: http://127.0.0.1:8080,...")

    # Auth / Login
    p.add_argument("--login-url",
                   default=None, metavar="URL",
                   help="Login page URL -- triggers automated form login before crawling")
    p.add_argument("--login-user",
                   default=None, metavar="USER",
                   help="Username / email to submit to the login form")
    p.add_argument("--login-pass",
                   default=None, metavar="PASS",
                   help="Password to submit to the login form")
    p.add_argument("--login-user-field",
                   default="username", metavar="FIELD",
                   help='Name attribute of the username input (default: "username")')
    p.add_argument("--login-pass-field",
                   default="password", metavar="FIELD",
                   help='Name attribute of the password input (default: "password")')

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
    p.add_argument("--deep-fuzz",    action="store_true",
                   help=(
                       "Extended vulnerability checks per param (implies --smart-fuzz):\n"
                       "  SQLi: error-based + time-based blind (SLEEP detection)  [CWE-89]\n"
                       "  XSS:  reflected payload detection (unencoded in body)   [CWE-79]\n"
                       "  Path traversal: /etc/passwd + win.ini content matching  [CWE-22]\n"
                       "  SSRF: AWS/GCP/Azure metadata endpoint probing           [CWE-918]\n"
                       "  Open redirect: Location header + meta-refresh           [CWE-601]\n"
                       "  Header injection: Host header + CRLF injection          [CWE-113]\n"
                       "  IDOR: numeric ID incrementation across params           [CWE-639]\n"
                       "  Each finding includes param, payload, evidence, CWE, and severity."
                   ))
    p.add_argument("--payload-file", default=None, metavar="FILE",
                   help=(
                       "Custom payload file for --deep-fuzz.\n"
                       "Format: one entry per line as LABEL:payload\n"
                       "  e.g.  SQLi:' OR SLEEP(5)--\n"
                       "        XSS:<img src=x onerror=alert(1)>\n"
                       "Valid labels: SQLi, XSS, PathTraversal, SSRF, OpenRedirect, HeaderInjection, IDOR"
                   ))

    # Scope
    p.add_argument("--scope-file",   default=None, metavar="FILE",
                   help=(
                       "File of in-scope domains (one per line, wildcards supported).\n"
                       "  e.g.  example.com\n"
                       "        *.example.com\n"
                       "When set, replaces the default same-domain restriction."
                   ))

    # Rate limiting
    p.add_argument("--rate-limit",   type=float, default=None, metavar="REQ/S",
                   help="Max requests per second per host (default: threads * 0.8)")

    # Resume
    p.add_argument("--resume",       action="store_true",
                   help="Resume a previous scan — skip already-visited URLs from checkpoint file")
    p.add_argument("--resume-file",  default=None, metavar="FILE",
                   help="Path to checkpoint file (default: auto-named in --output-dir)")

    # Output directory
    p.add_argument("--output-dir",   default=".", metavar="DIR",
                   help="Directory for all output files (default: current directory)")

    # Verbosity (NEW in v6.0)
    verbosity_group = p.add_mutually_exclusive_group()
    verbosity_group.add_argument("--quiet",   action="store_true",
                                 help="Suppress per-page output; show only findings and final summary")
    verbosity_group.add_argument("--verbose", action="store_true",
                                 help="Show retry, skip, and dedup messages (debug level)")

    args = p.parse_args()

    # Apply verbosity level globally
    if args.quiet:
        VERBOSITY.level = 0
    elif args.verbose:
        VERBOSITY.level = 2
    else:
        VERBOSITY.level = 1

    # Input validation
    args.url = validate_url(args.url)
    if getattr(args, "login_url", None):
        if not args.login_user or not args.login_pass:
            p.error("--login-url requires both --login-user and --login-pass")

    def _yn(v): return col("yes", C.GREEN) if v else col("no", C.GRAY)
    W = 20
    sep = col("─" * 60, C.GRAY)

    print(f"  {col('WARNING:', C.RED+C.BOLD)} Only test targets you have explicit written authorisation to test.\n")
    print(sep)
    print(f"  {col('TARGET', C.BOLD+C.WHITE)}")
    print(f"  {'URL':<{W}} {col(args.url, C.CYAN)}")
    print(f"  {'Mode':<{W}} {col(args.mode, C.YELLOW)}")
    print(f"  {'Output format':<{W}} {col(args.output, C.WHITE)}")
    print(f"  {'Output dir':<{W}} {col(args.output_dir, C.WHITE)}")
    print(f"  {'Export targets':<{W}} {_yn(args.export_targets)}")
    if args.scope_file:
        print(f"  {'Scope file':<{W}} {col(args.scope_file, C.CYAN)}")
    print(sep)
    print(f"  {col('CRAWL SETTINGS', C.BOLD+C.WHITE)}")
    print(f"  {'Threads':<{W}} {col(args.threads, C.WHITE)}")
    print(f"  {'Depth':<{W}} {col(args.depth, C.WHITE)}")
    print(f"  {'Max pages':<{W}} {col(args.max_pages, C.WHITE)}")
    print(f"  {'Delay':<{W}} {col(str(args.delay) + 's', C.WHITE)}")
    print(f"  {'Timeout':<{W}} {col(str(args.timeout) + 's', C.WHITE)}")
    print(f"  {'Max retries':<{W}} {col(args.max_retries, C.WHITE)}")
    print(f"  {'Rate limit':<{W}} {col(str(args.rate_limit) + ' req/s' if args.rate_limit else 'auto', C.WHITE)}")
    print(f"  {'Strategy':<{W}} {col(args.strategy, C.WHITE)}")
    print(f"  {'Rotate UA':<{W}} {_yn(args.rotate_ua)}")
    print(f"  {'Follow external':<{W}} {_yn(args.follow_external)}")
    print(f"  {'Ignore robots':<{W}} {_yn(args.ignore_robots)}")
    print(f"  {'Playwright':<{W}} {_yn(args.playwright)}")
    print(f"  {'Resume':<{W}} {_yn(args.resume)}")
    print(f"  {'Verbosity':<{W}} {col('quiet' if args.quiet else 'verbose' if args.verbose else 'normal', C.WHITE)}")
    if args.login_url:
        print(sep)
        print(f"  {col('FORM LOGIN', C.BOLD+C.WHITE)}")
        print(f"  {'Login URL':<{W}} {col(args.login_url, C.CYAN)}")
        print(f"  {'Username':<{W}} {col(args.login_user, C.WHITE)}")
        print(f"  {'Password':<{W}} {col('*' * min(len(args.login_pass), 8), C.GRAY)}")
        print(f"  {'User field':<{W}} {col(args.login_user_field, C.WHITE)}")
        print(f"  {'Pass field':<{W}} {col(args.login_pass_field, C.WHITE)}")
    if args.mode in ("fuzz", "full"):
        print(sep)
        print(f"  {col('DIRECTORY HUNTING', C.BOLD+C.WHITE)}")
        print(f"  {'Wordlist':<{W}} {args.wordlist or col('built-in', C.GRAY)}")
        print(f"  {'Extensions':<{W}} {col(args.extensions or '(none)', C.WHITE)}")
        print(f"  {'Recursive':<{W}} {_yn(args.recursive)}")
        if args.recursive:
            print(f"  {'Recurse depth':<{W}} {col(args.recursive_depth, C.WHITE)}")
        print(f"  {'Match codes':<{W}} {col(args.match_codes or 'any', C.WHITE)}")
        print(f"  {'Hide codes':<{W}} {col(args.hide_codes, C.WHITE)}")
    if args.mode in ("param", "full"):
        print(sep)
        print(f"  {col('PARAMETER FUZZING', C.BOLD+C.WHITE)}")
        print(f"  {'Wordlist':<{W}} {args.param_wordlist or col('built-in', C.GRAY)}")
        print(f"  {'Method':<{W}} {col(args.param_method, C.WHITE)}")
        print(f"  {'Smart fuzz':<{W}} {_yn(args.smart_fuzz)}")
        print(f"  {'Deep fuzz':<{W}} {_yn(args.deep_fuzz)}")
        if args.payload_file:
            print(f"  {'Payload file':<{W}} {col(args.payload_file, C.CYAN)}")
    if args.mode in ("subdomain", "full"):
        print(sep)
        print(f"  {col('SUBDOMAIN ENUM', C.BOLD+C.WHITE)}")
        print(f"  {'Wordlist':<{W}} {args.sub_wordlist or col('built-in', C.GRAY)}")
    if args.proxies:
        print(sep)
        print(f"  {col('PROXY', C.BOLD+C.WHITE)}")
        print(f"  {'Proxies':<{W}} {col(args.proxies, C.WHITE)}")
    if not DNS_AVAILABLE:
        print(sep)
        print(f"  {col('NOTE:', C.YELLOW+C.BOLD)} dnspython not installed -- socket fallback active.")
        print(f"       Run: {col('pip install dnspython', C.CYAN)}")
    if not TQDM_AVAILABLE:
        print(sep)
        print(f"  {col('NOTE:', C.YELLOW+C.BOLD)} tqdm not installed -- progress bars disabled.")
        print(f"       Run: {col('pip install tqdm', C.CYAN)}")
    print(sep)
    print(f"  {col('Ctrl+C once = graceful stop (saves partial results)', C.GRAY)}")
    print(f"  {col('Ctrl+C twice = force quit immediately', C.GRAY)}")
    print(sep + "\n")

    ParamSpecter(args).run()


if __name__ == "__main__":
    main()
