"""
utils/helpers.py
Colors, logging, URL helpers, input validation, wordlist loader.
"""

import os, re, sys, hashlib, random, threading
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from datetime import datetime
from typing import Optional, List

# -----------------------------------------------------------------
#  VERBOSITY
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
#  LOGGING
# -----------------------------------------------------------------
_log_lock = threading.Lock()
_log_suppress = False        # set True while curses dashboard is active
_log_buffer   = []           # buffered messages while suppressed

def ts():
    return col(datetime.now().strftime("%H:%M:%S"), C.GRAY)

def log(prefix, msg, pcolor=C.WHITE, min_level: int = 1):
    if VERBOSITY.level < min_level:
        return
    with _log_lock:
        line = f"  {ts()}  {col(prefix, pcolor)}  {msg}"
        if _log_suppress:
            _log_buffer.append(line)
        else:
            print(line)

def log_section(title):
    if VERBOSITY.level < 1:
        return
    lines = [
        f"\n{col('─'*60, C.RED)}",
        f"  {col('>> ' + title, C.BOLD+C.CYAN)}",
        col('─'*60, C.RED),
    ]
    with _log_lock:
        if _log_suppress:
            _log_buffer.extend(lines)
        else:
            for line in lines:
                print(line)

def vlog(prefix, msg, pcolor=C.WHITE):
    log(prefix, msg, pcolor, min_level=2)


# -----------------------------------------------------------------
#  INPUT VALIDATION
# -----------------------------------------------------------------
def validate_url(url: str) -> str:
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
#  URL HELPERS
# -----------------------------------------------------------------
from .constants import SKIP_EXTENSIONS

_VOLATILE_PATTERNS = [
    re.compile(r"csrfmiddlewaretoken\b[^>]{0,80}value=[\"'][^\"']{10,64}[\"']", re.I),
    re.compile(r"name=[\"'](?:_token|authenticity_token|csrf_token)[\"'][^>]*value=[\"'][^\"']{10,}[\"']", re.I),
    re.compile(r"(?<=[=:\"])" r"(?:nonce|_csrf|xsrf)[^\"\s&]{16,}", re.I),
    re.compile(r"(?<!\d)\d{13}(?!\d)"),
    re.compile(r"(?<=[=\"'])([0-9a-f]{40,64})(?=[\"'\s&]|$)", re.I),
]

def normalize_url(url: str, parent: str = "") -> Optional[str]:
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
    try:
        host = urlparse(url).hostname or ""
        return host == base_domain or host.endswith("." + base_domain)
    except Exception:
        return False

def content_hash(text: str) -> str:
    stripped = text
    for pat in _VOLATILE_PATTERNS:
        stripped = pat.sub("", stripped)
    return hashlib.sha256(stripped.encode("utf-8", errors="ignore")).hexdigest()[:16]

def random_ua() -> str:
    from .constants import USER_AGENTS
    return random.choice(USER_AGENTS)

def load_wordlist(path: Optional[str], default: List[str]) -> List[str]:
    if not path:
        return default
    path = validate_file_arg(path, "Wordlist")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    log("+WL", f"Loaded {col(len(words), C.BOLD)} words from {col(path, C.CYAN)}", C.GREEN)
    return words

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
