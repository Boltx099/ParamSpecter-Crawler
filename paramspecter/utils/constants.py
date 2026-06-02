"""
utils/constants.py
All constants: user-agents, MIME types, extensions, wordlists,
regex patterns, tech/WAF signatures, security headers, CWE map.
"""

import re
from typing import Dict, List

# -----------------------------------------------------------------
#  HTTP
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

CRAWLABLE_MIME = {"text/html", "text/plain", "application/xhtml+xml", "application/xml"}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".webm", ".ogg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dll", ".so", ".bin",
}

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


# -----------------------------------------------------------------
#  BUILT-IN WORDLISTS
# -----------------------------------------------------------------
BUILTIN_DIRS = [
    "admin","administrator","login","dashboard","panel","portal","console","manage",
    "management","backend","cms","wp-admin","wp-content","wp-login.php","wp-json",
    "wp-includes","joomla","drupal","typo3","laravel","symfony","rails",
    "api","v1","v2","v3","v4","rest","graphql","gql","swagger","swagger-ui",
    "swagger.json","openapi.json","openapi.yaml","api-docs","redoc","rpc",
    "dev","development","staging","test","testing","debug","debugbar","phpinfo.php",
    "info.php","server-status","server-info",".git","git","actuator","metrics",
    "health","healthz","ready","livez","status","monitor","trace",
    ".env",".env.local",".env.production","config","configuration","settings",
    "database","db","sql","phpmyadmin","adminer","backup","backups",
    ".htaccess",".htpasswd","web.config","crossdomain.xml","clientaccesspolicy.xml",
    "security.txt",".well-known","robots.txt","sitemap.xml",
    "upload","uploads","files","file","media","images","img","static","assets",
    "public","private","storage","data","downloads","export","import",
    "auth","oauth","oauth2","sso","logout","register","signup","forgot",
    "reset","verify","token","session","callback","profile","account","user","users",
    "nginx","apache","grafana","prometheus","kibana","elastic",
    "jenkins","ci","cd","pipeline","k8s","docker","terraform",
    "old","new","bak","backup","archive","temp","tmp","cache","hidden",
    "internal","secret","legacy","deprecated","_old","_backup",
    "search","query","feed","rss","atom","sitemap","download","report","reports",
    "log","logs","audit","error","errors","exception","exceptions",
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
    "api_key":     re.compile(r'(?:api[_\-]?key|apikey|secret)\s*[:=]\s*["\'\w\-]{8,}', re.I),
    "sourcemap":   re.compile(r'//# sourceMappingURL=(.+\.map)'),
    "endpoints":   re.compile(r"""['\"`](/(?:api|v\d+|admin|auth|user|graphql|rest)[^\s'"`<>]*)['\"`]""", re.I),
    "jwt":         re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
    "uuid":        re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    "internal_ip": re.compile(r'\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b'),
    "openapi":     re.compile(r'(?:href|src|url)\s*=\s*["\']((?:[^"\']*/)(?:swagger|openapi)[^"\'\s]*\.(?:json|yaml))["\']', re.I),
}

SOCIAL_DOMAINS = {
    "facebook.com","twitter.com","x.com","linkedin.com","instagram.com",
    "github.com","youtube.com","tiktok.com","t.me","discord.gg","reddit.com",
}

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

_CWE_MAP: Dict[str, str] = {
    "SQLi":            "CWE-89 (SQL Injection)",
    "XSS":             "CWE-79 (Cross-site Scripting)",
    "PathTraversal":   "CWE-22 (Path Traversal)",
    "SSRF":            "CWE-918 (SSRF)",
    "OpenRedirect":    "CWE-601 (Open Redirect)",
    "HeaderInjection": "CWE-113 (HTTP Response Splitting)",
    "IDOR":            "CWE-639 (IDOR)",
}
