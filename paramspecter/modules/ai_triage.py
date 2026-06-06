"""
modules/ai_triage.py
Phase 3 — AI-Powered Attack Surface Triage.

Supports every major AI provider. Users bring their own API key.
No key = no AI features, everything else still works normally.

Supported providers:
  - Anthropic   (Claude)        ANTHROPIC_API_KEY
  - OpenAI      (GPT-4o etc.)   OPENAI_API_KEY
  - Google      (Gemini)        GEMINI_API_KEY
  - Groq        (Llama/Mixtral) GROQ_API_KEY
  - Mistral                     MISTRAL_API_KEY
  - Ollama      (local models)  No key needed
  - Any OpenAI-compatible API   Custom base URL + key

Config via env vars or ~/.paramspecter/ai.conf (INI format).
"""

import configparser
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError

from ..utils import log, log_section, col, C


# -----------------------------------------------------------------
#  CONFIG FILE
# -----------------------------------------------------------------
CONFIG_PATH = os.path.expanduser("~/.paramspecter/ai.conf")

CONFIG_TEMPLATE = """\
# ParamSpecter AI Triage Configuration
# Place API keys here OR set them as environment variables.
# Environment variables always take precedence.
#
# Supported providers: anthropic, openai, gemini, groq, mistral, ollama, custom
#
[ai]
# Which provider to use by default
provider = anthropic

# Model override (leave blank to use provider default)
model =

# Max tokens in the AI response
max_tokens = 2000

[anthropic]
# Get yours at: https://console.anthropic.com/
api_key =
model = claude-sonnet-4-5

[openai]
# Get yours at: https://platform.openai.com/api-keys
api_key =
model = gpt-4o-mini

[gemini]
# Get yours at: https://aistudio.google.com/app/apikey
api_key =
model = gemini-1.5-flash

[groq]
# Get yours at: https://console.groq.com/keys
api_key =
model = llama3-70b-8192

[mistral]
# Get yours at: https://console.mistral.ai/api-keys/
api_key =
model = mistral-large-latest

[ollama]
# No API key needed — runs locally
base_url = http://localhost:11434
model = llama3

[custom]
# Point at any OpenAI-compatible API (Together, Anyscale, vLLM, etc.)
base_url =
api_key =
model =
"""


def _ensure_config_dir():
    d = os.path.dirname(CONFIG_PATH)
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            f.write(CONFIG_TEMPLATE)
        log("AI", f"Created config template at {col(CONFIG_PATH, C.CYAN)}", C.CYAN)
        log("AI", "Add your API key there or set the env var to enable AI triage.", C.CYAN)


def load_ai_config() -> configparser.ConfigParser:
    _ensure_config_dir()
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_PATH)
    return cfg


# -----------------------------------------------------------------
#  PROVIDER DEFINITIONS
# -----------------------------------------------------------------

class AIProvider:
    NAME    = "base"
    DEFAULT_MODEL = ""

    def __init__(self, api_key: str, model: str = "", max_tokens: int = 2000):
        self.api_key    = api_key
        self.model      = model or self.DEFAULT_MODEL
        self.max_tokens = max_tokens

    def chat(self, system: str, user: str) -> str:
        raise NotImplementedError

    def _http_post(self, url: str, headers: Dict, payload: Dict) -> Dict:
        data = json.dumps(payload).encode()
        req  = Request(url, data=data, headers=headers, method="POST")
        try:
            with urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            body = e.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {e.code}: {body[:200]}")

    def available(self) -> bool:
        return bool(self.api_key)


# ── Anthropic ────────────────────────────────────────────────────
class AnthropicProvider(AIProvider):
    NAME          = "anthropic"
    DEFAULT_MODEL = "claude-sonnet-4-5"
    API_URL       = "https://api.anthropic.com/v1/messages"

    def chat(self, system: str, user: str) -> str:
        payload = {
            "model":      self.model,
            "max_tokens": self.max_tokens,
            "system":     system,
            "messages":   [{"role": "user", "content": user}],
        }
        headers = {
            "x-api-key":         self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        }
        resp = self._http_post(self.API_URL, headers, payload)
        return resp["content"][0]["text"]


# ── OpenAI ───────────────────────────────────────────────────────
class OpenAIProvider(AIProvider):
    NAME          = "openai"
    DEFAULT_MODEL = "gpt-4o-mini"
    API_URL       = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str, model: str = "", max_tokens: int = 2000,
                 base_url: str = ""):
        super().__init__(api_key, model, max_tokens)
        self.api_url = (base_url.rstrip("/") + "/chat/completions") if base_url else self.API_URL

    def chat(self, system: str, user: str) -> str:
        payload = {
            "model":      self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
        }
        resp = self._http_post(self.api_url, headers, payload)
        return resp["choices"][0]["message"]["content"]


# ── Google Gemini ─────────────────────────────────────────────────
class GeminiProvider(AIProvider):
    NAME          = "gemini"
    DEFAULT_MODEL = "gemini-1.5-flash"

    def chat(self, system: str, user: str) -> str:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": user}]}],
            "generationConfig": {"maxOutputTokens": self.max_tokens},
        }
        headers = {"Content-Type": "application/json"}
        resp = self._http_post(url, headers, payload)
        return resp["candidates"][0]["content"]["parts"][0]["text"]


# ── Groq ─────────────────────────────────────────────────────────
class GroqProvider(OpenAIProvider):
    NAME          = "groq"
    DEFAULT_MODEL = "llama3-70b-8192"
    API_URL       = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self, api_key: str, model: str = "", max_tokens: int = 2000):
        super().__init__(api_key, model, max_tokens, base_url="https://api.groq.com/openai/v1")
        self.api_url = self.API_URL


# ── Mistral ──────────────────────────────────────────────────────
class MistralProvider(OpenAIProvider):
    NAME          = "mistral"
    DEFAULT_MODEL = "mistral-large-latest"
    API_URL       = "https://api.mistral.ai/v1/chat/completions"

    def __init__(self, api_key: str, model: str = "", max_tokens: int = 2000):
        super().__init__(api_key, model, max_tokens, base_url="https://api.mistral.ai/v1")
        self.api_url = self.API_URL


# ── Ollama (local) ───────────────────────────────────────────────
class OllamaProvider(AIProvider):
    NAME          = "ollama"
    DEFAULT_MODEL = "llama3"

    def __init__(self, model: str = "", max_tokens: int = 2000,
                 base_url: str = "http://localhost:11434"):
        super().__init__(api_key="", model=model, max_tokens=max_tokens)
        self.base_url = base_url.rstrip("/")

    def available(self) -> bool:
        # Check if Ollama is running
        try:
            with urlopen(f"{self.base_url}/api/tags", timeout=3):
                return True
        except Exception:
            return False

    def chat(self, system: str, user: str) -> str:
        url     = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ],
            "stream": False,
            "options": {"num_predict": self.max_tokens},
        }
        headers = {"Content-Type": "application/json"}
        resp = self._http_post(url, headers, payload)
        return resp["message"]["content"]


# ── Custom OpenAI-compatible ─────────────────────────────────────
class CustomProvider(OpenAIProvider):
    NAME = "custom"

    def __init__(self, api_key: str, model: str, base_url: str, max_tokens: int = 2000):
        super().__init__(api_key, model, max_tokens, base_url=base_url)


# -----------------------------------------------------------------
#  PROVIDER FACTORY
# -----------------------------------------------------------------
PROVIDER_MAP = {
    "anthropic": AnthropicProvider,
    "openai":    OpenAIProvider,
    "gemini":    GeminiProvider,
    "groq":      GroqProvider,
    "mistral":   MistralProvider,
    "ollama":    OllamaProvider,
    "custom":    CustomProvider,
}

ENV_KEY_MAP = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai":    "OPENAI_API_KEY",
    "gemini":    "GEMINI_API_KEY",
    "groq":      "GROQ_API_KEY",
    "mistral":   "MISTRAL_API_KEY",
}


def build_provider(provider_name: str = "",
                   model: str = "",
                   max_tokens: int = 2000,
                   cfg: configparser.ConfigParser = None) -> Optional[AIProvider]:
    """
    Build an AIProvider from env vars + config file.
    Returns None if no credentials found for the requested provider.
    """
    if cfg is None:
        cfg = load_ai_config()

    name = (provider_name or cfg.get("ai", "provider", fallback="anthropic")).lower()

    # Override model from global [ai] section if not specified
    if not model:
        model = cfg.get("ai", "model", fallback="") or cfg.get(name, "model", fallback="")

    max_tokens = int(cfg.get("ai", "max_tokens", fallback=str(max_tokens)))

    if name == "ollama":
        base_url = os.getenv("OLLAMA_BASE_URL") or cfg.get("ollama", "base_url", fallback="http://localhost:11434")
        p = OllamaProvider(model=model, max_tokens=max_tokens, base_url=base_url)
        return p if p.available() else None

    if name == "custom":
        base_url = os.getenv("CUSTOM_AI_BASE_URL") or cfg.get("custom", "base_url", fallback="")
        api_key  = os.getenv("CUSTOM_AI_API_KEY")  or cfg.get("custom", "api_key",  fallback="")
        model    = model or cfg.get("custom", "model", fallback="")
        if not base_url or not model:
            return None
        return CustomProvider(api_key=api_key, model=model, base_url=base_url, max_tokens=max_tokens)

    # Standard providers
    env_var = ENV_KEY_MAP.get(name)
    api_key = (os.getenv(env_var) if env_var else None) or cfg.get(name, "api_key", fallback="")
    if not api_key:
        return None

    cls = PROVIDER_MAP.get(name)
    if not cls:
        log("AI", col(f"Unknown provider: {name}", C.RED), C.RED)
        return None

    return cls(api_key=api_key, model=model, max_tokens=max_tokens)


def auto_detect_provider(cfg: configparser.ConfigParser = None) -> Optional[AIProvider]:
    """Try providers in priority order and return the first one with credentials."""
    if cfg is None:
        cfg = load_ai_config()

    priority = ["anthropic", "openai", "gemini", "groq", "mistral", "ollama", "custom"]
    for name in priority:
        p = build_provider(name, cfg=cfg)
        if p and p.available():
            return p
    return None


# -----------------------------------------------------------------
#  TRIAGE ENGINE
# -----------------------------------------------------------------
SYSTEM_PROMPT = """\
You are an expert penetration tester and bug bounty hunter analyzing the output
of an automated recon scan. Your job is to:
1. Identify the most critical attack vectors based on the findings
2. Explain WHY each vector is dangerous in the context of this specific target
3. Recommend concrete next steps (specific tools, specific commands)
4. Identify any patterns that suggest a larger systemic vulnerability
5. Flag anything that looks like a quick win for a bug bounty report

Be specific. Reference exact URLs, parameters, and technologies found.
Format your response in clear sections. Do not be generic.
"""

# -----------------------------------------------------------------
#  TECH-AWARE CONTEXT INJECTIONS
#  Appended to SYSTEM_PROMPT when the matching tech is detected.
#  Each block tells the AI exactly what to look for on that stack.
# -----------------------------------------------------------------
TECH_SYSTEM_PROMPTS: Dict[str, str] = {
    "WordPress": """
WORDPRESS-SPECIFIC GUIDANCE:
- Check for user enumeration via /?author=1, /?author=2 (username disclosure)
- Test xmlrpc.php for brute force amplification (multicall)
- Look for wp-config.php, wp-config.php.bak, wp-config.php~ exposure
- Check /wp-json/wp/v2/users for REST API user enumeration
- Probe /wp-content/uploads/ for directory listing
- Test wp-cron.php for CPU abuse (unauthenticated triggering)
- Common vulnerable params: p, page_id, cat, tag, s, attachment_id
- Check all plugins found in /wp-content/plugins/ for known CVEs
""",

    "Laravel": """
LARAVEL-SPECIFIC GUIDANCE:
- Test for .env file exposure at /.env, /.env.backup, /.env.local
- Check if APP_DEBUG=true leaks stack traces with credentials
- Probe /telescope for Telescope dashboard (often left open in staging)
- Test /_ignition/execute-solution for RCE (CVE-2021-3129 on Laravel < 8.4.3)
- Look for mass assignment vulnerabilities on all POST endpoints
- Check /storage symlink for file access bypass
- Test session cookies for insecure deserialization (Laravel uses HMAC but custom serializers exist)
- Probe /api/user, /api/v1/user for unauthenticated access
""",

    "Django": """
DJANGO-SPECIFIC GUIDANCE:
- Check for DEBUG=True error pages leaking settings and installed apps
- Test admin panel at /admin/, /django-admin/, /backend/
- Look for SECRET_KEY exposure in error pages or .env files
- Test CSRF token handling on all forms
- Probe /media/ and /static/ for directory traversal
- Check for Host header injection if ALLOWED_HOSTS is misconfigured
- Test for SSTI in custom template tags: {{ 7*7 }}, {{config}}
""",

    "Rails": """
RUBY ON RAILS-SPECIFIC GUIDANCE:
- Check for /rails/info/properties (often exposed in development mode)
- Test for mass assignment via params[:user] patterns
- Look for secret_key_base exposure enabling cookie forgery
- Probe /assets/ for source map files leaking original CoffeeScript/JS
- Test CSRF token on non-GET requests
- Check for open redirect in redirect_to with user input
- Probe /sidekiq for job queue dashboard (often unprotected)
""",

    "Spring": """
SPRING/JAVA-SPECIFIC GUIDANCE:
- Probe ALL Spring Actuator endpoints: /actuator, /actuator/env,
  /actuator/heapdump, /actuator/beans, /actuator/mappings, /actuator/loggers
- Test for Spring4Shell (CVE-2022-22965) on Spring MVC with JDK 9+
- Check /actuator/heapdump for credentials in heap dump
- Test Thymeleaf template injection: __${7*7}__::.x, ${7*7}
- Probe /h2-console for exposed H2 database console
- Look for Spring Security misconfiguration allowing /actuator/** access
- Test Java deserialization endpoints (Content-Type: application/x-java-serialized-object)
""",

    "GraphQL": """
GRAPHQL-SPECIFIC GUIDANCE:
- Test introspection: {"query":"{__schema{types{name}}}"}
- Try field suggestion attacks to enumerate hidden fields
- Test for nested query DoS: deeply nested __typename queries
- Test batching attacks: send array of queries in one request
- Look for IDOR through object IDs in queries: user(id: 2), user(id: 3)
- Test for query aliasing to bypass rate limits: {a:user(id:1) b:user(id:2)}
- Check mutations for missing authorization checks
- Probe /graphiql, /playground for exposed IDE
""",

    "AWS": """
AWS/CLOUD-SPECIFIC GUIDANCE:
- Test SSRF payloads targeting: http://169.254.169.254/latest/meta-data/
- Check for exposed S3 buckets: s3.amazonaws.com, target.s3.amazonaws.com
- Look for AWS keys in JS files: AKIA[0-9A-Z]{16} pattern
- Test for S3 bucket listing: bucket.s3.amazonaws.com/?list-type=2
- Probe Cognito endpoints for user pool enumeration
- Check CloudFront distributions for origin bypass
- Look for exposed Lambda function URLs
""",

    "Next.js": """
NEXT.JS-SPECIFIC GUIDANCE:
- Check /_next/static/ for source maps and bundle analysis
- Probe /api/ routes for unauthenticated access (Next.js API routes)
- Test getServerSideProps for SSRF if it fetches external URLs
- Look for exposed /_next/data/ endpoints leaking server-rendered data
- Check window.__NEXT_DATA__ in page source for sensitive props
- Test /api/auth/ (NextAuth) endpoints for misconfiguration
""",

    "Node.js": """
NODE.JS-SPECIFIC GUIDANCE:
- Test for prototype pollution: ?__proto__[admin]=true, ?constructor[prototype][admin]=true
- Check for path traversal in express static file serving
- Test template injection in Pug/EJS/Handlebars: {{7*7}}, #{7*7}
- Look for exposed /.env, /package.json, /package-lock.json
- Probe /node_modules/ for directory listing
- Test JWT tokens: alg:none attack, HS256→RS256 confusion
""",

    "PHP": """
PHP-SPECIFIC GUIDANCE:
- Test for LFI: ?file=../../../etc/passwd, ?page=php://filter/convert.base64-encode/resource=index
- Check for RFI if allow_url_include is on
- Test file upload endpoints for PHP shell upload (.php, .phtml, .php5)
- Look for phpinfo() exposure: /phpinfo.php, /info.php, /test.php
- Check for exposed .php~ backup files and .swp files
- Test deserialization in cookies/parameters if using serialize()
- Probe /phpmyadmin/, /pma/, /mysql/ for database admin panels
""",

    "Nginx": """
NGINX-SPECIFIC GUIDANCE:
- Test for path traversal via alias misconfiguration: /static../etc/passwd
- Check for off-by-slash: /files vs /files/ behaviour difference
- Look for exposed /nginx_status endpoint
- Test CRLF injection in redirect rules
- Probe /.git/, /.svn/ for source code exposure
""",

    "Apache": """
APACHE-SPECIFIC GUIDANCE:
- Check for exposed /server-status and /server-info pages
- Test for mod_status information disclosure
- Look for .htaccess exposure if AllowOverride is misconfigured
- Test for directory traversal via mod_rewrite rules
- Probe for exposed backup files: .bak, .old, ~, .orig
- Check for Apache Struts if Java — test CVE-2017-5638 (Content-Type injection)
""",
}

# Map common tech detection strings to prompt keys
_TECH_KEY_MAP = {
    "wordpress": "WordPress", "wp-": "WordPress",
    "laravel":   "Laravel",
    "django":    "Django",
    "rails":     "Rails",    "ruby":    "Rails",
    "spring":    "Spring",   "java":    "Spring",
    "graphql":   "GraphQL",
    "aws":       "AWS",      "amazon":  "AWS",      "s3":    "AWS",
    "next.js":   "Next.js",  "nextjs":  "Next.js",  "next":  "Next.js",
    "node":      "Node.js",  "express": "Node.js",
    "php":       "PHP",
    "nginx":     "Nginx",
    "apache":    "Apache",
}


def _build_tech_context(techs: set) -> str:
    """Build extra system context based on detected technologies."""
    matched_keys: set = set()
    for tech in techs:
        tech_lower = tech.lower()
        for keyword, prompt_key in _TECH_KEY_MAP.items():
            if keyword in tech_lower and prompt_key not in matched_keys:
                matched_keys.add(prompt_key)

    if not matched_keys:
        return ""

    context = "\n\n=== TECH-SPECIFIC ATTACK GUIDANCE ===\n"
    for key in matched_keys:
        if key in TECH_SYSTEM_PROMPTS:
            context += TECH_SYSTEM_PROMPTS[key]
    return context

TRIAGE_PROMPT_TEMPLATE = """\
Target: {target}
Scan mode: {mode}
Duration: {duration}
Technologies detected: {techs}
WAFs detected: {wafs}

=== FINDINGS SUMMARY ===
Pages crawled: {pages}
Emails found: {emails}
Secrets found: {secrets}
Forms found: {forms}
Subdomains: {subdomains}
URL parameters: {params}
Open API specs: {openapi}
Missing security headers: {sec_headers}

=== HIGH-PRIORITY FINDINGS ===
{high_findings}

=== INTERESTING ENDPOINTS ===
{interesting}

=== JS SECRETS DISCOVERED ===
{js_secrets}

=== DIRECTORY/FILE HITS ===
{dir_hits}

=== PARAMETER FUZZ HITS ===
{param_hits}

Based on these findings, provide:
1. TOP 3 ATTACK VECTORS (most likely to yield a valid bug bounty finding)
2. TECH STACK ANALYSIS (what vulnerabilities are common in this stack)
3. RECOMMENDED NEXT STEPS (exact commands)
4. QUICK WINS (anything that looks immediately reportable)
5. WHAT TO INVESTIGATE FURTHER
"""


def _build_triage_prompt(scanner) -> str:
    """Build the triage prompt from a ParamSpecter scanner instance."""

    def _fmt_list(items, limit=10):
        items = list(items)[:limit]
        if not items:
            return "none"
        return "\n  - " + "\n  - ".join(str(i) for i in items)

    high_findings = []
    for f in scanner.all_secrets[:5]:
        high_findings.append(f"[SECRET] {f.get('type','?')}: {f.get('value','')[:40]} (src: {f.get('source','')})")
    for h in scanner.param_hits[:5]:
        if h.get("reflected"):
            high_findings.append(f"[XSS-CANDIDATE] ?{h.get('param')} reflected on {h.get('url','')}")
    for h in scanner.dir_hits[:5]:
        high_findings.append(f"[DIR] {h.get('url','')} [{h.get('status')}]")

    interesting = []
    seen = set()
    for item in scanner.all_interesting[:15]:
        if item not in seen:
            seen.add(item)
            interesting.append(item)

    return TRIAGE_PROMPT_TEMPLATE.format(
        target       = scanner.start_url,
        mode         = scanner.mode,
        duration     = scanner.stats.elapsed(),
        techs        = ", ".join(scanner.all_techs) or "unknown",
        wafs         = ", ".join(scanner.all_wafs) or "none detected",
        pages        = scanner.stats.pages_crawled,
        emails       = len(scanner.all_emails),
        secrets      = len(scanner.all_secrets),
        forms        = scanner.all_forms,
        subdomains   = len(scanner.all_subdomains) + len(scanner.subdomain_hits),
        params       = len(scanner.all_params),
        openapi      = len(scanner.all_openapi),
        sec_headers  = _fmt_list(
            f"{h}: {c} page(s)" for h, c in
            sorted(scanner.missing_sec_headers.items(), key=lambda x: -x[1])
        ),
        high_findings = "\n".join(high_findings) or "  none",
        interesting   = _fmt_list(interesting),
        js_secrets    = _fmt_list(
            f"[{s.get('type','?')}] {s.get('value','')[:50]}"
            for s in scanner.all_secrets[:10]
        ),
        dir_hits      = _fmt_list(
            f"{h.get('url','')} [{h.get('status')}] {h.get('size','')}B"
            for h in scanner.dir_hits[:8]
        ),
        param_hits    = _fmt_list(
            f"?{h.get('param','')} — {h.get('check','?')} [{h.get('severity','?')}] conf={h.get('confidence',0)}%"
            for h in scanner.param_hits[:8]
        ),
    )


def _build_system_prompt(scanner) -> str:
    """Build a tech-aware system prompt for the specific target."""
    tech_context = _build_tech_context(getattr(scanner, "all_techs", set()))
    return SYSTEM_PROMPT + tech_context


class AITriage:
    """
    Runs AI triage after a scan and returns a structured analysis.
    """

    def __init__(self, provider: Optional[AIProvider] = None,
                 provider_name: str = "", model: str = ""):
        self.provider = provider or build_provider(provider_name, model)

    def available(self) -> bool:
        return self.provider is not None and self.provider.available()

    def run(self, scanner) -> Optional[str]:
        """
        Send scan results to the AI provider and return the triage text.
        Returns None if AI is not configured.
        """
        if not self.available():
            log("AI", col(
                "No AI provider configured. Set an API key env var or edit "
                f"~/.paramspecter/ai.conf  (run once to generate the template)",
                C.YELLOW
            ), C.YELLOW)
            return None

        pname = self.provider.NAME
        model = self.provider.model
        log_section(f"AI TRIAGE — {pname.upper()} / {model}")
        log("AI", f"Sending scan results to {col(pname, C.CYAN)} ({col(model, C.GRAY)})...", C.CYAN)

        prompt     = _build_triage_prompt(scanner)
        sys_prompt = _build_system_prompt(scanner)

        # Log which tech-specific prompts were injected
        matched = _build_tech_context(getattr(scanner, "all_techs", set()))
        if matched:
            techs_str = ", ".join(scanner.all_techs)
            log("AI", col(f"Tech-aware prompts injected for: {techs_str}", C.CYAN), C.CYAN)

        t0 = time.monotonic()
        try:
            result = self.provider.chat(sys_prompt, prompt)
        except Exception as e:
            log("AI", col(f"AI triage failed: {e}", C.RED), C.RED)
            return None

        elapsed = time.monotonic() - t0
        log("AI", f"Response received in {col(f'{elapsed:.1f}s', C.CYAN)}", C.GREEN)

        self._print_result(result, pname, model)
        return result

    def _print_result(self, text: str, provider: str, model: str) -> None:
        sep = col("─" * 70, C.CYAN)
        print(f"\n{sep}")
        print(f"  {col('AI TRIAGE REPORT', C.BOLD+C.WHITE)}  "
              f"{col(f'({provider} / {model})', C.GRAY)}")
        print(sep)
        for line in text.splitlines():
            if line.startswith("#") or line.isupper() or line.startswith("==="):
                print(f"  {col(line, C.YELLOW+C.BOLD)}")
            elif line.strip().startswith("-") or line.strip().startswith("*"):
                print(f"  {col(line, C.CYAN)}")
            else:
                print(f"  {line}")
        print(sep + "\n")

    def save(self, text: str, output_dir: str, base_domain: str) -> str:
        """Save triage report to a markdown file."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(output_dir, f"paramspecter_{base_domain}_{ts}_ai_triage.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# AI Triage Report\n\n")
            f.write(f"**Provider:** {self.provider.NAME} / {self.provider.model}\n")
            f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
            f.write("---\n\n")
            f.write(text)
        log("AI", f"Triage report saved → {col(path, C.CYAN)}", C.GREEN)
        return path


# -----------------------------------------------------------------
#  CLI HELPER — print provider status
# -----------------------------------------------------------------
def print_ai_status() -> None:
    """Print which providers are configured — useful for --ai-status flag."""
    cfg = load_ai_config()
    log_section("AI PROVIDER STATUS")
    for name, env_var in ENV_KEY_MAP.items():
        key = os.getenv(env_var) or cfg.get(name, "api_key", fallback="")
        model = cfg.get(name, "model", fallback=PROVIDER_MAP[name].DEFAULT_MODEL
                        if hasattr(PROVIDER_MAP[name], "DEFAULT_MODEL") else "?")
        if key:
            masked = key[:4] + "..." + key[-4:] if len(key) > 8 else "****"
            log(name.upper(), f"{col('configured', C.GREEN)}  key={col(masked, C.GRAY)}  model={col(model, C.CYAN)}", C.GREEN)
        else:
            log(name.upper(), col(f"not configured  (set {env_var})", C.GRAY), C.GRAY)

    # Ollama
    p = OllamaProvider()
    if p.available():
        log("OLLAMA", col("running locally", C.GREEN), C.GREEN)
    else:
        log("OLLAMA", col("not running (start with: ollama serve)", C.GRAY), C.GRAY)

    print(f"\n  Config file: {col(CONFIG_PATH, C.CYAN)}")
    print(f"  Docs: {col('https://github.com/Boltx/ParamSpecter#ai-triage', C.CYAN)}\n")
