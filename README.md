<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

---

# ParamSpecter v7.4 — Advanced Recon Crawler

> **For authorized and educational use ONLY.**
> Only test targets you own or have explicit written permission to test.
> Unauthorized testing is illegal.

---

## What is ParamSpecter?

ParamSpecter is an advanced AI reconnaissance crawler built for bug bounty hunters and security researchers. It performs deep recursive crawling, JS analysis, subdomain discovery, directory enumeration, parameter fuzzing with active vulnerability detection, secret scanning, technology fingerprinting, automated form login — and now **out-of-band blind detection**, **confidence scoring**, and **session health monitoring** — all from a single command.

---

## Changelog

### v7.4 — Current Release (Tier 3)

**Smart Phase-Aware Resume (`--resume`)**

The checkpoint system is now fully phase-aware. Instead of only tracking visited URLs, it stores the complete scan state including which phases completed, how many findings each produced, and discovered params/techs/subdomains. On resume, completed phases are skipped entirely — not just their URLs. If crawling and subdomain enumeration finished but the scan was interrupted during directory hunting, `--resume` jumps straight to directory hunting.

```bash
# Scan interrupted mid-way
python -m paramspecter https://target.com --mode full --max-pages 100

# Resume — skips already-completed phases automatically
python -m paramspecter https://target.com --mode full --max-pages 100 --resume
```

Checkpoint files are now JSON (`.json` instead of `.txt`) and stored atomically. Old `.txt` checkpoints still load fine.

**Scope Diffing (`--scope-diff`, `--h1-program`, `--bc-program`)**

Compare current scan against a previous scan to surface only new attack surface — new endpoints, new parameters, new subdomains, new secrets, removed endpoints, and status changes.

Also validates crawled URLs against HackerOne and Bugcrowd program scopes so you know before reporting whether a finding is in-scope.

```bash
# Save a baseline scan
python -m paramspecter https://target.com --mode full -o json

# A week later — show only what's new
python -m paramspecter https://target.com --mode full --scope-diff paramspecter_target_com_20260101_120000.json

# Validate scope against HackerOne program
python -m paramspecter https://target.com --mode full --h1-program uber

# Validate scope against Bugcrowd program
python -m paramspecter https://target.com --mode full --bc-program tesla
```

**Nuclei Template Auto-Generator (`--nuclei-gen`)**

Generates a complete set of production-quality Nuclei YAML templates from all findings. Creates four template categories with a ready-to-run shell script.

```bash
python -m paramspecter https://target.com --mode full --deep-fuzz --nuclei-gen

# Then run all generated templates:
nuclei -t ./paramspecter_target_com_*_nuclei_templates/ -u https://target.com
# Or use the generated run script:
./paramspecter_target_com_*_nuclei_templates/run.sh
```

Template categories generated: `vulnerabilities/` (SQLi, XSS, SSRF, etc.), `secrets/` (exposed credentials), `paths/` (discovered endpoints), `headers/` (missing security headers). Each template includes evidence-based matchers, CVSS metadata, CWE IDs, and proper tags.

### v7.3 — Tier 2

**Adaptive AI Prompting by Tech Stack**

AI triage and chat now inject tech-specific attack guidance based on detected technologies. Covers 11 stacks: WordPress, Laravel, Django, Rails, Spring/Java, GraphQL, AWS, Next.js, Node.js, PHP, Nginx, Apache. If Spring Boot is detected, the AI automatically focuses on Actuator endpoints, heapdump credential extraction, Spring4Shell, and Thymeleaf SSTI instead of giving generic advice.

**Professional Pentest Report (`--pro-report`)**

Deliverable-ready HTML report with CVSS v3 scores, executive summary, impact analysis, OWASP/CWE mapping, copy-paste curl PoC commands, confidence bars, and auto-generated Nuclei YAML templates for every finding.

```bash
python -m paramspecter https://target.com --mode full --deep-fuzz --pro-report --ai-triage
```

**JavaScript Source Map Exploitation**

Detected source maps are automatically downloaded and original pre-minified TypeScript/JSX source is scanned for secrets, internal API paths, and security-relevant developer comments. Runs automatically — no flag needed.

### v7.2 — Tier 1 Security Intelligence Update (Current)

Three major new systems that put ParamSpecter in a different class from free open-source tools.

---

#### 🔴 Feature 1 — OOB Blind Detection Engine (`--oob`)

**The single biggest gap in most free scanners.** Blind SQLi, SSRF, XXE, CMDi, and Log4Shell never appear in response analysis — they only show up when the server phones home. ParamSpecter now detects them automatically via [interactsh](https://github.com/projectdiscovery/interactsh) (ProjectDiscovery's free Burp Collaborator alternative).

**45 payloads across 6 vulnerability classes:**

| Class | Payloads | Coverage |
|---|---|---|
| **BlindSQLi** | 8 | MySQL `LOAD_FILE` UNC, MSSQL `xp_dirtree`/`xp_subdirs`, Oracle `UTL_HTTP`/`UTL_INADDR`, PostgreSQL `COPY TO PROGRAM` |
| **BlindSSRF** | 9 | HTTP/HTTPS, `dict://`, `gopher://`, IPv6 bypass, `@`-bypass, double-slash, AWS metadata redirect |
| **BlindXXE** | 4 | Classic entity, parameter entity (bypasses basic filters), SVG XXE, ZIP/Excel XXE |
| **BlindCMDi** | 11 | Backtick, `$()`, `;`, `\|`, `&&`, `curl`/`wget`, Windows `&`, newline injection |
| **Log4Shell** | 7 | JNDI ldap/dns/rmi + 4 WAF-bypass obfuscation variants |
| **BlindSSTI** | 5 | Jinja2, Freemarker, Velocity, Smarty, Pebble |

**Log4Shell also injects into 9 HTTP headers** that commonly get logged server-side: `User-Agent`, `X-Forwarded-For`, `CF-Connecting-IP`, `X-Originating-IP`, `X-Remote-Addr`, `X-Api-Version`, `Referer`, `X-Request-Id`, `X-Remote-IP`.

Every payload embeds a **unique subdomain** so each DNS/HTTP callback is attributed to the exact parameter that triggered it. No manual correlation needed.

Uses the **public interactsh pool** by default — no server, no account, no config needed:

```bash
# Enable OOB detection
paramspecter https://target.com --mode param --deep-fuzz --oob

# Use a self-hosted interactsh server
paramspecter https://target.com --oob --oob-server https://my-interact.sh
```

Output in terminal and HTML report:
```
[OOB]  [!!!] BLIND HIT  BlindSQLi  param=id  via=DNS  from=13.56.23.10
       DNS callback confirmed from 13.56.23.10 to sqli-a1b2c3.abc123.oast.pro
       [95% CONFIRMED]
```

OOB findings get their own section in the HTML report — separated from response-analysis hits — so you know immediately which ones are confirmed vs heuristic.

**No extra dependencies for public interactsh pool.** Install `pycryptodome` only if self-hosting interactsh with AES encryption.

---

#### 🟡 Feature 2 — Confidence Scoring Engine (`--min-confidence`)

Every finding now gets a **0–100 confidence score** so you know which bugs to act on first and which are likely false positives.

| Score | Label | Action |
|---|---|---|
| **85–100** | `CONFIRMED` | Act on this. Hard evidence. |
| **65–84** | `LIKELY` | Strong signal — investigate. |
| **40–64** | `POSSIBLE` | Interesting — manual verify. |
| **20–39** | `LOW-CONFIDENCE` | Probably FP. |
| **0–19** | `NOISE` | Drop it. |

**Per-check scoring logic — not a one-size-fits-all formula:**

- **SQLi**: DB error keyword match (+35), time delta ≥ 2.5s above baseline (+30), stack trace leaked (+15), HTTP 500 (+10). Penalised for WAF block pages (-20), Cloudflare challenges (-25), empty bodies (-15).
- **XSS**: Unencoded `<script>alert()` in response (+40), event handler reflected (+30), `alert(1)` without entity encoding (+20). Penalised heavily if payload was HTML-entity encoded (-25) — that's output escaping, not a bug.
- **PathTraversal**: `/etc/passwd` or `win.ini` content in response (+50). This one is binary — either you have it or you don't.
- **SSRF**: Cloud metadata content (AMI IDs, IAM credentials) (+50), internal RFC-1918 IP in body (+25).
- **CORS**: Evil origin reflected in `ACAO` header (+35), `ACAC: true` with reflected origin (+10), `ACAO: null` (+15).
- **OOB**: Always 85–97. DNS/HTTP callbacks are cryptographically attributed — they don't lie.

Noise filtering — drop everything below a threshold before saving:

```bash
# Keep only POSSIBLE and above (recommended starting point)
paramspecter https://target.com --mode param --deep-fuzz --min-confidence 40

# Keep only high-confidence findings (CONFIRMED + LIKELY)
paramspecter https://target.com --mode param --deep-fuzz --min-confidence 65
```

The HTML report shows confidence badges colour-coded by level. The JSON export includes `confidence`, `conf_label`, `conf_reasons`, and a `finding_summary` block with counts per tier.

---

#### 🟢 Feature 3 — Session Health Monitor

Authenticated scans silently break when JWTs expire, CSRF tokens rotate, or Laravel sessions time out. Every page starts returning a login form — the scanner keeps crawling, finding nothing, and you don't know until you look at the empty output.

ParamSpecter now detects session expiry in real time and re-authenticates automatically without stopping the scan.

**How it works:**

1. After initial login, the monitor learns what "healthy" looks like: which indicator strings appear only when logged in, which cookies must be present.
2. Every 20 pages (configurable), it GETs a check URL and verifies the indicators are still there.
3. On any `401`/`403` response during crawl, it triggers an immediate check.
4. If unhealthy: re-runs `FormLoginHandler.login()` up to 3 times with exponential backoff. Up to 5 full heal events before flagging the scan as broken.
5. While healing, other worker threads pause briefly so no URLs are lost from the queue.

```bash
# Basic — auto-detects auth indicators ("logout", "dashboard", etc.)
paramspecter https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass password \
  --mode full

# Custom indicators (use strings unique to authenticated pages)
paramspecter https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass password \
  --auth-indicators "Welcome, Admin" "Sign Out" "My Dashboard" \
  --auth-check-url https://target.com/dashboard \
  --health-check-interval 10
```

Session health summary in final output:
```
Session Health:  12 checks, 2 heals, 0 failed re-auths — OK
```

---

### Previous Releases

#### v7.2 (pre-Tier1) — Chrome TLS + SPA Detection

- **Chrome TLS fingerprint spoofing** via `curl_cffi` — bypasses Cloudflare/DataDome/Akamai bot detection that fingerprints Python's TLS handshake
- **SPA auto-detection** — upgrades to Playwright automatically when a page returns a JS shell with < 500 chars visible text
- **Full XHR/fetch/WebSocket interception** — intercepts all network traffic, blocks images/fonts for 3–5× speed improvement
- **Playwright resource blocking via `page.route()`** — fixed from v7.1 where `request.abort()` was incorrectly called on non-intercepted requests

#### v7.1 — Live Dashboard + AI Chat + Burp Export

- **Live terminal dashboard** — real-time curses UI, 4 updates/second, falls back gracefully on Windows CMD
- **AI Chat mode** (`--ai-chat`) — multi-turn conversation about scan results with full history
- **Burp Suite XML export** (`--burp-export`) — param hit payloads injected into URLs, high findings highlighted red

#### v7.0 — Auto Orchestrator + Watch Mode + AI Triage

- **Auto Orchestrator** (`--auto`) — detects and runs subfinder, gau, katana, arjun, dalfox, sqlmap, nuclei, trufflehog; merges all results
- **Watch Mode** (`--watch`) — continuous monitoring with SQLite diff engine; alerts via Slack/Discord/Telegram/email
- **AI Triage** (`--ai-triage`) — 7 provider support (Anthropic, OpenAI, Gemini, Groq, Mistral, Ollama, custom); BYOK

#### v6.0

Refactored from a single monolithic file into a proper Python package. Added IDOR, HeaderInjection, OpenAPI discovery, JSONL streaming, per-phase timing, CWE cross-references, scope file, rate limiting, resume/checkpoint, HTML report.

---

## Installation

### 1. Clone

```bash
git clone https://github.com/Boltx/ParamSpecter-Crawler.git
cd ParamSpecter-Crawler
```

### 2. Virtual environment (recommended)

```bash
# Linux / macOS
python3 -m venv venv && source venv/bin/activate

# Windows CMD
python -m venv venv && venv\Scripts\activate.bat

# Windows PowerShell
python -m venv venv; venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. (Optional but strongly recommended) WAF bypass

```bash
pip install curl-cffi
```

You'll see `HTTP  Using curl_cffi — Chrome TLS fingerprint active` at startup.

### 5. (Optional) OOB with AES-encrypted self-hosted interactsh

Public interactsh pool works with zero extra dependencies. Only needed if self-hosting with AES encryption:

```bash
pip install pycryptodome
```

### 6. (Optional) JS-rendered sites

```bash
pip install playwright && playwright install chromium
```

### 7. (Optional) Install as global command

```bash
pip install -e .
# Now run: paramspecter https://example.com
```

### 8. (Optional) External tools for Auto Orchestrator

```bash
# Go tools (requires Go 1.21+: https://go.dev/dl/)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Python tools
pip install arjun sqlmap

# OOB self-hosted (optional — public pool works without this)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

paramspecter --tools-status   # verify what's detected
```

### 9. (Optional) AI providers

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # Claude
export OPENAI_API_KEY=sk-...           # GPT-4o
export GEMINI_API_KEY=AI...            # free tier
export GROQ_API_KEY=gsk_...            # free tier, fastest
# or: ollama serve && ollama pull llama3

paramspecter --ai-status               # verify detection
```

---

## System Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.8+ |
| OS | Linux, macOS, Windows |
| RAM | 256 MB (512 MB+ with Playwright) |
| Network | Outbound HTTP/HTTPS + DNS |

---

## Quick Start

```bash
# Basic crawl
paramspecter https://example.com

# Full recon — all built-in phases
paramspecter https://example.com --mode full -t 20 --ignore-robots

# Deep fuzz with OOB blind detection + noise filtering
paramspecter https://example.com --mode param --deep-fuzz \
  --oob --min-confidence 40

# Authenticated full scan with session health monitor
paramspecter https://example.com --mode full \
  --login-url https://example.com/login \
  --login-user admin --login-pass hunter2 \
  --auth-indicators "Logout" "My Account" \
  --oob --deep-fuzz --min-confidence 20

# Everything — full scan + auto orchestrator + OOB + AI triage
paramspecter https://example.com --mode full --auto \
  --oob --deep-fuzz --min-confidence 20 \
  --ai-triage --ai-provider groq

# Watch mode — re-scan every 6 hours, alert on new findings
paramspecter https://example.com --watch --interval 6h \
  --notify-webhook https://hooks.slack.com/services/YOUR/WEBHOOK

# Check tools + providers
paramspecter --tools-status
paramspecter --ai-status
```

---

## All CLI Options

```
positional:
  url                        Target URL  e.g. https://example.com

mode:
  --mode                     crawl | fuzz | param | subdomain | full  (default: crawl)

crawl:
  -m, --max-pages            Max pages to crawl (default: 100)
  -d, --delay                Delay between requests in seconds (default: 0.2)
  -D, --depth                Max crawl depth (default: 4)
  -t, --threads              Number of worker threads (default: 10)
  --timeout                  Request timeout in seconds (default: 10)
  --max-retries              Max retries per URL (default: 3)
  --strategy                 bfs | dfs | priority  (default: bfs)
  --follow-external          Follow links to external domains
  --ignore-robots            Ignore robots.txt restrictions
  --playwright               Use headless Chromium for JS rendering + XHR interception

identity and evasion:
  -u, --user-agent           Custom User-Agent string
  --rotate-ua                Rotate User-Agent from pool on each request
  --cookies                  Cookie string: "a=1; b=2"
  --headers                  Extra request headers: "X-Foo: bar"  (repeatable)
  --proxies                  Comma-separated proxy list: http://127.0.0.1:8080,...

authentication:
  --login-url URL            Login page URL — triggers automated form login
  --login-user USER          Username or email
  --login-pass PASS          Password
  --login-user-field FIELD   name= of username input (default: username)
  --login-pass-field FIELD   name= of password input (default: password)

── Session Health Monitor (NEW) ─────────────────────────────────
  --auth-check-url URL       URL to GET to verify auth is still alive
                             (default: --login-url)
  --auth-indicators STRING+  Strings that ONLY appear when logged in
                             e.g. --auth-indicators "Logout" "My Dashboard"
                             (default: auto-detect common patterns)
  --health-check-interval N  Check session health every N pages (default: 20)

subdomain enumeration:
  -sw, --sub-wordlist        Custom subdomain wordlist

directory hunting:
  -w,  --wordlist            Directory / endpoint wordlist
  -x,  --extensions          File extensions to append: .php,.html,.bak
  --match-codes              Only show these HTTP codes: 200,301,403
  --hide-codes               Hide these HTTP codes (default: 404)
  --recursive                Recursively enumerate discovered directories
  --recursive-depth          Max recursion depth (default: 2)

parameter fuzzing:
  -pw, --param-wordlist      Parameter wordlist
  --param-method             GET | POST  (default: GET)
  --smart-fuzz               Test 6 payloads per param
  --deep-fuzz                Full per-param vuln checks with CWE refs
  --payload-file FILE        Custom payload file: LABEL:payload per line

── OOB Blind Detection (NEW) ────────────────────────────────────
  --oob                      Enable out-of-band blind detection via interactsh
                             Finds: blind SQLi, SSRF, XXE, CMDi, Log4Shell, SSTI
                             Uses public interactsh pool by default (no config needed)
  --oob-server URL           Custom interactsh server URL
                             (default: auto-select from public pool)

── Confidence Scoring (NEW) ─────────────────────────────────────
  --min-confidence 0-100     Drop findings below this confidence score
                             0 = keep all findings (default)
                             20 = remove obvious noise
                             40 = POSSIBLE and above only (recommended)
                             65 = LIKELY and CONFIRMED only

scope / rate / resume / output:
  --scope-file FILE          File of in-scope domains (wildcards: *.example.com)
  --rate-limit REQ/S         Max requests per second per host
  --resume                   Resume a previous scan
  --resume-file FILE         Path to checkpoint file
  -o, --output               json | csv | both | jsonl  (default: both)
  --output-dir DIR           Directory for all output files (default: .))
  --export-targets           Write nuclei-ready targets.txt + sqlmap_targets.txt

verbosity (mutually exclusive):
  --quiet                    Findings and summary only
  --verbose                  Show retry, skip, and dedup messages

── Auto Orchestrator ────────────────────────────────────────────
  --auto                     Run all available external tools and merge results
  --tools-status             Show which external tools are installed and exit

── Watch Mode ───────────────────────────────────────────────────
  --watch                    Continuous monitoring — re-scan on a schedule
  --interval INTERVAL        Scan interval: 6h, 30m, 1d  (default: 24h)
  --watch-db FILE            SQLite db file for scan history
  --notify-webhook URL       Webhook URL for alerts (Slack / Discord / custom)
  --notify-telegram          Send Telegram alerts
  --tg-token TOKEN           Telegram bot token
  --tg-chat CHAT_ID          Telegram chat ID
  --notify-email TO          Email address for alerts
  --smtp-host HOST           SMTP server hostname
  --smtp-port PORT           SMTP port (default: 587)
  --smtp-user USER           SMTP username
  --smtp-pass PASS           SMTP password

── AI Triage ────────────────────────────────────────────────────
  --ai-triage                AI-powered attack surface analysis after scan
  --ai-chat                  Interactive AI chat about scan results
  --ai-provider PROVIDER     anthropic | openai | gemini | groq | mistral | ollama | custom
  --ai-model MODEL           Model override: gpt-4o, claude-sonnet-4-5, llama3
  --ai-status                Show configured AI providers and exit

── Output Extras ────────────────────────────────────────────────
  --burp-export              Export results as Burp Suite XML
  --dashboard                Live terminal dashboard during scan
  --pro-report               Professional pentest report with CVSS, PoC commands, nuclei templates
  --nuclei-gen               Auto-generate Nuclei YAML templates for all findings

── Scope Diffing (Tier 3) ───────────────────────────────────────
  --scope-diff PREV_JSON     Diff against a previous scan JSON — shows only new attack surface
  --h1-program HANDLE        Validate scope against HackerOne program  (e.g. uber, shopify)
  --bc-program HANDLE        Validate scope against Bugcrowd program   (e.g. tesla, verizon)
```

---

## Deep Fuzz Checks (`--deep-fuzz`)

| Check | Severity | CWE | Detection method |
|---|---|---|---|
| SQLi | HIGH | CWE-89 | DB error keywords + baseline-aware time-based blind |
| XSS | HIGH | CWE-79 | Unencoded reflection + event handler survives tag strip |
| PathTraversal | HIGH | CWE-22 | `/etc/passwd` or `win.ini` content in response |
| SSRF | HIGH | CWE-918 | AWS/GCP/Azure metadata endpoint content |
| OpenRedirect | MEDIUM | CWE-601 | `Location` header redirect to canary domain |
| HeaderInjection | HIGH | CWE-113 | CRLF injected header appears in response |
| IDOR | HIGH | CWE-639 | Status/size delta on numeric ID ±1/±100/0 |
| GraphQL | MEDIUM | CWE-200 | Introspection query on 9 common endpoints |
| CORS | HIGH | CWE-942 | Reflects evil Origin with credentials, `ACAO: null` |
| **BlindSQLi** | **CRITICAL** | **CWE-89** | **OOB DNS/HTTP callback (--oob)** |
| **BlindSSRF** | **CRITICAL** | **CWE-918** | **OOB HTTP callback (--oob)** |
| **BlindXXE** | **CRITICAL** | **CWE-611** | **OOB HTTP callback (--oob)** |
| **BlindCMDi** | **CRITICAL** | **CWE-78** | **OOB DNS callback (--oob)** |
| **Log4Shell** | **CRITICAL** | **CWE-917** | **OOB JNDI callback (--oob)** |
| **BlindSSTI** | **CRITICAL** | **CWE-94** | **OOB DNS callback (--oob)** |

Custom payload file format:

```
# my_payloads.txt
SQLi:' OR SLEEP(10)-- -
XSS:<details open ontoggle=alert(1)>
HeaderInjection:%0d%0aSet-Cookie:injected=1
IDOR:99999
```

---

## Output Files

All files written atomically (temp + rename). Ctrl+C mid-write never corrupts output.

| File | Contents |
|---|---|
| `<pfx>_report.html` | Dark-theme HTML report — OOB findings in red section, confidence badges on all hits |
| `<pfx>.json` | Full scan data including `oob_hits`, `confirmed_hits`, `finding_summary`, `session_health` |
| `<pfx>.csv` | Per-page flat CSV |
| `<pfx>.jsonl` | Streaming — one page JSON per line (`--output jsonl`) |
| `<pfx>_dirs.csv` | Directory hits: URL, status, size, redirect |
| `<pfx>_params.csv` | Param findings with CWE + confidence columns |
| `<pfx>_secrets.csv` | Secrets: type, value (truncated), source URL |
| `<pfx>_subdomains.csv` | Subdomains: FQDN, IPs, method, HTTP status |
| `<pfx>_targets.txt` | All parameterised URLs — nuclei-ready |
| `<pfx>_sqlmap_targets.txt` | Injectable subset — sqlmap-ready |
| `<pfx>_checkpoint.json` | Smart phase-aware checkpoint for `--resume` (JSON, saved every 50 pages and on Ctrl+C) |
| `<pfx>_ai_triage.md` | AI triage report in Markdown (also embedded in HTML) |
| `paramspecter_watch_<domain>.db` | SQLite scan history for watch mode |

`<pfx>` = `paramspecter_<domain>_<YYYYMMDD_HHMMSS>`

---

## Architecture

```
paramspecter/
├── cli.py               argparse, banner, entry point — wires all tiers together
├── core/
│   ├── analyzer.py      JSAnalyzer (async), SourceMapExploiter, analyze_page(), RobotsTxtHandler
│   ├── crawler.py       ParamSpecter orchestrator + crawl worker + PhaseManager integration
│   └── stats.py         CrawlStats, CrawlQueue, TokenBucket, ProxyManager
├── modules/
│   ├── oob.py           ★ Tier 1 — OOB blind detection (interactsh, 45 payloads, 6 checks)
│   ├── confidence.py    ★ Tier 1 — per-check confidence scoring engine (0–100)
│   ├── session_health.py ★ Tier 1 — session health monitor + auto re-authentication
│   ├── ai_triage.py     ★ Tier 2 — AI Triage + tech-aware prompts (11 stacks) + 7 providers
│   ├── ai_chat.py       ★ Interactive multi-turn AI chat about scan results
│   ├── orchestrator.py  ★ Phase 1 — Auto Orchestrator + 9 external tool runners + Windows PATH
│   ├── watchmode.py     ★ Phase 2 — Watch Mode, ScanDatabase (SQLite), AlertManager
│   ├── paramfuzz.py     ParamFuzzer + 9 DeepFuzzCheck subclasses (deduped, baseline-aware)
│   ├── dirhunt.py       DirectoryHunter
│   ├── subdomain.py     SubdomainHunter
│   └── login.py         FormLoginHandler
├── output/
│   ├── reporter.py      JSON / CSV / JSONL / HTML (OOB + AI triage + confidence + orchestrator)
│   ├── report_builder.py ★ Tier 2 — Pro report: CVSS, PoC curl commands, Nuclei templates
│   ├── nuclei_gen.py    ★ Tier 3 — Nuclei YAML template generator (4 categories + run.sh)
│   ├── burp_export.py   ★ Burp Suite XML export
│   └── dashboard.py     ★ Live curses terminal dashboard (log-suppression safe)
└── utils/
    ├── constants.py     Regex patterns, wordlists, tech/WAF signatures
    ├── helpers.py       Colors, logging (suppress-aware), URL helpers
    ├── http.py          curl_cffi TLS spoofing, SPA auto-detection, XHR interception
    ├── checkpoint.py    ★ Tier 3 — Smart phase-aware JSON checkpoint + PhaseManager
    └── scope_diff.py    ★ Tier 3 — ScopeDiffer, ScopeValidator, HackerOne/Bugcrowd APIs
```

---

## Known Limitations

- **OOB requires outbound DNS.** Firewalled internal networks may block DNS callbacks — use `--oob-server` with an internal interactsh instance.
- **OOB callback wait is 8 seconds.** Some very slow servers (WAFs, rate limiters) may fire callbacks after this window. Increase via `OOB_CALLBACK_WAIT_S` in `oob.py`.
- **IDOR detection is heuristic.** Confidence scoring helps reduce FPs but always confirm manually.
- **Session health uses string matching.** Tokens embedded in JS (`window.__user`) won't be detected — use `--auth-check-url` pointing to an API endpoint that returns 401 on session expiry instead.
- **Form login is single-step.** OTP, CAPTCHA, OAuth, and MFA are not supported.
- **Confidence scoring is not infallible.** WAF-generated 500 errors can inflate SQLi scores. Manual verification of POSSIBLE-tier findings is always recommended before reporting.
- **AI triage is advisory.** All findings should be verified manually before submitting to a bug bounty program.

---

## Legal

This tool is for **authorized security testing and educational use only**.

- Only test targets you own or have explicit written permission to test
- Unauthorized scanning is illegal in most jurisdictions
- The authors accept no liability for misuse

---

*Created by Boltx — ParamSpecter v7.4*
