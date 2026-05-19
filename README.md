<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

---

# ParamSpecter v5.0 — Advanced Recon Crawler

> **For authorized and educational use ONLY.**
> Only test targets you own or have explicit written permission to test.
> Unauthorized testing is illegal.

---

## What is ParamSpecter?

ParamSpecter is an advanced reconnaissance web crawler built for bug bounty hunting and security research. It performs deep recursive crawling, subdomain discovery, directory and file enumeration, parameter fuzzing with active vulnerability detection, JS analysis, secret detection, technology fingerprinting, automated form login, JS-rendered page crawling via Playwright, multi-domain scope control, scan resumption, custom payload injection, and downstream tool target export — all from a single command.

---

## Changelog

### v5.0 — Current Release

**New features**

| Feature | Flag | Description |
|---|---|---|
| Header Injection check | `--deep-fuzz` | Detects Host header injection (password reset poisoning, cache poisoning) and CRLF injection (`%0d%0a`) by checking if the canary host or injected header appears in the response body or `Location` header |
| IDOR check | `--deep-fuzz` | For every numeric parameter, probes `id±1`, `id+100`, and `id=0`; flags status-code changes (e.g. 403→200) and significant response-size deltas indicating a different record was returned |
| Custom payload file | `--payload-file FILE` | Inject your own payloads into any deep-fuzz category. Format: `LABEL:payload` per line. Valid labels: `SQLi`, `XSS`, `PathTraversal`, `SSRF`, `OpenRedirect`, `HeaderInjection`, `IDOR` |
| Scope file | `--scope-file FILE` | One domain or wildcard per line (`*.example.com`). Replaces the default same-domain restriction for multi-domain bug bounty programs |
| Rate limit CLI | `--rate-limit REQ/S` | Explicit per-host request rate (overrides the default `threads × 0.8`). Applies to the TokenBucket used by every worker thread |
| Resume / checkpoint | `--resume` | Skips already-visited URLs loaded from a checkpoint file. Checkpoint is auto-saved every 50 pages and on graceful stop |
| Output directory | `--output-dir DIR` | All output files (JSON, CSV, HTML report, checkpoint, target lists) are written here |
| HTML report | automatic | Self-contained dark-theme HTML report with summary cards, technology/WAF badges, secrets table, param hits, dir hits, and subdomain results. Written alongside JSON/CSV on every scan |

**Deep-fuzz check registry (v5.0)**

| Check | Severity | New in v5.0 |
|---|---|---|
| SQLi | HIGH | — |
| XSS | HIGH | — |
| PathTraversal | HIGH | — |
| SSRF | HIGH | — |
| OpenRedirect | MEDIUM | — |
| **HeaderInjection** | HIGH | ✓ |
| **IDOR** | HIGH | ✓ |

---

### v4.3

**New features**

| Feature | Flag | Description |
|---|---|---|
| Playwright crawling | `--playwright` | Headless Chromium rendering; waits for `networkidle` before extracting HTML; intercepts all XHR and `fetch()` calls and enqueues discovered API endpoints; each worker thread gets its own `BrowserContext` for thread safety; falls back to `requests` automatically if Playwright is not installed or the page fails to load |
| Form-based login | `--login-url` | GETs the login page, extracts the form action URL, auto-extracts CSRF / nonce / token hidden fields, POSTs credentials, injects resulting session cookies into the shared session before any crawl worker starts; hard-exits with a clear error if the server redirects back to the login page |
| Deep vulnerability fuzzing | `--deep-fuzz` | Per-parameter active checks across five vulnerability categories (see Deep Fuzz section); implies `--smart-fuzz`; prints findings inline with severity label and evidence, then a deduplicated summary table |
| Target export | `--export-targets` | After the scan writes `<pfx>_targets.txt` (all parameterised URLs, nuclei-ready) and `<pfx>_sqlmap_targets.txt` (injectable-looking subset, sqlmap-ready); prints ready-to-run command lines at the end of the scan |

**Stability and accuracy**

| Area | Change |
|---|---|
| Rate limiting | Replaced flat semaphore with per-host **TokenBucket** (req/s enforcement, configurable burst) |
| Memory | Host bucket dict **bounded to 512 entries** with LRU eviction — no unbounded growth on large crawls |
| Content dedup | Volatile token stripping now **context-aware** — only strips tokens inside HTML attribute values, not visible body text like Git commit IDs |
| JS analysis | **Dynamic imports followed** — `import()`, `require.ensure()`, webpack chunks discovered and analyzed |
| Secrets | **Deduplication** at aggregation — same secret found on 50 pages stored once, not 50 times |
| Wildcard detection | **stdev=0 floor** — proportional threshold (3% of baseline, min 32B) instead of flat 100B |
| Concurrency | **`threading.Barrier`** completion — no polling loop, no race window between queue empty and task_done |
| Output | All output files written **atomically** (temp + rename) — corrupt files on Ctrl+C are impossible |

### v4.2 — Core Fixes

| Area | Change |
|---|---|
| Wildcard detection | 5 probes + stddev threshold (was 2 probes, flat size check) |
| JS analysis | Inline `<script>` blocks analyzed in addition to external src files |
| Content dedup | Dynamic tokens stripped before hashing (CSRF, nonces, timestamps) |
| Rate limiting | 429 auto-backoff with `Retry-After` header support |
| Crawl join | Proper queue-done detection via `unfinished_tasks` |
| Stop event | Checked inside link-enqueue loop |

### v4.1 — Bug Fixes

| Bug | Fix |
|---|---|
| `CrawlQueue.get()` crash on Empty in priority mode | Priority tuple unwrapped after get, not inline |
| `internal_paths` regex stray space | Fixed to `[^"'<>]` |
| `pages_crawled` incremented before fetch | Moved to after successful fetch |
| Blocking `queue.join()` hangs on Ctrl+C | Replaced with stop-event-aware drain loop |
| Workers ignored stop event | All workers check stop event each iteration |
| `except: pass` silently swallowing errors | Replaced with logged `except Exception as e` |
| Second Ctrl+C had no effect | Now force-quits immediately |
| Phases 2–4 launched after Ctrl+C in phase 1 | Each phase gated on stop event |

### v4.0 — Major Features

| Feature | Description |
|---|---|
| SubdomainHunter | DNS brute-force + crt.sh cert transparency + DNS records + HTTP probe |
| DirectoryHunter | Wildcard/soft-404 detection, size dedup, recursive enumeration |
| URL normalization | Fragment stripping, port normalization, param sorting, mime-type gating |
| New CLI flags | `--recursive`, `--recursive-depth`, `--sub-wordlist`, `--smart-fuzz` |

---

## Installation

```bash
pip install -r requirements.txt
```

For full subdomain DNS enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA records):

```bash
pip install dnspython
```

For JS-rendered page crawling with Playwright:

```bash
pip install playwright
playwright install chromium
```

Without `dnspython`, subdomain brute-force falls back to `socket.gethostbyname` which returns one A record only.
Without `playwright`, the `--playwright` flag logs a warning and falls back to `requests` automatically.

---

## Quick Start

```bash
# Basic crawl
python ParamSpecter.py https://example.com --ignore-robots

# Subdomain enumeration
python ParamSpecter.py https://example.com --mode subdomain
python ParamSpecter.py https://example.com --mode subdomain --sub-wordlist subs.txt

# Directory hunting
python ParamSpecter.py https://example.com --mode fuzz
python ParamSpecter.py https://example.com --mode fuzz -w dirs.txt -x .php,.html,.bak --recursive

# Parameter fuzzing (smart = 6 payloads per param)
python ParamSpecter.py https://example.com/search --mode param --smart-fuzz

# Deep vulnerability scan (SQLi / XSS / LFI / SSRF / redirect / header injection / IDOR)
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz

# Deep fuzz with custom payloads
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz --payload-file my_payloads.txt

# Full recon: all four phases in order
python ParamSpecter.py https://example.com --mode full -t 20 --ignore-robots

# Multi-domain scope file
python ParamSpecter.py https://example.com --mode full --scope-file scope.txt

# Rate limiting (max 5 req/s per host)
python ParamSpecter.py https://example.com --rate-limit 5

# Resume an interrupted scan
python ParamSpecter.py https://example.com --resume
python ParamSpecter.py https://example.com --resume --resume-file /tmp/my_checkpoint.txt

# Save all output to a specific directory
python ParamSpecter.py https://example.com --output-dir /tmp/scans/example/

# JS-rendered crawl with XHR endpoint discovery
python ParamSpecter.py https://example.com --playwright

# Automated form login before crawling
python ParamSpecter.py https://example.com \
  --login-url https://example.com/login \
  --login-user admin@example.com \
  --login-pass hunter2

# Form login with non-standard field names
python ParamSpecter.py https://example.com \
  --login-url https://example.com/login \
  --login-user admin \
  --login-pass secret \
  --login-user-field email \
  --login-pass-field pwd

# Export nuclei + sqlmap target lists after crawl
python ParamSpecter.py https://example.com --export-targets
python ParamSpecter.py https://example.com --mode full --export-targets --ignore-robots

# Deep crawl with UA rotation and Burp proxy
python ParamSpecter.py https://example.com \
  --ignore-robots \
  --depth 6 \
  --threads 15 \
  --rotate-ua \
  --proxies http://127.0.0.1:8080

# Authenticated session via static cookie
python ParamSpecter.py https://example.com \
  --cookies "session=abc123; auth=xyz" \
  --headers "X-API-Key: mykey" "Authorization: Bearer token123"
```

**Ctrl+C once** — graceful stop, saves partial results and checkpoint.
**Ctrl+C twice** — force quit immediately.

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
  --max-retries              Max retries per URL with exponential backoff (default: 3)
  --strategy                 bfs | dfs | priority  (default: bfs)
  --follow-external          Follow links to external domains
  --ignore-robots            Ignore robots.txt restrictions
  --playwright               Use headless Chromium for JS rendering + XHR interception
                             Falls back to requests if Playwright is not installed

scope:
  --scope-file FILE          File of in-scope domains (one per line)
                             Supports wildcards: *.example.com
                             Replaces the default same-domain restriction

rate and resume:
  --rate-limit REQ/S         Max requests per second per host (default: threads × 0.8)
  --resume                   Resume a previous scan — skips already-visited URLs
  --resume-file FILE         Path to checkpoint file (default: auto-named in --output-dir)

identity and evasion:
  -u, --user-agent           Custom User-Agent string
  --rotate-ua                Rotate User-Agent from pool on each request
  --cookies                  Cookie string: "a=1; b=2"
  --headers                  Extra request headers: "X-Foo: bar"  (repeatable)
  --proxies                  Comma-separated proxy list: http://127.0.0.1:8080,...

authentication:
  --login-url URL            Login page URL — triggers automated form login before crawling
  --login-user USER          Username or email to submit
  --login-pass PASS          Password to submit
  --login-user-field FIELD   name= attribute of the username input (default: username)
  --login-pass-field FIELD   name= attribute of the password input (default: password)

subdomain enumeration:
  -sw, --sub-wordlist        Custom subdomain wordlist

directory hunting:
  -w,  --wordlist            Directory / endpoint wordlist
  -x,  --extensions          File extensions: .php,.html,.bak  (default: none)
  --match-codes              Only show these HTTP codes: 200,301,403
  --hide-codes               Hide these HTTP codes  (default: 404)
  --recursive                Recursively enumerate discovered directories
  --recursive-depth          Max recursion depth  (default: 2)

parameter fuzzing:
  -pw, --param-wordlist      Parameter wordlist
  --param-method             GET | POST  (default: GET)
  --smart-fuzz               Test 6 payloads per param:
                             default value, SQLi, XSS, SSRF, SSTI, path traversal
  --deep-fuzz                Extended per-param vulnerability checks (implies --smart-fuzz):
                             SQLi, XSS, path traversal, SSRF, open redirect,
                             header injection, IDOR
                             Prints param / payload / evidence / severity for each finding
  --payload-file FILE        Custom payload file for --deep-fuzz
                             Format: LABEL:payload (one per line)
                             Labels: SQLi, XSS, PathTraversal, SSRF, OpenRedirect,
                                     HeaderInjection, IDOR

output:
  -o, --output               json | csv | both | jsonl  (default: both)
  --output-dir DIR           Directory for all output files (default: current directory)
  --export-targets           Write targets.txt and sqlmap_targets.txt after the scan
                             Prints nuclei and sqlmap command lines at the end
```

---

## Modes

### crawl
Recursively follows links from the target URL up to `--depth` levels.
On every page it extracts: emails, phone numbers, URL parameters, forms and input fields,
JS endpoints, secrets and credentials, cookies with flag analysis, security header coverage,
technology fingerprints, WAF signatures, HTML comments, internal IP leaks, source maps,
and social media links.

Use `--playwright` to render JS-heavy pages with a real browser engine and intercept API calls made at runtime.
Use `--scope-file` to crawl across multiple domains within the same bug bounty program.

### subdomain
Three-phase subdomain discovery:
1. DNS brute-force against the built-in 161-entry wordlist (or your own `--sub-wordlist`). Wildcard DNS is detected upfront.
2. Certificate transparency via crt.sh — queries all certificates ever issued for `*.domain.tld`.
3. DNS record enumeration — pulls A, AAAA, MX, NS, TXT, CNAME, SOA for the root domain.

Every discovered subdomain is HTTP-probed (HTTPS first, HTTP fallback) with a thread pool capped at 50 to check liveness and grab title.

### fuzz
Directory and file brute-force against the target. Sends 5 random non-existent probes to detect wildcard/catch-all behaviour. Uses mean + 2×stddev threshold to filter false positives. Supports `--recursive` to re-enumerate discovered directories up to `--recursive-depth` levels.

### param
Fuzzes URL parameters against the target. Takes a baseline response first (status + size), then tests each parameter. Reports any parameter that causes a different status code, a response size change over 100B, or reflects the payload back in the response body. Use `--smart-fuzz` for full 6-payload coverage. Use `--deep-fuzz` for active vulnerability detection across seven categories.

### full
Runs all four phases in sequence: crawl → subdomain → fuzz → param.
If a phase is interrupted with Ctrl+C, subsequent phases are skipped and results saved.

---

## Playwright Mode

When `--playwright` is passed, each crawl worker:

1. Opens a dedicated `BrowserContext` in headless Chromium (thread-safe — no shared Page objects)
2. Navigates to the URL and waits for `networkidle` before extracting HTML
3. Intercepts all `XMLHttpRequest` and `fetch()` calls made by the page, collecting their URLs
4. Enqueues discovered API endpoints into the main crawl queue for recursive processing
5. Falls back to a normal `requests` GET if Playwright fails for any reason

The standard `requests` GET still runs alongside Playwright to capture real response headers, cookies, and status codes. The rendered HTML body replaces the raw HTML before analysis.

---

## Automated Form Login

When `--login-url` is passed, the following happens before any crawl worker starts:

1. **GET** the login page and parse the HTML
2. **Locate the login form** — selects the `<form>` that contains `<input type="password">`, falling back to the first form on the page
3. **Extract CSRF tokens** — all `<input type="hidden">` fields whose names match `csrf`, `token`, `nonce`, `_wpnonce`, `authenticity_token`, or `__RequestVerificationToken` are captured automatically
4. **POST** credentials + CSRF fields to the form's `action` URL
5. **Validate** the response — non-2xx status or redirect back to the login page causes a hard exit
6. **Inject cookies** into the shared `requests.Session` — all worker threads are authenticated from their first request

```bash
# Standard login
python ParamSpecter.py https://example.com \
  --login-url https://example.com/login \
  --login-user admin \
  --login-pass secret123

# Non-standard field names
python ParamSpecter.py https://example.com \
  --login-url https://example.com/login \
  --login-user admin@corp.com \
  --login-pass secret123 \
  --login-user-field email \
  --login-pass-field pwd
```

---

## Deep Fuzz (`--deep-fuzz`)

`--deep-fuzz` adds a second pass after the standard smart-fuzz run. It tests every parameter against **seven** vulnerability categories using dedicated payloads and detection logic. `--deep-fuzz` implies `--smart-fuzz`.

Each finding is printed immediately with severity (colour-coded), category, parameter name, payload, and evidence. A deduplicated summary table prints after all probes complete.

You can extend any category's payload list using `--payload-file`:

```
# my_payloads.txt
SQLi:' OR SLEEP(10)-- -
XSS:<details open ontoggle=alert(1)>
HeaderInjection:crlf_inject:%0d%0aSet-Cookie:injected=1
IDOR:99999
```

### SQL Injection — HIGH

| Payload | Detection method |
|---|---|
| `' OR '1'='1` | DB error keyword in response body |
| `1 AND SLEEP(3)-- -` | Response time ≥ 3s (time-based blind) |
| `1; DROP TABLE users--` | DB error keyword |
| `' OR SLEEP(3)--` | Response time ≥ 3s |
| `1 OR 1=1` | DB error keyword |
| MSSQL `CONVERT` injection | DB error keyword |

Error keywords cover MySQL, PostgreSQL, Oracle, MSSQL, and SQLite. Time-based detection only fires if the payload itself contains a sleep call. Sleep-carrying payloads get an extended 8-second socket timeout.

### XSS — HIGH

| Payload | Detection method |
|---|---|
| `<script>alert(1)</script>` | Payload appears unencoded in response body |
| `"><img src=x onerror=alert(1)>` | `onerror=alert(1)` appears unencoded |
| `javascript:alert(1)` | Marker appears unencoded |
| `'><svg onload=alert(1)>` | `onload=alert(1)` appears unencoded |

### Path Traversal / LFI — HIGH

| Payload | Detection method |
|---|---|
| `../../../etc/passwd` | `root:.*:/bin/bash` pattern in response |
| `..%2F..%2F..%2Fetc%2Fpasswd` | Same |
| `....//....//....//etc/passwd` | Same |
| `%252e%252e%252fetc%252fpasswd` (double-encoded) | Same |
| `../../../etc/shadow` | `daemon:x:\d+` pattern |
| `..\..\..\windows\win.ini` | `[boot loader]` or `[extensions]` in response |

### SSRF — HIGH

| Payload | Detection method |
|---|---|
| `http://169.254.169.254/latest/meta-data/` | AWS metadata content in response |
| `http://metadata.google.internal/computeMetadata/v1/` | GCP metadata in response |
| `http://169.254.169.254/metadata/instance?api-version=...` | Azure instance JSON in response |

Detects reflected SSRF only. For blind SSRF use an out-of-band collaborator (Burp Collaborator, interactsh).

### Open Redirect — MEDIUM

| Payload | Detection method |
|---|---|
| `https://evil.paramspecter.test` | `Location` header points to canary domain |
| `//evil.paramspecter.test` (protocol-relative) | Same |
| `////evil.paramspecter.test` | Same |

Requests are sent with `allow_redirects=False`. Also detects `<meta http-equiv="refresh">` targets. The canary domain `evil.paramspecter.test` never resolves in DNS.

### Header Injection — HIGH *(new in v5.0)*

| Probe | Detection method |
|---|---|
| Spoofed `Host: evil.paramspecter.test` header | Canary host reflected in response body or `Location` header |
| `%0d%0aX-Injected-Header:paramspecter` in param value | Injected header appears in response headers |
| `\r\nX-Injected-Header:paramspecter` (raw CRLF) | Same |
| `%250d%250a...` (double-encoded) | Same |

Host header injection can enable password reset link poisoning and web cache poisoning. CRLF injection can enable response splitting and header smuggling.

### IDOR — HIGH *(new in v5.0)*

For every parameter carrying a numeric value, probes:

| Probe | Detection method |
|---|---|
| `id + 1` | Status-code change (e.g. 403→200) or significant response-size delta |
| `id - 1` | Same |
| `id + 100` | Same |
| `id = 0` | Same |

When a size delta is detected on a 200 response, the tool also checks for different owner/account fields in JSON (`"user"`, `"email"`, `"owner"`) and includes them in the evidence. Non-numeric parameters are skipped silently.

```bash
# Deep fuzz via GET
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz

# Deep fuzz via POST
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz --param-method POST

# Deep fuzz with custom payloads
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz --payload-file payloads.txt

# Deep fuzz as part of full recon
python ParamSpecter.py https://example.com --mode full --deep-fuzz --ignore-robots
```

---

## Scope File (`--scope-file`)

For bug bounty programs with multiple in-scope assets, pass a scope file instead of relying on the default same-domain restriction:

```
# scope.txt
example.com
*.example.com
api.example-cdn.com
staging.example.net
```

Lines starting with `#` are treated as comments. Wildcard entries (`*.example.com`) match any subdomain. When a scope file is provided, the `--follow-external` flag is not needed — ParamSpecter uses the scope list as the authority for what to crawl.

---

## Resume (`--resume`)

Checkpoint files are written automatically every 50 pages crawled and again on graceful stop (Ctrl+C). To resume:

```bash
# Auto-detect checkpoint in the current directory (or --output-dir)
python ParamSpecter.py https://example.com --resume

# Specify checkpoint file explicitly
python ParamSpecter.py https://example.com --resume --resume-file /tmp/scans/checkpoint.txt
```

The checkpoint file is a plain-text list of visited URLs, one per line, written atomically. Already-visited URLs are skipped immediately on pickup from the crawl queue, so the resumed scan continues exactly where it left off without re-analyzing pages.

---

## Target Export (`--export-targets`)

After the scan completes, `--export-targets` generates two plain-text files:

**`<pfx>_targets.txt`** — every URL with at least one query parameter that returned HTTP < 400. Feed directly to nuclei:

```bash
nuclei -l paramspecter_example_com_20240501_120000_targets.txt -t ~/nuclei-templates/
```

**`<pfx>_sqlmap_targets.txt`** — filtered subset where at least one parameter matches a known injectable name (`id`, `uid`, `product_id`, etc.), carries a numeric value, or appeared in deep-fuzz findings:

```bash
sqlmap -m paramspecter_example_com_20240501_120000_sqlmap_targets.txt --batch --dbs
```

Both files are written atomically and the ready-to-run commands are printed to the terminal at the end of the scan.

---

## Detection Coverage

### Secret and Credential Patterns (10)
AWS Access Keys, Google API Keys, GitHub Personal Access Tokens, OpenAI API Keys,
Bearer tokens, JWTs, generic `api_key` / `secret` / `token` JS assignments,
database connection strings (MySQL, PostgreSQL, MongoDB, Redis, JDBC),
RSA private keys, Slack / Discord / Telegram tokens.

Secrets found on multiple pages are deduplicated by `(type, value[:40])`.

### Technology Fingerprints (25)
WordPress, Joomla, Drupal, React, Next.js, Nuxt.js, Angular, Vue.js,
jQuery, Bootstrap, Tailwind, Cloudflare, AWS, GCP, PHP, ASP.NET,
Django, Laravel, Express.js, FastAPI, Spring, GraphQL, Nginx, Apache, IIS.

### WAF Detection (10)
Cloudflare, AWS WAF, Akamai, Sucuri, Incapsula, ModSecurity, Imperva, F5 BIG-IP, Barracuda, Fortinet.

### Built-in Wordlists

| List | Entries | Coverage |
|---|---|---|
| Directories / endpoints | 165 | CMS, API paths, dev/debug, sensitive files, upload dirs, infra |
| Parameters | 153 | IDs, auth tokens, redirect params, file paths, search, commands |
| Subdomains | 161 | Web, mail, dev, staging, API, admin, CDN, DB, CI/CD, VPN |
| Extensions | 14 | `.php`, `.html`, `.asp`, `.aspx`, `.jsp`, `.json`, `.bak`, `.env`, etc. |

---

## Output Files

All files are written atomically (temp file → rename). A Ctrl+C mid-write never produces a truncated or corrupt file.

| File | Contents |
|---|---|
| `<pfx>.json` | Full scan: all pages, meta summary, secrets, dir hits, param hits, subdomain hits |
| `<pfx>.csv` | Per-page flat CSV: URL, status, title, technologies, emails, params, forms, headers |
| `<pfx>_report.html` | Self-contained dark-theme HTML summary report |
| `<pfx>_dirs.csv` | Directory / file hunt hits: URL, status, size, redirect |
| `<pfx>_params.csv` | Interesting parameters: param name, payload, status delta, size delta, reflected flag |
| `<pfx>_secrets.csv` | Extracted secrets: type, value (truncated at 80 chars), source URL |
| `<pfx>_subdomains.csv` | Subdomains: FQDN, IPs, discovery method, HTTP status, title |
| `<pfx>_targets.txt` | All parameterised URLs — nuclei-ready (`--export-targets` only) |
| `<pfx>_sqlmap_targets.txt` | Injectable-looking subset — sqlmap-ready (`--export-targets` only) |
| `<pfx>_checkpoint.txt` | Visited URLs for `--resume` (auto-saved every 50 pages) |

`<pfx>` = `paramspecter_<domain>_<YYYYMMDD_HHMMSS>`

All files land in `--output-dir` (default: current directory).

---

## Architecture

```
ParamSpecter v5.0
├── TokenBucket          Per-host token-bucket rate limiter (--rate-limit)
├── CrawlQueue           BFS / DFS / Priority queue
├── RobotsTxtHandler     robots.txt parsing + sitemap URL extraction
├── JSAnalyzer           External JS + inline blocks + dynamic chunk following
├── analyze_page()       Full HTML pipeline: links, forms, params, cookies, headers, techs
├── SubdomainHunter      DNS brute-force + crt.sh + DNS records + HTTP probe (pooled)
├── DirectoryHunter      Wildcard detection (5 probes + stddev) + recursive enumeration
├── DeepFuzzCheck        Base class for per-category vulnerability checks
│   ├── SQLiCheck            Error-based + time-based blind SQL injection
│   ├── XSSCheck             Reflected XSS detection
│   ├── PathTraversalCheck   LFI / path traversal content matching
│   ├── SSRFCheck            Cloud metadata endpoint probing
│   ├── OpenRedirectCheck    Location header + meta-refresh redirect detection
│   ├── HeaderInjectionCheck Host header injection + CRLF injection  [v5.0]
│   └── IDORCheck            Numeric ID incrementation detection      [v5.0]
├── ParamFuzzer          Baseline + smart-fuzz + deep-fuzz + custom payload injection
├── FormLoginHandler     Form login with CSRF extraction + session injection
├── ProxyManager         Round-robin proxy rotation
├── save_checkpoint()    Atomic checkpoint write for --resume          [v5.0]
├── load_scope_file()    Multi-domain scope file parser                [v5.0]
└── ParamSpecter         Main orchestrator + Playwright lifecycle + atomic output
```

---

## Known Limitations

- **Playwright falls back silently.** If a page fails to load in Playwright (timeout, JS crash), the worker falls back to a normal `requests` GET. XHR interception is skipped for that page but crawling continues.
- **SSRF detection is reflection-only.** Blind SSRF requires an out-of-band collaborator — Burp Collaborator or interactsh.
- **IDOR detection is heuristic.** Size deltas and status-code changes are indicators, not proof. Confirm findings manually.
- **Form login is single-step.** Multi-step auth flows (OTP, CAPTCHA, OAuth, MFA) are not supported.
- **No path-scope filtering.** Crawl is bounded by domain (or scope file), not by path prefix.
- **DNS fallback.** Without `dnspython`, subdomain brute-force uses `socket.gethostbyname` which returns one A record only.
- **Deep fuzz is not a full scanner.** Black-box heuristics only. False negatives are possible; confirm all findings manually.

---

## Scaling to Distributed Crawling

Replace `CrawlQueue` with a Redis-backed queue and the visited set with a Redis SET for multi-instance shared deduplication:

```python
import redis
r = redis.Redis()

# Producer
if r.sadd("visited", url):     # returns 1 if new, 0 if already seen
    r.lpush("queue", url)

# Consumer (in _crawl_worker)
url = r.brpop("queue", timeout=3)
```

Write results directly to MongoDB or PostgreSQL instead of flat files for large-scale crawls.

---

## Legal

This tool is for **authorized security testing and educational use only**.

- Only test targets you own or have explicit written permission to test
- Unauthorized scanning is illegal in most jurisdictions
- The authors accept no liability for misuse

---

*Created by Boltx*
