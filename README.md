<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

---

# ParamSpecter v4.3 — Advanced Recon Crawler

> **For authorized and educational use ONLY.**
> Only test targets you own or have explicit written permission to test.
> Unauthorized testing is illegal.

---

## What is ParamSpecter?

ParamSpecter is an advanced reconnaissance web crawler built for bug bounty hunting and security research. It performs deep recursive crawling, subdomain discovery, directory and file enumeration, parameter fuzzing with active vulnerability detection, JS analysis, secret detection, technology fingerprinting, automated form login, JS-rendered page crawling via Playwright, and downstream tool target export — all from a single command.

---

## Changelog

### v4.3 — Current Release

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
| Wildcard detection | **stdev=0 floor** — proportional threshold (3% of baseline, min 32B) instead of flat 100B, handles zero-delay probes correctly |
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
| `internal_paths` regex stray space in `[ ^"'<>]` | Fixed to `[^"'<>]` |
| `pages_crawled` incremented before fetch | Moved to after successful fetch |
| Blocking `queue.join()` hangs on Ctrl+C | Replaced with stop-event-aware drain loop |
| Workers (subdomain/dir/param) ignored stop event | All workers check stop event each iteration |
| `except: pass` silently swallowing all errors | Replaced with logged `except Exception as e` |
| Second Ctrl+C had no effect | Now force-quits immediately |
| Phases 2–4 launched even after Ctrl+C in phase 1 | Each phase gated on stop event |

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

# Deep vulnerability scan (SQLi / XSS / LFI / SSRF / open redirect)
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz

# Full recon: all four phases in order
python ParamSpecter.py https://example.com --mode full -t 20 --ignore-robots

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

**Ctrl+C once** — graceful stop, saves partial results.
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
                             SQLi, XSS, path traversal, SSRF, open redirect
                             Prints param / payload / evidence / severity for each finding

output:
  -o, --output               json | csv | both | jsonl  (default: both)
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

### subdomain
Three-phase subdomain discovery:
1. DNS brute-force against the built-in 161-entry wordlist (or your own `--sub-wordlist`). Wildcard DNS is detected upfront.
2. Certificate transparency via crt.sh — queries all certificates ever issued for `*.domain.tld`.
3. DNS record enumeration — pulls A, AAAA, MX, NS, TXT, CNAME, SOA for the root domain.

Every discovered subdomain is HTTP-probed (HTTPS first, HTTP fallback) with a thread pool capped at 50 to check liveness and grab title.

### fuzz
Directory and file brute-force against the target. Sends 5 random non-existent probes to detect wildcard/catch-all behaviour. Uses mean + 2×stddev threshold to filter false positives. Supports `--recursive` to re-enumerate discovered directories up to `--recursive-depth` levels.

### param
Fuzzes URL parameters against the target. Takes a baseline response first (status + size), then tests each parameter. Reports any parameter that causes a different status code, a response size change over 100B, or reflects the payload back in the response body. Use `--smart-fuzz` for full 6-payload coverage. Use `--deep-fuzz` for active vulnerability detection across five categories.

### full
Runs all four phases in sequence: crawl → subdomain → fuzz → param.
If a phase is interrupted with Ctrl+C, subsequent phases are skipped and results saved.

---

## Playwright Mode

When `--playwright` is passed, each crawl worker:

1. Opens a dedicated `BrowserContext` in headless Chromium (thread-safe — no shared Page objects)
2. Navigates to the URL and waits for `networkidle` before extracting HTML, so JS-rendered content and lazy-loaded data are captured
3. Intercepts all `XMLHttpRequest` and `fetch()` calls made by the page, collecting their URLs
4. Enqueues discovered API endpoints into the main crawl queue for recursive processing
5. Falls back to a normal `requests` GET if Playwright fails for any reason (network error, timeout, JS crash)

The standard `requests` GET still runs alongside Playwright to capture real response headers, cookies, and status codes that the Playwright response object doesn't expose cleanly. The rendered HTML body replaces the raw HTML before analysis.

**Fallback behaviour:** if `playwright` is not installed, the flag is silently ignored with a one-time warning and the crawler continues normally with `requests`.

---

## Automated Form Login

When `--login-url` is passed, the following happens before any crawl worker starts:

1. **GET** the login page and parse the HTML
2. **Locate the login form** — selects the `<form>` that contains a `<input type="password">`, falling back to the first form on the page
3. **Extract CSRF tokens** — all `<input type="hidden">` fields whose names match `csrf`, `token`, `nonce`, `_wpnonce`, `authenticity_token`, or `__RequestVerificationToken` are captured automatically
4. **POST** `{user_field: username, pass_field: password, ...csrf_fields}` to the form's `action` URL
5. **Validate** the response:
   - Non-2xx status → hard error, exits immediately
   - Server redirects back to the login page path → hard error with a diagnostic message
   - Password field still in response body → warning (some apps re-embed the form on success)
6. **Inject cookies** from the response into the shared `requests.Session` — all worker threads are authenticated from their first request

```bash
# Standard login
python ParamSpecter.py https://example.com \
  --login-url https://example.com/login \
  --login-user admin \
  --login-pass secret123

# Non-standard field names (e.g. a form using name="email" and name="pwd")
python ParamSpecter.py https://example.com \
  --login-url https://example.com/login \
  --login-user admin@corp.com \
  --login-pass secret123 \
  --login-user-field email \
  --login-pass-field pwd
```

`--login-url` requires both `--login-user` and `--login-pass`. Omitting either causes an immediate argument error before any network traffic.

---

## Deep Fuzz (`--deep-fuzz`)

`--deep-fuzz` adds a second pass after the standard smart-fuzz run. It tests every parameter against five vulnerability categories using dedicated payloads and detection logic. `--deep-fuzz` implies `--smart-fuzz` — the baseline pass always runs first.

Each finding is printed immediately during the scan with:
- **Severity** — `HIGH`, `MEDIUM`, or `LOW` (colour-coded)
- **Category** — which check triggered
- **Parameter** — the parameter name that was fuzzed
- **Payload** — the exact string sent
- **Evidence** — what in the response triggered the flag (error snippet, reflected content, response time, redirect destination)

A deduplicated summary table prints after all probes complete.

### SQL Injection — HIGH

| Payload | Detection method |
|---|---|
| `' OR '1'='1` | DB error keyword in response body |
| `1 AND SLEEP(3)-- -` | Response time ≥ 3s (time-based blind) |
| `1; DROP TABLE users--` | DB error keyword |
| `' OR SLEEP(3)--` | Response time ≥ 3s |
| `1 OR 1=1` | DB error keyword |
| MSSQL `CONVERT` injection | DB error keyword |

Error keywords cover MySQL, PostgreSQL, Oracle, MSSQL, and SQLite. Time-based detection only fires if the payload itself contains a `SLEEP()` / `pg_sleep()` call, preventing slow pages from being misclassified. Sleep-carrying payloads get an extended 8-second socket timeout so the delay completes before the connection closes.

### XSS — HIGH

| Payload | Detection method |
|---|---|
| `<script>alert(1)</script>` | Payload appears unencoded in response body |
| `"><img src=x onerror=alert(1)>` | `onerror=alert(1)` appears unencoded |
| `javascript:alert(1)` | Marker appears unencoded |
| `'><svg onload=alert(1)>` | `onload=alert(1)` appears unencoded |

A server that HTML-encodes `<` to `&lt;` produces no false positive. Evidence shows 15 characters of surrounding context so you can see which tag or attribute the reflection landed in.

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
| `http://169.254.169.254/latest/meta-data/ami-id` | `ami-` pattern in response |
| `http://metadata.google.internal/computeMetadata/v1/` | `computeMetadata` in response |
| `http://169.254.169.254/metadata/instance?api-version=...` | Azure instance JSON in response |

Detects reflected SSRF only. For blind SSRF (no response reflection) use an out-of-band collaborator (Burp Collaborator, interactsh).

### Open Redirect — MEDIUM

| Payload | Detection method |
|---|---|
| `https://evil.paramspecter.test` | `Location` header points to canary domain |
| `//evil.paramspecter.test` (protocol-relative) | Same |
| `////evil.paramspecter.test` | Same |
| `https:////evil.paramspecter.test` | Same |

Requests are sent with `allow_redirects=False` so the raw `Location` header is inspectable before following. Also detects `<meta http-equiv="refresh">` redirect targets in the response body. The canary domain `evil.paramspecter.test` will never resolve in DNS, so there is no accidental outbound connection.

```bash
# Deep fuzz via GET
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz

# Deep fuzz via POST
python ParamSpecter.py https://example.com/search --mode param --deep-fuzz --param-method POST

# Deep fuzz as part of full recon
python ParamSpecter.py https://example.com --mode full --deep-fuzz --ignore-robots
```

---

## Target Export (`--export-targets`)

After the scan completes, `--export-targets` generates two plain-text files ready for downstream tools.

### `<pfx>_targets.txt` — all parameterised URLs

Every URL with at least one query parameter that returned HTTP < 400. Sources include directly crawled pages, outbound links discovered in `<a href>` tags (even if not crawled due to depth or page limits), and URLs fuzzed during the param phase.

```
https://example.com/page?id=1
https://example.com/search?q=test&page=2
https://example.com/product?cat=electronics&sort=price
```

Feed directly to nuclei:

```bash
nuclei -l paramspecter_example_com_20240501_120000_targets.txt -t ~/nuclei-templates/
```

### `<pfx>_sqlmap_targets.txt` — injectable-looking subset

A filtered subset of `targets.txt` where at least one of these is true:

- A parameter name matches a known injectable identifier: `id`, `uid`, `user_id`, `item_id`, `product_id`, `product`, `item`, `cat`, `category`, `pid`, `sid`, `nid`, `order_id`, and 15 others
- A parameter carries a pure numeric value (e.g. `?id=42`, `?page=3`, `?ref=17`) — catches renamed ID parameters that the name heuristic would miss
- The URL appeared in `--deep-fuzz` / `--smart-fuzz` findings (confirmed interesting response)

Feed directly to sqlmap:

```bash
sqlmap -m paramspecter_example_com_20240501_120000_sqlmap_targets.txt --batch --dbs
```

Both files are written atomically (temp + rename). The ready-to-run commands are printed to the terminal at the end of the scan with the actual generated filenames.

---

## Detection Coverage

### Secret and Credential Patterns (10)
AWS Access Keys, Google API Keys, GitHub Personal Access Tokens, OpenAI API Keys,
Bearer tokens, JWTs, generic `api_key` / `secret` / `token` JS assignments,
database connection strings (MySQL, PostgreSQL, MongoDB, Redis, JDBC),
RSA private keys, Slack / Discord / Telegram tokens.

Secrets found on multiple pages are deduplicated by `(type, value[:40])` — the same key appearing on 50 pages appears once in the output.

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

## JS Analysis

For every page crawled, ParamSpecter:

1. Fetches all `<script src=...>` files
2. Scans all inline `<script>` blocks
3. Follows dynamic imports: `import("./chunk.js")`, `require.ensure(["./mod"])`, webpack `__webpack_require__.p + "chunk.js"` patterns
4. Extracts API endpoint paths matching `/api/`, `/v1/`, `/graphql/`, `/admin/`, etc.
5. Scans for secrets using 10 credential patterns
6. Extracts JS variable assignments where the variable name suggests credentials
7. Identifies source map references (`.map` files which often contain original source)
8. Flags JWTs found anywhere in the JS

When `--playwright` is active, XHR and `fetch()` calls made by the page after load are intercepted at the network layer and added to the crawl queue — these are API endpoints that would be invisible to static JS analysis.

---

## Rate Limiting

ParamSpecter uses a **TokenBucket per target host** to enforce a configurable request rate, not just a concurrency cap.

- Default rate: `threads × 0.8` requests/second per host
- Burst capacity: `rate × 2` (allows short bursts without throttling normal browsing patterns)
- Automatic 429 handling: reads `Retry-After` header and waits the specified time (capped at 60s)
- The host bucket dictionary is bounded to 512 entries with LRU eviction to prevent memory growth on crawls that touch many external domains

---

## Output Files

All files are written atomically (temp file → rename) so a Ctrl+C or kill signal mid-write never produces a truncated or corrupt file.

| File | Contents |
|---|---|
| `<pfx>.json` | Full scan: all pages, meta summary, secrets, dir hits, param hits, subdomain hits |
| `<pfx>.csv` | Per-page flat CSV: URL, status, title, technologies, emails, params, forms, headers |
| `<pfx>_dirs.csv` | Directory / file hunt hits: URL, status, size, redirect |
| `<pfx>_params.csv` | Interesting parameters: param name, payload, status delta, size delta, reflected flag |
| `<pfx>_secrets.csv` | Extracted secrets: type, value (truncated at 80 chars), source URL |
| `<pfx>_subdomains.csv` | Subdomains: FQDN, IPs, discovery method, HTTP status, title |
| `<pfx>_targets.txt` | All parameterised URLs — nuclei-ready (`--export-targets` only) |
| `<pfx>_sqlmap_targets.txt` | Injectable-looking subset — sqlmap-ready (`--export-targets` only) |

The JSON file includes an `"interrupted": true` flag if the scan was stopped early with Ctrl+C.

`<pfx>` = `paramspecter_<domain>_<YYYYMMDD_HHMMSS>`

---

## Architecture

```
ParamSpecter v4.3
├── TokenBucket          Per-host token-bucket rate limiter (req/s enforcement)
├── CrawlQueue           BFS / DFS / Priority queue
├── RobotsTxtHandler     robots.txt parsing + sitemap URL extraction
├── JSAnalyzer           External JS + inline blocks + dynamic chunk following
├── analyze_page()       Full HTML pipeline: links, forms, params, cookies, headers, techs
├── SubdomainHunter      DNS brute-force + crt.sh + DNS records + HTTP probe (pooled)
├── DirectoryHunter      Wildcard detection (5 probes + stddev) + recursive enumeration
├── DeepFuzzCheck        Base class for per-category vulnerability checks
│   ├── SQLiCheck        Error-based + time-based blind SQL injection
│   ├── XSSCheck         Reflected XSS detection
│   ├── PathTraversalCheck  LFI / path traversal content matching
│   ├── SSRFCheck        Cloud metadata endpoint probing
│   └── OpenRedirectCheck   Location header + meta-refresh redirect detection
├── ParamFuzzer          Baseline comparison + smart-fuzz + deep-fuzz orchestration
├── FormLoginHandler     Form login with CSRF extraction + session injection
├── ProxyManager         Round-robin proxy rotation
└── ParamSpecter         Main orchestrator + Playwright lifecycle + atomic output
```

---

## Known Limitations

- **Playwright falls back silently.** If a page fails to load in Playwright (timeout, JS crash), the worker falls back to a normal `requests` GET. XHR interception is skipped for that page but crawling continues.
- **SSRF detection is reflection-only.** Blind SSRF (server makes an outbound request but does not reflect the response) requires an out-of-band collaborator — Burp Collaborator or interactsh.
- **Form login is single-step.** Multi-step auth flows (OTP, CAPTCHA, OAuth, MFA challenge pages) are not supported.
- **No path-scope filtering.** Crawl is bounded by domain, not by path prefix. If you want `/app/` only, disable `--follow-external` and set a shallow `--depth`.
- **DNS fallback.** Without `dnspython`, subdomain brute-force uses `socket.gethostbyname` which returns one A record only.
- **Deep fuzz is not a full scanner.** It uses black-box heuristics. False negatives are possible; false positives are possible on error-prone pages. Confirm findings manually.

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
