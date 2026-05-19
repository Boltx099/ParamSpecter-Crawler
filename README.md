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

ParamSpecter is an advanced reconnaissance web crawler built for bug bounty hunting and security research. It performs deep recursive crawling, subdomain discovery, directory and file enumeration, parameter fuzzing, JS analysis, secret detection, and technology fingerprinting — all from a single command.

---

## Changelog

### v4.3 — Stability and Accuracy

| Area | Change |
|---|---|
| Rate limiting | Replaced flat semaphore with per-host **TokenBucket** (req/s enforcement, configurable burst) |
| Memory | Host bucket dict **bounded to 512 entries** with LRU eviction — no unbounded growth on large crawls |
| Content dedup | Volatile token stripping now **context-aware** — only strips tokens inside HTML attribute values, not visible body text like Git commit IDs |
| JS analysis | **Dynamic imports followed** — `import()`, `require.ensure()`, webpack chunks discovered and analyzed |
| Secrets | **Deduplication** at aggregation — same secret found on 50 pages stored once, not 50 times |
| Wildcard detection | **stdev=0 floor** — proportional threshold (3% of baseline, min 32B) instead of flat 100B, handles zero-delay probes correctly |
| Concurrency | **`threading.Barrier`** completion — no polling loop, no race window between queue empty and task_done |
| Output | All six output files written **atomically** (temp + rename) — corrupt files on Ctrl+C are impossible |

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
| Phases 2-4 launched even after Ctrl+C in phase 1 | Each phase gated on stop event |

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

Without `dnspython`, subdomain brute-force falls back to `socket.gethostbyname` which only returns one A record.

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

# Full recon: all four phases in order
python ParamSpecter.py https://example.com --mode full -t 20 --ignore-robots

# Deep crawl with UA rotation and Burp proxy
python ParamSpecter.py https://example.com \
  --ignore-robots \
  --depth 6 \
  --threads 15 \
  --rotate-ua \
  --proxies http://127.0.0.1:8080

# Authenticated session
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
  url                     Target URL  e.g. https://example.com

mode:
  --mode                  crawl | fuzz | param | subdomain | full  (default: crawl)

crawl:
  -m, --max-pages         Max pages to crawl (default: 100)
  -d, --delay             Delay between requests in seconds (default: 0.2)
  -D, --depth             Max crawl depth (default: 4)
  -t, --threads           Number of worker threads (default: 10)
  --timeout               Request timeout in seconds (default: 10)
  --max-retries           Max retries per URL with exponential backoff (default: 3)
  --strategy              bfs | dfs | priority  (default: bfs)
  --follow-external       Follow links to external domains
  --ignore-robots         Ignore robots.txt restrictions

identity and evasion:
  -u, --user-agent        Custom User-Agent string
  --rotate-ua             Rotate User-Agent from pool on each request
  --cookies               Cookie string: "a=1; b=2"
  --headers               Extra request headers: "X-Foo: bar"  (repeatable)
  --proxies               Comma-separated proxy list: http://127.0.0.1:8080,...

subdomain enumeration:
  -sw, --sub-wordlist     Custom subdomain wordlist

directory hunting:
  -w,  --wordlist         Directory / endpoint wordlist
  -x,  --extensions       File extensions: .php,.html,.bak  (default: none)
  --match-codes           Only show these HTTP codes: 200,301,403
  --hide-codes            Hide these HTTP codes  (default: 404)
  --recursive             Recursively enumerate discovered directories
  --recursive-depth       Max recursion depth  (default: 2)

parameter fuzzing:
  -pw, --param-wordlist   Parameter wordlist
  --param-method          GET | POST  (default: GET)
  --smart-fuzz            Test 6 payloads per param:
                          default value, SQLi, XSS, SSRF, SSTI, path traversal

output:
  -o, --output            json | csv | both | jsonl  (default: both)
```

---

## Modes

### crawl
Recursively follows links from the target URL up to `--depth` levels.
On every page it extracts: emails, phone numbers, URL parameters, forms and input fields,
JS endpoints, secrets and credentials, cookies with flag analysis, security header coverage,
technology fingerprints, WAF signatures, HTML comments, internal IP leaks, source maps,
and social media links.

### subdomain
Three-phase subdomain discovery:
1. DNS brute-force against the built-in 161-entry wordlist (or your own `--sub-wordlist`). Wildcard DNS is detected upfront — if the domain resolves every random name, results are flagged as potentially unreliable.
2. Certificate transparency via crt.sh — queries all certificates ever issued for `*.domain.tld`.
3. DNS record enumeration — pulls A, AAAA, MX, NS, TXT, CNAME, SOA for the root domain.

Every discovered subdomain is then HTTP-probed (HTTPS first, HTTP fallback) with a thread pool capped at 50 to check liveness and grab title.

### fuzz
Directory and file brute-force against the target. Sends 5 random non-existent probes first to detect wildcard/catch-all behavior. Uses mean + 2×stddev threshold to filter false positives accurately even when the server returns slightly varying sizes. Supports `--recursive` to re-enumerate discovered directories up to `--recursive-depth` levels.

### param
Fuzzes URL parameters against the target. Takes a baseline response first (status + size), then tests each parameter. Reports any parameter that causes a different status code, a response size change over 100B, or reflects the payload back in the response body. Use `--smart-fuzz` for full 6-payload coverage.

### full
Runs all four phases in sequence: crawl → subdomain → fuzz → param.
If a phase is interrupted with Ctrl+C, subsequent phases are skipped and results saved.

---

## Detection Coverage

### Secret and Credential Patterns (10)
AWS Access Keys, Google API Keys, GitHub Personal Access Tokens, OpenAI API Keys,
Bearer tokens, JWTs, generic `api_key` / `secret` / `token` JS assignments,
database connection strings (MySQL, PostgreSQL, MongoDB, Redis, JDBC),
RSA private keys, Slack / Discord / Telegram tokens.

Secrets found on multiple pages are deduplicated by `(type, value[:40])` — the same
key appearing on 50 pages appears once in the output.

### Technology Fingerprints (25)
WordPress, Joomla, Drupal, React, Next.js, Nuxt.js, Angular, Vue.js,
jQuery, Bootstrap, Tailwind, Cloudflare, AWS, GCP, PHP, ASP.NET,
Django, Laravel, Express.js, FastAPI, Spring, GraphQL, Nginx, Apache, IIS.

### WAF Detection (9)
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

**Limitation:** only static JS is analyzed. Content assembled by the JS runtime after page load is not visible without a headless browser.

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
| `paramspecter_domain_ts.json` | Full scan: all pages, meta summary, secrets, dir hits, param hits, subdomain hits |
| `paramspecter_domain_ts.csv` | Per-page flat CSV: URL, status, title, technologies, emails, params, forms, headers |
| `paramspecter_domain_ts_dirs.csv` | Directory / file hunt hits: URL, status, size, redirect |
| `paramspecter_domain_ts_params.csv` | Interesting parameters: param name, payload, status delta, size delta, reflected flag |
| `paramspecter_domain_ts_secrets.csv` | Extracted secrets: type, value (truncated at 80 chars), source URL |
| `paramspecter_domain_ts_subdomains.csv` | Subdomains: FQDN, IPs, discovery method, HTTP status, title |

The JSON file includes an `"interrupted": true` flag if the scan was stopped early with Ctrl+C so you can tell apart complete and partial results.

---

## Architecture

```
ParamSpecter v4.3
├── TokenBucket         Per-host token-bucket rate limiter (req/s enforcement)
├── CrawlQueue          BFS / DFS / Priority queue
├── RobotsTxtHandler    robots.txt parsing + sitemap URL extraction
├── JSAnalyzer          External JS + inline blocks + dynamic chunk following
├── analyze_page()      Full HTML pipeline: links, forms, params, cookies, headers, techs
├── SubdomainHunter     DNS brute-force + crt.sh + DNS records + HTTP probe (pooled)
├── DirectoryHunter     Wildcard detection (5 probes + stddev) + recursive enumeration
├── ParamFuzzer         Baseline comparison + multi-payload parameter discovery
├── ProxyManager        Round-robin proxy rotation
└── ParamSpecter        Main orchestrator + threading.Barrier join + atomic output
```

---

## Known Limitations

- **No JS rendering.** React / Vue / Angular content loaded after page-load is not visible. Use Playwright or Selenium for that.
- **No multi-step auth.** Only static cookie / header auth is supported. OAuth flows, MFA, and login form automation are not implemented.
- **No path-scope filtering.** Crawl is bounded by domain, not by path prefix. If you want `/app/` only, filter `--follow-external` off and add your own scope logic.
- **DNS fallback.** Without `dnspython`, subdomain brute-force uses `socket.gethostbyname` which returns one A record only.

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
