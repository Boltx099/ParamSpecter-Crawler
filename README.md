<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

---

# ParamSpecter v4.0 — Advanced Recon Crawler

> **For authorized and educational use ONLY.** Only test targets you own or have explicit written permission to test.

---

## What is ParamSpecter?

ParamSpecter is an advanced reconnaissance web crawler built for bug bounty hunting and security research. It performs deep crawling of web applications, hunts subdomains, enumerates directories and files, extracts API endpoints, detects secrets and credentials, and generates structured reports for further testing.

---

## What's New in v4.0

| Feature | v3.0 | v4.0 |
|---|---|---|
| Subdomain enumeration | Passive (from HTML only) | Active: DNS brute-force + crt.sh + DNS records + HTTP probe |
| Wildcard DNS detection | None | Auto-detects and filters false positives |
| Directory enumeration | Basic fuzzer | DirectoryHunter with wildcard/soft-404 detection + size dedup |
| Recursive directory scan | None | Yes, configurable depth |
| URL normalization | Basic | Fragment stripping, port normalization, param sorting, dedup |
| Link extraction | All hrefs | Skips mailto, javascript, tel, data, binary/media extensions |
| MIME-type gating | None | Only parses HTML/text responses |
| Subdomain mode | None | Dedicated `--mode subdomain` |
| New CLI flags | — | `--recursive`, `--recursive-depth`, `--sub-wordlist` |
| Output files | 5 | 6 (adds `_subdomains.csv`) |

---

## What v3.0 Already Had (still included)

| Feature | Description |
|---|---|
| Crawl strategies | BFS / DFS / Priority queue |
| Retry system | Exponential backoff (configurable) |
| User-Agent rotation | Pool of 9 + per-request rotation |
| Content dedup | URL + SHA-256 content hash |
| Proxy rotation | Round-robin proxy support |
| Secret detection | 10+ patterns: AWS, GitHub, OpenAI, JWTs, DB strings, Bearer tokens |
| JS analysis | Endpoints + secrets + sourcemaps + config vars from JS files |
| Param fuzzing | 6 payloads: normal, SQLi, XSS, SSRF, SSTI, path traversal |
| Technology detection | 22 techs (Next.js, Nuxt, FastAPI, Spring, GraphQL, etc.) |
| WAF detection | 10 WAFs (Cloudflare, AWS WAF, Imperva, F5, etc.) |
| Cookie flag analysis | HttpOnly / Secure / SameSite checks |
| Internal IP detection | RFC-1918 range leaks in responses |
| Sitemap integration | Auto-enqueue URLs from robots.txt Sitemap entries |
| CAPTCHA detection | hCaptcha / reCAPTCHA / Turnstile / Arkose |
| Header leak detection | X-Powered-By, Server, X-Backend-Server, X-Debug-Token |
| Security header audit | 7 headers tracked across all crawled pages |

---

## Installation

```bash
pip install -r requirements.txt
```

For best subdomain enumeration results, install dnspython:

```bash
pip install dnspython
```

---

## Quick Start

```bash
# Basic crawl
python ParamSpecter.py https://example.com --ignore-robots

# Subdomain enumeration only
python ParamSpecter.py https://example.com --mode subdomain

# Subdomain enumeration with custom wordlist
python ParamSpecter.py https://example.com --mode subdomain --sub-wordlist /path/to/subs.txt

# Directory hunting with recursive scan
python ParamSpecter.py https://example.com --mode fuzz --recursive --recursive-depth 3

# Directory hunting with extensions and custom wordlist
python ParamSpecter.py https://example.com --mode fuzz -w /path/to/dirs.txt -x .php,.html,.bak

# Parameter fuzzing with smart payloads
python ParamSpecter.py https://example.com/search --mode param --smart-fuzz

# Full recon: crawl + subdomains + directories + params
python ParamSpecter.py https://example.com --mode full -t 20

# Deep crawl with UA rotation and proxy
python ParamSpecter.py https://example.com \
  --ignore-robots \
  --depth 5 \
  --threads 20 \
  --rotate-ua \
  --proxies http://127.0.0.1:8080

# With session cookies and custom headers
python ParamSpecter.py https://example.com \
  --cookies "session=abc123; auth=xyz" \
  --headers "X-API-Key: mykey" "Authorization: Bearer token123"
```

---

## All CLI Options

```
positional:
  url                     Target URL  e.g. https://example.com

mode:
  --mode                  crawl | fuzz | param | subdomain | full  (default: crawl)

crawl options:
  -m, --max-pages         Max pages to crawl (default: 100)
  -d, --delay             Delay between requests in seconds (default: 0.2)
  -D, --depth             Max crawl depth (default: 4)
  -t, --threads           Number of threads (default: 10)
  --timeout               Request timeout in seconds (default: 10)
  --max-retries           Retries with exponential backoff (default: 3)
  --strategy              bfs | dfs | priority (default: bfs)
  --follow-external       Follow links to other domains
  --ignore-robots         Ignore robots.txt restrictions

identity and evasion:
  -u, --user-agent        Set a custom User-Agent string
  --rotate-ua             Rotate UA from pool on each request
  --cookies               Cookie string: "a=1; b=2"
  --headers               Extra headers: "X-Foo: bar" (repeatable)
  --proxies               Comma-sep proxy list: http://127.0.0.1:8080,...

subdomain enumeration:
  -sw, --sub-wordlist     Custom subdomain wordlist (subdomain/full modes)

directory hunting:
  -w, --wordlist          Wordlist for directory hunting
  -x, --extensions        File extensions to probe: .php,.html,.bak
  --match-codes           Only show these HTTP codes: 200,301,403
  --hide-codes            Hide these HTTP codes (default: 404)
  --recursive             Recursively enumerate discovered directories
  --recursive-depth       Max recursion depth (default: 2)

parameter fuzzing:
  -pw, --param-wordlist   Wordlist for parameter fuzzing
  --param-method          GET | POST (default: GET)
  --smart-fuzz            Test 6 payloads per param (SQLi, XSS, SSRF, SSTI, path traversal)

output:
  -o, --output            json | csv | both | jsonl (default: both)
```

---

## Modes Explained

**crawl** — Recursively follows links from the target URL. Extracts emails, parameters, JS endpoints, secrets, cookies, forms, technologies, and WAF signatures from every page.

**subdomain** — Three-phase subdomain discovery. Phase 1 brute-forces DNS using a wordlist with wildcard detection to filter false positives. Phase 2 queries crt.sh certificate transparency logs. Phase 3 pulls DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA). Every discovered subdomain is then HTTP-probed to check liveness and grab its title.

**fuzz** — Directory and file enumeration against the target. Sends two random non-existent probes first to detect wildcard/catch-all behavior. Responses matching the wildcard baseline size are silently dropped. With `--recursive`, any discovered path that looks like a directory is re-enumerated up to `--recursive-depth` levels.

**param** — Fuzzes URL parameters against the target page. Compares response code and size against a baseline. Reports parameters that produce a different status code, a significant size change, or reflect the payload back (potential XSS surface). Use `--smart-fuzz` to test 6 payloads per parameter instead of one.

**full** — Runs all four phases in order: crawl, subdomain, fuzz, param.

---

## API Endpoint and Secret Detection

ParamSpecter finds API endpoints through static JS analysis (every `<script src>` is fetched and scanned for paths like `/api/...`, `/v1/...`, `/graphql/...`), inline JS string extraction, URL parameter harvesting from all links, and directory fuzzing against known API paths.

Secret and credential detection covers AWS Access Keys, Google API Keys, GitHub Personal Access Tokens, OpenAI API Keys, Bearer tokens, JWTs, generic `api_key`/`secret`/`token` assignments in JS, database connection strings (MySQL, PostgreSQL, MongoDB, Redis), private RSA keys, Slack/Discord/Telegram tokens, and JS config variable names that suggest credentials.

Note: only static analysis is performed. Secrets assembled at runtime or endpoints loaded dynamically via `fetch()` are not caught without a headless browser.

---

## Output Files

| File | Contents |
|---|---|
| `paramspecter_domain_ts.json` | Full scan data: pages, meta, secrets, all hits |
| `paramspecter_domain_ts.csv` | Per-page flat CSV |
| `paramspecter_domain_ts_dirs.csv` | Directory and file hunt hits |
| `paramspecter_domain_ts_params.csv` | Interesting parameter hits |
| `paramspecter_domain_ts_secrets.csv` | Extracted secrets and credentials |
| `paramspecter_domain_ts_subdomains.csv` | Discovered subdomains with IPs, status, method |

---

## Architecture

```
ParamSpecter v4.0
├── CrawlQueue          BFS / DFS / Priority queue
├── RobotsTxtHandler    robots.txt + sitemap extraction
├── JSAnalyzer          JS endpoint + secret + sourcemap analysis
├── analyze_page()      Full HTML page analysis pipeline
├── SubdomainHunter     DNS brute-force + crt.sh + DNS records + HTTP probe
├── DirectoryHunter     Wildcard detection + recursive directory enumeration
├── ParamFuzzer         Multi-payload parameter discovery
├── ProxyManager        Round-robin proxy rotation
└── ParamSpecter        Main orchestrator + stats + output
```

---

## Scaling for Distributed Crawling

Replace `CrawlQueue` with a Redis-backed queue, move the visited set to Redis SET for shared deduplication, and run multiple instances pointing at the same queue. Write results to MongoDB or PostgreSQL instead of flat files.

```python
import redis
r = redis.Redis()
r.sadd("visited", url)
r.lpush("queue", url)
url = r.brpop("queue", timeout=3)
```
