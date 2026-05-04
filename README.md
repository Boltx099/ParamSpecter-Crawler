<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

---

# ParamSpecterPro v3.0 — Advanced Recon Crawler

> **For authorized and educational use ONLY.** Only test targets you own or have explicit written permission to test
--- 

ParamSpecter is an advanced reconnaissance web crawler designed for bug bounty hunting and cybersecurity research. It performs deep crawling of web applications, extracts endpoints, analyzes JavaScript files, detects sensitive information, and generates structured outputs for further testing.


---


## What's New in v3.0 (vs v2.0)

| Feature | v2.0 | v3.0 |
|---|---|---|
| Crawl strategies | BFS only | BFS / DFS / Priority queue |
| Retry system | None | Exponential backoff (configurable) |
| User-Agent | Single fixed | Pool of 9 + per-request rotation |
| Content dedup | URL only | URL + content hash (SHA-256) |
| Proxy support | None | Proxy rotation with round-robin |
| Secret patterns | 3 | 10+ (AWS, GitHub, OpenAI, JWTs, DBs) |
| JS analysis | Basic endpoints | Endpoints + secrets + sourcemaps + config vars |
| Param fuzzing payloads | 1 | 6 (normal + SQLi + XSS + SSRF + SSTI + path traversal) |
| Technology detection | 14 techs | 22 techs (Next.js, Nuxt, FastAPI, Spring, GraphQL) |
| WAF detection | 6 WAFs | 10 WAFs (AWS WAF, Imperva, F5) |
| Cookie analysis | None | Flags: HttpOnly / Secure / SameSite |
| Internal IP leak | None | RFC-1918 range detection |
| Sitemap integration | None | Auto-enqueue from robots.txt Sitemap |
| Captcha detection | None | hCaptcha / reCAPTCHA / Turnstile / Arkose |
| Header leak detection | None | X-Powered-By, Server, X-Backend-Server |
| SIGINT handling | Hard stop | Graceful drain of active requests |
| Output | JSON + CSV | JSON + CSV + JSONL + Secrets CSV |
| Security header check | 4 headers | 7 headers tracked |
| Max pages default | 50 | 100 |
| Max crawl depth | 3 | 4 |

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Basic crawl
python ParamSpecter.py https://example.com --ignore-robots

# Full recon (crawl + dir fuzz + param fuzz)
python ParamSpecter.py https://example.com --mode full --ignore-robots

# Deep crawl with UA rotation and proxy
python ParamSpecter.py https://example.com \
  --ignore-robots \
  --depth 5 \
  --threads 20 \
  --rotate-ua \
  --proxies http://127.0.0.1:8080

# Directory bruteforce with custom wordlist
python ParamSpecter.py https://example.com \
  --mode fuzz \
  -w /path/to/wordlist.txt \
  -x .php,.html,.bak \
  --match-codes 200,301,403

# Parameter discovery with smart fuzzing (SQLi, XSS, SSRF)
python ParamSpecter.py https://example.com/search \
  --mode param \
  --smart-fuzz

# DFS crawl (goes deep before wide)
python ParamSpecter.py https://example.com \
  --strategy dfs \
  --depth 6

# With session cookies and custom headers
python ParamSpecter.py https://example.com \
  --cookies "session=abc123; auth=xyz" \
  --headers "X-API-Key: mykey" "Authorization: Bearer token123"
```

---

## All CLI Options

```
positional:
  url                   Target URL  e.g. https://example.com

mode:
  --mode                crawl | fuzz | param | full  (default: crawl)

crawl options:
  -m, --max-pages       Max pages to crawl (default: 100)
  -d, --delay           Delay between requests in seconds (default: 0.2)
  -D, --depth           Max crawl depth (default: 4)
  -t, --threads         Number of threads (default: 10)
  --timeout             Request timeout in seconds (default: 10)
  --max-retries         Retries with exponential backoff (default: 3)
  --strategy            bfs | dfs | priority (default: bfs)
  --follow-external     Follow links to other domains
  --ignore-robots       Ignore robots.txt restrictions

identity and evasion:
  -u, --user-agent      Set a custom User-Agent string
  --rotate-ua           Rotate UA from pool on each request
  --cookies             Cookie string: "a=1; b=2"
  --headers             Extra headers: "X-Foo: bar" (repeatable)
  --proxies             Comma-sep proxy list: http://127.0.0.1:8080,...

fuzzing:
  -w, --wordlist        Wordlist for directory fuzzing
  -pw, --param-wordlist Wordlist for parameter fuzzing
  -x, --extensions      File extensions: .php,.html,.bak
  --match-codes         Only show these HTTP codes: 200,301,403
  --hide-codes          Hide these HTTP codes (default: 404)
  --param-method        GET | POST (default: GET)
  --smart-fuzz          Test 6 payloads per param (SQLi, XSS, SSRF)

output:
  -o, --output          json | csv | both | jsonl (default: both)
```

---

## Output Files

| File | Contents |
|---|---|
| paramspecter_domain_ts.json | Full crawl data (pages, meta, secrets) |
| paramspecter_domain_ts.csv | Per-page flat CSV |
| paramspecter_domain_ts_fuzz.csv | Directory fuzz hits |
| paramspecter_domain_ts_params.csv | Interesting parameter hits |
| paramspecter_domain_ts_secrets.csv | Extracted secrets |

---

## Architecture

```
ParamSpecter
├── CrawlQueue          BFS / DFS / Priority queue
├── RobotsTxtHandler    robots.txt + sitemap extraction
├── JSAnalyzer          JS endpoint + secret + sourcemap analysis
├── analyze_page()      Full HTML page analysis pipeline
├── DirFuzzer           Multi-threaded directory bruteforce
├── ParamFuzzer         Multi-payload parameter discovery
├── ProxyManager        Round-robin proxy rotation
└── ParamSpecter        Main orchestrator + stats + output
```

---

## Security Research Features

| Feature | Description |
|---|---|
| JS source analysis | Extracts API endpoints, secrets, config vars, sourcemaps |
| Secret detection | 10+ patterns: AWS keys, GitHub PATs, JWTs, DB strings, OpenAI keys |
| Parameter reflection | Detects reflected params (XSS surface) |
| Smart fuzzing | Tests SQLi, XSS, SSRF, SSTI, path traversal payloads |
| Cookie flags | Flags cookies missing HttpOnly/Secure/SameSite |
| WAF fingerprinting | Identifies 10 common WAF products |
| Internal IP detection | Flags RFC-1918 addresses leaking in responses |
| Security header audit | Tracks 7 security headers across all pages |
| CAPTCHA detection | Detects reCAPTCHA, hCaptcha, Turnstile, Arkose |
| Technology fingerprinting | Identifies 22 frameworks, servers, CDNs |

---

## Scaling for Distributed Crawling

1. Replace CrawlQueue with Redis-backed queue (rq, celery)
2. Move visited set to Redis SET for shared deduplication
3. Run multiple instances pointing at the same Redis queue
4. Write results to MongoDB or PostgreSQL instead of flat files
5. Use Kubernetes Jobs or AWS Fargate for worker scaling

Redis example:
```python
import redis
r = redis.Redis()
r.sadd("visited", url)
r.lpush("queue", url)
url = r.brpop("queue", timeout=3)
```
