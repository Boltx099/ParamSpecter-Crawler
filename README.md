<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

---

# ParamSpecter v6.0 — Advanced Recon Crawler

> **For authorized and educational use ONLY.**
> Only test targets you own or have explicit written permission to test.
> Unauthorized testing is illegal.

---

## What is ParamSpecter?

ParamSpecter is an advanced reconnaissance web crawler built for bug bounty hunting and security research. It performs deep recursive crawling, subdomain discovery, directory and file enumeration, parameter fuzzing with active vulnerability detection, JS analysis, secret detection, technology fingerprinting, automated form login, JS-rendered page crawling via Playwright, multi-domain scope control, scan resumption, custom payload injection, and downstream tool target export — all from a single command.

---

## Changelog

### v6.0 — Current Release

**Architecture**

Refactored from a single monolithic file into a proper Python package:

```
paramspecter/
├── __init__.py
├── __main__.py          ← python -m paramspecter entry point
├── cli.py               ← argparse, banner, config display
├── core/
│   ├── analyzer.py      ← JSAnalyzer, analyze_page(), RobotsTxtHandler
│   ├── crawler.py       ← ParamSpecter orchestrator + crawl worker
│   └── stats.py         ← CrawlStats, CrawlQueue, TokenBucket, ProxyManager
├── modules/
│   ├── dirhunt.py       ← DirectoryHunter
│   ├── login.py         ← FormLoginHandler
│   ├── paramfuzz.py     ← DeepFuzzCheck subclasses + ParamFuzzer
│   └── subdomain.py     ← SubdomainHunter
├── output/
│   └── reporter.py      ← JSON / CSV / HTML / JSONL output + export_targets()
└── utils/
    ├── constants.py     ← All regex patterns, wordlists, signatures
    ├── helpers.py       ← Colors, logging, URL helpers, validation
    └── http.py          ← fetch_with_retry(), Playwright, checkpoints
```

**Bug fixes**

| Bug | Fix |
|---|---|
| Syntax error in `SECRET_PATTERNS` regex strings | `["\'']` → `["\']` in all 7 affected patterns |
| Duplicate param hits printed and recorded twice | Hit recording moved inside dedup lock; `(param, payload)` key checked before append |
| Blank lines between param results | tqdm removed from `_worker` and `_deep_worker`; per-hit `PARAM XX%` log lines provide progress without terminal corruption |

**New features**

| Feature | Description |
|---|---|
| Retry with exponential backoff | Retries on `ConnectionReset`, 503, 429 with jitter |
| Input validation | URL, file, and output-dir args validated upfront with clear error messages |
| Configurable verbosity | `--quiet` (findings + summary only) / `--verbose` (retry/skip/dupe messages) |
| Per-phase timing | Duration of each phase shown in summary and saved to JSON meta |
| Request-rate telemetry | Total requests sent and avg req/s in summary and HTML report |
| OpenAPI / Swagger discovery | Detects `swagger.json`, `openapi.yaml` linked from HTML during crawl |
| robots.txt sitemap depth cap | Prevents infinite sitemap-index chains (max 3 hops) |
| JSONL streaming writes | `--output jsonl` streams one JSON object per page, never buffers full result list in RAM |
| CWE cross-reference | Deep-fuzz findings include CWE ID (e.g. `CWE-89`, `CWE-79`) |

---

### v5.0

| Feature | Description |
|---|---|
| Header Injection check | `--deep-fuzz` — Host header injection + CRLF injection detection |
| IDOR check | `--deep-fuzz` — Numeric ID incrementation across params |
| Custom payload file | `--payload-file FILE` |
| Scope file | `--scope-file FILE` — Multi-domain bug bounty scope |
| Rate limit CLI | `--rate-limit REQ/S` |
| Resume / checkpoint | `--resume` |
| Output directory | `--output-dir DIR` |
| HTML report | Auto-generated dark-theme report on every scan |

### v4.3

| Feature | Description |
|---|---|
| Playwright crawling | `--playwright` — Headless Chromium + XHR interception |
| Form-based login | `--login-url` — Auto CSRF extraction + session injection |
| Deep vulnerability fuzzing | `--deep-fuzz` — SQLi, XSS, PathTraversal, SSRF, OpenRedirect |
| Target export | `--export-targets` — nuclei + sqlmap target lists |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Boltx/ParamSpecter-Crawler.git
cd ParamSpecter-Crawler
```

### 2. (Recommended) Create a virtual environment

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows CMD
python -m venv venv
venv\Scripts\activate.bat

# Windows PowerShell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install core dependencies

```bash
pip install -r requirements.txt
```

**What gets installed:**

| Package | Version | Purpose |
|---|---|---|
| `requests` | ≥ 2.31.0 | HTTP client for all crawl, fuzz, and probe requests |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing — links, forms, comments, meta tags |
| `lxml` | ≥ 4.9.0 | Faster HTML parser backend for BeautifulSoup |
| `dnspython` | ≥ 2.4.0 | Full DNS resolution (A, AAAA, MX, NS, TXT, CNAME, SOA) |
| `tqdm` | ≥ 4.66.0 | Progress bars for directory hunt and subdomain brute-force |
| `colorama` | ≥ 0.4.6 | ANSI color support on Windows terminals |

### 4. (Optional) Install Playwright for JS rendering

Required only when using the `--playwright` flag:

```bash
pip install playwright
playwright install chromium
```

Without Playwright, `--playwright` logs a warning and automatically falls back to `requests`.

### 5. (Optional) Install as a system command

```bash
pip install -e .
```

Registers the `paramspecter` command globally so you can run it from anywhere without `python -m`.

---

## System Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.8 or newer |
| OS | Linux, macOS, Windows |
| RAM | 256 MB (Playwright crawls may use more) |
| Network | Outbound HTTP/HTTPS + DNS |

### Check your Python version

```bash
python3 --version
```

If you have Python 3.7 or older, upgrade:

```bash
# Ubuntu / Debian
sudo apt install python3.11

# macOS (Homebrew)
brew install python@3.11

# Windows — download from https://www.python.org/downloads/
```

### Install pip if missing

```bash
# Ubuntu / Debian
sudo apt install python3-pip

# macOS / Windows
python3 -m ensurepip --upgrade
```

---

## Quick Start

> **v6.0 is now a package.** Use `python -m paramspecter` instead of `python ParamSpecter.py`.
> After `pip install -e .` you can also just run `paramspecter` directly.

```bash
# Basic crawl
python -m paramspecter https://example.com --ignore-robots

# Subdomain enumeration
python -m paramspecter https://example.com --mode subdomain
python -m paramspecter https://example.com --mode subdomain --sub-wordlist subs.txt

# Directory hunting (recursive, with extensions)
python -m paramspecter https://example.com --mode fuzz --recursive
python -m paramspecter https://example.com --mode fuzz -w dirs.txt -x .php,.html,.bak --recursive-depth 3

# Parameter fuzzing (smart = 6 payloads per param)
python -m paramspecter https://example.com/search --mode param --smart-fuzz

# Deep vulnerability scan (SQLi / XSS / LFI / SSRF / redirect / header injection / IDOR)
python -m paramspecter https://example.com/search --mode param --deep-fuzz

# Deep fuzz via POST with custom payloads
python -m paramspecter https://example.com/search --mode param --deep-fuzz \
  --param-method POST --payload-file my_payloads.txt

# Full recon: all four phases in order
python -m paramspecter https://example.com --mode full -t 20 --ignore-robots

# Multi-domain scope file
python -m paramspecter https://example.com --mode full --scope-file scope.txt

# Rate limiting (max 5 req/s per host)
python -m paramspecter https://example.com --rate-limit 5

# Resume an interrupted scan
python -m paramspecter https://example.com --resume
python -m paramspecter https://example.com --resume --resume-file /tmp/my_checkpoint.txt

# Save all output to a specific directory
python -m paramspecter https://example.com --output-dir /tmp/scans/example/

# Memory-efficient JSONL streaming (large crawls)
python -m paramspecter https://example.com --output jsonl

# JS-rendered crawl with XHR endpoint discovery
python -m paramspecter https://example.com --playwright

# Automated form login before crawling
python -m paramspecter https://example.com \
  --login-url https://example.com/login \
  --login-user admin@example.com \
  --login-pass hunter2

# Form login with non-standard field names
python -m paramspecter https://example.com \
  --login-url https://example.com/login \
  --login-user admin \
  --login-pass secret \
  --login-user-field email \
  --login-pass-field pwd

# Export nuclei + sqlmap target lists after crawl
python -m paramspecter https://example.com --export-targets
python -m paramspecter https://example.com --mode full --export-targets --ignore-robots

# Deep crawl with UA rotation and Burp proxy
python -m paramspecter https://example.com \
  --ignore-robots --depth 6 --threads 15 \
  --rotate-ua --proxies http://127.0.0.1:8080

# Authenticated session via static cookie
python -m paramspecter https://example.com \
  --cookies "session=abc123; auth=xyz" \
  --headers "X-API-Key: mykey" "Authorization: Bearer token123"

# Quiet mode (only findings and summary)
python -m paramspecter https://example.com --quiet

# Verbose mode (retry/skip/dupe messages)
python -m paramspecter https://example.com --verbose
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

scope:
  --scope-file FILE          File of in-scope domains (one per line, wildcards: *.example.com)

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
  -x,  --extensions          File extensions to append: .php,.html,.bak
  --match-codes              Only show these HTTP codes: 200,301,403
  --hide-codes               Hide these HTTP codes (default: 404)
  --recursive                Recursively enumerate discovered directories
  --recursive-depth          Max recursion depth (default: 2)

parameter fuzzing:
  -pw, --param-wordlist      Parameter wordlist
  --param-method             GET | POST  (default: GET)
  --smart-fuzz               Test 6 payloads per param (SQLi, XSS, SSRF, SSTI, traversal)
  --deep-fuzz                Extended per-param vuln checks with CWE refs (implies --smart-fuzz)
  --payload-file FILE        Custom payload file: LABEL:payload per line
                             Labels: SQLi XSS PathTraversal SSRF OpenRedirect HeaderInjection IDOR

output:
  -o, --output               json | csv | both | jsonl  (default: both)
  --output-dir DIR           Directory for all output files (default: current directory)
  --export-targets           Write nuclei-ready targets.txt + sqlmap_targets.txt

verbosity (mutually exclusive):
  --quiet                    Suppress per-page output; show only findings and final summary
  --verbose                  Show retry, skip, and dedup messages (debug level)
```

---

## Deep Fuzz (`--deep-fuzz`)

Seven categories, all with CWE cross-reference:

| Check | Severity | CWE | Detection |
|---|---|---|---|
| SQLi | HIGH | CWE-89 | DB error keywords + time-based blind (SLEEP) |
| XSS | HIGH | CWE-79 | Payload reflected unencoded in response body |
| PathTraversal | HIGH | CWE-22 | `/etc/passwd` or `win.ini` content in response |
| SSRF | HIGH | CWE-918 | AWS/GCP/Azure metadata content in response |
| OpenRedirect | MEDIUM | CWE-601 | `Location` header or meta-refresh to canary domain |
| HeaderInjection | HIGH | CWE-113 | Host header reflected + CRLF injected header appears |
| IDOR | HIGH | CWE-639 | Status change or size delta on numeric ID ±1/±100/0 |

Custom payload file format:

```
# my_payloads.txt
SQLi:' OR SLEEP(10)-- -
XSS:<details open ontoggle=alert(1)>
HeaderInjection:crlf_inject:%0d%0aSet-Cookie:injected=1
IDOR:99999
```

---

## Output Files

All files written atomically (temp + rename). Ctrl+C mid-write never produces a corrupt file.

| File | Contents |
|---|---|
| `<pfx>.json` | Full scan: pages, secrets, dir hits, param hits, subdomain hits |
| `<pfx>.jsonl` | Streaming — one page JSON per line (`--output jsonl`) |
| `<pfx>_meta.json` | Scan metadata when using `--output jsonl` |
| `<pfx>.csv` | Per-page flat CSV |
| `<pfx>_report.html` | Self-contained dark-theme HTML report |
| `<pfx>_dirs.csv` | Directory hit: URL, status, size, redirect |
| `<pfx>_params.csv` | Param findings with CWE column |
| `<pfx>_secrets.csv` | Secrets: type, value (truncated 80 chars), source URL |
| `<pfx>_subdomains.csv` | Subdomains: FQDN, IPs, method, HTTP status, title |
| `<pfx>_targets.txt` | All parameterised URLs — nuclei-ready (`--export-targets`) |
| `<pfx>_sqlmap_targets.txt` | Injectable subset — sqlmap-ready (`--export-targets`) |
| `<pfx>_checkpoint.txt` | Visited URLs for `--resume` (auto-saved every 50 pages) |

`<pfx>` = `paramspecter_<domain>_<YYYYMMDD_HHMMSS>`

---

## Architecture

```
ParamSpecter v6.0
├── utils/
│   ├── constants.py     All regex patterns, built-in wordlists, tech/WAF signatures
│   ├── helpers.py       Colors, logging, URL helpers, input validation
│   └── http.py          fetch_with_retry() + backoff, Playwright fetch, checkpoints
├── core/
│   ├── stats.py         CrawlStats, CrawlQueue (BFS/DFS/Priority), TokenBucket, ProxyManager
│   ├── analyzer.py      RobotsTxtHandler, JSAnalyzer, analyze_page()
│   └── crawler.py       ParamSpecter — phase orchestration + crawl worker + summary
├── modules/
│   ├── subdomain.py     SubdomainHunter — DNS brute + crt.sh + HTTP probe
│   ├── dirhunt.py       DirectoryHunter — wildcard detection + recursive enumeration
│   ├── paramfuzz.py     ParamFuzzer + all DeepFuzzCheck subclasses
│   └── login.py         FormLoginHandler — CSRF extraction + session injection
└── output/
    └── reporter.py      JSON / CSV / JSONL / HTML output + export_targets()
```

---

## Known Limitations

- **SSRF detection is reflection-only.** Blind SSRF requires Burp Collaborator or interactsh.
- **IDOR detection is heuristic.** Confirm findings manually.
- **Form login is single-step.** OTP, CAPTCHA, OAuth, MFA not supported.
- **No path-scope filtering.** Scope is by domain/host, not URL path prefix.
- **DNS fallback.** Without `dnspython`, subdomain brute uses `socket.gethostbyname` (one A record only).
- **Deep fuzz is not a full scanner.** Black-box heuristics — confirm all findings manually.

---

## Legal

This tool is for **authorized security testing and educational use only**.

- Only test targets you own or have explicit written permission to test
- Unauthorized scanning is illegal in most jurisdictions
- The authors accept no liability for misuse

---

*Created by Boltx*
