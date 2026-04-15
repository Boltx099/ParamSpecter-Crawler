<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

# ParamSpecter-Crawler

ParamSpecter is an advanced reconnaissance web crawler designed for bug bounty hunting and cybersecurity research. It performs deep crawling of web applications, extracts endpoints, analyzes JavaScript files, detects sensitive information, and generates structured outputs for further testing.

---

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Do not use ParamSpecter on systems without proper permission.

---

## Features

- Multi-threaded crawling engine
- Depth-based crawling
- Robots.txt support (optional)
- Internal and external link discovery
- Parameter detection (?id=, ?search=, etc.)
- JavaScript file extraction
- Deep JavaScript endpoint analysis
- Secret detection:
  - API keys
  - Tokens
  - Bearer authentication
  - AWS keys
- Email, IP, and subdomain extraction
- Technology fingerprinting
- WAF detection
- Security headers analysis
- JSON and CSV output

---

## How It Works

### 1. Initialization

ParamSpecter starts by taking a target URL and initializing:

- A queue-based crawling system
- Thread workers
- Depth and page limits
- HTTP session with headers

---

### 2. Crawling Engine

The crawler uses multiple threads. Each worker:

1. Fetches a URL from the queue
2. Checks if it was already visited
3. Verifies robots.txt rules (if enabled)
4. Sends an HTTP request
5. Parses the response

---

### 3. Page Analysis

Each page is processed using:

analyze_page(url, resp, soup, raw_html)

This function extracts:

#### Basic Information
- Status code
- Content type
- Server headers
- Redirect chain

#### Metadata
- Page title
- Meta description

#### Links
- Internal links
- External links
- Social media links

---
### 4. JavaScript Analysis

ParamSpecter extracts JavaScript files from HTML:

<script src="...">

Then downloads and scans them for:

- Hidden API endpoints
- Internal routes

Examples:
- /api/login
- /api/v1/user
- /admin/dashboard
- /auth/token### 4. JavaScript Analysis

ParamSpecter extracts JavaScript files from HTML:

<script src="...">

Then downloads and scans them for:

- Hidden API endpoints
- Internal routes

Examples:
- /api/login
- /api/v1/user
- /admin/dashboard
- /auth/token



