<p align="center">
  <img src="banner.png" alt="ParamSpecter Banner" width="100%">
</p>

---

# ParamSpecter

ParamSpecter is an advanced reconnaissance web crawler designed for bug bounty hunting and cybersecurity research. It performs deep crawling of web applications, extracts endpoints, analyzes JavaScript files, detects sensitive information, and generates structured outputs for further testing.

---
## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Do not use ParamSpecter on systems without proper permission.

---
## Features
```
- Multi-threaded crawling engine  
- Depth-based crawling  
- Robots.txt support (optional)  
- Internal and external link discovery  
- Parameter detection (`?id=`, `?search=` etc.)  
- JavaScript file extraction  
- Deep JavaScript endpoint analysis  
- Secret detection (API keys, tokens, bearer authentication, AWS keys)  
- Email, IP, and subdomain extraction  
- Technology fingerprinting  
- WAF detection  
- Security headers analysis  
- JSON and CSV output  
```
---
## How It Works

ParamSpecter works by initializing a queue-based crawling system with multiple threads. Each worker fetches URLs, checks if they were visited, respects robots.txt (optional), sends HTTP requests, and parses responses. Pages are analyzed using `analyze_page(url, resp, soup, raw_html)` to extract metadata, links, endpoints, and sensitive information.

JavaScript files are extracted using `<script src="...">`, downloaded, and scanned for hidden endpoints such as `/api/login`, `/api/v1/user`, `/admin/dashboard`, and `/auth/token`. It also detects secrets like API keys, tokens, bearer authentication, and AWS keys (e.g., `api_key=abcd1234`, `Bearer eyJhbGciOi...`, `AKIA...`).

Collected data includes URLs, parameters, emails, IPs, subdomains, technologies, WAF indicators, and security headers. Results are saved in JSON and CSV formats (e.g., `paramspecter_example_com_20260101.json`).

---
## Installation, Requirements, Usage and Options

Clone the repository, install dependencies, and run:
```bash
git clone  https://github.com/Boltx099/ParamSpecter-Crawler.git

cd ParamSpecter-Crawler
cd ParamSpecter  
pip install -r requirements.txt

python setup.py install  
```
Requirements:

requests>=2.31.0  
beautifulsoup4>=4.12.0  

Usage:
```bash
python ParamSpecter.py https://example.com
```

Options:
```
-m, --max-pages     Maximum pages to crawl (default: 50)  
-d, --delay         Delay between requests (default: 0.8)  
-D, --depth         Crawl depth (default: 3)  
-t, --threads       Number of threads (default: 5)  
--timeout           Request timeout (default: 10)  
-o, --output        Output format (json, csv, both)  
--follow-external   Crawl external links  
--ignore-robots     Ignore robots.txt rules  
-u, --user-agent    Custom user agent  
```
Example:

```
python ParamSpecter.py https://testphp.vulnweb.com -D 2 -t 5  

```
---
## Project Structure

ParamSpecter.py      Main crawler script  
requirements.txt     Dependencies  
README.md            Documentation  

---
## Use Cases

- Bug bounty reconnaissance  
- Endpoint discovery  
- Parameter identification  
- JavaScript analysis  
- Sensitive data exposure detection  
- Web application mapping  

---
## Limitations

- Does not execute JavaScript  
- May miss dynamic content  
- Regex-based detection may produce false positives  

---
## Future Improvements

- Headless browser support (Playwright)  
- Advanced parameter fuzzing  
- Secret validation  
- Subdomain enumeration  
- Integration with tools like ffuf and nuclei  

---
## Author

Boltx

---
## License

This project is for educational use only.


