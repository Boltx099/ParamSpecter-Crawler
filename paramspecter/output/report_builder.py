"""
output/report_builder.py
Professional pentest-style report generator.

Produces a self-contained HTML report that looks like a real
deliverable — executive summary, CVSS scores, reproduction steps,
curl PoC commands, and remediation guidance.

Also generates auto-ready nuclei YAML templates for each finding.

Usage (called automatically after scan if --pro-report flag set,
or imported and called directly):
    from paramspecter.output.report_builder import build_pro_report
    build_pro_report(scanner, output_dir)
"""

import html
import json
import os
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

from ..utils import log, col, C


# -----------------------------------------------------------------
#  CVSS v3 BASE SCORES + REMEDIATION DATABASE
# -----------------------------------------------------------------
VULN_DB: Dict[str, Dict] = {
    "SQLi": {
        "cvss":        9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe":         "CWE-89",
        "owasp":       "A03:2021 – Injection",
        "title":       "SQL Injection",
        "description": (
            "The application passes user-supplied input directly into SQL queries "
            "without proper sanitisation. An attacker can manipulate the query logic "
            "to extract data, bypass authentication, modify records, or execute "
            "operating system commands depending on the database configuration."
        ),
        "impact": "Complete database compromise, authentication bypass, potential RCE via xp_cmdshell / INTO OUTFILE.",
        "remediation": (
            "Use parameterised queries (prepared statements) for ALL database interactions. "
            "Never concatenate user input into SQL strings. Apply the principle of least privilege "
            "to the database user. Enable WAF rules for SQL injection patterns."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "XSS": {
        "cvss":        6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe":         "CWE-79",
        "owasp":       "A03:2021 – Injection",
        "title":       "Cross-Site Scripting (XSS)",
        "description": (
            "The application reflects unsanitised user input in the HTTP response. "
            "An attacker can inject malicious JavaScript that executes in the victim's "
            "browser, enabling session hijacking, credential theft, or malware distribution."
        ),
        "impact": "Session hijacking, credential theft, defacement, phishing, keylogging.",
        "remediation": (
            "HTML-encode all output. Use a strict Content-Security-Policy header. "
            "Validate and sanitise all input server-side. Use framework-provided "
            "templating engines with auto-escaping enabled."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "SSRF": {
        "cvss":        9.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe":         "CWE-918",
        "owasp":       "A10:2021 – Server-Side Request Forgery",
        "title":       "Server-Side Request Forgery (SSRF)",
        "description": (
            "The server fetches a remote resource based on user-controlled input "
            "without validating the destination. An attacker can target internal services, "
            "cloud metadata endpoints (AWS/GCP/Azure), or use the server as a proxy "
            "for further attacks."
        ),
        "impact": "Cloud credential theft via metadata API, internal network scanning, RCE in severe cases.",
        "remediation": (
            "Validate and allowlist URLs server-side. Block requests to 169.254.169.254, "
            "10.x.x.x, 172.16.x.x, 192.168.x.x. Use a dedicated HTTP client that "
            "does not follow redirects to private ranges."
        ),
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "PathTraversal": {
        "cvss":        7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe":         "CWE-22",
        "owasp":       "A01:2021 – Broken Access Control",
        "title":       "Path Traversal",
        "description": (
            "The application uses user-controlled input to construct file paths "
            "without properly sanitising directory traversal sequences (../). "
            "An attacker can read arbitrary files from the server including "
            "configuration files, credentials, and source code."
        ),
        "impact": "Arbitrary file read, credential disclosure, source code exposure.",
        "remediation": (
            "Canonicalise file paths and verify they reside within the intended "
            "base directory. Use allowlists for permitted file names. "
            "Never pass user input directly to file system APIs."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
    },
    "CORS": {
        "cvss":        8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cwe":         "CWE-942",
        "owasp":       "A01:2021 – Broken Access Control",
        "title":       "CORS Misconfiguration",
        "description": (
            "The server reflects arbitrary origins in the Access-Control-Allow-Origin "
            "header, potentially combined with Access-Control-Allow-Credentials: true. "
            "This allows a malicious website to make cross-origin requests and read "
            "the victim's authenticated responses."
        ),
        "impact": "Cross-origin data theft, account takeover if credentials are permitted.",
        "remediation": (
            "Maintain an explicit allowlist of trusted origins. Never reflect the "
            "Origin header verbatim. Do not combine wildcard ACAO with "
            "Access-Control-Allow-Credentials: true."
        ),
        "references": [
            "https://portswigger.net/web-security/cors",
        ],
    },
    "OpenRedirect": {
        "cvss":        6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe":         "CWE-601",
        "owasp":       "A01:2021 – Broken Access Control",
        "title":       "Open Redirect",
        "description": (
            "The application redirects users to a destination controlled by the "
            "attacker via a URL parameter. This can be used to bypass security "
            "checks, steal OAuth tokens, or launch phishing campaigns using the "
            "trusted domain as a redirect proxy."
        ),
        "impact": "OAuth token theft, phishing, credential harvesting.",
        "remediation": (
            "Validate redirect destinations against an allowlist. Avoid using "
            "user-supplied input in redirect logic. If redirects are necessary, "
            "use indirect references (e.g. numeric IDs mapped server-side)."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
    },
    "HeaderInjection": {
        "cvss":        6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe":         "CWE-113",
        "owasp":       "A03:2021 – Injection",
        "title":       "HTTP Header Injection",
        "description": (
            "The application reflects user-supplied input in HTTP response headers "
            "without sanitising CR/LF characters. An attacker can inject arbitrary "
            "headers, split responses, set malicious cookies, or perform cache poisoning."
        ),
        "impact": "Cache poisoning, session fixation, XSS via injected headers.",
        "remediation": (
            "Strip or reject CR (\\r) and LF (\\n) characters from any user input "
            "that is placed into HTTP response headers."
        ),
        "references": [
            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
        ],
    },
    "IDOR": {
        "cvss":        8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe":         "CWE-639",
        "owasp":       "A01:2021 – Broken Access Control",
        "title":       "Insecure Direct Object Reference (IDOR)",
        "description": (
            "The application exposes a reference to an internal object (database ID, "
            "filename, etc.) without verifying that the requesting user has authorisation "
            "to access that object. An attacker can enumerate or modify other users' data."
        ),
        "impact": "Unauthorised data access, account takeover, mass data exposure.",
        "remediation": (
            "Implement object-level authorisation checks on every request. Use "
            "indirect references (UUIDs, hashed IDs) instead of sequential integers. "
            "Enforce row-level security at the database layer."
        ),
        "references": [
            "https://portswigger.net/web-security/access-control/idor",
        ],
    },
    "GraphQL": {
        "cvss":        5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe":         "CWE-200",
        "owasp":       "A05:2021 – Security Misconfiguration",
        "title":       "GraphQL Introspection Enabled",
        "description": (
            "The GraphQL endpoint has introspection enabled in a production environment. "
            "This exposes the complete API schema including all types, fields, queries, "
            "and mutations to unauthenticated attackers, significantly aiding reconnaissance."
        ),
        "impact": "Full schema disclosure, enabling targeted attacks on hidden endpoints.",
        "remediation": (
            "Disable introspection in production. If needed for development, "
            "restrict it to authenticated internal users only."
        ),
        "references": [
            "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/",
        ],
    },
    "Secret": {
        "cvss":        9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe":         "CWE-798",
        "owasp":       "A02:2021 – Cryptographic Failures",
        "title":       "Hardcoded Secret / API Key",
        "description": (
            "A secret credential (API key, token, password, or private key) was "
            "discovered in publicly accessible JavaScript, HTML, or configuration files. "
            "This allows an attacker to authenticate as the service or user associated "
            "with the credential."
        ),
        "impact": "Unauthorised API access, account compromise, data breach.",
        "remediation": (
            "Immediately rotate all exposed credentials. Store secrets in environment "
            "variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). "
            "Scan all commits for secrets using trufflehog or gitleaks pre-commit hooks."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ],
    },
}

# CVSS score → risk rating
def _risk_rating(cvss: float) -> Tuple[str, str]:
    if cvss >= 9.0:  return "Critical", "#e74c3c"
    if cvss >= 7.0:  return "High",     "#e67e22"
    if cvss >= 4.0:  return "Medium",   "#f39c12"
    if cvss >= 0.1:  return "Low",      "#3498db"
    return "Informational", "#95a5a6"


# -----------------------------------------------------------------
#  POC GENERATOR
# -----------------------------------------------------------------

def _generate_poc(hit: Dict) -> str:
    """Generate a copy-paste curl PoC command for a finding."""
    check   = hit.get("check", "")
    url     = hit.get("url", "")
    param   = hit.get("param", "")
    payload = str(hit.get("payload", ""))
    evidence = hit.get("evidence", "")

    # Build fuzz URL
    if param and payload:
        sep = "&" if "?" in url else "?"
        fuzz_url = f"{url}{sep}{quote(param)}={quote(payload)}"
    else:
        fuzz_url = url

    if check == "SQLi":
        grep_pat = "error\\|syntax\\|mysql\\|pg_query\\|ora-"
        return (
            f'# SQLi — time-based check\n'
            f'curl -s -o /dev/null -w "%{{time_total}}" \\\n'
            f'  "{fuzz_url}"\n\n'
            f'# SQLi — error-based check\n'
            f'curl -s "{fuzz_url}" | grep -i "{grep_pat}"'
        )
    elif check == "XSS":
        marker = payload[:20].replace('"', '\\"')
        return (
            f'# XSS — check for reflected payload\n'
            f'curl -s "{fuzz_url}" | grep -F "{marker}"'
        )
    elif check == "SSRF":
        return (
            f'# SSRF — check for metadata access\n'
            f'# Replace with your interactsh/Burp Collaborator domain\n'
            f'curl -s "{fuzz_url}" | grep -i "ami-id\\|instance-id\\|hostname"'
        )
    elif check == "PathTraversal":
        return (
            f'# Path Traversal — check for file content\n'
            f'curl -s "{fuzz_url}" | grep -i "root:\\|\\[boot loader\\]"'
        )
    elif check == "CORS":
        origin = "https://evil.attacker.com"
        return (
            f'# CORS — check reflected origin and credentials\n'
            f'curl -s -I -H "Origin: {origin}" "{url}" \\\n'
            f'  | grep -i "access-control"'
        )
    elif check == "OpenRedirect":
        return (
            f'# Open Redirect — check Location header\n'
            f'curl -s -I "{fuzz_url}" | grep -i "location:"'
        )
    elif check == "IDOR":
        return (
            f'# IDOR — compare responses for different IDs\n'
            f'curl -s "{fuzz_url}" > /tmp/resp_a.txt\n'
            f'# Change the ID and compare:\n'
            f'# curl -s "...?{param}=2" > /tmp/resp_b.txt\n'
            f'# diff /tmp/resp_a.txt /tmp/resp_b.txt'
        )
    elif check == "GraphQL":
        gql_query = '{"query":"{__schema{types{name}}}"}'
        return (
            f'# GraphQL introspection\n'
            f'curl -s -X POST "{url}" \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            f"  -d '{gql_query}' \\\n"
            f'  | python3 -m json.tool | head -50'
        )
    elif check in ("Secret", "secret"):
        val = str(hit.get("value", ""))[:20]
        return (
            f'# Secret found — verify it is valid\n'
            f'# Value (truncated): {val}...\n'
            f'# Source: {hit.get("source", url)}\n'
            f'curl -s "{hit.get("source", url)}" | grep -o "[A-Za-z0-9_\\-]{{20,}}"'
        )
    else:
        return f'curl -s "{fuzz_url}"'


# -----------------------------------------------------------------
#  NUCLEI TEMPLATE GENERATOR
# -----------------------------------------------------------------

def _slugify(s: str) -> str:
    import re
    return re.sub(r"[^a-z0-9-]", "-", s.lower())[:40].strip("-")


def generate_nuclei_template(hit: Dict) -> str:
    """Generate a Nuclei YAML template for a finding."""
    check   = hit.get("check", "vuln")
    param   = hit.get("param", "param")
    url     = hit.get("url", "")
    payload = str(hit.get("payload", ""))
    evidence = str(hit.get("evidence", ""))[:50]
    severity = hit.get("severity", "medium").lower()
    cwe      = hit.get("cwe", "")
    vuln     = VULN_DB.get(check, {})

    template_id = f"paramspecter-{_slugify(check)}-{_slugify(param)}"
    parsed      = urlparse(url)
    path        = parsed.path or "/"
    sep         = "&" if "?" in url else "?"

    matcher_word = evidence if evidence else payload[:30]

    return f"""id: {template_id}

info:
  name: "{vuln.get('title', check)} in parameter '{param}'"
  author: paramspecter
  severity: {severity}
  description: |
    {vuln.get('description', f'{check} vulnerability detected by ParamSpecter')[:200]}
  reference:
    - {vuln.get('references', ['https://owasp.org'])[0]}
  tags: {_slugify(check)},paramspecter,automated
  metadata:
    cwe-id: {cwe}
    cvss-score: {vuln.get('cvss', 0)}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}{sep}{quote(param)}={quote(payload)}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{matcher_word}"
        condition: or

      - type: status
        status:
          - 200
"""


# -----------------------------------------------------------------
#  HTML REPORT
# -----------------------------------------------------------------
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f1117; color: #e0e0e0; line-height: 1.6;
}
.page { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
h1 { font-size: 2rem; color: #fff; margin-bottom: 4px; }
h2 { font-size: 1.3rem; color: #3498db; margin: 32px 0 12px; border-bottom: 1px solid #1e2535; padding-bottom: 8px; }
h3 { font-size: 1rem; color: #ecf0f1; margin: 16px 0 6px; }
p  { color: #b0b8c4; margin: 6px 0; }
a  { color: #3498db; }
.subtitle { color: #7f8c8d; font-size: 0.9rem; margin-bottom: 32px; }
.exec-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin: 20px 0 32px; }
.stat-card { background: #1a1f2e; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #2a3045; }
.stat-card .val { font-size: 2.2rem; font-weight: 700; }
.stat-card .lbl { font-size: 0.8rem; color: #7f8c8d; margin-top: 4px; }
.crit  { color: #e74c3c; }
.high  { color: #e67e22; }
.med   { color: #f39c12; }
.low   { color: #3498db; }
.info  { color: #95a5a6; }
.finding {
    background: #1a1f2e; border-radius: 10px; padding: 24px;
    margin: 16px 0; border-left: 4px solid #3498db;
    border: 1px solid #2a3045;
}
.finding.critical { border-left-color: #e74c3c; }
.finding.high     { border-left-color: #e67e22; }
.finding.medium   { border-left-color: #f39c12; }
.finding.low      { border-left-color: #3498db; }
.finding-header   { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.badge {
    padding: 3px 10px; border-radius: 20px; font-size: 0.75rem;
    font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;
}
.badge.critical { background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }
.badge.high     { background: #e67e2222; color: #e67e22; border: 1px solid #e67e2244; }
.badge.medium   { background: #f39c1222; color: #f39c12; border: 1px solid #f39c1244; }
.badge.low      { background: #3498db22; color: #3498db; border: 1px solid #3498db44; }
.cvss-score { font-size: 1.5rem; font-weight: 700; }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 12px 0; }
.meta-item { background: #0f1117; border-radius: 6px; padding: 10px 14px; }
.meta-item .key { font-size: 0.75rem; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; }
.meta-item .val { font-size: 0.9rem; color: #ecf0f1; margin-top: 2px; word-break: break-all; }
.section-label { font-size: 0.75rem; color: #7f8c8d; text-transform: uppercase; letter-spacing: 0.5px; margin: 14px 0 6px; }
.description, .impact, .remediation { color: #b0b8c4; font-size: 0.92rem; margin: 6px 0 12px; }
.poc { background: #0a0d14; border-radius: 6px; padding: 14px; font-family: 'Fira Code', 'Consolas', monospace; font-size: 0.82rem; color: #a8d8a8; overflow-x: auto; white-space: pre; border: 1px solid #1e2535; }
.refs a { display: inline-block; margin-right: 16px; margin-top: 4px; font-size: 0.85rem; }
.toc { background: #1a1f2e; border-radius: 10px; padding: 20px 24px; margin: 20px 0 32px; border: 1px solid #2a3045; }
.toc li { margin: 4px 0; padding-left: 8px; }
.risk-bar { height: 6px; border-radius: 3px; margin: 8px 0 16px; }
.no-findings { color: #7f8c8d; font-style: italic; padding: 16px 0; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.88rem; }
th { background: #0f1117; color: #7f8c8d; text-align: left; padding: 8px 12px; font-weight: 600; }
td { padding: 8px 12px; border-top: 1px solid #1e2535; word-break: break-all; }
tr:hover td { background: #1e2535; }
.confidence-bar { display: inline-block; height: 8px; border-radius: 4px; vertical-align: middle; margin-left: 8px; }
"""


def _esc(s) -> str:
    return html.escape(str(s))


def _severity_class(s: str) -> str:
    return {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(s.upper(), "low")


def _cvss_color(score: float) -> str:
    if score >= 9: return "#e74c3c"
    if score >= 7: return "#e67e22"
    if score >= 4: return "#f39c12"
    return "#3498db"


def _build_html_report(scanner, ai_triage_text: str = "") -> str:
    ts     = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    target = scanner.start_url
    domain = urlparse(target).netloc

    # Gather all findings
    param_hits  = scanner.param_hits  or []
    dir_hits    = scanner.dir_hits    or []
    secrets     = scanner.all_secrets or []

    # Counts by severity
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in param_hits:
        sev_counts[h.get("severity", "LOW")] = sev_counts.get(h.get("severity","LOW"), 0) + 1
    for s in secrets:
        sev_counts["HIGH"] += 1

    risk, risk_color = _risk_rating(max(
        VULN_DB.get(h.get("check",""), {}).get("cvss", 0) for h in param_hits
    ) if param_hits else 0.0)

    # ── Executive Summary ─────────────────────────────────────────
    exec_summary_cards = f"""
    <div class="exec-grid">
      <div class="stat-card"><div class="val" style="color:{risk_color}">{risk}</div><div class="lbl">Overall Risk</div></div>
      <div class="stat-card"><div class="val crit">{sev_counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
      <div class="stat-card"><div class="val high">{sev_counts['HIGH']}</div><div class="lbl">High</div></div>
      <div class="stat-card"><div class="val med">{sev_counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
      <div class="stat-card"><div class="val low">{sev_counts['LOW']}</div><div class="lbl">Low</div></div>
      <div class="stat-card"><div class="val">{scanner.stats.pages_crawled}</div><div class="lbl">Pages Crawled</div></div>
      <div class="stat-card"><div class="val">{len(scanner.all_params)}</div><div class="lbl">Parameters</div></div>
      <div class="stat-card"><div class="val">{len(secrets)}</div><div class="lbl">Secrets Found</div></div>
    </div>
    """

    # ── Finding Cards ─────────────────────────────────────────────
    finding_cards = ""
    sorted_hits   = sorted(
        param_hits,
        key=lambda h: VULN_DB.get(h.get("check",""), {}).get("cvss", 0),
        reverse=True,
    )

    for i, hit in enumerate(sorted_hits, 1):
        check   = hit.get("check", "?")
        vuln    = VULN_DB.get(check, {})
        cvss    = vuln.get("cvss", 0.0)
        sev     = hit.get("severity", "LOW")
        conf    = hit.get("confidence", 50)
        sev_cls = _severity_class(sev)
        rating, rcolor = _risk_rating(cvss)
        poc     = _generate_poc(hit)
        refs    = vuln.get("references", [])

        conf_bar = f'<div class="confidence-bar" style="width:{conf}px;max-width:100px;background:{"#2ecc71" if conf>=70 else "#f39c12" if conf>=40 else "#e74c3c"}"></div>'

        finding_cards += f"""
        <div class="finding {sev_cls}" id="finding-{i}">
          <div class="finding-header">
            <span class="badge {sev_cls}">{_esc(sev)}</span>
            <span class="cvss-score" style="color:{_cvss_color(cvss)}">{cvss}</span>
            <strong style="font-size:1.05rem">{_esc(vuln.get('title', check))}</strong>
          </div>

          <div class="meta-grid">
            <div class="meta-item"><div class="key">Parameter</div><div class="val">{_esc(hit.get('param','?'))}</div></div>
            <div class="meta-item"><div class="key">URL</div><div class="val">{_esc(hit.get('url','?'))}</div></div>
            <div class="meta-item"><div class="key">CWE</div><div class="val">{_esc(vuln.get('cwe', hit.get('cwe','?')))}</div></div>
            <div class="meta-item"><div class="key">OWASP</div><div class="val">{_esc(vuln.get('owasp','?'))}</div></div>
            <div class="meta-item"><div class="key">CVSS Vector</div><div class="val" style="font-size:0.78rem">{_esc(vuln.get('cvss_vector','?'))}</div></div>
            <div class="meta-item"><div class="key">Confidence</div><div class="val">{conf}% {conf_bar}</div></div>
          </div>

          <div class="section-label">Description</div>
          <div class="description">{_esc(vuln.get('description', hit.get('evidence','?')))}</div>

          <div class="section-label">Impact</div>
          <div class="impact">{_esc(vuln.get('impact','?'))}</div>

          <div class="section-label">Evidence</div>
          <div class="description">{_esc(str(hit.get('evidence',''))[:300])}</div>

          <div class="section-label">Proof of Concept</div>
          <pre class="poc">{_esc(poc)}</pre>

          <div class="section-label">Remediation</div>
          <div class="remediation">{_esc(vuln.get('remediation','Apply security best practices.'))}</div>

          {'<div class="section-label">References</div><div class="refs">' + "".join(f'<a href="{_esc(r)}" target="_blank">{_esc(r)}</a>' for r in refs) + '</div>' if refs else ''}
        </div>
        """

    # ── Secrets Section ───────────────────────────────────────────
    secret_rows = ""
    for s in secrets[:30]:
        stype = _esc(s.get("type", "?"))
        val   = _esc(s.get("value", "")[:40])
        src   = _esc(s.get("source", "?"))
        secret_rows += f"<tr><td>{stype}</td><td><code>{val}...</code></td><td>{src}</td></tr>"

    secrets_section = f"""
    <h2>Secrets & Credentials</h2>
    {"<table><thead><tr><th>Type</th><th>Value (truncated)</th><th>Source</th></tr></thead><tbody>" + secret_rows + "</tbody></table>" if secrets else '<p class="no-findings">No secrets discovered.</p>'}
    """

    # ── Missing Headers ───────────────────────────────────────────
    hdr_rows = "".join(
        f"<tr><td>{_esc(h)}</td><td>{c} page(s)</td></tr>"
        for h, c in sorted(scanner.missing_sec_headers.items(), key=lambda x: -x[1])
    ) if scanner.missing_sec_headers else ""

    headers_section = f"""
    <h2>Missing Security Headers</h2>
    {"<table><thead><tr><th>Header</th><th>Affected Pages</th></tr></thead><tbody>" + hdr_rows + "</tbody></table>" if hdr_rows else '<p class="no-findings">All checked headers present.</p>'}
    """

    # ── AI Triage Section ─────────────────────────────────────────
    ai_section = ""
    if ai_triage_text:
        ai_lines = []
        for line in ai_triage_text.splitlines():
            s = line.strip()
            if s.startswith("#"):
                ai_lines.append(f"<h3>{_esc(s.lstrip('#').strip())}</h3>")
            elif s.startswith("- ") or s.startswith("* "):
                ai_lines.append(f"<li>{_esc(s[2:])}</li>")
            elif s == "":
                ai_lines.append("<br>")
            else:
                ai_lines.append(f"<p>{_esc(line)}</p>")
        ai_section = f"""
        <h2>🧠 AI Triage Analysis</h2>
        <div style="background:#1a1f2e;border-radius:10px;padding:24px;border:1px solid #2a3045">
            {"".join(ai_lines)}
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ParamSpecter Report — {_esc(domain)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="page">

  <h1>Security Assessment Report</h1>
  <div class="subtitle">
    Target: <strong>{_esc(target)}</strong> &nbsp;|&nbsp;
    Generated: {ts} &nbsp;|&nbsp;
    Tool: ParamSpecter v7.2
  </div>

  <h2>Executive Summary</h2>
  {exec_summary_cards}
  <p>
    This report documents the security findings identified during an automated
    reconnaissance and vulnerability scan of <strong>{_esc(target)}</strong>.
    The assessment identified <strong>{len(param_hits)}</strong> parameter-level
    vulnerability candidates and <strong>{len(secrets)}</strong> exposed secrets
    across <strong>{scanner.stats.pages_crawled}</strong> crawled pages.
    Technologies detected: <strong>{_esc(", ".join(scanner.all_techs) or "unknown")}</strong>.
  </p>

  <h2>Findings ({len(param_hits)} total)</h2>
  {finding_cards if finding_cards else '<p class="no-findings">No parameter-level findings. Run with --deep-fuzz for active vulnerability detection.</p>'}

  {secrets_section}
  {headers_section}
  {ai_section}

  <h2>Scan Statistics</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Target</td><td>{_esc(target)}</td></tr>
    <tr><td>Mode</td><td>{_esc(scanner.mode)}</td></tr>
    <tr><td>Duration</td><td>{scanner.stats.elapsed()}</td></tr>
    <tr><td>Pages Crawled</td><td>{scanner.stats.pages_crawled}</td></tr>
    <tr><td>Total Requests</td><td>{scanner.stats.requests_sent}</td></tr>
    <tr><td>Links Found</td><td>{scanner.stats.links_found}</td></tr>
    <tr><td>Technologies</td><td>{_esc(", ".join(scanner.all_techs) or "none detected")}</td></tr>
    <tr><td>WAF Detected</td><td>{_esc(", ".join(scanner.all_wafs) or "none")}</td></tr>
  </table>

  <p style="color:#3d4a5c;font-size:0.8rem;margin-top:40px;text-align:center">
    Generated by ParamSpecter v7.2 — For authorized security testing only
  </p>
</div>
</body>
</html>"""


# -----------------------------------------------------------------
#  PUBLIC ENTRY POINT
# -----------------------------------------------------------------

def build_pro_report(scanner, output_dir: str = ".",
                     ai_triage_text: str = "") -> str:
    """
    Generate the professional HTML report and nuclei templates.
    Returns the path to the HTML report file.
    """
    ts     = time.strftime("%Y%m%d_%H%M%S")
    domain = urlparse(scanner.start_url).netloc.replace(".", "_")
    pfx    = f"paramspecter_{domain}_{ts}"

    # HTML report
    html_path = os.path.join(output_dir, f"{pfx}_pro_report.html")
    tmp_path  = html_path + ".tmp"
    html_content = _build_html_report(scanner, ai_triage_text)
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    os.replace(tmp_path, html_path)
    log("REPORT", col(f"Pro report → {html_path}", C.GREEN), C.GREEN)

    # Nuclei templates
    if scanner.param_hits:
        nuc_dir = os.path.join(output_dir, f"{pfx}_nuclei_templates")
        os.makedirs(nuc_dir, exist_ok=True)
        for hit in scanner.param_hits:
            check = hit.get("check", "vuln")
            param = hit.get("param", "param")
            fname = f"{_slugify(check)}-{_slugify(param)}.yaml"
            fpath = os.path.join(nuc_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(generate_nuclei_template(hit))
        log("REPORT", col(
            f"Nuclei templates → {nuc_dir}/ ({len(scanner.param_hits)} templates)",
            C.GREEN), C.GREEN)

    return html_path
