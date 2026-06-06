"""
output/nuclei_gen.py
Standalone Nuclei YAML template generator.

Generates production-quality Nuclei templates from ParamSpecter findings.
Templates are saved to a directory and can be run immediately with:
    nuclei -t ./paramspecter_templates/ -u https://target.com

Template types generated:
  - Vulnerability templates (SQLi, XSS, SSRF, etc.) from param_hits
  - Secret detection templates from discovered secrets
  - Directory/path templates from dir_hits
  - Technology fingerprint templates from detected techs
  - Missing header templates from security header gaps

Each template includes:
  - Proper CVSS metadata
  - Evidence-based matchers (not just generic patterns)
  - Tags for easy filtering
  - Reference links
"""

import os
import re
import time
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse

from ..utils import log, col, C


# -----------------------------------------------------------------
#  HELPERS
# -----------------------------------------------------------------

def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", str(s).lower())[:40].strip("-")


def _yaml_str(s: str) -> str:
    """Safely quote a string for YAML."""
    s = str(s).replace('"', '\\"').replace("\n", " ").replace("\r", "")
    return f'"{s}"'


# Severity map
_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "info",
}

# CVSS scores per check type
_CVSS = {
    "SQLi":            9.8,
    "XSS":             6.1,
    "SSRF":            9.0,
    "PathTraversal":   7.5,
    "CORS":            8.1,
    "OpenRedirect":    6.1,
    "HeaderInjection": 6.5,
    "IDOR":            8.1,
    "GraphQL":         5.3,
}


# -----------------------------------------------------------------
#  TEMPLATE GENERATORS
# -----------------------------------------------------------------

def vuln_template(hit: Dict) -> str:
    """Generate a vulnerability detection template from a param hit."""
    check    = hit.get("check", "vuln")
    param    = hit.get("param", "param")
    url      = hit.get("url", "")
    payload  = str(hit.get("payload", ""))
    evidence = str(hit.get("evidence", ""))
    sev      = _SEV_MAP.get(hit.get("severity", "HIGH"), "high")
    cwe      = hit.get("cwe", "CWE-0")
    conf     = hit.get("confidence", 50)
    cvss     = _CVSS.get(check, 6.0)

    template_id = f"paramspecter-{_slugify(check)}-{_slugify(param)}-{int(time.time()) % 10000}"
    parsed      = urlparse(url)
    path        = parsed.path or "/"
    sep         = "&" if "?" in url else "?"

    # Build evidence-based matcher
    matcher_word = ""
    if evidence:
        # Extract a short unique string from evidence
        m = re.search(r'«([^»]{5,50})»', evidence)
        if m:
            matcher_word = m.group(1)
        else:
            matcher_word = evidence[:40]

    # Build check-specific matchers
    if check == "SQLi":
        matchers = """    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "sql syntax"
          - "syntax error"
          - "mysql_fetch"
          - "ORA-"
          - "pg_query"
          - "SQLite"
          - "Microsoft OLE DB"
          - "JDBC"
        condition: or

      - type: dsl
        dsl:
          - "duration>=3"
        name: time-based"""

    elif check == "XSS":
        marker = payload[:30].replace('"', '\\"')
        matchers = f"""    matchers:
      - type: word
        part: body
        words:
          - {_yaml_str(marker)}

      - type: status
        status:
          - 200"""

    elif check == "SSRF":
        matchers = """    matchers:
      - type: word
        part: body
        words:
          - "ami-id"
          - "instance-id"
          - "iam/security-credentials"
          - "computeMetadata"
        condition: or"""

    elif check == "PathTraversal":
        matchers = """    matchers:
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
          - "\\[boot loader\\]"
          - "\\[extensions\\]"
        condition: or"""

    elif check == "CORS":
        matchers = """    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.attacker.com"

      - type: status
        status:
          - 200"""

    elif check == "OpenRedirect":
        matchers = """    matchers:
      - type: word
        part: header
        words:
          - "Location: https://evil.attacker.com"
          - "Location: //evil.attacker.com"
        condition: or"""

    elif check == "GraphQL":
        matchers = """    matchers:
      - type: word
        part: body
        words:
          - "__schema"
          - "__types"
        condition: or"""

    else:
        evidence_word = _yaml_str(matcher_word[:50]) if matcher_word else '"error"'
        matchers = f"""    matchers:
      - type: word
        part: body
        words:
          - {evidence_word}"""

    # Build request section
    if check == "CORS":
        request_section = f"""  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"
    headers:
      Origin: "https://evil.attacker.com"

{matchers}"""
    elif check == "GraphQL":
        gql_body = '{"query":"{__schema{types{name}}}"}'
        request_section = f"""  - method: POST
    path:
      - "{{{{BaseURL}}}}{path}"
    headers:
      Content-Type: "application/json"
    body: '{gql_body}'

{matchers}"""
    else:
        fuzz_path = f"{path}{sep}{quote(param)}={quote(payload)}"
        request_section = f"""  - method: GET
    path:
      - "{{{{BaseURL}}}}{fuzz_path}"

{matchers}"""

    return f"""id: {template_id}

info:
  name: {_yaml_str(f"{check} in parameter '{param}'")}
  author: paramspecter
  severity: {sev}
  description: |
    ParamSpecter detected a potential {check} vulnerability in the '{param}' parameter.
    Evidence: {evidence[:100] if evidence else 'See payload'}
  metadata:
    verified: false
    confidence: {conf}%
    cvss-score: {cvss}
    cwe-id: {cwe}
    max-request: 1
  tags: paramspecter,{_slugify(check)},automated

http:
{request_section}
"""


def secret_template(secret: Dict, base_url: str) -> str:
    """Generate a secret detection template."""
    stype   = secret.get("type", "secret")
    value   = secret.get("value", "")
    source  = secret.get("source", base_url)
    parsed  = urlparse(source)
    path    = parsed.path or "/"

    # Build a regex from the secret value (first 10 chars as anchor)
    anchor  = re.escape(value[:10]) if len(value) >= 10 else re.escape(value)
    tid     = f"paramspecter-secret-{_slugify(stype)}-{int(time.time()) % 10000}"

    return f"""id: {tid}

info:
  name: {_yaml_str(f"Exposed Secret: {stype}")}
  author: paramspecter
  severity: high
  description: |
    A {stype} credential was discovered in a publicly accessible file.
    Source: {source}
  metadata:
    cwe-id: CWE-798
    cvss-score: 9.1
  tags: paramspecter,secret,exposure,{_slugify(stype)}

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"

    matchers:
      - type: regex
        part: body
        regex:
          - "{anchor}"
"""


def dir_hit_template(hit: Dict) -> str:
    """Generate a path discovery template from a dir hit."""
    url    = hit.get("url", "")
    status = hit.get("status", 200)
    parsed = urlparse(url)
    path   = parsed.path or "/"
    tid    = f"paramspecter-path-{_slugify(path)}-{int(time.time()) % 10000}"

    return f"""id: {tid}

info:
  name: {_yaml_str(f"Exposed Path: {path}")}
  author: paramspecter
  severity: {"high" if status == 200 else "info"}
  description: |
    ParamSpecter discovered an accessible path during directory enumeration.
    Path: {path}
    Status: {status}
  tags: paramspecter,exposure,directory

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"

    matchers:
      - type: status
        status:
          - {status}
"""


def missing_header_template(header: str, base_url: str) -> str:
    """Generate a missing security header detection template."""
    parsed = urlparse(base_url)
    tid    = f"paramspecter-missing-header-{_slugify(header)}"

    return f"""id: {tid}

info:
  name: {_yaml_str(f"Missing Security Header: {header}")}
  author: paramspecter
  severity: low
  description: |
    The '{header}' security header is missing from the response.
  reference:
    - https://owasp.org/www-project-secure-headers/
  tags: paramspecter,headers,misconfiguration

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/"

    matchers:
      - type: dsl
        dsl:
          - "!contains(tolower(all_headers), '{header.lower()}')"
"""


# -----------------------------------------------------------------
#  MAIN GENERATOR
# -----------------------------------------------------------------

class NucleiTemplateGenerator:
    """
    Generates a full set of Nuclei templates from scanner results.
    """

    def __init__(self, scanner, output_dir: str = "."):
        self.scanner    = scanner
        self.output_dir = output_dir

    def generate_all(self) -> str:
        """
        Generate templates for all finding types.
        Returns path to the templates directory.
        """
        ts       = time.strftime("%Y%m%d_%H%M%S")
        domain   = urlparse(self.scanner.start_url).netloc.replace(".", "_")
        out_dir  = os.path.join(self.output_dir, f"paramspecter_{domain}_{ts}_nuclei_templates")
        os.makedirs(out_dir, exist_ok=True)

        counts = {
            "vuln":    0,
            "secret":  0,
            "path":    0,
            "header":  0,
        }

        # Vulnerability templates
        vuln_dir = os.path.join(out_dir, "vulnerabilities")
        os.makedirs(vuln_dir, exist_ok=True)
        seen_hits: set = set()
        for hit in self.scanner.param_hits:
            key = (hit.get("check",""), hit.get("param",""), str(hit.get("payload",""))[:20])
            if key in seen_hits:
                continue
            seen_hits.add(key)
            fname = f"{_slugify(hit.get('check','vuln'))}-{_slugify(hit.get('param','p'))}.yaml"
            fpath = os.path.join(vuln_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(vuln_template(hit))
            counts["vuln"] += 1

        # Secret templates
        secret_dir = os.path.join(out_dir, "secrets")
        os.makedirs(secret_dir, exist_ok=True)
        seen_secrets: set = set()
        for s in self.scanner.all_secrets:
            key = (s.get("type",""), s.get("value","")[:20])
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            fname = f"secret-{_slugify(s.get('type','?'))}.yaml"
            fpath = os.path.join(secret_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(secret_template(s, self.scanner.start_url))
            counts["secret"] += 1

        # Directory/path templates
        path_dir = os.path.join(out_dir, "paths")
        os.makedirs(path_dir, exist_ok=True)
        for hit in self.scanner.dir_hits:
            if hit.get("status", 999) < 400:
                p     = urlparse(hit.get("url","")).path or "/"
                fname = f"path-{_slugify(p)}.yaml"
                fpath = os.path.join(path_dir, fname)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(dir_hit_template(hit))
                counts["path"] += 1

        # Missing header templates
        header_dir = os.path.join(out_dir, "headers")
        os.makedirs(header_dir, exist_ok=True)
        for header in self.scanner.missing_sec_headers:
            fname = f"missing-{_slugify(header)}.yaml"
            fpath = os.path.join(header_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(missing_header_template(header, self.scanner.start_url))
            counts["header"] += 1

        # Write a run script
        run_script = os.path.join(out_dir, "run.sh")
        with open(run_script, "w", encoding="utf-8") as f:
            f.write(f"""#!/bin/bash
# Auto-generated by ParamSpecter v7.3
# Run all templates against the target

TARGET="{self.scanner.start_url}"
TEMPLATES_DIR="$(dirname "$0")"

echo "[*] Running ParamSpecter nuclei templates against $TARGET"
echo "[*] Templates: {sum(counts.values())} total"
echo ""

nuclei -t "$TEMPLATES_DIR/vulnerabilities/" -u "$TARGET" -severity critical,high,medium &
nuclei -t "$TEMPLATES_DIR/secrets/" -u "$TARGET" &
nuclei -t "$TEMPLATES_DIR/paths/" -u "$TARGET" -severity high,medium &
nuclei -t "$TEMPLATES_DIR/headers/" -u "$TARGET" -severity low &

wait
echo "[*] Done."
""")
        try:
            os.chmod(run_script, 0o755)
        except Exception:
            pass

        total = sum(counts.values())
        log("NUCLEI", col(
            f"Generated {total} Nuclei templates → {out_dir}/\n"
            f"  Vuln: {counts['vuln']}  Secret: {counts['secret']}  "
            f"Path: {counts['path']}  Header: {counts['header']}",
            C.GREEN), C.GREEN)
        log("NUCLEI", col(
            f"Run with: nuclei -t {out_dir}/ -u {self.scanner.start_url}",
            C.CYAN), C.CYAN)

        return out_dir
