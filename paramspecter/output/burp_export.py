"""
output/burp_export.py
Export scan results as Burp Suite XML.

The exported file can be imported directly into Burp Suite via:
  Proxy → HTTP History → right-click → "Import from file"
  OR
  Target → Site Map → right-click → "Import from file"

Each crawled page, param hit, and dir hit becomes a Burp item
with full request/response representation so you can replay
and investigate directly in Burp.
"""

import base64
import os
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlencode, quote

from ..utils import log, col, C


# ─────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────

def _b64(s: str) -> str:
    """Base64-encode a string for Burp's base64Request/Response fields."""
    return base64.b64encode(s.encode("utf-8", errors="replace")).decode()


def _esc(s: str) -> str:
    """XML-escape a string."""
    return (str(s)
            .replace("&",  "&amp;")
            .replace("<",  "&lt;")
            .replace(">",  "&gt;")
            .replace('"',  "&quot;")
            .replace("'",  "&apos;"))


def _build_request(url: str, method: str = "GET",
                   headers: Dict[str, str] = None,
                   body: str = "") -> str:
    """Build a raw HTTP request string."""
    parsed   = urlparse(url)
    path     = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host     = parsed.netloc
    hdrs     = {
        "Host":            host,
        "User-Agent":      "ParamSpecter/7.0",
        "Accept":          "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection":      "close",
    }
    if headers:
        hdrs.update(headers)
    if body:
        hdrs["Content-Length"] = str(len(body.encode()))

    header_lines = "\r\n".join(f"{k}: {v}" for k, v in hdrs.items())
    req = f"{method} {path} HTTP/1.1\r\n{header_lines}\r\n\r\n"
    if body:
        req += body
    return req


def _build_response(status: int, body: str = "",
                    content_type: str = "text/html") -> str:
    """Build a synthetic HTTP response string."""
    status_text = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed",
        500: "Internal Server Error", 503: "Service Unavailable",
    }.get(status, "Unknown")

    body_bytes  = body.encode("utf-8", errors="replace")
    headers     = (
        f"HTTP/1.1 {status} {status_text}\r\n"
        f"Content-Type: {content_type}; charset=utf-8\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"X-ParamSpecter: exported\r\n"
        f"\r\n"
    )
    return headers + body


# ─────────────────────────────────────────────────────────────────
#  MAIN EXPORT FUNCTION
# ─────────────────────────────────────────────────────────────────

def export_burp_xml(scanner, output_path: str) -> str:
    """
    Generate a Burp Suite-compatible XML file from all scan results.

    Includes:
    - All crawled pages (with status, title, params)
    - All param hits (fuzz findings)
    - All directory hits
    - All subdomain hits (as site map entries)

    Returns the path to the written file.
    """
    items: List[Dict] = []

    # ── 1. Crawled pages ──────────────────────────────────────────
    for page in scanner.results:
        url    = page.get("url", "")
        status = page.get("status") or 200
        title  = page.get("title", "")
        params = page.get("params", [])

        if not url:
            continue

        # Build a realistic-looking request
        req = _build_request(url)
        # Synthetic response — we have status + title but not the full body
        resp_body = f"<html><head><title>{_esc(title)}</title></head><body><!-- crawled by ParamSpecter --></body></html>"
        resp = _build_response(status, resp_body)

        items.append({
            "url":       url,
            "host":      urlparse(url).netloc,
            "port":      _port(url),
            "protocol":  urlparse(url).scheme,
            "method":    "GET",
            "path":      urlparse(url).path or "/",
            "status":    status,
            "request":   req,
            "response":  resp,
            "highlight": None,
            "comment":   f"Crawled — title: {title[:80]}" + (f" | params: {','.join(params)}" if params else ""),
            "mimetype":  page.get("mime", "text/html"),
        })

    # ── 2. Param hits (fuzz findings) ─────────────────────────────
    SEV_HIGHLIGHT = {
        "CRITICAL": "red",
        "HIGH":     "red",
        "MEDIUM":   "orange",
        "LOW":      "yellow",
        "INFO":     None,
    }
    for hit in scanner.param_hits:
        url     = hit.get("url", "")
        param   = hit.get("param", "")
        payload = hit.get("payload", "")
        check   = hit.get("check", "?")
        sev     = hit.get("severity", "HIGH")
        cwe     = hit.get("cwe", "")
        status  = hit.get("status") or 200

        if not url:
            continue

        # Build request with the fuzz payload injected
        fuzz_url = url
        if "?" in url:
            fuzz_url = url + f"&{quote(param)}={quote(str(payload))}"
        else:
            fuzz_url = url + f"?{quote(param)}={quote(str(payload))}"

        req  = _build_request(fuzz_url)
        resp = _build_response(status, f"<!-- {check} finding -->")

        items.append({
            "url":       fuzz_url,
            "host":      urlparse(url).netloc,
            "port":      _port(url),
            "protocol":  urlparse(url).scheme,
            "method":    "GET",
            "path":      urlparse(fuzz_url).path or "/",
            "status":    status,
            "request":   req,
            "response":  resp,
            "highlight": SEV_HIGHLIGHT.get(sev),
            "comment":   f"[{check}] [{sev}] {cwe} param={param} payload={str(payload)[:60]}",
            "mimetype":  "text/html",
        })

    # ── 3. Directory / file hits ──────────────────────────────────
    for hit in scanner.dir_hits:
        url    = hit.get("url", "")
        status = hit.get("status") or 200
        size   = hit.get("size", 0)

        if not url:
            continue

        req  = _build_request(url)
        resp = _build_response(status, f"<!-- dir hit — {size} bytes -->")

        items.append({
            "url":       url,
            "host":      urlparse(url).netloc,
            "port":      _port(url),
            "protocol":  urlparse(url).scheme,
            "method":    "GET",
            "path":      urlparse(url).path or "/",
            "status":    status,
            "request":   req,
            "response":  resp,
            "highlight": "cyan" if status == 200 else None,
            "comment":   f"Dir hit — {status} — {size}B",
            "mimetype":  "text/html",
        })

    # ── 4. Subdomain hits ─────────────────────────────────────────
    for hit in scanner.subdomain_hits:
        sub    = hit.get("subdomain", "")
        status = hit.get("status") or 200
        ips    = ", ".join(hit.get("ips", []))

        if not sub:
            continue

        url  = f"https://{sub}/"
        req  = _build_request(url)
        resp = _build_response(status, f"<!-- subdomain: {sub} IPs: {ips} -->")

        items.append({
            "url":       url,
            "host":      sub,
            "port":      "443",
            "protocol":  "https",
            "method":    "GET",
            "path":      "/",
            "status":    status,
            "request":   req,
            "response":  resp,
            "highlight": None,
            "comment":   f"Subdomain — IPs: {ips}",
            "mimetype":  "text/html",
        })

    # ── Build XML ─────────────────────────────────────────────────
    root = ET.Element("items", burpVersion="2024.1", exportTime=time.strftime("%c"))

    for item in items:
        el = ET.SubElement(root, "item")

        ET.SubElement(el, "time").text        = time.strftime("%a %b %d %H:%M:%S UTC %Y")
        ET.SubElement(el, "url").text         = _esc(item["url"])
        ET.SubElement(el, "host",
                      ip=item.get("ip","")).text  = _esc(item["host"])
        ET.SubElement(el, "port").text        = str(item["port"])
        ET.SubElement(el, "protocol").text    = item["protocol"]
        ET.SubElement(el, "method").text      = item["method"]
        ET.SubElement(el, "path").text        = _esc(item["path"])
        ET.SubElement(el, "extension").text   = _ext(item["path"])
        ET.SubElement(el, "request",
                      base64="true").text     = _b64(item["request"])
        ET.SubElement(el, "status").text      = str(item["status"])
        ET.SubElement(el, "responselength").text = str(len(item["response"]))
        ET.SubElement(el, "mimetype").text    = item.get("mimetype","text/html")
        ET.SubElement(el, "response",
                      base64="true").text     = _b64(item["response"])
        ET.SubElement(el, "comment").text     = _esc(item.get("comment",""))

        if item.get("highlight"):
            ET.SubElement(el, "highlight").text = item["highlight"]

    # Write with indent
    _indent(root)
    tree = ET.ElementTree(root)

    tmp = output_path + ".tmp"
    try:
        tree.write(tmp, encoding="utf-8", xml_declaration=True)
        os.replace(tmp, output_path)
        log("BURP", f"Burp XML → {col(output_path, C.CYAN)}  ({len(items)} items)", C.GREEN)
    except Exception as e:
        log("BURP", col(f"Burp XML export failed: {e}", C.RED), C.RED)

    return output_path


# ─────────────────────────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────────────────────────

def _port(url: str) -> str:
    parsed = urlparse(url)
    if parsed.port:
        return str(parsed.port)
    return "443" if parsed.scheme == "https" else "80"


def _ext(path: str) -> str:
    """Extract file extension from path for Burp's extension field."""
    if "." in path.split("/")[-1]:
        return path.rsplit(".", 1)[-1].lower()
    return ""


def _indent(elem, level=0):
    """Add pretty-print indentation to XML tree in-place."""
    indent = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = indent + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = indent
        for child in elem:
            _indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = indent
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = indent
