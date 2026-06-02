"""
output/reporter.py
All output: JSON, JSONL, CSV, HTML report, export_targets (nuclei/sqlmap lists).
"""

import csv, json, os, tempfile
from datetime import datetime
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse, parse_qs

from ..utils import log, col, status_color, C, SECURITY_HEADERS, save_checkpoint


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _write_csv_atomic(path, fieldnames, rows, extra_fn=None):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            wtr = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            wtr.writeheader()
            if extra_fn:
                for row in rows:
                    wtr.writerow(extra_fn(dict(row)))
            else:
                wtr.writerows(rows)
        os.replace(tmp, path)
        log("SAVED", f"CSV  -> {col(path, C.CYAN)}", C.GREEN)
    except Exception as e:
        log("SAVE", col(f"Failed writing {path}: {e}", C.RED), C.RED)
        try:
            os.unlink(tmp)
        except OSError:
            pass


def save_results(scanner) -> str:
    """
    Write all output files for *scanner* (a ParamSpecter instance).
    Returns the file prefix used so callers can derive paths.
    """
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    base   = f"paramspecter_{scanner.base_domain.replace('.', '_')}_{ts_str}"
    pfx    = os.path.join(scanner.output_dir, base)

    save_checkpoint(scanner._checkpoint_file, scanner.visited)

    meta = _build_meta(scanner)

    if scanner.output in ("json", "both"):
        _save_json(pfx, meta, scanner)

    if scanner.output == "jsonl":
        _save_jsonl_meta(pfx, meta)

    if scanner.output in ("csv", "both"):
        _save_csv(pfx, scanner)

    _save_html_report(pfx, scanner, meta)
    return pfx


def _build_meta(scanner) -> Dict:
    return {
        "target":       scanner.start_url,
        "mode":         scanner.mode,
        "strategy":     scanner.strategy,
        "crawled_at":   scanner.start_time.isoformat(),
        "duration":     scanner.stats.elapsed(),
        "interrupted":  scanner._stop_event.is_set(),
        "total_pages":  scanner.stats.pages_crawled,
        "total_requests": scanner.stats.requests_sent,
        "avg_rps":      scanner.stats.avg_rps(),
        "phase_times":  scanner.stats.phase_times,
        "emails":       list(scanner.all_emails),
        "phones":       list(scanner.all_phones),
        "subdomains_crawl": list(scanner.all_subdomains),
        "subdomains_hunt":  [h["subdomain"] for h in scanner.subdomain_hits],
        "technologies": list(scanner.all_techs),
        "waf":          list(scanner.all_wafs),
        "params":       list(scanner.all_params),
        "openapi_specs": list(scanner.all_openapi),
        "secrets_count": len(scanner.all_secrets),
        "missing_security_headers": dict(scanner.missing_sec_headers),
    }


def _save_json(pfx, meta, scanner):
    fname   = f"{pfx}.json"
    payload = {
        "meta":           meta,
        "pages":          scanner.results,
        "secrets":        scanner.all_secrets,
        "fuzz_hits":      scanner.fuzz_hits,
        "dir_hits":       scanner.dir_hits,
        "param_hits":     scanner.param_hits,
        "subdomain_hits": scanner.subdomain_hits,
    }
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".json.tmp",
                                        dir=os.path.dirname(fname) or ".")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, fname)
    except Exception as e:
        log("SAVE", col(f"Atomic write failed ({e}), trying direct write", C.YELLOW), C.YELLOW)
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    log("SAVED", f"JSON -> {col(fname, C.CYAN)}", C.GREEN)


def _save_jsonl_meta(pfx, meta):
    meta_fname = f"{pfx}_meta.json"
    try:
        with open(meta_fname, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        log("SAVED", f"JSONL meta -> {col(meta_fname, C.CYAN)}", C.GREEN)
    except Exception as e:
        log("SAVE", col(f"Meta write failed: {e}", C.RED), C.RED)


def _save_csv(pfx, scanner):
    fields = [
        "url", "status", "title", "content_type", "technologies", "waf",
        "emails", "phones", "ips", "internal_ips", "subdomains", "params",
        "forms", "html_comments", "redirect_chain", "social_links",
        "security_headers", "leaked_headers", "js_endpoints", "sourcemaps",
        "captcha_detected", "content_length", "content_hash", "openapi_specs",
    ]
    fname    = f"{pfx}.csv"
    _tmp_csv = fname + ".tmp"
    with open(_tmp_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in scanner.results:
            row = dict(r)
            for k in ["emails", "phones", "ips", "internal_ips", "subdomains", "params",
                      "technologies", "waf", "html_comments", "redirect_chain",
                      "social_links", "js_endpoints", "sourcemaps", "openapi_specs"]:
                if isinstance(row.get(k), list):
                    row[k] = " | ".join(str(i) for i in row[k])
            row["forms"]            = len(r.get("forms", []))
            row["security_headers"] = str(r.get("security_headers", {}))
            row["leaked_headers"]   = str(r.get("leaked_headers", {}))
            w.writerow(row)
    os.replace(_tmp_csv, fname)
    log("SAVED", f"CSV  -> {col(fname, C.CYAN)}", C.GREEN)

    if scanner.dir_hits:
        _write_csv_atomic(f"{pfx}_dirs.csv",
                          ["url", "status", "size", "redirect"], scanner.dir_hits)
    if scanner.param_hits:
        _write_csv_atomic(f"{pfx}_params.csv",
                          ["param", "payload", "url", "status", "size", "size_diff", "reflected", "cwe"],
                          scanner.param_hits)
    if scanner.all_secrets:
        _write_csv_atomic(f"{pfx}_secrets.csv",
                          ["type", "value", "source"], scanner.all_secrets)
    if scanner.subdomain_hits:
        def _fix_sub(row):
            row["ips"] = ", ".join(row.get("ips", []) if isinstance(row.get("ips"), list) else [row.get("ips", "")])
            return row
        _write_csv_atomic(f"{pfx}_subdomains.csv",
                          ["subdomain", "ips", "method", "status", "http_url", "title"],
                          scanner.subdomain_hits, extra_fn=_fix_sub)


def _save_html_report(pfx: str, scanner, meta: Dict) -> None:
    html_path = f"{pfx}_report.html"

    def _rows(items, fields):
        rows = ""
        for item in items:
            rows += "<tr>" + "".join(f"<td>{_esc(item.get(f, ''))}</td>" for f in fields) + "</tr>\n"
        return rows

    def _th(fields):
        return "<tr>" + "".join(f"<th>{_esc(f)}</th>" for f in fields) + "</tr>"

    secrets_html = "".join(
        f"<tr><td><span class='badge badge-red'>{_esc(s.get('type','?'))}</span></td>"
        f"<td><code>{_esc(s.get('value','')[:80])}</code></td>"
        f"<td>{_esc(s.get('source',''))}</td></tr>\n"
        for s in scanner.all_secrets
    )

    param_hits_html = _rows(scanner.param_hits,
                            ["param", "url", "status", "size_diff", "reflected", "payload", "cwe"])
    dir_hits_html   = _rows(scanner.dir_hits, ["url", "status", "size", "redirect"])

    sub_hits_html = "".join(
        f"<tr><td>{_esc(h.get('subdomain',''))}</td>"
        f"<td>{_esc(', '.join(h.get('ips', [])))}</td>"
        f"<td>{_esc(h.get('status', ''))}</td>"
        f"<td>{_esc(h.get('method', ''))}</td></tr>\n"
        for h in scanner.subdomain_hits
    )

    openapi_html = "".join(
        f"<tr><td><a href='{_esc(spec)}' target='_blank' style='color:#80c8ff'>{_esc(spec)}</a></td></tr>\n"
        for spec in sorted(scanner.all_openapi)
    )

    tech_badges = " ".join(f"<span class='badge badge-blue'>{_esc(t)}</span>" for t in sorted(scanner.all_techs))
    waf_badges  = " ".join(f"<span class='badge badge-yellow'>{_esc(w)}</span>" for w in sorted(scanner.all_wafs))
    param_list  = " ".join(f"<span class='badge badge-gray'>?{_esc(p)}</span>" for p in sorted(scanner.all_params)[:80])

    phase_timing_html = ""
    if scanner.stats.phase_times:
        rows_html = "".join(
            f"<tr><td>{_esc(phase)}</td><td>{secs}</td></tr>"
            for phase, secs in scanner.stats.phase_times.items()
        )
        phase_timing_html = (
            "<div class='section'><h2>Phase Timing</h2>"
            "<table><thead><tr><th>Phase</th><th>Duration (s)</th></tr></thead>"
            f"<tbody>{rows_html}</tbody></table></div>"
        )

    missing_headers_html = "".join(
        f"<tr><td>{_esc(h)}</td><td>{c}</td></tr>"
        for h, c in sorted(scanner.missing_sec_headers.items(), key=lambda x: -x[1])
    ) if scanner.missing_sec_headers else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ParamSpecter v6.0 Report — {_esc(scanner.start_url)}</title>
<style>
  :root{{--red:#e74c3c;--green:#2ecc71;--blue:#3498db;--yellow:#f39c12;--gray:#95a5a6;--dark:#1a1a2e;--card:#16213e;--text:#e0e0e0}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--dark);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:20px}}
  h1{{color:var(--red);font-size:1.8rem;margin-bottom:4px}}
  h2{{color:var(--blue);font-size:1.1rem;margin:20px 0 8px;border-bottom:1px solid #333;padding-bottom:4px}}
  .meta{{color:var(--gray);font-size:.85rem;margin-bottom:20px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}}
  .card{{background:var(--card);border-radius:8px;padding:16px;text-align:center;border:1px solid #2a2a4a}}
  .card .num{{font-size:2rem;font-weight:700;color:var(--red)}}
  .card .lbl{{font-size:.8rem;color:var(--gray);margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-bottom:16px}}
  th{{background:#0f3460;color:var(--text);padding:8px;text-align:left}}
  td{{padding:7px 8px;border-bottom:1px solid #222;word-break:break-all}}
  tr:hover td{{background:#1e2a45}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;margin:2px}}
  .badge-red{{background:#5c1a1a;color:#ff8080}}
  .badge-blue{{background:#1a3a5c;color:#80c8ff}}
  .badge-yellow{{background:#5c4a1a;color:#ffd080}}
  .badge-gray{{background:#2a2a2a;color:#aaa}}
  code{{background:#0d1117;padding:1px 5px;border-radius:3px;font-family:monospace;font-size:.82rem}}
  .warn{{background:#5c3a1a;border:1px solid var(--yellow);border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:.9rem}}
  .section{{background:var(--card);border-radius:8px;padding:16px;margin-bottom:16px;border:1px solid #2a2a4a}}
</style>
</head>
<body>
<h1>⚡ ParamSpecter v6.0 — Scan Report</h1>
<p class="meta">
  Target: <strong>{_esc(scanner.start_url)}</strong> &nbsp;|&nbsp;
  Mode: {_esc(scanner.mode)} &nbsp;|&nbsp;
  Duration: {_esc(scanner.stats.elapsed())} &nbsp;|&nbsp;
  Requests: {scanner.stats.requests_sent} ({scanner.stats.avg_rps()} req/s) &nbsp;|&nbsp;
  Generated: {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
</p>
<div class="warn">⚠️ For authorized security testing only.</div>

<div class="grid">
  <div class="card"><div class="num">{scanner.stats.pages_crawled}</div><div class="lbl">Pages Crawled</div></div>
  <div class="card"><div class="num">{len(scanner.all_params)}</div><div class="lbl">URL Params</div></div>
  <div class="card"><div class="num">{len(scanner.all_emails)}</div><div class="lbl">Emails</div></div>
  <div class="card"><div class="num">{len(scanner.all_secrets)}</div><div class="lbl">Possible Secrets</div></div>
  <div class="card"><div class="num">{len(scanner.dir_hits)}</div><div class="lbl">Dir Hits</div></div>
  <div class="card"><div class="num">{len(scanner.param_hits)}</div><div class="lbl">Param Hits</div></div>
  <div class="card"><div class="num">{len(scanner.subdomain_hits)}</div><div class="lbl">Subdomains</div></div>
  <div class="card"><div class="num">{scanner.all_forms}</div><div class="lbl">Forms Found</div></div>
  <div class="card"><div class="num">{len(scanner.all_openapi)}</div><div class="lbl">OpenAPI Specs</div></div>
  <div class="card"><div class="num">{scanner.stats.requests_sent}</div><div class="lbl">Total Requests</div></div>
</div>

<div class="section">
  <h2>Technologies Detected</h2>
  <p>{tech_badges or "<span style='color:var(--gray)'>None detected</span>"}</p>
  <h2 style="margin-top:12px">WAF Detected</h2>
  <p>{waf_badges or "<span style='color:var(--gray)'>None detected</span>"}</p>
</div>

<div class="section">
  <h2>URL Parameters Discovered</h2>
  <p>{param_list or "<span style='color:var(--gray)'>None</span>"}</p>
</div>

{phase_timing_html}

{"<div class='section'><h2>OpenAPI / Swagger Specs (" + str(len(scanner.all_openapi)) + ")</h2><table><thead><tr><th>URL</th></tr></thead><tbody>" + openapi_html + "</tbody></table></div>" if scanner.all_openapi else ""}

{"<div class='section'><h2>⚠️ Possible Secrets (" + str(len(scanner.all_secrets)) + ")</h2><table><thead>" + _th(["Type","Value","Source"]) + "</thead><tbody>" + secrets_html + "</tbody></table></div>" if scanner.all_secrets else ""}

{"<div class='section'><h2>Emails Found</h2><p>" + " ".join(f"<span class='badge badge-gray'>{_esc(e)}</span>" for e in sorted(scanner.all_emails)) + "</p></div>" if scanner.all_emails else ""}

{"<div class='section'><h2>Directory / File Hits (" + str(len(scanner.dir_hits)) + ")</h2><table><thead>" + _th(["URL","Status","Size","Redirect"]) + "</thead><tbody>" + dir_hits_html + "</tbody></table></div>" if scanner.dir_hits else ""}

{"<div class='section'><h2>Parameter Hits (" + str(len(scanner.param_hits)) + ")</h2><table><thead>" + _th(["Param","URL","Status","Size Delta","Reflected","Payload","CWE"]) + "</thead><tbody>" + param_hits_html + "</tbody></table></div>" if scanner.param_hits else ""}

{"<div class='section'><h2>Subdomains Found (" + str(len(scanner.subdomain_hits)) + ")</h2><table><thead>" + _th(["Subdomain","IPs","Status","Method"]) + "</thead><tbody>" + sub_hits_html + "</tbody></table></div>" if scanner.subdomain_hits else ""}

<div class="section">
  <h2>Missing Security Headers</h2>
  {"<table><thead>" + _th(["Header","Pages Missing"]) + "</thead><tbody>" + missing_headers_html + "</tbody></table>" if missing_headers_html else "<p style='color:var(--gray)'>All checked</p>"}
</div>

</body></html>"""

    try:
        tmp = html_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(html)
        os.replace(tmp, html_path)
        log("SAVED", f"HTML -> {col(html_path, C.CYAN)}", C.GREEN)
    except Exception as e:
        log("SAVE", col(f"HTML report failed: {e}", C.YELLOW), C.YELLOW)


def export_targets(scanner, pfx: str) -> Tuple[str, str]:
    """Build targets.txt and sqlmap_targets.txt from crawl results."""
    import re as _re
    candidates: Dict[str, Set[str]] = {}

    def _register(url_str: str):
        if not url_str:
            return
        parsed = urlparse(url_str)
        if not parsed.query:
            return
        params = set(parse_qs(parsed.query, keep_blank_values=True).keys())
        if params:
            candidates[url_str] = params

    for page in scanner.results:
        if (page.get("status") or 0) < 400:
            _register(page.get("url", ""))
        for link in page.get("links", []):
            _register(link)
    for hit in scanner.param_hits:
        _register(hit.get("url", ""))

    INJECTABLE_NAMES: Set[str] = {
        "id", "uid", "user_id", "userid", "item_id", "itemid",
        "product_id", "productid", "product", "item", "cat",
        "category", "category_id", "page_id", "post_id", "article_id",
        "order_id", "orderid", "pid", "sid", "tid", "cid", "nid",
        "news_id", "blog_id", "entry_id", "record_id", "row_id",
    }
    _NUMERIC_VAL_RE = _re.compile(r"^\d+$")
    confirmed_urls: Set[str] = {h.get("url", "") for h in scanner.param_hits if h.get("url")}

    def _is_sqlmap_candidate(url_str: str, param_names: Set[str]) -> bool:
        if url_str in confirmed_urls:
            return True
        if param_names & INJECTABLE_NAMES:
            return True
        qs = parse_qs(urlparse(url_str).query, keep_blank_values=True)
        return any(_NUMERIC_VAL_RE.match(v) for vals in qs.values() for v in vals)

    all_targets    = sorted(candidates.keys())
    sqlmap_targets = sorted(
        url for url, params in candidates.items()
        if _is_sqlmap_candidate(url, params)
    )

    def _write_txt(path, lines):
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + ("\n" if lines else ""))
            os.replace(tmp, path)
            log("SAVED", f"TXT  -> {col(path, C.CYAN)}  ({len(lines)} URLs)", C.GREEN)
        except Exception as e:
            log("SAVE", col(f"Failed writing {path}: {e}", C.RED), C.RED)

    t_path   = f"{pfx}_targets.txt"
    sql_path = f"{pfx}_sqlmap_targets.txt"
    _write_txt(t_path, all_targets)
    _write_txt(sql_path, sqlmap_targets)
    return t_path, sql_path
