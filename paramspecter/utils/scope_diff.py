"""
utils/scope_diff.py
Scope diffing for bug bounty programs.

Compares current scan results against a previous scan to find:
- New endpoints that appeared since last scan
- New parameters found on existing endpoints
- New subdomains that came online
- Removed endpoints (these sometimes reveal hidden features)
- New secrets discovered

Supports:
- Local scope file (list of domains/wildcards)
- HackerOne API (public scope, no auth required for public programs)
- Bugcrowd API (public scope)
- Manual diff against a saved JSON results file

Usage:
    paramspecter https://target.com --mode full --scope-diff prev_scan.json
    paramspecter https://target.com --mode full --h1-program uber
    paramspecter https://target.com --mode full --bc-program tesla
"""

import json
import os
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from urllib.request import urlopen, Request

from .helpers import log, log_section, col, C


# -----------------------------------------------------------------
#  PLATFORM API CLIENTS
# -----------------------------------------------------------------

class HackerOneScope:
    """
    Fetch public program scope from HackerOne API.
    No authentication required for public programs.
    """
    API_BASE = "https://api.hackerone.com/v1"

    def __init__(self, program_handle: str):
        self.handle = program_handle

    def fetch_scope(self) -> Dict:
        """Returns {in_scope: [...], out_of_scope: [...]}"""
        url = f"{self.API_BASE}/hackers/programs/{self.handle}"
        try:
            req = Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "ParamSpecter/7.3 (security research)",
            })
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            relationships = data.get("relationships", {})
            structured    = relationships.get("structured_scopes", {}).get("data", [])

            in_scope  = []
            out_scope = []
            for item in structured:
                attrs      = item.get("attributes", {})
                identifier = attrs.get("asset_identifier", "")
                asset_type = attrs.get("asset_type", "")
                eligible   = attrs.get("eligible_for_submission", True)

                entry = {
                    "identifier": identifier,
                    "type":       asset_type,
                    "max_severity": attrs.get("max_severity", "critical"),
                }
                if eligible:
                    in_scope.append(entry)
                else:
                    out_scope.append(entry)

            log("H1", col(
                f"HackerOne scope for '{self.handle}': "
                f"{len(in_scope)} in-scope, {len(out_scope)} out-of-scope",
                C.GREEN), C.GREEN)
            return {"in_scope": in_scope, "out_of_scope": out_scope}

        except Exception as e:
            log("H1", col(f"HackerOne API error: {e}", C.RED), C.RED)
            return {"in_scope": [], "out_of_scope": []}

    def is_in_scope(self, url: str) -> bool:
        """Quick check if a URL is in scope for this program."""
        scope = self.fetch_scope()
        host  = urlparse(url).netloc.lower()
        for entry in scope.get("in_scope", []):
            pattern = entry["identifier"].lower().lstrip("*.")
            if host == pattern or host.endswith("." + pattern):
                return True
        return False


class BugcrowdScope:
    """
    Fetch public program scope from Bugcrowd API.
    No authentication required for public programs.
    """
    API_BASE = "https://bugcrowd.com"

    def __init__(self, program_handle: str):
        self.handle = program_handle

    def fetch_scope(self) -> Dict:
        """Returns {in_scope: [...], out_of_scope: [...]}"""
        url = f"{self.API_BASE}/{self.handle}.json"
        try:
            req = Request(url, headers={
                "Accept": "application/json",
                "User-Agent": "ParamSpecter/7.3 (security research)",
            })
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            in_scope  = []
            out_scope = []

            for target in data.get("targets", {}).get("in_scope", []):
                in_scope.append({
                    "identifier": target.get("target", ""),
                    "type":       target.get("type", "website"),
                })
            for target in data.get("targets", {}).get("out_of_scope", []):
                out_scope.append({
                    "identifier": target.get("target", ""),
                    "type":       target.get("type", "website"),
                })

            log("BC", col(
                f"Bugcrowd scope for '{self.handle}': "
                f"{len(in_scope)} in-scope, {len(out_scope)} out-of-scope",
                C.GREEN), C.GREEN)
            return {"in_scope": in_scope, "out_of_scope": out_scope}

        except Exception as e:
            log("BC", col(f"Bugcrowd API error: {e}", C.RED), C.RED)
            return {"in_scope": [], "out_of_scope": []}


# -----------------------------------------------------------------
#  DIFF ENGINE
# -----------------------------------------------------------------

class ScopeDiffer:
    """
    Compare two scan result sets to surface new attack surface.

    new_endpoints   → appeared in current scan, not in previous
    new_params      → parameters found on endpoints not seen before
    new_subdomains  → new subdomains that came online
    new_secrets     → secrets not seen in previous scan
    removed_endpoints → were in previous scan but gone now
                        (worth investigating — sometimes reveals hidden features)
    changed_status  → endpoints that returned different HTTP status
    """

    def __init__(self, prev_scan_path: Optional[str] = None,
                 prev_data: Optional[Dict] = None):
        self._prev = {}
        if prev_scan_path and os.path.isfile(prev_scan_path):
            try:
                with open(prev_scan_path, "r", encoding="utf-8") as f:
                    self._prev = json.load(f)
                log("DIFF", col(
                    f"Loaded previous scan: {prev_scan_path} "
                    f"({len(self._prev.get('pages', []))} pages, "
                    f"{len(self._prev.get('subdomains', []))} subdomains)",
                    C.CYAN), C.CYAN)
            except Exception as e:
                log("DIFF", col(f"Could not load previous scan: {e}", C.YELLOW), C.YELLOW)
        elif prev_data:
            self._prev = prev_data

    def diff(self, scanner) -> Dict:
        """
        Compare scanner results against previous scan.
        Returns diff dict with new/changed/removed items.
        """
        prev_pages      = {p["url"]: p for p in self._prev.get("pages", [])}
        prev_subs       = {s.get("subdomain","") for s in self._prev.get("subdomains", [])}
        prev_secrets    = {
            (s.get("type",""), s.get("value","")[:20])
            for s in self._prev.get("secrets", [])
        }
        prev_params: Set[str] = set()
        for p in self._prev.get("pages", []):
            for param in p.get("params", []):
                prev_params.add(f"{p['url']}:{param}")

        # Current scan data
        curr_urls   = {r["url"] for r in scanner.results}
        curr_subs   = {h.get("subdomain","") for h in scanner.subdomain_hits}
        curr_secrets = {
            (s.get("type",""), s.get("value","")[:20])
            for s in scanner.all_secrets
        }
        curr_params: Set[str] = set()
        for r in scanner.results:
            for param in r.get("params", []):
                curr_params.add(f"{r['url']}:{param}")

        # Compute diffs
        new_endpoints   = sorted(curr_urls - set(prev_pages.keys()))
        removed         = sorted(set(prev_pages.keys()) - curr_urls)
        new_subdomains  = sorted(curr_subs - prev_subs - {""})
        new_params      = sorted(curr_params - prev_params)
        new_secret_keys = curr_secrets - prev_secrets
        new_secrets     = [
            s for s in scanner.all_secrets
            if (s.get("type",""), s.get("value","")[:20]) in new_secret_keys
        ]

        # Status changes
        changed_status = []
        for r in scanner.results:
            prev = prev_pages.get(r["url"])
            if prev and prev.get("status") != r.get("status"):
                changed_status.append({
                    "url":      r["url"],
                    "was":      prev.get("status"),
                    "now":      r.get("status"),
                })

        diff = {
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%S"),
            "target":           scanner.start_url,
            "new_endpoints":    new_endpoints,
            "removed_endpoints": removed,
            "new_params":       new_params,
            "new_subdomains":   new_subdomains,
            "new_secrets":      new_secrets,
            "changed_status":   changed_status,
            "summary": {
                "new_endpoints":    len(new_endpoints),
                "removed_endpoints": len(removed),
                "new_params":       len(new_params),
                "new_subdomains":   len(new_subdomains),
                "new_secrets":      len(new_secrets),
                "changed_status":   len(changed_status),
            }
        }
        return diff

    def print_diff(self, diff: Dict) -> None:
        """Pretty-print diff results to terminal."""
        log_section("SCOPE DIFF RESULTS")
        s = diff["summary"]

        SEV_MAP = [
            ("new_secrets",       "NEW SECRETS",           C.RED + C.BOLD),
            ("new_endpoints",     "NEW ENDPOINTS",         C.YELLOW),
            ("new_subdomains",    "NEW SUBDOMAINS",        C.CYAN),
            ("new_params",        "NEW PARAMETERS",        C.GREEN),
            ("changed_status",    "STATUS CHANGES",        C.YELLOW),
            ("removed_endpoints", "REMOVED ENDPOINTS",     C.GRAY),
        ]

        total_new = s["new_endpoints"] + s["new_subdomains"] + s["new_secrets"]
        if total_new == 0:
            log("DIFF", col("No new attack surface found since last scan.", C.GREEN), C.GREEN)
        else:
            log("DIFF", col(
                f"{total_new} new item(s) found since last scan!", C.RED + C.BOLD
            ), C.RED)

        for key, label, color in SEV_MAP:
            count = s.get(key, 0)
            if count:
                log("DIFF", col(f"{label}: {count}", color), color)
                items = diff.get(key, [])[:10]
                for item in items:
                    if isinstance(item, dict):
                        if key == "changed_status":
                            log("  →", col(
                                f"{item['url']} — {item['was']} → {item['now']}",
                                C.YELLOW), C.YELLOW)
                        elif key == "new_secrets":
                            log("  →", col(
                                f"[{item.get('type','?')}] {item.get('value','')[:40]}",
                                C.RED), C.RED)
                    else:
                        log("  →", col(str(item), color), color)
                if len(diff.get(key, [])) > 10:
                    log("  …", col(
                        f"and {len(diff[key])-10} more", C.GRAY
                    ), C.GRAY)

    def save_diff(self, diff: Dict, output_dir: str, domain: str) -> str:
        """Save diff report as JSON."""
        ts    = time.strftime("%Y%m%d_%H%M%S")
        path  = os.path.join(output_dir, f"paramspecter_{domain}_{ts}_diff.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(diff, f, indent=2)
        log("DIFF", col(f"Diff saved → {path}", C.GREEN), C.GREEN)
        return path


# -----------------------------------------------------------------
#  SCOPE VALIDATOR
# -----------------------------------------------------------------

class ScopeValidator:
    """
    Validate URLs against a bug bounty program scope.
    Supports wildcards: *.example.com, example.com/api/*
    """

    def __init__(self, scope_entries: List[str] = None,
                 h1_program: str = "",
                 bc_program: str = ""):
        self.entries: List[str] = []

        if scope_entries:
            self.entries.extend(scope_entries)

        if h1_program:
            h1    = HackerOneScope(h1_program)
            scope = h1.fetch_scope()
            for e in scope.get("in_scope", []):
                if e.get("type", "") in ("URL", "WILDCARD", "DOMAIN", ""):
                    self.entries.append(e["identifier"])

        if bc_program:
            bc    = BugcrowdScope(bc_program)
            scope = bc.fetch_scope()
            for e in scope.get("in_scope", []):
                self.entries.append(e["identifier"])

        if self.entries:
            log("SCOPE", col(
                f"Scope loaded: {len(self.entries)} entries",
                C.GREEN), C.GREEN)
            for e in self.entries[:5]:
                log("SCOPE", f"  {col(e, C.CYAN)}", C.CYAN)
            if len(self.entries) > 5:
                log("SCOPE", col(f"  ... and {len(self.entries)-5} more", C.GRAY), C.GRAY)

    def in_scope(self, url: str) -> bool:
        """Return True if url matches any scope entry."""
        if not self.entries:
            return True   # no scope defined = everything in scope

        host = urlparse(url).netloc.lower()
        path = urlparse(url).path.lower()

        for entry in self.entries:
            entry = entry.lower().strip()

            # Strip protocol
            if "://" in entry:
                entry = entry.split("://", 1)[1]

            # Wildcard subdomain: *.example.com
            if entry.startswith("*."):
                base = entry[2:]
                if host == base or host.endswith("." + base):
                    return True
                continue

            # Path wildcard: example.com/api/*
            if "*" in entry:
                entry_host, _, entry_path = entry.partition("/")
                if host == entry_host or host.endswith("." + entry_host):
                    entry_path = entry_path.rstrip("*")
                    if path.startswith("/" + entry_path):
                        return True
                continue

            # Exact domain or subdomain match
            if host == entry or host.endswith("." + entry):
                return True

        return False
