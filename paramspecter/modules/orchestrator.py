"""
modules/orchestrator.py
Phase 1 — Auto Orchestrator.

Detects installed external tools (subfinder, gau, katana, arjun,
dalfox, sqlmap, nuclei, trufflehog) and runs them in the right order
against the target. Falls back to ParamSpecter built-ins if a tool
isn't installed. All findings are merged into a single unified schema
and returned for reporting.
"""

import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..utils import log, log_section, col, C, vlog


# -----------------------------------------------------------------
#  UNIFIED FINDING SCHEMA
#  Every tool's output gets normalised into this dict shape so the
#  reporter only needs to handle one format.
# -----------------------------------------------------------------
def make_finding(
    source: str,
    category: str,           # "subdomain" | "url" | "param" | "vuln" | "secret"
    severity: str,           # "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    title: str,
    target: str,
    detail: str = "",
    raw: Optional[Dict] = None,
) -> Dict:
    return {
        "source":   source,
        "category": category,
        "severity": severity,
        "title":    title,
        "target":   target,
        "detail":   detail,
        "raw":      raw or {},
        "ts":       time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


# -----------------------------------------------------------------
#  TOOL DETECTION
# -----------------------------------------------------------------
EXTERNAL_TOOLS = {
    "subfinder":  "subfinder",
    "gau":        "gau",
    "katana":     "katana",
    "arjun":      "arjun",
    "dalfox":     "dalfox",
    "sqlmap":     "sqlmap",
    "nuclei":     "nuclei",
    "trufflehog": "trufflehog",
    "httpx":      "httpx",
}


def _windows_extra_paths() -> List[str]:
    """
    Return extra PATH entries to check on Windows where Go/pip tools
    land in non-standard locations that aren't always in %PATH%.
    Returns empty list on non-Windows.
    """
    import platform
    if platform.system() != "Windows":
        return []

    extra = []

    # Go tools: %USERPROFILE%\go\bin  and  %GOPATH%\bin
    userprofile = os.environ.get("USERPROFILE", "")
    gopath      = os.environ.get("GOPATH", "")
    go_default  = os.path.join(userprofile, "go", "bin") if userprofile else ""

    for p in [go_default, os.path.join(gopath, "bin") if gopath else ""]:
        if p and os.path.isdir(p) and p not in extra:
            extra.append(p)

    # pipx: %USERPROFILE%\AppData\Local\Programs\Python\PythonXX\Scripts
    # and   %USERPROFILE%\.local\bin  (pipx default)
    appdata = os.environ.get("LOCALAPPDATA", "")
    if appdata:
        import glob
        for scripts in glob.glob(os.path.join(appdata, "Programs", "Python", "Python*", "Scripts")):
            if os.path.isdir(scripts) and scripts not in extra:
                extra.append(scripts)

    pipx_home = os.path.join(userprofile, ".local", "bin") if userprofile else ""
    if pipx_home and os.path.isdir(pipx_home) and pipx_home not in extra:
        extra.append(pipx_home)

    # Scoop: %USERPROFILE%\scoop\shims
    scoop_shims = os.path.join(userprofile, "scoop", "shims") if userprofile else ""
    if scoop_shims and os.path.isdir(scoop_shims) and scoop_shims not in extra:
        extra.append(scoop_shims)

    return extra


def detect_tools() -> Dict[str, Optional[str]]:
    """Return {tool_name: full_path_or_None} for every known tool.
    On Windows, also checks Go/pip/pipx/scoop install dirs automatically.
    """
    # Temporarily extend PATH with Windows-specific dirs
    extra = _windows_extra_paths()
    original_path = os.environ.get("PATH", "")
    if extra:
        os.environ["PATH"] = os.pathsep.join(extra) + os.pathsep + original_path

    found = {}
    try:
        for name, binary in EXTERNAL_TOOLS.items():
            # On Windows, also try .exe extension explicitly
            path = shutil.which(binary)
            if path is None and os.name == "nt":
                path = shutil.which(binary + ".exe")
            found[name] = path
    finally:
        # Always restore original PATH
        if extra:
            os.environ["PATH"] = original_path

    return found


def _tool_status_line(found: Dict[str, Optional[str]]) -> None:
    log_section("TOOL DETECTION")
    for name, path in found.items():
        if path:
            log("TOOL", f"{col(name, C.CYAN):<20} {col('found', C.GREEN)}  {col(path, C.GRAY)}", C.GREEN)
        else:
            log("TOOL", f"{col(name, C.CYAN):<20} {col('not found — using built-in fallback', C.YELLOW)}", C.YELLOW)


# -----------------------------------------------------------------
#  SUBPROCESS HELPER
# -----------------------------------------------------------------
def _run(cmd: List[str], timeout: int = 300, env: Dict = None) -> Tuple[int, str, str]:
    """Run a command, stream stdout, return (returncode, stdout, stderr)."""
    _env = os.environ.copy()
    if env:
        _env.update(env)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except FileNotFoundError:
        return -1, "", f"Binary not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


# -----------------------------------------------------------------
#  INDIVIDUAL TOOL RUNNERS
#  Each returns List[Dict] in unified finding schema.
# -----------------------------------------------------------------

class _ToolRunner:
    """Base class for all tool runners."""
    NAME     = "base"
    CATEGORY = "url"
    SEVERITY = "INFO"

    def __init__(self, target_url: str, output_dir: str,
                 tool_path: Optional[str], threads: int = 10, timeout: int = 300):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.root_domain = ".".join(self.base_domain.split(".")[-2:])
        self.output_dir = output_dir
        self.tool_path = tool_path
        self.threads = threads
        self.timeout = timeout

    def run(self) -> List[Dict]:
        raise NotImplementedError

    def available(self) -> bool:
        return self.tool_path is not None


# ---- Subfinder -------------------------------------------------------
class SubfinderRunner(_ToolRunner):
    NAME     = "subfinder"
    CATEGORY = "subdomain"
    SEVERITY = "INFO"

    def run(self) -> List[Dict]:
        findings = []
        log("AUTO", f"Running {col('subfinder', C.CYAN)} on {self.root_domain}", C.CYAN)

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
            out_path = tf.name

        cmd = [
            self.tool_path, "-d", self.root_domain,
            "-o", out_path, "-silent", "-t", str(self.threads),
        ]
        rc, stdout, stderr = _run(cmd, timeout=self.timeout)

        try:
            with open(out_path) as f:
                for line in f:
                    sub = line.strip()
                    if sub:
                        findings.append(make_finding(
                            source="subfinder", category="subdomain",
                            severity="INFO", title=f"Subdomain: {sub}",
                            target=sub, detail=f"Discovered by subfinder on {self.root_domain}",
                        ))
        except Exception:
            pass
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

        log("AUTO", f"subfinder: {col(len(findings), C.BOLD)} subdomains", C.GREEN)
        return findings


# ---- GAU (Get All URLs) ---------------------------------------------
class GauRunner(_ToolRunner):
    NAME     = "gau"
    CATEGORY = "url"
    SEVERITY = "INFO"

    def run(self) -> List[Dict]:
        findings = []
        log("AUTO", f"Running {col('gau', C.CYAN)} on {self.base_domain}", C.CYAN)

        cmd = [self.tool_path, "--threads", str(self.threads), self.base_domain]
        rc, stdout, stderr = _run(cmd, timeout=self.timeout)

        seen = set()
        for line in stdout.splitlines():
            url = line.strip()
            if url and url not in seen:
                seen.add(url)
                findings.append(make_finding(
                    source="gau", category="url",
                    severity="INFO", title=f"Historical URL",
                    target=url, detail="Discovered via Wayback Machine / OTX / Common Crawl",
                ))

        log("AUTO", f"gau: {col(len(findings), C.BOLD)} historical URLs", C.GREEN)
        return findings


# ---- Katana (crawler) -----------------------------------------------
class KatanaRunner(_ToolRunner):
    NAME     = "katana"
    CATEGORY = "url"
    SEVERITY = "INFO"

    def run(self) -> List[Dict]:
        findings = []
        log("AUTO", f"Running {col('katana', C.CYAN)} on {self.target_url}", C.CYAN)

        cmd = [
            self.tool_path, "-u", self.target_url,
            "-silent", "-jc",           # JS crawling
            "-kf", "all",               # known files
            "-c", str(self.threads),
            "-d", "5",
        ]
        rc, stdout, stderr = _run(cmd, timeout=self.timeout)

        seen = set()
        for line in stdout.splitlines():
            url = line.strip()
            if url and url.startswith("http") and url not in seen:
                seen.add(url)
                findings.append(make_finding(
                    source="katana", category="url",
                    severity="INFO", title="Crawled URL",
                    target=url, detail="Discovered by katana crawler",
                ))

        log("AUTO", f"katana: {col(len(findings), C.BOLD)} URLs crawled", C.GREEN)
        return findings


# ---- Arjun (param discovery) ----------------------------------------
class ArjunRunner(_ToolRunner):
    NAME     = "arjun"
    CATEGORY = "param"
    SEVERITY = "INFO"

    def run(self, url_list: List[str] = None) -> List[Dict]:
        findings = []
        targets = url_list or [self.target_url]
        log("AUTO", f"Running {col('arjun', C.CYAN)} on {len(targets)} URL(s)", C.CYAN)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_path = tf.name

        for url in targets[:20]:  # cap to avoid very long runs
            cmd = [
                self.tool_path, "-u", url,
                "--stable", "-oJ", out_path,
                "-t", str(min(self.threads, 5)),
                "-q",
            ]
            _run(cmd, timeout=120)
            try:
                with open(out_path) as f:
                    data = json.load(f)
                for endpoint, params in data.items():
                    for param in (params or []):
                        findings.append(make_finding(
                            source="arjun", category="param",
                            severity="INFO", title=f"Live parameter: {param}",
                            target=endpoint,
                            detail=f"Arjun confirmed server responds to ?{param}",
                        ))
            except Exception:
                pass

        try:
            os.unlink(out_path)
        except OSError:
            pass

        log("AUTO", f"arjun: {col(len(findings), C.BOLD)} live params discovered", C.GREEN)
        return findings


# ---- Dalfox (XSS) ---------------------------------------------------
class DalfoxRunner(_ToolRunner):
    NAME     = "dalfox"
    CATEGORY = "vuln"
    SEVERITY = "HIGH"

    def run(self, url_list: List[str] = None) -> List[Dict]:
        findings = []
        targets = url_list or [self.target_url]
        log("AUTO", f"Running {col('dalfox', C.CYAN)} on {len(targets)} URL(s)", C.CYAN)

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
            tf.write("\n".join(targets))
            urls_file = tf.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_path = tf.name

        cmd = [
            self.tool_path, "file", urls_file,
            "--silence", "--format", "json",
            "-o", out_path,
            "--worker", str(min(self.threads, 5)),
        ]
        _run(cmd, timeout=self.timeout)

        try:
            with open(out_path) as f:
                for line in f:
                    try:
                        item = json.loads(line)
                        findings.append(make_finding(
                            source="dalfox", category="vuln",
                            severity="HIGH", title=f"XSS: {item.get('param', '?')}",
                            target=item.get("url", ""),
                            detail=item.get("evidence", ""),
                            raw=item,
                        ))
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            for p in (urls_file, out_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

        log("AUTO", f"dalfox: {col(len(findings), C.BOLD+C.RED if findings else C.BOLD)} XSS findings", C.GREEN)
        return findings


# ---- Nuclei (templates) ---------------------------------------------
class NucleiRunner(_ToolRunner):
    NAME     = "nuclei"
    CATEGORY = "vuln"
    SEVERITY = "MEDIUM"

    def run(self, url_list: List[str] = None,
            tags: List[str] = None, tech_stack: List[str] = None) -> List[Dict]:
        findings = []
        targets = url_list or [self.target_url]

        # Smart template selection based on detected tech
        nuclei_tags = list(tags or [])
        if tech_stack:
            tech_tag_map = {
                "WordPress":  ["wordpress", "wp"],
                "Laravel":    ["laravel"],
                "Django":     ["django"],
                "Rails":      ["rails"],
                "Spring":     ["spring"],
                "Apache":     ["apache"],
                "Nginx":      ["nginx"],
                "PHP":        ["php"],
                "Node.js":    ["nodejs"],
                "AWS":        ["aws", "s3"],
                "GraphQL":    ["graphql"],
            }
            for tech in tech_stack:
                for key, tags_for_tech in tech_tag_map.items():
                    if key.lower() in tech.lower():
                        nuclei_tags.extend(tags_for_tech)

        log("AUTO", f"Running {col('nuclei', C.CYAN)} on {len(targets)} URL(s)"
            + (f" [tags: {','.join(set(nuclei_tags))}]" if nuclei_tags else ""), C.CYAN)

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
            tf.write("\n".join(targets))
            urls_file = tf.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_path = tf.name

        cmd = [
            self.tool_path,
            "-l", urls_file,
            "-jsonl", "-o", out_path,
            "-silent",
            "-c", str(min(self.threads, 25)),
            "-timeout", "10",
        ]
        if nuclei_tags:
            cmd += ["-tags", ",".join(set(nuclei_tags))]

        _run(cmd, timeout=self.timeout)

        SEV_MAP = {
            "critical": "CRITICAL", "high": "HIGH",
            "medium": "MEDIUM",     "low": "LOW",
            "info": "INFO",         "unknown": "INFO",
        }
        try:
            with open(out_path) as f:
                for line in f:
                    try:
                        item = json.loads(line)
                        sev = SEV_MAP.get(item.get("info", {}).get("severity", "").lower(), "INFO")
                        findings.append(make_finding(
                            source="nuclei", category="vuln",
                            severity=sev,
                            title=item.get("info", {}).get("name", "nuclei finding"),
                            target=item.get("matched-at", item.get("host", "")),
                            detail=item.get("info", {}).get("description", ""),
                            raw=item,
                        ))
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            for p in (urls_file, out_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

        highs = sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL"))
        log("AUTO",
            f"nuclei: {col(len(findings), C.BOLD)} findings  "
            f"({col(highs, C.RED+C.BOLD if highs else C.BOLD)} high/critical)",
            C.GREEN)
        return findings


# ---- SQLmap ---------------------------------------------------------
class SQLmapRunner(_ToolRunner):
    NAME     = "sqlmap"
    CATEGORY = "vuln"
    SEVERITY = "HIGH"

    def run(self, url_list: List[str] = None) -> List[Dict]:
        findings = []
        targets = url_list or [self.target_url]
        log("AUTO", f"Running {col('sqlmap', C.CYAN)} on {len(targets)} URL(s)", C.CYAN)

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
            tf.write("\n".join(targets))
            urls_file = tf.name

        with tempfile.TemporaryDirectory() as out_dir:
            cmd = [
                self.tool_path,
                "-m", urls_file,
                "--batch",
                "--output-dir", out_dir,
                "--forms",
                "--level", "2",
                "--risk", "1",
                "--threads", str(min(self.threads, 5)),
                "--no-cast",
                "--answers", "quit=N",
            ]
            rc, stdout, stderr = _run(cmd, timeout=self.timeout)

            # Parse sqlmap log output for findings
            combined = stdout + stderr
            for line in combined.splitlines():
                line = line.strip()
                if "is vulnerable" in line.lower() or "parameter" in line.lower() and "injectable" in line.lower():
                    findings.append(make_finding(
                        source="sqlmap", category="vuln",
                        severity="HIGH", title="SQL Injection",
                        target=self.target_url,
                        detail=line,
                    ))

        try:
            os.unlink(urls_file)
        except OSError:
            pass

        log("AUTO", f"sqlmap: {col(len(findings), C.BOLD+C.RED if findings else C.BOLD)} SQLi findings", C.GREEN)
        return findings


# ---- Trufflehog (secrets) -------------------------------------------
class TrufflehogRunner(_ToolRunner):
    NAME     = "trufflehog"
    CATEGORY = "secret"
    SEVERITY = "HIGH"

    def run(self) -> List[Dict]:
        findings = []
        log("AUTO", f"Running {col('trufflehog', C.CYAN)} on {self.target_url}", C.CYAN)

        cmd = [
            self.tool_path, "filesystem",
            "--json", "--no-update",
            "--directory", ".",      # user can point at a local clone
        ]
        # Also try scanning the URL directly if supported
        url_cmd = [
            self.tool_path, "git",
            "--json", "--no-update",
            self.target_url,
        ]

        findings = []
        for c in (cmd, url_cmd):
            rc, stdout, stderr = _run(c, timeout=120)
            for line in stdout.splitlines():
                try:
                    item = json.loads(line)
                    det = item.get("DetectorName", "secret")
                    raw_val = item.get("Raw", "")[:60]
                    findings.append(make_finding(
                        source="trufflehog", category="secret",
                        severity="HIGH", title=f"Secret: {det}",
                        target=item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", self.target_url),
                        detail=f"Detector: {det}  Value: {raw_val}",
                        raw=item,
                    ))
                except Exception:
                    pass
            if findings:
                break

        log("AUTO", f"trufflehog: {col(len(findings), C.BOLD+C.RED if findings else C.BOLD)} secrets", C.GREEN)
        return findings


# -----------------------------------------------------------------
#  MAIN ORCHESTRATOR
# -----------------------------------------------------------------
class AutoOrchestrator:
    """
    Runs all available external tools in the right order,
    feeds outputs between phases, and returns a unified findings list.
    """

    def __init__(self, scanner, stop_event: threading.Event = None):
        self.scanner     = scanner
        self.args        = scanner.args
        self.target_url  = scanner.start_url
        self.base_domain = scanner.base_domain
        self.output_dir  = scanner.output_dir
        self.threads     = scanner.threads
        self.stop_event  = stop_event or threading.Event()
        self.findings: List[Dict] = []
        self._lock = threading.Lock()

    def _add(self, new_findings: List[Dict]) -> None:
        with self._lock:
            self.findings.extend(new_findings)

    def _urls_from_findings(self, categories=("url",)) -> List[str]:
        seen = set()
        urls = []
        for f in self.findings:
            if f["category"] in categories:
                t = f["target"]
                if t and t not in seen:
                    seen.add(t)
                    urls.append(t)
        return urls

    def _param_urls_from_scanner(self) -> List[str]:
        """Pull URLs with known params from ParamSpecter's crawl results."""
        urls = []
        for r in (self.scanner.results or []):
            if r.get("params") and r.get("status", 999) < 400:
                urls.append(r["url"])
        return urls[:20]

    def run(self) -> List[Dict]:
        found_tools = detect_tools()
        _tool_status_line(found_tools)

        def mk(name, **kw):
            # Per-tool timeout: default 5 minutes; heavy tools (sqlmap, nuclei) get 10 min
            req_timeout = getattr(self.args, "timeout", 10)
            tool_timeout = 600 if name in ("sqlmap", "nuclei", "dalfox") else max(300, req_timeout * 30)
            return dict(
                target_url=self.target_url,
                output_dir=self.output_dir,
                tool_path=found_tools.get(name),
                threads=self.threads,
                timeout=tool_timeout,
                **kw,
            )

        # ── Phase 1a: Subdomain enumeration ──────────────────────────
        if self.stop_event.is_set():
            return self.findings
        log_section("AUTO PHASE 1 — SUBDOMAIN & HISTORICAL URL DISCOVERY")

        if found_tools["subfinder"]:
            self._add(SubfinderRunner(**mk("subfinder")).run())
        else:
            # Fallback: use ParamSpecter's built-in subdomain hits
            for h in self.scanner.subdomain_hits:
                self._add([make_finding(
                    source="paramspecter", category="subdomain",
                    severity="INFO", title=f"Subdomain: {h['subdomain']}",
                    target=h["subdomain"],
                    detail=f"IPs: {', '.join(h.get('ips', []))}",
                )])

        # ── Phase 1b: Historical URLs ─────────────────────────────────
        if not self.stop_event.is_set():
            if found_tools["gau"]:
                self._add(GauRunner(**mk("gau")).run())

        # ── Phase 2: Deep crawl ───────────────────────────────────────
        if self.stop_event.is_set():
            return self.findings
        log_section("AUTO PHASE 2 — DEEP CRAWL")

        if found_tools["katana"]:
            self._add(KatanaRunner(**mk("katana")).run())
        else:
            # Fallback: use ParamSpecter's own crawl results
            for r in self.scanner.results:
                if r.get("url") and r.get("status", 999) < 400:
                    self._add([make_finding(
                        source="paramspecter", category="url",
                        severity="INFO", title="Crawled URL",
                        target=r["url"],
                        detail=f"Status: {r.get('status')}",
                    )])

        # ── Phase 3: Parameter discovery ─────────────────────────────
        if self.stop_event.is_set():
            return self.findings
        log_section("AUTO PHASE 3 — PARAMETER DISCOVERY")

        all_urls = self._urls_from_findings(categories=("url",))
        if found_tools["arjun"] and all_urls:
            self._add(ArjunRunner(**mk("arjun")).run(url_list=all_urls[:15]))
        else:
            # Fallback: use params found during crawl
            for param in self.scanner.all_params:
                self._add([make_finding(
                    source="paramspecter", category="param",
                    severity="INFO", title=f"URL parameter: {param}",
                    target=self.target_url,
                    detail=f"Discovered during crawl",
                )])

        # ── Phase 4: Vuln scanning ────────────────────────────────────
        if self.stop_event.is_set():
            return self.findings
        log_section("AUTO PHASE 4 — VULNERABILITY SCANNING")

        param_urls = self._param_urls_from_scanner() or all_urls[:10]
        tech_stack = list(self.scanner.all_techs)

        # XSS with dalfox
        if found_tools["dalfox"] and param_urls:
            self._add(DalfoxRunner(**mk("dalfox")).run(url_list=param_urls))

        # SQLi with sqlmap
        if found_tools["sqlmap"] and param_urls:
            self._add(SQLmapRunner(**mk("sqlmap")).run(url_list=param_urls))

        # Nuclei (tech-aware template selection)
        if found_tools["nuclei"]:
            nuclei_urls = list(set(all_urls + [self.target_url]))[:100]
            self._add(NucleiRunner(**mk("nuclei")).run(
                url_list=nuclei_urls, tech_stack=tech_stack
            ))

        # ── Phase 5: Secret scanning ──────────────────────────────────
        if not self.stop_event.is_set():
            log_section("AUTO PHASE 5 — SECRET SCANNING")
            if found_tools["trufflehog"]:
                self._add(TrufflehogRunner(**mk("trufflehog")).run())

            # Always add ParamSpecter's own secret findings
            for s in self.scanner.all_secrets:
                self._add([make_finding(
                    source="paramspecter", category="secret",
                    severity="HIGH", title=f"Secret: {s.get('type', '?')}",
                    target=s.get("source", self.target_url),
                    detail=s.get("value", "")[:80],
                    raw=s,
                )])

        self._print_summary()
        return self.findings

    def _print_summary(self) -> None:
        by_cat: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for f in self.findings:
            by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

        SEV_COLORS = {
            "CRITICAL": C.RED + C.BOLD,
            "HIGH":     C.RED,
            "MEDIUM":   C.YELLOW,
            "LOW":      C.CYAN,
            "INFO":     C.GRAY,
        }
        log_section("AUTO ORCHESTRATOR — MERGED SUMMARY")
        log("TOTAL", f"{col(len(self.findings), C.BOLD+C.WHITE)} findings across all tools", C.WHITE)
        for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
            log("  CAT", f"{col(cat, C.CYAN):<16} {count}", C.CYAN)
        log("", "", C.WHITE)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = by_sev.get(sev, 0)
            if count:
                log("  SEV", f"{col(sev, SEV_COLORS[sev]):<16} {count}", SEV_COLORS[sev])
