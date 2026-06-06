"""
modules/confidence.py
Finding Confidence Scoring Engine.

Assigns a 0–100 confidence score to every DeepFuzz + OOB finding
so hunters can triage HIGH-confidence bugs first and ignore likely
false positives without wasting time.

Scoring philosophy:
  - Start at a check-specific base (not every check has the same FP rate)
  - Add evidence bonuses (hard indicators that can't be coincidental)
  - Subtract FP penalties (generic errors, tiny bodies, WAF interference)
  - OOB callbacks are always 90+ (DNS doesn't lie)
  - Clamp to [0, 100]

Each scorer is a pure function:
    score(payload, resp, elapsed_s, evidence, context) -> int

so they're testable in isolation and easy to extend.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# -----------------------------------------------------------------
#  RESULT SCHEMA
# -----------------------------------------------------------------
@dataclass
class ScoredFinding:
    """A deep-fuzz finding decorated with a confidence score."""
    # Original finding dict (from param_hits / deep_hits)
    finding:        Dict[str, Any]

    # Confidence score 0-100
    confidence:     int = 50

    # Human-readable breakdown of why this score was assigned
    score_reasons:  List[str] = field(default_factory=list)

    # Label: CONFIRMED / LIKELY / POSSIBLE / LOW-CONFIDENCE / NOISE
    label:          str = "POSSIBLE"

    @property
    def check(self) -> str:
        return self.finding.get("check", "?")

    @property
    def severity(self) -> str:
        return self.finding.get("severity", "MEDIUM")

    @property
    def is_oob(self) -> bool:
        return bool(self.finding.get("oob", False))

    def display_label(self) -> str:
        colors = {
            "CONFIRMED":      "\033[91m\033[1m",   # red bold
            "LIKELY":         "\033[93m\033[1m",   # yellow bold
            "POSSIBLE":       "\033[96m",           # cyan
            "LOW-CONFIDENCE": "\033[90m",           # gray
            "NOISE":          "\033[90m",           # gray
        }
        reset = "\033[0m"
        c = colors.get(self.label, "")
        return f"{c}[{self.confidence}% {self.label}]{reset}"


def _label_for_score(score: int) -> str:
    if score >= 85:  return "CONFIRMED"
    if score >= 65:  return "LIKELY"
    if score >= 40:  return "POSSIBLE"
    if score >= 20:  return "LOW-CONFIDENCE"
    return "NOISE"


# -----------------------------------------------------------------
#  GENERIC PENALTIES (apply to all checks)
# -----------------------------------------------------------------
def _generic_penalties(resp, elapsed_s: float,
                       evidence: str) -> Tuple[int, List[str]]:
    """
    Penalties that indicate a false positive regardless of check type.
    Returns (penalty_points, reasons).
    """
    penalties = 0
    reasons: List[str] = []

    if resp is None:
        return 30, ["no response received"]

    body = ""
    try:
        body = resp.text or ""
    except Exception:
        pass

    body_len = len(body)

    # Extremely short body — often a WAF block or 0-byte error
    if body_len < 50:
        penalties += 15
        reasons.append(f"tiny response body ({body_len}B)")

    # Generic 500 without error keywords
    if resp.status_code == 500 and not re.search(
        r"sql|syntax|mysql|ora-|pg_|sqlite|query|database", body, re.I
    ):
        penalties += 10
        reasons.append("generic 500 (no DB error keywords)")

    # WAF block signatures
    if re.search(
        r"access denied|blocked by|security policy|firewall|waf|"
        r"request blocked|forbidden.*security|illegal request",
        body[:2000], re.I
    ):
        penalties += 20
        reasons.append("WAF/security block page detected")

    # Cloudflare challenge
    if re.search(r"cf-ray|checking your browser|ddos protection", body[:2000], re.I):
        penalties += 25
        reasons.append("Cloudflare challenge page")

    # Empty evidence string
    if not evidence or evidence == "":
        penalties += 10
        reasons.append("no evidence string")

    return penalties, reasons


# -----------------------------------------------------------------
#  PER-CHECK SCORERS
# -----------------------------------------------------------------

class _SQLiScorer:
    BASE        = 35
    # Hard evidence patterns — unambiguous DB error strings
    _DB_ERRORS  = re.compile(
        r"sql syntax|syntax error|mysql_fetch|ora-\d{4,5}|pg_query|"
        r"unclosed quotation|sqlite_|microsoft ole db|division by zero|"
        r"invalid query|pdoexception|jdbc|sqlstate\[|quoted string not properly terminated|"
        r"odbc.*error|warning.*mysql|db2 sql error|supplied argument is not a valid.*mysql",
        re.I,
    )
    _SLEEP_RE   = re.compile(r"sleep\s*\(|pg_sleep|waitfor\s+delay", re.I)
    _STACK_TRACE = re.compile(r"at com\.|at org\.|at java\.|at net\.|stack trace:|traceback", re.I)

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str, baseline_time: float = 0.0) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        body = ""
        try:
            body = resp.text or ""
        except Exception:
            pass

        # Strong: DB error keyword match
        m = self._DB_ERRORS.search(body)
        if m:
            score += 35
            snippet = body[max(0, m.start()-20):m.end()+30].replace("\n", " ").strip()[:80]
            reasons.append(f"DB error keyword: '{snippet}'")

        # Strong: time-based with meaningful delta over baseline
        if self._SLEEP_RE.search(payload):
            delta = elapsed_s - baseline_time
            if elapsed_s >= 3.0 and delta >= 2.5:
                score += 30
                reasons.append(f"time delay: {elapsed_s:.1f}s (baseline {baseline_time:.1f}s, Δ+{delta:.1f}s)")
            elif elapsed_s >= 5.0:
                score += 20
                reasons.append(f"response slow ({elapsed_s:.1f}s) but baseline unknown")

        # Moderate: stack trace leaked
        if self._STACK_TRACE.search(body):
            score += 15
            reasons.append("stack trace in response")

        # Moderate: different status code than baseline
        if resp.status_code == 500:
            score += 10
            reasons.append("HTTP 500 triggered")

        # Weak: response size significantly different
        # (handled by caller via size_diff field)

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _XSSScorer:
    BASE = 40

    _UNENCODED_SCRIPT = re.compile(r"<script[^>]*>.*?alert\s*\(", re.I | re.S)
    _EVENT_HANDLER    = re.compile(r"on(?:load|error|click|mouseover|focus)\s*=\s*alert\s*\(", re.I)
    _ENCODED_RE       = re.compile(r"&(?:lt|gt|amp|quot);|&#\d+;|\\u003[ce]", re.I)

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        body = ""
        try:
            body = resp.text or ""
        except Exception:
            pass

        # Strongest: unencoded <script>alert executed
        if self._UNENCODED_SCRIPT.search(body):
            score += 40
            reasons.append("unencoded <script>alert() reflected in response")

        # Strong: event handler survived
        elif self._EVENT_HANDLER.search(body):
            score += 30
            reasons.append("event handler with alert() reflected")

        # Moderate: payload partially reflected (check not fully encoded)
        elif "alert(1)" in body and not self._ENCODED_RE.search(
            body[max(0, body.find("alert(1)")-30):body.find("alert(1)")+40]
        ):
            score += 20
            reasons.append("alert(1) reflected without HTML encoding")

        # Penalty: payload was HTML-entity encoded (output-escaped, not exploitable)
        if "<script>" in payload and "&lt;script&gt;" in body:
            score -= 25
            reasons.append("payload HTML-entity encoded (likely safe)")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _PathTraversalScorer:
    BASE = 40
    _UNIX_FILE = re.compile(
        r"root:.*:/bin/(?:bash|sh|nologin|false)|daemon:x:\d+|nobody:x:\d+",
        re.I,
    )
    _WIN_FILE  = re.compile(r"\[boot loader\]|\[extensions\]|for 16-bit app support", re.I)

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        body = ""
        try:
            body = resp.text or ""
        except Exception:
            pass

        if self._UNIX_FILE.search(body):
            score += 50
            reasons.append("/etc/passwd content in response — definite path traversal")
        elif self._WIN_FILE.search(body):
            score += 50
            reasons.append("win.ini content in response — definite path traversal")
        elif len(body) > 100 and resp.status_code == 200:
            score += 10
            reasons.append("200 OK with content (may need manual verification)")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _SSRFScorer:
    BASE = 35
    _CLOUD_META = re.compile(
        r"ami-[0-9a-f]{8,17}|instance-id|placement/availability-zone|"
        r"iam/security-credentials|computeMetadata|\"compute\":\s*\{|"
        r"169\.254\.169\.254|metadata\.google\.internal",
        re.I,
    )
    _INTERNAL_IP = re.compile(
        r"\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"
    )

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        body = ""
        try:
            body = resp.text or ""
        except Exception:
            pass

        if self._CLOUD_META.search(body):
            score += 50
            reasons.append("cloud metadata content in response — confirmed SSRF")
        elif self._INTERNAL_IP.search(body):
            score += 25
            reasons.append("internal IP address in response")
        elif resp.status_code == 200 and len(body) > 50:
            score += 10
            reasons.append("unexpected 200 response with content")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _OpenRedirectScorer:
    BASE       = 45
    _EVIL_HOST = "evil.paramspecter.test"

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        loc = resp.headers.get("Location", "") if resp else ""

        if self._EVIL_HOST in loc:
            score += 45
            reasons.append(f"Location header redirects to canary host: {loc[:80]}")
        elif self._EVIL_HOST in (getattr(resp, "text", "") or "")[:3000]:
            score += 25
            reasons.append("canary host reflected in response body")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _IDORScorer:
    BASE = 30
    _OWNER_FIELDS = re.compile(
        r'"(?:user(?:name|_?id)?|email|account|owner|author)"\s*:\s*"([^"]{3,})"',
        re.I,
    )

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str, baseline_size: int = 0) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        body = ""
        try:
            body = resp.text or ""
        except Exception:
            pass

        size_delta = abs(len(resp.content) - baseline_size) if baseline_size else 0

        # Different record returned
        if resp.status_code == 200 and size_delta > 200:
            score += 20
            reasons.append(f"response size changed by {size_delta}B — different record likely")

        # Owner field in response
        m = self._OWNER_FIELDS.search(body)
        if m:
            score += 20
            reasons.append(f"owner field in response: {m.group(1)[:40]}")

        # Status code changed to 200 (was 403/404)
        if resp.status_code == 200 and "status_changed" in evidence:
            score += 25
            reasons.append("status changed to 200 for adjacent ID")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _CORSScorer:
    BASE = 50

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if "evil.paramspecter.test" in acao:
            score += 35
            reasons.append(f"evil origin reflected in ACAO: {acao}")
            if acac.lower() == "true":
                score += 10
                reasons.append("ACAC: true — credentials exposed")
        elif acao == "*" and acac.lower() == "true":
            score += 30
            reasons.append("wildcard ACAO + credentials = exploitable misconfiguration")
        elif acao == "null":
            score += 15
            reasons.append("ACAO: null — sandboxed iframe attack possible")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _HeaderInjectionScorer:
    BASE = 35

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        # CRLF: injected header appeared in response headers
        if "X-Injected-Header" in (resp.headers if resp else {}):
            score += 50
            reasons.append("CRLF injection: X-Injected-Header appeared in response headers")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


class _GraphQLScorer:
    BASE = 45

    def score(self, payload: str, resp, elapsed_s: float,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if resp is None:
            return 10, ["no response"]

        body = ""
        try:
            body = resp.text or ""
        except Exception:
            pass

        if '"__schema"' in body:
            score += 40
            reasons.append("GraphQL introspection schema returned — fully enabled")
        elif '"errors"' in body and '"message"' in body:
            score += 15
            reasons.append("GraphQL error response — endpoint confirmed")

        pen, pen_reasons = _generic_penalties(resp, elapsed_s, evidence)
        score -= pen
        reasons.extend(pen_reasons)

        return max(0, min(100, score)), reasons


# OOB is always high confidence — DNS doesn't lie
class _OOBScorer:
    BASE = 85

    def score(self, interaction_type: str, remote_address: str,
              evidence: str) -> Tuple[int, List[str]]:
        score   = self.BASE
        reasons = []

        if interaction_type == "dns":
            score += 10
            reasons.append(f"DNS callback confirmed from {remote_address or 'unknown'}")
        elif interaction_type == "http":
            score += 12
            reasons.append(f"HTTP callback confirmed from {remote_address or 'unknown'}")
        elif interaction_type in ("smtp", "ftp"):
            score += 8
            reasons.append(f"{interaction_type.upper()} callback confirmed")

        # Cap at 97 — we're not infallible
        return min(97, score), reasons


# -----------------------------------------------------------------
#  SCORER REGISTRY
# -----------------------------------------------------------------
_SCORERS = {
    "SQLi":            _SQLiScorer(),
    "XSS":             _XSSScorer(),
    "PathTraversal":   _PathTraversalScorer(),
    "SSRF":            _SSRFScorer(),
    "OpenRedirect":    _OpenRedirectScorer(),
    "IDOR":            _IDORScorer(),
    "CORS":            _CORSScorer(),
    "HeaderInjection": _HeaderInjectionScorer(),
    "GraphQL":         _GraphQLScorer(),
    # OOB checks
    "BlindSQLi":       None,   # uses OOBScorer
    "BlindSSRF":       None,
    "BlindXXE":        None,
    "BlindCMDi":       None,
    "BlindXSS":        None,
    "Log4Shell":       None,
    "BlindSSTI":       None,
}
_OOB_SCORER = _OOBScorer()


# -----------------------------------------------------------------
#  PUBLIC API
# -----------------------------------------------------------------
def score_finding(hit: Dict[str, Any],
                  resp=None,
                  elapsed_s: float = 0.0,
                  baseline_time: float = 0.0,
                  baseline_size: int = 0) -> ScoredFinding:
    """
    Score a single finding dict (from param_hits / deep_hits / oob hits).

    Args:
        hit:            The finding dict (must have "check", "payload", "evidence").
        resp:           The HTTP response object (may be None for OOB/blind).
        elapsed_s:      How long the request took.
        baseline_time:  Baseline response time (for time-based SQLi).
        baseline_size:  Baseline response size (for IDOR delta).

    Returns:
        ScoredFinding with confidence + label populated.
    """
    check    = hit.get("check", "?")
    payload  = hit.get("payload", "")
    evidence = hit.get("evidence", "")

    # OOB findings — use OOB scorer
    if hit.get("oob"):
        itype   = hit.get("interaction_type", "dns")
        raddr   = hit.get("remote_address", "")
        raw_score, reasons = _OOB_SCORER.score(itype, raddr, evidence)
        scored = ScoredFinding(
            finding=hit, confidence=raw_score, score_reasons=reasons,
            label=_label_for_score(raw_score),
        )
        return scored

    scorer = _SCORERS.get(check)
    if scorer is None:
        # Unknown check — generic score
        raw_score = 40
        reasons   = [f"unknown check type '{check}' — generic baseline score"]
    elif isinstance(scorer, _SQLiScorer):
        raw_score, reasons = scorer.score(payload, resp, elapsed_s, evidence, baseline_time)
    elif isinstance(scorer, _IDORScorer):
        raw_score, reasons = scorer.score(payload, resp, elapsed_s, evidence, baseline_size)
    else:
        raw_score, reasons = scorer.score(payload, resp, elapsed_s, evidence)

    label = _label_for_score(raw_score)
    return ScoredFinding(
        finding=hit, confidence=raw_score,
        score_reasons=reasons, label=label,
    )


def score_all(hits: List[Dict[str, Any]],
              resp_map: Optional[Dict[str, Any]] = None,
              baseline_time: float = 0.0,
              baseline_size: int = 0) -> List[ScoredFinding]:
    """
    Score a list of findings.

    resp_map: optional dict keyed by (check, param, payload[:40]) → resp object
    """
    resp_map = resp_map or {}
    scored = []
    for hit in hits:
        key  = (hit.get("check", ""), hit.get("param", ""), str(hit.get("payload", ""))[:40])
        resp = resp_map.get(key)
        scored.append(score_finding(
            hit, resp=resp,
            baseline_time=baseline_time,
            baseline_size=baseline_size,
        ))
    return sorted(scored, key=lambda s: -s.confidence)


def filter_noise(findings: List[ScoredFinding],
                 min_confidence: int = 20) -> List[ScoredFinding]:
    """Drop findings below the minimum confidence threshold."""
    return [f for f in findings if f.confidence >= min_confidence]


def enrich_hit(hit: Dict[str, Any], scored: ScoredFinding) -> Dict[str, Any]:
    """
    Add confidence fields to an existing hit dict in-place.
    Returns the mutated dict for chaining.
    """
    hit["confidence"]    = scored.confidence
    hit["conf_label"]    = scored.label
    hit["conf_reasons"]  = scored.score_reasons
    return hit
