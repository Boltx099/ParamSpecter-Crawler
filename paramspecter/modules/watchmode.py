"""
modules/watchmode.py
Phase 2 — Continuous Watch Mode.

Stores scan history in SQLite, diffs each run against the previous,
and fires alerts (webhook / Telegram / email) only on NEW findings.
No external dependencies beyond the standard library.

Usage (from CLI):
    paramspecter https://target.com --watch --interval 24h
    paramspecter https://target.com --watch --interval 6h --notify-webhook https://hooks.slack.com/...
    paramspecter https://target.com --watch --interval 1h --notify-telegram --tg-token TOKEN --tg-chat CHAT_ID
"""

import hashlib
import json
import os
import smtplib
import sqlite3
import time
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import urlopen, Request

from ..utils import log, log_section, col, C


# -----------------------------------------------------------------
#  DATABASE
# -----------------------------------------------------------------
DB_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    finding_count INTEGER DEFAULT 0,
    meta        TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    fingerprint TEXT NOT NULL,
    source      TEXT,
    category    TEXT,
    severity    TEXT,
    title       TEXT,
    target      TEXT,
    detail      TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    is_new      INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""


def _fingerprint(finding: Dict) -> str:
    """Stable hash for a finding — used to detect duplicates across scans."""
    key = "|".join([
        finding.get("source", ""),
        finding.get("category", ""),
        finding.get("title", ""),
        finding.get("target", ""),
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class ScanDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._open()

    def _open(self):
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        log("WATCH", f"Database: {col(self.db_path, C.CYAN)}", C.CYAN)

    def start_scan(self, target: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (target, started_at, meta) VALUES (?,?,?)",
                (target, datetime.utcnow().isoformat(), "{}")
            )
            self._conn.commit()
            return cur.lastrowid

    def finish_scan(self, scan_id: int, finding_count: int, meta: Dict = None):
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET finished_at=?, finding_count=?, meta=? WHERE id=?",
                (datetime.utcnow().isoformat(), finding_count,
                 json.dumps(meta or {}), scan_id)
            )
            self._conn.commit()

    def get_known_fingerprints(self, target: str) -> set:
        """Return all fingerprints ever seen for this target."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT DISTINCT f.fingerprint
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE s.target = ?""",
                (target,)
            ).fetchall()
        return {r["fingerprint"] for r in rows}

    def save_findings(self, scan_id: int, findings: List[Dict],
                      known_fps: set) -> Tuple[List[Dict], List[Dict]]:
        """
        Persist findings. Returns (new_findings, seen_again_findings).
        """
        now = datetime.utcnow().isoformat()
        new_findings = []
        seen_again   = []

        with self._lock:
            for f in findings:
                fp = _fingerprint(f)
                is_new = fp not in known_fps
                self._conn.execute(
                    """INSERT INTO findings
                       (scan_id, fingerprint, source, category, severity,
                        title, target, detail, first_seen, last_seen, is_new)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, fp, f.get("source"), f.get("category"),
                     f.get("severity"), f.get("title"), f.get("target"),
                     f.get("detail"), now, now, 1 if is_new else 0)
                )
                if is_new:
                    new_findings.append({**f, "fingerprint": fp})
                else:
                    seen_again.append({**f, "fingerprint": fp})
            self._conn.commit()

        return new_findings, seen_again

    def get_scan_history(self, target: str, limit: int = 10) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM scans WHERE target=?
                   ORDER BY started_at DESC LIMIT ?""",
                (target, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        if self._conn:
            self._conn.close()


# -----------------------------------------------------------------
#  ALERTING
# -----------------------------------------------------------------

class AlertManager:
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        tg_token: Optional[str] = None,
        tg_chat_id: Optional[str] = None,
        smtp_host: Optional[str] = None,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        smtp_to: Optional[str] = None,
    ):
        self.webhook_url = webhook_url
        self.tg_token    = tg_token
        self.tg_chat_id  = tg_chat_id
        self.smtp_host   = smtp_host
        self.smtp_port   = smtp_port
        self.smtp_user   = smtp_user
        self.smtp_pass   = smtp_pass
        self.smtp_to     = smtp_to

    def _has_any(self) -> bool:
        return bool(self.webhook_url or (self.tg_token and self.tg_chat_id) or self.smtp_host)

    def send(self, target: str, new_findings: List[Dict]) -> None:
        if not new_findings or not self._has_any():
            return

        high = [f for f in new_findings if f.get("severity") in ("CRITICAL", "HIGH")]
        summary = (
            f"ParamSpecter — {len(new_findings)} NEW finding(s) on {target}\n"
            f"High/Critical: {len(high)}\n\n"
        )
        lines = []
        for f in new_findings[:15]:
            sev = f.get("severity", "?")
            lines.append(f"[{sev}] {f.get('title','?')}  →  {f.get('target','?')}")
        if len(new_findings) > 15:
            lines.append(f"... and {len(new_findings)-15} more")
        body = summary + "\n".join(lines)

        if self.webhook_url:
            self._send_webhook(body, target, new_findings)
        if self.tg_token and self.tg_chat_id:
            self._send_telegram(body)
        if self.smtp_host:
            self._send_email(body, target)

    def _send_webhook(self, body: str, target: str, findings: List[Dict]) -> None:
        """POST JSON to a generic webhook (Slack, Discord, custom)."""
        payload = json.dumps({
            "text": body,
            "target": target,
            "new_findings": len(findings),
            "high_critical": sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH")),
        }).encode()
        try:
            req = Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10):
                pass
            log("ALERT", col(f"Webhook sent → {self.webhook_url[:60]}", C.GREEN), C.GREEN)
        except Exception as e:
            log("ALERT", col(f"Webhook failed: {e}", C.RED), C.RED)

    def _send_telegram(self, body: str) -> None:
        """Send via Telegram Bot API."""
        api_url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        # Telegram has 4096 char limit
        text = body[:4000]
        payload = json.dumps({
            "chat_id": self.tg_chat_id,
            "text": text,
            "parse_mode": "HTML",
        }).encode()
        try:
            req = Request(api_url, data=payload,
                          headers={"Content-Type": "application/json"},
                          method="POST")
            with urlopen(req, timeout=10):
                pass
            log("ALERT", col("Telegram notification sent", C.GREEN), C.GREEN)
        except Exception as e:
            log("ALERT", col(f"Telegram failed: {e}", C.RED), C.RED)

    def _send_email(self, body: str, target: str) -> None:
        """Send via SMTP."""
        if not self.smtp_to:
            return
        try:
            msg = MIMEText(body)
            msg["Subject"] = f"[ParamSpecter] New findings on {target}"
            msg["From"]    = self.smtp_user or "paramspecter@localhost"
            msg["To"]      = self.smtp_to

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as s:
                s.ehlo()
                s.starttls()
                if self.smtp_user and self.smtp_pass:
                    s.login(self.smtp_user, self.smtp_pass)
                s.sendmail(msg["From"], [self.smtp_to], msg.as_string())
            log("ALERT", col(f"Email sent → {self.smtp_to}", C.GREEN), C.GREEN)
        except Exception as e:
            log("ALERT", col(f"Email failed: {e}", C.RED), C.RED)


# -----------------------------------------------------------------
#  INTERVAL PARSER
# -----------------------------------------------------------------
def parse_interval(s: str) -> int:
    """Parse '6h', '30m', '1d', '3600' → seconds."""
    s = s.strip().lower()
    if s.endswith("d"):
        return int(s[:-1]) * 86400
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)


# -----------------------------------------------------------------
#  WATCH LOOP
# -----------------------------------------------------------------
class WatchMode:
    """
    Runs a scan function on a schedule, persists results in SQLite,
    and fires alerts on new findings only.
    """

    def __init__(
        self,
        target: str,
        scan_fn,                     # callable() → List[Dict]  (unified findings)
        interval_s: int = 3600 * 24,
        db_path: Optional[str] = None,
        alert_manager: Optional[AlertManager] = None,
        output_dir: str = ".",
        stop_event: Optional[threading.Event] = None,
    ):
        self.target        = target
        self.scan_fn       = scan_fn
        self.interval_s    = interval_s
        self.alert_manager = alert_manager or AlertManager()
        self.stop_event    = stop_event or threading.Event()

        db_file = db_path or os.path.join(
            output_dir,
            f"paramspecter_watch_{urlparse(target).netloc.replace('.','_')}.db"
        )
        self.db = ScanDatabase(db_file)

    def _run_once(self) -> Tuple[int, int]:
        """Execute one scan cycle. Returns (total_findings, new_findings)."""
        log_section(f"WATCH SCAN — {self.target}")
        log("WATCH", f"Started at {col(datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'), C.CYAN)}", C.CYAN)

        scan_id = self.db.start_scan(self.target)
        known   = self.db.get_known_fingerprints(self.target)

        try:
            findings = self.scan_fn()
        except Exception as e:
            log("WATCH", col(f"Scan error: {e}", C.RED), C.RED)
            self.db.finish_scan(scan_id, 0, {"error": str(e)})
            return 0, 0

        new_findings, seen_again = self.db.save_findings(scan_id, findings, known)
        self.db.finish_scan(scan_id, len(findings), {
            "new": len(new_findings),
            "seen_again": len(seen_again),
        })

        # Print diff
        log_section("WATCH DIFF")
        if new_findings:
            log("DIFF", col(f"{len(new_findings)} NEW finding(s)!", C.RED + C.BOLD), C.RED)
            SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            SEV_COL   = {
                "CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
                "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.GRAY,
            }
            for f in sorted(new_findings, key=lambda x: SEV_ORDER.get(x.get("severity","INFO"), 4)):
                sev = f.get("severity", "?")
                log(
                    f"  NEW [{sev}]",
                    f"{col(f.get('title','?'), SEV_COL.get(sev, C.WHITE))}  "
                    f"→  {col(f.get('target','?'), C.CYAN)}",
                    SEV_COL.get(sev, C.WHITE),
                )
        else:
            log("DIFF", col("No new findings since last scan.", C.GREEN), C.GREEN)

        log("DIFF", f"{col(len(seen_again), C.GRAY)} previously known finding(s) unchanged", C.GRAY)

        # Send alerts
        if new_findings:
            self.alert_manager.send(self.target, new_findings)

        return len(findings), len(new_findings)

    def run(self) -> None:
        """Block and run the watch loop until stop_event is set."""
        log_section("WATCH MODE ACTIVE")
        interval_human = _human_interval(self.interval_s)
        log("WATCH", f"Target:   {col(self.target, C.CYAN)}", C.CYAN)
        log("WATCH", f"Interval: {col(interval_human, C.YELLOW)}", C.YELLOW)
        log("WATCH", "Press Ctrl+C to stop.", C.GRAY)

        cycle = 0
        while not self.stop_event.is_set():
            cycle += 1
            log("WATCH", f"Starting cycle #{cycle}", C.WHITE)
            total, new = self._run_once()
            log("WATCH",
                f"Cycle #{cycle} done — "
                f"{col(total, C.BOLD)} total findings, "
                f"{col(new, C.RED+C.BOLD if new else C.BOLD)} new",
                C.WHITE)

            if self.stop_event.is_set():
                break

            next_run = datetime.utcnow() + timedelta(seconds=self.interval_s)
            log("WATCH",
                f"Next scan at {col(next_run.strftime('%Y-%m-%d %H:%M UTC'), C.CYAN)} "
                f"(in {col(_human_interval(self.interval_s), C.YELLOW)})",
                C.GRAY)

            # Sleep in small chunks so Ctrl+C is responsive
            deadline = time.monotonic() + self.interval_s
            while not self.stop_event.is_set() and time.monotonic() < deadline:
                time.sleep(min(5, deadline - time.monotonic()))

        self.db.close()
        log("WATCH", col("Watch mode stopped.", C.YELLOW), C.YELLOW)


def _human_interval(seconds: int) -> str:
    if seconds >= 86400:
        return f"{seconds // 86400}d"
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    if seconds >= 60:
        return f"{seconds // 60}m"
    return f"{seconds}s"
