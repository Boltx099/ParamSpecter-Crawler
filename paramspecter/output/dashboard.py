"""
output/dashboard.py
Live terminal dashboard — real-time scan stats using curses.

While the curses UI is active, normal log() output is suppressed
and buffered. When the dashboard stops, all buffered messages are
flushed to the terminal so nothing is lost.
"""

import sys
import threading
import time
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.crawler import ParamSpecter

try:
    import curses
    _CURSES_OK = True
except ImportError:
    _CURSES_OK = False


# ─────────────────────────────────────────────────────────────────
#  FALLBACK — plain status line (no curses)
# ─────────────────────────────────────────────────────────────────

class _FallbackDashboard:
    def __init__(self, scanner):
        self.scanner = scanner
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self): self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        sys.stderr.write("\r" + " " * 80 + "\r")
        sys.stderr.flush()

    def add_finding(self, severity, label, target): pass

    def _loop(self):
        while not self._stop.is_set():
            s = self.scanner.stats
            line = (
                f"\r[{s.elapsed()}] "
                f"crawled={s.pages_crawled} "
                f"queue={self.scanner.crawl_queue.qsize()} "
                f"params={len(self.scanner.all_params)} "
                f"secrets={len(self.scanner.all_secrets)} "
                f"hits={len(self.scanner.param_hits)+len(self.scanner.dir_hits)} "
                f"rps={s.avg_rps()}   "
            )
            sys.stderr.write(line)
            sys.stderr.flush()
            self._stop.wait(2)


# ─────────────────────────────────────────────────────────────────
#  CURSES DASHBOARD
# ─────────────────────────────────────────────────────────────────

class _CursesDashboard:
    REFRESH_HZ = 4

    def __init__(self, scanner):
        self.scanner         = scanner
        self._stop           = threading.Event()
        self._thread         = threading.Thread(target=self._run, daemon=True)
        self._stdscr         = None
        self._findings_lock  = threading.Lock()
        self._findings       = []

    def start(self):
        # Suppress normal log output while dashboard owns the terminal
        import paramspecter.utils.helpers as _h
        _h._log_suppress = True
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)
        # Restore logging and flush buffered messages
        import paramspecter.utils.helpers as _h
        _h._log_suppress = False
        if _h._log_buffer:
            print()  # blank line after dashboard
            for line in _h._log_buffer:
                print(line)
            _h._log_buffer.clear()

    def add_finding(self, severity: str, label: str, target: str):
        with self._findings_lock:
            self._findings.append((severity, label, target[:60]))
            if len(self._findings) > 50:
                self._findings.pop(0)

    def _run(self):
        try:
            curses.wrapper(self._main_loop)
        except Exception:
            # If curses fails mid-run, restore logging immediately
            import paramspecter.utils.helpers as _h
            _h._log_suppress = False

    def _main_loop(self, stdscr):
        self._stdscr = stdscr
        curses.curs_set(0)
        stdscr.nodelay(True)
        curses.start_color()
        curses.use_default_colors()

        curses.init_pair(1, curses.COLOR_RED,     -1)
        curses.init_pair(2, curses.COLOR_YELLOW,  -1)
        curses.init_pair(3, curses.COLOR_CYAN,    -1)
        curses.init_pair(4, curses.COLOR_GREEN,   -1)
        curses.init_pair(5, curses.COLOR_WHITE,   -1)
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)
        curses.init_pair(7, curses.COLOR_BLACK,   curses.COLOR_CYAN)
        curses.init_pair(8, curses.COLOR_BLACK,   curses.COLOR_GREEN)

        RED     = curses.color_pair(1) | curses.A_BOLD
        YELLOW  = curses.color_pair(2)
        CYAN    = curses.color_pair(3)
        GREEN   = curses.color_pair(4)
        WHITE   = curses.color_pair(5)
        MAGENTA = curses.color_pair(6)
        HEADER  = curses.color_pair(7) | curses.A_BOLD
        SECHEAD = curses.color_pair(8) | curses.A_BOLD

        interval = 1.0 / self.REFRESH_HZ

        while not self._stop.is_set():
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                s    = self.scanner

                def add(row, col_x, text, attr):
                    if row >= h or col_x >= w:
                        return
                    try:
                        stdscr.addstr(row, col_x, str(text)[:w - col_x], attr)
                    except curses.error:
                        pass

                # Header
                title = f" ParamSpecter v7.1  |  {s.start_url} "
                add(0, 0, title.ljust(w)[:w], HEADER)

                # Row 1 — timing
                add(1, 2,  "Elapsed : ", CYAN)
                add(1, 12, s.stats.elapsed(),      GREEN | curses.A_BOLD)
                add(1, 24, "Requests : ", CYAN)
                add(1, 35, str(s.stats.requests_sent), WHITE)
                add(1, 44, "RPS : ", CYAN)
                add(1, 50, s.stats.avg_rps(),      GREEN)
                add(1, 58, "Mode : ", CYAN)
                add(1, 65, s.mode.upper(),         YELLOW | curses.A_BOLD)

                # Row 2 — crawl
                queue_sz = s.crawl_queue.qsize()
                add(2, 2,  "Crawled : ", CYAN)
                add(2, 12, str(s.stats.pages_crawled), GREEN | curses.A_BOLD)
                add(2, 22, "Queue : ", CYAN)
                add(2, 30, str(queue_sz), YELLOW if queue_sz > 0 else WHITE)
                add(2, 38, "Failed : ", CYAN)
                add(2, 47, str(s.stats.pages_failed),
                    RED if s.stats.pages_failed > 0 else WHITE)

                # Divider
                try:
                    stdscr.addstr(3, 0, "─" * min(w - 1, 80), CYAN)
                except curses.error:
                    pass

                # Row 4-5 — counters grid
                counters = [
                    ("Params",     len(s.all_params),              WHITE),
                    ("Emails",     len(s.all_emails),               WHITE),
                    ("Forms",      s.all_forms,                     WHITE),
                    ("Subdomains", len(s.subdomain_hits),           CYAN),
                    ("Dir Hits",   len(s.dir_hits),                 YELLOW if s.dir_hits   else WHITE),
                    ("Param Hits", len(s.param_hits),               RED    if s.param_hits else WHITE),
                    ("Secrets",    len(s.all_secrets),              MAGENTA if s.all_secrets else WHITE),
                    ("Techs",      len(s.all_techs),                GREEN),
                    ("Links",      s.stats.links_found,             WHITE),
                    ("OpenAPI",    len(s.all_openapi),              CYAN if s.all_openapi else WHITE),
                ]
                col_w = max(1, (w - 2) // 5)
                for i, (label, val, clr) in enumerate(counters):
                    r = 4 + (i // 5)
                    c = (i % 5) * col_w + 2
                    add(r, c, f"{label}: ", CYAN)
                    add(r, c + len(label) + 2, str(val), clr)

                # Divider
                try:
                    stdscr.addstr(6, 0, "─" * min(w - 1, 80), CYAN)
                except curses.error:
                    pass

                # Techs / WAFs
                add(7, 2, "Techs : ", CYAN)
                add(7, 10, (", ".join(list(s.all_techs)[:6]) or "detecting...")[:w-12], GREEN)
                add(8, 2, "WAFs  : ", CYAN)
                add(8, 10, (", ".join(list(s.all_wafs)[:4]) or "none detected")[:w-12],
                    YELLOW if s.all_wafs else WHITE)

                # Divider
                try:
                    stdscr.addstr(9, 0, "─" * min(w - 1, 80), CYAN)
                except curses.error:
                    pass

                # Live findings feed
                add(10, 0, " LIVE FINDINGS ".center(min(w - 1, 80), "─"), SECHEAD)
                max_rows = h - 13
                with self._findings_lock:
                    recent = list(reversed(self._findings[-max(1, max_rows):]))

                SEV_CLR = {
                    "CRITICAL": RED, "HIGH": RED,
                    "MEDIUM": YELLOW, "LOW": CYAN,
                }
                for i, (sev, label, target) in enumerate(recent):
                    if 11 + i >= h - 2:
                        break
                    sc = SEV_CLR.get(sev, WHITE)
                    add(11 + i, 0,  f" [{sev[:4]}] ", sc)
                    add(11 + i, 9,  f"{label[:28]:<28} {target}"[:w - 10], WHITE)

                if not recent:
                    add(11, 2, "No findings yet — scan in progress...", CYAN)

                # Footer
                add(h - 1, 0, " Q=quit dashboard  R=clear findings  (scan continues) ".ljust(w)[:w], HEADER)

                key = stdscr.getch()
                if key in (ord('q'), ord('Q')):
                    self._stop.set()
                    break
                elif key in (ord('r'), ord('R')):
                    with self._findings_lock:
                        self._findings.clear()

                stdscr.refresh()

            except curses.error:
                pass

            self._stop.wait(interval)


# ─────────────────────────────────────────────────────────────────
#  PUBLIC FACTORY
# ─────────────────────────────────────────────────────────────────

def Dashboard(scanner):
    if _CURSES_OK and sys.stdout.isatty():
        return _CursesDashboard(scanner)
    return _FallbackDashboard(scanner)
