"""
modules/session_health.py
Session Health Monitor — keeps authenticated scans alive.

Problem it solves:
  Pentest targets use JWTs with 15-min expiry, rolling CSRF tokens,
  Laravel sessions that time out, or Cloudflare Access cookies that
  rotate. When the session dies mid-crawl, the crawler goes silent:
  every page returns a 200 with a login form, params disappear,
  and the whole scan is wasted.

How it works:
  1.  After login, we learn what "healthy" looks like:
        - Auth indicator strings that appear ONLY when logged in
          (e.g. "logout", "dashboard", "my account", avatar URL)
        - Cookies that should be present (session_id, jwt, etc.)
        - HTTP status codes that would indicate auth failure (401, 403)

  2.  Every N pages a lightweight health check fires:
        - GET the check_url (default: the original login page or a
          known-authenticated endpoint the user provides)
        - Verify auth_indicators appear in the response
        - Verify expected_cookies are still in the session jar

  3.  If unhealthy:
        - Pause worker queue briefly (don't lose queued URLs)
        - Re-run the FormLoginHandler.login() flow
        - Wait for confirmation, then resume
        - Track heal attempts — give up after max_heal_attempts

  4.  Integrates with the crawler via a simple hook:
        health.tick(resp, url, pages_crawled)
      called from _crawl_worker after every successful response.

Usage:
    monitor = SessionHealthMonitor.from_args(args, session, login_handler)
    # in _crawl_worker, after getting resp:
    if monitor:
        monitor.tick(resp, url, self.stats.pages_crawled)
"""

import re
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set

from ..utils import log, vlog, col, C
from ..utils.http import fetch_with_retry


# How many pages between health checks (configurable per-instance)
_DEFAULT_CHECK_INTERVAL = 20

# Maximum heal attempts before giving up and flagging the scan
_DEFAULT_MAX_HEALS = 5

# Seconds to sleep between heal retry attempts
_HEAL_RETRY_SLEEP = 3.0


@dataclass
class HealthStatus:
    """Current health state of the session."""
    healthy:          bool  = True
    last_check_page:  int   = 0
    heal_count:       int   = 0
    total_checks:     int   = 0
    last_heal_at:     float = 0.0
    failed_checks:    int   = 0
    gave_up:          bool  = False


class SessionHealthMonitor:
    """
    Monitors authentication health throughout a crawl and
    automatically re-authenticates when the session expires.

    Thread-safe — designed to be called from multiple crawl workers.
    """

    def __init__(
        self,
        session,
        login_handler,
        check_url:          str,
        auth_indicators:    List[str],
        expected_cookies:   List[str]     = None,
        fail_status_codes:  Set[int]      = None,
        check_interval:     int           = _DEFAULT_CHECK_INTERVAL,
        max_heal_attempts:  int           = _DEFAULT_MAX_HEALS,
        timeout:            int           = 10,
    ):
        """
        Args:
            session:            The requests.Session used by the crawler.
            login_handler:      FormLoginHandler instance (pre-configured).
            check_url:          URL to GET to verify auth health.
                                Use a page that requires login to show meaningful content.
            auth_indicators:    Strings that MUST appear in check_url response
                                when authenticated (e.g. ["logout", "Welcome,"]).
                                Case-insensitive. At least one must match.
            expected_cookies:   Cookie names that must be present in session jar.
                                If empty, cookie check is skipped.
            fail_status_codes:  HTTP status codes that mean auth failed.
                                Default: {401, 403}.
            check_interval:     Check health every N pages crawled.
            max_heal_attempts:  Give up after this many re-login failures.
            timeout:            HTTP timeout for health check requests.
        """
        self._session            = session
        self._login_handler      = login_handler
        self._check_url          = check_url
        self._auth_indicators    = [ind.lower() for ind in (auth_indicators or [])]
        self._expected_cookies   = list(expected_cookies or [])
        self._fail_codes         = fail_status_codes or {401, 403}
        self._check_interval     = check_interval
        self._max_heals          = max_heal_attempts
        self._timeout            = timeout

        # Compile auth indicator patterns for fast matching
        self._indicator_re = re.compile(
            "|".join(re.escape(ind) for ind in self._auth_indicators),
            re.I,
        ) if self._auth_indicators else None

        self.status   = HealthStatus()
        self._lock    = threading.Lock()
        self._healing = threading.Event()  # set while a heal is in progress

        log("HEALTH",
            f"Session monitor active — "
            f"check every {col(check_interval, C.BOLD)} pages  "
            f"indicators: {col(len(self._auth_indicators), C.BOLD)}  "
            f"cookies: {col(len(self._expected_cookies), C.BOLD)}",
            C.CYAN)

    # ------------------------------------------------------------------
    #  Public interface
    # ------------------------------------------------------------------
    def tick(self, resp, url: str, pages_crawled: int) -> bool:
        """
        Called by _crawl_worker after every response.

        Does a full health check every `check_interval` pages.
        If another worker is already healing, this call blocks
        until the heal completes (so we don't fire two logins at once).

        Returns True if the session is healthy after the tick.
        """
        if self.status.gave_up:
            return False

        # Block if a heal is in progress
        if self._healing.is_set():
            self._healing.wait(timeout=30)

        # Opportunistic quick check from the response we already have
        if resp is not None:
            if resp.status_code in self._fail_codes:
                log("HEALTH",
                    col(f"Auth failure detected via {resp.status_code} on {url[:60]}", C.YELLOW),
                    C.YELLOW)
                return self._maybe_heal(pages_crawled)

        # Periodic deep check
        with self._lock:
            due = (pages_crawled - self.status.last_check_page) >= self._check_interval
        if not due:
            return True

        with self._lock:
            # Double-check under lock (another thread may have just checked)
            if (pages_crawled - self.status.last_check_page) < self._check_interval:
                return True
            self.status.last_check_page = pages_crawled
            self.status.total_checks   += 1

        healthy = self._deep_check()
        if not healthy:
            return self._maybe_heal(pages_crawled)

        return True

    def is_healthy(self) -> bool:
        """Synchronous health check — returns True/False immediately."""
        return self._deep_check()

    def force_heal(self) -> bool:
        """Force a re-login regardless of current health state."""
        return self._heal()

    # ------------------------------------------------------------------
    #  Internal
    # ------------------------------------------------------------------
    def _deep_check(self) -> bool:
        """
        Perform a full health check:
          1. GET check_url and look for auth indicators
          2. Verify expected cookies are present
        Returns True if healthy.
        """
        try:
            resp, _ = fetch_with_retry(
                self._session, self._check_url,
                timeout=self._timeout, max_retries=1,
            )
        except Exception as e:
            vlog("HEALTH", col(f"Health check fetch failed: {e}", C.YELLOW), C.YELLOW)
            return True  # Network error ≠ auth failure — don't trigger heal

        if resp is None:
            return True  # Network error — don't trigger heal

        # Status code check
        if resp.status_code in self._fail_codes:
            log("HEALTH",
                col(f"Deep check: HTTP {resp.status_code} on check URL — session dead", C.RED),
                C.RED)
            return False

        # Auth indicator check
        if self._indicator_re:
            body = ""
            try:
                body = resp.text or ""
            except Exception:
                pass
            if not self._indicator_re.search(body):
                log("HEALTH",
                    col(f"Deep check: auth indicators not found in response "
                        f"(status {resp.status_code}) — session likely expired", C.YELLOW),
                    C.YELLOW)
                # Log a snippet to help the user tune their indicators
                snippet = body[:200].replace("\n", " ").strip()
                vlog("HEALTH",
                     col(f"Response snippet: {snippet[:120]}", C.GRAY), C.GRAY)
                return False

        # Cookie check
        if self._expected_cookies:
            jar_names = {c.name for c in self._session.cookies}
            missing   = [c for c in self._expected_cookies if c not in jar_names]
            if missing:
                log("HEALTH",
                    col(f"Deep check: expected cookies missing: {missing}", C.YELLOW),
                    C.YELLOW)
                return False

        vlog("HEALTH", col(f"Session healthy (page {self.status.last_check_page})", C.GREEN), C.GREEN)
        return True

    def _maybe_heal(self, pages_crawled: int) -> bool:
        """
        Attempt a heal if one isn't already in progress.
        Only one thread heals at a time; others wait.
        """
        # If another thread is already healing, wait for it
        if self._healing.is_set():
            self._healing.wait(timeout=30)
            return self.status.healthy

        with self._lock:
            if self.status.gave_up:
                return False
            if self.status.heal_count >= self._max_heals:
                log("HEALTH",
                    col(f"⚠  Max heal attempts ({self._max_heals}) reached — "
                        f"scan continues but auth may be broken", C.RED + C.BOLD),
                    C.RED)
                self.status.gave_up = True
                return False
            # Mark healing in progress
            self._healing.set()

        success = self._heal()

        with self._lock:
            self.status.healthy    = success
            self.status.heal_count += 1
            self.status.last_heal_at = time.monotonic()
            if not success:
                self.status.failed_checks += 1
            self._healing.clear()

        return success

    def _heal(self) -> bool:
        """
        Re-run the login flow and verify it worked.
        Returns True if the new session is healthy.
        """
        log("HEALTH",
            col(f"Session expired — re-authenticating "
                f"(attempt {self.status.heal_count + 1}/{self._max_heals})",
                C.YELLOW + C.BOLD),
            C.YELLOW)

        for attempt in range(1, 4):   # up to 3 login retries per heal event
            try:
                self._login_handler.login()
                time.sleep(_HEAL_RETRY_SLEEP)

                # Verify the new session works
                if self._deep_check():
                    log("HEALTH",
                        col(f"✓ Re-authentication successful (attempt {attempt})", C.GREEN + C.BOLD),
                        C.GREEN)
                    return True
                else:
                    log("HEALTH",
                        col(f"Login ran but session still unhealthy (attempt {attempt}/3)", C.YELLOW),
                        C.YELLOW)
            except SystemExit:
                # FormLoginHandler calls sys.exit on hard failure
                log("HEALTH",
                    col(f"Login hard-failed on attempt {attempt}/3 — will retry", C.RED),
                    C.RED)
            except Exception as e:
                log("HEALTH",
                    col(f"Heal error on attempt {attempt}/3: {e}", C.RED), C.RED)

            time.sleep(_HEAL_RETRY_SLEEP * attempt)   # back off

        log("HEALTH",
            col("✗ Re-authentication failed after 3 attempts — session remains dead", C.RED + C.BOLD),
            C.RED)
        return False

    # ------------------------------------------------------------------
    #  Factory
    # ------------------------------------------------------------------
    @classmethod
    def from_args(cls, args, session, login_handler) -> Optional["SessionHealthMonitor"]:
        """
        Build a SessionHealthMonitor from CLI args if login is configured.
        Returns None if authentication isn't enabled.
        """
        if not getattr(args, "login_url", None):
            return None
        if login_handler is None:
            return None

        # Auth indicators: user-supplied or auto-detect common patterns
        indicators = list(getattr(args, "auth_indicators", None) or [])
        if not indicators:
            # Sensible defaults that appear on most post-login pages
            indicators = [
                "logout", "log out", "sign out", "signout",
                "dashboard", "my account", "my profile",
                "welcome,", "hello,", "hi,",
                "account settings", "preferences",
            ]

        # Check URL: prefer user-supplied, fall back to login URL
        check_url = (
            getattr(args, "auth_check_url", None)
            or getattr(args, "login_url", None)
            or args.url
        )

        # Expected cookies: auto-detect common session cookie names
        expected_cookies = list(getattr(args, "auth_cookies", None) or [])
        if not expected_cookies:
            # Populate from the current session jar
            jar_names = [c.name for c in session.cookies]
            # Keep only names that look like session cookies
            _session_re = re.compile(
                r"session|sid|token|jwt|auth|login|connect\.sid|laravel|phpsessid|"
                r"csrf|xsrf|csrftoken|remember|access",
                re.I,
            )
            expected_cookies = [n for n in jar_names if _session_re.search(n)]

        check_interval = int(getattr(args, "health_check_interval", _DEFAULT_CHECK_INTERVAL))

        return cls(
            session           = session,
            login_handler     = login_handler,
            check_url         = check_url,
            auth_indicators   = indicators,
            expected_cookies  = expected_cookies,
            check_interval    = check_interval,
            max_heal_attempts = _DEFAULT_MAX_HEALS,
            timeout           = getattr(args, "timeout", 10),
        )

    def summary(self) -> str:
        """Return a one-line summary for the final report."""
        s = self.status
        if s.heal_count == 0:
            return f"Session remained healthy throughout scan ({s.total_checks} checks)"
        healword = "heal" if s.heal_count == 1 else "heals"
        outcome  = "OK" if not s.gave_up else "GAVE UP"
        return (
            f"Session health: {s.total_checks} checks, "
            f"{s.heal_count} {healword}, "
            f"{s.failed_checks} failed re-auths — {outcome}"
        )
