"""
utils/checkpoint.py
Smart phase-aware resume system.

Unlike the basic checkpoint (which only tracks visited URLs),
this stores the complete scan state per phase so --resume can
skip already-completed phases entirely and resume mid-phase.

Checkpoint file: JSON (not plain text) saved atomically.
Backward compatible — plain-text checkpoints still load fine.

State stored:
  - visited_urls        : set of crawled URLs
  - completed_phases    : list of fully finished phase names
  - phase_findings      : {phase: count} findings per phase
  - findings_so_far     : total finding count at save time
  - all_params          : discovered parameter names
  - all_techs           : detected technologies
  - all_subdomains      : discovered subdomains
  - interrupted_at      : ISO timestamp
  - target              : original target URL
  - mode                : scan mode
"""

import json
import os
import threading
import time
from typing import Dict, List, Optional, Set

from .helpers import log, col, C


_LOCK = threading.Lock()


# -----------------------------------------------------------------
#  CHECKPOINT STATE
# -----------------------------------------------------------------

class CheckpointState:
    """Holds the full resumable state of a scan."""

    VERSION = 2   # bump when schema changes

    def __init__(self, target: str = "", mode: str = "crawl"):
        self.target:            str        = target
        self.mode:              str        = mode
        self.visited_urls:      Set[str]   = set()
        self.completed_phases:  List[str]  = []
        self.pending_phases:    List[str]  = []
        self.phase_findings:    Dict[str, int] = {}
        self.findings_so_far:   int        = 0
        self.all_params:        Set[str]   = set()
        self.all_techs:         Set[str]   = set()
        self.all_subdomains:    Set[str]   = set()
        self.interrupted_at:    str        = ""
        self.version:           int        = self.VERSION

    # ── Serialisation ────────────────────────────────────────────
    def to_dict(self) -> Dict:
        return {
            "version":          self.VERSION,
            "target":           self.target,
            "mode":             self.mode,
            "visited_urls":     sorted(self.visited_urls),
            "completed_phases": self.completed_phases,
            "pending_phases":   self.pending_phases,
            "phase_findings":   self.phase_findings,
            "findings_so_far":  self.findings_so_far,
            "all_params":       sorted(self.all_params),
            "all_techs":        sorted(self.all_techs),
            "all_subdomains":   sorted(self.all_subdomains),
            "interrupted_at":   self.interrupted_at,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "CheckpointState":
        s = cls(target=d.get("target",""), mode=d.get("mode","crawl"))
        s.visited_urls      = set(d.get("visited_urls", []))
        s.completed_phases  = d.get("completed_phases", [])
        s.pending_phases    = d.get("pending_phases", [])
        s.phase_findings    = d.get("phase_findings", {})
        s.findings_so_far   = d.get("findings_so_far", 0)
        s.all_params        = set(d.get("all_params", []))
        s.all_techs         = set(d.get("all_techs", []))
        s.all_subdomains    = set(d.get("all_subdomains", []))
        s.interrupted_at    = d.get("interrupted_at", "")
        s.version           = d.get("version", 1)
        return s

    def is_phase_done(self, phase: str) -> bool:
        return phase in self.completed_phases

    def mark_phase_done(self, phase: str, finding_count: int = 0):
        if phase not in self.completed_phases:
            self.completed_phases.append(phase)
        self.phase_findings[phase] = finding_count
        if phase in self.pending_phases:
            self.pending_phases.remove(phase)

    def mark_phase_started(self, phase: str):
        if phase not in self.pending_phases and phase not in self.completed_phases:
            self.pending_phases.append(phase)


# -----------------------------------------------------------------
#  SAVE / LOAD
# -----------------------------------------------------------------

def save_smart_checkpoint(path: str, state: CheckpointState) -> None:
    """Save checkpoint atomically. Never corrupts existing checkpoint on crash."""
    state.interrupted_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    tmp = path + ".tmp"
    with _LOCK:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state.to_dict(), f, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            log("CKPT", col(f"Smart checkpoint save failed: {e}", C.YELLOW), C.YELLOW)


def load_smart_checkpoint(path: str) -> Optional[CheckpointState]:
    """
    Load checkpoint. Handles both new JSON format and old plain-text URL list.
    Returns None if no checkpoint exists.
    """
    if not path or not os.path.isfile(path):
        return None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().strip()

    # Old format: one URL per line
    if content and not content.startswith("{"):
        urls = {line.strip() for line in content.splitlines() if line.strip()}
        state = CheckpointState()
        state.visited_urls = urls
        log("CKPT", col(
            f"Loaded legacy checkpoint: {len(urls)} visited URLs (upgrading to smart format)",
            C.YELLOW), C.YELLOW)
        return state

    # New JSON format
    try:
        d = json.loads(content)
        state = CheckpointState.from_dict(d)
        log("CKPT", col(
            f"Resumed smart checkpoint:\n"
            f"  Target:    {state.target}\n"
            f"  Visited:   {len(state.visited_urls)} URLs\n"
            f"  Completed: {', '.join(state.completed_phases) or 'none'}\n"
            f"  Pending:   {', '.join(state.pending_phases) or 'none'}\n"
            f"  Findings:  {state.findings_so_far} so far\n"
            f"  Stopped:   {state.interrupted_at}",
            C.GREEN), C.GREEN)
        return state
    except Exception as e:
        log("CKPT", col(f"Checkpoint load failed: {e} — starting fresh", C.YELLOW), C.YELLOW)
        return None


# -----------------------------------------------------------------
#  PHASE MANAGER
# -----------------------------------------------------------------

# Ordered list of all phases in a full scan
ALL_PHASES = ["crawl", "subdomain", "dirhunt", "param", "fuzz", "deep-fuzz"]

# Map from mode to the phases it runs
MODE_PHASES = {
    "crawl":     ["crawl"],
    "param":     ["crawl", "param"],
    "fuzz":      ["crawl", "fuzz"],
    "subdomain": ["subdomain"],
    "full":      ALL_PHASES,
}


class PhaseManager:
    """
    Wraps CheckpointState to provide a clean phase skip/run API
    that the crawler uses instead of checking raw state.
    """

    def __init__(self, state: Optional[CheckpointState],
                 mode: str, checkpoint_path: str):
        self.state    = state or CheckpointState()
        self.mode     = mode
        self.ck_path  = checkpoint_path
        self._planned = MODE_PHASES.get(mode, ALL_PHASES)

    def should_run(self, phase: str) -> bool:
        """Return True if this phase should execute."""
        if phase not in self._planned:
            return False
        if self.state.is_phase_done(phase):
            log("RESUME", col(
                f"Skipping phase '{phase}' — already completed in previous run "
                f"({self.state.phase_findings.get(phase, 0)} findings)",
                C.YELLOW), C.YELLOW)
            return False
        return True

    def start_phase(self, phase: str) -> None:
        self.state.mark_phase_started(phase)
        self.save()

    def finish_phase(self, phase: str, finding_count: int = 0) -> None:
        self.state.mark_phase_done(phase, finding_count)
        self.save()
        log("RESUME", col(
            f"Phase '{phase}' complete — {finding_count} findings. Checkpoint saved.",
            C.GREEN), C.GREEN)

    def update_visited(self, visited: Set[str]) -> None:
        self.state.visited_urls = visited

    def update_discovery(self, scanner) -> None:
        """Sync discovered params/techs/subdomains into checkpoint state."""
        self.state.all_params.update(scanner.all_params)
        self.state.all_techs.update(scanner.all_techs)
        self.state.all_subdomains.update(scanner.all_subdomains)
        self.state.findings_so_far = (
            len(scanner.param_hits) + len(scanner.dir_hits) +
            len(scanner.subdomain_hits) + len(scanner.all_secrets)
        )

    def save(self) -> None:
        save_smart_checkpoint(self.ck_path, self.state)

    @property
    def visited_urls(self) -> Set[str]:
        return self.state.visited_urls

    def print_resume_plan(self) -> None:
        """Print what will be skipped and what will run."""
        log_section = __import__(
            "paramspecter.utils.helpers", fromlist=["log_section"]
        ).log_section
        log_section("SMART RESUME PLAN")
        for phase in self._planned:
            if self.state.is_phase_done(phase):
                fc = self.state.phase_findings.get(phase, 0)
                log("SKIP", col(
                    f"{phase:<12} — DONE ({fc} findings from previous run)",
                    C.GRAY), C.GRAY)
            else:
                log("RUN ", col(f"{phase:<12} — will execute", C.GREEN), C.GREEN)
