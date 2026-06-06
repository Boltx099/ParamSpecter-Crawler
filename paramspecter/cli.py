"""
cli.py
Argument parsing, banner, config display, and main() entry point.
"""

import os
import textwrap
from .utils import VERBOSITY, C, col, validate_url
from .core.crawler import ParamSpecter

_SPIDER_ART = [
    '                        /\\  .-"""-  /\\',
    '                       //\\\\/  ,,,  \\//\\\\',
    '                       |/\\| ,;;;;;, |/\\|',
    '                       //\\\\\\;-"""-;///\\\\',
    '                      //  \\/   .   \\/  \\\\',
    '                     (| ,-_| \\ | / |_-, |)',
    '                       //`__\\.-.-./__`\\\\',
    '                      // /.-(() ())-.\\  \\\\',
    '                     (\\ |)   \'---\'   (| /)',
    "                      ` (|           |) `",
    '                        \\)           (/v',
]

BANNER = (
    C.RED + C.BOLD +
    "\n"
    "  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗\n"
    "  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n"
    "  ██████╔╝███████║██████╔╝███████║██╔████╔██║█████╗  ██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝\n"
    "  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗\n"
    "  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║███████╗╚██████╗   ██║   ███████╗██║  ██║\n"
    "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
    "\n" +
    "\n".join(_SPIDER_ART) + "\n" +
    C.RESET +
    C.GRAY  + "\n  ParamSpecter v7.4 -- Advanced Recon Crawler | Security Edition\n" +
    C.BOLD  + C.CYAN + "  Created by Boltx\n" +
    C.RED   + "─" * 90 + C.RESET + "\n"
)


def print_banner():
    print(BANNER)


def build_parser():
    import argparse
    p = argparse.ArgumentParser(
        description="ParamSpecter v7.4 -- Advanced Recon Crawler",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          Basic crawl:
            python -m paramspecter https://example.com --ignore-robots

          Subdomain enumeration:
            python -m paramspecter https://example.com --mode subdomain

          Directory hunting (recursive):
            python -m paramspecter https://example.com --mode fuzz --recursive

          Parameter fuzzing + deep vuln scan:
            python -m paramspecter https://example.com/search --mode param --deep-fuzz

          Full recon:
            python -m paramspecter https://example.com --mode full -t 20 --ignore-robots

          Resume interrupted scan:
            python -m paramspecter https://example.com --resume

          Ctrl+C once = graceful stop | Ctrl+C twice = force quit
        """)
    )

    # Core
    p.add_argument("url", help="Target URL  e.g. https://example.com")
    p.add_argument("--mode", choices=["crawl","fuzz","param","subdomain","full"],
                   default="crawl")

    # Crawl
    p.add_argument("-m","--max-pages",    type=int,   default=100)
    p.add_argument("-d","--delay",        type=float, default=0.2)
    p.add_argument("-D","--depth",        type=int,   default=4)
    p.add_argument("-t","--threads",      type=int,   default=10)
    p.add_argument("--timeout",           type=int,   default=10)
    p.add_argument("--max-retries",       type=int,   default=3)
    p.add_argument("-o","--output",       choices=["json","csv","both","jsonl"], default="both")
    p.add_argument("--export-targets",    action="store_true")
    p.add_argument("--follow-external",   action="store_true")
    p.add_argument("--ignore-robots",     action="store_true")
    p.add_argument("--rotate-ua",         action="store_true")
    p.add_argument("--strategy",          choices=["bfs","dfs","priority"], default="bfs")
    p.add_argument("--playwright",        action="store_true")

    # Identity
    p.add_argument("-u","--user-agent",   default=None)
    p.add_argument("--cookies",           default=None)
    p.add_argument("--headers",           nargs="*")
    p.add_argument("--proxies",           default=None)

    # Auth
    p.add_argument("--login-url",         default=None, metavar="URL")
    p.add_argument("--login-user",        default=None, metavar="USER")
    p.add_argument("--login-pass",        default=None, metavar="PASS")
    p.add_argument("--login-user-field",  default="username", metavar="FIELD")
    p.add_argument("--login-pass-field",  default="password", metavar="FIELD")

    # Wordlists
    p.add_argument("-w","--wordlist",        default=None)
    p.add_argument("-pw","--param-wordlist", default=None)
    p.add_argument("-sw","--sub-wordlist",   default=None)

    # Directory hunting
    p.add_argument("-x","--extensions",      default="")
    p.add_argument("--match-codes",          default=None)
    p.add_argument("--hide-codes",           default="404")
    p.add_argument("--recursive",            action="store_true")
    p.add_argument("--recursive-depth",      type=int, default=2)

    # Param fuzzing
    p.add_argument("--param-method",  choices=["GET","POST"], default="GET")
    p.add_argument("--smart-fuzz",    action="store_true")
    p.add_argument("--deep-fuzz",     action="store_true")
    p.add_argument("--payload-file",  default=None, metavar="FILE")

    # OOB blind detection
    oob = p.add_argument_group("OOB Blind Detection")
    oob.add_argument(
        "--oob", action="store_true",
        help="Enable out-of-band blind detection via interactsh "
             "(finds blind SQLi, SSRF, XXE, CMDi, Log4Shell)",
    )
    oob.add_argument(
        "--oob-server", default="", metavar="URL",
        help="Custom interactsh server URL (default: auto-select from public pool)",
    )

    # Confidence scoring
    conf_grp = p.add_argument_group("Confidence Scoring")
    conf_grp.add_argument(
        "--min-confidence", type=int, default=0, metavar="0-100",
        help="Drop findings below this confidence score (0=keep all, "
             "recommended: 20 to remove obvious noise)",
    )

    # Session health monitor
    health = p.add_argument_group("Session Health Monitor")
    health.add_argument(
        "--auth-check-url", default=None, metavar="URL",
        help="URL to check for auth health during crawl (default: --login-url)",
    )
    health.add_argument(
        "--auth-indicators", nargs="+", default=None, metavar="STRING",
        help="Strings that appear ONLY when logged in, e.g. logout dashboard",
    )
    health.add_argument(
        "--health-check-interval", type=int, default=20, metavar="N",
        help="Check session health every N pages crawled (default: 20)",
    )

    # Scope / rate / resume / output-dir
    p.add_argument("--scope-file",    default=None, metavar="FILE")
    p.add_argument("--rate-limit",    type=float, default=None, metavar="REQ/S")
    p.add_argument("--resume",        action="store_true")
    p.add_argument("--resume-file",   default=None, metavar="FILE")
    p.add_argument("--output-dir",    default=".", metavar="DIR")

    # ── Tier 3: Scope Diffing ─────────────────────────────────────
    diff_grp = p.add_argument_group("Scope Diffing (Tier 3)")
    diff_grp.add_argument("--scope-diff", default=None, metavar="PREV_JSON",
        help="Diff current scan against a previous scan JSON file — surfaces new attack surface")
    diff_grp.add_argument("--h1-program", default=None, metavar="HANDLE",
        help="HackerOne program handle — fetch scope and validate URLs  (e.g. --h1-program uber)")
    diff_grp.add_argument("--bc-program", default=None, metavar="HANDLE",
        help="Bugcrowd program handle — fetch scope and validate URLs  (e.g. --bc-program tesla)")

    # ── Tier 3: Nuclei Template Generator ────────────────────────
    ngen_grp = p.add_argument_group("Nuclei Template Generator (Tier 3)")
    ngen_grp.add_argument("--nuclei-gen", action="store_true",
        help="Auto-generate Nuclei YAML templates for all findings")

    # Verbosity
    vg = p.add_mutually_exclusive_group()
    vg.add_argument("--quiet",   action="store_true")
    vg.add_argument("--verbose", action="store_true")

    # ── Phase 1: Auto Orchestrator ────────────────────────────────
    orch = p.add_argument_group("Auto Orchestrator (Phase 1)")
    orch.add_argument(
        "--auto", action="store_true",
        help="Run all available external tools and merge results",
    )
    orch.add_argument(
        "--tools-status", action="store_true",
        help="Show which external tools are installed and exit",
    )

    # ── Phase 2: Watch Mode ───────────────────────────────────────
    watch = p.add_argument_group("Watch Mode (Phase 2)")
    watch.add_argument("--watch", action="store_true",
        help="Continuous monitoring — re-scan on a schedule, alert on new findings")
    watch.add_argument("--interval", default="24h", metavar="INTERVAL",
        help="Watch interval: 6h, 30m, 1d  (default: 24h)")
    watch.add_argument("--watch-db", default=None, metavar="FILE",
        help="SQLite db file for watch history")
    watch.add_argument("--notify-webhook", default=None, metavar="URL",
        help="Webhook URL for new-finding alerts (Slack/Discord/custom)")
    watch.add_argument("--notify-telegram", action="store_true",
        help="Send Telegram alerts (requires --tg-token and --tg-chat)")
    watch.add_argument("--tg-token",  default=None, metavar="TOKEN")
    watch.add_argument("--tg-chat",   default=None, metavar="CHAT_ID")
    watch.add_argument("--notify-email", default=None, metavar="TO",
        help="Email address for alerts")
    watch.add_argument("--smtp-host", default=None, metavar="HOST")
    watch.add_argument("--smtp-port", type=int, default=587, metavar="PORT")
    watch.add_argument("--smtp-user", default=None, metavar="USER")
    watch.add_argument("--smtp-pass", default=None, metavar="PASS")

    # ── Phase 3: AI Triage ────────────────────────────────────────
    ai = p.add_argument_group("AI Triage (Phase 3)")
    ai.add_argument("--ai-triage", action="store_true",
        help="AI-powered attack surface analysis after scan (bring your own API key)")
    ai.add_argument("--ai-provider",
        choices=["anthropic","openai","gemini","groq","mistral","ollama","custom"],
        default=None, metavar="PROVIDER",
        help="AI provider (default: auto-detect from env vars)")
    ai.add_argument("--ai-model", default=None, metavar="MODEL",
        help="Model override e.g. gpt-4o, claude-opus-4-6, gemini-1.5-pro")
    ai.add_argument("--ai-status", action="store_true",
        help="Show configured AI providers and exit")
    ai.add_argument("--ai-chat", action="store_true",
        help="Interactive chat about scan results after scan completes")

    # ── Output extras ─────────────────────────────────────────────
    out = p.add_argument_group("Output Extras")
    out.add_argument("--burp-export", action="store_true",
        help="Export results as Burp Suite XML (importable into Proxy/Site Map)")
    out.add_argument("--dashboard", action="store_true",
        help="Show live terminal dashboard during scan (requires a real TTY)")
    out.add_argument("--pro-report", action="store_true",
        help="Generate professional pentest report with CVSS scores, PoC commands, and nuclei templates")

    return p


def print_config(args):
    def _yn(v): return col("yes", C.GREEN) if v else col("no", C.GRAY)
    W   = 20
    sep = col("─" * 60, C.GRAY)

    print(f"  {col('WARNING:', C.RED+C.BOLD)} Only test targets you have explicit written authorisation to test.\n")
    print(sep)
    print(f"  {col('TARGET', C.BOLD+C.WHITE)}")
    print(f"  {'URL':<{W}} {col(args.url, C.CYAN)}")
    print(f"  {'Mode':<{W}} {col(args.mode, C.YELLOW)}")
    print(f"  {'Output format':<{W}} {col(args.output, C.WHITE)}")
    print(f"  {'Output dir':<{W}} {col(args.output_dir, C.WHITE)}")
    print(f"  {'Export targets':<{W}} {_yn(args.export_targets)}")
    if args.scope_file:
        print(f"  {'Scope file':<{W}} {col(args.scope_file, C.CYAN)}")
    print(sep)
    print(f"  {col('CRAWL SETTINGS', C.BOLD+C.WHITE)}")
    print(f"  {'Threads':<{W}} {col(args.threads, C.WHITE)}")
    print(f"  {'Depth':<{W}} {col(args.depth, C.WHITE)}")
    print(f"  {'Max pages':<{W}} {col(args.max_pages, C.WHITE)}")
    print(f"  {'Delay':<{W}} {col(str(args.delay)+'s', C.WHITE)}")
    print(f"  {'Timeout':<{W}} {col(str(args.timeout)+'s', C.WHITE)}")
    print(f"  {'Max retries':<{W}} {col(args.max_retries, C.WHITE)}")
    print(f"  {'Rate limit':<{W}} {col(str(args.rate_limit)+' req/s' if args.rate_limit else 'auto', C.WHITE)}")
    print(f"  {'Strategy':<{W}} {col(args.strategy, C.WHITE)}")
    print(f"  {'Rotate UA':<{W}} {_yn(args.rotate_ua)}")
    print(f"  {'Follow external':<{W}} {_yn(args.follow_external)}")
    print(f"  {'Ignore robots':<{W}} {_yn(args.ignore_robots)}")
    print(f"  {'Playwright':<{W}} {_yn(args.playwright)}")
    print(f"  {'Resume':<{W}} {_yn(args.resume)}")
    print(f"  {'Verbosity':<{W}} {col('quiet' if args.quiet else 'verbose' if args.verbose else 'normal', C.WHITE)}")

    if args.login_url:
        print(sep)
        print(f"  {col('FORM LOGIN', C.BOLD+C.WHITE)}")
        print(f"  {'Login URL':<{W}} {col(args.login_url, C.CYAN)}")
        print(f"  {'Username':<{W}} {col(args.login_user, C.WHITE)}")
        print(f"  {'Password':<{W}} {col('*'*min(len(args.login_pass),8), C.GRAY)}")

    if args.mode in ("fuzz", "full"):
        print(sep)
        print(f"  {col('DIRECTORY HUNTING', C.BOLD+C.WHITE)}")
        print(f"  {'Wordlist':<{W}} {args.wordlist or col('built-in', C.GRAY)}")
        print(f"  {'Extensions':<{W}} {col(args.extensions or '(none)', C.WHITE)}")
        print(f"  {'Recursive':<{W}} {_yn(args.recursive)}")

    if args.mode in ("param", "full"):
        print(sep)
        print(f"  {col('PARAMETER FUZZING', C.BOLD+C.WHITE)}")
        print(f"  {'Wordlist':<{W}} {args.param_wordlist or col('built-in', C.GRAY)}")
        print(f"  {'Method':<{W}} {col(args.param_method, C.WHITE)}")
        print(f"  {'Smart fuzz':<{W}} {_yn(args.smart_fuzz)}")
        print(f"  {'Deep fuzz':<{W}} {_yn(args.deep_fuzz)}")
        oob_val = col('enabled (interactsh)', C.GREEN+C.BOLD) if args.oob else col('disabled', C.GRAY)
        print(f"  {'OOB detection':<{W}} {oob_val}")
        if args.oob and args.oob_server:
            print(f"  {'OOB server':<{W}} {col(args.oob_server, C.CYAN)}")
        if args.min_confidence:
            print(f"  {'Min confidence':<{W}} {col(str(args.min_confidence)+'%', C.YELLOW)}")

    if args.mode in ("subdomain", "full"):
        print(sep)
        print(f"  {col('SUBDOMAIN ENUM', C.BOLD+C.WHITE)}")
        print(f"  {'Wordlist':<{W}} {args.sub_wordlist or col('built-in', C.GRAY)}")

    if args.proxies:
        print(sep)
        print(f"  {'Proxies':<{W}} {col(args.proxies, C.WHITE)}")

    # Phase 1/2/3 display
    if getattr(args, "auto", False) or getattr(args, "watch", False) or getattr(args, "ai_triage", False):
        print(sep)
        print(f"  {col('ADVANCED FEATURES', C.BOLD+C.WHITE)}")
        if getattr(args, "auto", False):
            print(f"  {'Auto Orchestrator':<{W}} {col('enabled', C.GREEN)}")
        if getattr(args, "watch", False):
            print(f"  {'Watch Mode':<{W}} {col('enabled', C.GREEN)}  interval={col(args.interval, C.YELLOW)}")
            if getattr(args, "notify_webhook", None):
                print(f"  {'Webhook':<{W}} {col(args.notify_webhook[:50], C.CYAN)}")
            if getattr(args, "notify_telegram", False):
                print(f"  {'Telegram':<{W}} {col('enabled', C.GREEN)}")
            if getattr(args, "notify_email", None):
                print(f"  {'Email alerts':<{W}} {col(args.notify_email, C.CYAN)}")
        if getattr(args, "ai_triage", False):
            provider = getattr(args, "ai_provider", None) or "auto-detect"
            model    = getattr(args, "ai_model", None) or "provider default"
            print(f"  {'AI Triage':<{W}} {col('enabled', C.GREEN)}  provider={col(provider, C.CYAN)}  model={col(model, C.GRAY)}")

    print(sep)
    print(f"  {col('Ctrl+C once = graceful stop | Ctrl+C twice = force quit', C.GRAY)}")
    print(sep + "\n")


def main():
    print_banner()
    p    = build_parser()
    args = p.parse_args()

    # Verbosity
    if args.quiet:
        VERBOSITY.level = 0
    elif args.verbose:
        VERBOSITY.level = 2
    else:
        VERBOSITY.level = 1

    # ── Early-exit info commands ──────────────────────────────────
    if getattr(args, "ai_status", False):
        from .modules.ai_triage import print_ai_status
        print_ai_status()
        return

    if getattr(args, "tools_status", False):
        from .modules.orchestrator import detect_tools, _tool_status_line
        _tool_status_line(detect_tools())
        return

    # Validate
    args.url = validate_url(args.url)
    if getattr(args, "login_url", None):
        if not args.login_user or not args.login_pass:
            p.error("--login-url requires both --login-user and --login-pass")

    if getattr(args, "notify_telegram", False):
        if not args.tg_token or not args.tg_chat:
            p.error("--notify-telegram requires --tg-token and --tg-chat")

    # Optional dep notices
    try:
        import dns.resolver  # noqa
    except ImportError:
        print(col("  NOTE: dnspython not installed -- socket fallback active. pip install dnspython", C.YELLOW))

    print_config(args)

    # ── Run the core scan ─────────────────────────────────────────
    scanner = ParamSpecter(args)

    # ── Dashboard (start before scan) ────────────────────────────
    _dashboard = None
    if getattr(args, "dashboard", False):
        from .output.dashboard import Dashboard
        _dashboard = Dashboard(scanner)
        _dashboard.start()

    if getattr(args, "watch", False):
        # ── Phase 2: Watch Mode ───────────────────────────────────
        from .modules.watchmode import WatchMode, AlertManager, parse_interval
        from .modules.orchestrator import AutoOrchestrator
        from .output.reporter import save_results

        interval_s = parse_interval(args.interval)

        alert = AlertManager(
            webhook_url = getattr(args, "notify_webhook", None),
            tg_token    = getattr(args, "tg_token", None),
            tg_chat_id  = getattr(args, "tg_chat", None),
            smtp_host   = getattr(args, "smtp_host", None),
            smtp_port   = getattr(args, "smtp_port", 587),
            smtp_user   = getattr(args, "smtp_user", None),
            smtp_pass   = getattr(args, "smtp_pass", None),
            smtp_to     = getattr(args, "notify_email", None),
        )

        def _scan_cycle():
            """One full scan cycle — returns unified findings list."""
            # Re-initialise scanner state for each cycle
            _s = ParamSpecter(args)
            _s.run()
            findings = []
            if getattr(args, "auto", False):
                orch = AutoOrchestrator(_s, _s._stop_event)
                findings = orch.run()
            else:
                # Convert scanner results to unified schema
                from .modules.orchestrator import make_finding
                for r in _s.results:
                    if r.get("url"):
                        findings.append(make_finding(
                            source="paramspecter", category="url",
                            severity="INFO", title="Crawled URL",
                            target=r["url"],
                            detail=f"status={r.get('status')} params={r.get('params',[])}",
                        ))
                for h in _s.param_hits:
                    findings.append(make_finding(
                        source="paramspecter", category="vuln",
                        severity=h.get("severity","MEDIUM"),
                        title=f"{h.get('check','?')}: {h.get('param','?')}",
                        target=h.get("url", _s.start_url),
                        detail=h.get("evidence",""),
                        raw=h,
                    ))
                for s in _s.all_secrets:
                    findings.append(make_finding(
                        source="paramspecter", category="secret",
                        severity="HIGH",
                        title=f"Secret: {s.get('type','?')}",
                        target=s.get("source", _s.start_url),
                        detail=s.get("value","")[:80],
                    ))
            return findings

        wm = WatchMode(
            target        = args.url,
            scan_fn       = _scan_cycle,
            interval_s    = interval_s,
            db_path       = getattr(args, "watch_db", None),
            alert_manager = alert,
            output_dir    = args.output_dir,
            stop_event    = scanner._stop_event,
        )
        wm.run()

    else:
        # ── Normal single scan ────────────────────────────────────
        scanner.run()

        # ── Stop dashboard ────────────────────────────────────────
        if _dashboard:
            _dashboard.stop()

        # ── Phase 1: Auto Orchestrator (post-crawl) ───────────────
        if getattr(args, "auto", False):
            from .modules.orchestrator import AutoOrchestrator
            from .output.reporter import save_results
            orch     = AutoOrchestrator(scanner, scanner._stop_event)
            findings = orch.run()
            scanner._auto_findings = findings

        # ── Burp Suite XML export ─────────────────────────────────
        if getattr(args, "burp_export", False):
            from .output.burp_export import export_burp_xml
            import time as _time
            ts      = _time.strftime("%Y%m%d_%H%M%S")
            domain  = scanner.base_domain.replace(".", "_")
            bpath   = os.path.join(scanner.output_dir,
                                   f"paramspecter_{domain}_{ts}_burp.xml")
            export_burp_xml(scanner, bpath)

        # ── Phase 3: AI Triage ────────────────────────────────────
        if getattr(args, "ai_triage", False):
            from .modules.ai_triage import AITriage, auto_detect_provider, build_provider

            provider = None
            if args.ai_provider:
                provider = build_provider(
                    provider_name = args.ai_provider,
                    model         = getattr(args, "ai_model", "") or "",
                )
            else:
                provider = auto_detect_provider()

            triage = AITriage(provider=provider)
            result = triage.run(scanner)
            if result:
                scanner._ai_triage_text   = result
                scanner._ai_provider_name = f"{triage.provider.NAME}/{triage.provider.model}"
                triage.save(result, scanner.output_dir, scanner.base_domain)

        # ── Pro Report ────────────────────────────────────────────
        if getattr(args, "pro_report", False):
            from .output.report_builder import build_pro_report
            ai_text = getattr(scanner, "_ai_triage_text", "")
            build_pro_report(scanner, scanner.output_dir, ai_triage_text=ai_text)

        # ── Nuclei Template Generator ─────────────────────────────
        if getattr(args, "nuclei_gen", False):
            from .output.nuclei_gen import NucleiTemplateGenerator
            gen = NucleiTemplateGenerator(scanner, scanner.output_dir)
            gen.generate_all()

        # ── Scope Diff ────────────────────────────────────────────
        scope_diff_path = getattr(args, "scope_diff", None)
        h1_program      = getattr(args, "h1_program", None)
        bc_program      = getattr(args, "bc_program", None)

        if scope_diff_path or h1_program or bc_program:
            from .utils.scope_diff import ScopeDiffer, ScopeValidator

            # Validate URLs against H1/BC scope
            if h1_program or bc_program:
                validator = ScopeValidator(
                    h1_program=h1_program or "",
                    bc_program=bc_program or "",
                )
                out_of_scope = [
                    r["url"] for r in scanner.results
                    if not validator.in_scope(r["url"])
                ]
                if out_of_scope:
                    log("SCOPE", col(
                        f"{len(out_of_scope)} URL(s) appear OUT OF SCOPE "
                        f"for this program — review before reporting",
                        C.RED), C.RED)
                    for u in out_of_scope[:5]:
                        log("OOS", col(u, C.GRAY), C.GRAY)
                else:
                    log("SCOPE", col(
                        "All crawled URLs appear IN SCOPE for this program.",
                        C.GREEN), C.GREEN)

            # Diff against previous scan
            if scope_diff_path:
                differ = ScopeDiffer(prev_scan_path=scope_diff_path)
                diff   = differ.diff(scanner)
                differ.print_diff(diff)
                domain = scanner.base_domain.replace(".", "_")
                differ.save_diff(diff, scanner.output_dir, domain)
        if getattr(args, "ai_chat", False):
            from .modules.ai_chat import AIChat
            from .modules.ai_triage import build_provider, auto_detect_provider

            provider = None
            if getattr(args, "ai_provider", None):
                provider = build_provider(
                    provider_name = args.ai_provider,
                    model         = getattr(args, "ai_model", "") or "",
                )
            else:
                provider = auto_detect_provider()

            chat = AIChat(provider=provider)
            chat.run(scanner)

