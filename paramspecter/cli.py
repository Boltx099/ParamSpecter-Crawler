"""
cli.py
Argument parsing, banner, config display, and main() entry point.
"""

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
    C.GRAY  + "\n  ParamSpecter v6.0 -- Advanced Recon Crawler | Security Edition\n" +
    C.BOLD  + C.CYAN + "  Created by Boltx\n" +
    C.RED   + "─" * 90 + C.RESET + "\n"
)


def print_banner():
    print(BANNER)


def build_parser():
    import argparse
    p = argparse.ArgumentParser(
        description="ParamSpecter v6.0 -- Advanced Recon Crawler",
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

    # Scope / rate / resume / output-dir
    p.add_argument("--scope-file",    default=None, metavar="FILE")
    p.add_argument("--rate-limit",    type=float, default=None, metavar="REQ/S")
    p.add_argument("--resume",        action="store_true")
    p.add_argument("--resume-file",   default=None, metavar="FILE")
    p.add_argument("--output-dir",    default=".", metavar="DIR")

    # Verbosity
    vg = p.add_mutually_exclusive_group()
    vg.add_argument("--quiet",   action="store_true")
    vg.add_argument("--verbose", action="store_true")

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

    if args.mode in ("subdomain", "full"):
        print(sep)
        print(f"  {col('SUBDOMAIN ENUM', C.BOLD+C.WHITE)}")
        print(f"  {'Wordlist':<{W}} {args.sub_wordlist or col('built-in', C.GRAY)}")

    if args.proxies:
        print(sep)
        print(f"  {'Proxies':<{W}} {col(args.proxies, C.WHITE)}")

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

    # Validate
    args.url = validate_url(args.url)
    if getattr(args, "login_url", None):
        if not args.login_user or not args.login_pass:
            p.error("--login-url requires both --login-user and --login-pass")

    # Optional dep notices
    try:
        import dns.resolver  # noqa
    except ImportError:
        print(col("  NOTE: dnspython not installed -- socket fallback active. pip install dnspython", C.YELLOW))

    print_config(args)
    ParamSpecter(args).run()
