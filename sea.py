#!/usr/bin/env python3
"""
sea — SEA Corporate Security Scanner command-line interface (SOP v4.0 Phase 1).

Anonymous scanning is the default: ``sea scan <target>`` behaves exactly like
the existing CLI flow. Authentication is optional and enabled with one of:

  --cookies FILE   Netscape or ``name=value`` cookie file
  --bearer  FILE   file containing a bearer token (first non-empty line)
  --jwt     FILE   file containing a JWT (first non-empty line)
  --header  "Name: Value"   custom HTTP header (repeatable)

Examples:
  python sea.py scan https://example.com
  python sea.py scan https://example.com --cookies cookies.txt
  python sea.py scan https://example.com --bearer token.txt
  python sea.py scan https://example.com --jwt token.txt
  python sea.py scan https://example.com --header "Authorization: ApiKey xxx"

Only one authentication method may be supplied per scan. Session validation
runs only when authentication is enabled; on failure the scan continues
anonymously with a clear warning (use --no-validate-session to skip probing).
"""

import argparse
import io
import sys

from core.auth.base import AuthSpec
from core.config import ScanConfig

VERSION = "1.0.0"


def _force_utf8_stdio() -> None:
    """Make the automation CLI robust when stdout is piped (Windows cp1252)."""
    if not isinstance(getattr(sys.stdout, "buffer", None), io.BufferedIOBase):
        return
    if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") in ("utf8", "utf8sig"):
        return
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass

MODE_PRESETS = {
    "quick": {"max_pages": 5, "max_workers": 3, "use_js_crawler": False, "timeout": 10},
    "standard": {"max_pages": 30, "max_workers": 5, "use_js_crawler": False, "timeout": 15},
    "deep": {"max_pages": 60, "max_workers": 8, "use_js_crawler": True, "timeout": 20},
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sea",
        description="SEA Corporate Security Scanner — optional authentication "
                    "via --cookies / --bearer / --jwt / --header. Default is anonymous.",
    )
    parser.add_argument("--version", action="version", version=f"sea {VERSION}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = subparsers.add_parser("scan", help="Run a security scan against a target")
    scan.add_argument("target", help="Target URL (scheme defaults to HTTPS)")
    auth = scan.add_argument_group("authentication (optional)")
    auth.add_argument("--cookies", metavar="FILE",
                      help="Netscape or name=value cookie file")
    auth.add_argument("--bearer", metavar="FILE",
                      help="File containing a bearer token")
    auth.add_argument("--jwt", metavar="FILE",
                      help="File containing a JWT")
    auth.add_argument("--header", action="append", metavar='"Name: Value"',
                      help="Custom HTTP header (repeatable)")
    auth.add_argument("--no-validate-session", action="store_true",
                      help="Skip session validation when authentication is enabled")
    opt = scan.add_argument_group("scan options")
    opt.add_argument("--mode", choices=("quick", "standard", "deep"),
                     default="standard", help="Scan depth preset (default: standard)")
    opt.add_argument("--threads", type=int, default=0,
                     help="Worker threads (default: mode preset)")
    opt.add_argument("--timeout", type=int, default=0,
                     help="Request timeout seconds (default: mode preset)")
    opt.add_argument("--no-auth-detection", action="store_true",
                     help="Skip the informational login-page detection")
    crawl = scan.add_argument_group("advanced crawling (Phase 2)")
    crawl.add_argument("--max-pages", type=int, default=0,
                       help="Maximum pages to crawl (default: mode preset)")
    crawl.add_argument("--max-depth", type=int, default=0,
                       help="Maximum crawl depth (0 = unlimited preset)")
    crawl.add_argument("--scope", choices=("domain", "subdomain", "path", "all"),
                       default="domain",
                       help="Crawl scope (default: domain incl. subdomains)")
    crawl.add_argument("--include-subdomains", action="store_true",
                       help="Crawl subdomains of the target")
    crawl.add_argument("--respect-robots", action="store_true",
                       help="Honour robots.txt disallowed paths")
    crawl.add_argument("--parse-sitemap", action="store_true",
                       help="Parse sitemap.xml and merge discovered URLs")
    crawl.add_argument("--no-sitemap", action="store_true",
                       help="Do not parse sitemap.xml (opt-out)")
    opt.add_argument("--no-html", action="store_true", help="Do not generate an HTML report")
    opt.add_argument("--json", action="store_true", help="Also generate a JSON report")
    opt.add_argument("--markdown", action="store_true", help="Also generate a Markdown report")
    opt.add_argument("--csv", action="store_true", help="Also generate a CSV report")
    opt.add_argument("--txt", action="store_true", help="Also generate a TXT report")
    opt.add_argument("--report-dir", metavar="DIR", default="reports",
                     help="Report output directory (default: reports)")
    return parser


def build_auth_spec(args) -> AuthSpec | None:
    methods = [name for name in ("cookies", "bearer", "jwt") if getattr(args, name)] + \
              (["headers"] if args.header else [])
    if not methods:
        return None
    if len(methods) > 1:
        print("Error: choose exactly one authentication method "
              "(--cookies / --bearer / --jwt / --header).", file=sys.stderr)
        sys.exit(2)
    validate = not args.no_validate_session
    method = methods[0]
    if method == "cookies":
        return AuthSpec(type="cookies", cookie_file=args.cookies, validate=validate)
    if method == "bearer":
        return AuthSpec(type="bearer", token_file=args.bearer, validate=validate)
    if method == "jwt":
        return AuthSpec(type="jwt", token_file=args.jwt, validate=validate)
    return AuthSpec(type="headers", headers=list(args.header or []), validate=validate)


def main(argv: list | None = None) -> int:
    _force_utf8_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return 0 if args.command is None else 2

    auth_spec = build_auth_spec(args)
    preset = MODE_PRESETS[args.mode]

    cfg = ScanConfig()
    cfg.max_pages = preset["max_pages"]
    if args.max_pages:
        cfg.max_pages = args.max_pages
    cfg.max_workers = args.threads or preset["max_workers"]
    cfg.request_timeout = args.timeout or preset["timeout"]
    cfg.long_request_timeout = min(int(cfg.request_timeout * 1.5), 30)
    cfg.use_js_crawler = preset["use_js_crawler"]
    cfg.auth_detection = not args.no_auth_detection
    cfg.auth_enabled = auth_spec is not None
    cfg.auth_type = auth_spec.type if auth_spec is not None else "cookies"
    cfg.auth_validate_session = auth_spec.validate if auth_spec is not None else True

    # Advanced crawling (SOP v4.0 Phase 2)
    cfg.crawl_scope = args.scope
    cfg.include_subdomains = args.include_subdomains
    cfg.respect_robots = args.respect_robots
    cfg.max_depth = args.max_depth or None
    if args.parse_sitemap:
        cfg.parse_sitemap = True
    if args.no_sitemap:
        cfg.parse_sitemap = False

    formats = []
    if not args.no_html:
        formats.append("html")
    if args.json:
        formats.append("json")
    if args.markdown:
        formats.append("markdown")
    if args.csv:
        formats.append("csv")
    if args.txt:
        formats.append("txt")
    if not formats:
        formats = ["html", "json"]

    from main import SeaScanner
    scanner = SeaScanner(cfg)
    scanner.run_scan(args.target, auth_spec=auth_spec, report_formats=tuple(formats),
                     report_dir=args.report_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
