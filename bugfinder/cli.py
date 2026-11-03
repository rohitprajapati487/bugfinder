import argparse
import sys

from .models import SEVERITY_ORDER
from .scanner import scan, write_reports


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="bugfinder",
        description="Automatic website bug scanner with a self-contained HTML report.",
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--max-pages", type=int, default=25, help="Maximum pages to crawl (default: 25)")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds (default: 15)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("-o", "--output", default="bugfinder-report.html", help="HTML report output path")
    parser.add_argument("--json", dest="json_path", default=None, help="Also write a JSON report to this path")
    parser.add_argument("--md", dest="md_path", default=None, help="Also write a Markdown report to this path")
    parser.add_argument(
        "--cookie",
        default=None,
        help="Cookie header for authenticated scans, or @path/to/cookies.txt (single line name=value; name2=value2)",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=None,
        metavar="NAME: VALUE",
        help="Extra request header (repeatable), e.g. --header 'Authorization: Bearer ...'",
    )
    parser.add_argument("--no-active", action="store_true", help="Disable active probes (XSS/SQLi/sensitive paths)")
    parser.add_argument("--no-external", action="store_true", help="Do not check external links")
    parser.add_argument("--max-external", type=int, default=15, help="Maximum external hosts to check (default: 15)")
    parser.add_argument("--no-playwright", action="store_true", help="Disable browser rendering checks")
    parser.add_argument("--max-runtime-pages", type=int, default=10, help="Maximum pages to render in a browser")
    parser.add_argument("--no-js-secrets", action="store_true", help="Disable JavaScript secret scanning")
    parser.add_argument("--max-js-files", type=int, default=20, help="Maximum JS files to scan for secrets (default: 20)")
    parser.add_argument("--no-wellknown", action="store_true", help="Disable .well-known/security.txt checks")
    parser.add_argument("--no-tech-detect", action="store_true", help="Disable technology stack detection")
    parser.add_argument("--no-options", action="store_true", help="Disable HTTP OPTIONS method checks")
    parser.add_argument("--sql-time", action="store_true", help="Enable time-based blind SQL injection probes (slow, adds ~3s per test)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument(
        "--fail-on",
        choices=["none", "critical", "high", "medium", "low", "info"],
        default="none",
        help="Exit with code 1 when a finding at this severity or higher exists",
    )
    return parser


def _load_cookie(value):
    if not value:
        return None
    if value.startswith("@"):
        try:
            with open(value[1:], "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError as exc:
            raise ValueError(f"cannot read cookie file '{value[1:]}': {exc}")
    return value


def _parse_headers(values):
    headers = {}
    for raw in values or []:
        if ":" not in raw:
            raise ValueError(f"invalid header '{raw}', expected 'Name: Value'")
        name, value = raw.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"invalid header '{raw}', empty name")
        headers[name] = value.strip()
    return headers


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        cookie = _load_cookie(args.cookie)
        headers = _parse_headers(args.header)
        result, _ = scan(
            args.url,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            timeout=args.timeout,
            delay=args.delay,
            active=not args.no_active,
            external=not args.no_external,
            max_external=args.max_external,
            use_playwright=not args.no_playwright,
            max_runtime_pages=args.max_runtime_pages,
            quiet=args.quiet,
            cookie=cookie,
            headers=headers,
            js_secrets=not args.no_js_secrets,
            max_js_files=args.max_js_files,
            wellknown=not args.no_wellknown,
            tech_detect=not args.no_tech_detect,
            options_check=not args.no_options,
            sql_time=args.sql_time,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130

    write_reports(result, args.output, args.json_path, args.md_path)
    counts = result.counts()
    print(f"Report written to: {args.output}")
    if args.json_path:
        print(f"JSON written to: {args.json_path}")
    if args.md_path:
        print(f"Markdown written to: {args.md_path}")
    print(
        "Findings: "
        + ", ".join(f"{severity}={counts.get(severity, 0)}" for severity in SEVERITY_ORDER)
        + f" (total={len(result.findings)})"
    )

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in result.findings):
            return 1
    return 0
