"""Command-line interface for Axios Guardian."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from axios_guardian import __version__
from axios_guardian import scanner as scan_module
from axios_guardian import fixer as fix_module
from axios_guardian import reporter
from axios_guardian import notifier


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="axios-guardian",
        description="Detect vulnerable Axios versions and malicious npm dependencies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--path", "-p",
        default=".",
        metavar="PATH",
        help="Path to scan (default: current directory)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically fix detected vulnerabilities",
    )
    parser.add_argument(
        "--report", "-r",
        metavar="REPORT",
        help="Output report file path (JSON)",
    )
    parser.add_argument(
        "--telegram",
        action="store_true",
        help="Send Telegram alert if threats are found",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print results as JSON to stdout",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the axios-guardian CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    timestamp = datetime.now(tz=timezone.utc).isoformat()

    # Run scan
    result = scan_module.scan(path=args.path, verbose=args.verbose)

    # Output
    if args.json_output:
        reporter.print_json(result, timestamp=timestamp)
    else:
        reporter.print_report(result, timestamp=timestamp, show_banner=not args.no_banner)

    # Save report file
    if args.report:
        reporter.save_report(result, report_path=args.report, timestamp=timestamp)

    # Auto-fix
    if args.fix:
        print("\n  🔧  Running auto-fix...\n")
        fix_module.fix(result, verbose=args.verbose)

    # Telegram notification
    if args.telegram:
        notifier.send_telegram_alert(result)

    # Exit code: 1 if threats found, 0 if clean
    return 1 if result.threats_found else 0


if __name__ == "__main__":
    sys.exit(main())
