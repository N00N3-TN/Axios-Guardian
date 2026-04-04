"""Console and JSON output for Axios Guardian scan results."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from axios_guardian.scanner import ScanResult

WIDTH = 70


def _banner() -> None:
    print("═" * WIDTH)
    print("  🛡️   AXIOS GUARDIAN — Security Scan Report")
    print("═" * WIDTH)


def _divider() -> None:
    print("─" * WIDTH)


def print_report(result: ScanResult, timestamp: str | None = None, show_banner: bool = True) -> None:
    """Print a human-readable console report."""
    if timestamp is None:
        timestamp = datetime.now(tz=timezone.utc).isoformat()

    if show_banner:
        _banner()

    print(f"  📅  Timestamp      : {timestamp}")
    print(f"  📁  Scan path      : {result.scan_path}")
    print(f"  📦  Projects found : {result.projects_scanned}")
    print()

    if not result.threats_found:
        print("  Status: ✅  CLEAN — No threats detected.")
    elif result.threat_level == "CRITICAL":
        print("  Status: 🚨  CRITICAL — Malicious packages detected!")
    else:
        print("  Status: ⚠️   HIGH — Suspicious files detected.")

    _divider()

    if result.vulnerable_axios:
        print("\n  🔴 Vulnerable Axios Versions:")
        for v in result.vulnerable_axios:
            print(f"     • axios@{v.version}  →  {v.file}  [{v.severity}]")

    if result.malicious_packages:
        print("\n  🔴 Malicious Packages:")
        for m in result.malicious_packages:
            print(f"     • {m.package}@{m.version}  →  {m.file}  [{m.severity}]")

    if result.suspicious_files:
        print("\n  ⚠️  Suspicious Files:")
        for s in result.suspicious_files:
            print(f"     • {s.path}  (pattern: {s.pattern})  [{s.severity}]")

    if result.threats_found:
        print()

    print("═" * WIDTH)


def print_json(result: ScanResult, timestamp: str | None = None) -> None:
    """Print JSON report to stdout."""
    if timestamp is None:
        timestamp = datetime.now(tz=timezone.utc).isoformat()

    payload = {"scan_timestamp": timestamp}
    payload.update(result.to_dict())
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def save_report(result: ScanResult, report_path: str | Path, timestamp: str | None = None) -> None:
    """Save JSON report to a file."""
    if timestamp is None:
        timestamp = datetime.now(tz=timezone.utc).isoformat()

    payload = {"scan_timestamp": timestamp}
    payload.update(result.to_dict())

    output = Path(report_path)
    try:
        with output.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"  📊  Report saved → {output.resolve()}", file=sys.stderr)
    except OSError as exc:
        print(f"  [error] Could not save report to {output}: {exc}", file=sys.stderr)
