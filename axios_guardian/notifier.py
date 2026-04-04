"""Telegram alert integration for Axios Guardian."""

from __future__ import annotations

import os
import urllib.error
import urllib.parse
import urllib.request
from axios_guardian.scanner import ScanResult


def _build_message(result: ScanResult) -> str:
    lines = [
        "🛡️ *AXIOS GUARDIAN ALERT*",
        "",
        f"⚠️ Threat Level: *{result.threat_level}*",
        f"📁 Path: `{result.scan_path}`",
        "",
    ]

    if result.vulnerable_axios:
        for v in result.vulnerable_axios:
            lines.append(f"🔴 Vulnerable: `axios@{v.version}`")

    if result.malicious_packages:
        for m in result.malicious_packages:
            lines.append(f"🔴 Malicious: `{m.package}@{m.version}`")

    if result.suspicious_files:
        for s in result.suspicious_files:
            lines.append(f"⚠️ Suspicious file: `{s.path}`")

    return "\n".join(lines)


def send_telegram_alert(result: ScanResult, token: str | None = None, chat_id: str | None = None) -> bool:
    """
    Send a Telegram alert if threats are found.

    Args:
        result: The scan result.
        token: Bot token (falls back to TG_TOKEN env var).
        chat_id: Chat ID (falls back to TG_CHAT_ID env var).

    Returns:
        True if the message was sent successfully, False otherwise.
    """
    if not result.threats_found:
        return False

    token = token or os.environ.get("TG_TOKEN", "")
    chat_id = chat_id or os.environ.get("TG_CHAT_ID", "")

    if not token or not chat_id:
        print("  [warn] Telegram credentials not set (TG_TOKEN / TG_CHAT_ID).")
        return False

    message = _build_message(result)
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode(
        {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
    ).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, method="POST")  # noqa: S310
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            if resp.status == 200:
                print("  📲  Telegram alert sent.")
                return True
            print(f"  [warn] Telegram returned status {resp.status}")
            return False
    except urllib.error.URLError as exc:
        print(f"  [warn] Telegram request failed: {exc}")
        return False
