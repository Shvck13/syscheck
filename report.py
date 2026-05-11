"""
Report generation for syscheck.
Supports plain-text and JSON output formats.
"""

import json
import socket
from datetime import datetime

from utils.output import get_distro, VERSION


# ── Public API ────────────────────────────────────────────────────────────────

def save_text_report(results: list[dict], path: str) -> None:
    """Write a human-readable plain-text audit report to *path*."""
    lines = _build_text_lines(results)
    _write(path, "\n".join(lines))
    print(f"  [*] Report saved → {path}")


def save_json_report(results: list[dict], path: str) -> None:
    """Write a JSON audit report to *path*."""
    payload = {
        "syscheck_version": VERSION,
        "host":   socket.gethostname(),
        "date":   datetime.now().isoformat(timespec="seconds"),
        "system": get_distro(),
        "summary": {
            "ok":       sum(r.get("ok",       0) for r in results),
            "warnings": sum(r.get("warnings", 0) for r in results),
            "critical": sum(r.get("critical", 0) for r in results),
        },
        "modules": results,
    }
    _write(path, json.dumps(payload, indent=2, default=str))
    print(f"  [*] JSON report saved → {path}")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _build_text_lines(results: list[dict]) -> list[str]:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 52

    lines = [
        sep,
        "  SYSCHECK — Security Audit Report",
        f"  Date   : {now}",
        f"  Host   : {socket.gethostname()}",
        f"  System : {get_distro()}",
        sep,
        "",
        f"SUMMARY:",
        f"  OK       : {sum(r.get('ok',       0) for r in results)}",
        f"  Warnings : {sum(r.get('warnings', 0) for r in results)}",
        f"  Critical : {sum(r.get('critical', 0) for r in results)}",
        "",
    ]

    for r in results:
        module = r.get("module", "unknown").upper()
        lines.append(f"[{module}]")
        for entry in r.get("findings", []):
            sev = entry.get("severity", "INFO")
            msg = entry.get("message", "")
            lines.append(f"  {sev:<8} {msg}")
        lines.append("")

    return lines


def _write(path: str, content: str) -> None:
    try:
        with open(path, "w") as f:
            f.write(content)
    except OSError as e:
        print(f"  [!] Could not save report to '{path}': {e}")
