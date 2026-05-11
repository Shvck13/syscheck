"""
Check: cron jobs — detect world-writable scripts and suspicious patterns.
"""

import os
import stat
import re
from pathlib import Path
from utils.output import print_section, ok, warn, critical, info


# Cron directories to inspect
CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]

CRON_FILES = [
    "/etc/crontab",
    "/var/spool/cron/crontabs",  # per-user crontabs (directory)
]

# Patterns that may indicate malicious or poorly configured cron entries
SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"curl\s+.*\|.*sh",    re.I), "curl-to-shell pipe (remote code execution risk)"),
    (re.compile(r"wget\s+.*\|.*sh",    re.I), "wget-to-shell pipe (remote code execution risk)"),
    (re.compile(r"bash\s+-[ci]\s+",    re.I), "bash -c/-i (potential reverse shell)"),
    (re.compile(r"/tmp/",              re.I), "executes from /tmp (world-writable directory)"),
    (re.compile(r"base64\s+--decode",  re.I), "base64-decoded payload"),
    (re.compile(r"nc\s+(-[a-z]+\s+)*\d+\.\d+", re.I), "netcat connecting to remote host"),
    (re.compile(r"python[23]?\s+-c",   re.I), "inline Python execution"),
    (re.compile(r">\s*/dev/null\s+2>&1\s*$", re.I), "fully silenced output (hides errors)"),
]


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0, "findings": []}

    cron_files = _collect_cron_files()

    if not cron_files:
        warn("No cron files found or no permission to read them")
        _add(result, "WARN", "No readable cron files found")
        result["warnings"] += 1
        return result

    info(f"Inspecting {len(cron_files)} cron file(s)...")

    any_issue = False
    for path in cron_files:
        _check_file(path, result)
        if _is_world_writable(path):
            critical(f"World-writable cron file: {path}")
            _add(result, "CRITICAL", f"World-writable cron file: {path}")
            result["critical"] += 1
            any_issue = True

    if not any_issue and result["critical"] == 0 and result["warnings"] == 0:
        ok("No suspicious cron entries detected")
        _add(result, "OK", "No suspicious cron entries detected")
        result["ok"] += 1

    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _collect_cron_files() -> list[Path]:
    paths: list[Path] = []
    for d in CRON_DIRS:
        p = Path(d)
        if p.is_dir():
            for f in sorted(p.iterdir()):
                if f.is_file():
                    paths.append(f)
    for cf in CRON_FILES:
        p = Path(cf)
        if p.is_file():
            paths.append(p)
        elif p.is_dir():
            paths.extend(sorted(p.iterdir()))
    return paths


def _check_file(path: Path, result: dict) -> None:
    try:
        text = path.read_text(errors="ignore")
    except PermissionError:
        return

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pattern, description in SUSPICIOUS_PATTERNS:
            if pattern.search(stripped):
                short = stripped[:80] + ("…" if len(stripped) > 80 else "")
                warn(f"Suspicious pattern in {path.name}: {description}")
                info(f"  → {short}")
                _add(result, "WARN",
                     f"{path.name}: {description} — {short}")
                result["warnings"] += 1
                break  # one warning per line is enough


def _is_world_writable(path: Path) -> bool:
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _add(result: dict, severity: str, message: str) -> None:
    result["findings"].append({"severity": severity, "message": message})
