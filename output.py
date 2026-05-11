"""
Terminal output formatting for syscheck.
Handles ANSI color codes, section headers, result indicators, and the summary.
"""

import os
import getpass
import platform
from datetime import datetime

VERSION = "1.0.0"

# ── ANSI color codes ──────────────────────────────────────────────────────────

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

_USE_COLOR = True


def disable_color() -> None:
    """Call once to strip all ANSI codes from output (e.g. for log files)."""
    global GREEN, YELLOW, RED, CYAN, BOLD, RESET, _USE_COLOR
    GREEN = YELLOW = RED = CYAN = BOLD = RESET = ""
    _USE_COLOR = False


# ── Public helpers ────────────────────────────────────────────────────────────

def print_header() -> None:
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user   = "root" if _is_root() else _get_user()
    distro = _get_distro()
    root_indicator = f"  {RED}▲ Running as root — elevated checks enabled{RESET}" if _is_root() else ""

    print(f"""
{BOLD}╔══════════════════════════════════════════╗
║          SYSCHECK  v{VERSION}              ║
║     Linux Security Audit Tool           ║
╚══════════════════════════════════════════╝{RESET}
{root_indicator}
  System  : {distro}
  Date    : {now}
  User    : {user}
""")


def print_section(label: str) -> None:
    bar = "─" * 47
    print(f"\n{BOLD}{bar}{RESET}")
    print(f"{BOLD}[CHECK] {label}{RESET}")
    print(f"{BOLD}{bar}{RESET}")


def ok(msg: str) -> None:
    print(f"  {GREEN}[✔]{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}[!]{RESET} {msg}")


def critical(msg: str) -> None:
    print(f"  {RED}[✘]{RESET} {msg}")


def info(msg: str) -> None:
    print(f"  {CYAN}[*]{RESET} {msg}")


def print_summary(results: list[dict]) -> None:
    ok_count   = sum(r.get("ok",       0) for r in results)
    warn_count = sum(r.get("warnings", 0) for r in results)
    crit_count = sum(r.get("critical", 0) for r in results)

    bar = "═" * 47
    print(f"\n{BOLD}{bar}")
    print(
        f"  SUMMARY  —  "
        f"{GREEN}{ok_count} OK{RESET}{BOLD}  /  "
        f"{YELLOW}{warn_count} warnings{RESET}{BOLD}  /  "
        f"{RED}{crit_count} critical{RESET}"
    )
    if crit_count:
        print(f"  {RED}Action required — review critical findings above.{RESET}")
    elif warn_count:
        print(f"  {YELLOW}Some items need attention — check warnings above.{RESET}")
    else:
        print(f"  {GREEN}All checks passed. System looks good.{RESET}")
    print(f"{BOLD}{bar}{RESET}\n")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _get_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def get_distro() -> str:
    """Public accessor used by report.py to avoid duplicating this logic."""
    return _get_distro()


def _get_distro() -> str:
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME"):
                    return line.split("=", 1)[1].strip().strip('"')
    except FileNotFoundError:
        pass
    return platform.system()
