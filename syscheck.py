#!/usr/bin/env python3
"""
syscheck — Linux Security Audit Tool
Runs modular checks on users, SSH, file permissions, open ports,
pending updates, firewall status, and suspicious cron jobs.
"""

import argparse
import json
import sys

from checks.users   import run as check_users
from checks.ssh     import run as check_ssh
from checks.perms   import run as check_perms
from checks.ports   import run as check_ports
from checks.updates import run as check_updates
from checks.cron    import run as check_cron
from utils.output   import print_header, print_summary, disable_color
from utils.report   import save_text_report, save_json_report


# ── Registry ──────────────────────────────────────────────────────────────────

CHECKS = {
    "users":   (check_users,   "Users & Passwords"),
    "ssh":     (check_ssh,     "SSH Configuration"),
    "perms":   (check_perms,   "File Permissions & SUID"),
    "ports":   (check_ports,   "Open Ports & Services"),
    "updates": (check_updates, "Pending Updates & Firewall"),
    "cron":    (check_cron,    "Cron Jobs"),
}


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="syscheck",
        description="Basic Linux security auditing tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "Examples:",
            "  sudo python3 syscheck.py                   # run all checks",
            "  sudo python3 syscheck.py --check ssh        # single module",
            "  sudo python3 syscheck.py --output report.txt",
            "  sudo python3 syscheck.py --json report.json",
            "  python3 syscheck.py --no-color > audit.log",
        ]),
    )
    p.add_argument(
        "--check",
        choices=list(CHECKS.keys()) + ["all"],
        default="all",
        metavar="MODULE",
        help=f"Module to run: {{{', '.join(CHECKS.keys())}, all}} (default: all)",
    )
    p.add_argument("--output", metavar="FILE", help="Save plain-text report to FILE")
    p.add_argument("--json",   metavar="FILE", help="Save JSON report to FILE")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    return p


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = build_parser().parse_args()

    if args.no_color:
        disable_color()

    print_header()

    selected = list(CHECKS.keys()) if args.check == "all" else [args.check]

    all_results: list[dict] = []
    for name in selected:
        fn, label = CHECKS[name]
        result = fn(label)
        result["module"] = name
        all_results.append(result)

    print_summary(all_results)

    if args.output:
        save_text_report(all_results, args.output)

    if args.json:
        save_json_report(all_results, args.json)

    # Exit 1 if any critical finding
    has_critical = any(r.get("critical", 0) > 0 for r in all_results)
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
