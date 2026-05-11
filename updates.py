"""
Check: pending system updates and active firewall.
"""

import shutil
import subprocess
from utils.output import print_section, ok, warn, critical


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0, "findings": []}

    # ── Pending updates ───────────────────────────────────────────────────────
    pending = _get_pending_updates()
    if pending is None:
        warn("Could not check for updates — package manager not detected")
        _add(result, "WARN", "Package manager not detected, could not check updates")
        result["warnings"] += 1
    elif pending == 0:
        ok("System is up to date — no pending packages")
        _add(result, "OK", "No pending package updates")
        result["ok"] += 1
    else:
        critical(f"{pending} package(s) pending update")
        _add(result, "CRITICAL", f"{pending} packages pending update")
        result["critical"] += 1

    # ── Firewall ─────────────────────────────────────────────────────────────
    fw_name, fw_active = _check_firewall()
    if fw_active:
        ok(f"Firewall active: {fw_name}")
        _add(result, "OK", f"Firewall active ({fw_name})")
        result["ok"] += 1
    else:
        warn("No active firewall detected (checked: ufw, firewalld, iptables)")
        _add(result, "WARN", "No active firewall detected")
        result["warnings"] += 1

    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_pending_updates() -> int | None:
    if shutil.which("apt"):
        try:
            subprocess.run(
                ["apt", "update", "-qq"],
                capture_output=True,
                timeout=30,
            )
            out = subprocess.check_output(
                ["apt", "list", "--upgradable"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=30,
            )
            return sum(1 for l in out.splitlines() if "/" in l)
        except Exception:
            return None

    if shutil.which("dnf"):
        try:
            out = subprocess.check_output(
                ["dnf", "check-update", "--quiet"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=30,
            )
            return sum(
                1 for l in out.splitlines()
                if l.strip() and not l.startswith(("Last", "Loaded", "Obsoleting"))
            )
        except subprocess.CalledProcessError as e:
            # dnf exits 100 when updates are available
            if e.returncode == 100 and e.output:
                return sum(
                    1 for l in e.output.splitlines()
                    if l.strip() and not l.startswith(("Last", "Loaded"))
                )
            return 0
        except Exception:
            return None

    if shutil.which("yum"):
        try:
            out = subprocess.check_output(
                ["yum", "check-update", "--quiet"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=30,
            )
            return sum(1 for l in out.splitlines() if l.strip())
        except subprocess.CalledProcessError as e:
            if e.returncode == 100:
                return sum(1 for l in (e.output or "").splitlines() if l.strip())
            return 0
        except Exception:
            return None

    return None  # No supported package manager found


def _check_firewall() -> tuple[str, bool]:
    checks = [
        ("ufw",       ["ufw", "status"],          lambda o: "active" in o.lower()),
        ("firewalld", ["firewall-cmd", "--state"], lambda o: "running" in o.lower()),
        ("iptables",  ["iptables", "-L", "-n"],    lambda o: len(o.strip().splitlines()) > 3),
        ("nftables",  ["nft", "list", "ruleset"],  lambda o: bool(o.strip())),
    ]
    for name, cmd, is_active in checks:
        if not shutil.which(cmd[0]):
            continue
        try:
            out = subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            if is_active(out):
                return name, True
        except Exception:
            continue
    return "none", False


def _add(result: dict, severity: str, message: str) -> None:
    result["findings"].append({"severity": severity, "message": message})
