"""
Check: users with empty passwords, unlocked root account, and sudo members.
"""

import subprocess
from utils.output import print_section, ok, warn, critical, info


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0, "findings": []}

    # ── Empty passwords ───────────────────────────────────────────────────────
    empty = _check_empty_passwords(result)
    if empty is None:
        pass  # permission error already recorded
    elif not empty:
        ok("No accounts with empty passwords found")
        _add(result, "ok", "No accounts with empty passwords found")
        result["ok"] += 1
    else:
        for user in empty:
            critical(f"Empty password: {user}")
            _add(result, "CRITICAL", f"Empty password: {user}")
            result["critical"] += 1

    # ── Root account ─────────────────────────────────────────────────────────
    locked = _check_locked_root()
    if locked is None:
        warn("Could not read /etc/shadow — run with sudo for full results")
        _add(result, "WARN", "Could not read /etc/shadow — run with sudo")
        result["warnings"] += 1
    elif locked:
        ok("Root account is locked for direct login")
        _add(result, "OK", "Root account is locked for direct login")
        result["ok"] += 1
    else:
        warn("Root account is NOT locked — consider running: passwd -l root")
        _add(result, "WARN", "Root account is not locked (passwd -l root recommended)")
        result["warnings"] += 1

    # ── Sudo members ─────────────────────────────────────────────────────────
    sudo_members = _get_sudo_members()
    if sudo_members:
        info(f"Sudo group members ({len(sudo_members)}): {', '.join(sudo_members)}")
        _add(result, "INFO", f"Sudo group members: {', '.join(sudo_members)}")
        for m in sudo_members:
            result["ok"] += 1

    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_empty_passwords(result: dict) -> list | None:
    empty = []
    try:
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empty.append(parts[0])
        return empty
    except PermissionError:
        warn("No permission to read /etc/shadow — run with sudo")
        _add(result, "WARN", "No permission to read /etc/shadow")
        result["warnings"] += 1
        return None
    except FileNotFoundError:
        warn("/etc/shadow not found")
        _add(result, "WARN", "/etc/shadow not found")
        result["warnings"] += 1
        return None


def _check_locked_root() -> bool | None:
    try:
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.strip().split(":")
                if parts[0] == "root" and len(parts) >= 2:
                    return parts[1].startswith(("!", "*"))
    except (PermissionError, FileNotFoundError):
        return None
    return False


def _get_sudo_members() -> list[str]:
    try:
        out = subprocess.check_output(
            ["getent", "group", "sudo"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        # Format: sudo:x:27:user1,user2
        parts = out.strip().split(":")
        if len(parts) >= 4 and parts[3]:
            return parts[3].split(",")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return []


def _add(result: dict, severity: str, message: str) -> None:
    result["findings"].append({"severity": severity, "message": message})
