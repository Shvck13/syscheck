"""
Check: critical system file permissions and SUID/SGID binaries.
"""

import os
import stat
import subprocess
from utils.output import print_section, ok, warn, critical, info


# Expected permissions for sensitive files: path → (octal_mode, display_string)
CRITICAL_FILES: dict[str, tuple[int, str]] = {
    "/etc/passwd":  (0o644, "rw-r--r--"),
    "/etc/shadow":  (0o640, "rw-r-----"),
    "/etc/sudoers": (0o440, "r--r-----"),
    "/etc/crontab": (0o644, "rw-r--r--"),
    "/etc/gshadow": (0o640, "rw-r-----"),
    "/boot/grub/grub.cfg": (0o600, "rw-------"),
}

# Well-known SUID binaries that are expected on most distros
SUID_WHITELIST = {
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/bin/ping",
    "/usr/bin/ping",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/sbin/pppd",
}


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0, "findings": []}

    # ── Critical file permissions ─────────────────────────────────────────────
    for filepath, (expected_mode, readable) in CRITICAL_FILES.items():
        if not os.path.exists(filepath):
            continue
        try:
            current = stat.S_IMODE(os.stat(filepath).st_mode)
            if current == expected_mode:
                ok(f"{filepath}  [{readable}]")
                _add(result, "OK", f"{filepath}: correct permissions ({readable})")
                result["ok"] += 1
            else:
                actual = oct(current)
                msg = (f"{filepath} — wrong permissions: {actual} "
                       f"(expected {oct(expected_mode)} / {readable})")
                critical(msg)
                _add(result, "CRITICAL", msg)
                result["critical"] += 1
        except PermissionError:
            warn(f"No permission to inspect {filepath}")
            _add(result, "WARN", f"Cannot inspect {filepath}")
            result["warnings"] += 1

    # ── SUID/SGID binaries ────────────────────────────────────────────────────
    suid_bins = _find_suid_binaries()
    unexpected = sorted(b for b in suid_bins if b not in SUID_WHITELIST)

    if not suid_bins:
        warn("Could not scan for SUID binaries — run with sudo for full results")
        _add(result, "WARN", "Could not scan SUID binaries")
        result["warnings"] += 1
    elif not unexpected:
        ok(f"SUID binaries: {len(suid_bins)} found, all in whitelist")
        _add(result, "OK", f"{len(suid_bins)} SUID binaries found, all whitelisted")
        result["ok"] += 1
    else:
        warn(f"SUID binaries outside whitelist ({len(unexpected)}) — review these:")
        for b in unexpected:
            info(f"  {b}")
        _add(result, "WARN",
             f"{len(unexpected)} unexpected SUID binaries: {', '.join(unexpected)}")
        result["warnings"] += len(unexpected)

    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_suid_binaries() -> list[str]:
    try:
        out = subprocess.check_output(
            ["find", "/usr", "/bin", "/sbin", "-perm", "/4000", "-type", "f"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return [line.strip() for line in out.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _add(result: dict, severity: str, message: str) -> None:
    result["findings"].append({"severity": severity, "message": message})
