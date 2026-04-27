"""
Check: permisos en archivos críticos del sistema y binarios con SUID/SGID.
"""

import os
import stat
import subprocess
from utils.output import print_section, ok, warn, critical, info


CRITICAL_FILES = {
    "/etc/passwd":  (0o644, "rw-r--r--"),
    "/etc/shadow":  (0o640, "rw-r-----"),
    "/etc/sudoers": (0o440, "r--r-----"),
    "/etc/crontab": (0o644, "rw-r--r--"),
}

# Binarios con SUID esperados en la mayoría de distros — no son preocupantes por sí solos
SUID_WHITELIST = {
    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/bin/ping", "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
}


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0}

    # Permisos de archivos críticos
    for filepath, (expected_mode, readable) in CRITICAL_FILES.items():
        if not os.path.exists(filepath):
            continue
        try:
            current = stat.S_IMODE(os.stat(filepath).st_mode)
            if current == expected_mode:
                ok(f"{filepath}  [{readable}]")
                result["ok"] += 1
            else:
                actual_str = oct(current)
                critical(f"{filepath} — permisos incorrectos: {actual_str} (debería ser {oct(expected_mode)})")
                result["critical"] += 1
        except PermissionError:
            warn(f"Sin permisos para inspeccionar {filepath}")
            result["warnings"] += 1

    # Binarios con SUID
    suid_bins = _find_suid_binaries()
    unexpected = [b for b in suid_bins if b not in SUID_WHITELIST]

    if not unexpected:
        ok(f"Binarios SUID: {len(suid_bins)} encontrados, todos en la whitelist")
        result["ok"] += 1
    else:
        warn(f"Binarios SUID fuera de la whitelist ({len(unexpected)}):")
        for b in unexpected:
            info(f"  {b}")
        result["warnings"] += len(unexpected)

    return result


def _find_suid_binaries() -> list:
    try:
        out = subprocess.check_output(
            ["find", "/usr", "/bin", "/sbin", "-perm", "/4000", "-type", "f"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return [line.strip() for line in out.strip().splitlines() if line.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
