"""
Check: usuarios con contraseña vacía o cuenta sin bloquear.
"""

import subprocess
from utils.output import print_section, ok, warn, critical


def run(label: str) -> dict:
    print_section(label)

    result = {"ok": 0, "warnings": 0, "critical": 0}
    empty_passwd = _check_empty_passwords()

    if not empty_passwd:
        ok("Ningún usuario con contraseña vacía")
        result["ok"] += 1
    else:
        for user in empty_passwd:
            critical(f"Usuario con contraseña vacía: {user}")
            result["critical"] += 1

    locked = _check_locked_root()
    if locked:
        ok("Cuenta root bloqueada para login directo")
        result["ok"] += 1
    else:
        warn("La cuenta root no está bloqueada — considera usar 'passwd -l root'")
        result["warnings"] += 1

    return result


def _check_empty_passwords() -> list:
    """Lee /etc/shadow y busca usuarios con campo de contraseña vacío."""
    empty = []
    try:
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empty.append(parts[0])
    except PermissionError:
        warn("Sin permisos para leer /etc/shadow — ejecuta con sudo")
    except FileNotFoundError:
        warn("/etc/shadow no encontrado")
    return empty


def _check_locked_root() -> bool:
    """Comprueba si la contraseña de root empieza con ! o * (cuenta bloqueada)."""
    try:
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.strip().split(":")
                if parts[0] == "root" and len(parts) >= 2:
                    return parts[1].startswith(("!", "*"))
    except (PermissionError, FileNotFoundError):
        pass
    return False
