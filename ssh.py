"""
Check: configuración del servidor SSH.
"""

import os
from utils.output import print_section, ok, warn, critical


SSH_CONFIG = "/etc/ssh/sshd_config"

CHECKS = {
    "PermitRootLogin":        ("no",  "Permite login de root por SSH"),
    "PasswordAuthentication": ("no",  "Autenticación por contraseña habilitada"),
    "PermitEmptyPasswords":   ("no",  "Permite contraseñas vacías en SSH"),
    "X11Forwarding":          ("no",  "X11 Forwarding habilitado"),
    "MaxAuthTries":           ("3",   "Número alto de intentos de autenticación permitidos"),
}


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0}

    if not os.path.exists(SSH_CONFIG):
        warn("sshd_config no encontrado — ¿está OpenSSH instalado?")
        result["warnings"] += 1
        return result

    config = _parse_sshd_config()

    # Puerto por defecto
    port = config.get("port", "22")
    if port == "22":
        warn("Puerto SSH por defecto (22) — considera cambiarlo")
        result["warnings"] += 1
    else:
        ok(f"Puerto SSH configurado en {port}")
        result["ok"] += 1

    # Resto de checks
    for directive, (safe_value, risk_msg) in CHECKS.items():
        current = config.get(directive.lower(), None)
        if current is None:
            warn(f"{directive} no definido explícitamente (revisar valor por defecto)")
            result["warnings"] += 1
        elif current.lower() == safe_value.lower():
            ok(f"{directive}: {current}")
            result["ok"] += 1
        else:
            critical(f"{directive}: {current}  — {risk_msg}")
            result["critical"] += 1

    return result


def _parse_sshd_config() -> dict:
    config = {}
    try:
        with open(SSH_CONFIG) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0].lower()] = parts[1]
    except PermissionError:
        warn(f"Sin permisos para leer {SSH_CONFIG}")
    return config
