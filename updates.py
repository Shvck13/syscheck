"""
Check: paquetes pendientes de actualizar y estado del firewall.
"""

import subprocess
import shutil
from utils.output import print_section, ok, warn, critical, info


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0}

    # Actualizaciones
    pending = _get_pending_updates()
    if pending is None:
        warn("No se pudo comprobar actualizaciones (gestor de paquetes no detectado)")
        result["warnings"] += 1
    elif pending == 0:
        ok("Sistema actualizado — no hay paquetes pendientes")
        result["ok"] += 1
    else:
        critical(f"{pending} paquetes pendientes de actualizar")
        result["critical"] += 1

    # Firewall
    fw_name, fw_active = _check_firewall()
    if fw_active:
        ok(f"Firewall activo: {fw_name}")
        result["ok"] += 1
    else:
        warn(f"No se detectó firewall activo (probado: ufw, firewalld, iptables)")
        result["warnings"] += 1

    return result


def _get_pending_updates() -> int | None:
    if shutil.which("apt"):
        try:
            subprocess.run(["apt", "update", "-qq"], capture_output=True, timeout=15)
            out = subprocess.check_output(
                ["apt", "list", "--upgradable"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=15,
            )
            lines = [l for l in out.strip().splitlines() if "/" in l]
            return len(lines)
        except Exception:
            return None

    if shutil.which("dnf"):
        try:
            out = subprocess.check_output(
                ["dnf", "check-update", "--quiet"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=20,
            )
            return len([l for l in out.strip().splitlines() if l and not l.startswith("Last")])
        except subprocess.CalledProcessError as e:
            # dnf check-update devuelve código 100 si hay actualizaciones
            if e.returncode == 100:
                return len(e.output.strip().splitlines())
            return 0
        except Exception:
            return None

    return None


def _check_firewall() -> tuple[str, bool]:
    checks = [
        ("ufw",      ["ufw", "status"],           lambda o: "active" in o.lower()),
        ("firewalld",["firewall-cmd", "--state"],  lambda o: "running" in o.lower()),
        ("iptables", ["iptables", "-L", "-n"],     lambda o: len(o.strip().splitlines()) > 3),
    ]
    for name, cmd, is_active in checks:
        if not shutil.which(cmd[0]):
            continue
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=5)
            if is_active(out):
                return name, True
        except Exception:
            continue
    return "none", False
