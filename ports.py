"""
Check: puertos abiertos y servicios escuchando.
"""

import subprocess
from utils.output import print_section, ok, warn, info


# Puertos que conviene revisar si están abiertos al exterior
SENSITIVE_PORTS = {
    21:   "FTP — considera usar SFTP",
    23:   "Telnet — protocolo sin cifrar, usa SSH",
    25:   "SMTP — normal si es un mail server, revisar si no",
    3306: "MySQL/MariaDB — ¿necesita estar expuesto?",
    5432: "PostgreSQL — ¿necesita estar expuesto?",
    6379: "Redis — asegúrate de que tiene autenticación",
    27017:"MongoDB — revisa si tiene autenticación activada",
}


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0}

    listening = _get_listening_ports()

    if not listening:
        warn("No se pudieron obtener los puertos — prueba con sudo")
        result["warnings"] += 1
        return result

    info(f"{len(listening)} puertos en escucha:")
    for proto, port, process in listening:
        flag = ""
        if port in SENSITIVE_PORTS:
            flag = f"  ← {SENSITIVE_PORTS[port]}"
            warn(f"  {proto:<5} :{port:<6}  {process}{flag}")
            result["warnings"] += 1
        else:
            info(f"  {proto:<5} :{port:<6}  {process}")
            result["ok"] += 1

    return result


def _get_listening_ports() -> list:
    """Devuelve lista de (proto, puerto, proceso) para sockets en LISTEN."""
    results = []
    try:
        out = subprocess.check_output(
            ["ss", "-tulnp"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[4]
            port_str = local.rsplit(":", 1)[-1]
            process = parts[-1] if len(parts) >= 6 else "unknown"
            try:
                port = int(port_str)
                results.append((proto, port, process))
            except ValueError:
                continue
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return results
