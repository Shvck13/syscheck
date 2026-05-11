"""
Check: open ports and listening services.
"""

import subprocess
from utils.output import print_section, ok, warn, info


# Ports worth flagging if externally reachable
SENSITIVE_PORTS: dict[int, str] = {
    21:    "FTP — unencrypted, consider SFTP/FTPS",
    23:    "Telnet — plaintext protocol, replace with SSH",
    25:    "SMTP — expected on mail servers, review otherwise",
    110:   "POP3 — unencrypted mail, prefer IMAPS/POP3S",
    143:   "IMAP — unencrypted mail, prefer IMAPS",
    512:   "rexec — legacy remote exec, should not be open",
    513:   "rlogin — legacy remote login, should not be open",
    3306:  "MySQL/MariaDB — should it be publicly reachable?",
    5432:  "PostgreSQL — should it be publicly reachable?",
    6379:  "Redis — ensure authentication is enabled",
    27017: "MongoDB — verify authentication is active",
    11211: "Memcached — no auth by default, bind to localhost",
}


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0, "findings": []}

    listening = _get_listening_ports()

    if not listening:
        warn("Could not retrieve port list — try running with sudo")
        _add(result, "WARN", "Could not retrieve listening ports")
        result["warnings"] += 1
        return result

    info(f"{len(listening)} listening port(s) detected:")

    for proto, port, process in sorted(listening, key=lambda x: x[1]):
        if port in SENSITIVE_PORTS:
            note = SENSITIVE_PORTS[port]
            warn(f"  {proto:<5} :{port:<6}  {process}  ← {note}")
            _add(result, "WARN", f"{proto} :{port} {process} — {note}")
            result["warnings"] += 1
        else:
            info(f"  {proto:<5} :{port:<6}  {process}")
            _add(result, "OK", f"{proto} :{port} {process}")
            result["ok"] += 1

    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_listening_ports() -> list[tuple[str, int, str]]:
    """Return list of (proto, port, process) for sockets in LISTEN state."""
    results: list[tuple[str, int, str]] = []
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
            process = _extract_process(parts[-1]) if len(parts) >= 6 else "unknown"
            try:
                results.append((proto, int(port_str), process))
            except ValueError:
                continue
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return results


def _extract_process(ss_field: str) -> str:
    """Parse 'users:(("nginx",pid=123,fd=6))' → 'nginx'."""
    if "users:" in ss_field:
        try:
            return ss_field.split('"')[1]
        except IndexError:
            pass
    return ss_field


def _add(result: dict, severity: str, message: str) -> None:
    result["findings"].append({"severity": severity, "message": message})
