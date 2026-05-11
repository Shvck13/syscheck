"""
Check: SSH server configuration (sshd_config).
"""

import os
from utils.output import print_section, ok, warn, critical


SSH_CONFIG = "/etc/ssh/sshd_config"

# directive → (safe_value, severity_if_wrong, human description of the risk)
CHECKS: dict[str, tuple[str, str, str]] = {
    "PermitRootLogin":        ("no",  "CRITICAL", "Root login over SSH is enabled"),
    "PasswordAuthentication": ("no",  "WARN",     "Password authentication is enabled (prefer key-based)"),
    "PermitEmptyPasswords":   ("no",  "CRITICAL", "Empty passwords are allowed over SSH"),
    "X11Forwarding":          ("no",  "WARN",     "X11 forwarding is enabled"),
    "MaxAuthTries":           ("3",   "WARN",     "High number of authentication attempts allowed"),
    "Protocol":               ("2",   "CRITICAL", "SSHv1 is in use — insecure, upgrade to SSHv2"),
    "UseDNS":                 ("no",  "WARN",     "UseDNS enabled — can slow down logins"),
}


def run(label: str) -> dict:
    print_section(label)
    result = {"ok": 0, "warnings": 0, "critical": 0, "findings": []}

    if not os.path.exists(SSH_CONFIG):
        warn("sshd_config not found — is OpenSSH installed?")
        _add(result, "WARN", "sshd_config not found")
        result["warnings"] += 1
        return result

    config = _parse_sshd_config(result)

    # Default port check
    port = config.get("port", "22")
    if port == "22":
        warn("SSH is on the default port (22) — consider changing it")
        _add(result, "WARN", "SSH running on default port 22")
        result["warnings"] += 1
    else:
        ok(f"SSH port configured to {port}")
        _add(result, "OK", f"SSH port: {port}")
        result["ok"] += 1

    # Per-directive checks
    for directive, (safe_value, severity, risk_msg) in CHECKS.items():
        current = config.get(directive.lower())
        if current is None:
            warn(f"{directive} not explicitly set — verify default value")
            _add(result, "WARN", f"{directive} not set explicitly")
            result["warnings"] += 1
        elif current.lower() == safe_value.lower():
            ok(f"{directive}: {current}")
            _add(result, "OK", f"{directive}: {current}")
            result["ok"] += 1
        else:
            msg = f"{directive}: {current!r}  —  {risk_msg}"
            if severity == "CRITICAL":
                critical(msg)
                result["critical"] += 1
            else:
                warn(msg)
                result["warnings"] += 1
            _add(result, severity, msg)

    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_sshd_config(result: dict) -> dict:
    config: dict[str, str] = {}
    try:
        with open(SSH_CONFIG) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0].lower()] = parts[1].strip()
    except PermissionError:
        warn(f"No permission to read {SSH_CONFIG} — run with sudo")
        _add(result, "WARN", f"No permission to read {SSH_CONFIG}")
        result["warnings"] += 1
    return config


def _add(result: dict, severity: str, message: str) -> None:
    result["findings"].append({"severity": severity, "message": message})
