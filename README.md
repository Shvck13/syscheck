# 🔍 syscheck — Linux Security Audit Tool

![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)

A lightweight, modular command-line tool for auditing the security posture of Linux systems. Run it with `sudo` for full coverage, or without for a partial scan.

---

## Features

| Module | What it checks |
|---|---|
| `users` | Empty passwords, locked root account, sudo group members |
| `ssh` | `sshd_config` hardening (root login, key auth, port, protocol…) |
| `perms` | Critical file permissions (`/etc/shadow`, `/etc/sudoers`, …) and unexpected SUID binaries |
| `ports` | Listening ports and services, flagging sensitive ones (FTP, Telnet, Redis, MongoDB…) |
| `updates` | Pending package updates (apt / dnf / yum) and active firewall (ufw, firewalld, iptables, nftables) |
| `cron` | Suspicious cron entries (curl-to-shell pipes, reverse shells, /tmp execution…) and world-writable cron files |

---

## Requirements

- Python 3.10+
- Linux (tested on Debian/Ubuntu and RHEL/Fedora families)
- `sudo` for full results (shadow file, SUID scan, firewall status)

No external Python dependencies — uses only the standard library.

---

## Installation

```bash
git clone https://github.com/your-username/syscheck.git
cd syscheck
```

The expected project layout is:

```
syscheck/
├── syscheck.py          # Entry point
├── checks/
│   ├── __init__.py
│   ├── users.py
│   ├── ssh.py
│   ├── perms.py
│   ├── ports.py
│   ├── updates.py
│   └── cron.py
└── utils/
    ├── output.py
    └── report.py
```

---

## Usage

```bash
# Run all checks (recommended: with sudo)
sudo python3 syscheck.py

# Run a single module
sudo python3 syscheck.py --check ssh

# Save a plain-text report
sudo python3 syscheck.py --output audit.txt

# Save a JSON report
sudo python3 syscheck.py --json audit.json

# Disable ANSI colors (useful for log files or CI)
python3 syscheck.py --no-color > audit.log
```

### Available modules

```
users, ssh, perms, ports, updates, cron, all (default)
```

---

## Sample Output

```
╔══════════════════════════════════════════╗
║          SYSCHECK  v1.0.0              ║
║     Linux Security Audit Tool           ║
╚══════════════════════════════════════════╝
  ▲ Running as root — elevated checks enabled

  System  : Ubuntu 24.04.1 LTS
  Date    : 2026-05-11 10:30:00
  User    : root

───────────────────────────────────────────────
[CHECK] SSH Configuration
───────────────────────────────────────────────
  [!] SSH is on the default port (22) — consider changing it
  [✘] PermitRootLogin: 'yes'  —  Root login over SSH is enabled
  [✔] PasswordAuthentication: no
  [✔] PermitEmptyPasswords: no

═══════════════════════════════════════════════
  SUMMARY  —  12 OK  /  3 warnings  /  1 critical
  Action required — review critical findings above.
═══════════════════════════════════════════════
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All checks passed (no critical findings) |
| `1` | One or more critical findings detected |

This makes `syscheck` suitable for use in scripts and CI/CD pipelines.

---

## Report Formats

### Plain text (`--output`)

Human-readable report with severity labels (`OK`, `WARN`, `CRITICAL`, `INFO`) saved to a file.

### JSON (`--json`)

Machine-readable output including host metadata, distro info, and per-module findings. Useful for integrating with dashboards, SIEM tools, or automated pipelines.

```json
{
  "syscheck_version": "1.0.0",
  "host": "my-server",
  "date": "2026-05-11T10:30:00",
  "system": "Ubuntu 24.04.1 LTS",
  "summary": { "ok": 12, "warnings": 3, "critical": 1 },
  "modules": [ ... ]
}
```

---

## Notes

- Some checks (reading `/etc/shadow`, scanning SUID binaries, querying firewall status) require root privileges. Without `sudo`, those checks will report a warning and continue.
- The tool is read-only — it never modifies any system configuration.
- SUID binary checks use a whitelist of well-known binaries; anything outside the whitelist is flagged for manual review, not automatically considered malicious.

---

## License

MIT © 2026 Sergio Vidal Orts — see [LICENSE](LICENSE.txt) for details.
