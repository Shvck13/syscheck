"""
Output formatting for syscheck.
"""

from datetime import datetime
import platform


GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def print_header():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = "root" if _is_root() else _get_user()
    distro = _get_distro()

    print(f"""
{BOLD}╔══════════════════════════════════════╗
║         SYSCHECK  v0.1.0            ║
║   Linux Security Audit Tool         ║
╚══════════════════════════════════════╝{RESET}

  Sistema : {distro}
  Fecha   : {now}
  Usuario : {user}
""")


def print_section(label):
    print(f"\n{BOLD}{'─' * 45}{RESET}")
    print(f"{BOLD}[CHECK] {label}{RESET}")
    print(f"{BOLD}{'─' * 45}{RESET}")


def ok(msg):
    print(f"  {GREEN}[✔]{RESET} {msg}")


def warn(msg):
    print(f"  {YELLOW}[!]{RESET} {msg}")


def critical(msg):
    print(f"  {RED}[✘]{RESET} {msg}")


def info(msg):
    print(f"  {CYAN}[*]{RESET} {msg}")


def print_summary(results):
    ok_count   = sum(r.get("ok", 0)       for r in results)
    warn_count = sum(r.get("warnings", 0) for r in results)
    crit_count = sum(r.get("critical", 0) for r in results)

    print(f"\n{BOLD}{'═' * 45}")
    print(f"  RESUMEN  — {GREEN}{ok_count} OK{RESET}{BOLD}  /  "
          f"{YELLOW}{warn_count} avisos{RESET}{BOLD}  /  "
          f"{RED}{crit_count} críticos{RESET}")
    print(f"{BOLD}{'═' * 45}{RESET}\n")


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _get_user():
    import getpass
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _get_distro():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME"):
                    return line.split("=")[1].strip().strip('"')
    except FileNotFoundError:
        pass
    return platform.system()
