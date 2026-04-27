"""
Genera un informe en texto plano a partir de los resultados de los checks.
"""

from datetime import datetime
import platform


def save_report(results: list, path: str):
    lines = []
    lines.append("=" * 50)
    lines.append("  SYSCHECK — Informe de auditoría")
    lines.append(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Sistema: {_get_distro()}")
    lines.append("=" * 50)
    lines.append("")

    ok_total   = sum(r.get("ok", 0)       for r in results)
    warn_total = sum(r.get("warnings", 0) for r in results)
    crit_total = sum(r.get("critical", 0) for r in results)

    lines.append(f"RESUMEN: {ok_total} OK  /  {warn_total} avisos  /  {crit_total} críticos")
    lines.append("")

    try:
        with open(path, "w") as f:
            f.write("\n".join(lines))
    except OSError as e:
        print(f"[!] No se pudo guardar el informe: {e}")


def _get_distro():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME"):
                    return line.split("=")[1].strip().strip('"')
    except FileNotFoundError:
        pass
    return platform.system()
