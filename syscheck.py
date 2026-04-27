#!/usr/bin/env python3
"""
syscheck — Basic Linux Security Audit Tool
"""

import argparse
import sys
import os
from datetime import datetime

from checks import users, ssh, perms, ports, updates
from utils.output import print_header, print_summary
from utils.report import save_report


CHECKS = {
    "users":   ("Usuarios sin contraseña",     users.run),
    "ssh":     ("Configuración SSH",            ssh.run),
    "perms":   ("Permisos de archivos críticos", perms.run),
    "ports":   ("Servicios y puertos abiertos", ports.run),
    "updates": ("Actualizaciones y firewall",   updates.run),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="syscheck — auditoría básica de seguridad en Linux",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--check",
        choices=list(CHECKS.keys()),
        help="Ejecuta solo un módulo concreto",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Guarda el informe en un archivo de texto",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Deshabilita los colores en la salida",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print_header()

    results = []
    selected = {args.check: CHECKS[args.check]} if args.check else CHECKS

    for key, (label, func) in selected.items():
        result = func(label)
        results.append(result)

    print_summary(results)

    if args.output:
        save_report(results, args.output)
        print(f"\n[*] Informe guardado en: {args.output}")


if __name__ == "__main__":
    main()
