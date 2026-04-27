# syscheck

Herramienta de línea de comandos para hacer auditorías básicas de seguridad en sistemas Linux. Sin dependencias raras, sin configuración complicada — ejecutas el script y te dice en qué estado está tu sistema.

Lo hice para practicar lo que veo en clase de ASIR: hardening, permisos, servicios, usuarios... La idea era tener algo concreto con lo que experimentar, no solo leer teoría.

---

## Qué comprueba

| Check | Descripción |
|-------|-------------|
| Usuarios sin contraseña | Detecta cuentas con campo de contraseña vacío en `/etc/shadow` |
| Permisos de archivos críticos | Verifica `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` |
| Configuración SSH | Comprueba `PermitRootLogin`, `PasswordAuthentication`, puerto por defecto |
| Archivos con SUID/SGID | Lista binarios con el bit SUID o SGID activado |
| Servicios escuchando | Muestra puertos abiertos y los procesos asociados |
| Actualizaciones pendientes | Comprueba si hay paquetes sin actualizar (apt/dnf) |
| Firewall activo | Detecta si ufw/iptables/firewalld está en marcha |

---

## Requisitos

- Python 3.8+
- Linux (probado en Ubuntu 22.04 y Debian 12)
- Algunos checks requieren ejecutar con `sudo`

---

## Instalación y uso

```bash
git clone https://github.com/Shvck13/syscheck.git
cd syscheck
chmod +x syscheck.py

# Ejecución normal (algunos checks con permisos limitados)
python3 syscheck.py

# Con privilegios para todos los checks
sudo python3 syscheck.py

# Solo un módulo concreto
sudo python3 syscheck.py --check ssh
sudo python3 syscheck.py --check users
sudo python3 syscheck.py --check ports

# Guardar el informe en un archivo
sudo python3 syscheck.py --output informe.txt
```

---

## Ejemplo de salida

```
╔══════════════════════════════════════╗
║         SYSCHECK  v0.1.0            ║
║   Linux Security Audit Tool         ║
╚══════════════════════════════════════╝

[*] Sistema: Ubuntu 22.04.3 LTS
[*] Fecha:   2024-11-12 18:42:03
[*] Usuario: root

─────────────────────────────────────
[CHECK] Usuarios sin contraseña
─────────────────────────────────────
[✔] Ningún usuario con contraseña vacía encontrado

─────────────────────────────────────
[CHECK] Configuración SSH
─────────────────────────────────────
[✔] PermitRootLogin: no
[✔] PasswordAuthentication: no
[!] Puerto SSH por defecto (22) en uso — considera cambiarlo

─────────────────────────────────────
[CHECK] Archivos con SUID activo
─────────────────────────────────────
[!] /usr/bin/sudo
[!] /usr/bin/passwd
[!] /usr/bin/newgrp
    (3 archivos encontrados — revisa si alguno es inesperado)

─────────────────────────────────────
[RESUMEN]  4 OK  /  2 avisos  /  0 críticos
─────────────────────────────────────
```

---

## Estructura del proyecto

```
syscheck/
├── syscheck.py       ← Punto de entrada y lógica principal
├── checks/
│   ├── __init__.py
│   ├── users.py      ← Checks de usuarios y contraseñas
│   ├── ssh.py        ← Análisis de configuración SSH
│   ├── perms.py      ← Permisos de archivos y SUID/SGID
│   ├── ports.py      ← Servicios y puertos abiertos
│   └── updates.py    ← Actualizaciones pendientes y firewall
├── utils/
│   ├── __init__.py
│   ├── output.py     ← Formateo de la salida en terminal
│   └── report.py     ← Generación del informe en texto
├── requirements.txt
└── README.md
```

---

## Cosas que me gustaría añadir

- [ ] Soporte para exportar en JSON y HTML
- [ ] Check de contraseñas débiles con wordlist básica
- [ ] Detección de cron jobs sospechosos
- [ ] Modo comparación: guardar baseline y comparar en el tiempo

---

## Notas

Este proyecto es educativo, orientado a entornos de laboratorio y aprendizaje. No está diseñado para auditorías en producción ni como sustituto de herramientas profesionales como Lynis o OpenVAS.

## Licencia

MIT
