# syscheck v2 - improved full project files

# main.py
import argparse, json
from checks.users import run as users_check
from checks.ssh import run as ssh_check
from checks.perms import run as perms_check
from checks.ports import run as ports_check
from checks.updates import run as updates_check
from output import print_results, save_report

CHECKS={"users":users_check,"ssh":ssh_check,"perms":perms_check,"ports":ports_check,"updates":updates_check}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--check', choices=list(CHECKS.keys())+['all'], default='all')
    p.add_argument('--output')
    p.add_argument('--json')
    p.add_argument('--no-color', action='store_true')
    args=p.parse_args()
    selected = CHECKS.keys() if args.check=='all' else [args.check]
    results={}
    for name in selected:
        results[name]=CHECKS[name]()
    print_results(results, use_color=not args.no_color)
    if args.output:
        save_report(results,args.output)
    if args.json:
        with open(args.json,'w') as f: json.dump(results,f,indent=2)

if __name__=='__main__':
    main()

# output.py
import os, socket, datetime

def c(txt, code, use=True): return f'[{code}m{txt}[0m' if use else txt

def print_results(results,use_color=True):
    for section,items in results.items():
        print(f'
== {section.upper()} ==')
        for item in items:
            sev=item['severity']
            color={'OK':'32','WARN':'33','CRITICAL':'31'}.get(sev,'0')
            print(c(f'[{sev}] {item["message"]}',color,use_color))

def save_report(results,path):
    with open(path,'w') as f:
        f.write(f'Syscheck Report
Host: {socket.gethostname()}
Date: {datetime.datetime.now()}
')
        for sec,items in results.items():
            f.write(f'
[{sec.upper()}]
')
            for i in items:
                f.write(f'{i["severity"]}: {i["message"]}
')

# checks/users.py
import subprocess

def run():
    out=[]
    try:
        r=subprocess.check_output(['getent','group','sudo'], text=True, stderr=subprocess.DEVNULL)
        out.append({'severity':'OK','message':'sudo group found'})
        out.append({'severity':'WARN','message':r.strip()})
    except Exception:
        out.append({'severity':'WARN','message':'sudo group not found'})
    return out

# checks/ssh.py
from pathlib import Path

def run():
    out=[]
    p=Path('/etc/ssh/sshd_config')
    if not p.exists(): return [{'severity':'WARN','message':'sshd_config not found'}]
    txt=p.read_text(errors='ignore')
    if 'PermitRootLogin yes' in txt:
        out.append({'severity':'CRITICAL','message':'Root login enabled'})
    else:
        out.append({'severity':'OK','message':'Root login disabled'})
    return out

# checks/perms.py
import os

def run():
    out=[]
    if os.path.exists('/etc/shadow'):
        mode=oct(os.stat('/etc/shadow').st_mode)[-3:]
        out.append({'severity':'OK' if mode=='640' else 'WARN','message':f'/etc/shadow perms {mode}'})
    return out

# checks/ports.py
import subprocess

def run():
    out=[]
    try:
        data=subprocess.check_output(['ss','-tuln'], text=True)
        lines=[l for l in data.splitlines() if 'LISTEN' in l]
        out.append({'severity':'OK','message':f'{len(lines)} listening ports detected'})
    except Exception:
        out.append({'severity':'WARN','message':'Could not inspect ports'})
    return out

# checks/updates.py
import shutil, subprocess

def run():
    if shutil.which('apt'):
        return [{'severity':'WARN','message':'Run apt update && apt upgrade to verify pending updates'}]
    return [{'severity':'WARN','message':'Package manager not supported yet'}]

