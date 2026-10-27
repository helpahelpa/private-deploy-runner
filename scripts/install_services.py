#!/usr/bin/env python3
"""Install per-user services from operator-only absolute configuration paths."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

PRIVATE=Path(__file__).resolve().parents[1]


def quoted(value):
    # systemd has its own escaping; shell quoting is not used in unit commands.
    value=str(value)
    if any(x in value for x in ('\n','\r','\x00','%')):raise ValueError('Unsafe unit value')
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'


def install(config, activate=False):
    config=Path(config).resolve(); c=json.loads(config.read_text()); units=Path.home()/'.config/systemd/user';units.mkdir(parents=True,exist_ok=True)
    common='[Unit]\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nRestart=on-failure\nRestartSec=10\nUMask=0077\nTimeoutStopSec=3600\n'
    common+='Environment='+quoted('PYTHONPATH='+c['python_dependencies'])+'\n'
    common+='Environment='+quoted('PATH='+c['tool_path'])+'\n'
    quoted(PRIVATE)  # Validate the path; this scalar directive does not unquote.
    common+='WorkingDirectory='+str(PRIVATE)+'\n'
    py=quoted(sys.executable)
    world=common.replace('Restart=on-failure','Restart=always')+'ExecStart='+py+' '+quoted(PRIVATE/'scripts/world_service.py')+' --config '+quoted(c['engine_config'])+'\n\n[Install]\nWantedBy=default.target\n'
    broker=common.replace('[Unit]\n','[Unit]\nWants=private-world.service\nAfter=private-world.service\n')
    broker+='ExecStart='+py+' '+quoted(PRIVATE/'scripts/broker.py')+' --config '+quoted(c['broker_config'])+'\n\n[Install]\nWantedBy=default.target\n'
    watcher=common.replace('[Unit]\n','[Unit]\nAfter=private-deploy-broker.service\n')+'ExecStart='+py+' '+quoted(PRIVATE/'scripts/watch_master.py')+' --config '+quoted(c['watcher_config'])+'\n\n[Install]\nWantedBy=default.target\n'
    for name,text in [('private-world.service',world),('private-deploy-broker.service',broker),('private-deploy-watch.service',watcher)]:
        p=units/name;p.write_text(text);p.chmod(0o600)
    subprocess.run(['systemctl','--user','daemon-reload'],check=True,capture_output=True)
    if activate:subprocess.run(['systemctl','--user','enable','--now','private-world.service','private-deploy-broker.service','private-deploy-watch.service'],check=True,capture_output=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--activate',action='store_true');a=p.parse_args();install(a.config,a.activate)

if __name__=='__main__':main()
