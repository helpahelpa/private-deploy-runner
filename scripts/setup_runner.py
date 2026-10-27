#!/usr/bin/env python3
"""Register a repository-only runner in a container with fixed host bindings."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import watch_master as watch

NAME='private-deploy-runner'
VOLUME='private-runner-state'


def approved_collaborators(config, identity):
    """An explicit numeric identity list; usernames cannot silently change it."""
    values = config.get('approved_collaborator_ids', [])
    if (not isinstance(values, list) or len(values) > 1000
            or any(type(value) is not int or value <= 0 or value == identity.owner_id for value in values)
            or len(set(values)) != len(values)):
        raise ValueError('Invalid approved collaborator identities')
    return set(values)


def verify_collaborators(gh, identity, approved):
    """Keep owner-only by default; approved collaborators may have write only."""
    seen = set()
    for page in range(1, 12):
        people = gh.request(f'repos/{identity.full_name}/collaborators?affiliation=all&per_page=100&page={page}')
        if not isinstance(people, list) or len(people) > 100:
            raise ValueError('Invalid repository collaborator response')
        for person in people:
            if not isinstance(person, dict):
                raise ValueError('Invalid repository collaborator identity')
            person_id = person.get('id')
            if type(person_id) is not int or person_id <= 0 or person_id in seen:
                raise ValueError('Invalid repository collaborator identity')
            seen.add(person_id)
            if person_id == identity.owner_id:
                continue
            permissions = person.get('permissions')
            if (person_id not in approved or person.get('role_name') != 'write'
                    or not isinstance(permissions, dict)
                    or set(permissions) != {'admin', 'maintain', 'push', 'triage', 'pull'}
                    or any(type(value) is not bool for value in permissions.values())
                    or permissions['admin'] or permissions['maintain']
                    or not permissions['push'] or not permissions['pull']):
                raise ValueError('Repository collaborator permissions rejected')
        if len(people) < 100:
            if identity.owner_id not in seen:
                raise ValueError('Repository owner missing from collaborator audit')
            return
    raise ValueError('Repository collaborator audit limit exceeded')


def run(argv,log=None):
    result=subprocess.run(list(map(str,argv)),capture_output=True,timeout=240)
    if log:
        descriptor=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        with os.fdopen(descriptor,'ab') as out:out.write(result.stdout+b'\n'+result.stderr)
    if result.returncode:raise ValueError('Private runner operation failed')
    return result.stdout


def verify(image):
    data=json.loads(run(['docker','inspect',NAME]))[0];h=data['HostConfig'];c=data['Config']
    assert data['Image']==image and c['Hostname']=='deploy-runner' and c['User']=='1000:1000'
    assert h['ReadonlyRootfs'] and not h['Privileged'] and h['CapDrop']==['ALL'] and not h.get('CapAdd')
    assert 'no-new-privileges' in ' '.join(h['SecurityOpt']) and h['NetworkMode']!='host'
    mounts={x['Destination']:x for x in data['Mounts'] if x['Type']!='tmpfs'}
    assert set(mounts)=={'/home/runner','/ipc','/config'}
    assert mounts['/home/runner']['Type']=='volume' and mounts['/home/runner']['Name']==VOLUME
    assert not mounts['/ipc']['RW'] and not mounts['/config']['RW']
    assert not h.get('Devices') and not h.get('DeviceRequests') and not h.get('PortBindings')
    return data['Id']


def setup(path,verify_only=False):
    c=json.loads(Path(path).read_text());identity=watch.Identity.read(c['repository'])
    private=c.get('repository_private',True)
    if type(private) is not bool:raise ValueError('Invalid expected repository visibility')
    gh=watch.GitHub();v=object.__new__(watch.Watcher);v.github=gh;v.verify_identity(identity,private=private)
    verify_collaborators(gh, identity, approved_collaborators(c, identity))
    image=c['image'];assert re.fullmatch('sha256:[0-9a-f]{64}',image)
    if verify_only:return verify(image)
    root=Path(c['local_root']).resolve();root.mkdir(parents=True,exist_ok=True,mode=0o700)
    token=root/'runner-registration-token';token.write_text(gh.request('repos/'+identity.full_name+'/actions/runners/registration-token',{})['token']);token.chmod(0o600)
    restrictions=['--hostname','deploy-runner','--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256','--memory','2g','--cpus','2','--tmpfs','/tmp:rw,nosuid,nodev,size=256m,mode=1777','--mount','type=volume,src='+VOLUME+',dst=/home/runner']
    log=root/'runner-setup.private.log'
    try:
        run(['docker','volume','create',VOLUME],log)
        run(['docker','run','--rm','--name','private-runner-registration',*restrictions,'--mount','type=bind,src='+str(token)+',dst=/registration-token,readonly','--entrypoint','bash',image,'-c','./config.sh --url "$1" --name deploy-main-01 --labels private-deploy --unattended --work _work --token "$(cat /registration-token)"','runner-config','https://github.com/'+identity.full_name],log)
    finally:token.unlink(missing_ok=True)
    run(['docker','run','-d','--name',NAME,'--restart','unless-stopped',*restrictions,'--mount','type=bind,src='+str(Path(c['ipc']).resolve())+',dst=/ipc,readonly','--mount','type=bind,src='+str(Path(c['runner_config']).resolve())+',dst=/config,readonly',image],log)
    return verify(image)


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--verify-only',action='store_true');a=p.parse_args()
    try:setup(a.config,a.verify_only)
    except Exception:p.exit(1,'Runner setup rejected; inspect private operator diagnostics.\n')
    print('Private runner isolation verified.')

if __name__=='__main__':main()
