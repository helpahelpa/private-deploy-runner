#!/usr/bin/env python3
"""Refresh operator launch pins after a healthy deployment; never install a client."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import deploy_engine as engine


def update(config, commit):
    c=json.loads(Path(config).read_text())
    private=c.get('control_repository_private',True)
    engine.require(type(private) is bool, 'Invalid controller repository visibility')
    runtime=engine.Engine(c['engine_config'])
    status=runtime.status()
    engine.require(status['managed_release']==commit, 'Registry commit mismatch')
    active=runtime.active(); release, manifest=runtime.verify(active['release_path'])
    main=Path(c['main_config']); value=json.loads(main.read_text())
    engine.require(value['role']=='Main' and value['mode']=='authenticated-shared-world', 'Wrong launcher role')
    expected=[x for x in value['containers'] if x['service'] not in ('world','ingress')]
    for item in expected:
        actual=json.loads(subprocess.check_output(['docker','inspect',item['id']]))[0]
        engine.require(actual['Id']==item['id'] and actual['Image']==item['image'] and actual['State']['Running'], 'Bridge identity changed')
    project=runtime.c['project']
    world={'id':active['container'],'image':active['image'],'project':project,'service':'world','data_volume':runtime.c['data_volume']}
    ingress={'id':active['ingress'],'image':runtime.base_id(),'project':project,'service':'ingress','data_volume':''}
    value['containers']=[world,ingress,*expected]
    value['deployed_commit']=commit
    # Keep the installed APK pin and per-install route. The separately published
    # APK is an available upgrade, not a claim that every player installed it.
    apk=release/'assets/client.apk'
    if apk.exists():
        target=Path(c['distribution_apk']);target.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as out:
            temp=Path(out.name)
            with apk.open('rb') as source: shutil.copyfileobj(source,out)
        engine.require(engine.digest(temp)==engine.digest(apk),'APK staging changed')
        temp.replace(target)
        value['distribution_apk_sha256']=engine.digest(apk)
    # Never read or write player saves, passwords, sessions or app preferences.
    engine.write_json(main,value)
    fingerprint=Path(c['fingerprint'])
    history=fingerprint.with_name(fingerprint.stem+'-history')
    prior_hash=None
    if fingerprint.exists():
        prior_hash=engine.digest(fingerprint)
        history.mkdir(parents=True,exist_ok=True)
        archived=history/(prior_hash+'.json')
        if not archived.exists(): shutil.copyfile(fingerprint,archived)
    server=json.loads((release/'server.json').read_text())
    published=json.loads((release/'assets/update_config.json').read_text()).get('server_versions',{}).get('Android_90')
    current={'schema_version':2,'role':'Main','status':'ACTIVE_TESTED_AUTOMATIC_DEPLOYMENT',
        'source_commit':commit,'source_commit_role':'Exact source master, immutable tested artifacts',
        'source_files':server['source_files'],'active_source_location':'restricted Docker /app/server',
        'active_runtime':{'image':active['image'],'container':active['container'],'ingress':active['ingress'],
            'containers':value['containers'],'data_volume':runtime.c['data_volume'],'timezone':runtime.c.get('timezone','Asia/Tokyo')},
        'deployment_pipeline':{'commit':commit,'manifest_sha256':engine.digest(release/'manifest.json'),
            'client_tests_receipt_sha256':manifest['client_tests_receipt_sha256'],
            'server_test_log_sha256':server.get('test_log_sha256'),'control_repository_private':private},
        'current_client':{'installed_apk_sha256':value['apk_sha256'],'published_apk_sha256':value.get('distribution_apk_sha256'),
            'published_version':published,'automatic_installation':False},
        'save_policy':{'data_volume_preserved':True,'automatic_data_restore':False,'DEV_independent':True},
        'job_runner_scheduler_created':True,'machine_local_record_only':True,'prior_record_sha256':prior_hash}
    engine.write_json(fingerprint,current)
    return {'commit':commit,'registry_updated':True}


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--commit',required=True);a=p.parse_args()
    try:
        engine.require(engine.SHA.fullmatch(a.commit),'Exact commit required');result=update(a.config,a.commit)
    except Exception:
        p.exit(1,'Registry synchronization failed; inspect private operator state.\n')
    print(json.dumps(result))

if __name__=='__main__':main()
