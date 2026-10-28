"""Optional runtime policy and disposable Docker replacement through Engine."""
import copy
import json
import os
import shutil
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import deploy_engine as e
import test_deploy_engine as fixtures


class AdminConfigurationTests(unittest.TestCase):
    setUp=fixtures.BoundaryTests.setUp

    def test_opt_in_rejects_mutable_images_shared_volumes_and_unsafe_connections(self):
        secret=self.root/'relay-secret';secret.write_text('fixture-relay-secret-'+'x'*32);secret.chmod(0o600)
        routes=self.root/'routes.json';routes.write_text('[{"method":"GET","path":"/api/v1/whoami"}]')
        admin={'state_volume':'test-admin','log_volume':'test-logs','environment':'main',
               'relay_image':'sha256:'+'b'*64,'edge_origin':'https://admin.example.invalid',
               'relay_secret_file':str(secret),'routes_file':str(routes)}
        for change in ({'relay_image':'relay:latest'},{'state_volume':'test-data'},
                       {'log_volume':'test-admin'},{'edge_origin':'http://admin.example.invalid'},
                       {'edge_origin':'https://127.0.0.1'},{'upstream_proxy':'socks5://user:pass@proxy:1080'},
                       {'environment':'main\nOTHER=bad'},{'unknown':'unsafe'}):
            e.write_json(self.config,dict(self.c,admin_runtime=dict(admin,**change)))
            with self.subTest(change=change),self.assertRaises((ValueError,e.DeploymentError)):
                e.Engine(self.config)
        e.write_json(self.config,dict(self.c,admin_runtime=admin))
        e.Engine(self.config)  # Validation itself must not contact Docker.
        secret.chmod(0o644)
        with self.assertRaises((ValueError,e.DeploymentError)):e.Engine(self.config)


@unittest.skipUnless(os.environ.get('PRIVATE_ENGINE_TEST_IMAGE') and os.environ.get('PRIVATE_ENGINE_TEST_GAME_DATA')
                     and os.environ.get('PRIVATE_ADMIN_RELAY_TEST_IMAGE'),
                     'Set pinned server/relay images and GameData for disposable admin lifecycle integration')
class DockerAdminRuntimeTests(unittest.TestCase):
    setUp=fixtures.BoundaryTests.setUp

    def test_legacy_world_upgrades_relay_recovers_rebinds_and_code_rollback_preserves_admin_state_logs(self):
        runtime=self.engine;tag='private-admin-test-'+uuid.uuid4().hex[:12]
        for name in ('project','data_volume'):runtime.c[name]=tag if name=='project' else tag+'-data'
        runtime.network=tag+'-internal';runtime.ingress_network=tag+'-ingress';runtime.ingress_name=tag+'-ingress';runtime.world_alias=tag+'-active-world'
        runtime.c['game_data']=Path(os.environ['PRIVATE_ENGINE_TEST_GAME_DATA']).resolve()
        ports=[]
        for _ in range(2):
            with socket.socket() as s:s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1])
        # Match the production health budget: relay-namespace verification
        # starts a separate restricted TLS client, unlike the fast unit seam.
        runtime.c.update(https_port=ports[0],game_port=ports[1],health_timeout_seconds=15)
        certs=self.root/'fixtures';e.make_test_certs(certs)
        for name in ('server.crt','server.key','ca.crt'):(self.root/'certs'/name).write_bytes((certs/name).read_bytes())
        secret=self.root/'control/secret';secret.write_text('disposable-control-'+uuid.uuid4().hex);secret.chmod(0o600)
        relay_secret=self.root/'relay-secret';relay_secret.write_text('disposable-relay-'+uuid.uuid4().hex);relay_secret.chmod(0o600)
        routes=self.root/'routes.json';routes.write_text('[{"method":"GET","path":"/api/v1/whoami"}]')
        runtime.c['admin_runtime']={'state_volume':tag+'-admin','log_volume':tag+'-logs','environment':'main',
            'relay_image':os.environ['PRIVATE_ADMIN_RELAY_TEST_IMAGE'],'edge_origin':'https://admin.example.invalid',
            'relay_secret_file':str(relay_secret),'routes_file':str(routes)}
        e.write_json(self.config,{k:str(v) if isinstance(v,Path) else v for k,v in runtime.c.items()})
        runtime=e.Engine(self.config);cids=[]
        def cleanup():
            try:
                cids.extend(runtime.docker('ps','--all','--quiet','--no-trunc','--filter','label=com.docker.compose.project='+tag,'--filter','label=com.docker.compose.service=world').decode().split())
            except e.DeploymentError:pass
            for cid in set(cids):
                try:runtime.docker('rm','--force',cid)
                except e.DeploymentError:pass
            for name in (tag+'-admin-relay',tag+'-ingress'):
                try:runtime.docker('rm','--force',name)
                except e.DeploymentError:pass
            for args in [('network','rm',runtime.network),('network','rm',runtime.ingress_network)]+[
                    ('volume','rm',tag+suffix) for suffix in ('-data','-admin','-logs')]:
                try:runtime.docker(*args)
                except e.DeploymentError:pass
        self.addCleanup(cleanup)
        if os.environ.get('PRIVATE_ADMIN_RUNTIME_EVIDENCE'):
            evidence=Path(os.environ['PRIVATE_ADMIN_RUNTIME_EVIDENCE'])
            self.addCleanup(lambda:shutil.copytree(runtime.root,evidence,dirs_exist_ok=True))
        image=os.environ['PRIVATE_ENGINE_TEST_IMAGE'];manifest={'commit':'a'*40,'image':image}
        for suffix in ('-data','-admin','-logs'):runtime.docker('volume','create',tag+suffix)
        for volume,destination in ((tag+'-data','/data'),(tag+'-admin','/admin'),(tag+'-logs','/app/server/logs')):
            runtime.docker('run','--rm','--network=none','--user=0:0','--mount','type=volume,src='+volume+',dst='+destination,
                '--entrypoint=python',image,'-I','-c',"import os;os.chown(%r,1000,1000)"%destination)
        archive=self.root/'server-image.tar';runtime.docker('image','save','--output',str(archive),image,timeout=120)
        def release_fixture(name,commit,admin):
            path=self.root/name;(path/'assets').mkdir(parents=True);(path/'assets/update_config.json').write_text('{}')
            os.link(archive,path/'server-image.tar')
            source_files={n:'fixture' for n in ('server/admin_api.py','server/admin_store.py','server/server_logs.py')} if admin else {}
            e.write_json(path/'server.json',{'commit':commit,'image':image,'tests_passed':True,'trusted_invariants_passed':True,
                'invitation_gate':True,'image_tar_sha256':e.digest(archive),'source_files':source_files})
            m={'format':1,'commit':commit,'image':image,'data_compatibility':runtime.c['data_compatibility'],
               'handoff_compatibility':e.PROTOCOL,'invitation_gate':True,'files':e.tree(path)}
            e.write_json(path/'manifest.json',m);return path,m
        release,manifest=release_fixture('legacy','a'*40,False);legacy_path=release
        target,target_manifest=release_fixture('target','b'*40,True)
        failed,failed_manifest=release_fixture('failed','c'*40,True)
        runtime.c['desired_commit_file']=self.root/'desired';runtime.c['desired_commit_file'].write_text('b'*40)
        runtime.ensure_network()
        legacy=runtime.start(release,manifest,admin_enabled=False);cids.append(legacy)
        runtime.healthy(legacy,release,manifest,time.monotonic()+15)
        runtime.record_active(legacy,release,manifest)
        self.assertFalse(runtime.active()['admin_enabled'])
        result=runtime.promote(target,'a'*40)
        self.assertEqual('healthy',result['phase']);current=runtime.active()['container'];cids.append(current)
        release,manifest=target,target_manifest
        active=runtime.active();self.assertTrue(active['admin_enabled']);relay=active['admin_relay']
        self.assertEqual('container:'+current,runtime.inspect(relay)['HostConfig']['NetworkMode'])
        runtime.docker('exec',current,'python','-I','-c',"from pathlib import Path;Path('/admin/preservation-marker').write_text('admin-history');Path('/app/server/logs/preservation-marker').write_text('durable-log')")
        runtime.docker('stop','--time','1',relay)
        # Recovery must restart the exact pinned relay without replacing the writer.
        from unittest.mock import patch
        with patch.object(runtime,'verify',return_value=(release,manifest)):runtime.recover_active()
        self.assertTrue(runtime.inspect(runtime.active()['admin_relay'])['State']['Running'])
        before_restart=runtime.active()['admin_relay']
        ns_command=('python','-I','-c',"import os;print(os.readlink('/proc/self/ns/net'))")
        old_namespace=runtime.docker('exec',before_restart,*ns_command)
        runtime.docker('stop','--time','2',current)  # Relay keeps the old namespace alive.
        with patch.object(runtime,'verify',return_value=(release,manifest)):runtime.recover_active()
        rebound=runtime.active()['admin_relay'];self.assertNotEqual(before_restart,rebound)
        world_namespace=runtime.docker('exec',current,*ns_command)
        self.assertEqual(world_namespace,runtime.docker('exec',rebound,*ns_command))
        self.assertNotEqual(old_namespace,world_namespace)

        runtime.docker('stop','--time','2',current)
        next_world=runtime.start(release,manifest);cids.append(next_world)
        runtime.healthy(next_world,release,manifest,time.monotonic()+15);runtime.record_active(next_world,release,manifest)
        self.assertNotEqual(relay,runtime.active()['admin_relay'])
        self.assertEqual('container:'+next_world,runtime.inspect(runtime.active()['admin_relay'])['HostConfig']['NetworkMode'])
        original_health=runtime.healthy
        def reject_candidate(cid,path,m,deadline):
            if m['commit']=='c'*40:raise e.DeploymentError('Disposable replacement health failure')
            return original_health(cid,path,m,deadline)
        runtime.c['desired_commit_file'].write_text('c'*40)
        with patch.object(runtime,'healthy',side_effect=reject_candidate),self.assertRaisesRegex(e.DeploymentError,'rolled_back_code_only'):
            runtime.promote(failed,'b'*40)
        self.assertEqual('b'*40,runtime.active()['release']);self.assertTrue(runtime.active()['admin_enabled'])
        result=runtime.promote(legacy_path,'b'*40,rollback=True)
        self.assertEqual('healthy',result['phase']);rollback=runtime.active()['container'];cids.append(rollback)
        self.assertFalse(runtime.active()['admin_enabled'])
        runtime.docker('stop','--time','2',rollback)
        final=runtime.start(release,manifest);cids.append(final)
        runtime.healthy(final,release,manifest,time.monotonic()+15)
        runtime.docker('exec',final,'python','-I','-c',"from pathlib import Path;assert Path('/admin/preservation-marker').read_text()=='admin-history';assert Path('/app/server/logs/preservation-marker').read_text()=='durable-log'")
        self.assertFalse(runtime.inspect(final)['HostConfig'].get('PortBindings'))
