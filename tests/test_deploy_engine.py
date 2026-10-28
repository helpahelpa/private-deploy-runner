"""Trusted boundary tests. Docker tests create only unique, disposable resources."""
import importlib.util
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

spec=importlib.util.spec_from_file_location('engine',Path(__file__).resolve().parents[1]/'scripts/deploy_engine.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.c={'local_root':'state','project':'test-project','data_volume':'test-data','game_data':'game',
                'certificates':'certs','control':'control','asset_origin':'https://assets.example.invalid',
                'https_port':23443,'game_port':23444,'handoff_timeout_seconds':30,'health_timeout_seconds':2,
                'backup_limit_bytes':10000000,'data_compatibility':e.COMPATIBILITY}
        for name in ('game','certs','control'):(self.root/name).mkdir()
        self.config=self.root/'config.json';e.write_json(self.config,self.c);self.engine=e.Engine(self.config)

    def test_secret_safe_external_command_failure(self):
        with self.assertRaises(e.DeploymentError) as caught:
            e.run(['python3','-c',"import sys;print('sensitive-fixture-secret');sys.exit(7)"])
        self.assertNotIn('sensitive-fixture-secret',str(caught.exception))

    def test_source_hooks_and_fsmonitor_disabled(self):
        with patch.object(e,'run',return_value=b'fixture') as command:e.git(self.root,'status','--porcelain')
        args=command.call_args.args[0]
        self.assertIn('core.hooksPath=/dev/null',args);self.assertIn('core.fsmonitor=false',args)


    def test_symlinks_and_path_traversal_rejected(self):
        (self.root/'game'/'escape').symlink_to('/etc/passwd')
        with self.assertRaises(e.DeploymentError):e.tree(self.root/'game')
        for name in ('../escape','/etc/passwd','a/../../escape','a\\escape'):
            with self.assertRaises(e.DeploymentError):e.relative(name)

    def test_server_git_fixture_mount_injection_rejected_before_docker(self):
        source=self.root/'source';(source/'server').mkdir(parents=True)
        (source/'server/multiplayer_server.py').write_text('# Disposable source data only\n')
        # Both src and dst can occur twice in Docker's CSV syntax; the last
        # value wins. A .py suffix does not constrain the injected host source.
        name='launch-build/x,src=/tmp/disposable-marker.txt,dst=/proof.py'
        fixture=source/name;fixture.parent.mkdir(parents=True);fixture.write_text('# Fixture data\n')
        for args in (['init','--quiet'],['add','.'],['-c','user.name=Boundary Test','-c','user.email=boundary@example.invalid','commit','--quiet','-m','Disposable fixture']):
            e.run(['git','-c','core.hooksPath=/dev/null','-C',str(source),*args])
        commit=e.git(source,'rev-parse','HEAD');original=e.run;docker=[]
        def guarded(args,**kwargs):
            if args[0]=='docker':
                docker.append(args)
                raise AssertionError('Unsafe source reached Docker')
            return original(args,**kwargs)
        with patch.object(e,'run',side_effect=guarded),self.assertRaises(e.DeploymentError):
            e.build_server(source,commit,self.root/'unpublished')
        self.assertEqual([],docker)

    def test_server_source_paths_reject_csv_controls_and_git_quoting_ambiguity(self):
        for name in ('launch-build/test_fixture.py','launch-build/nested/fixture-1.py','server/test_fixture.json'):
            self.assertEqual(name,e.source_build_path(name).as_posix())
        for name in ('launch-build/x,src=/tmp/marker,dst=/proof.py','launch-build/a\n.py',
                     'launch-build/a\t.py','launch-build/a\r.py','launch-build/a".py',
                     'launch-build/a\\b.py','launch-build/../escape.py','launch-build//a.py'):
            with self.subTest(name=name),self.assertRaises(e.DeploymentError):e.source_build_path(name)

    def test_same_world_deployment_lock_exclusive(self):
        other=e.Engine(self.config)
        with self.engine.lock():
            with self.assertRaises(e.DeploymentError):
                with other.lock():pass

    def test_obsolete_queued_commit_rejected(self):
        desired=self.root/'desired';desired.write_text('a'*40)
        self.engine.c['desired_commit_file']=desired
        with self.assertRaises(e.DeploymentError):self.engine.check_desired('b'*40)
        self.engine.check_desired('a'*40)

    def test_invitationless_compatibility_config_rejected(self):
        self.c['data_compatibility']='legacy';e.write_json(self.config,self.c)
        with self.assertRaises(e.DeploymentError):e.Engine(self.config)

    def test_configured_schema_namespace_is_preserved_and_other_policies_rejected(self):
        self.c['data_compatibility']='legacy-'+e.COMPATIBILITY;e.write_json(self.config,self.c)
        runtime=e.Engine(self.config)
        self.assertEqual('legacy-'+e.COMPATIBILITY,runtime.c['data_compatibility'])
        for value in ('legacy',None,'anything-invitations-v1',False):
            self.assertFalse(e.compatible_schema(value))

    def test_authenticated_socket_token_is_not_in_request_or_receipt(self):
        secret='ephemeral-fixture-token-'+'x'*40;e.write_json(self.root/'unused',{})
        path=self.root/'control'/'secret';path.write_text(secret);path.chmod(0o600)
        request={'op':'status'};received=[]
        server=socket.socket(socket.AF_UNIX);server.bind(str(self.root/'control'/'socket'));server.listen(1)
        def respond():
            connection,_=server.accept()
            with connection:
                received.append(json.loads(connection.makefile('rb').readline()))
                connection.sendall(b'{"ok":true,"data":{"release":"fixture"}}\n')
        thread=threading.Thread(target=respond);thread.start()
        try:self.assertEqual('fixture',self.engine.control(request)['release'])
        finally:thread.join(3);server.close()
        self.assertEqual(secret,received[0]['token']);self.assertEqual({'op':'status'},request)
        self.assertFalse((self.engine.root/'logs').exists())

    def test_bounded_lock_wait_allows_background_guardian_to_release(self):
        other=e.Engine(self.config);acquired=threading.Event()
        def wait():
            with self.engine.lock(wait_seconds=1):acquired.set()
        with other.lock():
            worker=threading.Thread(target=wait);worker.start()
            self.assertFalse(acquired.wait(.05))
        worker.join(2)
        self.assertTrue(acquired.is_set())
        with other.lock(),self.assertRaises(e.DeploymentError):
            with self.engine.lock(wait_seconds=.02):pass

    def test_runtime_logs_stay_private_while_explicit_build_output_streams(self):
        import build_logs,sys
        from unittest.mock import patch
        with patch.dict(os.environ,{},clear=False):
            journal=build_logs.configure(self.root/'public')
            e.run([sys.executable,'-c',"print('private_runtime_value')"],log=self.root/'runtime.private.log')
            self.assertNotIn('private_runtime_value',journal.read_text())
            self.assertIn('private_runtime_value',(self.root/'runtime.private.log').read_text())
            e.run([sys.executable,'-c',"print('build_test_output ... PASS')"],log=self.root/'build.private.log',public_output=True)
            self.assertIn('build_test_output',journal.read_text())

    def test_release_tampering_rejected(self):
        # Deliberately synthetic unit fixture, never a passed build receipt.
        release=self.root/'release';(release/'assets').mkdir(parents=True)
        (release/'assets'/'update_config.json').write_text('{}');(release/'server-image.tar').write_text('fixture')
        info={'commit':'a'*40,'image':'sha256:'+'b'*64,'tests_passed':True,'trusted_invariants_passed':True,
              'invitation_gate':True,'image_tar_sha256':e.digest(release/'server-image.tar')}
        e.write_json(release/'server.json',info)
        m={'format':1,'commit':info['commit'],'image':info['image'],'handoff_compatibility':e.PROTOCOL,
           'data_compatibility':e.COMPATIBILITY,'invitation_gate':True,'files':e.tree(release)}
        e.write_json(release/'manifest.json',m);self.engine.verify(release)
        (release/'assets'/'update_config.json').write_text('{"changed":true}')
        with self.assertRaises(e.DeploymentError):self.engine.verify(release)



class ServerComponentTests(unittest.TestCase):
    def setUp(self):
        BoundaryTests.setUp(self)
        self.repo=self.root/'source';(self.repo/'server').mkdir(parents=True);(self.repo/'launch-build').mkdir()
        (self.repo/'server/multiplayer_server.py').write_text('# Synthetic trusted fixture only\n')
        (self.repo/'server/test_alpha.py').write_text('# Synthetic test fixture\n')
        (self.repo/'server/test_beta.py').write_text('# Independent synthetic test fixture\n')
        (self.repo/'launch-build/qa_stage2_combat_fixture.py').write_text('# Mounted fixture\n')
        (self.repo/'launch-build/client_only.py').write_text('# Client component only\n')
        (self.repo/'README.md').write_text('first')
        for args in (['init','--quiet'],['config','user.name','Fixture'],['config','user.email','fixture@example.invalid']):e.run(['git','-C',str(self.repo),*args])
        self.commit=self.commit_source('first')
        self.data=self.root/'data';self.data.mkdir();(self.data/'table.json').write_text('{}')
        self.text=self.root/'text';self.text.write_text('fixture text')
        self.cache=self.root/'cache';self.calls=[];self.invariants=0;self.builds=0
        self.barrier=threading.Barrier(2);self.original_run=e.run
        self.enterContext(patch.object(e.server_qa,'MINIMUM_TESTS',2))
        self.enterContext(patch.object(e,'run',side_effect=self.command))
        self.enterContext(patch.object(e,'make_test_certs',side_effect=lambda path:path.mkdir()))
        self.enterContext(patch.object(e,'run_test_container',side_effect=self.container))

    def commit_source(self,message):
        e.run(['git','-C',str(self.repo),'add','.']);e.run(['git','-C',str(self.repo),'commit','--quiet','-m',message])
        return e.git(self.repo,'rev-parse','HEAD')

    def command(self,args,**kwargs):
        if args[0]!='docker':return self.original_run(args,**kwargs)
        if args[1]=='build':
            self.builds+=1;Path(args[args.index('--iidfile')+1]).write_text('sha256:'+'a'*64)
        elif args[1:3]==['image','save']:Path(args[args.index('--output')+1]).write_bytes(b'synthetic-image')
        elif args[1:3]!=['image','load']:raise AssertionError('Unexpected Docker fixture command')
        if kwargs.get('log'):Path(kwargs['log']).write_text('synthetic build log\n')
        return b''

    def container(self,args,*,work,timeout,log):
        if '-c' in args:
            self.invariants+=1;Path(log).write_text('fresh invariant fixture pass\n');return b''
        if '--discover-only' in args:
            output=(e.server_qa.MARKER+json.dumps({'passed':True,'inventory':
                ['test_alpha.A.test_a','test_beta.B.test_b']})+'\n').encode()
            Path(log).write_bytes(output);return output
        self.calls.append((tuple(args),str(work)))
        if '--module' in args or '--modules' in args:
            modules=(json.loads(args[args.index('--modules')+1]) if '--modules' in args
                     else [args[args.index('--module')+1]])
            selected=sorted('test_alpha.A.test_a' if module=='test_alpha' else 'test_beta.B.test_b' for module in modules)
            report=dict(test_ids=selected,tests=len(selected),passed=True,failures=0,errors=0,skipped=0)
            output=(e.server_qa.MARKER+json.dumps(report)+'\n').encode();Path(log).write_bytes(output);return output
        self.barrier.wait(3)
        index=int(args[args.index('--worker')+1]);workers=int(args[args.index('--workers')+1])
        inventory=['test_alpha.A.test_a','test_beta.B.test_b'];selected=e.server_qa.partition(inventory,workers)[index]
        report=dict(worker=index,workers=workers,inventory=inventory,selected=selected,executed=selected,
                    tests=len(selected),passed=True,failures=0,errors=0,skipped=0)
        output=(e.server_qa.MARKER+json.dumps(report)+'\n').encode();Path(log).write_bytes(output);return output

    def build(self,name,**kwargs):
        output=self.root/name
        e.build_server(self.repo,self.commit,output,self.data,self.text,component_cache=self.cache,**kwargs)
        return json.loads((output/'server.json').read_text())

    def test_whole_component_reuse_rebinds_commit_runs_fresh_invariants_and_force_refreshes(self):
        first=self.build('first');first_commit=self.commit;first_pointer=next(self.cache.glob('*/current.json')).read_text()
        self.assertEqual((2,1,1),(len(self.calls),self.invariants,self.builds))
        self.assertEqual(2,len({work for args,work in self.calls}))
        for args,work in self.calls:
            self.assertIn('--network=none',args);self.assertIn('--read-only',args)
            self.assertTrue(all(value.endswith(',readonly') for value in args if value.startswith('type=bind')))
        (self.repo/'README.md').write_text('docs-only second commit');self.commit=self.commit_source('docs only')
        reused=self.build('reused')
        self.assertEqual((2,2,1),(len(self.calls),self.invariants,self.builds))
        self.assertEqual(self.commit,reused['commit']);self.assertEqual(first_commit,reused['tested_source_commit'])
        self.assertTrue(reused['cache_provenance']['reused']);self.assertEqual(first['source_files'],reused['source_files'])
        (self.repo/'launch-build/client_only.py').write_text('# Client-only change\n')
        self.commit=self.commit_source('client only')
        self.assertTrue(self.build('client-only-reused')['cache_provenance']['reused'])
        self.assertEqual((2,3,1),(len(self.calls),self.invariants,self.builds))
        forced=self.build('forced',force_full_qa=True)
        self.assertEqual((4,4,2),(len(self.calls),self.invariants,self.builds))
        self.assertFalse(forced['cache_provenance']['reused']);self.assertEqual(self.commit,forced['tested_source_commit'])
        self.assertNotEqual(first_pointer,next(self.cache.glob('*/current.json')).read_text())

    def test_game_data_text_and_mounted_fixture_changes_invalidate_whole_component(self):
        self.build('first')
        (self.data/'table.json').write_text('{"changed":true}');self.build('changed-data')
        self.text.write_text('changed text');self.build('changed-text')
        (self.repo/'launch-build/qa_stage2_combat_fixture.py').write_text('# Changed mounted fixture\n');self.commit=self.commit_source('fixture')
        self.build('changed-fixture')
        self.assertEqual((8,4,4),(len(self.calls),self.invariants,self.builds))

    def test_changed_test_module_reuses_independent_evidence_but_shared_runtime_runs_both(self):
        self.build('first')
        (self.repo/'server/test_alpha.py').write_text('# Changed alpha behavior\n')
        self.commit=self.commit_source('change one module');changed=self.build('changed-one')
        qa=json.loads((self.root/'changed-one/qa.json').read_text())
        self.assertEqual(3,len(self.calls));self.assertFalse(changed['cache_provenance']['reused'])
        self.assertEqual([('test_alpha',False),('test_beta',True)],[(item['module'],item['reused']) for item in qa['modules']])
        self.assertEqual(1,qa['fresh_tests']);self.assertEqual(['test_alpha.A.test_a','test_beta.B.test_b'],qa['test_ids'])
        (self.repo/'server/multiplayer_server.py').write_text('# Shared runtime changed\n')
        self.commit=self.commit_source('shared runtime');self.build('changed-runtime')
        self.assertEqual(5,len(self.calls));self.assertEqual(3,self.invariants)

    def test_corrupt_cache_fails_closed_and_force_full_qa_publishes_new_immutable_generation(self):
        info=self.build('first');key=info['cache_provenance']['key']
        stored=e.server_qa.Store(self.cache).lookup(key);old=stored['path']
        (old/'server-image.tar').write_bytes(b'tampered')
        with self.assertRaises(ValueError):self.build('rejected')
        self.assertEqual(2,len(self.calls))
        self.build('repaired',force_full_qa=True)
        self.assertNotEqual(old,e.server_qa.Store(self.cache).lookup(key)['path'])
        self.assertEqual(b'tampered',(old/'server-image.tar').read_bytes())

    def test_worker_cleanup_failure_cannot_publish_any_component(self):
        def failed(args,**kwargs):
            result=self.container(args,**kwargs)
            if '--modules' in args and 'test_alpha' in json.loads(args[args.index('--modules')+1]):raise e.DeploymentError('Synthetic worker cleanup failure')
            return result
        with patch.object(e,'run_test_container',side_effect=failed),self.assertRaises(e.DeploymentError):self.build('failed')
        self.assertEqual(2,len(self.calls));self.assertEqual(0,self.invariants)
        self.assertFalse((self.root/'failed').exists());self.assertEqual([],list(self.cache.glob('*/current.json')))

    def test_cached_suite_does_not_bypass_failed_fresh_admission_invariants(self):
        self.build('first')
        with patch.object(e,'run_test_container',side_effect=e.DeploymentError('Synthetic invariant failure')),self.assertRaises(e.DeploymentError):self.build('rejected')
        self.assertEqual(2,len(self.calls));self.assertFalse((self.root/'rejected').exists())


class SameCommitPromotionTests(unittest.TestCase):
    def setUp(self):
        BoundaryTests.setUp(self)
        self.old=self.root/'old';self.new=self.root/'new';self.old.mkdir();self.new.mkdir()
        self.sha='a'*40;self.cid='b'*64;self.next_cid='c'*64
        self.manifest={'commit':self.sha,'image':'sha256:'+'d'*64}
        self.running=True;self.ignore_stop=False
        self.engine.c['desired_commit_file']=self.root/'desired';self.engine.c['desired_commit_file'].write_text(self.sha)
        self.enterContext(patch.object(self.engine,'verify',side_effect=lambda path:(Path(path),dict(self.manifest))))
        self.enterContext(patch.object(self.engine,'active',return_value={'release':self.sha,'image':self.manifest['image'],'container':self.cid,'release_path':str(self.old)}))
        self.enterContext(patch.object(self.engine,'inspect',side_effect=lambda cid,**kwargs:{'State':{'Running':self.running}}))
        self.commands=[]
        self.enterContext(patch.object(self.engine,'docker',side_effect=self.docker))
        self.enterContext(patch.object(self.engine,'healthy'))
        self.enterContext(patch.object(self.engine,'control',return_value={}))
        for name in ('ensure_network','ensure_ingress','mounts','volume_preflight'):self.enterContext(patch.object(self.engine,name))
        self.enterContext(patch.object(self.engine,'snapshot',return_value=self.root/'snapshot'))
        self.auth=self.enterContext(patch.object(self.engine,'preserve_auth'))
        self.record=self.enterContext(patch.object(self.engine,'record_active'))
        self.start=self.enterContext(patch.object(self.engine,'start',side_effect=lambda path,*args:self.next_cid if Path(path)==self.new else 'e'*64))

    def docker(self,*args,**kwargs):
        self.commands.append(args)
        if args[:2]==('image','inspect'):return json.dumps([{'Id':self.manifest['image']}]).encode()
        if args[0]=='stop' and self.cid in args and not self.ignore_stop:self.running=False
        return b''

    def test_same_commit_requires_explicit_flag_and_distinct_immutable_release(self):
        for path,kwargs in ((self.new,{}),(self.old,{'replace_same_commit':True}),
                            (self.new,{'replace_same_commit':True,'rollback':True})):
            with self.subTest(path=path,kwargs=kwargs),self.assertRaises(e.DeploymentError):self.engine.promote(path,self.sha,**kwargs)
        self.assertEqual([],self.commands);self.start.assert_not_called()


    def test_same_commit_does_not_bypass_latest_commit_authority(self):
        self.engine.c['desired_commit_file'].write_text('f'*40)
        with self.assertRaises(e.DeploymentError):self.engine.promote(self.new,self.sha,replace_same_commit=True)
        self.assertEqual([],self.commands)

    def test_reusing_old_cid_or_leaving_old_running_fails_with_rollback(self):
        for same_cid in (True,False):
            with self.subTest(same_cid=same_cid):
                self.running=True;self.ignore_stop=not same_cid
                self.next_cid=self.cid if same_cid else 'c'*64
                with self.assertRaises(e.DeploymentError):self.engine.promote(self.new,self.sha,replace_same_commit=True)
        receipts=[json.loads(path.read_text()) for path in (self.engine.root/'deployments').glob('*.json')]
        self.assertEqual(2,len(receipts));self.assertTrue(all(value['phase']!='healthy' for value in receipts))


class DesktopRecoveryTests(unittest.TestCase):
    def setUp(self):
        BoundaryTests.setUp(self)
        self.release=self.root/'release';(self.release/'assets').mkdir(parents=True)
        for name in ('server.crt','server.key','ca.crt'):(self.root/'certs'/name).write_text('fixture')
        self.manifest={'commit':'a'*40,'image':'sha256:'+'b'*64}
        self.cid='c'*64
        self.registry=dict(release=self.manifest['commit'],image=self.manifest['image'],container=self.cid,release_path=str(self.release))
        self.state={'Image':self.manifest['image'],'State':{'Running':False},
                    'Config':{'Labels':{'desktop.docker.io/wsl-distro':'FixtureDistro'},'Env':['TZ=Asia/Tokyo'],
                              'User':'1000:1000','Cmd':['--deployment-release='+self.manifest['commit'],
                              '--deployment-control=/control/socket','--deployment-secret=/control/secret']},
                    'HostConfig':{'Tmpfs':{'/tmp':'','/app/server/logs':''},'ReadonlyRootfs':True,
                                  'NetworkMode':self.engine.network,'CapDrop':['ALL'],
                                  'SecurityOpt':['no-new-privileges:true'],'RestartPolicy':{'Name':'no'}},
                    'NetworkSettings':{'Networks':{self.engine.network:{}}}}
        self.expected_mounts=[('volume','test-data','/data',False),
                              ('bind',str(self.root/'control'),'/control',False),
                              ('bind',str(self.root/'game'),'/app/work/apk/luapack_extracted/GameData',True),
                              ('bind',str(self.release/'assets'),'/assets',True)]
        self.expected_mounts += [('bind',str(self.root/'certs'/name),'/certs/'+name,True)
                                 for name in ('server.crt','server.key','ca.crt')]
        self.set_mounts(translated=True)
        self.commands=[];self.running=b'';self.helper_error=None
        self.cleanup=self.enterContext(patch.object(e.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'No such container: fixture')))
        self.enterContext(patch.object(self.engine,'active',return_value=self.registry))
        self.enterContext(patch.object(self.engine,'verify',return_value=(self.release,self.manifest)))
        self.enterContext(patch.object(self.engine,'inspect',side_effect=lambda *args,**kwargs:copy.deepcopy(self.state)))
        self.enterContext(patch.object(self.engine,'docker',side_effect=self.docker))
        self.ingress=self.enterContext(patch.object(self.engine,'ensure_ingress'))
        self.health=self.enterContext(patch.object(self.engine,'healthy'))
        self.record=self.enterContext(patch.object(self.engine,'record_active'))
        self.enterContext(patch.object(self.engine,'ingress_id',return_value='d'*64))

    def set_mounts(self,*,translated):
        self.state['Mounts']=[]
        for kind,source,target,ro in self.expected_mounts:
            value={'Type':kind,'Destination':target,'RW':not ro}
            if kind=='volume':value['Name']=source
            else:
                value['Source']=('/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/FixtureDistro/'+hashlib.sha256(source.encode()).hexdigest()) if translated else source
            self.state['Mounts'].append(value)

    def docker(self,*args,**kwargs):
        self.commands.append((args,kwargs))
        if args[:2]==('network','inspect'):return b'[{"Internal":true}]'
        if args[0]=='ps':return self.running
        if args[0]=='run':
            if self.helper_error:raise self.helper_error
            return b''
        if args==('start',self.cid):return self.cid.encode()
        raise AssertionError('Unexpected Docker operation')

    def test_stopped_validated_desktop_world_refreshes_only_readonly_binds_before_original_start(self):
        result=self.engine.recover_active()
        self.assertEqual(self.cid,result['container'])
        commands=[args for args,kwargs in self.commands]
        helper=next(args for args in commands if args[0]=='run')
        self.assertLess(commands.index(helper),commands.index(('start',self.cid)))
        self.assertEqual(('-I','-c','pass'),helper[-3:])
        self.assertEqual(('python',self.manifest['image']),helper[-5:-3])
        for flag in ('--network=none','--read-only','--user=1000:1000','--cap-drop=ALL','--security-opt=no-new-privileges:true'):
            self.assertIn(flag,helper)
        mounts=[helper[n+1] for n,value in enumerate(helper) if value=='--mount']
        expected=['type=bind,src='+source+',dst='+target+',readonly' for kind,source,target,ro in self.expected_mounts if kind=='bind']
        self.assertCountEqual(expected,mounts)
        self.assertTrue(all('type=volume' not in value for value in mounts))
        for flag in ('--env','--publish','--privileged'):self.assertNotIn(flag,helper)
        cleanup=self.cleanup.call_args.args[0]
        self.assertEqual(['docker','rm','--force',helper[helper.index('--name')+1]],cleanup)
        self.record.assert_called_once_with(self.cid,self.release,self.manifest)

    def test_unvalidated_foreign_container_never_refreshes_or_starts(self):
        for mutation in ('image','mount','isolation','distro'):
            with self.subTest(mutation=mutation):
                original=copy.deepcopy(self.state);self.commands.clear()
                if mutation=='image':self.state['Image']='sha256:'+'f'*64
                elif mutation=='mount':self.state['Mounts'][1]['Source']+='/foreign'
                elif mutation=='isolation':self.state['HostConfig']['Privileged']=True
                else:self.state['Config']['Labels']['desktop.docker.io/wsl-distro']='../foreign'
                with self.assertRaises(e.DeploymentError):self.engine.recover_active()
                self.assertFalse(any(args[0] in ('run','start') for args,kwargs in self.commands))
                self.state=original
        self.cleanup.assert_not_called();self.health.assert_not_called()

    def test_another_managed_world_blocks_bind_refresh_and_start(self):
        self.running=('e'*64).encode()
        with self.assertRaises(e.DeploymentError):self.engine.recover_active()
        self.assertFalse(any(args[0] in ('run','start') for args,kwargs in self.commands))
        self.cleanup.assert_not_called();self.ingress.assert_not_called()

    def test_running_world_does_not_refresh_or_restart(self):
        self.state['State']['Running']=True
        self.engine.recover_active()
        self.assertFalse(any(args[0] in ('run','start') for args,kwargs in self.commands))
        self.cleanup.assert_not_called();self.health.assert_called_once()

    def test_native_bind_sources_start_without_desktop_refresh(self):
        self.set_mounts(translated=False)
        for labels in ({},{'desktop.docker.io/wsl-distro':'FixtureDistro'}):
            self.state['Config']['Labels']=labels;self.commands.clear()
            self.engine.recover_active()
            self.assertIn(('start',self.cid),[args for args,kwargs in self.commands])
            self.assertFalse(any(args[0]=='run' for args,kwargs in self.commands))
        self.cleanup.assert_not_called()

    def test_helper_failure_cleans_exact_disposable_name_and_blocks_world_start(self):
        self.helper_error=e.DeploymentError('Fixture timeout')
        with self.assertRaises(e.DeploymentError):self.engine.recover_active()
        self.cleanup.assert_called_once()
        self.assertFalse(any(args[0]=='start' for args,kwargs in self.commands))
        self.health.assert_not_called();self.record.assert_not_called()

    def test_cleanup_failure_or_timeout_blocks_world_start(self):
        for timeout in (False,True):
            with self.subTest(timeout=timeout):
                self.commands.clear()
                self.cleanup.side_effect=subprocess.TimeoutExpired('docker',10) if timeout else None
                self.cleanup.return_value=subprocess.CompletedProcess([],1,b'',b'Fixture failure')
                with self.assertRaises(e.DeploymentError):self.engine.recover_active()
                self.assertFalse(any(args[0]=='start' for args,kwargs in self.commands))
        self.health.assert_not_called();self.record.assert_not_called()

    def test_bind_csv_injection_rejected_before_helper(self):
        unsafe=self.root/'game,readonly=false';unsafe.mkdir();self.engine.c['game_data']=unsafe
        self.set_mounts(translated=True)
        with self.assertRaises(e.DeploymentError):self.engine.recover_active()
        self.assertFalse(any(args[0] in ('run','start') for args,kwargs in self.commands))
        self.cleanup.assert_not_called()


@unittest.skipUnless(os.environ.get('PRIVATE_ENGINE_TEST_IMAGE') and os.environ.get('PRIVATE_ENGINE_TEST_GAME_DATA'),'Set test image and GameData paths to run disposable Docker integration')
class DockerIsolationTests(unittest.TestCase):
    setUp=BoundaryTests.setUp
    def test_real_world_internal_network_snapshot_and_auth_preservation(self):
        image=os.environ['PRIVATE_ENGINE_TEST_IMAGE'];self.assertRegex(image,r'^sha256:[0-9a-f]{64}$')
        tag='private-engine-test-'+uuid.uuid4().hex[:12]
        self.engine.c.update(project=tag,data_volume=tag+'-data',game_data=Path(os.environ['PRIVATE_ENGINE_TEST_GAME_DATA']).resolve());self.engine.network=tag+'-internal';self.engine.ingress_network=tag+'-ingress';self.engine.ingress_name=tag+'-ingress';self.engine.world_alias=tag+'-active-world'
        # Choose loopback ports without contacting any production listener.
        ports=[]
        for _ in range(2):
            with socket.socket() as s:s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1])
        self.engine.c.update(https_port=ports[0],game_port=ports[1])
        self.engine.docker('volume','create',self.engine.c['data_volume'])
        cids=[]
        def cleanup():
            for cid in cids:
                try:self.engine.docker('rm','--force',cid)
                except e.DeploymentError:pass
            try:self.engine.docker('rm','--force',self.engine.ingress_name)
            except e.DeploymentError:pass
            for args in [('network','rm',self.engine.network),('network','rm',self.engine.ingress_network),('volume','rm',self.engine.c['data_volume'])]:
                try:self.engine.docker(*args)
                except e.DeploymentError:pass
        self.addCleanup(cleanup)
        certs=self.root/'fixtures';e.make_test_certs(certs)
        for n in ('server.crt','server.key','ca.crt'):shutil.copyfile(certs/n,self.root/'certs'/n)
        secret=self.root/'control'/'secret';secret.write_text('disposable-integration-secret-'+uuid.uuid4().hex);secret.chmod(0o600)
        release=self.root/'release';(release/'assets').mkdir(parents=True);(release/'assets'/'update_config.json').write_text('{}')
        manifest={'commit':'a'*40,'image':image}
        # Seed an actual old account/token in the disposable named volume.
        seed="import hashlib;from account_auth import AccountAuth;from shared_world import SharedWorld;w=SharedWorld('/data/world.sqlite3');a=AccountAuth('/data/auth.sqlite3',hasher=lambda p,s:hashlib.sha256(p+s).digest());a.create_invitation('Disposable-Integration-Invitation');a.register('ExistingOwner','password-good!',w,invitation_code='Disposable-Integration-Invitation');a.close();w.close()"
        self.engine.docker('run','--rm',*e.sandbox_flags(),'--mount','type=volume,src='+self.engine.c['data_volume']+',dst=/data','--mount','type=bind,src='+str(self.engine.c['game_data'])+',dst=/app/work/apk/luapack_extracted/GameData,readonly','--workdir','/app/server','--entrypoint','python',image,'-c',seed)
        self.engine.ensure_network()
        cid=self.engine.start(release,manifest);cids.append(cid)
        try:self.engine.healthy(cid,release,manifest,time.monotonic()+10)
        except e.DeploymentError:
            self.engine.validate_container(cid,release,manifest)
            self.fail((self.engine.root/'last-health-error.json').read_text())
        with self.assertRaises(e.DeploymentError):
            bad=dict(manifest,image='sha256:'+'f'*64);self.engine.validate_container(cid,release,bad)
        gateway=json.loads(self.engine.docker('network','inspect',self.engine.network))[0]['IPAM']['Config'][0]['Gateway']
        denial="import socket; targets=[('1.1.1.1',443),(%r,2375),(%r,2376)];\nfor target in targets:\n try: s=socket.create_connection(target,timeout=.5)\n except OSError: continue\n else: s.close(); raise AssertionError('Unexpected egress/protected host port access')" % (gateway,gateway)
        self.engine.docker('exec','--user','1000:1000',cid,'python','-I','-c',denial,timeout=5)
        timezone=self.engine.docker('exec',cid,'python','-I','-c',"import time;assert time.strftime('%z')=='+0900'")
        self.engine.volume_preflight(image)
        self.engine.docker('exec',cid,'python','-I','-c',"import sqlite3;db=sqlite3.connect('/data/auth.sqlite3');assert db.execute('PRAGMA journal_mode=WAL').fetchone()[0]=='wal';db.close()")
        self.engine.control({'op':'prepare','id':'test-handoff','target_release':'b'*40,'compatibility':e.PROTOCOL,'timeout_seconds':30})
        self.engine.control({'op':'commit','id':'test-handoff'})
        self.assertTrue(self.engine.control({'op':'status'})['write_fenced'])
        self.engine.docker('stop','--time','2',cid)
        try:snapshot=self.engine.snapshot('disposable-handoff',image,time.monotonic()+15)
        except e.DeploymentError:
            newest=max((self.engine.root/'logs').glob('*.log'),key=lambda p:p.stat().st_mtime)
            self.fail(newest.read_text())
        db=sqlite3.connect(snapshot/'auth.sqlite3')
        try:
            self.assertEqual('wal',db.execute('PRAGMA journal_mode=WAL').fetchone()[0])
            self.assertEqual(1,db.execute('SELECT count(*) FROM accounts').fetchone()[0])
            self.assertEqual(1,db.execute('SELECT count(*) FROM sessions').fetchone()[0])
        finally:db.close()
        # Sealed SQLite backups can retain a WAL header without any sidecars.
        # An open host connection here would mask the read-only baseline bug.
        self.assertEqual(b'\x02\x02',(snapshot/'auth.sqlite3').read_bytes()[18:20])
        self.assertFalse((snapshot/'auth.sqlite3-shm').exists())
        self.assertFalse((snapshot/'auth.sqlite3-wal').exists())
        next_manifest=dict(manifest,commit='b'*40)
        next_cid=self.engine.start(release,next_manifest,'test-handoff');cids.append(next_cid)
        self.engine.healthy(next_cid,release,next_manifest,time.monotonic()+10)
        self.engine.preserve_auth(snapshot,image,time.monotonic()+10)
        status=self.engine.control({'op':'status'})
        self.assertEqual('consumed',status['handoff']['phase'])
        self.assertEqual('b'*40,status['release'])
        # A newly issued session after the snapshot must survive code rollback.
        issued="import sqlite3,hashlib;db=sqlite3.connect('/data/auth.sqlite3');db.execute('INSERT INTO sessions VALUES(?,(SELECT account FROM accounts LIMIT 1))',(hashlib.sha256(b'new-earned-fixture-token').digest(),));db.commit();db.close()"
        self.engine.docker('exec',next_cid,'python','-I','-c',issued)
        self.engine.docker('stop','--time','2',next_cid)
        rollback_cid=self.engine.start(release,manifest);cids.append(rollback_cid)
        self.engine.healthy(rollback_cid,release,manifest,time.monotonic()+10)
        count=self.engine.docker('exec',rollback_cid,'python','-I','-c',"import sqlite3;db=sqlite3.connect('/data/auth.sqlite3');print(db.execute('SELECT count(*) FROM sessions').fetchone()[0])")
        self.assertEqual(b'2',count.strip())
        self.engine.preserve_auth(snapshot,image,time.monotonic()+10)
        # Reboot recovery restarts only the registered CID and trusted ingress.
        self.engine.record_active(rollback_cid,release,manifest)
        self.engine.docker('stop','--time','2',rollback_cid,self.engine.ingress_name)
        with patch.object(self.engine,'verify',return_value=(release,manifest)):
            recovered=self.engine.recover_active()
        self.assertEqual(rollback_cid,recovered['container'])
        self.assertEqual('a'*40,recovered['release'])


if __name__=='__main__':unittest.main()
