"""Source-QA lifetime checks; no production/runtime world operations."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('server_cleanup_engine',Path(__file__).resolve().parents[1]/'scripts/deploy_engine.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)


class ServerCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
        self.args=['docker','run','--rm','--network=none','fixture-image','fixture-test']

    def succeeded(self,args,**kw):
        Path(args[args.index('--cidfile')+1]).write_text('a'*64)
        return b'fixture-result'

    def cleanup(self,result=0,stderr=b''):
        return SimpleNamespace(returncode=result,stdout=b'',stderr=stderr)

    def test_success_removes_exact_cid_without_mutating_input(self):
        original=self.args[:]
        with patch.object(e,'run',side_effect=self.succeeded) as run,patch.object(e.subprocess,'run',return_value=self.cleanup()) as cleanup:
            self.assertEqual(b'fixture-result',e.run_test_container(self.args,work=self.work,timeout=3))
        self.assertEqual(original,self.args)
        argv=run.call_args.args[0]
        self.assertIn('private.private-role=server-qa',argv)
        self.assertRegex(argv[argv.index('--name')+1],r'^private-private-server-qa-[0-9a-f]{32}$')
        self.assertEqual(['docker','rm','--force','a'*64],cleanup.call_args.args[0])
        self.assertFalse(list(self.work.glob('*.cid')))

    def test_cli_timeout_still_removes_owned_cid(self):
        calls=[]
        def process(argv,**kw):
            calls.append(argv)
            if argv[:2]==['docker','run']:
                Path(argv[argv.index('--cidfile')+1]).write_text('b'*64)
                raise subprocess.TimeoutExpired(argv,kw['timeout'])
            return self.cleanup()
        with patch.object(e.subprocess,'run',side_effect=process):
            with self.assertRaisesRegex(e.DeploymentError,'exceeded its time limit'):
                e.run_test_container(self.args,work=self.work,timeout=1)
        self.assertEqual(['docker','rm','--force','b'*64],calls[-1])

    def test_timeout_before_cidfile_uses_exact_generated_name(self):
        with patch.object(e,'run',side_effect=e.DeploymentError('fixture timeout')) as command,patch.object(e.subprocess,'run',return_value=self.cleanup()) as cleanup:
            with self.assertRaises(e.DeploymentError):e.run_test_container(self.args,work=self.work,timeout=1)
        argv=command.call_args.args[0]
        self.assertEqual(['docker','rm','--force',argv[argv.index('--name')+1]],cleanup.call_args.args[0])

    def test_invalid_cidfile_cannot_select_cleanup_target(self):
        def invalid(args,**kw):
            Path(args[args.index('--cidfile')+1]).write_text('not-an-owned-container')
            return b'fixture'
        with patch.object(e,'run',side_effect=invalid) as command,patch.object(e.subprocess,'run',return_value=self.cleanup()) as cleanup:
            e.run_test_container(self.args,work=self.work,timeout=1)
        self.assertEqual(command.call_args.args[0][command.call_args.args[0].index('--name')+1],cleanup.call_args.args[0][-1])

    def test_auto_removed_container_is_expected(self):
        with patch.object(e,'run',side_effect=self.succeeded),patch.object(e.subprocess,'run',return_value=self.cleanup(1,b'Error response from daemon: No such container: fixture')):
            self.assertEqual(b'fixture-result',e.run_test_container(self.args,work=self.work,timeout=1))

    def test_cleanup_daemon_failure_is_not_silenced(self):
        with patch.object(e,'run',side_effect=self.succeeded),patch.object(e.subprocess,'run',return_value=self.cleanup(1,b'Cannot connect to Docker daemon')):
            with self.assertRaisesRegex(e.DeploymentError,'cleanup failed'):e.run_test_container(self.args,work=self.work,timeout=1)

    def test_each_invocation_has_unique_identity(self):
        commands=[]
        def success(argv,**kw):commands.append(argv);return b'fixture'
        with patch.object(e,'run',side_effect=success),patch.object(e.subprocess,'run',return_value=self.cleanup()):
            e.run_test_container(self.args,work=self.work,timeout=1)
            e.run_test_container(self.args,work=self.work,timeout=1)
        self.assertNotEqual(commands[0][commands[0].index('--name')+1],commands[1][commands[1].index('--name')+1])
        self.assertNotEqual(commands[0][commands[0].index('--cidfile')+1],commands[1][commands[1].index('--cidfile')+1])

    def test_runtime_commands_cannot_enter_source_qa_helper(self):
        for command in (['docker','start','fixture'],['docker','run','--name','live-world','fixture'],['docker','run','--cidfile=/tmp/untrusted','fixture']):
            with self.assertRaises(e.DeploymentError):e.run_test_container(command,work=self.work,timeout=1)


@unittest.skipUnless(os.environ.get('PRIVATE_SERVER_CLEANUP_DOCKER')=='1','Enable isolated Docker timeout regression explicitly')
class RealDockerCleanupTests(unittest.TestCase):
    def test_self_stopped_source_qa_is_killed_after_one_second_timeout(self):
        real_run=subprocess.run;observed={};commands=[]
        def recorded(argv,**kw):
            commands.append(argv)
            try:return real_run(argv,**kw)
            except subprocess.TimeoutExpired as error:
                observed['stdout']=error.stdout or b''
                raise
        args=['docker','run','--rm','--init','--network=none','--read-only','--user=1000:1000','--cap-drop=ALL',
              '--security-opt=no-new-privileges:true','--memory=64m','--pids-limit=16','--entrypoint=python',e.BASE,
              '-I','-c',"import os,signal;print('qa-self-stopped',flush=True);os.kill(os.getpid(),signal.SIGSTOP)"]
        name=None
        try:
            with tempfile.TemporaryDirectory() as work,patch.object(e.subprocess,'run',side_effect=recorded):
                with self.assertRaisesRegex(e.DeploymentError,'exceeded its time limit'):
                    e.run_test_container(args,work=Path(work),timeout=1)
            run=next(argv for argv in commands if argv[:2]==['docker','run'])
            name=run[run.index('--name')+1]
            self.assertIn(b'qa-self-stopped',observed.get('stdout',b''),'Self-stop code must actually execute before timeout')
            inspection=real_run(['docker','inspect',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertNotEqual(0,inspection.returncode,'Timed-out source-QA container must be removed')
            remaining=real_run(['docker','ps','--all','--quiet','--filter','label='+run[run.index('private.private-qa-id='+name.rsplit('-',1)[1])]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertEqual(0,remaining.returncode)
            self.assertEqual(b'',remaining.stdout.strip())
        finally:
            if name:real_run(['docker','rm','--force',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)


if __name__=='__main__':unittest.main()
