#!/usr/bin/env python3
"""Trusted local deployment boundary. Never execute repository commands on the host."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import build_logs
import server_qa
import component_inputs
import git_source
import client_qa
import qa_tasks
import admin_runtime

BASE = 'python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72'
PROTOCOL = 'clone-coop-handoff-v1'
COMPATIBILITY = 'world-invitations-v2'
SHA = re.compile(r'[0-9a-f]{40}')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}')
FORBIDDEN = re.compile(r'(^|[._-])(sqlite3?|db|pem|key|crt|p12|pfx|jks|save|profile|secret|token|credentials)([._-]|$)', re.I)


def compatible_schema(value):
    return isinstance(value,str) and NAME.fullmatch(value) and (value==COMPATIBILITY or value.endswith('-'+COMPATIBILITY))
PROXY_PROGRAM = """import os,select,socket,socketserver,threading
TARGET=os.environ['WORLD_TARGET']
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  try:
   with socket.create_connection((TARGET,self.server.server_address[1]),timeout=3) as upstream:
    upstream.settimeout(None);self.request.settimeout(None)
    peers=[self.request,upstream]
    while True:
     ready,_,_=select.select(peers,[],[],60)
     for source in ready:
      data=source.recv(65536)
      if not data:return
      (upstream if source is self.request else self.request).sendall(data)
  except OSError:pass
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
for port in (9443,9444,9445):
 server=Server(('0.0.0.0',port),Handler)
 threading.Thread(target=server.serve_forever,daemon=True).start()
threading.Event().wait()
"""
DOCKERFILE = '''FROM %s
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --chown=1000:1000 server/ /app/server/
RUN mkdir -p /data /admin /app/server/logs && chown -R 1000:1000 /data /admin /app/server/logs
USER 1000:1000
ENTRYPOINT ["python", "/app/server/multiplayer_server.py"]
''' % BASE


class DeploymentError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DeploymentError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(data, out, sort_keys=True, indent=2)
        out.write('\n'); out.flush(); os.fsync(out.fileno())
    os.replace(temporary, path)


def tree(path):
    root = Path(path)
    require(root.is_dir() and not root.is_symlink(), 'Expected a regular directory')
    result = {}
    for child in sorted(root.rglob('*')):
        require(not child.is_symlink() and (child.is_dir() or child.is_file()), 'Links and special files are forbidden')
        if child.is_file():
            result[child.relative_to(root).as_posix()] = digest(child)
    return result


def server_identity(release):
    """Content identity of a release's server build, independent of its image build id.

    Two rebuilds of identical sources get different image IDs because the image
    configuration carries a creation timestamp; deployment decisions use this
    content identity instead."""
    info=json.loads((Path(release)/'server.json').read_text())
    source=info.get('source_files')
    require(isinstance(source,dict) and source and isinstance(info.get('base'),str),'Invalid server receipt')
    return hashlib.sha256(json.dumps({'base':info['base'],'source':source},sort_keys=True).encode()).hexdigest()


def admin_port_bindings(config):
    """Docker port bindings for the admin API: nothing unless explicitly published."""
    published = admin_publish(config)
    return {} if published is None else {'9445/tcp': [{'HostIp': published[0], 'HostPort': str(published[1])}]}


def admin_publish(config):
    """The reviewed admin publication as (address, port), or None when unpublished."""
    address = config.get('admin_publish_address')
    if not address:
        return None
    port = config.get('admin_public_port')
    require(type(port) is int and 1 <= port <= 65535 and isinstance(address, str) and 0 < len(address) <= 64,
            'Invalid admin publication')
    return address, port


def assets_digest(release):
    """Digest of the assets a release would serve."""
    return hashlib.sha256(json.dumps(tree(Path(release)/'assets'),sort_keys=True).encode()).hexdigest()


def relative(value):
    require(isinstance(value, str), 'Invalid relative path')
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and '..' not in path.parts and '\\' not in value, 'Invalid relative path')
    return path


def source_build_path(value):
    """Keep Git names out of Docker's unescaped comma-separated mount syntax."""
    path = relative(value)
    require(re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value)
            and value == path.as_posix() and '.' not in path.parts,
            'Unsafe server source or fixture filename')
    return path


def run(args, *, timeout=300, input=None, cwd=None, log=None, public_output=False):
    require(isinstance(args, list) and args and all(isinstance(x, str) and '\x00' not in x for x in args), 'Expected argument array')
    try:
        if public_output:
            build_logs.emit('Build/test command started: ' + (Path(log).name if log else 'source QA'))
            result = build_logs.run(args, timeout=timeout, log=log)
            require(result.returncode == 0, 'Trusted command failed; inspect the private local log')
            return result.stdout
        result = subprocess.run(args, cwd=cwd, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DeploymentError('Trusted command exceeded its time limit') from None
    if log:
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(result.stdout + b'\nSTDERR\n' + result.stderr)
    require(result.returncode == 0, 'Trusted command failed; inspect the private local log')
    return result.stdout


def run_test_container(args, *, work, timeout, log=None):
    """Bound only source-QA container lifetime, including Docker CLI timeout."""
    require(args[:2] == ['docker', 'run'], 'Expected a source-QA Docker run')
    require(not any(x in ('--cidfile', '--name') or x.startswith(('--cidfile=', '--name=')) for x in args[2:]),
            'Source-QA identity must be generated by the trusted helper')
    identifier = uuid.uuid4().hex
    name = 'private-private-server-qa-' + identifier
    cidfile = Path(work) / ('server-qa-' + identifier + '.cid')
    command = args[:2] + ['--cidfile', str(cidfile), '--name', name,
                          '--label', 'private.private-role=server-qa',
                          '--label', 'private.private-qa-id=' + identifier] + args[2:]
    try:
        return run(command, timeout=timeout, log=log, public_output=True)
    finally:
        # The CID file is never mounted into untrusted code. A trusted unique
        # name also covers a CLI timeout before Docker writes the CID file.
        target = name
        if cidfile.is_file() and not cidfile.is_symlink():
            value = cidfile.read_text().strip()
            if re.fullmatch(r'[0-9a-f]{64}', value):
                target = value
        try:
            cleanup = subprocess.run(['docker', 'rm', '--force', target], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=10)
        except subprocess.TimeoutExpired:
            raise DeploymentError('Source-QA container cleanup exceeded its time limit') from None
        require(cleanup.returncode == 0 or b'No such container:' in cleanup.stderr,
                'Source-QA container cleanup failed')
        cidfile.unlink(missing_ok=True)


def git(source, *args):
    # No hooks, aliases, credential helpers, submodules or source scripts run.
    return run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-C', str(source), *args]).decode().strip()


def verify_source(source, commit):
    require(SHA.fullmatch(commit), 'Full commit SHA required')
    require(git(source, 'rev-parse', 'HEAD') == commit, 'Source HEAD differs from requested commit')
    require(not git(source, 'status', '--porcelain', '--untracked-files=no'), 'Source has tracked changes')


def sandbox_flags():
    return ['--network=none', '--read-only', '--user=1000:1000', '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true', '--pids-limit=256', '--memory=2g', '--cpus=2',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=256m,mode=1777',
            '--tmpfs=/app/server/logs:rw,nosuid,nodev,size=32m,uid=1000,gid=1000,mode=0700']


def make_test_certs(destination):
    # Fixed host openssl commands; these keys are disposable test fixtures only.
    destination.mkdir()
    ext = destination/'extensions.cnf'
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    for args in [
        ['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=Ephemeral Deployment Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout','ca.key','-out','ca.crt'],
        ['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout','server.key','-out','server.csr'],
        ['x509','-req','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-set_serial','1','-days','1','-extfile','extensions.cnf','-out','server.crt']]:
        run(['openssl', *args], cwd=destination)
    for p in destination.iterdir():
        p.chmod(0o444)
    destination.chmod(0o755)


def build_server(source, commit, output, game_data=None, game_text=None, data_compatibility=COMPATIBILITY,*,component_cache=None,force_full_qa=False,qa_workers=2):
    started = time.monotonic()
    require(compatible_schema(data_compatibility), 'Invitation-enforcing compatibility policy required')
    require(type(force_full_qa) is bool and type(qa_workers) is int and 1<=qa_workers<=4,'Invalid server QA policy')
    source, output = Path(source).resolve(), Path(output).absolute()
    verify_source(source, commit)
    require(not output.exists(), 'Build output already exists')
    logs = output.with_name(output.name+'.logs')/uuid.uuid4().hex; logs.mkdir(parents=True, mode=0o700)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='server-build-', dir=output.parent) as temporary:
        work = Path(temporary); work.chmod(0o755)
        context = work/'context'; (context/'server').mkdir(parents=True)
        require((source/'server').is_dir() and not (source/'server').is_symlink(), 'Unsafe server directory')
        # NUL records preserve literal Git names. Line splitting and Git's
        # quoted output can otherwise hide controls or change filename meaning.
        names=run(['git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-C',str(source),
                   'ls-tree','-rz','--full-tree',commit])
        objects={}
        for raw in names.split(b'\0'):
            if not raw:continue
            header,name=raw.split(b'\t',1);mode,kind,oid=header.split()
            objects[name.decode('utf-8')]=(mode.decode(),kind.decode(),oid.decode())
        committed=list(objects)
        curated=[n for n in committed if (n.startswith('server/') and '/' not in n[len('server/'):] and (n.endswith('.py') or n=='server/native_contracts.json'))]
        potential_fixtures=[n for n in committed if (n.startswith('launch-build/') and n.endswith('.py')) or (n.startswith('server/test_') and n.endswith('.json')) or component_inputs.server_fixture(n)]
        for name in set(curated+potential_fixtures):
            source_build_path(name)
        fixture_names=[n for n in potential_fixtures if component_inputs.server_fixture(n) or n.startswith('server/')]
        selected=sorted(set(curated+fixture_names))
        require(all(objects[n][0] in ('100644','100755') and objects[n][1]=='blob' for n in selected),'Unsafe server source kind')
        contents=dict(zip(selected,git_source.read_blobs(source,[objects[n][2] for n in selected])))
        require('server/multiplayer_server.py' in curated,'Server entry point missing')
        source_hashes={}
        for name in curated:
            path=source/name;require(path.is_file() and not path.is_symlink(),'Unsafe server source file')
            content=contents[name]
            require(len(content)<=32*1024*1024,'Oversized source file')
            target=context/name;target.write_bytes(content);os.utime(target,(0,0))
            source_hashes[name]=hashlib.sha256(content).hexdigest()
        fixtures=work/'fixtures';fixtures.mkdir();fixtures.chmod(0o755)
        for name in fixture_names:
            path=source/name
            require(path.is_file() and not path.is_symlink(),'Unsafe test fixture')
            target=fixtures/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(contents[name])
        data=None;text=None
        if game_data:
            data=Path(game_data).resolve();require(data.is_dir(),'GameData directory missing')
            if game_text is None and len(data.parents)>2 and (data.parents[2]/'GameText_xored.txt').is_file():game_text=data.parents[2]/'GameText_xored.txt'
        if game_text:
            text=Path(game_text).absolute();require(text.is_file() and not text.is_symlink(),'GameText fixture missing')
        def material():
            return {'schema':2,'server':source_hashes,'fixtures':tree(fixtures),
                    'source_boundary':component_inputs.identity({n:':'.join(v) for n,v in objects.items()},'server'),
                    'boundary_policy':digest(component_inputs.__file__),'object_reader':digest(git_source.__file__),
                    'game_data':tree(data) if data else None,
                    'game_text':digest(text) if text else None,'base':BASE,'dockerfile':DOCKERFILE,
                    'compatibility':data_compatibility,'protocol':PROTOCOL,'workers':qa_workers,
                    'engine':digest(__file__),'admin_runtime':digest(admin_runtime.__file__),'qa_runner':digest(server_qa.__file__),'module_cache':digest(qa_tasks.__file__),
                    'evidence_validator':digest(client_qa.__file__),'build_logging':digest(build_logs.__file__),
                    'host_tools':{name:digest(Path(found).resolve()) if (found:=shutil.which(name)) else None for name in ('docker','openssl')},
                    'minimum_tests':server_qa.MINIMUM_TESTS}
        material_inputs=material();cache_key=server_qa.fingerprint(material_inputs)
        store=server_qa.Store(component_cache) if component_cache else None
        cached=store.lookup(cache_key) if store and not force_full_qa else None
        (context/'Dockerfile').write_text(DOCKERFILE)
        iid = work/'image-id'
        if cached:
            image=cached['receipt']['image']
            run(['docker','image','load','--input',str(cached['path']/'server-image.tar')],timeout=1800,log=logs/'build.log')
            build_logs.emit('Whole server component cache hit; full suite evidence reused, admission invariants run fresh.')
            build_logs.emit('Cached server QA: '+str(cached['qa']['tests'])+' passed; zero failures, errors or skips.')
        else:
            build_logs.emit('Full server QA requested.' if force_full_qa else 'Server component changed; building and testing the complete server.')
            run(['docker','build','--network=none','--pull=false','--iidfile',str(iid),'-f',str(context/'Dockerfile'),str(context)], timeout=1800, log=logs/'build.log', public_output=True)
            image=iid.read_text().strip()
        require(IMAGE.fullmatch(image),'Immutable image ID missing')
        certs = work/'test-certs'; make_test_certs(certs)
        # Tests need a certificate generator path. Supply a fixed copy adapter,
        # never repository deployment tooling, and only ephemeral fixture keys.
        helper_dir = work/'helper'; helper_dir.mkdir(); helper_dir.chmod(0o755)
        helper = helper_dir/'create_private_certs.py'
        helper.write_text("import argparse,shutil\nfrom pathlib import Path\np=argparse.ArgumentParser();p.add_argument('--directory',required=True);a=p.parse_args();d=Path(a.directory);d.mkdir(parents=True,exist_ok=True)\nfor n in ('ca.key','ca.crt','server.key','server.crt'): shutil.copyfile(Path('/test-certs')/n,d/n)\n")
        helper.chmod(0o444)
        cmd = ['docker','run','--rm',*sandbox_flags(),
               '--mount',f'type=bind,src={certs},dst=/test-certs,readonly',
               '--mount',f'type=bind,src={helper_dir},dst=/app/deploy/multiplayer,readonly']
        for name in fixture_names:
            cmd += ['--mount',f'type=bind,src={fixtures/name},dst=/app/{name},readonly']
        if data:
            cmd += ['--mount',f'type=bind,src={data},dst=/app/work/apk/luapack_extracted/GameData,readonly']
        if text:
            cmd += ['--mount',f'type=bind,src={text},dst=/app/work/GameText_xored.txt,readonly']
        cmd += ['--mount',f'type=bind,src={Path(server_qa.__file__).resolve()},dst=/trusted/server_qa.py,readonly',
                '--workdir=/app/server','--entrypoint=python',image]
        granular=None
        if store:
            discovery_root=work/'qa-discovery';discovery_root.mkdir()
            discovery=run_test_container(cmd+['/trusted/server_qa.py','--discover-only'],
                work=discovery_root,timeout=1800,log=logs/'discovery.log')
            reports=[json.loads(line[len(server_qa.MARKER):]) for line in discovery.decode().splitlines()
                     if line.startswith(server_qa.MARKER)]
            require(len(reports)==1 and reports[0].get('passed') is True,'Server module discovery failed')
            inventory=reports[0]['inventory'];module_ids=qa_tasks.modules(inventory)
            require(len(inventory)>=server_qa.MINIMUM_TESTS,'Server module inventory is incomplete')
        if cached:
            qa=dict(cached['qa'],fresh_tests=0)
            qa['modules']=[dict(item,reused=True,reason='verified whole server inputs unchanged')
                           for item in qa.get('modules',[])]
            shutil.copyfile(cached['path']/'tests.log',logs/'tests.log')
            require(qa['test_ids']==inventory,'Cached server inventory differs from fresh discovery')
        elif store:
            module_store=client_qa.Store(Path(component_cache)/'modules')
            keys,views,module_group={},{},{}
            batches=qa_tasks.server_batches(inventory)
            common=dict(material_inputs,source_boundary={'fallback':component_inputs.fallback_source(
                {n:':'.join(v) for n,v in objects.items()})})
            common.pop('server');common.pop('workers')
            common_sha256=client_qa.fingerprint(common)
            for index,batch in enumerate(batches):
                readable={name:value for module in batch
                          for name,value in qa_tasks.server_inputs(context,source_hashes,module).items()}
                views[index]=qa_tasks.materialize(context,work/('source-group-'+str(index)),readable)
                for name in fixture_names:
                    if name.startswith('server/'):
                        target=views[index]/name;target.parent.mkdir(parents=True,exist_ok=True)
                        os.link(fixtures/name,target)
                for module in batch:
                    module_group[module]=index
                    keys[module]=client_qa.fingerprint({'common_sha256':common_sha256,'server':readable,
                        'module':module,'test_ids':module_ids[module],'readable_group':batch})
            def execute_batch(batch,expected):
                index=module_group[batch[0]]
                worker_root=work/('qa-group-'+str(index));worker_root.mkdir()
                command=list(cmd)
                position=command.index('--workdir=/app/server')
                command[position:position]=['--mount',f'type=bind,src={views[index]/"server"},dst=/app/server,readonly']
                result=run_test_container(command+['/trusted/server_qa.py','--modules',json.dumps(batch)],
                    work=worker_root,timeout=1800,log=logs/('tests-group-'+str(index)+'.log'))
                reports=[json.loads(line[len(server_qa.MARKER):]) for line in result.decode().splitlines()
                         if line.startswith(server_qa.MARKER)]
                require(len(reports)==1,'Missing or ambiguous server QA group evidence')
                report=reports[0];expected_ids=sorted(name for names in expected.values() for name in names)
                command_report={'command':['server modules',*batch],'exit_code':0,'result':report}
                totals=client_qa.validate_results([command_report],expected_ids,len(expected_ids))
                require(totals['test_ids']==expected_ids,'Incomplete server QA execution group')
                build_logs.emit('Server QA group '+str(index)+': '+str(len(batch))+' modules, '
                    +str(report['tests'])+' tests freshly executed in '+str(report.get('elapsed_seconds'))+' seconds.')
                return {module:({'command':['server modules',*batch],'exit_code':0,
                    'result':dict(report,test_ids=sorted(name for name in report['test_ids']
                        if name.rsplit('.',2)[0]==module),tests=len(expected[module]))},result) for module in batch}
            granular=qa_tasks.run(inventory,keys,module_store,commit,execute_batch,
                workers=qa_workers,force=force_full_qa,minimum=server_qa.MINIMUM_TESTS,batches=batches)
            for item in granular['modules']:
                item['readable_group']=batches[module_group[item['module']]]
            qa=dict(granular['qa'],workers=qa_workers,partition='verified whole modules',
                    modules=granular['modules'],fresh_tests=granular['fresh_tests'],cache_groups=batches)
            (logs/'tests.log').write_bytes(b'\n'.join(granular['logs']));(logs/'tests.log').chmod(0o600)
            for item in granular['modules']:
                if item['reused']:
                    build_logs.emit('Server module '+item['module']+': cache hit; '+str(item['tests'])
                        +' passed at '+item['tested_source_commit'][:12]+', verified inputs unchanged.')
            build_logs.emit('Server module QA: '+str(sum(item['reused'] for item in granular['modules']))
                +'/'+str(len(module_ids))+' cache hits; '+str(granular['fresh_tests'])+' tests freshly executed.')
        else:
            def worker(index):
                worker_root=work/('qa-worker-'+str(index));worker_root.mkdir()
                result=run_test_container(cmd+['/trusted/server_qa.py','--worker',str(index),'--workers',str(qa_workers)],
                                          work=worker_root,timeout=1800,log=logs/('tests-worker-'+str(index)+'.log'))
                reports=[json.loads(line[len(server_qa.MARKER):]) for line in result.decode().splitlines() if line.startswith(server_qa.MARKER)]
                require(len(reports)==1,'Missing or ambiguous server QA worker evidence');return reports[0]
            with ThreadPoolExecutor(max_workers=qa_workers,thread_name_prefix='server-qa') as workers:
                futures=[workers.submit(worker,index) for index in range(qa_workers)]
                reports=[future.result() for future in futures]
            qa=server_qa.aggregate(reports,qa_workers,server_qa.MINIMUM_TESTS)
            with (logs/'tests.log').open('wb') as combined:
                for index in range(qa_workers):combined.write((logs/('tests-worker-'+str(index)+'.log')).read_bytes()+b'\n')
            (logs/'tests.log').chmod(0o600)
        # A trusted invariant suite prevents source tests accidentally omitting
        # invitation admission, durable tokens, and original recovery deadlines.
        invariants = """import tempfile,hashlib,time
from pathlib import Path
from unittest.mock import patch
from account_auth import AccountAuth,AuthError
from shared_world import SharedWorld
import clone_coop
assert clone_coop.DISCONNECT_GRACE_SECONDS==90
with tempfile.TemporaryDirectory() as t:
 p=Path(t); w=SharedWorld(p/'world.sqlite3'); a=AccountAuth(p/'auth.sqlite3',hasher=lambda p,s:hashlib.sha256(s+p).digest())
 try:
  a.register('GateCheck','password-pass!',w)
 except AuthError: pass
 else: raise AssertionError('Invitationless signup allowed')
 a.create_invitation('ephemeral-invariant-invitation'); s=a.register('GateCheck','password-pass!',w,invitation_code='ephemeral-invariant-invitation')
 token=s.token; guid=s.guid; a.close(); a=AccountAuth(p/'auth.sqlite3',hasher=lambda p,s:hashlib.sha256(s+p).digest())
 with patch('account_auth.time.time',return_value=time.time()+20*365*86400): assert a.authenticate_token('GateCheck',token,w).guid==guid
 a.close();w.close()
"""
        run_test_container(cmd+['-c',invariants],work=work,timeout=60,log=logs/'invariants.log')
        build_logs.emit('Fresh server admission invariants passed.')
        verify_source(source, commit)
        require(all(digest(source/name) == value for name,value in source_hashes.items()), 'Source changed while building')
        require(material()==material_inputs,'Server QA material inputs changed during build')
        if granular:qa_tasks.publish(module_store,granular,commit)
        artifact = work/'artifact'; artifact.mkdir()
        if cached:shutil.copyfile(cached['path']/'server-image.tar',artifact/'server-image.tar')
        else:run(['docker','image','save','--output',str(artifact/'server-image.tar'),image], timeout=1800)
        for name in ('build.log','tests.log','invariants.log'):
            shutil.copyfile(logs/name,artifact/name); (artifact/name).chmod(0o600)
        write_json(artifact/'qa.json',qa)
        receipt = {'format':1,'commit':commit,'image':image,'base':BASE,'source_files':source_hashes,
                   'tested_source_commit':cached['receipt'].get('tested_source_commit',cached['tested_source_commit']) if cached
                       else granular['tested_source_commit'] if granular else commit,
                   'cache_provenance':{'component':'whole server','key':cache_key,'reused':bool(cached),'force_full_qa':force_full_qa},
                   'tests_passed':True,'trusted_invariants_passed':True,'invitation_gate':True,
                   'handoff_compatibility':PROTOCOL,'data_compatibility':data_compatibility,
                   'image_tar_sha256':digest(artifact/'server-image.tar'),
                   'qa_receipt_sha256':digest(artifact/'qa.json'),
                   'test_log_sha256':digest(artifact/'tests.log'),'invariants_log_sha256':digest(artifact/'invariants.log')}
        write_json(artifact/'server.json',receipt)
        if store and not cached:store.publish(cache_key,artifact)
        os.replace(artifact,output)
        build_logs.emit('Server component complete: '+str(round(time.monotonic()-started,3))+' seconds.')
    return {'commit':commit,'image':image,'tests_passed':True}


def assemble(server, assets, provenance, tests_receipt, output):
    server, assets, output = Path(server), Path(assets), Path(output).absolute()
    info = json.loads((server/'server.json').read_text()); commit = info.get('commit','')
    require(SHA.fullmatch(commit) and IMAGE.fullmatch(info.get('image','')), 'Invalid server receipt')
    require(info.get('tests_passed') is True and info.get('trusted_invariants_passed') is True and info.get('invitation_gate') is True, 'Server checks required')
    require(compatible_schema(info.get('data_compatibility')), 'Invitation-enforcing compatibility policy required')
    require(digest(server/'server-image.tar') == info['image_tar_sha256'], 'Server image archive changed')
    asset_files = tree(assets)
    require('update_config.json' in asset_files and len(asset_files) > 1, 'Matching client assets required')
    require(not any(FORBIDDEN.search(part) for name in asset_files for part in PurePosixPath(name).parts), 'Persistent or secret data in assets')
    p, t = json.loads(Path(provenance).read_text()), json.loads(Path(tests_receipt).read_text())
    require(p.get('commit') == commit and p.get('tested') is True and p.get('files') == asset_files and
            p.get('tests_receipt_sha256') == digest(tests_receipt) and t.get('commit') == commit and t.get('passed') is True, 'Matching tested client provenance required')
    require(not output.exists(), 'Immutable release already exists')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='assemble-',dir=output.parent) as temporary:
        artifact=Path(temporary)/'release';artifact.mkdir()
        shutil.copytree(assets,artifact/'assets')
        shutil.copyfile(server/'server-image.tar',artifact/'server-image.tar')
        shutil.copyfile(server/'server.json',artifact/'server.json')
        require(tree(artifact/'assets') == asset_files, 'Assets changed during assembly')
        manifest={'format':1,'commit':commit,'image':info['image'],'handoff_compatibility':PROTOCOL,
                  'data_compatibility':info['data_compatibility'],'invitation_gate':True,
                  'client_tests_receipt_sha256':digest(tests_receipt),'files':tree(artifact)}
        write_json(artifact/'manifest.json',manifest); os.replace(artifact,output)
    return {'release':commit,'manifest_sha256':digest(output/'manifest.json')}


class Engine:
    def __init__(self, config):
        self.config_path=Path(config).resolve(); self.c=json.loads(self.config_path.read_text())
        c=self.c
        for key in ('local_root','game_data','certificates','control'):
            require(isinstance(c.get(key),str), 'Missing private path configuration')
            c[key]=(self.config_path.parent/c[key]).resolve()
        for key in ('desired_commit_file','repository','runtime_registry'):
            if c.get(key): c[key]=(self.config_path.parent/c[key]).resolve()
        self.root=c['local_root'];require(self.root != Path('/'), 'Dedicated private release store required')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700);self.root.chmod(0o700)
        for key in ('project','data_volume'):
            require(NAME.fullmatch(c.get(key,'')), 'Invalid runtime identity')
        self.network=c.get('network',c['project']+'-internal');require(NAME.fullmatch(self.network), 'Invalid network name')
        self.ingress_network=c.get('ingress_network',c['project']+'-ingress');require(NAME.fullmatch(self.ingress_network),'Invalid ingress network')
        self.world_alias=c['project']+'-active-world'
        self.ingress_name=c['project']+'-ingress'
        require(c.get('timezone','Asia/Tokyo')=='Asia/Tokyo','World timezone must remain Asia/Tokyo')
        require(compatible_schema(c.get('data_compatibility')), 'Invitation-enforcing compatibility policy required')
        require(1 <= c.get('handoff_timeout_seconds',30) <= 30 and 1 <= c.get('health_timeout_seconds',15) <= 20, 'Invalid bounded deployment timeout')
        for key in ('https_port','game_port'):
            require(type(c.get(key)) is int and 1024 <= c[key] <= 65535, 'Invalid loopback port')
        require(c['https_port'] != c['game_port'], 'Loopback ports must differ')
        require(isinstance(c.get('asset_origin'),str) and c['asset_origin'].startswith('https://') and '\n' not in c['asset_origin'], 'HTTPS asset origin required')
        require(type(c.get('backup_limit_bytes')) is int and 0 < c['backup_limit_bytes'] <= 128*1024*1024, 'Snapshot size bound must fit 128MiB staging limit')
        self.admin=admin_runtime.AdminRuntime(self)

    @contextmanager
    def lock(self, wait_seconds=0):
        require(type(wait_seconds) in (int, float) and 0 <= wait_seconds <= 30, 'Invalid deployment lock wait')
        with (self.root/'deployment.lock').open('a') as h:
            os.chmod(h.name,0o600)
            deadline = time.monotonic() + wait_seconds
            while True:
                try:
                    fcntl.flock(h,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise DeploymentError('Another deployment is running') from None
                    time.sleep(min(.05, remaining))
            try: yield
            finally: fcntl.flock(h,fcntl.LOCK_UN)

    def docker(self,*args,timeout=30,input=None):
        logs=self.root/'logs';logs.mkdir(exist_ok=True,mode=0o700)
        return run(['docker',*args],timeout=timeout,input=input,log=logs/(uuid.uuid4().hex+'.log'))

    def inspect(self,cid,timeout=30):
        require(re.fullmatch(r'[0-9a-f]{12,64}',cid or ''), 'Exact container ID required')
        result=json.loads(self.docker('inspect',cid,timeout=timeout));require(len(result)==1,'Expected one container');return result[0]

    def verify(self,release):
        require(not Path(release).is_symlink(),'Release may not be a symlink')
        path=Path(release).resolve();manifest=json.loads((path/'manifest.json').read_text())
        require(SHA.fullmatch(manifest.get('commit','')) and IMAGE.fullmatch(manifest.get('image','')), 'Invalid immutable release identity')
        require(manifest.get('format')==1 and manifest.get('data_compatibility')==self.c['data_compatibility'] and
                manifest.get('handoff_compatibility')==PROTOCOL and manifest.get('invitation_gate') is True, 'Incompatible release')
        actual=tree(path);actual.pop('manifest.json',None)
        require(actual==manifest.get('files'), 'Release content hash mismatch')
        require('assets/update_config.json' in actual and 'server-image.tar' in actual and 'server.json' in actual, 'Incomplete release')
        require(all(n in ('server-image.tar','server.json') or n.startswith('assets/') for n in actual),'Unexpected release content')
        info=json.loads((path/'server.json').read_text())
        require(info.get('commit')==manifest['commit'] and info.get('image')==manifest['image'] and
                info.get('tests_passed') is True and info.get('trusted_invariants_passed') is True and
                info.get('invitation_gate') is True and info.get('image_tar_sha256')==actual['server-image.tar'],'Server attestation mismatch')
        return path,manifest

    def active(self):
        p=self.root/'active.json';require(p.is_file() and not p.is_symlink(),'No adopted world');return json.loads(p.read_text())

    def tracked(self, active=None):
        """Latest adopted commit; the running server image may be older."""
        active=self.active() if active is None else active
        return active.get('tracked') or active['release']

    def control(self,request,timeout=3):
        secret=self.c['control']/'secret'
        require(secret.is_file() and not secret.is_symlink() and not secret.stat().st_mode & 0o077,'Private control secret required')
        value=secret.read_text().strip();require(32<=len(value)<=256,'Invalid control secret')
        frame=dict(request,token=value)
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(timeout);s.connect(str(self.c['control']/'socket'));s.sendall((json.dumps(frame)+'\n').encode())
            reply=s.makefile('rb').readline(65537)
        require(len(reply)<=65536,'Oversized control reply')
        result=json.loads(reply);require(result.get('ok') is True and isinstance(result.get('data'),dict),'Authenticated control rejected')
        return result['data']

    @property
    def served_assets(self):
        return self.root/'served'/'assets'

    def sync_assets(self,release,retain=()):
        """Publish a release's assets onto the stable served mount, atomically per file.

        Configuration files are replaced last so a client never sees a version
        whose payload is only half published. Only the current release and the
        explicitly retained previous one keep their files."""
        served=self.served_assets;source=Path(release)/'assets'
        wanted=tree(source)
        served.mkdir(parents=True,exist_ok=True)
        ordered=sorted(wanted,key=lambda name:(name.endswith('update_config.json') or name.endswith('apk-update.json'),name))
        for name in ordered:
            target=served/name;target.parent.mkdir(parents=True,exist_ok=True)
            if target.is_file() and digest(target)==wanted[name]:continue
            temporary=target.with_name('.pending-'+target.name)
            temporary.write_bytes((source/name).read_bytes())
            os.replace(temporary,target)
        keep=set(wanted)
        for previous in retain:
            keep.update(tree(Path(previous)/'assets'))
        for path in sorted(served.rglob('*'),reverse=True):
            name=path.relative_to(served).as_posix()
            if path.is_file() and name not in keep:path.unlink()
            elif path.is_dir() and not any(path.iterdir()):path.rmdir()
        require(tree(served) and all(digest(served/name)==wanted[name] for name in wanted),
                'Served asset publication is incomplete')
        return assets_digest(release)

    def assets_reload_supported(self):
        try:
            return self.control({'op':'status'}).get('assets_reload') is True
        except (DeploymentError,OSError,ValueError):
            return False

    def mounts(self,release,admin_enabled=None):
        c=self.c
        for key in ('game_data','certificates','control'):
            require(c[key].is_dir() and not c[key].is_symlink(),'Required runtime directory missing')
        mounts=[('volume',c['data_volume'],'/data',False),('bind',str(c['control']),'/control',False),
                ('bind',str(c['game_data']),'/app/work/apk/luapack_extracted/GameData',True),
                ('bind',str(self.served_assets),'/assets',True)]
        for name in ('server.crt','server.key','ca.crt'):
            p=c['certificates']/name;require(p.is_file() and not p.is_symlink(),'TLS identity missing')
            mounts.append(('bind',str(p),'/certs/'+name,True))
        return mounts+self.admin.mounts(self.admin.enabled() if admin_enabled is None else admin_enabled)

    def validate_container(self,cid,release,manifest,*,running=True,deadline=None):
        def budget():return max(.05,min(8,deadline-time.monotonic())) if deadline else 30
        data=self.inspect(cid,timeout=budget());host=data['HostConfig'];cfg=data['Config']
        require(data['Image']==manifest['image'] and (not running or data['State']['Running']),'World image/state mismatch')
        enabled=self.admin.enabled(cid)
        require(set(host.get('Tmpfs') or {})==({'/tmp'} if enabled else {'/tmp','/app/server/logs'}),'Unexpected world temporary mounts')
        self.admin.validate_world(cid,cfg)
        require(host.get('ReadonlyRootfs') and not host.get('Privileged') and host.get('NetworkMode')==self.network,'Unsafe world isolation')
        require(set(host.get('CapDrop') or [])=={'ALL'} and not host.get('CapAdd') and 'no-new-privileges:true' in (host.get('SecurityOpt') or []),'Unsafe world capabilities')
        require('TZ=Asia/Tokyo' in cfg.get('Env',[]),'World timezone mismatch')
        require(cfg.get('User')=='1000:1000' and host.get('RestartPolicy',{}).get('Name') in ('no',''),'Unsafe world user/restart policy')
        require(not host.get('Devices') and not host.get('DeviceRequests') and host.get('PidMode','')!='host' and host.get('IpcMode','')!='host','Host resources exposed')
        # Assets are served from the stable mount. A world started before that
        # mount existed still serves its own release directory; both are exact.
        variants=[]
        for source in (self.served_assets,Path(release)/'assets'):
            variant={(kind,str(path),target,ro) for kind,path,target,ro in self.mounts(release,enabled) if target!='/assets'}
            variant.add(('bind',str(source),'/assets',True))
            variants.append(variant)
        distro=cfg.get('Labels',{}).get('desktop.docker.io/wsl-distro','')
        expected=set()
        for variant in variants:
            translated=set()
            for kind,source,target,ro in variant:
                if kind=='bind' and re.fullmatch(r'[A-Za-z0-9_.-]+',distro):
                    # Docker Desktop rewrites WSL bind sources to a deterministic
                    # broker path; match its exact distro label + SHA256(source).
                    translated.add((kind,'/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/'+distro+'/'+hashlib.sha256(source.encode()).hexdigest(),target,ro))
                else:
                    translated.add((kind,source,target,ro))
            expected.add(frozenset(variant));expected.add(frozenset(translated))
        actual=frozenset((m['Type'],m.get('Name') if m['Type']=='volume' else m['Source'],m['Destination'],not m['RW']) for m in data['Mounts'] if m['Type']!='tmpfs')
        require(actual in expected,'Unexpected runtime mount binding')
        ports=host.get('PortBindings') or {}
        require(not ports,'World ports must be exposed only by the trusted ingress')
        networks=data.get('NetworkSettings',{}).get('Networks',{})
        require(set(networks)=={self.network},'Unexpected world network')
        network=json.loads(self.docker('network','inspect',self.network,timeout=budget()))[0]
        require(network.get('Internal') is True,'World network must deny external egress')
        command=cfg.get('Cmd') or []
        require('--deployment-release='+manifest['commit'] in command and '--deployment-control=/control/socket' in command and
                '--deployment-secret=/control/secret' in command,'World deployment identity flags missing')
        return data

    def container_assets_source(self,cid,release=None,deadline=None):
        """The host directory the running world serves /assets from."""
        data=self.inspect(cid,timeout=max(.05,min(8,deadline-time.monotonic())) if deadline else 30)
        distro=data['Config'].get('Labels',{}).get('desktop.docker.io/wsl-distro','')
        candidates=[self.served_assets]+([Path(release)/'assets'] if release is not None else [])
        for mount in data['Mounts']:
            if mount['Destination']!='/assets':continue
            source=Path(mount['Source'])
            for candidate in candidates:
                if source==candidate:return candidate
                # Docker Desktop rewrites the bind source to SHA256(host path).
                if re.fullmatch(r'[A-Za-z0-9_.-]+',distro) and source.name==hashlib.sha256(str(candidate).encode()).hexdigest():
                    return candidate
            require(source.is_dir(),'Asset mount source is unavailable')
            return source
        raise DeploymentError('Missing asset mount')

    def healthy(self,cid,release,manifest,deadline):
        last=None
        while time.monotonic()<deadline:
            try:
                remaining=max(.05,min(2,deadline-time.monotonic()))
                status=self.control({'op':'status'},remaining)
                require(status.get('release')==manifest['commit'] and status.get('compatibility')==PROTOCOL and not status.get('write_fenced'),'World control identity mismatch')
                self.validate_container(cid,release,manifest,deadline=deadline)
                self.validate_ingress(deadline=deadline)
                self.admin.healthy(cid,timeout=max(.1,min(3,deadline-time.monotonic())))
                context=ssl.create_default_context(cafile=str(self.c['certificates']/'ca.crt'))
                connection=http.client.HTTPSConnection('localhost',self.c['https_port'],context=context,timeout=max(.05,min(2,deadline-time.monotonic())))
                try:
                    connection.request('GET','/healthz');response=connection.getresponse();require(response.status==200,'HTTPS health rejected');response.read(65536)
                    served=self.container_assets_source(cid,release,deadline)
                    connection.request('GET','/update_config.json');response=connection.getresponse();require(response.status==200 and hashlib.sha256(response.read()).hexdigest()==digest(served/'update_config.json'),'Served asset identity mismatch')
                finally:connection.close()
                require(time.monotonic()<deadline,'World health exceeded deadline')
                return status
            except (DeploymentError,OSError,ValueError) as e:
                last=e;time.sleep(.1)
        write_json(self.root/'last-health-error.json',{'error_type':type(last).__name__,'error':str(last)})
        raise DeploymentError('World health deadline expired') from None

    def ensure_network(self):
        self.docker('volume','inspect',self.c['data_volume'])
        self.admin.preflight()
        try: found=json.loads(self.docker('network','inspect',self.network))[0]
        except DeploymentError:
            self.docker('network','create','--internal','--label','private.trusted-project='+self.c['project'],self.network)
            found=json.loads(self.docker('network','inspect',self.network))[0]
        require(found.get('Internal') is True,'Existing network is not internal')

    def base_id(self):
        if not getattr(self,'_base_image',None):
            self._base_image=json.loads(self.docker('image','inspect',BASE))[0]['Id']
        return self._base_image

    def ingress_id(self):
        value=self.docker('inspect','--type','container','--format','{{.Id}}',self.ingress_name).decode().strip()
        require(re.fullmatch(r'[0-9a-f]{64}',value),'Trusted ingress container missing')
        return value

    def validate_ingress(self,deadline=None,running=True):
        def budget():return max(.05,min(3,deadline-time.monotonic())) if deadline else 15
        data=json.loads(self.docker('inspect','--type','container',self.ingress_name,timeout=budget()))[0]
        host,cfg=data['HostConfig'],data['Config']
        require(data['Image']==self.base_id() and (not running or data['State']['Running']),'Trusted ingress image/state mismatch')
        require(cfg.get('Entrypoint')==['python'] and cfg.get('Cmd')==['-I','-c',PROXY_PROGRAM],'Untrusted ingress program')
        require('WORLD_TARGET='+self.world_alias in cfg.get('Env',[]),'Ingress target mismatch')
        require(not data.get('Mounts') and host.get('ReadonlyRootfs') and not host.get('Privileged'),'Unsafe ingress mounts/isolation')
        require(cfg.get('User')=='1000:1000' and set(host.get('CapDrop') or [])=={'ALL'} and not host.get('CapAdd') and
                'no-new-privileges:true' in (host.get('SecurityOpt') or []),'Unsafe ingress privileges')
        require(not host.get('Devices') and not host.get('DeviceRequests') and host.get('PidMode','')!='host' and host.get('IpcMode','')!='host','Host resources exposed to ingress')
        require(host.get('RestartPolicy',{}).get('Name') in ('no',''),'Unmanaged ingress restart policy')
        require(host.get('PortBindings')==self.ingress_bindings(),'Unsafe ingress port bindings')
        require(set(data['NetworkSettings']['Networks'])=={self.network,self.ingress_network},'Unexpected ingress networks')
        return data

    def ingress_bindings(self):
        return {'9443/tcp':[{'HostIp':'127.0.0.1','HostPort':str(self.c['https_port'])}],
                '9444/tcp':[{'HostIp':'127.0.0.1','HostPort':str(self.c['game_port'])}]}

    def ensure_ingress(self):
        try:data=json.loads(self.docker('inspect','--type','container',self.ingress_name))[0]
        except DeploymentError:data=None
        if data is not None:
            self.validate_ingress(running=False)
            if not data['State']['Running']:self.docker('start',data['Id'])
            return data['Id']
        try:network=json.loads(self.docker('network','inspect',self.ingress_network))[0]
        except DeploymentError:
            self.docker('network','create','--label','private.trusted-project='+self.c['project'],self.ingress_network)
            network=json.loads(self.docker('network','inspect',self.ingress_network))[0]
        require(network.get('Driver')=='bridge' and not network.get('Internal'),'Ingress requires its dedicated bridge')
        cid=self.docker('create','--name',self.ingress_name,'--network',self.ingress_network,
                        '--label','private.trusted-project='+self.c['project'],
                        '--label','com.docker.compose.project='+self.c['project'],'--label','com.docker.compose.service=ingress',
                        '--read-only','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges:true',
                        '--restart','no','--pids-limit','128','--memory','128m','--cpus','0.5',
                        *[item for port,binding in self.ingress_bindings().items() for target in binding
                          for item in ('--publish','%s:%s:%s' % (target['HostIp'],target['HostPort'],
                                                                 port.split('/')[0]))],
                        '--env','WORLD_TARGET='+self.world_alias,'--entrypoint','python',self.base_id(),'-I','-c',PROXY_PROGRAM).decode().strip()
        try:
            self.docker('network','connect',self.network,cid)
            self.validate_ingress(running=False)
            self.docker('start',cid)
        except Exception:
            try:self.docker('rm','--force',cid)
            except Exception:pass
            raise
        return cid

    def start(self,release,manifest,handoff='',deadline=None,*,admin_enabled=None):
        self.sync_assets(release)
        if not deadline:self.ensure_network();self.ensure_ingress()
        c=self.c;enabled=self.admin.enabled() if admin_enabled is None else admin_enabled
        require(type(enabled) is bool and (not enabled or self.admin.config is not None),'Invalid admin runtime selection')
        name=c['project']+'-world-'+manifest['commit'][:12]+'-'+uuid.uuid4().hex[:8]
        args=['create','--name',name,
              '--label','private.trusted-project='+c['project'],'--label','private.release='+manifest['commit'],
              '--label','com.docker.compose.project='+c['project'],'--label','com.docker.compose.service=world',
              '--network',self.network,'--network-alias',self.world_alias,'--env','TZ='+c.get('timezone','Asia/Tokyo'),'--read-only','--user','1000:1000','--cap-drop','ALL',
              '--security-opt','no-new-privileges:true','--restart','no','--init','--pids-limit','256','--memory','2g',
              '--tmpfs','/tmp:rw,nosuid,nodev,size=32m,mode=1777',
              ]
        if not enabled:args+=['--tmpfs','/app/server/logs:rw,nosuid,nodev,size=32m,uid=1000,gid=1000,mode=0700']
        for kind,source,target,ro in self.mounts(release,enabled):
            args+=['--mount','type=%s,src=%s,dst=%s%s'%(kind,source,target,',readonly' if ro else '')]
        args += [manifest['image'],'--host=0.0.0.0','--container-only','--world=/data/world.sqlite3','--auth-db=/data/auth.sqlite3',
                 '--cert=/certs/server.crt','--key=/certs/server.key','--assets=/assets','--update-config=/assets/update_config.json',
                 '--asset-origin='+c['asset_origin'],'--deployment-control=/control/socket','--deployment-secret=/control/secret',
                 '--deployment-release='+manifest['commit']]
        args+=self.admin.flags(enabled)
        if handoff:args+=['--deployment-id='+handoff]
        timeout=max(.1,deadline-time.monotonic()) if deadline else 30
        try:
            cid=self.docker(*args,timeout=timeout).decode().strip()
            self.admin.modes[cid]=enabled
            self.docker('start',cid,timeout=max(.1,deadline-time.monotonic()) if deadline else 15)
            self.admin.attach(cid,deadline)
            return cid
        except Exception:
            try:self.docker('stop','--time','2',name,timeout=4)
            except Exception:pass
            raise

    def snapshot(self,deployment, image,deadline):
        target=self.root/'backups'/deployment;target.mkdir(parents=True,mode=0o700)
        # Fixed isolated stdlib helper reads exactly the named appdata volume;
        # image application code never executes in this process.
        code="""import sqlite3,json,os,time,shutil
from pathlib import Path
root=Path('/data');dest=Path('/snapshots');limit=int(os.environ['SNAPSHOT_LIMIT'])
assert sum(p.stat().st_size for p in root.rglob('*') if p.is_file())<=limit
for n in ('world.sqlite3','auth.sqlite3'):
 assert (root/n).is_file() and not (root/n).is_symlink()
 staging=Path('/tmp')/n;shutil.copyfile(root/n,staging)
 wal=root/(n+'-wal')
 if wal.exists():
  assert wal.is_file() and not wal.is_symlink()
  shutil.copyfile(wal,Path(str(staging)+'-wal'))
 with sqlite3.connect(str(staging)) as src,sqlite3.connect(str(dest/n)) as dst:
  src.backup(dst,pages=64)
  assert dst.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
 os.chmod(dest/n,0o600)
"""
        self.docker('run','--rm',*sandbox_flags(),'--mount','type=volume,src='+self.c['data_volume']+',dst=/data,readonly',
                    '--mount','type=bind,src='+str(target)+',dst=/snapshots','--env','SNAPSHOT_LIMIT='+str(self.c['backup_limit_bytes']),
                    '--entrypoint','python',image,'-I','-c',code,timeout=max(.1,deadline-time.monotonic()))
        require(all((target/n).is_file() for n in ('world.sqlite3','auth.sqlite3')),'Snapshot missing')
        write_json(target/'receipt.json',{'files':tree(target),'restore_automatically':False})
        return target

    def volume_preflight(self,image):
        code="from pathlib import Path; import os; r=Path('/data'); assert all((r/n).is_file() and not (r/n).is_symlink() for n in ('world.sqlite3','auth.sqlite3')); assert sum(p.stat().st_size for p in r.rglob('*') if p.is_file()) <= int(os.environ['SNAPSHOT_LIMIT'])"
        self.docker('run','--rm',*sandbox_flags(),'--mount','type=volume,src='+self.c['data_volume']+',dst=/data,readonly',
                    '--env','SNAPSHOT_LIMIT='+str(self.c['backup_limit_bytes']),'--entrypoint','python',image,'-I','-c',code,timeout=15)

    def preserve_auth(self,snapshot,image,deadline):
        # Existing accounts and bearer-token verifiers must survive startup. New
        # rows are allowed; credentials never leave the isolated helper.
        # The baseline is a sealed SQLite backup: immutable mode reads a WAL
        # header without trying to create SHM on its read-only bind mount.
        code="""import sqlite3
from pathlib import Path
with sqlite3.connect('file:/data/auth.sqlite3?mode=ro',uri=True) as now, sqlite3.connect('file:/baseline/auth.sqlite3?mode=ro&immutable=1',uri=True) as before:
 for table in ('accounts','sessions'):
  expected=set(before.execute('SELECT * FROM '+table).fetchall())
  assert expected <= set(now.execute('SELECT * FROM '+table).fetchall()), 'Existing auth rows changed'
"""
        self.docker('run','--rm',*sandbox_flags(),'--mount','type=volume,src='+self.c['data_volume']+',dst=/data,readonly',
                    '--mount','type=bind,src='+str(snapshot)+',dst=/baseline,readonly','--entrypoint','python',image,'-I','-c',code,
                    timeout=max(.1,deadline-time.monotonic()))

    def record_active(self,cid,release,manifest):
        value={'release':manifest['commit'],'tracked':manifest['commit'],'assets_release':manifest['commit'],
               'assets_release_path':str(release),'server_identity':server_identity(release),
               'image':manifest['image'],'container':cid,'release_path':str(release),
               'ingress':self.ingress_id(),'assets_sha256':hashlib.sha256(json.dumps(tree(Path(release)/'assets'),sort_keys=True).encode()).hexdigest()}
        value.update(self.admin.record(cid))
        write_json(self.root/'active.json',value)
        if self.c.get('runtime_registry'):write_json(self.c['runtime_registry'],value)
        return value

    def publish_unchanged(self, release, expected_tracked):
        """Adopt a release whose server image and assets are already active."""
        with self.lock(wait_seconds=20):
            path, new = self.verify(release)
            active = self.active()
            require(SHA.fullmatch(expected_tracked or '') and self.tracked(active) == expected_tracked,
                    'Stale unchanged publication')
            assets = assets_digest(path)
            require(self.same_server(path,active) and assets == active['assets_sha256'],
                    'Release changes the server build or assets; a handoff is required')
            old_path, old = self.verify(active['release_path'])
            self.healthy(active['container'], old_path, old, time.monotonic() + self.c.get('health_timeout_seconds', 15))
            current = self.inspect(active['container'])
            require(current['State']['Running'] and current['Image'] == active['image'],
                    'Active world is not the expected image')
            deployment = uuid.uuid4().hex
            event = {'id': deployment, 'from': old['commit'], 'to': new['commit'], 'phase': 'unchanged',
                     'restarted': False, 'rollback': False, 'container': active['container'],
                     'image': active['image'], 'assets_sha256': assets,
                     'previous_release_path': str(old_path), 'release_path': str(path)}
            write_json(self.root/'deployments'/(deployment+'.json'), event)
            updated = dict(active, tracked=new['commit'], assets_release=new['commit'],
                           assets_release_path=str(path))
            write_json(self.root/'active.json', updated)
            if self.c.get('runtime_registry'):
                write_json(self.c['runtime_registry'], updated)
            build_logs.emit('Deployment: server image and assets unchanged; the active world was left running.')
            return event

    def same_server(self, release, active):
        """True when the release runs the same server content and published shape."""
        try:
            matched = server_identity(release) == server_identity(active['release_path'])
        except (OSError, ValueError, KeyError, DeploymentError):
            try:
                image = json.loads((Path(release)/'manifest.json').read_text()).get('image')
            except (OSError, ValueError):
                return False
            matched = image is not None and image == active.get('image')
        if not matched:
            return False
        # A changed publication (for example the reviewed admin port) needs a
        # container recreation even when the server code is byte-identical.
        try:
            data = self.inspect(active['container'])
            enabled = self.admin.enabled(active['container'])
            return (data['HostConfig'].get('PortBindings') or {}) == admin_port_bindings(self.c if enabled else {})
        except (OSError, ValueError, KeyError, DeploymentError, AttributeError):
            return True

    def publish_assets(self, release, expected_tracked):
        """Publish a release's assets onto the running world without restarting it."""
        with self.lock(wait_seconds=20):
            path,new=self.verify(release);active=self.active()
            require(SHA.fullmatch(expected_tracked or '') and self.tracked(active)==expected_tracked,
                    'Stale asset publication')
            self.check_desired(new['commit'])
            require(self.same_server(path,active),'Changed server build requires a handoff')
            assets=assets_digest(path)
            require(assets!=active.get('assets_sha256'),'Identical assets require no publication')
            old_path,old=self.verify(active['release_path'])
            require(self.assets_reload_supported(),'Running world cannot reload published assets')
            require(self.container_assets_source(active['container'],active['release_path'])==self.served_assets,
                    'Running world serves a release directory; a handoff is required')
            self.healthy(active['container'],old_path,old,time.monotonic()+self.c.get('health_timeout_seconds',15))
            build_logs.emit('Deployment: publishing assets onto the running world.')
            self.sync_assets(path,retain=[old_path])
            self.healthy(active['container'],old_path,old,time.monotonic()+self.c.get('health_timeout_seconds',15))
            deployment=uuid.uuid4().hex
            event={'id':deployment,'from':old['commit'],'to':new['commit'],'phase':'assets','restarted':False,
                   'rollback':False,'container':active['container'],'image':active['image'],
                   'assets_sha256':assets,'assets_release':new['commit'],
                   'previous_release_path':str(old_path),'release_path':str(path)}
            write_json(self.root/'deployments'/(deployment+'.json'),event)
            updated=dict(active,tracked=new['commit'],assets_release=new['commit'],
                         assets_release_path=str(path),assets_sha256=assets)
            write_json(self.root/'active.json',updated)
            if self.c.get('runtime_registry'):write_json(self.c['runtime_registry'],updated)
            build_logs.emit('Deployment: assets published; the running world was not restarted.')
            return event

    def check_desired(self,commit):
        require(self.c.get('desired_commit_file') or self.c.get('repository'),'Latest-commit authority required')
        if self.c.get('desired_commit_file'):
            require(self.c['desired_commit_file'].read_text().strip()==commit,'Obsolete queued commit rejected')
        if self.c.get('repository'):
            require(git(self.c['repository'],'rev-parse','HEAD')==commit,'Current repository HEAD differs from promotion')

    def adopt(self,release,expected_current,bootstrap=False):
        with self.lock():
            require(not (self.root/'active.json').exists(),'World already adopted')
            path,manifest=self.verify(release);require(manifest['commit']==expected_current,'Unexpected adoption release')
            b=self.c.get('bootstrap',{});cid=b.get('container','')
            require(b.get('release')==expected_current,'Explicit bootstrap/adoption identity required')
            if bootstrap:
                current=self.inspect(cid)
                require(IMAGE.fullmatch(b.get('image','')) and current['State']['Running'] and current['Image']==b['image'],'Bootstrap image mismatch')
                require(any(m['Type']=='volume' and m.get('Name')==self.c['data_volume'] and m['Destination']=='/data' for m in current['Mounts']),'Bootstrap persistent volume mismatch')
                self.volume_preflight(manifest['image']);self.ensure_network()
                bootstrap_deadline=time.monotonic()+30
                self.docker('stop','--time','3',cid,timeout=5)
                try:
                    self.ensure_ingress()
                    snapshot=self.snapshot('bootstrap-'+uuid.uuid4().hex,manifest['image'],bootstrap_deadline)
                    new=self.start(path,manifest,deadline=bootstrap_deadline)
                    self.healthy(new,path,manifest,min(bootstrap_deadline,time.monotonic()+self.c.get('health_timeout_seconds',15)))
                    self.preserve_auth(snapshot,manifest['image'],bootstrap_deadline);cid=new
                except Exception:
                    # Same source/image failed initialization: keep original code
                    # and latest data; root must inspect before another bootstrap.
                    try:
                        if 'new' in locals():self.docker('stop','--time','3',new,timeout=5)
                        try:self.docker('stop','--time','2',self.ingress_name,timeout=4)
                        except Exception:pass
                        self.docker('start',cid)
                    except Exception:pass
                    raise DeploymentError('Bootstrap failed; inspect private runtime') from None
            else:self.healthy(cid,path,manifest,time.monotonic()+self.c.get('health_timeout_seconds',15))
            self.record_active(cid,path,manifest)
            return {'release':manifest['commit'],'adopted':True,'bootstrap':bootstrap,'container':cid}

    def promote(self,release,expected_current,rollback=False,*,replace_same_commit=False):
        with self.lock(wait_seconds=20):
            path,new=self.verify(release);active=self.active();old_path,old=self.verify(active['release_path'])
            require(type(replace_same_commit) is bool and SHA.fullmatch(expected_current or '')
                    and self.tracked(active)==expected_current,'Stale promotion')
            require(new['commit']!=expected_current or (replace_same_commit and not rollback and path!=old_path),
                    'Redundant promotion requires an explicit distinct release')
            if not rollback:
                self.check_desired(new['commit'])
                if self.c.get('repository'):git(self.c['repository'],'merge-base','--is-ancestor',old['commit'],new['commit'])
            self.healthy(active['container'],old_path,old,time.monotonic()+self.c.get('health_timeout_seconds',15))
            # Loading and all expensive hash/compatibility checks precede pause.
            self.docker('image','load','--input',str(path/'server-image.tar'),timeout=1800)
            require(json.loads(self.docker('image','inspect',new['image']))[0]['Id']==new['image'],'Loaded image identity mismatch')
            self.ensure_network();self.ensure_ingress();self.mounts(path);self.volume_preflight(new['image'])
            if self.admin.enabled() and not rollback:require(self.admin.supported(path),'Configured admin runtime requires an admin-capable release')
            if not rollback:self.check_desired(new['commit'])
            build_logs.emit('Deployment: target release and current world validated.')
            deployment=uuid.uuid4().hex;receipt=self.root/'deployments'/(deployment+'.json')
            event={'id':deployment,'from':old['commit'],'to':new['commit'],'phase':'preparing','rollback':rollback,
                   'from_container':active['container'],'previous_release_path':str(old_path),'release_path':str(path),
                   'replace_same_commit':replace_same_commit}
            write_json(receipt,event)
            started=time.monotonic();deadline=started+self.c.get('handoff_timeout_seconds',30)
            attempted=False;fenced=False;stopped=False;new_cid=None
            def budget():
                require(time.monotonic()<deadline,'Handoff budget exhausted');return max(.05,min(3,deadline-time.monotonic()))
            try:
                attempted=True
                build_logs.emit('Deployment: preparing planned handoff.')
                self.control({'op':'prepare','id':deployment,'target_release':new['commit'],'compatibility':PROTOCOL,'timeout_seconds':self.c.get('handoff_timeout_seconds',30)},budget())
                self.control({'op':'commit','id':deployment},budget());fenced=True
                build_logs.emit('Deployment: previous world fenced against writes.')
                self.admin.detach(active['container'],deadline)
                self.docker('stop','--time','2',active['container'],timeout=min(3,max(.1,deadline-time.monotonic())));stopped=True
                build_logs.emit('Deployment: previous world stopped.')
                snapshot=self.snapshot(deployment,new['image'],deadline)
                build_logs.emit('Deployment: consistent snapshot verified; automatic data restore disabled.')
                require(time.monotonic()<deadline-2,'Handoff budget exhausted before activation')
                build_logs.emit('Deployment: starting replacement container.')
                runtime_options={'admin_enabled':self.admin.supported(path)} if self.admin.enabled() else {}
                new_cid=self.start(path,new,deployment,deadline,**runtime_options)
                require(new_cid!=active['container'],'Replacement must use a new container')
                self.healthy(new_cid,path,new,min(deadline,time.monotonic()+self.c.get('health_timeout_seconds',15)))
                self.preserve_auth(snapshot,new['image'],deadline)
                build_logs.emit('Deployment: replacement health and account/session preservation verified.')
                require(not self.inspect(active['container'],timeout=budget())['State']['Running'],'Previous world is still running')
                require(time.monotonic()<deadline,'Handoff budget exhausted after auth verification')
                self.record_active(new_cid,path,new)
                event.update(phase='healthy',interruption_seconds=round(time.monotonic()-started,3),container=new_cid,old_stopped=True)
                write_json(receipt,event)
                build_logs.emit('Deployment: replacement active; previous container verified stopped.')
                return event
            except Exception:
                build_logs.emit('Deployment: handoff failed; checking runtime recovery.')
                if attempted and not fenced:
                    try:
                        state=self.control({'op':'status'});marker=state.get('handoff',{})
                        fenced=bool(state.get('write_fenced') and marker.get('id')==deployment and marker.get('phase')=='committed')
                        if not fenced:
                            if marker.get('id')==deployment and marker.get('phase')=='prepared':self.control({'op':'cancel','id':deployment})
                            event['phase']='cancelled'
                    except Exception:event['phase']='recovery_required'
                if fenced:
                    try:
                        # Never resume a consumed permit and never restore a DB.
                        build_logs.emit('Deployment: rolling back code while preserving current player data.')
                        if new_cid:
                            self.admin.detach(new_cid)
                            self.docker('stop','--time','2',new_cid,timeout=4)
                        self.docker('stop','--time','2',active['container'],timeout=4)
                        rollback_cid=self.start(old_path,old,admin_enabled=active.get('admin_enabled',False))
                        self.healthy(rollback_cid,old_path,old,time.monotonic()+self.c.get('health_timeout_seconds',15))
                        self.record_active(rollback_cid,old_path,old);event['phase']='rolled_back_code_only'
                    except Exception:event['phase']='recovery_required'
                write_json(receipt,event)
                build_logs.emit({'cancelled':'Deployment: handoff cancelled; deployment remains failed.',
                                 'rolled_back_code_only':'Deployment: previous code recovered; deployment remains failed.',
                                 'recovery_required':'Deployment: operator recovery required; deployment remains failed.'}.get(
                                     event['phase'],'Deployment: runtime recovery incomplete; deployment remains failed.'))
                raise DeploymentError('Deployment failed; outcome: '+event['phase']) from None

    def recover_active(self):
        with self.lock():
            active=self.active();path,manifest=self.verify(active['release_path'])
            require(active['release']==manifest['commit'] and active['image']==manifest['image'],'Active registry mismatch')
            state=self.validate_container(active['container'],path,manifest,running=False)
            running=self.docker('ps','--quiet','--filter','label=com.docker.compose.project='+self.c['project'],
                                '--filter','label=com.docker.compose.service=world','--no-trunc').decode().split()
            require(all(cid==active['container'] for cid in running),'Another managed world is running')
            self.ensure_ingress()
            if not state['State']['Running']:
                self.refresh_desktop_binds(path,manifest,state)
                self.docker('start',active['container'],timeout=10)
            self.admin.attach(active['container'],restarted=not state['State']['Running'])
            self.healthy(active['container'],path,manifest,time.monotonic()+self.c.get('health_timeout_seconds',15))
            self.record_active(active['container'],path,manifest)
            return {'release':manifest['commit'],'recovered':True,'container':active['container'],'ingress':self.ingress_id()}

    def refresh_desktop_binds(self,release,manifest,validated):
        """Re-register vanished Desktop bind mappings for a validated stopped world."""
        if validated['State']['Running']:return
        distro=validated['Config'].get('Labels',{}).get('desktop.docker.io/wsl-distro','')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',distro):return
        binds=[(source,target) for kind,source,target,ro in self.mounts(release,self.admin.enabled(validated.get('Id'))) if kind=='bind']
        translated={'/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/'+distro+'/'+hashlib.sha256(source.encode()).hexdigest()
                    for source,target in binds}
        if not any(m['Type']=='bind' and m['Source'] in translated for m in validated['Mounts']):return
        # Only exact paths already matched by validate_container are admitted.
        # No application data volume or application program enters this helper.
        require(all(not re.search(r'[,\x00-\x1f\x7f]',value) for pair in binds for value in pair),'Unsafe bind refresh path')
        name='private-bind-refresh-'+uuid.uuid4().hex
        args=['run','--rm','--name',name,'--label','private.trusted-project='+self.c['project'],
              '--label','private.runtime-role=bind-refresh',*sandbox_flags()]
        for source,target in binds:
            args+=['--mount','type=bind,src='+source+',dst='+target+',readonly']
        args+=['--entrypoint','python',manifest['image'],'-I','-c','pass']
        try:self.docker(*args,timeout=30)
        finally:
            # A CLI timeout can precede receipt of a CID. The trusted unique
            # name also removes that helper without touching any world CID.
            try:
                cleanup=subprocess.run(['docker','rm','--force',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            except subprocess.TimeoutExpired:
                raise DeploymentError('Bind refresh cleanup exceeded its time limit') from None
            require(cleanup.returncode==0 or b'No such container:' in cleanup.stderr,'Bind refresh cleanup failed')

    def status(self):
        with self.lock(wait_seconds=5):
            active=self.active();path,manifest=self.verify(active['release_path'])
            state=self.healthy(active['container'],path,manifest,time.monotonic()+self.c.get('health_timeout_seconds',15))
            return {'managed_release':active.get('tracked') or active['release'],'server_release':active['release'],
                    'image':active['image'],'container':active['container'],'server':state}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=('build-server','assemble','promote','adopt','status','rollback','recover-active'))
    for name in ('source','commit','output','game-data','game-text','server','assets','provenance','tests-receipt','config','release','expected-current'):p.add_argument('--'+name)
    p.add_argument('--bootstrap',action='store_true');a=p.parse_args()
    try:
        if a.command=='build-server':
            require(a.source and a.commit and a.output,'Build source/commit/output required');value=build_server(a.source,a.commit,a.output,a.game_data,a.game_text)
        elif a.command=='assemble':
            require(all((a.server,a.assets,a.provenance,a.tests_receipt,a.output)),'Assembly inputs required');value=assemble(a.server,a.assets,a.provenance,a.tests_receipt,a.output)
        else:
            require(a.config,'Private config required');engine=Engine(a.config)
            if a.command=='status':value=engine.status()
            elif a.command=='recover-active':value=engine.recover_active()
            else:
                require(a.release and a.expected_current,'Release and expected-current required')
                value=engine.adopt(a.release,a.expected_current,a.bootstrap) if a.command=='adopt' else engine.promote(a.release,a.expected_current,a.command=='rollback')
        print(json.dumps(value,sort_keys=True));return 0
    except Exception:
        print('Deployment command failed. Inspect private local logs/receipts; credentials are not printed.',file=sys.stderr);return 1


if __name__=='__main__':sys.exit(main())
