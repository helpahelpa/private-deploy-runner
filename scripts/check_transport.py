#!/usr/bin/env python3
"""Check exact-commit relay transports in fixed isolated Python/Node containers."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import time

import deploy_engine as engine
import git_source
import server_qa

IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
PYTHON_FLOOR = 59
NODE_FLOOR = 20


def require(value):
    if not value:
        raise ValueError("transport check failed")


def config_read(path):
    value = json.loads(Path(path).read_text())
    require(isinstance(value, dict) and set(value) <= {
        "python_image", "node_image", "minimum_python_tests", "minimum_node_tests", "fixtures", "python_workers"})
    require(type(value.get('python_workers',1)) is int and 1 <= value.get('python_workers',1) <= 3)
    for key in ("python_image", "node_image"):
        require(isinstance(value.get(key), str) and IMAGE.fullmatch(value[key]))
    for key, floor in (("minimum_python_tests", PYTHON_FLOOR), ("minimum_node_tests", NODE_FLOOR)):
        value.setdefault(key, floor)
        require(type(value[key]) is int and floor <= value[key] <= 100000)
    fixtures = value.get("fixtures", {})
    require(isinstance(fixtures, dict) and len(fixtures) <= 10000)
    for name, item in fixtures.items():
        require(isinstance(name, str))
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and "\\" not in name
                and path.parts[:4] == ("work", "apk", "luapack_extracted", "GameData") and len(path.parts) > 4
                and isinstance(item, dict) and set(item) == {"path", "sha256"}
                and isinstance(item["path"], str) and Path(item["path"]).is_absolute()
                and isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
    return value


def copy_fixtures(config, destination):
    files = {}
    total = 0
    for name, item in config.get("fixtures", {}).items():
        source = Path(item["path"])
        require(source.is_file() and not source.is_symlink())
        size = source.stat().st_size
        total += size
        require(size <= 32 * 1024 * 1024 and total <= 128 * 1024 * 1024)
        data = source.read_bytes()
        require(hashlib.sha256(data).hexdigest() == item["sha256"])
        target = destination / name
        require(not target.exists())
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files[name] = item["sha256"]
    return files


def git(source, *args):
    result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                             "-C", str(source), *args], capture_output=True, timeout=60)
    require(result.returncode == 0)
    return result.stdout


def curated(name):
    path = PurePosixPath(name)
    return ((path.parent in (PurePosixPath("deploy/cloudflare"), PurePosixPath("deploy/admin")) and path.suffix in (".py", ".mjs"))
            or (path.parent in (PurePosixPath("server"), PurePosixPath("tools")) and path.suffix == ".py")
            or name in ("server/native_contracts.json", "deploy/multiplayer/create_private_certs.py"))


def snapshot(source, commit, destination):
    require(isinstance(commit, str) and SHA.fullmatch(commit))
    require(git(source, "rev-parse", "--verify", commit + "^{commit}").decode().strip() == commit)
    require(git(source, "rev-parse", "HEAD").decode().strip() == commit)
    require(not git(source, "status", "--porcelain", "--untracked-files=no").strip())
    files = {}
    admitted = []
    for entry in git(source, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        if not entry:
            continue
        header, raw = entry.split(b"\t", 1)
        name = raw.decode("utf-8")
        if not curated(name):
            continue
        path = PurePosixPath(name)
        mode, kind, oid = header.split()
        require(mode in (b"100644", b"100755") and kind == b"blob"
                and not path.is_absolute() and ".." not in path.parts and "\\" not in name)
        admitted.append((name,oid.decode()))
    for (name,_),data in zip(admitted,git_source.read_blobs(source,[oid for _,oid in admitted],maximum_total=128*1024*1024)):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files[name] = hashlib.sha256(data).hexdigest()
    required = {
        "deploy/cloudflare/test_outbound443_agent.py", "deploy/cloudflare/test_private_relay.py",
        "deploy/cloudflare/test_wss_gateway.py", "deploy/cloudflare/test_outbound443_worker.mjs",
        "deploy/cloudflare/outbound443_worker.mjs", "server/multiplayer_server.py",
        "server/native_contracts.json", "deploy/multiplayer/create_private_certs.py",
    }
    require(required <= files.keys())
    (destination / "server/logs").mkdir()
    return files


def container(image, source, language, worker=None, workers=1):
    require(isinstance(image, str) and IMAGE.fullmatch(image))
    require(language in ("python", "node"))
    source = Path(source).resolve()
    require("," not in str(source) and ":" not in str(source))
    flags = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
             "--user=1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
             "--pids-limit=256", "--memory=2g", "--cpus=2", "--workdir=/source",
             "--env=HOME=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1",
             "--tmpfs=/tmp:rw,nosuid,nodev,size=1g,mode=1777",
             "--tmpfs=/source/server/logs:rw,nosuid,nodev,size=32m,uid=1000,gid=1000,mode=0700",
             "--mount", f"type=bind,src={source},dst=/source,readonly"]
    if language == "python":
        worker = 0 if worker is None else worker
        require(type(workers) is int and 1 <= workers <= 3 and type(worker) is int and 0 <= worker < workers)
        # Keep all transport/CLI modules in the same bounded worker pool.
        flags[flags.index('--memory=2g')] = '--memory=1g'
        flags[flags.index('--cpus=2')] = '--cpus=1'
        flags += ['--mount',f'type=bind,src={Path(server_qa.__file__).resolve()},dst=/trusted/server_qa.py,readonly']
        directories = ['deploy/cloudflare'] + [name for name in ('deploy/admin', 'tools')
                        if any((source / name).glob('test_*.py'))]
        return flags + ['--entrypoint=python3',image,'/trusted/server_qa.py','--directories',json.dumps(directories),
                        '--worker',str(worker),'--workers',str(workers)]
    tests = sorted(path for directory in ('deploy/cloudflare', 'deploy/admin')
                   for path in (source / directory).glob('test_*.mjs'))
    require(bool(tests))
    return flags + ["--entrypoint=node", image, "--test", "--test-reporter=tap",
                    *['/source/' + path.relative_to(source).as_posix() for path in tests]]


def python_result(output, minimum):
    text = output.decode("utf-8", errors="replace")
    totals = re.findall(r"^Ran ([0-9]+) tests? in .+$", text, re.MULTILINE)
    require(len(totals) == 1 and int(totals[0]) >= minimum
            and re.search(r"^OK\s*$", text, re.MULTILINE)
            and not re.search(r"\bskipped\b|\bexpected failure\b|\bunexpected success\b", text, re.IGNORECASE))
    return {"tests": int(totals[0]), "passed": int(totals[0]), "skipped": 0}


def node_result(output, minimum):
    text = output.decode("utf-8", errors="replace")
    result = {}
    for name in ("tests", "pass", "fail", "cancelled", "skipped", "todo"):
        values = re.findall(r"^# " + name + r" ([0-9]+)\s*$", text, re.MULTILINE)
        require(len(values) == 1)
        result[name] = int(values[0])
    require(result["tests"] >= minimum and result["pass"] == result["tests"]
            and all(result[key] == 0 for key in ("fail", "cancelled", "skipped", "todo")))
    return {"tests": result["tests"], "passed": result["pass"], "skipped": 0}


def private_log(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def check(config, source, commit, output):
    started = time.monotonic()
    output = Path(output).absolute()
    require(not output.exists())
    output.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="transport-source-", dir=output.parent) as directory:
        curated_source = Path(directory)
        curated_source.chmod(0o755)
        hashes = snapshot(Path(source), commit, curated_source)
        fixture_hashes = copy_fixtures(config, curated_source)
        outcomes = {}
        workers = config.get('python_workers',1)
        def run(language,index=None):
            name = language if index is None or workers==1 else language+'-worker-'+str(index)
            log = output / (name + ".private.log")
            work = output / name;work.mkdir()
            try:
                # Share the trusted server-QA lifetime guard. Its generated
                # name/CID file are outside the source mount, so even a test
                # that stops itself cannot outlive this bounded operation.
                engine.run_test_container(container(config[language + "_image"], curated_source, language,index,workers),
                                          work=work, timeout=1200, log=log)
            except engine.DeploymentError:
                if not log.exists():
                    private_log(log, b"Transport sandbox exceeded its lifetime or failed cleanup.\n")
                raise ValueError("transport sandbox failed") from None
            if index is not None:
                reports=[json.loads(line[len(server_qa.MARKER):]) for line in log.read_text().splitlines() if line.startswith(server_qa.MARKER)]
                require(len(reports)==1)
                return reports[0]
            parser = python_result if language=='python' else node_result
            return parser(log.read_bytes(),config['minimum_'+language+'_tests'])
        with ThreadPoolExecutor(max_workers=workers+1,thread_name_prefix='transport-qa') as pool:
            python=[pool.submit(run,'python',index) for index in range(workers)]
            node=pool.submit(run,'node')
            reports=[future.result() for future in python]
            outcomes['node']=node.result()
        aggregate=server_qa.aggregate(reports,workers,config['minimum_python_tests'])
        outcomes['python']=dict(aggregate,passed=aggregate['tests'])
        if workers>1:
            private_log(output/'python.private.log',b'\n'.join((output/('python-worker-'+str(index)+'.private.log')).read_bytes() for index in range(workers)))
        for language in ('python','node'):
            outcomes[language]['log_sha256']=engine.digest(output/(language+'.private.log'))
        engine.build_logs.emit('Fresh transport QA complete: '+str(round(time.monotonic()-started,3))+' seconds; '+str(workers)+' Python workers.')
        require(engine.tree(curated_source) == dict(hashes, **fixture_hashes))
        receipt = {"schema": 1, "commit": commit, "passed": True, "source_files": hashes,
                   "fixture_files": fixture_hashes,
                   "python_image": config["python_image"], "node_image": config["node_image"],
                   "results": outcomes, "sandbox": {"network": "none", "user": "1000:1000", "read_only": True,
                                                       "capabilities": [], "secret_mounts": False}}
        engine.write_json(output / "transport.json", receipt)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "source", "commit", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        check(config_read(args.config), args.source, args.commit, args.output)
    except Exception:
        print("transport_failed", flush=True)
        return 1
    print("transport_passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
