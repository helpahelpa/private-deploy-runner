#!/usr/bin/env python3
"""Private host broker: authenticated fixed operations and one deployment worker."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import shlex
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import traceback

import deploy_engine as engine
import check_transport as transport
import build_logs
import native_apk
import git_source
import watch_master as watch

SHA = re.compile(r"[0-9a-f]{40}\Z")
REQUEST_ID = re.compile(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,9}\Z")
LFS_POINTER = re.compile(rb"version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n\Z")
LIMIT = 4096
PRIVATE = Path(__file__).resolve().parents[1]


def job_key(sha, request_id=None):
    require(isinstance(sha, str) and SHA.fullmatch(sha))
    if request_id is None:
        return sha
    require(isinstance(request_id, str) and REQUEST_ID.fullmatch(request_id))
    return sha + '--' + request_id


def job_identity(key):
    require(isinstance(key,str))
    values=key.split('--')
    require(len(values) in (1,2))
    sha=values[0];request_id=values[1] if len(values)==2 else None
    require(job_key(sha,request_id)==key)
    return sha,request_id


@contextmanager
def public_logging(config, sha):
    keys = ("PRIVATE_BUILD_LOG_FILE", "PRIVATE_BUILD_LOG_PRIVACY")
    previous = {key: os.environ.get(key) for key in keys}
    literals = list(config.get("log_redactions", []))
    if config.get("client_config"):
        client = json.loads(Path(config["client_config"]).read_text())
        literals.extend(client.get("forbidden_apk_strings", []))
    if config.get("token_file"):
        literals.append(Path(config["token_file"]).read_text().strip())
    try:
        build_logs.configure(config["local_root"] / "public-logs" / sha, literals)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class BrokerError(Exception):
    pass


class PromotionRecoveryRequired(BrokerError):
    pass


def require(condition):
    if not condition:
        raise BrokerError("private operation rejected")


def config_read(path):
    value = json.loads(Path(path).read_text())
    for name in ("source", "control"):
        value[name] = watch.Identity.read(value[name])
    require(value["source"].full_name.lower() != value["control"].full_name.lower())
    for name in ("local_root", "source_cache", "source_deploy_key", "known_hosts", "client_config", "engine_config", "socket_path", "token_file"):
        require(isinstance(value.get(name), str) and Path(value[name]).is_absolute())
        value[name] = Path(value[name])
    require(value["local_root"] != Path("/") and value["source_cache"] != Path("/"))
    minimum = value.get("minimum_version", 62)
    require(type(minimum) is int and 62 <= minimum <= 2147483647)
    value["minimum_version"] = minimum
    require(isinstance(value.get("log_redactions", []), list)
            and all(isinstance(x, str) and x for x in value.get("log_redactions", [])))
    aliases = value.get("history_aliases", {})
    require(isinstance(aliases, dict) and all(isinstance(a, str) and SHA.fullmatch(a)
            and isinstance(b, str) and SHA.fullmatch(b) for a, b in aliases.items()))
    require(type(value.get("publish_apk", True)) is bool)
    require(type(value.get('require_request_id_for_submit',False)) is bool)
    require(type(value.get('server_qa_workers',2)) is int and 1 <= value.get('server_qa_workers',2) <= 4)
    require(type(value.get("control_private", True)) is bool)
    if value.get("static_assets"):
        base = value["static_assets"]
        require(isinstance(base, dict) and set(base) == {"path", "tree_sha256"}
                and isinstance(base["path"], str) and Path(base["path"]).is_absolute()
                and isinstance(base["tree_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", base["tree_sha256"]))
    if value.get("game_data"):
        require(isinstance(value["game_data"], str) and Path(value["game_data"]).is_absolute())
    if value.get("registry_config"):
        require(isinstance(value["registry_config"], str) and Path(value["registry_config"]).is_absolute())
    if value.get("transport_config"):
        require(isinstance(value["transport_config"], str) and Path(value["transport_config"]).is_absolute())
    if value.get("lfs_object_store"):
        require(isinstance(value["lfs_object_store"], str) and Path(value["lfs_object_store"]).is_absolute())
    if value.get("lfs_binary"):
        item = value["lfs_binary"]
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}
                and isinstance(item["path"], str) and Path(item["path"]).is_absolute()
                and isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
    return value


def verify_apk_update(client, manifest):
    # Older sealed releases predate native-content reuse. New builder output
    # binds public update metadata to the actual APK, independent asset release.
    if 'apk_input_sha256' not in manifest:
        return
    require(isinstance(manifest.get('apk_input_sha256'), str)
            and re.fullmatch(r'[0-9a-f]{64}', manifest['apk_input_sha256'])
            and isinstance(manifest.get('apk_source_commit'), str)
            and SHA.fullmatch(manifest['apk_source_commit']) and type(manifest.get('apk_reused')) is bool)
    expected = native_apk.update_metadata(manifest, client / 'client.apk')
    actual = json.loads((client / 'assets/apk-update.json').read_text())
    require(actual == expected)


class Operations:
    def __init__(self, config):
        self.c = config
        self.root = config["local_root"]
        self.github = watch.GitHub()

    def identities(self):
        # Reuse identity checks without loading watcher state or dispatching.
        verifier = object.__new__(watch.Watcher)
        verifier.github = self.github
        verifier.verify_identity(self.c["source"])
        verifier.verify_identity(self.c["control"], private=self.c.get("control_private", True))

    def current(self):
        self.identities()
        value = self.github.request(f"repos/{self.c['source'].full_name}/git/ref/heads/master")
        require(value["object"]["type"] == "commit" and isinstance(value["object"]["sha"], str)
                and SHA.fullmatch(value["object"]["sha"]))
        return value["object"]["sha"]

    def preflight(self):
        # Configuration errors must fail before any compiler or test container
        # starts. Read the private file directly without initializing runtime.
        value = json.loads(Path(self.c["engine_config"]).read_text())
        authority = value.get("desired_commit_file")
        require(isinstance(authority, str) and Path(authority).is_absolute())
        if self.c.get("transport_config"):
            transport.config_read(self.c["transport_config"])

    def command(self, argv, *, env=None, timeout=1800, cwd=None):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=timeout, env=env, cwd=cwd)
        if result.returncode:
            logs = self.root / "logs"
            logs.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(logs / (str(time.time_ns()) + ".log"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(result.stdout + b"\nSTDERR\n" + result.stderr)
            raise BrokerError("private command failed")
        return result.stdout

    def git_environment(self):
        # The cache is private and freshly initialized without host/global config.
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                   GIT_TERMINAL_PROMPT="0", GIT_ATTR_NOSYSTEM="1")
        for key in list(env):
            if key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_") or key in (
                "GIT_CONFIG_COUNT", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
                env.pop(key, None)
        env["GIT_SSH_COMMAND"] = " ".join(map(shlex.quote, [
            "ssh", "-i", str(self.c["source_deploy_key"]), "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o",
            "UserKnownHostsFile=" + str(self.c["known_hosts"]), "-o", "PasswordAuthentication=no",
        ]))
        env["GIT_ASKPASS"] = "/bin/false"
        env["SSH_ASKPASS"] = "/bin/false"
        return env

    def git(self, *arguments):
        env = self.git_environment()
        return self.command(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                             "-c", "credential.helper=", "-c", "core.filemode=false", *arguments], env=env)

    def fetch_lfs(self, sha):
        item = self.c.get("lfs_binary")
        require(item is not None)
        binary = Path(item["path"])
        require(binary.is_file() and not binary.is_symlink() and engine.digest(binary) == item["sha256"])
        cache = self.c["source_cache"]
        remote = "git@github.com:" + self.c["source"].full_name + ".git"
        # Git LFS otherwise reads source-owned .lfsconfig from HEAD. This bare
        # cache has no worktree and keeps HEAD on a trusted, unborn private ref;
        # the exact fetched SHA is supplied separately as the object source.
        require(not (cache / ".lfsconfig").exists() and not (cache / ".lfsconfig").is_symlink()
                and not (cache / "refs/heads/broker-lfs-unborn").exists()
                and not (cache / "packed-refs").exists())
        (cache / "HEAD").write_text("ref: refs/heads/broker-lfs-unborn\n")
        settings = {
            "core.hooksPath": "/dev/null", "core.fsmonitor": "false", "credential.helper": "",
            "core.askpass": "/bin/false", "remote.origin.url": remote,
            "lfs.storage": str(cache / "lfs"),
            "lfs.fetchinclude": "", "lfs.fetchexclude": "", "lfs.fetchrecentalways": "false",
            "lfs.remote.autodetect": "false", "lfs.remote.searchall": "false",
            "lfs.sshtransfer": "never", "lfs.skipdownloaderrors": "false",
        }
        env = self.git_environment()
        env["GIT_DIR"] = str(cache)
        env["GIT_CONFIG_COUNT"] = str(len(settings))
        for index, (key, value) in enumerate(settings.items()):
            env["GIT_CONFIG_KEY_" + str(index)] = key
            env["GIT_CONFIG_VALUE_" + str(index)] = value
        original_config = (cache / "config").read_bytes()
        try:
            # Pinned trusted Git LFS handles SSH authentication; source filters,
            # .lfsconfig URLs, and custom transfer executables cannot select it.
            self.command([binary, "fetch", "--include=", "--exclude=", "origin", sha], env=env, timeout=1800, cwd=cache)
        finally:
            # Git LFS can persist endpoint access hints. Keep the cache's strict
            # trusted init-only config instead of accepting those on next use.
            (cache / "config").write_bytes(original_config)

    def hydrate_lfs(self, pointers, destination, sha):
        if not pointers:
            return
        require(all(isinstance(oid, str) and re.fullmatch(r"[0-9a-f]{64}", oid)
                    and type(size) is int and 0 <= size <= 256 * 1024 * 1024
                    for oid, size in pointers.items()))
        require(sum(pointers.values()) <= 2 * 1024 * 1024 * 1024)
        roots = [self.c["source_cache"] / "lfs" / "objects"]
        if self.c.get("lfs_object_store"):
            roots.insert(0, Path(self.c["lfs_object_store"]))

        def locate(oid, size):
            for root in roots:
                path = root / oid[:2] / oid[2:4] / oid
                if not path.exists() and not path.is_symlink():
                    continue
                require(all(not part.is_symlink() for part in (root, root / oid[:2], path.parent, path))
                        and path.is_file() and path.stat().st_size == size and engine.digest(path) == oid)
                return path
            return None

        found = {oid: locate(oid, size) for oid, size in pointers.items()}
        if any(value is None for value in found.values()):
            self.fetch_lfs(sha)
            found = {oid: locate(oid, size) for oid, size in pointers.items()}
        for oid, source in found.items():
            require(source is not None)
            target = destination / ".git" / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, target)
            target.chmod(0o400)

    def source(self, sha, request_id=None):
        cache = self.c["source_cache"]
        cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        require(not cache.is_symlink())
        if not cache.exists():
            self.git("init", "--bare", cache)
        require((cache / "HEAD").is_file() and not (cache / "config").is_symlink())
        # Do not trust config from an imported/source-owned repository cache.
        config = self.git("--git-dir=" + str(cache), "config", "--local", "--list").decode()
        allowed = ("core.repositoryformatversion=", "core.filemode=", "core.bare=")
        require(all(line.startswith(allowed) for line in config.splitlines()))
        remote = "git@github.com:" + self.c["source"].full_name + ".git"
        self.git("--git-dir=" + str(cache), "fetch", "--no-tags", "--no-recurse-submodules", remote, sha)
        require(self.git("--git-dir=" + str(cache), "rev-parse", sha + "^{commit}").decode().strip() == sha)
        destination = self.root / "work" / job_key(sha, request_id)
        if destination.exists():
            require(request_id is None)
            shutil.rmtree(destination)
        destination.mkdir(parents=True, mode=0o700)
        entries = self.git("--git-dir=" + str(cache), "ls-tree", "-rz", "--full-tree", sha).split(b"\0")
        pointers = {}
        admitted = []
        for entry in entries:
            if not entry:
                continue
            header, raw_name = entry.split(b"\t", 1)
            mode, kind, oid = header.split()
            name = raw_name.decode("utf-8")
            path = PurePosixPath(name)
            require(mode in (b"100644", b"100755") and kind == b"blob" and not path.is_absolute()
                    and ".." not in path.parts and ".git" not in path.parts and "\\" not in name)
            admitted.append((name, oid.decode()))
        for (name, _), data in zip(admitted, git_source.read_blobs(cache, [oid for _, oid in admitted])):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            pointer = LFS_POINTER.fullmatch(data)
            if pointer:
                object_id, object_size = pointer[1].decode(), int(pointer[2])
                require(object_size <= 256 * 1024 * 1024 and pointers.get(object_id, object_size) == object_size)
                pointers[object_id] = object_size
            target.write_bytes(data)
        # Populate a clean index without checkout hooks, filters, or source scripts.
        self.git("init", destination)
        self.git("-C", destination, "config", "core.filemode", "false")
        self.git("-C", destination, "fetch", "--no-tags", "--no-recurse-submodules", cache, sha)
        self.git("-C", destination, "reset", "--mixed", sha)
        self.hydrate_lfs(pointers, destination, sha)
        engine.verify_source(destination, sha)
        return destination

    def cached(self, sha):
        cache = self.root / "builds" / sha
        receipt = cache / "receipt.json"
        if not receipt.exists():
            return None
        value = json.loads(receipt.read_text())
        require(value["sha"] == sha)
        files = engine.tree(cache)
        files.pop("receipt.json", None)
        require(files == value["files"])
        return cache

    def build(self, sha, version, stage, *, request_id=None, force_full_qa=False):
        with public_logging(self.c, job_key(sha, request_id)):
            return self._build(sha, version, stage, request_id=request_id, force_full_qa=force_full_qa)

    def client_material_unchanged(self, active_assets, client, manifest):
        """True when the built client publishes exactly what the active release already serves."""
        active_assets = Path(active_assets)
        if not (active_assets / 'update_config.json').is_file():
            return False
        if self.c.get('publish_apk', True):
            published = active_assets / 'client.apk'
            if not published.is_file() or engine.digest(published) != manifest['apk_sha256']:
                return False
        versioned = [name for name in manifest['asset_files'] if '/IncrementPack/' in name]
        if not versioned:
            return False
        for name in versioned:
            parts = PurePosixPath(name).parts
            marker = parts.index('IncrementPack')
            pattern = '/'.join(parts[:marker + 1]) + '/*/' + '/'.join(parts[marker + 2:])
            peers = [path for path in sorted(active_assets.glob(pattern)) if path.is_file()]
            if not peers or engine.digest(peers[0]) != engine.digest(client / 'assets' / name):
                return False
        return True

    def _build(self, sha, version, stage, *, request_id=None, force_full_qa=False):
        require(type(force_full_qa) is bool)
        key = job_key(sha, request_id)
        cached = self.cached(sha) if request_id is None and not force_full_qa else None
        if cached:
            build_logs.emit("Reusing verified cached artifacts; recorded test results follow. Tests are not being rerun.")
            self.replay_logs(cached)
            return cached / "release"
        build_logs.emit("Fetching exact source commit " + sha)
        source_started = time.monotonic()
        source = self.source(sha) if request_id is None else self.source(sha, request_id=request_id)
        build_logs.emit('Exact source fetch and preparation: ' + str(round(time.monotonic()-source_started, 3)) + ' seconds.')
        builds = self.root / "builds"
        builds.mkdir(parents=True, exist_ok=True, mode=0o700)
        scratch = builds / (key + ".incomplete")
        if scratch.exists():
            require(request_id is None)
            shutil.rmtree(scratch)
        scratch.mkdir(mode=0o700)
        # Only fixed build/check operations overlap. All finish before assets
        # are inspected or a failed job can release/reuse its scratch directory.
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="trusted-build") as workers:
            stage("server")
            policy=json.loads(Path(self.c['engine_config']).read_text())['data_compatibility']
            server = workers.submit(engine.build_server, source, sha, scratch / "server", self.c.get("game_data"),
                                    data_compatibility=policy, component_cache=self.root / 'components' / 'server',
                                    force_full_qa=force_full_qa, qa_workers=self.c.get('server_qa_workers',2))
            stage("client")
            client_build = workers.submit(self.command,
                [sys.executable, PRIVATE / "scripts/build_client.py", "--config", self.c["client_config"],
                 "--source", source, "--commit", sha, "--output", scratch / "client", "--version", "4.2.0." + str(version),
                 *(['--force-full-qa'] if force_full_qa else [])], timeout=3000)
            transport_check = None
            if self.c.get("transport_config"):
                stage("transport")
                transport_check = workers.submit(self.command,
                    [sys.executable, PRIVATE / "scripts/check_transport.py", "--config", self.c["transport_config"],
                     "--source", source, "--commit", sha, "--output", scratch / "transport"], timeout=2500)
            server.result()
            client_build.result()
            if transport_check is not None:
                transport_check.result()
        if self.c.get("transport_config"):
            checked = json.loads((scratch / "transport/transport.json").read_text())
            require(checked.get("commit") == sha and checked.get("passed") is True)
        client = scratch / "client"
        manifest = json.loads((client / "manifest.json").read_text())
        receipt = client / "client-tests.json"
        tests = json.loads(receipt.read_text())
        require(manifest["commit"] == sha and tests["commit"] == sha and tests["passed"] is True
                and engine.digest(receipt) == manifest["client_tests_sha256"]
                and engine.tree(client / "assets") == manifest["asset_files"]
                and engine.digest(client / "client.apk") == manifest["apk_sha256"])
        verify_apk_update(client, manifest)
        stage("assemble")
        assets = scratch / "assets"
        active_assets = None
        try:
            active_assets = Path(engine.Engine(self.c['engine_config']).active()['release_path']) / 'assets'
        except Exception:
            active_assets = None
        if active_assets is not None and self.client_material_unchanged(active_assets, client, manifest):
            # Nothing the client serves changed: publish the active assets as they
            # are instead of minting a new version, so no world restart is needed.
            build_logs.emit('Client material is unchanged; the served assets are reused without a new version.')
            shutil.copytree(active_assets, assets)
            provenance = scratch / "provenance.json"
            engine.write_json(provenance, {"commit": sha, "tested": True, "files": engine.tree(assets),
                                           "tests_receipt_sha256": engine.digest(receipt)})
            engine.assemble(scratch / "server", assets, provenance, receipt, scratch / "release")
            engine.write_json(scratch / "receipt.json", {"sha": sha, "request_id": request_id,
                                                         "version": version, "files": engine.tree(scratch)})
            destination = builds / key
            require(not destination.exists())
            os.replace(scratch, destination)
            build_logs.emit("Signed client and matching server/assets verified and assembled successfully.")
            return destination / "release"
        base = self.c.get("static_assets")
        if base:
            files = engine.tree(base["path"])
            require(hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest() == base["tree_sha256"])
            shutil.copytree(base["path"], assets)
        else:
            assets.mkdir()
        for name in manifest["asset_files"]:
            target = assets / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(client / "assets" / name, target)
        if self.c.get("publish_apk", True):
            shutil.copyfile(client / "client.apk", assets / "client.apk")
        provenance = scratch / "provenance.json"
        engine.write_json(provenance, {"commit": sha, "tested": True, "files": engine.tree(assets),
                                       "tests_receipt_sha256": engine.digest(receipt)})
        engine.assemble(scratch / "server", assets, provenance, receipt, scratch / "release")
        engine.write_json(scratch / "receipt.json", {"sha": sha, "request_id":request_id,"version": version, "files": engine.tree(scratch)})
        destination = builds / key
        require(not destination.exists())
        os.replace(scratch, destination)
        build_logs.emit("Signed client and matching server/assets verified and assembled successfully.")
        return destination / "release"

    def replay_logs(self, cache):
        for name in ("server/build.log", "server/tests.log", "server/invariants.log",
                     "client/tests.private.log", "transport/python.private.log", "transport/node.private.log"):
            path = cache / name
            if path.is_file():
                build_logs.emit("Recorded log: " + name)
                with path.open(errors="replace") as stream:
                    for line in stream:
                        build_logs.emit(line)
        client = cache / "client/client-tests.json"
        if client.is_file():
            for command in json.loads(client.read_text()).get("commands", []):
                result = command.get("result") or {}
                if result.get("passed") is True and result.get("skipped") == 0:
                    for name in result.get("test_ids", []):
                        if isinstance(name, str):
                            build_logs.emit("Recorded client PASS: " + name)
                    build_logs.emit("Recorded client totals: tests=" + str(result.get("tests"))
                                    + " failures=" + str(result.get("failures"))
                                    + " errors=" + str(result.get("errors")) + " skipped=0")

    def status(self):
        return engine.Engine(self.c["engine_config"]).status()["managed_release"]

    def check_successor(self, current, target):
        # Only an operator-owned alias can bridge rewritten commit metadata.
        # The alias must have the exact deployed tree; source code cannot use
        # it to bless a divergent content change or select another ancestor.
        base = self.c.get("history_aliases", {}).get(current, current)
        if base != current:
            require(self.git("--git-dir=" + str(self.c["source_cache"]), "rev-parse", current + "^{tree}")
                    == self.git("--git-dir=" + str(self.c["source_cache"]), "rev-parse", base + "^{tree}"))
        self.git("--git-dir=" + str(self.c["source_cache"]), "merge-base", "--is-ancestor", base, target)

    def promote(self, sha, release, *, replace_same_commit=False):
        runtime = engine.Engine(self.c["engine_config"])
        current = runtime.status()["managed_release"]
        require(isinstance(current, str) and SHA.fullmatch(current)
                and isinstance(sha, str) and SHA.fullmatch(sha))
        if current != sha or replace_same_commit:
            # Automatic promotion only advances the active source history.
            # Explicit operator rollbacks remain an engine-only operation.
            if current != sha:self.check_successor(current, sha)
            authority = runtime.c.get("desired_commit_file")
            require(authority is not None and Path(authority).is_absolute())
            require(self.current() == sha)
            watch.save_desired(authority, sha)
            try:
                result = (runtime.promote(release, current, replace_same_commit=True) if replace_same_commit
                          else runtime.promote(release, current))
                require(runtime.status()["managed_release"] == sha)
                return result
            except Exception:
                # Code rollback can replace the active container. Synchronize
                # registries with whichever exact release is actually healthy,
                # while preserving the failed promotion outcome.
                try:
                    active = self.status()
                    require(isinstance(active, str) and SHA.fullmatch(active))
                    self.finalize(active)
                except Exception:
                    raise PromotionRecoveryRequired("promotion recovery required") from None
                raise

    def release_is_active(self, release):
        """True when the built release changes neither the server image nor the assets."""
        runtime = engine.Engine(self.c["engine_config"])
        active = runtime.active()
        path, manifest = runtime.verify(release)
        return (manifest['image'] == active['image']
                and engine.assets_digest(path) == active['assets_sha256']
                and str(path) != active['release_path'])

    def publish_unchanged(self, sha, release):
        """Adopt the commit without touching the running world."""
        runtime = engine.Engine(self.c["engine_config"])
        active = runtime.active()
        authority = runtime.c.get("desired_commit_file")
        require(authority is not None and Path(authority).is_absolute())
        require(self.current() == sha)
        watch.save_desired(authority, sha)
        return runtime.publish_unchanged(release, runtime.tracked(active))

    def verify_publication(self, sha, release, proof):
        require(isinstance(proof, dict) and re.fullmatch(r'[0-9a-f]{32}', proof.get('id', ''))
                and proof.get('phase') == 'unchanged' and proof.get('restarted') is False
                and proof.get('to') == sha and proof.get('rollback') is False
                and proof.get('release_path') == str(Path(release).resolve())
                and proof.get('previous_release_path') != proof.get('release_path')
                and re.fullmatch(r'[0-9a-f]{64}', proof.get('container', ''))
                and re.fullmatch(r'[0-9a-f]{64}', proof.get('image', '')))
        runtime = engine.Engine(self.c['engine_config'])
        require(json.loads((runtime.root / 'deployments' / (proof['id'] + '.json')).read_text()) == proof)
        require(runtime.status()['managed_release'] == sha)
        active = runtime.active()
        require(active['container'] == proof['container'] and active.get('tracked') == sha
                and active['release'] == proof['from'] and active['image'] == proof['image'])
        require(runtime.inspect(proof['container'])['State']['Running'] is True)
        return True

    def verify_replacement(self, sha, release, proof):
        require(isinstance(proof,dict) and re.fullmatch(r'[0-9a-f]{32}',proof.get('id',''))
                and proof.get('phase')=='healthy' and proof.get('to')==sha and proof.get('old_stopped') is True
                and proof.get('replace_same_commit') is True and proof.get('rollback') is False
                and proof.get('release_path')==str(Path(release).resolve())
                and proof.get('previous_release_path')!=proof.get('release_path')
                and proof.get('from_container')!=proof.get('container')
                and re.fullmatch(r'[0-9a-f]{64}',proof.get('container',''))
                and re.fullmatch(r'[0-9a-f]{64}',proof.get('from_container','')))
        runtime=engine.Engine(self.c['engine_config'])
        require(json.loads((runtime.root/'deployments'/(proof['id']+'.json')).read_text())==proof)
        require(runtime.status()['managed_release']==sha)
        active=runtime.active()
        require(active['release']==sha and active['container']==proof['container']
                and active['release_path']==proof['release_path']
                and not runtime.inspect(proof['from_container'])['State']['Running'])
        return True

    def finalize(self, sha):
        # This fixed private script is the only optional registry callback. The
        # source payload cannot select a command, configuration, or argument.
        if self.c.get("registry_config"):
            self.command([sys.executable, PRIVATE / "scripts/sync_registry.py", "--config",
                          self.c["registry_config"], "--commit", sha], timeout=120)


class Broker:
    def __init__(self, config, operations=None):
        self.c = config
        self.root = config["local_root"]
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.jobs = self.root / "jobs"
        self.jobs.mkdir(exist_ok=True, mode=0o700)
        require(config["token_file"].is_file() and not config["token_file"].is_symlink())
        self.token = config["token_file"].read_text().strip()
        require(32 <= len(self.token) <= 256)
        self.operations = operations or Operations(config)
        self.mutex = threading.RLock()
        self.pending = queue.Queue()
        self.recover()

    def path(self, sha, request_id=None):
        return self.jobs / (job_key(sha,request_id) + ".json")

    def load(self, sha, request_id=None):
        path = self.path(sha,request_id)
        return json.loads(path.read_text()) if path.exists() else None

    def load_key(self,key):
        return self.load(*job_identity(key))

    def save(self, job):
        watch.save_state(self.path(job["sha"],job.get('request_id')), job)

    def recover(self):
        for path in sorted(self.jobs.glob("*.json")):
            sha,request_id=job_identity(path.stem)
            job = self.load(sha,request_id)
            require(job["sha"] == sha and job.get('request_id')==request_id and job["status"] in ("queued", "running", "success", "failed"))
            require(type(job.get('force_full_qa',False)) is bool)
            if job["status"] == "running":
                if request_id is not None or job["stage"] in ("promote", "verify"):
                    try:
                        actual = self.operations.status()
                        require(isinstance(actual, str) and SHA.fullmatch(actual))
                        self.operations.finalize(actual)
                        healthy = self.operations.status() == actual
                    except Exception:
                        healthy = False
                    # SHA equality cannot prove which container won an interrupted
                    # handoff, especially when replacing the same commit.
                    job.update(status="failed",stage="failed",recovery_required=not healthy or actual!=job['sha'])
                else:
                    job.update(status="queued", stage="queued")
                self.save(job)
            if job["status"] == "queued":
                self.pending.put(path.stem)

    def public(self, job):
        result={name: job[name] for name in ("sha", "status", "stage")}
        phase={'source':'building','server':'building_testing','client':'building_testing',
               'transport':'building_testing','assemble':'building_testing','promote':'deploying','verify':'verifying'}.get(job['stage'],job['stage'])
        if job.get('request_id') is not None:
            result['phase']=phase
            result['request_id']=job['request_id']
            result['replacement_verified']=job.get('replacement_verified',False)
            result['force_full_qa']=job.get('force_full_qa',False)
        return result

    def handle(self, request):
        require(isinstance(request, dict))
        operation = request.get("op")
        expected = {"op", "sha", "token", "cursor"} if operation == "logs" else {"op", "sha", "token"}
        if 'request_id' in request:expected.add('request_id')
        if 'force_full_qa' in request:
            require(operation=='submit' and 'request_id' in request and type(request['force_full_qa']) is bool)
            expected.add('force_full_qa')
        require(set(request) == expected)
        require(isinstance(request["token"], str) and hmac.compare_digest(request["token"], self.token))
        require(operation in ("submit", "status", "logs"))
        if operation == "logs":
            require(type(request["cursor"]) is int and 0 <= request["cursor"] < (1 << 63))
        request_id=request.get('request_id')
        force_full_qa=request.get('force_full_qa',False)
        if 'request_id' in request:require(isinstance(request_id,str) and REQUEST_ID.fullmatch(request_id))
        require(operation!='submit' or not self.c.get('require_request_id_for_submit',False) or request_id is not None)
        sha = request["sha"]
        with self.mutex:
            if sha=='' and operation=='submit' and request_id is not None:
                binding=self.root/'attempts'/(request_id+'.json')
                sha=json.loads(binding.read_text())['sha'] if binding.exists() else self.operations.current()
            key=job_key(sha,request_id)
            if request_id is not None:
                binding=self.root/'attempts'/(request_id+'.json')
                if binding.exists():require(json.loads(binding.read_text())=={'sha':sha,'request_id':request_id})
                elif operation=='submit':watch.save_state(binding,{'sha':sha,'request_id':request_id})
                else:require(False)
            job = self.load(sha,request_id)
            if operation=='submit' and job is not None:
                require(job.get('force_full_qa',False)==force_full_qa)
            if request_id is None and operation != "logs" and job is not None and job["status"] == "success":
                # A historical receipt is not proof that the release is active
                # now, including after an operator rollback or later deployment.
                try:
                    active = self.operations.status() == sha
                except Exception:
                    active = False
                if not active:
                    job.update(status="failed", stage="failed")
                    self.save(job)
            if request["op"] == "submit" and (job is None or (request_id is None and job["status"] == "failed" and not job.get("recovery_required"))):
                # An allocation is persisted before starting any client build and
                # is reused on restart. Failed builds never recycle a version.
                counter = self.root / "version.json"
                previous = json.loads(counter.read_text())["last"] if counter.exists() else self.c["minimum_version"] - 1
                version = max(previous + 1, self.c["minimum_version"])
                require(version <= 2147483647)
                watch.save_state(counter, {"last": version})
                job = {"sha": sha, "status": "queued", "stage": "queued", "version": version}
                if request_id is not None:
                    job['request_id']=request_id
                    job['force_full_qa']=force_full_qa
                self.save(job)
                self.pending.put(key)
            require(job is not None)
            result = self.public(job)
            if request_id is not None and operation!='logs' and job['status']=='success':
                try:
                    verified=self.operations.verify_replacement(sha,Path(job['release_path']),job['promotion']) is True
                except Exception:
                    verified=False
                if not verified:
                    # Keep historical logs/receipt intact, but never let a final
                    # runner status poll attest to a different current container.
                    result.update(status='failed',stage='failed',phase='failed',replacement_verified=False)
            if operation == "logs":
                import build_logs
                result.update(build_logs.read_page(self.root / "public-logs" / key / "journal.log", request["cursor"]))
            return result

    def stage(self, sha, stage):
        with self.mutex:
            job = self.load_key(sha)
            job.update(status="running", stage=stage)
            self.save(job)
            build_logs.emit("Stage: " + stage)

    def process(self, sha):
        try:
            with self.mutex:
                job=self.load_key(sha)
                if job.get('request_id') is not None and job['status']!='queued':return
                if job.get('request_id') is not None:
                    job.update(status='running',stage='source');self.save(job)
            with public_logging(self.c, sha):
                self._process(sha)
        except Exception as error:
            # A journal/privacy setup failure must fail the job, rather than
            # terminate the single deployment worker and strand future pushes.
            self.record_failure(sha, error)

    def _process(self, sha):
        try:
            key=sha
            sha,request_id=job_identity(key)
            self.stage(key, "source")
            require(self.operations.current() == sha)
            self.operations.preflight()
            job = self.load(sha,request_id)
            build_args=(sha,job['version'],lambda stage:self.stage(key,stage))
            build_options={'request_id':request_id} if request_id is not None else {}
            if job.get('force_full_qa',False):build_options['force_full_qa']=True
            release = self.operations.build(*build_args,**build_options)
            require(self.operations.current() == sha)
            self.stage(key, "promote")
            restarted=True
            if request_id is not None:
                # A release that changes neither the server image nor the assets
                # is adopted without stopping the world.
                if self.operations.release_is_active(release):
                    proof=self.operations.publish_unchanged(sha,release);restarted=False
                else:
                    proof=self.operations.promote(sha,release,replace_same_commit=True)
                with self.mutex:
                    job=self.load(sha,request_id);job.update(release_path=str(Path(release).resolve()),
                        promotion=proof,server_restarted=restarted);self.save(job)
            else:self.operations.promote(sha, release)
            self.stage(key, "verify")
            self.operations.finalize(sha)
            require(self.operations.status() == sha)
            if request_id is not None:
                require((self.operations.verify_publication(sha,release,proof) if not restarted
                         else self.operations.verify_replacement(sha,release,proof)) is True)
            with self.mutex:
                job = self.load(sha,request_id)
                require(job['status']=='running')
                job.update(status="success", stage="complete")
                if request_id is not None:job['replacement_verified']=True
                self.save(job)
                build_logs.emit("Deployment complete: the requested commit is active; server restarted="
                                + ("no" if request_id is not None and not restarted else "yes") + ".")
        except Exception as error:
            self.record_failure(key, error)

    def record_failure(self, sha, error):
        # Full diagnostics are host-private, never sent through IPC.
        descriptor = os.open(self.root / "broker.private.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a") as log:
            traceback.print_exc(file=log)
        with self.mutex:
            job = self.load_key(sha)
            job.update(status="failed", stage="failed")
            try:
                build_logs.emit("Deployment failed; see the preceding build/test output. Private operator diagnostics are retained.")
            except Exception:
                pass  # Never bypass a failed privacy filter to print text.
            if isinstance(error, PromotionRecoveryRequired):
                job["recovery_required"] = True
            self.save(job)

    def worker(self):
        while True:
            sha = self.pending.get()
            try:
                if sha is None:
                    return
                self.process(sha)
            finally:
                self.pending.task_done()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            raw = self.rfile.readline(LIMIT + 1)
            require(len(raw) <= LIMIT and raw.endswith(b"\n"))
            data = self.server.broker.handle(json.loads(raw))
            result = {"ok": True, "data": data}
        except Exception:
            result = {"ok": False, "error": "request_rejected"}
        try:
            self.wfile.write((json.dumps(result) + "\n").encode())
        except OSError:
            pass


@contextmanager
def process_lock(root):
    with watch.state_lock(root / "broker"):
        yield


def serve(config):
    with process_lock(config["local_root"]):
        broker = Broker(config)
        path = config["socket_path"]
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists():
            require(path.is_socket())
            path.unlink()
        with socketserver.UnixStreamServer(str(path), Handler) as server:
            server.broker = broker
            os.chmod(path, 0o660)
            threading.Thread(target=broker.worker, daemon=True).start()
            server.serve_forever(poll_interval=0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        serve(config_read(args.config))
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("broker_unavailable", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
