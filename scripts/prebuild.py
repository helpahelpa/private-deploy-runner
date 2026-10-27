#!/usr/bin/env python3
"""Operator-only offline prebuild of a clean exact local commit; never promote."""
import argparse
import json
from pathlib import Path

import broker
import deploy_engine as engine
import watch_master as watch


class LocalOperations(broker.Operations):
    def __init__(self, config, source):
        self.local_source = Path(source).resolve()
        config = dict(config)
        super().__init__(config)
        # Only local, hash-checked objects may hydrate a prebuild. The ordinary
        # broker's separately pinned network fetch is deliberately unavailable.
        common = self.git("-C", self.local_source, "rev-parse", "--git-common-dir").decode().strip()
        common = Path(common)
        if not common.is_absolute():
            common = self.local_source / common
        config["lfs_object_store"] = str(common.resolve() / "lfs/objects")

    def git(self, *arguments):
        values = list(arguments)
        expected = "git@github.com:" + self.c["source"].full_name + ".git"
        # Substitute only the fixed source-cache fetch. No caller-provided
        # command, URL, Git ref, or repository config is forwarded to builds.
        if (len(values) == 6 and values[:4] == ["--git-dir=" + str(self.c["source_cache"]),
                                              "fetch", "--no-tags", "--no-recurse-submodules"]):
            broker.require(values[4] == expected and broker.SHA.fullmatch(values[5]))
            values[4] = str(self.local_source)
        return super().git(*values)

    def fetch_lfs(self, sha):
        raise broker.BrokerError("local LFS object is required")


def verify_local(operations, commit):
    broker.require(isinstance(commit, str) and broker.SHA.fullmatch(commit))
    source = operations.local_source
    broker.require(source.is_dir())
    broker.require(operations.git("-C", source, "rev-parse", "HEAD").decode().strip() == commit)
    broker.require(not operations.git("-C", source, "status", "--porcelain", "--untracked-files=no").strip())
    origin = operations.git("-C", source, "config", "--get", "remote.origin.url").decode().strip()
    name = operations.c["source"].full_name
    broker.require(origin in {
        "git@github.com:" + name + ".git", "https://github.com/" + name + ".git",
        "https://github.com/" + name, "ssh://git@github.com/" + name + ".git",
    })


def prebuild(config, source, commit, *, operations_factory=LocalOperations):
    root = config["local_root"]
    with broker.process_lock(root):
        operations = operations_factory(config, source)
        verify_local(operations, commit)
        operations.preflight()
        cached = operations.cached(commit)
        if cached is not None:
            receipt = json.loads((cached / "receipt.json").read_text())
            return {"commit": commit, "version": receipt["version"], "cached": True,
                    "manifest_sha256": engine.digest(cached / "release/manifest.json")}
        counter = root / "version.json"
        previous = json.loads(counter.read_text())["last"] if counter.exists() else config["minimum_version"] - 1
        broker.require(type(previous) is int)
        version = max(previous + 1, config["minimum_version"])
        broker.require(62 <= version <= 2147483647)
        watch.save_state(counter, {"last": version})
        release = operations.build(commit, version, lambda stage: print("prebuild_" + stage, flush=True))
        # Same immutable receipt/cache verification as the deployment worker.
        cached = operations.cached(commit)
        broker.require(cached is not None and cached / "release" == release)
        return {"commit": commit, "version": version, "cached": False,
                "manifest_sha256": engine.digest(release / "manifest.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "source", "commit"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        value = prebuild(broker.config_read(args.config), args.source, args.commit)
    except Exception:
        print("prebuild_failed", flush=True)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
