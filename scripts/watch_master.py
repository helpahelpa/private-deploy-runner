#!/usr/bin/env python3
"""Outbound-only dispatcher for a private, repository-scoped deployment runner.

Only host-side gh authentication is used. Neither credentials nor this configuration
belong in the source repository. The deployment controller independently verifies
the source identity and current master before handling the dispatched commit.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
BRANCH = re.compile(r"[A-Za-z0-9_-]+\Z")
WORKFLOW = "deploy.yml"
STATUS_DESCRIPTIONS = {
    "queued": "Queued for Main deployment",
    "running": "Main build, tests, and deployment running",
    "success": "Deployment completed successfully",
    "failure": "Main deployment failed or was cancelled; see logs",
    "timeout": "Deployment dispatch was not observed; retry may follow",
    "superseded": "Superseded by a newer master push before deployment",
}


class WatchError(Exception):
    """A deliberately non-sensitive operational error."""


@dataclass(frozen=True)
class Identity:
    full_name: str
    repository_id: int
    owner_id: int

    @classmethod
    def read(cls, value):
        if not isinstance(value, dict):
            raise WatchError("invalid repository identity")
        name = value.get("full_name", "")
        ids = (value.get("repository_id"), value.get("owner_id"))
        if (not isinstance(name, str) or not REPOSITORY.fullmatch(name)
                or any(type(n) is not int or n <= 0 for n in ids)):
            raise WatchError("invalid repository identity")
        return cls(name, *ids)


@dataclass(frozen=True)
class Config:
    source: Identity
    control: Identity
    state_file: Path
    control_branch: str = "master"
    poll_seconds: int = 10
    dispatch_grace_seconds: int = 120
    retry_seconds: int = 30
    max_attempts: int = 3
    desired_commit_file: Path | None = None
    publish_status: bool = False
    control_private: bool = True

    @classmethod
    def read(cls, value):
        try:
            config = cls(
                source=Identity.read(value["source"]),
                control=Identity.read(value["control"]),
                state_file=Path(value["state_file"]),
                desired_commit_file=(Path(value["desired_commit_file"])
                                     if value.get("desired_commit_file") is not None else None),
                **{key: value[key] for key in (
                    "control_branch", "poll_seconds", "dispatch_grace_seconds",
                    "retry_seconds", "max_attempts", "publish_status", "control_private") if key in value},
            )
        except (KeyError, TypeError, ValueError):
            raise WatchError("invalid configuration") from None
        if (not config.state_file.is_absolute()
                or (config.desired_commit_file is not None and (
                    not config.desired_commit_file.is_absolute()
                    or config.desired_commit_file.resolve() == config.state_file.resolve()))
                or not isinstance(config.control_branch, str)
                or not BRANCH.fullmatch(config.control_branch)
                or any(type(n) is not int or n <= 0 for n in (
                    config.poll_seconds, config.dispatch_grace_seconds,
                    config.retry_seconds, config.max_attempts))
                or config.max_attempts > 10
                or type(config.publish_status) is not bool
                or type(config.control_private) is not bool
                or config.source.full_name.lower() == config.control.full_name.lower()):
            raise WatchError("invalid configuration")
        return config


class GitHub:
    def request(self, endpoint, body=None):
        command = ["gh", "api", "--hostname", "github.com", endpoint]
        if body is not None:
            command += ["--method", "POST", "--input", "-"]
        try:
            result = subprocess.run(
                command, input=None if body is None else json.dumps(body),
                text=True, capture_output=True, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise WatchError("GitHub unavailable") from None
        if result.returncode:
            raise WatchError("GitHub unavailable")
        try:
            return json.loads(result.stdout) if result.stdout.strip() else None
        except ValueError:
            raise WatchError("invalid GitHub response") from None


def initial_state():
    return {"version": 1, "deployed_sha": None, "inflight": None, "failures": {},
            "last_deployment_run_id": None, "commit_statuses": {}}


def read_state(path):
    try:
        value = json.loads(path.read_text())
    except FileNotFoundError:
        return initial_state()
    except (OSError, ValueError):
        raise WatchError("cannot read deployment state") from None
    try:
        if value["version"] != 1:
            raise ValueError()
        deployed = value["deployed_sha"]
        if deployed is not None and not SHA.fullmatch(deployed):
            raise ValueError()
        last_run = value.setdefault("last_deployment_run_id", None)
        if last_run is not None and (type(last_run) is not int or last_run <= 0 or deployed is None):
            raise ValueError()
        statuses = value.setdefault("commit_statuses", {})
        if not isinstance(statuses, dict) or len(statuses) > 32:
            raise ValueError()
        for sha, status in statuses.items():
            body = status["body"]
            if (not SHA.fullmatch(sha) or type(status["published"]) is not bool
                    or not isinstance(status["at"], (int, float))
                    or not isinstance(body, dict)
                    or set(body) != {"state", "context", "description", "target_url"}
                    or body["state"] not in ("pending", "success", "failure")
                    or body["context"] != "deployment/Main"
                    or body["description"] not in STATUS_DESCRIPTIONS.values()
                    or not isinstance(body["target_url"], str)
                    or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/(?:runs/[1-9][0-9]*|workflows/deploy\.yml)", body["target_url"])):
                raise ValueError()
        for sha, failure in value["failures"].items():
            if (not SHA.fullmatch(sha) or type(failure["count"]) is not int
                    or failure["count"] < 1
                    or not isinstance(failure["at"], (int, float))):
                raise ValueError()
        inflight = value["inflight"]
        if inflight is not None and (
            not SHA.fullmatch(inflight["sha"])
            or not isinstance(inflight["since"], (int, float))
            or (inflight["run_id"] is not None and (
                type(inflight["run_id"]) is not int or inflight["run_id"] <= 0))
        ):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise WatchError("invalid deployment state") from None
    return value


def save_state(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".watch-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_desired(path, sha):
    """Publish current master as a private, atomic plain-text engine authority."""
    path = Path(path)
    if not path.is_absolute() or not isinstance(sha, str) or not SHA.fullmatch(sha) or path.is_symlink():
        raise WatchError("invalid desired commit")
    value = sha + "\n"
    try:
        if path.read_text() == value and path.stat().st_mode & 0o777 == 0o600:
            return False
    except FileNotFoundError:
        pass
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".desired-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


@contextmanager
def state_lock(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise WatchError("watcher already running") from None
        yield
    finally:
        os.close(descriptor)


class Watcher:
    def __init__(self, config, github=None, clock=time.time):
        self.config = config
        self.github = github or GitHub()
        self.clock = clock
        self.state = read_state(config.state_file)

    def save(self):
        save_state(self.config.state_file, self.state)

    def verify_identity(self, expected, private=None):
        repository = self.github.request(f"repos/{expected.full_name}")
        try:
            valid = (
                repository["id"] == expected.repository_id
                and repository["owner"]["id"] == expected.owner_id
                and repository["owner"]["login"].lower() == expected.full_name.split("/")[0].lower()
                and repository["full_name"].lower() == expected.full_name.lower()
                and (private is None or repository["private"] is private)
            )
        except (KeyError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise WatchError("repository identity rejected")

    def master(self):
        response = self.github.request(
            f"repos/{self.config.source.full_name}/git/ref/heads/master")
        try:
            sha = response["object"]["sha"]
            valid = response["object"]["type"] == "commit" and SHA.fullmatch(sha)
        except (KeyError, TypeError):
            valid = False
        if not valid:
            raise WatchError("source master rejected")
        return sha

    def find_run(self, inflight):
        base = f"repos/{self.config.control.full_name}/actions"
        if inflight["run_id"] is not None:
            run = self.github.request(f"{base}/runs/{inflight['run_id']}")
            return run if self.valid_run(run, inflight) else None
        runs = self.github.request(
            f"{base}/workflows/{WORKFLOW}/runs?branch={self.config.control_branch}"
            "&event=workflow_dispatch&per_page=100")["workflow_runs"]
        matches = []
        for run in runs:
            if self.valid_run(run, inflight):
                matches.append(run)
        return min(matches, key=lambda run: run["id"]) if matches else None

    def valid_run(self, run, inflight):
        try:
            created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00")).timestamp()
            return (type(run["id"]) is int and run["id"] > 0
                    and (inflight["run_id"] is None or run["id"] == inflight["run_id"])
                    and run["display_title"] == "deploy-" + inflight["sha"]
                    and run["event"] == "workflow_dispatch"
                    and run["head_branch"] == self.config.control_branch
                    and run["path"] == ".github/workflows/" + WORKFLOW
                    and run["status"] in ("queued", "requested", "waiting", "pending", "in_progress", "completed")
                    and created >= inflight["since"] - 5)
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def status(self, sha, phase, run_id=None):
        if not self.config.publish_status:
            return
        suffix = f"runs/{run_id}" if run_id is not None else f"workflows/{WORKFLOW}"
        body = {"state": "success" if phase == "success" else "failure" if phase in ("failure", "timeout", "superseded") else "pending",
                "context": "deployment/Main", "description": STATUS_DESCRIPTIONS[phase],
                "target_url": f"https://github.com/{self.config.control.full_name}/actions/{suffix}"}
        statuses = self.state["commit_statuses"]
        previous = statuses.get(sha)
        if previous is not None and previous["body"] == body:
            return
        statuses[sha] = {"body": body, "published": False, "at": self.clock()}
        for old in sorted(statuses, key=lambda key: statuses[key]["at"])[:-32]:
            del statuses[old]
        self.save()

    def publish_statuses(self):
        if not self.config.publish_status:
            return
        prefix = f"https://github.com/{self.config.control.full_name}/actions/"
        for sha, status in self.state["commit_statuses"].items():
            if status["published"]:
                continue
            # Stored state is private, but never forward a persisted URL outside
            # the currently verified controls repository.
            if not status["body"]["target_url"].startswith(prefix):
                continue
            try:
                self.github.request(f"repos/{self.config.source.full_name}/statuses/{sha}", status["body"])
            except WatchError:
                # One unavailable API call is enough for this poll; do not turn
                # a bounded outbox into many consecutive network timeouts.
                break
            status["published"] = True
            self.save()

    def failed(self, sha, now, run_id=None):
        failures = self.state["failures"]
        failures[sha] = {"count": failures.get(sha, {}).get("count", 0) + 1, "at": now}
        # Bound disk state while retaining the most recent retry history.
        for old in sorted(failures, key=lambda key: failures[key]["at"])[:-32]:
            del failures[old]
        self.state["inflight"] = None
        self.save()
        self.status(sha, "failure" if run_id is not None else "timeout", run_id)

    def tick(self):
        self.verify_identity(self.config.source)
        self.verify_identity(self.config.control, private=self.config.control_private)
        try:
            return self.verified_tick()
        finally:
            self.publish_statuses()

    def verified_tick(self):
        latest = self.master()
        if self.config.desired_commit_file is not None:
            save_desired(self.config.desired_commit_file, latest)
        now = self.clock()
        inflight = self.state["inflight"]
        if self.config.publish_status:
            for sha, status in list(self.state["commit_statuses"].items()):
                if (sha != latest and (inflight is None or sha != inflight["sha"])
                        and status["body"]["state"] == "pending"):
                    self.status(sha, "superseded")
        if latest != self.state["deployed_sha"] and inflight is not None and latest != inflight["sha"]:
            if latest not in self.state["failures"]:
                self.status(latest, "queued")
        if inflight is not None:
            run = self.find_run(inflight)
            if run is not None:
                if inflight["run_id"] != run["id"]:
                    inflight["run_id"] = run["id"]
                    self.save()
                if run["status"] != "completed":
                    self.status(inflight["sha"], "running" if run["status"] == "in_progress" else "queued", run["id"])
                    return "deployment_running"
                if run["conclusion"] == "success":
                    self.state["deployed_sha"] = inflight["sha"]
                    self.state["last_deployment_run_id"] = run["id"]
                    self.state["failures"].pop(inflight["sha"], None)
                    self.state["inflight"] = None
                    self.save()
                    self.status(inflight["sha"], "success", run["id"])
                else:
                    self.failed(inflight["sha"], now, run["id"])
            elif now - inflight["since"] < self.config.dispatch_grace_seconds:
                self.status(inflight["sha"], "queued")
                return "dispatch_pending"
            else:
                self.failed(inflight["sha"], now)

        if latest == self.state["deployed_sha"]:
            if self.state["last_deployment_run_id"] is not None:
                self.status(latest, "success", self.state["last_deployment_run_id"])
            return "current"
        failure = self.state["failures"].get(latest)
        if failure:
            if failure["count"] >= self.config.max_attempts:
                return "retry_exhausted"
            if now - failure["at"] < self.config.retry_seconds:
                return "retry_wait"

        # Resolve again immediately before dispatch: a queued observation must not
        # overwrite a newer master push. The controller also verifies this later.
        confirmed = self.master()
        if confirmed != latest:
            if self.config.desired_commit_file is not None:
                save_desired(self.config.desired_commit_file, confirmed)
            return "source_changed"
        self.state["inflight"] = {"sha": latest, "since": now, "run_id": None}
        self.save()  # Durable intent precedes the API call, including timeouts.
        self.status(latest, "queued")
        self.github.request(
            f"repos/{self.config.control.full_name}/actions/workflows/{WORKFLOW}/dispatches",
            {"ref": self.config.control_branch, "inputs": {"source_sha": latest}},
        )
        return "dispatched"


def main():
    parser = argparse.ArgumentParser(description="Poll source master from a private host")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    try:
        config = Config.read(json.loads(Path(args.config).read_text()))
        with state_lock(config.state_file):
            watcher = Watcher(config)
            while True:
                try:
                    print(watcher.tick(), flush=True)
                except (WatchError, KeyError, TypeError, ValueError, OSError):
                    print("watcher_unavailable", flush=True)
                    if args.once:
                        return 1
                if args.once:
                    return 0
                time.sleep(config.poll_seconds)
    except (WatchError, OSError, ValueError, TypeError):
        print("watcher_unavailable", flush=True)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
