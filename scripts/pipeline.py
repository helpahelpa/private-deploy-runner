#!/usr/bin/env python3
"""Runner-side authenticated IPC client. No host tools or source code run here."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import time

SHA = re.compile(r"[0-9a-f]{40}\Z")
REQUEST_ID = re.compile(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,9}\Z")
PHASES = {"queued", "building", "building_testing", "testing", "deploying", "verifying", "complete", "failed"}
LIMIT = 4096
MAX_CURSOR = (1 << 63) - 1
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_LOG_PAGES = 8192


def request(config, token, operation, sha, cursor=None, *, request_id=None, force_full_qa=None):
    payload = {"token": token, "op": operation, "sha": sha}
    if request_id is not None:
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise ValueError("invalid deployment attempt")
        payload["request_id"] = request_id
    if force_full_qa is not None:
        if operation != "submit" or request_id is None or type(force_full_qa) is not bool:
            raise ValueError("invalid QA policy")
        payload["force_full_qa"] = force_full_qa
    if operation == "logs":
        if type(cursor) is not int or not 0 <= cursor <= MAX_CURSOR:
            raise ValueError("invalid log cursor")
        payload["cursor"] = cursor
    elif cursor is not None:
        raise ValueError("unexpected log cursor")
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(10)
        stream.connect(config["socket_path"])
        stream.sendall((json.dumps(payload) + "\n").encode())
        raw = stream.makefile("rb").readline(LIMIT + 1)
    if len(raw) > LIMIT or not raw.endswith(b"\n"):
        raise ValueError("invalid response")
    response = json.loads(raw)
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise ValueError("request rejected")
    data = response.get("data")
    if (not isinstance(data, dict) or not isinstance(data.get("sha"), str) or not SHA.fullmatch(data["sha"])
            or (data["sha"] != sha and not (operation == "submit" and sha == "" and request_id is not None))
            or data.get("status") not in ("queued", "running", "success", "failed")):
        raise ValueError("invalid status")
    if request_id is not None and (data.get("request_id") != request_id or data.get("phase") not in PHASES
                                  or type(data.get("replacement_verified")) is not bool):
        raise ValueError("invalid deployment attempt status")
    if "force_full_qa" in data and type(data["force_full_qa"]) is not bool:
        raise ValueError("invalid QA policy")
    if force_full_qa is not None and data.get("force_full_qa") is not force_full_qa:
        raise ValueError("QA policy not acknowledged")
    if operation == "logs":
        if (not isinstance(data.get("text"), str) or type(data.get("cursor")) is not int
                or not 0 <= data["cursor"] <= MAX_CURSOR or type(data.get("more")) is not bool):
            raise ValueError("invalid log page")
        if data["cursor"] - cursor != len(data["text"].encode("utf-8")) or (data["more"] and not data["text"]):
            raise ValueError("invalid log progress")
    return data


class BuildOutput:
    """Bounded, cursor-based journal reader; every emitted line is inert text."""
    def __init__(self, request_id=None):
        self.cursor = 0
        self.pending = ""
        self.pages = 0
        self.request_id = request_id

    @staticmethod
    def emit(line):
        # A fixed prefix prevents ::workflow-command:: interpretation. Strip
        # terminal control characters so a log cannot overwrite that prefix.
        line = line.removeprefix("[build] ")
        safe = "".join(character if character >= " " and character != "\x7f" else "?" for character in line)
        print("[build] " + safe, flush=True)

    def drain(self, config, token, sha, *, final=False):
        while True:
            self.pages += 1
            if self.pages > MAX_LOG_PAGES:
                raise ValueError("log page limit exceeded")
            options = {"request_id": self.request_id} if self.request_id is not None else {}
            page = request(config, token, "logs", sha, self.cursor, **options)
            offset = page["cursor"]
            text = page["text"]
            if (offset < self.cursor or offset > MAX_LOG_BYTES
                    or (offset == self.cursor and (text or page["more"]))
                    or (offset > self.cursor and not text)):
                raise ValueError("invalid log progress")
            self.cursor = offset
            self.pending += text
            while "\n" in self.pending or len(self.pending) >= 16384:
                newline = self.pending.find("\n")
                size = min(newline if newline >= 0 else len(self.pending), 16384)
                self.emit(self.pending[:size])
                self.pending = self.pending[size + (newline == size):]
            if not page["more"]:
                if final and self.pending:
                    self.emit(self.pending)
                    self.pending = ""
                return page


def authenticate(config, sha, request_id=None):
    if request_id is not None and (not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id)):
        raise ValueError("invalid deployment attempt")
    if not isinstance(sha, str) or (not SHA.fullmatch(sha) and not (sha == "" and request_id is not None)):
        raise ValueError("invalid source commit")
    token = Path(config["token_file"]).read_text().strip()
    if not 32 <= len(token) <= 256:
        raise ValueError("invalid authentication")
    return token


def show_logs(config, sha):
    token = authenticate(config, sha)
    print("Recorded build/test logs; no build or deployment requested.", flush=True)
    BuildOutput().drain(config, token, sha, final=True)
    print("log replay complete", flush=True)
    return 0


def execute(config, sha, *, clock=time.monotonic, sleep=time.sleep, request_id=None, force_full_qa=False):
    token = authenticate(config, sha, request_id)
    options = {"request_id": request_id} if request_id is not None else {}
    interval = config.get("poll_seconds", 2)
    timeout = config.get("timeout_seconds", 3500)
    if type(interval) is not int or not 1 <= interval <= 30 or type(timeout) is not int or not 1 <= timeout <= 3500:
        raise ValueError("invalid timing")
    deadline = clock() + timeout
    if type(force_full_qa) is not bool or (force_full_qa and request_id is None):
        raise ValueError("invalid QA policy")
    submit_options = dict(options)
    if force_full_qa:
        submit_options["force_full_qa"] = True
    data = request(config, token, "submit", sha, **submit_options)
    sha = data["sha"]
    previous = None
    output = BuildOutput(request_id)
    while True:
        status = data["status"]
        stage = data.get("stage")
        if stage in ("queued", "source", "server", "client", "transport", "assemble", "promote", "verify", "complete", "failed") and stage != previous:
            print("deployment_" + stage, flush=True)
            previous = stage
        terminal = status in ("success", "failed") or clock() >= deadline
        page = output.drain(config, token, sha, final=terminal)
        # Reading logs never mutates historical jobs. Revalidate active health
        # with a separate status request after draining the final success log.
        if terminal:
            if status == "success" and page["status"] == "success":
                verified = request(config, token, "status", sha, **options)
                return 0 if verified["status"] == "success" and (request_id is None or verified.get("replacement_verified") is True) else 1
            return 1
        if page["status"] in ("success", "failed"):
            data = page
            continue
        sleep(interval)
        data = request(config, token, "status", sha, **options)


def save_progress(path, state):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), "w") as stream:
        json.dump(state, stream)
        stream.write("\n")
    os.replace(temporary, path)


def summarize(data):
    labels = {"queued": "Queued", "building": "Building", "building_testing": "Building and testing",
              "testing": "Testing", "deploying": "Replacing the active server", "verifying": "Verifying the replacement",
              "complete": "Replacement deployed and verified", "failed": "Deployment failed"}
    label = labels[data["phase"]]
    policy = "Full QA forced" if data.get("force_full_qa") else "Verified whole component reuse allowed"
    print("Pipeline phase: " + label, flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        # Only validated hashes, numeric attempt IDs and fixed labels enter Markdown.
        Path(path).write_text("## Main deployment\n\nSource: `" + data["sha"] + "`\n\nAttempt: `"
                              + data["request_id"] + "`\n\n**" + label + "**\n\n"
                              + "QA policy: " + policy + ".\n\n"
                              + "Success requires a healthy new server container and the previous server stopped.\n")


def start_attempt(config, sha, request_id, state_path, *, clock=time.time, force_full_qa=False):
    token = authenticate(config, sha, request_id)
    if request_id is None:
        raise ValueError("workflow deployment attempt required")
    if type(force_full_qa) is not bool:
        raise ValueError("invalid QA policy")
    print("QA policy: " + ("force full QA; component test caches bypassed" if force_full_qa
                           else "verified whole client/server component reuse allowed"), flush=True)
    data = request(config, token, "submit", sha, request_id=request_id, force_full_qa=force_full_qa)
    state = {"schema": 1, "sha": data["sha"], "request_id": request_id, "cursor": 0, "pending": "", "pages": 0,
             "started_at": clock()}
    save_progress(state_path, state)
    summarize(data)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a") as stream:
            stream.write("source_sha=" + data["sha"] + "\nrequest_id=" + request_id + "\n")
    return 1 if data["status"] == "failed" else 0


def wait_through(config, state_path, through, *, clock=time.time, sleep=time.sleep):
    state = json.loads(Path(state_path).read_text())
    if (set(state) != {"schema", "sha", "request_id", "cursor", "pending", "pages", "started_at"}
            or state["schema"] != 1 or not isinstance(state["sha"], str) or not SHA.fullmatch(state["sha"])
            or not isinstance(state["request_id"], str) or not REQUEST_ID.fullmatch(state["request_id"])
            or type(state["cursor"]) is not int or not 0 <= state["cursor"] <= MAX_LOG_BYTES
            or not isinstance(state["pending"], str) or len(state["pending"]) > 16384
            or type(state["pages"]) is not int or not 0 <= state["pages"] <= MAX_LOG_PAGES
            or type(state["started_at"]) not in (int, float)):
        raise ValueError("invalid workflow progress")
    sha, identifier = state["sha"], state["request_id"]
    token = authenticate(config, sha, identifier)
    interval, timeout = config.get("poll_seconds", 2), config.get("timeout_seconds", 3500)
    if type(interval) is not int or not 1 <= interval <= 30 or type(timeout) is not int or not 1 <= timeout <= 3500:
        raise ValueError("invalid timing")
    output = BuildOutput(identifier)
    output.cursor, output.pending, output.pages = state["cursor"], state["pending"], state["pages"]
    reached = {"build": {"promote", "verify", "complete"}, "deploy": {"verify", "complete"}, "verify": {"complete"}}[through]
    previous = None
    while True:
        data = request(config, token, "status", sha, request_id=identifier)
        if data["phase"] != previous:
            summarize(data)
            previous = data["phase"]
        terminal = data["status"] in ("success", "failed") or clock() - state["started_at"] >= timeout
        page = output.drain(config, token, sha, final=terminal)
        state.update(cursor=output.cursor, pending=output.pending, pages=output.pages)
        save_progress(state_path, state)
        if data["status"] == "failed" or page["status"] == "failed" or clock() - state["started_at"] >= timeout:
            return 1
        if data["status"] == "success" or page["status"] == "success":
            # Final logs and an independent health/proof read must agree.
            output.drain(config, token, sha, final=True)
            state.update(cursor=output.cursor, pending=output.pending, pages=output.pages)
            save_progress(state_path, state)
            final = request(config, token, "status", sha, request_id=identifier)
            summarize(final)
            return 0 if final["status"] == "success" and final["replacement_verified"] else 1
        if through != "verify" and (data["stage"] in reached or page.get("stage") in reached):
            summarize(page)
            return 0
        sleep(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--logs-only", action="store_true", help="Read recorded logs without requesting deployment")
    parser.add_argument("--start", action="store_true", help="Start an independent workflow deployment attempt")
    parser.add_argument("--wait-through", choices=("build", "deploy", "verify"))
    parser.add_argument("--state", default=".pipeline-progress.json", help="Runner-local phase and log cursor state")
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text())
        if sum((args.logs_only, args.start, args.wait_through is not None)) > 1:
            raise ValueError("conflicting workflow actions")
        if args.wait_through:
            return wait_through(config, args.state, args.wait_through)
        if args.start:
            identifier = os.environ.get("GITHUB_RUN_ID", "") + "-" + os.environ.get("GITHUB_RUN_ATTEMPT", "")
            policy = os.environ.get("FORCE_FULL_QA", "false")
            if policy not in ("true", "false"):
                raise ValueError("invalid QA policy")
            return start_attempt(config, os.environ.get("SOURCE_SHA", ""), identifier, args.state,
                                 force_full_qa=policy == "true")
        action = show_logs if args.logs_only else execute
        return action(config, os.environ.get("SOURCE_SHA"))
    except Exception:
        print("log_replay_unavailable" if args.logs_only else "deployment_unavailable", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
