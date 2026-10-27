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
LIMIT = 4096
MAX_CURSOR = (1 << 63) - 1
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_LOG_PAGES = 8192


def request(config, token, operation, sha, cursor=None):
    payload = {"token": token, "op": operation, "sha": sha}
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
    if not isinstance(data, dict) or data.get("sha") != sha or data.get("status") not in ("queued", "running", "success", "failed"):
        raise ValueError("invalid status")
    if operation == "logs":
        if (not isinstance(data.get("text"), str) or type(data.get("cursor")) is not int
                or not 0 <= data["cursor"] <= MAX_CURSOR or type(data.get("more")) is not bool):
            raise ValueError("invalid log page")
        if data["cursor"] - cursor != len(data["text"].encode("utf-8")) or (data["more"] and not data["text"]):
            raise ValueError("invalid log progress")
    return data


class BuildOutput:
    """Bounded, cursor-based journal reader; every emitted line is inert text."""
    def __init__(self):
        self.cursor = 0
        self.pending = ""
        self.pages = 0

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
            page = request(config, token, "logs", sha, self.cursor)
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


def authenticate(config, sha):
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
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


def execute(config, sha, *, clock=time.monotonic, sleep=time.sleep):
    token = authenticate(config, sha)
    interval = config.get("poll_seconds", 2)
    timeout = config.get("timeout_seconds", 3500)
    if type(interval) is not int or not 1 <= interval <= 30 or type(timeout) is not int or not 1 <= timeout <= 3500:
        raise ValueError("invalid timing")
    deadline = clock() + timeout
    data = request(config, token, "submit", sha)
    previous = None
    output = BuildOutput()
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
                verified = request(config, token, "status", sha)
                return 0 if verified["status"] == "success" else 1
            return 1
        if page["status"] in ("success", "failed"):
            data = page
            continue
        sleep(interval)
        data = request(config, token, "status", sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--logs-only", action="store_true", help="Read recorded logs without requesting deployment")
    args = parser.parse_args()
    try:
        action = show_logs if args.logs_only else execute
        return action(json.loads(Path(args.config).read_text()), os.environ.get("SOURCE_SHA"))
    except Exception:
        print("log_replay_unavailable" if args.logs_only else "deployment_unavailable", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
