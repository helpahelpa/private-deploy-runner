#!/usr/bin/env python3
"""Keep only the recorded, verified world alive across process/daemon restarts."""
import argparse
import json
import signal
import threading
import time

from deploy_engine import DeploymentError, Engine, PROTOCOL, require, run


class WorldService:
    def __init__(self, engine, *, verify_seconds=60, clock=time.monotonic):
        require(1 <= verify_seconds <= 300, 'Invalid verification interval')
        self.engine = engine
        self.clock = clock
        self.verify_seconds = verify_seconds
        self.verified = None
        self.next_verification = 0

    @staticmethod
    def identity(active):
        return tuple(active.get(name) for name in
                     ('release', 'image', 'container', 'release_path', 'ingress', 'assets_sha256'))

    def running(self, cid):
        # Read-only, bounded probes deliberately avoid the engine's per-command
        # evidence logs: an always-on service must not accumulate inspect dumps.
        import re
        require(re.fullmatch(r'[0-9a-f]{64}', cid or ''), 'Exact recorded container required')
        state = json.loads(run(['docker', 'inspect', '--format', '{{json .State}}', cid], timeout=3))
        return state.get('Running') is True and not state.get('Paused') and not state.get('Restarting')

    def tick(self):
        engine = self.engine
        observed = None
        try:
            # Promotion owns this same nonblocking lock throughout handoff.
            # Hold it only for the registry snapshot: slow read-only Docker
            # probes must not delay a new deployment acquiring its writer lock.
            with engine.lock():
                active = engine.active()
                observed = self.identity(active)
            if self.verified == observed and self.clock() < self.next_verification:
                if self.running(active['container']) and self.running(active.get('ingress')):
                    state = engine.control({'op': 'status'}, timeout=2)
                    if (state.get('release') == active['release'] and
                            state.get('compatibility') == PROTOCOL and
                            not state.get('write_fenced')):
                        return 'healthy'
        except DeploymentError as error:
            if str(error) == 'Another deployment is running':
                return 'deployment_in_progress'
            # Missing/unavailable containers or control transport are recovered
            # only by the fully validating engine, never by a raw docker start.
        except (OSError, ValueError, KeyError, TypeError):
            pass

        try:
            recovered = engine.recover_active()
        except DeploymentError as error:
            if str(error) == 'Another deployment is running':
                return 'deployment_in_progress'
            raise
        if observed and (recovered['release'], recovered['container'], recovered['ingress']) == (
                observed[0], observed[2], observed[4]):
            self.verified = observed
            self.next_verification = self.clock() + self.verify_seconds
        else:
            # A promotion or ingress recreation changed the registry while the
            # probe lock was released. Revalidate that new identity next pass.
            self.verified = None
        return 'recovered'


def serve(service, *, poll_seconds=10, once=False, stopped=None, emit=print):
    require(1 <= poll_seconds <= 60, 'Invalid polling interval')
    stopped = stopped or threading.Event()
    previous = None
    while not stopped.is_set():
        try:
            state = service.tick()
        except Exception:
            # Docker/config/control failures can contain private paths or
            # credentials. Journal only fixed events and retry without exiting.
            state = 'recovery_pending'
        if state != previous:
            emit('World service: ' + state, flush=True)
            previous = state
        if once:
            return 0 if state in ('healthy', 'recovered', 'deployment_in_progress') else 1
        stopped.wait(poll_seconds)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--poll-seconds', type=int, default=10)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    try:
        service = WorldService(Engine(args.config))
        return serve(service, poll_seconds=args.poll_seconds, once=args.once, stopped=stopped)
    except Exception:
        print('World service: configuration_unavailable', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
