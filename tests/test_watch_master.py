import importlib.util
from dataclasses import replace
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("watch_master", ROOT / "scripts/watch_master.py")
watch = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = watch
spec.loader.exec_module(watch)

A, B, C = "a" * 40, "b" * 40, "c" * 40


class FakeGitHub:
    """Simulate the gh JSON boundary, including asynchronous dispatch visibility."""

    def __init__(self):
        self.sha = A
        self.read_shas = []
        self.runs = []
        self.dispatches = []
        self.requests = []
        self.private = True
        self.owner_id = 1
        self.dispatch_error = False
        self.statuses = []
        self.status_error = False

    def request(self, endpoint, body=None):
        self.requests.append((endpoint, body))
        if endpoint == "repos/example/source":
            return {"id": 10, "owner": {"id": self.owner_id, "login": "example"},
                    "full_name": "example/source", "private": False}
        if endpoint == "repos/example/control":
            return {"id": 11, "owner": {"id": 1, "login": "example"},
                    "full_name": "example/control", "private": self.private}
        if endpoint.endswith("/git/ref/heads/master"):
            return {"object": {"type": "commit", "sha": self.read_shas.pop(0) if self.read_shas else self.sha}}
        if endpoint.endswith("/dispatches"):
            self.dispatches.append(body)
            if self.dispatch_error:
                raise watch.WatchError("GitHub unavailable")
            return None
        if "/statuses/" in endpoint:
            if self.status_error:
                raise watch.WatchError("GitHub unavailable")
            self.statuses.append((endpoint.rsplit("/", 1)[1], dict(body)))
            return {"id": len(self.statuses)}
        if "/workflows/deploy.yml/runs?" in endpoint:
            return {"workflow_runs": list(self.runs)}
        if "/actions/runs/" in endpoint:
            return next(run for run in self.runs if str(run["id"]) == endpoint.rsplit("/", 1)[1])
        raise AssertionError(endpoint)

    def run(self, sha=A, status="in_progress", conclusion=None, run_id=101, created_at="2025-01-01T00:00:00Z"):
        value = {"id": run_id, "display_title": "deploy-" + sha,
                 "event": "workflow_dispatch", "head_branch": "master",
                 "path": ".github/workflows/deploy.yml",
                 "created_at": created_at, "status": status, "conclusion": conclusion}
        self.runs.append(value)
        return value


class WatcherTests(unittest.TestCase):
    def enable_manual_attempts(self):
        self.bindings = self.path.parent / 'attempts'
        self.bindings.mkdir(parents=True)
        self.config = replace(self.config, attempt_bindings=self.bindings, publish_status=True)
        self.watcher = self.restart()
        self.watcher.state.update(deployed_sha=A, last_deployment_run_id=100)
        self.watcher.save()

    def bind_attempt(self, run_id=101, attempt=1, sha=A):
        identifier = str(run_id) + '-' + str(attempt)
        watch.save_state(self.bindings / (identifier + '.json'), {'sha':sha, 'request_id':identifier})

    def test_manual_current_master_run_overrides_old_green_and_failure_stays_red(self):
        self.enable_manual_attempts()
        run = self.github.run(run_id=101)
        run['display_title'] = 'deploy-current-master'
        self.bind_attempt()
        self.assertEqual(self.watcher.tick(), 'deployment_running')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'pending')
        run.update(status='completed', conclusion='failure')
        self.assertEqual(self.watcher.tick(), 'latest_deployment_failed')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'failure')
        self.assertEqual(self.restart().tick(), 'latest_deployment_failed')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'failure')
        self.assertFalse(self.github.dispatches)

    def test_same_github_run_retry_attempt_replaces_previous_green_until_verified(self):
        self.enable_manual_attempts()
        run = self.github.run(run_id=101, status='completed', conclusion='success')
        self.bind_attempt()
        self.assertEqual(self.watcher.tick(), 'current')
        run.update(run_attempt=2, status='in_progress', conclusion=None)
        self.bind_attempt(attempt=2)
        self.assertEqual(self.restart().tick(), 'deployment_running')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'pending')
        run.update(status='completed', conclusion='failure')
        self.assertEqual(self.restart().tick(), 'latest_deployment_failed')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'failure')
        run.update(run_attempt=3, status='in_progress', conclusion=None)
        self.bind_attempt(attempt=3)
        self.assertEqual(self.restart().tick(), 'deployment_running')
        run.update(status='completed', conclusion='success')
        self.assertEqual(self.restart().tick(), 'current')
        self.assertEqual(watch.read_state(self.path)['last_deployment_run_attempt'], 3)
        self.assertEqual(self.github.statuses[-1][1]['state'], 'success')

    def test_older_run_retry_after_newer_success_tracks_pending_failure_and_later_success(self):
        self.enable_manual_attempts()
        old = self.github.run(run_id=101, status='completed', conclusion='success')
        self.bind_attempt(101)
        self.assertEqual(self.watcher.tick(), 'current')
        newer = self.github.run(run_id=102, status='completed', conclusion='success',
                                created_at='2025-01-01T00:01:00Z')
        newer['updated_at'] = '2025-01-01T00:01:30Z'
        self.bind_attempt(102)
        self.assertEqual(self.watcher.tick(), 'current')
        old.update(run_attempt=2, status='in_progress', conclusion=None,
                   run_started_at='2025-01-01T00:02:00Z', updated_at='2025-01-01T00:02:00Z')
        self.bind_attempt(101, 2)
        self.assertEqual(self.restart().tick(), 'deployment_running')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'pending')
        old.update(status='completed', conclusion='failure', updated_at='2025-01-01T00:02:30Z')
        self.assertEqual(self.restart().tick(), 'latest_deployment_failed')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'failure')
        self.assertEqual(self.restart().tick(), 'latest_deployment_failed')
        old.update(run_attempt=3, status='in_progress', conclusion=None,
                   run_started_at='2025-01-01T00:03:00Z', updated_at='2025-01-01T00:03:00Z')
        self.bind_attempt(101, 3)
        self.assertEqual(self.restart().tick(), 'deployment_running')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'pending')
        old.update(status='completed', conclusion='success')
        self.assertEqual(self.restart().tick(), 'current')
        state = watch.read_state(self.path)
        self.assertEqual((state['last_deployment_run_id'], state['last_deployment_run_attempt']), (101, 3))
        self.assertEqual(self.github.statuses[-1][1]['state'], 'success')
        self.assertFalse(self.github.dispatches)

    def test_attempt_watermark_migration_ignores_completed_history_but_discovers_new_retry(self):
        self.enable_manual_attempts()
        self.watcher.state.update(last_deployment_run_id=102, last_deployment_run_attempt=1)
        self.watcher.save()
        old = self.github.run(run_id=101, status='completed', conclusion='failure')
        old.update(run_attempt=2, updated_at='2025-01-01T00:01:00Z')
        self.github.run(run_id=102, status='completed', conclusion='success',
                        created_at='2025-01-01T00:02:00Z')
        self.assertEqual(self.watcher.tick(), 'current')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'success')
        self.assertIsNone(self.watcher.state['inflight'])
        old.update(run_attempt=3, status='in_progress', conclusion=None,
                   updated_at='2025-01-01T00:03:00Z')
        self.bind_attempt(101, 3)
        self.assertEqual(self.restart().tick(), 'deployment_running')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'pending')

    def test_new_observations_use_execution_time_instead_of_run_id_order(self):
        self.enable_manual_attempts()
        self.watcher.state.update(last_observed_run=[102, 1],
                                  observed_run_attempts={'101': 1, '102': 1},
                                  last_observed_run_time=1735689660.0)
        self.watcher.save()
        older = self.github.run(run_id=101, status='completed', conclusion='success')
        older.update(run_attempt=2, updated_at='2025-01-01T00:03:00Z')
        self.bind_attempt(101, 2)
        self.github.run(run_id=103, status='completed', conclusion='failure',
                        created_at='2025-01-01T00:02:00Z')
        self.bind_attempt(103)
        self.assertEqual(self.watcher.tick(), 'current')
        self.assertEqual(self.watcher.state['last_deployment_run_id'], 101)
        self.assertEqual(self.github.statuses[-1][1]['state'], 'success')
        self.assertEqual(self.restart().tick(), 'current')

    def test_per_run_attempt_history_is_bounded_and_persisted_values_are_validated(self):
        self.enable_manual_attempts()
        self.watcher.state['last_deployment_run_id'] = 200
        self.watcher.save()
        for identifier in range(1, 141):
            self.github.run(run_id=identifier, status='completed', conclusion='failure')
        self.assertEqual(self.watcher.tick(), 'current')
        state = watch.read_state(self.path)
        self.assertEqual(len(state['observed_run_attempts']), watch.MAX_OBSERVED_RUNS)
        self.assertEqual(state['observed_run_attempts']['140'], 1)
        for invalid in ({'../escape': 1}, {'101': True}, {'101': 0}, {'101': 10**10}):
            with self.subTest(invalid=invalid):
                changed = dict(state, observed_run_attempts=invalid)
                watch.save_state(self.path, changed)
                with self.assertRaises(watch.WatchError):
                    watch.read_state(self.path)

    def test_manual_green_without_controller_attempt_binding_is_rejected(self):
        self.enable_manual_attempts()
        run = self.github.run(run_id=101, status='completed', conclusion='success')
        run['display_title'] = 'deploy-current-master'
        self.assertEqual(self.watcher.tick(), 'latest_deployment_failed')
        self.assertEqual(self.github.statuses[-1][1]['state'], 'failure')

    def test_blank_manual_queued_run_uses_exact_resolved_binding_after_source_push(self):
        self.enable_manual_attempts()
        run = self.github.run(run_id=101, status='queued')
        run['display_title'] = 'deploy-current-master'
        self.assertEqual(self.watcher.tick(), 'deployment_running')
        self.github.sha = B
        self.bind_attempt(sha=B)
        run.update(status='in_progress')
        self.assertEqual(self.watcher.tick(), 'deployment_running')
        self.assertEqual(self.watcher.state['inflight']['sha'], B)
        run.update(status='completed', conclusion='success')
        self.assertEqual(self.watcher.tick(), 'current')
        self.assertEqual(self.watcher.state['deployed_sha'], B)
        self.assertFalse(self.github.dispatches)

    def test_logs_only_and_malformed_attempts_cannot_override_deployment_status(self):
        self.enable_manual_attempts()
        replay = self.github.run(run_id=101)
        replay['display_title'] = 'logs-' + A
        malformed = self.github.run(run_id=102)
        malformed['run_attempt'] = '../escape'
        self.assertEqual(self.watcher.tick(), 'current')
        self.assertIsNone(self.watcher.state['inflight'])
        self.assertFalse(self.github.dispatches)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "private" / "state.json"
        self.config = watch.Config.read({
            "source": {"full_name": "example/source", "repository_id": 10, "owner_id": 1},
            "control": {"full_name": "example/control", "repository_id": 11, "owner_id": 1},
            "state_file": str(self.path),
        })
        self.github = FakeGitHub()
        self.now = 1735689600.0
        self.watcher = self.restart()

    def restart(self):
        return watch.Watcher(self.config, self.github, lambda: self.now)

    def test_first_push_dispatches_private_workflow_and_waits_for_success(self):
        self.assertEqual(self.watcher.tick(), "dispatched")
        self.assertIsNone(self.watcher.state["deployed_sha"])
        self.assertEqual(self.github.dispatches, [{"ref": "master", "inputs": {"source_sha": A}}])
        run = self.github.run()
        self.assertEqual(self.restart().tick(), "deployment_running")
        self.assertIsNone(watch.read_state(self.path)["deployed_sha"])
        run.update(status="completed", conclusion="success")
        restarted = self.restart()
        self.assertEqual(restarted.tick(), "current")
        self.assertEqual(restarted.state["deployed_sha"], A)
        self.assertEqual(len(self.github.dispatches), 1)
        self.assertEqual(self.restart().tick(), "current")

    def test_new_pushes_coalesce_without_cancelling_live_handoff(self):
        self.watcher.tick()
        run = self.github.run()
        self.github.sha = B
        self.assertEqual(self.watcher.tick(), "deployment_running")
        self.github.sha = C
        self.assertEqual(self.watcher.tick(), "deployment_running")
        self.assertEqual(len(self.github.dispatches), 1)
        run.update(status="completed", conclusion="success")
        self.assertEqual(self.watcher.tick(), "dispatched")
        self.assertEqual(self.watcher.state["deployed_sha"], A)
        self.assertEqual(self.github.dispatches[-1]["inputs"]["source_sha"], C)
        self.assertFalse(any("cancel" in endpoint for endpoint, _ in self.github.requests))

    def test_latest_master_authority_changes_during_live_deployment_without_rewriting_same_sha(self):
        desired = self.path.parent / "desired-master"
        self.config = replace(self.config, desired_commit_file=desired)
        self.watcher = self.restart()
        self.watcher.tick()
        self.github.run()
        self.assertEqual(desired.read_text(), A + "\n")
        previous = desired.stat()
        self.assertEqual(self.watcher.tick(), "deployment_running")
        self.assertEqual(desired.stat().st_ino, previous.st_ino)
        self.assertEqual(desired.stat().st_mtime_ns, previous.st_mtime_ns)
        self.github.sha = B
        self.assertEqual(self.watcher.tick(), "deployment_running")
        self.assertEqual(desired.read_text(), B + "\n")
        self.assertEqual(stat.S_IMODE(desired.stat().st_mode), 0o600)
        self.assertEqual(len(self.github.dispatches), 1)

    def test_latest_authority_uses_reverified_sha_when_source_changes_before_dispatch(self):
        desired = self.path.parent / "desired-master"
        self.config = replace(self.config, desired_commit_file=desired)
        self.watcher = self.restart()
        self.github.read_shas = [A, B]
        self.assertEqual(self.watcher.tick(), "source_changed")
        self.assertEqual(desired.read_text(), B + "\n")
        self.assertFalse(self.github.dispatches)

    def test_source_is_rechecked_before_dispatch(self):
        self.github.read_shas = [A, B]
        self.assertEqual(self.watcher.tick(), "source_changed")
        self.assertFalse(self.github.dispatches)
        self.assertFalse(self.path.exists())
        self.github.sha = B
        self.assertEqual(self.watcher.tick(), "dispatched")
        self.assertEqual(self.github.dispatches[0]["inputs"]["source_sha"], B)

    def test_restart_reconciles_dispatch_timeout_without_duplicate(self):
        self.github.dispatch_error = True
        with self.assertRaises(watch.WatchError):
            self.watcher.tick()
        self.assertEqual(watch.read_state(self.path)["inflight"]["sha"], A)
        self.github.dispatch_error = False
        self.assertEqual(self.restart().tick(), "dispatch_pending")
        self.github.run()
        self.assertEqual(self.restart().tick(), "deployment_running")
        self.assertEqual(len(self.github.dispatches), 1)

    def test_invisible_dispatch_has_bounded_retries_across_restarts(self):
        for attempt in range(3):
            self.watcher = self.restart()
            self.assertEqual(self.watcher.tick(), "dispatched")
            self.now += 121
            self.assertEqual(self.watcher.tick(), "retry_wait" if attempt < 2 else "retry_exhausted")
            self.now += 31
        self.assertEqual(self.restart().tick(), "retry_exhausted")
        self.assertEqual(len(self.github.dispatches), 3)
        self.assertIsNone(watch.read_state(self.path)["deployed_sha"])
        self.github.sha = B
        self.assertEqual(self.restart().tick(), "dispatched")

    def test_failed_old_run_does_not_delay_newest_commit(self):
        self.watcher.tick()
        self.github.run(status="completed", conclusion="failure")
        self.github.sha = B
        self.assertEqual(self.watcher.tick(), "dispatched")
        self.assertEqual(self.github.dispatches[-1]["inputs"]["source_sha"], B)
        self.assertEqual(self.watcher.state["failures"][A]["count"], 1)
        self.assertIsNone(self.watcher.state["deployed_sha"])

    def test_failed_current_run_retries_after_delay(self):
        self.watcher.tick()
        self.github.run(status="completed", conclusion="cancelled")
        self.assertEqual(self.watcher.tick(), "retry_wait")
        self.now += 31
        self.assertEqual(self.restart().tick(), "dispatched")
        # A previous run with the same SHA cannot satisfy the new dispatch.
        self.assertEqual(self.restart().tick(), "dispatch_pending")

    def test_unrelated_and_old_runs_do_not_mark_commit_active(self):
        self.watcher.tick()
        self.github.run(status="completed", conclusion="success", created_at="2024-12-31T00:00:00Z")
        self.github.run(sha=B, status="completed", conclusion="success", run_id=102)
        unrelated = self.github.run(status="completed", conclusion="success", run_id=103)
        unrelated["event"] = "push"
        self.assertEqual(self.restart().tick(), "dispatch_pending")
        self.assertIsNone(watch.read_state(self.path)["deployed_sha"])

    def test_identity_and_private_repository_fail_closed(self):
        self.github.owner_id = 5
        with self.assertRaises(watch.WatchError):
            self.watcher.tick()
        self.github.owner_id = 1
        self.github.private = False
        with self.assertRaises(watch.WatchError):
            self.watcher.tick()
        self.assertFalse(self.github.dispatches)

    def test_public_controller_requires_explicit_visibility_and_pinned_identity(self):
        self.github.private = False
        self.config = replace(self.config, control_private=False)
        self.assertEqual(self.restart().tick(), "dispatched")
        self.github.owner_id = 5
        with self.assertRaises(watch.WatchError):
            self.restart().tick()
        self.github.owner_id = 1
        self.github.private = True
        with self.assertRaises(watch.WatchError):
            self.restart().tick()

    def test_controller_visibility_setting_requires_boolean(self):
        for value in (None, "false", 0, 1):
            with self.subTest(value=value), self.assertRaises(watch.WatchError):
                watch.Config.read({"source": {"full_name": "example/source", "repository_id": 10, "owner_id": 1},
                                   "control": {"full_name": "example/control", "repository_id": 11, "owner_id": 1},
                                   "state_file": str(self.path), "control_private": value})

    def test_malformed_source_sha_cannot_be_dispatched(self):
        for value in ["A" * 40, "refs/heads/master", A + ";echo bad", "a" * 39]:
            with self.subTest(value=value):
                self.github.sha = value
                with self.assertRaises(watch.WatchError):
                    self.watcher.tick()
        self.assertFalse(self.github.dispatches)

    def test_state_is_atomic_private_and_single_writer(self):
        with watch.state_lock(self.path):
            with self.assertRaises(watch.WatchError):
                with watch.state_lock(self.path):
                    self.fail("a second writer acquired the lock")
            self.watcher.tick()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(list(self.path.parent.glob(".watch-state-*")), [])
        self.path.write_text("broken")
        with self.assertRaises(watch.WatchError):
            self.restart()

    def test_config_only_accepts_separate_allowlisted_identities(self):
        base = json.loads((ROOT / "watcher.config.example.json").read_text())
        for change in [
            {"max_attempts": 0}, {"max_attempts": 11}, {"poll_seconds": False},
            {"control_branch": "master;echo bad"}, {"state_file": "relative"},
            {"publish_status": 1}, {"publish_status": "true"},
            {"desired_commit_file": "relative"}, {"desired_commit_file": base["state_file"]},
            {"control": base["source"]},
            {"source": {"full_name": "bad/name/more", "repository_id": 1, "owner_id": 1}},
        ]:
            with self.subTest(change=change), self.assertRaises(watch.WatchError):
                watch.Config.read(dict(base, **change))


class CommitStatusTests(unittest.TestCase):
    restart = WatcherTests.restart

    def setUp(self):
        WatcherTests.setUp(self)
        self.config = replace(self.config, publish_status=True)
        self.watcher = self.restart()

    def status(self, sha=A):
        return [body for current, body in self.github.statuses if current == sha][-1]

    def test_statuses_link_exact_private_run_and_success_is_durable(self):
        self.assertEqual(self.watcher.tick(), "dispatched")
        self.assertEqual(self.status()["state"], "pending")
        self.assertEqual(self.status()["context"], "deployment/Main")
        self.assertTrue(self.status()["target_url"].endswith("/workflows/deploy.yml"))
        run = self.github.run()
        self.assertEqual(self.restart().tick(), "deployment_running")
        self.assertEqual(self.status()["state"], "pending")
        self.assertEqual(self.status()["target_url"], "https://github.com/example/control/actions/runs/101")
        run.update(status="completed", conclusion="success")
        self.assertEqual(self.restart().tick(), "current")
        self.assertEqual(self.status()["state"], "success")
        self.assertEqual(watch.read_state(self.path)["last_deployment_run_id"], 101)
        count = len(self.github.statuses)
        self.assertEqual(self.restart().tick(), "current")
        self.assertEqual(len(self.github.statuses), count)

    def test_status_api_error_retries_across_restart_without_dispatch_or_completion_loss(self):
        self.github.status_error = True
        self.assertEqual(self.watcher.tick(), "dispatched")
        self.assertFalse(self.github.statuses)
        self.github.status_error = False
        self.assertEqual(self.restart().tick(), "dispatch_pending")
        self.assertEqual(len(self.github.dispatches), 1)
        self.assertEqual(self.status()["state"], "pending")
        self.github.run(status="completed", conclusion="success")
        self.github.status_error = True
        self.assertEqual(self.restart().tick(), "current")
        saved = watch.read_state(self.path)
        self.assertEqual(saved["deployed_sha"], A)
        self.assertIsNone(saved["inflight"])
        self.assertFalse(saved["commit_statuses"][A]["published"])
        self.github.status_error = False
        self.assertEqual(self.restart().tick(), "current")
        self.assertEqual(self.status()["state"], "success")
        self.assertEqual(len(self.github.dispatches), 1)

    def test_cancelled_run_stays_failed_until_retry_is_dispatched(self):
        self.watcher.tick()
        self.github.run(status="completed", conclusion="cancelled")
        self.assertEqual(self.restart().tick(), "retry_wait")
        self.assertEqual(self.status()["state"], "failure")
        count = len(self.github.statuses)
        self.assertEqual(self.restart().tick(), "retry_wait")
        self.assertEqual(len(self.github.statuses), count)
        self.now += 31
        self.assertEqual(self.restart().tick(), "dispatched")
        self.assertEqual(self.status()["state"], "pending")

    def test_old_success_never_marks_new_master_success(self):
        self.watcher.tick()
        run = self.github.run()
        self.github.sha = B
        self.assertEqual(self.restart().tick(), "deployment_running")
        self.assertEqual(self.status(B)["state"], "pending")
        run.update(status="completed", conclusion="success")
        self.assertEqual(self.restart().tick(), "dispatched")
        self.assertEqual(self.status(A)["state"], "success")
        self.assertEqual(self.status(B)["state"], "pending")
        self.assertFalse(any(sha == B and body["state"] == "success" for sha, body in self.github.statuses))

    def test_superseded_queued_commit_is_not_left_pending(self):
        self.watcher.tick()
        self.github.run()
        self.github.sha = B
        self.restart().tick()
        self.assertEqual(self.status(B)["state"], "pending")
        self.github.sha = C
        self.restart().tick()
        self.assertEqual(self.status(B)["state"], "failure")
        self.assertIn("Superseded", self.status(B)["description"])
        self.assertEqual(self.status(C)["state"], "pending")
        self.assertEqual(self.status(A)["state"], "pending")

    def test_unconfirmed_source_change_cannot_publish_dispatch_or_success(self):
        self.github.read_shas = [A, B]
        self.assertEqual(self.watcher.tick(), "source_changed")
        self.assertFalse(self.github.statuses)
        self.assertFalse(self.github.dispatches)

    def test_readonly_log_run_never_satisfies_list_or_persisted_run_id(self):
        self.watcher.tick()
        run = self.github.run(status="completed", conclusion="success")
        run["display_title"] = "logs-" + A
        self.assertEqual(self.restart().tick(), "dispatch_pending")
        state = watch.read_state(self.path)
        state["inflight"]["run_id"] = run["id"]
        watch.save_state(self.path, state)
        self.assertEqual(self.restart().tick(), "dispatch_pending")
        self.assertIsNone(watch.read_state(self.path)["deployed_sha"])
        self.assertFalse(any(body["state"] == "success" for _, body in self.github.statuses))

    def test_dispatch_timeout_reports_failure_and_invalid_identity_prevents_status_post(self):
        self.watcher.tick()
        self.now += 121
        self.assertEqual(self.restart().tick(), "retry_wait")
        self.assertEqual(self.status()["state"], "failure")
        self.github.owner_id = 5
        self.github.statuses.clear()
        with self.assertRaises(watch.WatchError):
            self.restart().tick()
        self.assertFalse(self.github.statuses)

    def test_legacy_current_state_without_success_run_cannot_invent_green_status(self):
        watch.save_state(self.path, {"version": 1, "deployed_sha": A, "inflight": None, "failures": {}})
        self.assertEqual(self.restart().tick(), "current")
        self.assertFalse(self.github.statuses)
        state = watch.read_state(self.path)
        state["last_deployment_run_id"] = 101
        watch.save_state(self.path, state)
        self.assertEqual(self.restart().tick(), "current")
        self.assertEqual(self.status()["state"], "success")

    def test_status_state_is_bounded_and_malformed_status_targets_rejected(self):
        for number in range(40):
            self.watcher.status(f"{number:040x}", "queued")
            self.now += 1
        self.assertEqual(len(watch.read_state(self.path)["commit_statuses"]), 32)
        saved = watch.read_state(self.path)
        status = next(iter(saved["commit_statuses"].values()))
        status["body"]["target_url"] = "https://private-host.invalid/secret"
        watch.save_state(self.path, saved)
        with self.assertRaises(watch.WatchError):
            self.restart()

    def test_status_publishing_is_disabled_by_default(self):
        self.config = replace(self.config, publish_status=False)
        self.assertEqual(self.restart().tick(), "dispatched")
        self.assertFalse(self.github.statuses)


class BoundaryTests(unittest.TestCase):
    def test_gh_uses_fixed_host_captured_output_and_json_stdin(self):
        result = subprocess.CompletedProcess([], 0, "", "private data")
        with patch.object(watch.subprocess, "run", return_value=result) as run:
            watch.GitHub().request("repos/example/control/actions/workflows/deploy.yml/dispatches",
                                   {"inputs": {"source_sha": A}})
        args, kwargs = run.call_args
        self.assertEqual(args[0][:4], ["gh", "api", "--hostname", "github.com"])
        self.assertEqual(args[0][-4:], ["--method", "POST", "--input", "-"])
        self.assertEqual(json.loads(kwargs["input"]), {"inputs": {"source_sha": A}})
        self.assertTrue(kwargs["capture_output"])
        self.assertNotIn("shell", kwargs)

    def test_gh_error_cannot_expose_private_output(self):
        result = subprocess.CompletedProcess([], 1, "credential-value", "private-host-path")
        with patch.object(watch.subprocess, "run", return_value=result):
            with self.assertRaises(watch.WatchError) as error:
                watch.GitHub().request("repos/example/control")
        self.assertEqual(str(error.exception), "GitHub unavailable")



if __name__ == "__main__":
    unittest.main()
