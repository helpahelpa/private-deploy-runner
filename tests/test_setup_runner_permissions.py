import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('setup_runner_permissions', ROOT / 'scripts/setup_runner.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

IDENTITY = setup.watch.Identity('example/control', 10, 1)
OWNER = {'id': 1, 'role_name': 'admin'}


def contributor(person_id=2, **changes):
    value = {'id': person_id, 'role_name': 'write', 'permissions': {
        'admin': False, 'maintain': False, 'push': True, 'triage': True, 'pull': True}}
    value.update(changes)
    return value


class RunnerPermissionTests(unittest.TestCase):
    def audit(self, people, approved=()):
        gh = Mock()
        gh.request.return_value = people
        setup.verify_collaborators(gh, IDENTITY, set(approved))
        return gh

    def test_owner_only_remains_default_and_unknown_collaborator_rejected(self):
        self.assertEqual(setup.approved_collaborators({}, IDENTITY), set())
        self.audit([OWNER])
        with self.assertRaises(ValueError):
            self.audit([OWNER, contributor()])

    def test_explicit_numeric_identity_allows_standard_write_permissions(self):
        approved = setup.approved_collaborators({'approved_collaborator_ids': [2]}, IDENTITY)
        self.assertEqual(approved, {2})
        self.audit([OWNER, contributor()], approved)
        self.audit([OWNER, contributor(permissions={
            'admin': False, 'maintain': False, 'push': True, 'triage': False, 'pull': True})], approved)

    def test_admin_maintain_custom_or_missing_permissions_are_rejected(self):
        for role in ('admin', 'maintain', 'custom-deployment-role', None):
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.audit([OWNER, contributor(role_name=role)], [2])
        for permission, change in (
                ('admin', True), ('maintain', True), ('push', False),
                ('pull', False), ('admin', 0), ('unknown', True)):
            value = contributor()
            value['permissions'][permission] = change
            with self.subTest(permission=permission, change=change), self.assertRaises(ValueError):
                self.audit([OWNER, value], [2])
        for permissions in (None, {}, {'push': True, 'pull': True}):
            with self.subTest(permissions=permissions), self.assertRaises(ValueError):
                self.audit([OWNER, contributor(permissions=permissions)], [2])

    def test_allowlist_rejects_names_boolean_duplicates_owner_and_invalid_ids(self):
        for values in ('example-user', [True], ['2'], [0], [-2], [2, 2], [1], None):
            with self.subTest(values=values), self.assertRaises(ValueError):
                setup.approved_collaborators({'approved_collaborator_ids': values}, IDENTITY)

    def test_collaborator_audit_rejects_empty_missing_owner_duplicate_and_invalid_identity(self):
        for people in ([], [contributor()], [OWNER, OWNER], [OWNER, {'id': True}],
                       [OWNER, None], {'collaborators': [OWNER]}):
            with self.subTest(people=people), self.assertRaises(ValueError):
                self.audit(people, [2])

    def test_pagination_audits_all_collaborators_and_rejects_later_unapproved_user(self):
        gh = Mock()
        first = [OWNER] + [contributor(person_id) for person_id in range(2, 101)]
        gh.request.side_effect = [first, [contributor(101)]]
        setup.verify_collaborators(gh, IDENTITY, set(range(2, 102)))
        self.assertEqual([call.args[0] for call in gh.request.call_args_list], [
            'repos/example/control/collaborators?affiliation=all&per_page=100&page=1',
            'repos/example/control/collaborators?affiliation=all&per_page=100&page=2'])
        gh.request.side_effect = [first, [contributor(999)]]
        with self.assertRaises(ValueError):
            setup.verify_collaborators(gh, IDENTITY, set(range(2, 102)))

    def test_verify_only_checks_permissions_without_creating_runner_or_registration_token(self):
        self.verify_only(private=True)

    def test_public_runner_repository_is_explicit_and_still_audits_contributors(self):
        self.verify_only(private=False)

    def test_invalid_visibility_is_rejected_before_contacting_github(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'runner.json'
            for private in ('false',0,None):
                path.write_text(json.dumps({'repository':{'full_name':IDENTITY.full_name,'repository_id':10,'owner_id':1},
                                            'repository_private':private}))
                with patch.object(setup.watch,'GitHub') as github,self.assertRaises(ValueError):
                    setup.setup(path,verify_only=True)
                github.assert_not_called()

    def verify_only(self, private):
        config = {'repository': {'full_name': IDENTITY.full_name, 'repository_id': 10, 'owner_id': 1},
                  'approved_collaborator_ids': [2], 'image': 'sha256:' + 'a' * 64,
                  'repository_private': private}
        repository = {'id': 10, 'owner': {'id': 1, 'login': 'example'},
                      'full_name': IDENTITY.full_name, 'private': private}
        gh = Mock()
        gh.request.side_effect = [repository, [OWNER, contributor()]]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runner.json'
            path.write_text(json.dumps(config))
            with patch.object(setup.watch, 'GitHub', return_value=gh), \
                    patch.object(setup, 'verify', return_value='verified-container') as verify, \
                    patch.object(setup, 'run') as run:
                self.assertEqual(setup.setup(path, verify_only=True), 'verified-container')
                verify.assert_called_once_with(config['image'])
                run.assert_not_called()
        self.assertEqual(len(gh.request.call_args_list), 2)


if __name__ == '__main__':
    unittest.main()
