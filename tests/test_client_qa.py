"""Whole-component QA reuse, partition coverage and bounded parallel execution."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import types
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import client_qa as qa
import qa_tasks

COMMIT = 'a' * 40
KEY = 'b' * 64


def commands(count=3):
    discovered = ['fixture.case' + str(index) for index in range(9)]
    return [{'command': ['fixture', str(index)], 'exit_code': 0,
             'result': {'passed': True, 'failures': 0, 'errors': 0, 'skipped': 0,
                        'tests': len(discovered[index::count]), 'test_ids': discovered[index::count],
                        'discovered_test_ids': discovered, 'shard_index': index, 'shard_count': count}}
            for index in range(count)]


class ClientQATests(unittest.TestCase):
    def test_module_cache_reuses_only_matching_evidence_and_full_run_executes_every_module(self):
        inventory=['alpha.C.test_a','beta.C.test_b'];calls=[]
        def execute(module, expected):
            calls.append(module)
            return ({'exit_code':0,'result':{'passed':True,'tests':1,'test_ids':expected,
                'failures':0,'errors':0,'skipped':0}},module.encode())
        with tempfile.TemporaryDirectory() as directory:
            store=qa.Store(directory);keys={'alpha':'a'*64,'beta':'b'*64}
            def run(commit=COMMIT,force=False,inventory=inventory):
                return qa_tasks.run(inventory,keys,store,commit,execute,workers=2,force=force,minimum=2)
            first=run();qa_tasks.publish(store,first,COMMIT)
            self.assertEqual(['alpha','beta'],sorted(calls));calls.clear()
            keys['alpha']='c'*64
            mixed=run('d'*40);qa_tasks.publish(store,mixed,'d'*40)
            self.assertEqual(['alpha'],calls);self.assertEqual(1,mixed['fresh_tests'])
            self.assertEqual([('alpha',False,'d'*40),('beta',True,COMMIT)],
                [(item['module'],item['reused'],item['tested_source_commit']) for item in mixed['modules']])
            self.assertEqual(inventory,mixed['qa']['test_ids']);calls.clear()
            warm=run();self.assertEqual([],calls);self.assertTrue(warm['reused'])
            forced=run(force=True);self.assertEqual(['alpha','beta'],sorted(calls));self.assertEqual(2,forced['fresh_tests'])
            with self.assertRaises(ValueError):
                run(inventory=['alpha.C.test_added','beta.C.test_b'])

    def test_single_trusted_summary_is_required(self):
        marker = b'PRIVATE_CLIENT_TEST_RESULT={"passed":true}\n'
        self.assertEqual(qa.parse_result(b'ordinary output\n' + marker), {'passed': True})
        for output in (b'no marker', marker + marker, b'PRIVATE_CLIENT_TEST_RESULT=[]',
                       b'PRIVATE_CLIENT_TEST_RESULT=invalid'):
            with self.subTest(output=output), self.assertRaises(ValueError):qa.parse_result(output)

    def test_force_full_qa_does_not_reuse_valid_cached_results_and_corruption_stays_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = qa.Store(directory)
            with store.locked():store.publish(KEY, COMMIT, commands(), b'Fixture passed', [], 9)
            self.assertIsNotNone(qa.load_cached(store, KEY, False))
            self.assertIsNone(qa.load_cached(store, KEY, True))
            # An explicit full run is allowed to run, but cannot erase corrupt
            # evidence or publish green over it without operator quarantine.
            (Path(directory) / KEY / 'tests.log').write_bytes(b'corrupt')
            self.assertIsNone(qa.load_cached(store, KEY, True))
            with self.assertRaises(ValueError):store.publish(KEY, COMMIT, commands(), b'fresh passed', [], 9)


    def test_aggregate_rejects_skips_failure_missing_duplicate_or_different_discovery(self):
        class Case(unittest.TestCase):
            def __init__(self, name):
                super().__init__('runTest');self.name = name
            def id(self):return self.name
        inventory = ['alpha.A.test_a', 'alpha.A.test_b', 'alpha.B.test_c',
                     'beta.C.test_a', 'gamma.D.test_a']
        groups = []
        for index in range(3):
            suite, found = qa.selected_suite(unittest.TestSuite(Case(name) for name in inventory), index, 3)
            groups.append([case.id() for case in suite])
            self.assertEqual(found, inventory)
        self.assertEqual(groups, [inventory[:3], inventory[3:4], inventory[4:]])
        fixtures = []
        cases = []
        for name in ('fixture_alpha','fixture_beta'):
            module=types.ModuleType(name);sys.modules[name]=module
            self.addCleanup(sys.modules.pop,name)
            case=type('Case',(unittest.TestCase,),{'__module__':name,'runTest':lambda self:None,
                'setUpClass':classmethod(lambda cls:fixtures.append(('setup',cls.__module__))),
                'tearDownClass':classmethod(lambda cls:fixtures.append(('cleanup',cls.__module__)))})
            cases.append(case())
        suite,_=qa.selected_suite(unittest.TestSuite(cases),0,1)
        result=unittest.TestResult();suite.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(fixtures,[('setup','fixture_alpha'),('cleanup','fixture_alpha'),
                                   ('setup','fixture_beta'),('cleanup','fixture_beta')])
        good = commands()
        self.assertEqual(qa.validate_results(good, ['fixture.case8'], 9)['tests'], 9)
        self.assertEqual(qa.validate_results(commands(4), ['fixture.case8'], 9)['tests'], 9)
        bad = []
        changed = copy.deepcopy(good);changed[0]['result']['skipped'] = 1;bad.append(changed)
        changed = copy.deepcopy(good);changed[0]['exit_code'] = 1;bad.append(changed)
        changed = copy.deepcopy(good);changed[0]['result']['passed'] = False;bad.append(changed)
        changed = copy.deepcopy(good);changed[0]['result']['test_ids'].pop();bad.append(changed)
        changed = copy.deepcopy(good);changed[1] = copy.deepcopy(changed[0]);bad.append(changed)
        changed = copy.deepcopy(good);changed[0]['result']['discovered_test_ids'].append('unknown');bad.append(changed)
        bad.append(good[:-1])
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                qa.validate_results(value, ['fixture.case8'], 9)
        with self.assertRaises(ValueError):qa.validate_results(good, ['missing'], 9)
        with self.assertRaises(ValueError):qa.validate_results(good, [], 10)

    def test_cache_preserves_original_test_identity_and_rejects_corruption(self):
        for corrupted in ('receipt.json', 'tests.log', 'seal.json'):
            with self.subTest(file=corrupted), tempfile.TemporaryDirectory() as directory:
                store = qa.Store(directory)
                self.assertIsNone(store.lookup(KEY))
                with store.locked():store.publish(KEY, COMMIT, commands(), b'Fixture tests passed\n', [], 9)
                cached = store.lookup(KEY)
                self.assertEqual(cached['tested_source_commit'], COMMIT)
                self.assertEqual(cached['input_sha256'], KEY)
                self.assertEqual(cached['log'], b'Fixture tests passed\n')
                with store.locked():store.publish(KEY, 'c' * 40, commands(), b'new', [], 9)
                self.assertEqual(store.lookup(KEY)['tested_source_commit'], COMMIT)
                (Path(directory) / KEY / corrupted).write_bytes(b'corrupt')
                with self.assertRaises(ValueError):store.lookup(KEY)

    def test_failed_suite_never_publishes_and_symlink_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = qa.Store(directory)
            bad = commands();bad[0]['result']['errors'] = 1
            with self.assertRaises(ValueError):store.publish(KEY, COMMIT, bad, b'failed', [], 9)
            self.assertFalse((Path(directory) / KEY).exists())
            (Path(directory) / KEY).symlink_to('/nonexistent')
            with self.assertRaises(ValueError):store.lookup(KEY)

    def test_mount_identity_tracks_unpinned_bytes_links_modes_and_empty_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);file = root / 'runtime';file.write_bytes(b'v1')
            first = qa.tree_identity(root)
            file.write_bytes(b'v2');self.assertNotEqual(qa.tree_identity(root), first)
            before = qa.tree_identity(root);file.chmod(0o755);self.assertNotEqual(qa.tree_identity(root), before)
            before = qa.tree_identity(root);(root / 'empty').mkdir();self.assertNotEqual(qa.tree_identity(root), before)
            (root / 'link').symlink_to('runtime');self.assertEqual(qa.tree_identity(root)['link'], {'link': 'runtime'})

    def test_parallel_execution_overlaps_is_bounded_and_joins_all_workers_on_failure(self):
        gate = threading.Barrier(3)
        active = 0
        peak = 0
        finished = []
        lock = threading.Lock()
        def run(index):
            nonlocal active, peak
            with lock:active += 1;peak = max(peak, active)
            try:
                gate.wait(2)
                if index == 0:raise ValueError('Fixture shard failed')
                time.sleep(.02)
                finished.append(index)
                return index
            finally:
                with lock:active -= 1
        with self.assertRaises(ValueError):qa.run_parallel([0, 1, 2], 3, run)
        self.assertEqual(peak, 3)
        self.assertEqual(active, 0)
        self.assertEqual(sorted(finished), [1, 2])
        self.assertEqual(qa.run_parallel([3, 2, 1], 3, lambda value: value), [3, 2, 1])
        self.assertEqual(qa.run_parallel([0, 1, 2, 3], 4, lambda value: value), [0, 1, 2, 3])


if __name__ == '__main__':
    unittest.main()
