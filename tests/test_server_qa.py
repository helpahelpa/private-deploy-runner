"""Whole-suite coverage, isolated worker execution and sealed cache regressions."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import server_qa as qa


class CoverageTests(unittest.TestCase):
    def reports(self):
        inventory=sorted(['test_one.A.test_a','test_one.A.test_b','test_two.B.test_c'])
        return [dict(worker=index,workers=2,inventory=inventory,selected=selected,executed=selected,
                     tests=len(selected),passed=True,failures=0,errors=0,skipped=0)
                for index,selected in enumerate(qa.partition(inventory,2))]


    def test_missing_duplicate_skipped_failed_or_inconsistent_evidence_is_rejected(self):
        mutations=[lambda reports:reports.pop(),lambda reports:reports[0].update(executed=[]),
                   lambda reports:reports[0].update(skipped=1),lambda reports:reports[1].update(errors=1),
                   lambda reports:reports[1].update(passed=False),
                   lambda reports:reports[1].update(inventory=['invented']),
                   lambda reports:reports[1].update(selected=reports[0]['selected'])]
        for mutate in mutations:
            reports=copy.deepcopy(self.reports());mutate(reports)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):qa.aggregate(reports,2,3)
        with self.assertRaises(ValueError):qa.aggregate(self.reports(),2,4)

    def test_real_worker_processes_collect_and_execute_every_synthetic_test_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for module in ('alpha','beta'):
                (root/('test_'+module+'.py')).write_text('import unittest\nclass Tests(unittest.TestCase):\n def test_pass(self): self.assertTrue(True)\n')
            reports=[]
            for index in range(2):
                result=subprocess.run([sys.executable,qa.__file__,'--worker',str(index),'--workers','2'],cwd=root,capture_output=True,text=True,check=True)
                reports.append(json.loads(next(line[len(qa.MARKER):] for line in result.stdout.splitlines() if line.startswith(qa.MARKER))))
            self.assertEqual(2,qa.aggregate(reports,2,2)['tests'])
            result=subprocess.run([sys.executable,qa.__file__,'--module','test_alpha'],cwd=root,capture_output=True,text=True,check=True)
            report=json.loads(next(line[len(qa.MARKER):] for line in result.stdout.splitlines() if line.startswith(qa.MARKER)))
            self.assertEqual(['test_alpha.Tests.test_pass'],report['test_ids'])
            result=subprocess.run([sys.executable,qa.__file__,'--discover-only'],cwd=root,capture_output=True,text=True,check=True)
            report=json.loads(next(line[len(qa.MARKER):] for line in result.stdout.splitlines() if line.startswith(qa.MARKER)))
            self.assertEqual(['test_alpha.Tests.test_pass','test_beta.Tests.test_pass'],report['inventory'])
            result=subprocess.run([sys.executable,qa.__file__,'--modules',json.dumps(['test_alpha','test_beta'])],cwd=root,capture_output=True,text=True,check=True)
            report=json.loads(next(line[len(qa.MARKER):] for line in result.stdout.splitlines() if line.startswith(qa.MARKER)))
            self.assertEqual(['test_alpha.Tests.test_pass','test_beta.Tests.test_pass'],report['test_ids'])


if __name__=='__main__':unittest.main()
