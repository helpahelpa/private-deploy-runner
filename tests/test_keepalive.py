"""Execute the reviewed keepalive task plan without registering an OS task."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = os.environ.get('PRIVATE_KEEPALIVE_POWERSHELL') or shutil.which('pwsh') or shutil.which('powershell.exe')


@unittest.skipUnless(POWERSHELL, 'Set PRIVATE_KEEPALIVE_POWERSHELL to test the Windows task plan')
class KeepalivePlanTests(unittest.TestCase):
    def plan(self, distribution):
        source = (ROOT / 'scripts/keepalive.ps1').read_text()
        # Invoke actual parameter validation and NoRegister branch. Neither
        # valid nor rejected plans instantiate COM or change scheduled tasks.
        command = '& {\n' + source + '\n} -Distribution ' + distribution + ' -NoRegister'
        return subprocess.run([POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)

    def test_distribution_plan_has_no_literal_quotes_and_rejects_unsafe_names(self):
        result = self.plan('ExampleDistro-24.04')
        self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))
        plan = json.loads(result.stdout.decode('utf-8-sig'))
        self.assertEqual('--distribution ExampleDistro-24.04 --exec /usr/bin/sleep infinity', plan['argument_string'])
        self.assertEqual(['--distribution', 'ExampleDistro-24.04', '--exec', '/usr/bin/sleep', 'infinity'], plan['arguments'])
        self.assertEqual(0, plan['execution_time_limit_seconds'])
        self.assertEqual('Interactive', plan['logon_type'])
        self.assertNotEqual(0, self.plan("'Example Distro'").returncode)
        self.assertNotEqual(0, self.plan("'bad&name'").returncode)


if __name__ == '__main__':
    unittest.main()
