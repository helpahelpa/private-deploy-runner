"""Intermediate build reuse through the persistent transform boundary."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import build_artifacts

class ArtifactTests(unittest.TestCase):
    def test_verified_outputs_reuse_across_builds_inputs_and_policy_invalidate_and_corruption_fails(self):
        calls=[]
        def compile(raw):
            calls.append(raw)
            return {b'one':b'compiled-one',b'two':b'compiled-two'}[raw]
        with tempfile.TemporaryDirectory() as directory:
            store=build_artifacts.Store(directory)
            first,receipt=store.transform('client',{'tool':'v1'},b'one',compile)
            self.assertEqual(b'compiled-one',first);self.assertFalse(receipt['reused'])
            cached,hit=build_artifacts.Store(directory).transform('client',{'tool':'v1'},b'one',compile)
            self.assertEqual(b'compiled-one',cached);self.assertTrue(hit['reused']);self.assertEqual([b'one'],calls)
            changed,_=store.transform('client',{'tool':'v1'},b'two',compile);self.assertEqual(b'compiled-two',changed)
            store.transform('client',{'tool':'v2'},b'one',compile);self.assertEqual([b'one',b'two',b'one'],calls)
            (Path(directory)/receipt['input_sha256']/'payload.bin').write_bytes(b'corrupted')
            with self.assertRaises(ValueError):store.transform('client',{'tool':'v1'},b'one',compile)
            before={p.name for p in Path(directory).iterdir()}
            def failed(raw):raise RuntimeError('Compiler failed')
            with self.assertRaises(RuntimeError):store.transform('client',{'tool':'v3'},b'one',failed)
            self.assertEqual(before,{p.name for p in Path(directory).iterdir()})

if __name__=='__main__':unittest.main()
