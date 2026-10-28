"""Whole-server QA evidence and immutable component cache; no per-test caching."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
import uuid

MARKER = 'PRIVATE_SERVER_QA_RESULT='
MINIMUM_TESTS = 740
HEX = re.compile(r'[0-9a-f]{64}\Z')


def checksum(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):value.update(block)
    return value.hexdigest()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def partition(inventory,workers):
    if type(workers) is not int or not 1<=workers<=4 or len(inventory)!=len(set(inventory)):
        raise ValueError('Invalid server QA inventory')
    modules={}
    for name in inventory:modules.setdefault(name.rsplit('.',2)[0],[]).append(name)
    groups=[[] for _ in range(workers)]
    for module,names in sorted(modules.items(),key=lambda item:(-len(item[1]),item[0])):
        index=min(range(workers),key=lambda n:(len(groups[n]),n));groups[index].extend(sorted(names))
    return [sorted(group) for group in groups]


def aggregate(reports,workers,minimum_tests=1):
    if len(reports)!=workers:raise ValueError('Missing server QA worker')
    expected=reports[0]['inventory'];groups=partition(expected,workers);executed=[]
    if len(expected)<minimum_tests:raise ValueError('Server QA baseline missing')
    for index,report in enumerate(reports):
        if (report.get('worker')!=index or report.get('workers')!=workers or report.get('inventory')!=expected
                or report.get('selected')!=groups[index] or report.get('executed')!=groups[index]
                or report.get('tests')!=len(groups[index]) or report.get('passed') is not True
                or any(report.get(name)!=0 for name in ('failures','errors','skipped'))):
            raise ValueError('Incomplete or failed server QA partition')
        executed.extend(report['executed'])
    if sorted(executed)!=expected or len(executed)!=len(set(executed)):
        raise ValueError('Missing or duplicate server QA test')
    return {'passed':True,'tests':len(expected),'failures':0,'errors':0,'skipped':0,
            'test_ids':expected,'workers':workers,'partition':'deterministic whole modules'}


def files(root):
    root=Path(root);result={}
    if root.is_symlink() or not root.is_dir():raise ValueError('Unsafe server cache directory')
    for path in sorted(root.rglob('*')):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):raise ValueError('Unsafe server cache entry')
        if path.is_file():result[path.relative_to(root).as_posix()]=checksum(path)
    return result


class Store:
    def __init__(self,root):
        self.root=Path(root).absolute()
        if self.root.is_symlink():raise ValueError('Unsafe server cache root')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)

    def entry(self,key):
        if not isinstance(key,str) or not HEX.fullmatch(key):raise ValueError('Invalid server cache key')
        path=self.root/key
        if path.is_symlink():raise ValueError('Unsafe server cache key directory')
        return path

    def lookup(self,key):
        root=self.entry(key);pointer=root/'current.json'
        if not pointer.exists():return None
        if pointer.is_symlink():raise ValueError('Unsafe server cache pointer')
        generation=json.loads(pointer.read_text())['generation']
        if not re.fullmatch(r'[0-9a-f]{32}',generation):raise ValueError('Invalid server cache generation')
        path=root/generation;seal=path/'cache.json'
        if seal.is_symlink():raise ValueError('Unsafe server cache seal')
        record=json.loads(seal.read_text());actual=files(path);actual.pop('cache.json',None)
        if record.get('key')!=key or record.get('files')!=actual:raise ValueError('Server cache integrity mismatch')
        info=json.loads((path/'server.json').read_text());qa=json.loads((path/'qa.json').read_text())
        if (info.get('tests_passed') is not True or qa.get('passed') is not True
                or info.get('commit')!=record.get('tested_source_commit')
                or info.get('image_tar_sha256')!=actual.get('server-image.tar')
                or info.get('test_log_sha256')!=actual.get('tests.log')
                or info.get('qa_receipt_sha256')!=actual.get('qa.json')
                or info.get('cache_provenance',{}).get('key')!=key
                or qa.get('tests')!=len(qa.get('test_ids',[]))
                or qa.get('tests',0)<MINIMUM_TESTS or qa.get('test_ids')!=sorted(set(qa.get('test_ids',[])))
                or any(qa.get(name)!=0 for name in ('failures','errors','skipped'))):
            raise ValueError('Invalid server cache QA evidence')
        return {'path':path,'receipt':info,'qa':qa,'tested_source_commit':record['tested_source_commit']}

    def publish(self,key,artifact):
        root=self.entry(key);root.mkdir(parents=True,exist_ok=True,mode=0o700)
        generation=uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix='.server-',dir=root) as temporary:
            staged=Path(temporary)/'artifact';shutil.copytree(artifact,staged)
            record={'key':key,'tested_source_commit':json.loads((staged/'server.json').read_text())['commit'],'files':files(staged)}
            (staged/'cache.json').write_text(json.dumps(record,sort_keys=True)+'\n')
            for path in staged.rglob('*'):
                if path.is_file():path.chmod(0o600)
            os.replace(staged,root/generation)
        pointer=root/('.current-'+uuid.uuid4().hex)
        pointer.write_text(json.dumps({'generation':generation})+'\n');pointer.chmod(0o600)
        os.replace(pointer,root/'current.json')


def flatten(suite):
    for test in suite:
        if isinstance(test,unittest.TestSuite):yield from flatten(test)
        else:yield test


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker',type=int,required=True);parser.add_argument('--workers',type=int,required=True)
    args=parser.parse_args()
    tests=list(flatten(unittest.defaultTestLoader.discover('.',pattern='test_*.py')))
    inventory=sorted(test.id() for test in tests);groups=partition(inventory,args.workers)
    if not 0<=args.worker<args.workers:raise ValueError('Invalid server QA worker')
    selected=groups[args.worker];chosen=set(selected)
    class Result(unittest.TextTestResult):
        def __init__(self,*values,**options):
            super().__init__(*values,**options);self.executed=[]
        def startTest(self,test):
            self.executed.append(test.id());super().startTest(test)
    runner=unittest.TextTestRunner(stream=sys.stdout,verbosity=2,resultclass=Result)
    result=runner.run(unittest.TestSuite(test for test in tests if test.id() in chosen))
    report={'worker':args.worker,'workers':args.workers,'inventory':inventory,'selected':selected,
            'executed':sorted(result.executed),'tests':result.testsRun,'failures':len(result.failures),
            'errors':len(result.errors),'skipped':len(result.skipped),'passed':result.wasSuccessful() and not result.skipped}
    print(MARKER+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':sys.exit(main())
