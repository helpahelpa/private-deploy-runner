#!/usr/bin/env python3
"""Rebuild the pinned sandbox image from verified, pre-provisioned dependencies."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import deploy_engine as engine

PRIVATE=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);a=p.parse_args();c=json.loads(Path(a.config).read_text())
    source=Path(c['dependencies']);engine.require(engine.tree(source)==c['files'],'Dependency tree changed')
    with tempfile.TemporaryDirectory(prefix='sandbox-image-') as t:
        stage=Path(t);shutil.copytree(source,stage/'dependencies');shutil.copyfile(PRIVATE/'runner/client.Dockerfile',stage/'Dockerfile')
        result=subprocess.run(['docker','build','--network','none','--pull=false','--iidfile',str(stage/'image.id'),str(stage)],capture_output=True)
        engine.require(result.returncode==0,'Sandbox image build failed')
        image=(stage/'image.id').read_text().strip();engine.require(engine.IMAGE.fullmatch(image),'Immutable image missing');Path(c['output']).write_text(image+'\n');print(image)

if __name__=='__main__':main()
