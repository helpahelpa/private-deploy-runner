import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import sync_registry


class RegistryTests(unittest.TestCase):
    def test_replaces_only_world_pins_and_preserves_installed_client_and_route(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); release=root/'release';release.mkdir();(release/'assets').mkdir();(release/'assets/update_config.json').write_text(json.dumps({'server_versions':{'Android_90':'4.2.0.64'}}))
            (release/'server.json').write_text(json.dumps({'source_files':{'server/game.py':'sourcehash'}}))
            (release/'manifest.json').write_text('{}')
            old=root/'fingerprint.json';old.write_text(json.dumps({'source_commit':'old','active_runtime':{'container':'old'}}))
            main=root/'main.json';value={'role':'Main','mode':'authenticated-shared-world','apk_sha256':'installed60','network_route_sha256':'routepin','network_route_file':'externalroute','containers':[{'id':'old','service':'world'}, {'id':'edge','image':'edgeimage','service':'agent'}]}; main.write_text(json.dumps(value))
            config=root/'config.json';config.write_text(json.dumps({'engine_config':'private','main_config':str(main),'fingerprint':str(root/'fingerprint.json'),'distribution_apk':str(root/'distribution.apk')}))
            runtime=SimpleNamespace(c={'project':'private-main-world','data_volume':'earned-volume'}, status=lambda:{'managed_release':'a'*40},active=lambda:{'container':'new','image':'newimage','ingress':'forwarder','release_path':str(release)},verify=lambda x:(release,{'client_tests_receipt_sha256':'tested'}),base_id=lambda:'trustedbase')
            with patch.object(sync_registry.engine,'Engine',return_value=runtime),patch.object(sync_registry.subprocess,'check_output',return_value=json.dumps([{'Id':'edge','Image':'edgeimage','State':{'Running':True}}]).encode()):
                sync_registry.update(config,'a'*40)
            updated=json.loads(main.read_text()); self.assertEqual(updated['apk_sha256'],'installed60');self.assertEqual(updated['network_route_sha256'],'routepin');self.assertEqual(updated['network_route_file'],'externalroute');self.assertEqual([x['id'] for x in updated['containers']],['new','forwarder','edge'])
            current=json.loads(old.read_text());self.assertEqual(current['source_commit'],'a'*40);self.assertEqual(current['active_runtime']['container'],'new');self.assertEqual(len(list((root/'fingerprint-history').glob('*.json'))),1)
            before=main.read_bytes()
            with patch.object(sync_registry.engine,'Engine',return_value=runtime),self.assertRaises(sync_registry.engine.DeploymentError):sync_registry.update(config,'b'*40)
            self.assertEqual(main.read_bytes(),before)
            settings=json.loads(config.read_text());settings['control_repository_private']=False;config.write_text(json.dumps(settings))
            with patch.object(sync_registry.engine,'Engine',return_value=runtime),patch.object(sync_registry.subprocess,'check_output',return_value=json.dumps([{'Id':'edge','Image':'edgeimage','State':{'Running':True}}]).encode()):
                sync_registry.update(config,'a'*40)
            self.assertFalse(json.loads(old.read_text())['deployment_pipeline']['control_repository_private'])
            settings['control_repository_private']='false';config.write_text(json.dumps(settings))
            with patch.object(sync_registry.engine,'Engine') as factory,self.assertRaises(sync_registry.engine.DeploymentError):
                sync_registry.update(config,'a'*40)
            factory.assert_not_called()

if __name__=='__main__':unittest.main()
