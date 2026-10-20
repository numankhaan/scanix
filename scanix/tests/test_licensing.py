"""License packaging failures must not silently become a clean policy result."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from validation.licensing import ROOT, validate, license_files
from validation.package_smoke import wheel_inventory


class LicensingTests(unittest.TestCase):
    def copy_source(self, folder):
        root=Path(folder)
        names=license_files() | {'native/LICENSE','native/Cargo.toml','native/Cargo.lock',
                                 'pyproject.toml','third_party/licenses.json','requirements.txt','validation/requirements.txt'}
        for name in names:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,path)
        return root

    def test_missing_tampered_or_incomplete_material_fails(self):
        for change in ('missing_notice','tampered_notice','metadata','dependency','license','incompatible','unicode_omitted','python_dependency'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as folder:
                root=self.copy_source(folder)
                manifest=json.loads((root/'third_party/licenses.json').read_text())
                notice=root/manifest['crates'][0]['files'][0]['path']
                if change=='missing_notice':notice.unlink()
                if change=='tampered_notice':notice.write_bytes(b'synthetic replacement')
                if change=='metadata':
                    file=root/'native/Cargo.toml';file.write_text(file.read_text().replace('GPL-2.0-only','GPL-2.0-or-later'))
                if change=='dependency':
                    manifest['crates'].pop();(root/'third_party/licenses.json').write_text(json.dumps(manifest))
                if change=='incompatible':
                    manifest['crates'][0]['declared']='Apache-2.0'
                    (root/'third_party/licenses.json').write_text(json.dumps(manifest))
                if change=='unicode_omitted':
                    next(x for x in manifest['crates'] if x['name']=='unicode-ident')['files'].pop()
                    (root/'third_party/licenses.json').write_text(json.dumps(manifest))
                if change=='license':(root/'LICENSE').write_bytes(b'GPL version 2, synthetic incomplete text')
                if change=='python_dependency':(root/'requirements.txt').write_text('synthetic-unreviewed==1\n')
                with self.assertRaises(ValueError):validate(root)

    def test_wheel_legal_files_are_explicit_without_weakening_artifact_rejections(self):
        files=license_files()
        approved='scanix-1.dist-info/licenses/LICENSE'
        self.assertEqual(wheel_inventory([approved],files),set())
        for name in ('scanix-1.dist-info/licenses/private.key',
                     'scanix-1.dist-info/licenses/../../LICENSE',
                     'scanix-1.dist-info/licenses/unreviewed.txt',
                     'scanix/openssl.dll'):
            with self.subTest(name=name),self.assertRaises(ValueError):wheel_inventory([name],files)

    def test_complete_code_license_and_independent_data_terms(self):
        data=validate()
        self.assertEqual(data['project_license'],'GPL-2.0-only')
        self.assertEqual(data['distribution_license'],'GPL-2.0-only AND CC0-1.0')
        for name in ('probes-v1.json','os-fingerprints-v1.json'):
            self.assertEqual(json.loads((ROOT/'scanix/data'/name).read_text())['license'],'CC0-1.0')
