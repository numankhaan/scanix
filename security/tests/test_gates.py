"""Synthetic inputs only. Assertions deliberately never print rejected sample values."""
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'security'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load('check')
sarif = load('redact_sarif')
workflow = load('workflow_policy')


class PrivacyTests(unittest.TestCase):
    def test_patterns_and_public_fixture_identity(self):
        sample = '/Users/' + 'synthetic-user/private.txt\ncontact: ' + 'person' + '@personal.test'
        findings = check.privacy(sample.encode(), 'sample.txt')
        self.assertTrue(any(x['category'] == 'home-path' for x in findings))
        self.assertTrue(sample not in json.dumps(findings), 'raw sample exposed')
        self.assertEqual(check.privacy(b'dev@example.invalid', 'fixture'), [])
        self.assertEqual(check.privacy(b'noreply@github.com', '(metadata)', metadata=True), [])
        self.assertEqual(check.privacy(b'127.0.0.1 ::1 192.0.2.1', 'fixture'), [])
        self.assertTrue(bool(check.privacy(b'dev@personal.test', '(metadata)', metadata=True)))

    def test_external_patterns_and_value_free_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary)/'patterns.json'
            config.write_text(json.dumps({'internal-label': 'synthetic-private-label'}))
            with patch.dict(os.environ, {'SCANIX_PRIVATE_PATTERNS': str(config)}):
                found = check.privacy(b'synthetic-private-label', 'plain.txt')
                self.assertEqual(len(found), 1)
                self.assertTrue('synthetic-private-label' not in json.dumps(found))
        self.assertTrue(check.safe_path('person'+'@private.test.txt').startswith('path-fingerprint:'))

    def test_windows_paths_phone_and_authenticated_url(self):
        samples = [('home-path', 'C:' + chr(92) + 'Users' + chr(92) + 'synthetic-user'),
                   ('phone-review', 'phone: ' + '+1 202 555 0100'),
                   ('authenticated-url', 'https://' + 'synthetic-user:synthetic-pass' + '@example.invalid')]
        for category, sample in samples:
            found = check.privacy(sample.encode(), 'fixture.txt')
            self.assertTrue(any(item['category'] == category for item in found))
            self.assertTrue(sample not in json.dumps(found), 'sample leaked')

    def test_long_untrusted_text_has_bounded_email_matching(self):
        code = "import runpy; m=runpy.run_path(" + repr(str(ROOT/'security/check.py')) + "); assert not m['privacy'](b'A'*1000000, 'synthetic.txt')"
        try:
            proc = subprocess.run(['python3', '-c', code], capture_output=True, timeout=10)
        except subprocess.TimeoutExpired:
            self.fail('privacy scan exceeded bounded input test deadline')
        self.assertEqual(proc.returncode, 0, 'long-text privacy scan failed')

    def test_privacy_in_filename_is_blocked_without_printing_it(self):
        path = 'nested/Users/' + 'synthetic-user/source.py'
        found = check.file_findings(path, b'pass', 'tree')
        self.assertTrue(any(x['category'] == 'home-path' for x in found))
        self.assertTrue(path not in json.dumps(found), 'private path appeared in output')

    def test_reports_detected_independently_of_filename(self):
        payload = json.dumps({'configuration': {}, 'results': [], 'completion_status': 'complete'}).encode()
        self.assertTrue(any(x['category'] == 'scan-report-review' for x in check.file_findings('arbitrary.json', payload, 'tree')))
        csv = b'record_type,target,resolved_ip,port\nresult,localhost,127.0.0.1,22\n'
        self.assertTrue(any(x['category'] == 'scan-report-review' for x in check.file_findings('arbitrary.csv', csv, 'tree')))
        html = b'<!doctype html><pre>&quot;configuration&quot;: {}</pre><th>resolved_ip</th>'
        self.assertTrue(any(x['category'] == 'scan-report-review' for x in check.file_findings('arbitrary.html', html, 'tree')))
        for name in ('deployment.env', '.envrc', '.git-credentials'):
            self.assertTrue(any(x['category'] == 'forbidden-file-review' for x in check.file_findings(name, b'SYNTHETIC=true', 'tree')))
        self.assertEqual(check.file_findings('database.json', b'{"schema_version":1,"probes":[]}', 'tree'), [])

    def test_continuation_artifacts_are_blocked_even_when_stream_is_renamed(self):
        for suffix in ('ndjson','sqlite-journal','sqlite3-wal','db-shm'):
            found=check.file_findings('synthetic.'+suffix,b'synthetic fixture','tree')
            self.assertTrue(any(x['category']=='forbidden-file-review' for x in found))
        header={'type':'header','configuration':{},'stream_version':1,'report_schema':4}
        header['synthetic_padding']='x'*65536
        payload=(json.dumps(header)+'\n'+json.dumps({'type':'result','id':0})+'\n').encode()
        self.assertTrue(any(x['category']=='scan-report-review' for x in
                            check.file_findings('renamed.txt',payload,'tree')))
        self.assertEqual(check.file_findings('safe.txt',b'{malformed}\n{}\n','tree'),[])

    def test_precise_key_exceptions(self):
        path = 'scanix/tests/fixtures/tls/ca-TEST-ONLY.key'
        data = (ROOT/path).read_bytes()
        self.assertTrue(check.fixture_ok(path, data))
        self.assertFalse(check.fixture_ok(path, data+b'changed'))
        self.assertFalse(check.fixture_ok('other.key', data))
        self.assertFalse(check.fixture_ok(path, data, 'github-pat'))

    def test_sarif_removes_source_and_messages(self):
        marker = 'synthetic-sensitive-value'
        source = {'runs': [{'tool': {'driver': {'name': marker, 'rules': [{'id': 'py/test', 'properties': {'security-severity': '8'}}]}},
                            'results': [{'ruleId': 'py/test', 'message': {'text': marker}, 'properties': {'raw': marker},
                                         'codeFlows': [{'raw': marker}], 'locations': [{'physicalLocation': {
                                             'artifactLocation': {'uri': 'scanix/cli.py'}, 'region': {'startLine': 2, 'snippet': {'text': marker}}}}]}]}]}
        cleaned, count = sarif.redact(source)
        self.assertEqual(count, 1)
        self.assertTrue(marker not in json.dumps(cleaned), 'SARIF retained sensitive sample')
        self.assertEqual(cleaned['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region'], {'startLine': 2})


class WorkflowPolicy(unittest.TestCase):
    def test_mutable_actions_permissions_and_untrusted_events(self):
        data = {'on': {'pull_request_target': {}}, 'permissions': 'write-all',
                'jobs': {'test': {'steps': [{'uses': 'actions/checkout@v4'},
                                          {'run': 'echo ${{ github.event.pull_request.title }}'}]}}}
        errors = workflow.validate(data, 'unsafe.yml')
        self.assertTrue({'mutable-action-reference', 'workflow-permissions',
                         'persisted-checkout-credentials', 'untrusted-event-boundary',
                         'inline-shell-context-expression'} <= set(errors))

    def test_pinned_read_only_workflow(self):
        data = {'on': ['push', 'pull_request'], 'permissions': {'contents': 'read'},
                'jobs': {'test': {'steps': [{'uses': 'actions/checkout@' + 'a'*40,
                                           'with': {'persist-credentials': False}}]}}}
        self.assertEqual(workflow.validate(data, 'safe.yml'), [])


class GitGates(unittest.TestCase):
    def setUp(self):
        if not shutil.which('gitleaks'):
            self.fail('gitleaks required; gate tests must not silently skip')
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Synthetic Fixture')
        self.git('config', 'user.email', 'fixture@users.noreply.github.com')
        self.write('file.txt', 'initial\n')
        self.commit('initial')
        self.base = self.git('rev-parse', 'HEAD').strip()

    def tearDown(self):
        self.folder.cleanup()

    def git(self, *args):
        result = subprocess.run(['git', *args], cwd=self.root, capture_output=True, text=True, check=True)
        return result.stdout

    def write(self, name, content):
        (self.root/name).write_text(content)
        self.git('add', name)

    def commit(self, message):
        self.git('commit', '-qm', message)

    def invoke(self, *args, input=None, env=None):
        proc = subprocess.run(['python3', str(ROOT/'security/check.py'), *args], cwd=self.root,
                              input=input, capture_output=True, text=True, env=env)
        return proc

    def test_staged_reads_index_and_never_prints_secret(self):
        token = 'ghp_' + 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4'
        self.write('sample.txt', 'token = '+token+'\n')
        (self.root/'sample.txt').write_text('clean working tree\n')
        proc = self.invoke('staged')
        self.assertTrue(token not in proc.stdout+proc.stderr, 'secret appeared in gate output')
        self.assertEqual(proc.returncode, 1)
        self.assertTrue('secret-' in proc.stdout)
        proc = self.invoke('tree')
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_intermediate_commit_and_merge_are_scanned(self):
        self.write('sample.txt', '/home/'+'synthetic-user/record\n')
        self.commit('temporary exposure')
        self.write('sample.txt', 'clean\n')
        self.commit('remove exposure')
        proc = self.invoke('range', '--base', self.base)
        self.assertEqual(proc.returncode, 1)
        self.assertTrue('home-path' in proc.stdout)
        self.assertTrue('synthetic-user' not in proc.stdout)
        self.git('checkout', '-qb', 'topic', self.base)
        self.write('other.txt', 'clean\n'); self.commit('other')
        self.git('merge', '-q', '--no-ff', 'main', '-m', 'merge history')
        self.assertEqual(self.invoke('range', '--base', self.base).returncode, 1)

    def test_secret_created_only_by_merge_resolution_is_scanned(self):
        self.git('checkout', '-qb', 'topic')
        self.write('file.txt', 'topic\n'); self.commit('topic')
        self.git('checkout', 'main')
        self.write('file.txt', 'main\n'); self.commit('main')
        base = self.git('rev-parse', 'HEAD').strip()
        result = subprocess.run(['git', 'merge', '--no-commit', 'topic'], cwd=self.root, capture_output=True)
        self.assertEqual(result.returncode, 1)
        token = 'ghp_' + 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4'
        self.write('file.txt', 'token = '+token+'\n'); self.commit('resolution')
        proc = self.invoke('range', '--base', base, '--secrets-only')
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(token not in proc.stdout+proc.stderr, 'merge sample leaked')

    def test_annotated_tag_secrets_are_scanned_without_new_commits(self):
        token = 'ghp_' + 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4'
        self.git('tag', '-a', 'synthetic-tag', '-m', 'token: '+token)
        self.git('tag', '-a', 'outer-tag', 'synthetic-tag', '-m', 'nested synthetic tag')
        for arguments in [('range', '--base', self.base, '--head', 'synthetic-tag', '--secrets-only'),
                          ('range', '--base', self.base, '--head', 'outer-tag', '--secrets-only'),
                          ('history', '--secrets-only')]:
            proc = self.invoke(*arguments)
            self.assertEqual(proc.returncode, 1)
            self.assertTrue(token not in proc.stdout+proc.stderr, 'tag message exposed')
        scripts = self.root/'security'
        scripts.mkdir()
        for name in ('check.py', 'ci_range.py', 'gitleaks.toml', 'synthetic-keys.json'):
            shutil.copyfile(ROOT/'security'/name, scripts/name)
        self.git('update-ref', 'refs/remotes/origin/main', self.base)
        env = dict(os.environ, EVENT='push', BASE='0'*40, HEAD=self.base,
                   DEFAULT_BRANCH='main', GIT_REF='refs/tags/outer-tag')
        proc = subprocess.run(['python3', 'security/ci_range.py'], cwd=self.root, env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(token not in proc.stdout+proc.stderr, 'CI tag message exposed')

    def test_historical_binary_secret_is_not_hidden_by_git_patch_output(self):
        token = 'ghp_' + 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4'
        (self.root/'synthetic.bin').write_bytes(b'\0token = '+token.encode()+b'\n')
        self.git('add', 'synthetic.bin'); self.commit('binary fixture')
        proc = self.invoke('history', '--secrets-only')
        self.assertEqual(proc.returncode, 1)
        self.assertTrue('secret-github-pat' in proc.stdout)
        self.assertTrue('blob:' in proc.stdout)
        self.assertTrue(token not in proc.stdout+proc.stderr, 'binary sample exposed')

    def test_metadata_and_commit_messages_are_scanned(self):
        self.git('config', 'user.email', 'synthetic'+'@personal.invalid')
        self.write('file.txt', 'changed\n'); self.commit('ordinary change')
        proc = self.invoke('range', '--base', self.base)
        self.assertEqual(proc.returncode, 1)
        self.assertTrue('email-review' in proc.stdout)
        self.assertTrue('personal.invalid' not in proc.stdout)
        self.git('config', 'user.email', 'fixture@users.noreply.github.com')
        token = 'ghp_' + 'Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4'
        self.write('file.txt', 'changed again\n'); self.commit('token: '+token)
        proc = self.invoke('range', '--base', self.git('rev-parse', 'HEAD^').strip(), '--secrets-only')
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(token not in proc.stdout+proc.stderr, 'commit message exposed')

    def test_new_branch_multiple_push_updates_and_deletion(self):
        self.git('update-ref', 'refs/remotes/origin/main', self.base)
        self.git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main')
        self.write('scope.log', 'synthetic local report\n'); self.commit('report')
        head = self.git('rev-parse', 'HEAD').strip(); zero = '0'*40
        proc = self.invoke('pre-push', input=f'refs/heads/topic {head} refs/heads/topic {zero}\n')
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.invoke('pre-push', input=f'(delete) {zero} refs/heads/topic {head}\n').returncode, 0)
        proc = self.invoke('pre-push', input=f'refs/heads/topic {head} refs/heads/topic {self.base}\n')
        self.assertEqual(proc.returncode, 1)

    def test_ci_event_range_uses_base_head_and_new_branch(self):
        scripts = self.root/'security'
        scripts.mkdir()
        for name in ('check.py', 'ci_range.py', 'gitleaks.toml', 'synthetic-keys.json'):
            shutil.copyfile(ROOT/'security'/name, scripts/name)
        self.git('update-ref', 'refs/remotes/origin/main', self.base)
        self.write('scope.log', 'synthetic report\n'); self.commit('first')
        self.write('file.txt', 'second\n'); self.commit('second')
        head = self.git('rev-parse', 'HEAD').strip()
        for event, base in [('push', self.base), ('pull_request', self.base), ('push', '0'*40)]:
            env = dict(os.environ, EVENT=event, BASE=base, HEAD=head, DEFAULT_BRANCH='main')
            proc = subprocess.run(['python3', 'security/ci_range.py'], cwd=self.root, env=env, capture_output=True)
            self.assertEqual(proc.returncode, 1)
        env = dict(os.environ, EVENT='pull_request', BASE='f'*40, HEAD=head, DEFAULT_BRANCH='main')
        proc = subprocess.run(['python3', 'security/ci_range.py'], cwd=self.root, env=env, capture_output=True)
        self.assertEqual(proc.returncode, 2)

    def test_missing_scanner_and_shallow_clone_fail_closed(self):
        # Keep Python/Git available but remove scanner; no scanner error text is emitted.
        with tempfile.TemporaryDirectory() as temporary:
            for tool in ('python3', 'git'):
                os.symlink(shutil.which(tool), Path(temporary)/tool)
            proc = self.invoke('tree', env=dict(os.environ, PATH=temporary))
            self.assertEqual(proc.returncode, 2)
            self.assertTrue('failure' in proc.stderr)
        with tempfile.TemporaryDirectory() as outside:
            proc = subprocess.run(['python3', str(ROOT/'security/check.py'), 'tree'], cwd=outside, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2)
            self.assertTrue(outside not in proc.stderr, 'Git error disclosed a local path')
        shallow = self.root/'shallow'
        subprocess.run(['git', 'clone', '-q', '--depth=1', self.root.as_uri(), str(shallow)], capture_output=True, check=True)
        proc = subprocess.run(['python3', str(ROOT/'security/check.py'), 'tree'], cwd=shallow, capture_output=True)
        self.assertEqual(proc.returncode, 2)


if __name__ == '__main__':
    unittest.main()
