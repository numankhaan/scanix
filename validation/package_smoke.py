"""Private local sdist/wheel, installation and reinstall checks. Never uploads artifacts."""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.parser import BytesParser
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import threading
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def wheel_inventory(names, license_files=()):
    """Only runtime Python/registry data and ordinary wheel metadata are permitted."""
    runtime = set()
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '\\' in name:
            raise ValueError('unsafe wheel member')
        if len(path.parts) < 2 or any(x in ('tests', '__pycache__') for x in path.parts):
            raise ValueError('unexpected wheel member')
        if path.parts[0] == 'scanix':
            if path.suffix != '.py' and not (path.parent == PurePosixPath('scanix/data') and path.suffix == '.json'):
                raise ValueError('unexpected runtime artifact')
            runtime.add(name)
        elif path.parts[0].endswith('.dist-info'):
            legal = len(path.parts) >= 3 and path.parts[1] == 'licenses' and '/'.join(path.parts[2:]) in license_files
            if not legal and (len(path.parts) != 2 or path.name not in ('METADATA','WHEEL','RECORD','entry_points.txt','top_level.txt')):
                raise ValueError('unexpected distribution metadata')
        else:
            raise ValueError('unexpected wheel package')
    return runtime


def execute(command, *, cwd, timeout=180):
    # Build/install tools may include local paths or metadata in diagnostics.
    # Keep raw output private in memory; CI emits only fixed failure categories.
    env = dict(os.environ, PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
               PIP_NO_INDEX='1', PIP_DISABLE_PIP_VERSION_CHECK='1')
    env.pop('PYTHONPATH', None)
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('local package validation subprocess failed')
    return result.stdout


class Handler(BaseHTTPRequestHandler):
    server_version = 'SyntheticPackage/1'
    sys_version = ''

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def run():
    from scanix import __version__
    from validation.licensing import license_files, EXPRESSION
    legal_files = license_files()
    with tempfile.TemporaryDirectory(prefix='scanix-package-') as folder:
        private = Path(folder); artifacts = private / 'artifacts'
        execute([sys.executable, '-B', '-m', 'build', '--no-isolation', '--outdir', str(artifacts), str(ROOT)], cwd=private)
        wheels = list(artifacts.glob('*.whl')); sources = list(artifacts.glob('*.tar.gz'))
        if len(wheels) != 1 or len(sources) != 1:
            raise ValueError('missing or ambiguous distribution')
        with zipfile.ZipFile(wheels[0]) as archive:
            names = archive.namelist(); runtime = wheel_inventory(names, legal_files)
            if len(names) != len(set(names)):
                raise ValueError('duplicate wheel members')
            expected = {p.relative_to(ROOT).as_posix() for p in (ROOT/'scanix').rglob('*.py')
                        if 'tests' not in p.relative_to(ROOT/'scanix').parts}
            expected.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'scanix/data').glob('*.json'))
            if runtime != expected:
                raise ValueError('installed runtime/database inventory differs from source')
            metadata_name = next(n for n in names if n.endswith('.dist-info/METADATA'))
            metadata = BytesParser().parsebytes(archive.read(metadata_name))
            if metadata['Version'] != __version__:
                raise ValueError('distribution metadata/package version mismatch')
            if metadata['License-Expression'] != EXPRESSION or set(metadata.get_all('License-File', [])) != legal_files:
                raise ValueError('wheel license metadata is incomplete')
            prefix = metadata_name.rsplit('/', 1)[0] + '/licenses/'
            for filename in legal_files:
                if archive.read(prefix+filename) != (ROOT/filename).read_bytes():
                    raise ValueError('wheel license/notice content differs from source')
        with tarfile.open(sources[0], 'r:gz') as archive:
            members = archive.getnames()
            prefix = members[0].split('/')[0]+'/'
            for filename in legal_files | {'native/LICENSE', 'third_party/licenses.json', 'validation/requirements.txt',
                                           'validation/licensing.py', 'validation/package_smoke.py', 'CHANGELOG.md'}:
                if archive.extractfile(prefix+filename).read() != (ROOT/filename).read_bytes():
                    raise ValueError('corresponding source license/build files missing or changed')
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if (path.is_absolute() or '..' in path.parts or member.issym() or member.islnk() or
                        'tests' in path.parts or path.suffix in ('.key','.pem','.pyc','.pcap','.sqlite','.ndjson')):
                    raise ValueError('unexpected source distribution artifact')
        environment = private/'installed'
        venv.EnvBuilder(with_pip=True).create(environment)
        binary = environment/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
        entry = environment/('Scripts/scanix.exe' if os.name=='nt' else 'bin/scanix')
        install = [str(binary), '-I', '-m', 'pip', 'install', '--no-index', '--no-deps', str(wheels[0])]
        execute(install, cwd=private)
        version = execute([str(entry), '--version'], cwd=private).decode().strip()
        if version != 'Scanix '+__version__:
            raise ValueError('installed CLI/package version mismatch')
        # Import from the installed wheel with isolated sys.path, outside checkout.
        smoke = '''from scanix.service.registry import load_registry
from scanix.core.os_fingerprint import database
from scanix.plugins.registry import PLUGINS
assert load_registry().version == '1.0.0'
assert database()['database_version'] == '1.0.0'
assert len(PLUGINS) == 4
'''
        execute([str(binary), '-I', '-B', '-c', smoke], cwd=private)
        preview = execute([str(binary), '-I', '-B', '-m', 'scanix', 'scan', '-t', '::1', '--family', '6',
                           '-p', '8080', '--plugins', 'http', '--preview'], cwd=private)
        if not preview:
            raise ValueError('installed preview produced no result')
        with ExitStack() as stack:
            server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            stack.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            stack.callback(thread.join, 2); stack.callback(server.shutdown)
            data = execute([str(binary), '-I', '-B', '-m', 'scanix', 'scan', '-t', '127.0.0.1', '-p',
                            str(server.server_port), '--plugins', 'http', '--history', str(private/'history.sqlite'),
                            '--out', 'json', '--out-file', '-'], cwd=private)
            report = json.loads(data)
            if (report['incomplete'] or len(report['results']) != 1 or report['results'][0]['state'] != 'open' or
                    report['results'][0]['plugin_results'][0]['status'] != 'complete'):
                raise ValueError('installed loopback scan/plugin/history failed')
        before = execute([str(entry), 'history', '--db', str(private/'history.sqlite'), 'list'], cwd=private)
        execute(install+['--force-reinstall'], cwd=private)
        after = execute([str(entry), 'history', '--db', str(private/'history.sqlite'), 'list'], cwd=private)
        if not before or before != after:
            raise ValueError('reinstall changed persisted history')
        return {'version': __version__, 'runtime_members': len(runtime),
                'checks': ['sdist_to_wheel','license_metadata_notices_and_source','inventory_no_keys_tests_or_captures','isolated_install',
                           'cli_version','bundled_databases','ipv6_preview','ipv4_loopback_plugin_history',
                           'same_candidate_reinstall_history_preserved'],
                'limitations': 'No prior published wheel exists; not a cross-version upgrade or native binary installation test.'}


if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as exc:
        print('Package validation failed: '+type(exc).__name__+'; raw output withheld', file=sys.stderr)
        raise SystemExit(1)
