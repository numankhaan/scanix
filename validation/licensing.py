"""Bounded license/notices integrity and locked primary crate archive checks."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
EXPRESSION = 'GPL-2.0-only AND CC0-1.0'


def read(root, name, limit=65536):
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError('license material must be a regular file')
    path.resolve().relative_to(root.resolve())
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('license material exceeds limit')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate(root=ROOT, *, cached=False):
    root = Path(root)
    manifest = json.loads(read(root, 'third_party/licenses.json', 131072))
    if manifest['schema_version'] != 1 or manifest['project_code_license'] != 'GPL-2.0-only' or manifest['python_distribution_license'] != EXPRESSION:
        raise ValueError('unsupported license policy')
    policies = manifest['policy_files']
    if set(policies) != {'pyproject.toml','requirements.txt','validation/requirements.txt'}:
        raise ValueError('incomplete Python dependency policy')
    for name, digest in policies.items():
        if sha(read(root, name)) != digest:
            raise ValueError('Python metadata/dependency change requires license review')
    gpl = read(root, 'LICENSE')
    if sha(gpl) != manifest['project_license_sha256'] or gpl != read(root, 'native/LICENSE'):
        raise ValueError('GPL text missing or changed')
    if not all(x in gpl for x in (b'Version 2, June 1991', b'NO WARRANTY', b'END OF TERMS AND CONDITIONS', b'How to Apply These Terms')):
        raise ValueError('incomplete GPL text')
    for filename, expected in (('pyproject.toml', EXPRESSION), ('native/Cargo.toml', 'GPL-2.0-only')):
        values = re.findall(r'^license = "([^"]+)"$', read(root, filename).decode(), re.M)
        if values != [expected]:
            raise ValueError('project license metadata differs from policy')
    lock = read(root, 'native/Cargo.lock', 1048576)
    if sha(lock) != manifest['cargo_lock_sha256']:
        raise ValueError('dependency change requires a new license review')
    locked = {}
    # Cargo-generated lock format only. Cargo itself validates full TOML in native CI.
    for block in lock.decode().split('[[package]]')[1:]:
        fields = {}
        for key in ('name', 'version', 'checksum'):
            values = re.findall(r'^' + key + r' = "([^"]+)"$', block, re.M)
            if len(values) > 1:
                raise ValueError('duplicate lock identity')
            fields[key] = values[0] if values else None
        if fields['name'] != 'scanix-engine':
            if not all(fields.values()):
                raise ValueError('unreviewed dependency source')
            key = (fields['name'], fields['version'])
            if key in locked:
                raise ValueError('duplicate dependency identity')
            locked[key] = fields['checksum']
    crates = manifest['crates']
    if not 1 <= len(crates) <= 128 or len({(x['name'], x['version']) for x in crates}) != len(crates):
        raise ValueError('invalid crate license inventory')
    if {(x['name'], x['version']): x['archive_sha256'] for x in crates} != locked:
        raise ValueError('missing or unreviewed locked dependency')
    notices = manifest['notice_files']
    if not 1 <= len(notices) <= 128:
        raise ValueError('notice count exceeds limits')
    for name, digest in notices.items():
        path = PurePosixPath(name)
        if path.parent != PurePosixPath('third_party/licenses') or path.suffix not in ('.txt', '.html'):
            raise ValueError('unapproved notice path')
        if sha(read(root, name)) != digest:
            raise ValueError('notice content changed')
    for crate in crates:
        expected = 'MIT AND Unicode-3.0' if crate['name'] == 'unicode-ident' else 'MIT'
        declarations = {'MIT','MIT OR Apache-2.0','Apache-2.0 OR MIT','Unlicense OR MIT',
                        'Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT'}
        if crate['name'] == 'unicode-ident':
            declarations = {'(MIT OR Apache-2.0) AND Unicode-3.0'}
        if crate['selected'] != expected or crate['declared'] not in declarations:
            raise ValueError('unapproved dependency license selection')
        paths = {x['upstream_path'] for x in crate['files']}
        if (crate['name'] == 'unicode-ident' and (len(crate['files']) != 2 or paths != {'LICENSE-MIT','LICENSE-UNICODE'}) or
                crate['name'] != 'unicode-ident' and (len(crate['files']) != 1 or
                not paths <= {'LICENSE','LICENSE-MIT','license-mit'})):
            raise ValueError('incomplete selected license coverage')
        for item in crate['files']:
            if notices.get(item['path']) != item['sha256']:
                raise ValueError('dependency notice missing')
    if cached:
        proc = subprocess.run(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1',
                               '--manifest-path', str(root/'native/Cargo.toml')],
                              capture_output=True, timeout=60)
        if proc.returncode or len(proc.stdout) > 4 * 1024 * 1024:
            raise ValueError('cached dependency metadata unavailable')
        packages = [x for x in json.loads(proc.stdout)['packages'] if x['name'] != 'scanix-engine']
        if {(x['name'], x['version']) for x in packages} != set(locked):
            raise ValueError('resolved dependencies differ from inventory')
        for package in packages:
            entry = next(x for x in crates if (x['name'],x['version']) == (package['name'],package['version']))
            if package['license'] != entry['declared']:
                raise ValueError('upstream license declaration changed')
            base = Path(package['manifest_path']).parent
            archive = base.parents[2]/'cache'/base.parent.name/(package['name']+'-'+package['version']+'.crate')
            if sha(read(archive.parent, archive.name, 16*1024*1024)) != entry['archive_sha256']:
                raise ValueError('primary crate archive checksum mismatch')
            with tarfile.open(archive, 'r:gz') as source:
                for item in entry['files']:
                    member = source.getmember(package['name']+'-'+package['version']+'/'+item['upstream_path'])
                    if not member.isfile() or member.size > 65536:
                        raise ValueError('invalid upstream license member')
                    if sha(source.extractfile(member).read(65537)) != item['sha256']:
                        raise ValueError('notices differ from published primary source')
    read(root, 'THIRD_PARTY_NOTICES.md')
    return {'project_license':'GPL-2.0-only','distribution_license':EXPRESSION,
            'locked_crates':len(crates),'notice_files':len(notices),'primary_archives_checked':cached}


def license_files(root=ROOT):
    validate(root)
    manifest = json.loads(read(root, 'third_party/licenses.json', 131072))
    return {'LICENSE','THIRD_PARTY_NOTICES.md',*manifest['notice_files']}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cached',action='store_true',help='also verify actual locked Cargo archives; no network')
    args=parser.parse_args()
    try:
        print(json.dumps(validate(cached=args.cached),sort_keys=True))
    except Exception as exc:
        print('License validation failed: '+type(exc).__name__+'; no clean result',file=sys.stderr)
        raise SystemExit(1)
