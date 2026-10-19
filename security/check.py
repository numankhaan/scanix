#!/usr/bin/env python3
"""Fail-closed, value-free secret/privacy gate. Raw reports never leave private temp files."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

TOOL_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip())
MAX_BYTES = 16 * 1024 * 1024
RUN_KEY = os.urandom(32)
RULES = {
    'home-path': r'(?:/Users/|/home/|[A-Za-z]:\\Users\\)[A-Za-z0-9][A-Za-z0-9_.-]*',
    'email-review': r'(?<![A-Za-z0-9_.+%-])[A-Za-z0-9_.+%-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}',
    'authenticated-url': r'https?://[^\s/<>\x22\x27]+@[^\s/<>\x22\x27]+',
    'phone-review': r'(?i)(?:phone|mobile|telephone)\s*[:=]\s*\+?[0-9][0-9 ()-]{7,}[0-9]',
}


class ScanError(Exception):
    pass


def git(*args):
    result = subprocess.run(['git', *args], cwd=ROOT, capture_output=True)
    if result.returncode:
        raise ScanError('git operation failed; no clean result')
    return result.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path):
    if path in ('(commit metadata/message)', '(prospective author)', '(prospective committer)'):
        return path
    # Paths themselves can disclose personal information or terminal controls.
    if re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', path) and not any(re.search(p, path) for p in RULES.values()):
        return path
    return 'path-fingerprint:' + hmac.new(RUN_KEY, path.encode(), hashlib.sha256).hexdigest()[:16]


def privacy(data, path, ref='tree', metadata=False):
    text = data.decode('utf-8', errors='replace')
    findings = []
    patterns = dict(RULES)
    private = os.environ.get('SCANIX_PRIVATE_PATTERNS')
    if private:
        try:
            extras = json.loads(Path(private).read_text())
            if not isinstance(extras, dict) or len(extras) > 32:
                raise ValueError()
            for key, pattern in extras.items():
                if not re.fullmatch(r'[a-z0-9-]{1,40}', key) or not isinstance(pattern, str) or len(pattern) > 512:
                    raise ValueError()
                patterns['private-' + key] = pattern
        except (OSError, ValueError, TypeError):
            raise ScanError('private pattern configuration invalid') from None
    for category, pattern in patterns.items():
        try:
            matches = re.finditer(pattern, text)
            for match in matches:
                value = match[0]
                if category == 'email-review':
                    domain = value.rsplit('@', 1)[-1].lower()
                    if domain == 'users.noreply.github.com' or value.lower() == 'noreply@github.com':
                        continue
                    # Reserved fixture/document domains are not personal identities.
                    if not metadata and (domain in ('example.com', 'example.org', 'example.net') or domain.endswith(('.invalid', '.test', '.example'))):
                        continue
                findings.append({'category': category, 'severity': 'medium', 'file': safe_path(path),
                                 'line': text.count('\n', 0, match.start()) + 1,
                                 'ref': ref, 'fingerprint': hmac.new(RUN_KEY, value.encode(), hashlib.sha256).hexdigest()[:16]})
        except re.error:
            raise ScanError('invalid detection pattern') from None
    return findings


def exceptions():
    return {item['file']: item['sha256'] for item in json.loads((TOOL_ROOT / 'security/synthetic-keys.json').read_text())}


def fixture_ok(path, data, rule='private-key'):
    return rule == 'private-key' and exceptions().get(path) == digest(data)


def file_findings(path, data, ref):
    result = privacy(data, path, ref)
    name = Path(path).name.lower()
    forbidden = (path.startswith('.security-private/') or '.env' in Path(path).parts or name == '.env' or name.startswith('.env.') or
                 name in ('.netrc', '.pypirc', '.npmrc', 'cookies.txt', 'credentials.json', 'terraform.tfstate') or
                 Path(path).suffix.lower() in ('.key', '.p12', '.pfx', '.pcap', '.pcapng', '.har', '.sqlite', '.sqlite3', '.db', '.log', '.pyc', '.pdf', '.docx', '.odt', '.xlsx', '.pptx') or
                 name in ('scan_results.json', 'scan_results.csv', 'scan_results.html'))
    report = False
    if data.lstrip().startswith(b'{'):
        try:
            value = json.loads(data)
            report = isinstance(value, dict) and (
                {'configuration', 'results', 'completion_status'} <= value.keys() or
                {'hosts', 'scope', 'completion_status'} <= value.keys())
        except (ValueError, RecursionError):
            # This is a narrow shape detector, not a claim to validate all JSON.
            report = False
    header = data.split(b'\n', 1)[0]
    report = report or (header.startswith(b'record_type,') and b'resolved_ip' in header)
    report = report or (data.lstrip().lower().startswith(b'<!doctype html') and
                        b'&quot;configuration&quot;' in data and b'<th>resolved_ip</th>' in data)
    if report:
        result.append({'category': 'scan-report-review', 'severity': 'review',
                       'file': safe_path(path), 'ref': ref, 'line': 1})
    if (forbidden or b'\0' in data) and not fixture_ok(path, data):
        result.append({'category': 'forbidden-file-review', 'severity': 'review', 'file': safe_path(path), 'ref': ref, 'line': 1})
    return result


def bounded_blob(oid):
    if int(git('cat-file', '-s', oid)) > MAX_BYTES:
        raise ScanError('object exceeds scan limit; coverage incomplete')
    return git('cat-file', 'blob', oid)


def commits(base, head):
    args = ['rev-list', head]
    if base:
        args += ['--not', base]
    return git(*args).decode().splitlines()


def inspect(mode, base=None, head='HEAD'):
    findings, blobs = [], {}
    if mode in ('tree', 'staged'):
        for entry in git('ls-files', '--stage', '-z').split(b'\0'):
            if not entry:
                continue
            info, raw_path = entry.split(b'\t', 1)
            filemode, oid, stage = info.split()
            path = raw_path.decode('utf-8', errors='replace')
            if stage != b'0' or filemode == b'160000':
                raise ScanError('unmerged index or submodule requires separate review')
            if mode == 'tree':
                source = ROOT / path
                if source.is_symlink():
                    data = os.readlink(source).encode()
                elif source.exists():
                    with source.open('rb') as stream:
                        data = stream.read(MAX_BYTES + 1)
                else:
                    continue
                if len(data) > MAX_BYTES:
                    raise ScanError('file exceeds scan limit; coverage incomplete')
            else:
                data = bounded_blob(oid.decode())
            findings.extend(file_findings(path, data, mode))
            blobs[path] = data
        if mode == 'staged':
            findings.extend(privacy(git('var', 'GIT_AUTHOR_IDENT'), '(prospective author)', metadata=True))
            findings.extend(privacy(git('var', 'GIT_COMMITTER_IDENT'), '(prospective committer)', metadata=True))
        return findings, blobs
    revisions = git('rev-list', '--all').decode().splitlines() if mode == 'history' else commits(base, head)
    seen = set()
    for revision in revisions:
        meta = git('show', '-s', '--format=%an%n%ae%n%cn%n%ce%n%B', revision)
        findings.extend(privacy(meta, '(commit metadata/message)', revision, metadata=True))
        blobs['commit-metadata/' + revision + '.txt'] = meta
        # Full snapshots catch merge resolutions and renamed/copied material, not only added lines.
        for entry in git('ls-tree', '-rz', revision).split(b'\0'):
            if not entry:
                continue
            info, raw_path = entry.split(b'\t', 1)
            filemode, kind, oid = info.split()
            if kind != b'blob':
                raise ScanError('submodule not scanned')
            path = raw_path.decode('utf-8', errors='replace')
            key = (path, oid)
            if key in seen:
                continue
            seen.add(key)
            data = bounded_blob(oid.decode())
            # Range mode compares inherited objects against the base, while still
            # inspecting every changed blob in intermediate outgoing commits.
            inherited = False
            if base:
                lookup = subprocess.run(['git', 'rev-parse', f'{base}:{path}'], cwd=ROOT, capture_output=True)
                inherited = lookup.returncode == 0 and lookup.stdout.strip() == oid
            if not inherited:
                findings.extend(file_findings(path, data, revision))
    return findings, blobs


def leak_scan(mode, base=None, head='HEAD', blobs=None):
    with tempfile.TemporaryDirectory(prefix='scanix-gate-') as temporary:
        folder = Path(temporary)
        report = folder / 'report.json'
        ignore = folder / 'empty-ignore'
        ignore.write_text('')
        command = ['gitleaks', '--redact=100', '--no-banner', '--ignore-gitleaks-allow',
                   '--exit-code=42', '--config=' + str(TOOL_ROOT/'security/gitleaks.toml'),
                   '--gitleaks-ignore-path=' + str(ignore), '--report-format=json', '--report-path=' + str(report),
                   '--max-decode-depth=2', '--max-archive-depth=2']
        if mode in ('tree', 'staged'):
            content = folder / 'content'
            content.mkdir()
            for path, data in blobs.items():
                dest = content / path
                if not dest.resolve().is_relative_to(content.resolve()):
                    raise ScanError('unsafe repository path')
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
            command += ['dir', str(content)]
        else:
            options = '--all' if mode == 'history' else head + (' ^' + base if base else '')
            command += ['git', '--log-opts=' + options + ' --full-history --diff-merges=first-parent', str(ROOT)]
        try:
            proc = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=600)
        except (OSError, subprocess.TimeoutExpired):
            raise ScanError('secret scanner unavailable or timed out') from None
        if proc.returncode not in (0, 42) or not report.is_file():
            raise ScanError('secret scanner failed; no clean result')
        try:
            results = json.loads(report.read_text())
        except (OSError, ValueError):
            raise ScanError('invalid secret scanner report') from None
        findings = []
        for item in results:
            path = item['File']
            if mode in ('tree', 'staged'):
                try:
                    path = str(Path(path).relative_to(content)) if Path(path).is_absolute() else path
                except ValueError:
                    raise ScanError('unexpected secret scanner path') from None
                data = blobs.get(path, b'')
            else:
                data = git('show', item['Commit'] + ':' + path)
            if not fixture_ok(path, data, item['RuleID']):
                findings.append({'category': 'secret-' + item['RuleID'], 'severity': 'high', 'file': safe_path(path),
                                 'line': item['StartLine'], 'ref': item.get('Commit', mode) or mode})
        return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('tree', 'staged', 'range', 'history', 'pre-push'))
    parser.add_argument('--base')
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--secrets-only', action='store_true')
    parser.add_argument('--privacy-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        if git('rev-parse', '--is-shallow-repository').strip() == b'true':
            raise ScanError('shallow repository: fetch full history first')
        ranges = [(args.mode, args.base, args.head)]
        if args.mode == 'pre-push':
            ranges = []
            for line in sys.stdin:
                fields = line.split()
                if len(fields) != 4 or not all(re.fullmatch('[0-9a-f]{40,64}', fields[i]) for i in (1, 3)):
                    raise ScanError('invalid push input')
                _, local, _, remote = fields
                if set(local) == {'0'}:
                    continue
                # Compare a new branch to the fetched default branch, scanning every
                # branch commit. Full-history audits remain a separate obligation.
                base = remote
                if set(remote) == {'0'}:
                    base = git('symbolic-ref', 'refs/remotes/origin/HEAD').decode().strip()
                    git('rev-parse', '--verify', base)
                ranges.append(('range', base, local))
        findings = []
        for mode, base, head in ranges:
            found, blobs = inspect(mode, base, head)
            if not args.secrets_only:
                findings += found
            if not args.privacy_only:
                findings += leak_scan(mode, base, head, blobs)
                if mode not in ('tree', 'staged') and blobs:
                    findings += leak_scan('tree', blobs=blobs)
        # No raw matches, author identities, messages, snippets, or scanner stderr.
        for finding in findings:
            print(json.dumps(finding, sort_keys=True))
        print(f'security gate: {len(findings)} unapproved findings')
        return 1 if findings else 0
    except (ScanError, OSError, ValueError, KeyError, TypeError, RecursionError):
        print('security gate: scanner/configuration failure; review privately', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('security gate interrupted; no clean result', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
