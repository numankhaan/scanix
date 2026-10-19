#!/usr/bin/env python3
"""Event-aware ranges: all PR commits, all push commits, complete new-branch delta."""
import os
import re
import subprocess
import sys


def main():
    event, base, head = (os.environ.get(x, '') for x in ('EVENT', 'BASE', 'HEAD'))
    if event not in ('push', 'pull_request'):
        print('No incremental event range; full-tree and history checks follow')
        return 0
    ref = os.environ.get('GIT_REF', '')
    if event == 'push' and ref.startswith('refs/tags/'):
        subprocess.run(['git', 'check-ref-format', ref], check=True, capture_output=True)
        head = subprocess.check_output(['git', 'rev-parse', '--verify', ref], text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}', head):
        raise ValueError()
    if event == 'push' and (not base or set(base) == {'0'}):
        default = os.environ['DEFAULT_BRANCH']
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', default) or default.startswith('-'):
            raise ValueError()
        base = 'refs/remotes/origin/' + default
    elif not re.fullmatch('[0-9a-f]{40}', base):
        raise ValueError()
    # Fetch-depth=0 is required; missing old/base objects fail, never become a clean scan.
    for ref in (base, head):
        subprocess.run(['git', 'cat-file', '-e', ref+'^{commit}'], check=True, capture_output=True)
    return subprocess.run([sys.executable, 'security/check.py', 'range', '--base', base, '--head', head]).returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, subprocess.CalledProcessError):
        print('commit range unavailable/invalid; security check failed', file=sys.stderr)
        sys.exit(2)
