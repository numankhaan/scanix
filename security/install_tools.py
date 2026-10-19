#!/usr/bin/env python3
"""Install pinned Linux CI scanners using release-asset SHA256 digests verified via GitHub."""
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import urllib.request

TOOLS = {
    'gitleaks': ('https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz',
                 '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
    'actionlint': ('https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz',
                   '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8'),
}


def main():
    destination = Path(sys.argv[1])
    destination.mkdir(parents=True, exist_ok=True)
    for name, (url, expected) in TOOLS.items():
        with urllib.request.urlopen(url, timeout=60) as stream:
            data = stream.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('scanner download verification failed')
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.getmember(name)
            if not member.isfile() or member.size > 64 * 1024 * 1024:
                raise ValueError('invalid scanner archive')
            # Only a named regular file; no archive path extraction or links.
            with archive.extractfile(member) as source:
                binary = source.read()
        target = destination/name
        target.write_bytes(binary)
        target.chmod(0o755)
    print('pinned scanner installation verified')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('scanner installation failed; no clean result', file=sys.stderr)
        sys.exit(2)
