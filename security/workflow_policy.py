#!/usr/bin/env python3
"""Repository-specific workflow trust policy; actionlint handles syntax/types."""
from pathlib import Path
import re
import sys
import yaml


def validate(data, filename):
    errors = []
    if not isinstance(data, dict):
        return ['invalid-document']
    events = data.get('on', data.get(True, {}))
    if isinstance(events, str):
        events = [events]
    if 'pull_request_target' in (events or {}):
        errors.append('untrusted-event-boundary')
    permissions = data.get('permissions')
    if permissions != {'contents': 'read'}:
        errors.append('workflow-permissions')
    for job in data.get('jobs', {}).values():
        permissions = job.get('permissions', {'contents': 'read'})
        allowed = ({'contents': 'read'}, {'contents': 'read', 'security-events': 'write'}) if filename == 'codeql.yml' else ({'contents': 'read'},)
        if permissions not in allowed:
            errors.append('job-permissions')
        for step in job.get('steps', []):
            uses = step.get('uses', '')
            if uses and not uses.startswith('./') and not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}', uses):
                errors.append('mutable-action-reference')
            if uses.startswith('actions/checkout@') and step.get('with', {}).get('persist-credentials') is not False:
                errors.append('persisted-checkout-credentials')
            if '/analyze@' in uses and uses.startswith('github/codeql-action/'):
                if step.get('with', {}).get('upload') != 'never' or step.get('with', {}).get('upload-database') is not False:
                    errors.append('automatic-codeql-data-upload')
            if '/init@' in uses and uses.startswith('github/codeql-action/') and step.get('with', {}).get('debug', False) is not False:
                errors.append('codeql-debug-artifact')
            if uses.startswith('actions/upload-artifact@'):
                errors.append('unreviewed-artifact-upload')
            if '/upload-sarif@' in uses and step.get('with', {}).get('sarif_file') != '${{ runner.temp }}/codeql-redacted':
                errors.append('unredacted-sarif-upload')
            if '${{' in str(step.get('run', '')):
                errors.append('inline-shell-context-expression')
            if '${{ secrets.' in str(step):
                errors.append('explicit-secret-access')
    return sorted(set(errors))


def main():
    errors = []
    for path in sorted(Path('.github/workflows').glob('*.y*ml')):
        data = yaml.safe_load(path.read_text())
        for category in validate(data, path.name):
            # Category only: filenames/YAML may themselves be malicious/private.
            print('workflow policy: ' + category)
            errors.append(category)
    print('workflow policy: ' + str(len(errors)) + ' failures')
    return int(bool(errors))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('workflow policy failed to parse/run; no clean result', file=sys.stderr)
        sys.exit(2)
