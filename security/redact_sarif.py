#!/usr/bin/env python3
"""Allowlist SARIF fields. Never upload source, messages, snippets or arbitrary metadata."""
import json
from pathlib import Path
import re
import sys


def redact(source):
    output = {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': []}
    blocking = 0
    for run in source['runs']:
        rules = {rule['id']: rule for rule in run['tool']['driver'].get('rules', [])}
        results = []
        for result in run.get('results', []):
            key = result['ruleId']
            if not re.fullmatch(r'[A-Za-z0-9_./-]{1,160}', key):
                raise ValueError('unsafe rule ID')
            locations = []
            for loc in result.get('locations', []):
                physical = loc.get('physicalLocation', {})
                uri = physical.get('artifactLocation', {}).get('uri', '')
                if not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', uri) or uri.startswith('/') or '..' in uri.split('/'):
                    continue
                line = physical.get('region', {}).get('startLine', 1)
                if type(line) is not int or not 1 <= line <= 10000000:
                    raise ValueError('invalid source position')
                locations.append({'physicalLocation': {'artifactLocation': {'uri': uri}, 'region': {'startLine': line}}})
            cleaned = {'ruleId': key, 'message': {'text': 'Security finding; details withheld from public reports'},
                       'level': 'warning', 'locations': locations}
            results.append(cleaned)
            severity = float(rules.get(key, {}).get('properties', {}).get('security-severity', 10))
            blocking += severity >= 4
        output['runs'].append({'tool': {'driver': {'name': 'CodeQL', 'rules': [{'id': k} for k in sorted({x['ruleId'] for x in results})]}}, 'results': results})
    return output, blocking


def main():
    directory = Path(sys.argv[1]); destination = Path(sys.argv[2]); destination.mkdir(parents=True, exist_ok=True)
    reports = list(directory.glob('*.sarif'))
    if not reports:
        raise ValueError('no CodeQL report')
    blocking = 0
    for i, report in enumerate(reports):
        safe, count = redact(json.loads(report.read_text()))
        (destination/f'redacted-{i}.sarif').write_text(json.dumps(safe))
        blocking += count
    print('CodeQL: blocking findings=' + str(blocking) + '; uploaded details are redacted')
    return int(bool(blocking))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        print('CodeQL report redaction failed; no upload/clean result', file=sys.stderr)
        sys.exit(2)
