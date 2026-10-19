#!/usr/bin/env python3
"""Full-tree checks. Scanner stdout/stderr and raw reports remain private."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from check import safe_path

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    try:
        return subprocess.run(command, cwd=ROOT, capture_output=True, timeout=600, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('scanner unavailable or timed out') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('check', choices=('bandit', 'dependencies', 'workflows', 'rust'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='scanix-static-') as temporary:
        folder = Path(temporary)
        if args.check == 'bandit':
            report = folder/'bandit.json'
            proc = run(['bandit', '-r', 'scanix', '-x', 'scanix/tests', '-f', 'json', '-o', str(report)])
            if proc.returncode not in (0, 1) or not report.is_file():
                raise RuntimeError('Bandit failed')
            data = json.loads(report.read_text())
            if data.get('errors'):
                raise RuntimeError('Bandit could not parse source')
            # Fail medium/high findings. Low findings are also reported for manual triage.
            findings = data.get('results', [])
            for item in findings:
                print(json.dumps({'rule': item['test_id'], 'severity': item['issue_severity'],
                                  'file': safe_path(item['filename']), 'line': item['line_number']}))
            print('Bandit: findings=' + str(len(findings)))
            return int(any(x['issue_severity'] in ('MEDIUM', 'HIGH') for x in findings))
        if args.check == 'dependencies':
            # Fully pinned runtime requirement; Scapy has no runtime dependencies.
            # --disable-pip avoids requirement resolution/build execution.
            all_issues = []
            audits = [('runtime', ['-r', 'requirements.txt', '--disable-pip', '--no-deps']),
                      ('tool environment', ['--local'])]
            for label, options in audits:
                report = folder/('audit-' + label.replace(' ', '-') + '.json')
                proc = run(['pip-audit', *options, '--format=json', '--output', str(report)])
                if proc.returncode not in (0, 1) or not report.is_file():
                    raise RuntimeError('dependency scanner failed')
                data = json.loads(report.read_text())
                if any(x.get('skip_reason') for x in data['dependencies']):
                    raise RuntimeError('dependency coverage incomplete')
                issues = [(x['name'], v['id']) for x in data['dependencies'] for v in x.get('vulns', [])]
                for package, advisory in issues:
                    print(json.dumps({'package': package, 'advisory': advisory}))
                print('pip-audit: ' + label + ' advisories=' + str(len(issues)))
                all_issues.extend(issues)
            return int(bool(all_issues))
        if args.check == 'workflows':
            proc = run(['actionlint', '-oneline'])
            # Never echo scanner source snippets or untrusted YAML expressions.
            print('actionlint: ' + ('passed' if proc.returncode == 0 else 'failed; inspect privately'))
            if proc.returncode:
                return 1
            policy = run([sys.executable, 'security/workflow_policy.py'])
            print(policy.stdout.decode() if policy.returncode in (0, 1) else 'workflow policy scanner failed')
            return policy.returncode
        locks = list(ROOT.rglob('Cargo.lock'))
        locks = [p for p in locks if 'target' not in p.parts and '.git' not in p.parts]
        if not locks:
            print('Rust: no Cargo.lock in this tree; no Rust audit performed')
            return 0
        for lock in locks:
            proc = run(['cargo', 'audit', '--file', str(lock), '--json'])
            if proc.returncode not in (0, 1):
                raise RuntimeError('cargo audit failed')
            data = json.loads(proc.stdout)
            if 'vulnerabilities' not in data:
                raise RuntimeError('invalid cargo audit result')
            issues = data['vulnerabilities'].get('list', [])
            warnings = data.get('warnings', {})
            for item in issues:
                print(json.dumps({'advisory': item['advisory']['id']}))
            print('cargo audit: advisories=' + str(len(issues)) + ', warnings=' + str(sum(len(x) for x in warnings.values())))
            if issues or warnings or proc.returncode:
                return 1
            for command in [['cargo', 'fmt', '--check'], ['cargo', 'clippy', '--locked', '--all-targets', '--', '-D', 'warnings']]:
                lint = subprocess.run(command, cwd=lock.parent, capture_output=True, timeout=600)
                if lint.returncode:
                    print('Rust formatting/static checks failed; inspect privately')
                    return 1
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.TimeoutExpired):
        print('security check failed to run; no clean result', file=sys.stderr)
        sys.exit(2)
