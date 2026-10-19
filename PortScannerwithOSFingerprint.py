#!/usr/bin/env python3
"""Compatibility launcher. OS fingerprinting is unimplemented.

Prefer python -m scanix. The old documented target/start/end form is accepted;
otherwise arguments are passed directly to the modular CLI.
"""
import sys
from scanix.cli import run_cli


def main():
    args = sys.argv[1:]
    if len(args) == 3 and all(value.isdecimal() for value in args[1:]):
        args = ['scan', '-t', args[0], '-p', f'{args[1]}-{args[2]}']
    return run_cli(args)


if __name__ == '__main__':
    raise SystemExit(main())
