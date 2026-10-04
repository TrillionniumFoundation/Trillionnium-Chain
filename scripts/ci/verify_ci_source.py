#!/usr/bin/env python3
"""Record the exact source; a PR head and its prospective merge are separate runs."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def verify(kind: str, expected_head: str, expected_base: str | None = None,
           expected_merge: str | None = None, root: Path = ROOT) -> dict:
    def git(*args: str) -> str:
        return subprocess.check_output(['git', *args], cwd=root, text=True).strip()

    for name, value in [('head', expected_head), ('base', expected_base), ('merge', expected_merge)]:
        if value is not None and re.fullmatch(r'[0-9a-f]{40}', value) is None:
            raise ValueError('noncanonical expected ' + name)
    actual = git('rev-parse', 'HEAD')
    if kind == 'head':
        if actual != expected_head or expected_base is not None or expected_merge is not None:
            raise ValueError('head identity mismatch')
    elif kind == 'prospective-merge':
        if expected_base is None or expected_merge is None or actual != expected_merge:
            raise ValueError('merge identity mismatch')
        parents = git('show', '-s', '--format=%P', 'HEAD').split()
        if parents != [expected_base, expected_head]:
            raise ValueError('merge parents differ from the event base and candidate')
    else:
        raise ValueError('unknown source kind')
    if git('status', '--porcelain'):
        raise ValueError('source is not clean')
    return {'schema': 'trnm-ci-source-v1', 'kind': kind, 'tested_commit': actual,
            'tested_tree': git('rev-parse', 'HEAD^{tree}'), 'candidate': expected_head,
            'base': expected_base, 'prospective_merge': expected_merge,
            'tests_executed_by_identity_check': False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', required=True, choices=['head', 'prospective-merge'])
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-base')
    parser.add_argument('--expected-merge')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.kind, args.expected_head, args.expected_base, args.expected_merge)
    text = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
