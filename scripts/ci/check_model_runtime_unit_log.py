#!/usr/bin/env python3
"""Require the complete fixed small-unit roster; no135M qualification."""
import argparse
import ast
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SUITES = {
    'setup': ('scripts/test_llm_initial_trainable_setup_v2.py', 'ActualInitialSetupTests', 13),
    'observer': ('scripts/test_llm_runtime_candidate_observation_v1.py', 'CandidateObservationTests', 9),
}


def expected_names(suite, root=ROOT):
    path, class_name, count = SUITES[suite]
    classes = [n for n in ast.parse((root / path).read_text()).body
               if isinstance(n, ast.ClassDef) and n.name == class_name]
    if len(classes) != 1:
        raise ValueError('one original unit class required')
    names = [n.name for n in classes[0].body
             if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
    if len(names) != count or len(set(names)) != count:
        raise ValueError('fixed complete unit inventory changed')
    return [f'__main__.{class_name}.{name}' for name in names]


def validate(path, suite, root=ROOT):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024**2:
        raise ValueError('bounded regular unit log required')
    with path.open('rb') as stream:
        raw = stream.read(8 * 1024**2 + 1)
    if len(raw) > 8 * 1024**2:
        raise ValueError('bounded unit log exceeded during read')
    text = raw.decode('utf-8')
    expected = expected_names(suite, root)
    rows = re.findall(r'^(test_[A-Za-z0-9_]+) \((__main__\.[A-Za-z0-9_]+\.test_[A-Za-z0-9_]+)\) \.\.\. (.+)$', text, re.M)
    if (len(rows) != len(expected) or {row[1] for row in rows} != set(expected)
            or any(name != identity.rsplit('.', 1)[1] or outcome != 'ok'
                   for name, identity, outcome in rows)):
        raise ValueError('every exact unit test must pass once with zero skips')
    summaries = re.findall(r'^Ran ([0-9]+) tests in [^\n]+s$', text, re.M)
    if (summaries != [str(len(expected))]
            or re.findall(r'^OK(?:[^\n]*)$', text, re.M) != ['OK']
            or not text.rstrip().endswith('\nOK')
            or re.search(r'^(?:FAILED|ERROR:|FAIL:)', text, re.M)):
        raise ValueError('one successful exact unit summary required')
    return {'scope': 'small unit controls, not pretrained-model qualification',
            'suite': suite, 'executed_tests': len(expected), 'skipped_tests': 0,
            'test_names': expected, 'result': 'PASS'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=tuple(SUITES), required=True)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.log, args.suite), sort_keys=True))
