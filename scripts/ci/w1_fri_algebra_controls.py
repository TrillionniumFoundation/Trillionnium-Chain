#!/usr/bin/env python3
"""Require named algebra controls to execute, then check their completion.

This runner records implementation tests, not cryptographic proof obligations.
The workflow separately binds all tracked bytes to the exact Git source.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
ROSTER = 'evidence/pon-w1-fri-algebra-20261108/required-tests.json'
ROSTER_SHA256 = '656cc0c0e6dcacd725435cc6bb996e0035fb378dd99de3c4887bed634d8ec483'
MODULES = ('test_w1_fri_algebra_replay', 'test_w1_fri_algebra_controls',
           'test_w1_fri_algebra_report_check', 'test_w1_fri_algebra_review_compare')
SCHEMA = 'TRNM-W1-FRI-ALGEBRA-CONTROLS1'
QUALIFICATION = {
    'complete_w1_soundness_qualified': False,
    'post_quantum_soundness_qualified': False,
    'quantum_work_qualified': False,
    'production_qualified': False,
    'unconditional_project_security_bits': None,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    with path.open('rb') as stream:
        raw = stream.read(512 * 1024 + 1)
    require(len(raw) <= 512 * 1024, 'oversized control record')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate JSON key')
            value[key] = item
        return value

    def invalid(value):
        raise ValueError('nonintegral JSON number: ' + value)

    return raw, json.loads(raw, object_pairs_hook=unique, parse_float=invalid,
                           parse_constant=invalid)


def roster(root):
    raw, value = read_json(root / ROSTER)
    require(hashlib.sha256(raw).hexdigest() == ROSTER_SHA256, 'reviewed roster identity')
    require(type(value) is dict and set(value) == {'schema', 'suites'}
            and value['schema'] == 'TRNM-W1-FRI-ALGEBRA-TESTS1', 'roster schema')
    rows = value['suites']
    require(type(rows) is list and tuple(row['module'] for row in rows) == MODULES,
            'roster modules')
    for row in rows:
        require(set(row) == {'module', 'tests'} and type(row['tests']) is list
                and bool(row['tests']), 'empty or malformed test roster')
        names = row['tests']
        require(all(type(name) is str and name.startswith(row['module'] + '.')
                    for name in names) and names == sorted(set(names)),
                'invalid, unsorted or duplicate test identities')
    return rows


def source_hashes(root):
    paths = ['scripts/w1_fri_algebra_replay.py',
             'scripts/ci/w1_fri_algebra_controls.py',
             'scripts/ci/w1_fri_algebra_report_check.py']
    paths += ['scripts/ci/' + name + '.py' for name in MODULES]
    return {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths}


def validate(value, required, hashes):
    require(type(value) is dict and set(value) == {
        'schema', 'roster_sha256', 'source_sha256', 'suites', 'qualification'},
        'completion fields')
    require(value['schema'] == SCHEMA and value['roster_sha256'] == ROSTER_SHA256,
            'completion identity')
    flags = value['qualification']
    require(type(flags) is dict and set(flags) == set(QUALIFICATION)
            and all(flags[key] is expected for key, expected in QUALIFICATION.items()),
            'qualification changed or mistyped')
    require(value['source_sha256'] == hashes, 'tested source changed')
    require(type(value['suites']) is list and len(value['suites']) == len(required),
            'missing suite completion')
    count = 0
    for row, expected in zip(value['suites'], required):
        require(type(row) is dict and set(row) == {
            'module', 'registered', 'started', 'successful', 'tests_run',
            'skipped', 'failures', 'errors', 'expected_failures',
            'unexpected_successes', 'exception'}, 'suite completion fields')
        require(row['module'] == expected['module'] and row['exception'] is None,
                'suite did not complete')
        names = expected['tests']
        require(type(row['tests_run']) is int and row['tests_run'] == len(names),
                'test count')
        for field in ('registered', 'started', 'successful'):
            require(type(row[field]) is list and Counter(row[field]) == Counter(names),
                    'missing or duplicate test identity: ' + field)
        for field in ('skipped', 'failures', 'errors', 'expected_failures', 'unexpected_successes'):
            require(row[field] == [], 'unsuccessful test: ' + field)
        count += len(names)
    return {'result': 'PASS', 'actual_successful_tests': count,
            'roster_sha256': ROSTER_SHA256, 'qualification': dict(QUALIFICATION)}


def check(root, out):
    _, value = read_json(out / 'named-controls.json')
    return validate(value, roster(root), source_hashes(root))


def run(root, out):
    required = roster(root)
    hashes = source_hashes(root)
    out.mkdir(parents=True, exist_ok=True)
    target = out / 'named-controls.json'
    require(not target.exists(), 'refusing to overwrite prior completion')
    sys.path.insert(0, str(root / 'scripts/ci'))
    sys.path.insert(0, str(root / 'scripts'))

    def flatten(suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from flatten(test)
            else:
                yield test

    class Observed(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.started, self.successful = [], []

        def startTest(self, test):
            self.started.append(test.id())
            super().startTest(test)

        def addSuccess(self, test):
            self.successful.append(test.id())
            super().addSuccess(test)

    records = []
    for expected in required:
        row = {'module': expected['module'], 'registered': [], 'started': [],
               'successful': [], 'tests_run': 0, 'skipped': [], 'failures': [],
               'errors': [], 'expected_failures': [], 'unexpected_successes': [],
               'exception': None}
        try:
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromName(expected['module'])
            row['registered'] = [test.id() for test in flatten(suite)]
            require(not loader.errors and Counter(row['registered']) == Counter(expected['tests']),
                    'loaded module differs from reviewed roster')
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2,
                                            resultclass=Observed).run(suite)
            row.update(tests_run=result.testsRun, started=result.started,
                       successful=result.successful)
            for key, values in (('skipped', result.skipped), ('failures', result.failures),
                                ('errors', result.errors), ('expected_failures', result.expectedFailures)):
                row[key] = [[test.id(), reason] for test, reason in values]
            row['unexpected_successes'] = [test.id() for test in result.unexpectedSuccesses]
        except (Exception, SystemExit) as error:
            row['exception'] = type(error).__name__ + ': ' + str(error)
        records.append(row)
    value = {'schema': SCHEMA, 'roster_sha256': ROSTER_SHA256,
             'source_sha256': hashes, 'suites': records,
             'qualification': dict(QUALIFICATION)}
    with target.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    return check(root, out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('run', 'check'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = (run if args.mode == 'run' else check)(ROOT, args.output)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('algebra controls refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
