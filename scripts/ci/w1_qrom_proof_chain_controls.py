#!/usr/bin/env python3
"""Run a pinned roster of arithmetic/replay controls; never a proof certificate.

The checker is a separate invocation: an early zero exit without a completed
record cannot pass. Skips and expected failures are not successful controls.
Full Git/source identity is checked independently by the hosted workflow.
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
ROSTER = 'evidence/pon-w1-qrom-proof-chain-20261108/required-tests.json'
ROSTER_SHA256 = '54dceecf6a8fb6d5f91252cbb79427ba92563663c2e8248cf61a10ecb581911c'
MODULES = (
    'test_w1_query_expression_feasibility',
    'test_w1_fri_query_replay',
    'test_w1_qrom_composition_budget',
    'test_w1_qrom_conditional_budget',
    'test_w1_qrom_bcs_budget',
    'test_w1_qrom_proof_chain_controls',
)
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
    require(len(raw) <= 512 * 1024, 'record exceeds size limit')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('nonintegral JSON number: ' + value)

    return raw, json.loads(raw, object_pairs_hook=unique,
                           parse_float=invalid, parse_constant=invalid)


def roster(root):
    raw, value = read_json(root / ROSTER)
    require(hashlib.sha256(raw).hexdigest() == ROSTER_SHA256, 'roster pin mismatch')
    require(type(value) is dict and set(value) == {'schema', 'suites'}, 'roster fields')
    require(value['schema'] == 'TRNM-W1-QROM-PROOF-CHAIN-TESTS1', 'roster schema')
    require(type(value['suites']) is list
            and tuple(row['module'] for row in value['suites']) == MODULES, 'roster modules')
    for row in value['suites']:
        require(set(row) == {'module', 'tests'} and type(row['tests']) is list
                and bool(row['tests']), 'empty or malformed required test list')
        names = row['tests']
        require(all(type(name) is str and name.startswith(row['module'] + '.')
                    for name in names), 'test identity outside module')
        require(names == sorted(set(names)), 'duplicate/unsorted required names')
    return value['suites']


def validate(value, required, hashes):
    require(type(value) is dict and set(value) == {
        'schema', 'roster_sha256', 'test_source_sha256', 'suites', 'qualification'},
        'completion fields')
    require(value['schema'] == 'TRNM-W1-QROM-PROOF-CHAIN-CONTROLS1'
            and value['roster_sha256'] == ROSTER_SHA256, 'completion identity')
    require(value['qualification'] == QUALIFICATION, 'unsupported qualification')
    # Use identity, not loose equality: Python considers 0 == False.
    require(all(value['qualification'][key] is expected
                for key, expected in QUALIFICATION.items()), 'qualification types')
    require(value['test_source_sha256'] == hashes, 'test source changed')
    require(type(value['suites']) is list and len(value['suites']) == len(required),
            'incomplete suite records')
    count = 0
    for row, expected in zip(value['suites'], required):
        require(set(row) == {'module', 'registered', 'started', 'successful',
                            'tests_run', 'skipped', 'failures', 'errors',
                            'expected_failures', 'unexpected_successes', 'exception'},
                'suite fields')
        require(row['module'] == expected['module'] and row['exception'] is None,
                'suite failed to complete')
        names = expected['tests']
        require(type(row['tests_run']) is int and row['tests_run'] == len(names),
                'test count mismatch')
        for key in ('registered', 'started', 'successful'):
            require(type(row[key]) is list and Counter(row[key]) == Counter(names),
                    'missing/duplicate actual test: ' + key)
        for key in ('skipped', 'failures', 'errors', 'expected_failures', 'unexpected_successes'):
            require(row[key] == [], 'unsuccessful control: ' + key)
        count += len(names)
    return {'result': 'PASS', 'actual_successful_tests': count,
            'qualification': dict(QUALIFICATION)}


def source_hashes(root):
    return {name: hashlib.sha256((root / 'scripts/ci' / (name + '.py')).read_bytes()).hexdigest()
            for name in MODULES}


def check(root, out):
    required = roster(root)
    _, value = read_json(out / 'named-controls.json')
    return validate(value, required, source_hashes(root))


def run(root, out):
    required = roster(root)
    out.mkdir(parents=True, exist_ok=True)
    target = out / 'named-controls.json'
    require(not target.exists(), 'refusing to overwrite completion record')
    initial_hashes = source_hashes(root)
    sys.path.insert(0, str(root / 'scripts/ci'))
    sys.path.insert(0, str(root / 'scripts'))

    def flatten(suite):
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                yield from flatten(item)
            else:
                yield item

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
    for item in required:
        row = {'module': item['module'], 'registered': [], 'started': [], 'successful': [],
               'tests_run': 0, 'skipped': [], 'failures': [], 'errors': [],
               'expected_failures': [], 'unexpected_successes': [], 'exception': None}
        try:
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromName(item['module'])
            row['registered'] = [test.id() for test in flatten(suite)]
            require(not loader.errors and Counter(row['registered']) == Counter(item['tests']),
                    'loaded module differs from pinned roster')
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
    value = {'schema': 'TRNM-W1-QROM-PROOF-CHAIN-CONTROLS1',
             'roster_sha256': ROSTER_SHA256, 'test_source_sha256': initial_hashes,
             'suites': records, 'qualification': dict(QUALIFICATION)}
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
        print('proof-chain controls refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
