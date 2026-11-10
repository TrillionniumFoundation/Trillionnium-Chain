#!/usr/bin/env python3
"""Execute and independently validate the fixed QROM continuation test roster.

This checks completion of named tests, not any cryptographic theorem. CI also
checks the entire tracked source before and after this runner. A zero exit code
without the complete, matching named observation is never accepted.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
import traceback
import unittest

ROSTER = 'config/pon/w1-qrom-closure-current-required-tests-v2.json'
MODULES = (
    'test_w1_lifetime_current_observation',
    'test_w1_qrom_composition_budget',
    'test_w1_qrom_joint_oracle_diagnostic',
    'test_w1_qrom_semantics_audit',
    'test_w1_zkr_artifact_audit',
    'test_w1_zkr_control_id_audit',
    'test_w1_qrom_closure_current_controls',
)
QUALIFICATION = {
    'post_quantum_soundness_qualified': False,
    'complete_w1_soundness_qualified': False,
    'quantum_work_qualified': False,
    'pq_signature_qualification_inferred': False,
    'production_qualified': False,
    'consensus_admission': False,
    'unconditional_project_security_bits': None,
}


def require(value, message):
    if not value:
        raise ValueError(message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('nonfinite JSON number')

    require(len(raw) <= 2 * 1024 * 1024, 'observation size bound')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def same_scope(value):
    return (type(value) is dict and set(value) == set(QUALIFICATION)
            and all(value[k] is v for k, v in QUALIFICATION.items()))


def load_roster(root, expected_digest):
    require(re.fullmatch('[0-9a-f]{64}', expected_digest) is not None,
            'noncanonical expected roster digest')
    raw = (root / ROSTER).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_digest, 'roster digest changed')
    value = strict_json(raw)
    require(type(value) is dict and set(value) == {'schema', 'suites', 'expected_tests', 'qualification'},
            'roster fields differ')
    require(value['schema'] == 'TRNM-W1-QROM-CLOSURE-CURRENT-REQUIRED-TESTS2'
            and same_scope(value['qualification']), 'roster schema or scope differs')
    require(type(value['suites']) is list and len(value['suites']) == len(MODULES), 'suite roster differs')
    names = []
    for row, module in zip(value['suites'], MODULES):
        require(type(row) is dict and set(row) == {'module', 'tests'} and row['module'] == module,
                'fixed suite order differs')
        ids = row['tests']
        require(type(ids) is list and bool(ids)
                and all(type(name) is str and re.fullmatch(
                    re.escape(module) + r'\.[A-Za-z_]\w*\.test_[A-Za-z_]\w*', name) for name in ids),
                'invalid required named test')
        require(sorted(set(ids)) == ids, 'required IDs must be unique and sorted')
        names.extend(ids)
    require(type(value['expected_tests']) is int and value['expected_tests'] == len(names)
            and len(set(names)) == len(names), 'required test total differs')
    return value


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids = []
        self.success_ids = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.success_ids.append(test.id())
        super().addSuccess(test)


def validate(value, roster, expected_digest):
    require(type(value) is dict and set(value) == {
        'schema', 'roster_sha256', 'required_tests', 'suites', 'qualification'}, 'completion fields differ')
    require(value['schema'] == 'TRNM-W1-QROM-CLOSURE-CURRENT-CONTROLS2'
            and value['roster_sha256'] == expected_digest and same_scope(value['qualification']),
            'completion identity or scope differs')
    require(type(value['required_tests']) is int
            and value['required_tests'] == roster['expected_tests'], 'completion total differs')
    require(type(value['suites']) is list and len(value['suites']) == len(roster['suites']),
            'completion suite count differs')
    for row, expected in zip(value['suites'], roster['suites']):
        require(type(row) is dict and set(row) == {
            'module', 'registered_ids', 'started_ids', 'success_ids', 'tests_run',
            'loader_errors', 'failures', 'errors', 'skipped', 'expected_failures',
            'unexpected_successes', 'exception'}, 'completion suite fields differ')
        require(row['module'] == expected['module'], 'completion suite order differs')
        for key in ('registered_ids', 'started_ids', 'success_ids'):
            require(type(row[key]) is list and all(type(x) is str for x in row[key])
                    and Counter(row[key]) == Counter(expected['tests']),
                    'required named completion differs: ' + key)
        require(type(row['tests_run']) is int and row['tests_run'] == len(expected['tests']),
                'executed test count differs')
        for key in ('loader_errors', 'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'):
            require(type(row[key]) is list and not row[key], 'unsuccessful named test: ' + key)
        require(row['exception'] is None, 'suite raised an exception')


def run(root, output, expected_digest):
    roster = load_roster(root, expected_digest)
    require(output.is_dir(), 'reserve the output directory before running')
    completion = output / 'named-controls.json'
    require(not completion.exists(), 'refusing to replace completion evidence')
    records = []
    for required in roster['suites']:
        record = {key: [] for key in ('registered_ids', 'started_ids', 'success_ids',
                  'loader_errors', 'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')}
        record.update(module=required['module'], tests_run=0, exception=None)
        try:
            loader = unittest.TestLoader()
            suite = loader.discover(str(root / 'scripts/ci'), pattern=required['module'] + '.py')
            record['registered_ids'] = [test.id() for test in flatten(suite)]
            record['loader_errors'] = list(loader.errors)
            require(not loader.errors and Counter(record['registered_ids']) == Counter(required['tests']),
                    'actual complete suite differs from required named IDs')
            result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, descriptions=False,
                                            resultclass=ObservedResult).run(suite)
            record.update(tests_run=result.testsRun, started_ids=result.started_ids,
                          success_ids=result.success_ids,
                          failures=[(test.id(), message) for test, message in result.failures],
                          errors=[(test.id(), message) for test, message in result.errors],
                          skipped=[(test.id(), reason) for test, reason in result.skipped],
                          expected_failures=[(test.id(), message) for test, message in result.expectedFailures],
                          unexpected_successes=[test.id() for test in result.unexpectedSuccesses])
        except (Exception, SystemExit) as error:
            record['exception'] = type(error).__name__ + ': ' + str(error)
            traceback.print_exc()
        records.append(record)
    value = {'schema': 'TRNM-W1-QROM-CLOSURE-CURRENT-CONTROLS2', 'roster_sha256': expected_digest,
             'required_tests': roster['expected_tests'], 'suites': records,
             'qualification': dict(QUALIFICATION)}
    with completion.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    validate(value, roster, expected_digest)
    return value


def check(root, output, expected_digest):
    roster = load_roster(root, expected_digest)
    value = strict_json((output / 'named-controls.json').read_bytes())
    validate(value, roster, expected_digest)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['run', 'check'])
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--roster-sha256', required=True)
    args = parser.parse_args()
    try:
        value = {'run': run, 'check': check}[args.mode](args.root, args.output, args.roster_sha256)
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as error:
        print('Current QROM closure controls refused: ' + str(error), file=sys.stderr)
        return 2
    print(json.dumps({'required_tests': value['required_tests'], 'named_completion_validated': True,
                      'qualification': QUALIFICATION}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
