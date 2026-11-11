#!/usr/bin/env python3
"""Run and verify the separate fixed W1 historical/current control rosters.

An exit status alone is not completion: every registered, started and successful
test ID must match the reviewed roster exactly, with no skipped controls. These
local execution records do not confer proof or quantum security qualification.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

from pq_source_reader import read_regular

ROOT = Path(__file__).resolve().parents[2]
ROSTER = 'config/pon/w1-qrom-supplemental-tests-v1.json'
ROSTER_SHA256 = '33bdae599edc3ef8f54efd84245d24b90b0b4effdb2f71b2cdae52a71d4001c4'
RETAINED_ROSTER = 'supplemental-required-tests.json'
SUITES = (
    ('historical', 'test_w1_qrom_historical_fixture', 8),
    ('current', 'test_w1_qrom_current_implementation_audit', 14),
)
OUTPUTS = {'historical': 'historical-controls.json', 'current': 'current-controls.json'}
QUALIFICATION = {
    'post_quantum_soundness_qualified': False, 'complete_w1_soundness_qualified': False,
    'quantum_work_qualified': False, 'pq_signature_qualification_inferred': False,
    'production_qualified': False, 'consensus_admission': False, 'security_bits_quantum': None,
}
EMPTY_FIELDS = ('loader_errors', 'skipped', 'failures', 'errors',
                'expected_failures', 'unexpected_successes')
ID_FIELDS = ('expected_ids', 'registered_ids', 'started_ids', 'success_ids')
RECEIPT_FIELDS = {
    'schema', 'roster_sha256', 'suite', 'module', 'required_tests', 'tests_run',
    'all_named_controls_passed', 'qualification', 'exception', *EMPTY_FIELDS, *ID_FIELDS,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def refuse_constant(value):
        raise ValueError('nonfinite JSON number: ' + value)

    return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=refuse_constant)


def unqualified(value):
    return (type(value) is dict and set(value) == set(QUALIFICATION)
            and all(value[key] is expected for key, expected in QUALIFICATION.items()))


def load_roster(root):
    raw = read_regular(Path(root), ROSTER, 65536)
    require(hashlib.sha256(raw).hexdigest() == ROSTER_SHA256,
            'supplemental roster differs from its reviewed pin')
    manifest = strict_json(raw)
    require(type(manifest) is dict and set(manifest) == {
                'schema', 'scope', 'expected_tests', 'suites', 'qualification'}
            and manifest['schema'] == 'TRNM-W1-QROM-SUPPLEMENTAL-TESTS1'
            and type(manifest['expected_tests']) is int and manifest['expected_tests'] == 22
            and type(manifest['suites']) is list and len(manifest['suites']) == len(SUITES)
            and unqualified(manifest['qualification']), 'supplemental roster schema or scope')
    all_names = []
    for row, (suite, module, count) in zip(manifest['suites'], SUITES):
        require(type(row) is dict and set(row) == {'suite', 'module', 'expected_tests', 'tests'}
                and row['suite'] == suite and row['module'] == module
                and type(row['expected_tests']) is int and row['expected_tests'] == count
                and type(row['tests']) is list and len(row['tests']) == count,
                'supplemental suite identity or count')
        names = row['tests']
        require(all(type(name) is str and re.fullmatch(
                    re.escape(module) + r'\.[A-Za-z_][A-Za-z0-9_]*\.test_[A-Za-z0-9_]+', name)
                    for name in names)
                and len(set(names)) == count and names == sorted(names),
                'supplemental names are missing, duplicated or invalid')
        all_names.extend(names)
    require(len(set(all_names)) == manifest['expected_tests'], 'supplemental total differs')
    return manifest, raw


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


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


def validate_receipt(report, row):
    require(type(report) is dict and set(report) == RECEIPT_FIELDS
            and report['schema'] == 'TRNM-W1-QROM-SUPPLEMENTAL-CONTROL-OBSERVATION1'
            and report['roster_sha256'] == ROSTER_SHA256
            and report['suite'] == row['suite'] and report['module'] == row['module']
            and type(report['required_tests']) is int
            and report['required_tests'] == row['expected_tests']
            and type(report['tests_run']) is int and report['tests_run'] == row['expected_tests']
            and report['all_named_controls_passed'] is True
            and report['exception'] is None and unqualified(report['qualification']),
            'supplemental completion identity, count or scope differs')
    for field in ID_FIELDS:
        actual = report[field]
        require(type(actual) is list and all(type(name) is str for name in actual)
                and Counter(actual) == Counter(row['tests']),
                'supplemental completion lost exact identities: ' + field)
    for field in EMPTY_FIELDS:
        require(type(report[field]) is list and not report[field],
                'supplemental completion retained a non-success outcome: ' + field)


def run_suite(root, selected, stream=None):
    manifest, _ = load_roster(root)
    row = next(row for row in manifest['suites'] if row['suite'] == selected)
    report = {
        'schema': 'TRNM-W1-QROM-SUPPLEMENTAL-CONTROL-OBSERVATION1',
        'roster_sha256': ROSTER_SHA256, 'suite': selected, 'module': row['module'],
        'required_tests': row['expected_tests'], 'tests_run': 0,
        'expected_ids': row['tests'], 'registered_ids': [], 'started_ids': [], 'success_ids': [],
        **{field: [] for field in EMPTY_FIELDS},
        'all_named_controls_passed': False, 'qualification': dict(QUALIFICATION), 'exception': None,
    }
    try:
        loader = unittest.TestLoader()
        suite = loader.discover(str(Path(root) / 'scripts/ci'), pattern=row['module'] + '.py')
        report['registered_ids'] = [test.id() for test in flatten(suite)]
        report['loader_errors'] = list(loader.errors)
        require(not loader.errors and Counter(report['registered_ids']) == Counter(row['tests']),
                'complete module registry differs from the supplemental named roster')
        result = unittest.TextTestRunner(stream=stream if stream is not None else sys.stderr,
            verbosity=2, descriptions=False, resultclass=ObservedResult).run(suite)
        report.update({
            'tests_run': result.testsRun, 'started_ids': result.started_ids,
            'success_ids': result.success_ids,
            'skipped': [(test.id(), reason) for test, reason in result.skipped],
            'failures': [(test.id(), reason) for test, reason in result.failures],
            'errors': [(test.id(), reason) for test, reason in result.errors],
            'expected_failures': [(test.id(), reason) for test, reason in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
            'all_named_controls_passed': True,
        })
        validate_receipt(report, row)
    except (Exception, SystemExit) as error:
        report['all_named_controls_passed'] = False
        report['exception'] = type(error).__name__ + ': ' + str(error)
    return report


def verify_completions(root, output):
    manifest, raw = load_roster(root)
    output = Path(output)
    require(read_regular(output, RETAINED_ROSTER, 65536) == raw,
            'retained supplemental roster differs from the reviewed checkout')
    digests = {}
    for row in manifest['suites']:
        observed = read_regular(output, OUTPUTS[row['suite']], 256 * 1024)
        validate_receipt(strict_json(observed), row)
        digests[row['suite']] = hashlib.sha256(observed).hexdigest()
    return digests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--suite', choices=OUTPUTS, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.output_dir.is_dir() and not args.output_dir.is_symlink(),
                'existing regular output directory required')
        target = args.output_dir / OUTPUTS[args.suite]
        require(not target.exists() and not target.is_symlink(),
                'existing supplemental observation will not be replaced')
        _, raw = load_roster(args.repo_root)
        retained = args.output_dir / RETAINED_ROSTER
        if retained.exists() or retained.is_symlink():
            require(read_regular(args.output_dir, RETAINED_ROSTER, 65536) == raw,
                    'retained supplemental roster differs')
        else:
            with retained.open('xb') as stream:
                stream.write(raw)
        report = run_suite(args.repo_root, args.suite)
        with target.open('x') as stream:
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
        require(report['all_named_controls_passed'] is True,
                'every supplemental named control must complete exactly once without skips')
        print('Supplemental ' + args.suite + ' controls completed; security remains unqualified.')
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
