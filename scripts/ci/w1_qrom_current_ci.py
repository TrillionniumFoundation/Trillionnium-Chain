#!/usr/bin/env python3
"""Current-source QROM observations, with an explicit historical-pin refusal.

The historical V1 lane executes its original source and roster separately. This
runner binds the reviewed current V2 map to the actual candidate; neither lane
qualifies cryptographic soundness, quantum work, production or consensus use.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[2]
ROSTER = 'config/pon/w1-qrom-current-required-tests-v1.json'
ROSTER_SHA256 = 'e48c23d4d6737d0143798a5c93a194310ebdf7ba1a0cb87bdf3a36af65b8f581'
MODULES = ('test_w1_control_tree_audit', 'test_w1_qrom_conditional_budget',
           'test_w1_qrom_current_implementation_audit', 'test_w1_fri_transcript_audit',
           'test_w1_qrom_current_ci')
HISTORICAL_SOURCE = '0c830e0be8939ce80c8443c9ad68021b87343a00'
HISTORICAL_JOB_SHA256 = 'f88c5e041b943ea39be2de6665e9621b0b6a0c056c44dcae2a6215615eb6b130'
DRIFT_REASON = 'input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs'
FALSE_FIELDS = (
    'post_quantum_soundness_qualified', 'complete_w1_soundness_qualified',
    'quantum_work_qualified', 'pq_signature_qualification_inferred',
    'production_qualified', 'consensus_admission',
)
REQUIRED_STAGES = (
    'observations', 'checkout', 'source_before', 'preflight', 'named_tests',
    'historical_drift', 'implementation', 'source_after',
)


class ObservationError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise ObservationError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result

    def invalid(value):
        raise ObservationError('nonfinite JSON value: ' + value)

    def finite(value):
        number = float(value)
        require(math.isfinite(number), 'nonfinite JSON number')
        return number

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid, parse_float=finite)


def read_json(path):
    with path.open('rb') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    require(len(raw) <= 2 * 1024 * 1024, 'observation exceeds read bound')
    value = strict_json(raw)
    require(type(value) is dict, 'observation must be an object')
    return value, raw


def write_once(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def scope():
    return {**dict.fromkeys(FALSE_FIELDS, False), 'security_bits_quantum': None}


def load_current(root):
    path = root / 'scripts/w1_qrom_current_implementation_audit.py'
    spec = importlib.util.spec_from_file_location('_qrom_current_ci_mapping', path)
    require(spec is not None and spec.loader is not None, 'current mapping module unavailable')
    current = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(current)
    audit, contract, raw = current.load_current(root)
    return current, audit, contract, raw


def validate_historical_job(workflow):
    """Bind the untouched original gates and explicit fixed-source checkout."""
    start = '  qrom-historical-implementation:\n'
    end = '  qrom-current-implementation:\n'
    require(workflow.count(start) == workflow.count(end) == 1
            and workflow.index(start) < workflow.index(end), 'QROM source job layout differs')
    historical = workflow[workflow.index(start):workflow.index(end)]
    require(sha(historical.encode()) == HISTORICAL_JOB_SHA256,
            'historical job source, original gates or scope changed')
    return HISTORICAL_JOB_SHA256


def load_roster(root):
    raw = (root / ROSTER).read_bytes()
    require(sha(raw) == ROSTER_SHA256, 'current roster differs from reviewed pin')
    roster = strict_json(raw)
    require(type(roster) is dict and set(roster) == {
        'schema', 'expected_tests', 'suites', 'qualification'}, 'current roster fields')
    require(roster['schema'] == 'TRNM-W1-QROM-CURRENT-REQUIRED-TESTS1'
            and roster['qualification'] == scope(), 'current roster schema or scope')
    require(type(roster['suites']) is list
            and all(type(row) is dict for row in roster['suites'])
            and tuple(row.get('module') for row in roster['suites']) == MODULES,
            'current roster module order')
    names = []
    for row in roster['suites']:
        require(set(row) == {'module', 'expected_tests', 'tests'}, 'current suite fields')
        count, ids = row['expected_tests'], row['tests']
        require(type(count) is int and count > 0 and type(ids) is list
                and len(ids) == count and all(type(name) is str for name in ids)
                and len(set(ids)) == count and sorted(ids) == ids
                and all(re.fullmatch(re.escape(row['module'])
                    + r'\.[A-Za-z_][A-Za-z0-9_]*\.test_[A-Za-z0-9_]+', name)
                    for name in ids), 'current suite exact names')
        names.extend(ids)
    require(type(roster['expected_tests']) is int
            and roster['expected_tests'] == len(names) == len(set(names)),
            'current roster total')
    return roster, raw


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


def execute_named(root, roster, stream):
    records = []
    for required in roster['suites']:
        module, expected = required['module'], required['tests']
        row = {'module': module, 'expected_ids': expected, 'passed': False}
        try:
            loader = unittest.TestLoader()
            suite = loader.discover(str(root / 'scripts/ci'), pattern=module + '.py')
            registered = [case.id() for case in flatten(suite)]
            row.update(registered_ids=registered, loader_errors=list(loader.errors))
            require(not loader.errors and Counter(registered) == Counter(expected),
                    'current complete module registry differs')
            result = unittest.TextTestRunner(stream=stream, verbosity=2,
                descriptions=False, resultclass=ObservedResult).run(suite)
            row.update({
                'tests_run': result.testsRun, 'started_ids': result.started_ids,
                'success_ids': result.success_ids,
                'skipped': [(case.id(), why) for case, why in result.skipped],
                'failures': [(case.id(), why) for case, why in result.failures],
                'errors': [(case.id(), why) for case, why in result.errors],
                'expected_failures': [(case.id(), why) for case, why in result.expectedFailures],
                'unexpected_successes': [case.id() for case in result.unexpectedSuccesses],
            })
            row['passed'] = (result.testsRun == required['expected_tests']
                and Counter(result.started_ids) == Counter(expected)
                and Counter(result.success_ids) == Counter(expected)
                and result.wasSuccessful() and not result.skipped
                and not result.expectedFailures and not result.unexpectedSuccesses)
        except (Exception, SystemExit) as error:
            row['exception'] = str(error)
            traceback.print_exc(file=stream)
        records.append(row)
    return {'schema': 'TRNM-W1-QROM-CURRENT-NAMED-OBSERVATION1',
        'roster_sha256': ROSTER_SHA256, 'required_tests': roster['expected_tests'],
        'suites': records, 'all_named_controls_passed':
            len(records) == len(roster['suites']) and all(x['passed'] is True for x in records),
        'qualification': scope()}


def validate_named(report, roster):
    require(type(report) is dict and set(report) == {
        'schema', 'roster_sha256', 'required_tests', 'suites',
        'all_named_controls_passed', 'qualification'}, 'named completion fields')
    require(report['schema'] == 'TRNM-W1-QROM-CURRENT-NAMED-OBSERVATION1'
            and report['roster_sha256'] == ROSTER_SHA256
            and type(report['required_tests']) is int
            and report['required_tests'] == roster['expected_tests']
            and report['all_named_controls_passed'] is True, 'named completion result')
    validate_qualification(report['qualification'])
    require(type(report['suites']) is list and len(report['suites']) == len(roster['suites']),
            'named completion suite count')
    fields = {'module', 'expected_ids', 'registered_ids', 'loader_errors', 'passed',
        'tests_run', 'started_ids', 'success_ids', 'skipped', 'failures', 'errors',
        'expected_failures', 'unexpected_successes'}
    for expected, actual in zip(roster['suites'], report['suites']):
        require(type(actual) is dict and set(actual) == fields
                and actual['module'] == expected['module'] and actual['passed'] is True
                and type(actual['tests_run']) is int
                and actual['tests_run'] == expected['expected_tests'], 'named suite completion')
        for name in ('expected_ids', 'registered_ids', 'started_ids', 'success_ids'):
            value = actual[name]
            require(type(value) is list and all(type(item) is str for item in value)
                    and Counter(value) == Counter(expected['tests']), 'named identities: ' + name)
        for name in ('loader_errors', 'skipped', 'failures', 'errors',
                     'expected_failures', 'unexpected_successes'):
            require(type(actual[name]) is list and not actual[name], 'non-success outcome: ' + name)


def validate_qualification(value):
    require(type(value) is dict and set(value) == set(FALSE_FIELDS) | {'security_bits_quantum'}
            and all(value[key] is False for key in FALSE_FIELDS)
            and value['security_bits_quantum'] is None, 'qualification escalation or malformed boolean')


def observe_drift(root, out):
    current, audit, contract, raw = load_current(root)
    legacy, legacy_raw = audit.load_contract(root)
    selected = current.pinned(root, contract['project_files'])
    before = {row['path']: row for row in legacy['project_files']}
    differences = []
    for row in contract['project_files']:
        if row != before[row['path']]:
            data = selected[row['path']]
            differences.append({'path': row['path'], 'historical': before[row['path']],
                'current': row, 'observed_bytes': len(data), 'observed_sha256': sha(data)})
    result = subprocess.run([sys.executable, str(root / current.LEGACY_READER),
        '--repo-root', str(root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=60)
    with (out / 'historical-on-current.stdout.log').open('xb') as stream:
        stream.write(result.stdout)
    with (out / 'historical-on-current.stderr.log').open('xb') as stream:
        stream.write(result.stderr)
    report = {'schema': 'TRNM-W1-QROM-HISTORICAL-CURRENT-DRIFT1',
        'historical_contract_sha256': sha(legacy_raw), 'current_contract_sha256': sha(raw),
        'historical_source_base_commit': legacy['source_base_commit'],
        'historical_replay_commit': HISTORICAL_SOURCE, 'selected_source_differences': differences,
        'historical_exit_code': result.returncode, 'historical_stdout_bytes': len(result.stdout),
        'historical_stdout_sha256': sha(result.stdout), 'historical_stderr_sha256': sha(result.stderr),
        'historical_result': strict_json(result.stderr),
        'classification': 'HISTORICAL_SOURCE_PIN_DRIFT', 'historical_v1_on_current_passed': False,
        'qualification': scope()}
    try:
        validate_drift(report, contract, legacy)
    except (ValueError, KeyError, TypeError) as error:
        # An unrelated refusal must remain an unclassified failure, even when
        # its original process output is retained for diagnosis.
        report['classification'] = 'UNCLASSIFIED_HISTORICAL_RESULT'
        report['validation_error'] = str(error)
        write_once(out / 'historical-drift.json', report)
        raise
    write_once(out / 'historical-drift.json', report)
    return report


def validate_drift(report, current, legacy):
    require(report.get('schema') == 'TRNM-W1-QROM-HISTORICAL-CURRENT-DRIFT1'
            and report.get('classification') == 'HISTORICAL_SOURCE_PIN_DRIFT'
            and type(report.get('historical_exit_code')) is int
            and report['historical_exit_code'] == 2
            and type(report.get('historical_stdout_bytes')) is int
            and report.get('historical_stdout_bytes') == 0
            and report.get('historical_v1_on_current_passed') is False,
            'historical current-source rejection missing')
    validate_qualification(report.get('qualification'))
    rejected = report.get('historical_result')
    require(type(rejected) is dict and set(rejected) == {'result', 'reason', 'qualification'}
            and rejected['result'] == 'INPUT_REJECTED' and rejected['reason'] == DRIFT_REASON,
            'unexpected historical current-source result')
    validate_qualification(rejected['qualification'])
    require(report.get('historical_source_base_commit') == legacy['source_base_commit']
            and report.get('historical_replay_commit') == HISTORICAL_SOURCE
            and report.get('historical_contract_sha256') == current['historical_contract']['sha256'],
            'historical source attribution differs')
    old = {row['path']: row for row in legacy['project_files']}
    expected = [{'path': row['path'], 'historical': old[row['path']], 'current': row,
        'observed_bytes': row['bytes'], 'observed_sha256': row['sha256']}
        for row in current['project_files'] if row != old[row['path']]]
    require(report.get('selected_source_differences') == expected and len(expected) == 2,
            'historical/current selected-byte differences lost')


def validate_source(before, after, kind, source, head, base):
    require(kind in ('head', 'prospective-merge') and before == after,
            'candidate source observations differ')
    require(before.get('schema') == 'trnm-ci-source-v1' and before.get('kind') == kind
            and before.get('tested_commit') == source and before.get('candidate') == head
            and before.get('tracked_worktree_verified') is True
            and before.get('tests_executed_by_identity_check') is False
            and type(before.get('tested_tree')) is str
            and re.fullmatch(r'[0-9a-f]{40}', before['tested_tree']) is not None
            and type(before.get('tracked_entries')) is int and before['tracked_entries'] > 0
            and type(before.get('tracked_bytes')) is int and before['tracked_bytes'] > 0,
            'candidate source identity incomplete')
    if kind == 'head':
        require(source == head and before.get('base') is None
                and before.get('prospective_merge') is None, 'candidate head source mismatch')
    else:
        require(before.get('base') == base and before.get('prospective_merge') == source,
                'candidate merge source mismatch')


def validate_mapping(report, current, audit, contract, raw, root):
    require(report.get('schema') == 'TRNM-W1-QROM-CURRENT-IMPLEMENTATION-AUDIT2'
            and report.get('result') == 'CURRENT_MAPPING_REPRODUCED_SECURITY_HOLD'
            and report.get('contract_sha256') == sha(raw)
            and report.get('source_base_commit') == contract['source_base_commit']
            and report.get('generator_sha256') == sha((root / 'scripts/w1_qrom_current_implementation_audit.py').read_bytes()),
            'current mapping namespace or input identity differs')
    validate_qualification(report.get('qualification'))
    require(report.get('lifetime_budget') == contract['lifetime_budget']
            and report.get('open_obligations') == [
                {'id': name, 'state': 'UNRESOLVED'} for name in contract['proof_obligations']],
            'current mapping unknown obligations or budget changed')
    budget = report['lifetime_budget']
    require(budget.get('policy_adopted') is False
            and all(value is None for key, value in budget.items() if key != 'policy_adopted'),
            'unknown budget fields and policy boolean must stay exact')
    require(report.get('project_files') == contract['project_files']
            and report.get('saved_fixture_files') == contract['saved_v2_files'],
            'current mapping selected inputs differ')
    closure = report.get('local_path_closure', {})
    require(closure.get('files') == contract['local_path_closure']['files']
            and type(closure.get('source_files_checked')) is int
            and closure['source_files_checked'] == len(contract['local_path_closure']['files'])
            and closure.get('source_before_after_equal') is True,
            'current mapping local closure incomplete')
    for flag in ('fresh_cryptographic_verification', 'native_binary_executed',
                 'whole_repository_source_verified', 'third_party_source_closure_verified',
                 'provider_build_identity_verified', 'git_commit_ancestry_verified'):
        require(report.get(flag) is False, 'mapping scope widened: ' + flag)
    require(report.get('historical_v1') == {
        'reader_sha256': current.LEGACY_READER_SHA256,
        'contract_sha256': contract['historical_contract']['sha256'],
        'result': 'INPUT_REJECTED', 'reason': DRIFT_REASON,
        'named_roster_completed': False, 'workflow_passed': False},
        'historical current-source rejection relabeled')
    require(report['historical_v1']['named_roster_completed'] is False
            and report['historical_v1']['workflow_passed'] is False,
            'historical scope booleans must stay exact')
    require(report.get('parameter_digest_independently_recomputed') == audit.PARAMETERS,
            'mapping parameters differ')


def verify(root, out, kind, source, head, base, steps):
    errors, identities = [], {}
    missing = [name for name in REQUIRED_STAGES if
        steps.get(name, {}).get('outcome') != 'success'
        or steps.get(name, {}).get('conclusion') != 'success']
    if missing:
        errors.append('failed or skipped stages: ' + ', '.join(missing))
    try:
        current, audit, contract, raw = load_current(root)
        historical_job = validate_historical_job(
            (root / '.github/workflows/pon-w1-qrom-implementation.yml').read_text())
        legacy, _ = audit.load_contract(root)
        roster, roster_raw = load_roster(root)
        retained = (out / 'required-tests.json').read_bytes()
        require(retained == roster_raw, 'retained current roster differs')
        names, names_raw = read_json(out / 'named-tests.json')
        validate_named(names, roster)
        before, _ = read_json(out / 'source-before.json')
        after, _ = read_json(out / 'source-after.json')
        validate_source(before, after, kind, source, head, base)
        implementation, implementation_raw = read_json(out / 'implementation.json')
        validate_mapping(implementation, current, audit, contract, raw, root)
        drift, drift_raw = read_json(out / 'historical-drift.json')
        validate_drift(drift, contract, legacy)
        require(drift['current_contract_sha256'] == sha(raw), 'drift current contract differs')
        stdout = (out / 'historical-on-current.stdout.log').read_bytes()
        stderr = (out / 'historical-on-current.stderr.log').read_bytes()
        require(not stdout and sha(stdout) == drift['historical_stdout_sha256']
                and sha(stderr) == drift['historical_stderr_sha256']
                and strict_json(stderr) == drift['historical_result'],
                'retained historical process output differs')
        identities = {'candidate_source': before, 'named_tests_sha256': sha(names_raw),
            'implementation_sha256': sha(implementation_raw), 'historical_drift_sha256': sha(drift_raw),
            'required_named_controls': roster['expected_tests'],
            'historical_job_sha256': historical_job}
    except (Exception, SystemExit) as error:
        errors.append(str(error))
    report = {'schema': 'TRNM-W1-QROM-CURRENT-CI-OBSERVATION1',
        'expected_source': source, 'expected_candidate': head, 'expected_base': base,
        'source_kind': kind, 'required_stages': list(REQUIRED_STAGES), 'steps': steps,
        'failed_or_skipped_stages': missing, 'validation_errors': errors,
        'all_required_current_observations_passed': not errors,
        'historical_v1_on_current_passed': False, 'historical_replay_commit': HISTORICAL_SOURCE,
        'scope': 'Exact candidate current V2 mapping and original V1 source-pin rejection. '
                 'The separate fixed historical V1 replay is not a current-source or cryptographic qualification.',
        'identities': identities, 'qualification': scope()}
    write_once(out / 'current-ci-status.json', report)
    require(not errors, '; '.join(errors))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('named', 'drift', 'verify'))
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--kind', choices=('head', 'prospective-merge'))
    parser.add_argument('--expected-source')
    parser.add_argument('--expected-head')
    parser.add_argument('--expected-base')
    args = parser.parse_args()
    root, out = args.repo_root.absolute(), args.out.absolute()
    try:
        require(root == root.resolve(strict=True), 'candidate root is an alias')
        require(out.is_dir() and not out.is_symlink(), 'observation directory unavailable')
        if args.command == 'named':
            roster, raw = load_roster(root)
            with (out / 'required-tests.json').open('xb') as stream:
                stream.write(raw)
            report = execute_named(root, roster, sys.stderr)
            write_once(out / 'named-tests.json', report)
            validate_named(report, roster)
        elif args.command == 'drift':
            observe_drift(root, out)
        else:
            steps = strict_json(os.environ['W1_QROM_CURRENT_STEP_RESULTS'])
            require(type(steps) is dict, 'workflow stage observations must be an object')
            verify(root, out, args.kind, args.expected_source, args.expected_head,
                   args.expected_base, steps)
        print('Source-specific observation completed; cryptographic and production qualification remain false.')
        return 0
    except (Exception, SystemExit) as error:
        print(json.dumps({'schema': 'TRNM-W1-QROM-CURRENT-CI-ERROR1',
            'result': 'OBSERVATION_FAILED', 'reason': str(error), 'qualification': scope()}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
