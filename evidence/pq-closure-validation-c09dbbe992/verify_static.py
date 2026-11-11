#!/usr/bin/env python3
"""Verify retained C1 static evidence. This never runs the original workloads."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

C1 = 'c09dbbe9921da12db8bf7240a8a95a0e9a789e50'
TREE = 'f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6'
SOURCE = {'commit': C1, 'tree': TREE}
INITIAL = 'python-validation-c09dbbe992'
RESUME = 'python-validation-c09dbbe992-resume01'
CARGO = 'cargo-static-c09dbbe992'
SUITES = [
    ('test_hash_use_contract', 30), ('test_pq_lifetime_budget', 58),
    ('test_pq_authority_effect_register', 18), ('test_pq_root_dependency_register', 43),
    ('test_run_pq_root_continuation_v4', 4), ('test_run_pq_root_witness_v5', 4),
    ('test_consensus_roster', 9), ('test_w1_lifetime_ledger', 19),
    ('test_cell_storage_convergence_ci', 19), ('test_pq_research_integration', 60),
    ('test_ci_contract', 180), ('test_codeql_retention', 14), ('test_export_codeql_analysis', 16),
]
CHECKS = ['hash_use_contract', 'pq_lifetime_budget', 'pq_authority_effect_register',
          'pq_root_dependency_register', 'check_ci_contract', 'check_pq_research_integration',
          'pq_chain_claim_guard']
STEPS = ['named_tests', 'historical_controls', 'implementation', 'current_implementation',
         'budget_unknown', 'budget_hypothetical', 'report_scopes']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object)


def evaluate(raw):
    def get(path):
        require(path in raw, 'missing retained file: ' + path)
        return raw[path]

    def doc(path):
        return decode(get(path))

    def verify_ref(base, ref):
        name = ref.get('name', ref.get('path'))
        if name.startswith('/'):
            marker = '/workspace/scratch/d4d2da8133e2/'
            require(name.startswith(marker), 'unexpected original path')
            path = name[len(marker):]
        else:
            path = base + '/' + name
        data = get(path)
        require(len(data) == ref['bytes'] and sha(data) == ref['sha256'], 'log/hash mismatch: ' + path)

    def suite_end(name, count, data):
        text = data.decode('utf-8')
        match = re.search(r'\n-{70}\nRan (\d+) tests in [0-9.]+s\n\nOK\n\Z', text)
        require(match is not None and int(match[1]) == count, 'incomplete/failed suite: ' + name)
        prefix = text[:match.start()].strip()
        if prefix and set(prefix) == {'.'}:
            require(len(prefix) == count, 'dot completion count: ' + name)
        else:
            lines = prefix.splitlines()
            require(len(lines) == count and all(line.endswith(' ... ok') for line in lines),
                    'non-success or missing verbose completion: ' + name)

    receipts = []
    initial_names = [name for name, _ in SUITES[:9]]
    resumed_names = [name for name, _ in SUITES[9:]] + CHECKS + ['workflow-' + step for step in STEPS]
    for base, names in [(INITIAL, initial_names), (RESUME, resumed_names)]:
        actual = {p[len(base) + 1:-len('.receipt.json')] for p in raw
                  if p.startswith(base + '/') and p.endswith('.receipt.json')}
        require(actual == set(names), 'unexpected/missing receipt set: ' + base)
        for name in names:
            receipt = doc(base + '/' + name + '.receipt.json')
            require(receipt['name'] == name and type(receipt['exit_code']) is int
                    and receipt['exit_code'] == 0 and receipt['passed'] is True
                    and receipt['timed_out'] is False, 'unsuccessful receipt: ' + name)
            require(receipt['source_before'] == SOURCE and receipt['source_after'] == SOURCE,
                    'source identity mismatch: ' + name)
            for stream in ['stdout', 'stderr']:
                verify_ref(base, receipt[stream])
            if name.startswith('test_'):
                count = dict(SUITES)[name]
                require(type(receipt['outer_tests']) is int and receipt['outer_tests'] == count,
                        'outer count mismatch: ' + name)
                script = ('scripts/' if name == 'test_export_codeql_analysis' else 'scripts/ci/') + name + '.py'
                require(receipt['argv'] == ['python3', '-B', script], 'suite argv mismatch')
                suite_end(name, count, get(base + '/' + receipt['stderr']['name']))
            elif name.startswith('workflow-'):
                require(receipt['argv'] == ['bash', '/workspace/scratch/d4d2da8133e2/' + base + '/' + name + '.sh'],
                        'workflow argv mismatch')
            else:
                require(receipt['argv'] == ['python3', '-B', 'scripts/ci/' + name + '.py'], 'check argv mismatch')
            if base == RESUME:
                started = doc(base + '/' + name + '.started.json')
                require(all(receipt.get(k) == v for k, v in started.items()), 'started/receipt mismatch: ' + name)
            receipts.append((base, receipt))

    partial = doc('python-validation-partial-observation.json')
    require(partial['completed_receipt_count'] == 9 and partial['completed_outer_tests_in_these_receipts'] == 204,
            'partial receipt counts')
    require(partial['overall_validation_status'] == 'incomplete-terminal-state-unknown', 'partial terminal status changed')
    incomplete = partial['incomplete_command']
    require(incomplete['terminal_state'] == 'unknown' and incomplete['terminal_exit_code'] is None
            and incomplete['test_failed'] is None and incomplete['progress_dots_observed'] == 18,
            'partial completion was upgraded')
    require(get(INITIAL + '/test_pq_research_integration.stderr.log') == b'.' * 18, 'incomplete log changed')
    for name in ['source-after.json', 'summary.json', 'test_pq_research_integration.receipt.json']:
        require(INITIAL + '/' + name not in raw, 'invented original terminal artifact')
    for ref in [partial['original_runner'], partial['source_before_record']]:
        verify_ref('', ref)
    for item in partial['completed_suite_receipts']:
        verify_ref('', item['receipt'])
        for ref in item['logs'].values():
            verify_ref('', ref)
    for ref in incomplete['logs'].values():
        verify_ref('', ref)

    snapshots = [get(INITIAL + '/source-before.json'), get(RESUME + '/source-before.json'),
                 get(RESUME + '/source-after.json')]
    require(snapshots[0] == snapshots[1] == snapshots[2], 'retained source snapshots differ')
    snapshot = decode(snapshots[0])
    require({key: snapshot[key] for key in SOURCE} == SOURCE and snapshot['full_checkout_materialized'] is False,
            'snapshot scope/source mismatch')
    materialized = [row['path'] for row in snapshot['files']]
    absent = snapshot['unmaterialized_sparse_paths']
    require(len(materialized) == len(set(materialized)) == 5135 and len(absent) == len(set(absent)) == 22777
            and not set(materialized).intersection(absent), 'snapshot partition shape')
    require(sum(row['bytes'] for row in snapshot['files']) == 171498180, 'materialized byte count')
    resume = doc(RESUME + '/summary.json')
    require(resume['source'] == SOURCE and resume['source_unchanged'] is True
            and resume['all_selected_commands_passed'] is True and resume['status'] == 'HOLD_NO_GO',
            'resume summary changed')
    require(resume['commands'] == [r for base, r in receipts if base == RESUME], 'resume summary receipt list mismatch')
    require(all(resume[key] is False for key in ['hosted_ci_observed', 'production_activation', 'whole_chain_pq_qualified']),
            'qualification upgraded')
    recovery = doc(RESUME + '/recovery-context.json')
    require(recovery['original_suites_repeated'] is False and recovery['same_uninterrupted_run_claimed'] is False
            and recovery['prior_integration_suite_terminal_state'] == 'unknown_no_receipt'
            and recovery['prior_completed_outer_tests'] == 204 and recovery['prior_completed_suites'] == 9,
            'recovery context changed')

    qbase = RESUME + '/qrom-observations/'
    named_roster = doc(qbase + 'required-tests.json')
    supplement_roster = doc(qbase + 'supplemental-required-tests.json')
    named = doc(qbase + 'named-tests.json')
    require(named['schema'] == 'TRNM-W1-QROM-NAMED-TEST-OBSERVATION1'
            and named['required_tests'] == 81 and named_roster['expected_tests'] == 81
            and named['all_named_controls_passed'] is True
            and named['roster_sha256'] == sha(get(qbase + 'required-tests.json'))
            and named['post_quantum_soundness_qualified'] is False
            and named['unconditional_project_security_bits'] is None, 'named completion invalid')
    observed = []

    def controls(item, roster):
        expected = roster['tests']
        require(len(expected) == len(set(expected)) == roster['expected_tests'], 'duplicate/empty roster IDs')
        require(item['module'] == roster['module'] and type(item['tests_run']) is int
                and item['tests_run'] == len(expected), 'named count/module mismatch')
        for field in ['expected_ids', 'registered_ids', 'started_ids', 'success_ids']:
            require(Counter(item[field]) == Counter(expected), 'missing/extra/duplicate IDs: ' + field)
        for field in ['errors', 'failures', 'loader_errors', 'skipped', 'expected_failures', 'unexpected_successes']:
            require(item[field] == [], 'non-success completion: ' + field)
        observed.append({'module': item['module'], 'tests_run': item['tests_run'], 'success_ids': item['success_ids']})

    require(len(named['suites']) == len(named_roster['suites']) == 5, 'named suite list mismatch')
    for item, roster in zip(named['suites'], named_roster['suites']):
        require(item['passed'] is True and doc(qbase + item['module'] + '.json') == item,
                'named per-suite completion mismatch')
        controls(item, roster)
    require(supplement_roster['expected_tests'] == 22 and len(supplement_roster['suites']) == 2,
            'supplemental roster mismatch')
    for scope, count, roster in zip(['historical', 'current'], [8, 14], supplement_roster['suites']):
        item = doc(qbase + scope + '-controls.json')
        require(item['schema'] == 'TRNM-W1-QROM-SUPPLEMENTAL-CONTROL-OBSERVATION1'
                and item['suite'] == roster['suite'] == scope and item['required_tests'] == count
                and item['all_named_controls_passed'] is True and item['exception'] is None
                and item['roster_sha256'] == sha(get(qbase + 'supplemental-required-tests.json')),
                'supplemental completion invalid')
        require(item['qualification'] == supplement_roster['qualification'], 'supplemental qualification mismatch')
        require(all(v is False or v is None for v in item['qualification'].values()), 'supplemental qualification upgraded')
        controls(item, roster)
    successes = [test_id for item in observed for test_id in item['success_ids']]
    require(len(successes) == len(set(successes)) == 103, 'QROM success IDs are not 103 disjoint IDs')
    require(observed[-1]['module'] == 'test_w1_qrom_current_implementation_audit', 'current 14 confused with workflow gate 14')
    require(not {name for name, _ in SUITES}.intersection(item['module'] for item in observed), 'outer/QROM module overlap')

    cargo = doc(CARGO + '/summary.json')
    require(cargo['source'] == SOURCE and cargo['scope'] == 'metadata-and-format-no-native-execution'
            and cargo['all_passed'] is True, 'cargo static scope changed')
    require([item['name'] for item in cargo['commands']] ==
            ['preflight', 'metadata-default', 'metadata-all-features', 'metadata-fuzz', 'format'], 'cargo command list mismatch')
    for item in cargo['commands']:
        require(type(item['exit_code']) is int and item['exit_code'] == 0
                and item['source_before'] == item['source_after'] == SOURCE, 'cargo source/exit mismatch')
        for stream in ['stdout', 'stderr']:
            verify_ref(CARGO, item[stream])

    return {
        'source': SOURCE, 'initial_completed_suite_count': 9, 'initial_completed_outer_tests': 204,
        'initial_integration_terminal_state': 'unknown_no_receipt', 'initial_progress_dots_excluded': 18,
        'resume_completed_commands': 18, 'resume_completed_suites': 4, 'resume_completed_outer_tests': 270,
        'completed_outer_suite_tests': 474, 'qrom_named': 81, 'qrom_historical': 8, 'qrom_current': 14,
        'qrom_unique_observed_success_ids': 103, 'top_level_python_controls': 577,
        'cargo_static_commands_passed': 5, 'retained_snapshot_sha256': sha(snapshots[0]),
        'same_uninterrupted_run_claimed': False, 'skipped_controls_counted': 0,
        'native_results_in_this_static_package': False, 'hosted_ci_results_in_this_static_package': False,
        'whole_chain_pq_qualified': False, 'production_activation': False,
        'qrom_suites': observed,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--originals', type=Path, help='also compare every archived byte with its original workspace file')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    for line in (base / 'STATIC_SHA256SUMS').read_text().splitlines():
        digest, path = line.split('  ', 1)
        require('/' not in path and path not in ['', '.', '..'], 'unsafe static checksum path')
        require(sha((base / path).read_bytes()) == digest, 'static checksum mismatch: ' + path)
    index = decode((base / 'static-raw-index.json').read_bytes())
    raw = {}
    with tarfile.open(base / index['archive']['path'], 'r:xz') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts
                    and member.name not in raw, 'unsafe/duplicate/non-file archive member')
            raw[member.name] = archive.extractfile(member).read()
    rows = {item['path']: item for item in index['files']}
    require(len(rows) == len(index['files']) and set(raw) == set(rows), 'raw archive inventory mismatch')
    for path, data in raw.items():
        require(len(data) == rows[path]['bytes'] and sha(data) == rows[path]['sha256'], 'raw member mismatch: ' + path)
        if args.originals:
            require((args.originals / path).read_bytes() == data, 'original bytes changed: ' + path)
    require(len(raw) == index['file_count'] and sum(map(len, raw.values())) == index['total_original_bytes'], 'raw totals mismatch')
    actual = evaluate(raw)
    summary = decode((base / 'static-summary.json').read_bytes())
    require(summary['verified_observations'] == actual, 'derived summary does not match retained observations')
    roster = decode((base / 'static-test-roster.json').read_bytes())
    require(roster['qrom_runtime_success_roster'] == actual['qrom_suites'], 'derived success roster mismatch')
    print(json.dumps({'verified': True, 'source': SOURCE, 'original_files': len(raw),
                      'original_bytes': sum(map(len, raw.values())), 'python_controls': 577,
                      'original_unknown_preserved': True, 'native_included': False,
                      'originals_compared': args.originals is not None}, sort_keys=True))


if __name__ == '__main__':
    main()
