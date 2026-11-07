#!/usr/bin/env python3
"""Read frozen bytes and provenance only; never execute archive members or tests."""
import collections
import hashlib
import json
from pathlib import Path

B = Path('/workspace/scratch/8a6ecb667c1e')
R = Path(__file__).resolve().parent
I = B / 'terminal-evidence-curated-final-20261106-v1/publication/archive-index.json'
EXPECTED_INDEX = '91ef1453209eb3b72eb0f90066ca05e4e5a93e8d1b1b00f5c87855ddcfe1e8ed'
F85 = 'f85fea4e8da02404d513d074ceb35ad5292b017b'
EBD = 'ebd3c06da7d5f2bd136b7a24f24604508d420279'
CURRENT = 'ca4e2fb9160d3e388e131624f7b3350ae4f5d56b'
CURRENT_TREE = 'ba691b8b5f06a0cfeb062261d6a33f0c086f06b0'

def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()

index_bytes = I.read_bytes()
assert sha_bytes(index_bytes) == EXPECTED_INDEX
index = json.loads(index_bytes)
assert index['candidate'] == CURRENT and index['tree'] == CURRENT_TREE
roundtrip = json.loads((R / 'fixed-verifier.stdout.log').read_text())
assert roundtrip['result'] == 'PASS_ARCHIVE_CONTENT_ONLY'
assert roundtrip['index_sha256'] == EXPECTED_INDEX
assert roundtrip['native_tests_executed'] == 0
members = {row['path']: row for row in index['members']}
assert len(members) == 5574
checked_raw_members = {}

def raw_member(name, expected_sha=None):
    row = members[name]
    value = (B / name).read_bytes()
    assert len(value) == row['bytes'] and sha_bytes(value) == row['sha256'], name
    if expected_sha:
        assert row['sha256'] == expected_sha, name
    checked_raw_members[name] = {'bytes': len(value), 'sha256': row['sha256']}
    return value

def json_member(name, expected_sha=None):
    return json.loads(raw_member(name, expected_sha))

final_hashes = {
    'final-evidence-delivery-v2/README.md': 'ab7e0f2fa2f549e6fdb9371d96d163f4915031b9cc00f5abcc8a1e317d51f326',
    'final-evidence-delivery-v2/qualification.json': '37c2ff8378620ec94dbec3e56e99fef5b22e39a7b17c3f583a7eba53fb070b26',
    'final-evidence-delivery-v2/source-publication-map.json': 'f00df89335be2fbff65adba2fcdf622a87ecba9139fc92626dfaa39129a65944',
}
for name, digest in final_hashes.items():
    raw_member(name, digest)
qual = json_member('final-evidence-delivery-v2/qualification.json')
publication = json_member('final-evidence-delivery-v2/source-publication-map.json')
readme = raw_member('final-evidence-delivery-v2/README.md').decode()
normalized_readme = ' '.join(readme.split())
assert '271 command/phase observations: 269 succeeded, one library timeout, one dependent readback blocked' in normalized_readme
assert '44 command/check observations comprise 40 successes, one native failure and three blocked readers.' in normalized_readme
assert 'No budget is enlarged, sample removed, or failed run replaced by a rerun.' in normalized_readme
assert CURRENT in readme and EBD in readme and F85 in readme

manifests = [
    ('quantum-readback-cad4c18f/desktop-f85-terminal-v2', 'e20fc9c30c0fae8102508b12bc9bff6153e85a545f0fe11e2ccc2af7a8c59a3c', 580),
    ('quantum-readback-cad4c18f/desktop-ebd14-terminal-v1', '754b565c4994ca01ae5d67abe574d3c66268e77071fdcff5fbadcb0a61e55357', 142),
    ('quantum-readback-cad4c18f/desktop-ebd-auth-cost-failure-v1', 'fb6435eb760b7279e89bc9a18bba1d822808e4df750d6b07ba2954a8b82a7d4d', 17),
]
coverage = []
for prefix, digest, count in manifests:
    manifest = json_member(prefix + '/manifest.json', digest)
    assert len(manifest['files']) == count
    for item in manifest['files']:
        archived = members[prefix + '/' + item['path']]
        assert archived['bytes'] == item['bytes'] and archived['sha256'] == item['sha256']
    coverage.append({'manifest': prefix + '/manifest.json', 'sha256': digest,
                     'declared_files': count, 'every_declared_raw_file_present_with_exact_sha': True})

f85_prefix = manifests[0][0] + '/green-f85fea4e-20261106-v1'
ebd_prefix = manifests[1][0] + '/supplement-ebd3c06d-14-controls-20261106-v1'
f85 = json_member(f85_prefix + '/summary.json', '91f8f712ad4382bac7ddd523bd650c770818e140766ee09a8220cf43d6f847c0')
ebd = json_member(ebd_prefix + '/summary.json', '6665ff2a50f54510fbf402477b85907cd56c5c46b1cf15ceea96efd369386158')
raw_progress = {}
for prefix, summary, head, expected_count, statuses in [
    (f85_prefix, f85, F85, 271, {'succeeded': 269, 'timed_out': 1, 'blocked': 1}),
    (ebd_prefix, ebd, EBD, 44, {'succeeded': 40, 'failed': 1, 'blocked': 3}),
]:
    assert summary['tested_commit'] == head and summary['success'] is False
    assert summary['fatal_error'] is None and summary['source_unchanged']
    assert summary['source_before'] == summary['source_after']
    progress = json_member(prefix + '/progress.json')
    assert len(progress) == expected_count and dict(collections.Counter(r['status'] for r in progress)) == statuses
    for row in progress:
        archived = members[prefix + '/' + row['label'] + '.log']
        assert archived['bytes'] == row['log_bytes'] and archived['sha256'] == row['log_sha256']
    raw_progress[head] = {row['label']: row for row in progress}
assert ebd['passing_named_controls_claim'] is None
assert ebd['full_node_suite_executed'] is False
assert ebd['f85_timeout_reclassified'] is False
assert ebd['f85_other_gates_transferred_to_this_source'] is False
assert ebd['paid_pending_prior_failure_root_cause_established'] is False
f85_row = raw_progress[F85]['node-full-feature-library']
assert f85_row['status'] == 'timed_out' and f85_row['exit_code'] == -15
assert raw_progress[F85]['new-base-node-coverage-readback']['status'] == 'blocked'
f85_log = raw_member(f85_prefix + '/node-full-feature-library.log').decode()
assert 'r4_paid_pending_eof_original_expiry_and_shutdown_never_create_body_or_work ... FAILED' in f85_log
inputs = json_member(ebd_prefix + '/reviewed-inputs.json')
controls = inputs['r4_controls'] + inputs['cost_gates']
assert len(inputs['r4_controls']) == 10 and len(inputs['cost_gates']) == 4
control_statuses = []
for control in controls:
    label = Path(control['reader_argv'][2]).stem
    row = raw_progress[EBD][label]
    reader = raw_progress[EBD][label + '-readback']
    assert reader['status'] == ('succeeded' if row['status'] == 'succeeded' else 'blocked')
    control_statuses.append({'selector': control['selector'], 'status': row['status'],
                             'exit_code': row['exit_code'], 'reader_status': reader['status']})
assert collections.Counter(r['status'] for r in control_statuses) == {'succeeded': 13, 'failed': 1}
for name in ('control-artifact-readback', 'cost-sample-readback'):
    assert raw_progress[EBD][name]['status'] == 'blocked'
assert raw_progress[EBD]['strict-workspace-clippy']['exit_code'] == 0
auth = [json.loads(line) for line in raw_member(
    'quantum-readback-cad4c18f/desktop-ebd-auth-cost-failure-v1/pq-authentication-cost.jsonl',
    '687f20a939bbe410da78de8bd0b13d44be030958b77f7d11c4cbdafb6450eea7').decode().splitlines()]
samples = [row for row in auth if row['schema'] == 'pon-pq-caller-auth-cost-sample-v1']
bad = [row for row in samples if not row['matches_expected'] or not row['original_accounting_preserved']]
assert len(auth) == 514 and len(samples) == 512 and len(bad) == 67
assert collections.Counter(row['arm'] for row in bad) == {'cached': 34, 'original': 33}
assert all(row['case'] == 'sixteen-key-churn' and row['error'] == 'PUBLIC_MUTATION_CPU_BUDGET'
           and row['charged_cpu_ns'] == row['actual_cache_hits'] == row['actual_completed_expansions'] == 0 for row in bad)
auth_log = raw_member(ebd_prefix + '/cost-pq_caller_authentication_complete_cost.log').decode()
assert 'left: 67' in auth_log and 'right: 0' in auth_log

assert qual['disposition'] == 'HOLD'
assert qual['f85_desktop']['terminal_exit_code'] == 1
assert qual['f85_desktop']['statuses'] == {'succeeded': 269, 'timed_out': 1, 'blocked': 1}
assert qual['f85_desktop']['full_library']['status'] == 'INCOMPLETE'
assert qual['f85_desktop']['full_library']['parent_summary_available'] is False
qebd = qual['ebd_native_supplement']
assert qebd['terminal']['durable_exit_code'] == 1
assert qebd['terminal']['statuses'] == {'succeeded': 40, 'failed': 1, 'blocked': 3}
assert qebd['observed_native_result']['passed'] == 13 and qebd['observed_native_result']['failed'] == 1
assert qebd['observed_authentication_failure']['native_exit_code'] == 101
assert qebd['observed_authentication_failure']['unexpected_outcomes_or_accounting'] == 67
assert qual['code']['commit'] == publication['code_commit'] == CURRENT
assert qual['code']['tree'] == publication['code_tree'] == CURRENT_TREE
assert qual['code']['native_execution_on_this_commit_claimed'] is False
assert qual['publication']['native_tests_on_containing_evidence_commit_claimed'] is False
assert all(row['native_results_transfer_by_this_mapping'] is False for row in publication['mapping'])
late = qual['late_composition_source_gates']
assert late['source'] == CURRENT and late['recorded_commands'] == 20 and late['python_test_observations'] == 232 and late['material_tests'] == 25
assert late['native_rust_tests_executed'] == 0 and late['strict_native_clippy_executed'] is False
assert late['prior_native_results_transferred'] is False
late_raw = json_member(late['evidence']['member'], late['evidence']['sha256'])
assert late_raw['source'] == CURRENT and late_raw['tree'] == CURRENT_TREE
assert len(late_raw['commands']) == 20 and late_raw['all_commands_succeeded']
assert sum(sum(row['reported_python_test_counts']) for row in late_raw['commands']) == 232
assert late_raw['runtime_material_test_count'] == [25]
assert late_raw['native_rust_tests_executed'] == 0 and late_raw['strict_native_clippy_executed'] is False
assert late_raw['prior_native_results_transferred'] is False
for key in ('whole_chain_pq_qualified', 'whole_chain_pq_128_or_256_bit_label_accepted',
            'quantum_mining_economic_security_qualified', 'public_wan_qualified',
            'production_activated', 'original_budgets_weakened',
            'archive_hash_integrity_implies_product_qualification'):
    assert qual[key] is False
assert I.read_bytes() == index_bytes

report = {
    'schema': 'trnm-independent-final-archive-and-source-scope-review-v1',
    'result': 'PASS_ARCHIVE_INTEGRITY_AND_FAILURE_PRESERVATION_ONLY',
    'archive_verification': roundtrip,
    'final_documents': {name: checked_raw_members[name] for name in final_hashes},
    'original_terminal_manifest_coverage': coverage,
    'all_315_original_command_logs_match_their_progress_hashes': True,
    'f85': {'tested_commit': F85, 'batch_success': False,
            'observations': {'succeeded': 269, 'timed_out': 1, 'blocked': 1},
            'full_library_exit': -15, 'original_failed_progress_row_preserved': True,
            'missing_panic_or_parent_summary_fabricated': False},
    'ebd': {'tested_commit': EBD, 'batch_success': False,
            'observations': {'succeeded': 40, 'failed': 1, 'blocked': 3},
            'named_controls_passed': 13, 'named_controls_failed': 1,
            'control_results': control_statuses, 'auth_failed_samples': 67,
            'auth_error': 'PUBLIC_MUTATION_CPU_BUDGET',
            'auth_failed_case': 'sixteen-key-churn', 'blocked_readers_preserved': True},
    'ca4': {'tested_commit': CURRENT, 'tree': CURRENT_TREE,
            'recorded_commands': 20, 'python_observations': 232, 'material_tests': 25,
            'native_rust_tests_executed': 0, 'strict_native_clippy_executed': False,
            'prior_native_results_transferred': False},
    'checked_original_raw_members': checked_raw_members,
    'native_tests_executed_by_this_review': 0, 'desktop_accessed': False,
    'archive_members_extracted_or_executed': False, 'second_archive_roundtrip': False,
    'product_disposition': 'HOLD', 'whole_chain_pq_qualified': False,
    'archive_pass_reclassified_as_native_pass': False,
}
with (R / 'review.json').open('x') as stream:
    json.dump(report, stream, sort_keys=True, indent=2)
    stream.write('\n')
print(json.dumps({'result': report['result'], 'report': str(R / 'review.json'),
                  'report_bytes': (R / 'review.json').stat().st_size,
                  'report_sha256': sha_bytes((R / 'review.json').read_bytes()),
                  'native_tests_executed_by_this_review': 0}, sort_keys=True))
