#!/usr/bin/env python3
"""Offline verification of the exact C2 eight-case and strict-Clippy packet.

All original C1 failures stay retained. The target directory was reused from the
closed C1 run; this is not a clean-build assertion, hosted CI, execution attestation,
or a whole-chain post-quantum qualification. No workload is run by this verifier.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re

C2 = '0e554f36ffdde3053a5eb1756eb5e526b1935032'
TREE = '753cdbad6714f00d8ccb9ddbb47f0fd71280ee62'
RUNNER_SHA = '47797db5d563ba3549cd8326f43015f7f5fd29eec713df22e55df38eb65413cc'
SUBSET_VERIFIER_SHA = '5045ab5b9cf24d8952f1fef5345dd07a28a053f864a2bb96c5377018d4e3b79a'
OUTPUT = '/data/chain-pq-closure-20261111-d4d2-validation-0e554f36ffdd-01'
NAMES = ('preflight', 'rustc-version', 'cargo-version', 'openssl-version',
         'metadata-default', 'metadata-all-features', 'metadata-fuzz', 'fmt',
         'node-account-scope', 'node-all-pq-profile-settlement',
         'tls-full-spki-1', 'tls-full-spki-2', 'tls-full-spki-3', 'strict-workspace-clippy')
# Read independently from the C1 and C2 Git objects, without replacement objects
# or lazy fetch. Two corpus pins changed inside one JSON, hence three files.
DELTA = {
    'config/pon/pq-cross-branch-corpus-v1.json': (
        ('e6b56b770675293c952f0b7d586ee46c5c297bd4', 202762, '702c54eec9a66541adeea48d6676cb772376565537391bbe1fc4f4affb45c521'),
        ('ec2d643f30e2382363eb65ec25a470b5bd492362', 202762, 'a809c7342000b710e4b76dc8f4573261968a1c34872ec424b89ea4091c56d3b4')),
    'scripts/ci/check_public_readiness_evidence.py': (
        ('70a1ef5e8bddd075ebf9d2805164b4ba8a3a5b4a', 71420, '7ce22c06b557ed5440bbb2361c9a190b2a7c051c8267b7cf221b333685767068'),
        ('73e4f87aeefc3f28e077ac1fc4c0cb2ae8114d7d', 71595, 'd73407a28cf7914b5c8f5eb53d2bc8e4fea2bf59e5c0853cd86655da33fd2026')),
    'scripts/ci/test_public_readiness_evidence.py': (
        ('99b2980efa5d1ffdcdb0dc0de7057fc232794790', 119264, '55a61e0220f684b8c5ffde00c5b1180c2d2d24757c94f6b0871bacc4ffda198b'),
        ('ba6c3badfcd5f173bce619b51c84334eeb9e866d', 120969, 'a5d6d7cc039b85d4c49865fec5866e7891d967446b35a145a66bf66825875696')),
}


def load_subset_verifier(path):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != SUBSET_VERIFIER_SHA:
        raise ValueError('fixed companion subset verifier changed')
    spec = importlib.util.spec_from_file_location('offline_c1_subsets', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(m, args, original, readback, witness, expected):
    packet = m.load_packet(args.archive, args.receipt, 'c2')
    raw, plan, summary = packet['raw'], packet['plan'], packet['summary']
    m.require(m.sha(raw['reproduction/desktop_validate.py']) == m.ORIGINAL_RUNNER_SHA
              and m.sha(raw['reproduction/desktop_validate_c2.py']) == RUNNER_SHA, 'C2 frozen runners')
    m.require(set(name for name in raw if name.startswith('reproduction/')) ==
              {'reproduction/desktop_validate.py', 'reproduction/desktop_validate_c2.py'}, 'C2 runner roster')
    m.require(plan['schema'] == 'trnm-c2-native-recheck-plan-v1'
              and summary['schema'] == 'trnm-c2-native-recheck-v1', 'C2 plan/summary schema')
    m.require(plan['commit'] == summary['source'] == C2 and plan['tree'] == summary['tree'] == TREE,
              'C2 source identity')
    m.require(packet['receipt']['archive'] == OUTPUT + '.tar.xz', 'C2 original archive location')
    identity = {'commit': C2, 'tree': TREE, 'branch': m.IDENTITY['branch'], 'status': ''}
    before = m.decode(raw['c2/source-before.json'])
    m.require(raw['c2/source-before.json'] == raw['c2/source-after.json'], 'C2 group source changed')
    m.require(before['schema'] == 'trnm-desktop-exact-source-v1'
              and {key: before[key] for key in identity} == identity
              and before['all_actual_bytes_compared_with_git_blobs'] is True
              and before['tracked_entries'] == len(before['files']) == 27912
              and before['tracked_bytes'] == sum(row['bytes'] for row in before['files']) == 2554108569,
              'C2 tracked source scope')
    old = m.decode(original['raw']['native/source-before.json'])
    m.require([row['path'] for row in before['files']] == [row['path'] for row in old['files']],
              'C2 tracked file roster differs')
    actual_changes = []
    for old_row, new_row in zip(old['files'], before['files']):
        path = old_row['path']
        if path not in DELTA:
            m.require(new_row == old_row, 'unexpected C2 source delta: ' + path)
            continue
        actual_changes.append(path)
        for row, values in ((old_row, DELTA[path][0]), (new_row, DELTA[path][1])):
            blob, size, digest = values
            m.require(row == {'path': path, 'mode': '100644', 'git_blob': blob,
                              'bytes': size, 'sha256': digest}, 'fixed C1/C2 changed Git blob: ' + path)
    m.require(set(actual_changes) == set(DELTA)
              and before['tracked_bytes'] - old['tracked_bytes'] == 1880, 'C2 three-file source delta')
    source_rows = {row['path']: row for row in before['files']}
    m.require(all(source_rows[row['path']] == row for row in expected['source_inputs']),
              'C2 native rosters differ from independent source-bound C1 roster')
    for name in ('provider-before.json', 'provider-after.json'):
        data = raw['c2/' + name]
        m.require(data == original['raw']['native/' + name]
                  == readback['raw']['subset/' + name] == witness['raw']['subset/' + name],
                  'C2 provider differs from closed C1 observations')
    m.require(summary['source_unchanged'] is True and summary['provider_unchanged'] is True,
              'C2 source/provider closure')
    m.check_member_pin(plan['runner'], packet, 'reproduction/desktop_validate_c2.py')
    m.check_member_pin(plan['original_runner'], packet, 'reproduction/desktop_validate.py')
    refs = m.check_references(packet, original)
    m.check_member_pin(plan['original_C1_summary'], original, 'native/summary.json')
    for name, prior, plan_name in (
            ('readback_subset', readback, 'C1_subset_summary'),
            ('witness_v5_subset', witness, 'C1_witness_v5_subset_summary')):
        m.check_file_pin(refs[name + '_archive'], prior['archive_path'], prior['receipt'])
        m.check_file_pin(refs[name + '_export_receipt'], prior['receipt_path'])
        m.check_member_pin(refs[name + '_summary'], prior, 'subset/summary.json', labelled=True)
        m.check_member_pin(plan[plan_name], prior, 'subset/summary.json')
    m.require(plan['source_directory'] == m.REPO and plan['output_directory'] == OUTPUT
              and plan['target_directory'] == original['plan']['target_directory'] == m.TARGET
              and plan['target_reused_from_closed_C1_group'] is True, 'C2 private target reuse scope')
    m.require(plan['environment'] == original['plan']['environment'], 'C2 inherited fixed provider/toolchain env')
    selected = {row['name']: row for row in expected['commands']}
    planned = [selected[name] for name in NAMES]
    m.require(plan['commands'] == planned and len(planned) == 14
              and sum(len(row['expected_tests'] or []) for row in planned) == 8,
              'C2 independent argv/budget/roster contract')
    for document in (plan, summary):
        m.require(document['C1_original_failures_retained'] is True
                  and document['whole_chain_quantum_security_qualified'] is False, 'C1 failure/C2 qualification scope')
    m.require(summary['production_activation'] is False and summary['native_run_is_not_hosted_ci'] is True,
              'C2 activation/hosted scope')
    commands = summary['commands']
    m.require(len(commands) <= 14 and [row['name'] for row in commands] == list(NAMES[:len(commands)]),
              'C2 command sequence')
    native = []
    versions = {'rustc-version': r'^release: 1\.95\.0$', 'cargo-version': r'^cargo 1\.95\.0 \(',
                'openssl-version': r'^OpenSSL 3\.5\.9\b'}
    for declared, row in zip(planned, commands):
        name = row['name']
        m.require(row['schema'] == 'trnm-desktop-command-v1' and row['cwd'] == m.REPO
                  and row['source_before'] == row['source_after'] == identity
                  and row['environment'] == plan['environment'], 'C2 command/source/environment')
        m.require(all(row[key] == declared[key] for key in ('name', 'argv', 'timeout_seconds', 'expected_tests')),
                  'C2 command differs from fixed expected plan: ' + name)
        texts = m.command_logs(packet, row, 'c2')
        derived_pass = (row['exit_code'] == 0 and not row['timed_out'] and row['exception'] is None
                        and 'source_error' not in row)
        if name in versions:
            observed_version = bool(re.search(versions[name], texts['stdout'], re.M))
            m.require(row['expected_version_observed'] is observed_version, 'C2 version/raw log projection')
            derived_pass = derived_pass and observed_version
        expected_names = declared['expected_tests']
        if expected_names is not None:
            observation = m.native_observation(texts['stdout'], expected_names)
            valid = row['exit_code'] == 0 and observation['valid']
            if valid:
                m.require(row.get('native_observation') == observation['projection']
                          and 'native_result_error' not in row, 'C2 native receipt/raw projection')
            else:
                m.require('native_observation' not in row and 'native_result_error' in row,
                          'failed C2 native target promoted')
            derived_pass = derived_pass and valid
            observation.update(target=name, target_passed=derived_pass, expected=len(expected_names),
                               timed_out=row['timed_out'], exit_code=row['exit_code'],
                               timeout_seconds=row['timeout_seconds'])
            native.append(observation)
        if name.startswith('metadata-') and derived_pass:
            metadata = m.decode(texts['stdout'])
            workspace = m.REPO + ('/tests/fuzz' if name == 'metadata-fuzz' else '/trillionnium')
            m.require(metadata['version'] == 1 and metadata['workspace_root'] == workspace
                      and metadata['target_directory'] == m.TARGET, 'C2 metadata actual workspace/target')
        m.require(row['passed'] is derived_pass, 'C2 pass/fail differs from retained exit/logs: ' + name)
        if (name == 'preflight' or name.endswith('-version') or name.startswith('metadata-')) and not derived_pass:
            m.require(commands[-1]['name'] == name, 'C2 proceeded beyond refused prerequisite')
    complete = len(commands) == 14
    group_passed = complete and all(row['passed'] for row in commands) and summary['fatal'] is None
    m.require(summary['complete'] is complete and summary['not_started'] == list(NAMES[len(commands):])
              and summary['all_selected_commands_passed'] is group_passed, 'C2 summary completion projection')
    if not complete:
        m.require(summary['fatal'] is not None or summary['stopped_reason'] is not None,
                  'incomplete C2 group lacks stop/fatal observation')
    m.check_export_scope(packet, 'c2', C2, summary)
    clippy = next((row for row in commands if row['name'] == 'strict-workspace-clippy'), None)
    result = {'schema': 'TRNM-C2-DESKTOP-EVIDENCE-VERIFICATION1', 'verified': True, 'source': identity,
              'archive_sha256': packet['receipt']['sha256'], 'original_C1_archive_sha256': original['receipt']['sha256'],
              'readback_subset_archive_sha256': readback['receipt']['sha256'],
              'witness_v5_subset_archive_sha256': witness['receipt']['sha256'],
              'planned_commands': 14, 'commands_recorded': len(commands), 'planned_native_executions': 8,
              'source_entries': 27912, 'source_bytes': 2554108569,
              'exact_C1_to_C2_changed_paths': actual_changes, 'C1_to_C2_byte_delta': 1880,
              'source_rows_bound_to_original_snapshot_and_three_fixed_Git_deltas': True,
              'original_C1_full_Git_blob_verification': original['verification']['git_blob_verification'],
              'complete': complete, 'all_selected_commands_passed': group_passed,
              'failed_commands': [row['name'] for row in commands if not row['passed']],
              'not_started': summary['not_started'], 'strict_clippy_passed': clippy['passed'] if clippy else None,
              'native_targets': native, 'passed_complete_target_executions':
                  sum(row['expected'] for row in native if row['target_passed']),
              'actual_named_ok_including_partial_targets': sum(len(row['completed_ok_names']) for row in native),
              'C1_original_group_passed': False, 'C1_readback_subset_complete': readback['verification']['remaining_subset_complete'],
              'C1_witness_v5_subset_complete': witness['verification']['remaining_subset_complete'],
              'private_target_reused_from_closed_C1_group': True, 'clean_build_claimed': False,
              'native_run_is_not_hosted_ci': True, 'host_or_execution_attestation_claimed': False,
              'independent_security_property_count': None, 'partial_ok_is_not_a_target_pass': True,
              'whole_chain_pq_qualified': False, 'production_activation': False, 'workloads_rerun': False}
    packet['verification'] = result
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--readback-archive', type=Path, required=True)
    parser.add_argument('--readback-receipt', type=Path, required=True)
    parser.add_argument('--witness-v5-archive', type=Path, required=True)
    parser.add_argument('--witness-v5-receipt', type=Path, required=True)
    parser.add_argument('--subset-verifier', type=Path, default=Path(__file__).with_name('verify_desktop_subsets.py'))
    parser.add_argument('--output', type=Path)
    # Only the fixed companion defines the original-packet arguments and helpers.
    initial, _ = parser.parse_known_args()
    m = load_subset_verifier(initial.subset_verifier)
    m.original_arguments(parser)
    args = parser.parse_args()
    expected = m.load_expected(args.expected_plan)
    original = m.verify_original(args)
    readback = m.verify_subset('readback', args.readback_archive, args.readback_receipt, original, expected)
    witness = m.verify_subset('witness-v5', args.witness_v5_archive, args.witness_v5_receipt, original, expected)
    packet = verify(m, args, original, readback, witness, expected)
    m.write_result(packet['verification'], args.output)


if __name__ == '__main__':
    main()
