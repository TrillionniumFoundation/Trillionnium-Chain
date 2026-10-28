#!/usr/bin/env python3
"""Read retained original GitHub ZIP; no fixture or runtime execution occurs here."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

HERE = Path(__file__).resolve().parent
HEAD = 'afc8d6dcb11168fa5d9799222c99dba2424dd520'
TREE = '473a6ff2a297a635c9e72b245b3bba4e84900a21'
ZIP_SHA = '02022560d614dcee8343b1a7683a45942e50697a1e56c0decdda8f374f1b63cc'
BINARY_SHA = '9855feed4ce0fb9f4142c16d43e3f2449140e8718b61cb48177f5a34b6064a6c'
PREFIX = 'store::history_effect_v6::tests::'
HELPER = PREFIX + 'history_effect_v6_process_child_helper'
ROSTER = sorted(PREFIX + name for name in [
    'history_effect_v6_process_child_helper',
    'history_publication_durable_unacknowledged_crash_repairs_and_resumes',
    'history_publication_final_directory_fsync_crash_repairs_and_resumes',
    'history_publication_pending_file_fsync_crash_repairs_and_resumes',
    'history_publication_pending_unlink_crash_repairs_and_resumes',
    'history_publication_two_hardlinks_crash_repairs_and_resumes',
    'publication::original_frame_and_physical_tail_refusals_preserve_every_byte',
    'settled_epoch::expired_old_budget_needs_fresh_close_authorization_then_separate_renewal',
    'settled_epoch::settled_activation_epoch_sigkill_requires_fresh_charge_then_resumes',
    'settled_epoch::settled_epoch_recovery_record_survives_every_publication_cut_and_retry',
    'v6_actual_sigkill_after_activation_commit_recovers_and_advances_again',
    'v6_actual_sigkill_during_registered_worker_recovers_with_fresh_claims',
    'v6_actual_two_worker_cancel_retry_close_and_cold_reopen_keep_predebits',
    'v6_late_journal_lock_failure_keeps_actual_native_and_original_cpu',
    'v6_unmarked_existing_bad_product_is_not_validated_by_sql_syntax',
    'v6_unsigned_worker_host_and_delegated_nonce_refuse_without_new_authority',
])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    archive = (HERE / 'artifact-12785735566.zip').read_bytes()
    assert len(archive) == 2596150 and digest(archive) == ZIP_SHA
    with zipfile.ZipFile(HERE / 'artifact-12785735566.zip') as z:
        manifest = json.loads((HERE / 'artifact-members.json').read_text())
        actual_members = [{'path': i.filename, 'bytes': i.file_size,
                           'compressed_bytes': i.compress_size, 'mode': i.external_attr >> 16,
                           'sha256': digest(z.read(i))} for i in z.infolist()]
        assert manifest['members'] == actual_members and len(actual_members) == 1196
        load = lambda path: json.loads(z.read(path))
        source = load('execution/source-before.json')
        assert source == load('execution/source-after.json') == load('final-source.json')
        assert source['tested_commit'] == HEAD and source['tested_tree'] == TREE
        assert source['tracked_worktree_verified'] and source['tracked_entries'] == 5228
        terminal = load('execution/terminal.json')
        assert terminal['passed'] and terminal['source_stable'] and terminal['binary_stable']
        assert terminal['expected_source'] == HEAD and terminal['binary_sha256'] == BINARY_SHA
        assert terminal['runtime_burst_ns'] == 2_000_000_000
        assert terminal['fixture_operation_allowance_ns'] == 4_000_000_000
        assert terminal['complete_parent_snapshot_attempts'] == 4
        assert terminal['native']['budget_seconds'] == terminal['native_test_budget_seconds'] == 600
        assert terminal['original_local_full_suite_budget_seconds'] == 600
        assert terminal['native']['elapsed_seconds'] < 600
        assert terminal['native']['actual_wait4_status'] == 0
        assert terminal['native']['passed'] and terminal['native']['exact_fifteen_pass_one_ignored']
        native_raw = z.read('execution/native/native.log')
        native = native_raw.decode()
        assert digest(native_raw) == terminal['native']['log_sha256']
        assert native.splitlines().count('running 16 tests') == 1
        assert sorted(re.findall(r'^test (' + re.escape(PREFIX) + r'\S+) \.\.\. ', native, re.M)) == ROSTER
        summaries = re.findall(r'^test result: .+$', native, re.M)
        assert len(summaries) == 1
        assert re.fullmatch(r'test result: ok\. 15 passed; 0 failed; 1 ignored; 0 measured; 734 filtered out; finished in .+s', summaries[0])
        assert f'test {HELPER} ... ignored' in native
        build = [json.loads(line) for line in z.read('execution/build/native.log').decode().splitlines()
                 if line.startswith('{')]
        artifacts = [row for row in build if row.get('target', {}).get('name') == 'trnm_pon_node'
                     and row.get('executable')]
        assert len(artifacts) == 1
        profile = artifacts[0]['profile']
        assert profile == {'opt_level': '3', 'debuginfo': 0, 'debug_assertions': False,
                           'overflow_checks': False, 'test': True}
        assert artifacts[0]['executable'] == terminal['binary']
        guardians = []
        for path in z.namelist():
            if not path.endswith('/guardian-result.json'):
                continue
            row = load(path)
            assert row['passed'] and row['actual_wait4'] and row['wait_status'] == 9
            assert row['binary_sha256'] == BINARY_SHA and row['fixture_selector'] == HELPER
            if 'closed_process' in row:
                assert row['closed_process']['actual_wait4'] and row['closed_process']['signal'] == 9
                assert row['closed_process']['executable_sha256'] == BINARY_SHA
            else:
                assert row['native_operation_started'] is False
                assert row['new_cpu_epoch_created'] is False
                assert row['v6_closed_process_receipt_created'] is False
            assert len(row['complete_parent_observations']) <= 4
            assert row['complete_matching_parent_snapshots'] == 2
            assert row['historical_process_tree_observed'] is False
            guardians.append({'path': path, 'sha256': digest(z.read(path)), 'cutpoint': row['cutpoint'],
                              'owned_child_pid': row['owned_child_pid'], 'actual_wait4': True,
                              'signal': 9, 'v6_closed_process_receipt': 'closed_process' in row,
                              'snapshot_attempts': len(row['complete_parent_observations'])})
        assert len(guardians) == 23
        processes = []
        startup_receipts = []
        for path in z.namelist():
            if not path.endswith('/process-result.json'):
                continue
            row = load(path)
            assert row['binary_sha256'] == BINARY_SHA and row['original_records_unchanged']
            assert row['duplicate_recovery_error'] == 'HISTORY_V6_JOURNAL_ROLLBACK'
            cold = row['finished']['cold_journal']
            assert cold['epoch'] is None and cold['pending'] is None
            processes.append({'path': path, 'cutpoint': row['cutpoint'], 'cold_journal': cold,
                              'frontier': row['finished']['frontier'], 'marker_count': row['finished']['marker_count']})
            prefix = path.removesuffix('process-result.json') + 'v6-journal/'
            frames = sorted(n for n in z.namelist() if n.startswith(prefix)
                            and re.fullmatch(r'\d{20}-[0-9a-f]{64}\.json', n.rsplit('/', 1)[1]))
            previous = '0' * 64
            operations = {}
            for sequence, name in enumerate(frames, 1):
                raw = z.read(name)
                frame = json.loads(raw)
                assert digest(raw) == name.rsplit('-', 1)[1].removesuffix('.json')
                assert frame['sequence'] == sequence and frame['previous'] == previous
                previous = digest(raw)
                event = frame['event']
                if event['kind'] == 'intent':
                    op = json.loads(bytes(event['signed']))['body']
                    operations[op['operation_id']] = op
                elif event['kind'] == 'settlement':
                    op = operations[event['operation']]
                    if op['purpose'] == 'startup':
                        assert event['native_error'] is None and not event['cpu']['accounting_unavailable']
                        assert not event['cpu']['live_refused']
                        startup_receipts.append({'case': row['cutpoint'], 'frame': name,
                                                 'request_nonce': op['request_nonce'], 'cpu': event['cpu']})
            assert cold['anchor'] == {'sequence': len(frames), 'digest': previous}
        assert len(processes) == 14 and len(startup_receipts) == 28
        report = {'schema': 'history-hosted-independent-archive-readback-v1',
                  'run_id': 40615369561, 'job_id': 122576500317, 'artifact_id': 12785735566,
                  'artifact_sha256': ZIP_SHA, 'source': source, 'binary_sha256': BINARY_SHA,
                  'build_profile': profile, 'native_summary': summaries[0],
                  'native_elapsed_seconds': terminal['native']['elapsed_seconds'],
                  'original_native_budget_seconds': 600, 'runtime_burst_ns': 2_000_000_000,
                  'operation_allowance_ns': 4_000_000_000, 'parent_snapshot_limit': 4,
                  'guardians': guardians, 'completed_process_windows': processes,
                  'startup_receipts': startup_receipts, 'passed': True,
                  'binary_bytes_in_artifact': False, 'runtime_tests_executed_by_this_readback': False,
                  'new_startup_callback_and_seal_candidate_qualified': False,
                  'whole_history_p0_closed': False, 'production_qualified': False}
        (HERE / 'readback.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'process_windows': len(processes), 'guardians': len(guardians),
                          'startup_receipts': len(startup_receipts), 'summary': summaries[0]}))


if __name__ == '__main__':
    main()
