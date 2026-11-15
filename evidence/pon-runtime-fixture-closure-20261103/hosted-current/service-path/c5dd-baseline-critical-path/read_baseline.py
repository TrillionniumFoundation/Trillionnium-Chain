#!/usr/bin/env python3
"""Read existing immutable c5dd campaign records; never run native code."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

HERE = Path(__file__).resolve().parent
ARCHIVE = Path('/workspace/scratch/b5a148b09b11/next-hosted/c5dd7c-review/c5dd7c-original-campaign-13276003536.zip')
EXPECTED_ARCHIVE = '78e1b41ced06d6b77568a132d60623a1a7b5059ef9791dd43cc8ed4110efaacb'
COMMIT = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
REPO = Path('/workspace/scratch/b5a148b09b11/fixture-committed-check')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(name, value):
    with (HERE / name).open('x') as target:
        json.dump(value, target, ensure_ascii=False, indent=2)
        target.write('\n')


def selected(value, keys):
    return {key: value.get(key) for key in keys}


def phases(rows):
    return [row for row in rows if row['started']]


def observer_match(observed, digest):
    matches = [row for row in observed if row['body_digest'] is not None
               and bytes(row['body_digest']).hex() == digest]
    assert len(matches) == 1, (digest, len(matches))
    return matches[0]


def receiver_fields(row):
    result = selected(row, ['connection_id', 'operation', 'complete', 'connection_closed',
                           'observation_failed', 'dispatch_started', 'dispatch_accepted',
                           'dispatch_error_code', 'dispatch_thread_cpu_ns', 'full_work_started',
                           'full_work_accepted', 'full_work_thread_cpu_ns', 'challenge_wait',
                           'grant_wait', 'paid_task_queue_wait', 'response_write',
                           'response_frame_complete', 'error_diagnostics'])
    result['submit_phases'] = phases(row['submit_phases'])
    return result


def actor_stages(j, prefix):
    before, after = j[prefix + '_before'], j[prefix + '_after']
    result = []
    first = {row['stage']: row['totals'] for row in before['stages']}
    assert not before['stage_observation_failed'] and not after['stage_observation_failed']
    for row in after['stages']:
        original = first[row['stage']]
        delta = {key: value - original[key] for key, value in row['totals'].items()}
        assert all(value >= 0 for value in delta.values())
        assert delta['cpu_known_calls'] + delta['cpu_unknown_calls'] == delta['calls']
        result.append({'stage': row['stage'], 'delta': delta})
    return result


def timeline_partition(round_record, events):
    start, end = round_record['started_ns'], round_record['ended_ns']
    spans = sorted((event for event in events if start <= event['started_ns'] < end),
                   key=lambda event: event['started_ns'])
    cursor, uncovered = start, 0
    totals = {}
    for event in spans:
        assert cursor <= event['started_ns'] <= event['ended_ns'] <= end, event
        uncovered += event['started_ns'] - cursor
        cursor = event['ended_ns']
        duration = event['ended_ns'] - event['started_ns']
        totals[event['kind']] = totals.get(event['kind'], 0) + duration
    uncovered += end - cursor
    assert sum(totals.values()) + uncovered == end - start
    return {'round': round_record['round'], 'start_ns': start, 'end_ns': end,
            'actual_round_wall_ns': end - start, 'disjoint_outer_interval_ns': totals,
            'uncovered_control_and_inter_call_gap_ns': uncovered,
            'all_intervals_disjoint_and_inside_round': True,
            'scope': 'Partition of actual same-client outer timestamp intervals; no nested phases, medians, receiver times or CPU are added.'}


def main():
    archive_raw = ARCHIVE.read_bytes()
    assert sha(archive_raw) == EXPECTED_ARCHIVE
    runs = []
    with zipfile.ZipFile(ARCHIVE) as archive:
        for run in range(1, 4):
            entry = f'run-{run}-raw/baseline.json'
            raw = archive.read(entry)
            j = json.loads(raw)
            assert j['mode'] == 'baseline' and j['duration_seconds'] == 30
            assert j['state_backend'] == 'authenticated-v1'
            assert j['attacker_processes_requested'] == j['attacker_processes_ready'] == 0
            observed = j['receiver_observation']['records']
            submissions, history, events, connection_ids = [], [], [], []
            by_block = {}
            for index, row in enumerate(j['submissions']):
                matched = observer_match(observed, row['public_request_body_digest'])
                assert row['status'] == 'ok' and not row['returned_after_window']
                assert matched['operation'] == 1 and matched['dispatch_accepted'] is True
                assert matched['full_work_accepted'] is True
                connection_ids.append(matched['connection_id'])
                block = row['response']['value']['block']
                assert block not in by_block
                by_block[block] = {'submission_index': index, 'packet_index': row['packet_index'],
                                  'height': row['height'], 'receiver_connection_id': matched['connection_id']}
                submissions.append({'index': index, **selected(row, ['packet_index', 'height',
                                    'started_ns', 'ended_ns', 'status', 'error', 'returned_after_window',
                                    'public_request_body_digest', 'recorded_request_digest', 'metrics']),
                                    'response_value': row['response']['value'],
                                    'receiver_digest_match_count': 1, 'receiver': receiver_fields(matched)})
                events.append({'kind': 'submit_network', 'index': index,
                               **selected(row, ['started_ns', 'ended_ns'])})
            for index, row in enumerate(j['history']):
                matched = observer_match(observed, row['public_request_body_digest'])
                assert row['status'] == 'ok' and not row['returned_after_window']
                assert matched['operation'] == 3 and matched['dispatch_accepted'] is True
                connection_ids.append(matched['connection_id'])
                client = row['client_import']
                observation = client['native_import_observation']
                assert observation['measurement_failures'] == 0
                assert len(observation['packets']) == observation['supplied_packets'] == 1
                packet = observation['packets'][0]
                packet_id = bytes(packet['packet_id']).hex()
                assert packet_id == row['response']['value']['next'] and packet_id in by_block
                history.append({'index': index, **selected(row, ['started_ns', 'ended_ns',
                                'status', 'error', 'returned_after_window', 'public_request_body_digest',
                                'recorded_request_digest', 'request', 'metrics']),
                                'complete_page': row['response']['value']['complete'],
                                'packet_id': packet_id, 'matched_submit': by_block[packet_id],
                                'receiver_digest_match_count': 1, 'receiver': receiver_fields(matched),
                                'client_import': selected(client, ['started_ns', 'ended_ns', 'wall_ns',
                                    'thread_cpu_ns', 'thread_cpu_observation_available', 'succeeded', 'error']),
                                'import_outer_phases': phases(observation['phases']),
                                'import_packet_phases': phases(packet['phases']),
                                'host_checks': observation['host_checks'],
                                'client_confirmation': row.get('client_confirmation'),
                                'clock_scope': observation['clock_scope']})
                events.extend([{'kind': 'history_network', 'index': index,
                                **selected(row, ['started_ns', 'ended_ns'])},
                               {'kind': 'client_import', 'index': index,
                                **selected(client, ['started_ns', 'ended_ns'])}])
                if 'client_confirmation' in row:
                    events.append({'kind': 'client_confirmation', 'index': index,
                                   **selected(row['client_confirmation'], ['started_ns', 'ended_ns'])})
            assert len(connection_ids) == len(set(connection_ids)) == 23
            assert len(submissions) == 14 and len(history) == 9
            assert len(j['confirmations']) == 2 and history[6]['complete_page'] is True
            assert history[8]['client_import']['error'] == 'PUBLIC_REQUEST_DEADLINE'
            failed_phases = {row['phase']: row for row in history[8]['import_packet_phases']}
            assert failed_phases['work']['accepted'] is True
            assert failed_phases['admission_prepare']['accepted'] is True
            assert failed_phases['execution']['accepted'] is True
            assert failed_phases['commit']['error_code'] == 'PUBLIC_REQUEST_DEADLINE'
            assert 'submit_result' not in failed_phases
            runs.append({'run': run, 'source_entry': {'path': entry, 'bytes': len(raw), 'sha256': sha(raw)},
                         'state_backend': j['state_backend'], 'observer_complete': j['observer_complete'],
                         'receiver_observer_clock_is_local': j['receiver_observation']['monotonic_epoch_is_observer_local'],
                         'matched_client_requests': 23, 'matched_unique_receiver_connections': 23,
                         'all_history_packet_ids_match_receiver_submit_ack_blocks': True,
                         'rounds': j['confirmations'],
                         'round_timing_partitions': [timeline_partition(r, events) for r in j['confirmations']],
                         'submissions': submissions, 'history': history,
                         'receiver_native_stages': actor_stages(j, 'native_history_arithmetic'),
                         'client_native_stages': actor_stages(j, 'client_native_history_arithmetic'),
                         'actual_result': selected(j, ['finite_phase_criteria_met', 'verifier_errors',
                             'receiver_client_state_equal', 'initial_tip', 'final_receiver_tip',
                             'final_client_tip', 'genuine_budget_depletion_observed'])})
    sources = []
    for path in ['trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs',
                 'trillionnium/crates/trnm-pon-node/tests/support/multiprocess_support.rs',
                 'trillionnium/crates/trnm-pon-node/src/ingress.rs',
                 'trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs',
                 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs']:
        raw = subprocess.run(['git', '--no-replace-objects', 'show', COMMIT + ':' + path],
                             cwd=REPO, check=True, stdout=subprocess.PIPE).stdout
        sources.append({'commit': COMMIT, 'path': path, 'bytes': len(raw), 'sha256': sha(raw)})
    report = {'schema': 'trnm-c5dd-baseline-actor-correlated-critical-path-v1',
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status': 'READBACK_ONLY_ORIGINAL_FAILURES_PRESERVED', 'commit': COMMIT,
              'archive': {'path': str(ARCHIVE), 'bytes': len(archive_raw), 'sha256': EXPECTED_ARCHIVE,
                          'artifact_id': 13276003536},
              'reader': {'path': str(Path(__file__)), 'sha256': sha(Path(__file__).read_bytes())},
              'sources': sources,
              'scope': 'Only the three baseline phases of the original three30s campaigns. No new workload or native execution. Individual client body digests are matched to unique receiver connections; imported packet IDs are matched to original Submit ACK blocks. Observer-local timestamps are not directly merged with phase timestamps. Host CPU sums each invoking thread, while import CPU is caller-only; native stage totals and phase/Host intervals overlap.',
              'source_timing_rules': [
                  'public_v3_multiprocess.rs944-946: capture a single30s absolute import deadline immediately before phase epoch.',
                  'public_v3_multiprocess.rs998-1006: rounds have scheduled t=1,5,9s, but the single sequential loop waits for prior round completion; late start does not reset end.',
                  'public_v3_multiprocess.rs1033-1095: sequential History network fetch, original independent import, then confirmation only after complete-page activation.',
                  'public_v3_multiprocess.rs1154-1160: native before/after snapshots exclude setup/final read_active; include failures/cancellations.',
                  'ingress.rs2537-2576 and ingress/history_import.rs291,385-400: full public import and final activation retain the same original resource/CPU/deadline checks.'
              ],
              'runs': runs, 'performance_acceptance': False, 'source_or_native_mutation': False,
              'claims_not_supported': ['No causal fsync attribution', 'No full/partial graph-per-request decomposition',
                                       'No cache or authorization-check weakening proposed',
                                       'No sum of nested medians, native stages, Host and caller CPU',
                                       'No c5dd-to-b280 measured speedup or regression inference from different executions']}
    save('critical-path-readback.json', report)
    compact = []
    for run in runs:
        complete, last = run['history'][6], run['history'][8]
        activation = next(p for p in complete['import_packet_phases'] if p['phase'] == 'submit_result')
        checkpoint = next(p for p in complete['host_checks'] if p['phase'] == 'checkpoint')
        failed = next(p for p in last['import_packet_phases'] if p['phase'] == 'commit')
        compact.append({'run': run['run'], 'round1': selected(run['rounds'][0], ['started_ns', 'ended_ns']),
                        'round2': selected(run['rounds'][1], ['started_ns', 'ended_ns']),
                        'round2_last_submit_ack_ns': run['submissions'][-1]['ended_ns'],
                        'round2_history': [{**selected(h, ['index', 'started_ns', 'ended_ns', 'packet_id',
                                                        'matched_submit', 'public_request_body_digest']),
                                           'receiver_connection_id': h['receiver']['connection_id'],
                                           'client_import': h['client_import']} for h in run['history'][7:]],
                        'round1_complete_page_import': complete['client_import'],
                        'round1_complete_page_activation': activation,
                        'round1_complete_page_host_checkpoints': checkpoint,
                        'last_failed_commit': failed,
                        'wall_timing_partitions': run['round_timing_partitions']})
    save('small-readback.json', {'scope': report['scope'], 'commit': COMMIT,
                               'readback_sha256': sha((HERE / 'critical-path-readback.json').read_bytes()),
                               'conclusion': 'All three baseline second rounds run out of the original window during independent client commit after accepted W1/M06 and successful History response. The first round already consumed~23.8-23.9s, including~5.48-5.50s complete-page activation; the original sequential loop delays round2. Receiver ACK progress is separate from independent confirmation.',
                               'runs': compact})
    save('artifact-index.json', {'files': {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
                                          for p in sorted(HERE.iterdir()) if p.is_file()}})
    print(json.dumps({'status': report['status'], 'runs': len(runs), 'matched_requests': 69,
                      'all_original_failures_retained': True,
                      'readback_sha256': sha((HERE / 'critical-path-readback.json').read_bytes()),
                      'small_readback_sha256': sha((HERE / 'small-readback.json').read_bytes())}))


if __name__ == '__main__':
    main()
