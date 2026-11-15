#!/usr/bin/env python3
"""Read-only triage of exact 8327 workflow failures and original retained data.

This replays Python report readers, not native work/state verification. No
budget, source, qualification, or failed result is modified.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ART = HERE / 'artifacts'
SOURCE = HERE / 'source'
sys.path[:0] = [str(SOURCE / 'scripts'), str(SOURCE / 'scripts/ci')]
import pon_public_v3_phase_read as phase_reader
import run_from_zero_native as native

HEAD = '8327719ebd90ad08c1d66bc10f6c6fd79d7c0b47'
TREE = '7b3bf58b08cf59ba1466059f3e0d5a7d8a96e74a'
MERGE = 'a7169139ce2a24f0d582ac348be8f74d56d44f9f'
CHECKS = 0


def check(ok, label):
    global CHECKS
    CHECKS += 1
    if not ok:
        raise AssertionError(label)


def read(path):
    return native.json_load(path.read_bytes())


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def rejected(call):
    try:
        value = call()
    except (ValueError, OSError, KeyError, TypeError) as error:
        return {'outcome': 'rejected', 'error': str(error), 'exception': type(error).__name__}
    return {'outcome': 'accepted', 'value': value}


def validate_files(root, inventory):
    count = 0
    for relative, expected in inventory.items():
        path = root / relative
        check(path.resolve().is_relative_to(root.resolve()) and path.is_file() and not path.is_symlink(), 'FILE_PATH')
        check(sha(path) == expected, 'FILE_SHA:' + relative)
        count += 1
    return count


def database(path, ids):
    connection = sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True)
    check(connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'SQLITE_INTEGRITY')
    active = connection.execute('SELECT b.height,a.tip,a.generation,b.chainwork FROM active a JOIN blocks b ON a.tip=b.id').fetchone()
    blocks = connection.execute('SELECT height,id FROM blocks ORDER BY height').fetchall()
    check(active is not None and blocks, 'SQLITE_ROWS')
    for height, block in blocks:
        if height:
            check(ids[height] == block.hex(), 'ONLY_EXPECTED_HONEST_BLOCK_IDS')
    connection.close()
    return {'active_height': active[0], 'active_tip': active[1].hex(), 'generation': active[2],
            'active_chainwork': active[3].hex(), 'stored_height_max': max(h for h, _ in blocks),
            'stored_heights': [h for h, _ in blocks], 'sha256': sha(path),
            'integrity_check': 'ok', 'all_non_genesis_ids_are_expected_honest_ids': True}


def compact_history(rows):
    output = []
    for row in rows:
        response = row.get('response') or {}
        value = response.get('value') or {}
        imported = row.get('client_import') or {}
        output.append({
            'status': row.get('status'), 'error': row.get('error'),
            'started_ns': row.get('started_ns'), 'ended_ns': row.get('ended_ns'),
            'returned_after_window': row.get('returned_after_window'),
            'complete_page': value.get('complete'), 'packet_count': len(value.get('packets', [])),
            'client_import': imported,
        })
    return output


def original_campaign():
    root = ART / '13080886111'
    inventory = read(root / 'artifact-files.json')
    check(len({x['path'] for x in inventory['files']}) == len(inventory['files']), 'UNIQUE_INVENTORY')
    hashes = {x['path']: x['sha256'] for x in inventory['files']}
    verified = validate_files(root, hashes)
    for item in inventory['files']:
        check((root / item['path']).stat().st_size == item['bytes'], 'INVENTORY_BYTES')
    result = read(root / 'results.json')
    check(result == read(HERE / 'original-campaign-results-from-joblog.json'), 'JOB_LOG_RESULTS_EQUAL_ARTIFACT')
    check(result['expected_head'] == HEAD and result['expected_tree'] == TREE, 'ORIGINAL_SOURCE')
    check(result['build']['returncode'] == 0 and result['build']['complete_success'] is True, 'ORIGINAL_BUILD_PASSED')
    check(sha(root / result['binary']['retained']) == result['binary']['sha256_before'] == result['binary']['sha256_after'], 'ORIGINAL_BINARY')
    runs = []
    for attempt in result['attempts']:
        number = attempt['number']
        base = root / attempt['report_directory']
        raw = read(base / 'report.json')
        expected = read(root / f'run-{number}-phase-readback.json')
        derived = phase_reader.read_report(base / 'report.json', attempt['report_sha256'], result['expected_public_policy_id'])
        # read_report echoes its input filesystem path, the sole relocation field.
        check(derived['input']['report'] == str(base / 'report.json'), 'LOCAL_INPUT_PATH')
        derived['input']['report'] = expected['input']['report']
        check(derived == expected, 'EXACT_READER_REDERIVATION')
        ids = {i + 1: entry['id'] for i, entry in enumerate(raw['preparation']['seed'] + raw['preparation']['business'])}
        phases = []
        for phase, summary in zip(raw['phases'], derived['phases']):
            mode = phase['mode']
            receiver = database(base / mode / 'receiver/native.sqlite', ids)
            client = database(base / mode / 'independent-client/native.sqlite', ids)
            check(receiver['active_tip'] == phase['final_receiver_tip'], 'RECEIVER_ACTIVE_TIP')
            check(client['active_tip'] == phase['final_client_tip'], 'CLIENT_ACTIVE_TIP')
            by_role = summary['receiver']['by_observed_body_role']
            attack = by_role.get('attack_submit', {})
            flow = phase['final_actual_flow']
            service = phase['service_outcome'].get('Ok') or {}
            phases.append({
                'mode': mode, 'duration_seconds': phase['duration_seconds'],
                'finite_phase_criteria_met': phase['finite_phase_criteria_met'],
                'scheduled_confirmation_rounds': summary['scheduled_confirmation_rounds'],
                'observed_confirmation_rounds': summary['observed_confirmation_rounds'],
                'confirmed_rounds': summary['confirmed_rounds'],
                'unobserved_scheduled_rounds': summary['unobserved_scheduled_rounds'],
                'submissions_acknowledged_on_time': summary['submissions']['acknowledged_on_time'],
                'submissions_acknowledged_after_window': summary['submissions']['acknowledged_after_window'],
                'full_work_accepted': phase['full_work_accepted'],
                'full_work_failed': phase['full_work_failed'],
                'attack_work_outcomes': attack.get('full_work_outcomes', {}),
                'attack_call_statuses': summary['attack_calls']['status_counts'],
                'attack_acknowledged_on_time': summary['attack_calls']['acknowledged_on_time'],
                'attack_acknowledged_after_window': summary['attack_calls']['acknowledged_after_window'],
                'receiver': receiver, 'independent_client': client,
                'receiver_client_state_equal': phase['receiver_client_state_equal'],
                'verifier_errors': phase['verifier_errors'],
                'history': compact_history(phase['history']),
                'observer_complete': phase['observer_complete'],
                'attacker_processes_requested': phase['attacker_processes_requested'],
                'attacker_processes_ready': phase['attacker_processes_ready'],
                'actor_reports_successful_without_cap_or_kill': phase['actor_reports_successful_without_cap_or_kill'],
                'genuine_budget_depletion_observed': phase['genuine_budget_depletion_observed'],
                'final_cpu_meter': phase['final_meter'], 'final_actual_flow': flow,
                'service_resource_counts': {k: service.get(k) for k in (
                    'mutation_cpu_refusals', 'mutation_cpu_clock_failures', 'mutation_cpu_in_flight_after_shutdown',
                    'work_started', 'work_finished', 'work_failed', 'mutation_full_work_cpu_ns',
                    'mutation_dispatch_excluding_work_cpu_ns')},
                'whole_parent_phase_cpu_ns': phase['whole_parent_phase_cpu_ns'],
                'whole_parent_phase_wall_ns': phase['whole_parent_phase_wall_ns'],
                'receiver_and_verifier_setup_cpu_ns': phase['receiver_and_verifier_setup_cpu_ns'],
                'receiver_and_verifier_setup_wall_ns': phase['receiver_and_verifier_setup_wall_ns'],
                'host_context': phase['phase_process_context'],
                'public_resource_policy': phase['public_resource_policy'],
                'client_native_history_stage_totals': phase['client_native_history_arithmetic_after']['stages'],
                'nested_stage_times_additive': False,
            })
        runs.append({'number': number, 'native_returncode': attempt['step']['returncode'],
                     'elapsed_seconds': attempt['step']['elapsed_seconds'],
                     'outer_timeout_seconds': attempt['step']['outer_stage_timeout_seconds'],
                     'original_criteria_met': attempt['original_criteria_met'],
                     'phase_startup_errors': attempt['phase_startup_errors'],
                     'report_validation_failure': attempt['report_validation_failure'],
                     'report_sha256': attempt['report_sha256'], 'python_reader_exactly_matches_ci': True,
                     'path_relocation_only': True, 'economics_complete': raw['economics_complete'],
                     'finite_experiment_criteria_met': raw['finite_experiment_criteria_met'], 'phases': phases})
    return {'run_id': 41298626861, 'job_id': 124824740351, 'artifact_id': 13080886111,
            'failure': result['failure'], 'source_head': HEAD, 'source_tree': TREE,
            'build_success': True, 'binary_sha256': result['binary']['sha256_before'],
            'verified_inventory_files': verified, 'finalization_failures': result['finalization_failures'],
            'original_inputs': result['original_inputs'], 'controller_resource_policy': result['expected_resources'],
            'receiver_and_verifier_placement': result['public_phase_placement'], 'runs': runs,
            'failure_class': 'actual_original_native_service_and_depletion_criteria',
            'compile_or_format_failure': False,
            'full_limb_causality_established': False,
            'failure_location': 'public_v3_multiprocess.rs:1758; phase predicates at 1216-1245; ordinary client history imports at 1036-1065',
            'interpretation': 'All three runs preserve 3 scheduled rounds per phase. Only first 7 honest submissions completed, 0/3 rounds confirmed in every phase, including attack-free baseline. No false-work ACK/accept; six attack phases did not show required paid-credit depletion. These logs alone do not establish new-default causality or a historical pass/fail comparison.'}


def required_baseline():
    lanes = [(13080304568, 'protocol-merge', 124825331929), (13080373152, 'protocol-head', 124825331892),
             (13080422819, 'cross-cost-x64', 124825331964), (13080717011, 'cross-cost-arm64', 124825331827)]
    rows = []
    for artifact, lane, job in lanes:
        root = ART / str(artifact)
        path = root / 'from-zero-native'
        manifest = read(path / 'manifest.json')
        count = validate_files(path, manifest['files'])
        check(manifest['source_before'] == manifest['source_after'], 'BASELINE_STABLE_SOURCE')
        check(manifest['source_before']['commit'] in (HEAD, MERGE) and manifest['source_before']['tree'] == TREE, 'BASELINE_SOURCE')
        check(sha(path / 'public_v3_from_zero') == manifest['binary_sha256_before'] == manifest['binary_sha256_after'], 'BASELINE_BINARY')
        service = native.validate_service_report(path / 'native/report.json')
        sustained = native.validate_sustained_report(path / 'native/sustained/report.json')
        check(service == manifest['service_report'], 'BASELINE_SERVICE_REDERIVATION')
        check(sustained == manifest['sustained_report'], 'BASELINE_SUSTAINED_REDERIVATION')
        confirmation_result = rejected(lambda: native.validate_confirmation_report(path / 'confirmation/report.json'))
        check(confirmation_result['outcome'] == 'rejected' and confirmation_result['error'] == 'CONFIRMATION_TARGET', 'BASELINE_CONF_REDERIVATION')
        report = read(path / 'confirmation/report.json')
        ids = {i + 1: native.ConfirmationReportChecks.packet_metadata(packet)[2].hex()
               for i, packet in enumerate(report['signed_honest_packets'])}
        phases = []
        for phase in report['phases']:
            pressure = phase['mode'] == 'from-zero-pressure'
            base = path / 'confirmation' / ('pressure' if pressure else 'baseline')
            summaries = {}
            for key, value in phase.items():
                if not isinstance(value, (list, dict)) and (not isinstance(value, str) or len(value) < 100):
                    summaries[key] = value
            summaries['receiver_database'] = database(base / 'receiver/native.sqlite', ids)
            summaries['independent_client_database'] = database(base / 'independent-client/native.sqlite', ids)
            summaries['verification_errors'] = phase.get('verification_errors')
            # Kept as independent facts: acknowledgments and actual stored/active heights.
            submissions = phase.get('honest_submissions', [])
            summaries['honest_submission_rows'] = len(submissions) if isinstance(submissions, list) else None
            phases.append(summaries)
        rows.append({'artifact_id': artifact, 'job_id': job, 'lane': lane,
                     'source_commit': manifest['source_before']['commit'], 'source_tree': TREE,
                     'format_passed': manifest['format_passed'], 'build_exit_code': manifest['build']['exit_code'],
                     'all_named_tests_passed': manifest['all_named_tests_passed'],
                     'named_tests': [{'name': x['name'], 'passed': x['passed'], 'exit_code': x['process']['exit_code']} for x in manifest['runs']],
                     'failures': manifest['failures'], 'passed': manifest['passed'],
                     'execution_finished': manifest['execution_finished'],
                     'verified_manifest_files': count,
                     'service_and_sustained_readers_exactly_match_ci': True,
                     'confirmation_reader': confirmation_result, 'confirmation_phases': phases,
                     'host_controller': read(root / 'from-zero-native-host/controller-result.json'),
                     'format_copy_exit_code_nonfatal': manifest['format_copy']['exit_code'],
                     'failure_class': 'actual_confirmation_target_under_original_4_second_service_window'})
    return rows


def main():
    pins = read(HERE / 'recent-batch-pin-comparison.json')
    recent = {'run_id': 41298626798, 'jobs': [124824740177, 124824740334, 124824740352, 124824740494],
              'source_verification_passed_before_blob_pins': True,
              'failure_class': 'new_branch_change_stale_exact_source_blob_pins',
              'workflow': '.github/workflows/pon-recent-batch-acceptance.yml',
              'pin_count': len(pins), 'matching': sum(x['head_matches'] for x in pins),
              'mismatches': [x for x in pins if not x['head_matches']],
              'first_failing_pin': next(x for x in pins if not x['head_matches']),
              'native_format_build_tests_executed': False,
              'changed_in_commit': '8d9a7015cadd39780c4a047b5a36e0fd4d5f494b',
              'secondary_finalization_failure': 'sha256sum recent-exact/*.log: No such file or directory because no native stages ran',
              'remediation': 'Update only the two exact blob pins to the reviewed new query-bound source bytes; parent owns changes.'}
    original = original_campaign()
    required = required_baseline()
    joblist = read(HERE / 'run-41298626810-jobs-refresh.json')['jobs']
    report = {'schema': '8327-other-ci-readback-v1', 'generated_utc': datetime.now(timezone.utc).isoformat(),
              'scope': 'Read-only job log and artifact audit; exact pinned Python reader replay; no native admission replay, independent-host authentication, performance causality, or qualification claim.',
              'source': {'head': HEAD, 'tree': TREE, 'merge': MERGE},
              'artifact_integrity': read(HERE / 'artifact-integrity.json'),
              'recent_batch': recent, 'original_campaign': original, 'required_baseline_failures': required,
              'required_baseline_snapshot': [{'job_id': x['id'], 'name': x['name'], 'status': x['status'], 'conclusion': x['conclusion']} for x in joblist],
              'checks': CHECKS, 'source_or_budget_modified_by_this_analysis': False,
              'work_hardness_accepted': False, 'public_service_qualified': False, 'production_activation': False}
    output = HERE / 'triage-report.json'
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'report': str(output), 'bytes': output.stat().st_size, 'sha256': sha(output), 'checks': CHECKS,
                      'recent_pin_mismatches': len(recent['mismatches']), 'original_phases': sum(len(x['phases']) for x in original['runs']),
                      'required_failed_jobs': len(required)}, ensure_ascii=False))
    for run in original['runs']:
        for p in run['phases']:
            print('ORIGINAL', run['number'], p['mode'], 'ACK', p['submissions_acknowledged_on_time'],
                  'conf', p['confirmed_rounds'], '/', p['scheduled_confirmation_rounds'],
                  'stored/active', p['independent_client']['stored_height_max'], '/', p['independent_client']['active_height'],
                  'reject', p['full_work_failed'], 'errors', p['verifier_errors'])
    for lane in required:
        print('REQUIRED', lane['lane'], lane['failures'], [(p['mode'], p['client_confirmed_transactions'],
              p['independent_client_database']['stored_height_max'], p['independent_client_database']['active_height']) for p in lane['confirmation_phases']])


if __name__ == '__main__':
    main()
