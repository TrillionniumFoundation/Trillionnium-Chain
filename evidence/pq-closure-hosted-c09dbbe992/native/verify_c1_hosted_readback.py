#!/usr/bin/env python3
"""Read the fixed C1 packet and original ZIPs; no test or source is executed."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
HEAD = 'c09dbbe9921da12db8bf7240a8a95a0e9a789e50'
TREE = 'f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6'
PACKET_SHA = '90f8da399cda835849001e5c65a49d0d8cc2a4b09e191e6c8b73dddbfb275456'
ZIP_IDENTITIES = {
    'campaign': ('campaign-901.zip', 70936486, '078f427e72d34dc1b0a96f13d16a231d78e9c949656ae57b1fe52665c91cfebe'),
    'cost-arm64': ('cost-arm64-901.zip', 9018574, 'e9236a8d2bb85e343d1faa842a2b0e463593a7f7445649513eb835a369707de5'),
    'cost-x64': ('cost-x64-901.zip', 9298938, 'ceeaca9e857020eec7dc948e2a2b92ee5aa3e2bbf208270779fceb1284811946'),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def save_new(name, obj):
    with (ROOT / name).open('x') as stream:
        json.dump(obj, stream, indent=2, sort_keys=True)
        stream.write('\n')


def main():
    packet = ROOT / 'readback-1.tar.xz'
    assert packet.stat().st_size == 1850508 and file_digest(packet) == PACKET_SHA
    with tarfile.open(packet, 'r:xz') as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        assert len(set(names)) == len(names)
        for m in members:
            assert m.isfile() and not PurePosixPath(m.name).is_absolute() and '..' not in PurePosixPath(m.name).parts
        inventory = json.load(archive.extractfile('packet-files.json'))
        assert set(names) == {r['path'] for r in inventory} | {'packet-files.json', 'SHA256SUMS'}
        assert len({r['path'] for r in inventory}) == len(inventory)
        for row in inventory:
            raw = archive.extractfile(row['path']).read()
            assert len(raw) == row['bytes'] and digest(raw) == row['sha256']
        sums = ''.join(f"{r['sha256']}  {r['path']}\n" for r in inventory).encode()
        assert archive.extractfile('SHA256SUMS').read() == sums
        for kind, (filename, size, expected_sha) in ZIP_IDENTITIES.items():
            path = ROOT / filename
            assert path.stat().st_size == size and file_digest(path) == expected_sha
            with zipfile.ZipFile(path) as z:
                index = {r['path']: r for r in json.load(archive.extractfile(kind + '/zip-member-index.json'))}
                for row in inventory:
                    prefix = kind + '/raw/'
                    if row['path'].startswith(prefix):
                        original_name = row['path'][len(prefix):]
                        assert row['sha256'] == index[original_name]['sha256']
                        assert z.read(original_name) == archive.extractfile(row['path']).read()
    packet_verification = {
        'schema': 'c1-native-packet-independent-verification-v1',
        'observed_utc': datetime.now(timezone.utc).isoformat(),
        'packet_sha256': PACKET_SHA, 'packet_bytes': packet.stat().st_size,
        'all_packet_members_regular_and_unique': True, 'indexed_files_verified': len(inventory),
        'complete_packet_index_coverage': True, 'all_retained_raw_members_equal_original_zip': True,
        'all_three_original_zips_match_fixed_github_digest': True,
        'native_tests_run': 0, 'old_315_outcomes_used': False,
    }
    save_new('packet-independent-verification.json', packet_verification)
    campaign = []
    logged = read_json(ROOT / 'original-campaign-result-from-log.json')
    with zipfile.ZipFile(ROOT / 'campaign-901.zip') as z:
        results = json.loads(z.read('results.json'))
        assert results == logged
        assert results['expected_head'] == HEAD and results['expected_tree'] == TREE
        for attempt in results['attempts']:
            n = attempt['number']
            member = f'run-{n}-raw/report.json'
            raw = z.read(member)
            assert digest(raw) == attempt['report_sha256']
            report = json.loads(raw)
            projected = read_json(ROOT / f'readback-1/campaign/projections/run-{n}-report.json')
            assert projected['source_sha256'] == digest(raw) and projected['source_bytes'] == len(raw)
            phase_rows = []
            for i, phase in enumerate(report['phases']):
                kept = projected['phases'][i]['retained_original_field_values']
                for key, value in kept.items():
                    if key != 'history_field_projections':
                        assert phase[key] == value
                samples = phase['budget_samples']
                meter_samples = [row.get('meter', {}).get('Ok') for row in samples]
                known = [m for m in meter_samples if isinstance(m, dict) and type(m.get('depleted')) is bool]
                credits = [m['actual_flow']['remaining_paid_credit_ns'] for m in known
                           if isinstance(m.get('actual_flow'), dict)]
                confirmations = phase['confirmations']
                phase_rows.append({
                    'mode': phase['mode'], 'window_seconds': phase['duration_seconds'],
                    'finite_phase_criteria_met': phase['finite_phase_criteria_met'],
                    'scheduled_rounds': 3, 'observed_rounds': len(confirmations),
                    'confirmed_rounds': sum(row['confirmed_inside_pressure_window'] is True for row in confirmations),
                    'confirmations': confirmations,
                    'receiver_client_state_equal': phase['receiver_client_state_equal'],
                    'verifier_errors': phase['verifier_errors'],
                    'genuine_budget_depletion_observed': phase['genuine_budget_depletion_observed'],
                    'depletion_at_ns': phase['depletion_at_ns'],
                    'budget_samples': len(samples), 'known_depletion_samples': len(known),
                    'unknown_or_error_depletion_samples': len(samples) - len(known),
                    'depleted_samples': sum(m['depleted'] for m in known),
                    'minimum_sampled_remaining_paid_credit_ns': min(credits) if credits else None,
                    'start_reserve_ns': phase['initial_meter']['start_reserve_ns'],
                    'final_actual_flow': phase['final_actual_flow'],
                    'observer_complete': phase['observer_complete'],
                    'service_outcome': phase['service_outcome'],
                    'attacker_processes_ready': phase['attacker_processes_ready'],
                    'attacker_processes_requested': phase['attacker_processes_requested'],
                    'actor_reports_successful_without_cap_or_kill': phase['actor_reports_successful_without_cap_or_kill'],
                    'full_work_accepted': phase['full_work_accepted'],
                    'full_work_failed': phase['full_work_failed'],
                })
            campaign.append({'run_number': n, 'raw_report_member': member,
                'raw_report_bytes': len(raw), 'raw_report_sha256': digest(raw),
                'economics_complete': report['economics_complete'],
                'finite_experiment_criteria_met': report['finite_experiment_criteria_met'],
                'process_returncode': attempt['step']['returncode'],
                'process_elapsed_seconds': attempt['step']['elapsed_seconds'],
                'phases': phase_rows})
    costs = []
    for arch in ('arm64', 'x64'):
        with zipfile.ZipFile(ROOT / f'cost-{arch}-901.zip') as z:
            manifest_raw = z.read('from-zero-native/manifest.json')
            manifest = json.loads(manifest_raw)
            assert manifest['source_before'] == manifest['source_after']
            assert manifest['source_after']['commit'] == HEAD and manifest['source_after']['tree'] == TREE
            raw = z.read('from-zero-native/confirmation/report.json')
            acceptance = manifest['terminal']['acceptance_stages']['confirmation_report']
            assert digest(raw) == acceptance['before_validation']['sha256'] == acceptance['retained_report']['sha256']
            report = json.loads(raw)
            phases = []
            for phase in report['phases']:
                fields = ('mode', 'workers', 'requested_window_ns', 'finite_business_target_met',
                    'invariant_target_met', 'client_confirmed_transactions', 'client_confirmed_before_original_window_end',
                    'client_confirmation_latency_ns', 'confirmation_ended_ns', 'full_native_state_equal',
                    'verification_errors', 'accounting_closed', 'no_attack_accepted', 'overlap_demonstrated',
                    'receiver_matches_valid_honest_prefix')
                phases.append({**{key: phase[key] for key in fields},
                    'replay_attempts': len(phase['independent_history_page_replay']),
                    'failed_or_deadline_replays': [{key: value for key, value in row.items() if not isinstance(value, (dict, list))}
                        for row in phase['independent_history_page_replay'] if row['replay_accepted'] is False],
                })
            costs.append({'architecture': arch,
                'manifest_member': 'from-zero-native/manifest.json', 'manifest_sha256': digest(manifest_raw),
                'confirmation_report_member': 'from-zero-native/confirmation/report.json',
                'confirmation_report_bytes': len(raw), 'confirmation_report_sha256': digest(raw),
                'format_passed': manifest['format_passed'], 'source_recompiled': manifest['source_recompiled'],
                'all_named_tests_passed': manifest['all_named_tests_passed'],
                'native_invocations': manifest['terminal']['native_invocations'],
                'native_execution_completed': manifest['terminal']['native_execution_completed'],
                'acceptance_stages': manifest['terminal']['acceptance_stages'],
                'execution_finished': manifest['execution_finished'],
                'finalization_completed': manifest['terminal']['finalization_completed'],
                'passed': manifest['passed'], 'failures': manifest['failures'],
                'original_finite_target_met': report['finite_target_met'],
                'original_invariant_target_met': report['invariant_target_met'], 'phases': phases})
    diagnosis = {
        'schema': 'c1-hosted-native-diagnosis-v1',
        'observed_utc': datetime.now(timezone.utc).isoformat(),
        'source_head': HEAD, 'source_tree': TREE, 'source_kind': 'head', 'pr': 901,
        'campaign_run_id': 42955583039, 'campaign_job_id': 130309763995,
        'cost_run_id': 42955583052, 'cost_job_ids': {'arm64': 130309764639, 'x64': 130309764652},
        'classification': {
            'campaign': 'actual original finite campaign criteria failed; build/startup/source/report preservation succeeded',
            'cost': 'native invariant tests passed, then unchanged confirmation business-target acceptance correctly failed',
        },
        'campaign': campaign, 'costs': costs,
        'no_deadline_budget_or_acceptance_threshold_changed': True,
        'native_executions_started_by_this_diagnosis': 0, 'old_315_outcomes_used': False,
        'full_chain_pq_or_release_qualification_inferred': False,
        'scope': 'one-host controlled finite experiments; no WAN, independent operator, quantum mining or lifetime composition qualification',
        'packet': {'path': 'readback-1.tar.xz', 'bytes': 1850508, 'sha256': PACKET_SHA},
    }
    save_new('native-diagnosis-c09dbbe992.json', diagnosis)
    print(json.dumps({'packet_verification': packet_verification,
        'diagnosis': str(ROOT / 'native-diagnosis-c09dbbe992.json'),
        'campaign_phases': sum(len(r['phases']) for r in campaign),
        'cost_architectures': len(costs), 'native_tests_run': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
