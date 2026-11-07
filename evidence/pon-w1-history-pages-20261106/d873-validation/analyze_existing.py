#!/usr/bin/env python3
"""Read retained artifacts only. No jobs, tests, source edits, or acceptance changes."""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path('/workspace/scratch/a66f84888260')
ARTIFACTS = ROOT / 'hosted-d873'
OUTPUT = ARTIFACTS / 'latency-diagnosis'
REPO = ROOT / 'chain-integration'
OLD = Path('/workspace/scratch/ab286a535ac8/w1-current-0ca272')
OLD_ZIP = Path('/workspace/scratch/ab286a535ac8/w1-fresh-current-0ca272.zip')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def load(path):
    return json.loads(path.read_text())


def aggregate(rows, fields):
    totals = defaultdict(lambda: defaultdict(int))
    for row in rows:
        if row.get('started') is False:
            continue
        out = totals[row['phase']]
        out['observations'] += 1
        if 'accepted' in row:
            out['accepted_observations'] += row['accepted'] is True
            out['rejected_observations'] += row['accepted'] is False
        for field in fields:
            value = row.get(field)
            if value is not None:
                out[field] += value
            else:
                out[field + '_unknown_observations'] += 1
    return dict(totals)


def summarize_imports(imports):
    observations = [r['native_import_observation'] for r in imports if r.get('native_import_observation')]
    host = aggregate((h for o in observations for h in o['host_checks']),
                     ('calls_started', 'calls_completed', 'calls_accepted', 'calls_rejected',
                      'thread_cpu_ns', 'wall_ns', 'cpu_clock_unknown_calls', 'calls_unfinished'))
    for row in host.values():
        row['mean_cpu_ns_per_completed_call'] = row['thread_cpu_ns'] / row['calls_completed'] if row['calls_completed'] else None
    packets = [packet for o in observations for packet in o['packets']]
    return {
        'replay_calls': len(imports),
        'replay_cpu_ns': sum(r.get('replay_thread_cpu_ns', r.get('thread_cpu_ns', 0)) or 0 for r in imports),
        'replay_wall_ns': sum(r.get('replay_wall_ns', r.get('wall_ns', 0)) or 0 for r in imports),
        'host_checks': host,
        'page_phases': aggregate((p for o in observations for p in o['phases']), ('thread_cpu_ns', 'wall_ns')),
        'packet_phases': aggregate((p for packet in packets for p in packet['phases']), ('thread_cpu_ns', 'wall_ns')),
        'pages': [{
            'supplied_packets': o['supplied_packets'],
            'host_checks': o['host_checks'],
            'phases': [p for p in o['phases'] if p['started']],
            'packets': [{'packet_index': p['packet_index'], 'phases': [s for s in p['phases'] if s['started']]} for p in o['packets']],
        } for o in observations],
        'failures': [{'page_index': i, 'packet_index': p['packet_index'], 'phase': s['phase'], 'error_code': s['error_code']}
                     for i, o in enumerate(observations) for p in o['packets'] for s in p['phases'] if s['accepted'] is False],
    }


def timeline(row):
    value = (row.get('response') or {}).get('value') or {}
    return {**{key: row.get(key) for key in ('started_ns', 'ended_ns', 'elapsed_wall_ns', 'status', 'error',
                                          'returned_after_window', 'client_thread_cpu_ns', 'calling_process_cpu_ns')},
            'returned_packets': len(value.get('packets', [])), 'complete': value.get('complete')}


def fresh(root, label):
    manifest_path = root / 'fresh-service/manifest.json'
    manifest = load(manifest_path)
    out = {'label': label, 'manifest': str(manifest_path), 'manifest_sha256': sha(manifest_path),
           'source_before': manifest['source_before'], 'source_after': manifest['source_after'],
           'binary_sha256_before': manifest['binary_sha256_before'], 'binary_sha256_after': manifest['binary_sha256_after'],
           'phases': []}
    assert out['source_before'] == out['source_after']
    assert out['binary_sha256_before'] == out['binary_sha256_after']
    for case in ('original', 'fresh'):
        path = root / 'fresh-service' / case / 'report.json'
        assert sha(path) == manifest['files'][case + '/report.json']
        report = load(path)
        packet_hash = hashlib.sha256(b''.join(bytes.fromhex(p) for p in report['signed_honest_packets'])).hexdigest()
        for phase in report['phases']:
            imports = phase['independent_history_page_replay']
            out['phases'].append({
                'case': case, 'mode': phase['mode'], 'raw_report': str(path), 'raw_report_sha256': sha(path),
                'policy_id': report['policy_id'], 'signed_packet_sequence_sha256': packet_hash,
                'workers': phase['workers'], 'requested_window_ns': phase['requested_window_ns'],
                'business_started_ns': phase['business_started_ns'], 'confirmation_ended_ns': phase['confirmation_ended_ns'],
                'client_confirmation_latency_ns': phase['client_confirmation_latency_ns'],
                'client_confirmed_transactions': phase['client_confirmed_transactions'],
                'finite_business_target_met': phase['finite_business_target_met'],
                'independent_replay_and_confirmation_cpu_ns': phase['independent_replay_and_confirmation_cpu_ns'],
                'independent_replay_and_confirmation_wall_ns': phase['independent_replay_and_confirmation_wall_ns'],
                'verification_errors': phase['verification_errors'],
                'submissions': [timeline(row) for row in phase['honest_submissions']],
                'submission_wall_sum_ns': sum(row['elapsed_wall_ns'] for row in phase['honest_submissions']),
                'history': [timeline(row) for row in phase['honest_history']],
                'replays': [{key: value for key, value in replay.items() if key != 'native_import_observation'} for replay in imports],
                'import_summary': summarize_imports(imports),
            })
    return out


def differences(before, after, key, row_key):
    b = {row[row_key]: row['totals'] for row in before[key]}
    a = {row[row_key]: row['totals'] for row in after[key]}
    return {name: {field: (value or 0) - (b[name].get(field) or 0)
                   for field, value in totals.items() if isinstance(value, (int, type(None)))}
            for name, totals in a.items()}


def counter_difference(before, after):
    return {key: value - before[key] for key, value in after.items()
            if isinstance(value, int) and isinstance(before.get(key), int)}


def native():
    rows = []
    for run in (1, 2, 3):
        for mode in ('baseline', 'from-zero', 'late-product'):
            path = ARTIFACTS / 'native-artifact' / f'run-{run}-raw' / (mode + '.json')
            report = load(path)
            imports = [h['client_import'] for h in report['history'] if h.get('client_import')]
            stages = {}
            for role, prefix in (('client', 'client_native_history_arithmetic'), ('receiver', 'native_history_arithmetic')):
                before, after = report[prefix + '_before'], report[prefix + '_after']
                stages[role] = {
                    'scope': 'after-minus-before; setup counters excluded; nested stages are not additive',
                    'stages': differences(before, after, 'stages', 'stage'),
                    'sql_commit_api': differences(before['sql_commit'], after['sql_commit'], 'sites', 'site'),
                    'counters': counter_difference(before['counters'], after['counters']),
                    'account_node_decode_arithmetic': counter_difference(before['account_node_decode_arithmetic']['counters'], after['account_node_decode_arithmetic']['counters']),
                }
            context = report['phase_process_context']
            rows.append({
                'run': run, 'mode': mode, 'raw_report': str(path), 'raw_report_sha256': sha(path),
                'duration_seconds': report['duration_seconds'], 'workers': report['attacker_processes_requested'],
                'state_backend': report['state_backend'], 'public_resource_policy': report['public_resource_policy'],
                'business_started_ns': report['business_started_ns'],
                'finite_phase_criteria_met': report['finite_phase_criteria_met'],
                'confirmations': [{k: c[k] for k in ('round', 'started_ns', 'ended_ns', 'confirmed_inside_pressure_window')} for c in report['confirmations']],
                'submissions': [timeline(row) for row in report['submissions']],
                'history': [timeline(row) for row in report['history']],
                'client_import_calls': [{k: v for k, v in i.items() if k != 'native_import_observation'} for i in imports],
                'import_summary': summarize_imports(imports),
                'native_owner_deltas': stages,
                'receiver_and_verifier_setup_cpu_ns': report['receiver_and_verifier_setup_cpu_ns'],
                'receiver_and_verifier_setup_wall_ns': report['receiver_and_verifier_setup_wall_ns'],
                'whole_parent_phase_cpu_ns': report['whole_parent_phase_cpu_ns'],
                'whole_parent_phase_wall_ns': report['whole_parent_phase_wall_ns'],
                'host_cgroup_deltas': counter_difference(context['host_before'], context['host_after']),
                'verifier_errors': report['verifier_errors'],
            })
    return rows


def main():
    assert subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO).strip() == b''
    candidates = [fresh(OLD, '0ca272d-original-head'),
                  fresh(ARTIFACTS / 'fresh-head-artifact', 'd87357d-head'),
                  fresh(ARTIFACTS / 'fresh-prospective-artifact', '6f036269-same-tree-same-binary')]
    assert candidates[1]['source_before']['tree'] == candidates[2]['source_before']['tree']
    assert candidates[1]['binary_sha256_before'] == candidates[2]['binary_sha256_before']
    host_meta = {}
    with zipfile.ZipFile(OLD_ZIP) as archive:
        host_meta['old'] = json.loads(archive.read('fresh-service-host/inside-before.json'))
    for key, folder in (('head', 'fresh-head-artifact'), ('prospective', 'fresh-prospective-artifact')):
        host_meta[key] = load(ARTIFACTS / folder / 'fresh-service-host/inside-before.json')
    paths = ['trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs',
             'trillionnium/crates/trnm-pon-node/src/ingress.rs',
             'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs',
             'trillionnium/crates/trnm-pon-node/src/ingress/history_import/observation.rs']
    source_blobs = {path: {commit: subprocess.check_output(['git', 'rev-parse', commit + ':' + path], cwd=REPO, text=True).strip()
                          for commit in ('0ca272d09d1522b0ffd740e441b6d3de1ed81de6', 'd87357de197db5ff750d08c96d52432e5d22a0b4')}
                    for path in paths}
    out = {'schema': 'retained-w1-failure-latency-analysis-v1', 'generated_utc': datetime.now(timezone.utc).isoformat(),
           'analysis_script': str(Path(__file__)), 'analysis_script_sha256': sha(Path(__file__)),
           'scope': 'read-only extraction of retained actual failed runs; no criteria, source, resource, deadline, raw artifact, or outcome changes',
           'nested_intervals_are_not_additive': True,
           'phase_cpu_excludes_scoped_workers': True,
           'host_cpu_includes_each_calling_thread_not_full_worker_cpu': True,
           'fresh_candidates': candidates, 'native_phases': native(),
           'actual_host_receipts': host_meta, 'unchanged_relevant_source_blobs': source_blobs,
           'native_runner_hardware': load(ARTIFACTS / 'native-artifact/hardware.json'),
           'fresh_runner_cpu_model_not_recorded_in_available_receipts': True,
           'causal_limits': [
               'Same tree and exact binary produce materially different per-check thread CPU on head and prospective runners; code-only regression attribution is unsupported.',
               'Host and M06/account-graph measurements are nested; do not add them to page replay or work/admission totals.',
               'SQL commit API measurements are not all SQL traversal time and not isolated physical fsync time.',
               'Explicit cpu_wait observations omit refill sleep inside a verified continuation; wall-minus-thread-CPU also includes cgroup throttling and other scheduling.',
               'Cgroup throttled_usec may accumulate over multiple runnable threads and cannot be subtracted as a single wall interval.',
               'The 30-second authenticated-state native campaign differs from the four-second fresh-service fixture; compare stages within each workload.',
               'No performance improvement or four-second qualification is inferred from these failed runs.'
           ]}
    output = OUTPUT / 'retained-failure-latency.json'
    with output.open('x') as stream:
        json.dump(out, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(output), 'sha256': sha(output), 'fresh_phases': sum(len(c['phases']) for c in candidates),
                      'native_phases': len(out['native_phases']), 'source_unchanged': True}, indent=2))


if __name__ == '__main__':
    main()
