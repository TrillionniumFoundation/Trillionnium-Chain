#!/usr/bin/env python3
"""Summarize an existing campaign and archive final logs; no verifier execution."""
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def parse_counts(value):
    return {key: int(number) for key, number in (line.split() for line in value.splitlines())}


def main():
    r = json.loads((ROOT / 'campaign-01/result.json').read_text())
    m = json.loads((ROOT / 'inputs/manifest.json').read_text())
    c = json.loads((ROOT / 'independent_cleanup.json').read_text())
    t = r['campaign_started_ns']
    rows = r['requests']
    initial = r['cgroup_campaign_start']['files']
    last = r['cgroup_at_decision_before_kill']['files']
    cpu0 = parse_counts(initial['cpu.stat'])
    cpu1 = parse_counts(last['cpu.stat'])
    samples = [json.loads(line) for line in (ROOT / 'campaign-01/events.jsonl').read_text().splitlines()]
    resource_samples = [x for x in samples if x.get('event') == 'resource_sample']
    before_values = [r['cgroup_before'], r['cgroup_campaign_start'], *[x['cgroup'] for x in resource_samples], r['cgroup_at_decision_before_kill']]
    limits_observed = [{key: snap['files'].get(key) for key in ('cpu.max', 'cpu.max.burst', 'memory.max', 'memory.swap.max', 'pids.max')} for snap in before_values]
    summary = {
        'schema': 'w1-node-pressure-r4-final-summary-v1',
        'qualification': 'HOLD_NO_GO', 'job_id': '1a1b9afa6de-12894-160e',
        'new_complete_proofs': 0, 'preflight_mutators': 4, 'preflight_exercises': 5,
        'campaign_exercises': 23, 'total_exercises_including_preflight': 28,
        'campaign_distinct_fixture_count': 1, 'legitimate_requests': 7, 'malicious_requests': 16,
        'malicious_distinct_mutations': 4, 'malicious_repeats_per_mutation': 4,
        'binary_sha256': m['binary_expected_sha256'], 'source_head_at_measurement': m['source_head_before'],
        'source_head_note': 'The Node adapter was uncommitted frozen v4 source above this HEAD; exact source hashes/copies, not HEAD alone, identify the binary.',
        'proof_origin': '/home/qian-qi/work/w1-r4-evidence-f16ac5/node-full-proof-v1/proof',
        'all_original_source_binary_inputs_unchanged': c['original_source_binaries_inputs_unchanged'],
        'all_copied_inputs_unchanged': c['all_copied_files_unchanged'] and c['manifest_unchanged'],
        'campaign': r['summary'],
        'wall_seconds_from_first_attempt': {
            'declared_deadline': (r['deadline_ns'] - t) / 1e9,
            'first_gate_release': (min(row['released_ns'] for row in rows) - t) / 1e9,
            'last_gate_release': (max(row['released_ns'] for row in rows) - t) / 1e9,
            'all_adapter_execs_observed_by': (max(row['adapter_exec_observed_ns'] for row in rows) - t) / 1e9,
            'deadline_decision_observed': (r['decision_ns'] - t) / 1e9,
            'kill_requested': (r['kill_events'][0]['requested_ns'] - t) / 1e9,
            'kill_returned': (r['kill_events'][0]['returned_ns'] - t) / 1e9,
            'last_wait4': (max(row['wait_observed_ns'] for row in rows) - t) / 1e9,
            'cgroup_absent_confirmed': (r['cgroup_after_cleanup']['monotonic_ns'] - t) / 1e9,
            'observer_total': r['observer_total_since_campaign_seconds'],
        },
        'deadline_overrun_ms_at_kill_request': (r['kill_events'][0]['requested_ns'] - r['deadline_ns']) / 1e6,
        'hard_four_second_termination_established': False,
        'resource_limits_initial_and_last': {'initial': limits_observed[0], 'last': limits_observed[-1]},
        'sampled_limits_equal_initial': all(x == limits_observed[0] for x in limits_observed),
        'resource_snapshot_count': len(before_values), 'continuous_drift_abort': False,
        'last_observed_kernel_memory_peak_bytes': int(last['memory.peak']),
        'last_observed_kernel_pids_peak': int(last['pids.peak']),
        'sentinel_included_in_cgroup_pid_and_resource_counts': True,
        'last_observed_kernel_memory_events': parse_counts(last['memory.events']),
        'last_observed_kernel_pids_events': parse_counts(last['pids.events']),
        'cpu_usage_delta_until_pre_kill_snapshot_seconds': (cpu1['usage_usec'] - cpu0['usage_usec']) / 1e6,
        'pre_kill_cpu_stat': cpu1,
        'post_kill_systemd_cpu_usage_ns': int(r['unit_after_kill']['CPUUsageNSec']),
        'post_kill_systemd_memory_peak_reported': r['unit_after_kill'].get('MemoryPeak'),
        'systemd_memory_peak_not_used_as_cgroup_peak': True,
        'worker_wait4_user_cpu_seconds': r['summary']['sum_worker_user_cpu_seconds'],
        'worker_wait4_system_cpu_seconds': r['summary']['sum_worker_system_cpu_seconds'],
        'worker_cpu_and_cgroup_cpu_have_different_boundaries': True,
        'request_output_directories_created': sum(x['request_output_exists'] for x in c['request_stores']),
        'receiver_node_directories_created': sum(x['receiver_node_exists'] for x in c['request_stores']),
        'exercise_receipts_created': sum(x['exercise_receipt_exists'] for x in c['request_stores']),
        'node_opened_report_unknown_count': sum(row['node_opened_reported'] is None for row in rows),
        'checkpoint_counts': dict(Counter(x['stage'] for row in rows for x in row['checkpoints'])),
        'before_proof_checkpoint_observed': sum(any(x['stage'] == 'BeforeProof' for x in row['checkpoints']) for row in rows),
        'late_pcs_rejection_measured_in_campaign': False,
        'preflight_results': [{'name': x['name'], 'result': x['result'], 'outer_wall_seconds': x['outer_wall_seconds'],
                               'max_rss_kib': x['max_rss_kib'], 'error': x['final']['error'],
                               'node_opened': x['final']['node_opened'], 'stages': x['stages']} for x in m['preflight']],
        'preflight_loadavg_after': {x['name']: json.loads((ROOT / 'preflight' / ('exercise-' + x['name']) / 'observation.json').read_text())['loadavg_after'] for x in m['preflight']},
        'shared_host_exclusive': False, 'machine_load_sampled_during_campaign': False,
        'root_and_security_heavy_work_coordination_retained': True,
        'cleanup_controller_and_independent_checks_pass': r['cleanup_confirmed'] and c['cleanup_confirmed'],
        'single_node_service': False, 'seven_independent_production_submissions': False,
        'production_slice_used': False, 'global_malicious_rejection_bound': False,
        'controller_and_observer_cpu_in_workload_quota': False,
        'adapter_input_read_binding_and_archive_persistence_in_worker_quota': True,
        'interpretation': 'Finite negative diagnostic: all 23 execs observed, no checkpoint/final receipt before SIGKILL, no receiver store. It establishes neither a global rejection bound nor a production-service starvation theorem.',
    }
    save(ROOT / 'final-summary.json', summary)
    files = []
    omitted = {}
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if '__pycache__' in path.parts or rel in ('final-evidence-files.json', 'final-archive.json'):
            continue
        if rel.endswith('.tar.gz'):
            omitted[rel] = {'bytes': path.stat().st_size, 'sha256': sha(path), 'reason': 'prior archive retained without overwriting'}
            continue
        if (rel in ('inputs/node-adapter', 'inputs/mutate_last_query') or rel.endswith('.bin') or 'receiver-node' in path.parts):
            omitted[rel] = {'bytes': path.stat().st_size, 'sha256': sha(path), 'retained_remote': str(path)}
            continue
        files.append(path)
    inventory = {'schema': 'w1-node-pressure-final-inventory-v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'included': {p.relative_to(ROOT).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in files},
        'omitted_but_retained_remote': omitted,
        'first_archive_note': 'The original collector archived while its own stdout and enclosing stage receipt were still being written. That original archive is retained; this final archive includes the completed collector logs/status and launch driver.'}
    save(ROOT / 'final-evidence-files.json', inventory)
    files.append(ROOT / 'final-evidence-files.json')
    archive = ROOT / 'node-pressure-evidence-final.tar.gz'
    with archive.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as tar:
                for path in sorted(files):
                    if path.name != 'final-evidence-files.json' and sha(path) != inventory['included'][path.relative_to(ROOT).as_posix()]['sha256']:
                        raise RuntimeError('ARCHIVE_INPUT_CHANGED:' + str(path))
                    info = tar.gettarinfo(str(path), arcname=path.relative_to(ROOT).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = 0
                    with path.open('rb') as stream:
                        tar.addfile(info, stream)
    receipt = {'schema': 'w1-node-pressure-final-archive-v1', 'archive': str(archive),
               'bytes': archive.stat().st_size, 'sha256': sha(archive), 'archived_files': len(files),
               'summary_sha256': sha(ROOT / 'final-summary.json'),
               'result_sha256': sha(ROOT / 'campaign-01/result.json'),
               'first_archive_retained_unchanged': True, 'new_exercises_or_proofs': 0}
    save(ROOT / 'final-archive.json', receipt)
    print(json.dumps(receipt, indent=2), flush=True)


if __name__ == '__main__':
    main()
