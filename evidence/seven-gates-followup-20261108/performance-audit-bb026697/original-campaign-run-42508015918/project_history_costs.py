#!/usr/bin/env python3
"""Project original client-import costs; never turn request timing into confirmation."""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / 'original-campaign-bb026697-attempt-1.zip'

def stats(values):
    known = sorted(value for value in values if value is not None)
    return {'known_count': len(known), 'unknown_count': len(values) - len(known),
            'sum_known_ns': sum(known), 'min_ns': known[0] if known else None,
            'max_ns': known[-1] if known else None}

rows = []
with zipfile.ZipFile(ARCHIVE) as archive:
    for number in (1, 2, 3):
        name = f'run-{number}-raw/report.json'
        raw = archive.read(name)
        report = json.loads(raw)
        for phase in report['phases']:
            histories = phase['history']
            imports = [row['client_import'] for row in histories if 'client_import' in row]
            observations = [row['native_import_observation'] for row in imports
                            if 'native_import_observation' in row]
            hosts = defaultdict(list)
            packets = defaultdict(list)
            for observation in observations:
                for check in observation['host_checks']:
                    hosts[check['phase']].append(check)
                for packet in observation['packets']:
                    for stage in packet['phases']:
                        if stage['started']:
                            packets[stage['phase']].append(stage)
            host_projection = {}
            for label, values in hosts.items():
                host_projection[label] = {
                    key: sum(value[key] for value in values)
                    for key in ('calls_started', 'calls_completed', 'calls_accepted', 'calls_rejected',
                                'calls_unfinished', 'cpu_clock_unknown_calls', 'wall_clock_unknown_calls')}
                host_projection[label]['thread_cpu_ns'] = stats([v['thread_cpu_ns'] for v in values])
                host_projection[label]['wall_ns'] = stats([v['wall_ns'] for v in values])
            packet_projection = {label: {
                'entered_records': len(values),
                'completed_records': sum(v['completed'] for v in values),
                'wall_ns': stats([v['wall_ns'] for v in values]),
                'importer_thread_cpu_ns': stats([v['thread_cpu_ns'] for v in values]),
            } for label, values in packets.items()}
            context = phase['phase_process_context']
            before, after = context['host_before'], context['host_after']
            rows.append({
                'run': number, 'mode': phase['mode'], 'raw_report_sha256': hashlib.sha256(raw).hexdigest(),
                'recorded_history_calls': len(histories), 'retained_import_records': len(imports),
                'imports_recorded_succeeded': sum(row['succeeded'] is True for row in imports),
                'imports_recorded_failed': sum(row['succeeded'] is False for row in imports),
                'import_wall_intervals': stats([row.get('wall_ns') for row in imports]),
                'importer_thread_cpu': stats([row.get('thread_cpu_ns') for row in imports]),
                'transport_history_call_wall_intervals': stats([row.get('elapsed_wall_ns') for row in histories]),
                'host_check_costs': host_projection,
                'packet_phase_costs': packet_projection,
                'whole_public_host_cpu_delta_ns': (after['cpu_usage_usec'] - before['cpu_usage_usec']) * 1000,
                'whole_public_host_throttled_period_delta': after['cpu_nr_throttled'] - before['cpu_nr_throttled'],
                'whole_public_host_period_delta': after['cpu_nr_periods'] - before['cpu_nr_periods'],
                'receiver_verifier_setup_thread_cpu_ns': phase['receiver_and_verifier_setup_cpu_ns'],
                'whole_parent_phase_cpu_ns': phase['whole_parent_phase_cpu_ns'],
                'whole_parent_phase_wall_ns': phase['whole_parent_phase_wall_ns'],
                'phase_service_contract_met': phase['finite_phase_criteria_met'],
            })
            if number == 1 and phase['mode'] == 'baseline':
                first = {'source_report': name,
                         'source_report_sha256': hashlib.sha256(raw).hexdigest(),
                         'json_pointer': '/phases/0/history/0/client_import',
                         'value': imports[0]}
                with (ROOT / 'baseline-first-import-projection.json').open('x') as stream:
                    json.dump(first, stream, indent=2, sort_keys=True)
                    stream.write('\n')
result = {
    'schema': 'trnm-original-campaign-history-cost-projection-v1',
    'source_commit': 'bb026697a972521009bc133ae6ed2b653e18e931',
    'derived_from_retained_original_bytes': True,
    'native_reexecution': False,
    'qualification': 'HOLD',
    'scope': {
        'import_wall_includes_recorded_failed_or_unfinished_business_work': True,
        'importer_thread_cpu_excludes_scoped_workers': True,
        'host_cpu_sums_each_actual_calling_thread': True,
        'host_cpu_and_importer_cpu_are_not_identical_scopes': True,
        'nested_phase_and_host_costs_are_not_additive': True,
        'not_full_business_tail_latency': True,
        'not_qualified_goodput': True,
        'no_causal_share_or_optimization_speedup_proved': True,
    },
    'rows': rows,
}
with (ROOT / 'history-cost-projection.json').open('x') as stream:
    json.dump(result, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps({'qualification': result['qualification'], 'rows': [
    {'run': row['run'], 'mode': row['mode'],
     'history_calls': row['recorded_history_calls'],
     'successful_imports': row['imports_recorded_succeeded'],
     'failed_imports': row['imports_recorded_failed'],
     'import_wall_sum_ns': row['import_wall_intervals']['sum_known_ns'],
     'checkpoint_calls': row['host_check_costs'].get('checkpoint', {}).get('calls_started'),
     'checkpoint_cpu_ns': row['host_check_costs'].get('checkpoint', {}).get('thread_cpu_ns'),
     'whole_public_host_cpu_delta_ns': row['whole_public_host_cpu_delta_ns'],
    } for row in rows]}, separators=(',', ':')))

