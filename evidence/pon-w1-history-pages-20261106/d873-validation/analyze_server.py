#!/usr/bin/env python3
"""Match retained client requests to the actual receiver by canonical wire digest."""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path('/workspace/scratch/a66f84888260/hosted-d873')
OUTPUT = ROOT / 'latency-diagnosis'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def domain_hash(tag, body):
    return hashlib.sha256(b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag
                          + len(body).to_bytes(4, 'little') + body).hexdigest()


def canonical(request, operation):
    # Request enum serde field order, independently checked against retained
    # first-business digest and actual receiver record digests below.
    value = {'op': 'submit', 'packet': request['packet']} if operation == 1 else {
        'op': 'history', 'tip': request['tip'], 'after': request['after']}
    return json.dumps(value, separators=(',', ':')).encode()


def summarize_record(row):
    phases = {p['phase']: p for p in row['submit_phases'] if p['started']}
    body = phases.get('body_decode')
    encoding = phases.get('response_encoding')
    dispatch_start = row['paid_task_queue_wait'].get('ended_ns')
    dispatch_end = row['lifecycle'].get('task_closed_ns')
    cpu = row.get('dispatch_thread_cpu_ns')
    cpu_observed_children = sum(p.get('thread_cpu_ns') or 0 for p in (body, encoding) if p)
    gap = encoding['started_ns'] - body['ended_ns'] if encoding and body else None
    response_frame = next((f for f in row['frames'] if f['phase'] == 'response'), None)
    return {
        'connection_id': row['connection_id'], 'operation': row['operation'],
        'public_body_digest': bytes(row['body_digest']).hex(),
        'dispatch_started': row['dispatch_started'], 'dispatch_accepted': row['dispatch_accepted'],
        'dispatch_error_code': row['dispatch_error_code'], 'terminal_error_code': row['terminal_error_code'],
        'dispatch_cpu_ns': cpu,
        'dispatch_enclosing_wall_ns': dispatch_end-dispatch_start if dispatch_start is not None and dispatch_end is not None else None,
        'dispatch_cpu_excluding_body_decode_and_response_encoding_ns': cpu-cpu_observed_children if cpu is not None and encoding and body else None,
        'body_decode_end_to_response_encoding_start_wall_ns': gap,
        'gap_scope': 'History gap includes owner acquisition, current ancestry/body reads, packet formatting and nearby dispatcher overhead; not a pure SQL or owner-wait measurement',
        'observed_stages': phases,
        'challenge_wait': row['challenge_wait'], 'grant_wait': row['grant_wait'],
        'paid_task_queue_wait': row['paid_task_queue_wait'], 'response_write': row['response_write'],
        'response_frame': response_frame, 'lifecycle': row['lifecycle'],
        'complete': row['complete'], 'response_frame_complete': row['response_frame_complete'],
        'application_bytes_read': row['application_bytes_read'], 'application_bytes_written': row['application_bytes_written'],
        'actual_history_sql_step_count': None,
        'actual_history_sql_step_count_scope': 'not recorded by this receiver report; the configured 1024 cap is not a measured count',
    }


def totals(rows):
    phases = defaultdict(lambda: defaultdict(int))
    for row in rows:
        for name, phase in row['observed_stages'].items():
            out = phases[name]
            out['observations'] += 1
            out['accepted'] += phase['accepted'] is True
            out['rejected'] += phase['accepted'] is False
            for field in ('thread_cpu_ns', 'wall_ns'):
                out[field] += phase.get(field) or 0
    return {'matched_records': len(rows), 'dispatch_cpu_ns': sum(r['dispatch_cpu_ns'] or 0 for r in rows),
            'dispatch_enclosing_wall_ns': sum(r['dispatch_enclosing_wall_ns'] or 0 for r in rows),
            'response_write_wall_ns': sum(r['response_write']['wall_ns'] or 0 for r in rows),
            'challenge_wait_wall_ns': sum(r['challenge_wait']['wall_ns'] or 0 for r in rows),
            'grant_wait_wall_ns': sum(r['grant_wait']['wall_ns'] or 0 for r in rows),
            'paid_task_queue_wait_wall_ns': sum(r['paid_task_queue_wait']['wall_ns'] or 0 for r in rows),
            'phases': dict(phases)}


def main():
    candidates = [('old-0ca', Path('/workspace/scratch/ab286a535ac8/w1-current-0ca272')),
                  ('d873-head', ROOT / 'fresh-head-artifact'),
                  ('same-binary-prospective', ROOT / 'fresh-prospective-artifact')]
    output = []
    for label, folder in candidates:
        for case in ('original', 'fresh'):
            path = folder / 'fresh-service' / case / 'report.json'
            report = json.loads(path.read_text())
            for phase in report['phases']:
                records = phase['observations']['records']
                honest_submits, history = [], []
                for index, packet in enumerate(report['signed_honest_packets']):
                    wire = canonical({'packet': packet}, 1)
                    digest = domain_hash(b'public-request-body-v3', wire)
                    if index == 0:
                        assert digest == phase['business_receive_clock']['first_business_packet_body_digest']
                    rows = [r for r in records if r['operation'] == 1 and r['body_digest'] and bytes(r['body_digest']).hex() == digest]
                    assert len(rows) == 1, (label, case, phase['mode'], index, len(rows))
                    record = summarize_record(rows[0])
                    record['honest_packet_index'] = index
                    honest_submits.append(record)
                for index, call in enumerate(phase['honest_history']):
                    wire = canonical(call['request'], 3)
                    digest = domain_hash(b'public-request-body-v3', wire)
                    rows = [r for r in records if r['operation'] == 3 and r['body_digest'] and bytes(r['body_digest']).hex() == digest]
                    assert len(rows) <= 1, (label, case, phase['mode'], index, len(rows))
                    value = (call.get('response') or {}).get('value') or {}
                    history.append({'history_call_index': index, 'client_status': call['status'],
                                    'client_error': call['error'], 'client_started_ns': call['started_ns'],
                                    'client_ended_ns': call['ended_ns'], 'client_wall_ns': call['elapsed_wall_ns'],
                                    'client_thread_cpu_ns': call['client_thread_cpu_ns'],
                                    'returned_packets': len(value.get('packets', [])), 'complete': value.get('complete'),
                                    'digest': digest, 'matched_records': len(rows),
                                    'receiver': summarize_record(rows[0]) if rows else None})
                output.append({'candidate': label, 'case': case, 'mode': phase['mode'],
                               'raw_report': str(path), 'raw_report_sha256': sha(path),
                               'observer_measurement_failures': phase['observations']['measurement_failures'],
                               'observer_records_not_retained': phase['observations']['records_not_retained'],
                               'source_timing_offset_ns': phase['business_receive_clock']['traffic_epoch_in_observer_ns'],
                               'honest_submissions': honest_submits, 'honest_submit_totals': totals(honest_submits),
                               'history': history,
                               'history_totals': totals([h['receiver'] for h in history if h['receiver']]),
                               'service_metrics': phase['service']['metrics']})
    result = {'schema': 'retained-w1-service-receiver-attribution-v1', 'generated_utc': datetime.now(timezone.utc).isoformat(),
              'script': str(Path(__file__)), 'script_sha256': sha(Path(__file__)),
              'scope': 'read-only original observer records matched by exact canonical request body domain hash; no source or artifact edits',
              'nested_intervals_not_additive': True,
              'unobserved_subdivision': ['actual SQL count', 'History owner-wait-only span', 'History lookup-only CPU', 'response-write CPU', 'scheduler/throttling versus socket writability inside response-write wall'],
              'phases': output}
    destination = OUTPUT / 'retained-server-latency.json'
    with destination.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(destination), 'sha256': sha(destination), 'phases': len(output)}, indent=2))


if __name__ == '__main__':
    main()
