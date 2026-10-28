#!/usr/bin/env python3
"""Read the four retained 682 pair artifacts without extraction or native execution.

All JSON objects and every selected client call remain in the readback denominator.
The input ZIP hashes are the independently verified download receipt's identities;
this small reader validates member CRC/length/SHA and does not reread ELF payloads.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import time
import zipfile


PAIRS = (
    ('122635467337', 12793540188, 5207845, '00deb8d8f3b4914b864b8ba8e25de8d9b494dda862544bbdbe97ace7709b52fb'),
    ('122635467343', 12792744792, 5434672, 'beec791979f0c77272d0f64027e7910988ad3591da5c8b39283c55f4d996d675'),
    ('122635467377', 12793306605, 5185189, 'a16ed8003b7c5b13527d58622ddcdbf04f5e0db5861cd2e0eac2c047c5b97638'),
    ('122635467442', 12793685376, 156056882, 'b52e746a133d68a43175d6425d6bbeaaa289ef2601cb88d19535abd38701ddf8'),
)
LOG_SHA = {
    '122635467337': '673de4ee30607956ae90e803904d2fd1499b6ca4da147b9ae68d1a16be1d4cb7',
    '122635467343': '6fb3cf49a38f6a6558bc10668687ad343dc958b9db53089de7275c8ceba53ca5',
    '122635467377': '14a2d62724b311f65edf3d2fdb97bd50905ed476b388fd2ae6ec64d9075aaa8e',
    '122635467442': '11694f43b0a758d7098523c0277ba816ce7de0c7b64a3eaa766b05227de9f3b8',
}
NATIVE = 'chain-from-zero-native/'
HOST = 'chain-from-zero-native-host/'
REPORTS = ('native/report.json', 'native/sustained/report.json', 'confirmation/report.json')
LIMIT = 32 * 1024 * 1024
EXPECTED_LIMITS = {
    'cpu.max': '25000 100000', 'cpu.max.burst': '0', 'memory.max': '2147483648',
    'memory.swap.max': '0', 'pids.max': '256',
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def load(data):
    return json.loads(data, object_pairs_hook=unique_pairs)


def pon_hash(domain, payload):
    framed = (b"TRNM-PON1\0" + len(domain).to_bytes(2, "little") + domain
              + len(payload).to_bytes(4, "little") + payload)
    return sha(framed)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def write_jsonl_gz(path, rows):
    with path.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as output:
            for row in rows:
                output.write(canonical(row) + b'\n')


def parse_job_log(path, job, index):
    raw = path.read_bytes()
    require(sha(raw) == LOG_SHA[job], 'job log hash')
    records = []
    prefixes = Counter()
    for number, line in enumerate(raw.decode('utf-8').splitlines(), 1):
        # GitHub log concatenation can retain a BOM on an interior chunk.
        message = re.sub(r'^\ufeff?\d{4}-\d\d-\d\dT\S+Z ', '', line)
        offset = message.find('{')
        if offset < 0:
            continue
        try:
            value = load(message[offset:])
        except json.JSONDecodeError:
            require(offset != 0, f'undecodable JSON output at {job}:{number}')
            continue
        require(isinstance(value, dict), 'top JSON object')
        prefix = message[:offset]
        if prefix:
            prefixes[prefix] += 1
        records.append(value)
        index.append({'job': job, 'line': number, 'prefix': prefix,
                      'schema': value.get('schema'), 'raw_json_sha256': sha(message[offset:].encode()),
                      'raw_json_bytes': len(message[offset:].encode()), 'top_keys': list(value)})
    wrappers = [row for row in records if 'tested_sha' in row]
    controller = [row for row in records if row.get('schema') == 'trnm-ci-original-public-host-controller-v2']
    require(len(controller) == 1, 'one original controller record')
    require(len(wrappers) == 64, 'all original wrapper invocations')
    require(all(row['before'] == row['after'] and row['before']['dirty'] is False for row in wrappers),
            'wrapper source identity moved')
    source = {(row['source_sha'], row['tested_sha'], row['lane'], row['before']['tree']) for row in wrappers}
    require(len(source) == 1, 'mixed wrapper identity')
    return {
        'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
        'complete_json_objects': len(records), 'prefixed_json_records': dict(prefixes),
        'schema_counts': dict(Counter(row.get('schema', '<none>') for row in records)),
        'wrapper_source': dict(zip(('source_sha', 'tested_sha', 'lane', 'tree'), next(iter(source)))),
        'wrapper_invocations': len(wrappers),
        'wrapper_status': dict(Counter(row['status'] for row in wrappers)),
        'observed_passed_test_occurrences': sum(row['observed_passed_tests'] for row in wrappers),
        'observed_failed_test_occurrences': sum(row['observed_failed_tests'] for row in wrappers),
        'unique_test_count_claimed': False,
        'wrapper_receipts': wrappers,
    }, controller[0]


def call_summary(rows):
    refusal_codes = []
    for row in rows:
        response = row.get('response')
        if isinstance(response, dict) and response.get('ok') is False:
            refusal_codes.append(response['value'].get('error', '<missing>'))
        elif row.get('response_ok') is False:
            refusal_codes.append(row.get('response_value_error', '<missing>'))
    return {
        'planned_or_observed_calls': len(rows),
        'status_counts': dict(Counter(row.get('status', '<missing>') for row in rows)),
        'error_counts': dict(Counter(row['error'] for row in rows if row.get('error') is not None)),
        'signed_refusal_codes': dict(Counter(refusal_codes)),
        'timely_successes': sum(row.get('status') == 'ok'
                               and row.get('returned_after_deadline') is False
                               and row.get('returned_after_window') is False for row in rows),
        'returned_after_call_deadline': sum(row.get('returned_after_deadline') is True for row in rows),
        'returned_after_original_window': sum(row.get('returned_after_window') is True for row in rows),
    }


def compact_call(row, origin):
    result = {key: row.get(key) for key in (
        'status', 'error', 'lane', 'caller_fixture', 'started_ns', 'ended_ns',
        'elapsed_wall_ns', 'deadline_ms', 'returned_after_deadline', 'returned_after_window',
        'packet_index', 'height', 'recorded_request_bytes', 'recorded_request_digest',
        'client_thread_cpu_ns', 'client_cpu_scope', 'metrics')}
    result['origin'] = origin
    result['canonical_original_call_sha256'] = sha(canonical(row))
    response = row.get('response')
    if isinstance(response, dict):
        result['response_ok'] = response.get('ok')
        result['response_value_error'] = response.get('value', {}).get('error')
        result['response_canonical_sha256'] = sha(canonical(response))
        value = response.get('value')
        if isinstance(value, dict) and 'packets' in value:
            result['history_response'] = {
                key: value.get(key) for key in ('after', 'next', 'tip', 'complete', 'schema')}
            result['history_response']['packet_count'] = len(value['packets'])
    return result


def metrics_checked(phase):
    metrics = phase['service']['metrics']
    require(phase['service']['error'] is None and isinstance(metrics, dict), 'known joined service result')
    require(metrics['mutation_cpu_charged_ns'] == metrics['mutation_full_work_cpu_ns']
            + metrics['mutation_dispatch_excluding_work_cpu_ns'], 'paid CPU sum')
    require(metrics['work_started'] == metrics['work_finished'], 'unjoined complete W1')
    require(metrics['mutation_cpu_in_flight_after_shutdown'] == 0, 'unsettled paid owners')
    require(metrics['mutation_cpu_clock_failures'] == 0
            and metrics['mutation_cpu_unavailable_after_shutdown'] is False, 'unknown paid CPU')
    return metrics


def summarize_report(doc, report, artifact, call_index, observer_index):
    require(isinstance(doc['phases'], list) and len(doc['phases']) == 2, 'two original phases')
    phases = []
    for ordinal, phase in enumerate(doc['phases']):
        pointer = f'/phases/{ordinal}'
        finite = report == 'native/report.json'
        confirmation = report == 'confirmation/report.json'
        if finite:
            attacks = [(f'{pointer}/from_zero/{n}/call', row['call'])
                       for n, row in enumerate(phase['from_zero']) if row['call'] is not None]
        else:
            attacks = [(f'{pointer}/attacks/{worker}/calls/{n}', row)
                       for worker, value in enumerate(phase['attacks']) for n, row in enumerate(value['calls'])]
        groups = {'attack': attacks}
        for name, field in (('honest_head', 'honest_heads' if confirmation else 'honest_reads'),
                            ('honest_submit', 'honest_submissions'), ('honest_history', 'honest_history')):
            if field in phase:
                groups[name] = [(f'{pointer}/{field}/{n}', row) for n, row in enumerate(phase[field])]
        if finite:
            groups['honest_submit'] = [(f'{pointer}/honest_submit', phase['honest_submit'])]
        if 'post_pressure_head' in phase:
            groups['post_pressure_head'] = [(f'{pointer}/post_pressure_head', phase['post_pressure_head'])]
        for role, rows in groups.items():
            for location, row in rows:
                call_index.append(compact_call(row, {'artifact_id': artifact, 'member': NATIVE + report,
                                                    'json_pointer': location, 'role': role}))
        metrics = metrics_checked(phase)
        summary = {
            'phase': ordinal, 'mode': phase.get('mode'),
            'groups': {role: call_summary([row for _, row in rows]) for role, rows in groups.items()},
            'flags': {key: value for key, value in phase.items() if isinstance(value, bool)},
            'service_metrics': metrics,
        }
        if finite:
            summary['constructors'] = {
                'planned': phase['construction_count'], 'observed': len(phase['from_zero']),
                'target_hits': phase['constructed_hits'], 'search_exhausted': phase['exhausted_searches'],
                'submitted': phase['submitted_attacks'], 'late_transcript_rejections': phase['late_transcript_rejections'],
            }
        samples = phase.get('meter_samples', [])
        if samples:
            for sample in samples:
                meter = sample['meter']
                require(meter['accounting_unavailable'] is False, 'unknown budget sample')
                require((meter['burst_ns'], meter['refill_ns_per_second'], meter['start_reserve_ns'], meter['worker_limit'])
                        == (2000000000, 250000000, 100000000, 2), 'changed original scalar profile')
            summary['meter_samples'] = {
                'observed': len(samples),
                'minimum_stored_credit_ns': min(sample['meter']['stored_credit_ns'] for sample in samples),
                'maximum_in_flight': max(sample['meter']['in_flight'] for sample in samples),
                'stored_credit_below_reserve_samples': sum(sample['meter']['stored_credit_ns'] < 100000000 for sample in samples),
                'complete_original_sample_records': samples,
                'not_a_paid_flow_or_physical_cpu_continuous_bound': True,
            }
        for name in ('initial_meter', 'meter_at_traffic_end', 'final_meter'):
            if name in phase:
                summary[name] = phase[name]
        if confirmation:
            summary['confirmation'] = {
                'planned': 1, 'observed_success_before_original_window': phase['client_confirmed_transactions'],
                'original_window_ns': phase['requested_window_ns'],
                'business_started_ns': phase['business_started_ns'],
                'confirmation_ended_ns': phase['confirmation_ended_ns'],
                'latency_ns': phase['client_confirmation_latency_ns'],
                'retained_native_confirmation': phase['independent_client_confirmation'],
                'verification_errors': phase['verification_errors'],
                'full_native_state_equal': phase['full_native_state_equal'],
                'overlapping_false_calls': phase['overlapping_false_calls'],
                'complete_history_response_count': sum(row.get('response', {}).get('value', {}).get('complete') is True
                                                       for _, row in groups['honest_history'] if isinstance(row.get('response'), dict)),
                'history_import_results_not_recorded_per_call': True,
            }
            require(phase['requested_window_ns'] == 4000000000, 'changed original confirmation window')
        observer = phase.get('observations')
        if observer is not None:
            require(observer['records_not_retained'] == 0 and observer['measurement_failures'] == 0
                    and observer['counter_overflow'] is False, 'incomplete receiver observer')
            # The retained client diagnostic and actual public wire use two
            # different hash domains. Bind both to the complete original packet;
            # direct comparison would silently produce an empty false cohort.
            constructions = phase.get('construction', doc.get('from_zero_construction', []))
            bindings = {}
            for _, row in attacks:
                if row.get('status') == 'not_submitted_exhausted':
                    continue
                packet_index = row['packet_index']
                require(type(packet_index) is int and 0 <= packet_index < len(constructions),
                        'complete hostile construction index')
                if packet_index not in bindings:
                    packet = constructions[packet_index]['packet']
                    require(isinstance(packet, str) and re.fullmatch('[0-9a-f]+', packet) is not None
                            and len(packet) % 2 == 0, 'canonical hostile packet')
                    body = canonical({'op': 'submit', 'packet': packet})
                    bindings[packet_index] = {
                        'packet_index': packet_index, 'packet_bytes': len(packet) // 2,
                        'packet_sha256': sha(bytes.fromhex(packet)),
                        'request_bytes': len(body),
                        'recorded_request_digest': pon_hash(b'pressure-recorded-request-v1', body),
                        'public_request_body_digest': pon_hash(b'public-request-body-v3', body),
                    }
                bound = bindings[packet_index]
                require(row['recorded_request_digest'] == bound['recorded_request_digest']
                        and row['recorded_request_bytes'] == bound['request_bytes'],
                        'retained client request differs from complete original packet')
            hostile = {bound['public_request_body_digest'] for bound in bindings.values()}
            selected = [row for row in observer['records'] if row['body_digest'] is not None
                        and bytes(row['body_digest']).hex() in hostile]
            require(not bindings or selected, 'nonempty hostile input has no receiver cohort')
            summary['hostile_receiver_cohort'] = {
                'match_kind': 'two exact hash domains bound to complete packet; repeated-body cohort, not unique request pairing',
                'construction_bindings': list(bindings.values()),
                'distinct_body_digests': len(hostile), 'matched_records': len(selected),
                'full_work_started': sum(row['full_work_started'] is True for row in selected),
                'full_work_accepted': sum(row['full_work_accepted'] is True for row in selected),
                'full_work_refused': sum(row['full_work_accepted'] is False for row in selected),
                'admission_started': sum(any(step['phase'] == 'admission' and step['started'] is True
                                             for step in row['submit_phases']) for row in selected),
            }
            summary['receiver_observer'] = {key: value for key, value in observer.items() if key != 'records'}
            for number, row in enumerate(observer['records']):
                observer_index.append({'artifact_id': artifact, 'member': NATIVE + report,
                                       'json_pointer': f'{pointer}/observations/records/{number}',
                                       'record': row})
        phases.append(summary)
    return {
        'schema': doc['schema'], 'flags': {key: value for key, value in doc.items() if isinstance(value, bool)},
        'phases': phases,
        'reopen': {key: doc[key] for key in ('meter_before_reopen', 'meter_after_reopen') if key in doc},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--log-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    args.out.mkdir(parents=True, exist_ok=False)
    receipts_raw = (args.artifact_dir / 'download-receipts.json').read_bytes()
    receipts = {row['id']: row for row in load(receipts_raw)}
    job_index, call_index, observer_index, small_raw, inputs, jobs = [], [], [], [], [], []
    small_raw.append(('download-receipts.json', receipts_raw))
    for job, artifact, expected_bytes, expected_sha in PAIRS:
        retrieval = receipts[artifact]
        require(retrieval['bytes'] == expected_bytes and retrieval['sha256'] == expected_sha
                and retrieval['metadata']['size_in_bytes'] == expected_bytes
                and retrieval['metadata']['digest'] == 'sha256:' + expected_sha, 'download identity')
        archive_path = args.artifact_dir / f'hepta-682-pair-{artifact}.zip'
        require(archive_path.is_file() and not archive_path.is_symlink()
                and archive_path.stat().st_size == expected_bytes, 'retained original archive identity')
        log, logged_controller = parse_job_log(args.log_dir / f'hepta-682-pair-{job}.log', job, job_index)
        with zipfile.ZipFile(archive_path) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'duplicate archive member')
            member_rows = []

            def read(name, retain=False):
                info = archive.getinfo(name)
                require(not info.is_dir() and info.file_size <= LIMIT, 'bounded selected member')
                raw = archive.read(name)
                require(len(raw) == info.file_size, 'selected member length')
                member_rows.append({'member': name, 'bytes': len(raw), 'sha256': sha(raw)})
                if retain:
                    small_raw.append((f'{artifact}/{name}', raw))
                return raw

            manifest = load(read(NATIVE + 'manifest.json', True))
            controller = load(read(HOST + 'controller-result.json', True))
            require(controller == logged_controller, 'log/controller mismatch')
            child = load(read(HOST + 'child-result.json', True))
            host_before = load(read(HOST + 'inside-before.json', True))
            host_after = load(read(HOST + 'inside-after.json', True))
            for observed in (host_before, host_after):
                require(observed['limits'] == EXPECTED_LIMITS and observed['read_errors'] == {}, 'Host budget mismatch')
                require(observed['thread_privileges'] == {'CapBnd': '0000000000000000', 'NoNewPrivs': '1'}, 'Host child privileges')
            require(host_before['parent'] == host_after['parent'], 'Host parent changed')
            require(manifest['source_before'] == manifest['source_after'], 'native source changed')
            require(manifest['binary_sha256_before'] == manifest['binary_sha256_after'], 'native binary changed')
            require(manifest['source_before'] == controller['preparation']['source_before'], 'preparation/native source mismatch')
            runs = []
            for row in manifest['runs']:
                for stream in ('stdout', 'stderr'):
                    name = f"{row['name']}/{stream}"
                    raw = read(NATIVE + name, True)
                    require(sha(raw) == row[stream + '_sha256'] == manifest['files'][name], 'native output hash mismatch')
                    if stream == 'stdout':
                        text = raw.decode('utf-8')
                        require(re.search(r'(?m)^test ' + re.escape(row['name']) + r' \.\.\.', text) is not None,
                                'selected original native test not run')
                        require('test result: ok. 1 passed; 0 failed;' in text, 'exact one original native result')
                runs.append(row)
            reports = {}
            for name in REPORTS:
                raw = read(NATIVE + name)
                require(sha(raw) == manifest['files'][name], 'report hash mismatch')
                doc = load(raw)
                reports[name] = summarize_report(doc, name, artifact, call_index, observer_index)
            inputs.append({'artifact_id': artifact, 'path': str(archive_path), 'bytes': expected_bytes,
                           'sha256_from_verified_download': expected_sha, 'entire_archive_rehashed_by_this_reader': False,
                           'selected_members_crc_and_sha_checked': member_rows,
                           'embedded_native_binary_executed_or_extracted': False})
            jobs.append({
                'job_id': job, 'artifact_id': artifact, 'name': retrieval['metadata']['name'],
                'log': log, 'native_source': manifest['source_before'],
                'native_runs': runs, 'native_manifest': {key: manifest[key] for key in (
                    'source_recompiled', 'all_named_tests_passed', 'format_passed', 'failures',
                    'passed', 'execution_finished', 'binary_sha256_before', 'binary_sha256_after')},
                'host': {'before': host_before, 'after': host_after, 'controller_passed': controller['passed'],
                         'systemd_run_exit': controller['systemd_run_exit'], 'final_host_errors': controller['final_host_errors'],
                         'child_host_errors': child['host_errors'], 'native_child_exit': child['native_child_exit']},
                'reports': reports,
            })
    confirmation_phases = [p for job in jobs for p in job['reports']['confirmation/report.json']['phases']]
    sustained = [p for job in jobs for p in job['reports']['native/sustained/report.json']['phases']]
    totals = {
        'jobs': len(jobs), 'original_native_selectors_planned': 20,
        'original_native_selectors_observed_passed': sum(row['passed'] is True for job in jobs for row in job['native_runs']),
        'strict_drivers_passed': sum(job['native_manifest']['passed'] is True for job in jobs),
        'confirmation_windows_planned': len(confirmation_phases),
        'confirmations_before_original_window_end': sum(p['confirmation']['observed_success_before_original_window'] for p in confirmation_phases),
        'pressure_windows_planned': sum(p['mode'] == 'from-zero-pressure' for p in confirmation_phases),
        'pressure_confirmations_before_original_window_end': sum(p['confirmation']['observed_success_before_original_window'] for p in confirmation_phases if p['mode'] == 'from-zero-pressure'),
        'confirmation_call_groups': {},
        'sustained_phases_observed': len(sustained),
        'sustained_phases_with_reported_budget_depletion': sum(p['flags']['budget_depletion_observed'] is True for p in sustained),
        'sustained_minimum_sampled_stored_credit_ns': min(p['meter_samples']['minimum_stored_credit_ns'] for p in sustained),
        'all_original_calls_indexed': len(call_index), 'all_receiver_observer_records_indexed': len(observer_index),
        'all_complete_job_json_objects_indexed': len(job_index),
        'no_new_native_execution': True, 'whole_chain_or_wan_qualification': False,
    }
    for group in ('honest_submit', 'honest_history', 'honest_head', 'attack'):
        selected = [row for row in call_index if row['origin']['member'] == NATIVE + 'confirmation/report.json'
                    and row['origin']['role'] == group]
        # The index carries all original call timing/status fields; response data
        # is separately hash-bound to its original report and not reconstructed.
        totals['confirmation_call_groups'][group] = call_summary(selected)
    write_jsonl_gz(args.out / 'all-client-calls.jsonl.gz', call_index)
    write_jsonl_gz(args.out / 'all-receiver-observations.jsonl.gz', observer_index)
    write_jsonl_gz(args.out / 'all-job-json-index.jsonl.gz', job_index)
    raw_manifest = []
    with zipfile.ZipFile(args.out / 'small-original-receipts.zip', 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in small_raw:
            info = zipfile.ZipInfo(name, (2026, 10, 28, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
            raw_manifest.append({'member': name, 'bytes': len(data), 'sha256': sha(data)})
    write_json(args.out / 'raw-files.json', raw_manifest)
    write_json(args.out / 'input-binding.json', inputs)
    write_json(args.out / 'readback.json', {'schema': 'hepta-682-pair-original-host-readback-r8-v1',
                                         'totals': totals, 'jobs': jobs,
                                         'readback_wall_seconds': time.monotonic() - started,
                                         'native_tests_executed_by_readback': False})
    print(json.dumps(totals, indent=2))


if __name__ == '__main__':
    main()
