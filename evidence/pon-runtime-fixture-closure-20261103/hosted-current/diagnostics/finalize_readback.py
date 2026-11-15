#!/usr/bin/env python3
"""Produce the small handoff; verify selected rows against existing originals."""
import collections
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

OUT = Path(__file__).resolve().parent
REPO = Path('/workspace/scratch/b5a148b09b11/chain-six-axis')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def write(name, obj):
    (OUT/name).write_text(json.dumps(obj, ensure_ascii=False, indent=2)+'\n')


def total(rows, slot, text=None, code=None, kind=None):
    return sum(item['count'] for row in rows for item in row['diagnostic_counts'][slot]
        if (text is None or item['message_prefix'] == text)
        and (code is None or item['typed_error_code'] == code)
        and (kind is None or item['kind'] == kind))


readback = json.loads((OUT/'readback.json').read_text())
selected_raw = gzip.decompress((OUT/'selected-original-rows.json.gz').read_bytes())
selected = json.loads(selected_raw)['examples']
assert len(selected) == 89
verified_rows = 0
for scope in readback['scopes']:
    raw = Path(scope['bundle']['path']).read_bytes()
    assert sha(raw) == scope['bundle']['sha256']
    bundle = json.loads(gzip.decompress(raw))
    records = {r['member']:r for r in bundle.get('selected_records', bundle.get('records'))}
    reports = {}
    for sample in selected:
        if sample['source_id'] != scope['id']:
            continue
        name = sample['report_member']
        if name not in reports:
            record = records[name]
            assert sha(record['text'].encode()) == record['sha256']
            reports[name] = json.loads(record['text'])
        original = reports[name]
        for component in sample['json_pointer'].lstrip('/').split('/'):
            original = original[int(component)] if isinstance(original,list) else original[component]
        assert original == sample['row']
        assert sha(canonical(original)) == sample['row_canonical_sha256']
        verified_rows += 1
assert verified_rows == 89

groups = []
for scope in readback['scopes']:
    for report in scope['reports']:
        rows = report['snapshots']
        groups.append(dict(scope=scope['id'], report_member=report['member'],
            source=scope['source_before_after']['tested_commit'],
            snapshots=len(rows), retained_records=sum(r['records'] for r in rows),
            root_untyped_dispatch=total(rows,'dispatch',text='ROOT',kind='unclassified'),
            transcript_untyped_dispatch=total(rows,'dispatch',text='WORK:Transcript',kind='unclassified'),
            product_untyped_dispatch=total(rows,'dispatch',text='WORK:Product',kind='unclassified'),
            typed_dispatch_cancel=total(rows,'dispatch',code='PUBLIC_REQUEST_CANCELLED'),
            dispatch_outcome_false=sum(r['dispatch_rejected_records'] for r in rows),
            dispatch_diagnostic_with_outcome_unknown=sum(r['diagnostic_captured_with_dispatch_outcome_unknown'] for r in rows),
            typed_terminal_eof=total(rows,'terminal',code='PUBLIC_EOF'),
            typed_terminal_cancel=total(rows,'terminal',code='PUBLIC_REQUEST_CANCELLED'),
            untyped_terminal_io=total(rows,'terminal',text='IO: Connection reset by peer (os error 104)'),
            records_not_retained=sum(r['scope_flags']['records_not_retained'] for r in rows),
            measurement_failures=sum(r['scope_flags']['measurement_failures'] for r in rows),
            all_retained_coverage_complete=all(r['computed_retained_coverage_complete'] for r in rows)))
all_snapshots=[p for s in readback['scopes'] for r in s['reports'] for p in r['snapshots']]
totals={key:sum(g[key] for g in groups) for key in groups[0]
        if type(groups[0][key]) is int}
root_phase=next(p for p in readback['scopes'][0]['reports'][0]['snapshots'] if p['mode']=='valid-work-root')
root_cost=next(b['cost'] for b in root_phase['dispatch_diagnostic_costs'] if b['message_prefix']=='ROOT')
code_identity=[]
for path in ('trillionnium/crates/trnm-pon-node/src/error.rs','trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'):
    values=[]
    for rev in ('b28098c092dca72165c0d26054fce95a8636d777','c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'):
        raw=subprocess.check_output(['git','--no-replace-objects','show',rev+':'+path],cwd=REPO)
        values.append(dict(commit=rev,sha256=sha(raw),bytes=len(raw)))
    assert values[0]['sha256']==values[1]['sha256']
    code_identity.append(dict(path=path,observations=values,unchanged_bytes=True))
summary=dict(schema='hosted-diagnostic-observability-summary-v1',
    completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    conclusion='Actual hosted receiver observations contain usable bounded diagnostic text and existing error kinds while legacy typed-code slots remain unchanged. This closes the missing-text evidence gap only for the retained new-source records read here; it does not close original business/performance gates.',
    distinct_artifact_source_scopes=4, original_primary_reports=8,
    groups=groups, totals=totals,
    total_scope='Occurrence counts across separate named executions, not globally unique requests or additional native tests. Dispatch and terminal populations overlap.',
    message_and_capture_bounds=dict(capacity_per_snapshot=16384, retention='first-N, no eviction; not an overwriting ring',
        all_19_snapshots_complete=all(r['computed_retained_coverage_complete'] for r in all_snapshots),
        maximum_actual_message_utf8_bytes=max((r['maximum_observed_message_utf8_bytes'] or 0) for r in all_snapshots),
        actual_truncated_messages=sum(r['truncated_diagnostic_messages'] for r in all_snapshots),
        actual_non_ascii_messages=sum(r['non_ascii_diagnostic_messages'] for r in all_snapshots),
        scope='The observed messages satisfy the 96-byte UTF8 bound. These traffic samples do not exercise non-ASCII truncation, capacity overflow or capture-contention failures; those scenarios are not labeled measured PASS.'),
    f0_root_evidence=dict(records=315, typed_code=None, existing_kind='unclassified', bounded_message_prefix='ROOT',
        same_rows_full_work_accepted=315, same_rows_execution_rejected=315,
        same_rows_root_commitment_completed_and_accepted=315,
        actual_full_work_thread_cpu_ns=root_cost['full_work_thread_cpu']['known_sum_ns'],
        actual_dispatch_thread_cpu_ns=root_cost['dispatch_thread_cpu']['known_sum_ns'],
        actual_admission_thread_cpu_ns=root_cost['submit_phases']['admission']['thread_cpu']['known_sum_ns'],
        actual_execution_thread_cpu_ns=root_cost['submit_phases']['execution']['thread_cpu']['known_sum_ns'],
        actual_root_commitment_thread_cpu_ns=root_cost['submit_phases']['root_commitment']['thread_cpu']['known_sum_ns'],
        scope='Original per-row cost fields retained for actual refusals. These nested caller-thread sums must not be added or treated as whole-worker cost. ROOT text does not turn phase null codes into typed ROOT.'),
    f0_cancel_and_eof=dict(dispatch_cancel=64, completed_dispatch_false=62,
        diagnostic_before_dispatch_started_and_outcome_unknown=2,
        same_record_cancel_and_terminal_eof=64, same_record_root_and_terminal_eof=3,
        terminal_eof_without_dispatch_diagnostic=18,
        scope='Two slots preserve distinct actual errors. They alone do not prove temporal order or causation. Complete observer retention does not mean every request entered dispatch.'),
    f0_existing_identity_correlation=root_phase['existing_identity_correlation'],
    unchanged_classification_and_reactor_sources=code_identity,
    source_semantics=[
        'request_observation.rs:28-53 copies existing ErrorKind and Display into diagnostic-only storage; it does not parse message text into an ErrorCode.',
        'request_observation.rs:56-79 keeps a maximum 96-byte prefix on a UTF8 boundary; untrusted text and no-control-authority flags are emitted explicitly.',
        'request_observation.rs:657-673 and787-791 retain error.code() in the original terminal/dispatch slots while capturing the additive diagnostic; actual terminal wait timing can include capture cost.',
        'Snapshot capture remains bounded and non-authoritative. Scope/counter failures are reported; original observation failures are never silently promoted to complete.',
        'The exact c5dd v4 reader validated all10372 records, including all19 phase slots, all wait intervals, typed code/diagnostic shape and the additive-extension constraints.'
    ],
    limits=readback['qualifications'],
    outputs=dict(readback_sha256=sha((OUT/'readback.json').read_bytes()),
        selected_original_rows_compressed_sha256=sha((OUT/'selected-original-rows.json.gz').read_bytes()),
        selected_original_rows_uncompressed_bytes=len(selected_raw),selected_original_rows_uncompressed_sha256=sha(selected_raw),
        selected_original_rows_independently_relocated_and_equal=verified_rows),
    native_executions_by_this_task=0, repository_or_target_changes=False,
    reader_attempt_scope='Two successful read-only parser runs of the same original bytes; no duplicated native denominator. First derived draft is retained after a wording clarification.')
write('summary.json',summary)
write('verification.json',dict(schema='diagnostic-observability-handoff-verification-v1',
    original_selected_rows_relocated=verified_rows, exact_row_value_and_canonical_hash_matches=verified_rows,
    all_original_bundle_digests_rechecked=True, typed_error_and_reactor_sources_unchanged_from_b280=True,
    complete_native_tests_or_performance_executed=False,
    summary_sha256=sha((OUT/'summary.json').read_bytes()),readback_sha256=sha((OUT/'readback.json').read_bytes())))
index=dict(schema='diagnostic-observability-artifact-index-v1',files={})
for path in sorted(OUT.rglob('*')):
    if path.is_file() and path.name!='artifact-index.json':
        raw=path.read_bytes();index['files'][str(path.relative_to(OUT))]=dict(bytes=len(raw),sha256=sha(raw))
write('artifact-index.json',index)
print(json.dumps(dict(groups=groups,totals=totals,summary_sha256=sha((OUT/'summary.json').read_bytes()),
    index_sha256=sha((OUT/'artifact-index.json').read_bytes()),selected_rows_verified=verified_rows)))
