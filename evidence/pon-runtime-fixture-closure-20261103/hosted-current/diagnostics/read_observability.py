#!/usr/bin/env python3
"""Read existing immutable hosted evidence; never execute native binaries."""
from __future__ import annotations

import collections
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types
import zipfile

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
REPO = Path('/workspace/scratch/b5a148b09b11/chain-six-axis')
HOSTED = Path('/workspace/scratch/b5a148b09b11/next-hosted')
C5 = 'c5dd7c7718925b951dc6e4d5ccc5a86ccfa8e3c1'
B4 = 'b4bdf142f513081715ecc8d1f9674291e85302cc'
PROFILE = dict(opt_level='3', debuginfo=0, debug_assertions=False,
               overflow_checks=False, test=True)
SPECS = [
    dict(id='c5dd-f0', bundle='c5dd7c-review/f0-selected-original-records.json.gz',
         bundle_sha='9d8f0cb98c8b66fee9f60277c011bd69f4ce06af9754035b43d46ef22adcefd9',
         compact='c5dd7c-review/f0-two-phase-terminal-readback.json',
         reports=['execution/raw/report.json'], source=('execution/source-before.json', 'execution/source-after.json'),
         binary='prepared/public_v3_multiprocess.bin', build='prepared/build.stdout.log'),
    dict(id='c5dd-three-campaigns', bundle='c5dd7c-review/original-three-campaign-selected-records.json.gz',
         bundle_sha='009de88d176c549718e4d89bd67f0a2ff2fee358f5c4df8c28ceeb8c38e89182',
         compact='c5dd7c-review/original-three-campaign-compact-terminal-readback.json',
         reports=[f'run-{i}-raw/report.json' for i in (1, 2, 3)],
         source=('source-before.json', 'source-after.json'),
         binary='public_v3_multiprocess.bin', build='build.stdout.log',
         archive='c5dd7c-review/c5dd7c-original-campaign-13276003536.zip',
         archive_sha='78e1b41ced06d6b77568a132d60623a1a7b5059ef9791dd43cc8ed4110efaacb'),
    dict(id='b4b-w1-head', bundle='b4bdf-review/w1-fresh-head-selected-original-records.json.gz',
         bundle_sha='6a0e7b09ad2fa5d934d1be3bea582715cab37d4723d30212a383a4c7307ef97b',
         compact='b4bdf-review/w1-fresh-head-terminal-readback.json',
         reports=['fresh-service/original/report.json', 'fresh-service/fresh/report.json'],
         source=('source.json', 'source-after.json'),
         binary='fresh-service/public_v3_from_zero', build='fresh-service/build.log'),
    dict(id='b4b-w1-merge', bundle='b4bdf-review/w1-fresh-merge-selected-original-records.json.gz',
         bundle_sha='675b6f08c059e9d1e0275ce0fe8c31124b98a821ebaa4cb1ee10203db7cb967e',
         compact='b4bdf-review/w1-fresh-merge-terminal-readback.json',
         reports=['fresh-service/original/report.json', 'fresh-service/fresh/report.json'],
         source=('source.json', 'source-after.json'),
         binary='fresh-service/public_v3_from_zero', build='fresh-service/build.log'),
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def count_rows(counter, fields):
    return [dict(zip(fields, key), count=n)
            for key, n in sorted(counter.items(), key=lambda item: repr(item[0]))]


def stat(values):
    known = [n for n in values if n is not None]
    assert all(type(n) is int and n >= 0 for n in known)
    return dict(known=len(known), unknown=len(values)-len(known),
                known_sum_ns=sum(known), minimum_ns=min(known, default=None),
                maximum_ns=max(known, default=None))


def git_source(revision, path):
    return subprocess.check_output(['git', '--no-replace-objects', 'show', revision + ':' + path], cwd=REPO)


def load_original_reader():
    for name in ('pon_public_v3_policy_read', 'pon_public_v3_phase_read'):
        path = 'scripts/' + name + '.py'
        module = types.ModuleType(name)
        module.__file__ = str(REPO / path)
        sys.modules[name] = module
        exec(compile(git_source(C5, path), 'git:' + C5 + ':' + path, 'exec'), module.__dict__)
    return sys.modules['pon_public_v3_phase_read']


def detail_key(row, slot):
    detail = row.get('error_diagnostics', {}).get(slot)
    return ((row.get(slot + '_error_code'), detail['kind'], detail['message_prefix'],
             detail['message_truncated']) if detail is not None else (None, None, None, None))


def cost_summary(rows):
    phases = {}
    for name in READER.PHASES_V4:
        actual = [next(p for p in row['submit_phases'] if p['phase'] == name) for row in rows]
        started = [p for p in actual if p['started']]
        phases[name] = dict(started=len(started), completed=sum(p['completed'] for p in started),
            accepted=sum(p.get('accepted') is True for p in started),
            rejected=sum(p.get('accepted') is False for p in started),
            unknown_outcome=sum(p.get('accepted') is None for p in started),
            unchanged_typed_error_slots=count_rows(collections.Counter(
                (p.get('error_code'), p.get('accepted')) for p in started), ['typed_error_code','accepted']),
            wall=stat([p.get('wall_ns') for p in started]),
            thread_cpu=stat([p.get('thread_cpu_ns') for p in started]))
    return dict(records=len(rows),
        full_work_started=sum(r['full_work_started'] for r in rows),
        full_work_outcomes=count_rows(collections.Counter((r['full_work_accepted'],) for r in rows), ['accepted']),
        full_work_thread_cpu=stat([r['full_work_thread_cpu_ns'] for r in rows if r['full_work_started']]),
        dispatch_started=sum(r['dispatch_started'] for r in rows),
        dispatch_outcomes=count_rows(collections.Counter((r['dispatch_accepted'],) for r in rows), ['accepted']),
        dispatch_thread_cpu=stat([r['dispatch_thread_cpu_ns'] for r in rows if r['dispatch_started']]),
        submit_phases=phases)


def digest(value):
    return bytes(value).hex() if isinstance(value, list) else value


def correlate(phase, rows):
    """Only exact existing public-body identities. Never align unrelated clocks."""
    by_body = collections.defaultdict(list)
    for i, row in enumerate(rows):
        if row.get('body_digest') is not None:
            by_body[digest(row['body_digest'])].append((i, row))
    populations = {'honest': [], 'attack': []}
    for name in ('submissions', 'history', 'honest_heads', 'honest_history', 'honest_submissions'):
        populations['honest'].extend(phase.get(name, []))
    for child in phase.get('children', []):
        result = (child.get('report') or {}).get('result') or {}
        populations['attack'].extend(result.get('calls', []))
    for attack in phase.get('attacks', []):
        populations['attack'].extend(attack.get('calls', []))
    output = {}
    sets = {}
    for actor, calls in populations.items():
        counts = collections.Counter()
        examples = []
        ids = {call.get('public_request_body_digest') for call in calls} - {None}
        sets[actor] = ids
        for i, call in enumerate(calls):
            body = call.get('public_request_body_digest')
            if body is None:
                counts['no_public_body_digest'] += 1
                continue
            matches = by_body.get(body, [])
            state = ('unmatched' if not matches else 'unique_receiver_record' if len(matches) == 1 else 'ambiguous_multiple_receiver_records')
            counts[state] += 1
            if len(matches) == 1 and len(examples) < 4:
                ri, row = matches[0]
                examples.append(dict(call_index_in_actor_population=i, body_digest=body,
                    receiver_record_index=ri, receiver_connection_id=row.get('connection_id'),
                    client_status=call.get('status'), client_error=call.get('error'),
                    receiver_dispatch=list(detail_key(row, 'dispatch')),
                    receiver_terminal=list(detail_key(row, 'terminal'))))
        output[actor] = dict(client_calls=len(calls), existing_public_body_digests=len(ids),
            match_counts=dict(counts), unique_match_examples=examples)
    overlap = sets['honest'] & sets['attack']
    for actor, bodies in sets.items():
        exclusive = bodies - overlap
        matched = [row for body in exclusive for _, row in by_body.get(body, [])]
        output[actor]['exclusive_body_group_receiver_records'] = len(matched)
        output[actor]['exclusive_body_group_dispatch_diagnostics'] = count_rows(collections.Counter(
            detail_key(row, 'dispatch') for row in matched if row.get('error_diagnostics', {}).get('dispatch') is not None),
            ['typed_error_code', 'kind', 'message_prefix', 'message_truncated'])
    output['overlapping_honest_and_attack_body_digests'] = len(overlap)
    output['scope'] = ('Body-population membership is not a one-to-one attempt match. Only exactly one retained receiver row is labeled a unique match. '
        'No identity is inferred from recorded_request_digest, error strings or observer-local timestamps; missing identities remain unknown.')
    return output


def snapshot_summary(phase, key, report_member, source_id):
    snap = phase[key]
    rows = snap['records']
    failures = []
    for i, row in enumerate(rows):
        try:
            READER.validate_v4_record(row)
        except Exception as error:
            failures.append(dict(record=i, error=str(error)))
    assert not failures, (source_id, report_member, failures)
    assert snap['schema'] == 'public-v3-local-request-resource-observation-v4'
    assert snap['observation_has_consensus_authority'] is False
    assert all('error_diagnostics' in row for row in rows)
    descriptors = ['typed_error_code', 'kind', 'message_prefix', 'message_truncated']
    diagnostics = {slot: count_rows(collections.Counter(detail_key(r, slot) for r in rows
        if r['error_diagnostics'][slot] is not None), descriptors) for slot in ('dispatch', 'terminal')}
    details = [r['error_diagnostics'][slot] for r in rows for slot in ('dispatch', 'terminal')
               if r['error_diagnostics'][slot] is not None]
    buckets = collections.defaultdict(list)
    for row in rows:
        if row['error_diagnostics']['dispatch'] is not None:
            buckets[detail_key(row, 'dispatch')].append(row)
    costs = [dict(zip(descriptors, key), cost=cost_summary(group)) for key, group in sorted(buckets.items(), key=lambda x: repr(x[0]))]
    ids = [r.get('connection_id') for r in rows if r.get('connection_id') is not None]
    output = dict(snapshot_key=key, mode=phase.get('mode', phase.get('name')),
        snapshot_canonical_sha256=sha(canonical(snap)),
        scope_flags={k:v for k,v in snap.items() if k != 'records'}, records=len(rows),
        original_phase_observer_complete=phase.get('observer_complete'),
        computed_retained_coverage_complete=(snap['records_not_retained'] == 0 and snap['measurement_failures'] == 0
            and not snap['counter_overflow'] and snap['accepted_connections_seen'] == len(rows)
            and all(r['complete'] and not r['observation_failed'] for r in rows)),
        retained_complete_records=sum(r['complete'] for r in rows),
        observation_failed_records=sum(r['observation_failed'] for r in rows),
        connection_ids_present=len(ids), duplicate_connection_id_occurrences=len(ids)-len(set(ids)),
        extension_present_records=len(rows), original_v4_reader_validated_records=len(rows),
        diagnostic_counts=diagnostics,
        dispatch_rejected_records=sum(r['dispatch_accepted'] is False for r in rows),
        rejected_dispatch_without_captured_diagnostic=sum(r['dispatch_accepted'] is False and r['error_diagnostics']['dispatch'] is None for r in rows),
        diagnostic_captured_before_dispatch_started=sum(not r['dispatch_started'] and r['error_diagnostics']['dispatch'] is not None for r in rows),
        diagnostic_captured_with_dispatch_outcome_unknown=sum(r['dispatch_accepted'] is None and r['error_diagnostics']['dispatch'] is not None for r in rows),
        no_dispatch_diagnostic_captured=sum(r['error_diagnostics']['dispatch'] is None for r in rows),
        no_terminal_diagnostic_captured=sum(r['error_diagnostics']['terminal'] is None for r in rows),
        maximum_observed_message_utf8_bytes=max((len(d['message_prefix'].encode()) for d in details), default=None),
        truncated_diagnostic_messages=sum(d['message_truncated'] for d in details),
        non_ascii_diagnostic_messages=sum(not d['message_prefix'].isascii() for d in details),
        same_record_dispatch_terminal_pairs=count_rows(collections.Counter(
            detail_key(r, 'dispatch') + detail_key(r, 'terminal') for r in rows),
            ['dispatch_typed_code','dispatch_kind','dispatch_message_prefix','dispatch_message_truncated',
             'terminal_typed_code','terminal_kind','terminal_message_prefix','terminal_message_truncated']),
        whole_retained_snapshot_cost=cost_summary(rows), dispatch_diagnostic_costs=costs,
        original_phase_parameters={k:phase[k] for k in ('duration_seconds','requested_window_ns','public_resource_policy','policy_id','finite_phase_criteria_met','finite_target_met') if k in phase},
        existing_identity_correlation=correlate(phase, rows))
    # One actual full row per observed distinct pair/outcome, bounded to 12 per snapshot.
    seen = set()
    selected = []
    for i, row in enumerate(rows):
        pair = detail_key(row, 'dispatch') + detail_key(row, 'terminal') + (row['dispatch_accepted'], row['full_work_accepted'])
        if pair in seen or len(selected) >= 12:
            continue
        seen.add(pair)
        selected.append(dict(source_id=source_id, report_member=report_member,
            phase_mode=output['mode'], snapshot_key=key, record_index=i,
            row_canonical_sha256=sha(canonical(row)), row=row))
    return output, selected


def main():
    sources = []
    files = ['trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs',
             'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs',
             'trillionnium/crates/trnm-pon-node/src/error.rs',
             'scripts/pon_public_v3_phase_read.py', 'scripts/pon_public_v3_policy_read.py',
             'scripts/ci/test_pon_public_v3_phase_read.py']
    for path in files:
        identities = []
        for revision in (C5, B4):
            raw = git_source(revision, path)
            identities.append(dict(commit=revision, bytes=len(raw), sha256=sha(raw),
                git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()))
        sources.append(dict(path=path, identities=identities,
            bytes_equal_across_c5dd_and_b4b=identities[0]['sha256'] == identities[1]['sha256']))
    assert all(s['bytes_equal_across_c5dd_and_b4b'] for s in sources)
    write('source-identities.json', dict(schema='diagnostic-observability-source-identities-v1', files=sources,
        scope='Exact Git source objects only. No claim that different executed whole commits or ELF identities are interchangeable.'))
    scopes = []
    examples = []
    for spec in SPECS:
        bundle_path = HOSTED / spec['bundle']; raw_bundle = bundle_path.read_bytes()
        assert sha(raw_bundle) == spec['bundle_sha'], spec['id']
        bundle = json.loads(gzip.decompress(raw_bundle))
        records = bundle.get('selected_records', bundle.get('records'))
        by_name = {}
        for rec in records:
            raw = rec['text'].encode('utf-8')
            assert len(raw) == rec['bytes'] and sha(raw) == rec['sha256'], rec['member']
            assert rec['member'] not in by_name
            by_name[rec['member']] = rec
        compact_path = HOSTED / spec['compact']; compact_raw = compact_path.read_bytes(); compact = json.loads(compact_raw)
        archive_path = HOSTED / spec['archive'] if 'archive' in spec else Path(bundle['artifact_file'])
        archive_sha = spec.get('archive_sha', bundle.get('artifact_sha256'))
        assert sha(archive_path.read_bytes()) == archive_sha
        binary_info = compact['binary']
        expected_binary = binary_info.get('sha256', binary_info.get('sha256_before'))
        verified_entries = []
        with zipfile.ZipFile(archive_path) as archive:
            binary_raw = archive.read(spec['binary'])
            assert len(binary_raw) == binary_info['bytes'] and sha(binary_raw) == expected_binary
            assert binary_raw[:4] == b'\x7fELF'
            del binary_raw
            for name in list(spec['source']) + [spec['build']] + spec['reports']:
                raw = archive.read(name); rec = by_name[name]
                assert sha(raw) == rec['sha256'] and len(raw) == rec['bytes']
                verified_entries.append({k:rec[k] for k in ('member','bytes','sha256')})
        before = json.loads(by_name[spec['source'][0]]['text']); after = json.loads(by_name[spec['source'][1]]['text'])
        assert before == after and before['tracked_worktree_verified'] is True
        assert before['tested_commit'] == compact.get('tested_commit', compact['candidate'])
        assert before['tested_tree'] == compact['tested_tree']
        compiler = []
        for line in by_name[spec['build']]['text'].splitlines():
            try: message = json.loads(line)
            except ValueError: continue
            if message.get('reason') == 'compiler-artifact' and message.get('executable') and message.get('target', {}).get('name') in ('public_v3_multiprocess','public_v3_from_zero'):
                compiler.append(message)
        assert len(compiler) == 1 and compiler[0]['profile'] == PROFILE, spec['id']
        scope = dict(id=spec['id'], bundle=dict(path=str(bundle_path), bytes=len(raw_bundle), sha256=sha(raw_bundle)),
            compact=dict(path=str(compact_path), bytes=len(compact_raw), sha256=sha(compact_raw)),
            archive=dict(path=str(archive_path), bytes=archive_path.stat().st_size, sha256=archive_sha),
            run_id=compact['run_id'], job_id=compact['job_id'], source_before_after=before,
            elf=dict(archive_member=spec['binary'], bytes=binary_info['bytes'], sha256=expected_binary, actual_archive_bytes_rehashed=True),
            compiler_artifact=compiler[0], verified_original_entries=verified_entries,
            lossless_bundle_records_hash_verified=len(records), reports=[])
        for name in spec['reports']:
            report = json.loads(by_name[name]['text'])
            rep = dict(member=name, raw_entry_sha256=by_name[name]['sha256'], raw_entry_bytes=by_name[name]['bytes'],
                schema=report['schema'], original_top_level_scope={k:report[k] for k in
                    ('scope','requested_window_ns','phase_seconds','target','public_resource_policy','parameters','settings_profile',
                     'finite_target_met','finite_experiment_criteria_met','original_campaign_qualified','production_candidate',
                     'production_activation','release_ready','work_profile_qualified','resource_fairness_qualified','wan_qualified') if k in report},
                snapshots=[])
            for i, phase in enumerate(report['phases']):
                keys = [k for k in ('receiver_observation','observations') if k in phase]
                assert len(keys) == 1, (spec['id'], name, i, keys)
                item, selected = snapshot_summary(phase, keys[0], name, spec['id'])
                item['json_pointer'] = f'/phases/{i}/{keys[0]}'
                for row in selected:
                    row['json_pointer'] = item['json_pointer'] + '/records/' + str(row['record_index'])
                rep['snapshots'].append(item); examples.extend(selected)
            scope['reports'].append(rep)
        scopes.append(scope)
    result = dict(schema='hosted-actual-error-diagnostic-observability-readback-v1',
        observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        native_executions=0, repository_source_or_target_writes=False, scratch_only_reader_and_evidence=True, downloaded_artifacts=0,
        original_reader_revision=C5, scopes=scopes,
        qualifications=[
            'Rows are counted once from the primary report for each actual execution, never again from its raw per-phase duplicate or a derived summary.',
            'Retained coverage concerns accepted connections in these snapshots only. It does not account for unaccepted network attempts or any unobserved population.',
            'Null typed codes remain null. ROOT/WORK text is bounded untrusted diagnostic evidence, not a typed error, owner-stop origin, authorization, or retry instruction.',
            'Dispatch and terminal diagnostics are independent slots on the same connection. Terminal EOF does not overwrite or reclassify a separately captured dispatch cause; the two slots alone do not establish temporal or causal order.',
            'Phase and full-W1 CPU/wall fields are retained, including rejection/cancellation samples. Nested intervals are not additive; caller-only CPU is not whole-worker CPU.',
            'No timing values are asserted unchanged by capture overhead. No qualification, speedup, business confirmation or original-budget acceptance is inferred.',
            'No historical116 records are modified, labeled or counted. No missing message, typed code, phase outcome or caller identity is backfilled.',
            'Actual retained samples do not test dropped-ring behavior or non-ASCII truncation unless such samples are explicitly counted. Source bounds and existing tests are separate evidence.'
        ])
    write('readback.json', result)
    raw_examples = json.dumps(dict(schema='limited-original-diagnostic-row-examples-v1',
        scope='Actual unchanged JSON row values selected by original report pointer; canonical row SHA is explicitly distinct from the original report-byte SHA.',
        examples=examples), ensure_ascii=False, indent=2).encode() + b'\n'
    (OUT/'selected-original-rows.json.gz').write_bytes(gzip.compress(raw_examples, mtime=0))
    print(json.dumps(dict(scopes=len(scopes), snapshots=sum(len(r['snapshots']) for s in scopes for r in s['reports']),
        records=sum(p['records'] for s in scopes for r in s['reports'] for p in r['snapshots']),
        selected_original_rows=len(examples), readback_sha256=sha((OUT/'readback.json').read_bytes()), native_executions=0)))


READER = load_original_reader()
if __name__ == '__main__':
    main()
