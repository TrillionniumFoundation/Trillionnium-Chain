#!/usr/bin/env python3
"""Read-only audit of pinned, already-completed C8 lifecycle records.

This program reads only its acquired local readset and creates a new external
evidence bundle. It does not run Node, tests, signals, SQL, or binary hashing.
"""
import hashlib
import gzip
import io
import json
import re
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / 'bundle'
COMMIT = '4e007a87ceecbec8d265f6a70cfd71d512a514b5'
TREE = '19a4f1a6e1cec5c27e595fa555b97cddc4717a3c'
SOURCE = {'commit': COMMIT, 'tree': TREE}
OP = 'a35153e046b91421e3d8d67c0d5f053b88a87f4f8ac8213f8e3ee09f5f1be1e9'
STATEMENT = 'a2dd4830465ce6192ef48b53be74582feb886b526a93fb4f8e8f52b1c7cb80e2'
ROOT = '/home/qian-qi/work/chain-w1-c8-timeout-reorg-20261108-ec265b-01'
JOBS = {'main': '1a1baa770fd-12894-1c3b', 'cold': '1a1baac4fa2-12894-1c66'}
QUAL_MANIFEST = 'd087c47faef1290bfb88edee517c1ee41dee06f23e04ac0ffad1af37c87e8f76'
QUAL_SUMMARY = '8137d11fb7db4995a550cbc073c132315dd5828ab23ec712cece1583a6989bfb'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError('Duplicate JSON key: ' + key)
        out[key] = value
    return out

def load(data):
    return json.loads(data.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                      parse_constant=lambda v: (_ for _ in ()).throw(ValueError(v)))

def dump(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')

def equal(actual, expected):
    # Canonical JSON comparison preserves bool/int and int/float distinctions.
    assert dump(actual) == dump(expected), (actual, expected)

def int_value(value):
    assert type(value) is int and value >= 0
    return value

def main():
    readset_bytes = ((HERE / 'readset.json').read_bytes() if (HERE / 'readset.json').exists()
                     else gzip.decompress((HERE / 'readset.json.gz').read_bytes()))
    readset = load(readset_bytes)
    raw = {}
    records = {}
    index = []
    byname = {}
    for item in readset['files']:
        data = item['text'].encode('utf-8')
        assert len(data) == item['bytes'] and sha(data) == item['sha256']
        name = item['name']
        assert re.fullmatch(r'[a-z0-9-]+\.json', name) and name not in raw
        raw[name] = data
        records[name[:-5]] = load(data)
        byname[name[:-5]] = item
        index.append({'member': name, 'bytes': len(data), 'sha256': sha(data),
                      'original_path': item['source_path'], 'kind': 'original-json'})
    assert len(raw) == 18
    job_summary = {}
    for role, job in JOBS.items():
        exits = records[role + '-job-exit']
        assert exits['job_id'] == job
        equal(exits['exit_code'], 0)
        for k in ('cancelled', 'timed_out'):
            assert exits[k] is False
        for k in ('output_complete', 'output_durable'):
            assert exits[k] is True
        logs = readset['job_log_reads'][role]
        assert logs['job_id'] == job
        for stream in ('stdout', 'stderr'):
            item = logs[stream]
            data = bytes.fromhex(item['bytes_hex'])
            assert data.decode('utf-8', 'strict') == item['text']
            assert item['eof'] is True and item['offset'] == 0
            assert item['next_offset'] == len(data) == item['size']
            equal(exits['log_bytes'][stream], {'seen': len(data), 'stored': len(data)})
            assert exits['log_synced'][stream] is True
            assert exits['log_truncated'][stream] is False
            assert exits['log_errors'][stream] is None
            if stream == 'stderr':
                assert data == b''
            name = role + '-job.' + stream
            raw[name] = data
            index.append({'member': name, 'bytes': len(data), 'sha256': sha(data),
                          'job_id': job, 'kind': 'original-durable-job-stream'})
        text = logs['stdout']['text']
        outcomes = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; 0 measured; \d+ filtered out; finished in ([0-9.]+)s$', text, re.M)
        assert len(outcomes) == 1 and outcomes[0][:3] == ('1', '0', '0')
        exact = ('funded_fresh_full_w1_generation_timeout_then_refund_and_reorg'
                 if role == 'main' else 'funded_w1_owner_cancellation_cold_reconcile')
        assert text.count('test store::async_w1_generation_v2::tests::heavy::' + exact + ' ... ok\n') == 1
        job_summary[role] = {'job_id': job, 'exit_code': 0, 'output_complete': True,
                             'output_durable': True, 'passed': 1, 'failed': 0,
                             'ignored': 0, 'reported_seconds': outcomes[0][3],
                             'exit_sha256': byname[role + '-job-exit']['sha256'],
                             'stdout_sha256': sha(raw[role + '-job.stdout'])}
    m = records['main-result']
    r = records['reorg-result']
    f = records['typed-failure']
    c = records['cold-result']
    plan = records['plan']
    cfg = records['config']
    launch = records['launch-declaration']
    final = records['terminal-readonly-observation']
    prep = records['preparation-provenance']
    req = records['owner-cancel-requested']
    accepted = records['owner-cancel-m12-outcome']
    od = records['owner-declaration']
    start = records['start-result']
    gates = records['complete-gates']
    coldlaunch = records['cold-launch-intent']
    probe = records['runner-source-probe']
    for rec in (plan, launch, prep, gates, final, coldlaunch, probe):
        equal(rec['source'], SOURCE)
    equal({'commit': cfg['expected_commit'], 'tree': cfg['expected_tree']}, SOURCE)
    assert cfg['repo'] == '/home/qian-qi/work/chain-w1-base9417-integration-20261108-ec265b'
    assert cfg['research_node_path'] == ROOT + '/research-node'
    assert cfg['provider_operation'] == plan['operation'] == m['original_provider_operation'] == OP
    assert cfg['out'] == ROOT + '/run' and cfg['target_root'] == ROOT + '/target-state'
    assert cfg['original_boot_id'] == final['current_boot_id']
    added = set(cfg) - set(plan['config_without_clock'])
    assert added == {'launch_observation', 'original_boot_id', 'original_deadline_declaration', 'original_deadline_ns'}
    equal({k: cfg[k] for k in plan['config_without_clock']}, plan['config_without_clock'])
    assert plan['deadline_selected'] is False and plan['winner_or_proof_started'] is False
    equal(plan['maximum_original_budget_ns'], 120_000_000_000)
    equal(launch['config']['sha256'], byname['config']['sha256'])
    equal(launch['plan']['sha256'], byname['plan']['sha256'])
    equal(coldlaunch['config']['sha256'], byname['config']['sha256'])
    equal(plan['owner_binary'], launch['owner_binary'])
    equal(coldlaunch['owner_binary'], launch['owner_binary'])
    assert launch['owner_binary']['sha256'] == cfg['owner_test_binary_sha256'] == od['owner_test_binary_sha256']
    equal(plan['driver'], launch['driver'])
    equal(prep['driver'], plan['driver'])
    equal(cfg['launch_observation'], launch['original_identity'])
    assert od['config_sha256'] == byname['config']['sha256']
    assert od['research_genesis_only'] is True and od['public_chain_transactions_sent'] is False
    equal(od['native_obligation_units'], 1000)
    d = cfg['original_deadline_declaration']
    assert d['operation'] == OP and d['plan_sha256'] == byname['plan']['sha256']
    assert d['deadline_can_be_renewed'] is False
    selected = int_value(d['selected_monotonic_ns'])
    deadline = int_value(cfg['original_deadline_ns'])
    equal(deadline - selected, 120_000_000_000)
    equal(d['original_deadline_ns'], deadline)
    equal(launch['original_deadline_ns'], deadline)
    equal(launch['selected_monotonic_ns'], selected)
    assert launch['proof_deadline_can_be_extended'] is False
    for rec in (m, r, c, req, od, start, m['target_terminal_observation']):
        equal(rec['original_deadline_ns'], deadline)
    obs = m['target_terminal_observation']
    target = obs['observation']['target']
    result = target['result']
    equal(target, c['target_observation']['retained_target_readback'])
    for rec in (start, obs):
        assert rec['operation'] == OP and rec['config_sha256'] == byname['config']['sha256']
        equal({k: rec['source'][k] for k in ('commit', 'tree')}, SOURCE)
        assert rec['source']['raw_file_pins_checked'] is True
        equal(rec['source']['source_files'], cfg['source_files'])
    for key in ('operation', 'statement', 'target_instance', 'task_scope', 'request_sha256', 'worker', 'original_deadline_monotonic_ns'):
        equal(start['target_readback'][key], target[key])
    assert target['operation'] == result['operation'] == f['operation'] == c['original_operation'] == OP
    assert target['statement'] == f['statement'] == c['original_statement'] == req['statement'] == STATEMENT
    assert target['target_instance'] == cfg['target_instance']
    equal(target['worker'], start['original_job'])
    equal(target['worker'], req['original_job'])
    equal(target['worker'], obs['observation']['original_job'])
    assert result['request_sha256'] == target['request_sha256'] == req['original_job']['request_sha256']
    equal(result['provider_job'], target['worker'])
    for rec in (target, result):
        equal(rec['original_deadline_monotonic_ns'], deadline)
        assert rec['sticky_cancel'] is False and rec['may_dispatch_again'] is False
        assert rec['can_authorize_payment'] is False
    assert target['state'] == 'terminal' and result['cause'] == 'original-deadline'
    equal(result['exit_code'], -9)
    assert result['command_success'] is False and result['error'] is None
    assert result['direct_child_reaped'] is True and result['all_owned_processes_terminal'] is True
    assert result['all_descendants_reaped'] is None and result['resource_qualification'] == 'unknown'
    assert result['resources']['gpu_ns'] is None and result['resources']['memory_peak_bytes'] is None
    assert start['fresh_generation_started'] is True and start['owned_generation_still_active'] is True
    assert start['owner_cancel_performed'] is False
    live = int_value(start['trigger']['observed_monotonic_ns'])
    finish = int_value(result['finished_monotonic_ns'])
    failure_at = int_value(f['recorded_monotonic_ns'])
    requested_at = int_value(req['requested_monotonic_ns'])
    assert selected < live < deadline < finish < obs['completed_monotonic_ns'] < failure_at < requested_at
    assert req['start_observation_sha256'] == byname['start-result']['sha256']
    assert req['request_is_not_acceptance'] is True
    assert req['provider_failure_is_not_owner_authority'] is True
    assert f['failure_kind'] == 'Unknown' and f['consumed'] is None and f['cancellation_at_failure'] is None
    for key in ('m12_resource_cap_retained', 'recorded_before_owner_veto'):
        assert f[key] is True
    assert f['native_refund_authorized'] is False and f['provider_payment_authorized'] is False
    assert accepted['accepted_observed'] is True and accepted['decision'] == 'CancellationObserved'
    assert accepted['resource_reservation_released'] is False
    assert accepted['journal_event_new'] is None and accepted['new_event_proven'] is False
    assert accepted['reason_sha256'] == req['reason_sha256'] == m['m12_cancellation_reason'] == c['cancellation']
    assert m['target_cancel_command']['target_cancel_request_sent'] is False
    assert m['target_cancel_command']['deadline_renewed'] is False
    for key in ('real_expensive_generation_started', 'original_deadline_timeout_observed',
                'm12_terminal_failure_recorded_before_owner_veto', 'explicit_owner_cancel_accepted',
                'm12_original_resource_cap_retained'):
        assert m[key] is True
    for key in ('deadline_renewed', 'full_proof_verified', 'node_positive',
                'production_qualified', 'provider_payment_observed', 'public_chain_transactions_sent'):
        assert m[key] is False
    assert m['all_descendants_reaped'] is None and m['gpu_accounting'] == 'UNKNOWN'
    equal(m['new_complete_proofs'], 0)
    equal(m['fresh_generation_attempts'], 1)
    assert m['m12_failure_kind'] == 'Unknown' and m['m12_cold_begin'] == 'Done'
    equal(m['native_reorg_roundtrip'], r)
    equal(r['before_reorg'], r['original_cancel_restored'])
    equal(r['cancel_removed'], r['actual_cold_reopen'])
    equal(m['native_task'], r['original_cancel_restored'])
    equal(c['native_task'], r['original_cancel_restored'])
    restored, removed = r['original_cancel_restored'], r['cancel_removed']
    assert restored['canonical_cancel_observed'] is True and removed['canonical_cancel_observed'] is False
    assert restored['canonical_inclusion'] == r['original_cancel_tip'] and removed['canonical_inclusion'] is None
    assert len({r['original_cancel_tip'], r['alternate_tip'], r['restored_tip']}) == 3
    assert restored['funding_row']['status'] == 'cancelled' and removed['funding_row']['status'] == 'reserved'
    equal(restored['funding_row']['remaining'], 0)
    equal(removed['funding_row']['remaining'], 1000)
    equal(restored['gross_owner_refund_units'], 1000)
    assert removed['gross_owner_refund_units'] is None and removed['refund_claim'] is False
    assert restored['refund_claim'] is True
    for rec in (restored, removed):
        assert rec['net_account_delta_not_claimed'] is True
        assert rec['new_transaction_submitted'] is False and rec['native_cancel_attempt_retained'] is True
        assert rec['original_operation'] == 'dba9793565d7ae83790eaba3abb255fad2643d9b2d5696196a426ae289c7d83f'
    assert r['provider_operation'] == OP and r['statement'] == STATEMENT
    assert r['provider_balance_unchanged'] is True and r['m12_readback_unchanged'] is True
    assert r['m12_dispatch_begin'] == c['m12_begin'] == 'Done'
    assert r['m12_original_resource_cap_retained'] is True and c['original_resource_cap_retained'] is True
    for key in ('new_generation_dispatches', 'new_native_cancel_transactions', 'new_target_cancel_requests'):
        equal(r[key], 0)
    for key in ('new_generation_dispatches', 'native_transactions_submitted', 'target_cancel_requests_sent'):
        equal(c[key], 0)
    assert r['new_cancel_wire_signed'] is False and r['deadline_renewed'] is False
    assert c['deadline_renewed'] is False and c['can_authorize_payment'] is False
    assert c['target_process_scope_reconciled_by_this_reader'] is False
    assert c['target_observation']['fresh_recursive_process_scope_qualification'] is False
    actual = c['target_observation']['actual_command']
    equal(actual['returncode'], 0)
    equal(actual['original_proof_deadline_ns'], deadline)
    assert actual['proof_deadline_renewed'] is False and actual['timed_out'] is False
    assert actual['direct_child_waited'] is True and actual['all_descendants_reaped'] is None
    assert actual['can_authorize_payment'] is False and OP in actual['argv']
    assert cfg['target_root'] in actual['argv'] and cfg['target_instance'] in actual['argv']
    assert 'reconcile' in actual['argv']
    assert final['started_monotonic_ns'] > actual['completed_monotonic_ns']
    assert final['root'] == ROOT and final['all_history_reaped'] is None
    for key in ('signals_sent', 'new_dispatches'):
        equal(final[key], 0)
    assert final['private_databases_read'] is False and final['environment_read'] is False
    expected_identities = {'owner': start['owner_identity'], 'worker': target['worker']['identity'],
                           'direct-child': result['child_identity'],
                           'runner': start['trigger']['stage_runner']['identity'],
                           'r0vm': start['trigger']['prover_identity']}
    assert len(final['known_processes']) == 5
    for item in final['known_processes']:
        equal(item['expected'], expected_identities[item['role']])
        assert item['status'] == 'ABSENT' and item['same_identity'] is False
        equal(item['signals_sent'], 0)
    assert len(final['owned_cgroups']) == 2 and len(final['exact_units']) == 2
    for item in final['owned_cgroups']:
        assert item['status'] == 'ABSENT' and item['all_history_reaped'] is None and item['recursive_empty'] is None
    assert {x['job_id'] for x in final['exact_units']} == set(JOBS.values())
    for item in final['exact_units']:
        equal(item['returncode'], 0)
        assert 'MainPID=0\n' in item['stdout'] and 'LoadState=not-found\n' in item['stdout'] and 'ActiveState=inactive\n' in item['stdout']
    assert prep['complete_gate_binding']['sha256'] == byname['complete-gates']['sha256']
    equal(prep['attempt_accounting'], gates['attempt_accounting'])
    equal(gates['attempt_accounting']['all_declared_qualification_attempts'],
          {'commands': 77, 'executed_methods': 697, 'passed_methods': 696, 'failed_methods': 1, 'ignored_methods': 4})
    equal(gates['attempt_accounting']['qualifying_coverage'],
          {'commands': 73, 'passed_methods': 665, 'failed_methods': 0, 'ignored_methods': 4})
    assert gates['all_first_attempts_passed'] is False and gates['prior_qualification_failures_preserved'] is True
    assert gates['operation_created'] is False and gates['deadline_selected'] is False
    assert prep['C7_unknown_request_replayed'] is False
    assert gates['provider_payment_authorized'] is False
    assert gates['global_historical_reap_or_full_resource_accounting_established'] is False
    expected_manifests = {
        'backend': 'a3d530e67e3fd916f3c5e906ba0b851c00c3393cef0173db443d644109e1a47d',
        'native': '0fcf604c56d415907fc721f9262d7b6a843b1db49cd62246d706ccf8d319f310',
        'owner': '6d9013a9ee10badb278215ac1ac81243ada13cd5c279cbc3833250cc50c63bef',
        'core': 'ed8cd6e6d6e2772ec0bbfc97181581df53e2d116d0c76823f3a68e90defe3daf',
        'receiver': '6cefe7af75dc4f075b26bb1f8ac77693769f16ce4a31173708399f334ebda29b',
        'historical-regressions': 'eef45c33e9aae4650c70fcaefc174841e6f75cd8c018139705d459e1fc71c1e6',
        'history-compile-list': 'b39888daf3d2223c6600a693f663ca213698dffd6d9854ee887afd36af741738',
        'staged-isolated': 'f7c7527fb00f542021f0c7ab0469b2c0f2905e0f71b9b55f5e577b8f94c3104f',
    }
    equal({x['role']: x['manifest']['sha256'] for x in gates['gates']}, expected_manifests)
    equal({x['role']: x['manifest']['sha256'] for x in prep['gate_manifests']}, expected_manifests)
    assert sum(x['actual_command_count'] for x in gates['gates']) == 73
    assert sum(x['actual_passed_tests'] for x in gates['gates']) == 665
    assert gates['strict_owner_import']['sha256'] == prep['owner_schema_import_original']['sha256'] == 'd7ce0440c68a30cd6a00c5c1e964a1a360f27767848bdca63667991e3f7d2619'
    assert probe['source_probe_stage_intentionally_unknown'] is True and probe['exit'] == 1
    assert probe['proof_launched'] is False and probe['checkpoint_path_created'] is False
    assert probe['runner']['sha256'] == cfg['runner']['sha256'] == start['trigger']['stage_runner']['executable_sha256']
    for rec in probe['raw_source_identity_records']:
        assert rec['stage'] == 'RAW_COMMITTED_SOURCE_VERIFIED'
        assert rec['identity']['tested_commit'] == COMMIT and rec['identity']['tested_tree'] == TREE
        assert rec['identity']['tracked_worktree_verified'] is True
    summary = {
        'schema': 'TRNM-W1-C8-INDEPENDENT-LIFECYCLE-REVIEW1',
        'finding': 'No contradictory record found within this bounded read-only review.',
        'four_engineering_gates': 'HOLD', 'source': SOURCE, 'operation': OP, 'statement': STATEMENT,
        'review_scope': {'new_test_methods': 0, 'new_operations': 0, 'signals': 0,
                        'target_database_reads': 0, 'elf_rehashes': 0, 'new_process_probes': 0,
                        'original_json_files': 18, 'original_job_streams': 4,
                        'original_bytes_rehashed': sum(len(x) for x in raw.values()),
                        'full_qualification_logs_rehashed_again': False,
                        'record_bundle_not_atomic_multi_file_snapshot': True},
        'jobs': job_summary,
        'chronology_monotonic_ns': {
            'selected': selected, 'live_first_prove_r0vm_observed': live,
            'original_deadline': deadline, 'target_terminal_recorded': finish,
            'typed_unknown_recorded': failure_at, 'explicit_owner_request_recorded': requested_at,
            'original_budget': deadline-selected, 'target_finish_after_deadline': finish-deadline,
            'owner_request_after_typed_failure': requested_at-failure_at},
        'clock_and_identity': {
            'boot_id': cfg['original_boot_id'], 'config_sha256': byname['config']['sha256'],
            'plan_sha256': byname['plan']['sha256'], 'launch_sha256': byname['launch-declaration']['sha256'],
            'config_equals_plan_with_only_four_clock_launch_additions': True,
            'original_job_identity_equal_in_start_terminal_and_owner_request': True,
            'main_and_cold_retained_target_objects_equal': True,
            'target_instance': target['target_instance'], 'task_scope': target['task_scope'],
            'request_sha256': target['request_sha256'], 'deadline_renewed': False},
        'failure_and_cap': {
            'target_cause': result['cause'], 'target_exit_code': result['exit_code'],
            'target_sticky_cancel': False, 'failure_kind': f['failure_kind'],
            'consumed': None, 'cancellation_at_failure': None,
            'original_resource_cap': cfg['resource_cap'], 'full_cap_retained_in_records': True,
            'provider_payment_observed': False, 'provider_payment_authorized': False,
            'typed_failure_native_refund_authorized': False,
            'owner_request_is_not_acceptance': True, 'owner_accepted_observed': True,
            'new_cancellation_journal_event_proven': False,
            'ordering_basis': 'Numeric timestamps prove target terminal then typed Unknown then explicit owner request. Accepted outcome has no independent timestamp; source-bound lifecycle records report acceptance after that request.'},
        'reorg_and_funds': {
            'four_readbacks_crossmatched': True, 'before_equals_restored': True,
            'removed_equals_actual_cold_reopen': True,
            'original_cancel_inclusion_restored': r['original_cancel_tip'],
            'new_restored_tip_distinct_from_original_and_alternate': True,
            'original_cancel_wire_sha256': r['original_cancel_wire_sha256'],
            'original_cancel_packet_sha256': r['original_cancel_packet_sha256'],
            'native_task': req['native_task'], 'native_original_operation': restored['original_operation'],
            'removed_status': 'reserved', 'removed_remaining': 1000,
            'restored_status': 'cancelled', 'restored_remaining': 0,
            'gross_research_principal_refund_units': 1000,
            'net_account_delta_claimed': False, 'globally_additive_refund_claimed': False,
            'provider_balance_unchanged_recorded': True, 'new_cancel_signed_or_submitted': False,
            'm12_readback_unchanged': True,
            'independent_database_or_signature_reverification_by_this_audit': False,
            'cross_C5_C6_binary_byte_comparison_by_this_audit': False,
            'boundary': 'The source-bound real Node test records fork removal, close/reopen, and restoration of the same original Cancel. This audit compares those records and original successful test output; it does not reopen the Node database. Separate deterministic fixtures cannot be summed as new global funds.'},
        'cold': {'m12_begin': 'Done', 'meaning': 'Dispatch remains closed; resource settlement and payment are not authorized.',
                 'new_generation_dispatches': 0, 'native_transactions_submitted': 0,
                 'target_cancel_requests_sent': 0, 'original_cap_retained': True,
                 'fresh_recursive_scope_qualification': False, 'same_retained_target': True},
        'process_scope': {'existing_observation_sha256': byname['terminal-readonly-observation']['sha256'],
                          'observed_interval_ns': [final['started_monotonic_ns'], final['completed_monotonic_ns']],
                          'same_boot_known_identities_checked': expected_identities,
                          'known_identities_recorded_absent': 5, 'exact_cgroups_recorded_absent': 2,
                          'exact_units_recorded_inactive_mainpid_zero': 2,
                          'all_historical_descendants_wait_reap': None, 'gpu_accounting': 'UNKNOWN',
                          'scope': 'Time-local observations of the five recorded identities and two exact cgroups/units only; absence does not prove historical reaping or full resource accounting.'},
        'qualification_binding': {'gate_sha256': byname['complete-gates']['sha256'],
                                  'preparation_sha256': byname['preparation-provenance']['sha256'],
                                  'previous_independent_qualification_manifest_sha256': QUAL_MANIFEST,
                                  'previous_independent_qualification_summary_sha256': QUAL_SUMMARY,
                                  'component_pins_equal_previous_independent_audit': True,
                                  'all_declared_attempts': gates['attempt_accounting']['all_declared_qualification_attempts'],
                                  'selected_coverage': gates['attempt_accounting']['qualifying_coverage'],
                                  'these_two_ignored_entry_executions_are_separate_from_697': True,
                                  'C7_unknown_replayed': False, 'copied_cache_fresh': False},
        'unclosed': ['Complete proof count remains zero for this operation.',
                     'No positive provider payment or complete resource settlement.',
                     'GPU use, aggregate peak resources, and all historical descendant wait/reap remain unknown.',
                     'The NativeTask research maintenance blocks do not establish admission of the original winning W1.',
                     'No new performance, tail latency, deployment budget, or cryptographic/protocol security qualification.']
    }
    OUT.mkdir(exist_ok=False)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w:gz', format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(raw):
            entry = tarfile.TarInfo(name)
            entry.size = len(raw[name]); entry.mode = 0o644; entry.mtime = 0
            archive.addfile(entry, io.BytesIO(raw[name]))
    payload_bytes = payload.getvalue()
    with tarfile.open(fileobj=io.BytesIO(payload_bytes), mode='r:gz') as archive:
        assert archive.getnames() == sorted(raw)
        for member in archive.getmembers():
            assert member.isfile() and archive.extractfile(member).read() == raw[member.name]
    readme = f'''# Independent C8 lifecycle review

The pinned records are mutually consistent within this bounded read-only review. The four engineering gates remain **HOLD**.

Executed source: `{COMMIT}` / tree `{TREE}`. Provider operation: `{OP}`. The main and independent cold jobs each have an original, complete, durable exit-0 record and one passing native test in their original stdout (122.68 s and 0.32 s). These are two actual executions of ignored entry points, separate from the 697 ordinary qualification executions; this audit runs zero tests.

## Ordering and identity

The original 120 s budget was selected at {selected}, with deadline {deadline}. A live first-prove r0vm identity was recorded at {live}. The retained target terminated with `original-deadline`, exit -9 and sticky cancellation false at {finish}: 292,570,577 ns after the original deadline. Typed M12 `Unknown`, consumed null and no cancellation was recorded at {failure_at}; the explicit owner request was recorded 1,995,728 ns later. The accepted outcome has no independent timestamp and does not prove a new journal append. It records acceptance without releasing the reservation. Numeric ordering, matching original job/request/clock identities, and the source-bound lifecycle output support the reported natural-timeout-before-owner-request sequence.

The config matches every field of the pre-launch plan and adds only four declared clock/launch fields. Main and cold retained target objects match exactly. The same operation, statement, config, request, original deadline, worker identity and target instance remain bound throughout; there is no deadline extension or observed redispatch.

## Funds, fork and cold recovery

The original and restored Cancel readbacks are equal. The fork-removed and actual-cold-reopen readbacks are equal: Reserved with 1000 remaining and no refund claim. Restoration retains the original Cancel inclusion/wire/packet and returns the funding row to Cancelled with zero remaining; no new Cancel signature or transaction is recorded. The separate provider balance is recorded unchanged. This is the source-bound real Node test's evidence, cross-checked here against its successful raw output; this audit does not reopen the database or independently verify the signature.

The reported 1000 units are gross research principal from this deterministic fixture, not a net account delta or additional global funds to sum across C5/C6/C8. This review does not perform a binary cross-generation wire comparison. `Done` closes dispatch only. Original resource cap remains held, consumed resources remain null and GPU accounting remains unknown; positive provider payment and full resource settlement are not established. Independent cold reports zero new generation dispatches, zero native transaction submissions and zero target-cancel requests.

## Process and qualification limits

The already-recorded final observation checks the five original PID/birth identities (owner, worker, direct child, runner, r0vm) and two exact cgroups/units. Their later absence/inactivity is time-local; all historical descendant wait/reap remains null. The cold reader expressly does not claim fresh recursive process-scope qualification. This audit sends no signals, performs no new process probe, and reads no target database, private environment or ELF.

The preparation's exact gate hash and all eight component manifest pins match the earlier independent qualification review. All declared qualification attempts retain **77 commands, 697 ordinary executions, 696 PASS, 1 FAIL, 4 ignored**. Selected successful coverage is separately **73 commands / 665 PASS / 4 ignored**. The failed first staged attempt is not reclassified, and C7's Unknown launch is not replayed or recast. Copied caches remain fresh=false. No full proof, actual original winning-W1 Node admission, deployment budget/performance, or full protocol security qualification follows from this lifecycle result.

`payload.tar.gz` contains 18 exact original JSON files and four exact durable-job streams. `source-index.json` gives each original path/job, length and SHA256. `summary.json` contains the bounded conclusions and limitations. File acquisition was individually stable, not an atomic multi-file snapshot. The included `audit.py` reconstructs the assertions from the acquisition readset; it is audit tooling, not product source or a new test suite.
'''
    output = {'summary.json': dump(summary), 'README.md': readme.encode('utf-8'),
              'source-index.json': dump({'schema': 'TRNM-W1-C8-LIFECYCLE-READ-INDEX1', 'members': index}),
              'payload.tar.gz': payload_bytes, 'audit.py': Path(__file__).read_bytes(),
              'readset.json.gz': gzip.compress(readset_bytes, mtime=0),
              'acquisition.json': dump({'schema': readset['schema'], 'scope': readset['scope'],
                                        'source_files': len(readset['files']), 'job_streams': 4,
                                        'readset_sha256': sha(readset_bytes)})}
    manifest = {'schema': 'TRNM-W1-C8-INDEPENDENT-LIFECYCLE-PACKAGE1', 'source': SOURCE,
                'operation': OP, 'four_engineering_gates': 'HOLD',
                'files': [{'path': n, 'bytes': len(b), 'sha256': sha(b)} for n,b in sorted(output.items())],
                'raw_member_count': len(raw), 'raw_bytes': sum(len(b) for b in raw.values()),
                'manifest_excludes_itself': True}
    output['manifest.json'] = dump(manifest)
    for name, data in output.items():
        with (OUT / name).open('xb') as fobj:
            fobj.write(data)
        assert (OUT / name).read_bytes() == data
    print(json.dumps({'bundle': str(OUT), 'files_including_manifest': len(output),
                      'manifest_sha256': sha(output['manifest.json']),
                      'summary_sha256': sha(output['summary.json']),
                      'payload_sha256': sha(payload_bytes), 'raw_members': len(raw),
                      'raw_bytes': sum(len(b) for b in raw.values())}, sort_keys=True))

if __name__ == '__main__':
    main()
