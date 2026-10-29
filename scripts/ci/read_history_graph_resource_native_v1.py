#!/usr/bin/env python3
"""Read actual owned-parent v1 controls; fixture receipts confer no authority."""
from __future__ import annotations

from pathlib import Path
import hashlib
import re

from history_graph_resource_guardian_v1 import CASES, CASE_SECONDS, HELPER, MUTATIONS, PROFILE
from read_native_history_verifier import LIMITS, PARENT, digest, graph_observation, integer, read, require

TOTAL_SECONDS = 1800
PURE_ROSTER = sorted([
    'ingress::history_graph_resource_v1::tests::graph_resource_v1_actual_empty_graph_entry_final_and_exit_refusals_never_qualify',
    'ingress::history_graph_resource_v1::tests::graph_resource_v1_cancels_every_node_inside_kernel_read_windows',
    'ingress::history_graph_resource_v1::tests::graph_resource_v1_ignored_resource_refusal_cannot_be_reused_as_success',
    'ingress::history_graph_resource_v1::tests::graph_resource_v1_keeps_every_cpu_point_and_exact_eight_body_limit',
    'ingress::history_graph_resource_v1::tests::graph_resource_v1_reads_current_sql_on_non_full_nodes_with_warm_arithmetic',
    'ingress::history_graph_resource_v1::tests::graph_resource_v1_rejects_forged_order_nested_and_unfinished_scopes',
    'ingress::public_v3::scalar_cpu::graph_resource_v1_close_holds_original_quiescence_against_concurrent_begin',
    'store::history_graph_resource_v1::tests::graph_resource_v1_clean_settlement_preserves_credit_and_allows_old_strict_next',
    'store::history_graph_resource_v1::tests::graph_resource_v1_early_resume_keeps_original_limits_without_rebinding_parent',
    'store::history_graph_resource_v1::tests::graph_resource_v1_finish_transaction_refusal_retains_both_original_markers',
    'store::history_graph_resource_v1::tests::graph_resource_v1_live_known_close_retries_only_original_epoch_without_credit',
    'store::history_graph_resource_v1::tests::graph_resource_v1_missing_changed_or_oversized_marker_never_reuses_a_verdict',
    'store::history_graph_resource_v1::tests::graph_resource_v1_policy_and_original_cpu_epoch_publish_atomically',
    'store::history_graph_resource_v1::tests::graph_resource_v1_refuses_profile_switch_or_borrowed_listener_last_close',
    'store::history_graph_resource_v1::tests::graph_resource_v1_reused_statement_rebinds_and_reads_after_failure_restore_and_eviction',
    'store::history_graph_resource_v1::tests::graph_resource_v1_unclean_and_resource_refused_closes_never_clear_original_debt',
    'store::history_graph_resource_v1::tests::graph_resource_v1_uncommitted_same_connection_change_cannot_hide_from_commit_fence',
])


def test_terminal(text, passed, ignored):
    rows = re.findall(r'^test (\S+) \.\.\. (ok|FAILED|ignored)(?:, .*)?$', text, re.M)
    require(sorted(name for name, status in rows if status == 'ok') == sorted(passed)
            and sorted(name for name, status in rows if status == 'ignored') == sorted(ignored)
            and not any(status == 'FAILED' for _, status in rows)
            and len(rows) == len(passed) + len(ignored), 'exact actual native roster and outcomes required')
    summary = re.findall(r'^test result: .+$', text, re.M)
    require(len(summary) == 1 and re.fullmatch(
        rf'test result: ok\. {len(passed)} passed; 0 failed; {len(ignored)} ignored; '
        r'0 measured; \d+ filtered out; finished in [0-9.]+s', summary[0]),
        'one original native terminal summary required')


def identity(value, cgroup):
    require(type(value) is dict and set(value) == {'pid', 'tid', 'uid', 'gid', 'thread_cgroup'},
            'exact actual native identity fields required')
    require(all(integer(value[key]) > 0 for key in ('pid', 'tid', 'uid', 'gid'))
            and value['pid'] != value['tid'], 'unprivileged original nonleader thread required')
    require(value['thread_cgroup'] == '0::' + cgroup, 'actual complete calling-thread membership required')


def parent(value, expected_limits, expected_pids=None):
    require(value['path'] == PARENT and value['limits'] == expected_limits,
            'exact actual parent limits required')
    require(type(value['uid']) is int and value['uid'] == 0
            and integer(value['mode']) & 0o170000 == 0o040000
            and value['mode'] & 0o022 == 0,
            'fresh guardian lstat must retain the original root-owned non-writable parent')
    require(integer(value['device']) > 0 and integer(value['inode']) > 0,
            'original physical parent identity required')
    require(type(value['boot_id']) is str and re.fullmatch(
        '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']), 'actual boot identity required')
    mode = integer(value['cpu_file_mode'])
    require(mode <= 0o7777, 'actual permission mode required')
    integer(value['pids_current'])
    if expected_pids is not None:
        require(value['pids_current'] == expected_pids, 'actual fixed parent must be empty after reap')
    fields = value['cpu_stat'].splitlines()
    stats = {}
    for line in fields:
        key, raw = line.split()
        require(key not in stats and raw.isdigit(), 'actual unique kernel CPU counters required')
        stats[key] = int(raw)
    require('usage_usec' in stats, 'actual kernel CPU usage required')
    return tuple(value[key] for key in ('path', 'device', 'inode', 'boot_id'))


def native_parent_identity(value):
    # The actual native checker emits a versioned identity descriptor, not the
    # campaign's independent CPU/memory sample. Do not invent missing ownership
    # or counter fields; the privileged guardian separately retains fresh lstat.
    numeric = {'cpu_quota_us': 25_000, 'cpu_period_us': 100_000, 'cpu_burst_us': 0,
               'memory_bytes': 2_147_483_648, 'swap_bytes': 0, 'tasks': 256}
    require(type(value) is dict and set(value) == {
        'schema', 'path', 'device', 'inode', 'boot_id', 'observation_is_authority', *numeric},
        'exact native fixed-parent identity observation fields required')
    require(value['schema'] == 'fixed-kernel-parent-identity-observation-v1'
            and value['path'] == PARENT and value['observation_is_authority'] is False,
            'original native checker identity must remain an observation')
    require(all(type(value[key]) is int and value[key] == expected for key, expected in numeric.items()),
            'native numeric limits must equal the unchanged original quarter-CPU policy')
    require(integer(value['device']) > 0 and integer(value['inode']) > 0
            and type(value['boot_id']) is str and re.fullmatch(
                '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['boot_id']),
            'actual native parent device, inode and boot identity required')
    return tuple(value[key] for key in ('path', 'device', 'inode', 'boot_id'))


def cpu_receipt(value):
    require(value['schema'] == 'service-owner-scoped-thread-cpu-settlement-v1'
            and value['accounting_unavailable'] is False,
            'actual original known owner and worker settlement required')
    fields = ('owner_cpu_ns', 'scoped_worker_cpu_ns', 'total_cpu_ns', 'live_paid_cpu_ns', 'residual_cpu_ns')
    for field in fields:
        integer(value[field])
    require(value['owner_cpu_ns'] > 0
            and value['total_cpu_ns'] == value['owner_cpu_ns'] + value['scoped_worker_cpu_ns']
            and value['total_cpu_ns'] == value['live_paid_cpu_ns'] + value['residual_cpu_ns'],
            'original actual CPU identity must balance without double counting')
    workers = [integer(value[key]) for key in ('spawned_workers', 'started_workers', 'finished_workers', 'known_workers')]
    require(len(set(workers)) == 1, 'every actually spawned native worker must be started, joined and known')
    require(type(value['live_refused']) is bool, 'actual CPU refusal observation required')


def cpu_state(value, flow):
    require(value['schema'] == 'public-v3-local-stored-cpu-budget-v1'
            and value['accounting_unavailable'] is False and value['in_flight'] == 0,
            'settled original CPU domain required')
    integer(value['stored_credit_ns'])
    require((value['burst_ns'], value['refill_ns_per_second'], value['start_reserve_ns'], value['worker_limit'])
            == (2_000_000_000, 250_000_000, 100_000_000, 2), 'original CPU admission policy must remain exact')
    require(flow['schema'] == 'public-v3-local-actual-cpu-flow-v1'
            and flow['balance_identity_verified'] is True and flow['live_owners'] == 0
            and flow['booked_reservation_ns'] == 0 and flow['unsettled_known_live_cpu_ns'] == 0,
            'actual closed CPU flow required')
    for key, item in flow.items():
        if key not in ('schema', 'balance_identity_verified'):
            integer(item)
    paid = flow['live_debited_cpu_ns'] + flow['settlement_residual_cpu_ns']
    require(paid == flow['paid_cpu_debit_ns'] == flow['settled_full_cpu_ns']
            and flow['initial_credit_ns'] + flow['credited_refill_ns'] - paid - flow['settlement_discard_ns']
            == flow['remaining_paid_credit_ns'] == flow['stored_credit_ns'] == value['stored_credit_ns'],
            'actual original credit, settlement and residual identities required')


def policy_digest():
    tag = b'ordinary-history-graph-resource-policy-v1'
    parts = (PROFILE.encode(), (8).to_bytes(4, 'little'),
             b'sealed-graph-ordinal;every-node-cpu-cancel-sql;full-enter-first-final-exit-commit-settlement;ordinary-only')
    raw = b'TRNM-PON1\0' + len(tag).to_bytes(2, 'little') + tag
    for part in parts:raw += len(part).to_bytes(4, 'little') + part
    return hashlib.sha256(raw).hexdigest()


def markers(value):
    require(type(value) is list and len(value) == 2 and all(type(row) is list and len(row) == 2 for row in value),
            'both original durable markers required')
    require([row[0] for row in value] == ['ordinary-history-graph-resource-policy-v1', 'ordinary-public-v3-epoch-v1']
            and value[1][1] == b'active-v1'.hex().upper(), 'original durable CPU epoch must be retained')
    import json
    require(type(value[0][1]) is str and len(value[0][1]) <= 32768
            and re.fullmatch('[0-9A-F]+', value[0][1]), 'bounded canonical durable binding bytes required')
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result, 'duplicate durable binding key refused')
            result[key] = item
        return result
    binding = json.loads(bytes.fromhex(value[0][1]), object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite binding')))
    require(binding['schema'] == 'ordinary-history-graph-resource-binding-v1'
            and binding['profile'] == PROFILE and type(binding['maximum_node_bodies_between_full_checks']) is int
            and binding['maximum_node_bodies_between_full_checks'] == 8
            and binding['policy_digest'] == policy_digest()
            and binding['cpu_epoch_key'] == 'ordinary-public-v3-epoch-v1'
            and binding['cpu_epoch_value'] == b'active-v1'.hex()
            and binding['new_cpu_credit_granted'] is False and binding['signed_v6_authority'] is False,
            'exact new policy must remain coupled to the original CPU marker')
    digest(binding['policy_digest']); digest(binding['epoch_nonce'])


def validate_case(directory, spec, binary_sha256):
    directory = Path(directory)
    require(directory.is_dir() and directory.resolve(strict=True) == directory,
            'canonical original physical case directory required')
    require(spec in CASES and type(spec) is dict and spec == next(row for row in CASES if row['case'] == spec['case']),
            'one exact finite physical case required')
    digest(binary_sha256)
    hashes = {}
    def load(name):
        path = directory / name
        require(path.resolve(strict=True).parent == directory and not path.is_symlink(), 'original retained direct member required')
        value, hashes[name] = read(path)
        return value
    job = load('job.json')
    require(job == {**spec, 'schema': 'history-graph-resource-physical-job-v1',
                    'parent': PARENT, 'profile': PROFILE, 'binary_sha256': binary_sha256}, 'exact job and executed ELF binding required')
    guardian = load('guardian.json'); ready = load('ready.json'); complete = load('complete.json')
    require(guardian['schema'] == 'history-graph-resource-physical-guardian-v1'
            and guardian['case'] == spec['case'] and guardian['action'] == spec['action']
            and guardian['profile'] == PROFILE and guardian['binary_sha256'] == binary_sha256
            and guardian['passed'] is True and guardian['native_exit_code'] == 0
            and guardian['root_lease_verified'] is True and guardian['actual_child_unprivileged'] is True
            and guardian['pidfd_pinned'] is True and guardian['production_qualified'] is False
            and guardian['whole_history_p0_closed'] is False and guardian['case_budget_seconds'] == CASE_SECONDS,
            'actual original guardian, lease, pidfd and clean child exit required')
    require(type(guardian['elapsed_seconds']) in (int, float) and 0 < guardian['elapsed_seconds'] <= CASE_SECONDS,
            'original finite physical case budget required')
    require(not any(key in guardian for key in ('error', 'cleanup_error', 'cleanup_stop', 'emergency_restore')),
            'failed or emergency-cleaned physical case cannot qualify')
    group = guardian['native_cgroup']; outer = guardian['outer_cgroup']; unit = guardian['unit']
    require(re.fullmatch(r'trnm-graph-[0-9]+-[0-9]+-[a-z0-9-]+\.service', unit)
            and group == '/trnmponpublic.slice/' + unit
            and type(outer) is str and outer.startswith('/') and not outer.startswith('/trnmponpublic.slice'),
            'separate owned native and original outer cgroups required')
    original_identity = guardian['original_identity']; identity(original_identity, group)
    require(guardian['actual_systemd_main_pid'] == original_identity['pid']
            and ready['case'] == complete['case'] == spec['case']
            and ready['binary_sha256'] == complete['binary_sha256'] == binary_sha256
            and ready['identity'] == complete['final_identity'] == original_identity
            and complete['schema'] == 'history-graph-resource-physical-completion-v1'
            and complete['passed'] is True and complete['parent_restored_and_rechecked'] is True,
            'actual same original process, thread, executable and restored completion required')
    original_parent = guardian['original_parent']; pin = parent(original_parent, LIMITS, 0)
    require(native_parent_identity(ready['parent']) == pin, 'native checker and guardian must observe the same physical parent')
    require(original_parent['cpu_file_mode'] & 0o444 != 0, 'original CPU quota readable by the real non-root verifier')
    for name in ('final_parent', 'cleanup_parent'):
        value = guardian[name]
        require(parent(value, LIMITS, 0) == pin and value['cpu_file_mode'] == original_parent['cpu_file_mode'],
                'physical identity and original permissions survive actual child reap')
    native = complete['result']
    require(native['schema'] == 'history-graph-resource-physical-native-result-v1'
            and native['case'] == spec['case'], 'exact native result required')
    if spec['action'] == 'none':
        require(spec['trigger'] == 'full-import-equivalence' and native['triggered'] is False
                and native['same_legal_packet_and_active_state'] is True
                and native['clean_both_epochs'] is True and native['cold_reopen_both_equal'] is True,
                'same actual ELF, legal packet, complete state and both cold reopen paths required')
        counters = graph_observation(native['graph_resource'])
        require(counters['imports'] == counters['imports_closed'] == 1 and counters['imports_failed'] == 0
                and counters['graph_entries'] == counters['graph_exits'] > 0
                and counters['kernel_failed_checks'] == counters['binding_failed_checks'] == 0
                and counters['unfinished_scopes'] == counters['scope_failures'] == 0
                and counters['before_commit_checks'] > 0 and native['graph_resource']['live_known_close_pending'] is False,
                'one genuine complete N8 import required')
        require('mutation' not in guardian and 'restoration' not in guardian
                and not any((directory / name).exists() for name in ('mutation-request.json', 'mutation-applied.json',
                    'mutation-restored.json', 'native-result-before-restore.json')), 'equivalence case must not invent a mutation')
    else:
        request = load('mutation-request.json'); mutation = load('mutation-applied.json')
        restored = load('mutation-restored.json'); before_restore = load('native-result-before-restore.json')
        require(request['schema'] == 'history-graph-resource-physical-request-v1'
                and request['case'] == mutation['case'] == restored['case'] == spec['case']
                and request['action'] == mutation['action'] == spec['action']
                and request['identity'] == mutation['identity'] == original_identity
                and request['binary_sha256'] == binary_sha256
                and mutation == guardian['mutation'] and restored == guardian['restoration'],
                'actual pinned mutation and restoration handshake required')
        require(mutation['actual_mutation_applied'] is True and mutation['pidfd_pinned'] is True
                and restored['actual_restored'] is True and restored['pidfd_pinned'] is True,
                'actual current kernel mutation and restoration required')
        expected = dict(LIMITS)
        if spec['action'] in MUTATIONS:
            name, changed_value = MUTATIONS[spec['action']]
            expected[name] = changed_value
        require(parent(mutation['before'], LIMITS) == parent(mutation['after'], expected) == pin
                and parent(restored['parent'], LIMITS) == pin,
                'same root-leased parent before, during and after actual change')
        migrated = spec['action'] == 'migrate-process'
        require(mutation['membership_before'] == group
                and mutation['membership_after'] == (outer if migrated else group)
                and mutation['process_wide_migration'] is migrated and restored['membership'] == group,
                'whole-process nonleader membership mutation and restoration must be explicit')
        require(mutation['before']['cpu_file_mode'] == original_parent['cpu_file_mode']
                and mutation['after']['cpu_file_mode'] == (0 if spec['action'] == 'unreadable-cpu' else original_parent['cpu_file_mode'])
                and restored['parent']['cpu_file_mode'] == original_parent['cpu_file_mode'], 'actual permission refusal and restoration required')
        expected_error = ('PUBLIC_HOST_KERNEL_CONTEXT' if migrated else 'PUBLIC_HOST_KERNEL_UNAVAILABLE'
                          if spec['action'] == 'unreadable-cpu' else 'PUBLIC_HOST_KERNEL_LIMITS_CHANGED')
        require(native['triggered'] is True and native['error'] == expected_error and native['protocol_invalid'] is False,
                'resource failure is an actual refusal, not a consensus-invalid verdict')
        identity(native['identity_after_refusal'], outer if migrated else group)
        require(native['identity_after_refusal']['pid'] == original_identity['pid']
                and native['identity_after_refusal']['tid'] == original_identity['tid'], 'same real thread observes the refusal')
        require(all(native.get(key) == value for key, value in before_restore.items()),
                'completed evidence may extend but never replace the pre-restoration native result')
        receipts = native.get('cpu_receipts', [native.get('cpu_receipt')])
        require(type(receipts) is list and len(receipts) > 0 and all(type(row) is dict for row in receipts), 'actual CPU receipts required')
        for row in receipts:cpu_receipt(row)
        cpu_state(native['original_cpu'], native['original_cpu_flow'])
        trigger = spec['trigger']
        if trigger in ('after-node', 'strict-after-node0', 'enter', 'final-relation', 'exit'):
            counters = graph_observation(native['graph_resource'])
            expected_completed = 8 if trigger == 'after-node' else 1 if trigger == 'strict-after-node0' else 0 if trigger == 'enter' else 63
            require(native['completed_node_bodies'] == expected_completed and native['fixture_account_count'] == 32,
                    'actual traversal stops at the declared bounded body or full fence')
            if trigger != 'strict-after-node0':
                expected_nodes = 9 if trigger == 'after-node' else 0 if trigger == 'enter' else 63
                expected_events = ['Enter'] + [f'BeforeNode {{ ordinal: {i} }}' for i in range(expected_nodes)]
                if trigger in ('final-relation', 'exit'):
                    expected_events.append('BeforeFinalRelation { completed: 63 }')
                success = 'true' if trigger == 'exit' else 'false'
                expected_events.append(f'Exit {{ completed: {expected_completed}, succeeded: {success} }}')
                require(native['actual_graph_events'] == expected_events, 'complete exact typed traversal and failure edge required')
            if trigger == 'after-node':
                require(request['point'] == {'after_typed_checkpoint_before_body': spec['offset']}
                        and 1 <= 8 - spec['offset'] <= 8 and counters['graph_node_checkpoints'] == 9,
                        'persistent change observed within eight real node bodies')
            elif trigger == 'strict-after-node0':
                require(request['point'] == {'strict_original_callback': True, 'after_full_check_before_body': 0}
                        and native['actual_graph_events'] == [], 'original strict callback remains at the next real node')
            elif trigger == 'enter':
                require(request['point'] == {'before_typed_full_boundary': 'Enter'}, 'original Enter boundary required')
                require(native['decode_before'] == native['decode_after'], 'entry refusal precedes any root SQL/decode')
            if trigger in ('final-relation', 'exit'):
                point = 'BeforeFinalRelation { completed: 63 }' if trigger == 'final-relation' else 'Exit { completed: 63, succeeded: true }'
                require(request['point'] == {'before_typed_full_boundary': point}, 'original final full boundary required')
            require(counters['kernel_failed_checks'] > 0, 'actual failed current kernel read required')
        elif trigger in ('admission-commit', 'activation-commit'):
            counters = graph_observation(native['graph_resource'])
            require(request['point'] == {'before_actual_native_commit': True, 'activation': trigger == 'activation-commit'}
                    and native['original_native_state_unchanged'] is True and native['original_markers_preserved'] is True
                    and native['known_abort_closed_after_actual_restore'] is True
                    and native['next_original_strict_epoch_completed'] is True and counters['before_commit_checks'] > 0,
                    'failed precommit has no durable effect and known abort does not permanently disable strict work')
            markers(native['markers'])
        elif trigger == 'settlement':
            require(request['point'] == {'inside_epoch_close_transaction_before_commit': True}
                    and native['original_markers_preserved'] is True
                    and native['cold_restart_did_not_clear_unsettled_markers'] is True,
                    'failed atomic settlement retains both original markers across cold restart')
            markers(native['markers'])
        elif trigger == 'public-import-known-close':
            markers(native['markers'])
            for field in ('actual_public_entry_returned_error_before_restore', 'original_native_state_unchanged',
                          'actual_premature_public_resume_refused_without_poison', 'original_markers_preserved',
                          'same_live_domain_preserved', 'known_abort_closed_after_actual_restore',
                          'repeated_resume_refused', 'next_original_strict_import_completed',
                          'next_explicit_v1_import_completed', 'clean_cold_readback_after_real_next_imports'):
                require(native[field] is True, 'actual public known-close recovery must complete: ' + field)
            require(native['cold_epoch_recovery_claimed'] is False and len(receipts) >= 2
                    and native['credit_before_resume'] == native['credit_after_resume']
                    and native['flow_before_resume'] == native['flow_after_resume']
                    and native['premature_resume_error'] == expected_error and native['final_height'] == 2,
                    'live close retry preserves original credit and flow; it cannot grant cold recovery')
            digest(native['actual_strict_tip']);digest(native['actual_next_tip'])
            require(native['actual_strict_tip'] != native['actual_next_tip'], 'two real next imports required')
            first = graph_observation(native['graph_resource']); resumed = graph_observation(native['graph_resource_after_resume'])
            final = graph_observation(native['final_graph_resource'])
            require(native['graph_resource']['live_known_close_pending'] is True
                    and native['graph_resource_after_resume']['live_known_close_pending'] is False
                    and first['imports'] == 1 and resumed['imports_closed'] == resumed['imports_failed'] == 1
                    and final['imports'] == final['imports_closed'] == 2 and final['imports_failed'] == 1
                    and native['final_graph_resource']['live_known_close_pending'] is False,
                    'actual pending close, successful resume and subsequent explicit import all required')
        else:
            raise ValueError('unsupported physical result')
    log = directory / 'native.log'
    require(log.is_file() and not log.is_symlink() and log.stat().st_size <= 4 * 1024 * 1024,
            'bounded original native terminal log required')
    test_terminal(log.read_text(), [HELPER], [])
    import hashlib
    hashes['native.log'] = hashlib.sha256(log.read_bytes()).hexdigest()
    return {'schema': 'history-graph-resource-physical-case-readback-v1', 'case': spec['case'],
            'profile': PROFILE, 'binary_sha256': binary_sha256, 'passed': True,
            'retained_files': hashes, 'actual_nonleader_thread': True,
            'wall_clock_revocation_bound_claimed': False, 'whole_history_p0_closed': False,
            'independent_host_authentication': False}
