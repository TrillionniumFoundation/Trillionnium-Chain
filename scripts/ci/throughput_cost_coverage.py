#!/usr/bin/env python3
"""Read the cost coverage of one pinned original native multiprocess report.

This is an observation reader, including failed/unfinished campaigns. It runs
no node, supplies no authority, and never sums overlapping CPU domains. The
caller pins the report SHA256 and its retained before/after source receipts;
these inputs establish consistency, not process attestation or current-source
qualification. Each receiver/import epoch remains local to its exact report
path. Absent measurements remain null, including the complete pipeline cost.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_public_v3_phase_read as phases
from read_native_cache_observation import read_bounded, strict_json

SCHEMA = 'pon-throughput-cost-coverage-v2'
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_RECORDS = 16384
SOURCE_FIELDS = {'schema', 'kind', 'candidate', 'tested_commit', 'tested_tree',
                 'base', 'prospective_merge', 'tracked_entries', 'tracked_bytes',
                 'tracked_worktree_verified', 'tests_executed_by_identity_check'}
HOST_FIELDS = ('cpu_usage_usec', 'cpu_nr_periods', 'cpu_nr_throttled',
               'cpu_throttled_usec', 'memory_current_bytes', 'pids_current')
PQ_FIELDS = ('pq_authentication_attempts', 'pq_authentication_bytes',
             'pq_authentication_thread_cpu_ns', 'pq_authentication_unavailable')
MUTATION_FIELDS = ('mutation_cpu_charged_ns', 'mutation_full_work_cpu_ns',
                   'mutation_dispatch_excluding_work_cpu_ns',
                   'mutation_body_decode_cpu_ns', 'mutation_response_cpu_ns')
CLIENT_IMPORT_SCOPE = ('calling client thread only; excludes scoped execution worker CPU; '
                       'unknown clock is null; no deadline or acceptance authority')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(value, digits=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{' + str(digits) + '}', value),
            'canonical digest required')
    return value


def number(value):
    require(type(value) is int and 0 <= value < 1 << 64, 'measured u64 required')
    return value


def optional_number(value):
    return None if value is None else number(value)


def measurements(values):
    """One metric over observed slots, never a sum across nested cost domains."""
    known = [number(value) for value in values if value is not None]
    return {'observed_slots': len(values), 'known_slots': len(known),
            'unknown_slots': len(values) - len(known),
            'sum_known': sum(known) if known else None,
            'sum_all_observed': sum(known) if known and len(known) == len(values) else None,
            'max_known': max(known) if known else None}


def source_binding(before, after, *, head, tree, kind='head', base=None, merge=None):
    digest(head, 40)
    digest(tree, 40)
    require(kind in ('head', 'prospective-merge'), 'source kind required')
    if kind == 'head':
        require(base is None and merge is None, 'unexpected merge source arguments')
        tested = head
    else:
        digest(base, 40)
        tested = digest(merge, 40)
    require(type(before) is dict and set(before) == SOURCE_FIELDS
            and type(after) is dict and set(after) == SOURCE_FIELDS
            and all(type(before[key]) is type(after[key]) and before[key] == after[key]
                    for key in SOURCE_FIELDS), 'unchanged complete source receipts required')
    require(before['schema'] == 'trnm-ci-source-v1'
            and before['kind'] == kind and before['candidate'] == head
            and before['tested_commit'] == tested and before['tested_tree'] == tree
            and before['base'] == base and before['prospective_merge'] == merge
            and before['tracked_worktree_verified'] is True
            and before['tests_executed_by_identity_check'] is False,
            'pinned source head/tree/kind mismatch')
    require(number(before['tracked_entries']) > 0 and number(before['tracked_bytes']) > 0,
            'tracked source coverage required')


def phase_epoch_records(observer):
    rows = observer.get('records')
    require(type(rows) is list and len(rows) <= MAX_RECORDS, 'bounded receiver records required')
    ids = [number(row.get('connection_id')) for row in rows]
    require(all(value > 0 for value in ids) and len(set(ids)) == len(ids),
            'duplicate receiver identity in one epoch')
    seen = number(observer.get('accepted_connections_seen'))
    omitted = number(observer.get('records_not_retained'))
    capacity = number(observer.get('capacity'))
    require(0 < capacity <= MAX_RECORDS and len(rows) <= capacity
            and len(rows) + omitted <= seen, 'receiver observation denominator mismatch')
    number(observer.get('measurement_failures'))
    require(type(observer.get('counter_overflow')) is bool
            and observer.get('observation_has_consensus_authority') is False
            and observer.get('stream_bytes_are_physical_network_bytes') is False,
            'receiver observation scope mismatch')
    require(observer.get('cpu_intervals_are_nested_not_additive') is True,
            'receiver CPU domains cannot be added')
    for row in rows:
        require(row.get('physical_network_bytes') is None,
                'this producer does not measure physical network bytes')
        for key in ('application_bytes_read', 'application_bytes_written',
                    'dispatch_thread_cpu_ns', 'full_work_thread_cpu_ns'):
            optional_number(row.get(key))
        # The record's lifecycle and its receiver phases share one local
        # epoch. History import snapshots below own different local epochs.
        life = row.get('lifecycle')
        if life is None:
            continue
        phases.request_owner_lifecycle_summary([row])
        if row.get('observation_failed') is True:
            continue
        accepted = life['accepted_ns']
        closed = [value for value in (life['connection_closed_ns'], life['task_closed_ns'])
                  if value is not None]
        for span in row.get('submit_phases', []):
            for key in ('started_ns', 'ended_ns'):
                value = span.get(key)
                if value is not None and accepted is not None:
                    require(value >= accepted, 'receiver span precedes its own epoch acceptance')
                if value is not None and closed and row.get('complete') is True:
                    require(value <= max(closed), 'receiver span escapes its own closed epoch')
    return rows, seen - len(rows)


def bounded_report_shape(report):
    """Reject malformed or oversized collections before the shared analyzer."""
    require(type(report) is dict and type(report.get('preparation')) is dict,
            'original report and preparation objects required')
    require(report.get('state_backend') in (None, 'legacy-v2', 'authenticated-v1'),
            'recognized or absent original state backend required')
    phase_rows = report.get('phases')
    require(type(phase_rows) is list and len(phase_rows) == 3
            and all(type(row) is dict for row in phase_rows), 'three original phase objects required')
    for phase in phase_rows:
        if phase.get('startup_or_campaign_error') is not None:
            require(type(phase['startup_or_campaign_error']) is str,
                    'original startup failure text required')
            continue
        observer, history = phase.get('receiver_observation'), phase.get('history')
        require(type(observer) is dict and type(observer.get('records')) is list
                and len(observer['records']) <= MAX_RECORDS
                and all(type(row) is dict for row in observer['records']),
                'bounded receiver record objects required')
        require(type(history) is list and len(history) <= 64
                and all(type(row) is dict for row in history), 'bounded History call objects required')
        rounds = phase.get('confirmations')
        require(type(rounds) is list and len(rounds) <= phases.ROUNDS
                and all(type(row) is dict for row in rounds), 'bounded confirmation round objects required')
        for row in history:
            require(row.get('client_import') is None or type(row['client_import']) is dict,
                    'original client import object required')


def request_costs(observer, epoch):
    rows, unobserved = phase_epoch_records(observer)
    output = {'epoch': epoch, 'retained_records': len(rows),
              'unobserved_records': unobserved,
              'measurement_failures': observer['measurement_failures'],
              'counter_overflow': observer['counter_overflow'],
              'all_request_costs_covered': False,
              'dispatch_thread_cpu_ns': measurements([row.get('dispatch_thread_cpu_ns')
                  for row in rows if row.get('dispatch_started') is True]),
              'full_work_thread_cpu_ns': measurements([row.get('full_work_thread_cpu_ns')
                  for row in rows if row.get('full_work_started') is True]),
              'application_bytes_read': measurements([row.get('application_bytes_read') for row in rows]),
              'application_bytes_written': measurements([row.get('application_bytes_written') for row in rows]),
              'physical_network_bytes': None, 'phases': [], 'waits': {},
              'scope': 'retained receiver records only; full work is inside dispatch; '
                       'dispatch/phase CPU excludes separately scoped workers; '
                       'stream counts are application bytes, not physical network bytes; '
                       'missing or unentered work is not a zero-cost sample'}
    names = (phases.PHASES_V4 if observer['schema'].endswith('-v4') else
             phases.PHASES if observer['schema'].endswith(('-v2', '-v3')) else ())
    for name in names:
        slots = [next(span for span in row['submit_phases'] if span['phase'] == name) for row in rows]
        entered = [span for span in slots if span['started'] is True]
        output['phases'].append({'phase': name, 'parent_phase': phases.PHASE_PARENTS_V4.get(name),
            'entered': len(entered), 'unentered': len(slots) - len(entered),
            'terminal': sum(span['completed'] is True for span in entered),
            'unfinished': sum(span['completed'] is not True for span in entered),
            'thread_cpu_ns': measurements([span.get('thread_cpu_ns') for span in entered]),
            'wall_ns': measurements([span.get('wall_ns') for span in entered])})
    if observer['schema'].endswith('-v4'):
        for name in phases.WAIT_FIELDS_V4:
            entered = [row[name] for row in rows if row[name]['started_ns'] is not None]
            output['waits'][name] = {
                'wall_ns': measurements([span['wall_ns'] for span in entered]),
                'terminal': sum(span['completed'] for span in entered),
                'unfinished': sum(not span['completed'] for span in entered),
                'scope': 'observed request wait durations, not CPU or a whole-phase latency'}
    values = [row['cpu_settlement'] for row in rows
              if row.get('cpu_settlement', {}).get('schema') == phases.CPU_SETTLEMENT_VALUES_SCHEMA]
    output['settlement'] = {
        'value_records': len(values), 'records_without_value_settlement': len(rows) - len(values),
        **{name: measurements([value[name] for value in values])
           for name in phases.CPU_SETTLEMENT_VALUE_FIELDS},
        'scope': 'original owner plus scoped-worker total; overlaps dispatch; '
                 'live-paid plus residual describes the same total, not additional work; '
                 'CPU-settle observer phase is not additive to this total'}
    return output


def listener_costs(outcome):
    require(type(outcome) is dict and set(outcome) in ({'Ok'}, {'Err'}),
            'original service Result required')
    if 'Err' in outcome:
        return {'outcome': outcome, 'pq_authentication': None, 'mutation_counters': None}
    metrics = outcome['Ok']
    require(type(metrics) is dict, 'service metrics required')
    pq = {key: metrics.get(key) for key in PQ_FIELDS}
    for key, value in pq.items():
        if key.endswith('unavailable'):
            require(value is None or type(value) is bool, 'PQ availability boolean required')
        else:
            optional_number(value)
    pq['missing_fields'] = [key for key in PQ_FIELDS if key not in metrics]
    pq['scope'] = ('listener intake epoch cumulative attempts/bytes/calling-thread CPU; '
                   'not a per-request increment; zero attempts does not exercise PQ; '
                   'never add to overlapping response/dispatch/process CPU')
    mutation = {key: optional_number(metrics.get(key)) for key in MUTATION_FIELDS}
    total, work, rest = (mutation[key] for key in MUTATION_FIELDS[:3])
    if all(value is not None for value in (total, work, rest)):
        require(total == work + rest, 'mutation CPU settlement partition mismatch')
    mutation['scope'] = ('original charged CPU and its partitions; body decode and response '
                         'are inside dispatch-excluding-work, not additional charges; '
                         'this is not full listener or Host CPU')
    return {'outcome': 'Ok', 'pq_authentication': pq, 'mutation_counters': mutation}


def history_costs(history, epoch):
    require(type(history) is list and len(history) <= 64, 'bounded original History calls required')
    imports = [row['client_import'] for row in history if type(row.get('client_import')) is dict]
    records = []
    for value in imports:
        require(value.get('scope') == CLIENT_IMPORT_SCOPE,
                'client import calling-thread CPU scope required')
        optional_number(value.get('thread_cpu_ns'))
        optional_number(value.get('wall_ns'))
    for index, row in enumerate(history):
        value = row.get('client_import')
        if type(value) is not dict:
            continue
        native = value.get('native_import_observation')
        if native is None:
            continue
        # Parent analyzer already checks request tip/after/packet count and
        # native import outcome. Retain each whole local snapshot unchanged.
        phases.validate_history_import_observation(native)
        records.append({'history_call_index': index,
            'epoch': epoch + f'/history/{index}/client_import/native_import_observation',
            'succeeded': value['succeeded'], 'error': value['error'],
            'caller_thread_cpu_ns': optional_number(value.get('thread_cpu_ns')),
            'caller_wall_ns': optional_number(value.get('wall_ns')),
            'native_snapshot': native})
    host = []
    for name in ('resolve', 'initial', 'checkpoint', 'final'):
        slots = [next(slot for slot in row['native_snapshot']['host_checks'] if slot['phase'] == name)
                 for row in records]
        host.append({'phase': name, 'observed_imports': len(slots),
            'calls_started': sum(slot['calls_started'] for slot in slots) if slots else None,
            'calls_unfinished': sum(slot['calls_unfinished'] for slot in slots) if slots else None,
            'thread_cpu_ns': measurements([slot['thread_cpu_ns'] for slot in slots]),
            'wall_ns': measurements([slot['wall_ns'] for slot in slots])})
    return {'history_calls': len(history), 'retained_imports': len(imports),
            'imports_with_native_snapshot': len(records),
            'imports_without_native_snapshot': len(imports) - len(records),
            'caller_thread_cpu_ns': measurements([value.get('thread_cpu_ns') for value in imports]),
            'caller_wall_ns': measurements([value.get('wall_ns') for value in imports]),
            'host_checks': host, 'records': records,
            'cold_recovery_cpu_ns': None,
            'scope': 'live History import, not full cold recovery; native/Host spans overlap '
                     'the outer import; Host CPU sums invoking threads, not all worker CPU; '
                     'each snapshot has its own epoch; no offsets are joined across snapshots'}


def host_costs(context):
    if context is None:
        return None
    require(type(context) is dict
            and context.get('schema') == 'fixed-public-phase-external-actors-v1'
            and context.get('same_original_receiver_and_verifier_owners') is True
            and context.get('attackers_launched_by_external_controller') is True
            and all(context.get(key) is False for key in ('runtime_business_deadline_changed',
                    'scalar_policy_changed', 'independent_administration', 'wan_qualified')),
            'fixed public phase context required')
    def canonical_cgroup(value):
        return (type(value) is str and value.startswith('/')
                and (value == '/' or all(part not in ('', '.', '..')
                                        for part in value[1:].split('/'))))

    require(canonical_cgroup(context.get('phase_cgroup'))
            and context['phase_cgroup'].startswith('/trnmponpublic.slice/')
            and canonical_cgroup(context.get('controller_cgroup'))
            and not context['controller_cgroup'].startswith('/trnmponpublic.slice/')
            and context['controller_cgroup'] != '/trnmponpublic.slice'
            and number(context.get('phase_pid')) > 0, 'distinct original phase/controller owners required')
    before, after = context.get('host_before'), context.get('host_after')
    require(type(before) is dict and type(after) is dict
            and set(before) == set(after) == set(HOST_FIELDS), 'complete Host counter snapshots required')
    for snapshot in (before, after):
        for value in snapshot.values():
            number(value)
    delta = {}
    for name in HOST_FIELDS[:4]:
        require(after[name] >= before[name], 'Host cumulative counter rewind')
        delta[name] = after[name] - before[name]
    return {'context': context, 'counter_deltas': delta,
            'serialized_boot_identity': None,
            'scope': 'the two samples of this one fixed-parent phase context only; '
                     'producer verifies Host identity, but these counters are not signed attestation; '
                     'CPU excludes the external controller; memory/pids are point samples, not deltas '
                     'or peaks; no counter subtraction across phases or process restarts'}



def finite_business_observation(original, derived, epoch):
    """Read distinct independently confirmed transactions in the original window.

    A retained native flag is not by itself a transaction observation. This
    finite workload is deliberately sparse; its rate is never a capacity or
    sustained-throughput claim. Failed and unobserved scheduled slots remain
    separate, and all timing is local to this one original phase.
    """
    available = derived['observations_available']
    window_ns = number(original['duration_seconds']) * 1_000_000_000 if available else None
    rounds = original['confirmations'] if available else []
    reasons = [] if rounds else ['no-retained-confirmation-rounds' if available
                                 else 'phase-observations-unavailable']
    observed_ids, confirmed_ids, records = set(), set(), []
    observation_fields = ('transaction', 'included_block', 'observed_tip', 'confirmed',
        'reorged', 'finalized', 'execution_authority', 'depth', 'included_height',
        'observed_height', 'work_delta', 'required_work_delta')
    for row in rounds:
        index = number(row['round'])
        claimed = row.get('confirmed_inside_pressure_window')
        require(type(claimed) is bool, 'native confirmation flag boolean required')
        scheduled = (1 + 4 * index) * 1_000_000_000
        start, end = (optional_number(row.get(key)) for key in ('started_ns', 'ended_ns'))
        if start is not None:
            require(start >= scheduled, 'round begins before its original scheduled epoch')
        if start is not None and end is not None:
            require(end >= start, 'confirmation round clock rewind')
        else:
            reasons.append(f'round-{index}:missing-round-time')
        transaction = row.get('transaction')
        if transaction is None:
            reasons.append(f'round-{index}:missing-transaction-id')
        else:
            observed_ids.add(digest(transaction))
        verified = False
        if claimed:
            observation = row.get('observation')
            require(observation is None or type(observation) is dict,
                    'independent confirmation observation object required')
            missing = [key for key in observation_fields
                       if observation is None or observation.get(key) is None]
            missing += [key for key in ('transaction', 'included_block', 'tip')
                        if row.get(key) is None]
            if missing:
                reasons.append(f'round-{index}:missing-independent-confirmation-fields:'
                               + ','.join(sorted(set(missing))))
            else:
                require(all(observation[key] is False for key in
                            ('reorged', 'finalized', 'execution_authority'))
                        and observation['confirmed'] is True
                        and type(observation['depth']) is int and observation['depth'] == 6
                        and number(observation['observed_height'])
                            - number(observation['included_height']) == 6,
                        'independent depth-six confirmation outcome mismatch')
                for outer, inner in (('transaction', 'transaction'),
                                     ('included_block', 'included_block'), ('tip', 'observed_tip')):
                    require(digest(row[outer]) == digest(observation[inner]),
                            'independent confirmation identity mismatch')
                work = int(digest(observation['work_delta'], 128), 16)
                required_work = int(digest(observation['required_work_delta'], 128), 16)
                require(required_work > 0 and work >= required_work,
                        'independent confirmation required work mismatch')
                if start is not None and end is not None:
                    require(end < window_ns, 'confirmed round outside its original pressure window')
                    confirmed_ids.add(transaction)
                    verified = True
        records.append({'round': index, 'transaction': transaction, 'scheduled_ns': scheduled,
            'started_ns': start, 'ended_ns': end, 'native_confirmed_inside_pressure_window': claimed,
            'independent_confirmation_fields_verified': verified,
            'round_wall_ns': end - start if start is not None and end is not None else None,
            'start_delay_ns': start - scheduled if start is not None else None,
            'scheduled_to_terminal_ns': end - scheduled if end is not None else None})
    complete_identity = available and bool(rounds) and not reasons
    confirmed = len(confirmed_ids) if complete_identity else None
    failed_rounds = sum(not row['native_confirmed_inside_pressure_window'] for row in records)
    return {'schema': 'pon-finite-confirmed-business-observation-v1', 'epoch': epoch,
        'window_ns': window_ns, 'scheduled_confirmation_rounds': phases.ROUNDS,
        'observed_confirmation_rounds': len(records),
        'native_confirmed_rounds': sum(row['native_confirmed_inside_pressure_window'] for row in records)
                                  if available else None,
        'native_unconfirmed_rounds': failed_rounds if available else None,
        'unobserved_scheduled_rounds': phases.ROUNDS - len(records),
        'observed_round_nonconfirmation_fraction': {'numerator': failed_rounds,
            'denominator': len(records)} if records else None,
        'observed_transaction_ids': sorted(observed_ids),
        'independently_checked_confirmed_transaction_ids': sorted(confirmed_ids),
        'observed_unique_confirmed_transactions': confirmed,
        'observed_confirmed_tps': confirmed * 1_000_000_000 / window_ns
                                  if confirmed is not None else None,
        'rate_unknown_reasons': sorted(set(reasons)), 'rounds': records,
        'confirmed_round_wall_ns': phases.stats([row['round_wall_ns'] for row in records
            if row['independent_confirmation_fields_verified']]),
        'unconfirmed_round_wall_ns': phases.stats([row['round_wall_ns'] for row in records
            if not row['native_confirmed_inside_pressure_window']]),
        'all_observed_scheduled_to_terminal_ns': phases.stats(
            [row['scheduled_to_terminal_ns'] for row in records]),
        'request_attempts': {'submit': derived['submissions'], 'history': derived['history']}
                            if available else None,
        'scope': {'rate_is_capacity_estimate': False, 'production_qualification': False,
            'acknowledgments_are_confirmations': False, 'repeated_transaction_ids_count_once': True,
            'unobserved_slots_are_failed_samples': False, 'cross_phase_clocks_are_joined': False,
            'statement': 'original sparse three-round, thirty-second phase only; unique retained '
                         'independent transaction confirmations, including all failed and unobserved '
                         'scheduled denominators; elapsed failure durations are not success latencies; '
                         'reader validates retained fields, not signatures or execution attestation'}}


def process_memory_costs(value):
    """Retain the producer's point RSS and lifetime high-water scopes."""
    if value is None:
        return None
    fields = ('rss_bytes', 'lifetime_peak_rss_bytes', 'kernel_rusage_self_peak_rss_bytes')
    scope = ('Linux /proc/self magic self and kernel RUSAGE_SELF; peak is whole process lifetime, '
             'not an isolated allocation or incremental memory bound')
    require(type(value) is dict and set(value) == {*fields, 'scope'} and value['scope'] == scope,
            'original process point and lifetime memory scope required')
    measured = {key: optional_number(value[key]) for key in fields}
    if measured['rss_bytes'] is not None and measured['lifetime_peak_rss_bytes'] is not None:
        require(measured['rss_bytes'] <= measured['lifetime_peak_rss_bytes'],
                'process RSS exceeds its recorded lifetime high-water mark')
    return {**measured, 'scope': scope, 'per_request_peak_measured': False}


def analyze(report, report_sha256):
    digest(report_sha256)
    bounded_report_shape(report)
    for key in ('finite_experiment_criteria_met', 'economics_complete'):
        require(type(report.get(key)) is bool, 'original outcome boolean required')
    native = phases.analyze(report)
    output = []
    for index, (original, derived) in enumerate(zip(report['phases'], native['phases'])):
        epoch = report_sha256 + f'/phases/{index}'
        row = {'mode': original['mode'], 'epoch': epoch,
               'original_outcome': {key: derived.get(key) for key in (
                   'native_phase_criteria_met', 'startup_or_campaign_error',
                   'scheduled_confirmation_rounds', 'observed_confirmation_rounds',
                   'confirmed_rounds', 'unobserved_scheduled_rounds', 'confirmation_rounds')},
               'business': finite_business_observation(original, derived, epoch),
               'phase_process_memory': process_memory_costs(original.get('rss')),
               'phase_process_cpu_ns': optional_number(original.get('whole_parent_phase_cpu_ns')),
               'phase_process_wall_ns': optional_number(original.get('whole_parent_phase_wall_ns')),
               'setup_process_cpu_ns': optional_number(original.get('receiver_and_verifier_setup_cpu_ns')),
               'setup_wall_ns': optional_number(original.get('receiver_and_verifier_setup_wall_ns')),
               'process_scope': 'original phase process; setup and all its threads are nested; '
                                'excludes child processes and unrelated Host work',
               'receiver': None, 'listener': None, 'history': None, 'fixed_parent': None,
               'complete_pipeline_cpu_ns': None, 'physical_network_bytes': None,
               'disk_growth_bytes': None, 'payload_transfer_cpu_ns': None,
               'cold_recovery_cpu_ns': None, 'request_peak_rss_bytes': None}
        if derived['observations_available']:
            row.update(receiver=request_costs(original['receiver_observation'], epoch + '/receiver_observation'),
                       listener=listener_costs(original['service_outcome']),
                       history=history_costs(original['history'], epoch),
                       fixed_parent=host_costs(original.get('phase_process_context')))
        output.append(row)
    return {'schema': SCHEMA, 'source_report_schema': report['schema'],
            'state_backend': report.get('state_backend'),
            'public_resource_policy': report.get('public_resource_policy'),
            'original_finite_experiment_criteria_met': report['finite_experiment_criteria_met'],
            'preparation_process_cpu_ns': optional_number(report['preparation'].get('cpu_ns')),
            'phases': output,
            'scope': {'reader_runs_native_work': False, 'production_qualification': False,
                      'complete_pipeline_cost_measured': False, 'business_tps_capacity': None,
                      'unknown_values_are_zero': False, 'overlapping_cpu_domains_are_added': False,
                      'cross_epoch_timestamps_are_joined': False, 'physical_network_bytes_measured': False,
                      'source_binding': 'caller-pinned report bytes and unchanged retained source receipts; '
                                        'not execution attestation or applicability to later source'}}


def read_coverage(report_path, source_path, source_after_path, *, expected_report_sha256,
                  head, tree, kind='head', base=None, merge=None):
    digest(expected_report_sha256)
    raw = read_bounded(report_path, MAX_REPORT_BYTES)
    require(hashlib.sha256(raw).hexdigest() == expected_report_sha256, 'pinned report SHA256 mismatch')
    before = read_bounded(source_path, 64 * 1024)
    after = read_bounded(source_after_path, 64 * 1024)
    source = strict_json(before)
    source_binding(source, strict_json(after), head=head, tree=tree, kind=kind, base=base, merge=merge)
    result = analyze(strict_json(raw), expected_report_sha256)
    result['source'] = source
    result['input'] = {'report_bytes': len(raw), 'report_sha256': expected_report_sha256,
                       'source_sha256': hashlib.sha256(before).hexdigest(),
                       'source_after_sha256': hashlib.sha256(after).hexdigest()}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--report-sha256', required=True)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--source-after', required=True, type=Path)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--expected-tree', required=True)
    parser.add_argument('--kind', choices=('head', 'prospective-merge'), default='head')
    parser.add_argument('--expected-base')
    parser.add_argument('--expected-merge')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = read_coverage(args.report, args.source, args.source_after,
            expected_report_sha256=args.report_sha256, head=args.expected_head, tree=args.expected_tree,
            kind=args.kind, base=args.expected_base, merge=args.expected_merge)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
    except (OSError, ValueError, KeyError, TypeError, StopIteration, RecursionError) as error:
        print(f'cost coverage refused: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
