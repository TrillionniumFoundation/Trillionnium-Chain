#!/usr/bin/env python3
"""Read retained multiprocess observations; never infer confirmations from ACKs.

Historical v1/v2 and the r11/r12/r13 paid CPU envelope's v3 observations are accepted.
The separate arithmetic-facts campaign retains its own schema and signed profile;
reading it cannot qualify raw r13 or arbitrary-key service.
An explicit observed policy is checked against exact revision vectors. Missing
historical policy metadata is not inferred from the shared observer schema.
Missing measurements stay unknown. This reader does not run native admission,
authenticate a host/source claim or issue a production qualification.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
import stat
from pathlib import Path
import re
import sys

from pon_public_v3_policy_read import ARITHMETIC_PROFILE, ARITHMETIC_REVISIONS, identify_observation

PHASES = ('decode', 'context_owner_wait', 'context', 'work',
          'admission_owner_wait', 'admission', 'submit_result')
PHASES_V4 = PHASES + ('admission_prepare', 'execution', 'commit_owner_wait', 'commit',
                     'cpu_wait', 'body_decode', 'response_encoding', 'history_epoch_open',
                     'history_epoch_close', 'history_import', 'cpu_settle', 'root_commitment')
PHASE_PARENTS_V4 = dict.fromkeys(('admission_prepare', 'execution', 'commit_owner_wait', 'commit'),
                               'admission') | {'root_commitment': 'execution'}
WAIT_FIELDS_V4 = ('challenge_wait', 'grant_wait', 'paid_task_queue_wait', 'response_write')
MODES = ('baseline', 'from-zero', 'late-product')
ROUNDS = 3
# The original native campaign schedules three seven-block business rounds at
# t=1/5/9 seconds in one 30-second phase. These are not per-round renewals.
BUSINESS_SCHEDULE_NS = (1_000_000_000, 5_000_000_000, 9_000_000_000)
BUSINESS_DEADLINE_NS = 30_000_000_000
BUSINESS_CONFIRMATION_DEPTH = 6
BUSINESS_CONFIRMATION_WORK_MULTIPLIER = 6
MAX_REPORT_BYTES = 256 * 1024 * 1024
ARITHMETIC_REPORT_SCHEMA = 'native-public-v3-arithmetic-facts-separate-process-campaign-v1'
ERROR_DIAGNOSTIC_SCHEMA = 'public-v3-request-error-diagnostics-v1'
REQUEST_ERROR_TIMING_SCHEMA = 'public-v3-request-error-timing-v1'
REQUEST_CANCELLATION_SCHEMA = 'public-v3-request-cancellation-observation-v1'
REQUEST_CANCELLATION_SOURCE_PHASES = {
    'connection_cleanup': {'cleanup'},
    'completion_refusal': {'work', 'shutdown'},
    'peer_input_failure': {'work', 'queue'},
    'peer_write_closed': {'work', 'queue'},
    'pending_peer_write_closed': {'hello', 'solution'},
}
REACTOR_IO_SCHEMA = 'public-v3-reactor-frame-io-observation-v1'
FRAME_PHASES = ('hello', 'challenge', 'solution', 'ready', 'body', 'response')
CPU_SETTLEMENT_SCHEMA = 'public-v3-cpu-settlement-observation-v1'
CPU_SETTLEMENT_VALUES_SCHEMA = 'public-v3-cpu-settlement-observation-v2'
CPU_SETTLEMENT_KNOWN_FIELDS = ('owner_cpu_known', 'scoped_worker_cpu_known',
                             'live_paid_cpu_known', 'residual_cpu_known')
CPU_SETTLEMENT_VALUE_FIELDS = ('owner_cpu_ns', 'scoped_worker_cpu_ns', 'total_cpu_ns',
                             'live_paid_cpu_ns', 'residual_cpu_ns')
ERROR_DIAGNOSTIC_KINDS = {'protocol_invalid', 'capacity', 'cancelled', 'stale_context',
    'identity_conflict', 'policy_refusal', 'local_structure', 'dependency_unavailable',
    'transport', 'serialization', 'remote_refusal', 'unclassified'}


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value):
    require(type(value) is int and value >= 0, 'nonnegative integer observation required')
    return value


def stats(values):
    known = sorted(integer(value) for value in values if value is not None)
    n = len(known)
    return {'known_count': n, 'unknown_count': len(values) - n,
            'sum_known_ns': sum(known), 'min_ns': known[0] if n else None,
            'p50_nearest_rank_ns': known[(n - 1) // 2] if n else None,
            'p95_nearest_rank_ns': known[(95 * n + 99) // 100 - 1] if n else None,
            'max_ns': known[-1] if n else None,
            'mean_known_ns': {'numerator': sum(known), 'denominator': n} if n else None}



def interval_outcome_summary(slots, *, phase=False):
    """Separate per-request terminal durations from unfinished observed costs.

    A dropped phase can have a finite elapsed duration and an unknown result.
    That duration is useful consumed-cost evidence, but is not a sample of
    latency to a terminal outcome. No aggregate waiter sum is a request sample.
    These are empirical nearest-rank statistics for retained entered slots;
    requests outside this observer, unentered stages and lost records cannot be
    reconstructed or turned into zero-duration requests.
    """
    entered = [slot for slot in slots if (slot.get('started') is True if phase
               else slot.get('started_ns') is not None)]
    terminal = [slot for slot in entered if slot.get('completed') is True]
    unfinished = [slot for slot in entered if slot.get('completed') is not True]
    for slot in entered:
        require(type(slot.get('completed')) is bool, 'interval completed boolean required')
        require(slot['completed'] is (slot.get('accepted') is not None),
                'interval completion/outcome mismatch')
        outcome(slot.get('accepted'))

    def terminal_stats(values):
        measured = stats(values)
        # Keep the actual missing-duration denominator. A percentile computed
        # after deleting an unknown terminal duration is a selected-cohort tail.
        known = sorted(value for value in values if value is not None)
        measured['p99_all_terminal_records_ns'] = (
            known[(99 * len(known) + 99) // 100 - 1]
            if known and len(known) == len(values) else None)
        return measured

    terminal_wall = terminal_stats([slot.get('wall_ns') for slot in terminal])
    return {
        'schema': 'pon-per-request-interval-outcomes-v1',
        'slots': len(slots), 'entered': len(entered),
        'unentered_or_entry_clock_unknown': len(slots) - len(entered),
        'terminal_records': len(terminal), 'unfinished_records': len(unfinished),
        'terminal_wall_ns': terminal_wall,
        'terminal_by_outcome': {
            name: terminal_stats([slot.get('wall_ns') for slot in terminal
                                  if outcome(slot.get('accepted')) == name])
            for name in ('accepted', 'rejected')},
        'typed_terminal_error_counts': dict(Counter(str(slot.get('error_code'))
                                                    for slot in terminal)),
        'typed_cancelled_terminal_records': sum(slot.get('error_code') == 'PUBLIC_REQUEST_CANCELLED'
                                                for slot in terminal),
        'unfinished_observed_elapsed_wall_ns': stats([slot.get('wall_ns') for slot in unfinished]),
        'p99_all_retained_entered_terminal_ns': (terminal_wall['p99_all_terminal_records_ns']
                                                if not unfinished else None),
        'scope': {
            'unit': 'one retained request interval',
            'terminal_includes_accepted_and_rejected': True,
            'unfinished_elapsed_is_not_terminal_latency': True,
            'known_only_statistics_keep_unknown_count': True,
            'p99_requires_all_cohort_outcomes_and_durations': True,
            'cumulative_waiter_time_is_not_request_p99': True,
            'inclusive_stages_are_not_additive': True,
            'unretained_or_unentered_requests_are_not_inferred': True,
            'whole_request_population_p99_ns': None,
        },
    }


def outcome(value):
    require(value is None or type(value) is bool, 'boolean or unknown outcome required')
    return 'accepted' if value is True else 'rejected' if value is False else 'unknown'


def validate_v4_interval(value, *, phase=False):
    require(type(value) is dict, 'v4 interval object required')
    required = {'started_ns', 'ended_ns', 'wall_ns', 'completed', 'accepted', 'error_code'}
    if phase:
        required |= {'phase', 'parent_phase', 'started', 'thread_cpu_ns'}
    require(set(value) == required, 'v4 exact interval shape required')
    require(type(value['completed']) is bool, 'v4 completed boolean required')
    outcome(value['accepted'])
    require(value['completed'] is (value['accepted'] is not None), 'v4 completion/outcome mismatch')
    code = value['error_code']
    require(code is None or (isinstance(code, str) and re.fullmatch('[A-Z][A-Z0-9_]*', code)
                            and value['accepted'] is False), 'v4 typed rejection code required')
    for key in ('started_ns', 'ended_ns', 'wall_ns') + (('thread_cpu_ns',) if phase else ()):
        if value[key] is not None:
            require(integer(value[key]) < 1 << 64, 'v4 interval u64 required')
    start, end, wall = (value[key] for key in ('started_ns', 'ended_ns', 'wall_ns'))
    if start is not None and end is not None:
        require(end >= start and wall == end - start, 'v4 monotonic interval mismatch')
    if not phase and start is None:
        require(not value['completed'] and all(value[key] is None for key in
                ('ended_ns', 'wall_ns', 'accepted', 'error_code')), 'v4 unentered wait must remain unknown')
    if phase:
        require(type(value['started']) is bool, 'v4 started boolean required')
        require(value['parent_phase'] == PHASE_PARENTS_V4.get(value['phase']),
                'v4 inclusive parent phase mismatch')
        if not value['started']:
            require(not value['completed'] and all(value[key] is None for key in
                    ('accepted', 'error_code', 'started_ns', 'ended_ns', 'wall_ns', 'thread_cpu_ns')),
                    'v4 unentered phase must remain unknown')


def validate_v4_phases(phases):
    require(isinstance(phases, list) and [p.get('phase') for p in phases if isinstance(p, dict)]
            == list(PHASES_V4) and len(phases) == len(PHASES_V4),
            'v4 nineteen ordered phase slots required')
    for phase in phases:
        validate_v4_interval(phase, phase=True)
    by_phase = {phase['phase']: phase for phase in phases}
    for child in phases:
        parent = by_phase.get(child['parent_phase'])
        if parent is not None and child['completed'] and parent['completed'] and all(
                span[key] is not None for span in (parent, child) for key in ('started_ns', 'ended_ns')):
            require(parent['started_ns'] <= child['started_ns'] <= child['ended_ns'] <= parent['ended_ns'],
                    'v4 child interval escapes its inclusive parent')


def validate_history_import_observation(value: dict) -> None:
    """Local diagnostic consistency only; no Host, work or State authority."""
    def number(value):
        require(type(value) is int and 0 <= value < 1 << 64, 'IMPORT_OBSERVATION_U64')
        return value

    def known(value):
        return None if value is None else number(value)

    def hash_or_unknown(value):
        require(value is None or (isinstance(value, list) and len(value) == 32
                and all(type(n) is int and 0 <= n <= 255 for n in value)), 'IMPORT_OBSERVATION_HASH')

    require(isinstance(value, dict)
            and value.get('schema') == 'pon-local-history-import-observation-v1', 'IMPORT_OBSERVATION_SCHEMA')
    require(value.get('packet_capacity') == 16 and type(value.get('packet_capacity')) is int
            and all(value.get(key) is True for key in ('cpu_intervals_are_nested_not_additive',
                    'host_checks_are_nested_not_additive', 'phase_cpu_excludes_scoped_workers',
                    'host_cpu_includes_each_calling_thread'))
            and value.get('host_cpu_is_full_worker_cpu') is False
            and value.get('observation_has_consensus_authority') is False,
            'IMPORT_OBSERVATION_SCOPE')
    require(isinstance(value.get('clock_scope'), str) and 0 < len(value['clock_scope']) <= 2048,
            'IMPORT_OBSERVATION_SCOPE')
    failures = number(value.get('measurement_failures'))
    for field in ('tip', 'after', 'supplied_packets'):
        require(field in value, 'IMPORT_OBSERVATION_CONTEXT_REQUIRED')
    hash_or_unknown(value['tip'])
    hash_or_unknown(value['after'])
    known(value['supplied_packets'])
    validate_v4_phases(value.get('phases'))
    packets = value.get('packets')
    require(isinstance(packets, list) and len(packets) <= 16, 'IMPORT_OBSERVATION_PACKET_BOUND')
    indices = []
    for packet in packets:
        require(isinstance(packet, dict) and set(packet) == {'packet_index', 'packet_id', 'phases'},
                'IMPORT_OBSERVATION_PACKET_SHAPE')
        index = number(packet['packet_index'])
        require(index < 16, 'IMPORT_OBSERVATION_PACKET_BOUND')
        indices.append(index)
        hash_or_unknown(packet['packet_id'])
        validate_v4_phases(packet['phases'])
    require(indices == sorted(set(indices)), 'IMPORT_OBSERVATION_PACKET_IDENTITY')
    host = value.get('host_checks')
    names = ('resolve', 'initial', 'checkpoint', 'final')
    require(isinstance(host, list) and len(host) == 4
            and [row.get('phase') for row in host if isinstance(row, dict)] == list(names),
            'IMPORT_OBSERVATION_HOST_SLOTS')
    count_fields = ('calls_started', 'calls_completed', 'calls_accepted', 'calls_rejected',
                    'calls_unfinished', 'wall_clock_unknown_calls', 'cpu_clock_unknown_calls')
    time_fields = ('first_started_ns', 'last_ended_ns', 'wall_ns', 'thread_cpu_ns')
    for row in host:
        require(set(row) == {'phase', 'last_error_code', *count_fields, *time_fields},
                'IMPORT_OBSERVATION_HOST_SHAPE')
        for key in count_fields:
            number(row[key])
        for key in time_fields:
            known(row[key])
        ended = row['calls_completed'] + row['calls_unfinished']
        require(row['calls_completed'] == row['calls_accepted'] + row['calls_rejected']
                and ended <= row['calls_started'] and (failures != 0 or ended == row['calls_started'])
                and row['wall_clock_unknown_calls'] <= ended and row['cpu_clock_unknown_calls'] <= ended,
                'IMPORT_OBSERVATION_HOST_COUNTS')
        if row['phase'] != 'checkpoint':
            require(row['calls_started'] <= 1 or failures != 0, 'IMPORT_OBSERVATION_HOST_REUSED')
        start, end = row['first_started_ns'], row['last_ended_ns']
        if start is not None and end is not None:
            require(start <= end, 'IMPORT_OBSERVATION_HOST_TIME')
        if row['calls_started'] == 0:
            require(all(row[key] is None for key in time_fields) and row['last_error_code'] is None,
                    'IMPORT_OBSERVATION_HOST_UNENTERED')
        for total, unknown in (('wall_ns', 'wall_clock_unknown_calls'),
                               ('thread_cpu_ns', 'cpu_clock_unknown_calls')):
            if row[unknown] or ended == 0:
                require(row[total] is None, 'IMPORT_OBSERVATION_HOST_UNKNOWN_TOTAL')
            elif failures == 0:
                require(row[total] is not None, 'IMPORT_OBSERVATION_HOST_MISSING_TOTAL')
        code = row['last_error_code']
        require(code is None or (isinstance(code, str) and re.fullmatch('[A-Z][A-Z0-9_]*', code)
                and row['calls_rejected'] > 0), 'IMPORT_OBSERVATION_HOST_ERROR')
    native = next(phase for phase in value['phases'] if phase['phase'] == 'history_import')
    if native['completed'] and native['started_ns'] is not None and native['ended_ns'] is not None:
        for packet in packets:
            for phase in packet['phases']:
                if phase['completed'] and phase['started_ns'] is not None and phase['ended_ns'] is not None:
                    require(native['started_ns'] <= phase['started_ns'] <= phase['ended_ns'] <= native['ended_ns'],
                            'IMPORT_OBSERVATION_PACKET_OUTSIDE_NATIVE')
        checkpoint = host[2]
        if checkpoint['first_started_ns'] is not None and checkpoint['last_ended_ns'] is not None:
            require(native['started_ns'] <= checkpoint['first_started_ns']
                    <= checkpoint['last_ended_ns'] <= native['ended_ns'], 'IMPORT_OBSERVATION_HOST_OUTSIDE_NATIVE')
        if host[1]['last_ended_ns'] is not None:
            require(host[1]['last_ended_ns'] <= native['started_ns'], 'IMPORT_OBSERVATION_HOST_ORDER')
        if host[3]['first_started_ns'] is not None:
            require(native['ended_ns'] <= host[3]['first_started_ns'], 'IMPORT_OBSERVATION_HOST_ORDER')
    if host[0]['last_ended_ns'] is not None and host[1]['first_started_ns'] is not None:
        require(host[0]['last_ended_ns'] <= host[1]['first_started_ns'], 'IMPORT_OBSERVATION_HOST_ORDER')


def validate_request_error_diagnostics(row):
    """Optional additive v4 diagnostic data; never infer a typed code from text."""
    if 'error_diagnostics' not in row:
        return
    value = row['error_diagnostics']
    require(type(value) is dict and set(value) == {'schema', 'has_control_authority',
            'messages_are_untrusted', 'message_capacity_bytes', 'dispatch', 'terminal'},
            'error diagnostic exact shape required')
    require(value['schema'] == ERROR_DIAGNOSTIC_SCHEMA
            and value['has_control_authority'] is False
            and value['messages_are_untrusted'] is True
            and type(value['message_capacity_bytes']) is int
            and value['message_capacity_bytes'] == 96, 'error diagnostic scope required')
    for name in ('dispatch', 'terminal'):
        require(f'{name}_error_code' in row, 'error diagnostic typed slot required')
        detail = value[name]
        if detail is None:
            require(row[f'{name}_error_code'] is None, 'error diagnostic missing known typed cause')
            continue
        require(type(detail) is dict and set(detail) == {'kind', 'message_prefix', 'message_truncated'},
                'error diagnostic detail shape required')
        require(type(detail['kind']) is str and detail['kind'] in ERROR_DIAGNOSTIC_KINDS,
                'error diagnostic kind required')
        require(type(detail['message_prefix']) is str
                and type(detail['message_truncated']) is bool, 'error diagnostic text required')
        size = len(detail['message_prefix'].encode('utf-8'))
        require(size <= 96 and (not detail['message_truncated'] or size >= 93),
                'error diagnostic bounded UTF-8 prefix required')
        code = row[f'{name}_error_code']
        require(code is None or (isinstance(code, str) and re.fullmatch('[A-Z][A-Z0-9_]*', code)),
                'error diagnostic typed slot must remain typed or unknown')
        # Reject impossible combinations without granting the text any typed
        # identity. local_integrity may upgrade any existing kind; Display is
        # independent, and kind alone cannot expose private History-budget origin.
        kind = detail['kind']
        require(code != 'ROOT' and not (code is not None and kind == 'unclassified'),
                'legacy diagnostic cannot become a typed code')
        remote_codes = ('REMOTE_TERMINAL', 'REMOTE_RETRYABLE')
        require(kind != 'remote_refusal' or code is None or code in remote_codes,
                'uncontrolled remote text cannot supply a local typed code')
        if code in remote_codes:
            require(kind in ('remote_refusal', 'local_structure'),
                    'controlled remote typed code kind mismatch')
        if code == 'PUBLIC_EOF':
            require(kind in ('transport', 'local_structure'), 'typed EOF kind mismatch')
        if name == 'dispatch':
            require(row.get('dispatch_accepted') is not True, 'accepted dispatch cannot have an Err diagnostic')
        else:
            require(type(row.get('terminal_phase')) is str, 'terminal Err phase required')


def request_error_diagnostic_summary(rows):
    observed = [row for row in rows if 'error_diagnostics' in row]
    if not observed:
        return None
    for row in observed:
        validate_request_error_diagnostics(row)
    def counts(name):
        known = [row for row in observed if row['error_diagnostics'][name] is not None]
        values = Counter((row[f'{name}_error_code'], detail['kind'], detail['message_prefix'],
                          detail['message_truncated']) for row in known
                         for detail in [row['error_diagnostics'][name]])
        return {'diagnostics_present': len(known),
                'no_diagnostic_captured': len(observed) - len(known),
                'counts': [dict(typed_error_code=key[0], kind=key[1], message_prefix=key[2],
                               message_truncated=key[3], count=count) for key, count in values.items()]}
    return {'observed_records': len(observed),
            'historical_records_without_extension': len(rows) - len(observed),
            'dispatch': counts('dispatch'), 'terminal': counts('terminal'),
            'scope': 'bounded actual Err text and existing kind only; untrusted text is not a typed '
                     'code, authorization or outcome; missing historical diagnostics remain unknown'}


def validate_request_error_timing(row):
    """Bind first actual errors to their own cause, phase and local epoch."""
    if 'error_timing' not in row:
        return
    value = row['error_timing']
    require(type(value) is dict and set(value) == {'schema', 'first_dispatch_error',
            'first_terminal_error', 'observation_failed', 'clock_is_observer_local',
            'has_control_authority'} and value['schema'] == REQUEST_ERROR_TIMING_SCHEMA,
            'request error timing exact shape required')
    require(value['clock_is_observer_local'] is True and value['has_control_authority'] is False,
            'request error timing local diagnostic scope required')
    require(type(row.get('observation_failed')) is bool
            and value['observation_failed'] is row['observation_failed'],
            'request error timing capture failure mismatch')
    require('lifecycle' in row, 'request error timing requires original lifecycle epoch')
    request_owner_lifecycle_summary([row])
    for name, close in (('first_dispatch_error', 'task_closed_ns'),
                        ('first_terminal_error', 'connection_closed_ns')):
        event = value[name]
        if event is None:
            continue
        require(type(event) is dict and set(event) == {'observed_ns', 'phase', 'error_code'},
                'request first error exact event shape required')
        stamp, phase, code = (event[key] for key in ('observed_ns', 'phase', 'error_code'))
        require(stamp is None or (type(stamp) is int and 0 <= stamp < 1 << 64),
                'request first error u64 or unknown clock required')
        require(type(phase) is str and 0 < len(phase) <= 64,
                'request first error phase required')
        require(name != 'first_dispatch_error' or (phase == 'dispatch' and row['task_created']),
                'request first dispatch error requires its task owner')
        require(code is None or (isinstance(code, str) and code != 'ROOT'
                and re.fullmatch('[A-Z][A-Z0-9_]*', code)),
                'request first error typed cause or unknown required')
        accepted, closed = row['lifecycle']['accepted_ns'], row['lifecycle'][close]
        require(stamp is None or accepted is None or accepted <= stamp,
                'request first error precedes accept')
        require(stamp is None or closed is None or stamp <= closed,
                'request first error follows its owner close')


def request_error_timing_summary(rows):
    """Error appearance is separate from response delivery and owner release."""
    observed = [row for row in rows if 'error_timing' in row]
    if not observed:
        return None
    for row in observed:
        validate_request_error_timing(row)
    failed = sum(row['error_timing']['observation_failed'] for row in observed)
    unfinished = sum(not row['complete'] for row in observed)
    result = {'schema': 'public-v3-request-error-timing-derivation-v1',
              'observed_records': len(observed),
              'historical_records_without_extension': len(rows) - len(observed),
              'measurement_failed_records': failed, 'incomplete_owner_records': unfinished}
    for name in ('first_dispatch_error', 'first_terminal_error'):
        events = [(row, row['error_timing'][name]) for row in observed
                  if row['error_timing'][name] is not None]
        elapsed = [event['observed_ns'] - row['lifecycle']['accepted_ns']
                   if not row['error_timing']['observation_failed']
                   and event['observed_ns'] is not None
                   and row['lifecycle']['accepted_ns'] is not None else None
                   for row, event in events]
        clocks = stats(elapsed)
        complete = bool(events) and not failed and not unfinished and len(observed) == len(rows) \
            and clocks['unknown_count'] == 0
        known = sorted(value for value in elapsed if value is not None)
        result[name] = {
            'events_observed': len(events), 'no_event_captured': len(observed) - len(events),
            'events_with_unknown_clock': sum(event['observed_ns'] is None for _, event in events),
            'events_with_failed_coverage': sum(row['error_timing']['observation_failed']
                                                for row, _ in events),
            'first_error_code_counts': dict(Counter(event['error_code'] for _, event in events
                                                    if event['error_code'] is not None)),
            'unknown_error_code_events': sum(event['error_code'] is None for _, event in events),
            'phase_counts': dict(Counter(event['phase'] for _, event in events)),
            'accept_to_first_error_wall_ns': clocks,
            'max_all_captured_error_events_ns': known[-1] if complete else None,
            'p99_all_captured_error_events_ns': known[(99 * len(known) + 99) // 100 - 1]
                                               if complete else None,
        }
    result['scope'] = {
        'first_event_keeps_its_own_phase_and_typed_cause': True,
        'last_error_code_may_differ_from_first_event': True,
        'lost_capture_cannot_establish_first_error_time': True,
        'open_owners_disable_complete_population_error_tail': True,
        'error_time_is_owner_close_or_response_delivery_time': False,
        'error_time_is_cancellation_signal_time': False,
        'local_monotonic_epoch_only': True,
        'whole_request_population_p99_ns': None,
        'has_control_authority': False,
    }
    return result


def validate_request_cancellation(row):
    """Validate actual flag-write brackets separately from worker/owner stops."""
    if 'cancellation' not in row:
        return
    value = row['cancellation']
    fields = {'schema', 'observed_signal_calls', 'first_flag_transition',
        'worker_entered', 'worker_entered_ns', 'worker_returned', 'worker_returned_ns',
        'observation_failed', 'clock_is_observer_local', 'signals_are_request_flag_writes',
        'has_control_authority'}
    require(type(value) is dict and set(value) == fields
            and value['schema'] == REQUEST_CANCELLATION_SCHEMA,
            'request cancellation exact shape required')
    require(value['clock_is_observer_local'] is True
            and value['signals_are_request_flag_writes'] is True
            and value['has_control_authority'] is False,
            'request cancellation local flag-write scope required')
    require(type(row.get('observation_failed')) is bool
            and value['observation_failed'] is row['observation_failed'],
            'request cancellation capture failure mismatch')
    require('lifecycle' in row, 'request cancellation requires original lifecycle epoch')
    request_owner_lifecycle_summary([row])
    require(type(value['observed_signal_calls']) is int
            and 0 <= value['observed_signal_calls'] < 1 << 64,
            'request cancellation bounded signal count required')
    failed = value['observation_failed']
    accepted = row['lifecycle']['accepted_ns']
    for name in ('worker_entered', 'worker_returned'):
        stamp = value[name + '_ns']
        require(type(value[name]) is bool, 'request cancellation worker flag required')
        require(stamp is None or (type(stamp) is int and 0 <= stamp < 1 << 64),
                'request cancellation worker clock must be u64 or unknown')
        require((stamp is None or value[name]) and (not value[name] or stamp is not None or failed),
                'request cancellation worker clock/flag mismatch')
        require(accepted is None or stamp is None or accepted <= stamp,
                'request cancellation worker event precedes accept')
    require(not value['worker_entered'] or row['task_created'],
            'request cancellation worker requires original task')
    require(not value['worker_returned'] or value['worker_entered'],
            'request cancellation return requires worker entry')
    entered, returned = value['worker_entered_ns'], value['worker_returned_ns']
    require(entered is None or returned is None or entered <= returned,
            'request cancellation worker return precedes entry')
    event = value['first_flag_transition']
    if event is not None:
        require(type(event) is dict and set(event) == {'before_ns', 'after_ns', 'source', 'phase'}
                and value['observed_signal_calls'] > 0,
                'request cancellation signal requires exact event and call count')
        require(type(event['source']) is str and event['source'] in REQUEST_CANCELLATION_SOURCE_PHASES
                and type(event['phase']) is str
                and event['phase'] in REQUEST_CANCELLATION_SOURCE_PHASES[event['source']],
                'request cancellation signal source and phase required')
        for name in ('before_ns', 'after_ns'):
            stamp = event[name]
            require(stamp is None or (type(stamp) is int and 0 <= stamp < 1 << 64),
                    'request cancellation signal clock must be u64 or unknown')
            require(accepted is None or stamp is None or accepted <= stamp,
                    'request cancellation signal precedes accept')
            closed = row['lifecycle']['connection_closed_ns']
            require(stamp is None or closed is None or stamp <= closed,
                    'request cancellation signal follows its connection owner')
        before, after = event['before_ns'], event['after_ns']
        require(before is None or after is None or before <= after,
                'request cancellation signal bracket reversed')


def request_cancellation_summary(rows):
    """A first flag transition has a time bracket, never an invented instant.

    Completion handoff, actual per-request worker return and connection/task
    resource release remain separate. A successful connection's ordinary drop
    writes the same flag, so source labels must survive every aggregation.
    """
    observed = [row for row in rows if 'cancellation' in row]
    if not observed:
        return None
    for row in observed:
        validate_request_cancellation(row)

    def bounds(event, terminal, unavailable, failed):
        result = {'status': unavailable, 'lower_ns': None, 'upper_ns': None}
        if failed:
            result['status'] = 'capture_failed'
        elif event is None:
            result['status'] = 'first_flag_transition_unknown'
        elif event['before_ns'] is None or event['after_ns'] is None:
            result['status'] = 'signal_clock_unknown'
        elif terminal is not None:
            if terminal < event['before_ns']:
                result['status'] = 'already_returned_before_signal_bracket'
            elif terminal < event['after_ns']:
                result['status'] = 'signal_and_terminal_order_unknown'
            else:
                result.update(status='bracketed', lower_ns=terminal - event['after_ns'],
                              upper_ns=terminal - event['before_ns'])
        return result

    records = []
    for index, row in enumerate(rows):
        value = row.get('cancellation')
        if value is None:
            missing = dict(status='historical_extension_missing', lower_ns=None, upper_ns=None)
            records.append(dict(record_index=index, source=None, phase=None,
                worker_return=dict(missing), all_request_owners_closed=dict(missing)))
            continue
        event = value['first_flag_transition']
        returned = value['worker_returned_ns'] if value['worker_returned'] else None
        worker_status = ('worker_clock_unknown' if value['worker_returned'] else
                         'worker_unfinished' if value['worker_entered'] else 'worker_not_entered')
        closed = row['lifecycle']['connection_closed_ns']
        task = row['lifecycle']['task_closed_ns']
        owners_terminal = (row['connection_closed'] and closed is not None
            and (not row['task_created'] or (row['task_closed'] and task is not None))
            and (not value['worker_entered'] or (value['worker_returned'] and returned is not None)))
        owner_end = max(closed, task if row['task_created'] else closed,
                        returned if value['worker_entered'] else closed) if owners_terminal else None
        records.append(dict(record_index=index,
            source=event['source'] if event else None, phase=event['phase'] if event else None,
            worker_return=bounds(event, returned, worker_status, value['observation_failed']),
            all_request_owners_closed=bounds(event, owner_end, 'owners_or_worker_unfinished',
                                             value['observation_failed'])))
    return {
        'schema': 'public-v3-request-cancellation-derivation-v1',
        'observed_records': len(observed), 'historical_records_without_extension': len(rows) - len(observed),
        'measurement_failed_records': sum(row['cancellation']['observation_failed'] for row in observed),
        'first_flag_transition_records': sum(row['cancellation']['first_flag_transition'] is not None
                                             for row in observed),
        'signal_calls_without_first_transition_records': sum(
            row['cancellation']['observed_signal_calls'] > 0
            and row['cancellation']['first_flag_transition'] is None for row in observed),
        'no_signal_call_observed_records': sum(row['cancellation']['observed_signal_calls'] == 0
                                               for row in observed),
        'worker_entered_records': sum(row['cancellation']['worker_entered'] for row in observed),
        'worker_returned_records': sum(row['cancellation']['worker_returned'] for row in observed),
        'first_transition_source_counts': dict(Counter(row['source'] for row in records
                                                       if row['source'] is not None)),
        'records': records,
        'scope': {
            'actual_request_flag_transition_is_bracketed': True,
            'unobserved_earlier_signal_is_not_reconstructed': True,
            'connection_cleanup_is_cancellation_success': False,
            'worker_return_is_process_exit': False,
            'worker_return_includes_task_cleanup_and_cpu_settlement': True,
            'worker_return_includes_output_handoff_or_disposal': True,
            'all_request_owners_includes_worker_return_when_entered': True,
            'closed_owners_prove_durable_effect_rollback': False,
            'external_caller_signal_and_shared_stop_time_measured': False,
            'zero_lower_bound_is_an_exact_zero_latency': False,
            'overlapping_signal_and_terminal_order_is_unknown': True,
            'local_monotonic_epoch_only': True,
            'has_control_authority': False,
        },
    }


def validate_reactor_io(row):
    if 'reactor_io' not in row:
        return
    value = row['reactor_io']
    require(type(value) is dict and set(value) == {'schema', 'frames', 'observation_failed',
            'calls_are_wrapper_returns', 'includes_read_buffer_preparation',
            'cpu_is_reactor_thread_only', 'includes_wait_between_calls', 'has_control_authority'}
            and value['schema'] == REACTOR_IO_SCHEMA, 'reactor I/O exact shape required')
    require(all(value[key] is True for key in ('calls_are_wrapper_returns',
            'includes_read_buffer_preparation', 'cpu_is_reactor_thread_only'))
            and value['includes_wait_between_calls'] is False
            and value['has_control_authority'] is False, 'reactor I/O diagnostic scope required')
    require(type(row.get('observation_failed')) is bool
            and value['observation_failed'] is row['observation_failed'],
            'reactor I/O capture failure mismatch')
    frames = value['frames']
    require(type(frames) is list and len(frames) == len(FRAME_PHASES),
            'reactor I/O ordered frame slots required')
    counts = ('calls_returned', 'progressed_calls', 'no_progress_calls', 'failed_calls',
              'wall_ns_known_sum', 'wall_unknown_calls', 'thread_cpu_ns_known_sum',
              'thread_cpu_unknown_calls')
    for frame, phase in zip(frames, FRAME_PHASES):
        require(type(frame) is dict and set(frame) == {'phase', 'wall_ns', 'thread_cpu_ns', *counts}
                and frame['phase'] == phase, 'reactor I/O exact ordered frame shape required')
        require(all(type(frame[key]) is int and 0 <= frame[key] < 1 << 64 for key in counts),
                'reactor I/O u64 counters required')
        calls = frame['calls_returned']
        require(calls == sum(frame[key] for key in ('progressed_calls', 'no_progress_calls',
                'failed_calls')), 'reactor I/O outcome denominator mismatch')
        for total, known_sum, unknown in (
                ('wall_ns', 'wall_ns_known_sum', 'wall_unknown_calls'),
                ('thread_cpu_ns', 'thread_cpu_ns_known_sum', 'thread_cpu_unknown_calls')):
            require(frame[total] is None or (type(frame[total]) is int
                    and 0 <= frame[total] < 1 << 64), 'reactor I/O u64 or unknown clock required')
            require(frame[unknown] <= calls, 'reactor I/O clock denominator mismatch')
            require(calls > frame[unknown] or frame[known_sum] == 0,
                    'reactor I/O unknown clocks cannot invent known subtotal')
            require(frame[total] == frame[known_sum] if calls and not frame[unknown]
                    else frame[total] is None, 'reactor I/O unknown or unentered total is not zero')


def reactor_io_summary(rows):
    """Per-request wrapper sums; these are not individual I/O or request tails."""
    observed = [row for row in rows if 'reactor_io' in row]
    if not observed:
        return None
    for row in observed:
        validate_reactor_io(row)
    frames = []
    for index, phase in enumerate(FRAME_PHASES):
        slots = [(row['reactor_io'], row['reactor_io']['frames'][index]) for row in observed]
        entered = [(value, frame) for value, frame in slots if frame['calls_returned']]
        frames.append({
            'phase': phase, 'records_with_calls': len(entered),
            'records_without_calls': len(slots) - len(entered),
            **{key: sum(frame[key] for _, frame in slots) for key in
               ('calls_returned', 'progressed_calls', 'no_progress_calls', 'failed_calls',
                'wall_ns_known_sum', 'wall_unknown_calls', 'thread_cpu_ns_known_sum',
                'thread_cpu_unknown_calls')},
            **{f'per_record_{key}': stats([frame[key] if not value['observation_failed'] else None
                                          for value, frame in entered])
               for key in ('wall_ns', 'thread_cpu_ns')},
        })
    return {'schema': 'public-v3-reactor-frame-io-derivation-v1',
            'observed_records': len(observed),
            'historical_records_without_extension': len(rows) - len(observed),
            'measurement_failed_records': sum(row['reactor_io']['observation_failed'] for row in observed),
            'frames': frames,
            'scope': 'returned frame read/write wrapper calls, including existing read-buffer preparation; '
                     'no-progress may be would-block, interrupted or already complete; '
                     'calling reactor CPU only, excluding authentication and waiting between calls; '
                     'clock sums are per-request aggregates, not individual-call or request p95/p99; '
                     'known sums and counters may be partial when capture failed; '
                     'no physical network, syscall, WAL/fsync or control authority'}


def validate_v4_record(row):
    require(type(row) is dict, 'v4 request record required')
    validate_request_error_diagnostics(row)
    validate_request_error_timing(row)
    validate_reactor_io(row)
    validate_v4_phases(row.get('submit_phases'))
    validate_cpu_settlement(row)
    for key in WAIT_FIELDS_V4:
        validate_v4_interval(row.get(key))
    require('terminal_error_code' in row, 'v4 terminal cause slot required')
    code = row['terminal_error_code']
    require(code is None or (isinstance(code, str) and re.fullmatch('[A-Z][A-Z0-9_]*', code)),
            'v4 terminal cause must be typed or unknown')


def validate_cpu_settlement(row):
    """Check optional actual settlement facts without reclassifying native work."""
    if 'cpu_settlement' not in row:
        return
    value = row['cpu_settlement']
    require(type(value) is dict, 'cpu settlement object required')
    with_values = value.get('schema') == CPU_SETTLEMENT_VALUES_SCHEMA
    require(type(value) is dict and set(value) == {'schema', 'budget_settled',
            'continuous_journal_persisted', 'has_control_authority',
            'interval_is_additive_to_dispatch_cpu', *CPU_SETTLEMENT_KNOWN_FIELDS}
            | (set(CPU_SETTLEMENT_VALUE_FIELDS) if with_values else set()),
            'cpu settlement exact shape required')
    require(value['schema'] in (CPU_SETTLEMENT_SCHEMA, CPU_SETTLEMENT_VALUES_SCHEMA)
            and value['has_control_authority'] is False
            and value['interval_is_additive_to_dispatch_cpu'] is False,
            'cpu settlement scope required')
    require(all(type(value[key]) is bool for key in (*CPU_SETTLEMENT_KNOWN_FIELDS, 'budget_settled')),
            'cpu settlement boolean facts required')
    journal = value['continuous_journal_persisted']
    require(journal is None or type(journal) is bool, 'cpu settlement journal boolean or no scope required')
    if with_values:
        for key in CPU_SETTLEMENT_VALUE_FIELDS:
            require(value[key] is None or (type(value[key]) is int and 0 <= value[key] < 1 << 64),
                    'cpu settlement measured u64 or unknown required')
        for key in CPU_SETTLEMENT_KNOWN_FIELDS:
            require(value[key] is (value[key.removesuffix('_known') + '_ns'] is not None),
                    'cpu settlement known flag and value disagree')
        owner, children, total, paid, residual = (value[key] for key in CPU_SETTLEMENT_VALUE_FIELDS)
        # Unknown total is retained: other integrity/clock failures can make the
        # original settlement refuse a sum even when these component clocks exist.
        require(total is None or (owner is not None and children is not None
                                 and owner + children == total),
                'cpu settlement owner plus scoped workers mismatch')
        # This field is the original checked subtraction, not a separate clock.
        # Keep unavailable totals/live samples and subtraction underflow unknown;
        # readable operands cannot invent an additional missing residual.
        expected_residual = (total - paid if total is not None and paid is not None
                             and paid <= total else None)
        require(residual == expected_residual, 'cpu settlement paid plus residual mismatch')
        require(not value['budget_settled'] or residual is not None,
                'cpu settlement successful budget requires original residual')
    phases = row.get('submit_phases')
    require(type(phases) is list, 'cpu settlement phase required')
    settled = [phase for phase in phases if type(phase) is dict and phase.get('phase') == 'cpu_settle']
    require(len(settled) == 1 and settled[0].get('started') is True
            and settled[0].get('completed') is True, 'cpu settlement completed phase required')
    succeeded = all(value[key] for key in (*CPU_SETTLEMENT_KNOWN_FIELDS, 'budget_settled')) and journal is not False
    require(settled[0].get('accepted') is succeeded, 'cpu settlement phase outcome mismatch')


def cpu_settlement_summary(rows):
    observed = [row for row in rows if 'cpu_settlement' in row]
    if not observed:
        return None
    for row in observed:
        validate_v4_record(row)
    facts = [row['cpu_settlement'] for row in observed]
    succeeded = sum(all(value[key] for key in (*CPU_SETTLEMENT_KNOWN_FIELDS, 'budget_settled'))
                    and value['continuous_journal_persisted'] is not False for value in facts)
    result = {
        'observed_records': len(observed),
        'records_without_settlement_extension': len(rows) - len(observed),
        'succeeded': succeeded, 'failed': len(observed) - succeeded,
        'cpu_known_counts': {key: sum(value[key] for value in facts) for key in CPU_SETTLEMENT_KNOWN_FIELDS},
        'budget_settled': sum(value['budget_settled'] for value in facts),
        'budget_not_settled': sum(not value['budget_settled'] for value in facts),
        'continuous_journal': {
            'persisted': sum(value['continuous_journal_persisted'] is True for value in facts),
            'failed': sum(value['continuous_journal_persisted'] is False for value in facts),
            'no_scope': sum(value['continuous_journal_persisted'] is None for value in facts),
        },
        'scope': {
            'has_control_authority': False,
            'native_dispatch_outcome_is_independent': True,
            'missing_extension_is_unknown': True,
            'journal_null_means_no_continuous_scope': True,
            'interval_overlaps_dispatch_cpu': True,
            'interval_is_additive_to_dispatch_cpu': False,
            'interval_extends_through_budget_and_journal': True,
            'phase_thread_cpu_excludes_scoped_workers': True,
        },
    }
    if any(value['schema'] == CPU_SETTLEMENT_VALUES_SCHEMA for value in facts):
        def actual(row):
            value = row.get('cpu_settlement')
            return value if value is not None and value['schema'] == CPU_SETTLEMENT_VALUES_SCHEMA else {}

        result['original_cpu_samples'] = {
            'schema': 'public-v3-original-cpu-settlement-samples-v1',
            'retained_records': len(rows),
            'settlements_with_values': sum(bool(actual(row)) for row in rows),
            'legacy_settlements_without_values': sum(value['schema'] == CPU_SETTLEMENT_SCHEMA
                                                     for value in facts),
            'records_without_settlement': len(rows) - len(observed),
            # Retain the whole cohort denominator. A read/no-start/old record
            # does not acquire a measured zero just because this scope is absent.
            'values_ns': {key: stats([actual(row).get(key) for row in rows])
                          for key in CPU_SETTLEMENT_VALUE_FIELDS},
            'by_dispatch_outcome': {
                name: {'records': sum(outcome(row.get('dispatch_accepted')) == name for row in rows),
                       'total_cpu_ns': stats([actual(row).get('total_cpu_ns') for row in rows
                                             if outcome(row.get('dispatch_accepted')) == name])}
                for name in ('accepted', 'rejected', 'unknown')},
            'scope': {
                'original_owner_plus_joined_scoped_worker_samples': True,
                'live_paid_plus_residual_equals_original_total_when_known': True,
                'actual_values_are_additional_debits': False,
                'cancelled_and_rejected_work_retained': True,
                'missing_scope_or_clock_is_not_zero': True,
                'includes_reactor_cpu': False,
                'includes_settlement_tail_after_original_owner_sample': False,
                'includes_durable_journal_after_original_owner_sample': False,
                'total_is_whole_request_cpu': False,
                'cpu_settle_phase_is_additive_to_original_total': False,
            },
        }
    return result


def request_owner_lifecycle_summary(rows):
    """Read actual owner closes, preserving post-disconnect and unfinished work.

    A connection close is not a cancellation-signal timestamp or a CPU sample.
    A task close may precede or follow it; completion owns its output buffer too.
    These clocks share only this observer's epoch and do not prove confirmation.
    """
    observed = [row for row in rows if 'lifecycle' in row]
    lifetime, tails, after_close_costs = [], [], []
    for row in observed:
        value = row['lifecycle']
        require(type(value) is dict and set(value) == {'schema', 'accepted_ns', 'connection_closed_ns',
                'task_closed_ns', 'clock_is_observer_local', 'has_control_authority'}
                and value['schema'] == 'public-v3-request-lifecycle-v1'
                and value['clock_is_observer_local'] is True and value['has_control_authority'] is False,
                'request lifecycle exact local scope required')
        for key in ('accepted_ns', 'connection_closed_ns', 'task_closed_ns'):
            require(value[key] is None or (type(value[key]) is int and 0 <= value[key] < 1 << 64),
                    'request lifecycle u64 or unknown required')
        require(all(type(row.get(key)) is bool for key in ('connection_closed', 'task_created',
                'task_closed', 'observation_failed', 'complete')), 'request lifecycle owner flags required')
        accepted, connection, task = (value[key] for key in
                                     ('accepted_ns', 'connection_closed_ns', 'task_closed_ns'))
        failed = row['observation_failed']
        require(accepted is not None or failed, 'request lifecycle missing accept clock')
        require((connection is None or row['connection_closed'])
                and (not row['connection_closed'] or connection is not None or failed),
                'request lifecycle connection close mismatch')
        require(row['task_created'] or (not row['task_closed'] and task is None),
                'request lifecycle uncreated task cannot close')
        require((task is None or row['task_closed'])
                and (not row['task_closed'] or task is not None or failed),
                'request lifecycle task close mismatch')
        require(all(accepted is None or end is None or accepted <= end for end in (connection, task)),
                'request lifecycle close precedes accept')
        owners_closed = row['connection_closed'] and (not row['task_created'] or row['task_closed'])
        require(row['complete'] is (owners_closed and not failed), 'request lifecycle completion mismatch')
        # No ordering between these independent owners is assumed. A live task
        # after socket close remains a missing terminal duration, not zero.
        closed = (max(connection, task if row['task_created'] else connection)
                  if owners_closed and connection is not None
                  and (not row['task_created'] or task is not None) else None)
        lifetime.append(closed - accepted if closed is not None and accepted is not None else None)
        if row['task_created'] and row['connection_closed']:
            tail = max(0, task - connection) if task is not None and connection is not None else None
            tails.append(tail)
            if tail is not None and tail > 0:
                cpu = row.get('cpu_settlement', {})
                after_close_costs.append(cpu.get('total_cpu_ns')
                    if cpu.get('schema') == CPU_SETTLEMENT_VALUES_SCHEMA else None)
    return {
        'schema': 'public-v3-request-owner-completion-v1',
        'retained_records': len(rows), 'records_with_lifecycle': len(observed),
        'records_without_lifecycle': len(rows) - len(observed),
        'measurement_failed_records': sum(row['observation_failed'] for row in observed),
        'owners_closed_records': sum(row['connection_closed'] and
            (not row['task_created'] or row['task_closed']) for row in observed),
        'connection_closed_task_still_open': sum(row['connection_closed'] and row['task_created']
                                               and not row['task_closed'] for row in observed),
        'no_task_created_records': sum(not row['task_created'] for row in observed),
        'accept_to_all_owners_closed_wall_ns': stats(lifetime + [None] * (len(rows) - len(observed))),
        'task_ownership_after_connection_close_wall_ns': stats(tails),
        'original_total_cpu_for_completed_post_disconnect_owners_ns': stats(after_close_costs),
        'scope': {
            'closed_owners_do_not_establish_native_success': True,
            'closed_owners_do_not_establish_independent_confirmation': True,
            'local_monotonic_epoch_only': True,
            'post_disconnect_tail_is_a_wall_interval': True,
            'post_disconnect_tail_is_cpu_cost': False,
            'cancellation_signal_time_measured': False,
            'task_owner_includes_buffered_completion': True,
            'original_total_cpu_includes_work_before_connection_close': True,
            'missing_or_unfinished_terminal_duration_is_not_zero': True,
            'whole_request_population_p99_ns': None,
            'business_tps_capacity': None,
        },
    }


def digest(value):
    if value is None:
        return None
    if isinstance(value, list):
        require(len(value) == 32 and all(type(n) is int and 0 <= n <= 255 for n in value),
                'canonical observed 32-byte digest required')
        return bytes(value).hex()
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
            'canonical observed digest required')
    return value


def refusal_error(row):
    """Project the native reply envelope, keeping retained legacy flat errors.

    Unknown is retained when neither shape recorded an error. Conflicting
    shapes cannot be silently attributed to either error or called successful.
    """
    response = row.get('response')
    if response is None:
        return None
    require(isinstance(response, dict), 'response object required')
    value = response.get('value')
    require(value is None or isinstance(value, dict), 'response value object required')
    flat, nested = response.get('error'), (value or {}).get('error')
    for error in (flat, nested):
        require(error is None or isinstance(error, str), 'observed refusal error string required')
    require(flat is None or nested is None or flat == nested,
            'conflicting flat and nested refusal errors')
    return nested if nested is not None else flat


def call_summary(rows):
    on_time = [row for row in rows if row['status'] == 'ok'
               and row['returned_after_window'] is False]
    return {'attempts': len(rows), 'status_counts': dict(Counter(row['status'] for row in rows)),
            'acknowledged_on_time': len(on_time),
            'acknowledged_after_window': sum(row['status'] == 'ok'
                and row['returned_after_window'] is True for row in rows),
            'all_calls_returned_after_window': sum(row['returned_after_window'] is True for row in rows),
            'on_time_unique_packet_indices': sorted({integer(row['packet_index']) for row in on_time
                                                     if 'packet_index' in row}),
            'errors': dict(Counter(str(row['error']) for row in rows if row.get('error') is not None)),
            'refusals': dict(Counter(str(refusal_error(row)) for row in rows
                                    if row['status'] == 'refused')),
            'elapsed_wall_ns': stats([row.get('elapsed_wall_ns') for row in rows]),
            'calling_process_cpu_ns': stats([row.get('calling_process_cpu_ns') for row in rows])}


def arithmetic_observation(value):
    require(type(value) is dict and set(value) == {'schema', 'slots', 'retained_software_bytes',
            'completed', 'arithmetic'} and value['schema'] == 'public-v3-work-arithmetic-observation-v1'
            and type(value['slots']) is int and value['slots'] == 64
            and type(value['retained_software_bytes']) is int
            and 0 < value['retained_software_bytes'] <= 4 * 1024 * 1024
            and type(value['completed']) is bool, 'exact bounded arithmetic observation required')
    actual = value['arithmetic']
    if not value['completed']:
        require(actual is None, 'unfinished arithmetic observation cannot claim completed facts')
        return value
    flags = ('lookup_contended', 'exact_fact_found', 'trace_reused', 'product_reused',
             'transcript_entered', 'transcript_completed', 'product_entered', 'product_completed')
    require(type(actual) is dict and set(actual) == {*flags, 'lookup_probes', 'publication_probes',
            'publication'} and all(type(actual[key]) is bool for key in flags)
            and all(type(actual[key]) is int and 0 <= actual[key] <= 64
                    for key in ('lookup_probes', 'publication_probes'))
            and actual['publication'] in ('none', 'trace', 'product', 'existing-stronger-or-equal',
                                          'contended'), 'exact arithmetic path facts required')
    require((not actual['product_reused'] or actual['trace_reused'])
            and (not actual['trace_reused'] or actual['exact_fact_found'])
            and not (actual['trace_reused'] and actual['transcript_entered'])
            and (not actual['transcript_completed'] or actual['transcript_entered'])
            and (not actual['product_entered'] or actual['transcript_completed'])
            and (not actual['product_completed'] or actual['product_entered'])
            and (not actual['lookup_contended'] or
                 (actual['lookup_probes'] == 0 and not actual['exact_fact_found']))
            and (actual['publication'] not in ('trace', 'product', 'existing-stronger-or-equal')
                 or actual['transcript_completed'])
            and (actual['publication'] != 'product' or actual['product_completed']),
            'inconsistent reused versus recomputed arithmetic facts')
    return value


def execution_summary(rows, instrumented, arithmetic_profile=False, observer_v4=False,
                      *, interval_outcomes=True):
    result = {
        'records': len(rows),
        'record_complete': sum(row.get('complete') is True for row in rows),
        'record_observation_failed': sum(row.get('observation_failed') is True for row in rows),
        'terminal_phase_counts': dict(Counter(str(row.get('terminal_phase')) for row in rows)),
        'dispatch_outcomes': dict(Counter(outcome(row.get('dispatch_accepted')) for row in rows)),
        'full_work_outcomes': dict(Counter(outcome(row.get('full_work_accepted')) for row in rows)),
        'dispatch_thread_cpu_ns': stats([row.get('dispatch_thread_cpu_ns') for row in rows
                                         if row.get('dispatch_started') is True]),
        'full_work_thread_cpu_ns': stats([row.get('full_work_thread_cpu_ns') for row in rows
                                          if row.get('full_work_started') is True]),
        'submit_phase_measurements_available': instrumented,
        'submit_phases': None,
    }
    diagnostics = request_error_diagnostic_summary(rows)
    if diagnostics is not None:
        require(observer_v4, 'request error diagnostic extension requires v4 observer scope')
        result['error_diagnostics'] = diagnostics
    for name, summarize in (('error_timing', request_error_timing_summary),
                            ('request_cancellation', request_cancellation_summary),
                            ('reactor_io', reactor_io_summary)):
        extension = summarize(rows)
        if extension is not None:
            require(observer_v4 and instrumented, f'{name} extension requires v4 observer scope')
            result[name] = extension
    if any('cpu_settlement' in row for row in rows):
        require(observer_v4 and instrumented, 'cpu settlement extension requires v4 observer scope')
        result['cpu_settlement'] = cpu_settlement_summary(rows)
        if 'original_cpu_samples' in result['cpu_settlement']:
            # The new settlement version explicitly selects this extension.
            # Old v1 settlements/lifecycle-bearing reports retain their exact
            # historical derivation; no missing past CPU value is reconstructed.
            result['request_owner_completion'] = request_owner_lifecycle_summary(rows)
    if arithmetic_profile:
        known = [arithmetic_observation(row['work_arithmetic']) for row in rows
                 if 'work_arithmetic' in row]
        actual = [row['arithmetic'] for row in known if row['completed']]
        result['work_arithmetic'] = {
            'observed_records': len(known), 'unobserved_records': len(rows) - len(known),
            'completed_observations': len(actual),
            'unfinished_observations': len(known) - len(actual),
            'path_counts': {key: sum(row[key] for row in actual) for key in
                ('trace_reused', 'product_reused', 'transcript_entered', 'transcript_completed',
                 'product_entered', 'product_completed')},
            'publication_counts': dict(Counter(row['publication'] for row in actual)),
            'scope': 'observed path facts only; completion is not acceptance; reuse is not fresh replay; absent observations are unknown',
        }
    else:
        require(all('work_arithmetic' not in row for row in rows),
                'arithmetic path facts require explicit arithmetic profile')
    if instrumented:
        names = PHASES_V4 if observer_v4 else PHASES
        columns = defaultdict(list)
        for row in rows:
            if observer_v4:
                validate_v4_record(row)
            phases = row.get('submit_phases')
            require(isinstance(phases, list) and [p.get('phase') for p in phases] == list(names),
                    'instrumented observation must retain all seven ordered phase slots')
            for phase in phases:
                columns[phase['phase']].append(phase)
        result['submit_phases'] = []
        for name in names:
            slots = columns[name]
            entered = [p for p in slots if p.get('started') is True]
            result['submit_phases'].append({
                'phase': name, 'slots': len(slots), 'started': len(entered),
                'not_started': len(slots) - len(entered),
                'completed': sum(p.get('completed') is True for p in entered),
                'unfinished': sum(p.get('completed') is not True for p in entered),
                'outcomes': dict(Counter(outcome(p.get('accepted')) for p in entered)),
                'wall_ns': stats([p.get('wall_ns') for p in entered]),
                'thread_cpu_ns': stats([p.get('thread_cpu_ns') for p in entered]),
                'scope': 'entered slots only; unentered slots are counted separately, not zero CPU',
                **({'interval_outcomes': interval_outcome_summary(slots, phase=True)}
                   if interval_outcomes else {}),
                **({'parent_phase': PHASE_PARENTS_V4.get(name),
                    'error_code_counts': dict(Counter(str(p.get('error_code')) for p in entered))}
                   if observer_v4 else {}),
            })
        if observer_v4:
            result['wait_intervals'] = {
                key: {
                    'started': sum(row[key]['started_ns'] is not None for row in rows),
                    'not_started_or_clock_unknown': sum(row[key]['started_ns'] is None for row in rows),
                    'outcomes': dict(Counter(outcome(row[key]['accepted']) for row in rows)),
                    'wall_ns': stats([row[key]['wall_ns'] for row in rows
                                      if row[key]['started_ns'] is not None]),
                    'scope': 'wall only; queue includes bounded enqueue backpressure and FIFO wait until dequeue',
                    **({'interval_outcomes': interval_outcome_summary([row[key] for row in rows])}
                       if interval_outcomes else {}),
                } for key in WAIT_FIELDS_V4
            }
    return result


def completion_work_observation(value):
    """Exact local r13 boundary, never a permanent spent-work or fairness proof."""
    fixed = {
        'schema': 'public-v3-live-owner-completion-work-v1',
        'identity_domain': 'public-v3-complete-work-identity-v1',
        'identity_capacity': 4096, 'identity_storage_bytes': 4096 * 32,
        'epoch_scope': 'same-shared-live-cpu-owner',
        'evicts_live_epoch_identities': False, 'survives_process_restart': False,
        'full_capacity_disables_ordinary_verification': False,
    }
    counters = ('retained_identities', 'live_completions', 'repeated_identity_skips',
                'full_capacity_skips')
    require(type(value) is dict and set(value) == set(fixed) | set(counters),
            'exact r13 completion-work observation required')
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in fixed.items()), 'r13 completion-work scope mismatch')
    for key in counters:
        require(type(value[key]) is int and 0 <= value[key] <= 2**64 - 1,
                'r13 completion-work counter must be known')
    require(value['retained_identities'] <= 4096
            and value['live_completions'] <= min(2, value['retained_identities']),
            'r13 completion-work capacity mismatch')
    return dict(value)


def client_history_import_observations(history):
    """Read optional actual imports without changing immutable legacy outputs.

    Absence is unknown, never a zero-cost successful import. New snapshots use
    the same validator as the four-second driver; their local epochs cannot be
    compared with the enclosing campaign epoch. Preserve the enclosing caller
    interval and each nested observation separately, with no CPU sum.
    """
    present = [index for index, row in enumerate(history)
               if isinstance(row.get('client_import'), dict)
               and 'native_import_observation' in row['client_import']]
    if not present:
        return None
    require(len(history) <= 64, 'bounded client History calls required')
    observed = []
    for index in present:
        row = history[index]
        stage = row['client_import']
        require(row.get('status') == 'ok' and row.get('returned_after_window') is False,
                'native import requires an original on-time History response')
        require(type(stage.get('succeeded')) is bool and 'error' in stage
                and ((stage['error'] is None) if stage['succeeded']
                     else isinstance(stage['error'], str)), 'client import outcome required')
        require(stage.get('scope') == 'calling client thread only; excludes scoped execution worker CPU; '
                'unknown clock is null; no deadline or acceptance authority',
                'client import calling-thread CPU scope required')
        for key in ('started_ns', 'ended_ns', 'wall_ns', 'thread_cpu_ns'):
            require(key in stage, 'client import clock slot required')
            if stage[key] is not None:
                require(integer(stage[key]) < 1 << 64, 'client import clock u64 required')
        require(type(stage.get('thread_cpu_observation_available')) is bool
                and stage['thread_cpu_observation_available'] is (stage['thread_cpu_ns'] is not None),
                'client import CPU availability mismatch')
        if stage['started_ns'] is not None and stage['ended_ns'] is not None:
            require(stage['started_ns'] <= stage['ended_ns'], 'client import clock order')
        native = stage['native_import_observation']
        validate_history_import_observation(native)
        request = row.get('request')
        require(isinstance(request, dict) and request.get('op') == 'history',
                'native import History request binding required')
        for key in ('tip', 'after'):
            expected = digest(request.get(key))
            require(expected is not None and (native[key] is None or digest(native[key]) == expected),
                    'native import History context mismatch')
        if native['supplied_packets'] is not None:
            response = row.get('response')
            page = response.get('value') if isinstance(response, dict) else None
            require(isinstance(page, dict) and isinstance(page.get('packets'), list)
                    and native['supplied_packets'] == len(page['packets']),
                    'native import supplied packet count mismatch')
        native_span = next(slot for slot in native['phases'] if slot['phase'] == 'history_import')
        if stage['succeeded'] and native['measurement_failures'] == 0:
            require(native_span['completed'] and native_span['accepted'] is True
                    and all(slot['calls_started'] == slot['calls_accepted']
                            for slot in native['host_checks'])
                    and all(slot['calls_started'] == 1 for slot in native['host_checks']
                            if slot['phase'] != 'checkpoint')
                    and native['host_checks'][2]['calls_started'] > 0,
                    'successful client import observation mismatch')
        # A final Host refusal can follow a successful native commit; preserve
        # that failed outer result without rewriting the native result.
        observed.append({'history_call_index': index,
            'public_request_body_digest': digest(row.get('public_request_body_digest')),
            'client_import': stage})
    imports = sum(isinstance(row.get('client_import'), dict) for row in history)
    return {'schema': 'pon-client-history-import-readback-v1',
            'history_calls': len(history), 'retained_client_imports': imports,
            'observed_imports': len(observed), 'legacy_imports_without_observation': imports - len(observed),
            'history_calls_without_import_stage': len(history) - imports,
            'observed_outcomes': dict(Counter(outcome(row['client_import']['succeeded']) for row in observed)),
            'records': observed,
            'scope': {'nested_intervals_are_not_additive': True,
                      'phase_cpu_excludes_scoped_workers': True,
                      'host_cpu_includes_each_calling_thread': True,
                      'host_cpu_is_full_worker_cpu': False,
                      'snapshot_epoch_is_separate_from_campaign_epoch': True,
                      'unknown_cpu_is_not_zero': True, 'business_tps_capacity': None}}


def business_confirmation_summary(phase):
    """Read the original offered business cohort, including missing rounds.

    Request ACKs, cold readback and the receiver's queue timings are not client
    confirmations. The native in-window flag is retained separately; a missing
    confirmation observation or end clock cannot establish an on-time result.
    This checks internal retained evidence, not W1 or independent source truth.
    """
    phase_error = phase.get('startup_or_campaign_error')
    # The current native panic wrapper emits an error-only object. If a
    # retained failed phase also supplies partial observations, do not erase
    # those rows or use them to restore the failed phase's acceptance.
    rows = phase.get('confirmations', [])
    require(isinstance(rows, list), 'business confirmation list required')
    available = phase_error is None or bool(rows)
    if available:
        require(type(phase.get('duration_seconds')) is int and phase['duration_seconds'] == 30,
                'original 30-second business phase required')
    by_round = {}
    for row in rows:
        require(isinstance(row, dict), 'business confirmation object required')
        index = integer(row['round'])
        require(index < ROUNDS and index not in by_round,
                'unique scheduled business confirmation rounds required')
        by_round[index] = row

    def clock(row, key):
        value = row.get(key)
        if value is not None:
            require(integer(value) < 1 << 64, 'business clock u64 required')
        return value

    def confirmation_evidence(row):
        observation = row.get('observation')
        if observation is None:
            return None
        require(isinstance(observation, dict), 'native confirmation observation required')
        fields = ('confirmed', 'reorged', 'finalized', 'execution_authority', 'depth',
                  'observed_height', 'included_height', 'transaction', 'included_block',
                  'observed_tip', 'work_delta', 'required_work_delta')
        if not all(key in observation for key in fields) or not all(
                key in row for key in ('transaction', 'included_block', 'tip')):
            return None
        require(observation['confirmed'] is True and observation['reorged'] is False
                and observation['finalized'] is False and observation['execution_authority'] is False
                and type(observation['depth']) is int and observation['depth'] == BUSINESS_CONFIRMATION_DEPTH
                and integer(observation['observed_height']) - integer(observation['included_height'])
                    == BUSINESS_CONFIRMATION_DEPTH,
                'original business confirmation relation mismatch')
        for source, target in (('transaction', 'transaction'), ('included_block', 'included_block'),
                               ('observed_tip', 'tip')):
            expected = digest(row[target])
            require(expected is not None and digest(observation[source]) == expected,
                    'business confirmation identity mismatch')
        work, required = observation['work_delta'], observation['required_work_delta']
        # Original settings require six times the included block's required
        # work. Native required_work(target) is at least one for every legal
        # 256-bit target. Zero or a non-multiple of six cannot be that threshold.
        # This necessary relation does not infer or authenticate the target.
        require(all(isinstance(value, str) and re.fullmatch('[0-9a-f]{128}', value)
                    for value in (work, required))
                and int(required, 16) >= BUSINESS_CONFIRMATION_WORK_MULTIPLIER
                and int(required, 16) % BUSINESS_CONFIRMATION_WORK_MULTIPLIER == 0
                and int(work, 16) >= int(required, 16),
                'original business confirmation work mismatch')
        return True

    records = []
    for index, scheduled in enumerate(BUSINESS_SCHEDULE_NS):
        row = by_round.get(index)
        start = end = flag = evidence = None
        status = 'unobserved'
        if row is not None:
            flag = row.get('confirmed_inside_pressure_window')
            require(flag is None or type(flag) is bool, 'business confirmation boolean required')
            start, end = clock(row, 'started_ns'), clock(row, 'ended_ns')
            require(start is None or start >= scheduled, 'business start precedes original schedule')
            require(end is None or end >= (start if start is not None else scheduled),
                    'business round clock order mismatch')
            if flag is True:
                require(end is None or end < BUSINESS_DEADLINE_NS,
                        'late confirmation cannot satisfy original business window')
                evidence = confirmation_evidence(row)
                status = ('confirmed_in_window' if evidence is True and end is not None
                          else 'confirmation_evidence_unknown')
            else:
                status = 'not_confirmed_in_window' if flag is False else 'outcome_unknown'
        confirmed = status == 'confirmed_in_window'
        records.append({'round': index, 'scheduled_start_ns': scheduled,
            'started_ns': start, 'ended_ns': end, 'status': status,
            'native_reported_in_window': flag, 'confirmation_evidence_consistent': evidence,
            'schedule_delay_ns': start - scheduled if start is not None else None,
            'confirmed_scheduled_latency_ns': end - scheduled if confirmed else None,
            'confirmed_started_latency_ns': end - start if confirmed and start is not None else None,
            'observed_elapsed_ns': end - start if start is not None and end is not None else None})

    successful = [row for row in records if row['status'] == 'confirmed_in_window']

    def tails(values):
        result = stats(values)
        known = sorted(value for value in values if value is not None)
        result['p99_nearest_rank_ns'] = known[(99 * len(known) + 99) // 100 - 1] if known else None
        return result

    scheduled_tails = tails([row['confirmed_scheduled_latency_ns'] for row in successful])
    started_tails = tails([row['confirmed_started_latency_ns'] for row in successful])
    complete = len(successful) == ROUNDS and phase_error is None
    return {'schema': 'pon-public-v3-business-completion-v1',
        'observations_available': available, 'scheduled_rounds': ROUNDS, 'retained_rounds': len(rows),
        'phase_error': phase_error, 'partial_observations_retained': phase_error is not None and bool(rows),
        'scheduled_start_ns': list(BUSINESS_SCHEDULE_NS), 'absolute_phase_deadline_ns': BUSINESS_DEADLINE_NS,
        'native_reported_in_window_rounds': sum(row['native_reported_in_window'] is True for row in records),
        'readback_confirmed_in_window_rounds': len(successful),
        'completion_fraction': {'numerator': len(successful), 'denominator': ROUNDS},
        'outcome_counts': dict(Counter(row['status'] for row in records)), 'rounds': records,
        'successful_only_scheduled_latency_ns': scheduled_tails,
        'successful_only_started_latency_ns': started_tails,
        'all_scheduled_rounds_latency_ns': {
            'complete_observation': complete,
            **{key: scheduled_tails[key] if complete else None
               for key in ('p95_nearest_rank_ns', 'p99_nearest_rank_ns', 'max_ns')}},
        'scope': {'scheduled_latency_includes_schedule_delay': True,
            'started_latency_excludes_schedule_delay': True, 'one_original_absolute_phase_deadline': True,
            'empirical_successful_cohort_tails_are_not_population_guarantees': True,
            'missing_failed_or_unknown_rounds_suppress_all_offered_tail': True,
            'phase_error_suppresses_all_offered_tail': True,
            'acknowledgments_or_cold_state_are_not_confirmations': True,
            'source_or_native_verification_performed': False, 'attacker_budget_verified': False,
            'native_acceptance_flags_changed': False, 'resource_fairness_qualified': False}}


def phase_summary(phase, *, interval_outcomes=True, business_outcomes=False):
    mode = phase['mode']
    require(mode in MODES, 'unknown campaign phase')
    base = {'mode': mode, 'state_backend': phase.get('state_backend'),
            'scheduled_confirmation_rounds': ROUNDS,
            'native_phase_criteria_met': phase.get('finite_phase_criteria_met'),
            'startup_or_campaign_error': phase.get('startup_or_campaign_error')}
    policy = None
    if 'public_resource_policy' in phase:
        policy = identify_observation(phase['public_resource_policy'])
        base['public_resource_policy'] = policy
    arithmetic_profile = policy is not None and policy['resource_revision'] in ARITHMETIC_REVISIONS
    require((phase.get('work_profile') == ARITHMETIC_PROFILE if arithmetic_profile
             else 'work_profile' not in phase and 'work_arithmetic_owner' not in phase),
            'explicit matching arithmetic phase profile required')
    if arithmetic_profile:
        require(phase.get('state_backend') == 'authenticated-v1',
                'arithmetic campaign requires authenticated-v1')
        base['work_profile'] = ARITHMETIC_PROFILE
    if base['startup_or_campaign_error'] is not None:
        require(base['native_phase_criteria_met'] is not True,
                'native phase success requires all three original confirmations')
        base.update(observations_available=False, confirmed_rounds=None)
        if interval_outcomes:
            base.update(observed_confirmation_rounds=0, unobserved_scheduled_rounds=ROUNDS,
                        confirmation_rounds=[])
        if business_outcomes:
            base['honest_business_completion'] = business_confirmation_summary(phase)
        return base
    if policy is not None and policy.get('base_resource_revision', policy['resource_revision']) in ('r13', 'r14', 'r15'):
        base['completion_work_observation'] = completion_work_observation(
            phase.get('completion_work_observation'))
    else:
        require('completion_work_observation' not in phase,
                'completion-work observation requires explicit r13, r14 or r15 policy')
    if arithmetic_profile:
        owner = phase.get('work_arithmetic_owner')
        require(type(owner) is dict and set(owner) == {'schema', 'initial_state', 'slots',
                'retained_software_bytes', 'setup_cpu_ns', 'setup_wall_ns', 'scope',
                'adversarial_key_churn_service_qualified'}
                and owner['schema'] == 'public-v3-campaign-arithmetic-owner-v1'
                and owner['initial_state'] == 'fresh-empty-by-construction'
                and type(owner['slots']) is int and owner['slots'] == 64
                and type(owner['retained_software_bytes']) is int
                and 0 < owner['retained_software_bytes'] <= 4 * 1024 * 1024
                and type(owner['scope']) is str
                and owner['adversarial_key_churn_service_qualified'] is False,
                'fresh bounded arithmetic campaign owner required')
        integer(owner['setup_cpu_ns'])
        integer(owner['setup_wall_ns'])
        base['work_arithmetic_owner'] = owner
    require(phase['duration_seconds'] == 30, 'original 30-second phase required')
    rounds = phase['confirmations']
    indices = [integer(row['round']) for row in rounds]
    require(len(indices) == len(set(indices)) and all(n < ROUNDS for n in indices),
            'unique scheduled confirmation rounds required')
    confirmed = sum(row['confirmed_inside_pressure_window'] is True for row in rounds)
    require(phase['all_signed_rounds_confirmed_in_window'] is (confirmed == ROUNDS),
            'native confirmation aggregate does not match retained rounds')
    for row in rounds:
        require(type(row['confirmed_inside_pressure_window']) is bool,
                'boolean confirmation outcome required')
        started, ended = row.get('started_ns'), row.get('ended_ns')
        for clock in (started, ended):
            if clock is not None:
                integer(clock)
        require(started is None or ended is None or started <= ended,
                'ordered confirmation clocks required')
        if row['confirmed_inside_pressure_window']:
            # The native producer checks this exact six-depth observation and
            # the original phase deadline. This is report consistency only;
            # the reader does not authenticate execution or grant finality.
            require(started is not None and ended is not None
                    and ended < 30_000_000_000,
                    'confirmed round requires clocks inside the original window')
            observed = row.get('observation')
            require(type(observed) is dict and observed.get('confirmed') is True
                    and observed.get('finalized') is False
                    and observed.get('execution_authority') is False
                    and type(observed.get('depth')) is int and observed['depth'] == 6,
                    'confirmed round requires the original six-depth observation')
    require(phase.get('finite_phase_criteria_met') is not True or confirmed == ROUNDS,
            'native phase success requires all three original confirmations')
    if business_outcomes:
        base['honest_business_completion'] = business_confirmation_summary(phase)
    submissions, history = phase['submissions'], phase['history']
    client_imports = client_history_import_observations(history)
    if client_imports is not None:
        base['client_history_import_observations'] = client_imports
    attacks = [row for child in phase['children'] for row in
               ((child.get('report') or {}).get('result') or {}).get('calls', [])]
    observer = phase['receiver_observation']
    schema = observer['schema']
    require(schema in ('public-v3-local-request-resource-observation-v1',
                       'public-v3-local-request-resource-observation-v2',
                       'public-v3-local-request-resource-observation-v3',
                       'public-v3-local-request-resource-observation-v4'), 'unknown observer schema')
    instrumented = schema.endswith(('-v2', '-v3', '-v4'))
    observer_v4 = schema.endswith('-v4')
    if observer_v4:
        require(all(observer.get(key) is True for key in (
            'phase_parent_links_are_inclusive', 'cpu_wait_is_outside_dispatch',
            'monotonic_epoch_is_observer_local')), 'v4 inclusive/local-clock scope required')
    if policy is not None:
        require(schema.endswith(('-v3', '-v4')) is (policy.get('base_resource_revision', policy['resource_revision'])
                                         in ('r11', 'r12', 'r13', 'r14', 'r15')),
                'public policy and observed CPU scope disagree')
    if schema.endswith(('-v3', '-v4')):
        require(observer.get('cpu_includes_reactor_authentication_or_response_signing') is True
                and observer.get('cpu_includes_reactor_authentication') is False
                and observer.get('dispatch_cpu_includes_paid_body_decode') is True
                and observer.get('dispatch_cpu_includes_response_signing') is True,
                'v3 paid body/response CPU scope required')
    require(observer['cpu_intervals_are_nested_not_additive'] is True,
            'nested CPU observation scope required')
    if instrumented:
        require(observer['submit_phase_cpu_excludes_scoped_workers'] is True,
                'dispatcher-only phase CPU scope required')
    roles = defaultdict(set)
    for role, calls in (('honest_submit', submissions), ('client_history', history), ('attack_submit', attacks)):
        for row in calls:
            body = digest(row['public_request_body_digest'])
            # Unknown observations do not share an identity with one another.
            if body is not None:
                roles[body].add(role)
    grouped = defaultdict(list)
    for row in observer['records']:
        if arithmetic_profile and 'work_arithmetic' in row:
            actual = arithmetic_observation(row['work_arithmetic'])
            require(actual['retained_software_bytes'] == owner['retained_software_bytes'],
                    'arithmetic request and phase owner storage disagree')
        body = digest(row.get('body_digest'))
        candidates = roles.get(body, set()) if body is not None else set()
        role = next(iter(candidates)) if len(candidates) == 1 else 'unattributed_or_ambiguous'
        grouped[role].append(row)
    base.update({
        'observations_available': True, 'window_seconds': 30,
        'observed_confirmation_rounds': len(rounds), 'confirmed_rounds': confirmed,
        'unobserved_scheduled_rounds': ROUNDS - len(rounds),
        'confirmation_rounds': [{key: row.get(key) for key in (
            'round', 'started_ns', 'ended_ns', 'confirmed_inside_pressure_window',
            'receiver_hostile_work_rejected_during_round', 'paid_credit_depletion_observed_during_round')}
            for row in rounds],
        'submissions': call_summary(submissions), 'history': call_summary(history),
        'attack_calls': call_summary(attacks),
        'receiver': {'schema': schema, **{key: observer.get(key) for key in (
            'capacity', 'accepted_connections_seen', 'records_not_retained',
            'measurement_failures', 'counter_overflow')},
            'dispatch_cpu_scope': ('paid-body-decode-native-dispatch-signed-response'
                                   if schema.endswith(('-v3', '-v4')) else 'native-dispatch-only'),
            'native_observer_complete': phase['observer_complete'],
            'all_retained_records': execution_summary(observer['records'], instrumented, arithmetic_profile, observer_v4,
                                                             interval_outcomes=interval_outcomes),
            'by_observed_body_role': {role: execution_summary(rows, instrumented, arithmetic_profile, observer_v4,
                                                              interval_outcomes=interval_outcomes)
                                      for role, rows in sorted(grouped.items())}},
        'native_service_outcome': phase['service_outcome'],
        'final_cpu_meter': phase['final_meter'], 'final_actual_flow': phase.get('final_actual_flow'),
        'native_verifier_errors': phase['verifier_errors'],
        'receiver_client_state_equal': phase['receiver_client_state_equal'],
        'genuine_budget_depletion_observed': phase['genuine_budget_depletion_observed'],
        'attacker_processes_requested': phase['attacker_processes_requested'],
        'attacker_processes_ready': phase['attacker_processes_ready'],
        'actor_reports_successful_without_cap_or_kill': phase['actor_reports_successful_without_cap_or_kill'],
        'whole_parent_phase_cpu_ns': phase['whole_parent_phase_cpu_ns'],
        'whole_parent_phase_wall_ns': phase['whole_parent_phase_wall_ns'],
        'receiver_and_verifier_setup_cpu_ns': phase['receiver_and_verifier_setup_cpu_ns'],
        'receiver_and_verifier_setup_wall_ns': phase['receiver_and_verifier_setup_wall_ns'],
    })
    return base


def analyze(report, *, interval_outcomes=True, business_outcomes=None):
    if business_outcomes is None:
        business_outcomes = interval_outcomes
    arithmetic_profile = report['schema'] == ARITHMETIC_REPORT_SCHEMA
    require(arithmetic_profile or report['schema'] == 'native-public-v3-separate-process-campaign-v2',
            'unknown campaign schema')
    require([row['mode'] for row in report['phases']] == list(MODES), 'all three original phases required')
    require(all(row.get('state_backend') == report.get('state_backend') for row in report['phases']),
            'mixed backend observations')
    if 'public_resource_policy' in report:
        policy = identify_observation(report['public_resource_policy'])
        require(arithmetic_profile is (policy['resource_revision'] in ARITHMETIC_REVISIONS),
                'campaign schema and arithmetic policy disagree')
        require(all(row.get('public_resource_policy') == report['public_resource_policy']
                    for row in report['phases'] if row.get('startup_or_campaign_error') is None),
                'mixed or missing phase resource policies')
    else:
        require(not arithmetic_profile, 'arithmetic report requires explicit policy')
        require(all('public_resource_policy' not in row for row in report['phases']),
                'phase resource policy without original report identity')
    require((report.get('work_profile') == ARITHMETIC_PROFILE and
             report.get('state_backend') == 'authenticated-v1' and
             report.get('original_r13_campaign_qualified') is False and
             report.get('adversarial_key_churn_service_qualified') is False
             if arithmetic_profile else 'work_profile' not in report),
            'explicit separate arithmetic campaign scope required')
    result = {'schema': ('pon-public-v3-multiprocess-phase-derivation-v4' if business_outcomes
                         else 'pon-public-v3-multiprocess-phase-derivation-v3' if interval_outcomes
                         else 'pon-public-v3-multiprocess-phase-derivation-v2'),
            'state_backend': report.get('state_backend'),
            'native_finite_experiment_criteria_met': report['finite_experiment_criteria_met'],
            'native_economics_complete': report['economics_complete'],
            'best_observed_cold_legal_method': report['best_observed_cold_legal_method'],
            'honest_preparation_cpu_ns': report['preparation']['cpu_ns'],
            'honest_preparation_wall_ns': report['preparation']['wall_ns'],
            'phases': [phase_summary(row, interval_outcomes=interval_outcomes,
                                    business_outcomes=business_outcomes) for row in report['phases']],
            'scope': {'reader_runs_native_admission': False,
                      'host_or_source_authentication_performed': False,
                      'production_qualification': False, 'business_tps_capacity': None,
                      'fixed_confirmation_denominator_per_phase': ROUNDS,
                      'acknowledgments_are_not_confirmations': True,
                      'cpu_intervals_are_nested_not_additive': True,
                      'submit_phase_cpu_excludes_scoped_workers': True,
                      'cpu_excludes_reactor_authentication': True,
                      'dispatch_cpu_scope_retained_per_observer_schema': True,
                      'submit_phase_cpu_excludes_response_signing': True,
                      'unknown_cpu_is_not_zero': True,
                      'v1_missing_phase_measurements_are_not_reconstructed': True}}
    if any(phase['observations_available'] and 'cpu_settlement' in
           phase['receiver']['all_retained_records'] for phase in result['phases']):
        # Preserve historical derivations exactly when this extension is absent.
        # CpuSettle overlaps dispatch and continues after its final CPU sample;
        # ResponseEncoding includes signing. A uniform nested/exclusion claim
        # cannot describe these new observations, although intervals stay non-additive.
        result['scope'].update(cpu_intervals_are_nested_not_additive=False,
                               cpu_intervals_are_not_additive=True,
                               submit_phase_cpu_excludes_response_signing=False,
                               submit_phase_cpu_scope_is_phase_specific=True)
    if arithmetic_profile:
        result.update(source_report_schema=report['schema'], work_profile=ARITHMETIC_PROFILE,
                      public_resource_policy=policy)
        result['scope'].update(original_r13_campaign_qualified=False,
                               adversarial_key_churn_service_qualified=False)
    return result


def analyze_for_retained_schema(report, schema):
    """Reproduce an explicitly named immutable derivation format exactly.

    The original v1 reader accepted only v1/v2 native CPU observations, which
    excluded response construction. Its output had one combined exclusion flag
    and no per-phase dispatch_cpu_scope. These are the only versioned formatting
    differences for v1/v2. Version 3 additionally separates completed per-request
    interval tails from unfinished elapsed costs. Version 4 additionally reads
    all three scheduled business confirmations and their empirical latency tails.
    Historical reproduction omits newer extensions: every original measurement,
    outcome, denominator and threshold remains in the exact equality comparison.
    """
    require(schema in ('pon-public-v3-multiprocess-phase-derivation-v1',
                       'pon-public-v3-multiprocess-phase-derivation-v2',
                       'pon-public-v3-multiprocess-phase-derivation-v3',
                       'pon-public-v3-multiprocess-phase-derivation-v4'),
            'unknown retained phase derivation schema')
    if schema.endswith('-v4'):
        return analyze(report)
    if schema.endswith('-v3'):
        return analyze(report, business_outcomes=False)
    if schema.endswith('-v2'):
        return analyze(report, interval_outcomes=False)
    require('public_resource_policy' not in report
            and all('public_resource_policy' not in phase for phase in report['phases']),
            'historical v1 derivation cannot erase explicit public policy')
    require(all(phase.get('startup_or_campaign_error') is not None
                or phase['receiver_observation']['schema'] in (
                    'public-v3-local-request-resource-observation-v1',
                    'public-v3-local-request-resource-observation-v2')
                for phase in report['phases']),
            'historical v1 derivation cannot describe paid-envelope v3 CPU')
    value = analyze(report, interval_outcomes=False)
    value['schema'] = schema
    for phase in value['phases']:
        if phase['observations_available']:
            del phase['receiver']['dispatch_cpu_scope']
    scope = value['scope']
    del scope['cpu_excludes_reactor_authentication']
    del scope['dispatch_cpu_scope_retained_per_observer_schema']
    del scope['submit_phase_cpu_excludes_response_signing']
    scope['cpu_excludes_reactor_authentication_and_response_signing'] = True
    return value


def read_report_bytes(path):
    """Bind checks and bounded reads to one nonblocking regular-file descriptor.

    A pathname size check cannot bound a later read: the file can grow or be
    replaced between those operations. The digest still authenticates the exact
    retained bytes; this helper only bounds input acquisition, not JSON expansion.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode), 'regular report file required')
        require(info.st_size <= MAX_REPORT_BYTES, 'report exceeds finite reader byte limit')
        chunks, used = [], 0
        while chunk := os.read(descriptor, min(65536, MAX_REPORT_BYTES - used + 1)):
            used += len(chunk)
            require(used <= MAX_REPORT_BYTES, 'report exceeds finite reader byte limit')
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b''.join(chunks)


def read_report(path, expected, expected_public_policy_id=None):
    require(re.fullmatch('[0-9a-f]{64}', expected), 'explicit report SHA256 required')
    path = Path(path)
    raw = read_report_bytes(path)
    require(hashlib.sha256(raw).hexdigest() == expected,
            'retained report SHA256 mismatch')
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate JSON observation key: ' + key)
            value[key] = item
        return value

    report = json.loads(raw, object_pairs_hook=unique_object,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if expected_public_policy_id is not None:
        digest(expected_public_policy_id)
        require('public_resource_policy' in report,
                'pinned public policy is absent from historical report')
        observed = identify_observation(report['public_resource_policy'])
        require(observed['policy_id'] == expected_public_policy_id,
                'observed public policy does not match requested pin')
    value = analyze(report)
    value['input'] = {'report': str(path), 'bytes': len(raw), 'sha256': expected}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-dir', required=True, type=Path)
    parser.add_argument('--expected-report-sha256', required=True)
    parser.add_argument('--expected-public-policy-id',
                        help='Require explicit matching policy metadata; never infer it for old reports')
    args = parser.parse_args()
    print(json.dumps(read_report(args.raw_dir / 'report.json', args.expected_report_sha256,
                                args.expected_public_policy_id),
                     sort_keys=True, indent=2, allow_nan=False))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
