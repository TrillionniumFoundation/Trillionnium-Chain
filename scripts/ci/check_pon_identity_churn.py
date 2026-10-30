#!/usr/bin/env python3
"""Read the PN1 identity supplement; consistency is not host or work-cost authority.

All native failures and unoffered slots remain in the denominator. Full scalar
replay is deliberately required for every retained nonce, including target
misses. The reader never runs a node, changes an owner, or grants activation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
import fnmatch
import json
import os
from pathlib import Path
import re
import sqlite3
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
from check_public_readiness_evidence import decode_packet, digest, integer, require, sha
from pon_public_v3_phase_read import completion_work_observation
from pon_public_v3_policy_read import identify_observation
from read_original_native_campaign import Bundle, resource, source, strict_json
from run_pon_identity_churn import (ACCEPTANCE, PLAN, SELECTOR, TARGET, profile,
    CLAIM_DOCUMENT_BYTES, CLAIM_PAIR_RESERVATION_BYTES, VIRTUAL_INPUT_NAMESPACES,
    LINK_SCHEMA, CLAIM_SCHEMA, CLAIM_TERMINAL_SCHEMA, CLAIM_DOMAIN, claim_basename,
    FD_DISPATCH_SCHEMA, held_file_names)
from contract_wire import H, header_decode, header_encode, tx_decode
from strict_signature import verify as verify_signature
import work_oracle

SCHEMA = 'native-public-v3-identity-churn-supplement-v1'
MODES = ('honest-only', 'replay-only', 'fresh-identities')
BURST, REFILL, RESERVE = 2_000_000_000, 250_000_000, 100_000_000
SECOND, CAPACITY, ACTORS = 1_000_000_000, 4096, 24
FLAGS = ('public_network_ready', 'production_activation', 'independent_accepted',
         'work_profile_qualified', 'work_hardness_accepted', 'wan_qualified',
         'merge_ready', 'independent_operators', 'original_campaign_qualified')


def flags(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FLAGS:
                require(item is False, 'unsupported qualification: ' + key)
            flags(item)
    elif isinstance(value, list):
        for item in value:
            flags(item)


def flow(value, *, settled=False):
    require(type(value) is dict and value.get('schema') == 'public-v3-local-actual-cpu-flow-v1',
            'known original CPU flow required')
    signed = ('initial_credit_ns', 'remaining_paid_credit_ns', 'stored_credit_ns')
    for key in (*signed, 'credited_refill_ns', 'discarded_refill_ns', 'booked_reservation_ns',
                'live_debited_cpu_ns', 'settlement_residual_cpu_ns', 'settled_full_cpu_ns',
                'unsettled_known_live_cpu_ns', 'paid_cpu_debit_ns', 'settlement_discard_ns', 'live_owners'):
        require(type(value.get(key)) is int and abs(value[key]) < 2**127
                and (key in signed or value[key] >= 0), 'unknown CPU field: ' + key)
    require(value['initial_credit_ns'] == BURST and value['live_owners'] <= 2
            and value.get('balance_identity_verified') is True
            and value['paid_cpu_debit_ns'] == value['live_debited_cpu_ns'] + value['settlement_residual_cpu_ns']
            and value['remaining_paid_credit_ns'] == BURST + value['credited_refill_ns']
                - value['paid_cpu_debit_ns'] - value['settlement_discard_ns']
            and value['stored_credit_ns'] == value['remaining_paid_credit_ns'] - value['booked_reservation_ns']
            and value['booked_reservation_ns'] == value['live_owners'] * RESERVE
            and value['unsettled_known_live_cpu_ns'] == value['paid_cpu_debit_ns'] - value['settled_full_cpu_ns'],
            'original paid CPU conservation')
    if settled:
        require(value['live_owners'] == value['booked_reservation_ns'] == value['unsettled_known_live_cpu_ns'] == 0
                and value['paid_cpu_debit_ns'] == value['settled_full_cpu_ns'], 'unsettled original owner')
    return value


def monotone(previous, current):
    for key in ('credited_refill_ns', 'discarded_refill_ns', 'live_debited_cpu_ns',
                'settlement_residual_cpu_ns', 'settled_full_cpu_ns', 'paid_cpu_debit_ns',
                'settlement_discard_ns'):
        require(current[key] >= previous[key], 'owner reset or reversed CPU counter: ' + key)


def depletion_interval(sample):
    """Conservative future interval, never interpolation between point samples."""
    start = integer(sample['observation_started_ns'])
    end = integer(sample['observation_ended_ns'])
    require(end >= start, 'sample clock order')
    fresh = sample['credit_freshness']
    require(type(fresh) is dict and fresh.get('schema') == 'public-v3-local-cpu-credit-freshness-v1',
            'unknown freshness sample')
    actual = flow(fresh['actual_flow'])
    age = integer(fresh['watermark_age_ns'])
    offered = age * REFILL // SECOND
    ceiling = BURST - actual['booked_reservation_ns']
    projected = min(actual['stored_credit_ns'] + offered, ceiling)
    require(fresh['projected_stored_credit_ns'] == projected
            and fresh['projected_paid_credit_ns'] == projected + actual['booked_reservation_ns']
            and fresh['projected_credited_refill_ns'] == projected - actual['stored_credit_ns']
            and fresh['projected_discarded_refill_ns'] == actual['stored_credit_ns'] + offered - projected
            and type(fresh['projected_scalar_start_eligible']) is bool
            and fresh['projected_scalar_start_eligible'] is
                (actual['live_owners'] < 2 and projected >= RESERVE), 'freshness arithmetic mismatch')
    # The original lock read happened somewhere inside [start,end]. Treat it as
    # the earliest possible time, and round refill upward to keep an upper bound.
    upper = fresh['projected_paid_credit_ns'] + ((end - start) * REFILL + SECOND - 1) // SECOND
    if actual['paid_cpu_debit_ns'] <= BURST - RESERVE or upper >= RESERVE:
        return None
    duration = ((RESERVE - upper) * SECOND - 1) // REFILL
    return (end, end + duration) if duration > 0 else None


def coverage(intervals, start, end):
    require(type(start) is int and type(end) is int and start < end, 'round interval')
    clipped = sorted((max(a, start), min(b, end)) for a, b in intervals if a < end and b > start)
    merged = []
    for a, b in clipped:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    proven = sum(b - a for a, b in merged)
    bounds = [start, *(v for pair in merged for v in pair), end]
    gaps = [bounds[i + 1] - bounds[i] for i in range(0, len(bounds) - 1, 2)]
    return {'covered_ns': proven, 'round_ns': end - start, 'max_unproven_gap_ns': max(gaps)}


def construction_budget(row):
    """Check the bounded per-construction receipt; not a full artifact ledger."""
    value = row.get('evidence_budget')
    require(type(value) is dict, 'missing complete-attempt byte budget')
    for key, expected in (('per_construction_limit_bytes', 8 * 1024**2),
            ('frame_reservation_bytes', 128 * 1024), ('attempt_reservation_bytes', 100 * 1024),
            ('working_buffer_limit_bytes', 32 * 1024**2), ('successful_proof_bytes', 49188)):
        require(type(value.get(key)) is int and value[key] == expected,
                'changed bounded construction policy: ' + key)
    limit = integer(value['stage_limit_bytes'], 1, 8 * 1024**3)
    used = integer(value['stage_used_before_bytes'], 0, limit)
    frame = integer(value['frame_limit_bytes'], 1, 8 * 1024**2)
    require(frame == min(max(0, limit - used - 8 * 1024), 8 * 1024**2)
            and value['cap_reached'] is False and value['poisoned'] is False,
            'construction evidence cap reached, poisoned writer or incorrect frame')
    encoded_attempts = 0
    for trial in row['attempts']:
        require(encoded_attempts + value['attempt_reservation_bytes'] + value['frame_reservation_bytes'] <= frame,
                'successful prove was begun without complete evidence reservation')
        # The Rust writer counts compact UTF-8 JSON plus one delimiter per row.
        # Unknown fields remain in this independent byte count.
        size = len(json.dumps(trial, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode())
        require(size <= value['attempt_reservation_bytes'], 'attempt exceeded reserved evidence bytes')
        encoded_attempts += size + 1
    require(type(value['attempt_serialized_bytes']) is int
            and value['attempt_serialized_bytes'] == encoded_attempts,
            'raw attempt serialized byte accounting mismatch')
    require(len(json.dumps(row, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()) <= frame,
            'construction exceeded bounded frame')


def construction(row, template, index, *, version='v1'):
    """Recreate all attempt proofs, not merely a winner or claimed hash ticket."""
    selected = profile(version)
    require(row.get('schema') == selected['construction_schema']
            and row.get('index') == index and row.get('attempt_limit') == 4096,
            'construction profile/index')
    require(version == 'v1' or type(row.get('index')) is int, 'typed v2 construction index required')
    # A terminal cap failure must remain available for diagnosis. It can never
    # be treated as an ordinary deadline or a successful finite sample.
    require(version == 'v1' or (row.get('error') != 'evidence-cap'
            and row.get('terminal_error') != 'evidence-cap'
            and row.get('evidence_budget', {}).get('cap_reached') is not True),
            'construction evidence cap reached')
    raw = bytes.fromhex(template)
    header_raw, _transactions, proof = decode_packet(raw)
    header = header_decode(header_raw)
    header['state'] = bytes([header['state'][0] ^ 1]) + header['state'][1:]
    initial = 2_000_000 + index * 4096
    require(row['initial_nonce'] == initial, 'disjoint nonce range')
    factors = struct.unpack('<' + 'I' * (2 * work_oracle.CELLS), proof[4:4 + 8 * work_oracle.CELLS])
    a, b = factors[:work_oracle.CELLS], factors[work_oracle.CELLS:]
    require(work_oracle.task_id(a, b) == header['work_task'], 'template task/actual factors mismatch')
    attempts = row['attempts']
    require(type(attempts) is list and len(attempts) <= 4096, 'missing/excess construction attempts')
    winner, total = None, 0
    for offset, trial in enumerate(attempts):
        header['nonce'] = initial + offset
        require(trial['nonce'] == header['nonce'], 'missing/mutated nonce attempt')
        total += integer(trial['thread_cpu_ns'], 1)
        # A producer error remains a failure, rather than a free successful miss.
        require('error' not in trial, 'producer error cannot qualify completed prefix')
        challenge = H('challenge', header_encode(header))
        rebuilt = work_oracle.prove(challenge, a, b)
        if version == 'v2':
            require(type(trial.get('proof')) is str and len(trial['proof']) == 2 * 49188
                    and re.fullmatch('[0-9a-f]+', trial['proof']) is not None,
                    'every completed v2 attempt requires complete raw proof bytes')
        if 'proof' in trial:
            require(trial['proof'] == rebuilt.hex(), 'retained complete attempt proof changed')
        if 'challenge' in trial:
            require(trial['challenge'] == challenge.hex(), 'retained attempt challenge changed')
        require(trial['trace'] == rebuilt[-32:].hex(), 'attempt transcript parity')
        ticket = H('ticket', challenge, rebuilt[-32:])
        hit = ticket <= header['target']
        require(trial['ticket'] == ticket.hex() and type(trial['target_hit']) is bool
                and trial['target_hit'] is hit, 'attempt ticket/target parity')
        if hit:
            require(offset == len(attempts) - 1, 'omitted/extra attempts after target hit')
            winner = header_encode(header) + raw[318:-len(proof)] + rebuilt
    if version == 'v2':
        construction_budget(row)
    if winner is None:
        require((row['status'] == 'exhausted' and len(attempts) == 4096 and row['error'] is None)
                or (row['status'] == 'producer-error' and row['error'] == 'outer-deadline'),
                'unexplained missing construction attempts')
        require(row['packet'] is row['completion_identity'] is None
                and row['production_verified'] is row['reference_verified'] is False,
                'failed construction fabricated winner')
        require(integer(row['construction_thread_cpu_ns']) >= total
                and integer(row['construction_wall_ns'], 1) > 0
                and integer(row['verification_thread_cpu_ns']) >= 0, 'unknown failed construction cost')
        return None, None
    require(row['status'] == 'winner' and row['error'] is None
            and row['production_verified'] is True and row['reference_verified'] is True
            and row['packet'] == winner.hex(), 'winner full packet mismatch')
    require(integer(row['construction_thread_cpu_ns'], 1) >= total
            and integer(row['construction_wall_ns'], 1) > 0
            and integer(row['verification_thread_cpu_ns'], 1) > 0, 'unknown/inconsistent construction CPU')
    identity = H('public-v3-complete-work-identity-v1', winner).hex()
    require(row['completion_identity'] == identity, 'complete work identity')
    return winner, identity


def call(row, *, epoch, end):
    start, stop = integer(row['started_ns']), integer(row['ended_ns'])
    require(start < stop and type(row['returned_after_window']) is bool
            and row['returned_after_window'] is (epoch + stop >= end), 'call clock/window')
    integer(row['calling_process_cpu_ns'], 1)
    require(row['status'] in ('ok', 'refused', 'error'), 'missing offered call disposition')
    if row['status'] == 'error':
        require(row['response'] is None and type(row['error']) is str and row['error'], 'missing failed call evidence')
    else:
        require(row['error'] is None and row['response']['ok'] is (row['status'] == 'ok'), 'signed call disposition')
    metrics = row['metrics']
    for key in ('construction_ns', 'challenge_ns', 'solution_search_ns', 'solution_trials',
                'solution_body_response_ns', 'total_elapsed_ns'):
        integer(metrics[key])
    require(metrics['total_elapsed_ns'] <= integer(row['elapsed_wall_ns'], 1)
            and type(metrics['solution_found']) is bool, 'call measurement scope')
    return digest(row['public_request_body_digest'])


def receiver(records, calls, final_flow, metrics):
    """Join exact submitted bodies; repeated replay bodies retain their counts."""
    require(records['schema'] == 'public-v3-local-request-resource-observation-v3'
            and records['records_not_retained'] == records['measurement_failures'] == 0
            and records['counter_overflow'] is False
            and records['accepted_connections_seen'] == len(records['records']) <= records['capacity']
            and records['cpu_intervals_are_nested_not_additive'] is True
            and records['dispatch_cpu_includes_paid_body_decode'] is True
            and records['dispatch_cpu_includes_response_signing'] is True,
            'incomplete receiver observations')
    offered = Counter(calls)
    observed = Counter()
    paid = 0
    root = []
    for row in records['records']:
        require(row['complete'] is True and row['observation_failed'] is False,
                'incomplete native receiver record')
        body = row['body_digest']
        body = bytes(body).hex() if isinstance(body, list) else digest(body)
        observed[body] += 1
        require(body in offered, 'unattributed receiver body')
        if row['operation'] == 1 and row['dispatch_started'] is True:
            paid += integer(row['dispatch_thread_cpu_ns'], 1)
            require(type(row['dispatch_accepted']) is bool, 'unknown dispatched outcome')
        if row['full_work_started'] is True:
            require(type(row['full_work_accepted']) is bool, 'unknown full-work outcome')
            integer(row['full_work_thread_cpu_ns'], 1)
        phases = row['submit_phases']
        require([phase['phase'] for phase in phases] == ['decode', 'context_owner_wait', 'context',
            'work', 'admission_owner_wait', 'admission', 'submit_result'], 'missing ordered native phase slots')
        for phase in phases:
            if phase['started'] is True:
                require(phase['completed'] is True and type(phase['accepted']) is bool,
                        'unknown entered native phase outcome')
                integer(phase['wall_ns'])
                integer(phase['thread_cpu_ns'])
        if row['full_work_accepted'] is True and row['dispatch_accepted'] is False:
            root.append(body)
    require(all(observed[body] <= count for body, count in offered.items()), 'duplicate receiver call observations')
    closed = flow(final_flow, settled=True)
    require(paid == closed['paid_cpu_debit_ns'] == metrics['mutation_cpu_charged_ns']
            and metrics['mutation_cpu_clock_failures'] == 0, 'closed receiver CPU reconciliation')
    return observed, root


def read_json(path):
    require(path.stat().st_size <= 256 * 1024 * 1024, 'bounded JSON artifact')
    return strict_json(path.read_bytes())


def packet_facts(wire):
    raw = bytes.fromhex(wire)
    encoded, transactions, proof = decode_packet(raw)
    header = header_decode(encoded)
    work_oracle.verify(H('challenge', encoded), header['work_task'], header['target'], proof)
    return dict(wire=wire, header=header, transactions=transactions,
                identity=H('block', encoded, proof[-32:]).hex())


def preparation(value, *, version='v1'):
    require(value['schema'] == profile(version)['campaign_schema'] and len(value['seed_packets']) == 4
            and len(value['business_packets']) == 21, 'original preparation denominator')
    integer(value['cpu_ns'], 1)
    integer(value['wall_ns'], 1)
    require(value['node_search_attempt_counts'] is None, 'unexposed seed search counts invented')
    facts = [packet_facts(wire) for wire in value['seed_packets'] + value['business_packets']]
    nonce = 0
    for index, fact in enumerate(facts):
        header, transactions = fact['header'], fact['transactions']
        require(header['height'] == index + 1 and (index == 0 or header['parent'].hex() == facts[index - 1]['identity']),
                'prepared chain linkage/height')
        require(header['network'] == facts[0]['header']['network']
                and header['parameters'] == facts[0]['header']['parameters'], 'prepared chain context')
        require(len(transactions) == (256 if index < 4 else 1 if (index - 4) % 7 == 0 else 0),
                'original signed transfer workload')
        for raw in transactions:
            transaction = tx_decode(raw)
            nonce += 1
            require(transaction['nonce'] == nonce and transaction['tag'] == 1
                    and transaction['network'] == header['network'], 'actual sequential transfer lineage')
            verify_signature(transaction['sender'], transaction['signature'], H('tx-sign', transaction['unsigned']))
    require(nonce == 1027, '1024 seed and three business transfers required')
    return facts


def durable_history(bundle, directory, facts, hostile):
    """Read a private copy including WAL; never open/repair producer storage."""
    with tempfile.TemporaryDirectory(prefix='pn1-readback-') as temporary:
        root = Path(temporary)
        for suffix in ('', '-wal', '-shm'):
            name = directory + '/native.sqlite' + suffix
            if name in bundle.files:
                (root / ('native.sqlite' + suffix)).write_bytes(bundle.raw(name, 256 * 1024 * 1024))
        require((root / 'native.sqlite').exists(), 'missing actual durable history')
        with closing(sqlite3.connect((root / 'native.sqlite').as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('PRAGMA trusted_schema=OFF')
            db.set_progress_handler(lambda: 1, 10_000_000)
            require(db.execute('PRAGMA quick_check').fetchone() == ('ok',), 'actual SQLite integrity')
            rows = list(db.execute('SELECT id,parent,height,packet,state_root,chainwork FROM blocks ORDER BY height'))
            require(len(rows) == 26, 'durable history contains missing/hostile block')
            require(rows[0][0].hex() == facts[0]['header']['parent'].hex() and rows[0][2] == 0,
                    'actual genesis binding')
            work = 0
            for row, fact in zip(rows[1:], facts):
                work += 2**256 // (int.from_bytes(fact['header']['target'], 'big') + 1)
                require(row[0].hex() == fact['identity'] and row[1] == fact['header']['parent']
                        and row[2] == fact['header']['height'] and row[3].hex() == fact['wire']
                        and row[4] == fact['header']['state'] and row[5] == work.to_bytes(64, 'big'),
                        'actual packet/state/work history differs from independent replay')
            tip, generation = db.execute('SELECT tip,generation FROM active WHERE singleton=1').fetchone()
            require(tip.hex() == facts[-1]['identity'] and generation == 25, 'actual active generation')
            require(not {row[0].hex() for row in rows} & set(hostile), 'hostile packet present in durable history')


def process_limits_v2(value, role, group, pid=None):
    caps = profile('v2')['evidence_caps']
    require(role in ('actor', 'campaign-parent') and type(value) is dict
            and value['schema'] == caps['schema'] and value['role'] == role
            and value['original_cgroup_required'] is True and value['full_ledger_implemented'] is True,
            'incomplete native process limit owner')
    before, after = value['before'], value['after']
    v2_identity_types('process_observation', before)
    v2_identity_types('process_observation', after)
    if pid is not None:
        integer(pid, 1)
    require(before['pid'] == after['pid'] and (pid is None or after['pid'] == pid)
            and before['cgroup'] == after['cgroup'] == group, 'limit receipt process/cgroup changed')
    integer(after['pid'], 1)
    expected = dict(address_space=caps['actor_vm_bytes'] if role == 'actor' else caps['parent_vm_bytes'],
                    file_size=caps['actor_file_bytes'] if role == 'actor' else caps['parent_file_bytes'])
    for key, limit in expected.items():
        require(type(before[key]['soft_bytes']) is int and type(before[key]['hard_bytes']) is int
                and before[key]['soft_bytes'] >= limit and before[key]['hard_bytes'] >= limit
                and type(after[key]['soft_bytes']) is int and type(after[key]['hard_bytes']) is int
                and after[key]['soft_bytes'] == after[key]['hard_bytes'] == limit,
                'native address-space/file hard cap absent or changed')
    return after['pid']


def sample_lines(bundle, path, value, *, version='v1'):
    if version == 'v1':
        yield from bundle.raw(path + value['sample_file']).splitlines()
        return
    caps = profile('v2')['evidence_caps']
    names = value['sample_files']
    expected_count = integer(value['sample_count'], 1)
    require(value['sample_chunk_bytes'] == caps['sample_chunk_bytes']
            and value['sample_chunks_limit'] == caps['sample_chunks_per_phase']
            and value['sample_cap_reached'] is False and value['sample_io_error'] is None
            and value['unpersisted_sample'] is None and value['final_sync_all_error'] is None,
            'incomplete or poisoned v2 sample owner')
    for key, expected in (('sync_data_attempts', expected_count), ('sync_data_successes', expected_count),
            ('final_sync_all_attempts', 1), ('final_sync_all_successes', 1)):
        require(type(value[key]) is int and value[key] == expected, 'sample persistence owner mismatch: ' + key)
    require(type(names) is list and 0 < len(names) <= caps['sample_chunks_per_phase']
            and names == [f'samples-{index:02}.jsonl' for index in range(len(names))],
            'missing, reordered or excessive v2 sample chunks')
    actual = {name for name in bundle.files if name.startswith(path) and '/' not in name[len(path):]
              and re.fullmatch(r'samples-[0-9]{2}\.jsonl', name[len(path):])}
    require(actual == {path + name for name in names}, 'unlisted or missing v2 sample chunk')
    count, measured_bytes = 0, 0
    for name in names:
        raw = bundle.raw(path + name, caps['sample_chunk_bytes'])
        require(raw and raw.endswith(b'\n'), 'truncated or empty v2 sample chunk')
        count += len(raw.splitlines())
        measured_bytes += len(raw)
        yield from raw.splitlines()
    require(count == expected_count and integer(value['sample_bytes']) == measured_bytes,
            'v2 sample row/byte denominator differs from actual persisted chunks')




# Only explicit identity/index/accounting fields from the existing v2 owner.
# These checks do not normalize missing/UNKNOWN values, change bounds or grant
# authority to a diagnostic component. Original equality checks remain below.
V2_INTEGER_IDENTITY_FIELDS = dict(
    phase='parent_pid prefix_epoch_ns prefix_end_ns pressure_epoch_ns pressure_end_ns',
    process_observation='pid',
    ready='pid ppid worker setup_calls', child='pid started_ns reaped_ns',
    result='pid worker', finished='pid worker', slot='slot index',
    started='index initial_nonce attempt_limit', construction='index initial_nonce attempt_limit',
    attempt='nonce', wrapper='worker index absolute_started_ns absolute_ended_ns',
    sample='index observation_started_ns observation_ended_ns',
    sample_owner='sample_count sample_bytes sample_chunk_bytes sample_chunks_limit '
        'sync_data_attempts sync_data_successes final_sync_all_attempts final_sync_all_successes',
    meter='burst_ns refill_ns_per_second start_reserve_ns worker_limit stored_credit_ns in_flight',
    freshness='watermark_age_ns projected_stored_credit_ns projected_paid_credit_ns '
        'projected_credited_refill_ns projected_discarded_refill_ns',
    round='round scheduled_ns started_ns ended_ns',
    confirmation='depth observed_height included_height active_generation',
    receiver='records_not_retained measurement_failures accepted_connections_seen capacity',
    receiver_metrics='mutation_cpu_charged_ns mutation_cpu_clock_failures',
    construction_budget='stage_limit_bytes stage_used_before_bytes')


def v2_identity_types(kind, value):
    require(type(value) is dict and kind in V2_INTEGER_IDENTITY_FIELDS, 'typed v2 identity record')
    for key in V2_INTEGER_IDENTITY_FIELDS[kind].split():
        require(type(value[key]) is int, 'v2 integer identity/index required: ' + kind + '.' + key)


def v2_copy_types(actual, expected):
    """Retained duplicate records must preserve scalar types as well as values."""
    require(type(actual) is type(expected), 'v2 copied record type alias')
    if type(expected) is dict:
        require(set(actual) == set(expected), 'v2 copied record fields')
        for key in expected:
            v2_copy_types(actual[key], expected[key])
    elif type(expected) is list:
        require(len(actual) == len(expected), 'v2 copied record length')
        for left, right in zip(actual, expected):
            v2_copy_types(left, right)


def v2_fd_census(value, *, minimum=3):
    require(type(value) is list, 'typed v2 FD census list required')
    for fd in value:
        integer(fd, minimum, 2**31-1)


def v2_sample_owner(phase):
    require(type(phase) is dict and type(phase.get('samples')) is dict,
            'actual v2 phase samples owner required; no synthetic top-level compatibility')
    owner = phase['samples']
    v2_identity_types('sample_owner', owner)
    require(owner['sampler_thread_joined'] is True and owner['sampler_thread_panicked'] is False,
            'v2 sampler thread not joined or panicked')
    return owner


def v2_receiver_types(records, metrics):
    v2_identity_types('receiver', records)
    v2_identity_types('receiver_metrics', metrics)
    for row in records['records']:
        # operation is a genuine Option<u8>; an unknown operation stays None.
        if row['operation'] is not None:
            require(type(row['operation']) is int, 'v2 receiver operation type')
        if type(row['body_digest']) is list:
            for byte in row['body_digest']:
                integer(byte, 0, 255)


# A separate nested domain: old first-exec receipts and old finite raw controls
# retain their original meanings. No gate is opened by this record reader.
DESCENDANT_SCHEMA = 'pon-identity-actor-fd-binding-v1'
DESCENDANT_SCOPE = 'dedicated-v2-exact-single-test-serialized-harness-spawn-v1'
DESCENDANT_READBACK = 'pon-identity-descendant-fd-readback-v1'


def exact_record(value, fields, label):
    require(type(value) is dict and set(value) == set(fields.split()), label + ' record fields')


def fd_identity(value):
    exact_record(value, 'device inode', 'FD identity')
    integer(value['device'], 0, 2**64-1)
    integer(value['inode'], 1, 2**64-1)
    return value


def executable_pin(value):
    exact_record(value, 'identity bytes sha256', 'actual executable')
    fd_identity(value['identity'])
    integer(value['bytes'], 1, 192 * 1024**2)
    digest(value['sha256'])
    return value


def caller_record(value):
    exact_record(value, 'schema kind scope parent_pid python_inputs remaining_inheritable '
        'external_library_concurrent_spawn_supported full_campaign_qualified', 'native caller')
    require(value['schema'] == DESCENDANT_SCHEMA and value['kind'] == 'caller-scope'
            and value['scope'] == DESCENDANT_SCOPE and value['remaining_inheritable'] == []
            and value['external_library_concurrent_spawn_supported'] is False
            and value['full_campaign_qualified'] is False, 'native caller scope/quarantine')
    integer(value['parent_pid'], 1)
    require(type(value['python_inputs']) is list, 'typed native caller inputs')
    return value


def descendant_caller_binding(caller, dispatch, parent_pid, binary):
    """Join already-validated first-exec/source custody to the native caller."""
    caller_record(caller)
    require(caller['parent_pid'] == integer(parent_pid, 1), 'native caller parent mismatch')
    descriptors = [integer(dispatch[key], 3, 2**31-1)
                   for key in ('executable_fd', 'execution_directory_fd', 'cwd_directory_fd')]
    v2_fd_census(dispatch['inherited_fds'])
    require(len(set(descriptors)) == 3 and dispatch['schema'] == FD_DISPATCH_SCHEMA
            and dispatch['qualification'] is False
            and dispatch['native_descendant_path_binding_complete'] is False
            and dispatch['inherited_fds'] == sorted(descriptors)
            and dispatch['actual_executable'] == '/proc/self/fd/' + str(descriptors[0])
            and dispatch['actual_cwd'] == '/proc/self/fd/' + str(descriptors[2])
            and dispatch['actual_raw_root'] == '/proc/self/fd/' + str(descriptors[1]) + '/raw',
            'first-exec to native caller FD domain')
    pin = executable_pin(dict(identity=dispatch['executable_identity'],
        bytes=dispatch['executable_bytes'], sha256=dispatch['executable_sha256']))
    require(pin['sha256'] == binary['sha256'] and pin['bytes'] == binary['bytes'],
            'native caller executable differs from frozen source binary')
    expected = {'executable': (descriptors[0], pin['identity']),
                'output': (descriptors[1], fd_identity(dispatch['execution_identity'])),
                'source-cwd': (descriptors[2], fd_identity(dispatch['cwd_identity']))}
    inputs, seen = caller['python_inputs'], set()
    require(len(inputs) == 3, 'three quarantined original Python inputs required')
    for row in inputs:
        exact_record(row, 'fd kind identity before_cloexec', 'quarantined Python input')
        require(row['kind'] in expected and row['kind'] not in seen, 'duplicate/extra caller FD class')
        seen.add(row['kind'])
        require((integer(row['fd'], 3), fd_identity(row['identity'])) == expected[row['kind']]
                and row['before_cloexec'] is False, 'Python/native inherited input mismatch')
    require([row['fd'] for row in inputs] == sorted(descriptors), 'caller input census order')
    return dict(caller=caller, executable=pin, raw_root=dispatch['actual_raw_root'],
                original_root_identity=dispatch['execution_identity'])


def binding_record(value):
    exact_record(value, 'schema scope parent_pid executable fds phase output job_identity '
        'job_bytes job_sha256 plan_sha256', 'actor FD binding')
    require(value['schema'] == DESCENDANT_SCHEMA and value['scope'] == DESCENDANT_SCOPE,
            'actor FD binding schema/scope')
    integer(value['parent_pid'], 1)
    executable_pin(value['executable'])
    require(type(value['fds']) is list and len(value['fds']) == 4
            and len({integer(fd, 3, 2**31-1) for fd in value['fds']}) == 4,
            'four distinct nonstdio actor descriptors required')
    ids = [value['executable']['identity']] + [fd_identity(value[key])
                                             for key in ('phase', 'output', 'job_identity')]
    require(len({(row['device'], row['inode']) for row in ids}) == 4, 'aliased actor input objects')
    integer(value['job_bytes'], 1, 448 * 1024)
    digest(value['job_sha256'])
    digest(value['plan_sha256'])
    return value


def live_original_identity(bundle, path, expected, directory):
    """Only called after a retained external claim proves this root is original.

    Archive copies use record continuity and actual retained bytes instead; their
    new inode numbers cannot authenticate the original runtime objects.
    """
    parts = bundle.path_parts(path.rstrip('/'))
    fd = os.dup(bundle.fd)
    try:
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                | (os.O_DIRECTORY if index + 1 < len(parts) or directory else 0), dir_fd=fd)
            os.close(fd)
            fd = child
        metadata = os.fstat(fd)
        fd_identity(expected)
        import stat
        require(dict(device=metadata.st_dev, inode=metadata.st_ino) == expected
                and (stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
                and metadata.st_uid == os.geteuid() and metadata.st_mode & 0o022 == 0
                and (metadata.st_nlink >= 2 if directory else metadata.st_nlink == 1),
                'original held actor object identity/private owner mismatch')
    finally:
        os.close(fd)


def descendant_actor_record(bundle, actor_path, phase_path, parent, child, job, *,
                            caller, executable, parent_pid, original_root_identity=None):
    """Strict cross-layer receipt/actual-byte continuity; not sandbox authority."""
    caller_record(caller)
    integer(parent_pid, 1)
    descendant_plan_types(job['plan'])
    exact_record(parent, 'schema kind binding inherited_nonstdio parent_restored_cloexec caller '
        'full_campaign_qualified', 'parent actor dispatch')
    exact_record(child, 'schema kind binding actual_executable inherited_nonstdio_after_quarantine '
        'job_raw_and_plan_checked input_lifetime scope general_process_sandbox full_campaign_qualified',
        'child actor verification')
    binding = binding_record(parent['binding'])
    v2_fd_census(parent['inherited_nonstdio'])
    v2_copy_types(parent['caller'], caller)
    require(parent['schema'] == child['schema'] == DESCENDANT_SCHEMA
            and parent['kind'] == 'parent-dispatch' and child['kind'] == 'child-verified'
            and parent['full_campaign_qualified'] is child['full_campaign_qualified'] is False
            and parent['parent_restored_cloexec'] is True and parent['caller'] == caller
            and parent['inherited_nonstdio'] == sorted(binding['fds'])
            and binding['parent_pid'] == caller['parent_pid'] == parent_pid
            and binding['executable'] == executable_pin(executable)
            and binding_record(child['binding']) == binding
            and executable_pin(child['actual_executable']) == executable
            and child['scope'] == DESCENDANT_SCOPE
            and child['inherited_nonstdio_after_quarantine'] == []
            and child['job_raw_and_plan_checked'] is True and child['general_process_sandbox'] is False
            and child['input_lifetime'] == 'process-lifetime-cloexec-quarantine-os-close-on-exit',
            'actor parent/child executable, exact binding or quarantine mismatch')
    raw = bundle.raw(actor_path + 'job.json', 448 * 1024)
    require(strict_json(raw) == job and len(raw) == binding['job_bytes']
            and sha(raw) == binding['job_sha256']
            and sha(json.dumps(job['plan'], sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False).encode()) == binding['plan_sha256']
            and job['binary_sha256'] == executable['sha256'], 'actor actual job/Plan raw SHA binding')
    live = original_root_identity is not None
    if live:
        require(fd_identity(original_root_identity)
                == dict(device=os.fstat(bundle.fd).st_dev, inode=os.fstat(bundle.fd).st_ino),
                'original held execution root changed; copied archive is not live inode authority')
        for path, identity, directory in [(phase_path, binding['phase'], True),
                (actor_path, binding['output'], True), (actor_path + 'job.json', binding['job_identity'], False)]:
            live_original_identity(bundle, path, identity, directory)
    return dict(schema=DESCENDANT_READBACK, recorded_binding_continuity=True, actual_job_bytes_checked=True,
        live_original_inode_checked=live, archive_inode_authentication=False,
        original_binding=binding, full_campaign_qualified=False, general_process_sandbox=False)




def descendant_plan_types(value):
    """Retain every original Plan value; reject JSON equality type aliases."""
    require(type(value) is dict and set(value) == set(PLAN), 'exact nested Plan fields required')
    require(all(type(value[key]) is type(expected) for key, expected in PLAN.items()),
            'nested Plan types must match original bool/int/string contract')
    return value


def descendant_job_location(job, raw_root, mode, worker):
    integer(worker, 0, ACTORS - 1)
    require(mode in MODES and integer(job['worker'], 0, ACTORS - 1) == worker and job['mode'] == mode,
            'cross-worker or cross-phase actor job replay')
    path = raw_root + '/' + mode + '/'
    require(job['output'] == path + f'actor-{worker:02}'
            and job['prefix_marker'] == path + 'prefix-start.json'
            and job['pressure_marker'] == path + 'pressure-start.json',
            'cross-worker or cross-phase actor job replay')


def validate_phase(bundle, top, mode, head, tree, binary, resources, *, version='v1', descendant_context=None):
    selected = profile(version)
    schema = selected['campaign_schema']
    require(version == 'v1' or selected['evidence_caps'] is not None,
            'v2 complete byte ledger not frozen')
    require(selected['execution_enabled'], 'v2 full I/O boundary not implemented')
    path = 'raw/' + mode + '/'
    value = bundle.json(path + 'report.json')
    require(value['schema'] == schema and value['kind'] == 'phase' and value['mode'] == mode
            and value['plan'] == PLAN and value['source_commit'] == head and value['source_tree'] == tree
            and value['binary_sha256'] == binary['sha256'], 'phase source/profile mismatch')
    facts = preparation(bundle.json('raw/' + top['preparation_file']), version=version)
    template = facts[4]['wire']
    group = '0::' + resources['cgroup'] + '\n'
    require(value['controller_cgroup'] == group, 'controller outside observed resource scope')
    if version == 'v2':
        v2_identity_types('phase', value)
        process_limits_v2(bundle.json('raw/process-limits.json'), 'campaign-parent', group, value['parent_pid'])
    epochs = {stage: (integer(value[stage + '_epoch_ns']), integer(value[stage + '_end_ns']))
              for stage in ('prefix', 'pressure')}
    require(all(end - epoch == PLAN[stage + '_seconds'] * SECOND for stage, (epoch, end) in epochs.items())
            and epochs['pressure'][0] >= epochs['prefix'][0], 'native original stage windows')
    known = flow(value['initial_flow'], settled=True)
    require(known['paid_cpu_debit_ns'] == 0, 'prefix did not begin at original empty owner')
    for key in ('post_prefix_flow', 'pressure_final_flow', 'final_flow'):
        current = flow(value[key], settled=key == 'final_flow')
        monotone(known, current)
        known = current
    initial = completion_work_observation(value['initial_work'])
    post = completion_work_observation(value['post_prefix_work'])
    final = completion_work_observation(value['final_work'])
    require(initial['retained_identities'] == initial['full_capacity_skips'] == initial['repeated_identity_skips'] == 0
            and post['retained_identities'] == final['retained_identities'] == CAPACITY,
            'real paid prefix did not fill same owner')
    children = value['children']
    require(len(children) == len(value['actor_readiness']) == ACTORS, 'all 24 actual children required')
    bodies, prefix_bodies, roots, identities, candidates, pids = [], set(), [], set(), {}, set()
    pressure_calls, all_attempts, retained_attempts = [], 0, 0
    construction_cpu, attempt_cpu, actor_cpu = 0, 0, 0
    attempt_costs, bindings = [], []
    if version == 'v2':
        require(descendant_context is not None, 'full v2 requires the new independently linked caller domain')
        descendant_plan_types(value['plan'])
    for worker, child in enumerate(children):
        actor_path = path + f'actor-{worker:02}/'
        job, ready, result = (bundle.json(actor_path + name) for name in ('job.json', 'ready.json', 'report.json'))
        finished = bundle.json(actor_path + 'prefix-finished.json')
        require(job['schema'] == selected['job_schema'] and job['worker'] == worker
                and job['plan'] == PLAN and job['mode'] == mode and job['template_packet'] == template
                and job['source_commit'] == head and job['source_tree'] == tree and job['binary_sha256'] == binary['sha256'],
                'actor job differs from frozen inputs')
        pid = integer(ready['pid'], 1)
        if version == 'v2':
            for kind, row in [('ready', ready), ('child', child), ('result', result), ('finished', finished)]:
                v2_identity_types(kind, row)
            for copied, original in [(child['ready'], ready), (value['actor_readiness'][worker], ready),
                    (child['report'], result), (child['prefix_finished'], finished)]:
                v2_copy_types(copied, original)
        require(pid not in pids and pid != value['parent_pid'] and ready['ppid'] == value['parent_pid']
                and child['pid'] == result['pid'] == finished['pid'] == pid
                and child['exit_success'] is True and child['parent_forced_kill'] is False
                and integer(child['reaped_ns']) >= integer(child['started_ns'])
                and child['ready'] == value['actor_readiness'][worker] == ready
                and child['report'] == result and child['prefix_finished'] == finished
                and ready['worker'] == result['worker'] == worker
                and ready['source_commit'] == head and ready['source_tree'] == tree
                and ready['binary_sha256'] == binary['sha256'] and ready['cgroup'] == result['cgroup'] == group,
                'missing/reused/wrong-source or unreaped actual actor')
        pids.add(pid)
        if version == 'v2':
            require(ready['schema'] == result['schema'] == finished['schema'] == schema,
                    'v2 actor metadata schema mismatch')
            process_limits_v2(bundle.json(actor_path + 'process-limits.json'), 'actor', group, pid)
            context = descendant_context
            descendant_job_location(job, context['raw_root'], mode, worker)
            bindings.append(descendant_actor_record(bundle, actor_path, path,
                child['execution_binding'], ready['execution_binding'], job,
                caller=context['caller'], executable=context['executable'], parent_pid=value['parent_pid'],
                original_root_identity=context['original_root_identity']))
        require(ready['setup_calls'] == 1 and ready['producer'] == 'prepared-generic', 'producer setup scope')
        for row, keys in ((ready, ('setup_cpu_ns', 'setup_wall_ns')),
                          (result, ('prefix_cpu_ns', 'pressure_cpu_ns', 'entire_actor_cpu_ns', 'entire_actor_wall_ns'))):
            for key in keys:
                integer(row[key], 1)
        require(finished['slots'] == result['prefix_slots'], 'prefix denominator changed after pressure')
        require(result['entire_actor_cpu_ns'] >= ready['setup_cpu_ns'] + result['prefix_cpu_ns'] + result['pressure_cpu_ns'],
                'nested actor CPU exceeds entire original owner')
        actor_cpu += result['entire_actor_cpu_ns']
        actor_construction_cpu = 0
        for stage in ('prefix', 'pressure'):
            slots = result[stage + '_slots']
            consumed = set()
            stage_bytes = 0
            expected = PLAN[stage + '_calls_per_actor'] if stage == 'prefix' or mode != 'honest-only' else 0
            require(len(slots) == expected, 'missing planned actor slots')
            for slot, offered in enumerate(slots):
                index = (slot + (192 if stage == 'pressure' else 0)) * ACTORS + worker
                if version == 'v2':
                    v2_identity_types('slot', offered)
                require(offered['slot'] == slot and offered['index'] == index, 'missing/relabelled offered slot')
                status = offered['status']
                require(status in ('called', 'construction-failed', 'deadline-unoffered', 'window-ended-unoffered'),
                        'unknown offered slot disposition')
                if status.endswith('unoffered'):
                    continue
                construction_name = f'{stage}/{index:05}-construction.json'
                if status == 'construction-failed' or stage == 'prefix' or mode == 'fresh-identities':
                    started = bundle.json(actor_path + f'{stage}/{index:05}-started.json')
                    if version == 'v2':
                        v2_identity_types('started', started)
                    require(started['index'] == index and started['template_header'] == template[:636], 'construction start missing/mutated')
                    material = bundle.json(actor_path + construction_name)
                    consumed.update((actor_path + construction_name, actor_path + f'{stage}/{index:05}-started.json'))
                    if version == 'v2':
                        v2_identity_types('construction', material)
                        v2_identity_types('construction_budget', material['evidence_budget'])
                        for trial in material['attempts']:
                            v2_identity_types('attempt', trial)
                        stage_bytes += bundle.files[actor_path + f'{stage}/{index:05}-started.json']['bytes']
                        limit_key = ('actor_prefix_bytes' if stage == 'prefix' else
                            'actor_fresh_pressure_bytes' if mode == 'fresh-identities' else 'actor_replay_pressure_bytes')
                        require(material['evidence_budget']['stage_limit_bytes'] == selected['evidence_caps'][limit_key]
                                and material['evidence_budget']['stage_used_before_bytes'] == stage_bytes,
                                'v2 stage counter omitted or relabelled prior actual files')
                        stage_bytes += bundle.files[actor_path + construction_name]['bytes']
                    packet, identity = construction(material, template, index, version=version)
                    all_attempts += len(material['attempts'])
                    retained_attempts += sum('proof' in trial for trial in material['attempts'])
                    construction_cpu += material['construction_thread_cpu_ns']
                    actor_construction_cpu += material['construction_thread_cpu_ns']
                    attempt_cpu += sum(trial['thread_cpu_ns'] for trial in material['attempts'])
                    attempt_costs.extend(trial['thread_cpu_ns'] for trial in material['attempts'])
                    if packet is not None:
                        require(identity not in identities, 'repeated complete work labelled fresh')
                        identities.add(identity)
                        candidates[actor_path + construction_name] = packet
                    if status == 'construction-failed':
                        require(packet is None, 'winning attempt hidden from offered denominator')
                        continue
                require(offered['file'] == f'{stage}/{index:05}-call.json', 'wrong actor call file')
                wrapper = bundle.json(actor_path + offered['file'])
                consumed.add(actor_path + offered['file'])
                if version == 'v2':
                    v2_identity_types('wrapper', wrapper)
                    stage_bytes += bundle.files[actor_path + offered['file']]['bytes']
                require(wrapper['schema'] == schema and wrapper['kind'] == 'call' and wrapper['stage'] == stage
                        and wrapper['worker'] == worker and wrapper['index'] == index, 'call wrapper identity')
                reference = actor_path + wrapper['construction_ref']
                require(reference in candidates and ((stage != 'prefix' and mode != 'fresh-identities')
                        or reference == actor_path + construction_name), 'replay/unrecorded material labelled fresh')
                packet = candidates[reference]
                body = H('public-request-body-v3', json.dumps(dict(op='submit', packet=packet.hex()), separators=(',', ':')).encode()).hex()
                row = wrapper['call']
                epoch, end = epochs[stage]
                require(call(row, epoch=epoch, end=end) == body
                        and wrapper['absolute_started_ns'] == epoch + row['started_ns']
                        and wrapper['absolute_ended_ns'] == epoch + row['ended_ns'] and row['status'] != 'ok',
                        'exact hostile body/actual call binding')
                bodies.append(body)
                if stage == 'prefix':
                    prefix_bodies.add(body)
                else:
                    require(mode != 'replay-only' or body in prefix_bodies, 'replay body was never offered in prefix')
                    pressure_calls.append((body, row))
                if row['status'] == 'refused' and row['response']['value'].get('error') == 'ROOT':
                    roots.append((body, row, stage))
            present = {name for name in bundle.files if name.startswith(actor_path + stage + '/')}
            require(present == consumed, 'omitted construction/call or failure relabelled unoffered')
        require(version == 'v1' or actor_construction_cpu <= result['prefix_cpu_ns'] + result['pressure_cpu_ns'],
                'recorded construction CPU exceeds actual actor stage CPU')
    honest = value['honest']
    submissions, history = honest['submissions'], honest['history']
    require(len(submissions) <= 128 and len(history) <= 64 and honest['verifier_errors'] == [], 'original honest caps/outcomes')
    succeeded = [row for row in submissions if row['status'] == 'ok' and row['returned_after_window'] is False]
    require([row['packet_index'] for row in succeeded] == list(range(21)), 'missing/duplicated real business block')
    for row in submissions:
        packet = facts[4 + integer(row['packet_index'], 0, 20)]
        body = H('public-request-body-v3', json.dumps(dict(op='submit', packet=packet['wire']), separators=(',', ':')).encode()).hex()
        require(call(row, epoch=epochs['pressure'][0], end=epochs['pressure'][1]) == body, 'honest submit bytes')
        if row['status'] == 'ok':
            require(row['response']['value']['block'] == row['response']['value']['active'] == packet['identity'], 'ACK packet binding')
        bodies.append(body)
    imported, after = [], facts[3]['identity']
    for row in history:
        body = call(row, epoch=epochs['pressure'][0], end=epochs['pressure'][1])
        request = row['request']
        expected_body = H('public-request-body-v3', json.dumps(dict(op='history', tip=request['tip'],
            after=request['after']), separators=(',', ':')).encode()).hex()
        require(request['op'] == 'history' and body == expected_body, 'history exact-body binding')
        bodies.append(body)
        if row['status'] == 'ok':
            page = row['response']['value']
            require(page['after'] == request['after'] == after and page['tip'] == request['tip']
                    and page['network'] == facts[0]['header']['network'].hex()
                    and page['parameters'] == facts[0]['header']['parameters'].hex()
                    and page['genesis'] == facts[0]['header']['parent'].hex()
                    and row['client_import']['succeeded'] is True, 'ordinary client import/context failed')
            integer(row['client_import']['thread_cpu_ns'], 1)
            integer(row['client_import']['wall_ns'], 1)
            for wire in page['packets']:
                require(len(imported) < 21 and wire == facts[4 + len(imported)]['wire'], 'independent client imported wrong bytes')
                after = facts[4 + len(imported)]['identity']
                imported.append(wire)
            require(page['next'] == after, 'client page continuation')
    require(len(imported) == 21 and honest['client_final_tip'] == value['final_tip'] == after, 'ordinary complete-page load/readback')
    if version == 'v2':
        v2_receiver_types(value['receiver_observation'], value['service_outcome']['Ok'])
    observed, accepted_roots = receiver(value['receiver_observation'], bodies, value['final_flow'], value['service_outcome']['Ok'])
    paid_prefix = {body for body in prefix_bodies if body in accepted_roots}
    require(len(paid_prefix) >= CAPACITY, 'offered prefix is not 4096 actually full-work-accepted identities')
    require(value['post_prefix_work']['full_capacity_skips'] >= len(paid_prefix) - CAPACITY, 'prefix capacity skip accounting')
    if mode == 'fresh-identities':
        require(any(body not in prefix_bodies and body in accepted_roots for body, _ in pressure_calls)
                and final['full_capacity_skips'] > post['full_capacity_skips'], 'no actual fresh identity after capacity')
    intervals, previous, count = [], None, 0
    sample_owner = value if version == 'v1' else v2_sample_owner(value)
    for raw in sample_lines(bundle, path, sample_owner, version=version):
        sample = strict_json(raw)
        if version == 'v2':
            v2_identity_types('sample', sample)
            v2_identity_types('meter', sample['meter'])
            v2_identity_types('freshness', sample['credit_freshness'])
            for key in ('meter', 'actual_flow', 'completion_work', 'credit_freshness'):
                v2_copy_types(sample['query_results'][key], {'Ok': sample[key]})
        require(sample['index'] == count and sample['schema'] == schema, 'missing sample denominator')
        for key in ('meter', 'actual_flow', 'completion_work', 'credit_freshness'):
            require(sample['query_results'][key] == {'Ok': sample[key]} and sample[key] is not None,
                    'unknown/contradictory original sample query')
        meter = sample['meter']
        require(meter['schema'] == 'public-v3-local-stored-cpu-budget-v1'
                and meter['burst_ns'] == BURST and meter['refill_ns_per_second'] == REFILL
                and meter['start_reserve_ns'] == RESERVE and meter['worker_limit'] == 2
                and meter['accounting_unavailable'] is False
                and type(meter['stored_credit_ns']) is int
                and type(meter['in_flight']) is int and 0 <= meter['in_flight'] <= 2,
                'changed or unavailable original scalar budget')
        queried = flow(sample['actual_flow'])
        completion_work_observation(sample['completion_work'])
        current = flow(sample['credit_freshness']['actual_flow'])
        if previous is not None:
            monotone(previous, queried)
        monotone(queried, current)
        previous, count = current, count + 1
        interval = depletion_interval(sample)
        if interval:
            intervals.append(interval)
    if version == 'v1':
        require(count == value['sample_count'] and count > 0, 'missing native credit samples')
    else:
        require(count == sample_owner['sample_count'] and count > 0, 'missing native credit samples')
    round_results = []
    require(len(honest['confirmations']) == 3, 'three actual ordinary rounds required')
    for index, row in enumerate(honest['confirmations']):
        if version == 'v2':
            v2_identity_types('round', row)
            v2_identity_types('confirmation', row['observation'])
        start, end = integer(row['started_ns']), integer(row['ended_ns'])
        require(row['round'] == index and row['scheduled_ns'] == (1 + 4 * index) * SECOND
                and row['scheduled_ns'] <= start < end < 30 * SECOND
                and row['confirmed_inside_pressure_window'] is True, 'original t=1/5/9 in-window rounds')
        observation = row['observation']
        included, tip = facts[4 + index * 7], facts[10 + index * 7]
        delta = sum(2**256 // (int.from_bytes(fact['header']['target'], 'big') + 1)
                    for fact in facts[5 + index * 7:11 + index * 7])
        required = 6 * (2**256 // (int.from_bytes(included['header']['target'], 'big') + 1))
        require(observation['confirmed'] is True and observation['reorged'] is False
                and observation['finalized'] is observation['execution_authority'] is False
                and observation['depth'] == 6 and observation['observed_height'] - observation['included_height'] == 6
                and observation['included_height'] == included['header']['height']
                and observation['observed_height'] == observation['active_generation'] == tip['header']['height']
                and observation['included_block'] == row['included_block'] == included['identity']
                and observation['observed_tip'] == row['tip'] == tip['identity']
                and observation['transaction'] == row['transaction'] == H('tx-id', included['transactions'][0]).hex()
                and int(digest(observation['work_delta'], 128), 16) == delta >= required
                and int(digest(observation['required_work_delta'], 128), 16) == required,
                'original signed depth-six confirmation binding')
        numeric = coverage(intervals, epochs['pressure'][0] + start, epochs['pressure'][0] + end)
        if mode != 'honest-only':
            require(numeric['covered_ns'] * 10 >= numeric['round_ns'] * 9
                    and numeric['max_unproven_gap_ns'] <= SECOND, 'insufficient conservatively proven pressure coverage')
            require(any(stage == 'pressure' and start <= call_row['started_ns'] < call_row['ended_ns'] <= end
                        and body in accepted_roots for body, call_row, stage in roots), 'round lacks exact-body paid ROOT response')
            before, later = row['receiver_hostile_before'], row['receiver_hostile_after']
            require(all(integer(later[key]) > integer(before[key]) for key in
                        ('accepted_work_admission_refusals', 'admission_cpu_ns')), 'missing actual admission rejection progress')
        round_results.append(numeric)
    if version == 'v2':
        records = [row['original_binding'] for row in bindings]
        require(len({tuple(row['fds'][:2]) for row in records}) == 1
                and len({(row['phase']['device'], row['phase']['inode']) for row in records}) == 1
                and len({fd for row in records for fd in row['fds'][2:]}) == 2 * ACTORS
                and len({(row[key]['device'], row[key]['inode'])
                         for row in records for key in ('output', 'job_identity')}) == 2 * ACTORS,
                'reused actor descriptors/objects or inconsistent shared phase')
    hostile_ids = {H('block', packet[:318], packet[-32:]).hex() for packet in candidates.values()}
    require({entry['packet_id'] for entry in value['hostile_candidates']} == hostile_ids
            and all(entry['live_absent'] is entry['cold_absent'] is True for entry in value['hostile_candidates'])
            and value['cold_equal'] is True, 'missing live/cold hostile observations')
    for name in ('receiver', 'independent-client'):
        durable_history(bundle, path + name, facts, hostile_ids)
    return dict(mode=mode, paid_prefix_unique=len(paid_prefix), actors=len(pids),
        planned_actor_slots=ACTORS * (192 + (0 if mode == 'honest-only' else 288)),
        actual_actor_calls=len(bodies) - len(submissions) - len(history),
        failed_calls=sum(count - observed[body] for body, count in Counter(bodies).items()),
        rounds=round_results, full_scalar_attempts_checked=all_attempts,
        actual_complete_attempt_bytes_retained=retained_attempts,
        all_completed_attempt_bytes_checked=version == 'v2' and all_attempts == retained_attempts and all_attempts > 0,
        recorded_attempt_thread_cpu_ns=attempt_cpu,
        recorded_minimum_attempt_thread_cpu_ns=min(attempt_costs) if attempt_costs else None,
        recorded_maximum_attempt_thread_cpu_ns=max(attempt_costs) if attempt_costs else None,
        recorded_construction_thread_cpu_ns=construction_cpu,
        recorded_entire_actor_thread_cpu_ns=actor_cpu,
        cost_clock_scope='Producer per-prove thread CPU, nested construction CPU and entire actor CPU are reported separately; reader replay CPU is excluded',
        acquisition_cost_qualified=False,
        **(dict(descendant_fd_binding=dict(schema=DESCENDANT_READBACK, actors=len(bindings),
            executable_fd=bindings[0]['original_binding']['fds'][0],
            live_original_inode_checked=all(row['live_original_inode_checked'] for row in bindings),
            full_campaign_qualified=False)) if bindings else {}))


class IdentityBundle(Bundle):
    """The original no-follow FD reader with explicit larger supplement bounds."""
    def __init__(self, root, expected, *, version='v1', directory_fd=None):
        self.fd = (os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                   if directory_fd is None else os.dup(directory_fd))
        try:
            raw = self._read('artifact-files.json', (31 if version == 'v2' else 64) * 1024 * 1024)
            self.manifest_bytes = len(raw)
            require(sha(raw) == digest(expected), 'artifact file-list SHA256 mismatch')
            value = strict_json(raw)
            require(value['schema'] == profile(version)['inventory_schema']
                    and type(value['files']) is list and 0 < len(value['files']) <= 200_000,
                    'bounded complete artifact inventory')
            self.files, total = {}, len(raw) if version == 'v2' else 0
            for row in value['files']:
                name = '/'.join(self.path_parts(row['path']))
                require(name not in self.files and name != 'artifact-files.json', 'duplicate inventory path')
                size = integer(row['bytes'], 0, 256 * 1024 * 1024)
                digest(row['sha256'])
                total += size
                require(total <= 8 * 1024**3, 'bounded artifact total')
                self.files[name] = row
            self.total_bytes = total
            for name, row in self.files.items():
                self._read(name, 256 * 1024 * 1024, retain=False, expected=row)
            observed = set()
            if version == 'v2':
                observed = set(held_file_names(self.fd)) - {'artifact-files.json'}
            else:
                for path in Path(root).rglob('*'):
                    require(not path.is_symlink(), 'symlink artifact outside manifest')
                    relative = path.relative_to(root).as_posix()
                    if path.is_file() and relative != 'artifact-files.json':
                        observed.add(relative)
                        require(len(observed) <= 200_000, 'bounded observed artifact count')
            require(observed == set(self.files), 'complete artifact inventory mismatch')
        except BaseException:
            os.close(self.fd)
            raise


def evidence_ledger_v2(files, manifest_bytes, caps, *, strict=True, preparation_only=False):
    """Charge every pinned file once; a frozen declaration is not enforcement."""
    require(caps == profile('v2')['evidence_caps'] and caps is not None, 'unfrozen or changed v2 ledger')
    groups, totals, forbidden = Counter(), Counter(), []
    rules = caps['namespace_rules']
    root_bytes = integer(manifest_bytes, 0, caps['inventory_bytes'])
    totals['root'] = root_bytes
    groups['inventory'] = root_bytes
    limit_keys = dict(node_database='node_database_total_bytes', node_metadata='node_metadata_total_bytes',
        samples='sample_total_bytes', binary='frozen_binary_bytes', phase='phase_report_total_bytes',
        actor_metadata='actor_metadata_total_bytes', actor_log='actor_log_total_bytes',
        outer='outer_outputs_total_bytes', preparation='preparation_bytes', root='root_outputs_total_bytes')
    for name, pin in files.items():
        require(name != 'artifact-files.json', 'inventory cannot recursively list itself')
        parts = Bundle.path_parts(name)
        size = integer(pin['bytes'])
        leaf = parts[-1]
        failed = any(fnmatch.fnmatchcase(leaf, pattern) for pattern in rules['strict_success_forbidden'])
        if failed or leaf == 'outer-terminal.json':
            forbidden.append(name)
        canonical = re.sub(r'\.(?:partial|tmp)\.json$', '.json', leaf)
        group, limit, kind = None, None, None
        binary = ('frozen/' if not preparation_only else '') + TARGET + '.bin'
        if name in (binary, binary + '.partial.json'):
            kind, group, limit = 'binary', 'binary', caps['frozen_binary_bytes']
        elif name == 'artifact-files.json.partial.json':
            kind, group, limit = 'root', 'inventory', caps['inventory_bytes']
        elif name == 'raw/preparation.json':
            kind, group, limit = 'preparation', 'preparation', caps['preparation_bytes']
        elif parts[0] == 'raw':
            relative = '/'.join(parts[1:])
            node = next((root for root in caps['node_roots'] if relative.startswith(root + '/')), None)
            if node is not None:
                require(relative == node + '/' + leaf and leaf in caps['node_file_names'],
                        'unknown nested or unowned Node artifact: ' + name)
                kind = 'node_database' if leaf.startswith('native.sqlite') else 'node_metadata'
                group, limit = kind, caps['node_file_names'][leaf]
            elif len(parts) == 2 and canonical in rules['raw_root_json']:
                kind, group, limit = 'root', 'raw_root', caps['raw_root_outputs_bytes']
            elif len(parts) >= 3 and parts[1] in MODES:
                mode = parts[1]
                if len(parts) == 3 and canonical in rules['phase_metadata_json']:
                    kind, group, limit = 'phase', mode + '/phase', caps['phase_report_bytes_each']
                elif len(parts) == 3 and re.fullmatch(r'samples-[0-9]{2}\.jsonl', leaf):
                    require(int(leaf[8:10]) < caps['sample_chunks_per_phase'], 'sample chunk count cap')
                    kind, group, limit = 'samples', mode + '/samples', caps['sample_chunk_bytes']
                elif len(parts) >= 4 and re.fullmatch(r'actor-(?:0[0-9]|1[0-9]|2[0-3])', parts[2]):
                    actor = mode + '/' + parts[2]
                    if len(parts) == 4 and canonical in rules['actor_metadata_json']:
                        kind, group, limit = 'actor_metadata', actor + '/metadata', caps['actor_metadata_bytes_each']
                    elif len(parts) == 4 and leaf == 'actor.log':
                        kind, group, limit = 'actor_log', actor + '/log', caps['actor_log_bytes_each']
                    elif len(parts) == 5 and parts[3] in ('prefix', 'pressure'):
                        require(parts[3] != 'pressure' or mode != 'honest-only', 'honest-only pressure is not empty')
                        require(re.fullmatch(r'[0-9]{5}-(started|construction|call)\.json', canonical),
                                'unknown actor stage artifact: ' + name)
                        stage = parts[3]
                        kind, group = 'actor_stage', actor + '/' + stage
                        limit = caps['construction_bytes'] if canonical.endswith('-construction.json') else 8192
                require(kind is not None, 'unowned phase artifact: ' + name)
            else:
                require(False, 'unowned raw artifact: ' + name)
        else:
            kind, group, limit = 'outer', 'outer', caps['parent_file_bytes']
        require(size <= limit, 'v2 per-file byte cap: ' + name)
        groups[group] += size
        totals[kind] += size
    for group, size in groups.items():
        if group.endswith('/prefix'):
            limit = caps['actor_prefix_bytes']
        elif group.endswith('/pressure'):
            limit = caps['actor_fresh_pressure_bytes'] if group.startswith('fresh-identities/') else caps['actor_replay_pressure_bytes']
        elif group.endswith('/metadata'):
            limit = caps['actor_metadata_bytes_each']
        elif group.endswith('/log'):
            limit = caps['actor_log_bytes_each']
        elif group.endswith('/phase'):
            limit = caps['phase_report_bytes_each']
        elif group.endswith('/samples'):
            limit = caps['sample_chunks_per_phase'] * caps['sample_chunk_bytes']
        elif group == 'raw_root':
            limit = caps['raw_root_outputs_bytes']
        elif group == 'inventory':
            limit = caps['inventory_bytes']
        else:
            limit = caps[limit_keys[group]]
        require(size <= limit, 'v2 group byte cap: ' + group)
    for kind, key in limit_keys.items():
        require(totals[kind] <= caps[key], 'v2 total bucket cap: ' + kind)
    total = sum(totals.values())
    require(total <= caps['reserved_total_bytes'] <= caps['artifact_total_bytes']
            and caps['reserved_total_bytes'] + caps['unassigned_bytes'] == 8 * 1024**3,
            'original eight-GiB artifact ledger')
    if strict:
        require(not forbidden, 'retained partial, cap terminal or initializing marker prevents qualification')
        require(all('raw/' + node + '/native.sqlite' in files for node in caps['node_roots']),
                'missing one of seven actual Node databases')
        require(all('raw/' + node + '/owner.lock' in files for node in caps['node_roots']),
                'missing one of seven actual Node lock files')
    return dict(total_bytes=total, inventory_bytes=manifest_bytes, bucket_bytes=dict(totals),
        group_bytes=dict(groups), retained_failure_files=forbidden,
        original_artifact_limit_bytes=8 * 1024**3, complete_route_enforcement_inferred=False)


def linked_evidence_ledger_v2(execution, manifest_bytes, prepared, claims, caps, *, strict=True):
    """Three physical path domains, never deduplicated by digest or inode.

    Each mapping contains its own actual files; inventories are real files too.
    The execution's self-inventory is supplied separately. No virtual namespace
    may exist as a real component in either source directory.
    """
    require(caps == profile('v2')['evidence_caps'], 'unchanged original linked byte caps required')
    for files in (execution, prepared):
        for name in files:
            require(not any(part in VIRTUAL_INPUT_NAMESPACES for part in Bundle.path_parts(name)),
                    'physical virtual namespace shadow')
    require(not any(Bundle.path_parts(name)[0] == 'raw' for name in prepared), 'native input-prepared artifacts forbidden')
    require('artifact-files.json' in prepared and 'frozen/artifact-files.json' in execution,
            'both real input inventory and frozen inventory copy required')
    source_inventory = prepared['artifact-files.json']['bytes']
    frozen_inventory = execution['frozen/artifact-files.json']['bytes']
    require(source_inventory == frozen_inventory
            and prepared['artifact-files.json']['sha256'] == execution['frozen/artifact-files.json']['sha256'],
            'frozen inventory is not the actual original inventory')
    allowed_claims = {'owner.lock':0, 'claim.json':CLAIM_DOCUMENT_BYTES,
        'claim.json.partial.json':CLAIM_DOCUMENT_BYTES, 'terminal.json':CLAIM_DOCUMENT_BYTES,
        'terminal.json.partial.json':CLAIM_DOCUMENT_BYTES}
    for name, pin in claims.items():
        require(name in allowed_claims and integer(pin['bytes']) <= allowed_claims[name],
                'unowned or oversized external claim file')
    if strict:
        require(set(claims) == {'owner.lock', 'claim.json', 'terminal.json'}, 'incomplete or failed one-shot claim')
    views = [
        evidence_ledger_v2({n:p for n,p in execution.items() if n != 'frozen/artifact-files.json'},
                           manifest_bytes + frozen_inventory, caps, strict=strict),
        evidence_ledger_v2({n:p for n,p in prepared.items() if n != 'artifact-files.json'},
                           source_inventory, caps, strict=False, preparation_only=True),
        evidence_ledger_v2({'external-claim/'+n:p for n,p in claims.items()}, 0, caps, strict=False),
    ]
    totals, groups = Counter(), Counter()
    for view in views:
        totals.update(view['bucket_bytes'])
        groups.update(view['group_bytes'])
    limits = dict(node_database='node_database_total_bytes', node_metadata='node_metadata_total_bytes',
        samples='sample_total_bytes', binary='frozen_binary_bytes', phase='phase_report_total_bytes',
        actor_metadata='actor_metadata_total_bytes', actor_log='actor_log_total_bytes',
        outer='outer_outputs_total_bytes', preparation='preparation_bytes', root='root_outputs_total_bytes')
    for bucket, key in limits.items():
        require(totals[bucket] <= caps[key], 'linked actual path bucket cap: '+bucket)
    require(groups['inventory'] <= caps['inventory_bytes'] and groups['raw_root'] <= caps['raw_root_outputs_bytes'],
            'linked original inventory31/rawroot1 caps')
    total = sum(totals.values())
    require(total <= caps['reserved_total_bytes'] <= caps['artifact_total_bytes'] == 8*1024**3,
            'linked original eight-GiB aggregate')
    return dict(schema='pon-identity-linked-actual-path-ledger-v1', total_bytes=total,
        bucket_bytes=dict(totals), group_bytes=dict(groups), domain_file_counts=dict(
            execution=len(execution)+1, input_prepared=len(prepared), external_claim=len(claims)),
        virtual_namespaces=list(VIRTUAL_INPUT_NAMESPACES), sha_or_inode_deduplication=False,
        claim_pair_reservation_bytes=CLAIM_PAIR_RESERVATION_BYTES, qualification=False,
        complete_route_enforcement_inferred=False)


class _HeldClaimReader(Bundle):
    """Borrow a caller-held FD; exact claim membership is checked separately."""
    def __init__(self, directory_fd):
        self.fd = directory_fd


def claim_inventory(source_input, *, directory_fd=None):
    """Count every actual fixed-namespace file, including failed partials."""
    owned = directory_fd is None
    fd = (os.open(claim_basename(source_input), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                  dir_fd=source_input.parent_fd) if owned else directory_fd)
    try:
        allowed = {'owner.lock':0, 'claim.json':CLAIM_DOCUMENT_BYTES, 'claim.json.partial.json':CLAIM_DOCUMENT_BYTES,
                   'terminal.json':CLAIM_DOCUMENT_BYTES, 'terminal.json.partial.json':CLAIM_DOCUMENT_BYTES}
        names = os.listdir(fd)
        require(len(names) <= len(allowed) and all(name in allowed for name in names), 'unknown external claim file')
        raw, pins = {}, {}
        for name in names:
            data = _HeldClaimReader(fd)._read(name, allowed[name])
            raw[name], pins[name] = data, dict(bytes=len(data), sha256=sha(data))
        return raw, pins
    finally:
        if owned: os.close(fd)


def validate_prepared_claim_link(bundle, source_input, *, native=True, cwd_directory_fd=None):
    """Read both retained bundles plus the original held sibling claim domain."""
    source_input.recheck()
    patterns = profile('v2')['evidence_caps']['namespace_rules']['strict_success_forbidden']
    require(not any(Path(name).name == 'outer-terminal.json' or any(fnmatch.fnmatchcase(Path(name).name, p)
                    for p in patterns) for files in (bundle.files, source_input.bundle.files) for name in files),
            'failed/partial linked artifact cannot qualify even as a component')
    link = bundle.json('prepared-claim-link.json')
    require(link['schema'] == LINK_SCHEMA and link['domain'] == CLAIM_DOMAIN and link['qualification'] is False
            and link['binding'] == source_input.binding
            and link['input_prepared'] == dict(canonical_root=str(source_input.root),
                prepared_sha256=source_input.binding['prepared_sha256'],
                inventory_sha256=source_input.binding['inventory_sha256']), 'unbound original preparation link')
    claim_root = source_input.root.with_name(claim_basename(source_input))
    require(link['claim']['canonical_root'] == str(claim_root) and link['claim']['path'] == 'claim.json'
            and link['observed_copy'] == 'claim-observed.json'
            and link['terminal_copy'] == 'claim-terminal-observed.json', 'noncanonical claim namespace')
    claim_fd = os.open(claim_basename(source_input), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                       dir_fd=source_input.parent_fd)
    try:
        raw, pins = claim_inventory(source_input, directory_fd=claim_fd)
        require(set(raw) == {'owner.lock', 'claim.json', 'terminal.json'}, 'failed/partial/existing claim state')
        claim, terminal = strict_json(raw['claim.json']), strict_json(raw['terminal.json'])
        require(claim['schema'] == CLAIM_SCHEMA and claim['domain'] == CLAIM_DOMAIN
                and claim['qualification'] is False and claim['administrator_deletion_resistance'] is False
                and claim['binding'] == source_input.binding and claim['execution_root'] == link['execution_root']
                and claim['execution_identity'] == dict(device=os.fstat(bundle.fd).st_dev, inode=os.fstat(bundle.fd).st_ino)
                and claim['claim_identity'] == dict(device=os.fstat(claim_fd).st_dev, inode=os.fstat(claim_fd).st_ino),
                'claim root/file identity or binding changed')
        require(link['claim'] == dict(canonical_root=str(claim_root), path='claim.json', **pins['claim.json'])
                and bundle.raw('claim-observed.json') == raw['claim.json'], 'external claim and observed bytes differ')
        require(terminal['schema'] == CLAIM_TERMINAL_SCHEMA and terminal['domain'] == CLAIM_DOMAIN
                and terminal['qualification'] is False and terminal['binding'] == source_input.binding
                and terminal['claim_sha256'] == pins['claim.json']['sha256']
                and terminal['dispatch_attempted'] is terminal['child_owner_called'] is terminal['child_exit_observed'] is True
                and terminal['native_owner_success'] is True and terminal['returncode'] == 0 and terminal['error'] is None
                and bundle.raw('claim-terminal-observed.json') == raw['terminal.json'], 'unclosed claimed child owner')
        step = bundle.json('campaign.step.json')
        require(step['returncode'] == 0 and step['complete_success'] is True and step['error'] is None
                and step['stdout_truncated'] is step['stderr_truncated'] is False
                and step['command'][0] == str(Path(link['execution_root'])/'frozen'/(TARGET+'.bin'))
                and step['elapsed_ns'] <= source_input.value['collector_seconds'] * SECOND,
                'claimed process step failed or changed')
        dispatch = step['fd_dispatch']
        descriptors = [integer(dispatch[key], 0, 2**31-1)
                       for key in ('executable_fd','execution_directory_fd','cwd_directory_fd')]
        executable, output, cwd = descriptors
        v2_fd_census(dispatch['inherited_fds'], minimum=0)
        require(len(set(descriptors)) == 3 and dispatch['schema'] == FD_DISPATCH_SCHEMA
                and dispatch['qualification'] is False
                and dispatch['native_descendant_path_binding_complete'] is False
                and dispatch['inherited_fds'] == sorted(descriptors)
                and dispatch['execution_identity'] == claim['execution_identity']
                and dispatch['executable_sha256'] == source_input.binding['binary_sha256']
                and dispatch['executable_bytes'] == source_input.binding['binary_bytes']
                and dispatch['actual_executable'] == '/proc/self/fd/'+str(executable)
                and dispatch['actual_cwd'] == '/proc/self/fd/'+str(cwd)
                and dispatch['actual_raw_root'] == '/proc/self/fd/'+str(output)+'/raw',
                'first-exec FD dispatch binding changed or overstated')
        from run_pon_identity_churn import identity, held_directory
        cwd_fd = held_directory(ROOT) if cwd_directory_fd is None else os.dup(cwd_directory_fd)
        try:
            require(dispatch['cwd_identity'] == identity(os.fstat(cwd_fd)), 'first-exec held source cwd changed')
        finally:
            os.close(cwd_fd)
        require(dispatch['executable_identity'] == identity(os.stat('frozen/'+TARGET+'.bin',
                    dir_fd=bundle.fd, follow_symlinks=False)), 'claimed frozen executable inode changed')
        expected_command = [step['command'][0]]
        for argument in step['command'][1:]:
            path = Path(argument)
            expected_command.append('/proc/self/fd/'+str(output)+'/'+path.relative_to(link['execution_root']).as_posix()
                if path.is_absolute() and path.is_relative_to(link['execution_root']) else argument)
        require(dispatch['actual_command'] == expected_command, 'first-exec actual argument mapping changed')
        for stream, limit in [('stdout',16*1024**2),('stderr',4*1024**2)]:
            data = bundle.raw(step[stream], limit)
            require(len(data) == step[stream+'_bytes'] and sha(data) == step[stream+'_sha256'], 'claimed stream changed')
        for name, pin in source_input.bundle.files.items():
            require(bundle.files['frozen/'+name]['bytes'] == pin['bytes']
                    and bundle.files['frozen/'+name]['sha256'] == pin['sha256'], 'frozen input file differs')
        inventory = source_input.bundle._read('artifact-files.json', 31*1024**2)
        prepared_files = dict(source_input.bundle.files,
            **{'artifact-files.json':dict(bytes=len(inventory), sha256=sha(inventory))})
        ledger = linked_evidence_ledger_v2(bundle.files, bundle.manifest_bytes, prepared_files, pins,
                                          profile('v2')['evidence_caps'], strict=native)
        return dict(schema='pon-identity-one-shot-claim-readback-v1', component_claim_readback_pass=True,
            native_campaign_required=native, full_campaign_qualified=False, evidence_ledger=ledger,
            first_exec_output_fd_binding_readback=True, native_descendant_path_binding_complete=False,
            physical_enospc_durability_qualified=False, administrator_deletion_resistance=False)
    finally:
        os.close(claim_fd)


class ObservedControlBundle(Bundle):
    """Local component observation pins; no prior host or exact-source custody."""
    def __init__(self, root):
        self.root = Path(root)
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.files, self.total_bytes = {}, 0
            for path in sorted(Path(root).rglob('*')):
                require(not path.is_symlink(), 'symlink in observed control')
                if path.is_file():
                    name = '/'.join(self.path_parts(path.relative_to(root).as_posix()))
                    raw = self._read(name, 256 * 1024**2)
                    self.files[name] = dict(path=name, bytes=len(raw), sha256=sha(raw))
                    self.total_bytes += len(raw)
                    require(self.total_bytes <= 8 * 1024**3 and len(self.files) <= 4096,
                            'bounded observed component control')
            require(self.files, 'empty observed control')
        except BaseException:
            os.close(self.fd)
            raise

    def recheck(self):
        observed = set()
        for path in self.root.rglob('*'):
            require(not path.is_symlink(), 'symlink added to observed control')
            if path.is_file():
                observed.add(path.relative_to(self.root).as_posix())
        require(observed == set(self.files), 'observed control file inventory changed')
        for name, pin in self.files.items():
            self._read(name, 256 * 1024**2, retain=False, expected=pin)


def read_acquisition_v2(folder):
    """Independently read a small actual control; never promote it to a campaign."""
    bundle = ObservedControlBundle(folder)
    try:
        pin, result = bundle.json('input-pin.json'), bundle.json('result.json')
        require(pin['schema'] == 'pn1-v2-short-acquisition-input-v1'
                and pin['source_overlay'] is True and pin['exact_source_qualified'] is False
                and pin['full_campaign_qualified'] is False
                and pin['original_two_actor_failure_closed'] is False,
                'small control source/scope changed')
        digest(pin['head'], 40)
        require(result['schema'] == 'pn1-v2-short-acquisition-result-v1'
                and result['native_complete_success'] is True and result['binary_unchanged'] is True
                and result['full_campaign_qualified'] is result['merge_ready'] is False
                and set(result['source_overlay_unchanged']) == set(pin['files'])
                and all(value is True for value in result['source_overlay_unchanged'].values()),
                'failed small native acquisition')
        binary = pin['binary']
        require(bundle.files[binary['file']]['sha256'] == digest(binary['sha256'])
                and bundle.files[binary['file']]['bytes'] == binary['bytes'], 'actual control binary changed')
        before, after = bundle.json('resource-before.json'), bundle.json('resource-after.json')
        require(resource(before) == resource(after) and before['cgroup'] == after['cgroup'],
                'small control resource scope changed')
        step = bundle.json('native.step.json')
        selector = 'three_real_full_attempt_receipts_and_preprove_cap_v2_control'
        require(pin['selector'] == selector and step['command'] == [str(Path(folder).resolve() / binary['file']),
                '--exact', selector, '--ignored', '--nocapture', '--test-threads=1']
                and step['returncode'] == 0 and step['complete_success'] is True and step['error'] is None
                and step['outer_stage_timeout_seconds'] == 180 and 0 < integer(step['elapsed_ns']) <= 180 * SECOND,
                'wrong/failed short native selector')
        for stream in ('stdout', 'stderr'):
            raw = bundle.raw(step[stream])
            require(step[stream + '_truncated'] is False and len(raw) == step[stream + '_bytes']
                    and sha(raw) == step[stream + '_sha256'], 'actual short-control stream changed')
        stdout = bundle.raw(step['stdout']).decode()
        require(len(re.findall(r'^running 1 test$', stdout, re.M)) == 1
                and re.search(r'^test ' + selector + r' \.\.\. ok$', stdout, re.M)
                and len(re.findall(r'^test result:', stdout, re.M)) == 1
                and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', stdout, re.M),
                'short control did not run exactly one real test')
        plan, seed, report = (bundle.json('raw/' + name) for name in ('plan.json', 'seed.json', 'report.json'))
        schema = profile('v2')['construction_schema']
        require(plan['schema'] == seed['schema'] == report['schema'] == schema
                and plan['requested'] == report['requested'] == 3 and plan['actors'] == 1
                and plan['outer_seconds'] == 30 and plan['search_attempt_limit'] == 4096
                and plan['setup_calls'] == 1 and plan['producer'] == 'prepared-generic'
                and report['component_pass'] is True and report['error'] is None
                and report['full_v2_io_boundary_implemented'] is False
                and report['honest_service_qualified'] is report['capacity_crossed'] is False,
                'actual acquisition is not the three-proof component profile')
        require(identify_observation(dict(schema='public-protected-resource-policy-observation-v1',
                transport_profile='public-protected-development-v3', policy_id=plan['profile'],
                ticket_bits=8, lifetime_ms=2000))['resource_revision'] == 'r13',
                'actual acquisition policy is not the original r13/8-bit/2000ms profile')
        flags(report)
        actual = flow(report['actual_flow'], settled=True)
        work = completion_work_observation(report['completion_work'])
        initial = completion_work_observation(plan['initial'])
        require(initial['retained_identities'] == initial['full_capacity_skips'] == initial['repeated_identity_skips'] == 0
                and work['retained_identities'] == 3 and work['full_capacity_skips'] == work['repeated_identity_skips'] == 0,
                'small control registry was not three actual identities')
        stage_used, bodies, rows, identities = 0, [], [], set()
        for index in range(3):
            base = 'raw/' + f'{index:05}'
            started = bundle.json(base + '-started.json')
            require(started['schema'] == schema and started['index'] == index
                    and started['template_header'] == seed['template'][:636], 'actual start/header changed')
            stage_used += bundle.files[base + '-started.json']['bytes']
            row = bundle.json(base + '-construction.json')
            require(row['evidence_budget']['stage_limit_bytes'] == 64 * 1024**2
                    and row['evidence_budget']['stage_used_before_bytes'] == stage_used,
                    'actual stage byte counter omitted a previous file')
            packet, identity = construction(row, seed['template'], index, version='v2')
            require(packet is not None and identity not in identities, 'missing or reused actual winner')
            identities.add(identity)
            body = H('public-request-body-v3', json.dumps(dict(op='submit', packet=packet.hex()), separators=(',', ':')).encode()).hex()
            offered = bundle.json(base + '-call.json')
            require(offered == report['calls'][index] and offered['schema'] == schema and offered['index'] == index
                    and offered['body_digest'] == body and offered['completion_identity'] == identity
                    and offered['packet_id'] == H('block', packet[:318], packet[-32:]).hex()
                    and offered['error'] is None and offered['reply']['ok'] is False
                    and offered['reply']['value']['error'] == 'ROOT', 'actual paid ROOT call bytes changed')
            integer(offered['client_thread_cpu_ns'], 1)
            integer(offered['wall_ns'], 1)
            require(completion_work_observation(offered['occupancy'])['retained_identities'] == index + 1,
                    'actual per-call identity promotion missing')
            stage_used += sum(bundle.files[base + suffix]['bytes'] for suffix in ('-construction.json', '-call.json'))
            rows.append(row)
            bodies.append(body)
        require(report['evidence_budget'] == dict(limit_bytes=64 * 1024**2, used_bytes=stage_used,
                cap_reached=False, poisoned=False), 'actual stage ledger differs from retained file bytes')
        observed, roots = receiver(report['receiver_observation'], bodies, report['actual_flow'], report['metrics'])
        require(sum(observed.values()) == len(report['calls']) == len(roots) == 3, 'not three actual paid ROOT observations')
        cap = bundle.json('raw/cap-negative/00003-construction.json')
        cap_started = bundle.json('raw/cap-negative/00003-started.json')
        cap_budget = cap['evidence_budget']
        require(cap['schema'] == cap_started['schema'] == schema and cap['index'] == cap_started['index'] == 3
                and cap['error'] == 'evidence-cap' and cap['attempts'] == []
                and cap['packet'] is cap['completion_identity'] is None
                and cap_budget['cap_reached'] is True and cap_budget['poisoned'] is False
                and cap_budget['stage_limit_bytes'] == 16384 and cap_budget['attempt_serialized_bytes'] == 0
                and cap_budget['stage_used_before_bytes'] == bundle.files['raw/cap-negative/00003-started.json']['bytes']
                and cap_budget['frame_limit_bytes'] < cap_budget['attempt_reservation_bytes'] + cap_budget['frame_reservation_bytes']
                and {name for name in bundle.files if name.startswith('raw/cap-negative/')} == {
                    'raw/cap-negative/00003-started.json', 'raw/cap-negative/00003-construction.json'},
                'tiny cap did not stop before prove with a retained terminal')
        rejected = False
        try:
            construction(cap, seed['template'], 3, version='v2')
        except ValueError:
            rejected = True
        require(rejected, 'cap terminal was promoted to completed work')
        bundle.recheck()
        attempts = [trial for row in rows for trial in row['attempts']]
        return dict(schema='pn1-v2-short-acquisition-independent-readback-v1', component_readback_pass=True,
            source_head=pin['head'], source_overlay=True, source_overlay_pin=pin['files'], binary_sha256=binary['sha256'],
            resource_envelope_unchanged=True, cgroup=before['cgroup'], cpu_max=before['limits'][0]['cpu.max'],
            memory_max=before['limits'][0]['memory.max'], nice=before['nice'],
            raw_files=bundle.files, raw_total_bytes=bundle.total_bytes,
            actual_fresh_paid_identities=3, all_attempts_checked=len(attempts),
            misses_checked=sum(trial['target_hit'] is False for trial in attempts),
            full_raw_proof_bytes_checked=len(attempts) * 49188,
            recorded_attempt_cpu_ns=[trial['thread_cpu_ns'] for trial in attempts],
            recorded_minimum_attempt_cpu_ns=min(trial['thread_cpu_ns'] for trial in attempts),
            stage_bytes_independently_checked=stage_used, paid_cpu_ns=actual['paid_cpu_debit_ns'],
            tiny_cap_zero_attempts=True, tiny_cap_strictly_rejected=True,
            exact_commit_qualified=False, full_campaign_qualified=False, finite_service_measurement_complete=False,
            original_two_actor_failure_closed=False, global_minimum_work_cost_proven=False,
            hardware_fairness_qualified=False, public_network_ready=False, merge_ready=False,
            scope='Actual debug/source-overlay single-host three-identity component; six sampled attempts do not establish the full profile, exact-commit custody, 4096 identities, 24 actors, three service rounds, hardware fairness or global minimum cost')
    finally:
        bundle.close()


def conclusions(phases, *, version='v1'):
    """Finite evidence cannot establish minimum work cost or hardware fairness."""
    service = tuple(row.get('mode') for row in phases) == MODES
    complete = (version == 'v2' and service
        and all(row.get('all_completed_attempt_bytes_checked') is True for row in phases))
    return dict(finite_service_measurement_complete=service,
        complete_attempt_construction_evidence=complete,
        finite_local_acceptance=complete,
        miss_cost_status=('SOURCE_BOUND_KNOWN_IMPLEMENTATION_MEASUREMENTS'
                          if complete else 'UNKNOWN_FULL_ATTEMPT_BYTES_NOT_RETAINED'),
        global_minimum_work_cost_proven=False, hardware_fairness_qualified=False,
        work_hardness_accepted=False, overall_qualified=False,
        public_network_ready=False, production_activation=False,
        scope=('Exact-source local finite service and recorded scalar evidence; '
               'recorded costs cover the selected implementation and sample only. '
               'No global cost lower bound, hardware fairness, independent host custody, WAN or public qualification'))


def validate_bundle(folder, expected_manifest, head, tree, *, version='v1', input_prepared_root=None):
    digest(head, 40)
    digest(tree, 40)
    selected = profile(version)
    require(version == 'v1' or selected['evidence_caps'] is not None,
            'v2 complete byte ledger not frozen')
    require(selected['execution_enabled'], 'v2 full I/O boundary not implemented')
    require(version == 'v1' or input_prepared_root is not None, 'explicit original preparation root required')
    bundle = IdentityBundle(folder, expected_manifest, version=version)
    original = None
    try:
        ledger = None
        if version == 'v2':
            from run_pon_identity_churn import PreparedInput
            link = bundle.json('prepared-claim-link.json')
            require(str(Path(input_prepared_root).absolute()) == link['input_prepared']['canonical_root'],
                    'explicit retained original differs from linked root')
            original = PreparedInput(Path(input_prepared_root).absolute()/'prepared.json',
                link['input_prepared']['prepared_sha256'], link['input_prepared']['inventory_sha256'], head, tree)
            ledger = validate_prepared_claim_link(bundle, original, native=True)['evidence_ledger']
        result = bundle.json('results.json')
        flags(result)
        require(result['schema'] == selected['execution_schema']
                and result['head'] == head and result['tree'] == tree and result['plan'] == PLAN
                and result['selector_executed'] is True and result['complete_success'] is True
                and result['failure'] is None, 'failed/unexecuted source-bound collection')
        prepared_raw = bundle.raw('frozen/prepared.json')
        require(sha(prepared_raw) == digest(result['prepared_sha256']), 'prepared manifest mismatch')
        prepared = strict_json(prepared_raw)
        require(prepared['schema'] == selected['prepared_schema']
                and prepared['head'] == head and prepared['tree'] == tree and prepared['plan'] == PLAN
                and prepared['acceptance'] == ACCEPTANCE and prepared['prepared'] is True
                and prepared['selector_executed'] is False, 'changed frozen preregistration')
        if version == 'v2':
            require(prepared['evidence_caps'] == result['evidence_caps'] == selected['evidence_caps'],
                    'changed frozen v2 byte ledger')
        for name, pin in prepared['files'].items():
            raw = bundle.raw('frozen/' + name, 256 * 1024 * 1024)
            require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'changed prepared member')
        binary = result['binary']
        require(binary['sha256'] == prepared['binary']['sha256']
                and sha(bundle.raw('frozen/' + TARGET + '.bin', 256 * 1024 * 1024)) == binary['sha256'],
                'exact collected executable changed')
        for prefix in ('frozen/', ''):
            before = source(bundle.json(prefix + 'source-before.json'), head, tree)
            require(source(bundle.json(prefix + 'source-after.json'), head, tree) == before,
                    'source inventory changed during collection')
        resources_before, resources_after = bundle.json('resource-before.json'), bundle.json('resource-after.json')
        require(resource(resources_before) == resource(resources_after)
                and resources_before['cgroup'] == resources_after['cgroup'], 'resource envelope changed')
        step = result['step']
        require(step['command'] == [binary['path'], '--exact', selected['selector'], '--ignored', '--nocapture', '--test-threads=1']
                and step['returncode'] == 0 and step['error'] is None
                and step['stdout_truncated'] is step['stderr_truncated'] is False
                and step['elapsed_ns'] <= prepared['collector_seconds'] * SECOND,
                'native selector failed or exceeded frozen collection budget')
        for stream in ('stdout', 'stderr'):
            raw = bundle.raw(step[stream])
            require(sha(raw) == step[stream + '_sha256'], 'native stream changed')
        native_stdout = bundle.raw(step['stdout']).decode('utf-8')
        require(len(re.findall(r'^running 1 test$', native_stdout, re.M)) == 1
                and re.search(r'^test ' + selected['selector'] + r' \.\.\. ok$', native_stdout, re.M)
                and len(re.findall(r'^test result:', native_stdout, re.M)) == 1
                and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', native_stdout, re.M),
                'exactly one actual native selector result required')
        require(all(result['post_observations'][key]['complete_success'] is True
                    and result['post_observations'][key]['failure'] is None
                    for key in ('source', 'binary', 'resources')), 'missing terminal source/binary/resource observation')
        report = bundle.json('raw/report.json')
        require(report['schema'] == selected['campaign_schema'] and report['plan'] == PLAN, 'full supplemental profile required')
        if version == 'v2':
            require(report['full_v2_io_boundary_implemented'] is True, 'incomplete native v2 I/O owner chain')
        require(report['phases'] == [dict(mode=mode, file=mode + '/report.json', error=None) for mode in MODES],
                'missing/relabelled matched control phase')
        plan = bundle.json('raw/plan.json')
        require(plan['schema'] == selected['campaign_schema'] and plan['plan'] == PLAN and plan['capacity_required'] == CAPACITY
                and plan['fresh_post_capacity_required'] == 1 and plan['pressure_coverage_percent'] == 90
                and plan['maximum_non_depleted_gap_ns'] == SECOND
                and identify_observation(plan['public_resource_policy'])['resource_revision'] == 'r13',
                'changed original policy or preregistered acceptance')
        if version == 'v2':
            require(plan['evidence_limits'] == selected['evidence_caps'], 'native v2 ledger differs from preregistration')
            node_files = bundle.json('raw/node-files.json')
            expected_files = {}
            metadata = 0
            for name, row in bundle.files.items():
                relative = name.removeprefix('raw/')
                if name.startswith('raw/') and any(relative.startswith(root + '/') for root in selected['evidence_caps']['node_roots']):
                    leaf = name.split('/')[-1]
                    expected_files[relative] = dict(path=relative, bytes=row['bytes'],
                        limit_bytes=selected['evidence_caps']['node_file_names'][leaf])
                    if leaf in ('owner.lock', 'initializing.json'):
                        metadata += row['bytes']
            observed = {row['path']: row for row in node_files['files']}
            require(len(observed) == len(node_files['files']) and observed == expected_files
                    and node_files['metadata_bytes'] == metadata
                    and node_files['metadata_limit_bytes'] == selected['evidence_caps']['node_metadata_total_bytes'],
                    'native Node file receipt omitted, invented or relabelled an actual file')
        flags(report)
        descendant_context = None
        if version == 'v2':
            # validate_prepared_claim_link above has already authenticated this
            # still-held original root; archived copies are never live authority.
            for original_plan in (plan['plan'], report['plan'], prepared['plan'], result['plan']):
                descendant_plan_types(original_plan)
            parent_pid = bundle.json('raw/process-limits.json')['after']['pid']
            descendant_context = descendant_caller_binding(plan['execution_caller'],
                bundle.json('campaign.step.json')['fd_dispatch'], parent_pid, binary)
        phases = [validate_phase(bundle, report, mode, head, tree, binary, resources_before,
                  version=version, descendant_context=descendant_context) for mode in MODES]
        if version == 'v2':
            require(len({row['descendant_fd_binding']['executable_fd'] for row in phases}) == 1,
                    'native caller executable FD changed across matched phases')
        return dict(schema='pon-identity-churn-readback-' + version, source_commit=head, source_tree=tree,
            phases=phases, evidence_ledger=ledger, **conclusions(phases, version=version))
    finally:
        if original is not None: original.close()
        bundle.close()


def diagnostic(bundle, *, version='v1'):
    """Preserve measurements from a failed native run without issuing a pass."""
    result, report = bundle.json('results.json'), bundle.json('raw/report.json')
    flags(report)
    phases = []
    for reference in report['phases']:
        name = 'raw/' + reference['file']
        if name not in bundle.files:
            phases.append(dict(mode=reference['mode'], missing_phase=True, error=reference['error']))
            continue
        value = bundle.json(name)
        row = dict(mode=value.get('mode'), raw_report_complete=True,
            recorded_prefix_work=value.get('post_prefix_work'), recorded_final_work=value.get('final_work'),
            recorded_children=len(value.get('children', [])),
            recorded_child_failures=sum(child.get('exit_success') is not True
                or child.get('parent_forced_kill') is not False for child in value.get('children', [])),
            recorded_confirmation_rounds=len(value.get('honest', {}).get('confirmations', [])),
            recorded_honest_failures=sum(call.get('status') != 'ok' or call.get('returned_after_window') is not False
                for key in ('submissions', 'history') for call in value.get('honest', {}).get(key, [])),
            original_flow_arithmetic_checked=False, flow_error=None)
        try:
            flow(value.get('final_flow'), settled=True)
            row['original_flow_arithmetic_checked'] = True
        except (ValueError, TypeError, KeyError) as error:
            row['flow_error'] = str(error)
        phases.append(row)
    return dict(schema='pon-identity-churn-failed-run-diagnostic-' + version,
        native_returncode=result.get('step', {}).get('returncode'), collection_failure=result.get('failure'),
        native_collection_success_recorded=result.get('complete_success'), phases=phases,
        finite_service_measurement_complete=False, overall_qualified=False, public_network_ready=False,
        production_activation=False, miss_cost_status='UNKNOWN_FULL_ATTEMPT_BYTES_NOT_RETAINED',
        scope='Partial recorded measurements; no scalar proof, complete denominator, source qualification or successful campaign is inferred')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-tree', required=True)
    parser.add_argument('--profile', choices=('v1', 'v2'), default='v1')
    parser.add_argument('--input-prepared-root', type=Path)
    parser.add_argument('--diagnostic', action='store_true', help='retain failed-run counts; always exit nonzero and NO_GO')
    args = parser.parse_args()
    if args.diagnostic:
        bundle = IdentityBundle(Path(args.bundle), args.manifest_sha256, version=args.profile)
        try:
            print(json.dumps(diagnostic(bundle, version=args.profile), sort_keys=True))
        finally:
            bundle.close()
        return 1
    result = validate_bundle(Path(args.bundle), args.manifest_sha256, args.source_commit, args.source_tree,
                             version=args.profile, input_prepared_root=args.input_prepared_root)
    print(json.dumps(result, sort_keys=True))
    # A structurally complete finite service measurement does not close the
    # missing-attempt-cost gate. Never turn that explicit Unknown into CI green.
    return 0 if result.get('finite_local_acceptance') is True else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        print(json.dumps(dict(result='FAIL', reason=str(error), overall_qualified=False,
                              public_network_ready=False, production_activation=False)), file=sys.stderr)
        raise SystemExit(1)
