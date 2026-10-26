#!/usr/bin/env python3
"""Strict original production-packet replay for the compact W1 miner.

Every deterministic nonce is independently recomputed, including unprinted
misses. This binds the online trace commitment and counts without requiring
miss diagnostic originals. It neither attests clocks/Node execution nor turns
posthoc reconstructions into original bytes, availability, or mining credit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import w1_parent_reuse_reader as p
from read_w1_cost_research import exact, require, uint64
from w1_lossless_raw import verified_raw_stream

SCHEMA = 'pon-w1-compact-miner-research-v1'
MAGIC = b'W1CMR1\0\0'
COMMIT_DOMAIN = b'TRNM-W1-COMPACT-ATTEMPTS1\0'
HEADER_BYTES, PACKET_BYTES, FRAME_LIMIT = 318, 49_508, 65_536
MAX_OUTPUT = 256 * 1024 * 1024
START, CONTEXT, SETUP_PACKET, SETUP_RECEIPT, PREPARED, BOUNDARY, WINNER, SEAL, RECEIVER, AUDIT, END = range(1, 12)
PHASES = ('setup', 'miner', 'receiver', 'audit', 'done')
FIELDS = {
    START: 'schema options origin phase_order cpu_scope winner_payload packet_bytes miss_originals_retained trace_commitment_is_paid_observation commitment_required_by_consensus trace_kernel production_activation minimum_attacker_cost_established',
    CONTEXT: 'begin observed genesis task observed_now maintenance_is_real_training',
    SETUP_RECEIPT: 'begin packet_flushed native_block_id original_completed_attempts original_target_misses original_miss_records setup_credit_separate active_unchanged',
    PREPARED: 'begin observed arm original_AB_and_prefix_paid_in_setup commitment_initialization_paid_in_setup',
    BOUNDARY: 'from to begin end elapsed_cpu_ns boundary_output_charged_to_next_phase',
    SEAL: 'setup_complete stop_reason attempts target_hits target_misses attempts_available_by_b full_winners_available_by_b trace_commitment committed_attempt_payload_bytes winner_packet_bytes original_miss_records first_attempt_begin last_attempt_begin last_attempt_available last_attempt_accounted stop_poll availability_to_accounting_observation_cpu_ns availability_to_accounting_observation_wall_ns',
    RECEIVER: 'ordinal available accounted within_miner_budget native_block_id active_tip admission_completed original_packet_bytes mature_reward_claim',
    AUDIT: 'research_recomputed setup_recomputed research_hits research_misses trace_commitment reference_relation_checks posthoc_miss_bytes_are_original posthoc_new_credit feedback_to_miner observed',
    END: 'schema status setup_complete attempts target_misses target_hits attempts_available_by_B full_winners_available_by_B native_accepted native_accepted_from_B late_attempts late_winners censored_by_attempt_cap phase_cpu_ns post_stop_seal_cpu_ns native_total_endpoint candidate_chain_activation minimum_attacker_cost_established production_activation final_serialization_and_remaining_drops_in_whole_child_residual',
}


def same(a, b):
    return json.dumps(a, sort_keys=True, allow_nan=False, separators=(',', ':')) == json.dumps(b, sort_keys=True, allow_nan=False, separators=(',', ':'))


def equals(a, b, label):
    require(same(a, b), label)


def decode_json(payload, tag):
    def nonfinite(_):
        raise ValueError('NONFINITE_JSON')
    value = json.loads(payload, object_pairs_hook=p.unique, parse_constant=nonfinite)
    require(type(value) is dict, 'FRAME_JSON_OBJECT')
    exact(value, FIELDS[tag].split(), 'FRAME_FIELDS:' + str(tag))
    return value


def validate_options(value):
    exact(value, 'setup_budget_ns miner_budget_ns max_attempts seed'.split(), 'OPTIONS')
    for key in ('setup_budget_ns', 'miner_budget_ns'):
        uint64(value[key], 'OPTION:' + key)
    uint64(value['max_attempts'], 'ATTEMPT_CAP', 1, 4096)
    uint64(value['seed'], 'SEED', 0, (1 << 32) - 1)
    return value


def options_from_args(args):
    require(type(args) is list and len(args) % 2 == 0 and all(type(x) is str for x in args), 'CLI_PAIRS')
    result = dict(setup_budget_ns=1_000_000_000, miner_budget_ns=128_000_000, max_attempts=4096, seed=1)
    seen = set()
    for key, value in zip(args[::2], args[1::2]):
        name = key.removeprefix('--').replace('-', '_')
        require(name in result and key == '--' + name.replace('_', '-') and key not in seen, 'CLI_OPTION')
        seen.add(key)
        require(value.isascii() and value.isdecimal(), 'CLI_INTEGER')
        result[name] = int(value)
    return validate_options(result)


class FrameStream:
    def __init__(self, path):
        self.path = Path(path)
        self.sha256 = hashlib.sha256()
        self.bytes = 0
        self.frames = 0

    def __iter__(self):
        pending = bytearray()
        magic = False
        for chunk in verified_raw_stream(self.path, max_output_bytes=MAX_OUTPUT):
            self.bytes += len(chunk)
            self.sha256.update(chunk)
            pending.extend(chunk)
            if not magic:
                if len(pending) < len(MAGIC):
                    continue
                require(pending[:len(MAGIC)] == MAGIC, 'COMPACT_MAGIC')
                del pending[:len(MAGIC)]
                magic = True
            offset = 0
            while len(pending) - offset >= 5:
                tag, length = struct.unpack_from('<BI', pending, offset)
                require(START <= tag <= END, 'FRAME_TAG')
                require(0 < length <= FRAME_LIMIT, 'FRAME_LENGTH')
                if len(pending) - offset < 5 + length:
                    break
                payload = bytes(pending[offset + 5:offset + 5 + length])
                offset += 5 + length
                self.frames += 1
                require(self.frames <= 2 * 4096 + 12, 'FRAME_COUNT')
                yield tag, payload
            del pending[:offset]
        require(magic, 'TRUNCATED_MAGIC')
        require(not pending, 'TRUNCATED_FRAME')


def packet_statement(raw, genesis):
    require(type(raw) is bytes and len(raw) == PACKET_BYTES, 'NATIVE_PACKET_LENGTH')
    require(raw[HEADER_BYTES:HEADER_BYTES + 2] == b'\0\0', 'NATIVE_EMPTY_TRANSACTIONS')
    header_raw = raw[:HEADER_BYTES]
    header = p.header_decode(header_raw)
    require(p.header_encode(header) == header_raw, 'NATIVE_HEADER_CANONICAL')
    params, network, parameters = p.fixed_context()
    model, inputs, task = p.material(0)
    require(header['network'] == network and header['parameters'] == parameters and
            header['parent'].hex() == genesis and header['height'] == 1 and header['timestamp'] == 11 and
            header['miner'] == p.public(0) and header['work_task'] == task and
            header['target'].hex() == params['initial_target_hex'], 'NATIVE_HEADER_CONTEXT')
    proof = raw[HEADER_BYTES + 2:]
    require(proof[:4] == b'PNW1' and proof[4:16388] == model and proof[16388:32772] == inputs,
            'NATIVE_PROOF_MATERIAL')
    trace = proof[-32:]
    challenge = p.H('challenge', header_raw)
    ticket = p.H('ticket', challenge, trace)
    require(header['target'] != bytes(32) and ticket <= header['target'], 'ORIGINAL_PACKET_NOT_WINNER')
    return dict(header=header, header_raw=header_raw, proof=proof, trace=trace, challenge=challenge,
                ticket=ticket, semantic_id=p.H('w1-cost-game-semantic-ticket-v1', task, challenge, ticket).hex(),
                block_id=p.H('block', header_raw, trace).hex(), raw=raw)


def check_seal(seal, options, setup_complete, origin, winner_count):
    equals(seal['setup_complete'], setup_complete, 'SEAL_SETUP')
    for field in ('attempts', 'target_hits', 'target_misses', 'attempts_available_by_b', 'full_winners_available_by_b'):
        uint64(seal[field], 'SEAL_COUNT:' + field, 0, options['max_attempts'])
    n = seal['attempts']
    equals(seal['target_hits'] + seal['target_misses'], n, 'ALL_FAILURES_COUNTED')
    equals(seal['target_hits'], winner_count, 'ALL_WINNERS_OUTPUT')
    equals(seal['original_miss_records'], 0, 'NO_MISS_DIAGNOSTIC_ORIGINALS')
    equals(seal['committed_attempt_payload_bytes'], 40 * n, 'COMMITMENT_PAYLOAD_LENGTH')
    equals(seal['winner_packet_bytes'], PACKET_BYTES * winner_count, 'WINNER_PACKET_BYTE_TOTAL')
    for field in ('availability_to_accounting_observation_cpu_ns', 'availability_to_accounting_observation_wall_ns'):
        uint64(seal[field], 'SEAL_LEDGER_OBSERVATION:' + field)
    p.stamp(seal['stop_poll'])
    p.before(origin, seal['stop_poll'], 'STOP_POLL_ORIGIN')
    if not setup_complete:
        require(n == 0 and seal['trace_commitment'] is None, 'INCOMPLETE_SETUP_NO_MINING')
        expected_stop = 'setup-incomplete'
    else:
        p.hx(seal['trace_commitment'], 32, 'TRACE_COMMITMENT')
        expected_stop = 'safety-cap-censored' if n == options['max_attempts'] else 'miner-cpu-budget-stopped'
        if expected_stop == 'miner-cpu-budget-stopped':
            require(seal['stop_poll']['process_cpu_ns'] - origin['process_cpu_ns'] >= options['miner_budget_ns'], 'BUDGET_NOT_EXHAUSTED')
    equals(seal['stop_reason'], expected_stop, 'STOP_REASON')
    first, begin, available, accounted = [seal[k] for k in ('first_attempt_begin', 'last_attempt_begin', 'last_attempt_available', 'last_attempt_accounted')]
    if n == 0:
        equals((first, begin, available, accounted), (None, None, None, None), 'EMPTY_ATTEMPT_STAMPS')
        equals((seal['attempts_available_by_b'], seal['full_winners_available_by_b'],
                seal['availability_to_accounting_observation_cpu_ns'], seal['availability_to_accounting_observation_wall_ns']),
               (0, 0, 0, 0), 'EMPTY_ATTEMPT_COUNTS')
    else:
        for stamp in (first, begin, available, accounted):
            p.stamp(stamp)
        for left, right in ((origin, first), (first, begin), (begin, available), (available, accounted), (accounted, seal['stop_poll'])):
            p.before(left, right, 'LAST_ATTEMPT_ORDER')
        require(begin['process_cpu_ns'] - origin['process_cpu_ns'] < options['miner_budget_ns'], 'ATTEMPT_STARTED_AFTER_B')
        if n == 1:
            equals(first, begin, 'SINGLE_ATTEMPT_BEGIN')
        expected_by_b = n - int(available['process_cpu_ns'] - origin['process_cpu_ns'] > options['miner_budget_ns'])
        equals(seal['attempts_available_by_b'], expected_by_b, 'BY_B_PREFIX')
        require(seal['availability_to_accounting_observation_cpu_ns'] >= accounted['process_cpu_ns'] - available['process_cpu_ns'] and
                seal['availability_to_accounting_observation_wall_ns'] >= accounted['wall_ns'] - available['wall_ns'], 'LAST_LEDGER_OBSERVATION')
    require(seal['full_winners_available_by_b'] <= min(seal['target_hits'], seal['attempts_available_by_b']), 'WINNER_B_COUNT')


def replay_all(setup, winners, seal, options):
    """Full scalar equations, not the inexpensive ticket-only precheck."""
    model, inputs, _ = p.material(0)
    a = list(struct.unpack('<4096I', model))
    b = list(struct.unpack('<4096I', inputs))
    identities, hits, winner_results = [], [], []
    setup_recomputed = 0
    if setup is not None:
        original_nonce = setup['header']['nonce']
        for nonce in range(original_nonce + 1):
            header = dict(setup['header']); header['nonce'] = nonce
            raw_header = p.header_encode(header)
            challenge = p.H('challenge', raw_header)
            proof = p.work_oracle.prove(challenge, a, b)
            ticket = p.H('ticket', challenge, proof[-32:])
            is_hit = ticket <= header['target']
            require(is_hit == (nonce == original_nonce), 'SETUP_SEARCH_SCALAR_REPLAY')
            if is_hit:
                require(proof == setup['proof'], 'ORIGINAL_SETUP_PROOF_SCALAR_REPLAY')
            setup_recomputed += 1
    digest = None
    if seal['setup_complete']:
        require(setup is not None, 'REPLAY_TEMPLATE')
        digest = hashlib.sha256(COMMIT_DOMAIN + setup['header_raw'] + struct.pack('<Q', options['seed']))
        winners_by_ordinal = {w['ordinal']: w for w in winners}
        for ordinal in range(seal['attempts']):
            header = dict(setup['header']); header['nonce'] = (1 << 63) + options['seed'] * 4096 + ordinal
            raw_header = p.header_encode(header)
            challenge = p.H('challenge', raw_header)
            proof = p.work_oracle.prove(challenge, a, b)
            trace = proof[-32:]
            ticket = p.H('ticket', challenge, trace)
            is_hit = ticket <= header['target']
            digest.update(struct.pack('<Q', ordinal)); digest.update(trace)
            identity = p.H('w1-cost-game-semantic-ticket-v1', header['work_task'], challenge, ticket).hex()
            identities.append(identity); hits.append(is_hit)
            require((ordinal in winners_by_ordinal) == is_hit, 'COMPLETE_WINNER_SET_SCALAR_REPLAY')
            if is_hit:
                w = winners_by_ordinal[ordinal]
                require(w['header_raw'] == raw_header and w['proof'] == proof and w['semantic_id'] == identity,
                        'ORIGINAL_WINNER_PACKET_SCALAR_REPLAY')
                winner_results.append(dict(ordinal=ordinal, semantic_id=identity,
                    challenge=challenge.hex(), ticket=ticket.hex(), trace=trace.hex(), block_id=w['block_id'],
                    header_hex=raw_header.hex(), proof_sha256=hashlib.sha256(proof).hexdigest(),
                    packet_sha256=hashlib.sha256(w['raw']).hexdigest(),
                    available=w['receiver']['available'], accounted=w['receiver']['accounted'],
                    within_miner_budget=w['receiver']['within_miner_budget']))
    expected_digest = None if digest is None else digest.hexdigest()
    equals(seal['trace_commitment'], expected_digest, 'ALL_MISS_TRACE_COMMITMENT_SCALAR_REPLAY')
    equals((sum(hits), len(hits) - sum(hits)), (seal['target_hits'], seal['target_misses']), 'ALL_TARGET_COUNTS_SCALAR_REPLAY')
    require(len(set(identities)) == len(identities) and
            (setup is None or setup['semantic_id'] not in identities), 'UNIQUE_OPPORTUNITIES')
    return dict(setup_recomputed=setup_recomputed, opportunity_identities=identities, hit_sequence=hits,
                winner_packets=winner_results, trace_commitment=expected_digest)


def read_compact(path, expected_options=None):
    stream = FrameStream(path)
    phase = 'setup'
    origin = dict(process_cpu_ns=0, wall_ns=0)
    last_observed = dict(origin)
    start = context = setup = setup_receipt = prepared = seal = audit = end = None
    options = None
    boundaries, phase_cpu = {}, {}
    winners, receivers = [], []
    previous_tag = None
    for tag, payload in stream:
        require(end is None, 'TRAILING_FRAME')
        if tag not in (SETUP_PACKET, WINNER):
            row = decode_json(payload, tag)
        if start is None:
            require(tag == START, 'START_REQUIRED')
            start = row
            options = validate_options(start['options'])
            if expected_options is not None:
                equals(options, validate_options(expected_options), 'EXPECTED_OPTIONS')
            equals({k: start[k] for k in FIELDS[START].split() if k != 'options'}, dict(
                schema=SCHEMA, origin=dict(origin), phase_order=list(PHASES),
                cpu_scope='actual-process-CPU-no-observer-subtraction', winner_payload='unchanged-Packet-encode',
                packet_bytes=PACKET_BYTES, miss_originals_retained=False, trace_commitment_is_paid_observation=True,
                commitment_required_by_consensus=False, trace_kernel='DeferredPrepared-integer-paired-general',
                production_activation=False, minimum_attacker_cost_established=False), 'START_CLAIMS')
            previous_tag = tag
            continue
        if tag == BOUNDARY:
            require(phase != 'done', 'EXCESS_BOUNDARY')
            nxt = PHASES[PHASES.index(phase) + 1]
            equals((row['from'], row['to']), (phase, nxt), 'BOUNDARY_ORDER')
            p.stamp(row['begin']); p.stamp(row['end'])
            equals(row['begin'], origin, 'BOUNDARY_BEGIN')
            p.before(last_observed, row['end'], 'BOUNDARY_END')
            elapsed = row['end']['process_cpu_ns'] - origin['process_cpu_ns']
            equals(row['elapsed_cpu_ns'], elapsed, 'PHASE_CPU')
            require(row['boundary_output_charged_to_next_phase'] is True, 'BOUNDARY_ACCOUNTING')
            if phase == 'setup':
                require(setup is None or setup_receipt is not None, 'SETUP_RECEIPT_MISSING')
            elif phase == 'miner':
                require(seal is not None and previous_tag == SEAL, 'MINER_SEAL_REQUIRED')
                for field, clock_key in (('availability_to_accounting_observation_cpu_ns', 'process_cpu_ns'),
                                         ('availability_to_accounting_observation_wall_ns', 'wall_ns')):
                    require(seal[field] <= row['end'][clock_key] - origin[clock_key], 'LEDGER_OBSERVATION_BOUND')
            elif phase == 'receiver':
                require(len(receivers) == len(winners), 'ALL_NATIVE_RECEIPTS')
            elif phase == 'audit':
                require(audit is not None and previous_tag == AUDIT, 'AUDIT_REQUIRED')
            boundaries[phase] = row
            phase_cpu[phase] = elapsed
            phase, origin = nxt, row['end']
            last_observed = dict(origin)
        elif tag == CONTEXT:
            require(phase == 'setup' and context is None and previous_tag == START, 'CONTEXT_ORDER')
            p.stamp(row['begin']); p.stamp(row['observed'])
            p.before(last_observed, row['begin'], 'CONTEXT_BEGIN'); p.before(row['begin'], row['observed'], 'CONTEXT_END')
            require(row['begin']['process_cpu_ns'] < options['setup_budget_ns'], 'CONTEXT_AFTER_P')
            p.hx(row['genesis'], 32, 'GENESIS')
            equals((row['task'], row['observed_now'], row['maintenance_is_real_training']),
                   (p.material(0)[2].hex(), 100000, False), 'NATIVE_CONTEXT')
            context, last_observed = row, row['observed']
        elif tag == SETUP_PACKET:
            require(phase == 'setup' and context is not None and setup is None and previous_tag == CONTEXT, 'SETUP_PACKET_ORDER')
            setup = packet_statement(payload, context['genesis'])
            require(setup['header']['nonce'] < 64, 'SETUP_MAKE_LIMIT')
        elif tag == SETUP_RECEIPT:
            require(phase == 'setup' and setup is not None and setup_receipt is None and previous_tag == SETUP_PACKET, 'SETUP_RECEIPT_ORDER')
            p.stamp(row['begin']); p.stamp(row['packet_flushed'])
            p.before(last_observed, row['begin'], 'SETUP_BEGIN'); p.before(row['begin'], row['packet_flushed'], 'SETUP_PACKET_FLUSH')
            require(row['begin']['process_cpu_ns'] < options['setup_budget_ns'], 'SETUP_STARTED_AFTER_P')
            equals(tuple(row[k] for k in ('native_block_id', 'original_completed_attempts', 'original_target_misses',
                                          'original_miss_records', 'setup_credit_separate', 'active_unchanged')),
                   (setup['block_id'], setup['header']['nonce'] + 1, setup['header']['nonce'], 0, True, True), 'SETUP_RECEIPT_BINDING')
            setup_receipt, last_observed = row, row['packet_flushed']
        elif tag == PREPARED:
            require(phase == 'setup' and setup_receipt is not None and prepared is None and previous_tag == SETUP_RECEIPT, 'PREPARED_ORDER')
            p.stamp(row['begin']); p.stamp(row['observed'])
            p.before(last_observed, row['begin'], 'PREPARE_BEGIN'); p.before(row['begin'], row['observed'], 'PREPARE_END')
            require(row['begin']['process_cpu_ns'] < options['setup_budget_ns'], 'PREPARE_AFTER_P')
            equals((row['arm'], row['original_AB_and_prefix_paid_in_setup'], row['commitment_initialization_paid_in_setup']),
                   ('integer-paired-general', True, True), 'PREPARATION_CLAIMS')
            prepared, last_observed = row, row['observed']
        elif tag == WINNER:
            require(phase == 'miner' and seal is None and prepared is not None, 'WINNER_PHASE')
            require(len(payload) == 8 + PACKET_BYTES, 'WINNER_FRAME_LENGTH')
            ordinal, = struct.unpack_from('<Q', payload)
            require(ordinal < options['max_attempts'] and (not winners or ordinal > winners[-1]['ordinal']), 'WINNER_ORDINAL')
            winner = packet_statement(payload[8:], context['genesis'])
            header = dict(setup['header']); header['nonce'] = (1 << 63) + options['seed'] * 4096 + ordinal
            require(winner['header_raw'] == p.header_encode(header), 'EXACT_NONCE_SCHEDULE')
            winner['ordinal'] = ordinal
            winners.append(winner)
        elif tag == SEAL:
            require(phase == 'miner' and seal is None, 'SEAL_ORDER')
            setup_complete = prepared is not None and boundaries['setup']['end']['process_cpu_ns'] <= options['setup_budget_ns']
            check_seal(row, options, setup_complete, origin, len(winners))
            require(all(w['ordinal'] < row['attempts'] for w in winners), 'WINNER_COMPLETED_PREFIX')
            seal, last_observed = row, row['stop_poll']
        elif tag == RECEIVER:
            require(phase == 'receiver' and seal is not None and len(receivers) < len(winners), 'RECEIVER_ORDER')
            winner = winners[len(receivers)]
            equals(row['ordinal'], winner['ordinal'], 'RECEIVER_ORDINAL')
            for key in ('available', 'accounted', 'admission_completed'):
                p.stamp(row[key])
            p.before(boundaries['setup']['end'], row['available'], 'WINNER_AVAILABILITY_ORIGIN')
            p.before(row['available'], row['accounted'], 'WINNER_LEDGER_ORDER')
            p.before(row['accounted'], seal['stop_poll'], 'WINNER_BEFORE_SEAL')
            if receivers:
                p.before(receivers[-1]['accounted'], row['available'], 'WINNER_COMPLETION_ORDER')
            p.before(last_observed, row['admission_completed'], 'NATIVE_ADMISSION_PHASE')
            within = row['available']['process_cpu_ns'] - boundaries['setup']['end']['process_cpu_ns'] <= options['miner_budget_ns']
            equals(within, winner['ordinal'] < seal['attempts_available_by_b'], 'WINNER_BY_B_PREFIX')
            equals((row['within_miner_budget'], row['native_block_id'], row['active_tip'], row['original_packet_bytes'], row['mature_reward_claim']),
                   (within, winner['block_id'], context['genesis'], PACKET_BYTES, False), 'NATIVE_RECEIPT_BINDING')
            if winner['ordinal'] == seal['attempts'] - 1:
                equals(row['available'], seal['last_attempt_available'], 'LAST_WINNER_AVAILABLE')
                equals(row['accounted'], seal['last_attempt_accounted'], 'LAST_WINNER_ACCOUNTED')
            winner['receiver'] = row
            receivers.append(row)
            last_observed = row['admission_completed']
        elif tag == AUDIT:
            require(phase == 'audit' and audit is None, 'AUDIT_ORDER')
            p.stamp(row['observed']); p.before(last_observed, row['observed'], 'AUDIT_OBSERVATION')
            audit, last_observed = row, row['observed']
        elif tag == END:
            require(phase == 'done' and previous_tag == BOUNDARY and end is None, 'END_ORDER')
            end = row
        else:
            raise ValueError('UNEXPECTED_FRAME')
        previous_tag = tag
    require(start is not None and end is not None and audit is not None and seal is not None, 'INCOMPLETE_RESEARCH_STREAM')
    equals(list(boundaries), list(PHASES[:-1]), 'ALL_PHASES')
    require(len(winners) == len(receivers), 'ALL_ORIGINAL_WINNERS_RECEIVED')
    b_winners = sum(r['within_miner_budget'] for r in receivers)
    equals(b_winners, seal['full_winners_available_by_b'], 'B_WINNERS_RECEIVED')
    for key, clock_key in (('availability_to_accounting_observation_cpu_ns', 'process_cpu_ns'),
                           ('availability_to_accounting_observation_wall_ns', 'wall_ns')):
        require(seal[key] >= sum(r['accounted'][clock_key] - r['available'][clock_key] for r in receivers), 'WINNER_LEDGER_SUM')
    p.stamp(end['native_total_endpoint'])
    p.before(boundaries['audit']['end'], end['native_total_endpoint'], 'TOTAL_ENDPOINT')
    expected_end = dict(schema=SCHEMA, status='PASS', setup_complete=seal['setup_complete'],
        attempts=seal['attempts'], target_misses=seal['target_misses'], target_hits=seal['target_hits'],
        attempts_available_by_B=seal['attempts_available_by_b'], full_winners_available_by_B=b_winners,
        native_accepted=len(winners), native_accepted_from_B=b_winners,
        late_attempts=seal['attempts']-seal['attempts_available_by_b'], late_winners=len(winners)-b_winners,
        censored_by_attempt_cap=seal['stop_reason']=='safety-cap-censored', phase_cpu_ns=phase_cpu,
        post_stop_seal_cpu_ns=boundaries['miner']['end']['process_cpu_ns']-seal['stop_poll']['process_cpu_ns'],
        native_total_endpoint=end['native_total_endpoint'], candidate_chain_activation=False,
        minimum_attacker_cost_established=False, production_activation=False,
        final_serialization_and_remaining_drops_in_whole_child_residual=True)
    equals(end, expected_end, 'END_RECONCILIATION')
    # This is deliberately after complete structural validation, not a target-only pass.
    replay = replay_all(setup, winners, seal, options)
    expected_audit = dict(research_recomputed=seal['attempts'], setup_recomputed=replay['setup_recomputed'],
        research_hits=seal['target_hits'], research_misses=seal['target_misses'],
        trace_commitment=replay['trace_commitment'], reference_relation_checks=seal['attempts']+replay['setup_recomputed'],
        posthoc_miss_bytes_are_original=False, posthoc_new_credit=0, feedback_to_miner=False, observed=audit['observed'])
    equals(audit, expected_audit, 'AUDIT_RECONCILIATION')
    return dict(schema='pon-w1-compact-miner-readback-v1', raw_path=str(path), raw_bytes=stream.bytes,
        raw_sha256=stream.sha256.hexdigest(), frames=stream.frames, options=options,
        **{k: v for k, v in expected_end.items() if k != 'schema'},
        total_process_cpu_ns=end['native_total_endpoint']['process_cpu_ns'],
        total_wall_ns=end['native_total_endpoint']['wall_ns'],
        phase_boundaries=boundaries, miner_seal=seal,
        setup_statement=None if setup is None else dict(header_hex=setup['header_raw'].hex(),
            proof_sha256=hashlib.sha256(setup['proof']).hexdigest()),
        original_setup_packet_count=int(setup is not None), original_research_packet_count=len(winners),
        full_proof_records_replayed=len(winners)+int(setup is not None),
        deterministic_attempts_recomputed=seal['attempts']+replay['setup_recomputed'],
        posthoc_miss_proofs_recomputed=seal['target_misses']+max(0,replay['setup_recomputed']-1),
        original_miss_records=0, **replay,
        original_node_admission_is_source_bound_observation=True, physical_or_clock_attestation=False,
        original_nonce_failure_timing_independently_attested=False)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--expected-raw-sha256', required=True)
    args = parser.parse_args(argv)
    p.hx(args.expected_raw_sha256, 32, 'EXTERNAL_RAW_SHA256')
    result = read_compact(args.raw)
    equals(result['raw_sha256'], args.expected_raw_sha256, 'EXTERNAL_RAW_PIN')
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError, struct.error) as error:
        raise SystemExit(str(error)) from error
