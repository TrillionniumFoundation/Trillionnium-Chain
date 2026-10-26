#!/usr/bin/env python3
"""Strict full-byte replay of eager and winner-only native W1 experiments.

The reader checks the actual relation for every original or reconstructed proof.
It cannot authenticate clocks, hardware, Node execution or when hidden setup
misses originally existed. Posthoc bytes never create or backdate miner credit.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import w1_parent_reuse_reader as p
from read_w1_cost_research import exact, require, uint64
from w1_lossless_raw import bounded_raw_lines

SCHEMA = 'pon-w1-late-assembly-research-v1'
COMMON = {'schema', 'sequence', 'phase', 'observed', 'kind'}
PHASES = ('setup', 'miner', 'receiver', 'audit', 'done')
FIELDS = {
    'start': 'options phase_order cpu_scope physical_cost_lower_bound production_activation same_trace_kernel_in_both_modes proof_compression',
    'context': 'begin genesis model_hex input_hex task observed_now maintenance_is_real_training',
    'setup-proof': 'begin statement proof native_block_id original_completed_attempts original_miss_bytes_retained setup_credit_is_separate research_activation',
    'prepared': 'begin original_AB_and_prefix_paid_in_setup arm',
    'boundary': 'from to begin end elapsed_cpu_ns boundary_encoding_charged_to_next_phase',
    'attempt': 'ordinal begin trace_done proof_ready statement proof node_or_verifier_called',
    'available': 'ordinal available elapsed_cpu_ns within_miner_budget full_proof_flushed original_trace_flushed',
    'receiver': 'ordinal native_block_id within_miner_budget active_unchanged mature_reward_claim',
    'audit': 'ordinal posthoc_proof full_relation reference_relation actual_target_hit posthoc_new_credit provides_miner_feedback',
    'setup-reconstruction': 'nonce statement proof original_winner original_bytes_observed new_work_credit',
    'end': 'status setup_complete setup_completed_at attempts traces_available_by_B full_proofs_available_by_B full_winners_available_by_B native_accepted native_accepted_from_B censored_by_attempt_cap phase_cpu_ns native_total_endpoint candidate_chain_activation minimum_attacker_cost_established production_activation',
}

def same(a, b):
    return json.dumps(a, sort_keys=True, allow_nan=False, separators=(',', ':')) == json.dumps(b, sort_keys=True, allow_nan=False, separators=(',', ':'))

def equals(a, b, label):
    require(same(a, b), label)

def validate_options(v):
    exact(v, 'setup_budget_ns miner_budget_ns max_attempts seed mode'.split(), 'OPTIONS')
    for k in ('setup_budget_ns', 'miner_budget_ns'): uint64(v[k], 'OPTION:' + k)
    uint64(v['max_attempts'], 'ATTEMPT_CAP', 1, 4096)
    uint64(v['seed'], 'SEED', 0, (1 << 32) - 1)
    require(type(v['mode']) is str and v['mode'] in ('eager', 'deferred'), 'MODE')
    return v

def options_from_args(args):
    require(type(args) is list and len(args) % 2 == 0 and all(type(x) is str for x in args), 'CLI_PAIRS')
    v = dict(setup_budget_ns=1_000_000_000, miner_budget_ns=128_000_000, max_attempts=4096, seed=1, mode='eager')
    seen = set()
    for key, value in zip(args[::2], args[1::2]):
        name = key.removeprefix('--').replace('-', '_')
        require(name in v and key == '--' + name.replace('_', '-') and key not in seen, 'CLI_OPTION')
        seen.add(key)
        if name != 'mode':
            require(value.isascii() and value.isdecimal(), 'CLI_INTEGER')
            value = int(value)
        v[name] = value
    return validate_options(v)

def statement(v, genesis):
    exact(v, 'header_hex trace challenge ticket semantic_id block_id target_hit'.split(), 'STATEMENT')
    raw = p.hx(v['header_hex'], 318, 'HEADER')
    header = p.header_decode(raw)
    equals(p.header_encode(header).hex(), raw.hex(), 'HEADER_CANONICAL')
    params, network, parameters = p.fixed_context()
    model, inputs, task = p.material(0)
    require(header['network'] == network and header['parameters'] == parameters and
            header['parent'].hex() == genesis and header['height'] == 1 and header['timestamp'] == 11 and
            header['miner'] == p.public(0) and header['work_task'] == task and
            header['target'].hex() == params['initial_target_hex'], 'NATIVE_HEADER_CONTEXT')
    trace = p.hx(v['trace'], 32, 'TRACE')
    challenge = p.H('challenge', raw)
    ticket = p.H('ticket', challenge, trace)
    semantic = p.H('w1-cost-game-semantic-ticket-v1', task, challenge, ticket)
    expected = dict(header_hex=raw.hex(), trace=trace.hex(), challenge=challenge.hex(), ticket=ticket.hex(),
                    semantic_id=semantic.hex(), block_id=p.H('block', raw, trace).hex(),
                    target_hit=bool(header['target'] != bytes(32) and ticket <= header['target']))
    equals(v, expected, 'STATEMENT_BINDING')
    return dict(header=header, raw=raw, trace=trace, challenge=challenge, ticket=ticket,
                hit=expected['target_hit'], identity=semantic.hex(), block=expected['block_id'], model=model, inputs=inputs)

def proof(v, st):
    exact(v, ('hex', 'bytes', 'sha256'), 'PROOF_FIELDS')
    raw = p.hx(v['hex'], p.PROOF_BYTES, 'PROOF_HEX')
    equals(v['bytes'], p.PROOF_BYTES, 'PROOF_LENGTH')
    equals(v['sha256'], hashlib.sha256(raw).hexdigest(), 'PROOF_HASH')
    require(raw[:4] == b'PNW1' and raw[4:16388] == st['model'] and raw[16388:32772] == st['inputs'] and raw[-32:] == st['trace'], 'PROOF_BINDING')
    ticket, _ = p.work_oracle.verify(st['challenge'], st['header']['work_task'], b'\xff' * 32, raw)
    require(ticket == st['ticket'], 'FULL_SCALAR_REPLAY')
    return raw

def read_late(path, expected_options=None):
    rows, digest, total = [], hashlib.sha256(), 0
    for line in bounded_raw_lines(Path(path), max_output_bytes=256 * 1024 * 1024, max_line_bytes=256 * 1024):
        require(line.endswith(b'\n'), 'INCOMPLETE_LINE')
        total += len(line); digest.update(line)
        row = json.loads(line, object_pairs_hook=p.unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE')))
        require(type(row) is dict and row.get('schema') == SCHEMA and type(row.get('sequence')) is int and row['sequence'] == len(rows), 'RAW_SEQUENCE')
        require(row.get('kind') in FIELDS and row.get('phase') in PHASES, 'RAW_KIND_PHASE')
        exact(row, COMMON | set(FIELDS[row['kind']].split()), 'RAW_FIELDS')
        p.stamp(row['observed'])
        if rows: p.before(rows[-1]['observed'], row['observed'], 'CLOCK_REVERSED')
        rows.append(row); require(len(rows) <= 40000, 'ROW_LIMIT')
    require(len(rows) >= 6 and rows[0]['kind'] == 'start' and rows[-1]['kind'] == 'end', 'RAW_COMPLETENESS')
    start, end = rows[0], rows[-1]
    require(start['phase'] == 'setup', 'START_PHASE')
    o = validate_options(start['options'])
    if expected_options is not None: equals(o, validate_options(expected_options), 'EXPECTED_OPTIONS')
    equals({k: start[k] for k in FIELDS['start'].split() if k != 'options'},
           dict(phase_order=list(PHASES), cpu_scope='process-CPU-with-all-original-output-until-flush',
                physical_cost_lower_bound=False, production_activation=False, same_trace_kernel_in_both_modes=True, proof_compression=False), 'START_CLAIMS')
    phase, origin = 'setup', dict(process_cpu_ns=0, wall_ns=0)
    phase_cpu, boundaries = {}, {}
    context = setup = prepared = None
    attempts, available, receivers, audits, reconstructions = [], [], [], [], []
    replayed = 0
    last = rows[0]
    for row in rows[1:]:
        kind = row['kind']
        if kind == 'boundary':
            nxt = PHASES[PHASES.index(phase) + 1]
            equals((row['from'], row['to'], row['phase']), (phase, nxt, nxt), 'BOUNDARY_ORDER')
            equals(row['begin'], origin, 'BOUNDARY_BEGIN')
            p.stamp(row['end']); p.before(last['observed'], row['end'], 'BOUNDARY_END'); p.before(row['end'], row['observed'], 'BOUNDARY_OBSERVED')
            elapsed = row['end']['process_cpu_ns'] - origin['process_cpu_ns']
            equals(row['elapsed_cpu_ns'], elapsed, 'PHASE_ELAPSED')
            require(row['boundary_encoding_charged_to_next_phase'] is True, 'BOUNDARY_ACCOUNTING')
            phase_cpu[phase] = elapsed; boundaries[phase] = row
            phase, origin = nxt, row['end']
            last = row; continue
        require(row['phase'] == phase, 'ROW_PHASE')
        if kind in ('context', 'setup-proof', 'prepared'):
            require(phase == 'setup', 'SETUP_PHASE')
            p.stamp(row['begin']); p.before(last['observed'], row['begin'], 'SETUP_START_ORDER'); p.before(row['begin'], row['observed'], 'SETUP_START_END')
            require(row['begin']['process_cpu_ns'] < o['setup_budget_ns'], 'SETUP_STARTED_AFTER_P')
        if kind == 'context':
            require(context is None, 'DUPLICATE_CONTEXT'); context = row
            model, inputs, task = p.material(0)
            equals((row['model_hex'], row['input_hex'], row['task'], row['observed_now'], row['maintenance_is_real_training']),
                   (model.hex(), inputs.hex(), task.hex(), 100000, False), 'MAINTENANCE_CONTEXT')
            p.hx(row['genesis'], 32, 'GENESIS')
        elif kind == 'setup-proof':
            require(context is not None and setup is None, 'SETUP_DEPENDENCY')
            setup = statement(row['statement'], context['genesis']); setup['proof'] = proof(row['proof'], setup); replayed += 1
            require(setup['hit'] and 0 <= setup['header']['nonce'] < 64, 'SETUP_ORIGINAL_WINNER')
            equals((row['native_block_id'], row['original_completed_attempts'], row['original_miss_bytes_retained'], row['setup_credit_is_separate'], row['research_activation']),
                   (setup['block'], setup['header']['nonce'] + 1, False, True, False), 'SETUP_CLAIMS')
        elif kind == 'prepared':
            require(setup is not None and prepared is None, 'PREPARATION_DEPENDENCY'); prepared = row
            equals((row['original_AB_and_prefix_paid_in_setup'], row['arm']), (True, 'integer-paired-general'), 'PREPARATION')
        elif kind == 'attempt':
            require(phase == 'miner' and prepared is not None and len(available) == len(attempts), 'MINER_DEPENDENCY')
            ordinal = len(attempts); equals(row['ordinal'], ordinal, 'ATTEMPT_ORDINAL')
            require(ordinal < o['max_attempts'] and row['node_or_verifier_called'] is False, 'MINER_SCOPE')
            for key in ('begin', 'trace_done', 'proof_ready'): p.stamp(row[key])
            p.before(last['observed'], row['begin'], 'ATTEMPT_START_ORDER')
            p.before(origin, row['begin'], 'ATTEMPT_ORIGIN'); p.before(row['begin'], row['trace_done'], 'TRACE_ORDER')
            p.before(row['trace_done'], row['proof_ready'], 'ASSEMBLY_ORDER'); p.before(row['proof_ready'], row['observed'], 'PROOF_ORDER')
            require(row['begin']['process_cpu_ns'] - origin['process_cpu_ns'] < o['miner_budget_ns'], 'START_AFTER_B')
            st = statement(row['statement'], context['genesis'])
            header = dict(setup['header']); header['nonce'] = (1 << 63) + o['seed'] * 4096 + ordinal
            require(st['raw'] == p.header_encode(header), 'EXACT_CHALLENGE_SCHEDULE')
            full = o['mode'] == 'eager' or st['hit']
            require((row['proof'] is not None) == full, 'WINNER_ONLY_ASSEMBLY')
            if full: st['proof'] = proof(row['proof'], st); replayed += 1
            else: st['proof'] = None
            st['begin'] = row['begin']; st['trace_done'] = row['trace_done']; st['proof_ready'] = row['proof_ready']
            attempts.append(st)
        elif kind == 'available':
            require(phase == 'miner' and last['kind'] == 'attempt' and len(attempts) == len(available) + 1, 'AVAILABILITY_ORDER')
            ordinal = len(available); equals(row['ordinal'], ordinal, 'AVAILABILITY_ORDINAL')
            p.stamp(row['available']); p.before(last['observed'], row['available'], 'AFTER_ORIGINAL_FLUSH'); p.before(row['available'], row['observed'], 'AVAILABILITY_OBSERVED')
            elapsed = row['available']['process_cpu_ns'] - origin['process_cpu_ns']
            expected = (elapsed, elapsed <= o['miner_budget_ns'], attempts[ordinal]['proof'] is not None, True)
            equals(tuple(row[k] for k in ('elapsed_cpu_ns', 'within_miner_budget', 'full_proof_flushed', 'original_trace_flushed')), expected, 'AVAILABILITY_BINDING')
            available.append(row)
        elif kind == 'receiver':
            require(phase == 'receiver', 'RECEIVER_PHASE')
            winners = [i for i, a in enumerate(attempts) if a['hit']]
            require(len(receivers) < len(winners), 'EXCESS_RECEIVER')
            ordinal = winners[len(receivers)]; a = attempts[ordinal]
            equals(tuple(row[k] for k in FIELDS['receiver'].split()), (ordinal, a['block'], available[ordinal]['within_miner_budget'], True, False), 'RECEIVER_BINDING')
            receivers.append(row)
        elif kind == 'audit':
            require(phase == 'audit' and len(audits) < len(attempts), 'AUDIT_PHASE_COUNT')
            ordinal = len(audits); a = attempts[ordinal]
            equals(tuple(row[k] for k in ('ordinal', 'full_relation', 'reference_relation', 'actual_target_hit', 'posthoc_new_credit', 'provides_miner_feedback')),
                   (ordinal, True, True, a['hit'], 0, False), 'AUDIT_BINDING')
            require((row['posthoc_proof'] is not None) == (a['proof'] is None), 'POSTHOC_PROOF_SCOPE')
            if row['posthoc_proof'] is not None: proof(row['posthoc_proof'], a); replayed += 1
            audits.append(row)
        elif kind == 'setup-reconstruction':
            require(phase == 'audit' and setup is not None and len(audits) == len(attempts), 'RECONSTRUCTION_ORDER')
            nonce = len(reconstructions); require(nonce <= setup['header']['nonce'], 'RECONSTRUCTION_CAP')
            st = statement(row['statement'], context['genesis']); header = dict(setup['header']); header['nonce'] = nonce
            require(st['raw'] == p.header_encode(header), 'RECONSTRUCTION_HEADER')
            raw = proof(row['proof'], st); replayed += 1
            winner = nonce == setup['header']['nonce']
            equals((row['nonce'], row['original_winner'], row['original_bytes_observed'], row['new_work_credit'], st['hit']),
                   (nonce, winner, winner, 0, winner), 'RECONSTRUCTION_CREDIT')
            if winner: require(raw == setup['proof'], 'ORIGINAL_WINNER_BYTES')
            reconstructions.append(row)
        elif kind == 'end': require(phase == 'done' and row is end, 'END_ORDER')
        else: raise ValueError('UNEXPECTED_KIND')
        last = row
    equals(list(boundaries), list(PHASES[:-1]), 'ALL_BOUNDARIES')
    require(len(attempts) == len(available) == len(audits), 'ALL_ATTEMPTS_ACCOUNTED')
    require(len(receivers) == sum(a['hit'] for a in attempts), 'ALL_WINNERS_RECEIVED')
    equals(len(reconstructions), 0 if setup is None else setup['header']['nonce'] + 1, 'ALL_SETUP_ATTEMPTS')
    p.stamp(end['setup_completed_at']); p.before(end['setup_completed_at'], boundaries['setup']['end'], 'SETUP_COMPLETION_BOUNDARY')
    if prepared: p.before(prepared['observed'], end['setup_completed_at'], 'SETUP_PREPARATION_FLUSH')
    setup_complete = prepared is not None and end['setup_completed_at']['process_cpu_ns'] <= o['setup_budget_ns']
    require(setup_complete or not attempts, 'INCOMPLETE_SETUP_NO_MINING')
    require(not setup_complete or len(attempts) == o['max_attempts'] or phase_cpu['miner'] >= o['miner_budget_ns'], 'PREMATURE_MINER_STOP')
    within = [i for i, a in enumerate(available) if a['within_miner_budget']]
    expected_end = dict(status='PASS', setup_complete=setup_complete, setup_completed_at=end['setup_completed_at'],
        attempts=len(attempts), traces_available_by_B=len(within), full_proofs_available_by_B=sum(attempts[i]['proof'] is not None for i in within),
        full_winners_available_by_B=sum(attempts[i]['hit'] for i in within), native_accepted=len(receivers),
        native_accepted_from_B=sum(attempts[i]['hit'] for i in within), censored_by_attempt_cap=len(attempts) == o['max_attempts'],
        phase_cpu_ns=phase_cpu, native_total_endpoint=end['native_total_endpoint'], candidate_chain_activation=False,
        minimum_attacker_cost_established=False, production_activation=False)
    equals({k: end[k] for k in FIELDS['end'].split()}, expected_end, 'END_RECONCILIATION')
    p.stamp(end['native_total_endpoint']); p.before(origin, end['native_total_endpoint'], 'TOTAL_ENDPOINT'); p.before(end['native_total_endpoint'], end['observed'], 'END_OBSERVATION')
    identities = [a['identity'] for a in attempts]
    require(len(set(identities)) == len(identities) and (setup is None or setup['identity'] not in identities), 'UNIQUE_OPPORTUNITIES')
    return dict(schema='pon-w1-late-assembly-readback-v1', raw_path=str(path), raw_bytes=total, raw_sha256=digest.hexdigest(),
        options=o, rows=len(rows), full_proof_records_replayed=replayed, **expected_end,
        total_process_cpu_ns=end['native_total_endpoint']['process_cpu_ns'], total_wall_ns=end['native_total_endpoint']['wall_ns'],
        original_miner_full_proofs=sum(a['proof'] is not None for a in attempts),
        posthoc_miss_proofs=sum(a['proof'] is None for a in attempts),
        late_attempts=len(attempts)-len(within), late_winners=sum(a['hit'] for i,a in enumerate(attempts) if i not in within),
        setup_statement=None if setup is None else dict(header_hex=setup['raw'].hex(), proof_sha256=hashlib.sha256(setup['proof']).hexdigest()),
        opportunity_identities=identities, hit_sequence=[a['hit'] for a in attempts],
        trace_kernel_cpu_ns=sum(a['trace_done']['process_cpu_ns']-a['begin']['process_cpu_ns'] for a in attempts),
        assembly_and_ticket_cpu_ns=sum(a['proof_ready']['process_cpu_ns']-a['trace_done']['process_cpu_ns'] for a in attempts),
        original_node_admission_is_source_bound_observation=True, physical_or_clock_attestation=False)
