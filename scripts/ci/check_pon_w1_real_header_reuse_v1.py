#!/usr/bin/env python3
"""Independent all-attempt relation reader; fixed RPC, owned by the original 120s collector.

No native verifier is imported. Native parent-state/signature observations remain
native observations; this reader does not confer admission or economic authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time

PROFILE = 'pn1-pnh1-signed-zero-fixed-64-reuse-component-v2'
SCHEMA = 'pn1-pnh1-independent-relation-reader-v2'
POLICY = ('pn1-pnh1-frozen-zero-dispatch-v1:canonical-A=B=zero=>'
          'blocked-zero-integer-paired;otherwise-refuse')
STREAM = b'TRNM-PON-W1-PNH1-64REUSE-STREAM-V1\0'
MIB = 1024 * 1024


def require(ok, why):
    if not ok:
        raise ValueError(why)


def uint(value, why, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, why)
    return value


def native_numbers(row):
    """Explicit schema locations: packet.id is a hash, RPC.id is an integer.

    bool is an int subclass and1.0 compares equal to1 in Python. Neither is a
    JSON integer in this protocol. Real target_hit booleans remain booleans.
    """
    uint(row['sequence'], 'SEQUENCE_INTEGER')
    kind = row['kind']
    if kind == 'initialized':
        uint(row['owner_pid'], 'OWNER_PID_INTEGER', minimum=1)
        require(type(row['owner_birth']) is str and row['owner_birth'].isdigit(), 'OWNER_BIRTH_STRING')
        uint(int(row['owner_birth']), 'OWNER_BIRTH_U64')
        for key in ('as_soft', 'as_hard', 'fsize_soft', 'fsize_hard'):
            uint(row['limits'][key], 'LIMIT_INTEGER:' + key, minimum=1)
        for key in ('attempts', 'supported', 'wall_ns', 'cpu_ns'):
            uint(row['selected_setup'][key], 'SETUP_INTEGER:' + key)
        uint(row['production_template_make_calls'], 'TEMPLATE_CALLS_INTEGER')
    elif kind in ('trial_started', 'trial_completed'):
        uint(row['search'], 'SEARCH_INTEGER', maximum=63)
        uint(row['ordinal'], 'ORDINAL_INTEGER', maximum=4095)
        if kind == 'trial_completed':
            uint(row['nonce'], 'NONCE_INTEGER')
            require(type(row['target_hit']) is bool, 'TARGET_HIT_BOOL')
    elif kind == 'response':
        uint(row['id'], 'RPC_ID_INTEGER', maximum=65)
        uint(row['operation_wall_ns'], 'OP_WALL_INTEGER')
        uint(row['operation_cpu_ns'], 'OP_CPU_INTEGER', minimum=1)
        data = row['data']
        if row['op'] == 'initialize':
            uint(data['owner_pid'], 'RESPONSE_OWNER_PID_INTEGER', minimum=1)
            require(data['initialized'] is True, 'INITIALIZED_BOOL')
            require(type(data['owner_birth']) is str and data['owner_birth'].isdigit(), 'RESPONSE_BIRTH_STRING')
        elif row['op'] == 'search':
            uint(data['search'], 'RESULT_SEARCH_INTEGER', maximum=63)
            uint(data['first'], 'FIRST_NONCE_INTEGER')
            uint(data['count_limit'], 'NONCE_LIMIT_INTEGER', minimum=1, maximum=4096)
            uint(data['attempts'], 'ATTEMPTS_INTEGER', minimum=1, maximum=4096)
            uint(data['setup_attempts'], 'SETUP_ATTEMPTS_INTEGER')
            uint(data['supported_setups'], 'SUPPORTED_SETUPS_INTEGER')
            for key in ('wall_ns', 'cpu_ns'):
                uint(data['producer_acquisition'][key], 'ACQUISITION_INTEGER:' + key)
        elif row['op'] == 'seal':
            uint(data['searches'], 'TOTAL_SEARCHES_INTEGER', maximum=64)
            uint(data['same_selected_setup_attempts'], 'TOTAL_SETUP_INTEGER')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def load_module(name, path):
    require(name not in sys.modules, 'AMBIENT_REFERENCE_MODULE_COLLISION')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # work_oracle imports contract_wire by name. Bind the exact source-selected
    # reference, rather than accepting a module found on an ambient sys.path.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emit(value):
    value['schema'] = SCHEMA
    sys.stdout.write(json.dumps(value, separators=(',', ':'), sort_keys=True) + '\n')
    sys.stdout.flush()


def request(expected_id, expected_op):
    raw = sys.stdin.buffer.readline(4097)
    require(raw and raw.endswith(b'\n') and len(raw) <= 4096, 'REQUEST_BOUNDARY')
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {'id', 'op'}, 'REQUEST_FIELDS')
    require(uint(value['id'], 'REQUEST_ID_INTEGER', maximum=65) == expected_id
            and value['op'] == expected_op, 'REQUEST_ORDER')


def packet(row, wire, oracle):
    hb = bytes.fromhex(row['header'])
    h = wire.header_decode(hb)
    require(wire.header_encode(h) == hb, 'HEADER_CANONICAL')
    proof = bytes.fromhex(row['proof'])
    c = wire.H('challenge', hb)
    ticket, product = oracle.verify(c, h['work_task'], h['target'], proof)
    require(ticket <= h['target'] and len(product) == 4096, 'WINNER_RELATION')
    transactions = [bytes.fromhex(t) for t in row['transactions']]
    require(len(transactions) <= 256, 'TX_COUNT')
    for tx in transactions:
        require(159 <= len(tx) <= 2048 and tx[:4] == b'PNX1', 'ENVELOPE_GRAMMAR')
        n = struct.unpack_from('<H', tx, 93)[0]
        require(len(tx) == 159 + n, 'ENVELOPE_LENGTH')
    require(wire.sequence_root('transactions', transactions) == h['transactions'], 'TX_ROOT')
    encoded = hb + struct.pack('<H', len(transactions))
    encoded += b''.join(struct.pack('<H', len(t)) + t for t in transactions) + proof
    require(hashlib.sha256(encoded).hexdigest() == row['encoded_sha256'], 'PACKET_DIGEST')
    require(wire.H('block', hb, proof[-32:]).hex() == row['id'], 'PACKET_ID')
    return h, proof, c, transactions


def read_native(path, pid, birth):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 8 * MIB, 'NATIVE_LOG_BOUNDARY')
    events = []
    with path.open('rb') as stream:
        for sequence, raw in enumerate(stream):
            require(len(raw) <= MIB and raw.endswith(b'\n'), 'FRAME_BOUNDARY')
            row = json.loads(raw, object_pairs_hook=unique)
            require(row['schema'] == PROFILE and row['sequence'] == sequence, 'NATIVE_SEQUENCE')
            require(row['kind'] != 'fatal', 'NATIVE_FATAL')
            require(row['kind'] in ('initialized', 'trial_started', 'trial_completed', 'response'), 'UNKNOWN_EVENT')
            native_numbers(row)
            events.append(row)
    initial = [r for r in events if r['kind'] == 'initialized']
    require(len(initial) == 1, 'INITIALIZATION_COUNT')
    initial = initial[0]
    require(initial['owner_pid'] == pid and initial['owner_birth'] == birth, 'ACTUAL_OWNER_BINDING')
    responses = [r for r in events if r['kind'] == 'response']
    require([uint(r['id'], 'RESPONSE_ID_INTEGER', maximum=65) for r in responses]
            == list(range(66)), 'COMPLETE_RPC_SEQUENCE')
    require([r['op'] for r in responses] == ['initialize'] + ['search'] * 64 + ['seal'], 'OP_SEQUENCE')
    for response in responses:
        require(type(response['operation_cpu_ns']) is int and response['operation_cpu_ns'] > 0, 'CPU_CLOCK_GAP')
    trials = {i: [] for i in range(64)}
    for row in events:
        if row['kind'].startswith('trial_'):
            require(type(row['search']) is int and row['search'] in trials, 'SEARCH_INDEX')
            trials[row['search']].append(row)
    return initial, responses, trials


def run(args):
    request(0, 'initialize')
    started = time.monotonic_ns()
    wire = load_module('contract_wire', args.source / 'formal/pon-nakamoto-v1/contract_wire.py')
    oracle = load_module('pn1_pnh1_work_reference', args.source / 'formal/pon-nakamoto-v1/work_oracle.py')
    initial, responses, trials = read_native(args.native_log, args.native_pid, args.native_birth)
    require(initial['policy'] == POLICY and initial['policy_sha256'] == hashlib.sha256(POLICY.encode()).hexdigest(), 'FROZEN_POLICY')
    require(initial['arm'] == 'blocked-zero-integer-paired', 'FIXED_ARM')
    require(initial['selected_setup']['attempts'] == initial['selected_setup']['supported'] == 1, 'ONE_SETUP')
    a_bytes = bytes.fromhex(initial['material']['model'])
    b_bytes = bytes.fromhex(initial['material']['input'])
    require(a_bytes == b_bytes == bytes(16384), 'EXACT_CONTROLLED_ZERO_MATERIAL')
    a = [0] * 4096
    b = [0] * 4096
    task = oracle.task_id(a, b)
    require(task.hex() == initial['material']['task'], 'MATERIAL_TASK')
    registration, _, _, txs = packet(initial['registration'], wire, oracle)
    template, _, _, template_tx = packet(initial['template'], wire, oracle)
    require([t[92] for t in txs] == [18, 21], 'REAL_LEASE_TASK_REGISTRATION_ENVELOPES')
    require(txs[0][95:-64].hex() == initial['demand_lease'], 'LEASE_PAYLOAD_BINDING')
    require(txs[1][95:-64].hex() == initial['signed_statement'], 'MANIFEST_PAYLOAD_BINDING')
    require(registration['height'] == 1 and template['height'] == 2, 'REAL_PARENT_HEIGHT')
    require(template['parent'].hex() == initial['registration']['id'] == initial['parent'], 'PARENT_ID')
    require(template['work_task'] == task and not template_tx, 'TEMPLATE_ELIGIBILITY_MATERIAL')
    require(initial['unregistered_error'] == 'TASK' and initial['changed_material_error'] == 'TASK_MATERIAL', 'NEGATIVE_CONTROLS')
    emit({'kind': 'response', 'id': 0, 'op': 'initialize', 'data': {'initialized': True,
         'independent_signature_verification': False, 'independent_parent_state_oracle': False},
         'operation_wall_ns': time.monotonic_ns() - started})
    seen = set()
    verified = []
    total_attempts = 0
    for index in range(64):
        request(index + 1, 'search')
        started = time.monotonic_ns()
        result = responses[index + 1]['data']
        require(result['search'] == index and result['first'] == 1_000_000 + index * 4096, 'FIXED_NONCE_WINDOWS')
        require(result['count_limit'] == 4096 and 1 <= result['attempts'] <= 4096, 'ORIGINAL_NONCE_CAP')
        require(result['setup_attempts'] == result['supported_setups'] == 1, 'SETUP_CONTINUITY')
        rows = trials[index]
        require(len(rows) == 2 * result['attempts'], 'ALL_ATTEMPTS_RETAINED')
        digest = hashlib.sha256(STREAM)
        last_header = None
        last_proof = None
        for ordinal in range(result['attempts']):
            begin, end = rows[2 * ordinal:2 * ordinal + 2]
            require(begin['kind'] == 'trial_started' and end['kind'] == 'trial_completed', 'PARTIAL_TRIAL')
            require(begin['ordinal'] == end['ordinal'] == ordinal, 'ORDINAL_SEQUENCE')
            h = dict(template)
            h['nonce'] = result['first'] + ordinal
            hb = wire.header_encode(h)
            require(begin['header'] == hb.hex(), 'FULL_LEGAL_HEADER_TEMPLATE')
            c = wire.H('challenge', hb)
            require(c not in seen and c.hex() == begin['challenge'], 'DISTINCT_BOUND_CHALLENGE')
            seen.add(c)
            # Recompute every complete proof, including target misses. No setup/N division.
            proof = oracle.prove(c, a, b)
            ticket = wire.H('ticket', c, proof[-32:])
            hit = ticket <= h['target']
            require(end['nonce'] == h['nonce'] and end['ticket'] == ticket.hex(), 'TICKET_REPLAY')
            require(end['proof_sha256'] == hashlib.sha256(proof).hexdigest(), 'FULL_PROOF_REPLAY')
            require(end['target_hit'] is hit and hit == (ordinal == result['attempts'] - 1), 'FIRST_HIT_STOP')
            digest.update(struct.pack('<Q', len(hb)) + hb + struct.pack('<Q', len(proof)) + proof)
            last_header, last_proof = hb, proof
        require(result['stream_sha256'] == digest.hexdigest(), 'COMPLETE_ORDERED_PROOF_STREAM')
        h, proof, _, tx = packet(result['packet'], wire, oracle)
        require(wire.header_encode(h) == last_header and proof == last_proof and not tx, 'ACTUAL_WINNER')
        require(result['ordinary_node_admission'] is True and result['admission_id'] == result['packet']['id'], 'NATIVE_ADMISSION_OBSERVATION')
        total_attempts += result['attempts']
        verified.append({'id': result['admission_id'], 'encoded_sha256': result['packet']['encoded_sha256'],
                         'state_sha256': result['state_sha256']})
        emit({'kind': 'response', 'id': index + 1, 'op': 'search',
              'operation_wall_ns': time.monotonic_ns() - started,
              'data': {'search': index, 'all_attempts_recomputed': result['attempts'],
                       'stream_sha256': digest.hexdigest(), 'complete_relation_verified': True}})
    request(65, 'seal')
    seal = responses[-1]['data']
    require(seal['native_component_completed'] is True and seal['searches'] == 64, 'NATIVE_SEAL')
    uint(total_attempts, 'TOTAL_ATTEMPTS_INTEGER', minimum=64, maximum=64 * 4096)
    require(seal['cold'] == verified and seal['same_selected_setup_attempts'] == 1, 'NATIVE_COLD_READBACK')
    require(seal['scope'] == '64-same-parent-siblings-not-64-successive-parents', 'SCOPE')
    emit({'kind': 'response', 'id': 65, 'op': 'seal', 'data': {
        'independent_relation_component_completed': True, 'searches': 64, 'attempts': total_attempts,
        'same_parent_siblings': True, 'successive_parents': False,
        'independent_signature_verification': False, 'independent_parent_state_oracle': False,
        'whole_13_kernel_matrix_qualified': False, 'native_three_fd_qualified': False,
        'hardware_fairness_qualified': False, 'lowest_known_cost_audit_complete': False,
        'whole_work_hardness_qualified': False, 'full4097_qualified': False, 'merge_ready': False}})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--native-log', type=Path, required=True)
    parser.add_argument('--native-pid', type=int, required=True)
    parser.add_argument('--native-birth', required=True)
    args = parser.parse_args()
    try:
        run(args)
    except Exception as error:
        emit({'kind': 'fatal', 'error': type(error).__name__ + ':' + str(error),
              'independent_relation_component_completed': False, 'whole_work_hardness_qualified': False,
              'merge_ready': False})
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
