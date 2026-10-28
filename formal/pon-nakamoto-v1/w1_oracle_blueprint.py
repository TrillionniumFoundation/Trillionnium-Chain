#!/usr/bin/env python3
"""Constructive, deliberately loose complete-W1 logical circuit cost bound.

The reusable gate templates are actually built. The full fixed-control-flow
wiring is specified as a hierarchical schedule, not expanded into billions of
gates or run on quantum hardware. This is one upper-bound construction, never a
least-cost claim, quantum security bound, or calibrated physical mining rate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from reversible_bits import Circuit, ZERO, ONE

ROOT = Path(__file__).resolve().parents[2]
N, R, Q = 64, 8, (1 << 32) - 5
NATIVE_WORK_BLOB = 'edc516a57cd57ecd8a80a059cc5ed98e997b745c'
REFERENCE_BLOB = '9cbfccd2d50af48fc43522b967ffdfb1f45ec098'
PROFILE = 'pon-w1-retain-all-logical-oracle-blueprint-v1'
IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


def sha256_compression():
    circuit = Circuit()
    initial = [circuit.input(32) for _ in range(8)]
    words = [circuit.input(32) for _ in range(16)]

    def rotate(word, shift):
        return [word[(bit + shift) % 32] for bit in range(32)]

    def right(word, shift):
        return word[shift:] + [ZERO] * shift

    def xor3(a, b, c):
        return [circuit.xor(circuit.xor(x, y), z) for x, y, z in zip(a, b, c)]

    def total(*values):
        result = values[0]
        for value in values[1:]:
            result = circuit.add(result, value)[0]
        return result

    for index in range(16, 64):
        a, b = words[index - 15], words[index - 2]
        small0 = xor3(rotate(a, 7), rotate(a, 18), right(a, 3))
        small1 = xor3(rotate(b, 17), rotate(b, 19), right(b, 10))
        words.append(total(words[index - 16], small0, words[index - 7], small1))
    a, b, c, d, e, f, g, h = initial
    for index in range(64):
        big1 = xor3(rotate(e, 6), rotate(e, 11), rotate(e, 25))
        choice = [circuit.xor(circuit.land(x, y), circuit.land(circuit.neg(x), z))
                  for x, y, z in zip(e, f, g)]
        first = total(h, big1, choice, circuit.constant(K[index], 32), words[index])
        big0 = xor3(rotate(a, 2), rotate(a, 13), rotate(a, 22))
        majority = [circuit.xor(circuit.xor(circuit.land(x, y), circuit.land(x, z)),
                               circuit.land(y, z)) for x, y, z in zip(a, b, c)]
        second = total(big0, majority)
        a, b, c, d, e, f, g, h = total(first, second), a, b, c, total(d, first), e, f, g
    output = [total(x, y) for x, y in zip(initial, (a, b, c, d, e, f, g, h))]
    return circuit, output


def dot8(width=32, terms=8):
    modulus = (1 << width) - 5
    if width < 3 or terms < 1:
        raise ValueError('supported positive arithmetic dimensions required')
    circuit = Circuit()
    previous = circuit.input(width)
    operands = [(circuit.input(width), circuit.input(width)) for _ in range(terms)]
    # Native W1's 8 products plus a prior prefix fit below 2**67. 70 is a
    # conservative fixed accumulator width, not the Rust u128 storage width.
    accumulator_width = 2 * width + terms.bit_length() + 2
    accumulator = previous + [ZERO] * (accumulator_width - width)
    for a, b in operands:
        product = circuit.multiply(a, b)
        accumulator = circuit.add(accumulator, product + [ZERO] * (accumulator_width - len(product)))[0]
    result = circuit.remainder(accumulator, modulus)
    return circuit, [result]


def field_add(width=32):
    circuit = Circuit()
    a, b = circuit.input(width), circuit.input(width)
    total, carry = circuit.add(a, b)
    return circuit, [circuit.remainder(total + [carry], (1 << width) - 5)]


def compact_step(width=32, slots=512):
    """Saturating, coherent first-valid-words selection; no data-dependent exit."""
    if width < 3 or not 1 <= slots <= 512:
        raise ValueError('unsupported compactor dimensions')
    circuit = Circuit()
    value = circuit.input(width)
    count = circuit.input(slots.bit_length())
    previous = [circuit.input(width) for _ in range(slots)]
    below_q = circuit.neg(circuit.le(circuit.constant((1 << width) - 5, width), value))
    not_full = circuit.neg(circuit.le(circuit.constant(slots, len(count)), count))
    take = circuit.land(below_q, not_full)
    output = []
    for index, old in enumerate(previous):
        selected = circuit.land(take, circuit.equal_constant(count, index))
        output.append([circuit.mux(selected, a, b) for a, b in zip(old, value)])
    following = circuit.add(count, [take] + [ZERO] * (len(count) - 1))[0]
    ready = circuit.equal_constant(following, slots)
    return circuit, [following, [ready], *output]


def predicate(ticket_width=256, nonce_width=64):
    circuit = Circuit()
    ticket, target = circuit.input(ticket_width), circuit.input(ticket_width)
    valid = circuit.input(4)
    nonce, first, last = [circuit.input(nonce_width) for _ in range(3)]
    marked = circuit.le(ticket, target)
    marked = circuit.land(marked, circuit.neg(circuit.equal_constant(target, 0)))
    for flag in valid:
        marked = circuit.land(marked, flag)
    marked = circuit.land(marked, circuit.le(first, nonce))
    marked = circuit.land(marked, circuit.le(nonce, last))
    return circuit, [[marked]]


def padded_blocks(message):
    if len(message) >= 1 << 61:
        raise ValueError('SHA-256 length outside this bounded experiment')
    padded = message + b'\x80'
    padded += bytes((56 - len(padded) % 64) % 64)
    padded += struct.pack('>Q', len(message) * 8)
    return [padded[index:index + 64] for index in range(0, len(padded), 64)]


def framed(tag, *parts):
    tag = tag.encode('ascii')
    return (b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag
            + b''.join(struct.pack('<I', len(part)) + part for part in parts))


def padded_noise(challenge, label):
    words = [0] * (N * R)
    accepted = 0
    for counter in range(128):
        digest = hashlib.sha256(framed('noise', challenge, bytes([label]),
                                      struct.pack('<I', counter))).digest()
        for (value,) in struct.iter_unpack('<I', digest):
            if value < Q and accepted < len(words):
                words[accepted] = value
                accepted += 1
    return words, accepted == N * R


def full_forward(challenge, a, b):
    """Classical value interpreter for the prescribed complete padded schedule.

    Arithmetic here is a fast value interpreter. Actual gate-level tests run the
    reusable templates separately; this function is not a full gate simulation.
    """
    if len(challenge) != 32 or len(a) != N * N or len(b) != N * N:
        raise ValueError('W1 dimensions')
    if any(type(value) is not int or not 0 <= value < Q for value in (*a, *b)):
        raise ValueError('W1 field')
    pairs = [padded_noise(challenge, label) for label in range(4)]
    el, er, fl, fr = [pair[0] for pair in pairs]

    def multiply(left, right):
        return [sum(left[i * R + k] * right[k * N + j] for k in range(R)) % Q
                for i in range(N) for j in range(N)]

    ap = [(x + y) % Q for x, y in zip(a, multiply(el, er))]
    bp = [(x + y) % Q for x, y in zip(b, multiply(fl, fr))]
    trace = hashlib.sha256(b'TRNM-PON-TRACE1\0' + challenge)
    prefixes = 0
    for bi in range(N // R):
        for bj in range(N // R):
            prior = [0] * (R * R)
            for bk in range(N // R):
                current = []
                for i in range(R):
                    for j in range(R):
                        value = prior[i * R + j] + sum(
                            ap[(bi * R + i) * N + k] * bp[k * N + bj * R + j]
                            for k in range(bk * R, (bk + 1) * R))
                        current.append(value % Q)
                trace.update(struct.pack('<64I', *current))
                prior = current
                prefixes += 1
    digest = trace.digest()
    return {'trace': digest, 'ticket': hashlib.sha256(framed('ticket', challenge, digest)).digest(),
            'noise_valid': all(pair[1] for pair in pairs), 'prefix_tiles': prefixes}


def source_binding():
    bindings = []
    for path, expected in [
        ('trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs', NATIVE_WORK_BLOB),
        ('formal/pon-nakamoto-v1/work_oracle.py', REFERENCE_BLOB),
    ]:
        raw = (ROOT / path).read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if blob != expected:
            raise ValueError('native/reference source drift: ' + path)
        bindings.append({'path': path, 'git_blob': blob, 'sha256': hashlib.sha256(raw).hexdigest()})
    for path in ('reversible_bits.py', 'w1_oracle_blueprint.py'):
        raw = Path(__file__).with_name(path).read_bytes()
        bindings.append({'path': 'formal/pon-nakamoto-v1/' + path,
                         'sha256': hashlib.sha256(raw).hexdigest()})
    return bindings


def report():
    bindings = source_binding()
    templates = {}
    for name, builder in [('sha256_compression', sha256_compression), ('dot8', dot8),
                          ('field_add', field_add), ('compact_step', compact_step),
                          ('predicate', predicate)]:
        circuit, output = builder()
        templates[name] = circuit.summary(output)
    schedule = [
        ('header_challenge_after_five_classical_prefix_blocks', 'sha256_compression', 1),
        ('all_four_noise_arrays_128_hashes_each', 'sha256_compression', 4 * 128 * 2),
        ('all_eight_words_of_every_noise_digest', 'compact_step', 4 * 128 * 8),
        ('E_and_F_all_cells', 'dot8', 2 * N * N),
        ('A_plus_E_and_B_plus_F', 'field_add', 2 * N * N),
        ('all_512_ordered_transcript_tiles', 'dot8', (N // R) ** 3 * R * R),
        ('one_streaming_transcript_hash', 'sha256_compression', 2049),
        ('ticket_hash', 'sha256_compression', 2),
        ('target_noise_and_nonce_range', 'predicate', 1),
    ]
    stages = []
    total = dict(x=0, cnot=0, toffoli=0, gates=0, logical_qubits=0, input_bits=0, output_bits=0)
    for name, template, calls in schedule:
        costs = {key: templates[template][key] * calls for key in total}
        stages.append({'stage': name, 'template': template, 'calls': calls, **costs})
        for key, value in costs.items():
            total[key] += value
    # Every macro call receives fresh input-port registers. At most one X or
    # CNOT loads each port from a constant or an earlier wire. Retaining all
    # ports/work registers until the outer adjoint avoids hidden free erasure.
    oracle_toffoli = 2 * total['toffoli']
    oracle_clifford_upper = 2 * (total['x'] + total['cnot'] + total['input_bits']) + 1
    return {
        'schema': PROFILE, 'production_activation': False,
        'native_consensus_source_binding': bindings,
        'construction': {'logical_gate_set': ['X', 'CNOT', 'Toffoli', 'Z'],
                         'retains_all_intermediates': True, 'fresh_input_ports_per_call': True,
                         'coherent_padded_noise_calls': 512, 'coherent_noise_candidate_words': 4096,
                         'trace_prefix_tiles': 512, 'trace_prefix_field_words': 32768,
                         'sha256_compression_calls_per_forward': 3076,
                         'mathematical_multiply_accumulate_terms': 327680,
                         'field_reductions': 49152, 'accumulator_bits': 70,
                         'header_midstate_classical_setup_blocks': 5,
                         'cached_AB_setup_excluded_from_queries': True,
                         'fixed_material_mode': 'compile public A/B and context constants; no QRAM assumption',
                         'noise_failure_behavior': 'all operations execute; failed arrays are coherently unmarked',
                         'bit_permutation_mode': 'logical wire naming with unrestricted connectivity'},
        'templates': templates, 'forward_schedule': stages,
        'clean_phase_oracle_upper_bound': {
            'toffoli': oracle_toffoli,
            'clifford_before_toffoli_decomposition_upper': oracle_clifford_upper,
            't_count_using_exact_7T_toffoli': 7 * oracle_toffoli,
            'retained_logical_qubits_upper': 64 + total['logical_qubits'],
            'serial_logical_gate_depth_upper': oracle_toffoli + oracle_clifford_upper,
            'includes_forward_phase_adjoint_and_input_loading': True,
        },
        'clean_macro_result_history_alternative_upper_bound': {
            'construction': 'each macro computes, copies all output bits, uncomputes scratch, unloads input ports; retain output history until outer adjoint',
            'toffoli': 4 * total['toffoli'],
            'clifford_before_toffoli_decomposition_upper':
                4 * (total['x'] + total['cnot'] + total['input_bits']) + 2 * total['output_bits'] + 1,
            't_count_using_exact_7T_toffoli': 28 * total['toffoli'],
            'persistent_result_history_bits': total['output_bits'],
            'reusable_scratch_qubits_upper': max(template['logical_qubits'] for template in templates.values()),
            'logical_qubits_upper': 64 + total['output_bits'] + max(template['logical_qubits'] for template in templates.values()),
            'each_erasure_replaced_with_explicit_adjoint': True,
            'result_history_pebbling_or_in_place_compaction_optimized': False,
        },
        'sixty_four_bit_diffusion_separate': {
            'construction': '62-AND ancilla ladder, one CZ, then inverse ladder; H/X on all 64 bits',
            'toffoli': 124, 't_count_using_exact_7T_toffoli': 868,
            'clifford_before_toffoli_decomposition': 257, 'ancilla_qubits': 62,
        },
        'search_model': {'approximate_iterations_for_known_fraction': 'pi/(4*sqrt(p)); conditional ideal amplitude amplification',
                         'nonce_search_domain_size': str(1 << 64),
                         'actual_marked_fraction': None,
                         'setup_and_winning_witness_and_admission_costs_separate': True,
                         'isolated_rate_r_0_25_derived_from_this_construction': False},
        'qualification': {'gate_templates_materialized': True,
                          'whole_circuit_gate_list_expanded': False,
                          'whole_circuit_quantum_state_simulated': False,
                          'hierarchical_wiring_formally_verified': False,
                          'lowest_cost_legal_oracle': False,
                          'quantum_security_lower_bound': False,
                          'quantum_resource_estimate_physical': None,
                          'noise_distribution_or_ticket_independence_proved': False,
                          'whole_chain_post_quantum': False},
        'required_competitors': ['paired multiplication', 'periodic maintenance prefix reuse',
                                'rank-bounded complete prefix producer', 'reversible pebbling and faster modular arithmetic'],
        'primary_references': ['https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf',
                               'https://arxiv.org/abs/1210.0974', 'https://arxiv.org/abs/2403.08023'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    raw = json.dumps(report(), sort_keys=True, indent=2) + '\n'
    if args.output:
        with args.output.open('x') as stream:
            stream.write(raw)
    else:
        print(raw, end='')


if __name__ == '__main__':
    main()
