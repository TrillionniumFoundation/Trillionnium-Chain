"""Actual logical-gate controls; full W1 differential uses a fast value interpreter.

No test turns a classical replay into a whole-circuit quantum simulation.
"""
import hashlib
import itertools
import random
import struct
import unittest

from reversible_bits import Circuit
import w1_oracle_blueprint as blueprint
import work_oracle
from contract_wire import H


class Arithmetic(unittest.TestCase):
    def test_compute_copy_uncompute_really_clears_scratch(self):
        original, output = blueprint.dot8(width=4, terms=2)
        clean, copied = original.clean_copy(output)
        values = [10, 9, 8, 7, 6]
        self.assertEqual(clean.evaluate(values, copied, check_adjoint=True),
                         [(10 + 9 * 8 + 7 * 6) % 11])
        state = bytearray(clean.width)
        for value, wires in zip(values, clean.inputs):
            for bit, wire in enumerate(wires):
                state[wire] = value >> bit & 1
        clean.run_gates(state)
        input_wires = {wire for word in clean.inputs for wire in word}
        copied_wires = {wire for word in copied for wire in word}
        self.assertTrue(all(value == 0 for wire, value in enumerate(state)
                            if wire not in input_wires | copied_wires))

    def test_remainder_all_small_inputs_and_adjoint(self):
        for modulus in (3, 7, 11, 13):
            circuit = Circuit()
            value = circuit.input(8)
            output = [circuit.remainder(value, modulus)]
            for number in range(256):
                self.assertEqual(circuit.evaluate([number], output, check_adjoint=True), [number % modulus])

    def test_modular_add_all_small_inputs_and_adjoint(self):
        circuit, output = blueprint.field_add(4)
        for a, b in itertools.product(range(11), repeat=2):
            self.assertEqual(circuit.evaluate([a, b], output, check_adjoint=True), [(a + b) % 11])

    def test_actual_dot_gate_template_at_boundary_and_random_values(self):
        circuit, output = blueprint.dot8()
        rng = random.Random(943711)
        samples = [[0] * 17, [blueprint.Q - 1] * 17,
                   [blueprint.Q - 1] + [value for i in range(8) for value in (0, blueprint.Q - 1)],
                   *[[rng.randrange(blueprint.Q) for _ in range(17)] for _ in range(5)]]
        for values in samples:
            expected = (values[0] + sum(values[i] * values[i + 1] for i in range(1, 17, 2))) % blueprint.Q
            self.assertEqual(circuit.evaluate(values, output, check_adjoint=True), [expected])
        for gate in circuit.gates:
            self.assertEqual(len(set(gate[1:])), len(gate) - 1)


class BoundedControlFlow(unittest.TestCase):
    def test_rejection_compaction_exhaustion_saturation_and_adjoint(self):
        circuit, output = blueprint.compact_step(width=4, slots=4)
        streams = [[11, 15, 10, 0, 13, 9, 1, 8], [11] * 16,
                   [3, 15, 4, 11, 5], [10, 9, 8, 7, 6, 5, 4, 3]]
        for stream in streams:
            count, state = 0, [0] * 4
            for value in stream:
                observed = circuit.evaluate([value, count, *state], output, check_adjoint=True)
                count, ready, *state = observed
            selected = [value for value in stream if value < 11][:4]
            self.assertEqual(count, len(selected))
            self.assertEqual(state, selected + [0] * (4 - len(selected)))
            self.assertEqual(ready, int(len(selected) == 4))

    def test_actual_32bit_noise_boundary(self):
        circuit, output = blueprint.compact_step(width=32, slots=2)
        for value in (0, blueprint.Q - 1, blueprint.Q, (1 << 32) - 1):
            observed = circuit.evaluate([value, 0, 0, 0], output, check_adjoint=True)
            accepted = value < blueprint.Q
            self.assertEqual(observed, [int(accepted), 0, value if accepted else 0, 0])

    def test_phase_predicate_target_nonce_noise_and_cleanup(self):
        circuit, output = blueprint.predicate(ticket_width=4, nonce_width=3)
        cases = itertools.product((0, 1, 7, 15), (0, 1, 7, 15), (0, 14, 15), range(8))
        for ticket, target, flags, nonce in cases:
            expected = target > 0 and ticket <= target and flags == 15 and 2 <= nonce <= 5
            self.assertEqual(circuit.evaluate([ticket, target, flags, nonce, 2, 5],
                                             output, check_adjoint=True), [int(expected)])
        self.assertEqual(circuit.evaluate([0, 15, 15, 3, 5, 2], output, check_adjoint=True), [0])


class ShaAndCompleteRelation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.circuit, cls.output = blueprint.sha256_compression()

    def test_real_sha_gate_sequence_multiple_padding_boundaries(self):
        # Independent hashlib evaluates the complete messages; every block here
        # actually passes through the materialized X/CNOT/Toffoli gate sequence.
        for length in (0, 3, 55, 56, 64, 66, 90, 343):
            message = bytes((i * 37 + 11) % 256 for i in range(length))
            state = list(blueprint.IV)
            for block in blueprint.padded_blocks(message):
                state = self.circuit.evaluate([*state, *struct.unpack('>16I', block)],
                                              self.output, check_adjoint=True)
            self.assertEqual(struct.pack('>8I', *state), hashlib.sha256(message).digest())

    def test_full_padded_schedule_matches_independent_complete_relation(self):
        samples = [([0] * 4096, [0] * 4096),
                   ([(i * 9187 + 31) % blueprint.Q for i in range(4096)],
                    [(i * i * 131 + 17) % blueprint.Q for i in range(4096)])]
        for index, (a, b) in enumerate(samples):
            challenge = hashlib.sha256(b'complete-w1-circuit-control' + bytes([index])).digest()
            actual = blueprint.full_forward(challenge, a, b)
            product, trace = work_oracle.evaluate(challenge, a, b)
            self.assertEqual(trace, actual['trace'])
            self.assertEqual(H('ticket', challenge, trace), actual['ticket'])
            self.assertTrue(actual['noise_valid'])
            self.assertEqual(actual['prefix_tiles'], 512)
            self.assertEqual(product, work_oracle.mm(a, b, 64, 64, 64))
            for label in range(4):
                self.assertEqual(blueprint.padded_noise(challenge, label)[0],
                                 work_oracle.expand(challenge, label, 512))

    def test_exact_message_framing_and_fixed_nonce_midstate(self):
        header = bytes((i * 19 + 3) % 256 for i in range(310)) + struct.pack('<Q', 11)
        changed = header[:-8] + struct.pack('<Q', (1 << 64) - 1)
        message = blueprint.framed('challenge', header)
        blocks = blueprint.padded_blocks(message)
        other = blueprint.padded_blocks(blueprint.framed('challenge', changed))
        self.assertEqual(len(message), 343)
        self.assertEqual(len(blocks), 6)
        self.assertEqual(blocks[:5], other[:5])
        self.assertNotEqual(blocks[5], other[5])
        self.assertEqual(hashlib.sha256(message).digest(), H('challenge', header))
        self.assertEqual(len(blueprint.framed('noise', bytes(32), b'\0', bytes(4))), 66)
        self.assertEqual(len(blueprint.framed('ticket', bytes(32), bytes(32))), 90)
        self.assertEqual(len(blueprint.padded_blocks(bytes(131120))), 2049)


class Scope(unittest.TestCase):
    def test_actual_bound_keeps_unknowns_and_full_control_flow(self):
        report = blueprint.report()
        construction = report['construction']
        self.assertEqual(construction['sha256_compression_calls_per_forward'],
                         sum(stage['calls'] for stage in report['forward_schedule']
                             if stage['template'] == 'sha256_compression'))
        self.assertEqual(construction['field_reductions'], 40960 + 8192)
        self.assertFalse(report['qualification']['whole_circuit_gate_list_expanded'])
        self.assertFalse(report['qualification']['lowest_cost_legal_oracle'])
        self.assertIsNone(report['qualification']['quantum_resource_estimate_physical'])
        self.assertFalse(report['search_model']['isolated_rate_r_0_25_derived_from_this_construction'])
        bound = report['clean_phase_oracle_upper_bound']
        actual_forward = sum(stage['toffoli'] for stage in report['forward_schedule'])
        self.assertEqual(bound['toffoli'], 2 * actual_forward)
        self.assertGreater(actual_forward, report['templates']['sha256_compression']['toffoli'])


if __name__ == '__main__':
    unittest.main()
