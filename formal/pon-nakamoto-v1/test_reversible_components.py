"""Classical basis controls on concrete reversible component netlists."""

import unittest

from reversible_components import (
    Circuit,
    ONE,
    Q,
    ZERO,
    decode,
    field_multiply,
    sha256_compression,
    circuit_sha256,
)


class ReversibleTests(unittest.TestCase):
    @staticmethod
    def copy_fixture():
        c = Circuit()
        inputs = c.input(2)
        scratch = c.allocate()[0]
        c.emit(2, scratch, inputs[0])
        return c.finish([scratch, inputs[1]])

    def test_exported_netlist_reopens_exactly_and_rejects_truncation_or_extra_bytes(
        self,
    ):
        c = field_multiply(4)
        encoded = c.encode()
        reopened = decode(encoded)
        self.assertEqual(reopened.encode(), encoded)
        self.assertEqual(reopened.metrics(), c.metrics())
        self.assertEqual(reopened.basis([13, 15], 3), ((13 * 15) % 11) ^ 3)
        for raw in (encoded[:-1], encoded + b"\0", b"wrong" + encoded):
            with self.subTest(bytes=len(raw)), self.assertRaises(ValueError):
                decode(raw)
        invalid_gate = bytearray(encoded)
        invalid_gate[-1] = 0xF0
        with self.assertRaises(ValueError):
            decode(bytes(invalid_gate))

    def test_modular_multiply_exhaustive_small_width_including_noncanonical_inputs(
        self,
    ):
        circuit = field_multiply(4)
        for a in range(16):
            for b in range(16):
                seed = (a + b) & 15
                self.assertEqual(circuit.basis([a, b], seed), ((a * b) % 11) ^ seed)

    def test_reversible_adder_exhaustive_and_nonzero_output_target(self):
        c = Circuit()
        a, b = c.input(4), c.input(4)
        c.finish(c.add(a, b, 4))
        for left in range(16):
            for right in range(16):
                self.assertEqual(c.basis([left, right], 13), ((left + right) & 15) ^ 13)

    def test_to_invert_requires_every_computation_gate(self):
        c = field_multiply(4)
        # Remove a genuine uncomputation gate. An unchanged numerical output
        # alone cannot pass: the simulator also enforces clean scratch.
        c.gates.pop()
        with self.assertRaisesRegex(ValueError, "dirty ancilla"):
            c.basis([15, 15])

    def test_decoder_rejects_changed_missing_or_reordered_inverse(self):
        changed = self.copy_fixture()
        changed.gates[-1] = (1 << 60) | changed.outputs[0]
        missing = self.copy_fixture()
        missing.gates.pop()
        reordered = Circuit()
        inputs = reordered.input(2)
        xor = reordered.bxor(*inputs)
        both = reordered.band(xor, inputs[0])
        reordered.finish([xor, both])
        count = reordered.compute_gates
        reordered.gates[-count:] = reordered.gates[:count]
        for name, c in (("changed", changed), ("missing", missing),
                        ("reordered", reordered)):
            # All gates, register references and updated lengths remain valid.
            # Reopening must reject before any finite basis sample is run.
            with self.subTest(mutation=name), self.assertRaisesRegex(
                ValueError, "netlist inverse"
            ):
                decode(c.encode())

    def test_decoder_rejects_false_compute_boundary(self):
        for count in (0, 2, 3, 4):
            c = self.copy_fixture()
            c.compute_gates = count
            with self.subTest(compute_gates=count), self.assertRaises(ValueError):
                decode(c.encode())

    def test_decoder_rejects_computation_writes_to_inputs(self):
        c = Circuit()
        inputs = c.input(2)
        c.emit(2, inputs[0], inputs[1])
        c.finish(inputs)
        # Even a matching inverse cannot turn an in-place input write into
        # the declared construction's scratch-only computation.
        with self.assertRaisesRegex(ValueError, "netlist compute writes input"):
            decode(c.encode())

    def test_decoder_rejects_computation_access_to_outputs(self):
        for access in ("target", "first-control", "second-control"):
            c = self.copy_fixture()
            source = c.inputs[0][0]
            scratch = c.gates[0] & ((1 << 20) - 1)
            output = c.outputs[0]
            gate = {
                "target": (1 << 60) | output,
                "first-control": (2 << 60) | (output << 40) | scratch,
                "second-control": (3 << 60) | (source << 40) | (output << 20) | scratch,
            }[access]
            # Preserve exact inverse equality to isolate the output dependency.
            c.gates[0] = c.gates[-1] = gate
            with self.subTest(access=access), self.assertRaisesRegex(
                ValueError, "netlist compute touches output"
            ):
                decode(c.encode())

    def test_decoder_rejects_copy_to_input_or_scratch(self):
        for destination in ("input", "scratch"):
            c = self.copy_fixture()
            target = c.inputs[0][0] if destination == "input" else c.gates[0] & ((1 << 20) - 1)
            c.gates[c.compute_gates] = (1 << 60) | target
            with self.subTest(destination=destination), self.assertRaisesRegex(
                ValueError, "netlist copy target"
            ):
                decode(c.encode())

    def test_decoder_rejects_noncopy_gates_and_output_controls(self):
        for operation in ("toffoli", "output-control"):
            c = self.copy_fixture()
            inputs = c.inputs[0]
            gate = ((3 << 60) | (inputs[0] << 40) | (inputs[1] << 20) | c.outputs[0]
                    if operation == "toffoli" else
                    (2 << 60) | (c.outputs[1] << 40) | c.outputs[0])
            c.gates[c.compute_gates] = gate
            with self.subTest(operation=operation), self.assertRaisesRegex(
                ValueError, "netlist copy"
            ):
                decode(c.encode())

    def test_decoder_rejects_duplicate_copy_destinations(self):
        c = self.copy_fixture()
        c.gates[c.compute_gates + 1] = c.gates[c.compute_gates]
        with self.assertRaisesRegex(ValueError, "netlist duplicate copy target"):
            decode(c.encode())

    def test_decoder_preserves_constants_zero_bits_and_direct_inputs(self):
        c = Circuit()
        inputs = c.input(2)
        c.finish([ZERO, ONE, inputs[0], ZERO, inputs[1]])
        reopened = decode(c.encode())
        self.assertEqual(reopened.encode(), c.encode())
        for value in range(4):
            expected = 2 | ((value & 1) << 2) | ((value >> 1) << 4)
            for seed in (0, 1, 31):
                self.assertEqual(reopened.basis([value], seed), expected ^ seed)

    def test_decoder_preserves_zero_function_without_gates(self):
        for has_inputs in (False, True):
            c = Circuit()
            if has_inputs:
                c.input(2)
            c.finish([ZERO, ZERO, ZERO])
            reopened = decode(c.encode())
            self.assertEqual(reopened.encode(), c.encode())
            self.assertEqual(len(reopened.gates), 0)
            self.assertEqual(reopened.metrics()["compute_gates"], 0)
            values = ([value] for value in range(4)) if has_inputs else ([],)
            for value in values:
                for seed in range(8):
                    self.assertEqual(reopened.basis(value, seed), seed)

    def test_decoder_preserves_compute_inverse_with_no_copy_gates(self):
        c = Circuit()
        inputs = c.input(1)
        scratch = c.allocate()[0]
        c.emit(2, scratch, inputs[0])
        c.finish([ZERO, ZERO])
        reopened = decode(c.encode())
        self.assertEqual(reopened.encode(), c.encode())
        for value in (0, 1):
            for seed in range(4):
                self.assertEqual(reopened.basis([value], seed), seed)

    def test_full_width_modular_multiply_strictly_reopens(self):
        c = decode(field_multiply().encode())
        seed = 0x5A5A5A5A
        for a, b in ((0, 0), (Q - 1, Q - 1), (Q, Q),
                     (Q + 1, (1 << 32) - 1), ((1 << 32) - 1, (1 << 32) - 1)):
            with self.subTest(a=a, b=b):
                self.assertEqual(c.basis([a, b], seed), ((a * b) % Q) ^ seed)

    def test_gate_aliases_and_wrong_input_ranges_fail(self):
        c = Circuit()
        q = c.input(2)
        with self.assertRaises(ValueError):
            c.emit(3, q[0], q[0], q[1])
        c.finish(q)
        for value in (-1, 4, True):
            with self.assertRaises(ValueError):
                c.basis([value])

    def test_full_sha256_rounds_against_published_abc_digest(self):
        c = decode(sha256_compression().encode())
        actual, blocks = circuit_sha256(c, b"abc")
        self.assertEqual(blocks, 1)
        self.assertEqual(
            actual.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


if __name__ == "__main__":
    unittest.main()
