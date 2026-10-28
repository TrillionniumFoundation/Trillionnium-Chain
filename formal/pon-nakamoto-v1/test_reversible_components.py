"""Classical basis controls on concrete reversible component netlists."""

import unittest

from reversible_components import (
    Circuit,
    decode,
    field_multiply,
    sha256_compression,
    circuit_sha256,
)


class ReversibleTests(unittest.TestCase):
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
        c = sha256_compression()
        actual, blocks = circuit_sha256(c, b"abc")
        self.assertEqual(blocks, 1)
        self.assertEqual(
            actual.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


if __name__ == "__main__":
    unittest.main()
