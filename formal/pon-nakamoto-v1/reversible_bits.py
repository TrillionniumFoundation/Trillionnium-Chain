"""Small explicit X/CNOT/Toffoli circuits, retaining every intermediate.

These are logical gates with unrestricted connectivity. There is no measurement,
reset, free erasure, hardware scheduler, QROM, or relative-phase Toffoli here.
New Boolean outputs start in zero ancillas; their adjoint restores those zeros.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json

ZERO, ONE = -1, -2


class Circuit:
    def __init__(self):
        self.width = 0
        self.inputs = []
        self.gates = []

    def _wire(self):
        wire = self.width
        self.width += 1
        return wire

    def input(self, width):
        if type(width) is not int or width < 1 or self.gates:
            raise ValueError('declare positive-width inputs before gates')
        wires = [self._wire() for _ in range(width)]
        self.inputs.append(wires)
        return wires

    @staticmethod
    def constant(value, width):
        if type(value) is not int or not 0 <= value < (1 << width):
            raise ValueError('unsigned constant out of range')
        return [ONE if value >> bit & 1 else ZERO for bit in range(width)]

    def neg(self, a):
        if a < 0:
            return ZERO if a == ONE else ONE
        target = self._wire()
        self.gates.extend([('X', target), ('CX', a, target)])
        return target

    def xor(self, a, b):
        if a == b:
            return ZERO
        if a == ZERO:
            return b
        if b == ZERO:
            return a
        if a == ONE:
            return self.neg(b)
        if b == ONE:
            return self.neg(a)
        target = self._wire()
        self.gates.extend([('CX', a, target), ('CX', b, target)])
        return target

    def land(self, a, b):
        if ZERO in (a, b):
            return ZERO
        if a == b or b == ONE:
            return a
        if a == ONE:
            return b
        target = self._wire()
        self.gates.append(('CCX', a, b, target))
        return target

    def mux(self, select, old, new):
        return self.xor(old, self.land(select, self.xor(old, new)))

    def add(self, a, b, carry=ZERO):
        if len(a) != len(b) or not a:
            raise ValueError('equal positive word widths required')
        result = []
        for x, y in zip(a, b):
            parity = self.xor(x, y)
            result.append(self.xor(parity, carry))
            # The two carry terms are mutually exclusive, so XOR is OR here.
            carry = self.xor(self.land(x, y), self.land(parity, carry))
        return result, carry

    def sub(self, a, b):
        return self.add(a, [self.neg(bit) for bit in b], ONE)

    def le(self, a, b):
        # Carry of b + ~a + 1 means b >= a, including equality.
        return self.sub(b, a)[1]

    def equal_constant(self, word, constant):
        expected = self.constant(constant, len(word))
        equal = ONE
        for bit, value in zip(word, expected):
            equal = self.land(equal, bit if value == ONE else self.neg(bit))
        return equal

    def multiply(self, a, b):
        width = len(a) + len(b)
        result = [ZERO] * width
        for shift, bit in enumerate(b):
            row = [ZERO] * shift + [self.land(x, bit) for x in a]
            row += [ZERO] * (width - len(row))
            result = self.add(result, row)[0]
        return result

    def remainder(self, word, modulus):
        if type(modulus) is not int or modulus < 2:
            raise ValueError('positive constant modulus required')
        width = modulus.bit_length()
        divisor = self.constant(modulus, width + 1)
        remainder = [ZERO] * (width + 1)
        # At each step prior remainder < modulus, hence shifted < 2*modulus.
        for bit in reversed(word):
            shifted = [bit] + remainder[:-1]
            difference, no_borrow = self.sub(shifted, divisor)
            remainder = [self.mux(no_borrow, a, b)
                         for a, b in zip(shifted, difference)]
        return remainder[:width]

    @staticmethod
    def bit_value(state, wire):
        return int(wire == ONE) if wire < 0 else state[wire]

    def run_gates(self, state, *, adjoint=False):
        sequence = reversed(self.gates) if adjoint else self.gates
        for gate in sequence:
            if gate[0] == 'X':
                state[gate[1]] ^= 1
            elif gate[0] == 'CX':
                state[gate[2]] ^= state[gate[1]]
            else:
                state[gate[3]] ^= state[gate[1]] & state[gate[2]]

    def evaluate(self, values, outputs, *, check_adjoint=False):
        if len(values) != len(self.inputs):
            raise ValueError('input count mismatch')
        state = bytearray(self.width)
        for value, wires in zip(values, self.inputs):
            if type(value) is not int or not 0 <= value < (1 << len(wires)):
                raise ValueError('input range')
            for bit, wire in enumerate(wires):
                state[wire] = value >> bit & 1
        initial = state[:] if check_adjoint else None
        self.run_gates(state)
        result = [sum(self.bit_value(state, wire) << bit
                      for bit, wire in enumerate(word)) for word in outputs]
        if check_adjoint:
            self.run_gates(state, adjoint=True)
            if state != initial:
                raise AssertionError('adjoint did not restore inputs and all zero ancillas')
        return result

    def summary(self, outputs):
        counts = Counter(gate[0] for gate in self.gates)
        raw = json.dumps({'inputs': self.inputs, 'gates': self.gates,
                          'outputs': outputs}, separators=(',', ':')).encode()
        return {'input_bits': sum(map(len, self.inputs)), 'output_bits': sum(map(len, outputs)),
                'logical_qubits': self.width,
                'retained_ancillas': self.width - sum(map(len, self.inputs)),
                'x': counts['X'], 'cnot': counts['CX'], 'toffoli': counts['CCX'],
                'gates': len(self.gates), 'template_sha256': sha256(raw).hexdigest()}

    def clean_copy(self, outputs):
        """Actual compute-copy-adjoint macro; inputs and copied result survive."""
        clean = Circuit()
        clean.width = self.width
        clean.inputs = [list(wires) for wires in self.inputs]
        clean.gates = list(self.gates)
        copies = []
        for word in outputs:
            copied = []
            for wire in word:
                target = clean._wire()
                if wire == ONE:
                    clean.gates.append(('X', target))
                elif wire != ZERO:
                    clean.gates.append(('CX', wire, target))
                copied.append(target)
            copies.append(copied)
        clean.gates.extend(reversed(self.gates))
        return clean, copies
