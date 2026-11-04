"""Executable clean-XOR leaves for the constructive W1 phase-oracle schedule.

Every leaf is an actual X/CNOT/Toffoli circuit from the retained gate builder.
The separate integer semantics accelerate macro interpretation; they are not
claimed to be gate execution. Native-sized gate counts use these actual leaves.
"""
from dataclasses import dataclass
from functools import cache
import hashlib

from reversible_components import (
    Circuit, IV, K, ONE, ZERO, constant, field_multiply, sha256_compression,
)


def integer(value, name, low=0, high=(1 << 64) - 1):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(name)
    return value


def sha_compress(message, chaining):
    """Independent word-level SHA-256 compression, in the leaf's word layout."""
    mask = (1 << 32) - 1

    def rotate(x, n):
        return ((x >> n) | (x << (32 - n))) & mask

    words = [(message >> (32 * i)) & mask for i in range(16)]
    initial = [(chaining >> (32 * i)) & mask for i in range(8)]
    for i in range(16, 64):
        x, y = words[i - 15], words[i - 2]
        words.append((words[i - 16] + (rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3))
                      + words[i - 7] + (rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10))) & mask)
    a, b, c, d, e, f, g, h = initial
    for i in range(64):
        t1 = (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25))
              + ((e & f) ^ ((~e) & g)) + K[i] + words[i]) & mask
        t2 = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22))
              + ((a & b) ^ (a & c) ^ (b & c))) & mask
        a, b, c, d, e, f, g, h = (t1 + t2) & mask, a, b, c, (d + t1) & mask, e, f, g
    return sum(((x + y) & mask) << (32 * i)
               for i, (x, y) in enumerate(zip(initial, (a, b, c, d, e, f, g, h))))


INITIAL_STATE = sum(word << (32 * i) for i, word in enumerate(IV))


def message_value(block):
    if len(block) != 64:
        raise ValueError("SHA_BLOCK_LENGTH")
    return sum(int.from_bytes(block[i:i + 4], "big") << (8 * i) for i in range(0, 64, 4))


def digest_bytes(chaining):
    return b"".join(((chaining >> (32 * i)) & 0xffffffff).to_bytes(4, "big") for i in range(8))


@dataclass(frozen=True)
class Primitive:
    kind: str
    width: int
    rank_bits: int
    circuit: Circuit

    @property
    def key(self):
        return f"{self.kind}:{self.width}:{self.rank_bits}"

    @property
    def input_widths(self):
        return tuple(map(len, self.circuit.inputs))

    def value(self, inputs):
        if len(inputs) != len(self.input_widths):
            raise ValueError("LEAF_INPUT_COUNT")
        for value, width in zip(inputs, self.input_widths):
            integer(value, "LEAF_INPUT_RANGE", high=(1 << width) - 1)
        q = (1 << self.width) - 5
        if self.kind == "sha":
            return sha_compress(*inputs)
        if self.kind == "multiply":
            return inputs[0] * inputs[1] % q
        if self.kind == "add":
            return sum(inputs) % q
        if self.kind == "accepted":
            return int(inputs[0] < q)
        if self.kind == "increment":
            return sum(inputs) & ((1 << self.rank_bits) - 1)
        if self.kind == "select":
            rank, address, good, word = inputs
            return word if good and rank == address else 0
        if self.kind == "leq":
            return int(inputs[0] <= inputs[1])
        if self.kind == "and":
            return int(inputs[0] == (1 << self.width) - 1)
        raise ValueError("UNKNOWN_LEAF")

    @cache
    def report(self):
        metrics = self.circuit.metrics()
        counts = dict(metrics["gate_counts"])
        # Actual wrapper: load EVERY input bit with a CNOT, including constants
        # wired to the reserved |0> and |1> registers, then unload in reverse.
        copies = 2 * sum(self.input_widths)
        counts["CNOT"] += copies
        encoded = self.circuit.encode()
        return {
            "key": self.key, "input_widths": self.input_widths,
            "output_width": len(self.circuit.outputs),
            "netlist_sha256": hashlib.sha256(encoded).hexdigest(),
            "netlist_bytes": len(encoded), "leaf_qubits": self.circuit.qubits,
            "wrapped_gate_counts": counts,
            "wrapped_gates": sum(counts.values()),
            "wrapped_depth_upper_bound": copies + metrics["gate_dependency_depth_with_all_to_all_connectivity"],
            "wrapped_toffoli_depth_upper_bound": metrics["Toffoli_dependency_depth_with_Clifford_cost_ignored"],
            "input_load_unload_cnots": copies,
            "clean_xor_output_for_arbitrary_output_seed": True,
        }


@cache
def primitive(kind, width=32, rank_bits=11):
    integer(width, "LEAF_WIDTH", 1, 256)
    integer(rank_bits, "RANK_BITS", 1, 16)
    if type(kind) is not str:
        raise ValueError("LEAF_KIND")
    if kind == "sha":
        if width != 32:
            raise ValueError("SHA_WORD_WIDTH")
        circuit = sha256_compression()
    elif kind == "multiply":
        integer(width, "FIELD_WIDTH", 4, 32)
        circuit = field_multiply(width)
    else:
        circuit = Circuit()
        if kind == "add":
            integer(width, "FIELD_WIDTH", 4, 32)
            a, b = circuit.input(width), circuit.input(width)
            word = circuit.add(a, b, width + 1)
            # Two subtractions also handle noncanonical raw operands. Native
            # W1 uses canonical operands; no encoding check is removed.
            for _ in range(2):
                word = circuit.select_subtract(word, (1 << width) - 5)
            result = word[:width]
        elif kind == "accepted":
            integer(width, "FIELD_WIDTH", 4, 32)
            word = circuit.input(width)
            carry = circuit.add(word, constant(5, width + 1), width + 1)[width]
            result = [circuit.bnot(carry)]
        elif kind == "increment":
            count, bit = circuit.input(rank_bits), circuit.input(1)
            result = circuit.add(count, bit, rank_bits)
        elif kind == "select":
            rank, address = circuit.input(rank_bits), circuit.input(rank_bits)
            good, word = circuit.input(1), circuit.input(width)
            selected = good[0]
            for a, b in zip(rank, address):
                selected = circuit.band(selected, circuit.bnot(circuit.bxor(a, b)))
            result = [circuit.band(selected, bit) for bit in word]
        elif kind == "leq":
            a, b = circuit.input(width), circuit.input(width)
            less, equal = ZERO, ONE
            for x, y in zip(reversed(a), reversed(b)):
                term = circuit.band(equal, circuit.band(circuit.bnot(x), y))
                less = circuit.bxor(less, term)  # Disjoint from an earlier less bit.
                equal = circuit.band(equal, circuit.bnot(circuit.bxor(x, y)))
            result = [circuit.bxor(less, equal)]
        elif kind == "and":
            result_bit = ONE
            for bit in circuit.input(width):
                result_bit = circuit.band(result_bit, bit)
            result = [result_bit]
        else:
            raise ValueError("UNKNOWN_LEAF")
        circuit.finish(result)
    return Primitive(kind, width, rank_bits, circuit)
