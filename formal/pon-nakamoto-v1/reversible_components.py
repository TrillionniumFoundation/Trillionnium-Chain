#!/usr/bin/env python3
"""Construct and basis-check reversible W1 arithmetic/hash components.

Research only: exact X/CNOT/Toffoli circuits, not quantum hardware execution,
not a complete W1 winner oracle, not an optimal circuit or a security bound.
The deliberately simple Bennett construction exposes all retained scratch and
all uncomputation. No gate counts are substituted for an actual mining attack.
"""

import argparse
from array import array
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import time

ZERO, ONE = -1, -2
WIRE_BITS = 20
WIRE_MASK = (1 << WIRE_BITS) - 1
Q = (1 << 32) - 5
IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
K = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


class Circuit:
    """A concrete packed permutation circuit, including its inverse gates."""

    def __init__(self):
        self.qubits = 0
        self.gates = array("Q")
        self.inputs = []
        self.outputs = []
        self.compute_gates = None

    def allocate(self, n=1):
        result = list(range(self.qubits, self.qubits + n))
        self.qubits += n
        if self.qubits > WIRE_MASK:
            raise ValueError("explicit circuit wire bound")
        return result

    def input(self, width):
        result = self.allocate(width)
        self.inputs.append(result)
        return result

    def emit(self, op, target, *controls):
        if op not in (1, 2, 3) or len(controls) != op - 1:
            raise ValueError("gate arity")
        used = (target, *controls)
        if len(set(used)) != len(used) or not all(0 <= q < self.qubits for q in used):
            raise ValueError("gate wire alias or unknown wire")
        a, b = (*controls, 0, 0)[:2]
        self.gates.append((op << 60) | (a << 40) | (b << 20) | target)

    def bxor(self, a, b):
        if a == b:
            return ZERO
        if a == ZERO:
            return b
        if b == ZERO:
            return a
        if a == ONE:
            return self.bnot(b)
        if b == ONE:
            return self.bnot(a)
        out = self.allocate()[0]
        self.emit(2, out, a)
        self.emit(2, out, b)
        return out

    def bnot(self, a):
        if a in (ZERO, ONE):
            return ONE if a == ZERO else ZERO
        out = self.allocate()[0]
        self.emit(1, out)
        self.emit(2, out, a)
        return out

    def band(self, a, b):
        if ZERO in (a, b):
            return ZERO
        if a == ONE or a == b:
            return b
        if b == ONE:
            return a
        out = self.allocate()[0]
        self.emit(3, out, a, b)
        return out

    def add(self, a, b, width):
        """A functional full-adder network, modulo 2**width."""
        a, b = (word[:width] + [ZERO] * max(0, width - len(word)) for word in (a, b))
        carry, result = ZERO, []
        for index in range(width):
            propagate = self.bxor(a[index], b[index])
            result.append(self.bxor(propagate, carry))
            if index + 1 < width:
                # These two carry terms are disjoint, so their OR is XOR.
                carry = self.bxor(
                    self.band(a[index], b[index]), self.band(propagate, carry)
                )
        return result

    def select_subtract(self, word, modulus):
        width = len(word)
        extended = self.add(
            word, constant((1 << width) - modulus, width + 1), width + 1
        )
        use_subtraction = extended[width]
        return [
            self.bxor(old, self.band(use_subtraction, self.bxor(old, new)))
            for old, new in zip(word, extended[:width])
        ]

    def finish(self, result):
        """Copy the function result, then reverse every computation gate."""
        if self.compute_gates is not None:
            raise ValueError("circuit already finalized")
        self.compute_gates = len(self.gates)
        out = self.allocate(len(result))
        for destination, source in zip(out, result):
            if source == ONE:
                self.emit(1, destination)
            elif source != ZERO:
                self.emit(2, destination, source)
        # All three primitive gates are exactly self-inverse. Retain the inverse
        # explicitly instead of claiming garbage cleanup in a cost multiplier.
        for index in range(self.compute_gates - 1, -1, -1):
            self.gates.append(self.gates[index])
        self.outputs = out
        return self

    def basis(self, values, output_seed=0):
        if len(values) != len(self.inputs):
            raise ValueError("input register count")
        state = bytearray(self.qubits)
        for wires, value in zip(
            self.inputs + [self.outputs], list(values) + [output_seed]
        ):
            if type(value) is not int or not 0 <= value < (1 << len(wires)):
                raise ValueError("input register range")
            for index, wire in enumerate(wires):
                state[wire] = (value >> index) & 1
        for gate in self.gates:
            target, op = gate & WIRE_MASK, gate >> 60
            a, b = (gate >> 40) & WIRE_MASK, (gate >> 20) & WIRE_MASK
            if op == 1:
                state[target] ^= 1
            elif op == 2:
                state[target] ^= state[a]
            elif op == 3:
                state[target] ^= state[a] & state[b]
            else:
                raise ValueError("unknown executable gate")
        for wires, value in zip(self.inputs, values):
            if bits_value(state, wires) != value:
                raise ValueError("input destroyed")
        retained = {q for register in self.inputs + [self.outputs] for q in register}
        if any(value for q, value in enumerate(state) if q not in retained):
            raise ValueError("dirty ancilla after uncomputation")
        return bits_value(state, self.outputs)

    def encode(self):
        gates = array("Q", self.gates)
        if sys.byteorder != "little":
            gates.byteswap()
        header = json.dumps(
            {
                "schema": "pon-reversible-components-netlist-v1",
                "qubits": self.qubits,
                "inputs": self.inputs,
                "outputs": self.outputs,
                "gate_count": len(gates),
                "compute_gates": self.compute_gates,
                "gate_encoding": "little-endian-u64:op[63:60],control_a[59:40],control_b[39:20],target[19:0]",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return (
            b"TRNM-QIR1\0" + struct.pack("<I", len(header)) + header + gates.tobytes()
        )

    def metrics(self):
        counts, depth, tdepth = (
            {"X": 0, "CNOT": 0, "Toffoli": 0},
            [0] * self.qubits,
            [0] * self.qubits,
        )
        for gate in self.gates:
            op, target = gate >> 60, gate & WIRE_MASK
            controls = [((gate >> 40) & WIRE_MASK), ((gate >> 20) & WIRE_MASK)][
                : op - 1
            ]
            wires = [target] + controls
            counts[("X", "CNOT", "Toffoli")[op - 1]] += 1
            layer = max(depth[q] for q in wires) + 1
            tlayer = max(tdepth[q] for q in wires) + (op == 3)
            for q in wires:
                depth[q], tdepth[q] = layer, tlayer
        input_qubits = sum(map(len, self.inputs))
        return {
            "logical_qubits": self.qubits,
            "input_qubits": input_qubits,
            "output_qubits": len(self.outputs),
            "clean_scratch_qubits": self.qubits - input_qubits - len(self.outputs),
            "compute_gates": self.compute_gates,
            "total_gates_including_copy_and_explicit_uncomputation": len(self.gates),
            "gate_counts": counts,
            "gate_dependency_depth_with_all_to_all_connectivity": max(depth),
            "Toffoli_dependency_depth_with_Clifford_cost_ignored": max(tdepth),
            "T_count_if_each_exact_Toffoli_uses_7_T": 7 * counts["Toffoli"],
            "T_count_is_conditional_decomposition_not_transpiled": True,
            "phase_oracle_complete": False,
            "physical_resources_estimated": False,
        }


def decode(raw):
    """Strictly reopen the exported gates; benchmark this reopened artifact."""
    magic = b"TRNM-QIR1\0"
    if len(raw) < len(magic) + 4 or not raw.startswith(magic):
        raise ValueError("netlist framing")
    length = struct.unpack_from("<I", raw, len(magic))[0]
    if length > 1024 * 1024:
        raise ValueError("netlist header bound")
    start = len(magic) + 4
    header = raw[start : start + length]
    meta = json.loads(header)
    if json.dumps(meta, sort_keys=True, separators=(",", ":")).encode() != header:
        raise ValueError("noncanonical netlist metadata")
    required = {
        "schema",
        "qubits",
        "inputs",
        "outputs",
        "gate_count",
        "compute_gates",
        "gate_encoding",
    }
    if (
        set(meta) != required
        or meta["schema"] != "pon-reversible-components-netlist-v1"
    ):
        raise ValueError("netlist schema")
    if (
        meta["gate_encoding"]
        != "little-endian-u64:op[63:60],control_a[59:40],control_b[39:20],target[19:0]"
    ):
        raise ValueError("netlist gate encoding")
    if type(meta["qubits"]) is not int or not 0 < meta["qubits"] <= WIRE_MASK:
        raise ValueError("netlist wire bound")
    if type(meta["gate_count"]) is not int or not 0 < meta["gate_count"] <= 10_000_000:
        raise ValueError("netlist gate bound")
    if (
        type(meta["compute_gates"]) is not int
        or not 0 <= meta["compute_gates"] <= meta["gate_count"]
    ):
        raise ValueError("netlist compute denominator")
    if len(raw) != start + length + 8 * meta["gate_count"]:
        raise ValueError("netlist exact length")
    if type(meta["inputs"]) is not list or type(meta["outputs"]) is not list:
        raise ValueError("netlist register type")
    used = set()
    for register in meta["inputs"] + [meta["outputs"]]:
        if type(register) is not list or not register:
            raise ValueError("netlist register")
        for wire in register:
            if type(wire) is not int or not 0 <= wire < meta["qubits"] or wire in used:
                raise ValueError("netlist duplicate or invalid input/output wire")
            used.add(wire)
    circuit = Circuit()
    circuit.qubits, circuit.inputs, circuit.outputs = (
        meta["qubits"],
        meta["inputs"],
        meta["outputs"],
    )
    circuit.compute_gates = meta["compute_gates"]
    for (gate,) in struct.iter_unpack("<Q", raw[start + length :]):
        op, target = gate >> 60, gate & WIRE_MASK
        a, b = (gate >> 40) & WIRE_MASK, (gate >> 20) & WIRE_MASK
        if op not in (1, 2, 3) or op == 1 and (a or b) or op == 2 and b:
            raise ValueError("noncanonical or invalid netlist gate")
        circuit.emit(op, target, *[a, b][: op - 1])
    return circuit


def bits_value(state, wires):
    return sum(state[wire] << index for index, wire in enumerate(wires))


def constant(value, width):
    return [ONE if (value >> index) & 1 else ZERO for index in range(width)]


def field_multiply(width=32):
    if not 4 <= width <= 32:
        raise ValueError("research width 4..32 required")
    circuit = Circuit()
    a, b = circuit.input(width), circuit.input(width)
    product = [ZERO] * (2 * width)
    for index in range(width):
        partial = [ZERO] * index + [circuit.band(bit, b[index]) for bit in a]
        product = circuit.add(product, partial, 2 * width)
    # p=2**width-5: 2**width == 5 modulo p. Two exact folds bound the
    # unreduced result by 2**width+24, including noncanonical u32 inputs.
    high = product[width:]
    five_high = circuit.add(high, [ZERO, ZERO] + high, width + 3)
    folded = circuit.add(product[:width], five_high, width + 3)
    high = folded[width:]
    bound = (1 << width) + 24
    folded_width = bound.bit_length()
    five_high = circuit.add(high, [ZERO, ZERO] + high, folded_width)
    folded = circuit.add(folded[:width], five_high, folded_width)
    modulus = (1 << width) - 5
    for _ in range(bound // modulus):
        folded = circuit.select_subtract(folded, modulus)
    return circuit.finish(folded[:width])


def rotate(word, count):
    return word[count:] + word[:count]


def shift(word, count):
    return word[count:] + [ZERO] * count


def sha256_compression():
    """Universal message AND chaining-state inputs; all 64 original rounds."""
    c = Circuit()
    message, chaining = c.input(512), c.input(256)
    words = [message[index * 32 : (index + 1) * 32] for index in range(16)]
    initial = [chaining[index * 32 : (index + 1) * 32] for index in range(8)]

    def xor(*items):
        result = [ZERO] * 32
        for item in items:
            result = [c.bxor(a, b) for a, b in zip(result, item)]
        return result

    def add(*items):
        result = [ZERO] * 32
        for item in items:
            result = c.add(result, item, 32)
        return result

    for index in range(16, 64):
        x, y = words[index - 15], words[index - 2]
        s0 = xor(rotate(x, 7), rotate(x, 18), shift(x, 3))
        s1 = xor(rotate(y, 17), rotate(y, 19), shift(y, 10))
        words.append(add(words[index - 16], s0, words[index - 7], s1))
    a, b, cc, d, e, f, g, h = initial
    for index in range(64):
        s1 = xor(rotate(e, 6), rotate(e, 11), rotate(e, 25))
        choose = [c.bxor(z, c.band(x, c.bxor(y, z))) for x, y, z in zip(e, f, g)]
        t1 = add(h, s1, choose, constant(K[index], 32), words[index])
        s0 = xor(rotate(a, 2), rotate(a, 13), rotate(a, 22))
        majority = [
            c.bxor(x, c.band(c.bxor(x, y), c.bxor(x, z))) for x, y, z in zip(a, b, cc)
        ]
        t2 = add(s0, majority)
        a, b, cc, d, e, f, g, h = add(t1, t2), a, b, cc, add(d, t1), e, f, g
    result = []
    for before, after in zip(initial, (a, b, cc, d, e, f, g, h)):
        result.extend(add(before, after))
    return c.finish(result)


def circuit_sha256(circuit, data):
    original_length = len(data)
    padded = data + b"\x80"
    padded += b"\0" * ((56 - len(padded) % 64) % 64)
    padded += (8 * original_length).to_bytes(8, "big")
    chaining = sum(word << (32 * index) for index, word in enumerate(IV))
    blocks = 0
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        message = sum(
            int.from_bytes(block[i : i + 4], "big") << (8 * i) for i in range(0, 64, 4)
        )
        chaining = circuit.basis([message, chaining])
        blocks += 1
    digest = b"".join(
        ((chaining >> (32 * i)) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(8)
    )
    return digest, blocks


def run(output):
    output.mkdir(parents=False, exist_ok=False)
    source = Path(__file__).read_bytes()
    result = {
        "schema": "pon-reversible-components-observation-v1",
        "status": "incomplete",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "native_relation_sha256": hashlib.sha256(
            (
                Path(__file__).parents[2]
                / "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs"
            ).read_bytes()
        ).hexdigest(),
        "scope": "constructed exact reversible components with classical basis checks only",
        "complete_W1_quantum_oracle": False,
        "quantum_hardware_executed": False,
        "quantum_attack_demonstrated": False,
        "quantum_soundness_proved": False,
        "optimality_or_cost_lower_bound": False,
        "consensus_activation": False,
        "physical_qubit_or_second_estimate": None,
        "components": {},
        "missing_complete_oracle_relations": [
            "canonical PNH1/PNW1 parsing and task/branch eligibility",
            "coherent bounded rejection sampling and reversible selection",
            "all four noise factors and original tiled-prefix schedule",
            "field addition, all matrix dataflow and clean reversible memory schedule",
            "challenge/ticket framing, target comparison, phase marking and full inverse",
            "cross-task/nonce/parent preprocessing and best legal algorithm comparison",
            "error-corrected physical architecture and quantum proof-system soundness",
        ],
    }
    try:
        generator = random.Random(0x504F4E)
        for name, factory in (
            ("fq32-multiply", field_multiply),
            ("sha256-compression-64-rounds", sha256_compression),
        ):
            started = time.perf_counter()
            circuit = factory()
            encoded = circuit.encode()
            (output / (name + ".qir")).write_bytes(encoded)
            reopened = decode((output / (name + ".qir")).read_bytes())
            if reopened.encode() != encoded or reopened.metrics() != circuit.metrics():
                raise ValueError("exported circuit changed on strict reopen")
            circuit = reopened
            row = dict(
                circuit.metrics(),
                netlist_sha256=hashlib.sha256(encoded).hexdigest(),
                netlist_bytes=len(encoded),
                checks=[],
            )
            result["components"][name] = row
            if name == "fq32-multiply":
                edge = [0, 1, 2, Q - 1, Q, Q + 1, (1 << 32) - 1]
                values = [(a, b) for a in edge for b in edge]
                values += [
                    (generator.getrandbits(32), generator.getrandbits(32))
                    for _ in range(64)
                ]
                for a, b in values:
                    seed = generator.getrandbits(32)
                    actual = circuit.basis([a, b], seed)
                    expected = ((a * b) % Q) ^ seed
                    row["checks"].append(
                        dict(
                            a=a,
                            b=b,
                            xor_output_seed=seed,
                            actual=actual,
                            expected=expected,
                            passed=actual == expected,
                        )
                    )
                    if actual != expected:
                        raise ValueError(
                            "field circuit differs from independent modular arithmetic"
                        )
            else:
                messages = [
                    b"",
                    b"abc",
                    bytes(range(55)),
                    bytes(range(56)),
                    bytes(range(64)),
                    bytes(range(65)),
                    bytes(range(256)),
                ]
                for message in messages:
                    actual, blocks = circuit_sha256(circuit, message)
                    expected = hashlib.sha256(message).digest()
                    row["checks"].append(
                        dict(
                            message_hex=message.hex(),
                            compression_calls=blocks,
                            actual=actual.hex(),
                            expected=expected.hex(),
                            passed=actual == expected,
                        )
                    )
                    if actual != expected:
                        raise ValueError("full SHA256 circuit differs from hashlib")
            row["classical_construction_and_basis_check_wall_seconds"] = (
                time.perf_counter() - started
            )
        result["status"] = "components-constructed-and-basis-checked"
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        (output / "report.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    run(parser.parse_args().output)
