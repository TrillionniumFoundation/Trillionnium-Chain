"""Constructive, deliberately nonoptimal reversible W1 winner phase oracle.

The search register is a nonce in a fixed canonical PNH1 or PGH2 header, not
an unconstrained challenge. This constructs a fixed-context circuit; native
task/parent/transaction eligibility is a checked-classical PRECONDITION, not
an admission conclusion of this module. No lower bound or physical calibration
is asserted. A native-sized scalar macro run is never labelled gate execution.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import struct

from reversible_components import ONE, ZERO, WIRE_MASK
from w1_quantum_primitives import (
    INITIAL_STATE, digest_bytes, integer, message_value, primitive, sha_compress,
)

SCHEMA = "trnm-w1-constructive-phase-oracle-v1"
ROOT = Path(__file__).resolve().parents[2]
SOURCE_FILES = (
    "formal/pon-nakamoto-v1/w1_quantum_oracle.py",
    "formal/pon-nakamoto-v1/w1_quantum_primitives.py",
    "formal/pon-nakamoto-v1/reversible_components.py",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs",
    "trillionnium/crates/trnm-protocol/src/pon_wire.rs",
    "trillionnium/crates/trnm-protocol/src/pon_growth.rs",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def h_bytes(tag, *parts):
    return (b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
            + b"".join(struct.pack("<I", len(part)) + part for part in parts))


@dataclass(frozen=True)
class Shape:
    n: int = 64
    r: int = 8
    field_bits: int = 32
    noise_counters: int = 128

    def validate(self):
        integer(self.n, "N", 1, 64)
        integer(self.r, "R", 1, 8)
        integer(self.field_bits, "FIELD_BITS", 4, 32)
        integer(self.noise_counters, "NOISE_COUNTERS", 1, 128)
        if self.n % self.r or self.n * self.r > 8 * self.noise_counters:
            raise ValueError("SHAPE_OR_NOISE_CAPACITY")

    @property
    def native(self):
        return (self.n, self.r, self.field_bits, self.noise_counters) == (64, 8, 32, 128)

    @property
    def q(self):
        return (1 << self.field_bits) - 5


@dataclass(frozen=True)
class FixedTemplate:
    header: bytes
    a: tuple[int, ...]
    b: tuple[int, ...]
    shape: Shape
    nonce_bits: int
    profile: str
    nonce_offset: int
    challenge_tag: bytes
    target: int

    @classmethod
    def from_header(cls, header, a, b, nonce_bits=64, shape=Shape()):
        if type(shape) is not Shape:
            raise ValueError("SHAPE_TYPE")
        shape.validate()
        integer(nonce_bits, "NONCE_BITS", 1, 64)
        if type(header) is not bytes:
            raise ValueError("HEADER_BYTES")
        if len(header) == 318 and header[:6] == b"PNH1\x01\0":
            profile, base, offset, tag = "PNH1", 0, 310, b"challenge"
        elif len(header) == 354 and header[:10] == b"PGH2PNH1\x01\0":
            profile, base, offset, tag = "PGH2", 4, 314, b"permanent-account-growth-challenge-v2"
        else:
            raise ValueError("CANONICAL_HEADER")
        matrices = []
        for values in (a, b):
            if type(values) not in (list, tuple) or len(values) != shape.n**2:
                raise ValueError("MATRIX_SHAPE")
            for value in values:
                integer(value, "CANONICAL_FIELD", high=shape.q - 1)
            matrices.append(tuple(values))
        a, b = matrices
        field = lambda values: struct.pack("<" + "I" * len(values), *values)
        task = hashlib.sha256(h_bytes(b"task", field(a), field(b))).digest()
        if header[base + 278:base + 310] != task:
            raise ValueError("HEADER_TASK_BINDING")
        target = int.from_bytes(header[base + 118:base + 150], "big")
        if target == 0:
            raise ValueError("ZERO_TARGET")
        # The complete nonce field is the search variable. A reduced domain
        # uses low nonce_bits, with all other bits fixed to zero.
        header = header[:offset] + bytes(8) + header[offset + 8:]
        return cls(header, a, b, shape, nonce_bits, profile, offset, tag, target)

    def header_for(self, nonce):
        integer(nonce, "NONCE_RANGE", high=(1 << self.nonce_bits) - 1)
        return self.header[:self.nonce_offset] + nonce.to_bytes(8, "little") + self.header[self.nonce_offset + 8:]

    def spec(self):
        return {"schema": SCHEMA, "shape": asdict(self.shape), "header_hex": self.header.hex(),
                "a": list(self.a), "b": list(self.b), "nonce_bits": self.nonce_bits}


def template_from_spec(value):
    if type(value) is not dict or set(value) != {"schema", "shape", "header_hex", "a", "b", "nonce_bits"}:
        raise ValueError("SPEC_SCHEMA")
    if value["schema"] != SCHEMA or type(value["shape"]) is not dict or set(value["shape"]) != set(Shape.__dataclass_fields__):
        raise ValueError("SPEC_VERSION_OR_SHAPE")
    encoded = value["header_hex"]
    if type(encoded) is not str or len(encoded) not in (636, 708) or encoded != encoded.lower():
        raise ValueError("HEADER_HEX")
    header = bytes.fromhex(encoded)
    if header.hex() != encoded:
        raise ValueError("CANONICAL_HEX")
    return FixedTemplate.from_header(header, value["a"], value["b"], value["nonce_bits"], Shape(**value["shape"]))


@dataclass(frozen=True)
class Reg:
    index: int
    width: int
    wire: int

    def value(self, values):
        return values[self.index]

    def bits(self):
        return range(self.wire, self.wire + self.width)


@dataclass(frozen=True)
class Constant:
    width: int
    number: int

    def value(self, values):
        return self.number

    def bits(self):
        return [ONE if self.number >> bit & 1 else ZERO for bit in range(self.width)]


@dataclass(frozen=True)
class Bank:
    index: int
    wire: int
    width: int
    count: int

    def __getitem__(self, item):
        if not 0 <= item < self.count:
            raise ValueError("REGISTER_INDEX")
        return Reg(self.index + item, self.width, self.wire + item * self.width)


class Layout:
    def __init__(self):
        self.registers = self.qubits = 0
        self.banks = []

    def allocate(self, name, width, count=1):
        bank = Bank(self.registers, self.qubits, width, count)
        self.registers += count
        self.qubits += width * count
        self.banks.append({"name": name, **asdict(bank)})
        return bank


@dataclass(frozen=True)
class Byte:
    register: Reg
    shift: int

    def value(self, values):
        return (values[self.register.index] >> self.shift) & 255

    def bit(self, bit):
        return self.register.wire + self.shift + bit if self.shift + bit < self.register.width else ZERO


def hash_bytes(register):
    return tuple(Byte(register, (i // 4) * 32 + (3 - i % 4) * 8) for i in range(32))


@dataclass(frozen=True)
class Message:
    data: tuple
    width: int = 512

    def value(self, values):
        return message_value(bytes(item if type(item) is int else item.value(values) for item in self.data))

    def bits(self):
        out = []
        for bit in range(512):
            byte = self.data[(bit // 32) * 4 + 3 - (bit % 32) // 8]
            out.append((ONE if byte >> (bit % 8) & 1 else ZERO) if type(byte) is int else byte.bit(bit % 8))
        return out


@dataclass(frozen=True)
class NoiseWord:
    register: Reg
    word: int
    width: int

    def value(self, values):
        word = (values[self.register.index] >> (32 * self.word)) & 0xffffffff
        return int.from_bytes(word.to_bytes(4, "big"), "little") & ((1 << self.width) - 1)

    def bits(self):
        return [self.register.wire + 32 * self.word + (3 - bit // 8) * 8 + bit % 8 for bit in range(self.width)]


@dataclass(frozen=True)
class DigestInteger:
    register: Reg
    width: int = 256

    def value(self, values):
        return int.from_bytes(digest_bytes(values[self.register.index]), "big")

    def bits(self):
        return [self.register.wire + (7 - bit // 32) * 32 + bit % 32 for bit in range(256)]


@dataclass(frozen=True)
class BitPack:
    registers: tuple[Reg, ...]

    @property
    def width(self):
        return len(self.registers)

    def value(self, values):
        return sum(values[reg.index] << i for i, reg in enumerate(self.registers))

    def bits(self):
        return [reg.wire for reg in self.registers]


@dataclass(frozen=True)
class Operation:
    leaf: object
    inputs: tuple
    output: Reg


def ordered(count, reverse):
    return range(count - 1, -1, -1) if reverse else range(count)


def selection_operations(raw, good, ranks, packed, complete, leaves, reverse=False):
    """The same oblivious sampler stage serves native and exhaustive controls."""
    accept, increment, select, enough = leaves
    bits, required = ranks.width, packed.count
    finish = Operation(enough, (Constant(bits, required), ranks[len(raw) - 1]), complete)
    if reverse:
        yield finish
    for index in ordered(len(raw), reverse):
        before = ranks[index - 1] if index else Constant(bits, 0)
        accepted = Operation(accept, (raw[index],), good[index])
        advanced = Operation(increment, (before, good[index]), ranks[index])
        if not reverse:
            yield accepted
            yield advanced
        for address in ordered(required, reverse):
            yield Operation(select, (before, Constant(bits, address), good[index], raw[index]), packed[address])
        if reverse:
            yield advanced
            yield accepted
    if not reverse:
        yield finish


def framed(tag, *parts):
    return tuple(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag) + tuple(
        item for part in parts for item in (*struct.pack("<I", len(part)), *part))


class HashPlan:
    def __init__(self, layout, name, data, precompute_blocks=0):
        self.input_bytes = len(data)
        padded = tuple(data) + (128,)
        padded += (0,) * ((56 - len(padded) % 64) % 64)
        padded += tuple((self.input_bytes * 8).to_bytes(8, "big"))
        self.initial = INITIAL_STATE
        for block in range(precompute_blocks):
            fixed = padded[64 * block:64 * (block + 1)]
            if any(type(item) is not int for item in fixed):
                raise ValueError("QUANTUM_DEPENDENCY_IN_CLASSICAL_PRECOMPUTE")
            self.initial = sha_compress(message_value(bytes(fixed)), self.initial)
        self.messages = tuple(Message(padded[i:i + 64]) for i in range(64 * precompute_blocks, len(padded), 64))
        self.states = layout.allocate(name, 256, len(self.messages))
        self.leaf = primitive("sha")
        self.precomputed_blocks = precompute_blocks

    @property
    def digest(self):
        return self.states[self.states.count - 1]

    def operations(self, reverse=False):
        for i in ordered(len(self.messages), reverse):
            before = self.states[i - 1] if i else Constant(256, self.initial)
            yield Operation(self.leaf, (self.messages[i], before), self.states[i])


class ProductPlan:
    def __init__(self, layout, name, a, b, rows, inner, cols, width):
        self.a, self.b, self.rows, self.inner, self.cols = a, b, rows, inner, cols
        self.width, self.count = width, rows * inner * cols
        self.products = layout.allocate(name + ".products", width, self.count)
        self.sums = layout.allocate(name + ".sums", width, self.count)
        self.multiply, self.add = primitive("multiply", width), primitive("add", width)

    def cells(self):
        return tuple(self.sums[(i + 1) * self.inner - 1] for i in range(self.rows * self.cols))

    def operations(self, reverse=False):
        for index in ordered(self.count, reverse):
            cell, k = divmod(index, self.inner)
            row, col = divmod(cell, self.cols)
            before = self.sums[index - 1] if k else Constant(self.width, 0)
            mul = Operation(self.multiply, (self.a[row * self.inner + k], self.b[k * self.cols + col]), self.products[index])
            add = Operation(self.add, (before, self.products[index]), self.sums[index])
            yield from (add, mul) if reverse else (mul, add)


class TranscriptPlan:
    def __init__(self, layout, a, b, shape):
        self.a, self.b, self.shape = a, b, shape
        self.count = shape.n**3
        self.products = layout.allocate("transcript.products", shape.field_bits, self.count)
        self.sums = layout.allocate("transcript.sums", shape.field_bits, self.count)
        self.multiply, self.add = primitive("multiply", shape.field_bits), primitive("add", shape.field_bits)

    def prefixes(self):
        # Every R-th accumulation ends one native (bi,bj,bk,i,j) prefix.
        return tuple(self.sums[index] for index in range(self.shape.r - 1, self.count, self.shape.r))

    def operations(self, reverse=False):
        n, r, w = self.shape.n, self.shape.r, self.shape.field_bits
        tiles = n // r
        for index in ordered(self.count, reverse):
            rest, k = divmod(index, r)
            rest, j = divmod(rest, r)
            rest, i = divmod(rest, r)
            rest, bk = divmod(rest, tiles)
            bi, bj = divmod(rest, tiles)
            if k:
                before = self.sums[index - 1]
            elif bk:
                before = self.sums[index - r**3 + r - 1]
            else:
                before = Constant(w, 0)
            left = self.a[(bi * r + i) * n + bk * r + k]
            right = self.b[(bk * r + k) * n + bj * r + j]
            mul = Operation(self.multiply, (left, right), self.products[index])
            add = Operation(self.add, (before, self.products[index]), self.sums[index])
            yield from (add, mul) if reverse else (mul, add)


class OracleProgram:
    STAGES = ("challenge", "noise_hashes", "noise_compaction", "low_rank", "offset_matrices",
              "transcript_arithmetic", "trace_hash", "ticket_hash", "predicate")

    def __init__(self, template):
        if type(template) is not FixedTemplate:
            raise ValueError("TEMPLATE_TYPE")
        # Revalidate even dataclass instances supplied directly by callers.
        template = FixedTemplate.from_header(template.header, template.a, template.b,
                                             template.nonce_bits, template.shape)
        self.template, self.shape, self.layout = template, template.shape, Layout()
        n, r, w = self.shape.n, self.shape.r, self.shape.field_bits
        self.nonce = self.layout.allocate("nonce", template.nonce_bits)[0]
        self.zero = self.layout.allocate("constant-zero", 1)[0]
        self.one = self.layout.allocate("constant-one", 1)[0]
        header = list(template.header)
        for i in range(8):
            header[template.nonce_offset + i] = Byte(self.nonce, 8 * i)
        self.challenge = HashPlan(self.layout, "challenge.states", framed(template.challenge_tag, tuple(header)), 5)
        challenge_bytes = hash_bytes(self.challenge.digest)
        self.noise = []
        self.raw = []
        for label in range(4):
            plans = [HashPlan(self.layout, f"noise.{label}.{counter}.states",
                             framed(b"noise", challenge_bytes, (label,), tuple(struct.pack("<I", counter))))
                     for counter in range(self.shape.noise_counters)]
            self.noise.append(plans)
            self.raw.append(tuple(NoiseWord(plan.digest, word, w) for plan in plans for word in range(8)))
        self.draws, self.required = 8 * self.shape.noise_counters, n * r
        self.rank_bits = self.draws.bit_length()
        self.good = [self.layout.allocate(f"noise.{label}.accepted", 1, self.draws) for label in range(4)]
        self.ranks = [self.layout.allocate(f"noise.{label}.prefix_ranks", self.rank_bits, self.draws) for label in range(4)]
        self.packed = [self.layout.allocate(f"noise.{label}.first_accepted", w, self.required) for label in range(4)]
        self.complete = self.layout.allocate("noise.complete_flags", 1, 4)
        self.accept = primitive("accepted", w)
        self.increment = primitive("increment", w, self.rank_bits)
        self.select = primitive("select", w, self.rank_bits)
        self.enough = primitive("leq", self.rank_bits)
        factors = [tuple(bank[i] for i in range(bank.count)) for bank in self.packed]
        self.low_rank = [ProductPlan(self.layout, name, factors[i], factors[i + 1], n, r, n, w)
                         for name, i in (("E", 0), ("F", 2))]
        self.offset = [self.layout.allocate(name, w, n**2) for name in ("A-prime", "B-prime")]
        self.add = primitive("add", w)
        ap, bp = (tuple(bank[i] for i in range(bank.count)) for bank in self.offset)
        self.transcript = TranscriptPlan(self.layout, ap, bp, self.shape)
        trace_bytes = tuple(b"TRNM-PON-TRACE1\0") + challenge_bytes
        trace_bytes += tuple(Byte(word, shift) for word in self.transcript.prefixes() for shift in (0, 8, 16, 24))
        self.trace = HashPlan(self.layout, "trace.states", trace_bytes)
        self.ticket = HashPlan(self.layout, "ticket.states", framed(b"ticket", challenge_bytes, hash_bytes(self.trace.digest)))
        self.target_hit = self.layout.allocate("ticket.leq_target", 1)[0]
        self.winner = self.layout.allocate("winner", 1)[0]
        self.compare = primitive("leq", 256)
        self.conjunction = primitive("and", 5)
        self._resources = None

    def stage_operations(self, stage, reverse=False):
        if stage == "challenge":
            yield from self.challenge.operations(reverse)
        elif stage == "noise_hashes":
            for label in ordered(4, reverse):
                for counter in ordered(self.shape.noise_counters, reverse):
                    yield from self.noise[label][counter].operations(reverse)
        elif stage == "noise_compaction":
            for label in ordered(4, reverse):
                yield from selection_operations(
                    self.raw[label], self.good[label], self.ranks[label], self.packed[label], self.complete[label],
                    (self.accept, self.increment, self.select, self.enough), reverse)
        elif stage == "low_rank":
            for index in ordered(2, reverse):
                yield from self.low_rank[index].operations(reverse)
        elif stage == "offset_matrices":
            for matrix in ordered(2, reverse):
                values = (self.template.a, self.template.b)[matrix]
                source = self.low_rank[matrix].cells()
                for index in ordered(len(values), reverse):
                    yield Operation(self.add, (Constant(self.shape.field_bits, values[index]), source[index]), self.offset[matrix][index])
        elif stage == "transcript_arithmetic":
            yield from self.transcript.operations(reverse)
        elif stage == "trace_hash":
            yield from self.trace.operations(reverse)
        elif stage == "ticket_hash":
            yield from self.ticket.operations(reverse)
        elif stage == "predicate":
            compare = Operation(self.compare, (DigestInteger(self.ticket.digest), Constant(256, self.template.target)), self.target_hit)
            conjunction = Operation(self.conjunction, (BitPack(tuple(self.complete[i] for i in range(4)) + (self.target_hit,)),), self.winner)
            yield from (conjunction, compare) if reverse else (compare, conjunction)
        else:
            raise ValueError("STAGE")

    def operations(self, reverse=False):
        for index in ordered(len(self.STAGES), reverse):
            yield from self.stage_operations(self.STAGES[index], reverse)

    def stage_counts(self):
        n, r = self.shape.n, self.shape.r
        sha, mul, add = self.challenge.leaf, self.transcript.multiply, self.add
        return {
            "challenge": {sha: len(self.challenge.messages)},
            "noise_hashes": {sha: 8 * self.shape.noise_counters},
            "noise_compaction": {self.accept: 4 * self.draws, self.increment: 4 * self.draws,
                                  self.select: 4 * self.draws * self.required, self.enough: 4},
            "low_rank": {mul: 2 * n * n * r, add: 2 * n * n * r},
            "offset_matrices": {add: 2 * n * n},
            "transcript_arithmetic": {mul: n**3, add: n**3},
            "trace_hash": {sha: len(self.trace.messages)},
            "ticket_hash": {sha: len(self.ticket.messages)},
            "predicate": {self.compare: 1, self.conjunction: 1},
        }

    def resources(self):
        if self._resources is not None:
            return json.loads(json.dumps(self._resources))
        counts = self.stage_counts()
        leaves = {leaf.key: leaf.report() for stage in counts.values() for leaf in stage}
        stages = {}
        for name, stage in counts.items():
            gates = {kind: sum(leaves[leaf.key]["wrapped_gate_counts"][kind] * amount for leaf, amount in stage.items())
                     for kind in ("X", "CNOT", "Toffoli")}
            stages[name] = {"calls": {leaf.key: amount for leaf, amount in stage.items()}, "gate_counts": gates,
                            "gate_count": sum(gates.values()),
                            "depth_upper_bound": sum(leaves[leaf.key]["wrapped_depth_upper_bound"] * amount for leaf, amount in stage.items()),
                            "toffoli_depth_upper_bound": sum(leaves[leaf.key]["wrapped_toffoli_depth_upper_bound"] * amount for leaf, amount in stage.items())}
        forward = {key: sum(stage["gate_counts"][key] for stage in stages.values()) for key in ("X", "CNOT", "Toffoli")}
        forward["X"] += 1  # Explicit initialization of the reusable constant-one wire.
        forward_depth = 1 + sum(stage["depth_upper_bound"] for stage in stages.values())
        forward_tdepth = sum(stage["toffoli_depth_upper_bound"] for stage in stages.values())
        scratch = max(row["leaf_qubits"] for row in leaves.values())
        n = self.template.nonce_bits
        sources = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}
        construction = {"schema": SCHEMA, "input": self.template.spec(), "source_sha256": sources,
                        "leaf_netlist_sha256": {name: row["netlist_sha256"] for name, row in leaves.items()},
                        "layout": self.layout.banks, "stage_calls": {name: stage["calls"] for name, stage in stages.items()}}
        self._resources = {
            "schema": SCHEMA, "construction_sha256": hashlib.sha256(canonical(construction)).hexdigest(),
            "scope": "NATIVE_W1_FIXED_TEMPLATE_CONSTRUCTION" if self.shape.native else "REDUCED_SHAPE_CIRCUIT_CONTROL",
            "shape": asdict(self.shape), "profile": self.template.profile, "nonce_bits": n,
            "source_sha256": sources, "logical_qubits": self.layout.qubits + scratch,
            "persistent_register_qubits": self.layout.qubits, "reused_workspace_qubits": scratch,
            "persistent_register_count": self.layout.registers,
            "lifetime": "all SSA outputs retained through phase; clean leaf input/scratch workspace reused; global reverse clears every output",
            "data_access": "static wire addresses, exhaustive oblivious accepted-word selection; no QRAM or dynamic memory oracle",
            "classical_preprocessing": {"fixed_header_sha_compressions": 5,
                                        "fixed_matrices_and_task_commitment": True,
                                        "AB_and_full_PNW1_materialization": "optional per-task/per-winner classical work outside this predicate"},
            "hash_framing": {"challenge_bytes": self.challenge.input_bytes,
                             "coherent_challenge_compressions": len(self.challenge.messages),
                             "noise_bytes_each": self.noise[0][0].input_bytes,
                             "noise_hashes_all_bounded_branches": 4 * self.shape.noise_counters,
                             "trace_bytes": self.trace.input_bytes,
                             "trace_compressions": len(self.trace.messages),
                             "ticket_bytes": self.ticket.input_bytes},
            "leaves": leaves, "stages": stages,
            "forward_gate_counts": forward,
            "forward_gate_count": sum(forward.values()),
            "forward_depth_upper_bound": forward_depth,
            "forward_toffoli_depth_upper_bound": forward_tdepth,
            "phase_oracle_gate_count": 2 * sum(forward.values()) + 1,
            "phase_oracle_gate_counts": {**{key: 2 * value for key, value in forward.items()}, "Z": 1},
            "phase_oracle_depth_upper_bound": 2 * forward_depth + 1,
            "phase_oracle_toffoli_depth_upper_bound": 2 * forward_tdepth,
            "prepare": {"H": n, "gate_count": n, "depth_upper_bound": 1},
            "diffusion": {"H": 2 * n, "X": 2 * n, "Z": 1, "Toffoli": 2 * (n - 1),
                          "gate_count": 6 * n - 1, "depth_upper_bound": 2 * n + 3,
                          "scratch_qubits": n - 1, "standard_diffusion_up_to_global_phase": True},
            "T_count_if_exact_Toffoli_uses_7_T": 14 * forward["Toffoli"],
            "T_decomposition_is_conditional_not_transpiled": True,
            "constructive_upper_bound_not_best_algorithm": True,
            "native_eligibility_is_checked_classical_precondition": True,
            "native_node_admission_verified": False, "quantum_hardware_executed": False,
            "physical_calibration": None, "quantum_work_lower_bound_proved": False,
            "quantum_mining_security_qualified": False, "production_activation": False,
        }
        return self.resources()

    def diffusion_gates(self):
        """Concrete reusable diffusion sequence; H/Z are Clifford gates."""
        wires = tuple(self.nonce.bits())
        for wire in wires:
            yield ("H", wire)
        for wire in wires:
            yield ("X", wire)
        ladder = []
        left = wires[0]
        for index, right in enumerate(wires[1:]):
            target = self.layout.qubits + index
            ladder.append(("Toffoli", target, left, right))
            left = target
        yield from ladder
        yield ("Z", left)
        yield from reversed(ladder)
        for wire in wires:
            yield ("X", wire)
        for wire in wires:
            yield ("H", wire)

    def resource_request(self, workload, classical, physical_models=()):
        from quantum_oracle_resources import Circuit, Request
        row = self.resources()
        qubits = row["logical_qubits"]
        provenance = "constructed-w1/" + row["construction_sha256"]
        def stage(count, depth, toffoli=0, tdepth=0):
            return Circuit(qubits, count, depth, toffoli, tdepth, 0, 0, provenance)
        circuits = {
            "prepare": stage(row["prepare"]["gate_count"], 1),
            "winner_compute": stage(row["forward_gate_count"], row["forward_depth_upper_bound"],
                                    row["forward_gate_counts"]["Toffoli"], row["forward_toffoli_depth_upper_bound"]),
            "phase_marker": stage(1, 1),
            "diffusion": stage(row["diffusion"]["gate_count"], row["diffusion"]["depth_upper_bound"],
                               row["diffusion"]["Toffoli"], row["diffusion"]["Toffoli"]),
        }
        request = Request("CALLER_SUPPLIED_UNVERIFIED_PREDICATE", "fixed canonical header and public matrices with nonce search",
                          "static wires and exhaustive coherent selection with fully charged input copies",
                          ("five fixed header SHA compression blocks", "fixed canonical matrices and task commitment", "optional fixed AB for later proof"),
                          circuits, workload, classical, physical_models)
        request.validate()
        return request

    def execute(self, nonce, mode="macro", inverse=True, gate_limit=100_000_000):
        integer(nonce, "NONCE_RANGE", high=(1 << self.template.nonce_bits) - 1)
        if mode not in ("macro", "gates") or type(inverse) is not bool:
            raise ValueError("EXECUTION_MODE")
        integer(gate_limit, "GATE_LIMIT", 1, 500_000_000)
        row = self.resources()
        if mode == "gates" and row["phase_oracle_gate_count"] > gate_limit:
            raise ValueError("EXPLICIT_GATE_EXECUTION_BUDGET")
        runner = Runner(self, mode)
        runner.values[self.nonce.index] = nonce
        runner.values[self.one.index] = 1
        if runner.bits is not None:
            for bit, wire in enumerate(self.nonce.bits()):
                runner.bits[wire] = nonce >> bit & 1
            runner.bits[self.one.wire] = 1
        for operation in self.operations():
            runner.apply(operation)
        result = {"nonce": nonce, "challenge": digest_bytes(runner.values[self.challenge.digest.index]).hex(),
                  "trace": digest_bytes(runner.values[self.trace.digest.index]).hex(),
                  "ticket": digest_bytes(runner.values[self.ticket.digest.index]).hex(),
                  "noise_complete": [bool(runner.values[self.complete[i].index]) for i in range(4)],
                  "accepted_word_counts": [runner.values[bank[bank.count - 1].index] for bank in self.ranks],
                  "winner": bool(runner.values[self.winner.index])}
        result["phase"] = -1 if result["winner"] else 1
        if inverse:
            for operation in self.operations(True):
                runner.apply(operation)
            runner.values[self.one.index] ^= 1
            if runner.bits is not None:
                runner.bits[self.one.wire] ^= 1
        clean = all(value == 0 for index, value in enumerate(runner.values) if index != self.nonce.index)
        if runner.bits is not None:
            clean &= all(bit == 0 for index, bit in enumerate(runner.bits) if index not in range(self.nonce.wire, self.nonce.wire + self.nonce.width))
        if inverse and not clean:
            raise ValueError("GLOBAL_UNCOMPUTATION_DIRTY_ANCILLA")
        result.update({"mode": mode, "clean_ancillas": clean, "inverse_executed": inverse,
                       "macro_calls_executed": runner.calls,
                       "leaf_gates_executed": runner.executed_gates if mode == "gates" else None,
                       "outer_X_Z_gates_executed": (3 if inverse else 2) if mode == "gates" else None,
                       "native_shape": self.shape.native, "quantum_hardware_executed": False,
                       "phase_sign_observed_by_classical_basis_interpreter": True})
        preserved = runner.values[self.nonce.index] == nonce
        if runner.bits is not None:
            preserved &= all(runner.bits[wire] == (nonce >> bit & 1) for bit, wire in enumerate(self.nonce.bits()))
        if not preserved:
            raise ValueError("SEARCH_REGISTER_DESTROYED")
        result["nonce_preserved"] = preserved
        return result


class Runner:
    def __init__(self, program, mode):
        self.program, self.mode = program, mode
        self.values = [0] * program.layout.registers
        self.bits = bytearray(program.resources()["logical_qubits"]) if mode == "gates" else None
        self.calls = self.executed_gates = 0

    def apply(self, operation):
        leaf, output = operation.leaf, operation.output
        inputs = [value.value(self.values) for value in operation.inputs]
        expected = self.values[output.index] ^ leaf.value(inputs)
        if self.bits is not None:
            circuit, state, scratch = leaf.circuit, self.bits, self.program.layout.qubits
            if tuple(value.width for value in operation.inputs) != leaf.input_widths or output.width != len(circuit.outputs):
                raise ValueError("LEAF_REGISTER_SIGNATURE")
            out_start = circuit.outputs[0]
            if circuit.outputs != list(range(out_start, out_start + output.width)):
                raise ValueError("NONCONTIGUOUS_LEAF_OUTPUT")
            def mapped(wire):
                return output.wire + wire - out_start if out_start <= wire < out_start + output.width else scratch + wire
            copies = []
            for expression, local in zip(operation.inputs, circuit.inputs):
                for source, destination in zip(expression.bits(), local):
                    source = self.program.zero.wire if source == ZERO else self.program.one.wire if source == ONE else source
                    if output.wire <= source < output.wire + output.width:
                        raise ValueError("LEAF_INPUT_OUTPUT_ALIAS")
                    destination = mapped(destination)
                    state[destination] ^= state[source]
                    copies.append((source, destination))
            for gate in circuit.gates:
                op, target = gate >> 60, mapped(gate & WIRE_MASK)
                if op == 1:
                    state[target] ^= 1
                elif op == 2:
                    state[target] ^= state[mapped((gate >> 40) & WIRE_MASK)]
                elif op == 3:
                    state[target] ^= state[mapped((gate >> 40) & WIRE_MASK)] & state[mapped((gate >> 20) & WIRE_MASK)]
                else:
                    raise ValueError("LEAF_GATE_KIND")
            for source, destination in reversed(copies):
                state[destination] ^= state[source]
            actual = sum(state[output.wire + bit] << bit for bit in range(output.width))
            if actual != expected or any(state[scratch:]):
                raise ValueError("LEAF_VALUE_OR_DIRTY_ANCILLA")
            self.executed_gates += len(circuit.gates) + 2 * len(copies)
        self.values[output.index] = expected
        self.calls += 1


class SelectionControl:
    """Reduced exhaustive gate control of the SAME bounded compaction generator.

    Raw words are inputs here, allowing forced noncanonical draws and exhaustion;
    this test object is not a mining oracle and does not replace native SHA noise.
    """
    def __init__(self, width=4, draws=2, required=2):
        integer(width, "CONTROL_WIDTH", 4, 8)
        integer(draws, "CONTROL_DRAWS", 1, 16)
        integer(required, "CONTROL_REQUIRED", 1, draws)
        self.layout = Layout()
        self.zero = self.layout.allocate("zero", 1)[0]
        self.one = self.layout.allocate("one", 1)[0]
        self.inputs = self.layout.allocate("raw", width, draws)
        self.good = self.layout.allocate("accepted", 1, draws)
        self.ranks = self.layout.allocate("ranks", draws.bit_length(), draws)
        self.packed = self.layout.allocate("packed", width, required)
        self.complete = self.layout.allocate("complete", 1)[0]
        self.leaves = (primitive("accepted", width), primitive("increment", width, draws.bit_length()),
                       primitive("select", width, draws.bit_length()), primitive("leq", draws.bit_length()))
        self.scratch = max(leaf.circuit.qubits for leaf in self.leaves)

    def resources(self):
        return {"logical_qubits": self.layout.qubits + self.scratch}

    def operations(self, reverse=False):
        return selection_operations(tuple(self.inputs[i] for i in range(self.inputs.count)),
                                    self.good, self.ranks, self.packed, self.complete, self.leaves, reverse)

    def execute(self, words, output_seed=None, mode="gates", inverse=True):
        if type(words) not in (list, tuple) or len(words) != self.inputs.count:
            raise ValueError("CONTROL_WORDS")
        if mode not in ("gates", "macro") or type(inverse) is not bool:
            raise ValueError("CONTROL_EXECUTION")
        if output_seed is None:
            output_seed = (0,) * self.packed.count
        if type(output_seed) not in (list, tuple) or len(output_seed) != self.packed.count:
            raise ValueError("CONTROL_OUTPUT_SEED")
        runner = Runner(self, mode)
        for bank, data in ((self.inputs, words), (self.packed, output_seed)):
            for index, value in enumerate(data):
                integer(value, "CONTROL_VALUE", high=(1 << bank.width) - 1)
                reg = bank[index]
                runner.values[reg.index] = value
                if runner.bits is not None:
                    for bit, wire in enumerate(reg.bits()):
                        runner.bits[wire] = value >> bit & 1
        original = list(runner.values)
        original_bits = bytes(runner.bits) if runner.bits is not None else None
        runner.values[self.one.index] = 1
        if runner.bits is not None:
            runner.bits[self.one.wire] ^= 1
        for operation in self.operations():
            runner.apply(operation)
        result = {"packed": [runner.values[self.packed[i].index] for i in range(self.packed.count)],
                  "complete": bool(runner.values[self.complete.index]),
                  "accepted_count": runner.values[self.ranks[self.ranks.count - 1].index]}
        if inverse:
            for operation in self.operations(True):
                runner.apply(operation)
            runner.values[self.one.index] ^= 1
            if runner.bits is not None:
                runner.bits[self.one.wire] ^= 1
        result["restored"] = runner.values == original and (runner.bits is None or bytes(runner.bits) == original_bits)
        if inverse and not result["restored"]:
            raise ValueError("SELECTION_DIRTY_ANCILLA")
        result["leaf_gates_executed"] = runner.executed_gates if mode == "gates" else None
        return result
