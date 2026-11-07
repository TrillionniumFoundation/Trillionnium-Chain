"""MU1: frozen, unactivated mandatory full-W1-unit research relation.

Every unit is the complete existing PNW1 relation at the maximal *unit* target.
Only the final MU1 aggregate predicate uses T0.  No native header, chainwork,
admission rule, activation or claimed minimum mining cost is changed here.
See MANDATORY_UNITS_RELATION_V1.md for the exact statement and scope.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
from pathlib import Path
import struct

from bounded_process import run_bounded
from contract_wire import H as w1_hash
import work_oracle as w1


DOMAIN = b"TRNM-PON-MU1\0"
PROFILE = b"pon-mandatory-w1-64-research-v1"
CONTEXT_MAGIC = b"PMH1"
PACKET_MAGIC = b"PMU1"
VERSION = 1
U_MIN, U_MAX = 1, 8
T0 = ((1 << 252) - 1).to_bytes(32, "big")
IDEAL_TICKET_PROBABILITY = Fraction(1, 16)
BASE_CREDIT = 16
MAX_CREDIT = BASE_CREDIT * U_MAX
UNIT_TARGET = bytes([255]) * 32
UNIT_RECORD_BYTES = 2 + 32 + w1.PROOF_BYTES
CONTEXT_BASE_BYTES = 368
PACKET_BASE_BYTES = 6 + CONTEXT_BASE_BYTES
PACKET_UNIT_BYTES = 32 + UNIT_RECORD_BYTES
MAX_PACKET_BYTES = PACKET_BASE_BYTES + U_MAX * PACKET_UNIT_BYTES


class RelationError(ValueError):
    """A specific refusal; never a successful mock or a work receipt."""


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RelationError(code)


def _uint(value: int, bits: int, code: str) -> int:
    _need(type(value) is int and 0 <= value < (1 << bits), code)
    return value


def _hash32(value: bytes, code: str) -> bytes:
    _need(type(value) is bytes and len(value) == 32, code)
    return value


def mu_hash(tag: bytes, *parts: bytes) -> bytes:
    _need(type(tag) is bytes and len(tag) < (1 << 16), "HASH_TAG")
    h = hashlib.sha256(DOMAIN + struct.pack("<H", len(tag)) + tag)
    for part in parts:
        _need(type(part) is bytes and len(part) < (1 << 32), "HASH_PART")
        h.update(struct.pack("<I", len(part)))
        h.update(part)
    return h.digest()


PARAMETER_BYTES = (
    PROFILE + b"\0" + struct.pack("<HIIIIHHI", VERSION, w1.N, w1.R,
                                    w1.Q, w1.PROOF_BYTES, U_MIN, U_MAX,
                                    BASE_CREDIT)
    + T0 + b"PNW1\0ordered-indexed-full-transcript\0single-final-ticket\0"
)
RELATION_PARAMETERS = mu_hash(b"parameters", PARAMETER_BYTES)


@dataclass(frozen=True)
class Context:
    network: bytes
    chain_parameters: bytes
    window_anchor: bytes
    window_start_height: int
    window_end_height: int
    parent: bytes
    height: int
    timestamp: int
    miner: bytes
    tx_root: bytes
    state_root: bytes
    receipts_root: bytes
    nonce: int
    tasks: tuple[bytes, ...]
    target: bytes = T0
    relation_parameters: bytes = RELATION_PARAMETERS

    @property
    def units(self) -> int:
        return len(self.tasks)


def encode_context(c: Context) -> bytes:
    _need(type(c) is Context, "CONTEXT_TYPE")
    for name in ("network", "chain_parameters", "window_anchor", "parent",
                 "miner", "tx_root", "state_root", "receipts_root", "target",
                 "relation_parameters"):
        _hash32(getattr(c, name), "CONTEXT_HASH")
    for name in ("window_start_height", "window_end_height", "height", "timestamp", "nonce"):
        _uint(getattr(c, name), 64, "CONTEXT_U64")
    _need(c.window_start_height <= c.height <= c.window_end_height, "HEIGHT_WINDOW")
    _need(type(c.tasks) is tuple and U_MIN <= len(c.tasks) <= U_MAX, "UNIT_COUNT")
    for task in c.tasks:
        _hash32(task, "TASK_HASH")
    _need(c.target == T0, "FIXED_TARGET")
    _need(c.relation_parameters == RELATION_PARAMETERS, "RELATION_PARAMETERS")
    # Repeated task contents are expressly legal.  Index and context distinguish
    # unit challenges; banning useful product caches would disguise real reuse.
    return (CONTEXT_MAGIC + struct.pack("<H", VERSION) + c.relation_parameters
            + c.network + c.chain_parameters + c.window_anchor
            + struct.pack("<QQ", c.window_start_height, c.window_end_height)
            + c.parent + struct.pack("<QQ", c.height, c.timestamp) + c.miner
            + c.tx_root + c.state_root + c.receipts_root + c.target
            + struct.pack("<QH", c.nonce, c.units) + b"".join(c.tasks))


def decode_context(raw: bytes) -> Context:
    _need(type(raw) is bytes and len(raw) >= CONTEXT_BASE_BYTES, "CONTEXT_LENGTH")
    _need(raw[:6] == CONTEXT_MAGIC + struct.pack("<H", VERSION), "CONTEXT_VERSION")
    offset = 6

    def h() -> bytes:
        nonlocal offset
        value = raw[offset:offset + 32]
        offset += 32
        return value

    relation_parameters, network, chain_parameters, anchor = h(), h(), h(), h()
    start, end = struct.unpack_from("<QQ", raw, offset)
    offset += 16
    parent = h()
    height, timestamp = struct.unpack_from("<QQ", raw, offset)
    offset += 16
    miner, tx_root, state_root, receipts_root, target = h(), h(), h(), h(), h()
    nonce, units = struct.unpack_from("<QH", raw, offset)
    offset += 10
    _need(offset == CONTEXT_BASE_BYTES, "INTERNAL_CONTEXT_LAYOUT")
    _need(U_MIN <= units <= U_MAX, "UNIT_COUNT")
    _need(len(raw) == CONTEXT_BASE_BYTES + 32 * units, "CONTEXT_LENGTH")
    tasks = tuple(raw[offset + 32 * j:offset + 32 * (j + 1)] for j in range(units))
    c = Context(network, chain_parameters, anchor, start, end, parent, height,
                timestamp, miner, tx_root, state_root, receipts_root, nonce,
                tasks, target, relation_parameters)
    _need(encode_context(c) == raw, "CONTEXT_NONCANONICAL")
    return c


def context_digest(c: Context) -> bytes:
    return mu_hash(b"context", encode_context(c))


def unit_challenge(c: Context, index: int) -> bytes:
    _uint(index, 16, "UNIT_INDEX")
    _need(index < c.units, "UNIT_INDEX")
    return mu_hash(b"unit", context_digest(c), struct.pack("<H", index), c.tasks[index])


@dataclass(frozen=True)
class ParsedPacket:
    context: Context
    proofs: tuple[bytes, ...]
    context_hash: bytes
    outputs_root: bytes
    ticket: bytes
    identity: bytes


def encode_packet(c: Context, proofs: tuple[bytes, ...]) -> bytes:
    context = encode_context(c)
    _need(type(proofs) is tuple and len(proofs) == c.units, "UNIT_COUNT")
    for proof in proofs:
        _need(type(proof) is bytes and len(proof) == w1.PROOF_BYTES, "UNIT_LENGTH")
        _need(proof[:4] == b"PNW1", "UNIT_VERSION")
    return (PACKET_MAGIC + struct.pack("<H", VERSION) + context
            + b"".join(struct.pack("<H", j) + c.tasks[j] + proof
                       for j, proof in enumerate(proofs)))


def inspect_packet(raw: bytes, expected: Context) -> ParsedPacket:
    """Framing, binding and aggregate hash only; NOT a valid-work result."""
    expected_raw = encode_context(expected)
    _need(type(raw) is bytes and len(raw) <= MAX_PACKET_BYTES, "PACKET_LENGTH")
    _need(raw[:6] == PACKET_MAGIC + struct.pack("<H", VERSION), "PACKET_VERSION")
    _need(len(raw) == PACKET_BASE_BYTES + expected.units * PACKET_UNIT_BYTES,
          "PACKET_LENGTH")
    context_end = 6 + len(expected_raw)
    claimed = decode_context(raw[6:context_end])
    _need(raw[6:context_end] == expected_raw and claimed == expected, "EXPECTED_CONTEXT")
    offset, proofs, leaves = context_end, [], []
    digest = mu_hash(b"context", expected_raw)
    for j, task in enumerate(expected.tasks):
        index = struct.unpack_from("<H", raw, offset)[0]
        _need(index == j, "UNIT_ORDER")
        _need(raw[offset + 2:offset + 34] == task, "UNIT_TASK_BINDING")
        proof = raw[offset + 34:offset + UNIT_RECORD_BYTES]
        _need(len(proof) == w1.PROOF_BYTES and proof[:4] == b"PNW1", "UNIT_ENCODING")
        proofs.append(proof)
        leaves.append(mu_hash(b"unit-output", struct.pack("<H", j), task, proof))
        offset += UNIT_RECORD_BYTES
    _need(offset == len(raw), "PACKET_TRAILING")
    root = mu_hash(b"ordered-units", digest, b"".join(leaves))
    ticket = mu_hash(b"ticket", digest, root)
    identity = mu_hash(b"identity", digest, root)
    return ParsedPacket(expected, tuple(proofs), digest, root, ticket, identity)


def _native(path: str | Path | None, mode: str, payload: bytes, size: int) -> bytes:
    _need(path is not None and Path(path).is_file(), "NATIVE_UNAVAILABLE")
    try:
        result = run_bounded([str(path), mode], payload, timeout=30,
                             stdout_limit=size, stderr_limit=4096)
    except ValueError as error:
        raise RelationError(str(error)) from error
    _need(result.returncode == 0, "NATIVE_W1_INVALID")
    _need(len(result.stdout) == size, "NATIVE_OUTPUT_LENGTH")
    return result.stdout


@dataclass(frozen=True)
class VerifiedUnits:
    """Local mathematical result, not a native admission capability."""
    identity: bytes
    ticket: bytes
    outputs_root: bytes
    units: int
    credit: int
    packet_bytes: int


def verify_packet(raw: bytes, expected: Context, *, backend: str = "scalar",
                  native_verifier: str | Path | None = None) -> VerifiedUnits:
    parsed = inspect_packet(raw, expected)
    _need(backend in ("scalar", "native"), "VERIFIER_BACKEND")
    for j, proof in enumerate(parsed.proofs):
        challenge, task = unit_challenge(expected, j), expected.tasks[j]
        if backend == "scalar":
            try:
                w1.verify(challenge, task, UNIT_TARGET, proof)
            except ValueError as error:
                raise RelationError("W1_" + str(error)) from error
        else:
            data = challenge + task + UNIT_TARGET + proof
            receipt = _native(native_verifier, "verify", data, 32)
            _need(receipt == w1_hash("native-work-verification", data), "NATIVE_BINDING")
    _need(parsed.ticket <= T0, "AGGREGATE_TARGET")
    return VerifiedUnits(parsed.identity, parsed.ticket, parsed.outputs_root,
                         expected.units, BASE_CREDIT * expected.units, len(raw))


def transcript_only(challenge: bytes, a: tuple[int, ...], b: tuple[int, ...]) -> bytes:
    """Constructive full trace path; it does NOT impose a producer lower bound."""
    _hash32(challenge, "CHALLENGE")
    w1.check(a)
    w1.check(b)
    el, er, fl, fr = (w1.expand(challenge, label, w1.N * w1.R) for label in range(4))
    e, f = w1.mm(el, er, w1.N, w1.R, w1.N), w1.mm(fl, fr, w1.N, w1.R, w1.N)
    ap = [(x + y) % w1.Q for x, y in zip(a, e)]
    bp = [(x + y) % w1.Q for x, y in zip(b, f)]
    cp = [0] * w1.CELLS
    trace = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    for bi in range(0, w1.N, w1.R):
        for bj in range(0, w1.N, w1.R):
            for bk in range(0, w1.N, w1.R):
                tile = []
                for i in range(bi, bi + w1.R):
                    for j in range(bj, bj + w1.R):
                        pos = i * w1.N + j
                        cp[pos] = (cp[pos] + sum(ap[i * w1.N + k] * bp[k * w1.N + j]
                                                for k in range(bk, bk + w1.R))) % w1.Q
                        tile.append(cp[pos])
                trace.update(w1.field_bytes(tile))
    return trace.digest()


class PreparedMatrices:
    """One lawful exact AB cache reusable across units/nonces/forks.

    Every challenge still uses its full 512-tile trace.  The cache has no
    verification authority and is not serialized as a valid-work receipt.
    """
    def __init__(self, a: tuple[int, ...], b: tuple[int, ...]):
        _need(type(a) is tuple and type(b) is tuple, "MATRIX_TYPE")
        w1.check(a)
        w1.check(b)
        self.a, self.b = a, b
        self.task = w1.task_id(a, b)
        self.product = tuple(w1.mm(a, b, w1.N, w1.N, w1.N))
        self.prefix = b"PNW1" + w1.field_bytes(a) + w1.field_bytes(b) + w1.field_bytes(self.product)

    def prove(self, challenge: bytes) -> bytes:
        return self.prefix + transcript_only(challenge, self.a, self.b)


def produce_packet(c: Context, material: tuple[PreparedMatrices, ...], *,
                   backend: str = "scalar-prepared",
                   native_prover: str | Path | None = None) -> bytes:
    encode_context(c)
    _need(type(material) is tuple and len(material) == c.units, "UNIT_COUNT")
    _need(backend in ("scalar-prepared", "scalar-fresh", "native-fresh", "native-prepared"),
          "PROVER_BACKEND")
    proofs = []
    for j, prepared in enumerate(material):
        _need(type(prepared) is PreparedMatrices and prepared.task == c.tasks[j], "TASK_MATERIAL")
        challenge = unit_challenge(c, j)
        if backend == "scalar-prepared":
            proof = prepared.prove(challenge)
        elif backend == "scalar-fresh":
            proof = w1.prove(challenge, prepared.a, prepared.b)
        else:
            payload = challenge + w1.field_bytes(prepared.a) + w1.field_bytes(prepared.b)
            mode = "prove" if backend == "native-fresh" else "generic"
            proof = _native(native_prover, mode, payload, w1.PROOF_BYTES)
        proofs.append(proof)
    return encode_packet(c, tuple(proofs))


class UniqueWorkCounter:
    """In-memory research accounting across all supplied branches.

    Not a consensus spent set, persistence mechanism or reorg policy.  Shared
    prefixes and repeated deliveries add zero to the all-branch unique-work
    observation.  Every submission is reverified before it can add credit.
    """
    def __init__(self):
        self._seen: set[bytes] = set()
        self.total_credit = 0

    def admit(self, raw: bytes, expected: Context, **verification_options) -> int:
        checked = verify_packet(raw, expected, **verification_options)
        if checked.identity in self._seen:
            return 0
        self._seen.add(checked.identity)
        self.total_credit += checked.credit
        return checked.credit


def canonical_byte_credit_bound(serialized_octets: int) -> Fraction:
    """Only for an explicit model charging every canonical packet octet.

    This is not a compression-resistant communication, FLOP, gate or time bound.
    """
    _uint(serialized_octets, 64, "SERIALIZED_OCTETS")
    return Fraction(BASE_CREDIT * serialized_octets, PACKET_UNIT_BYTES)


CLAIMS = {
    "frozen_research_relation": True,
    "all_units_full_existing_w1_relation": True,
    "one_final_aggregate_lottery": True,
    "native_consensus_activation": False,
    "actual_sha_independent_uniform_tickets_proved": False,
    "all_algorithm_minimum_gate_cost_proved": False,
    "physical_resource_tail_proved": False,
    "native_six_successor_risk_certified": False,
    "production_qualified": False,
}
