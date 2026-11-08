"""Deterministic full-size MU1 fixtures, including every attempted nonce.

Fixtures contain canonical dense and zero task material, not a claim that these
tasks represent an independently sampled workload or have a cost lower bound.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import struct

import mandatory_units_relation as mu


def label(value: str) -> bytes:
    return hashlib.sha256(("MU1 fixture / " + value).encode("ascii")).digest()


def dense_values(name: str) -> tuple[int, ...]:
    return tuple(int.from_bytes(hashlib.sha256(label(name) + struct.pack("<I", i)).digest()[:4],
                                "little") % mu.w1.Q for i in range(mu.w1.CELLS))


def materials() -> dict[str, mu.PreparedMatrices]:
    zero = tuple([0] * mu.w1.CELLS)
    return {"dense": mu.PreparedMatrices(dense_values("A"), dense_values("B")),
            "zero": mu.PreparedMatrices(zero, zero)}


def make_context(tasks: tuple[bytes, ...], *, nonce: int = 0) -> mu.Context:
    return mu.Context(
        network=label("network"), chain_parameters=label("chain-parameters"),
        window_anchor=label("externally-fixed-window-anchor"),
        window_start_height=100, window_end_height=200,
        parent=label("parent"), height=144, timestamp=1_799_999_000,
        miner=label("reward-owner"), tx_root=label("transactions"),
        state_root=label("state"), receipts_root=label("receipts"),
        nonce=nonce, tasks=tasks,
    )


@dataclass(frozen=True)
class Vector:
    name: str
    context: mu.Context
    material: tuple[mu.PreparedMatrices, ...]
    packet: bytes
    attempts: tuple[dict[str, object], ...]


def mine_vector(name: str, material: tuple[mu.PreparedMatrices, ...], *,
                native_prepared: str | Path, max_attempts: int = 256) -> Vector:
    context = make_context(tuple(item.task for item in material))
    attempts = []
    for nonce in range(max_attempts):
        candidate = replace(context, nonce=nonce)
        raw = mu.produce_packet(candidate, material, backend="native-prepared",
                                native_prover=native_prepared)
        parsed = mu.inspect_packet(raw, candidate)
        winner = parsed.ticket <= mu.T0
        attempts.append({
            "nonce": nonce, "aggregate_ticket": parsed.ticket.hex(), "winner": winner,
            "context_hash": parsed.context_hash.hex(), "outputs_root": parsed.outputs_root.hex(),
            "packet_sha256": hashlib.sha256(raw).hexdigest(),
            "unit_proof_sha256": [hashlib.sha256(p).hexdigest() for p in parsed.proofs],
            "constructed_complete_units": len(parsed.proofs),
        })
        if winner:
            return Vector(name, candidate, material, raw, tuple(attempts))
    raise ValueError("BOUNDED_NONCE_SEARCH_EXHAUSTED: " + name + ": " + repr(attempts))


def build_vectors(native_prepared: str | Path) -> tuple[Vector, ...]:
    material = materials()
    return tuple(mine_vector(f"dense-repeat-u{u}", tuple([material["dense"]] * u),
                             native_prepared=native_prepared) for u in (1, 2, 4, 8)) + (
        mine_vector("mixed-dense-zero-u2", (material["dense"], material["zero"]),
                    native_prepared=native_prepared),
    )


def replace_proof(raw: bytes, context: mu.Context, index: int, proof: bytes) -> bytes:
    """Fixture mutation; the verifier, not this helper, decides validity."""
    start = 6 + len(mu.encode_context(context)) + index * mu.UNIT_RECORD_BYTES + 34
    return raw[:start] + proof + raw[start + mu.w1.PROOF_BYTES:]


def mutations(vector: Vector) -> tuple[tuple[str, mu.Context, bytes, str], ...]:
    """Whole-envelope negative controls.  Expected scalar errors are explicit."""
    c, raw = vector.context, vector.packet
    parsed = mu.inspect_packet(raw, c)
    start = 6 + len(mu.encode_context(c))
    proof = parsed.proofs[0]
    out = [
        ("trailing-byte", c, raw + b"\0", "PACKET_LENGTH"),
        ("missing-byte", c, raw[:-1], "PACKET_LENGTH"),
        ("wrong-packet-domain", c, b"PNW1" + raw[4:], "PACKET_VERSION"),
    ]
    for name, changed in (
        ("nonce-rebind", replace(c, nonce=c.nonce + 1)),
        ("parent-rebind", replace(c, parent=label("different-parent"))),
        ("reward-owner-rebind", replace(c, miner=label("different-miner"))),
        ("window-anchor-rebind", replace(c, window_anchor=label("different-anchor"))),
        ("state-root-rebind", replace(c, state_root=label("different-state"))),
    ):
        out.append((name, changed, mu.encode_packet(changed, parsed.proofs), "W1_TRANSCRIPT"))
    bad_field = proof[:4] + struct.pack("<I", mu.w1.Q) + proof[8:]
    out.append(("noncanonical-A-field", c, replace_proof(raw, c, 0, bad_field), "W1_FIELD"))
    product_offset = 4 + 2 * mu.w1.CELLS * 4
    old_value = struct.unpack_from("<I", proof, product_offset)[0]
    bad_product = (proof[:product_offset] + struct.pack("<I", (old_value + 1) % mu.w1.Q)
                   + proof[product_offset + 4:])
    out.append(("correct-trace-wrong-product", c, replace_proof(raw, c, 0, bad_product), "W1_PRODUCT"))
    bad_trace = proof[:-1] + bytes([proof[-1] ^ 1])
    out.append(("correct-product-wrong-trace", c, replace_proof(raw, c, 0, bad_trace), "W1_TRANSCRIPT"))
    if c.units >= 2:
        # Preserve wire indexes for copied-proof and renumbered-reorder tests:
        # these must fail the complete unit relation, not only framing.
        out.append(("duplicate-unit-proof", c, replace_proof(raw, c, 1, proof), "W1_TRANSCRIPT"))
        swapped = mu.encode_packet(c, (parsed.proofs[1], parsed.proofs[0], *parsed.proofs[2:]))
        out.append(("reordered-proofs-renumbered", c, swapped, "W1_TRANSCRIPT"))
        duplicated_index = raw[:start + mu.UNIT_RECORD_BYTES] + struct.pack("<H", 0) + raw[start + mu.UNIT_RECORD_BYTES + 2:]
        out.append(("duplicate-wire-index", c, duplicated_index, "UNIT_ORDER"))
        missing = raw[:start + mu.UNIT_RECORD_BYTES] + raw[start + 2 * mu.UNIT_RECORD_BYTES:]
        out.append(("missing-unit", c, missing, "PACKET_LENGTH"))
        smaller = replace(c, tasks=c.tasks[:-1])
        out.append(("reused-prefix-smaller-u", smaller,
                    mu.encode_packet(smaller, parsed.proofs[:-1]), "W1_TRANSCRIPT"))
    return tuple(out)
