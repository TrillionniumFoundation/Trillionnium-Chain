#!/usr/bin/env python3
"""Reconstruct PoCO-BFT v0 weighted QC/TC vectors without third-party code.

The fixture seeds exist only in this checker.  The committed JSON exposes
public keys, full CEV0 objects, signing roots, and signatures, but no private
key material.  The Ed25519 implementation below is intentionally small and is
cross-checked against RFC 8032 test 1 before any protocol vector is accepted.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR = (
    REPO_ROOT / "docs/protocol/poco-bft-v0/vectors/qc-tc-threshold-v0.json"
)
HASH_PREFIX = b"trnm.cev0.hash.v0"
DOMAIN_VOTE = b"trnm.poco-bft.vote.v0"
DOMAIN_TIMEOUT = b"trnm.poco-bft.timeout.v0"
DOMAIN_QC = b"trnm.poco-bft.qc.v0"
DOMAIN_TC = b"trnm.poco-bft.tc.v0"
DOMAIN_VALIDATOR_SET = b"trnm.poco-bft.validator-set.v0"

# RFC 8032 / Ed25519 constants.
FIELD = 2**255 - 19
GROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
CURVE_D = (-121665 * pow(121666, FIELD - 2, FIELD)) % FIELD
SQRT_MINUS_ONE = pow(2, (FIELD - 1) // 4, FIELD)
IDENTITY = (0, 1, 1, 0)


class VectorError(ValueError):
    pass


def uint(value: int, bits: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VectorError(f"u{bits} value is not an integer")
    if value < 0 or value >= 1 << bits:
        raise VectorError(f"value {value} is outside u{bits}")
    return value.to_bytes(bits // 8, "big")


def fixed_hex(value: str, length: int, label: str) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise VectorError(f"{label} is not lowercase hexadecimal") from error
    if value != value.lower() or decoded.hex() != value:
        raise VectorError(f"{label} is not canonical lowercase hexadecimal")
    if len(decoded) != length:
        raise VectorError(f"{label} must contain exactly {length} bytes")
    return decoded


def cev0_bytes(value: bytes) -> bytes:
    return uint(len(value), 32) + value


def consensus_string(value: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise VectorError("ConsensusString must be ASCII") from error
    allowed = b"abcdefghijklmnopqrstuvwxyz0123456789._:-"
    if not encoded or len(encoded) > 128 or encoded[0] not in allowed[:36]:
        raise VectorError("ConsensusString violates its length or first-byte rule")
    if any(byte not in allowed for byte in encoded[1:]):
        raise VectorError("ConsensusString violates its frozen grammar")
    return uint(len(encoded), 16) + encoded


def cev0_list(values: Iterable[bytes]) -> bytes:
    items = tuple(values)
    return uint(len(items), 32) + b"".join(items)


def framed(value: bytes) -> bytes:
    return uint(len(value), 32) + value


def cev0_digest(domain: bytes, encoded: bytes) -> bytes:
    return hashlib.sha256(
        framed(HASH_PREFIX) + framed(domain) + framed(encoded)
    ).digest()


def point_add(first: tuple[int, int, int, int], second: tuple[int, int, int, int]):
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = ((y1 - x1) * (y2 - x2)) % FIELD
    b = ((y1 + x1) * (y2 + x2)) % FIELD
    c = (2 * CURVE_D * t1 * t2) % FIELD
    d = (2 * z1 * z2) % FIELD
    e = (b - a) % FIELD
    f = (d - c) % FIELD
    g = (d + c) % FIELD
    h = (b + a) % FIELD
    return (e * f % FIELD, g * h % FIELD, f * g % FIELD, e * h % FIELD)


def point_double(point: tuple[int, int, int, int]):
    x, y, z, _ = point
    a = x * x % FIELD
    b = y * y % FIELD
    c = 2 * z * z % FIELD
    d = -a % FIELD
    e = ((x + y) * (x + y) - a - b) % FIELD
    g = (d + b) % FIELD
    f = (g - c) % FIELD
    h = (d - b) % FIELD
    return (e * f % FIELD, g * h % FIELD, f * g % FIELD, e * h % FIELD)


def scalar_multiply(point: tuple[int, int, int, int], scalar: int):
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        scalar >>= 1
    return result


def affine(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    inverse = pow(z, FIELD - 2, FIELD)
    return x * inverse % FIELD, y * inverse % FIELD


def points_equal(first, second) -> bool:
    return (
        (first[0] * second[2] - second[0] * first[2]) % FIELD == 0
        and (first[1] * second[2] - second[1] * first[2]) % FIELD == 0
    )


def recover_x(y: int, sign: int) -> int | None:
    numerator = (y * y - 1) % FIELD
    denominator = (CURVE_D * y * y + 1) % FIELD
    x_squared = numerator * pow(denominator, FIELD - 2, FIELD) % FIELD
    x = pow(x_squared, (FIELD + 3) // 8, FIELD)
    if (x * x - x_squared) % FIELD != 0:
        x = x * SQRT_MINUS_ONE % FIELD
    if (x * x - x_squared) % FIELD != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = FIELD - x
    return x


BASE_Y = 4 * pow(5, FIELD - 2, FIELD) % FIELD
BASE_X = recover_x(BASE_Y, 0)
if BASE_X is None:  # pragma: no cover - module invariant
    raise RuntimeError("failed to construct the RFC 8032 base point")
BASE_POINT = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % FIELD)


def encode_point(point) -> bytes:
    x, y = affine(point)
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def decode_point(encoded: bytes):
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= FIELD:
        return None
    x = recover_x(y, sign)
    if x is None:
        return None
    point = (x, y, 1, x * y % FIELD)
    # Strict verification rejects weak/small-order public keys and R values.
    if points_equal(scalar_multiply(point, 8), IDENTITY):
        return None
    return point


def secret_scalar(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise VectorError("Ed25519 seed must contain 32 bytes")
    expanded = bytearray(hashlib.sha512(seed).digest())
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    return int.from_bytes(expanded[:32], "little"), bytes(expanded[32:])


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = secret_scalar(seed)
    return encode_point(scalar_multiply(BASE_POINT, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = secret_scalar(seed)
    public_key = encode_point(scalar_multiply(BASE_POINT, scalar))
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % GROUP_ORDER
    encoded_r = encode_point(scalar_multiply(BASE_POINT, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % GROUP_ORDER
    s = (nonce + challenge * scalar) % GROUP_ORDER
    return encoded_r + s.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public_point = decode_point(public_key)
    r_point = decode_point(signature[:32])
    if public_point is None or r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= GROUP_ORDER:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % GROUP_ORDER
    return points_equal(
        scalar_multiply(BASE_POINT, s),
        point_add(r_point, scalar_multiply(public_point, challenge)),
    )


def ed25519_self_test() -> None:
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    expected_public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    expected_signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    if ed25519_public_key(seed) != expected_public:
        raise VectorError("Ed25519 key generation failed RFC 8032 test 1")
    if ed25519_sign(seed, b"") != expected_signature:
        raise VectorError("Ed25519 signing failed RFC 8032 test 1")
    if not ed25519_verify(expected_public, b"", expected_signature):
        raise VectorError("Ed25519 verification failed RFC 8032 test 1")


def common_context(context: dict[str, object], view: int, kind: int) -> bytes:
    return b"".join(
        (
            uint(0, 16),
            fixed_hex(str(context["genesis_hash_hex"]), 32, "genesis hash"),
            consensus_string(str(context["chain_id"])),
            uint(int(context["protocol_version"]), 32),
            uint(int(context["epoch"]), 64),
            fixed_hex(
                str(context["validator_set_id_hex"]), 32, "validator-set ID"
            ),
            uint(view, 64),
            uint(kind, 8),
        )
    )


def validator_set_cev0(context: dict[str, object], validators: list[dict[str, object]]) -> bytes:
    entries = []
    for validator in validators:
        entries.append(
            cev0_bytes(str(validator["id_ascii"]).encode("ascii"))
            + fixed_hex(str(validator["public_key_hex"]), 32, "validator public key")
            + uint(int(validator["power"]), 64)
        )
    return b"".join(
        (
            uint(0, 16),
            fixed_hex(str(context["genesis_hash_hex"]), 32, "genesis hash"),
            consensus_string(str(context["chain_id"])),
            uint(int(context["protocol_version"]), 32),
            uint(int(context["epoch"]), 64),
            fixed_hex(
                str(context["consensus_parameters_hash_hex"]),
                32,
                "consensus-parameters hash",
            ),
            cev0_list(entries),
        )
    )


def vote_preimage(context: dict[str, object], qc: dict[str, object]) -> bytes:
    return (
        common_context(context, int(qc["view"]), 1)
        + uint(int(qc["height"]), 64)
        + fixed_hex(str(qc["block_id_hex"]), 32, "QC block ID")
    )


def qc_signing_root(context: dict[str, object], qc: dict[str, object]) -> bytes:
    return cev0_digest(DOMAIN_VOTE, vote_preimage(context, qc))


def qc_cev0(context: dict[str, object], qc: dict[str, object]) -> bytes:
    votes = []
    for vote in qc["votes"]:
        votes.append(
            cev0_bytes(str(vote["signer_id_ascii"]).encode("ascii"))
            + fixed_hex(str(vote["signature_hex"]), 64, "QC vote signature")
        )
    return b"".join(
        (
            uint(0, 16),
            fixed_hex(str(context["genesis_hash_hex"]), 32, "genesis hash"),
            consensus_string(str(context["chain_id"])),
            uint(int(context["protocol_version"]), 32),
            uint(int(context["epoch"]), 64),
            fixed_hex(str(context["validator_set_id_hex"]), 32, "validator-set ID"),
            uint(int(qc["view"]), 64),
            uint(int(qc["height"]), 64),
            fixed_hex(str(qc["block_id_hex"]), 32, "QC block ID"),
            cev0_list(votes),
        )
    )


def qc_id(context: dict[str, object], qc: dict[str, object]) -> bytes:
    return cev0_digest(DOMAIN_QC, qc_cev0(context, qc))


def qc_ref(context: dict[str, object], qc: dict[str, object]) -> dict[str, object]:
    return {
        "qc_digest_hex": qc_id(context, qc).hex(),
        "epoch": int(context["epoch"]),
        "view": int(qc["view"]),
        "height": int(qc["height"]),
        "block_id_hex": str(qc["block_id_hex"]),
        "validator_set_id_hex": str(context["validator_set_id_hex"]),
    }


def encode_qc_ref(reference: dict[str, object]) -> bytes:
    return b"".join(
        (
            fixed_hex(str(reference["qc_digest_hex"]), 32, "QC digest"),
            uint(int(reference["epoch"]), 64),
            uint(int(reference["view"]), 64),
            uint(int(reference["height"]), 64),
            fixed_hex(str(reference["block_id_hex"]), 32, "QC block ID"),
        )
    )


def timeout_signing_root(
    context: dict[str, object], timed_out_view: int, reference: dict[str, object]
) -> bytes:
    return cev0_digest(
        DOMAIN_TIMEOUT,
        common_context(context, timed_out_view, 2) + encode_qc_ref(reference),
    )


def tc_cev0(
    context: dict[str, object],
    tc: dict[str, object],
    qcs: dict[str, dict[str, object]],
) -> bytes:
    entries = []
    for entry in tc["entries"]:
        entries.append(
            cev0_bytes(str(entry["signer_id_ascii"]).encode("ascii"))
            + encode_qc_ref(entry["high_qc"])
            + fixed_hex(str(entry["signature_hex"]), 64, "timeout signature")
        )
    referenced = [qc_cev0(context, qcs[label]) for label in tc["referenced_qcs"]]
    return b"".join(
        (
            uint(0, 16),
            fixed_hex(str(context["genesis_hash_hex"]), 32, "genesis hash"),
            consensus_string(str(context["chain_id"])),
            uint(int(context["protocol_version"]), 32),
            uint(int(context["epoch"]), 64),
            fixed_hex(str(context["validator_set_id_hex"]), 32, "validator-set ID"),
            uint(int(tc["timed_out_view"]), 64),
            cev0_list(entries),
            cev0_list(referenced),
            fixed_hex(str(tc["selected_high_qc_digest_hex"]), 32, "selected QC"),
        )
    )


def validator_map(data: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(validator["id_ascii"]): validator
        for validator in data["validator_set"]["validators"]
    }


def validate_qc(
    context: dict[str, object],
    validators: dict[str, dict[str, object]],
    quorum: int,
    qc: dict[str, object],
) -> str:
    previous: bytes | None = None
    signed_power = 0
    root = qc_signing_root(context, qc)
    for vote in qc["votes"]:
        signer = str(vote["signer_id_ascii"])
        signer_bytes = signer.encode("ascii")
        if previous == signer_bytes:
            return "duplicate_signer"
        if previous is not None and previous > signer_bytes:
            return "noncanonical_signer_order"
        previous = signer_bytes
        validator = validators.get(signer)
        if validator is None:
            return "unknown_signer"
        signature = fixed_hex(str(vote["signature_hex"]), 64, "QC signature")
        public_key = fixed_hex(str(validator["public_key_hex"]), 32, "public key")
        if not ed25519_verify(public_key, root, signature):
            return "invalid_signature"
        signed_power += int(validator["power"])
    if signed_power < quorum:
        return "insufficient_quorum"
    return "valid"


def validate_tc(
    context: dict[str, object],
    validators: dict[str, dict[str, object]],
    quorum: int,
    tc: dict[str, object],
    qcs: dict[str, dict[str, object]],
) -> str:
    referenced: list[tuple[str, dict[str, object], dict[str, object]]] = []
    previous_id: bytes | None = None
    coordinates: dict[tuple[int, int], tuple[int, str]] = {}
    block_coordinates: dict[str, tuple[int, int, int]] = {}
    timed_out_view = int(tc["timed_out_view"])
    for label in tc["referenced_qcs"]:
        qc = qcs.get(str(label))
        if qc is None:
            return "unknown_referenced_qc"
        if validate_qc(context, validators, quorum, qc) != "valid":
            return "invalid_referenced_qc"
        reference = qc_ref(context, qc)
        if (
            int(reference["epoch"]) != int(context["epoch"])
            or reference["validator_set_id_hex"] != context["validator_set_id_hex"]
        ):
            return "reference_context_mismatch"
        # The frozen Rust relation permits equality and rejects only a QC from
        # a strictly future view.
        if int(reference["view"]) > timed_out_view:
            return "future_reference_view"
        identifier = fixed_hex(str(reference["qc_digest_hex"]), 32, "QC digest")
        if previous_id is not None and previous_id >= identifier:
            return "noncanonical_qc_order"
        previous_id = identifier
        coordinate = (int(reference["epoch"]), int(reference["view"]))
        certified = (int(reference["height"]), str(reference["block_id_hex"]))
        if coordinate in coordinates and coordinates[coordinate] != certified:
            return "conflicting_same_view_qc"
        coordinates[coordinate] = certified
        block_id = str(reference["block_id_hex"])
        block_coordinate = (
            int(reference["epoch"]),
            int(reference["view"]),
            int(reference["height"]),
        )
        if (
            block_id in block_coordinates
            and block_coordinates[block_id] != block_coordinate
        ):
            return "same_block_different_coordinates"
        block_coordinates[block_id] = block_coordinate
        referenced.append((str(label), qc, reference))

    if not referenced:
        return "missing_reference"
    previous_signer: bytes | None = None
    used: set[str] = set()
    maximum: tuple[int, bytes, bytes] | None = None
    signed_power = 0
    for entry in tc["entries"]:
        signer = str(entry["signer_id_ascii"])
        signer_bytes = signer.encode("ascii")
        if previous_signer == signer_bytes:
            return "duplicate_signer"
        if previous_signer is not None and previous_signer > signer_bytes:
            return "noncanonical_signer_order"
        previous_signer = signer_bytes
        validator = validators.get(signer)
        if validator is None:
            return "unknown_signer"
        matching = [
            label for label, _, reference in referenced if reference == entry["high_qc"]
        ]
        if len(matching) != 1:
            return "reference_summary_mismatch"
        used.add(matching[0])
        reference = entry["high_qc"]
        candidate = (
            int(reference["view"]),
            fixed_hex(str(reference["block_id_hex"]), 32, "QC block ID"),
            fixed_hex(str(reference["qc_digest_hex"]), 32, "QC digest"),
        )
        maximum = candidate if maximum is None or candidate > maximum else maximum
        root = timeout_signing_root(context, timed_out_view, reference)
        if not ed25519_verify(
            fixed_hex(str(validator["public_key_hex"]), 32, "public key"),
            root,
            fixed_hex(str(entry["signature_hex"]), 64, "timeout signature"),
        ):
            return "invalid_signature"
        signed_power += int(validator["power"])
    if used != {label for label, _, _ in referenced}:
        return "unreferenced_qc"
    selected = fixed_hex(
        str(tc["selected_high_qc_digest_hex"]), 32, "selected QC digest"
    )
    if maximum is None or selected != maximum[2]:
        return "selected_not_maximum"
    if signed_power < quorum:
        return "insufficient_quorum"
    return "valid"


def fixture_seed(label: str) -> bytes:
    # Deliberately never emitted into the public JSON.
    return hashlib.sha256(b"trnm.poco-bft.qc-tc.private-fixture.v0:" + label.encode()).digest()


def fixture_hash(label: str) -> str:
    return hashlib.sha256(b"trnm.poco-bft.qc-tc.public-fixture.v0:" + label.encode()).hexdigest()


def sign_qc(
    context: dict[str, object],
    qc: dict[str, object],
    signers: list[str],
    roots: dict[str, bytes] | None = None,
) -> dict[str, object]:
    value = copy.deepcopy(qc)
    object_root = qc_signing_root(context, value)
    roots = roots or {}
    value["votes"] = []
    for signer in signers:
        signed_root = roots.get(signer, object_root)
        value["votes"].append(
            {
                "signer_id_ascii": signer,
                "signing_root_hex": object_root.hex(),
                "signature_hex": ed25519_sign(fixture_seed(signer), signed_root).hex(),
            }
        )
    return value


def finalize_qc(context: dict[str, object], qc: dict[str, object], power: int, valid: bool):
    value = copy.deepcopy(qc)
    encoded = qc_cev0(context, value)
    value["signed_power"] = power
    value["cev0_hex"] = encoded.hex()
    value["digest_hex"] = cev0_digest(DOMAIN_QC, encoded).hex()
    value["expected_result"] = "valid" if valid else "insufficient_quorum"
    return value


def make_tc_entry(
    context: dict[str, object],
    timed_out_view: int,
    signer: str,
    reference: dict[str, object],
) -> dict[str, object]:
    root = timeout_signing_root(context, timed_out_view, reference)
    return {
        "signer_id_ascii": signer,
        "high_qc": copy.deepcopy(reference),
        "signing_root_hex": root.hex(),
        "signature_hex": ed25519_sign(fixture_seed(signer), root).hex(),
    }


def finalize_tc(
    context: dict[str, object],
    tc: dict[str, object],
    qcs: dict[str, dict[str, object]],
    expected: str,
) -> dict[str, object]:
    value = copy.deepcopy(tc)
    encoded = tc_cev0(context, value, qcs)
    value["cev0_hex"] = encoded.hex()
    value["digest_hex"] = cev0_digest(DOMAIN_TC, encoded).hex()
    value["expected_result"] = expected
    return value


def build_vectors() -> dict[str, object]:
    ed25519_self_test()
    validator_specs = [
        ("validator-a", 4),
        ("validator-b", 3),
        ("validator-c", 2),
        ("validator-d", 1),
    ]
    validators = [
        {
            "id_ascii": identifier,
            "power": power,
            "public_key_hex": ed25519_public_key(fixture_seed(identifier)).hex(),
        }
        for identifier, power in validator_specs
    ]
    context: dict[str, object] = {
        "genesis_hash_hex": fixture_hash("genesis"),
        "chain_id": "trnm-qc-tc-v0",
        "protocol_version": 0,
        "epoch": 7,
        "consensus_parameters_hash_hex": fixture_hash("consensus-parameters"),
    }
    validator_set_bytes = validator_set_cev0(context, validators)
    context["validator_set_id_hex"] = cev0_digest(
        DOMAIN_VALIDATOR_SET, validator_set_bytes
    ).hex()

    low_base = {
        "view": 3,
        "height": 11,
        "block_id_hex": fixture_hash("low-block"),
    }
    high_base = {
        "view": 5,
        "height": 13,
        "block_id_hex": fixture_hash("high-block"),
    }
    future_base = {
        "view": 10,
        "height": 15,
        "block_id_hex": fixture_hash("future-block"),
    }
    same_block_variant_base = {
        "view": 4,
        "height": 12,
        "block_id_hex": low_base["block_id_hex"],
    }
    low = finalize_qc(
        context,
        sign_qc(context, low_base, ["validator-a", "validator-b"]),
        7,
        True,
    )
    high = finalize_qc(
        context,
        sign_qc(context, high_base, ["validator-a", "validator-b"]),
        7,
        True,
    )
    one_below = finalize_qc(
        context,
        sign_qc(context, high_base, ["validator-b", "validator-c", "validator-d"]),
        6,
        False,
    )
    future = finalize_qc(
        context,
        sign_qc(context, future_base, ["validator-a", "validator-b"]),
        7,
        True,
    )
    same_block_variant = finalize_qc(
        context,
        sign_qc(
            context,
            same_block_variant_base,
            ["validator-a", "validator-b"],
        ),
        7,
        True,
    )
    high_alternate = finalize_qc(
        context,
        sign_qc(
            context,
            high_base,
            ["validator-a", "validator-c", "validator-d"],
        ),
        7,
        True,
    )
    qcs = {
        "low_exact_7": low,
        "high_exact_7": high,
        "future_exact_7": future,
        "same_block_variant_exact_7": same_block_variant,
        "high_alternate_exact_7": high_alternate,
        "one_below_6": one_below,
    }
    reference_qcs = {
        label: value
        for label, value in qcs.items()
        if value["expected_result"] == "valid"
    }
    exact_qcs = {"low_exact_7": low, "high_exact_7": high}
    reference_labels = sorted(exact_qcs, key=lambda label: qc_id(context, exact_qcs[label]))
    low_ref = qc_ref(context, low)
    high_ref = qc_ref(context, high)
    timed_out_view = 9
    tc = {
        "timed_out_view": timed_out_view,
        "entries": [
            make_tc_entry(context, timed_out_view, "validator-a", low_ref),
            make_tc_entry(context, timed_out_view, "validator-c", high_ref),
            make_tc_entry(context, timed_out_view, "validator-d", high_ref),
        ],
        "referenced_qcs": reference_labels,
        "selected_high_qc_digest_hex": high_ref["qc_digest_hex"],
        "signed_power": 7,
    }
    valid_tc = finalize_tc(context, tc, reference_qcs, "valid")

    tie_labels = sorted(
        ["high_exact_7", "high_alternate_exact_7"],
        key=lambda label: qc_id(context, reference_qcs[label]),
    )
    tie_lower_ref = qc_ref(context, reference_qcs[tie_labels[0]])
    tie_greater_ref = qc_ref(context, reference_qcs[tie_labels[1]])
    digest_tiebreak_tc = {
        "timed_out_view": timed_out_view,
        "entries": [
            make_tc_entry(context, timed_out_view, "validator-a", tie_lower_ref),
            make_tc_entry(context, timed_out_view, "validator-c", tie_greater_ref),
            make_tc_entry(context, timed_out_view, "validator-d", tie_greater_ref),
        ],
        "referenced_qcs": tie_labels,
        "selected_high_qc_digest_hex": tie_greater_ref["qc_digest_hex"],
        "signed_power": 7,
        "selection_rule_witness": "same view and block; greater qc_digest wins",
    }
    valid_digest_tiebreak_tc = finalize_tc(
        context, digest_tiebreak_tc, reference_qcs, "valid"
    )

    negative_cases: list[dict[str, object]] = []
    negative_cases.append(
        {
            "id": "qc_one_below_threshold",
            "object_type": "qc",
            "rust_error_contains": "InsufficientQuorum",
            "object": copy.deepcopy(one_below),
        }
    )
    duplicate_qc = sign_qc(context, low_base, ["validator-a", "validator-a"])
    out_of_order_qc = sign_qc(context, low_base, ["validator-b", "validator-a"])
    unknown_qc = sign_qc(context, low_base, ["validator-a"])
    unknown_qc["votes"].append(
        {
            "signer_id_ascii": "validator-z",
            "signing_root_hex": qc_signing_root(context, unknown_qc).hex(),
            "signature_hex": unknown_qc["votes"][0]["signature_hex"],
        }
    )
    alternate_block_qc = copy.deepcopy(low_base)
    alternate_block_qc["block_id_hex"] = fixture_hash("wrong-block")
    wrong_block_root = qc_signing_root(context, alternate_block_qc)
    wrong_block_qc = sign_qc(
        context,
        low_base,
        ["validator-a", "validator-b"],
        {"validator-b": wrong_block_root},
    )
    wrong_context = copy.deepcopy(context)
    wrong_context["epoch"] = int(context["epoch"]) + 1
    wrong_context_root = qc_signing_root(wrong_context, low_base)
    wrong_context_qc = sign_qc(
        context,
        low_base,
        ["validator-a", "validator-b"],
        {"validator-b": wrong_context_root},
    )
    wrong_domain_root = cev0_digest(DOMAIN_TIMEOUT, vote_preimage(context, low_base))
    wrong_domain_qc = sign_qc(
        context,
        low_base,
        ["validator-a", "validator-b"],
        {"validator-b": wrong_domain_root},
    )
    bad_signature_qc = sign_qc(context, low_base, ["validator-a", "validator-b"])
    bad_signature = bytearray.fromhex(bad_signature_qc["votes"][1]["signature_hex"])
    bad_signature[0] ^= 1
    bad_signature_qc["votes"][1]["signature_hex"] = bytes(bad_signature).hex()
    qc_mutations = [
        ("qc_duplicate_signer", duplicate_qc, "duplicate_signer", "DuplicateSigner", None),
        (
            "qc_noncanonical_signer_order",
            out_of_order_qc,
            "noncanonical_signer_order",
            "NonCanonicalSignerOrder",
            None,
        ),
        ("qc_unknown_signer", unknown_qc, "unknown_signer", "UnknownValidator", None),
        (
            "qc_wrong_block_root",
            wrong_block_qc,
            "invalid_signature",
            "InvalidSignature",
            wrong_block_root.hex(),
        ),
        (
            "qc_wrong_context_root",
            wrong_context_qc,
            "invalid_signature",
            "InvalidSignature",
            wrong_context_root.hex(),
        ),
        (
            "qc_wrong_domain_root",
            wrong_domain_qc,
            "invalid_signature",
            "InvalidSignature",
            wrong_domain_root.hex(),
        ),
        (
            "qc_bad_signature",
            bad_signature_qc,
            "invalid_signature",
            "InvalidSignature",
            None,
        ),
    ]
    for identifier, value, expected, rust_error, signed_root in qc_mutations:
        encoded = qc_cev0(context, value)
        case = {
            "id": identifier,
            "object_type": "qc",
            "rust_error_contains": rust_error,
            "object": {
                **value,
                "cev0_hex": encoded.hex(),
                "digest_hex": cev0_digest(DOMAIN_QC, encoded).hex(),
                "expected_result": expected,
            },
        }
        if signed_root is not None:
            case["mutation_signed_root_hex"] = signed_root
        negative_cases.append(case)

    below_tc = copy.deepcopy(tc)
    below_tc["entries"] = [
        make_tc_entry(context, timed_out_view, "validator-b", low_ref),
        make_tc_entry(context, timed_out_view, "validator-c", high_ref),
        make_tc_entry(context, timed_out_view, "validator-d", high_ref),
    ]
    below_tc["signed_power"] = 6
    missing_reference_tc = copy.deepcopy(tc)
    missing_reference_tc["referenced_qcs"] = ["high_exact_7"]
    selected_wrong_tc = copy.deepcopy(tc)
    selected_wrong_tc["selected_high_qc_digest_hex"] = low_ref["qc_digest_hex"]
    summary_conflict_tc = copy.deepcopy(tc)
    summary_conflict_tc["entries"][1]["high_qc"]["height"] = int(high_ref["height"]) + 1
    conflicting_ref = summary_conflict_tc["entries"][1]["high_qc"]
    conflict_root = timeout_signing_root(context, timed_out_view, conflicting_ref)
    summary_conflict_tc["entries"][1]["signing_root_hex"] = conflict_root.hex()
    summary_conflict_tc["entries"][1]["signature_hex"] = ed25519_sign(
        fixture_seed("validator-c"), conflict_root
    ).hex()
    reference_order_tc = copy.deepcopy(tc)
    reference_order_tc["referenced_qcs"] = list(reversed(reference_labels))
    duplicate_tc = copy.deepcopy(tc)
    duplicate_tc["entries"] = [
        make_tc_entry(context, timed_out_view, "validator-a", low_ref),
        make_tc_entry(context, timed_out_view, "validator-a", high_ref),
    ]
    out_of_order_tc = copy.deepcopy(tc)
    out_of_order_tc["entries"] = [
        make_tc_entry(context, timed_out_view, "validator-c", high_ref),
        make_tc_entry(context, timed_out_view, "validator-a", low_ref),
        make_tc_entry(context, timed_out_view, "validator-d", high_ref),
    ]
    unknown_tc = copy.deepcopy(tc)
    unknown_entry = copy.deepcopy(unknown_tc["entries"][2])
    unknown_entry["signer_id_ascii"] = "validator-z"
    unknown_tc["entries"][2] = unknown_entry
    future_ref = qc_ref(context, future)
    future_reference_tc = {
        "timed_out_view": timed_out_view,
        "entries": [
            make_tc_entry(context, timed_out_view, "validator-a", future_ref),
            make_tc_entry(context, timed_out_view, "validator-c", future_ref),
            make_tc_entry(context, timed_out_view, "validator-d", future_ref),
        ],
        "referenced_qcs": ["future_exact_7"],
        "selected_high_qc_digest_hex": future_ref["qc_digest_hex"],
        "signed_power": 7,
    }
    same_block_variant_ref = qc_ref(context, same_block_variant)
    same_block_labels = sorted(
        ["low_exact_7", "same_block_variant_exact_7"],
        key=lambda label: qc_id(context, reference_qcs[label]),
    )
    same_block_coordinates_tc = {
        "timed_out_view": timed_out_view,
        "entries": [
            make_tc_entry(context, timed_out_view, "validator-a", low_ref),
            make_tc_entry(
                context,
                timed_out_view,
                "validator-c",
                same_block_variant_ref,
            ),
            make_tc_entry(
                context,
                timed_out_view,
                "validator-d",
                same_block_variant_ref,
            ),
        ],
        "referenced_qcs": same_block_labels,
        "selected_high_qc_digest_hex": same_block_variant_ref["qc_digest_hex"],
        "signed_power": 7,
    }
    digest_tiebreak_selected_smaller = copy.deepcopy(digest_tiebreak_tc)
    digest_tiebreak_selected_smaller["selected_high_qc_digest_hex"] = tie_lower_ref[
        "qc_digest_hex"
    ]
    tc_mutations = [
        ("tc_one_below_threshold", below_tc, "insufficient_quorum", "InsufficientQuorum"),
        ("tc_missing_full_reference", missing_reference_tc, "reference_summary_mismatch", "InvalidCertificate"),
        ("tc_selected_not_maximum", selected_wrong_tc, "selected_not_maximum", "InvalidCertificate"),
        ("tc_summary_conflict", summary_conflict_tc, "reference_summary_mismatch", "InvalidCertificate"),
        ("tc_noncanonical_reference_order", reference_order_tc, "noncanonical_qc_order", "NonCanonicalQcOrder"),
        ("tc_duplicate_signer", duplicate_tc, "duplicate_signer", "DuplicateSigner"),
        ("tc_noncanonical_signer_order", out_of_order_tc, "noncanonical_signer_order", "NonCanonicalSignerOrder"),
        ("tc_unknown_signer", unknown_tc, "unknown_signer", "UnknownValidator"),
        (
            "tc_future_reference_view",
            future_reference_tc,
            "future_reference_view",
            "CertificateMismatch",
        ),
        (
            "tc_same_block_different_coordinates",
            same_block_coordinates_tc,
            "same_block_different_coordinates",
            "InvalidCertificate",
        ),
        (
            "tc_digest_tiebreak_selected_smaller",
            digest_tiebreak_selected_smaller,
            "selected_not_maximum",
            "InvalidCertificate",
        ),
    ]
    for identifier, value, expected, rust_error in tc_mutations:
        negative_cases.append(
            {
                "id": identifier,
                "object_type": "tc",
                "rust_error_contains": rust_error,
                "object": finalize_tc(context, value, reference_qcs, expected),
            }
        )

    data: dict[str, object] = {
        "schema": "trnm_poco_bft_qc_tc_threshold_vectors_v0",
        "scope": (
            "Full-object weighted QC/TC CEV0 and strict Ed25519 conformance; "
            "not a general parser, production signer, or protocol source of truth"
        ),
        "private_key_policy": (
            "Deterministic 32-byte seeds exist only in the independent checker; "
            "this JSON contains public verification material only"
        ),
        "cryptography": {
            "algorithm": "RFC8032 Ed25519",
            "message_boundary": "exact raw 32-byte SigningRoot",
            "verification_profile": "strict canonical encodings, S < L, and small-order rejection",
        },
        "context": context,
        "validator_set": {
            "validators": validators,
            "total_power": 10,
            "quorum_power": 7,
            "threshold_formula": "floor(2 * W / 3) + 1",
            "cev0_hex": validator_set_bytes.hex(),
            "validator_set_id_hex": context["validator_set_id_hex"],
        },
        "quorum_certificates": qcs,
        "timeout_certificate_exact_7": valid_tc,
        "timeout_certificate_digest_tiebreak_exact_7": valid_digest_tiebreak_tc,
        "negative_cases": negative_cases,
        "coverage": [
            "unequal powers 4/3/2/1 with W=10 and exact quorum=7",
            "QC exact threshold and one-below rejection",
            "TC exact threshold and one-below rejection",
            "duplicate, noncanonical, and unknown signer rejection",
            "wrong block root, context, domain, and mutated signature rejection",
            "full TC references, deterministic selected maximum, and exact summary binding",
            "strictly future referenced-QC view and same-block coordinate rejection",
            "same-view same-block selected-high-QC tie broken by greater QC digest",
        ],
        "remaining_obligations": (
            "B2 logical-schema/parser-source-of-truth, epoch transition, complete "
            "receipt/evidence, light-client, and production key custody remain out of scope"
        ),
    }
    validate_vector_data(data)
    return data


def validate_vector_data(data: dict[str, object]) -> None:
    if data.get("schema") != "trnm_poco_bft_qc_tc_threshold_vectors_v0":
        raise VectorError("unexpected vector schema")
    context = data["context"]
    validator_set = data["validator_set"]
    validators = validator_map(data)
    ordered_ids = [identifier.encode("ascii") for identifier in validators]
    if ordered_ids != sorted(ordered_ids):
        raise VectorError("validators are not in canonical ID order")
    total = sum(int(value["power"]) for value in validators.values())
    quorum = 2 * total // 3 + 1
    if total != 10 or quorum != 7:
        raise VectorError("fixture no longer proves W=10, quorum=7")
    if int(validator_set["total_power"]) != total:
        raise VectorError("validator total power mismatch")
    if int(validator_set["quorum_power"]) != quorum:
        raise VectorError("validator quorum power mismatch")
    encoded_set = validator_set_cev0(context, list(validators.values()))
    expected_set_id = cev0_digest(DOMAIN_VALIDATOR_SET, encoded_set).hex()
    if encoded_set.hex() != validator_set["cev0_hex"]:
        raise VectorError("validator-set CEV0 mismatch")
    if expected_set_id != context["validator_set_id_hex"]:
        raise VectorError("validator-set ID mismatch")
    if expected_set_id != validator_set["validator_set_id_hex"]:
        raise VectorError("duplicated validator-set ID mismatch")

    qcs = data["quorum_certificates"]
    for label, qc in qcs.items():
        result = validate_qc(context, validators, quorum, qc)
        if result != qc["expected_result"]:
            raise VectorError(f"{label} result {result!r} != {qc['expected_result']!r}")
        encoded = qc_cev0(context, qc)
        if encoded.hex() != qc["cev0_hex"]:
            raise VectorError(f"{label} CEV0 mismatch")
        if cev0_digest(DOMAIN_QC, encoded).hex() != qc["digest_hex"]:
            raise VectorError(f"{label} digest mismatch")
        object_root = qc_signing_root(context, qc).hex()
        for vote in qc["votes"]:
            if vote["signing_root_hex"] != object_root:
                raise VectorError(f"{label} exposes a mismatched object signing root")

    valid_qcs = {
        label: qc for label, qc in qcs.items() if qc["expected_result"] == "valid"
    }
    for field in [
        "timeout_certificate_exact_7",
        "timeout_certificate_digest_tiebreak_exact_7",
    ]:
        tc = data[field]
        result = validate_tc(context, validators, quorum, tc, valid_qcs)
        if result != "valid":
            raise VectorError(f"{field} unexpectedly returned {result}")
        encoded_tc = tc_cev0(context, tc, valid_qcs)
        if encoded_tc.hex() != tc["cev0_hex"]:
            raise VectorError(f"{field} CEV0 mismatch")
        if cev0_digest(DOMAIN_TC, encoded_tc).hex() != tc["digest_hex"]:
            raise VectorError(f"{field} digest mismatch")

    seen_cases: set[str] = set()
    for case in data["negative_cases"]:
        identifier = str(case["id"])
        if identifier in seen_cases:
            raise VectorError(f"duplicate negative-case ID: {identifier}")
        seen_cases.add(identifier)
        value = case["object"]
        if case["object_type"] == "qc":
            result = validate_qc(context, validators, quorum, value)
            encoded = qc_cev0(context, value)
            domain = DOMAIN_QC
        elif case["object_type"] == "tc":
            result = validate_tc(context, validators, quorum, value, valid_qcs)
            encoded = tc_cev0(context, value, valid_qcs)
            domain = DOMAIN_TC
        else:
            raise VectorError(f"unknown case object type: {case['object_type']}")
        if result != value["expected_result"]:
            raise VectorError(
                f"{identifier} result {result!r} != {value['expected_result']!r}"
            )
        if encoded.hex() != value["cev0_hex"]:
            raise VectorError(f"{identifier} CEV0 mismatch")
        if cev0_digest(domain, encoded).hex() != value["digest_hex"]:
            raise VectorError(f"{identifier} digest mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vector", nargs="?", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument(
        "--emit", action="store_true", help="print reconstructed canonical JSON"
    )
    arguments = parser.parse_args()
    expected = build_vectors()
    if arguments.emit:
        print(json.dumps(expected, indent=2, sort_keys=True))
        return 0
    try:
        actual = json.loads(arguments.vector.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VectorError(f"cannot read {arguments.vector}: {error}") from error
    validate_vector_data(actual)
    if actual != expected:
        raise VectorError(
            "committed QC/TC vector differs from the independently reconstructed corpus"
        )
    print(
        "PoCO-BFT v0 QC/TC vectors verified: Ed25519, full CEV0, W=10, quorum=7, mutations"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except VectorError as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
