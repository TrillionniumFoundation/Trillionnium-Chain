"""Offline reproduction of an Ed25519 seed relation on PUBLIC fixtures only.

The public entry points select three published RFC 8032 vectors or sixteen
fixed, label-derived synthetic seeds. They do not accept a wallet seed, witness
file, mnemonic, arbitrary private key, stdin input or network resource. The
small integer implementation is variable-time research code, never a wallet
implementation. Every fixture seed is publicly known and unsafe for assets.

For each fixture we independently reproduce SHA-512(seed), first-half pruning,
little-endian scalar multiplication and compressed Ed25519 point encoding, then
compare the public key against cryptography's Ed25519 backend. We also compare
SHA-512(message || seed) through hashlib and cryptography's incremental hash
API. The message comes from the unchanged pq_seed_recovery_v1 public statement.
The PQ key and artifact identities in the default statements are fabricated
public bytes, not qualified keys or artifacts.

This aligns with the deterministic relation in SoundnessLabs/pqchain at
598cdff516c3086487a173d7d9f9af2830e04a32, sdk/cpp/examples/PQChain/pqchain.cpp.
Its byte reversal before a big-endian scalar import is equivalent to the
little-endian import here; hx is the complete 64-byte SHA-512(message || seed).
It does not run that circuit, Ligetron, a prover or a proof verifier. In
particular it does not establish the randomized-relation knowledge theorem,
quantum knowledge soundness, zero knowledge, seed entropy or migration safety.
There is no signature verification, authorization, nonce consumption or ledger.
An hx chosen by the prover is not an additional ownership constraint.

The clamped scalar has 251 free bits; its residue modulo the subgroup order
uniquely identifies the clamped representative. Reconstructing that scalar is
not reconstruction of the seed. No 128-bit post-quantum security claim follows:
the idealized any-seed-preimage query scale of about 2**125.5 is not a security
lower bound or a measured attack cost. This module checks only finite fixtures
and the scalar arithmetic, not a hash-inversion or security theorem.

Key generation and published fixtures:
https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5
https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
import hashlib
import json
import sys

import pq_seed_recovery_v1 as recovery


RELATION_PROFILE = "trnm-public-seed-relation-vectors-v1"
RESEARCH_STATUS = "PUBLIC_FIXTURE_RELATION_ONLY_NO_PROOF_OR_AUTHORITY"
SYNTHETIC_SEED_DOMAIN = b"TRNM/PoN/PublicSyntheticSeed/v1\x00"
CLAMPED_SCALAR_FREE_BITS = 251

_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BASE_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)
_IDENTITY = (0, 1, 1, 0)
_CLAMPED_MIN = 1 << 254
_CLAMPED_MAX = (1 << 255) - 8


class ReproductionError(ValueError):
    """A fixture, exact relation or mandatory backend failed to reproduce."""


@dataclass(frozen=True)
class _Fixture:
    name: str
    source: str
    seed: bytes = field(repr=False)
    expected_public_key: bytes | None = None


# Public RFC test keys: never use these, or the synthetic seeds below, for funds.
_RFC_FIXTURES = tuple(
    _Fixture(name, "RFC8032-section-7.1", bytes.fromhex(seed), bytes.fromhex(key))
    for name, seed, key in (
        (
            "rfc8032-test-1",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ),
        (
            "rfc8032-test-2",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ),
        (
            "rfc8032-test-3",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        ),
    )
)
_SYNTHETIC_FIXTURES = tuple(
    _Fixture(
        name := f"synthetic-{index:02d}",
        "public-label-derived",
        hashlib.sha512(SYNTHETIC_SEED_DOMAIN + name.encode("ascii")).digest()[:32],
    )
    for index in range(16)
)
_FIXTURES = _RFC_FIXTURES + _SYNTHETIC_FIXTURES


def vector_names() -> tuple[str, ...]:
    """The complete finite catalogue; no caller-provided seed or label space."""
    return tuple(item.name for item in _FIXTURES)


def _fixture(name: str) -> _Fixture:
    if type(name) is not str:
        raise ReproductionError("built-in public fixture name required")
    for item in _FIXTURES:
        if item.name == name:
            return item
    # Do not echo arbitrary arguments, which might accidentally contain secrets.
    raise ReproductionError("unknown built-in public fixture")


def _seed32(seed: bytes) -> bytes:
    """Internal arithmetic only; public callers must select a built-in fixture."""
    if type(seed) is not bytes or len(seed) != 32:
        raise ReproductionError("exact seed32 fixture required; no format conversion")
    return seed


def _expand_seed(seed: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha512(_seed32(seed)).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return digest, bytes(scalar)


def _add(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    """Extended Edwards coordinates, independently evaluated over Python ints."""
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _multiply_base(scalar: int) -> tuple[int, ...]:
    if type(scalar) is not int or not 0 <= scalar < 1 << 256:
        raise ReproductionError("reference scalar must be an exact u256")
    result, addend = _IDENTITY, _BASE
    # A bounded reference loop, not a constant-time secret-key implementation.
    for bit in range(256):
        if scalar & (1 << bit):
            result = _add(result, addend)
        addend = _add(addend, addend)
    return result


def _encode_point(point: tuple[int, ...]) -> bytes:
    x, y, z, _ = point
    if z % _P == 0:
        raise ReproductionError("invalid reference projective point")
    inverse = pow(z, _P - 2, _P)
    x, y = x * inverse % _P, y * inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _reference_public_key(seed: bytes) -> bytes:
    _, scalar = _expand_seed(seed)
    return _encode_point(_multiply_base(int.from_bytes(scalar, "little")))


def _recover_clamped_scalar(residue: int) -> int | None:
    """Recover a representative of a PUBLIC canonical residue, not a seed.

    Clamped a is in [2**254, 2**255) and a == 0 (mod 8). Since a < 8*L
    and L is odd, exactly one multiplier j in [0, 8) can make residue+j*L
    divisible by 8. It is either inside the clamped interval or no clamped
    representative exists. There is no modular normalization of bad inputs.
    """
    if type(residue) is not int or not 0 <= residue < _L:
        raise ReproductionError("canonical public scalar residue required")
    multiplier = (-residue * pow(_L, -1, 8)) % 8
    candidate = residue + multiplier * _L
    if _CLAMPED_MIN <= candidate <= _CLAMPED_MAX:
        return candidate
    return None


def _reference_hx(seed: bytes, message: bytes) -> bytes:
    if type(message) is not bytes or len(message) != 32:
        raise ReproductionError("exact public message32 required")
    return hashlib.sha512(message + _seed32(seed)).digest()


def _backend_material(seed: bytes, message: bytes) -> tuple[bytes, bytes, bytes]:
    """Mandatory cross-check; missing/unsupported backends cannot become PASS."""
    _seed32(seed)
    if type(message) is not bytes or len(message) != 32:
        raise ReproductionError("exact public message32 required")
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        raise ReproductionError("cryptography backend required; no reference-only result") from None
    try:
        key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        expansion = hashes.Hash(hashes.SHA512())
        expansion.update(seed)
        binding = hashes.Hash(hashes.SHA512())
        binding.update(message)
        binding.update(seed)
        return key, expansion.finalize(), binding.finalize()
    except (UnsupportedAlgorithm, ValueError):
        raise ReproductionError("cryptography backend cannot reproduce fixture") from None


def _statement_for_key(public_key: bytes) -> recovery.SeedRecoveryStatement:
    return recovery.SeedRecoveryStatement(
        version=1,
        purpose=recovery.PURPOSE,
        message_hash_profile=recovery.MESSAGE_HASH_PROFILE,
        proof_profile=recovery.PROOF_PROFILE,
        derivation_profile=recovery.DERIVATION_PROFILE,
        pq_algorithm=recovery.PQ_ALGORITHM,
        source_commit=recovery.SOURCE_COMMIT,
        network=b"n" * 32,
        genesis=b"g" * 32,
        crypto_profile_id=b"p" * 32,
        account_id=hashlib.sha256(b"TRNM/PoN/PublicSeedRelationAccount/v1\x00" + public_key).digest(),
        old_public_key=public_key,
        source_snapshot_root=b"s" * 32,
        migration_root=b"m" * 32,
        new_pq_public_key=b"k" * recovery.ML_DSA_65_PUBLIC_KEY_BYTES,
        circuit_source_sha256=recovery.CIRCUIT_SOURCE_SHA256,
        verifier_source_sha256=recovery.VERIFIER_SOURCE_SHA256,
        parameter_source_sha256=recovery.PARAMETER_SOURCE_SHA256,
        parameter_profile_sha256=recovery.PARAMETER_PROFILE_SHA256,
        circuit_artifact_sha256=b"c" * 32,
        verifier_artifact_sha256=b"v" * 32,
        account_generation=7,
        operation_nonce=11,
        not_before=100,
        expires_at=200,
        recovery_state="restricted",
    )


def public_statement(name: str) -> recovery.SeedRecoveryStatement:
    """A fabricated PUBLIC statement for one catalogue entry; no authority."""
    return _statement_for_key(_reference_public_key(_fixture(name).seed))


@dataclass(frozen=True)
class RelationVector:
    """Reproduced public bytes, never a proof-verification or ownership verdict."""

    name: str
    source: str
    public_key: bytes
    public_message: bytes
    hx: bytes
    statement_sha256: bytes
    status: str = field(default=RESEARCH_STATUS, init=False)

    def __bool__(self) -> bool:
        raise TypeError("a public fixture vector is not an authorization verdict")


def reproduce_public_vector(
    name: str, *, statement: recovery.SeedRecoveryStatement | None = None,
) -> RelationVector:
    """Reproduce one fixed public seed against a public statement.

    Optional statement changes exercise public binding only. The self-created
    ResearchContext below is fixture data, not trusted chain state. There is no
    clock read, proof input, signature, owner lookup or authorization output.
    """
    fixture = _fixture(name)
    key = _reference_public_key(fixture.seed)
    if fixture.expected_public_key is not None and key != fixture.expected_public_key:
        raise ReproductionError("RFC8032 public key mismatch")
    if statement is None:
        statement = _statement_for_key(key)
    if type(statement) is not recovery.SeedRecoveryStatement:
        raise ReproductionError("exact public statement required")
    statement.encode()
    if statement.old_public_key != key:
        raise ReproductionError("public fixture does not derive the declared old key")
    expected = recovery.ResearchContext(**{
        item.name: getattr(statement, item.name) for item in fields(recovery.ResearchContext)
    })
    inputs = recovery.prepare_public_inputs(
        statement, expected=expected, now=statement.not_before,
    )
    expansion, scalar_bytes = _expand_seed(fixture.seed)
    hx = _reference_hx(fixture.seed, inputs.message)
    backend_key, backend_expansion, backend_hx = _backend_material(fixture.seed, inputs.message)
    if (key, expansion, hx) != (backend_key, backend_expansion, backend_hx):
        raise ReproductionError("independent reference/backend mismatch")
    scalar = int.from_bytes(scalar_bytes, "little")
    if _recover_clamped_scalar(scalar % _L) != scalar:
        raise ReproductionError("clamped scalar residue reconstruction mismatch")
    return RelationVector(
        fixture.name, fixture.source, key, inputs.message, hx,
        hashlib.sha256(inputs.statement).digest(),
    )


def reproduce_public_vectors() -> tuple[RelationVector, ...]:
    """Reproduce the entire finite, publicly known corpus without secret input."""
    return tuple(reproduce_public_vector(name) for name in vector_names())


def main(argv: list[str] | None = None) -> int:
    """No arguments or stdin are accepted; stdout contains only public outputs."""
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("no arguments accepted; built-in public fixtures only", file=sys.stderr)
        return 2
    try:
        vectors = reproduce_public_vectors()
    except (ReproductionError, recovery.Reject):
        print("public fixture reproduction failed; no qualified result", file=sys.stderr)
        return 1
    print(json.dumps({
        "profile": RELATION_PROFILE,
        "status": RESEARCH_STATUS,
        "source_commit": recovery.SOURCE_COMMIT,
        "derivation_profile": recovery.DERIVATION_PROFILE,
        "rfc8032_vectors": len(_RFC_FIXTURES),
        "synthetic_vectors": len(_SYNTHETIC_FIXTURES),
        "clamped_scalar_free_bits": CLAMPED_SCALAR_FREE_BITS,
        "vectors": [
            {item.name: (value.hex() if type(value := getattr(vector, item.name)) is bytes else value)
             for item in fields(vector)}
            for vector in vectors
        ],
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
