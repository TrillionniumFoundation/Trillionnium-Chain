"""Public-input research contract for an Ed25519-seed recovery experiment.

This module does not take a seed, run a prover/verifier, check either signature,
consume a nonce, write a journal or grant any account/Chain/Hepta authority. Its
only result is public input or an explicitly unverified research diagnostic.
Identical requests remain identical observations; the real migration owner
would have to enforce one-use, retirement, revocation and reorganization rules.

The proposed circuit message is SHA-256 over a fresh versioned domain and the
complete canonical statement below. A future PQ possession signature must bind
that same complete statement. SHA-256 here is an explicit *research* profile,
not a claim that the composition has independently established 128-bit quantum
security. The known upstream circuit accepts a public message and constrains
hx = SHA-512(message || seed); this module never computes hx or knows its seed.

Upstream reference: SoundnessLabs/pqchain at SOURCE_COMMIT, based on Ligetron
v1.1.0; see https://eprint.iacr.org/2025/1368. Three source files are pinned by
SHA-256. Artifact digests are required caller declarations, not attestations of
compiled circuit/verifier identity. Neither source pins nor parser checks
qualify a verifier. All profiles remain unqualified for actual recovery.

Transport is a small JSON header plus a separate opaque proof byte string.
Limits are experimental parser limits, not measured proving/verifying budgets.
There is no queue, sandbox, network service or production admission path here.
Tests use fabricated public bytes; they do not construct a valid ZK proof.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, fields


VERSION = 1
PURPOSE = "legacy-eddsa-seed-recovery-v1"
MESSAGE_HASH_PROFILE = "trnm-seed-recovery-sha256-v1"
PROOF_PROFILE = "pqchain-ligetron-1.1.0-unqualified-v1"
DERIVATION_PROFILE = "rfc8032-ed25519-seed32-v1"
PQ_ALGORITHM = "ml-dsa-65-fips204-pure-v1"
SOURCE_COMMIT = "598cdff516c3086487a173d7d9f9af2830e04a32"

# Recomputed from the complete UTF-8 bytes at SOURCE_COMMIT, with their Git blob
# identities checked independently. These are source identities, not binaries.
# sdk/cpp/examples/PQChain/pqchain.cpp: ee243b99651870509101240d83e098202cbcca4f
CIRCUIT_SOURCE_SHA256 = bytes.fromhex(
    "ad7914a99a3e3f8bcf647f116da602a65e5e14d1b379ad59a6075523caeb9272"
)
# src/webgpu_verifier.cpp: 8f7bdeb5ffd48fb075d667b9afafed4b5e0ae16c
VERIFIER_SOURCE_SHA256 = bytes.fromhex(
    "714bcac596b193173d67d86cedd97204ed7c88d856e35c03c2913c8c43c50b97"
)
# include/params.hpp: ae55604b344eb2764d65c1019e45538d8ba01dfa
PARAMETER_SOURCE_SHA256 = bytes.fromhex(
    "99b1aecc916de8fb63e16c0cdb021633be5cc53df05bce1807654baf35c12db3"
)

STATEMENT_DOMAIN = b"TRNM/PoN/SeedRecoveryStatement/v1\x00"
MESSAGE_DOMAIN = b"TRNM/PoN/SeedRecoveryPublicMessage/v1\x00"
REQUEST_DOMAIN = b"TRNM/PoN/SeedRecoveryResearchRequest/v1\x00"
PARAMETER_DOMAIN = b"TRNM/PoN/SeedRecoveryResearchParameters/v1\x00"

# The CLI packing in the upstream example is 8192, whereas its compile-time
# default_packing_size is 8000. Both the source pin and this explicit experiment
# configuration matter. No experiment or audited parameter selection is claimed.
PARAMETER_PROFILE_BYTES = (
    b'{"gpu_threads":8192,"hx_bytes":64,"message_bytes":32,'
    b'"packing":8192,"private_indices":[1],"public_key_bytes":32,'
    b'"seed_bytes":32,"source_commit":"598cdff516c3086487a173d7d9f9af2830e04a32"}'
)
PARAMETER_PROFILE_SHA256 = hashlib.sha256(
    PARAMETER_DOMAIN + PARAMETER_SOURCE_SHA256 + PARAMETER_PROFILE_BYTES
).digest()

ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309
MAX_HEADER_BYTES = 32 * 1024
MAX_PROOF_BYTES = 6 * 1024 * 1024
MAX_VALIDITY_SECONDS = 24 * 60 * 60
RESEARCH_STATUS = "RESEARCH_ONLY_NO_PROOF_OR_SIGNATURE_VERIFICATION"


class Reject(ValueError):
    """Malformed, unsupported or context-mismatched research input."""


def _bytes(value: bytes, size: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != size or not any(value):
        raise Reject(name + " bytes/length/nonzero")
    return value


def _u64(value: int, name: str, *, allow_zero: bool = False) -> bytes:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or not minimum <= value < 1 << 64:
        raise Reject(name + (" u64" if allow_zero else " positive u64"))
    return value.to_bytes(8, "big")


def _hex(value: str, size: int, name: str) -> bytes:
    if (type(value) is not str or len(value) != size * 2
            or any(c not in "0123456789abcdef" for c in value)):
        raise Reject(name + " canonical lowercase hex")
    return _bytes(bytes.fromhex(value), size, name)


def _keys(value: dict, expected: frozenset[str], name: str) -> None:
    if type(value) is not dict or frozenset(value) != expected:
        raise Reject(name + " exact fields")


_TEXT_FIELDS = (
    ("purpose", PURPOSE),
    ("message_hash_profile", MESSAGE_HASH_PROFILE),
    ("proof_profile", PROOF_PROFILE),
    ("derivation_profile", DERIVATION_PROFILE),
    ("pq_algorithm", PQ_ALGORITHM),
    ("source_commit", SOURCE_COMMIT),
)
_BYTE_FIELDS = (
    ("network", 32),
    ("genesis", 32),
    ("crypto_profile_id", 32),
    ("account_id", 32),
    ("old_public_key", 32),
    ("source_snapshot_root", 32),
    ("migration_root", 32),
    ("new_pq_public_key", ML_DSA_65_PUBLIC_KEY_BYTES),
    ("circuit_source_sha256", 32),
    ("verifier_source_sha256", 32),
    ("parameter_source_sha256", 32),
    ("parameter_profile_sha256", 32),
    ("circuit_artifact_sha256", 32),
    ("verifier_artifact_sha256", 32),
)
_PINNED_BYTES = (
    ("circuit_source_sha256", CIRCUIT_SOURCE_SHA256),
    ("verifier_source_sha256", VERIFIER_SOURCE_SHA256),
    ("parameter_source_sha256", PARAMETER_SOURCE_SHA256),
    ("parameter_profile_sha256", PARAMETER_PROFILE_SHA256),
)
_U64_FIELDS = ("account_generation", "operation_nonce", "not_before", "expires_at")
_STATES = {"restricted": 1, "frozen": 2}


@dataclass(frozen=True)
class SeedRecoveryStatement:
    """Proposed public binding, with an observed current account generation.

    account_generation may be zero for a restricted imported account before
    CLAIM establishes PQ authority. It is not a new PQ key generation or an
    authorization grant. The operation nonce and validity times remain positive.
    """

    version: int
    purpose: str
    message_hash_profile: str
    proof_profile: str
    derivation_profile: str
    pq_algorithm: str
    source_commit: str
    network: bytes
    genesis: bytes
    crypto_profile_id: bytes
    account_id: bytes
    old_public_key: bytes
    source_snapshot_root: bytes
    migration_root: bytes
    new_pq_public_key: bytes
    circuit_source_sha256: bytes
    verifier_source_sha256: bytes
    parameter_source_sha256: bytes
    parameter_profile_sha256: bytes
    circuit_artifact_sha256: bytes
    verifier_artifact_sha256: bytes
    account_generation: int
    operation_nonce: int
    not_before: int
    expires_at: int
    recovery_state: str

    def encode(self) -> bytes:
        """Canonical public statement; not a signed/verified object."""
        if type(self) is not SeedRecoveryStatement:
            raise Reject("statement type")
        if type(self.version) is not int or self.version != VERSION:
            raise Reject("statement version")
        parts = [STATEMENT_DOMAIN, self.version.to_bytes(2, "big")]
        for name, required in _TEXT_FIELDS:
            value = getattr(self, name)
            if type(value) is not str or value != required:
                raise Reject(name + " unsupported research identity")
            encoded = value.encode("ascii")
            parts.append(len(encoded).to_bytes(2, "big") + encoded)
        for name, size in _BYTE_FIELDS:
            parts.append(_bytes(getattr(self, name), size, name))
        for name, required in _PINNED_BYTES:
            if getattr(self, name) != required:
                raise Reject(name + " unknown source/parameters")
        for name in _U64_FIELDS:
            parts.append(_u64(getattr(self, name), name,
                              allow_zero=name == "account_generation"))
        if not 0 < self.expires_at - self.not_before <= MAX_VALIDITY_SECONDS:
            raise Reject("validity window")
        if type(self.recovery_state) is not str or self.recovery_state not in _STATES:
            raise Reject("recovery_state")
        parts.append(bytes([_STATES[self.recovery_state]]))
        return b"".join(parts)

    def to_mapping(self) -> dict:
        """Public JSON representation; byte fields are lowercase hex."""
        self.encode()
        return {item.name: (value.hex() if type(value := getattr(self, item.name)) is bytes
                            else value) for item in fields(self)}


_STATEMENT_FIELDS = frozenset(item.name for item in fields(SeedRecoveryStatement))


def statement_from_mapping(value: dict) -> SeedRecoveryStatement:
    _keys(value, _STATEMENT_FIELDS, "statement")
    decoded = dict(value)
    for name, size in _BYTE_FIELDS:
        decoded[name] = _hex(value[name], size, name)
    result = SeedRecoveryStatement(**decoded)
    result.encode()
    return result


@dataclass(frozen=True)
class ResearchContext:
    """Caller-supplied expected observation, with no trusted-state capability.

    Matching these values cannot establish that a snapshot is canonical or
    current. This record deliberately has no state-loading or mutation methods.
    """

    network: bytes
    genesis: bytes
    crypto_profile_id: bytes
    account_id: bytes
    old_public_key: bytes
    source_snapshot_root: bytes
    migration_root: bytes
    new_pq_public_key: bytes
    circuit_artifact_sha256: bytes
    verifier_artifact_sha256: bytes
    account_generation: int
    operation_nonce: int
    recovery_state: str


@dataclass(frozen=True)
class PublicInputs:
    """Public bytes to bind a future experiment, without seed or proof."""

    statement: bytes
    message: bytes
    old_public_key: bytes


def prepare_public_inputs(statement: SeedRecoveryStatement, *,
                          expected: ResearchContext, now: int) -> PublicInputs:
    if type(statement) is not SeedRecoveryStatement or type(expected) is not ResearchContext:
        raise Reject("statement/context type")
    encoded = statement.encode()
    _u64(now, "now")
    for item in fields(expected):
        value = getattr(expected, item.name)
        claimed = getattr(statement, item.name)
        if type(value) is not type(claimed) or value != claimed:
            raise Reject("context mismatch: " + item.name)
    # Half-open validity prevents an equality-at-expiry ambiguity.
    if not statement.not_before <= now < statement.expires_at:
        raise Reject("outside validity window")
    return PublicInputs(encoded, hashlib.sha256(MESSAGE_DOMAIN + encoded).digest(),
                        statement.old_public_key)


_REQUEST_FIELDS = frozenset({
    "version", "statement", "public_message", "hx", "new_pq_signature",
    "proof_length", "proof_sha256",
})
_SECRET_NAMES = frozenset({
    "seed", "seedbytes", "rawseed", "seedphrase", "mnemonic", "privatekey",
    "secretkey", "witness",
})


def _json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        normalized = key.casefold().replace("_", "").replace("-", "")
        if normalized in _SECRET_NAMES:
            # Do not echo private values or unexpected objects into diagnostics.
            raise Reject("secret input fields forbidden")
        if key in result:
            raise Reject("duplicate JSON field")
        result[key] = value
    return result


def _json_constant(_: str) -> None:
    raise Reject("nonfinite JSON number")


@dataclass(frozen=True)
class ResearchDiagnostic:
    """Only binding/shape inspection; even a fabricated proof yields this status.

    There is no cryptographic verdict and no one-use state change. The object
    cannot be coerced to a boolean authorization decision.
    """

    public_inputs: PublicInputs
    hx: bytes
    proof_length: int
    proof_sha256: bytes
    request_sha256: bytes
    status: str = field(default=RESEARCH_STATUS, init=False)

    def __bool__(self) -> bool:
        raise TypeError("research diagnostic is not an authorization verdict")


def inspect_research_request(header: bytes, proof: bytes, *,
                             expected: ResearchContext, now: int) -> ResearchDiagnostic:
    """Inspect public framing and bindings only; NEVER verify or authorize.

    The caller already owns these in-memory bytes. Header and proof limits are
    checked before JSON decoding or hashing the proof. No URL, artifact path,
    code, private witness or callback is accepted. The PQ signature and hx are
    structurally checked and included in the diagnostic request digest; their
    cryptographic validity is deliberately unexamined.
    """
    if type(header) is not bytes or not 0 < len(header) <= MAX_HEADER_BYTES:
        raise Reject("header size/type")
    if type(proof) is not bytes or not 0 < len(proof) <= MAX_PROOF_BYTES:
        raise Reject("proof size/type")
    try:
        request = json.loads(header.decode("utf-8"), object_pairs_hook=_json_pairs,
                             parse_constant=_json_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, Reject):
            raise
        raise Reject("malformed JSON header") from None
    _keys(request, _REQUEST_FIELDS, "request")
    if type(request["version"]) is not int or request["version"] != VERSION:
        raise Reject("request version")
    statement = statement_from_mapping(request["statement"])
    public_inputs = prepare_public_inputs(statement, expected=expected, now=now)
    if _hex(request["public_message"], 32, "public_message") != public_inputs.message:
        raise Reject("public_message binding")
    hx = _hex(request["hx"], 64, "hx")
    pq_signature = _hex(request["new_pq_signature"], ML_DSA_65_SIGNATURE_BYTES,
                        "new_pq_signature")
    proof_length = request["proof_length"]
    if type(proof_length) is not int or proof_length != len(proof):
        raise Reject("proof_length binding")
    declared_proof_hash = _hex(request["proof_sha256"], 32, "proof_sha256")
    proof_hash = hashlib.sha256(proof).digest()
    if declared_proof_hash != proof_hash:
        raise Reject("proof_sha256 binding")
    request_hash = hashlib.sha256(
        REQUEST_DOMAIN + public_inputs.statement + hx + pq_signature
        + proof_length.to_bytes(8, "big") + proof_hash
    ).digest()
    return ResearchDiagnostic(public_inputs, hx, proof_length, proof_hash, request_hash)
