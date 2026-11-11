"""Research-only strict TPQ1 / pure ML-DSA-65 signature envelope.

No chain authority is created by this module. In particular it does NOT authorize
PoN block admission, nonce consumption, key migration, Hepta final-use, TLS or an
active protocol upgrade. The OpenSSL CLI adapter is an offline conformance oracle,
not an RPC-facing verifier or production key manager.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

MAGIC = b"TPQ1"
VERSION = 1
ML_DSA_65 = 0x65
ML_DSA_65_SIGNATURE_BYTES = 3309
DOMAIN = b"TRNM/PoN/PQAuth/ML-DSA-65/v1\x00"
PURPOSES = frozenset({1, 2, 3, 4, 5, 6})  # tx, artifact, eval, release, custody, peer
UNSIGNED_BYTES = 4 + 4 + 32 * 3 + 8 * 3 + 48
SIGNED_BYTES = UNSIGNED_BYTES + 2 + ML_DSA_65_SIGNATURE_BYTES
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_PEM_BYTES = 16 * 1024
# DER OID 2.16.840.1.101.3.4.3.18 (id-ml-dsa-65); exact SPKI algorithm.
ML_DSA_65_OID_DER = bytes.fromhex("0609608648016503040312")


class Reject(ValueError):
    """A malformed, stale, nonmatching or unverified candidate."""


def _u64(value: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise Reject(name)
    return value.to_bytes(8, "big")


def _exact(value: bytes, length: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise Reject(name)
    return value


def _digest_payload(payload: bytes) -> bytes:
    if type(payload) is not bytes or len(payload) > MAX_PAYLOAD_BYTES:
        raise Reject("payload size/type")
    return hashlib.sha384(DOMAIN + b"payload\x00" + len(payload).to_bytes(8, "big") + payload).digest()


def _run(argv: list[str], *, stdin: bytes | None = None) -> bytes:
    # Separate argument vector; never launch a shell. Bounded input and offline only.
    try:
        result = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject("OpenSSL unavailable") from exc
    if result.returncode != 0:
        raise Reject("OpenSSL refused cryptographic operation")
    return result.stdout


def _der_length(data: bytes, start: int) -> tuple[int, int]:
    if start >= len(data):
        raise Reject("SPKI truncated")
    first = data[start]
    if first < 128:
        return first, start + 1
    n = first & 127
    if n == 0 or n > 4 or start + 1 + n > len(data):
        raise Reject("SPKI length")
    value = int.from_bytes(data[start + 1:start + 1 + n], "big")
    if value < 128 or data[start + 1] == 0:
        raise Reject("SPKI noncanonical length")
    return value, start + 1 + n


def _verify_spki_algorithm(der: bytes) -> None:
    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE{OID}, BIT STRING }.
    # No parameter fields, trailing bytes or alternative OIDs are admitted.
    if not der or der[0] != 0x30:
        raise Reject("SPKI outer tag")
    total, p = _der_length(der, 1)
    if p + total != len(der) or p >= len(der) or der[p] != 0x30:
        raise Reject("SPKI outer length")
    algorithm_len, q = _der_length(der, p + 1)
    if der[q:q + algorithm_len] != ML_DSA_65_OID_DER:
        raise Reject("SPKI algorithm is not ML-DSA-65")
    bit_string_start = q + algorithm_len
    if bit_string_start >= len(der) or der[bit_string_start] != 0x03:
        raise Reject("SPKI public key missing")
    bit_len, b = _der_length(der, bit_string_start + 1)
    if b + bit_len != len(der) or bit_len != 1953 or der[b] != 0:
        raise Reject("SPKI public key size/padding")


def public_key_id(public_pem: bytes) -> bytes:
    if type(public_pem) is not bytes or not 0 < len(public_pem) <= MAX_PEM_BYTES:
        raise Reject("public PEM size/type")
    with tempfile.TemporaryDirectory(prefix="trnm-pq-key-") as root:
        key = Path(root) / "key.pem"
        key.write_bytes(public_pem)  # public key only, not private material
        der = _run(["openssl", "pkey", "-pubin", "-in", str(key), "-outform", "DER"])
    _verify_spki_algorithm(der)
    return hashlib.sha256(b"TRNM/PoN/PQKey/v1\x00" + der).digest()


@dataclass(frozen=True)
class Unsigned:
    purpose: int
    network: bytes
    context: bytes
    signer_key_id: bytes
    owner_generation: int
    operation_sequence: int
    expires_at: int
    payload_digest: bytes

    def encode(self) -> bytes:
        if type(self.purpose) is not int or self.purpose not in PURPOSES:
            raise Reject("purpose")
        return (MAGIC + bytes([VERSION, ML_DSA_65, self.purpose, 0])
                + _exact(self.network, 32, "network")
                + _exact(self.context, 32, "context")
                + _exact(self.signer_key_id, 32, "signer_key_id")
                + _u64(self.owner_generation, "owner_generation")
                + _u64(self.operation_sequence, "operation_sequence")
                + _u64(self.expires_at, "expires_at")
                + _exact(self.payload_digest, 48, "payload_digest"))


def make_unsigned(*, purpose: int, network: bytes, context: bytes,
                  signer_key_id: bytes, owner_generation: int,
                  operation_sequence: int, expires_at: int, payload: bytes) -> Unsigned:
    if not owner_generation or not operation_sequence or not expires_at:
        raise Reject("zero lifetime/identity")
    instance = Unsigned(purpose, network, context, signer_key_id, owner_generation,
                        operation_sequence, expires_at, _digest_payload(payload))
    instance.encode()
    return instance


def parse_unsigned(data: bytes) -> Unsigned:
    if type(data) is not bytes or len(data) != UNSIGNED_BYTES:
        raise Reject("unsigned length")
    if (data[:4] != MAGIC or data[4] != VERSION or data[5] != ML_DSA_65
            or data[7] != 0):
        raise Reject("magic/version/algorithm/reserved")
    o = 8
    network, context, key_id = data[o:o + 32], data[o + 32:o + 64], data[o + 64:o + 96]
    o += 96
    generation, sequence, expiry = [int.from_bytes(data[o + i * 8:o + (i + 1) * 8], "big") for i in range(3)]
    o += 24
    if generation == 0 or sequence == 0 or expiry == 0:
        raise Reject("zero lifetime/identity")
    instance = Unsigned(data[6], network, context, key_id, generation,
                        sequence, expiry, data[o:o + 48])
    if instance.encode() != data:
        raise Reject("noncanonical unsigned")
    return instance


def attach_signature(unsigned: Unsigned, signature: bytes) -> bytes:
    if type(signature) is not bytes or len(signature) != ML_DSA_65_SIGNATURE_BYTES:
        raise Reject("signature length")
    return unsigned.encode() + len(signature).to_bytes(2, "big") + signature


def parse_signed(frame: bytes) -> tuple[Unsigned, bytes]:
    if type(frame) is not bytes or len(frame) != SIGNED_BYTES:
        raise Reject("signed length")
    unsigned = parse_unsigned(frame[:UNSIGNED_BYTES])
    size = int.from_bytes(frame[UNSIGNED_BYTES:UNSIGNED_BYTES + 2], "big")
    if size != ML_DSA_65_SIGNATURE_BYTES:
        raise Reject("signature size field")
    return unsigned, frame[UNSIGNED_BYTES + 2:]


def verify_reference(frame: bytes, *, payload: bytes, public_pem: bytes,
                     expected_network: bytes, expected_context: bytes,
                     expected_purpose: int, expected_generation: int,
                     expected_sequence: int, now: int) -> Unsigned:
    """Offline crypto check only; caller MUST separately enforce durable replay and authority."""
    unsigned, signature = parse_signed(frame)
    _u64(now, "now")
    _u64(expected_generation, "expected_generation")
    _u64(expected_sequence, "expected_sequence")
    if type(expected_purpose) is not int or expected_purpose not in PURPOSES:
        raise Reject("expected_purpose")
    if (unsigned.purpose != expected_purpose or unsigned.network != _exact(expected_network, 32, "network")
            or unsigned.context != _exact(expected_context, 32, "context")
            or unsigned.owner_generation != expected_generation
            or unsigned.operation_sequence != expected_sequence
            or now > unsigned.expires_at
            or unsigned.signer_key_id != public_key_id(public_pem)
            or unsigned.payload_digest != _digest_payload(payload)):
        raise Reject("context/identity/payload/expiry")
    with tempfile.TemporaryDirectory(prefix="trnm-pq-verify-") as root:
        p = Path(root)
        (p / "public.pem").write_bytes(public_pem)
        (p / "message.bin").write_bytes(unsigned.encode())
        (p / "sig.bin").write_bytes(signature)
        _run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(p / "public.pem"),
              "-rawin", "-in", str(p / "message.bin"), "-sigfile", str(p / "sig.bin")])
    return unsigned


def sign_reference(unsigned: Unsigned, *, private_key_path: Path) -> bytes:
    """Offline test-key use ONLY. Product key custody must never call this function."""
    with tempfile.TemporaryDirectory(prefix="trnm-pq-sign-") as root:
        msg, sig = Path(root) / "message.bin", Path(root) / "sig.bin"
        msg.write_bytes(unsigned.encode())
        _run(["openssl", "pkeyutl", "-sign", "-inkey", os.fspath(private_key_path),
              "-rawin", "-in", str(msg), "-out", str(sig)])
        return attach_signature(unsigned, sig.read_bytes())
