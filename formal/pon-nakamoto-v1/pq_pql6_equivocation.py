"""PQL6 research-only ML-DSA-65 witness-equivocation evidence.

An independently pinned verifier can establish that one exact PQL5 signer
signed two different frontier IDs for the same sequence and context. This
module NEVER grants chain state, signer revocation, slashing, FinalUse, model
adoption or a non-rewindable checkpoint. Silence is not proof of honesty:
a colluding 2/3 majority can rewind without emitting detectable conflicts.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess
import tempfile

PQL5_PREFIX = b"TRNM/PQ/PQL5Witness/v1\x00"
PQL6_PREFIX = b"TRNM/PQ/PQL6Equivocation/v1\x00"
KEY_PREFIX = b"TRNM/PoN/PQKey/v1\x00"
MLDSA65_OID = bytes.fromhex("0609608648016503040312")
PQL5_UNSIGNED = 269
MLDSA65_SIG = 3309
PQL5_SIGNED = PQL5_UNSIGNED + 2 + MLDSA65_SIG
PQL6_HEADER = b"PQL6\x01"
PQL6_LEN = len(PQL6_HEADER) + 32 + 2 * PQL5_SIGNED + 48
MAX_PEM = 16 * 1024


class Reject(ValueError):
    """Invalid grammar, identity, signature or contradictory-witness claim."""


def _exact(v: bytes, size: int, label: str, *, nonzero=False) -> bytes:
    if type(v) is not bytes or len(v) != size or (nonzero and not any(v)):
        raise Reject(label)
    return v


def _der_len(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise Reject("truncated DER")
    first = data[offset]
    if first < 128:
        return first, offset + 1
    n = first & 127
    if not 1 <= n <= 4 or offset + n + 1 > len(data):
        raise Reject("bad DER length")
    raw = data[offset + 1:offset + 1 + n]
    if raw[0] == 0 or int.from_bytes(raw, "big") < 128:
        raise Reject("noncanonical DER length")
    return int.from_bytes(raw, "big"), offset + 1 + n


def _strict_spki(der: bytes) -> None:
    if not der or der[0] != 0x30:
        raise Reject("missing SPKI sequence")
    outer, a = _der_len(der, 1)
    if a + outer != len(der) or a >= len(der) or der[a] != 0x30:
        raise Reject("SPKI outer length")
    alg, b = _der_len(der, a + 1)
    if der[b:b + alg] != MLDSA65_OID:
        raise Reject("ML-DSA-65 OID or unexpected algorithm parameters")
    offset = b + alg
    if offset >= len(der) or der[offset] != 0x03:
        raise Reject("SPKI BIT STRING")
    size, value = _der_len(der, offset + 1)
    if size != 1953 or value + size != len(der) or der[value] != 0:
        raise Reject("ML-DSA-65 raw public key")


def _run(argv: list[str]) -> bytes:
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Reject("OpenSSL unavailable") from exc
    if p.returncode:
        raise Reject("cryptographic operation failed")
    return p.stdout


def _public_key(public_pem: bytes) -> tuple[bytes, bytes]:
    if type(public_pem) is not bytes or not 0 < len(public_pem) <= MAX_PEM:
        raise Reject("public key size/type")
    with tempfile.TemporaryDirectory(prefix="pql6-pub-") as tmp:
        pub = Path(tmp) / "pub.pem"
        pub.write_bytes(public_pem)
        normalized = _run(["openssl", "pkey", "-pubin", "-in", str(pub), "-pubout"])
        if normalized != public_pem:
            raise Reject("noncanonical public PEM")
        der = _run(["openssl", "pkey", "-pubin", "-in", str(pub), "-outform", "DER"])
    _strict_spki(der)
    return hashlib.sha256(KEY_PREFIX + der).digest(), public_pem


def _verify_sig(public_pem: bytes, signed_unsigned: bytes, signature: bytes) -> None:
    _exact(signature, MLDSA65_SIG, "signature")
    with tempfile.TemporaryDirectory(prefix="pql6-verify-") as tmp:
        p = Path(tmp)
        (p / "key").write_bytes(public_pem)
        (p / "message").write_bytes(PQL5_PREFIX + signed_unsigned)
        (p / "signature").write_bytes(signature)
        _run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(p / "key"),
              "-rawin", "-in", str(p / "message"), "-sigfile", str(p / "signature")])


@dataclass(frozen=True)
class SignedHead:
    signer_key_id: bytes
    network: bytes
    import_root: bytes
    genesis: bytes
    sequence: int
    frontier_id: bytes
    challenge: bytes
    observed_at: int


def _parse_signed(raw: bytes, public_pem: bytes, key_id: bytes) -> SignedHead:
    if type(raw) is not bytes or len(raw) != PQL5_SIGNED:
        raise Reject("PQL5 exact length")
    unsigned = raw[:PQL5_UNSIGNED]
    if unsigned[:5] != b"PQL5\x01" or raw[PQL5_UNSIGNED:PQL5_UNSIGNED + 2] != MLDSA65_SIG.to_bytes(2, "big"):
        raise Reject("PQL5 version/signature length")
    if unsigned[5:37] != key_id:
        raise Reject("witness key identity")
    net = _exact(unsigned[37:69], 32, "network", nonzero=True)
    root = _exact(unsigned[69:117], 48, "import root", nonzero=True)
    genesis = _exact(unsigned[117:165], 48, "genesis", nonzero=True)
    seq = int.from_bytes(unsigned[165:173], "big")
    fid = _exact(unsigned[173:221], 48, "frontier", nonzero=True)
    challenge = _exact(unsigned[221:253], 32, "challenge", nonzero=True)
    observed = int.from_bytes(unsigned[253:261], "big")
    expiry = int.from_bytes(unsigned[261:269], "big")
    if seq == 0 or observed > (1 << 64) - 31 or expiry != observed + 30:
        raise Reject("witness sequence or bounded 30-second signing interval")
    # Historical double-sign evidence does not expire as a cryptographic fact.
    _verify_sig(public_pem, unsigned, raw[PQL5_UNSIGNED + 2:])
    return SignedHead(key_id, net, root, genesis, seq, fid, challenge, observed)


@dataclass(frozen=True)
class EquivocationObservation:
    """Third-party verifiable contradictory signing observation; NO authority."""
    evidence_id: bytes
    signer_key_id: bytes
    sequence: int
    first_frontier: bytes
    second_frontier: bytes


def _ordered_pair(a: bytes, b: bytes, *, pub: bytes, key_id: bytes,
                  network: bytes, import_root: bytes, genesis: bytes) -> tuple[bytes, bytes, SignedHead, SignedHead]:
    ha = _parse_signed(a, pub, key_id)
    hb = _parse_signed(b, pub, key_id)
    expected = (_exact(network, 32, "caller network", nonzero=True),
                _exact(import_root, 48, "caller import root", nonzero=True),
                _exact(genesis, 48, "caller genesis", nonzero=True))
    if ((ha.network, ha.import_root, ha.genesis) != expected
            or (hb.network, hb.import_root, hb.genesis) != expected
            or ha.sequence != hb.sequence or ha.frontier_id == hb.frontier_id):
        raise Reject("not contradictory statements of one identical frontier sequence/context")
    if b[:PQL5_UNSIGNED] < a[:PQL5_UNSIGNED]:
        return b, a, hb, ha
    return a, b, ha, hb


def build_evidence(a: bytes, b: bytes, *, public_pem: bytes,
                   expected_signer_key_id: bytes, network: bytes,
                   import_root: bytes, genesis: bytes) -> bytes:
    key_id, pub = _public_key(public_pem)
    if key_id != _exact(expected_signer_key_id, 32, "externally pinned signer", nonzero=True):
        raise Reject("witness not externally pinned")
    a, b, _, _ = _ordered_pair(a, b, pub=pub, key_id=key_id,
                               network=network, import_root=import_root, genesis=genesis)
    body = PQL6_HEADER + key_id + a + b
    digest = hashlib.sha384(PQL6_PREFIX + key_id + a[:PQL5_UNSIGNED] + b[:PQL5_UNSIGNED]).digest()
    return body + digest


def verify_evidence(encoded: bytes, *, public_pem: bytes,
                    expected_signer_key_id: bytes, network: bytes,
                    import_root: bytes, genesis: bytes) -> EquivocationObservation:
    if type(encoded) is not bytes or len(encoded) != PQL6_LEN or encoded[:5] != PQL6_HEADER:
        raise Reject("PQL6 length/version")
    key_id, pub = _public_key(public_pem)
    if encoded[5:37] != key_id or key_id != _exact(expected_signer_key_id, 32, "caller signer", nonzero=True):
        raise Reject("witness not independently pinned")
    start = 37
    a = encoded[start:start + PQL5_SIGNED]
    b = encoded[start + PQL5_SIGNED:start + 2 * PQL5_SIGNED]
    aa, bb, ha, hb = _ordered_pair(a, b, pub=pub, key_id=key_id,
                                   network=network, import_root=import_root, genesis=genesis)
    if a != aa or b != bb:
        raise Reject("noncanonical evidence order")
    digest = hashlib.sha384(PQL6_PREFIX + key_id + a[:PQL5_UNSIGNED] + b[:PQL5_UNSIGNED]).digest()
    if encoded[-48:] != digest:
        raise Reject("evidence identity mismatch")
    return EquivocationObservation(digest, key_id, ha.sequence, ha.frontier_id, hb.frontier_id)
