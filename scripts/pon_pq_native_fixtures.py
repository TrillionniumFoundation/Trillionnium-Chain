#!/usr/bin/env python3
"""Generate/check public ML-DSA fixtures using the real cryptography backend.

No private key is written. Generated keys have no ledger authority. Regeneration
changes source fixtures and requires review; CI checks existing immutable bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

DOMAIN = b"TRNM/PoN/PQAuth/ML-DSA-65/v1\0"
KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\0"
CONTEXT_DOMAIN = b"TRNM/PoN/QTX1Context/v1\0"
NETWORK = hashlib.sha256(b"TRNM/PoN/QTX1NativeTransfer/v1\0" + bytes([1]) * 32 + bytes([2]) * 32).digest()


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def public_der(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def body(key_id: bytes, *, generation=1, nonce=1, fee=1_000_000, network=NETWORK) -> bytes:
    memo = b"native M01 to M06"
    return (b"QTX1\x01\x01" + network + key_id + bytes([7]) * 32 + u64(generation)
            + u64(nonce) + u64(1_800_001_000) + u64(1_000) + u64(fee)
            + len(memo).to_bytes(2, "big") + memo)


def signed_transfer(key, key_id: bytes, data: bytes, *, purpose=1) -> bytes:
    network, sender = data[6:38], data[38:70]
    context = hashlib.sha256(CONTEXT_DOMAIN + network + sender).digest()
    commitment = hashlib.sha384(DOMAIN + b"payload\0" + u64(len(data)) + data).digest()
    statement = (b"TPQ1\x01\x65" + bytes([purpose, 0]) + network + context + key_id
                 + data[102:126] + commitment)
    if len(statement) != 176:
        raise ValueError("wrong TPQ1 construction")
    signature = key.sign(statement)
    key.public_key().verify(signature, statement)
    if len(signature) != 3309:
        raise ValueError("not ML-DSA-65")
    return data + statement + len(signature).to_bytes(2, "big") + signature


def repeated_hint(signature: bytes) -> bytes:
    """Add one duplicate hint while preserving the represented hint bitset.

    This targets strict FIPS-204 hint ordering, including the published
    RustCrypto duplicate-hint decoder regression fixed before stable 0.1.1.
    """
    omega, k = 55, 6
    start = len(signature) - omega - k
    hints = list(signature[start:start + omega])
    ends = list(signature[-k:])
    total = ends[-1]
    if total >= omega:
        raise ValueError("signature has no hint padding")
    begin = 0
    for polynomial, end in enumerate(ends):
        if end > begin:
            changed = hints[:begin + 1] + [hints[begin]] + hints[begin + 1:total]
            changed.extend([0] * (omega - len(changed)))
            new_ends = [value + int(i >= polynomial) for i, value in enumerate(ends)]
            return signature[:start] + bytes(changed) + bytes(new_ends)
        begin = end
    raise ValueError("signature has no nonempty hint polynomial")


def generate(directory: Path) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError("refuse to overwrite an existing fixture directory")
    key = mldsa.MLDSA65PrivateKey.generate()
    der = public_der(key)
    key_id = hashlib.sha256(KEY_DOMAIN + der).digest()
    transfer = signed_transfer(key, key_id, body(key_id))
    for _ in range(32):
        try:
            bad_signature = repeated_hint(transfer[-3309:])
            break
        except ValueError:
            transfer = signed_transfer(key, key_id, body(key_id))
    else:
        raise ValueError("unable to produce duplicate-hint negative")
    vectors = {
        "public.der": der,
        "wrong-public.der": public_der(mldsa.MLDSA65PrivateKey.generate()),
        "transfer.bin": transfer,
        "same-statement-second-signature.bin": signed_transfer(key, key_id, body(key_id)),
        "low-fee.bin": signed_transfer(key, key_id, body(key_id, fee=1)),
        "nonce-two.bin": signed_transfer(key, key_id, body(key_id, nonce=2)),
        "generation-two.bin": signed_transfer(key, key_id, body(key_id, generation=2)),
        "wrong-network.bin": signed_transfer(key, key_id, body(key_id, network=bytes([1]) * 32)),
        "wrong-purpose.bin": signed_transfer(key, key_id, body(key_id), purpose=2),
        "duplicate-hint.bin": transfer[:-3309] + bad_signature,
    }
    for name, value in vectors.items():
        (directory / name).write_bytes(value)
    metadata = {
        "schema": "native-pq-public-fixtures-v1",
        "crypto_backend": "cryptography " + cryptography.__version__,
        "openssl_backend": backend.openssl_version_text(),
        "algorithm": "ML-DSA-65", "storage_encoding": "raw_binary",
        "public_key_bytes": len(der), "signature_bytes": 3309,
        "network": NETWORK.hex(), "sender": key_id.hex(),
        "private_keys_written": False, "production_activation": False,
        "source_native_head": "4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251",
        "source_pq_head": "6f4b9cae0dafcb0e6bc171e2aa9b8f630e74eca6",
        "files": {name: hashlib.sha256(value).hexdigest() for name, value in vectors.items()},
    }
    (directory / "manifest.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return check(directory)


def check(directory: Path) -> dict:
    metadata = json.loads((directory / "manifest.json").read_text())
    if (metadata.get("production_activation") is not False
            or metadata.get("private_keys_written") is not False
            or metadata.get("storage_encoding") != "raw_binary"):
        raise ValueError("fixture boundary")
    vectors = {}
    for name, wanted in metadata["files"].items():
        if Path(name).name != name or Path(name).suffix not in {".bin", ".der"}:
            raise ValueError("fixture path")
        value = (directory / name).read_bytes()
        if hashlib.sha256(value).hexdigest() != wanted:
            raise ValueError("fixture digest " + name)
        vectors[name] = value
    public = serialization.load_der_public_key(vectors["public.der"])
    if not isinstance(public, mldsa.MLDSA65PublicKey):
        raise ValueError("wrong public algorithm")
    accepted, rejected = [], []
    for name, value in vectors.items():
        if name.endswith(".der"):
            continue
        frame = value[-3487:]
        if frame[:6] != b"TPQ1\x01\x65" or frame[176:178] != (3309).to_bytes(2, "big"):
            raise ValueError("fixture framing")
        try:
            public.verify(frame[178:], frame[:176])
            accepted.append(name)
        except InvalidSignature:
            rejected.append(name)
    if rejected != ["duplicate-hint.bin"] or len(accepted) != 7:
        raise ValueError("unexpected actual ML-DSA results")
    return {"result": "PASS", "actual_crypto_positive_vectors": sorted(accepted),
            "actual_crypto_negative_vectors": rejected,
            "production_activation": False,
            "note": "cryptographic validity of a vector is not native state permission"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = generate(args.generate) if args.generate else check(args.check)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
