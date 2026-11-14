#!/usr/bin/env python3
"""Run both actual canonical adapters against independent OpenSSL ML-DSA.

Build each repo's pq_message_oracle example, then pass both executable paths.
Requires exactly cryptography==50.0.2. No runtime fallback or test skip exists.
Report records the actual backend, binaries and upstream vector digest.
This differential check does not substitute for independent cryptographic audit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

VECTOR_SHA256 = "1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034"
DOMAIN = b"TRNM/PoN/PQKey/v1\0"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def invoke(path, items):
    run = subprocess.run([str(path)], input=json.dumps(items), text=True,
                         capture_output=True, timeout=45, check=True)
    result = json.loads(run.stdout)
    if len(result) != len(items):
        raise AssertionError("oracle result cardinality")
    return result


def verification(spki, message, signature, key_id=None):
    return {"mode": "verify", "spki": spki.hex(),
            "key_id": key_id or digest(DOMAIN + spki),
            "message": message.hex(), "signature": signature.hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain-oracle", required=True, type=Path)
    parser.add_argument("--hepta-oracle", required=True, type=Path)
    parser.add_argument("--wycheproof", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    if cryptography.__version__ != "50.0.2":
        raise AssertionError("install pinned cryptography==50.0.2")
    binaries = [args.chain_oracle.resolve(strict=True), args.hepta_oracle.resolve(strict=True)]
    if binaries[0] == binaries[1]:
        raise AssertionError("distinct Chain and Hepta executables are required")
    started = time.monotonic()
    cases, expected, categories = [], [], {}

    def add(category, payload, accepted):
        cases.append(payload)
        expected.append({"accepted": accepted})
        categories[category] = categories.get(category, 0) + 1

    seeds = [0, 1, 7, 127, 255]
    messages = [b"", b"TRNM/Cell/Provider/ML-DSA-65/v2\0statement",
                bytes(range(256)), b"x" * 65536]
    requests = [{"mode": "sign", "test_seed": seed, "message": message.hex()}
                for seed in seeds for message in messages]
    signed = [invoke(binary, requests) for binary in binaries]
    # Both adapters use FIPS204 deterministic signing with the same fixed seed.
    if signed[0] != signed[1]:
        raise AssertionError("Chain/Hepta canonical deterministic output drift")
    for request, item in zip(requests, signed[0], strict=True):
        key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes([request["test_seed"]]) * 32)
        public = key.public_key()
        spki = public.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        message = bytes.fromhex(request["message"])
        if item["spki"] != spki.hex() or item["key_id"] != digest(DOMAIN + spki):
            raise AssertionError("independent fixed-seed public-key/key-id drift")
        public.verify(bytes.fromhex(item["signature"]), message, context=b"")
        for backend_signature in [bytes.fromhex(item["signature"]), key.sign(message, context=b"")]:
            add("cross_backend_positive", verification(spki, message, backend_signature), True)
            changed = bytearray(backend_signature)
            changed[100] ^= 1
            add("changed_signature", verification(spki, message, bytes(changed)), False)
        add("context_domain_rejection", verification(spki, message, key.sign(message, context=b"domain")), False)
        signature = bytes.fromhex(item["signature"])
        add("wrong_message", verification(spki, message + b"!", signature), False)
        add("wrong_pin", verification(spki, message, signature, "00" * 32), False)
        add("signature_length", verification(spki, message, signature[:-1]), False)
        add("signature_length", verification(spki, message, signature + b"\0"), False)
    # Exact FIPS204 SPKI, absent algorithm params, no trailing bytes or raw-key shortcut.
    key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes([7]) * 32)
    spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    message = b"SPKI negative corpus"
    signature = key.sign(message)
    for index in range(22):
        changed = bytearray(spki)
        changed[index] ^= 1
        add("strict_spki", verification(bytes(changed), message, signature), False)
    with_null = bytearray(spki)
    with_null[2:4] = (len(spki) - 4 + 2).to_bytes(2, "big")
    with_null[5] += 2
    with_null[17:17] = b"\x05\x00"
    for bad in [bytes(with_null), spki + b"\0", spki[22:], spki[:-1]]:
        add("strict_spki", verification(bad, message, signature), False)
    oversized = b"m" * 65537
    add("message_limit", verification(spki, oversized, key.sign(oversized)), False)

    raw = args.wycheproof.read_bytes()
    if digest(raw) != VECTOR_SHA256:
        raise AssertionError("upstream Wycheproof bytes changed")
    vectors = json.loads(raw)
    total, valid = 0, 0
    for group in vectors["testGroups"]:
        try:
            public = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(group["publicKey"]))
        except ValueError:
            public = None
        der = bytes.fromhex(group["publicKeyDer"])
        for test in group["tests"]:
            total += 1
            message = bytes.fromhex(test["msg"])
            signature = bytes.fromhex(test["sig"])
            context = bytes.fromhex(test.get("ctx", ""))
            accepted = test["result"] == "valid"
            valid += int(accepted)
            try:
                if public is None:
                    raise ValueError("invalid upstream public-key length")
                public.verify(signature, message, context=context)
                independent = True
            except (InvalidSignature, ValueError):
                independent = False
            if independent != accepted:
                raise AssertionError(f"OpenSSL/Wycheproof disagreement tcId={test['tcId']}")
            # The application wrapper intentionally supports only empty context.
            add("wycheproof_application_policy", verification(der, message, signature),
                accepted and not context and len(message) <= 65536)
    if (total, valid) != (210, 79):
        raise AssertionError("upstream corpus count changed")
    for binary in binaries:
        # Bound aggregate JSON and don't rely on one giant child-process request.
        for start in range(0, len(cases), 20):
            actual = invoke(binary, cases[start:start + 20])
            wanted = expected[start:start + 20]
            if actual != wanted:
                mismatch = next(i for i, (a, b) in enumerate(zip(actual, wanted, strict=True)) if a != b)
                raise AssertionError(f"{binary.name} differential rejection mismatch case {start + mismatch}")
    report = {
        "schema": "trnm.pq.independent-message-differential.v2",
        "result": "PASS", "cryptography": cryptography.__version__,
        "independent_backend": backend.openssl_version_text(),
        "canonical_backend": "RustCrypto ml-dsa 0.1.1, pure, empty context",
        "binaries": [{"path": str(p), "sha256": digest(p.read_bytes())} for p in binaries],
        "upstream_vector_sha256": VECTOR_SHA256,
        "wycheproof": {"total": total, "valid": valid, "invalid": total - valid},
        "fixed_seed_signatures_each_adapter": len(requests),
        "verification_cases_each_adapter": len(cases), "categories": categories,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "independent_implementation_audit": "HOLD",
        "quantum_work_and_proof_audit": "HOLD",
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
