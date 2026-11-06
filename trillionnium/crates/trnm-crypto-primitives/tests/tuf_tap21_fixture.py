#!/usr/bin/env python3
"""Audit/recreate the public TAP 21 fixture with pinned independent sources.

No network access or production private key is used. The seed is deliberately
public test material. Signatures may differ between runs because this backend
uses randomized signing; canonical bytes, SPKI and key id must stay identical.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import types

SDK_BLOBS = {
    "securesystemslib/__init__.py": "31edbbe96f4cffefcba008e577967f7e16412893",
    "securesystemslib/exceptions.py": "bce02977f32ed3882a4e930d4def6f1376d4165d",
    "securesystemslib/formats.py": "447bef28a8797cb3687707fd0f9ddec447e0d204",
}
FIXTURE = Path(__file__).parent / "fixtures/pq/tuf_tap21_mldsa65_v1.json"


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sslib-source", type=Path, required=True,
                        help="local securesystemslib v1.5.0 source root")
    parser.add_argument("--emit", type=Path,
                        help="write a newly signed public fixture to this new path")
    args = parser.parse_args()
    source = args.sslib_source.resolve(strict=True)
    pinned_sources = {}
    for relative, expected in SDK_BLOBS.items():
        data = (source / relative).read_bytes()
        if git_blob(data) != expected:
            raise ValueError(f"independent source pin mismatch: {relative}")
        pinned_sources[relative] = data
    # Execute the exact bytes just checked. Normal imports could read a stale
    # bytecode cache, a previously imported module or a later file replacement.
    package = types.ModuleType("securesystemslib")
    package.__path__ = []
    sys.modules[package.__name__] = package
    for relative, data in pinned_sources.items():
        leaf = Path(relative).stem
        module = package if leaf == "__init__" else types.ModuleType(
            "securesystemslib." + leaf)
        module.__file__ = str(source / relative)
        sys.modules[module.__name__] = module
        if module is not package:
            setattr(package, leaf, module)
        exec(compile(data, module.__file__, "exec"), module.__dict__)
    encode_canonical = package.formats.encode_canonical
    import cryptography
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mldsa

    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    canonical = encode_canonical(fixture["signed"]).encode("utf-8")
    message = b"tuf\x01" + hashlib.sha512(canonical).digest()
    key = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes([177]) * 32)
    public = key.public_key()
    spki = public.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(b"TRNM/PoN/PQKey/v1\0" + spki).digest()
    for name, actual in (("canonical_hex", canonical), ("presigning_hex", message),
                         ("public_spki_hex", spki), ("key_id_hex", key_id)):
        if fixture[name] != actual.hex():
            raise ValueError(f"independent fixture mismatch: {name}")
    public.verify(bytes.fromhex(fixture["signature_hex"]), message, context=b"")
    # First prove this is a genuine signature in the other context. A random
    # malformed signature must not satisfy this context-isolation fixture.
    public.verify(bytes.fromhex(fixture["wrong_context_signature_hex"]),
                  message, context=b"tuf")
    try:
        public.verify(bytes.fromhex(fixture["wrong_context_signature_hex"]),
                      message, context=b"")
    except InvalidSignature:
        pass
    else:
        raise ValueError("nonempty ML-DSA context unexpectedly accepted")
    if args.emit:
        fixture["source"] = ("securesystemslib v1.5.0 formats.encode_canonical; "
                             f"cryptography {cryptography.__version__} / "
                             + backend.openssl_version_text())
        fixture["signature_hex"] = key.sign(message, context=b"").hex()
        fixture["wrong_context_signature_hex"] = key.sign(message, context=b"tuf").hex()
        with args.emit.open("x", encoding="utf-8") as output:
            json.dump(fixture, output, ensure_ascii=False, sort_keys=True, indent=2)
            output.write("\n")
    print(json.dumps({
        "status": "PASS", "scope": "public TAP21 ML-DSA-65/1 fixture only",
        "sdk": "securesystemslib v1.5.0", "sdk_blobs": SDK_BLOBS,
        "cryptography": cryptography.__version__, "backend": backend.openssl_version_text(),
        "canonical_bytes": len(canonical), "presigning_bytes": len(message),
        "canonical_sha512": hashlib.sha512(canonical).hexdigest(),
        "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
