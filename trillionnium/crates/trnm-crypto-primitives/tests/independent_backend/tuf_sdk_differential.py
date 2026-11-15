#!/usr/bin/env python3
"""Run the actual pinned TUF SDK signer/verifier against the Rust TAP 21 adapter.

The SDK receives canonical metadata, not a caller-built pre-signing message.
The Rust oracle invokes sign_tuf_mldsa65_v1/verify_tuf_mldsa65_v1 directly.
Only disposable public fixture seeds are used. This is the bounded ML-DSA-65/1
signature profile, not a TUF updater, threshold-role or activation qualification.
No dependency, source, signature or unsupported-version failure is skipped.
"""
from __future__ import annotations

import argparse
import importlib.abc
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

from mldsa_native_differential import checked_source, digest, rust

SDK_COMMIT = "15064ca640222edba024af9f13191fa5dbad3825"
SDK_VERSION = "1.5.1"
CRYPTOGRAPHY_VERSION = "50.0.2"
SCHEME = "ml-dsa-65/1"
KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\0"


class PinnedSdkLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Import only captured, hash-checked SDK source, never cached bytecode."""

    def __init__(self, source: Path, expected: dict):
        files = {str(p.relative_to(source)): p.read_bytes()
                 for p in (source / "securesystemslib").rglob("*") if p.is_file()}
        identities = {path: digest(data) for path, data in files.items()}
        if digest(json.dumps(identities, sort_keys=True).encode()) != expected["source_sha256"]:
            raise ValueError("SDK source changed before capture")
        self.modules = {}
        self.loaded = {}
        for relative, data in files.items():
            path = Path(relative)
            if path.suffix != ".py":
                continue
            is_package = path.name == "__init__.py"
            parts = path.parts[:-1] if is_package else (*path.parts[:-1], path.stem)
            self.modules[".".join(parts)] = (source / path, data, is_package)
        # Upstream also has namespace packages without __init__.py. Derive
        # those only from captured descendants; never search another install.
        self.namespaces = {".".join(name.split(".")[:i])
                           for name in self.modules for i in range(1, len(name.split(".")))}
        self.namespaces.difference_update(self.modules)

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "securesystemslib" and not fullname.startswith("securesystemslib."):
            return None
        if fullname not in self.modules and fullname not in self.namespaces:
            raise ModuleNotFoundError("SDK import outside pinned source: " + fullname)
        return importlib.util.spec_from_loader(fullname, self,
            is_package=fullname in self.namespaces or self.modules[fullname][2])

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        if module.__name__ in self.namespaces:
            module.__path__ = []
            return
        path, data, is_package = self.modules[module.__name__]
        module.__file__ = str(path)
        if is_package:
            module.__path__ = []
        exec(compile(data, str(path), "exec"), module.__dict__)
        self.loaded[module.__name__] = digest(data)


def run(args: argparse.Namespace, report: dict) -> None:
    source = args.source.resolve(strict=True)
    oracle = args.chain_oracle.resolve(strict=True)
    report["upstream"] = checked_source(source, commit=SDK_COMMIT,
                                        subtree="securesystemslib")
    if any(name == "securesystemslib" or name.startswith("securesystemslib.")
           for name in sys.modules):
        raise ValueError("SDK was already imported outside the pinned loader")
    loader = PinnedSdkLoader(source, report["upstream"])
    sys.meta_path.insert(0, loader)
    import securesystemslib
    from securesystemslib.exceptions import UnverifiedSignatureError
    from securesystemslib.formats import encode_canonical
    from securesystemslib.signer import CryptoSigner, Key, Signature, SSlibKey
    from securesystemslib.signer._utils import get_mldsa_payload
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.bindings import _rust
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mldsa

    if securesystemslib.__version__ != SDK_VERSION:
        raise ValueError("SDK version drift")
    if cryptography.__version__ != CRYPTOGRAPHY_VERSION:
        raise ValueError("cryptography version differs from the interoperability profile")
    report["backend"] = {"sdk": SDK_VERSION, "cryptography": cryptography.__version__,
                         "openssl": backend.openssl_version_text(),
                         "extension_sha256": digest(Path(_rust.__file__).read_bytes())}
    oracle_digest = digest(oracle.read_bytes())
    report["oracle_sha256"] = oracle_digest
    report["runner_sha256"] = digest(Path(__file__).read_bytes())
    outcomes = []
    report["observations"] = outcomes

    def canonical(signed):
        return encode_canonical(signed).encode("utf-8")

    def key_material(seed):
        secret = mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes([seed]) * 32)
        signer = CryptoSigner(secret)
        # Exercise the SDK's real key deserializer as well as its signer.
        key = SSlibKey.from_dict(signer.public_key.keyid, signer.public_key.to_dict())
        if key.scheme != SCHEME or key.keytype != "ml-dsa":
            raise AssertionError("SDK selected a different signing scheme")
        spki = secret.public_key().public_bytes(serialization.Encoding.DER,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
        return secret, signer, key, spki

    def sdk_check(label, key, signature, signed, expected):
        try:
            key.verify_signature(signature, canonical(signed))
            accepted = True
        except UnverifiedSignatureError:
            accepted = False
        outcomes.append({"backend": "sdk", "case": label, "accepted": accepted,
                         "expected": expected})
        if accepted is not expected:
            raise AssertionError("SDK verification disagreement: " + label)

    def rust_check(label, spki, signature, signed, expected, *, scheme=SCHEME,
                   key_id=None):
        request = {"mode": "tuf_verify", "scheme": scheme, "signed": signed,
                   "spki": spki.hex(), "key_id": key_id or digest(KEY_DOMAIN + spki),
                   "signature": signature.signature}
        actual = rust(oracle, [request])
        outcomes.append({"backend": "rust", "case": label, "observed": actual,
                         "expected": expected})
        if actual != [{"accepted": expected}]:
            raise AssertionError("Rust TAP21 verification disagreement: " + label)

    fixture_path = Path(__file__).resolve().parents[1] / "fixtures/pq/tuf_tap21_mldsa65_v1.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    metadata = [fixture["signed"],
                {"_type": "root", "version": 2, "keys": {}, "roles": {}},
                {"_type": "snapshot", "version": 3, "meta": {"targets.json": {"version": 9}}},
                {"_type": "timestamp", "version": 4, "meta": {"snapshot.json": {"version": 3}}},
                {"z": 2**64 - 1, "a": -(2**63), "q": "\\\"\n\0é界", "arr": [True, None, False]},
                {"_type": "targets", "version": 5, "custom": "x" * 65537}]
    for seed in (0, 177, 255):
        _, signer, key, spki = key_material(seed)
        for index, signed in enumerate(metadata):
            label = f"seed-{seed}-metadata-{index}"
            generated = rust(oracle, [{"mode": "tuf_sign", "test_seed": seed,
                                      "scheme": SCHEME, "signed": signed}])[0]
            if generated["spki"] != spki.hex() or generated["key_id"] != digest(KEY_DOMAIN + spki):
                raise AssertionError("SDK/Rust public-key derivation differs")
            sdk_check("rust-to-sdk-" + label, key,
                      Signature(key.keyid, generated["signature"]), signed, True)
            sdk_signature = signer.sign(canonical(signed))
            sdk_check("sdk-positive-" + label, key, sdk_signature, signed, True)
            rust_check("sdk-to-rust-" + label, spki, sdk_signature, signed, True)
            reordered = dict(reversed(list(signed.items())))
            rust_check("canonical-key-order-" + label, spki, sdk_signature, reordered, True)

    secret, signer, key, spki = key_material(177)
    signed = fixture["signed"]
    signature = signer.sign(canonical(signed))
    fixture_signature = Signature(key.keyid, fixture["signature_hex"])
    sdk_check("retained-fixture", key, fixture_signature, signed, True)
    rust_check("retained-fixture", spki, fixture_signature, signed, True)

    # Generic dispatch is intentionally not patched. Version 1.5.1 still makes
    # this keytype opt-in; direct SSlibKey/CryptoSigner support is the tested API.
    try:
        Key.from_dict(key.keyid, key.to_dict())
    except ValueError:
        report["sdk_generic_key_dispatch"] = "ML-DSA not registered by default in pinned 1.5.1"
    else:
        raise AssertionError("SDK default registry differs from the pinned profile")

    for field, value in (("_type", "root"), ("version", 9999), ("targets", {})):
        changed = {**signed, field: value}
        sdk_check("changed-" + field, key, signature, changed, False)
        rust_check("changed-" + field, spki, signature, changed, False)

    raw_signature = bytes.fromhex(signature.signature)
    corrupt = bytearray(raw_signature)
    corrupt[100] ^= 1
    for label, malformed in (("bit", bytes(corrupt)), ("short", raw_signature[:-1]),
                              ("long", raw_signature + b"\0"), ("empty", b"")):
        changed = Signature(key.keyid, malformed.hex())
        sdk_check("signature-" + label, key, changed, signed, False)
        rust_check("signature-" + label, spki, changed, signed, False)

    for scheme in ("ml-dsa", "ml-dsa-65", "ml-dsa-65/0", "ml-dsa-65/01",
                   "ml-dsa-65/2", "ml-dsa-44/1", "ml-dsa-87/1", "ML-DSA-65/1",
                   "ml-dsa-65/1 ", "hash-ml-dsa-65/1"):
        changed_key = SSlibKey(key.keyid, "ml-dsa", scheme, dict(key.keyval))
        sdk_check("scheme-" + scheme, changed_key, signature, signed, False)
        rust_check("scheme-" + scheme, spki, signature, signed, False, scheme=scheme)

    payload = get_mldsa_payload(canonical(signed), 1)
    for label, message, context in (
            ("raw-metadata", canonical(signed), b""),
            ("digest-only", payload[4:], b""),
            ("version2", payload[:3] + b"\2" + payload[4:], b""),
            ("other-domain", b"not" + payload[3:], b""),
            ("nonempty-context", payload, b"tuf")):
        other = secret.sign(message, context=context)
        # Prove a real signature under the wrong interpretation before refusal.
        secret.public_key().verify(other, message, context=context)
        changed = Signature(key.keyid, other.hex())
        sdk_check("no-fallback-" + label, key, changed, signed, False)
        rust_check("no-fallback-" + label, spki, changed, signed, False)

    sdk_check("wrong-key-id", key, Signature("00" * 32, signature.signature), signed, False)
    rust_check("wrong-key-pin", spki, signature, signed, False, key_id="00" * 32)
    _, _, other_key, other_spki = key_material(178)
    sdk_check("wrong-key", other_key, Signature(other_key.keyid, signature.signature), signed, False)
    rust_check("wrong-key", other_spki, signature, signed, False)

    # The SDK's signature API is intentionally broader than the bounded product
    # profile. Valid SDK signatures outside those limits must still refuse.
    deep = None
    for _ in range(64):
        deep = [deep]
    for label, outside in (("not-object", []), ("integer-domain", {"n": 2**64}),
                           ("canonical-byte-limit", {"s": "x" * 1048576}),
                           ("value-count-limit", {"a": [None] * 65536}),
                           ("depth-limit", {"deep": deep})):
        authentic = signer.sign(canonical(outside))
        sdk_check("valid-outside-product-" + label, key, authentic, outside, True)
        rust_check("product-refuses-" + label, spki, authentic, outside, False)

    if checked_source(source, commit=SDK_COMMIT, subtree="securesystemslib") != report["upstream"]:
        raise AssertionError("SDK source changed during execution")
    if digest(oracle.read_bytes()) != oracle_digest:
        raise AssertionError("Rust oracle changed during execution")
    report.update(result="PASS", fixture_sha256=digest(fixture_path.read_bytes()),
                  positive_metadata_pairs=len(metadata) * 3,
                  sdk_verifications=sum(x["backend"] == "sdk" for x in outcomes),
                  rust_verifications=sum(x["backend"] == "rust" for x in outcomes),
                  sdk_namespace_packages=sorted(loader.namespaces),
                  imported_sdk_modules=loader.loaded, observations=outcomes)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="pristine securesystemslib v1.5.1 Git checkout")
    parser.add_argument("--chain-oracle", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    report = {"schema": "trnm.pq.tuf-sdk-differential.v1", "result": "FAIL",
              "host": {"system": platform.system(), "machine": platform.machine(),
                       "python": platform.python_version()},
              "scope": "actual SSlibKey/CryptoSigner and Rust ML-DSA-65/1 signature APIs only",
              "full_tuf_updater_qualified": False, "production_activation": False}
    started = time.monotonic()
    try:
        run(args, report)
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            report["stderr"] = str(error.stderr)[-4000:]
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("observations", "imported_sdk_modules")}, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
