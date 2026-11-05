#!/usr/bin/env python3
"""Build pinned mldsa-native and cross-check the actual RustCrypto adapter.

No installed Python cryptographic provider is required. The independent C
implementation is compiled from an exact, byte-checked upstream checkout.
All keys are disposable fixtures. Failure/missing dependencies are failures,
never skips; this is finite interoperability evidence, not a security proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

UPSTREAM_COMMIT = "834a90d5e846ffa1e1611bd24e160bb2e9b86d35"
VECTOR_SHA256 = "1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034"
SPKI_PREFIX = bytes.fromhex("308207b2300b0609608648016503040312038207a100")
KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\0"
PUBLIC_BYTES, SIGNATURE_BYTES = 1952, 3309


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_source(source: Path, *, commit: str = UPSTREAM_COMMIT,
                   subtree: str = "mldsa") -> dict:
    def git(*args: str) -> bytes:
        return subprocess.check_output(
            ["git", "--no-replace-objects", "-C", str(source), *args], timeout=30)
    if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != source:
        raise ValueError("upstream checkout root mismatch")
    if git("for-each-ref", "--format=%(refname)", "refs/replace/").strip():
        raise ValueError("Git replacement objects are not upstream source")
    grafts = Path(git("rev-parse", "--git-path", "info/grafts").decode().strip())
    if not grafts.is_absolute():
        grafts = source / grafts
    if grafts.exists() or grafts.is_symlink():
        raise ValueError("Git grafts are not upstream source")
    if git("rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("independent source must be the exact pinned commit")
    entries = git("ls-tree", "-rz", "--full-tree", "HEAD", "--", subtree).split(b"\0")
    identities = {}
    for entry in filter(None, entries):
        metadata, path_bytes = entry.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        path = path_bytes.decode()
        target = source / path
        if (kind != "blob" or mode not in ("100644", "100755") or target.is_symlink()
                or not target.is_file() or not target.resolve().is_relative_to(source)):
            raise ValueError("non-regular upstream input: " + path)
        data = target.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != blob:
            raise ValueError("changed upstream source: " + path)
        identities[path] = digest(data)
    actual_paths = {str(p.relative_to(source)) for p in (source / subtree).rglob("*")
                    if not p.is_dir() or p.is_symlink()}
    if not identities or actual_paths != set(identities):
        raise ValueError("extra or missing upstream source files")
    return {"commit": commit, "files": len(identities),
            "source_sha256": digest(json.dumps(identities, sort_keys=True).encode())}


def field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def native(executable: Path, mode: str, message: bytes, context: bytes = b"",
           seed: int = 7, public: bytes = b"", signature: bytes = b"") -> bytes:
    args = [str(executable), mode]
    payload = field(context) + field(message)
    if mode == "sign":
        args.append(str(seed))
    else:
        payload += field(public) + field(signature)
    return subprocess.run(args, input=payload, capture_output=True, timeout=30,
                          check=True).stdout


def rust(executable: Path, requests: list[dict]) -> list[dict]:
    result = subprocess.run([str(executable)], input=json.dumps(requests), text=True,
                            capture_output=True, timeout=60, check=True)
    values = json.loads(result.stdout)
    if type(values) is not list or len(values) != len(requests):
        raise ValueError("RustCrypto oracle result cardinality")
    return values


def verification(public: bytes, message: bytes, signature: bytes,
                 spki: bytes | None = None, key_id: str | None = None) -> dict:
    if spki is None:
        spki = SPKI_PREFIX + public
    return {"mode": "verify", "spki": spki.hex(),
            "key_id": key_id or digest(KEY_DOMAIN + spki),
            "message": message.hex(), "signature": signature.hex()}


def run(args: argparse.Namespace, report: dict) -> None:
    source = args.source.resolve(strict=True)
    oracle = args.chain_oracle.resolve(strict=True)
    output = args.build_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report["upstream"] = checked_source(source)
    here = Path(__file__).resolve().parent
    adapter = here / "mldsa_native_oracle.c"
    executable = output / "mldsa-native-oracle"
    command = [args.cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror",
               "-DMLD_CONFIG_PARAMETER_SET=65", "-DMLD_CONFIG_NO_RANDOMIZED_API",
               "-DMLD_CONFIG_NAMESPACE_PREFIX=trnm_test_mldsa",
               "-I" + str(source / "mldsa"), str(adapter),
               str(source / "mldsa/mldsa_native.c"), "-o", str(executable)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    report["build"] = {"command": command, "backend": "portable C; pure ML-DSA-65",
                       "compiler": subprocess.check_output([args.cc, "--version"],
                           text=True, timeout=10).splitlines()[0]}
    report["binaries"] = [{"path": str(p), "sha256": digest(p.read_bytes())}
                          for p in (oracle, executable)]
    report["adapter_sha256"] = digest(adapter.read_bytes())
    report["runner_sha256"] = digest(Path(__file__).read_bytes())
    cases, expected, categories = [], [], {}
    native_checks = 0

    def add(category: str, request: dict, accepted: bool) -> None:
        cases.append(request)
        expected.append({"accepted": accepted})
        categories[category] = categories.get(category, 0) + 1

    def check_native(public: bytes, message: bytes, signature: bytes,
                     accepted: bool, context: bytes = b"") -> None:
        nonlocal native_checks
        observed = native(executable, "verify", message, context,
                          public=public, signature=signature)
        if observed != (b"\1" if accepted else b"\0"):
            raise AssertionError("independent native verification disagreement")
        native_checks += 1

    messages = [b"", b"TRNM/Cell/Provider/ML-DSA-65/v2\0statement",
                bytes(range(256)), b"x" * 65536]
    requests = [{"mode": "sign", "test_seed": seed, "message": message.hex()}
                for seed in (0, 1, 7, 127, 255) for message in messages]
    signed = rust(oracle, requests)
    for request, item in zip(requests, signed, strict=True):
        message = bytes.fromhex(request["message"])
        generated = native(executable, "sign", message, seed=request["test_seed"])
        if len(generated) != PUBLIC_BYTES + SIGNATURE_BYTES:
            raise AssertionError("native signing output length")
        public, signature = generated[:PUBLIC_BYTES], generated[PUBLIC_BYTES:]
        spki = SPKI_PREFIX + public
        if item != {"spki": spki.hex(), "key_id": digest(KEY_DOMAIN + spki),
                    "signature": signature.hex()}:
            raise AssertionError("independent fixed-seed key/signature drift")
        check_native(public, message, bytes.fromhex(item["signature"]), True)
        add("native_to_rust_positive", verification(public, message, signature), True)
        for changed_message, changed_signature in (
                (message + b"!", signature),
                (message, signature[:100] + bytes([signature[100] ^ 1]) + signature[101:]),
                (message, signature[:-1]), (message, signature + b"\0")):
            check_native(public, changed_message, changed_signature, False)
            add("cross_backend_negative", verification(public, changed_message, changed_signature), False)
        add("wrong_key_pin", verification(public, message, signature, key_id="00" * 32), False)
        for context in (b"domain", bytes(range(255))):
            contextual = native(executable, "sign", message, context,
                                seed=request["test_seed"])[PUBLIC_BYTES:]
            check_native(public, message, contextual, True, context)
            check_native(public, message, contextual, False)
            add("nonempty_context_refused_by_application",
                verification(public, message, contextual), False)

    message = b"strict application envelope"
    generated = native(executable, "sign", message)
    public, signature = generated[:PUBLIC_BYTES], generated[PUBLIC_BYTES:]
    spki = SPKI_PREFIX + public
    for index in range(len(SPKI_PREFIX)):
        changed = bytearray(spki)
        changed[index] ^= 1
        add("strict_spki", verification(public, message, signature, spki=bytes(changed)), False)
    for invalid in (public, spki + b"\0", spki[:-1]):
        add("strict_spki", verification(public, message, signature, spki=invalid), False)
    oversized = b"m" * 65537
    signature = native(executable, "sign", oversized)[PUBLIC_BYTES:]
    check_native(public, oversized, signature, True)
    add("application_message_limit", verification(public, oversized, signature), False)

    raw = args.wycheproof.resolve(strict=True).read_bytes()
    if digest(raw) != VECTOR_SHA256:
        raise ValueError("upstream Wycheproof bytes changed")
    total, valid = 0, 0
    for group in json.loads(raw)["testGroups"]:
        public = bytes.fromhex(group["publicKey"])
        for test in group["tests"]:
            message, signature = bytes.fromhex(test["msg"]), bytes.fromhex(test["sig"])
            context = bytes.fromhex(test.get("ctx", ""))
            accepted = test["result"] == "valid"
            check_native(public, message, signature, accepted, context)
            add("wycheproof_application_policy", verification(public, message, signature,
                spki=bytes.fromhex(group["publicKeyDer"])),
                accepted and not context and len(message) <= 65536)
            total += 1
            valid += int(accepted)
    if (total, valid) != (210, 79):
        raise ValueError("upstream corpus count changed")
    for start in range(0, len(cases), 20):
        actual = rust(oracle, cases[start:start + 20])
        if actual != expected[start:start + 20]:
            mismatch = next(i for i, (a, b) in enumerate(zip(actual,
                expected[start:start + 20], strict=True)) if a != b)
            raise AssertionError(f"RustCrypto disagreement at case {start + mismatch}")
    # Detect any source/binary changes during the run, not just at startup.
    if checked_source(source) != report["upstream"]:
        raise AssertionError("upstream source changed during execution")
    for record in report["binaries"]:
        if digest(Path(record["path"]).read_bytes()) != record["sha256"]:
            raise AssertionError("oracle binary changed during execution")
    report.update(result="PASS", fixed_seed_signatures=len(requests),
                  native_verification_cases=native_checks,
                  rust_verification_cases=len(cases), categories=categories,
                  wycheproof={"total": total, "valid": valid, "invalid": total - valid},
                  vector_sha256=VECTOR_SHA256)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--chain-oracle", required=True, type=Path)
    parser.add_argument("--wycheproof", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    report = {"schema": "trnm.pq.mldsa-native-differential.v1", "result": "FAIL",
              "host": {"system": platform.system(), "machine": platform.machine()},
              "canonical_backend": "RustCrypto ml-dsa 0.1.1; pure, empty context",
              "production_activation": False, "independent_security_accepted": False,
              "scope": "finite primitive interoperability; no deployment or chain-security claim"}
    started = time.monotonic()
    try:
        run(args, report)
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        report["error"] = f"{type(error).__name__}: {error}"
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            report["stderr"] = str(error.stderr)[-8000:]
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
