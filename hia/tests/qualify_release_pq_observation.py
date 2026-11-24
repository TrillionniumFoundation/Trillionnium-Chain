#!/usr/bin/env python3
"""Exercise typed release messages with the actual HIA-owned pinned verifier.

Qualification only. Python copies public values between existing native
entries. It neither implements ML-DSA nor admits or activates a release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tomllib
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_auth.build_owned import Build
from hia.platform.pq_auth.qualification.api import buffer, data, load
from hia.tests.native_support import NativeModule
from hia.tests.test_release_pq_signing import DIR, MESSAGE_DOMAIN, ZERO, payload

ROLE_DOMAIN = MESSAGE_DOMAIN + b"bundle-role\0"
WORK = 1256
ADAPTER = Path(__file__).with_name("rust_release_pq_observation_reference.rs")
SPKI, SIGNATURE = 1974, 3309


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def execute(command, **kwargs):
    result = subprocess.run(list(map(str, command)), check=False, capture_output=True,
                            timeout=kwargs.pop("timeout", 60), **kwargs)
    require(result.returncode == 0, result.stderr.decode(errors="replace"))
    return result


def build_original(out, adapter=ADAPTER):
    pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc, cargo = [Path(shutil.which(name) or "/nonexistent").absolute()
                    for name in ("rustc", "cargo")]
    for name in (rustc, cargo):
        require(execute([name, "--version"]).stdout.decode().split()[1] == pin,
                f"expected toolchain {pin}: {name.name}")
    target = out / "rust-target"
    argv = [cargo, "build", "--locked", "--offline", "-p", "trnm-release-bundle",
            "--lib", "--target-dir", target, "--message-format=json"]
    run = execute(argv, cwd=ROOT / "trillionnium", timeout=240,
                  env={**os.environ, "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2"})
    (out / "rust-build.stdout.jsonl").write_bytes(run.stdout)
    (out / "rust-build.stderr.raw").write_bytes(run.stderr)
    crates = {"trnm_release_bundle", "trnm_crypto_primitives", "trnm_protocol", "zeroize"}
    libraries = {}
    for line in run.stdout.splitlines():
        row = json.loads(line)
        name = row.get("target", {}).get("name")
        if row.get("reason") == "compiler-artifact" and name in crates:
            files = [Path(item) for item in row["filenames"] if item.endswith(".rlib")]
            require(len(files) == 1 and name not in libraries, "ambiguous original rlib")
            libraries[name] = files[0]
    require(set(libraries) == crates, "missing original locked rlib")
    binary = out / "rust-original"
    command = [rustc, "--edition=2024", "-Dwarnings", adapter, "-L",
               f"dependency={target / 'debug/deps'}", "-o", binary]
    for name, path in sorted(libraries.items()):
        command += ["--extern", f"{name}={path}"]
    execute(command)
    return binary, {"rust_pin": pin, "workspace_lock_sha256": sha(
        (ROOT / "trillionnium/Cargo.lock").read_bytes()), "public_adapter_sha256": sha(
        adapter.read_bytes()), "original_binary_sha256": sha(binary.read_bytes()),
        "libraries": {name: sha(p.read_bytes()) for name, p in sorted(libraries.items())}}


def issue(binary, descriptor, root_network):
    # No seed enters or exits this subprocess. Only the exact native-independent
    # original Rust signing fixture emits SPKI, pins, unsigned bytes and signature.
    result = execute([binary, "issue"], input=descriptor + root_network)
    raw = result.stdout
    require(len(raw) == 184 + 128 + 32 + SPKI + SIGNATURE and not result.stderr,
            "incomplete original public fixture")
    return raw[:184], raw[184:312], raw[312:344], raw[344:344 + SPKI], raw[-SIGNATURE:]


def original_verify(binary, cases):
    request = bytearray()
    for _, pin, spki, message, signature, _ in cases:
        request.extend(pin)
        for field in (spki, message, signature):
            request.extend(struct.pack("<I", len(field)))
            request.extend(field)
    result = execute([binary, "verify"], input=bytes(request))
    pending, values = result.stdout, []
    for _, _, _, message, _, _ in cases:
        require(bool(pending), "incomplete original verifier statuses")
        status = pending[0]
        size = 1 if status else 1 + 32 + len(message)
        require(len(pending) >= size, "incomplete original authenticated observation")
        values.append((status, pending[1:size]))
        pending = pending[size:]
    require(not pending and not result.stderr, "unexpected original verifier stream")
    return values


def read_model(module, frame, want, out, scratch, expected_status=0):
    canary_out, canary_work = b"\xca" * out, b"\x96" * scratch
    answer = module.call_many([("f0", [frame, canary_out, canary_work])], timeout=45)[0]
    answer.require_returned()
    require(answer.value == expected_status and answer.arguments[0] == frame,
            "bad framing outcome or input write")
    require(answer.arguments[1] == want + canary_out[len(want):], "wrong or partial public output")
    if expected_status or not scratch:
        require(answer.arguments[2] == canary_work, "scratch write on a refused input")
    else:
        require(answer.arguments[2][WORK:] == canary_work[WORK:], "scratch extent exceeded")
    return answer.arguments[1][:len(want)]


def native_verify(functions, cases):
    def value(result):
        require(result.status == 0 and result.value, "owned verifier ABI failure")
        return result.value

    observations, alive = [], {}
    try:
        for _, pin, spki, message, signature, _ in cases:
            cache_key = pin, spki
            if cache_key not in alive:
                alive[cache_key] = value(functions["verifier_from_pinned_spki"](
                    buffer(spki), len(spki), buffer(pin)))
            verifier = alive[cache_key]
            kind = functions["kind"](verifier)
            if kind == 255:
                observations.append((functions["value_code"](verifier), b""))
                continue
            require(kind == 3 and data(functions["key_public_spki"], verifier) == spki
                    and data(functions["key_public_key_id"], verifier) == pin, "wrong public verifier pin")
            result = value(functions["verify_exact_message"](
                verifier, buffer(message), len(message), buffer(signature), len(signature)))
            try:
                result_kind = functions["kind"](result)
                if result_kind == 255:
                    observations.append((functions["value_code"](result), b""))
                else:
                    require(result_kind == 102, "unexpected HIA-owned result")
                    observations.append((0, data(functions["message_signer_key_id"], result)
                                         + data(functions["message_authenticated_message"], result)))
            finally:
                require(functions["drop"](result) == 0, "drop owned observation")
    finally:
        for verifier in alive.values():
            require(functions["drop"](verifier) == 0, "drop owned verifier")
    return observations


def flip(raw, offset):
    return raw[:offset] + bytes([raw[offset] ^ 1]) + raw[offset + 1:]


def check(out):
    platform = Build(out / "owned")
    build = platform.run()
    binary, rust = build_original(out)
    root_network = bytes(range(31, -1, -1))
    release = payload(previous=None, values=(0x0102030405060708, 2**63, 2**64 - 1))
    second = payload(role=4, network=bytes(range(32)), previous=ZERO, rollback=1)
    require(release[1:33] != root_network and second[1:33] != root_network,
            "fixture did not separate root and metadata networks")
    issue_a, issue_b = (issue(binary, raw, root_network) for raw in (release, second))
    alternate_root = bytes(range(32))
    alternate_identities = issue(binary, release, alternate_root)[1]
    want, identities, pin, spki, sig = issue_a
    want_b, same_identities, pin_b, spki_b, sig_b = issue_b
    require(identities == same_identities and pin != pin_b,
            "role identity changed with the ephemeral root keys")
    library, functions = load(platform.output / "pq-owned.so")
    results = {}
    for backend in ("direct", "selfhost"):
        with ExitStack() as stack:
            iso = stack.enter_context(NativeModule(DIR / "pq_role_identity.hepta",
                                       byte_exports=("f0",), backend=backend))
            msg = stack.enter_context(NativeModule(DIR / "pq_signing_message.hepta",
                                       byte_exports=("f0",), backend=backend))
            for role in range(1, 5):
                frame = root_network + bytes([role])
                digest = identities[(role - 1) * 32:role * 32]
                require(digest == hashlib.sha256(ROLE_DOMAIN + frame).digest(),
                        "original role digest did not equal literal transcript")
                read_model(iso, frame, digest, 39, WORK + 7)
                alternate_frame = alternate_root + bytes([role])
                alternate_digest = alternate_identities[(role - 1) * 32:role * 32]
                require(alternate_digest != digest and
                        alternate_digest == hashlib.sha256(ROLE_DOMAIN + alternate_frame).digest(),
                        "root network not bound")
                read_model(iso, alternate_frame, alternate_digest, 32, WORK)
                require(digest != hashlib.sha256(ROLE_DOMAIN + release[1:33]
                                                + bytes([role])).digest(), "metadata substituted")
            bad_identity = [b"", root_network, root_network + b"\x01\x00"]
            bad_identity += [root_network + bytes([r]) for r in (0, 5, 255)]
            for frame in bad_identity:
                read_model(iso, frame, b"", 32, WORK, 100)
            read_model(iso, root_network + b"\x01", b"", 31, WORK, 102)
            read_model(iso, root_network + b"\x01", b"", 32, WORK - 1, 102)
            a = read_model(msg, release, want, 193, 0)
            b = read_model(msg, second, want_b, 193, 0)
            cases = [("valid_first", pin, spki, a, sig, 0),
                     ("valid_second", pin_b, spki_b, b, sig_b, 0)]
            # These offsets hit role/network, all three integers, independent
            # expected checkpoint, content, and rollback flag in the signed bytes.
            for at in (0, 1, 32, 33, 40, 41, 48, 49, 56, 57, 88, 122, 153, 154):
                altered = flip(release, at)
                if at == 0:  # NodeSoftware -> ProtocolConfiguration, still typed.
                    altered = b"\x02" + release[1:]
                changed = msg.call_many([("f0", [altered, bytes(184), b""])], timeout=45)[0]
                changed.require_returned()
                require(changed.value == 0 and changed.arguments[0] == altered, "mutated typed framing")
                cases.append((f"descriptor_byte_{at}", pin, spki, changed.arguments[1], sig, 4))
            previous = release[:89] + b"\x01" + release[90:]
            patched = read_model(msg, previous, a[:118] + b"\x01" + a[119:], 184, 0)
            cases.extend([
                ("none_is_not_some_zero", pin, spki, patched, sig, 4),
                ("altered_domain", pin, spki, flip(a, 0), sig, 4),
                ("short_signature", pin, spki, a, sig[:-1], 4),
                ("altered_signature", pin, spki, a, flip(sig, 6), 4),
                ("replacement_public_key", pin_b, spki_b, a, sig, 4),
                ("wrong_pin_precedes_short_signature", pin_b, spki, a, sig[:1], 3),
                ("malformed_spki_precedes_pin", pin_b, flip(spki, 0), a, sig, 1),
                ("same_verifier_positive_after_refusal", pin, spki, a, sig, 0),
            ])
            expected = [(status, b"" if status else key + message)
                        for _, key, _, message, _, status in cases]
            original = original_verify(binary, cases)
            observed = native_verify(functions, cases)
            for row, old, new, expectation in zip(cases, original, observed, expected, strict=True):
                require(old == new == expectation, f"{backend}: {row[0]} outcome")
            results[backend] = {"role_identity_image_sha256": iso.artifact_sha256,
                "transcript_image_sha256": msg.artifact_sha256,
                "valid_identities": 8, "role_identity_refusals": 8,
                "observations": [{"name": row[0], "status": new[0],
                    "message_sha256": sha(row[3]), "public_observation_sha256": sha(new[1])}
                    for row, new in zip(cases, observed, strict=True)]}
    for key in ("role_identity_image_sha256", "transcript_image_sha256"):
        require(results["direct"][key] != results["selfhost"][key], f"non-independent {key}")
    # Keep library loaded until all opaque value owners have been destroyed.
    require(library is not None, "missing HIA-owned library")
    source = execute(["git", "show", "-s", "--format=%H %T"], cwd=ROOT).stdout.decode().split()
    dirty = bool(execute(["git", "status", "--porcelain"], cwd=ROOT).stdout)
    return {"status": "PASS", "source_head": source[0], "source_tree": source[1],
            "source_state": "dirty-candidate" if dirty else "committed-clean",
            "rust": rust, "backends": results,
            "owned_verifier_image": build["final_image"], "secret_material_retained": False,
            "qualification_only": True, "release_authorized": False, "quorum_verified": False}


if __name__ == "__main__":
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--output", required=True, type=Path)
    output = args.parse_args().output.absolute()
    # A fixture process failure must never create a private-key-bearing core.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output.mkdir(mode=0o700)
    report = check(output)
    (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "source_head": report["source_head"],
                      "observations_per_emitter": len(report["backends"]["direct"]["observations"]),
                      "quorum_verified": False, "release_authorized": False}, sort_keys=True))
