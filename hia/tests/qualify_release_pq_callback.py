#!/usr/bin/env python3
"""Test-only composition of native V0/PQ shadow phases against locked Rust."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import struct
import sys
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_auth.qualification.contract import check_platform_environment
from hia.tests.native_support import NativeModule
from hia.tests.qualify_release_pq_observation import build_original, execute, require, sha
from hia.tests.test_release_pq_bundle_state import snapshot
from hia.tests.test_release_pq_signing import DIR, pack_signatures
from hia.tests.test_release_unsigned_candidate import ADAPTER as UNSIGNED_ADAPTER, case
from hia.tools.ml_dsa_original import check_environment

ADAPTER = Path(__file__).with_name("rust_release_pq_callback_reference.rs")
KEY_WIDTH = 2006
SIG_WIDTH = 3341
CASES = (
    ("valid", 0, "state", 0),
    ("valid_signature_wrong_generation", 204, "state", 204),
    ("valid_signature_wrong_network", 204, "state", 204),
    ("bad_signature_before_wrong_generation", 2, "quorum", 106),
    ("bad_locator_before_checkpoint", 2, "locator_mismatch", 0),
    ("invalid_unsigned_before_bad_signature", 2, "unsigned", 101),
    ("invalid_role_before_invalid_unsigned", 1, "outer", 1),
    ("declared_content_mismatch_before_invalid_unsigned", 1, "outer", 1),
    ("valid_signature_stale_candidate_checkpoint", 205, "state", 205),
    ("bad_signature_before_checkpoint", 2, "quorum", 106),
    ("valid_signature_expiry_before_wrong_generation", 203, "state", 203),
    ("identity_before_locator_and_math", 2, "identity_mismatch", 0),
    ("duplicate_locator_before_quorum_and_checkpoint", 2, "locator", 107),
    ("valid_cross_role_signature_refused", 2, "quorum", 108),
)


def bound_original(out):
    parser = UNSIGNED_ADAPTER.read_bytes()
    helpers = parser[parser.index(b"fn le16("):parser.index(b"fn main(")]
    decode = parser[parser.index(b"        let art_begin ="):parser.index(b"        let code =")]
    old = b"let mut release = bundle(20, 7);"
    require(decode.count(old) == 1, "unexpected prior typed fixture initialization")
    decode = decode.replace(old, b"let mut release = blank();")
    source = out / "release_callback_locked_fixture.rs"
    source.write_bytes(ADAPTER.read_bytes() + helpers
        + b"\nfn decode(frame: &[u8]) -> (ReleaseBundleV0, Vec<(Vec<u8>, Vec<u8>)>, usize) {\n"
        + decode + b"assert_eq!(frame.len(), full_end);\n(release, required, fixed + 288)\n}\n")
    binary, provenance = build_original(out, source)
    provenance["shared_unsigned_fixture_parser_sha256"] = sha(parser)
    return binary, provenance


def native(module, raw, room, scratch_len):
    args = [raw, b"\x4e" * room, b"\x2f" * scratch_len]
    observed, = module.call_many([("f0", args)], timeout=45)
    observed.require_returned()
    require(observed.arguments[0] == raw, "native borrowed input changed")
    if observed.value:
        require(observed.arguments[1] == args[1], "output changed on refusal")
    return observed.value, observed.arguments[1]


def observations(modules, frame, metadata, roster, signatures, network, tip, expiry, now):
    trace = []

    def run(stage, data, output=0, scratch=0):
        status, observed = native(modules[stage], data, output, scratch)
        trace.append((stage, status))
        return status, observed

    counts = struct.unpack_from("<HHH", frame, 4)
    declared_digest_at = 1067 + sum(n * w for n, w in zip(counts, (877, 1351, 772))) + 290
    if metadata[0] != 1 or metadata[122:154] != frame[declared_digest_at:declared_digest_at + 32]:
        return 1, [("outer", 1)]
    code, unsigned = run("unsigned", frame, 168, 5360)
    if code:
        return 2, trace
    require(unsigned[:32] == metadata[122:154], "unsigned returned a different checked digest")
    code, role_identity = run("identity", network + metadata[:1], 32, 1256)
    require(not code, "trusted role identity frame unexpectedly refused")
    if role_identity != frame[42:74]:
        return 2, trace + [("identity_mismatch", 0)]
    count = struct.pack("<H", len(signatures))
    packed = pack_signatures(signatures)
    code, locator = run("locator", packed, 32, 1240)
    if code:
        return 2, trace
    if locator != frame[74:106]:
        return 2, trace + [("locator_mismatch", 0)]
    code, message = run("message", metadata, 184)
    require(not code, "typed original transcript was refused")
    quorum_input = (struct.pack("<H", 2) + count + struct.pack("<HBB", 2, 1, 0)
                    + network + struct.pack("<Q", 1) + message + roster + packed[2:])
    code, _ = run("quorum", quorum_input, 0, 32896)
    # Control: the previously published strict scoped ABI still rejects the
    # right bytes before its math if scope differs. It does not drive this path.
    if metadata[1:33] != network or struct.unpack_from("<Q", metadata, 33)[0] != 1:
        strict, _ = native(modules["strict"], quorum_input, 0, 32896)
        require(strict == 110, "strict ABI's root check changed")
    if code:
        return 2, trace
    # Synthetic original owner is initially pinned with no events. Supply the
    # very same immutable metadata; no math result or authorizing token enters
    # the state guard. This does not authenticate a source of current state.
    state = snapshot(trusted_tip=tip, owner_tip=tip, root_network=network, generation=1,
                     root_expiry=expiry, now=now, floor=now, version=0, events=0)
    code, _ = run("state", metadata + state[155:])
    return code, trace


def check(out):
    check_environment(ROOT, os.environ)
    check_platform_environment(os.environ)
    source = execute(["git", "show", "-s", "--format=%H %T"], cwd=ROOT).stdout
    initially_clean = not execute(["git", "status", "--porcelain"], cwd=ROOT).stdout
    binary, provenance = bound_original(out)
    raw_template = case()[0]
    signed = execute([binary], input=raw_template)
    head = 80 + 2 * KEY_WIDTH
    row_width = 1 + 155 + 2 * SIG_WIDTH + len(raw_template)
    require(len(signed.stdout) == head + row_width * len(CASES) and not signed.stderr,
            "unexpected original fixture stream")
    raw = signed.stdout
    network, tip, roster = raw[:32], raw[32:64], raw[80:head]
    expiry, now = struct.unpack_from("<QQ", raw, 64)
    results = {}
    sources = {"unsigned": "unsigned_candidate", "identity": "pq_role_identity",
               "locator": "pq_signature_set", "message": "pq_signing_message",
               "quorum": "pq_bundle_callback_quorum", "strict": "pq_quorum",
               "state": "pq_bundle_state"}
    for backend in ("direct", "selfhost"):
        with ExitStack() as stack:
            modules = {name: stack.enter_context(NativeModule(DIR / (stem + ".hepta"),
                                      backend=backend, byte_exports=("f0",)))
                       for name, stem in sources.items()}
            rows = []
            for i, (label, expected, phase, stage_code) in enumerate(CASES):
                start = head + i * row_width
                row = raw[start:start + row_width]
                compare, metadata = row[0], row[1:156]
                slots = (row[156:156 + SIG_WIDTH], row[156 + SIG_WIDTH:156 + 2 * SIG_WIDTH])
                signatures = [(sig[:32], sig[32:]) for sig in slots]
                bundle = row[156 + 2 * SIG_WIDTH:]
                actual, trace = observations(modules, bundle, metadata, roster, signatures,
                                             network, tip, expiry, now)
                require(actual == compare == expected and trace[-1] == (phase, stage_code),
                        f"{backend} {label}: native {actual} {trace}, original {compare}")
                rows.append({"case": label, "actual_original": compare, "native": actual,
                             "native_phases": trace, "public_fixture_sha256": sha(row)})
            images = {}
            for name, module in modules.items():
                images[name] = module.artifact_sha256
                (out / f"{backend}-{name}-native-build.json").write_text(
                    json.dumps(module.receipt, sort_keys=True, indent=2) + "\n")
                if name in ("quorum", "strict"):
                    image = module.library.read_bytes()
                    require(sha(image) == images[name], "native callback proof image changed")
                    (out / f"{backend}-{name}.so").write_bytes(image)
            results[backend] = {"images": images, "rows": rows}
    require(all(results["direct"]["images"][name] != results["selfhost"]["images"][name]
                for name in sources), "independent machine emitters are required for every phase")
    require(source == execute(["git", "show", "-s", "--format=%H %T"], cwd=ROOT).stdout,
            "local source changed")
    clean = not execute(["git", "status", "--porcelain"], cwd=ROOT).stdout
    h, t = source.decode().split()
    return {"status": "PASS", "source_head": h, "source_tree": t, "source_state":
            "committed-clean" if initially_clean and clean else "dirty-candidate",
            "locked_original": provenance, "backends": results, "production_authority": False,
            "native_same_call_token": False, "test_only_composition": True}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output", required=True, type=Path)
    output = cli.parse_args().output.absolute()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output.mkdir(mode=0o700)
    report = check(output)
    (output / "qualification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "source_head": report["source_head"],
                      "original_rows_per_backend": len(CASES), "production_authority": False},
                     sort_keys=True))
