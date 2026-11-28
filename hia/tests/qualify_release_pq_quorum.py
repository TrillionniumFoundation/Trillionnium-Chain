#!/usr/bin/env python3
"""Test the bounded native release quorum against the exact private Rust logic."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import struct
import sys
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_auth.qualification.contract import check_platform_environment
from hia.tests.native_support import NativeModule
from hia.tests.qualify_release_pq_observation import build_original, execute, flip, read_model, require, sha
from hia.tests.test_release_pq_signing import DIR, RELEASE
from hia.tools.ml_dsa_original import check_environment

WORK = 32896
SPKI = 1974
SIGNATURE = 3309
SLOT = 4096
KEYS = 16
ADAPTER = Path(__file__).with_name("rust_release_pq_quorum_reference.rs")
EXACT_FUNCTIONS = "fb3af026f3cded8589de64f2e9a7f159f51125eea219cbea0630f694ea362c4b"


def bound_original(out):
    raw = RELEASE.read_bytes()
    verifiers = re.findall(rb"(?m)^type ReleaseVerifiersV1 =[^\n]+;", raw)
    functions = re.findall(
        rb"(?ms)^fn verify_quorum\(.*?(?=^#\[derive\(Debug, Clone, Copy, Eq, PartialEq\)\])", raw)
    require(len(verifiers) == len(functions) == 1, "original quorum ownership moved")
    exact = verifiers[0] + b"\n" + functions[0]
    require(sha(exact) == EXACT_FUNCTIONS, "original private quorum functions require review")
    fixture = out / "release_pq_quorum_locked.rs"
    fixture.write_bytes(ADAPTER.read_bytes() + b"\n" + exact)
    binary, provenance = build_original(out, fixture)
    provenance.update(original_release_source_sha256=sha(raw),
                      test_adapter_sha256=sha(ADAPTER.read_bytes()),
                      extracted_quorum_sha256=sha(exact))
    return binary, provenance


def issue(binary):
    result = execute([binary, "issue"])
    raw = result.stdout
    width = 32 + SPKI + SIGNATURE
    require(len(raw) == 155 + 184 + (KEYS + 1) * width and not result.stderr,
            "incomplete original synthetic public fixture")
    parts = [raw[at:at + width] for at in range(339, len(raw), width)]
    public = [(row[:32], row[32:32 + SPKI], row[32 + SPKI:]) for row in parts]
    roster, outsider = public[:-1], public[-1]
    require(sorted(roster) == roster and outsider[0] not in {row[0] for row in roster},
            "unusable independent role roster")
    return raw[:155], raw[155:339], roster, outsider


def envelope(descriptor, message, roles, signatures, *, threshold=2, other_scope=None):
    generation = struct.unpack_from("<Q", descriptor, 33)[0]
    role_flag = descriptor[0]
    network = descriptor[1:33]
    if other_scope is not None:
        role_flag, network, generation = other_scope
    frame = (struct.pack("<HHHBB", len(roles), len(signatures), threshold, role_flag, 0)
             + network + struct.pack("<Q", generation) + message)
    frame += b"".join(key + spki for key, spki in roles)
    for key, declared, actual in signatures:
        require(len(actual) <= SLOT, "outside sig slot")
        frame += key + struct.pack("<H", declared) + actual.ljust(SLOT, b"\xd2")
    return frame


def compare_model(module, label, frame, expected, extent=WORK + 17):
    unmodified = [frame, bytes([0x4c]) * 23, bytes([0xca]) * extent]
    returned = module.call_many([("f0", unmodified)], timeout=60)[0]
    returned.require_returned()
    require(returned.value == expected, f"{label}: expected {expected}, got {returned.value}")
    require(returned.arguments[:2] == unmodified[:2], f"{label}: input or output changed")
    scratch = returned.arguments[2]
    if expected in {0, 103, 106, 107, 108, 109}:
        require(scratch == bytes(WORK) + unmodified[2][WORK:], f"{label}: scratch cleanup")
    else:
        require(scratch == unmodified[2], f"{label}: malformed inputs must not mutate buffers")
    return {"case": label, "status": returned.value, "public_request_sha256": sha(frame)}


def cases_for(descriptor, encoded, public, outside):
    keys = [(key, spki) for key, spki, _ in public]
    signed = [(key, len(sig), sig) for key, _, sig in public]
    a, b, c = signed[0], signed[1], signed[2]
    outside = (outside[0], len(outside[2]), outside[2])
    short = (a[0], SIGNATURE - 1, a[2][:-1])
    duplicate_short = (a[0], 1, b"\x42")
    wrong_sig = (c[0], SIGNATURE, flip(c[2], 1))
    wrong_a = (a[0], SIGNATURE, flip(a[2], 1))
    wrong_der = [(a[0], flip(keys[0][1], 21)), *keys[1:]]
    mismatched_pin = [(a[0], keys[1][1]), *keys[1:]]
    max_declared = (a[0], 65535, b"")
    make = lambda ss, ks=keys, **kw: envelope(descriptor, encoded, ks, ss, **kw)
    original = [
        ("two_signers", make([a, b]), 0),
        ("two_in_reverse_order", make([b, a]), 0),
        ("three_above_threshold", make([c, a, b]), 0),
        ("maximum_16", make(signed[::-1]), 0),
        ("zero_signature", make([]), 105),
        ("below_threshold", make([outside]), 105),
        ("above_16", make([short] + signed), 105),
        ("duplicate_then_width", make([a, duplicate_short]), 107),
        ("first_width_then_duplicate", make([short, a]), 106),
        ("unknown_before_duplicate", make([outside, a, a]), 108),
        ("duplicate_before_unknown", make([a, a, outside]), 107),
        ("unknown_mathematically_valid_cross_role", make([a, outside]), 108),
        ("width_before_later_unknown", make([short, outside]), 106),
        ("late_unknown_precedes_earlier_math", make([wrong_a, outside]), 108),
        ("late_duplicate_precedes_earlier_math", make([wrong_a, b, b]), 107),
        ("late_invalid_pin_precedes_earlier_math",
         make([wrong_a, b], [keys[0], (b[0], keys[0][1]), *keys[2:]]), 109),
        ("check_all_past_threshold", make([a, b, wrong_sig]), 106),
        ("der_before_signature_width", make([short, b], wrong_der), 109),
        ("wrong_pin_before_width", make([short, b], mismatched_pin), 109),
        ("declared_width_outside_slot", make([max_declared, b]), 106),
        ("all_sixteen_at_max_threshold", make(signed, threshold=16), 0),
        ("max_threshold_not_met", make(signed[:-1], threshold=16), 105),
        ("wrong_exact_message_checkpoint",
         envelope(descriptor, flip(encoded, 90), keys, [a, b]), 106),
    ]
    good = make([a, b])
    private = [
        ("empty_private_frame", b"", 100, WORK),
        ("truncated_frame", good[:-1], 100, WORK),
        ("appended_byte", good + b"\x00", 100, WORK),
        ("duplicate_trusted_pins", make([a, b], [keys[0], *keys[:-1]]), 100, WORK),
        ("unsorted_trusted_pins", make([a, b], keys[::-1]), 100, WORK),
        ("trusted_zero_threshold", make([a, b], threshold=0), 100, WORK),
        ("reserved_byte", flip(good, 7), 100, WORK),
        ("invalid_transcript_domain", flip(good, 48), 100, WORK),
        ("invalid_transcript_optional_encoding", flip(good, 167), 100, WORK),
        ("source_role_mismatch", make([a, b], other_scope=(2, descriptor[1:33], 1)), 110, WORK),
        ("source_network_mismatch", make([a, b], other_scope=(1, bytes(range(32)), 1)), 110, WORK),
        ("source_generation_mismatch", make([a, b], other_scope=(1, descriptor[1:33], 2)), 110, WORK),
        ("scratch_too_short", good, 102, WORK - 1),
        ("count_precedes_scratch", make([a]), 105, 0),
        ("valid_exact_scratch", good, 0, WORK),
    ]
    return original, private


def check(out):
    check_environment(ROOT, os.environ)
    check_platform_environment(os.environ)
    start = execute(["git", "show", "-s", "--format=%H %T"], cwd=ROOT).stdout
    initially_clean = not execute(["git", "status", "--porcelain"], cwd=ROOT).stdout
    binary, rust = bound_original(out)
    descriptor, original_message, public, outside = issue(binary)
    results = {}
    for backend in ("direct", "selfhost"):
        with ExitStack() as stack:
            native = stack.enter_context(NativeModule(DIR / "pq_quorum.hepta",
                                         byte_exports=("f0",), backend=backend))
            transcript = stack.enter_context(NativeModule(DIR / "pq_signing_message.hepta",
                                             byte_exports=("f0",), backend=backend))
            exact_message = read_model(transcript, descriptor, original_message, 184, 0)
            original, private = cases_for(descriptor, exact_message, public, outside)
            expected = bytes(status for _, _, status in original)
            framed = b"".join(struct.pack("<I", len(frame)) + frame for _, frame, _ in original)
            rust_checked = execute([binary, "verify"], input=framed, timeout=60)
            require(rust_checked.stdout == expected and not rust_checked.stderr,
                    f"exact Rust quorum differed: {list(rust_checked.stdout)} vs {list(expected)}")
            for title, module in (("quorum", native), ("transcript", transcript)):
                image = module.library.read_bytes()
                require(sha(image) == module.artifact_sha256, "emitted image changed")
                (out / f"{backend}-{title}.so").write_bytes(image)
                (out / f"{backend}-{title}-native-build.json").write_text(
                    json.dumps(module.receipt, indent=2, sort_keys=True) + "\n")
            results[backend] = {
                "native_quorum_sha256": native.artifact_sha256,
                "native_transcript_sha256": transcript.artifact_sha256,
                "original_owner_synthetic_accept_reached": True,
                "differential": [compare_model(native, name, frame, status)
                                 for name, frame, status in original],
                "private_boundary": [compare_model(native, *args) for args in private],
            }
    require(results["direct"]["native_quorum_sha256"] != results["selfhost"]["native_quorum_sha256"],
            "independent machine emitters expected")
    require(start == execute(["git", "show", "-s", "--format=%H %T"], cwd=ROOT).stdout,
            "local source changed during qualification")
    clean = not execute(["git", "status", "--porcelain"], cwd=ROOT).stdout
    head, tree = start.decode().split()
    return {"status": "PASS", "source_head": head, "source_tree": tree, "source_state":
            "committed-clean" if initially_clean and clean else "dirty-candidate", "rust": rust,
            "backends": results, "trusted_snapshot_is_current_proved": False,
            "release_authorized": False, "ephemeral_secret_input_or_output": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    output = parser.parse_args().output.absolute()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output.mkdir(mode=0o700)
    report = check(output)
    (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    counts = report["backends"]["direct"]
    print(json.dumps({"status": "PASS", "source_head": report["source_head"],
                      "per_backend_rust_differential": len(counts["differential"]),
                      "per_backend_private_cases": len(counts["private_boundary"]),
                      "release_authorized": False}, sort_keys=True))
