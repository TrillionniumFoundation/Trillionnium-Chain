"""Version 2 continues only exact archived witnesses, never a fresh trace.

The legacy same-trace guard stays unchanged and rejects the observed new
MEMORY_IMAGE_ENTROPY. Independent execution is a statement control only.
"""
from pathlib import Path
import segment_continue_source as legacy
from segment_continue_source import *  # Explicitly reuse the unchanged provenance/resource guards.
from segment_witness import check_chain, claims_record

POLICY = HERE / "segment-continuation-v2.json"


def load_policy(root=ROOT, policy_path=POLICY):
    selected = read(policy_path)
    require(selected == {"schema": "pon-w1-frozen-witness-continuation-policy-v2",
        "legacy_policy_sha256": sha(checked_bytes(legacy.POLICY, 1024 * 1024)),
        "witness_source": "byte-exact-original-archive",
        "fresh_execution_role": "independent-full-statement-control",
        "mix_fresh_and_original_witnesses": False,
        "native_receipt_claim_binding_required": True}, "unknown or changed v2 continuation policy")
    return legacy.load_policy(root=root)


def original_members(policy, manifest, root=ROOT):
    files = legacy.original_members(policy, manifest, root)
    session = decode(files["segmented/session/session.json"])
    check_chain(session, [files[f"segmented/session/segment-{i}"] for i in range(62)])
    return files


def check_frozen_session(files, directory):
    expected = {name.removeprefix("segmented/session/"): data for name, data in files.items()
                if name.startswith("segmented/session/")}
    require(set(bounded_file_index(directory)) == set(expected), "frozen session missing/extra files")
    for name, data in expected.items():
        require(checked_bytes(path_under(directory, name), 1024 * 1024) == data,
                "frozen witness/session/claim bytes changed")
    session = decode(expected["session.json"])
    return session, claims_record(session, [expected[f"segment-{i}"] for i in range(62)])


def compare_fresh_session(files, directory):
    old = decode(files["segmented/session/session.json"])
    fresh = read(directory / "session.json")
    require(type(fresh.get("execute_and_export_wall_ns")) is int
            and fresh["execute_and_export_wall_ns"] > 0, "fresh export measurement unavailable")
    def statement(value):
        return {k: v for k, v in value.items() if k not in ("execute_and_export_wall_ns", "segments")}
    require(statement(old) == statement(fresh), "fresh full W1 statement differs")
    require(len(fresh["segments"]) == len(old["segments"]) == 62, "fresh segment count differs")
    for a, b in zip(old["segments"], fresh["segments"]):
        require({k: v for k, v in a.items() if k != "sha256"}
                == {k: v for k, v in b.items() if k != "sha256"}, "fresh segment profile differs")
    expected = {f"segment-{i}" for i in range(62)} | {"session.json", "session.claim.bin"}
    require(set(bounded_file_index(directory)) == expected, "fresh session missing/extra files")
    require(checked_bytes(directory / "session.claim.bin", 16 * 1024)
            == files["segmented/session/session.claim.bin"], "fresh full session claim differs")
    encoded = [checked_bytes(directory / f"segment-{i}", 1024 * 1024) for i in range(62)]
    # Each fresh trace remains internally complete; it is not a continuation witness.
    check_chain(fresh, encoded)
    require(claims_record(fresh, encoded)["segments"][0]["pre_state"]
            == claims_record(old, [files[f"segmented/session/segment-{i}"] for i in range(62)])["segments"][0]["pre_state"],
            "fresh initial memory differs")
    return fresh


def implementation_identity():
    names = ["segment_continue_v2.py", "segment_frozen_v2.py", "segment_witness.py",
             "segment-continuation-v2.json", "host/src/bin/check_frozen_receipts.rs"]
    return {name: {"bytes": len(data), "sha256": sha(data)}
            for name in names for data in [checked_bytes(HERE / name, 1024 * 1024)]}
