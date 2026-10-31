#!/usr/bin/env python3
"""Read retained CI bytes and metadata; do not execute a verifier or prover."""

import hashlib
import json
import pathlib
import re
import subprocess
import zlib


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HEAD = "1d11f875493f8125e36b9adceacb342df108e5e5"
TREE = "64b82137eebeb96b572abc62e5fce39af3593200"
CASES = {
    "valid": (True, "verified"),
    "first-seal-tamper": (False, "verification_failed"),
    "last-seal-tamper": (False, "verification_failed"),
    "wrong-verifier-parameters": (False, "verification_failed"),
    "wrong-statement-miner": (False, "verification_failed"),
    "truncated-receipt": (False, "malformed_encoding"),
    "trailing-receipt-bytes": (False, "malformed_encoding"),
    "seal-length-allocation-bomb": (False, "refused_not_evaluated"),
}


def load(name):
    return json.loads((HERE / name).read_text())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_bytes(data, record):
    assert len(data) == record["bytes"]
    assert sha(data) == record["sha256"]


def main():
    recovery = load("recovery-binding.json")
    originals = load("original-files.json")["files"]
    assert len(originals) == len({r["path"] for r in originals}) == 57
    assert {p.name for p in (HERE / "original").iterdir()} == {
        pathlib.PurePosixPath(r["path"]).name for r in originals
    }
    for record in originals:
        assert pathlib.PurePosixPath(record["path"]).parts[0] == "original"
        assert len(pathlib.PurePosixPath(record["path"]).parts) == 2
        check_bytes((HERE / record["path"]).read_bytes(), record)

    before = load("original/source-before.json")
    assert before == load("original/source-after.json")
    assert before["tested_commit"] == before["candidate"] == HEAD
    assert before["tested_tree"] == TREE and before["tracked_worktree_verified"]
    assert (before["tracked_entries"], before["tracked_bytes"]) == (7435, 960706544)
    run = load("github-run.json")
    assert (run["id"], run["head_sha"], run["run_attempt"], run["conclusion"]) == (
        40988668868, HEAD, 1, "success"
    )
    jobs = load("github-jobs.json")["jobs"]
    assert len(jobs) == 1 and jobs[0]["id"] == 123845534943
    assert jobs[0]["conclusion"] == "success"
    assert all(s["conclusion"] == "success" for s in jobs[0]["steps"])
    artifacts = load("github-artifacts.json")["artifacts"]
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["id"] == 12947349925
    assert artifact["size_in_bytes"] == recovery["zip_bytes"] == 15912715
    assert artifact["digest"] == "sha256:" + recovery["zip_sha256"]
    assert recovery["zip_sha256"] == "8fc5e5d914ab2fa99b2b68388837c056fe4a347cc5636d3a12d7be3d96438131"
    assert artifact["workflow_run"]["head_sha"] == HEAD

    members = load("archive-members.json")["members"]
    assert len(members) == len({r["archive_member"] for r in members}) == 61
    assert sum(r["bytes"] for r in members) == 22289086
    indexed = {r["archive_member"]: r for r in members}
    for record in originals:
        prior = indexed[pathlib.PurePosixPath(record["path"]).name]
        assert (record["bytes"], record["sha256"]) == (prior["bytes"], prior["sha256"])

    fixture = load("original/fixture-binding.json")
    manifest_path = (HERE / recovery["fixture_manifest"]).resolve()
    assert sha(manifest_path.read_bytes()) == fixture["object_manifest_sha256"]
    manifest = json.loads(manifest_path.read_text())
    assert manifest["schema"] == "pon-w1-durable-gzip-objects-v2"
    chunk_count = 0
    for name, pin in fixture["assets"].items():
        asset = manifest["assets"][name]
        assert {k: asset[k] for k in ("bytes", "sha256")} == pin
        assert {k: indexed["fixture/" + name][k] for k in ("bytes", "sha256")} == pin
        whole = hashlib.sha256()
        length = 0
        for chunk in asset["object"]["chunks"]:
            data = (manifest_path.parent / chunk["file"]).read_bytes()
            check_bytes(data, chunk)
            whole.update(data)
            length += len(data)
            chunk_count += 1
        assert (length, whole.hexdigest()) == (asset["object"]["bytes"], asset["object"]["sha256"])
    assert chunk_count == fixture["chunks_verified"] == 4

    binary = recovery["verifier_gzip"]
    packed = (HERE / binary["path"]).read_bytes()
    check_bytes(packed, binary)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = decoder.decompress(packed, binary["raw_bytes"] + 1)
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert len(raw) == binary["raw_bytes"] == 5990744
    assert sha(raw) == binary["raw_sha256"] == indexed["verifier"]["sha256"]
    for name in ("verifier-before.sha256", "verifier-after.sha256"):
        assert (HERE / "original" / name).read_text().split()[0] == binary["raw_sha256"]

    processes = sorted((HERE / "original").glob("*.process.json"))
    assert len(processes) == 13
    for path in processes:
        process = json.loads(path.read_text())
        assert process["returncode"] == 0 and process["timed_out"] is False
        assert process["source_sha"] == HEAD
    audit = load("original/original-audit.stdout.log")
    assert audit["real_proof_positive_control"] is True
    assert len(audit["negative_cases"]) == 16
    assert all(c["rejected"] for c in audit["negative_cases"])

    cases = []
    source = None
    caps = None
    for name, expected in CASES.items():
        case = load("original/case-" + name + ".stdout.log")
        binding = load("original/case-" + name + ".binding.json")
        assert case["case"] == name.replace("-", "_") == binding["case"]
        assert (case["receiver"]["accepted"], case["receiver"]["outcome"]) == expected
        assert case["real_proof_positive_control"] and case["positive_prerequisite_warms_verifier"]
        assert binding["metadata_and_byte_bindings_pass"] and binding["source_files_checked"] == 15
        assert binding["receiver_total_wall_ns"] == case["receiver"]["receiver_total_wall_ns"]
        assert binding["proof_reverified_by_reader"] is False
        for key in ("consensus_authority", "minimum_work_cost_proved", "native_w1_recomputed",
                    "new_proof_generated", "pq_128_security_qualified", "public_ingress_qualified"):
            assert case[key] is False
        assert case["original_input"] == fixture["assets"]["input.bin"]
        assert case["original_receipt"] == fixture["assets"]["receipt.bin"]
        if source is None:
            source, caps = case["source_inputs"], case["resource_caps"]
        assert case["source_inputs"] == source and case["resource_caps"] == caps
        cases.append({"case": case["case"], "accepted": expected[0], "outcome": expected[1],
                      "receiver_ms": case["receiver"]["receiver_total_wall_ns"] / 1000000,
                      "positive_prerequisite_ms": case["positive_prerequisite_wall_ns"] / 1000000})
    assert len(source) == len({r["path"] for r in source}) == 15
    for record in source:
        data = subprocess.check_output(["git", "show", HEAD + ":" + record["path"]], cwd=ROOT)
        check_bytes(data, record)

    for filename, count in (("fixture-controls.log", 39), ("reader-controls.log", 15)):
        log = (HERE / "original" / filename).read_text()
        assert re.search(rf"Ran {count} tests in [\d.]+s\s+OK\s*$", log)
    assert "test result: ok. 17 passed; 0 failed" in (HERE / "original/host-tests.stdout.log").read_text()
    print(json.dumps({
        "schema": "pon-proof-ci-recovery-readback-v1", "execution_commit": HEAD, "execution_tree": TREE,
        "run_id": 40988668868, "job_id": 123845534943, "artifact_id": 12947349925,
        "conclusion": "success", "original_files_checked": 57, "source_before_equals_after": True,
        "source_inputs_checked_against_published_commit": 15, "process_records_checked": 13,
        "fixture_controls": 39, "reader_controls": 15, "host_tests": 17,
        "real_proof_positive": True, "original_negative_controls": 16,
        "durable_fixture_chunks_checked": 4, "ci_verifier_raw_sha256": binary["raw_sha256"],
        "cases": cases, "positive_prerequisite_warms_verifier": True,
        "receiver_scope": "bounded-preflight/sdk-decode/strict-verify/decoded-drop",
        "new_native_execution": False, "new_proof_generation": False, "proof_reverified_by_readback": False,
        "zip_digest_recomputed_by_readback": False, "reproducible_build_proved": False,
        "minimum_work_cost_proved": False, "public_ingress_qualified": False,
        "pq128_qualified": False, "prior_unpublished_72_file_snapshot_recreated": False,
    }, indent=2))


if __name__ == "__main__":
    main()
