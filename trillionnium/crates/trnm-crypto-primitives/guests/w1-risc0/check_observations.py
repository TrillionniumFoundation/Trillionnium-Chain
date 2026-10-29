#!/usr/bin/env python3
"""Check actual backend observations; never replace a failed or absent proof."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat


UNSUPPORTED_AUTHORITY_FLAGS = frozenset({
    "pq128_qualified", "pq_128_security_qualified", "public_ingress_qualified",
    "consensus_authority", "consensus_activation", "production_activation",
    "production_consensus_activation", "physical_quantum_oracle_measured",
    "quantum_cost_bound", "fake_receipts_allowed", "groth16_receipts_allowed",
    "remote_proving_allowed",
})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def scope_flags(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in UNSUPPORTED_AUTHORITY_FLAGS:
                require(item is False, "unsupported research authority " + key)
            scope_flags(item)
    elif isinstance(value, list):
        for item in value:
            scope_flags(item)


def decode_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key " + key)
            result[key] = value
        return result

    def constant(value):
        raise ValueError("noncanonical JSON constant " + value)

    def floating(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=constant,
                       parse_float=floating)
    scope_flags(value)
    return value


def load(path):
    return decode_json(path.read_text())


def bounded_raw(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= cap, "observation file type/limit")
        parts = []
        count = 0
        while True:
            piece = os.read(fd, min(65536, cap - count + 1))
            if not piece:
                break
            parts.append(piece)
            count += len(piece)
            require(count <= cap, "observation grew past limit")
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "observation changed during read")
        return b"".join(parts)
    finally:
        os.close(fd)


def validate_process_schema(name, process, out, require_proof_observer=False):
    require(type(process) is dict, "process object")
    namespace = process.get("schema")
    require(namespace == "pon-w1-actual-process-v1"
            or name == "prove" and namespace == "pon-w1-observed-process-v2",
            "unsupported process schema for " + name)
    if namespace == "pon-w1-actual-process-v1":
        legacy_fields = {"schema", "command", "started_utc", "finished_utc", "timeout_seconds", "source_sha",
                         "returncode", "timed_out", "wall_seconds", "user_cpu_seconds", "system_cpu_seconds",
                         "max_waited_descendant_rss_kib", "rss_scope", "consensus_authority"}
        require(legacy_fields <= set(process) <= legacy_fields | {"runner_error"},
                "legacy process field set cannot contain observer claims")
        require(not (name == "prove" and require_proof_observer), "explicit workflow requires proof observer v2")
        return  # Historical records retain their original waited-child scope.
    from proof_observer_v1 import PHASE_CAP, SAMPLE_CAP, STREAM_CAPS, phase_readback
    fields = {"schema", "command", "started_utc", "finished_utc", "timeout_seconds", "source_sha",
              "returncode", "timed_out", "wall_seconds", "user_cpu_seconds", "system_cpu_seconds",
              "max_waited_descendant_rss_kib", "rss_scope", "cpu_scope", "supplement",
              "supplement_sha256", "family_capture_complete", "complete_family_cpu_seconds",
              "consensus_authority"}
    require(set(process) == fields, "observed process fields")
    require(process["cpu_scope"] == "direct host wait4 only; adopted rows separate; total family unknown"
            and process["rss_scope"] == "direct host wait4, potentially including descendants it waited; not whole-family peak",
            "observed process CPU/RSS scope")
    require(process["family_capture_complete"] is False and process["complete_family_cpu_seconds"] is None,
            "unknown whole-family cost cannot be promoted")
    require(process["supplement"] == "prove.observer.json", "fixed observer supplement path")
    require(type(process["source_sha"]) is str and re.fullmatch(r"[0-9a-f]{40}", process["source_sha"]),
            "observed source commit shape")
    require(type(process["returncode"]) is int and type(process["timed_out"]) is bool
            and type(process["wall_seconds"]) in (int, float)
            and math.isfinite(process["wall_seconds"]) and process["wall_seconds"] >= 0,
            "observed result types")
    command = process["command"]
    require(type(command) is list and len(command) == 7 and all(type(arg) is str for arg in command)
            and Path(command[0]).name == "trnm-w1-risc0-host" and command[1] == "prove"
            and command[5] == "18" and type(process["timeout_seconds"]) is int
            and process["timeout_seconds"] == 5400, "observed original proof profile")
    for field in ("user_cpu_seconds", "system_cpu_seconds"):
        value = process[field]
        require(value is None or type(value) in (int, float) and math.isfinite(value) and value >= 0,
                "observed nullable CPU type")
    rss = process["max_waited_descendant_rss_kib"]
    require(rss is None or type(rss) is int and rss >= 0, "observed nullable RSS type")
    raw = bounded_raw(out / "prove.observer.json", 256 * 1024)
    require(hashlib.sha256(raw).hexdigest() == process["supplement_sha256"], "observer supplement hash")
    observed = decode_json(raw)
    require(type(observed) is dict and observed.get("schema") == "pon-w1-proof-process-observer-v1",
            "observer supplement namespace")
    for field in ("command", "source_sha", "started_utc", "finished_utc", "timeout_seconds",
                  "returncode", "timed_out", "wall_seconds"):
        require(type(observed.get(field)) is type(process[field]) and observed[field] == process[field],
                "observer process binding " + field)
    require(observed.get("family_capture_complete") is False and observed.get("complete_family_cpu_seconds") is None
            and observed.get("proof_qualification") is False and observed.get("consensus_authority") is False,
            "observer unsupported authority")
    require(observed.get("finite_cleanup_observed") is True and observed.get("failure") is None
            and observed.get("secondary_failures") == [], "observer failed or unfinished cleanup")
    require(observed.get("adoption_probe") == "ECHILD-observed-not-full-family-certification",
            "finite cleanup observation does not certify historical family")
    row = observed.get("direct_wait4")
    require(type(row) is dict and type(row.get("pid")) is int and row["pid"] > 0
            and row["pid"] == observed.get("leader_pid") and type(row.get("returncode")) is int
            and row["returncode"] == process["returncode"], "direct wait4 process binding")
    for destination, source in (("user_cpu_seconds", "user_cpu_seconds"),
                                ("system_cpu_seconds", "system_cpu_seconds"),
                                ("max_waited_descendant_rss_kib", "max_rss_kib")):
        require(type(row.get(source)) is type(process[destination]) and row[source] == process[destination],
                "direct wait4 cost binding")
    current_source = Path(__file__).with_name("proof_observer_v1.py").read_bytes()
    source_identity = observed.get("observer_source")
    require(type(source_identity) is dict
            and source_identity.get("sha256") == hashlib.sha256(current_source).hexdigest()
            and type(source_identity.get("bytes")) is int and source_identity["bytes"] == len(current_source),
            "observer source binding")
    for label in ("host", "backend"):
        before, after = observed.get(label + "_before"), observed.get(label + "_after")
        require(type(before) is dict and before == after and type(before.get("bytes")) is int
                and 0 < before["bytes"] <= 256 * 1024 * 1024
                and type(before.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", before["sha256"]),
                "held executable before/after binding " + label)
    require(observed.get("stream_limits") == STREAM_CAPS, "observer fixed stream limits")
    effective = list(command)
    effective[2] = str(Path(command[6]).parent / "prove.backend-shim.py")
    require(observed.get("effective_command") == effective, "exact backend shim substitution")
    shim_identity = observed.get("shim_source")
    require(type(shim_identity) is dict and shim_identity.get("sha256") == source_identity["sha256"]
            and type(shim_identity.get("bytes")) is int and shim_identity["bytes"] == len(current_source),
            "shim source identity")
    shim = bounded_raw(out / "prove.backend-shim.py", 256 * 1024)
    require(shim == current_source, "retained shim differs from observer source")
    streams = observed.get("streams")
    require(type(streams) is dict and set(streams) == set(STREAM_CAPS), "observer stream set")
    for stream, cap in STREAM_CAPS.items():
        item = streams[stream]
        require(type(item) is dict and type(item.get("bytes")) is int and 0 <= item["bytes"] <= cap
                and item.get("truncated") is False, "observer stream shape or truncation")
        raw = bounded_raw(out / ("prove." + stream + ".log"), cap)
        require(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item.get("sha256"),
                "observer stream raw binding")
    sample = observed.get("samples")
    require(type(sample) is dict and type(sample.get("count")) is int and 0 < sample["count"] <= 1082
            and type(sample.get("bytes")) is int and 0 <= sample["bytes"] <= SAMPLE_CAP,
            "observer sample bound")
    raw = bounded_raw(out / "prove.process-samples.jsonl", SAMPLE_CAP)
    require(len(raw) == sample["bytes"] and hashlib.sha256(raw).hexdigest() == sample.get("sha256"),
            "observer sample raw binding")
    lines = raw.splitlines(keepends=True)
    require(len(lines) == sample["count"] and all(len(line) <= 65536 and line.endswith(b"\n") for line in lines),
            "observer sample line bound")
    for line in lines:
        value = decode_json(line)
        require(type(value) is dict and value.get("schema") == "pon-w1-process-sample-v1"
                and value.get("historical_family_complete") is False, "sample observation scope")
    bounded_raw(out / "prove.host-phases.jsonl", PHASE_CAP)
    actual = phase_readback(out / "prove.host-phases.jsonl", observed["leader_pid"])
    require(actual["complete"] is True and actual == observed.get("host_phases"),
            "complete original host phase stream binding")


def validate_manifest(observed):
    # The same source manifest is compiled into the native host and read by the
    # installer/build driver. The artifact copy is not an independent authority
    # for its image, algorithm, security parameters or source/compiler hashes.
    pinned = load(Path(__file__).with_name("backend-manifest.json"))
    require(type(observed) is dict, "backend manifest must be an object")
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    # JSON encoding retains false versus 0 and integers versus floats, unlike
    # Python container equality. Formatting and object-key order are immaterial.
    require(canonical(observed) == canonical(pinned),
            "backend manifest differs from checker source")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--require-proof-observer", action="store_true",
                        help="this workflow's prove record must use the explicitly bound v2 observer")
    args = parser.parse_args()
    out = args.out
    manifest = load(out / "backend-manifest.json")
    validate_manifest(manifest)
    for filename, key in [("guest.raw.elf", "guest_raw_elf_sha256"),
                          ("guest.bin", "guest_program_sha256")]:
        actual = hashlib.sha256((out / filename).read_bytes()).hexdigest()
        require(actual == manifest[key], f"unreviewed or non-reproducible {filename}: {actual}")
    bake = load(out / "bake.stdout.log")
    require(bake["image_id"] == manifest["guest_image_id"], "unreviewed actual guest image")
    require((out / "input.bin").stat().st_size == 49640, "incorrect fixed W1 input length")
    if args.build_only:
        print(json.dumps({"build_identity_checked": True, "proof_checked": False}))
        return
    observations = {name: load(out / f"{name}.stdout.log")
                    for name in ["native-execute", "execute", "prove", "verify", "audit"]}
    processes = {name: load(out / f"{name}.process.json") for name in observations}
    for name, process in processes.items():
        validate_process_schema(name, process, out, args.require_proof_observer)
        require(type(process["returncode"]) is int and process["returncode"] == 0
                and process["timed_out"] is False, f"failed actual {name}")
    native, executed, proved, verified, audited = (observations[name] for name in observations)
    require(executed["guest_matches_native"] is True, "guest/native execution mismatch")
    require(executed["image_id"] == manifest["guest_image_id"], "execution image mismatch")
    require(native["journal_hex"] == executed["journal_hex"], "actual guest journal differs from M01 native oracle")
    for value in [proved, verified]:
        require(value["real_composite_stark_verified"] is True, "missing real proof verification")
        require(value["image_id"] == manifest["guest_image_id"], "proof image mismatch")
        require(value["statement_id"] == native["statement_id"], "proof statement mismatch")
    require(verified["native_w1_recomputed"] is False, "verifier silently recomputed W1")
    require(audited["real_proof_positive_control"] is True, "adversarial tests lack real positive proof")
    expected_cases = {"wrong_image", "wrong_statement_miner", "truncated_receipt",
                      "first_seal_tamper", "last_seal_tamper", "wrong_hash_profile",
                      "wrong_verifier_parameters", "fake_receipt_refused", "groth16_kind_refused",
                      "segment_count_allocation_bomb", "seal_length_allocation_bomb",
                      "empty_seal_before_sdk", "outer_journal_allocation_bomb",
                      "nested_assumptions_refused", "seal_dimension_budget", "trailing_receipt_bytes"}
    cases = audited["negative_cases"]
    require({case["case"] for case in cases} == expected_cases, "missing or duplicate negative controls")
    require(len(cases) == len(expected_cases) and all(case["rejected"] is True for case in cases), "accepted adversarial control")
    receipt = out / "receipt.bin"
    require(receipt.stat().st_size == proved["receipt_bytes"] == verified["receipt_bytes"], "proof byte count mismatch")
    result = {"schema": "pon-complete-w1-actual-proof-observation-v1",
              "backend_manifest": manifest, "observations": observations,
              "processes": processes, "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
              "full_work_profile_preserved": True, "real_proof_verified": True,
              "maximum_tested_reject_wall_ns": max(case["reject_wall_ns"] for case in cases),
              "native_complete_replay_wall_ns": native["elapsed_wall_ns"],
              "public_ingress_qualified": False, "pq128_qualified": False,
              "consensus_activation": False,
              "limits": ["one research fixture and finite adversarial controls",
                         "98-bit classical conjectured backend claim, not a quantum-bit estimate",
                         "quantum Fiat-Shamir, Poseidon2, Merkle, FRI and multi-target analysis remain separate",
                         "CPU/wall samples under this runner load are observations, not throughput or service guarantees"]}
    (out / "checked-observation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"real_proof_verified": True, "negative_controls": len(cases),
                      "public_ingress_qualified": False, "pq128_qualified": False}))


if __name__ == "__main__":
    main()
