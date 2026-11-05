#!/usr/bin/env python3
"""Execute and independently check the fixed native W1 cache lifecycle campaign.

This reuses the original native verifiers. The report covers component CPU and
actual cache paths; it grants no Node service, fairness, hardness or RSS verdict.
Every failed command and the original raw stream remain in the output directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import ci_observation as ci
from run_cross_arch_cost import (build_environment_overrides,
    cargo_configuration_snapshot, require_cargo_configuration)

ROOT = ci.ROOT
SCHEMA = "pon-work-expensive-verifier-v1"
EXAMPLE = "pon_work_expensive_verifier_v1"
SELECTOR = "--work-expensive-verifier-v1"
SCENARIOS = (
    "distinct-material-cold", "exact-retransmission", "same-input-new-forgeries",
    "new-challenge", "one-slot-eviction", "owner-restart", "negative-ttl-expiry",
    "legal-cold-warm", "cheap-malformed",
)
PATHS = ("native-raw", "negative-cache", "arithmetic-facts")
SAMPLES, LIMIT, CELLS = 8, 4096, 4096
PROOF_BYTES = 4 + 3 * CELLS * 4 + 32
TARGET = bytes([127]) + bytes([255]) * 31
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value, name="integer"):
    require(type(value) is int and 0 <= value < 1 << 64, name)
    return value


def timing(value):
    require(type(value) is dict and set(value) == {"cpu_ns", "wall_ns"}, "timing fields")
    for key in value:
        integer(value[key], "known integer " + key)
    return value["cpu_ns"]


def hex_bytes(value, length=None):
    require(type(value) is str and len(value) % 2 == 0 and
            all(c in "0123456789abcdef" for c in value), "canonical hex")
    if length is not None:
        require(len(value) == length * 2, "hex width")
    return bytes.fromhex(value)


def H(tag, *parts):
    if isinstance(tag, str):
        tag = tag.encode()
    raw = b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
    for part in parts:
        raw += struct.pack("<I", len(part)) + part
    return hashlib.sha256(raw).digest()


def challenge(scenario, index):
    return H("work-expensive-verifier-challenge-v1", scenario.encode(), struct.pack("<Q", index))


def material(index):
    a = [(i * 17 + index * 13) % 251 for i in range(CELLS)]
    b = [(i * 29 + index * 31) % 241 for i in range(CELLS)]
    a[0] = index
    a, b = struct.pack("<4096I", *a), struct.pack("<4096I", *b)
    return H("task", a, b), b"PNW1" + a + b + bytes(CELLS * 4 + 32)


def no_duplicates(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_records(path):
    require(path.is_file() and not path.is_symlink(), "regular native log required")
    with path.open("rb") as stream:
        raw = stream.read(MAX_LOG_BYTES + 1)
    require(len(raw) <= MAX_LOG_BYTES, "native log byte limit")
    lines = raw.splitlines()
    require(1 <= len(lines) <= 1000, "native row limit")
    require(all(0 < len(line) <= MAX_LINE_BYTES for line in lines), "native row byte limit")
    rows = [json.loads(line, object_pairs_hook=no_duplicates,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON nonfinite")))
            for line in lines]
    return rows, hashlib.sha256(raw).hexdigest()


def expected_outcome(scenario, index):
    if scenario == "legal-cold-warm":
        return "Accepted"
    if scenario == "cheap-malformed":
        return ("Length", "Version", "Target", "Field", "Field", "Field", "Task", "Target")[index]
    return "Transcript"


def expected_tiles(scenario, index, path):
    if scenario == "cheap-malformed":
        return 0
    if path == "native-raw":
        return 512
    if scenario == "owner-restart":
        return 512 if index % 2 == 0 else 0
    if scenario == "exact-retransmission":
        return 512 if index == 0 else 0
    if path == "arithmetic-facts" and scenario in (
            "same-input-new-forgeries", "negative-ttl-expiry", "legal-cold-warm"):
        return 512 if index == 0 else 0
    return 512


def validate_candidate(row, earlier):
    scenario, index = row["scenario"], integer(row["index"])
    require(scenario in SCENARIOS and index < SAMPLES, "candidate grid")
    expected_material = index if scenario == "distinct-material-cold" else index % 2 if scenario == "one-slot-eviction" else 0
    require(integer(row.get("material_index")) == expected_material, "candidate material identity")
    require(integer(row.get("challenge_index")) == (index if scenario == "new-challenge" else 0),
            "candidate challenge index")
    expected_task, prefix = material(expected_material)
    task = hex_bytes(row.get("task"), 32)
    context = hex_bytes(row.get("challenge"), 32)
    target = hex_bytes(row.get("target"), 32)
    proof = hex_bytes(row.get("proof_hex"))
    require(len(proof) <= PROOF_BYTES, "candidate proof byte limit")
    require(hashlib.sha256(proof).hexdigest() == row.get("proof_sha256"), "candidate proof digest")
    require(integer(row.get("trial_limit")) == LIMIT, "fixed search budget")
    require(row.get("expected_outcome") == expected_outcome(scenario, index), "candidate expected outcome")
    trials = row.get("trials")
    require(type(trials) is list and len(trials) <= LIMIT, "bounded complete trial stream")
    repeat = (scenario in ("exact-retransmission", "owner-restart", "negative-ttl-expiry", "legal-cold-warm") and index > 0) or (scenario == "one-slot-eviction" and index >= 2)
    if repeat:
        repeated_index = index % 2 if scenario == "one-slot-eviction" else 0
        prior = earlier[(scenario, repeated_index)]
        require(row.get("method") == "exact-byte-reuse" and integer(row.get("repeat_of")) == repeated_index
                and trials == [], "exact reuse has no invented new search")
        require(all(row.get(key) == prior[key] for key in
                    ("challenge", "task", "target", "proof_hex", "proof_sha256", "expected_outcome")),
                "exact reuse preserves entire statement")
    else:
        require(row.get("repeat_of") is None, "no undeclared reuse")
        if scenario == "cheap-malformed":
            require(row.get("method") == "malformed-encoding" and trials == [], "malformed preparation")
            expected = bytearray(prefix)
            expected_target = TARGET
            if index == 0:
                expected.pop()
            elif index == 1:
                expected[0] = ord("X")
            elif index == 2:
                expected_target = bytes(32)
            elif index <= 5:
                struct.pack_into("<I", expected, 4 + (index - 3) * CELLS * 4, 4294967291)
            elif index == 6:
                expected_task = bytes([expected_task[0] ^ 1]) + expected_task[1:]
            else:
                expected_target = bytes(31) + b"\1"
            require(proof == expected and target == expected_target, "exact malformed bytes/target")
        else:
            method = "legal-native-prove" if scenario == "legal-cold-warm" else "from-zero"
            require(row.get("method") == method and len(trials) > 0 and target == TARGET,
                    "complete successful fixed search")
            for ordinal, trial in enumerate(trials):
                require(type(trial) is dict and set(trial) ==
                        {"nonce", "challenge", "trace", "ticket", "target_hit"}, "trial fields")
                nonce = integer(trial["nonce"])
                require(nonce == index * LIMIT + ordinal, "missing or reordered losing trial")
                trial_context = challenge(scenario, nonce if method == "legal-native-prove"
                                          else index if scenario == "new-challenge" else 0)
                require(hex_bytes(trial["challenge"], 32) == trial_context, "trial challenge")
                trace = hex_bytes(trial["trace"], 32)
                if method == "from-zero":
                    require(trace == H("public-v3-from-zero-v1", trial_context, struct.pack("<Q", nonce)),
                            "actual from-zero trial")
                ticket = H("ticket", trial_context, trace)
                hit = ticket <= target
                require(hex_bytes(trial["ticket"], 32) == ticket and trial["target_hit"] is hit
                        and hit is (ordinal == len(trials) - 1), "all losers and first winner")
            require(context == hex_bytes(trials[-1]["challenge"], 32) and
                    proof[-32:] == hex_bytes(trials[-1]["trace"], 32), "winner statement binding")
            if method == "from-zero":
                require(proof[:-32] == prefix[:-32], "uncomputed from-zero prefix")
            else:
                require(len(proof) == PROOF_BYTES and proof[:4 + 2 * CELLS * 4] == prefix[:4 + 2 * CELLS * 4],
                        "legal proof material")
        require(task == expected_task, "expected current task")
        if scenario != "legal-cold-warm":
            require(context == challenge(scenario, index if scenario == "new-challenge" else 0),
                    "context identity")
    timing(row.get("timing"))
    timing(row.get("operation_timing"))
    require(all(row["operation_timing"][key] <= row["timing"][key]
                for key in ("cpu_ns", "wall_ns")), "operation is nested inside total construction")
    return row


def analyze_rows(rows):
    require(all(type(row) is dict and row.get("schema") == SCHEMA for row in rows), "explicit native schema")
    require(rows[0].get("kind") == "header" and rows[-1].get("kind") == "footer", "complete stream endpoints")
    header, footer = rows[0], rows[-1]
    for key in ("samples", "proof_bytes"):
        integer(header.get(key), "header integer " + key)
    for key in ("scenarios_completed", "candidates_completed", "verifications_completed"):
        integer(footer.get(key), "footer integer " + key)
    require(header.get("scenarios") == list(SCENARIOS) and header.get("paths") == list(PATHS)
            and header.get("samples") == SAMPLES and header.get("proof_bytes") == PROOF_BYTES
            and header.get("profile") == "pon-matmul-transcript-64-v1", "fixed campaign plan")
    require(header.get("native_component_execution") is True and header.get("synthetic_public_material") is True,
            "explicit component/material scope")
    require(all(header.get(key) is False for key in ("node_runtime_measured", "resource_fairness_qualified",
                "work_hardness_qualified", "production_activation")), "no scope promotion")
    candidates, prepared, verified, owners, waits = {}, {}, {}, {}, {}
    for row in rows[1:-1]:
        kind, scenario = row.get("kind"), row.get("scenario")
        require(scenario in SCENARIOS, "known scenario")
        if kind == "preparation":
            require(scenario not in prepared, "one actual preparation")
            integer(row.get("material_count"), "material count")
            count = SAMPLES if scenario == "distinct-material-cold" else 2 if scenario == "one-slot-eviction" else 1
            require(row.get("material_count") == count and row.get("tasks") ==
                    [material(i)[0].hex() for i in range(count)], "preparation material inventory")
            timing(row.get("timing"))
            prepared[scenario] = row
        elif kind == "candidate":
            require(scenario in prepared, "preparation before search")
            key = scenario, integer(row.get("index"))
            require(key not in candidates and key[1] == sum(s == scenario for s, _ in candidates),
                    "complete ordered candidates")
            candidates[key] = validate_candidate(row, candidates)
        elif kind == "owner":
            epoch = integer(row.get("epoch"))
            integer(row.get("capacity"), "owner capacity")
            integer(row.get("negative_ttl_ms"), "owner ttl")
            key = scenario, epoch
            require(key not in owners and epoch == sum(s == scenario for s, _ in owners), "actual ordered owner epochs")
            require(row.get("capacity") == (1 if scenario == "one-slot-eviction" else 64)
                    and row.get("negative_ttl_ms") == (5 if scenario == "negative-ttl-expiry" else 30000),
                    "fixed cache settings")
            require(0 < integer(row.get("arithmetic_software_bytes")) <= 4 * 1024 * 1024, "software storage bound")
            timing(row.get("negative_setup")); timing(row.get("arithmetic_setup"))
            owners[key] = row
        elif kind == "lifecycle-wait":
            index = integer(row.get("index"))
            key = scenario, index
            require(scenario == "negative-ttl-expiry" and 0 < index < SAMPLES and key not in waits
                    and row.get("reason") == "expire-negative-cache", "fixed expiry waits")
            timing(row.get("timing"))
            require(row["timing"]["wall_ns"] >= 20_000_000, "actual expiry interval")
            waits[key] = row
        elif kind == "verification":
            index, path = integer(row.get("index")), row.get("path")
            for key in ("epoch", "capacity", "tiles", "before_replay", "before_product", "before_verified", "owner_age_wall_ns"):
                integer(row.get(key), "verification integer " + key)
            key = scenario, index, path
            epoch = index // 2 if scenario == "owner-restart" else 0
            require((scenario, index) in candidates and (scenario, epoch) in owners and key not in verified
                    and path in PATHS, "one verification per actual candidate/path/owner")
            require(row.get("epoch") == epoch and row.get("capacity") == owners[(scenario, epoch)]["capacity"],
                    "verification owner identity")
            require(row.get("outcome") == expected_outcome(scenario, index), "native verifier disagreement")
            require(row.get("tiles") == expected_tiles(scenario, index, path), "actual replay/reuse path")
            require(row.get("before_replay") == (0 if scenario == "cheap-malformed" else 1)
                    and row.get("before_product") == (1 if scenario == "legal-cold-warm" else 0)
                    and row.get("before_verified") == (1 if scenario == "legal-cold-warm" else 0), "native checkpoints")
            if path == "arithmetic-facts":
                observation = row.get("arithmetic")
                require(type(observation) is dict, "actual arithmetic observations")
                full = row["tiles"] == 512
                reused = not full and scenario != "cheap-malformed"
                require(observation.get("transcript_entered") is full and observation.get("transcript_completed") is full
                        and observation.get("trace_reused") is reused
                        and observation.get("exact_fact_found") is reused
                        and observation.get("product_reused") is (reused and scenario == "legal-cold-warm"), "arithmetic path consistency")
                require(integer(observation.get("lookup_probes")) <= row["capacity"]
                        and integer(observation.get("publication_probes")) <= row["capacity"], "bounded cache probes")
            else:
                require(row.get("arithmetic") is None, "no invented raw arithmetic observation")
            if scenario == "negative-ttl-expiry" and index > 0:
                require((scenario, index) in waits, "expiry precedes verification")
            timing(row.get("timing"))
            verified[key] = row
        else:
            raise ValueError("unrecognized or exhausted native row")
    require(len(prepared) == len(SCENARIOS) and len(candidates) == len(SCENARIOS) * SAMPLES
            and len(verified) == len(SCENARIOS) * SAMPLES * len(PATHS)
            and len(owners) == len(SCENARIOS) + SAMPLES // 2 - 1 and len(waits) == SAMPLES - 1,
            "complete declared grid including resets/expiry")
    require(footer.get("scenarios_completed") == len(SCENARIOS) and
            footer.get("candidates_completed") == len(candidates) and
            footer.get("verifications_completed") == len(verified) and
            footer.get("all_expected_outcomes") is True, "native footer reconciliation")
    timing(footer.get("total_including_diagnostics"))
    summary = []
    for scenario in SCENARIOS:
        selected = [candidates[(scenario, i)] for i in range(SAMPLES)]
        setup = prepared[scenario]["timing"]["cpu_ns"]
        construction = sum(row["operation_timing"]["cpu_ns"] for row in selected)
        including_diagnostics = sum(row["timing"]["cpu_ns"] for row in selected)
        total = setup + construction
        path_records = {}
        for path in PATHS:
            cpu = sum(verified[(scenario, i, path)]["timing"]["cpu_ns"] for i in range(SAMPLES))
            setup_key = "negative_setup" if path == "negative-cache" else "arithmetic_setup"
            receiver_setup = 0 if path == "native-raw" else sum(row[setup_key]["cpu_ns"] for (s, _), row in owners.items() if s == scenario)
            path_records[path] = {"verification_cpu_ns": cpu, "cache_setup_cpu_ns": receiver_setup,
                "total_transcript_tiles": sum(verified[(scenario, i, path)]["tiles"] for i in range(SAMPLES)),
                "actual_arithmetic_reuses": sum(verified[(scenario, i, path)]["tiles"] == 0 and scenario != "cheap-malformed" for i in range(SAMPLES)),
                "observed_owner_lifetime_ns": {str(epoch): max(row["owner_age_wall_ns"] for (s, _, p), row in verified.items()
                    if s == scenario and p == path and row["epoch"] == epoch) for (s, epoch) in owners if s == scenario},
                "verifier_to_full_construction_cpu_ratio": cpu / total if total else None,
                "verifier_to_diagnostic_inclusive_construction_cpu_ratio": cpu / (setup + including_diagnostics) if setup + including_diagnostics else None,
                "including_cache_setup_ratio": (cpu + receiver_setup) / total if total else None}
        summary.append({"scenario": scenario, "submitted_candidates": SAMPLES,
            "completed_search_trials": sum(len(row["trials"]) for row in selected),
            "completed_losing_trials": sum(sum(not t["target_hit"] for t in row["trials"]) for row in selected),
            "exact_byte_reuses": sum(row["method"] == "exact-byte-reuse" for row in selected),
            "preparation_cpu_ns": setup, "all_construction_cpu_ns": construction,
            "full_construction_cpu_ns": total,
            "construction_diagnostic_overhead_cpu_ns": including_diagnostics - construction,
            "full_construction_with_diagnostics_cpu_ns": setup + including_diagnostics,
            "paths": path_records})
    return {"schema": SCHEMA + "-checked-report", "record_consistency": "PASS", "scenarios": summary,
        "native_component_records": len(verified), "consensus_accepted_work": None,
        "node_runtime_measured": False, "resource_fairness_qualified": False,
        "work_hardness_qualified": False, "production_activation": False,
        "limits": ["Synthetic public fixtures; actual Hepta routing/model semantics are not exercised.",
                   "Operation construction CPU includes all trial/search bookkeeping and proof clones; proof hex/hash diagnostics have a separate nested total. Neither is an attacker cost lower bound.",
                   "Receiver setup is explicit; software cache bytes are not process RSS or host isolation.",
                   "Ratios compare all actual fixed-stream construction with one verifier path; no winner-only denominator.",
                   "The reader checks records, bytes and chronology, not independent native execution or machine CPU truth."]}


def analyze(path):
    rows, digest = load_records(path)
    result = analyze_rows(rows)
    result["native_log_sha256"] = digest
    return result


def source_inputs():
    paths = sorted(p for p in (ROOT / "trillionnium").rglob("*") if p.is_file() and
                   (p.suffix == ".rs" or p.name in {"Cargo.toml", "Cargo.lock", "config.toml", "rust-toolchain.toml"}))
    paths += [p for p in (ROOT / "rust-toolchain.toml", ROOT / ".cargo/config.toml") if p.is_file()]
    paths += [Path(__file__).resolve()]
    return {str(p.relative_to(ROOT)): ci.digest(p) for p in paths}


def run(output):
    require(output.is_absolute() and output.resolve() == output and not output.is_relative_to(ROOT),
            "new canonical output directory outside checkout")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA + "-execution", "result": "FAIL", "commands": [],
              "source_inputs_before": source_inputs(), "native_component_executed": False,
              "node_runtime_measured": False, "resource_fairness_qualified": False,
              "work_hardness_qualified": False, "production_activation": False}
    def save():
        (output / "execution.json").write_text(json.dumps(report, indent=2) + "\n")
    def execute(command, name, timeout):
        observed = ci.run(command, output / name, timeout=timeout)
        report["commands"].append(observed)
        save()
        require(observed["exit_code"] == 0 and observed["process_exit_code"] == 0
                and observed["timed_out"] is False and observed["executed"] is True, name + " failed")
    save()
    try:
        report["build_environment_overrides"] = build_environment_overrides(dict(os.environ))
        require(not report["build_environment_overrides"], "original release configuration forbids overrides")
        report["cargo_configuration_before"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
        require_cargo_configuration(report["cargo_configuration_before"])
        execute(["rustc", "-vV"], "rustc.log", 30)
        require("\nrelease: 1.95.0\n" in (output / "rustc.log").read_text(), "original Rust 1.95.0 required")
        execute(["cargo", "build", "--offline", "--locked", "--release", "--manifest-path",
                 "trillionnium/Cargo.toml", "-p", "trnm-crypto-primitives", "--example", EXAMPLE,
                 "--jobs", "2", "--message-format=json"], "build.log", 900)
        binaries = []
        for line in (output / "build.log").read_text().splitlines():
            if line.startswith("{"):
                row = json.loads(line)
                if row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == EXAMPLE:
                    require(row.get("target", {}).get("kind") == ["example"] and row.get("executable"),
                            "actual example artifact")
                    binaries.append(Path(row["executable"]))
        require(len(binaries) == 1, "one actual compiled binary")
        binary = binaries[0]
        report["binary_sha256_before"] = ci.digest(binary)
        execute([str(binary), SELECTOR], "native.jsonl", 180)
        report["native_component_executed"] = True
        report["reader"] = analyze(output / "native.jsonl")
        report["binary_sha256_after"] = ci.digest(binary)
        require(report["binary_sha256_before"] == report["binary_sha256_after"], "binary changed")
        report["result"] = "PASS"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
    finally:
        report["source_inputs_after"] = source_inputs()
        try:
            report["cargo_configuration_after"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
            require_cargo_configuration(report["cargo_configuration_after"])
            require(report["cargo_configuration_before"] == report["cargo_configuration_after"],
                    "Cargo configuration changed")
        except (OSError, ValueError, KeyError) as error:
            report["result"] = "FAIL"
            report["configuration_failure"] = str(error)
        if report["source_inputs_before"] != report["source_inputs_after"]:
            report["result"] = "FAIL"
            report["source_changed"] = True
        report["logs"] = {p.name: ci.digest(p) for p in sorted(output.iterdir())
                          if p.is_file() and p.name != "execution.json"}
        save()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--out", type=Path)
    modes.add_argument("--read", type=Path)
    args = parser.parse_args()
    if args.read:
        print(json.dumps(analyze(args.read), indent=2))
    else:
        result = run(args.out)
        print(json.dumps({"result": result["result"], "failure": result.get("failure")}))
        raise SystemExit(0 if result["result"] == "PASS" else 1)
