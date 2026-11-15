#!/usr/bin/env python3
"""Execute/read the finite native from-zero filter cost experiment.

The reader checks byte identities, the complete first-hit stream and stage order.
It does not authenticate execution or prove a work-cost lower bound. The runner
requires a clean fixed commit and retains failed commands and incomplete streams.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys

import ci_observation as ci
from pq_source_reader import read_regular
from run_cross_arch_cost import (build_environment_overrides,
    cargo_configuration_snapshot, require_cargo_configuration)

sys.path.insert(0, str(ci.ROOT / "scripts"))
import pon_w1_cost_matrix_reader as material_reader

ROOT = ci.ROOT
SCHEMA = "pon-from-zero-filter-cost-v1"
SELECTOR = "--from-zero-filter-cost-v1"
EXAMPLE = "pon_from_zero_filter_cost_v1"
CLASSES = ("zero", "full-rank-field")
BITS = (1, 4, 8)
SAMPLES, LIMIT, CELLS, PROOF_BYTES = 8, 4096, 4096, 49188
PATHS = ("precheck", "raw-first", "raw-repeat", "arithmetic-cold",
         "arithmetic-hot", "scalar-reference")
MAX_BYTES, MAX_LINE_BYTES = 64 * 1024 * 1024, 2 * 1024 * 1024
FALSE_FLAGS = {"native_header_admission": False, "node_service_measured": False,
               "work_cost_lower_bound_proved": False, "production_activation": False}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, fields, label):
    require(type(value) is dict and set(value) == set(fields), label + " fields")
    return value


def integer(value, label):
    require(type(value) is int and 0 <= value < 1 << 64, label + " integer")
    return value


def timing(value):
    exact(value, ("cpu_ns", "wall_ns"), "timing")
    for key, entry in value.items():
        integer(entry, key)
    return value


def canonical_hex(value, width):
    require(type(value) is str and len(value) == width * 2 and
            all(char in "0123456789abcdef" for char in value), "canonical hex")
    return bytes.fromhex(value)


def target(bits):
    return bytes([255 >> bits]) + bytes([255]) * 31


def context(task, sample, bits, nonce):
    return material_reader.pon_hash(b"pon-from-zero-filter-challenge-v1", task,
        struct.pack("<Q", sample), bytes([bits]), struct.pack("<Q", nonce))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def reject_number(_):
    raise ValueError("inexact/nonfinite JSON number")


def load_records(path):
    path = Path(path).absolute()
    raw = read_regular(Path("/"), str(path).removeprefix("/"), MAX_BYTES)
    lines = raw.splitlines()
    require(1 <= len(lines) <= 1100 and all(0 < len(line) <= MAX_LINE_BYTES for line in lines),
            "bounded native rows")
    rows = [json.loads(line, object_pairs_hook=unique_object,
                      parse_float=reject_number, parse_constant=reject_number) for line in lines]
    return rows, hashlib.sha256(raw).hexdigest()


def check_key(value, expected):
    exact(value, ("class", "bits", "sample", "arm"), "sample key")
    integer(value["bits"], "bits"); integer(value["sample"], "sample")
    require(value == expected, "fixed sample identity/order")


def check_construction(row, key, task, prefix):
    check_key(row["key"], key)
    for name in ("setup", "search"):
        timing(row[name])
    limit = target(key["bits"])
    require(canonical_hex(row["target"], 32) == limit, "exact target")
    require(row["status"] == "target-hit", "exhausted or unfinished search")
    trials = row["trials"]
    require(type(trials) is list and 0 < len(trials) <= LIMIT, "complete trial stream")
    for nonce, trial in enumerate(trials):
        exact(trial, ("nonce", "challenge", "trace", "ticket", "target_hit"), "trial")
        require(integer(trial["nonce"], "nonce") == nonce, "omitted/reordered losing trial")
        challenge = context(task, key["sample"], key["bits"], nonce if key["arm"] == "legal" else 0)
        require(canonical_hex(trial["challenge"], 32) == challenge, "trial context")
        trace = canonical_hex(trial["trace"], 32)
        if key["arm"] == "from-zero":
            require(trace == material_reader.pon_hash(b"public-v3-from-zero-v1", challenge,
                    struct.pack("<Q", nonce)), "from-zero trace recipe")
        ticket = material_reader.pon_hash(b"ticket", challenge, trace)
        hit = ticket <= limit
        require(canonical_hex(trial["ticket"], 32) == ticket and trial["target_hit"] is hit
                and hit is (nonce == len(trials) - 1), "first hit and all prior misses")
    winner = exact(row["winner"], ("challenge", "proof_hex", "proof_sha256"), "winner")
    proof = canonical_hex(winner["proof_hex"], PROOF_BYTES)
    require(hashlib.sha256(proof).hexdigest() == winner["proof_sha256"], "proof digest")
    require(winner["challenge"] == trials[-1]["challenge"] and
            proof[-32:] == canonical_hex(trials[-1]["trace"], 32), "winner/trial binding")
    expected_prefix = prefix if key["arm"] == "legal" else prefix[:4 + 8 * CELLS] + bytes(4 * CELLS)
    require(proof[:-32] == expected_prefix, "exact public inputs/product prefix")
    return len(trials)


def ratio(numerator, denominator):
    return {"numerator_cpu_ns": numerator, "denominator_cpu_ns": denominator,
            "ratio": numerator / denominator if denominator else None}


def analyze_rows(rows):
    require(type(rows) is list and bool(rows), "nonempty records")
    position = 0
    interval_totals = {"cpu_ns": 0, "wall_ns": 0}

    def account(value):
        timing(value)
        for axis in interval_totals:
            interval_totals[axis] += value[axis]
        return value

    def take(kind, fields):
        nonlocal position
        require(position < len(rows), "incomplete native stream")
        row = rows[position]
        position += 1
        exact(row, {"schema", "kind", *fields}, kind)
        require(row["schema"] == SCHEMA and row["kind"] == kind, "native event order/schema")
        return row

    expected_header = {"selector": SELECTOR, "profile": "pon-matmul-transcript-64-v1",
        "classes": list(CLASSES), "target_leading_zero_bits": list(BITS),
        "samples": SAMPLES, "attempt_limit": LIMIT, "paths": list(PATHS),
        "proof_bytes": PROOF_BYTES, "legal_producer": "full-limb-dense-preparation-lazy-winner",
        "algorithm_timing_scope": "all-attempts-binary-bookkeeping-no-json-no-hex-no-output",
        "precheck_is_separate_invocation": True, "synthetic_material": True, **FALSE_FLAGS}
    header = take("header", expected_header)
    require(all(type(header[key]) is type(value) and header[key] == value
                for key, value in expected_header.items()), "exact native plan")
    require(all(type(value) is int for value in header["target_leading_zero_bits"]),
            "integer target bit plan")
    fixtures = take("fixtures", ("timing", "generated_classes", "retained_classes", "scope"))
    account(fixtures["timing"])
    require(integer(fixtures["generated_classes"], "generated classes") == 7 and
            fixtures["retained_classes"] == list(CLASSES) and
            fixtures["scope"] == "all-existing-public-diagnostic-recipes", "fixture scope")
    summaries, constructions, verifications = [], 0, 0
    material_cpu = 0
    for name in CLASSES:
        _, _, task, prefix = material_reader.material(name)
        material = take("material", ("class", "source", "task", "timing"))
        require(material["class"] == name and material["task"] == task.hex() and
                material["source"] == ("synthetic-fixture" if name == "zero" else "hash-generated-rank-checked"),
                "exact public material")
        material_cpu += account(material["timing"])["cpu_ns"]
        for bits in BITS:
            aggregate = {arm: {"setup_cpu_ns": 0, "search_cpu_ns": 0, "all_trials": 0,
                "receiver_setup_cpu_ns": 0, "stages_cpu_ns": dict.fromkeys(PATHS, 0)}
                for arm in ("from-zero", "legal")}
            for sample in range(SAMPLES):
                arms = ("from-zero", "legal") if sample % 2 == 0 else ("legal", "from-zero")
                for arm in arms:
                    key = dict(zip(("class", "bits", "sample", "arm"), (name, bits, sample, arm)))
                    start = take("sample-start", ("key", "target"))
                    check_key(start["key"], key)
                    require(start["target"] == target(bits).hex(), "start target")
                    row = take("construction", ("key", "setup", "search", "target", "status", "trials", "winner"))
                    count = check_construction(row, key, task, prefix)
                    account(row["setup"]); account(row["search"])
                    group = aggregate[arm]
                    group["all_trials"] += count
                    group["setup_cpu_ns"] += row["setup"]["cpu_ns"]
                    group["search_cpu_ns"] += row["search"]["cpu_ns"]
                    owner = take("receiver-setup", ("key", "timing", "capacity", "software_bytes"))
                    check_key(owner["key"], key)
                    require(integer(owner["capacity"], "capacity") == 1 and
                            0 < integer(owner["software_bytes"], "software bytes") <= 4 * 1024 * 1024,
                            "one bounded fresh arithmetic owner")
                    group["receiver_setup_cpu_ns"] += account(owner["timing"])["cpu_ns"]
                    for path in PATHS:
                        checked = take("verification", ("key", "path", "outcome", "timing",
                            "transcript_tiles", "before_product", "before_verified"))
                        check_key(checked["key"], key)
                        expected = "PrecheckPass" if path == "precheck" else "Accepted" if arm == "legal" else "Transcript"
                        require(checked["path"] == path and checked["outcome"] == expected, "native outcome/path")
                        tiles = 0 if path in ("precheck", "arithmetic-hot") else 512
                        boundary = int(arm == "legal" and path != "precheck")
                        require(integer(checked["transcript_tiles"], "tiles") == tiles and
                            integer(checked["before_product"], "before product") == boundary and
                            integer(checked["before_verified"], "before verified") == boundary,
                            "actual native replay/cache boundaries")
                        group["stages_cpu_ns"][path] += account(checked["timing"])["cpu_ns"]
                        verifications += 1
                    check_key(take("sample-end", ("key",))["key"], key)
                    constructions += 1
            for arm, group in aggregate.items():
                total = group["setup_cpu_ns"] + group["search_cpu_ns"]
                stages = group["stages_cpu_ns"]
                summaries.append({"class": name, "target_bits": bits, "target": target(bits).hex(),
                    "conditional_uniform_ticket_probability": f"1/{1 << bits}", "arm": arm,
                    "samples": SAMPLES, "completed_losing_trials": group["all_trials"] - SAMPLES,
                    "all_construction_cpu_ns": total, **group,
                    "precheck_plus_raw_first_over_construction": ratio(stages["precheck"] + stages["raw-first"], total),
                    "raw_first_over_construction": ratio(stages["raw-first"], total)})
    end = take("end", ("samples_completed", "verifications_completed", "all_expected_outcomes",
        "work_cost_lower_bound_proved", "node_service_measured", "production_activation", "total_before_terminal"))
    require(integer(end["samples_completed"], "samples completed") == constructions == 96 and
            integer(end["verifications_completed"], "verifications completed") == verifications == 576,
            "complete fixed grid")
    require(end["all_expected_outcomes"] is True and all(end[key] is False for key in
        ("work_cost_lower_bound_proved", "node_service_measured", "production_activation")), "no qualification promotion")
    timing(end["total_before_terminal"])
    require(all(interval_totals[axis] <= end["total_before_terminal"][axis]
                for axis in interval_totals), "disjoint intervals exceed complete campaign")
    require(position == len(rows), "extra native records")
    return {"schema": SCHEMA + "-checked", "record_consistency": "PASS", "samples": constructions,
        "stage_observations": verifications, "fixture_generation": fixtures["timing"],
        "public_statement_setup_cpu_ns": material_cpu, "total_before_terminal": end["total_before_terminal"],
        "disjoint_interval_totals": interval_totals,
        "observations": summaries, **FALSE_FLAGS,
        "limits": [
            "Finite synthetic inputs and fixed seeds/targets; no all-legal-strategy cost bound.",
            "All search misses and binary observation bookkeeping are included; JSON/hex/output and retained-buffer cleanup are outside algorithm intervals and inside the whole campaign interval.",
            "Public fixture generation and statement setup are reported separately from per-sample construction ratios.",
            "Precheck and raw verifier are separate calls; their sum is a component cost, not measured Node admission.",
            "Raw-first/raw-repeat identify call order only, not controlled hardware cache temperature; arithmetic-cold/hot identify a new cache owner and exact-statement reuse.",
            "Verifier intervals include their progress-count callbacks; path order is fixed, while construction arm order rotates by sample.",
            "Legal and forged searches share material/target/sample, but legal attempts change the challenge and forged attempts change the claimed trace at fixed challenge; they need not finish on the same statement.",
            "ArithmeticFactCache is an opt-in mathematical component; these hot results do not establish default public-listener behavior, paid admission, restart/cross-receiver fairness or a service speedup.",
            "The legal comparator is one explicit full-limb/dense-setup/lazy-winner implementation, not a fastest legal producer.",
            "Records do not independently authenticate clocks, binary execution, hardware or physical resource isolation."]}


def analyze(path):
    rows, digest = load_records(path)
    result = analyze_rows(rows)
    result["native_log_sha256"] = digest
    return result


def run(output):
    require(output.is_absolute() and output.resolve() == output and not output.is_relative_to(ROOT),
            "new canonical evidence directory outside checkout")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA + "-execution", "result": "FAIL", "commands": [],
              "native_component_executed": False, **FALSE_FLAGS}
    def save():
        (output / "execution.json").write_text(json.dumps(report, indent=2) + "\n")
    def execute(command, name, timeout):
        result = ci.run(command, output / name, timeout=timeout, expected_source=report["source_expected"])
        report["commands"].append(result); save()
        require(result["exit_code"] == result["process_exit_code"] == 0 and
                result["executed"] is True and result["timed_out"] is False and
                result["source_verified"] is True, name + " failed")
    save()
    try:
        report["source_expected"] = ci.pin_source()
        report["source_before"] = ci.source()
        report["host"] = {"system": platform.system(), "machine": platform.machine(),
                          "kernel": platform.release(), "logical_cpus": os.cpu_count()}
        cpuinfo = Path("/proc/cpuinfo")
        if cpuinfo.is_file():
            lines = cpuinfo.read_text().splitlines()
            report["host"]["cpu_model"] = next((line.split(":", 1)[1].strip() for line in lines
                if line.startswith("model name") and ":" in line), None)
        report["build_environment_overrides"] = build_environment_overrides(dict(os.environ))
        require(not report["build_environment_overrides"], "default release configuration required")
        report["cargo_configuration_before"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
        require_cargo_configuration(report["cargo_configuration_before"])
        execute(["bash", "scripts/project-preflight.sh"], "preflight.log", 60)
        execute(["rustc", "-vV"], "rustc.log", 30)
        require("\nrelease: 1.95.0\n" in (output / "rustc.log").read_text(), "Rust 1.95.0 required")
        execute(["cargo", "build", "--offline", "--locked", "--release", "--manifest-path",
            "trillionnium/Cargo.toml", "-p", "trnm-crypto-primitives", "--example", EXAMPLE,
            "--jobs", "2", "--message-format=json"], "build.log", 900)
        artifacts = []
        for line in (output / "build.log").read_text().splitlines():
            if line.startswith("{"):
                item = json.loads(line)
                if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == EXAMPLE:
                    require(item["target"].get("kind") == ["example"] and item.get("executable"), "native example artifact")
                    artifacts.append(Path(item["executable"]))
        require(len(artifacts) == 1, "one compiled example")
        binary = artifacts[0]
        report["binary_sha256_before"] = ci.digest(binary)
        execute([str(binary), SELECTOR], "native.jsonl", 180)
        report["native_component_executed"] = True
        report["checked"] = analyze(output / "native.jsonl")
        report["binary_sha256_after"] = ci.digest(binary)
        require(report["binary_sha256_before"] == report["binary_sha256_after"], "binary changed")
        report["result"] = "PASS"
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
    finally:
        report["source_after"] = ci.source()
        if (report["source_after"].get("commit") != report.get("source_expected") or
                report["source_after"].get("tracked_worktree_verified") is not True):
            report["result"], report["source_changed"] = "FAIL", True
        try:
            report["cargo_configuration_after"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
            require_cargo_configuration(report["cargo_configuration_after"])
            require(report["cargo_configuration_after"] == report.get("cargo_configuration_before"), "Cargo configuration changed")
        except (OSError, ValueError) as error:
            report["result"], report["configuration_failure"] = "FAIL", str(error)
        report["logs"] = {path.name: ci.digest(path) for path in sorted(output.iterdir())
                          if path.is_file() and path.name != "execution.json"}
        save()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path)
    mode.add_argument("--read", type=Path)
    arguments = parser.parse_args()
    try:
        result = analyze(arguments.read) if arguments.read else run(arguments.out)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result.get("result", "PASS") == "PASS" else 1)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError) as error:
        print(json.dumps({"schema": SCHEMA + "-refused", "reason": str(error), **FALSE_FLAGS}))
        raise SystemExit(2)
