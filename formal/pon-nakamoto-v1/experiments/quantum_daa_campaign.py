#!/usr/bin/env python3
"""Produce or read back conditional DAA arithmetic; never native attack evidence."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from decimal import Decimal
import gzip
import hashlib
import json
import platform
from pathlib import Path
import resource
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from quantum_daa_model import (  # noqa: E402
    ASSUMPTIONS, U256, Scenario, common_history, run_scenario, standard_scenarios,
)

SCHEMA = "trnm-quantum-daa-research-v1"
SOURCE_FILES = (
    "config/pon/devnet-v1.json",
    "trillionnium/crates/trnm-pon-node/src/consensus.rs",
    "formal/pon-nakamoto-v1/reference.py",
    "formal/pon-nakamoto-v1/quantum_daa_model.py",
    "formal/pon-nakamoto-v1/test_quantum_daa_model.py",
    "formal/pon-nakamoto-v1/experiments/quantum_daa_campaign.py",
    "formal/pon-nakamoto-v1/vectors/quantum-daa-asert-bchn-v1.json",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    output: dict = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("DUPLICATE_JSON_KEY")
        output[key] = value
    return output


def load_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4_000_000:
        raise ValueError("JSON_FILE_BOUND")
    return json.loads(path.read_text(), object_pairs_hook=strict_object)


def source_record() -> dict:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    changed = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True
    ).splitlines()
    files = {name: digest(ROOT / name) for name in SOURCE_FILES}
    uncommitted = []
    for name in SOURCE_FILES:
        old = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or hashlib.sha256(old.stdout).hexdigest() != files[name]:
            uncommitted.append(name)
    return {
        "git_head": head,
        "tracked_tree_dirty": bool(changed),
        "all_model_source_files_committed_at_head": not uncommitted,
        "uncommitted_model_source_files": uncommitted,
        "source_sha256": files,
        "untracked_non_source_files": "excluded; neither inputs nor attested by this receipt",
    }


def write_rows(path: Path, rows: list[dict]) -> None:
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as zipped:
            for row in rows:
                zipped.write(canonical(row))


def read_rows(path: Path) -> list[dict]:
    if path.is_symlink() or path.stat().st_size > 5_000_000:
        raise ValueError("ROW_FILE_BOUND")
    rows = []
    size = 0
    with gzip.open(path, "rb") as zipped:
        while True:
            line = zipped.readline(4097)
            if not line:
                break
            size += len(line)
            if len(line) > 4096 or size > 64_000_000 or len(rows) >= 100000:
                raise ValueError("ROW_DECOMPRESSION_BOUND")
            row = json.loads(line, object_pairs_hook=strict_object)
            if not isinstance(row, dict):
                raise ValueError("ROW_OBJECT")
            rows.append(row)
    return rows


def run_campaign(out: Path, argv: list[str]) -> dict:
    source = source_record()
    out.mkdir(parents=True, exist_ok=False)
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    records, files = [], {}
    for case in standard_scenarios():
        summary, rows = run_scenario(case)
        name = case.name + ".jsonl.gz"
        write_rows(out / name, rows)
        files[name] = digest(out / name)
        records.append({"parameters": asdict(case), "summary": summary, "rows_file": name})
    actual_cpu = time.process_time() - cpu_start
    actual_wall = time.perf_counter() - wall_start
    usage = resource.getrusage(resource.RUSAGE_SELF)
    report = {
        "schema": SCHEMA,
        "source": source,
        "argv": argv,
        "assumptions": ASSUMPTIONS,
        "observations": records,
        "actual_python_process": {
            "wall_seconds": actual_wall,
            "cpu_seconds": actual_cpu,
            "maximum_resident_set": usage.ru_maxrss,
            "maximum_resident_set_unit": "bytes" if sys.platform == "darwin" else "KiB",
            "measurement_scope": "model execution and compressed row serialization; excludes final receipt serialization",
            "peak_memory_scope": "whole Python producer process including startup",
            "python": sys.version,
            "platform": platform.platform(),
            "quantum_hardware_seconds": None,
            "w1_native_execution_seconds": None,
        },
    }
    (out / "report.json").write_bytes(canonical(report))
    files["report.json"] = digest(out / "report.json")
    manifest = {"schema": SCHEMA + "-manifest", "files_sha256": files}
    (out / "manifest.json").write_bytes(canonical(manifest))
    return {
        "result": "CONDITIONAL_MODEL_COMPLETE",
        "scenarios": len(records),
        "rows": sum(record["summary"]["rows"] for record in records),
        "actual_wall_seconds": actual_wall,
        "actual_cpu_seconds": actual_cpu,
        "source_committed": source["all_model_source_files_committed_at_head"],
        "release_ready": False,
    }


def check_row_arithmetic(case: Scenario, rows: list[dict]) -> None:
    """Separately total raw integer credit and check MTP/future bounds.

    This does not import the producer's work/time helper. Full policy/cost replay
    still uses the shared model, and neither check verifies a W1/quantum proof.
    """
    history = common_history()
    stamps = [h.timestamp for h in history[-11:]]
    start = history[-1].timestamp
    credit = 0
    for index, row in enumerate(rows):
        if type(row["index"]) is not int or row["index"] != index:
            raise ValueError("ROW_INDEX")
        if type(row["height"]) is not int or row["height"] != history[-1].height + index + 1:
            raise ValueError("ROW_HEIGHT")
        stamp, units = row["timestamp"], row["mandatory_units"]
        if type(stamp) is not int or type(units) is not int or not 1 <= units <= case.max_units:
            raise ValueError("ROW_INTEGER")
        target = int(row["target_hex"], 16)
        if len(row["target_hex"]) != 64 or not 1 <= target < U256:
            raise ValueError("ROW_TARGET")
        weight = U256 // (target + 1)
        if case.policy == "fixed-p-work":
            weight *= units
        credit += weight
        if row["required_work"] != str(weight) or row["cumulative_work"] != str(credit):
            raise ValueError("ROW_CHAINWORK")
        elapsed = Decimal(row["modeled_elapsed_seconds"])
        if not elapsed.is_finite() or elapsed < 0:
            raise ValueError("ROW_CLOCK")
        completed = row["modeled_completion_time"]
        if type(completed) is not int or completed < start:
            raise ValueError("ROW_CLOCK")
        if stamp <= sorted(stamps[-11:])[5] or stamp > completed + 120:
            raise ValueError("ROW_TIMESTAMP")
        stamps.append(stamp)


def verify_campaign(out: Path) -> dict:
    if out.is_symlink() or not out.is_dir():
        raise ValueError("OUTPUT_DIRECTORY")
    manifest = load_json(out / "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA + "-manifest":
        raise ValueError("MANIFEST_SCHEMA")
    cases = standard_scenarios()
    expected_files = {case.name + ".jsonl.gz" for case in cases} | {"report.json"}
    files = manifest.get("files_sha256")
    if not isinstance(files, dict) or set(files) != expected_files:
        raise ValueError("MANIFEST_INVENTORY")
    if {path.name for path in out.iterdir()} != expected_files | {"manifest.json"}:
        raise ValueError("OUTPUT_INVENTORY")
    for name, expected_hash in files.items():
        path = out / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
            raise ValueError("ARTIFACT_BOUND")
        if digest(path) != expected_hash:
            raise ValueError("ARTIFACT_DIGEST")
    report = load_json(out / "report.json")
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ValueError("REPORT_SCHEMA")
    if report.get("assumptions") != ASSUMPTIONS:
        raise ValueError("ASSUMPTION_SUBSTITUTION")
    source = report.get("source", {})
    if source.get("source_sha256") != {name: digest(ROOT / name) for name in SOURCE_FILES}:
        raise ValueError("SOURCE_DIGEST")
    observations = report.get("observations")
    if not isinstance(observations, list) or len(observations) != len(cases):
        raise ValueError("OBSERVATION_INVENTORY")
    total = 0
    for case, record in zip(cases, observations):
        if record.get("parameters") != asdict(case) or record.get("rows_file") != case.name + ".jsonl.gz":
            raise ValueError("SCENARIO_SUBSTITUTION")
        rows = read_rows(out / record["rows_file"])
        check_row_arithmetic(case, rows)
        expected_summary, expected_rows = run_scenario(case)
        if record.get("summary") != expected_summary or rows != expected_rows:
            raise ValueError("DETERMINISTIC_REPLAY_MISMATCH")
        total += len(rows)
    return {
        "result": "ARITHMETIC_READBACK_PASS",
        "scenarios": len(cases), "rows": total,
        "source_git_head_reported": source["git_head"],
        "native_proof_verification": False, "quantum_cost_verification": False,
        "runtime_receipt_independently_attested": False,
        "security_theorem": False, "release_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path, help="fresh output directory; never overwritten")
    mode.add_argument("--verify", type=Path, help="read back exact rows and source hashes")
    args = parser.parse_args()
    try:
        result = verify_campaign(args.verify) if args.verify else run_campaign(args.out, sys.argv)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"result": "FAIL", "error": str(error), "release_ready": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
