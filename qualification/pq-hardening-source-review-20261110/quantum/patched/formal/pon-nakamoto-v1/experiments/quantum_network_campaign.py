#!/usr/bin/env python3
"""Seeded conditional network observations with source-bound replay receipts."""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import gzip
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from quantum_network_sim import (  # noqa: E402
    ASSUMPTIONS, WORK_MAX, run_network_scenario, standard_network_scenarios,
)
from quantum_daa_model import common_history  # noqa: E402

SCHEMA = "trnm-quantum-network-campaign-v1"
SOURCE_FILES = (
    "config/pon/devnet-v1.json",
    "trillionnium/crates/trnm-pon-node/src/consensus.rs",
    "formal/pon-nakamoto-v1/reference.py",
    "formal/pon-nakamoto-v1/quantum_daa_model.py",
    "formal/pon-nakamoto-v1/quantum_adversarial_search.py",
    "formal/pon-nakamoto-v1/quantum_network_sim.py",
    "formal/pon-nakamoto-v1/test_quantum_network_sim.py",
    "formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[name] = value
    return result


def load_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4_000_000:
        raise ValueError("JSON_FILE_BOUND")
    return json.loads(path.read_text(), object_pairs_hook=strict_object)


def source_record() -> dict:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    files = {name: digest(ROOT / name) for name in SOURCE_FILES}
    uncommitted = []
    for name in SOURCE_FILES:
        old = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or hashlib.sha256(old.stdout).hexdigest() != files[name]:
            uncommitted.append(name)
    return {"git_head": head, "source_sha256": files,
            "all_source_files_committed_at_head": not uncommitted,
            "uncommitted_source_files": uncommitted,
            "scope": "only enumerated source bytes; excludes unrelated concurrent files"}


def validate_source_record(record: dict) -> None:
    if not isinstance(record, dict) or not isinstance(record.get("git_head"), str) or not re.fullmatch(r"[0-9a-f]{40}", record["git_head"]):
        raise ValueError("SOURCE_HEAD")
    head = record["git_head"]
    resolved = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if resolved.returncode or resolved.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    files = {name: digest(ROOT / name) for name in SOURCE_FILES}
    if record.get("source_sha256") != files:
        raise ValueError("SOURCE_DIGEST")
    actual_uncommitted = []
    for name in SOURCE_FILES:
        old = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or hashlib.sha256(old.stdout).hexdigest() != files[name]:
            actual_uncommitted.append(name)
    if (record.get("uncommitted_source_files") != actual_uncommitted
            or record.get("all_source_files_committed_at_head") is not (not actual_uncommitted)):
        raise ValueError("SOURCE_COMMITMENT_CLAIM")


def cases_for(seeds: list[int] | tuple[int, ...]) -> list:
    if not isinstance(seeds, (list, tuple)) or not 1 <= len(seeds) <= 16:
        raise ValueError("SEED_COUNT")
    if any(type(seed) is not int or not 0 <= seed < (1 << 64) for seed in seeds):
        raise ValueError("SEED_VALUE")
    if len(set(seeds)) != len(seeds):
        raise ValueError("DUPLICATE_SEED")
    return [replace(case, seed=seed) for seed in seeds for case in standard_network_scenarios()]


def write_rows(path: Path, rows: list[dict]) -> None:
    with path.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as out:
            for row in rows:
                out.write(canonical(row))


def read_rows(path: Path) -> list[dict]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
        raise ValueError("TRACE_FILE_BOUND")
    rows, total = [], 0
    with gzip.open(path, "rb") as stream:
        while True:
            line = stream.readline(4097)
            if not line:
                break
            total += len(line)
            if len(line) > 4096 or total > 64_000_000 or len(rows) >= 300_000:
                raise ValueError("TRACE_DECOMPRESSION_BOUND")
            row = json.loads(line, object_pairs_hook=strict_object)
            if not isinstance(row, dict):
                raise ValueError("TRACE_OBJECT")
            rows.append(row)
    return rows


def check_trace_arithmetic(rows: list[dict]) -> None:
    """Independent integer credit/time readback; no native cryptographic check."""
    prefix = common_history()
    credit = sum((1 << 256) // (h.target + 1) for h in prefix)
    known = {"prefix": (prefix[-1].height, credit, [h.timestamp for h in prefix[-11:]],
                        max(h.timestamp for h in prefix))}
    previous = 0.0
    for index, row in enumerate(rows):
        now = row.get("at_seconds")
        if type(row.get("row")) is not int or row["row"] != index:
            raise ValueError("TRACE_INDEX")
        if type(now) not in (int, float) or not previous <= now <= 86400:
            raise ValueError("TRACE_CLOCK")
        previous = now
        if row.get("kind") == "adopt":
            tip = row.get("tip")
            if tip not in known or known[tip][3] > prefix[-1].timestamp + int(now) + 120:
                raise ValueError("TRACE_FUTURE_ADOPTION")
            if row.get("chainwork") != str(known[tip][1]):
                raise ValueError("TRACE_ADOPTION_CREDIT")
        if row.get("kind") != "block":
            continue
        if row.get("parent") not in known or row.get("block") in known:
            raise ValueError("TRACE_ANCESTRY")
        height, parent_work, stamps, ancestor_max_stamp = known[row["parent"]]
        target_text = row.get("target_hex", "")
        if not isinstance(target_text, str) or len(target_text) != 64:
            raise ValueError("TRACE_TARGET")
        target = int(target_text, 16)
        if not 1 <= target < (1 << 256):
            raise ValueError("TRACE_TARGET")
        required = (1 << 256) // (target + 1)
        accumulated = parent_work + required
        if accumulated > WORK_MAX or row.get("required_work") != str(required) or row.get("chainwork") != str(accumulated):
            raise ValueError("TRACE_CHAINWORK")
        stamp = row.get("timestamp")
        if type(stamp) is not int or stamp <= sorted(stamps[-11:])[5]:
            raise ValueError("TRACE_TIMESTAMP")
        future = stamp > prefix[-1].timestamp + int(now) + 120
        if row.get("future_at_creation") is not future:
            raise ValueError("TRACE_FUTURE_FLAG")
        if future and (row.get("private_builder") is not True or row.get("miner") != "q"):
            raise ValueError("TRACE_FUTURE_BUILDER")
        if type(row.get("height")) is not int or row["height"] != height + 1:
            raise ValueError("TRACE_HEIGHT")
        known[row["block"]] = (height + 1, accumulated, (stamps + [stamp])[-11:],
                               max(ancestor_max_stamp, stamp))


def run_campaign(out: Path, argv: list[str], seeds: tuple[int, ...] = (4101, 4102, 4103)) -> dict:
    cases = cases_for(seeds)
    source = source_record()
    out.mkdir(parents=True, exist_ok=False)
    started, cpu = time.perf_counter(), time.process_time()
    records, files = [], {}
    for case in cases:
        summary, rows = run_network_scenario(case)
        check_trace_arithmetic(rows)
        filename = f"{case.name}_s{case.seed}.jsonl.gz"
        write_rows(out / filename, rows)
        files[filename] = digest(out / filename)
        records.append({"parameters": asdict(case), "summary": summary, "trace_file": filename})
    if source["source_sha256"] != {name: digest(ROOT / name) for name in SOURCE_FILES}:
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    report = {"schema": SCHEMA, "source": source, "argv": argv, "seeds": seeds,
              "assumptions": ASSUMPTIONS, "observations": records,
              "actual_python_process": {
                  "wall_seconds": time.perf_counter() - started,
                  "cpu_seconds": time.process_time() - cpu,
                  "python": sys.version, "platform": platform.platform(),
                  "scope": "simulator and trace serialization, not W1 or quantum hardware",
              }}
    (out / "report.json").write_bytes(canonical(report))
    files["report.json"] = digest(out / "report.json")
    (out / "manifest.json").write_bytes(canonical({"schema": SCHEMA + "-manifest", "files_sha256": files}))
    return {"result": "CONDITIONAL_NETWORK_OBSERVATIONS", "runs": len(records),
            "trace_rows": sum(r["summary"]["trace_rows"] for r in records),
            "source_committed": source["all_source_files_committed_at_head"],
            "horizon_completed_runs": sum(r["summary"]["termination"] == "horizon" for r in records),
            "release_ready": False}


def verify_campaign(out: Path) -> dict:
    if out.is_symlink() or not out.is_dir():
        raise ValueError("OUTPUT_DIRECTORY")
    report = load_json(out / "report.json")
    manifest = load_json(out / "manifest.json")
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ValueError("REPORT_SCHEMA")
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA + "-manifest":
        raise ValueError("MANIFEST_SCHEMA")
    if report.get("assumptions") != ASSUMPTIONS:
        raise ValueError("ASSUMPTION_SUBSTITUTION")
    cases = cases_for(report.get("seeds"))
    expected = {f"{c.name}_s{c.seed}.jsonl.gz" for c in cases} | {"report.json"}
    files = manifest.get("files_sha256")
    if not isinstance(files, dict) or set(files) != expected:
        raise ValueError("MANIFEST_INVENTORY")
    if {p.name for p in out.iterdir()} != expected | {"manifest.json"}:
        raise ValueError("OUTPUT_INVENTORY")
    for name, wanted in files.items():
        path = out / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
            raise ValueError("ARTIFACT_BOUND")
        if digest(path) != wanted:
            raise ValueError("ARTIFACT_DIGEST")
    validate_source_record(report.get("source"))
    records = report.get("observations")
    if not isinstance(records, list) or len(records) != len(cases):
        raise ValueError("OBSERVATION_INVENTORY")
    for case, record in zip(cases, records):
        filename = f"{case.name}_s{case.seed}.jsonl.gz"
        if canonical(record.get("parameters")) != canonical(asdict(case)) or record.get("trace_file") != filename:
            raise ValueError("SCENARIO_SUBSTITUTION")
        rows = read_rows(out / filename)
        check_trace_arithmetic(rows)
        summary, replay = run_network_scenario(case)
        if record.get("summary") != summary or rows != replay:
            raise ValueError("SEEDED_REPLAY_MISMATCH")
    return {"result": "SEEDED_REPLAY_AND_INTEGER_READBACK_PASS", "runs": len(cases),
            "native_w1_verified": False, "quantum_resource_verified": False, "release_ready": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--out", type=Path)
    action.add_argument("--verify", type=Path)
    parser.add_argument("--seeds", nargs="+", type=int, default=[4101, 4102, 4103])
    args = parser.parse_args()
    result = (verify_campaign(args.verify) if args.verify else
              run_campaign(args.out, sys.argv, tuple(args.seeds)))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
