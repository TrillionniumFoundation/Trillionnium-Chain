#!/usr/bin/env python3
"""Source-bound observations/replay of the separate OHIE text-profile model."""
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

from parallel_variable_ohie import (  # noqa: E402
    ASSUMPTIONS, SOURCE, Limits, Scenario, State, block_from_dict, canonical,
    run_scenario, standard_scenarios,
)

SCHEMA = "trnm-ohie-text-campaign-v1"
SOURCE_FILES = (
    "formal/pon-nakamoto-v1/parallel_variable_ohie.py",
    "formal/pon-nakamoto-v1/test_parallel_variable_ohie.py",
    "formal/pon-nakamoto-v1/experiments/parallel_variable_ohie_campaign.py",
)


def canonical_line(value: object) -> bytes:
    return canonical(value) + b"\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[name] = value
    return result


def read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
        raise ValueError("JSON_FILE_BOUND")
    result = json.loads(path.read_text(), object_pairs_hook=strict_object)
    if type(result) is not dict:
        raise ValueError("JSON_OBJECT")
    return result


def atomic_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("xb") as stream:
        stream.write(data)
    temporary.replace(path)


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
            "scope": "only enumerated model/test/runner bytes; no native node claim"}


def validate_source(record: dict) -> None:
    if type(record) is not dict or type(record.get("git_head")) is not str or not re.fullmatch(r"[0-9a-f]{40}", record["git_head"]):
        raise ValueError("SOURCE_HEAD")
    head = record["git_head"]
    resolved = subprocess.run(["git", "cat-file", "-t", head], cwd=ROOT,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if resolved.returncode or resolved.stdout.strip() != "commit":
        raise ValueError("SOURCE_HEAD")
    files = {name: digest(ROOT / name) for name in SOURCE_FILES}
    if record.get("source_sha256") != files:
        raise ValueError("SOURCE_DIGEST")
    uncommitted = []
    for name in SOURCE_FILES:
        old = subprocess.run(["git", "show", head + ":" + name], cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if old.returncode or hashlib.sha256(old.stdout).hexdigest() != files[name]:
            uncommitted.append(name)
    if (record.get("uncommitted_source_files") != uncommitted
            or record.get("all_source_files_committed_at_head") is not (not uncommitted)):
        raise ValueError("SOURCE_COMMITMENT_CLAIM")


def cases_for(seeds: list[int] | tuple[int, ...]) -> list[Scenario]:
    if type(seeds) not in (list, tuple) or not 1 <= len(seeds) <= 8:
        raise ValueError("SEED_COUNT")
    if any(type(seed) is not int or not 0 <= seed < (1 << 64) for seed in seeds):
        raise ValueError("SEED_VALUE")
    if len(set(seeds)) != len(seeds):
        raise ValueError("DUPLICATE_SEED")
    return [replace(case, seed=seed) for seed in seeds for case in standard_scenarios()]


def write_trace(path: Path, rows: list[dict]) -> None:
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
            for row in rows:
                stream.write(canonical_line(row))
    temporary.replace(path)


def read_trace(path: Path) -> list[dict]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000:
        raise ValueError("TRACE_FILE_BOUND")
    rows, total = [], 0
    with gzip.open(path, "rb") as stream:
        while True:
            line = stream.readline(2_000_001)
            if not line:
                break
            total += len(line)
            if len(line) > 2_000_000 or total > 128_000_000 or len(rows) >= 200_002:
                raise ValueError("TRACE_DECOMPRESSION_BOUND")
            row = json.loads(line, object_pairs_hook=strict_object)
            if type(row) is not dict:
                raise ValueError("TRACE_OBJECT")
            rows.append(row)
    return rows


def check_trace(rows: list[dict], case: Scenario) -> dict:
    """Read back actual header hashes/targets/dependencies using the state machine.

    This checker is distinct from the mining/event sampler, but shares the model
    admission predicates. It is not a second proof or a native cryptographic
    verifier. Exact event/pool/ledger behavior is additionally checked by replay.
    """
    case.validate()
    if not 2 <= len(rows) <= case.max_trace_rows:
        raise ValueError("TRACE_ROW_BOUND")
    if rows[0].get("kind") != "start" or rows[0].get("profile") != case.profile.identity or rows[0].get("source") != SOURCE:
        raise ValueError("TRACE_PROFILE_OR_SOURCE")
    if rows[-1].get("kind") != "finish":
        raise ValueError("TRACE_UNFINISHED")
    reader = State(case.profile, Limits(max_blocks=case.max_blocks + case.profile.chains,
                                       max_pending_blocks=case.max_blocks))
    created: dict[str, int] = {}
    miners = {f"m{i}" for i in range(len(case.queries_per_miner))}
    previous, checked_blocks, queries = 0, 0, 0
    for index, row in enumerate(rows):
        now = row.get("round")
        if type(row.get("row")) is not int or row["row"] != index:
            raise ValueError("TRACE_INDEX")
        if type(now) is not int or not previous <= now <= case.rounds:
            raise ValueError("TRACE_ROUND")
        previous = now
        kind = row.get("kind")
        if kind not in ("start", "query", "delivery", "probe_arrival", "private_release", "finish"):
            raise ValueError("TRACE_KIND")
        if kind == "query":
            queries += 1
            if row.get("miner") not in miners or type(row.get("ticket")) is not int or type(row.get("target")) is not int:
                raise ValueError("TRACE_QUERY")
            if not 0 <= row["ticket"] < (1 << case.profile.hash_bits) or not 1 <= row["target"] <= (1 << case.profile.hash_bits):
                raise ValueError("TRACE_TICKET_BOUND")
            if row.get("won") is not (row["ticket"] < row["target"]):
                raise ValueError("TRACE_WIN_FLAG")
            if not row["won"]:
                if "block" in row or "disposition" in row:
                    raise ValueError("TRACE_FALSE_WINNER")
                continue
            block = block_from_dict(json.loads(canonical(row.get("block"))))
            if (block.ticket(case.profile.hash_bits) != row["ticket"] or block.target != row["target"]
                    or block.chain != row.get("chain") or block.nonce != row.get("nonce")
                    or block.miner != row["miner"] or block.timestamp != now):
                raise ValueError("TRACE_BLOCK_QUERY_BINDING")
            if any(parent not in reader.records for parent in block.dependencies()):
                raise ValueError("TRACE_MISSING_ANCESTRY")
            disposition = row.get("disposition")
            if disposition == "diagnostic_discard":
                if block.chain != case.diagnostic_discard_chain:
                    raise ValueError("TRACE_DISCARD_POLICY")
                reader._shape(block)
                reader._derive(block)
            else:
                result = reader.receive(block, now)
                if disposition == "rejected_by_profile":
                    if result.status != "REJECTED" or result.reason != row.get("reason"):
                        raise ValueError("TRACE_REJECTION_CLAIM")
                elif disposition in ("published", "private_withheld", "publication_censored_by_limit"):
                    if result.status != "ACCEPTED" or block.block_id in created:
                        raise ValueError("TRACE_BLOCK_ADMISSION")
                    created[block.block_id] = now
                else:
                    raise ValueError("TRACE_DISPOSITION")
            checked_blocks += 1
        elif kind == "delivery":
            if row.get("recipient") not in miners | {"observer"}:
                raise ValueError("TRACE_RECIPIENT")
            sent = row.get("sent_round")
            if type(sent) is not int or sent + case.delay_rounds != now:
                raise ValueError("TRACE_DELIVERY_CLOCK")
            roots = row.get("roots")
            if type(roots) not in (tuple, list) or len(roots) > case.max_blocks:
                raise ValueError("TRACE_DELIVERY_ROOTS")
            if any(root not in created or created[root] > sent for root in roots):
                raise ValueError("TRACE_EARLY_DELIVERY")
            for block_id in row.get("accepted", []):
                if block_id not in reader.records or reader.records[block_id].timestamp > now:
                    raise ValueError("TRACE_EARLY_ADMISSION")
    if rows[-1].get("queries") != queries:
        raise ValueError("TRACE_QUERY_ACCOUNTING")
    return {"checked_winning_headers": checked_blocks, "admitted_block_inventory": len(created),
            "scope": "model admission predicates/readback; full deterministic replay is separate",
            "native_w1_verified": False, "security_theorem": False}


def run_campaign(out: Path, argv: list[str], seeds: tuple[int, ...] = (7101, 7102, 7103)) -> dict:
    cases = cases_for(seeds)
    source = source_record()
    out.mkdir(parents=True, exist_ok=False)
    started, cpu = time.perf_counter(), time.process_time()
    records, files = [], {}
    for case in cases:
        summary, rows = run_scenario(case)
        readback = check_trace(rows, case)
        filename = f"{case.name}_s{case.seed}.jsonl.gz"
        write_trace(out / filename, rows)
        files[filename] = digest(out / filename)
        records.append({"parameters": asdict(case), "summary": summary,
                        "readback": readback, "trace_file": filename})
    if source["source_sha256"] != {name: digest(ROOT / name) for name in SOURCE_FILES}:
        raise ValueError("SOURCE_CHANGED_DURING_CAMPAIGN")
    report = {"schema": SCHEMA, "source": source, "paper_source": SOURCE, "assumptions": ASSUMPTIONS,
              "seeds": seeds, "argv": argv, "observations": records,
              "actual_python_process": {"wall_seconds": time.perf_counter() - started,
                                         "cpu_seconds": time.process_time() - cpu,
                                         "python": sys.version, "platform": platform.platform(),
                                         "scope": "Python research model and serialization only"}}
    atomic_bytes(out / "report.json", canonical_line(report))
    files["report.json"] = digest(out / "report.json")
    atomic_bytes(out / "manifest.json", canonical_line({"schema": SCHEMA + "-manifest", "files_sha256": files}))
    return {"result": "BOUNDED_OHIE_TEXT_PROFILE_OBSERVATIONS", "runs": len(records),
            "horizon_completed_runs": sum(record["summary"]["horizon_completed"] for record in records),
            "trace_rows": sum(record["summary"]["trace_rows"] for record in records),
            "source_committed": source["all_source_files_committed_at_head"],
            "security_theorem": False, "fast_daa_2026_implemented": False, "release_ready": False}


def verify_campaign(out: Path) -> dict:
    if out.is_symlink() or not out.is_dir():
        raise ValueError("OUTPUT_DIRECTORY")
    report, manifest = read_json(out / "report.json"), read_json(out / "manifest.json")
    if report.get("schema") != SCHEMA or manifest.get("schema") != SCHEMA + "-manifest":
        raise ValueError("CAMPAIGN_SCHEMA")
    if report.get("assumptions") != ASSUMPTIONS or report.get("paper_source") != SOURCE:
        raise ValueError("SOURCE_INTERPRETATION_SUBSTITUTION")
    cases = cases_for(report.get("seeds"))
    expected = {f"{case.name}_s{case.seed}.jsonl.gz" for case in cases} | {"report.json"}
    files = manifest.get("files_sha256")
    if type(files) is not dict or set(files) != expected or {path.name for path in out.iterdir()} != expected | {"manifest.json"}:
        raise ValueError("ARTIFACT_INVENTORY")
    for name, wanted in files.items():
        path = out / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8_000_000 or digest(path) != wanted:
            raise ValueError("ARTIFACT_DIGEST_OR_BOUND")
    validate_source(report.get("source"))
    records = report.get("observations")
    if type(records) is not list or len(records) != len(cases):
        raise ValueError("OBSERVATION_INVENTORY")
    for case, record in zip(cases, records):
        filename = f"{case.name}_s{case.seed}.jsonl.gz"
        if canonical(record.get("parameters")) != canonical(asdict(case)) or record.get("trace_file") != filename:
            raise ValueError("SCENARIO_SUBSTITUTION")
        rows = read_trace(out / filename)
        if check_trace(rows, case) != record.get("readback"):
            raise ValueError("READBACK_CLAIM")
        summary, replay = run_scenario(case)
        if canonical(record.get("summary")) != canonical(summary) or canonical(rows) != canonical(replay):
            raise ValueError("DETERMINISTIC_REPLAY_MISMATCH")
    return {"result": "OHIE_MODEL_READBACK_AND_SEEDED_REPLAY_PASS", "runs": len(cases),
            "native_w1_verified": False, "security_theorem": False,
            "fast_daa_2026_implemented": False, "release_ready": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--out", type=Path)
    action.add_argument("--verify", type=Path)
    parser.add_argument("--seeds", default="7101,7102,7103")
    args = parser.parse_args()
    if args.verify:
        result = verify_campaign(args.verify)
    else:
        result = run_campaign(args.out, sys.argv[1:], tuple(int(part) for part in args.seeds.split(",")))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
