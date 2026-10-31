#!/usr/bin/env python3
"""New bounded readback of recovered V5 rows; never reconstruct lost capture receipts."""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time


COMMIT = "1d11f875493f8125e36b9adceacb342df108e5e5"
TREE = "64b82137eebeb96b572abc62e5fce39af3593200"
READER = "scripts/ci/check_legal_ticket_cost_v5.py"
READER_SHA = "a8d6c0c48e044a1835b4eedabf5362872ef163ac85e09aa7b4f7d0a3a66d5b99"
DRIVER = "trillionnium/crates/trnm-pon-node/examples/pon_legal_ticket_cost_v5.rs"
LOCK = "trillionnium/Cargo.lock"
RAW_GZIP_SHA = "6781436c5acfc932df0aac3d46ee1f04c9e987158d87d74f107ed542529dbe7d"
RAW_GIT_BLOB = "581b49bfef116c952903c6519c9f179c4cdd6214"
RAW_SHA = "7d2729358a669c56ef47c1056f1ec87b5f8b02a8cebdcf0ae6b7d65532c528fc"
BINARY_GZIP_SHA = "b876349e5f5c3dbebeb50f4c791cfaecc72911d59276383136d1b98b46cc2c9e"
BINARY_GIT_BLOB = "93c4e04b5cbf8c4ae180f2258f26a4af06475f68"
BINARY_SHA = "e363b0c87ccca5a99567ce3fb2c4b759784ccfb724dd295b08e5fae132a3fbbe"
CONFIGS = (
    "devnet-v1.json", "public-evaluation-native-v1.json", "continuity-v1.json",
    "qualified-task-lifecycle-v4.json", "work-profile-v1.json", "ledger-v1.json",
    "model-family-v1.json",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git_blob_oid(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def git(repository, *arguments):
    return subprocess.check_output(
        ["git", "--no-replace-objects", "-C", str(repository), *arguments]
    )


def checked_gzip(path, compressed_sha, oid, uncompressed_sha, max_raw_bytes):
    require(path.stat().st_size <= 8 * 1024 * 1024, "compressed object bound")
    compressed = path.read_bytes()
    require(digest(compressed) == compressed_sha, "compressed object SHA-256")
    require(git_blob_oid(compressed) == oid, "compressed Git object identity")
    with gzip.open(path, "rb") as handle:
        raw = handle.read(max_raw_bytes + 1)
    require(len(raw) <= max_raw_bytes, "uncompressed object bound")
    require(digest(raw) == uncompressed_sha, "uncompressed object SHA-256")
    return {"compressed_bytes": len(compressed), "compressed_sha256": compressed_sha,
            "git_blob_oid": oid, "uncompressed_bytes": len(raw),
            "uncompressed_sha256": uncompressed_sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--raw-gzip", type=Path, required=True)
    parser.add_argument("--binary-gzip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    started_clock = time.monotonic_ns()
    require(git(args.repository, "rev-parse", COMMIT + "^{tree}").decode().strip() == TREE,
            "pinned source commit/tree identity")
    raw_identity = checked_gzip(args.raw_gzip, RAW_GZIP_SHA, RAW_GIT_BLOB, RAW_SHA,
                                64 * 1024 * 1024)
    binary_identity = checked_gzip(args.binary_gzip, BINARY_GZIP_SHA, BINARY_GIT_BLOB,
                                   BINARY_SHA, 16 * 1024 * 1024)
    inputs = {}
    with tempfile.TemporaryDirectory(prefix="trnm-recovered-v5-reader-") as directory:
        source = Path(directory)
        for relative in (READER, DRIVER, LOCK, *("config/pon/" + p for p in CONFIGS)):
            data = git(args.repository, "show", COMMIT + ":" + relative)
            require(len(data) <= 2 * 1024 * 1024, "pinned source input bound")
            oid = git(args.repository, "rev-parse", COMMIT + ":" + relative).decode().strip()
            require(git_blob_oid(data) == oid, "pinned source input Git identity")
            inputs[relative] = {"bytes": len(data), "sha256": digest(data), "git_blob_oid": oid}
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        require(inputs[READER]["sha256"] == READER_SHA, "unchanged hardened reader identity")
        spec = importlib.util.spec_from_file_location("pinned_recovered_v5_reader", source / READER)
        require(spec is not None and spec.loader is not None, "reader loader")
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        rows, byte_count, raw_sha = reader.read_rows(args.raw_gzip)
        require(byte_count == raw_identity["uncompressed_bytes"] and raw_sha == RAW_SHA,
                "unchanged bounded row reader identity")
        require(rows[0]["compiled_driver_sha256"] == inputs[DRIVER]["sha256"],
                "embedded compiled driver binding")
        require(rows[0]["compiled_cargo_lock_sha256"] == inputs[LOCK]["sha256"],
                "embedded compiled Cargo.lock binding")
        validation_start = time.monotonic_ns()
        summary = reader.validate(rows)
        validation_wall_ns = time.monotonic_ns() - validation_start
    summary_bytes = (json.dumps(summary, indent=2) + "\n").encode()
    with (args.output / "core-summary.json.gz").open("wb") as handle:
        with gzip.GzipFile(fileobj=handle, filename="", mode="wb", mtime=0) as compressed:
            compressed.write(summary_bytes)
    cohorts = [row for row in rows if row["kind"] == "cohort"]
    result = {
        "schema": "pon-recovered-v5-core-readback-v1",
        "new_readback_started_at_utc": started,
        "new_readback_finished_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "new_readback_wall_ns": time.monotonic_ns() - started_clock,
        "new_validate_call_wall_ns": validation_wall_ns,
        "row_validation_result": "PASS",
        "reader_source_commit": COMMIT, "reader_source_tree": TREE,
        "source_input_scope": "Unchanged reader, its seven configuration files, and the two raw-record-embedded driver/lock bindings, extracted from pinned Git objects.",
        "source_inputs": inputs,
        "raw_identity": raw_identity, "binary_identity": binary_identity,
        "records": len(rows), "cohorts": len(cohorts),
        "searches": sum(len(row["searches"]) for row in cohorts),
        "attempts": sum(row["attempts"] for row in cohorts),
        "first_admissions": sum(row["winners"] for row in cohorts),
        "misses": sum(row["attempts"] - row["winners"] for row in cohorts),
        "exhausted_searches": sum(row["exhausted"] for row in cohorts),
        "distinct_paired_packet_ids": summary["distinct_fixture_packet_ids_across_paired_cohorts"],
        "raw_declared_native_budget_seconds": rows[0]["budget_seconds"],
        "raw_reported_native_terminal_status": rows[-1]["status"],
        "raw_reported_native_terminal_wall_ns": rows[-1]["wall_ns"],
        "context_binding": summary["context_binding"],
        "core_summary_uncompressed_bytes": len(summary_bytes),
        "core_summary_uncompressed_sha256": digest(summary_bytes),
        "core_summary_is_new_derivation": True,
        "original_full_cli_capture_verdict_reproduced": False,
        "original_full_source_guards_recovered": False,
        "original_capture_process_receipt_recovered": False,
        "original_build_logs_and_depfile_recovered": False,
        "original_reader_process_receipt_recovered": False,
        "native_execution_commit_proved_by_raw_records": False,
        "new_native_execution": False,
        "recovered_binary_executed": False,
        "binary_execution_link_proved_by_raw_records": False,
        "scope": "Fresh validation of recovered raw rows with unchanged read_rows and validate functions. The original main CLI was not invoked because original capture metadata and full source guards are unavailable. No substitute receipts or native execution were created.",
        "exclusive_host_claim": False, "cross_source_speedup_claim": False,
        "global_minimum_cost_claim": False, "production_qualification_claim": False,
    }
    (args.output / "readback.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in (
        "row_validation_result", "records", "cohorts", "searches", "attempts",
        "first_admissions", "misses", "exhausted_searches", "distinct_paired_packet_ids",
        "original_full_cli_capture_verdict_reproduced", "new_native_execution",
    )}))


if __name__ == "__main__":
    main()
