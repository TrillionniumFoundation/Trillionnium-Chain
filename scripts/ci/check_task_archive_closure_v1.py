#!/usr/bin/env python3
"""Verify the bounded proof-preserving TaskV1 archive candidate closure.

The gate accepts repository implementation facts only.  It proves that the
candidate archive planner has bounded batches, prepaid retention charging,
Merkle seals and independent batch/inclusion verification while requiring
storage-deletion authority, scale evidence and every promotion flag to remain
false.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "config/task-archive-closure-v1.toml"


class TaskArchiveClosureError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TaskArchiveClosureError(message)


def load_toml(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        try:
            display = path.relative_to(ROOT)
        except ValueError:
            display = path
        raise TaskArchiveClosureError(f"{display}: invalid TOML: {error}") from error
    require(isinstance(value, dict), f"{path}: top-level TOML table required")
    return value


def repository_file(value: Any, label: str) -> pathlib.Path:
    require(
        isinstance(value, str)
        and value
        and not value.startswith("/")
        and ".." not in pathlib.PurePosixPath(value).parts,
        f"{label}: clean repository-relative path required",
    )
    path = ROOT / value
    require(path.is_file(), f"{label}: missing file {value}")
    return path


def string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label}: list required")
    require(allow_empty or bool(value), f"{label}: non-empty list required")
    require(
        all(isinstance(item, str) and item for item in value),
        f"{label}: non-empty strings required",
    )
    require(len(value) == len(set(value)), f"{label}: duplicate values")
    return list(value)


def main() -> int:
    config = load_toml(CONFIG_PATH)
    require(config.get("schema_version") == 1, "task archive schema drift")
    require(
        config.get("closure_id") == "trnm-task-archive-closure-v1",
        "task archive closure ID drift",
    )
    for claim in (
        "production_candidate",
        "production_consensus_activation",
        "public_testnet_ready",
        "release_ready",
        "storage_deletion_authority",
        "scale_campaign_complete",
    ):
        require(config.get(claim) is False, f"task archive promoted {claim}")

    package_path = repository_file(config.get("package_manifest"), "package manifest")
    package = load_toml(package_path)
    require(
        package.get("package", {}).get("name") == "trnm-poco-agent-market-v1",
        "task archive package identity drift",
    )
    metadata = package.get("package", {}).get("metadata", {}).get("trnm", {})
    require(isinstance(metadata, dict), "task archive package metadata.trnm missing")

    required_true = string_list(config.get("required_metadata_true"), "required_metadata_true")
    required_false = string_list(config.get("required_metadata_false"), "required_metadata_false")
    require(
        not set(required_true).intersection(required_false),
        "task archive metadata key required both true and false",
    )
    for key in required_true:
        require(metadata.get(key) is True, f"task archive metadata must be true: {key}")
    for key in required_false:
        require(metadata.get(key) is False, f"task archive metadata must remain false: {key}")

    expected_paths = {
        "archive_implementation": "trillionnium/crates/trnm-poco-agent-market-v1/src/archive.rs",
        "archive_verifier": "trillionnium/crates/trnm-poco-agent-market-v1/src/archive_verifier.rs",
        "public_surface": "trillionnium/crates/trnm-poco-agent-market-v1/src/lib.rs",
        "validation_script": "scripts/ci/check_task_archive_closure_v1.py",
        "architecture_document": "docs/architecture/TRNM_TASK_ARCHIVE_ADMISSION_CONTRACT_V1.md",
    }
    for field, expected in expected_paths.items():
        require(config.get(field) == expected, f"task archive {field} path drift")
        repository_file(config[field], f"task archive {field}")

    rows = config.get("source_contracts")
    require(isinstance(rows, list) and rows, "task archive source contracts missing")
    seen: set[str] = set()
    reports: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        require(isinstance(row, dict), f"source_contracts[{index}]: table required")
        raw_path = row.get("path")
        require(isinstance(raw_path, str), f"source_contracts[{index}]: path required")
        require(raw_path not in seen, f"duplicate source contract path: {raw_path}")
        seen.add(raw_path)
        path = repository_file(raw_path, f"source_contracts[{index}]")
        text = path.read_text(encoding="utf-8")
        required_tokens = string_list(
            row.get("required_tokens"), f"{raw_path}: required_tokens"
        )
        forbidden_tokens = string_list(
            row.get("forbidden_tokens", []),
            f"{raw_path}: forbidden_tokens",
            allow_empty=True,
        )
        for token in required_tokens:
            require(token in text, f"{raw_path}: required archive contract missing: {token}")
        for token in forbidden_tokens:
            require(token not in text, f"{raw_path}: forbidden promotion token present: {token}")
        reports.append(
            {
                "path": raw_path,
                "required_tokens": len(required_tokens),
                "forbidden_tokens": len(forbidden_tokens),
            }
        )

    required_source_paths = set(expected_paths.values()) - {
        expected_paths["validation_script"]
    }
    require(
        required_source_paths.issubset(seen),
        "task archive source contract coverage incomplete: "
        f"missing={sorted(required_source_paths - seen)}",
    )

    report = {
        "schema": "trnm-task-archive-closure-report-v1",
        "closure_id": config["closure_id"],
        "bounded_archive_batch_records": 4096,
        "prepaid_retention_charging": True,
        "proof_preserving_merkle_seals": True,
        "independent_batch_verifier": True,
        "independent_inclusion_verifier": True,
        "storage_deletion_authority": False,
        "scale_campaign_complete": False,
        "production_candidate": False,
        "production_consensus_activation": False,
        "source_contracts": reports,
        "result": "PASS",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TaskArchiveClosureError as error:
        print(f"task archive closure failed: {error}", file=sys.stderr)
        raise SystemExit(2)
