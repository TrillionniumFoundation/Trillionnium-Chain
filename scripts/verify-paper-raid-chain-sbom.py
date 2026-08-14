#!/usr/bin/env python3
"""Verify canonical Paper Raid Chain release SBOM and dual-build provenance."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from paper_raid_chain_sbom_lib import EvidenceError, verify_artifacts


def mappings(values: list[str], label: str) -> dict[str, pathlib.Path]:
    result: dict[str, pathlib.Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path or name in result:
            raise EvidenceError(f"invalid or duplicate {label} mapping: {value!r}")
        result[name] = pathlib.Path(raw_path)
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--sbom", required=True, type=pathlib.Path)
    result.add_argument("--provenance", required=True, type=pathlib.Path)
    result.add_argument("--metadata", required=True, type=pathlib.Path)
    result.add_argument("--metadata-evidence", required=True, type=pathlib.Path)
    result.add_argument("--source", required=True, type=pathlib.Path)
    result.add_argument("--revision", required=True)
    result.add_argument("--tree", required=True)
    result.add_argument("--component-lock", required=True, type=pathlib.Path)
    result.add_argument("--producer-contract", required=True, type=pathlib.Path)
    result.add_argument("--cargo-version-evidence", required=True, type=pathlib.Path)
    result.add_argument("--rustc-version-evidence", required=True, type=pathlib.Path)
    result.add_argument("--binary-a", action="append", default=[])
    result.add_argument("--binary-b", action="append", default=[])
    result.add_argument("--tool", action="append", default=[])
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        hashes = verify_artifacts(
            sbom_path=arguments.sbom,
            provenance_path=arguments.provenance,
            metadata_path=arguments.metadata,
            metadata_evidence_path=arguments.metadata_evidence,
            source_root=arguments.source,
            revision=arguments.revision,
            source_tree=arguments.tree,
            component_lock_path=arguments.component_lock,
            producer_contract_path=arguments.producer_contract,
            cargo_version_path=arguments.cargo_version_evidence,
            rustc_version_path=arguments.rustc_version_evidence,
            binaries_a=mappings(arguments.binary_a, "build A binary"),
            binaries_b=mappings(arguments.binary_b, "build B binary"),
            tool_paths=mappings(arguments.tool, "tool"),
        )
    except EvidenceError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(hashes, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
