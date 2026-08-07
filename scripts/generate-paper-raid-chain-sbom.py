#!/usr/bin/env python3
"""Generate deterministic Paper Raid Chain CycloneDX and provenance evidence."""

from __future__ import annotations

import argparse
import os
import pathlib
import sys

from paper_raid_chain_sbom_lib import EvidenceError, build_artifacts, canonical_json


def mappings(values: list[str], label: str) -> dict[str, pathlib.Path]:
    result: dict[str, pathlib.Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path or name in result:
            raise EvidenceError(f"invalid or duplicate {label} mapping: {value!r}")
        result[name] = pathlib.Path(raw_path)
    return result


def write_new(path: pathlib.Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise EvidenceError(f"refusing to overwrite evidence output {path}: {error}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--metadata", required=True, type=pathlib.Path)
    result.add_argument("--source", required=True, type=pathlib.Path)
    result.add_argument("--revision", required=True)
    result.add_argument("--tree", required=True)
    result.add_argument("--component-lock", required=True, type=pathlib.Path)
    result.add_argument("--cargo-version-evidence", required=True, type=pathlib.Path)
    result.add_argument("--rustc-version-evidence", required=True, type=pathlib.Path)
    result.add_argument("--binary-a", action="append", default=[])
    result.add_argument("--binary-b", action="append", default=[])
    result.add_argument("--tool", action="append", default=[])
    result.add_argument("--output", required=True, type=pathlib.Path)
    result.add_argument("--provenance-output", required=True, type=pathlib.Path)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        sbom, provenance = build_artifacts(
            metadata_path=arguments.metadata,
            source_root=arguments.source,
            revision=arguments.revision,
            source_tree=arguments.tree,
            component_lock_path=arguments.component_lock,
            cargo_version_path=arguments.cargo_version_evidence,
            rustc_version_path=arguments.rustc_version_evidence,
            binaries_a=mappings(arguments.binary_a, "build A binary"),
            binaries_b=mappings(arguments.binary_b, "build B binary"),
            tool_paths=mappings(arguments.tool, "tool"),
        )
        write_new(arguments.output, canonical_json(sbom))
        write_new(arguments.provenance_output, canonical_json(provenance))
    except EvidenceError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
