#!/usr/bin/env python3
"""Check complete ownership and refuse premature old-stack retirement."""
from pathlib import Path
import argparse
import hashlib
import json
import lzma

ROOT = Path(__file__).resolve().parents[2]


def compiler_qualification(revision):
    root = ROOT / "hia/qualification"
    binding = json.loads((root / "compiler-binding.json").read_text())
    if binding["toolchain_revision"] != revision or binding["whole_chain_native"] is not False:
        raise ValueError("Compiler qualification revision/scope differs")
    for key in ("outer_report", "nested_report"):
        name = binding[key]
        if not isinstance(name, str) or Path(name).name != name or (root / name).is_symlink():
            raise ValueError("Invalid compiler report path")
    raw = (root / binding["outer_report"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != binding["outer_sha256"]:
        raise ValueError("Cold report hash differs")
    outer = json.loads(raw)
    if (outer["status"] != "COLD_SELFHOST_REPLAY_PASS" or not all(outer["checks"].values())
            or outer["qualification_wall_limit_seconds"] != 180
            or outer["cleanup_wall_limit_seconds"] != 3
            or len(outer["source_manifest"]) != binding["source_inputs"]):
        raise ValueError("Original compiler cold qualification did not pass")
    compressed = (root / binding["nested_report"]).read_bytes()
    if hashlib.sha256(compressed).hexdigest() != binding["compressed_sha256"]:
        raise ValueError("Compressed compiler report hash differs")
    size = binding["uncompressed_bytes"]
    if type(size) is not int or not 0 < size <= 64 * 1024 * 1024:
        raise ValueError("Invalid compiler report size")
    with lzma.open(root / binding["nested_report"], "rb") as stream:
        nested = stream.read(size + 1)
    if (len(nested) != size or hashlib.sha256(nested).hexdigest() != binding["uncompressed_sha256"]
            or binding["uncompressed_sha256"] != outer["nested_report_sha256"]):
        raise ValueError("Full nested compiler report differs")
    observed = json.loads(nested)
    if (observed["status"] != "SELF_HOSTED_FIXED_CORE_PASS"
            or not observed["checks"] or not all(observed["checks"].values())):
        raise ValueError("Nested compiler checks did not all pass")
    return {"compiler_sha256": binding["compiler_sha256"],
            "outer_checks": len(outer["checks"]), "nested_checks": len(observed["checks"]),
            "wall_seconds": outer["wall_elapsed_ns"] / 1e9}


def check(require_retirement=False):
    inventory = json.loads((ROOT / "config/hia-migration-v1.json").read_text())
    portable = json.loads((ROOT / "config/portability-inventory-v1.json").read_text())
    lock = json.loads((ROOT / "hia/toolchain.lock.json").read_text())
    if inventory["schema"] != "trnm.hia.migration.v1" or inventory["baseline_toolchain"] != lock["revision"]:
        raise ValueError("Migration schema/toolchain identity differs")
    original = {row["package"]: row for row in portable["packages"]}
    rows = inventory["legacy_packages"]
    if len(rows) != len(original) or {row["package"] for row in rows} != set(original):
        raise ValueError("Migration inventory omitted or duplicated an original package")
    components = inventory["components"]
    ids = {row["id"] for row in components}
    if len(ids) != len(components):
        raise ValueError("Duplicate HIA component identity")
    paths = {p.relative_to(ROOT).as_posix() for p in (ROOT / "hia/src").rglob("*.hepta")}
    if {row["source"] for row in components} != paths:
        raise ValueError("HIA source inventory differs from the actual source tree")
    for component in components:
        for name in [component["source"], *component["tests"]]:
            path = ROOT / name
            if Path(name).is_absolute() or ".." in Path(name).parts or not path.is_file() or path.is_symlink():
                raise ValueError("Missing or aliased migration source/test: " + name)
    for row in rows:
        original_row = original[row["package"]]
        if row["legacy_path"] != original_row["path"] or row["module"] != original_row["module"]:
            raise ValueError("Original source ownership changed")
        if not set(row["components"]) <= ids:
            raise ValueError("Unknown component assigned to an original package")
        if row["retirement_accepted"] is not False or not (ROOT / row["legacy_path"]).is_dir():
            raise ValueError("This migration has no accepted full-package retirement witness")
    if (inventory["status"] != "IN_PROGRESS" or inventory["whole_chain_native"] is not False
            or inventory["old_stack_can_be_removed"] is not False
            or inventory["production_activation"] is not False
            or inventory["historical_failures_preserved"] is not True):
        raise ValueError("Unwitnessed whole-project completion or retirement claim")
    archive = ROOT / inventory["history_archive"]
    if not archive.is_file():
        raise ValueError("Missing retained history archive index")
    compiler = compiler_qualification(lock["revision"])
    if require_retirement:
        pending = [row["package"] for row in rows if not row["retirement_accepted"]]
        raise ValueError("Old stack retirement is not accepted: " + ", ".join(pending))
    return {"result": "PASS", "native_source_units": len(components),
            "legacy_packages_accounted_for": len(rows), "retired_packages": 0,
            "open_gates": [row["id"] for row in inventory["blocking_gates"] if row["state"] != "CLOSED"],
            "archive_index_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "retained_compiler_qualification": compiler,
            "whole_chain_native": False, "old_stack_can_be_removed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-retirement", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.require_retirement), sort_keys=True))
    except (ValueError, KeyError, OSError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
