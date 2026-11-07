#!/usr/bin/env python3
"""Exercise the real Cargo cache across refused/qualified compiler-path changes.

This checks a build-fence recovery contract. It neither runs a SQLite operation
nor qualifies a public service, dependency provenance, or a reusable build owner.
All four commands share a fresh target directory; no clean or source edit occurs
between them. Failed commands and every emitted build-script output are retained.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time


PACKAGE = "trillionnium/crates/trnm-sqlite-io-boundary"
SOURCE_PATHS = (
    f"{PACKAGE}/Cargo.toml",
    f"{PACKAGE}/build.rs",
    f"{PACKAGE}/build_loader_paths.rs",
    f"{PACKAGE}/unix_layout_witness.c",
    "trillionnium/Cargo.lock",
    "scripts/ci/check_sqlite_build_requalification.py",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def source_identity(root):
    return {
        "head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "status": subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=root, text=True
        ),
        "files": {name: digest((root / name).read_bytes()) for name in SOURCE_PATHS},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.root, args.output, args.target, args.rustc, args.cargo):
        if not path.is_absolute():
            parser.error("all paths must be absolute")
    if args.rustc.name != "rustc" or not args.rustc.is_file() or not args.cargo.is_file():
        parser.error("provide the real pinned rustc and cargo executables")
    if args.output.exists() or args.target.exists():
        parser.error("output and isolated target must both be fresh; retain old attempts")
    args.output.mkdir(parents=True)
    args.target.mkdir(parents=True)
    command = [str(args.cargo), "check", "--offline", "--locked", "--manifest-path",
               "trillionnium/Cargo.toml", "-p", "trnm-sqlite-io-boundary"]
    environment = os.environ.copy()
    # Both spellings execute the same compiler; only its path spelling changes.
    rustc_binary = args.rustc.resolve()
    if rustc_binary.parent.name != "bin":
        parser.error("the pinned rustc must be the canonical toolchain bin/rustc")
    toolchain = rustc_binary.parent.parent.resolve()
    toolchain_lib = (toolchain / "lib").resolve()
    if not toolchain_lib.is_dir() or toolchain_lib.parent != toolchain:
        parser.error("the pinned toolchain must contain its canonical lib directory")
    environment["PATH"] = str(rustc_binary.parent) + os.pathsep + environment.get("PATH", "")
    environment["CARGO_TARGET_DIR"] = str(args.target)
    # Cargo adds target/deps and rustlib to each build-script loader path. Seed
    # only the canonical parent toolchain lib directory that Cargo 1.95 omits;
    # the native build fence verifies the complete exact set and rejects extras.
    environment["LD_LIBRARY_PATH"] = str(toolchain_lib)
    initial = source_identity(args.root)
    write_json(args.output / "source-before.json", initial)
    phases = [("refuse-1", "rustc", False), ("qualify-1", str(args.rustc), True),
              ("refuse-2", "rustc", False), ("qualify-2", str(args.rustc), True)]
    records = []
    for label, rustc, expected in phases:
        environment["RUSTC"] = "rustc" if rustc == "rustc" else str(rustc_binary)
        start = time.monotonic_ns()
        usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        log_path = args.output / f"{label}.log"
        with log_path.open("xb") as log:
            result = subprocess.run(command, cwd=args.root, env=environment,
                                    stdout=log, stderr=subprocess.STDOUT, check=False)
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        outputs = []
        for output in sorted((args.target / "debug/build").glob(
                "trnm-sqlite-io-boundary-*/output")):
            raw = output.read_bytes()
            copy = f"{label}-{output.parent.name}.txt"
            with (args.output / copy).open("xb") as retained:
                retained.write(raw)
            outputs.append({
                "path": str(output), "retained": copy, "sha256": digest(raw),
                "mtime_ns": output.stat().st_mtime_ns,
                "watches_rustc": b"cargo:rerun-if-env-changed=RUSTC\n" in raw,
                "qualified": b"cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in raw,
                "unqualified_reason": next((line for line in raw.decode().splitlines()
                                            if "UNQUALIFIED:" in line), None),
            })
        expected_reason = "RUSTC must be absolute"
        passed = result.returncode == 0 and len(outputs) == 1
        if passed:
            observed = outputs[0]
            passed = observed["watches_rustc"] and observed["qualified"] == expected
            passed = passed and (observed["unqualified_reason"] is None if expected else
                                 expected_reason in (observed["unqualified_reason"] or ""))
            if records and len(records[-1]["build_outputs"]) == 1:
                passed = passed and observed["mtime_ns"] != records[-1]["build_outputs"][0]["mtime_ns"]
        raw_log = log_path.read_bytes()
        record = {
            "label": label, "argv": command, "rustc": rustc,
            "loader_path_seed": str(toolchain_lib),
            "exit_code": result.returncode, "passed": bool(passed),
            "wall_ns": time.monotonic_ns() - start,
            "waited_child_cpu_seconds": usage_after.ru_utime + usage_after.ru_stime
            - usage_before.ru_utime - usage_before.ru_stime,
            "log_sha256": digest(raw_log), "log_bytes": len(raw_log),
            "build_outputs": outputs,
        }
        records.append(record)
        write_json(args.output / f"{label}.json", record)
        print(json.dumps({"phase": label, "passed": bool(passed), "exit": result.returncode}),
              flush=True)
    final = source_identity(args.root)
    write_json(args.output / "source-after.json", final)
    passed = all(record["passed"] for record in records) and initial == final
    write_json(args.output / "summary.json", {
        "schema": "trnm-sqlite-build-requalification-v1", "passed": passed,
        "source_unchanged": initial == final, "commands": records,
        "target_cleaned_between_phases": False, "sqlite_operations_executed": False,
        "public_service_qualified": False, "dependency_provenance_qualified": False,
    })
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
