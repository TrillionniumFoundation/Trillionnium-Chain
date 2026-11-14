#!/usr/bin/env python3
"""Exercise the real Cargo cache across refused/qualified compiler-path changes.

This checks a build-fence recovery contract. It neither runs a SQLite operation
nor qualifies a public service, dependency provenance, or a reusable build owner.
All four commands share a fresh target directory; no clean or source edit occurs
between them. Two additional loader-path refusal/recovery controls use that same
cache, with their denominator retained separately. Failed commands and every
emitted build-script output are retained.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time


PINNED_TOOLCHAIN = "1.95.0"
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


def executable_identity(path):
    resolved = path.resolve(strict=True)
    raw = resolved.read_bytes()
    return {"requested_path": str(path), "resolved_path": str(resolved),
            "bytes": len(raw), "sha256": digest(raw)}


def inspect_launcher(args, environment):
    """Observe the installed launcher; never assume its version or install a toolchain."""
    identity = {"toolchain": PINNED_TOOLCHAIN, "commands": [], "matched": True,
                "executables": {name: executable_identity(getattr(args, name))
                                for name in ("rustup", "cargo", "rustc")}}
    probes = [("version", [str(args.rustup), "--version"])]
    probes.extend((name, [str(args.rustup), "which", "--toolchain",
                          PINNED_TOOLCHAIN, name]) for name in ("cargo", "rustc"))
    for label, command in probes:
        try:
            result = subprocess.run(command, cwd=args.root, env=environment,
                                    capture_output=True, text=True, check=False, timeout=20)
            record = {"label": label, "argv": command, "exit_code": result.returncode,
                      "stdout": result.stdout, "stderr": result.stderr}
            valid = result.returncode == 0
            if label != "version":
                # The launcher must select the exact executables already supplied
                # by the caller; an alternate toolchain or Cargo fallback is refused.
                valid = valid and result.stdout.strip() == str(getattr(args, label))
            else:
                valid = valid and bool(result.stdout.strip())
            record["matched"] = valid
        except (OSError, subprocess.TimeoutExpired) as error:
            record = {"label": label, "argv": command, "matched": False,
                      "error": str(error)}
        identity["commands"].append(record)
        identity["matched"] = identity["matched"] and record["matched"]
    return identity


def phase_environment(base, rustc, foreign_loader=None):
    environment = base.copy()
    environment["RUSTC"] = rustc
    if foreign_loader is not None:
        # Add only an intentionally foreign empty directory. Preserve every
        # inherited entry, including an explicitly empty value, for rejection.
        suffix = str(foreign_loader)
        if "LD_LIBRARY_PATH" in environment:
            suffix = environment["LD_LIBRARY_PATH"] + os.pathsep + suffix
        environment["LD_LIBRARY_PATH"] = suffix
    return environment


def phase_passed(exit_code, outputs, expected, foreign_loader, previous_outputs):
    if exit_code != 0 or len(outputs) != 1:
        return False
    observed = outputs[0]
    passed = observed["watches_rustc"] and observed["qualified"] == expected
    reason = observed["unqualified_reason"]
    if expected:
        passed = passed and reason is None
    elif foreign_loader is None:
        passed = passed and "RUSTC must be absolute" in (reason or "")
    else:
        passed = passed and str(foreign_loader) in (reason or "")
        passed = passed and any(message in (reason or "") for message in (
            "extra Cargo loader directory:", "unknown or duplicate Cargo loader directory:"))
    if previous_outputs is not None and len(previous_outputs) == 1:
        passed = passed and observed["mtime_ns"] != previous_outputs[0]["mtime_ns"]
    return bool(passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustup", type=Path, required=True)
    args = parser.parse_args()
    for path in (args.root, args.output, args.target, args.rustc, args.cargo, args.rustup):
        if not path.is_absolute():
            parser.error("all paths must be absolute")
    if (args.rustc.name != "rustc" or not args.rustc.is_file()
            or not args.cargo.is_file() or not args.rustup.is_file()):
        parser.error("provide the real pinned rustc, cargo and installed rustup executables")
    if args.output.exists() or args.target.exists():
        parser.error("output and isolated target must both be fresh; retain old attempts")
    args.output.mkdir(parents=True)
    args.target.mkdir(parents=True)
    command = [str(args.rustup), "run", PINNED_TOOLCHAIN, "cargo",
               "check", "--offline", "--locked", "--manifest-path",
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
    launcher = inspect_launcher(args, environment)
    launcher["inherited_loader_path"] = {
        "present": "LD_LIBRARY_PATH" in os.environ,
        "value": os.environ.get("LD_LIBRARY_PATH"),
    }
    launcher["selected_loader_path_seed"] = str(toolchain_lib)
    write_json(args.output / "launcher.json", launcher)
    if not launcher["matched"]:
        final = source_identity(args.root)
        write_json(args.output / "source-after.json", final)
        write_json(args.output / "summary.json", {
            "schema": "trnm-sqlite-build-requalification-v1", "passed": False,
            "source_unchanged": initial == final, "commands": [], "loader_controls": [],
            "required_original_commands": 4, "required_loader_controls": 2,
            "launcher_matched": False, "blocked_before_execution": "launcher identity mismatch",
            "target_cleaned_between_phases": False, "sqlite_operations_executed": False,
            "public_service_qualified": False, "dependency_provenance_qualified": False,
        })
        return 1
    foreign_loader = (args.output / "foreign-loader").resolve()
    foreign_loader.mkdir()
    phases = [("refuse-1", "rustc", False), ("qualify-1", str(args.rustc), True),
              ("refuse-2", "rustc", False), ("qualify-2", str(args.rustc), True)]
    original_count = len(phases)
    phases.extend([("foreign-loader-refuse", str(args.rustc), False),
                   ("foreign-loader-restore", str(args.rustc), True)])
    records = []
    for label, rustc, expected in phases:
        injected = foreign_loader if label == "foreign-loader-refuse" else None
        selected_rustc = "rustc" if rustc == "rustc" else str(rustc_binary)
        phase_env = phase_environment(environment, selected_rustc, injected)
        start = time.monotonic_ns()
        usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        log_path = args.output / f"{label}.log"
        with log_path.open("xb") as log:
            result = subprocess.run(command, cwd=args.root, env=phase_env,
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
                "watches_loader_path": b"cargo:rerun-if-env-changed=LD_LIBRARY_PATH\n" in raw,
                "qualified": b"cargo:rustc-cfg=trnm_sqlite_layout_witness\n" in raw,
                "unqualified_reason": next((line for line in raw.decode().splitlines()
                                            if "UNQUALIFIED:" in line), None),
            })
        previous = records[-1]["build_outputs"] if records else None
        passed = phase_passed(result.returncode, outputs, expected, injected, previous)
        if len(records) >= original_count:
            passed = passed and len(outputs) == 1 and outputs[0]["watches_loader_path"]
        raw_log = log_path.read_bytes()
        record = {
            "label": label, "argv": command, "rustc": selected_rustc,
            "loader_path_seed": str(toolchain_lib),
            "group": "original" if len(records) < original_count else "foreign-loader",
            "loader_input": {"present": "LD_LIBRARY_PATH" in phase_env,
                             "value": phase_env.get("LD_LIBRARY_PATH")},
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
    final_executables = {name: executable_identity(getattr(args, name))
                         for name in ("rustup", "cargo", "rustc")}
    write_json(args.output / "executables-after.json", final_executables)
    executables_unchanged = final_executables == launcher["executables"]
    original_records = records[:original_count]
    loader_records = records[original_count:]
    original_passed = len(original_records) == 4 and all(row["passed"] for row in original_records)
    loader_passed = len(loader_records) == 2 and all(row["passed"] for row in loader_records)
    passed = original_passed and loader_passed and initial == final and executables_unchanged
    write_json(args.output / "summary.json", {
        "schema": "trnm-sqlite-build-requalification-v1", "passed": passed,
        "source_unchanged": initial == final, "commands": original_records,
        "loader_controls": loader_records, "required_original_commands": 4,
        "required_loader_controls": 2, "original_phases_passed": original_passed,
        "loader_controls_passed": loader_passed, "launcher_matched": True,
        "executables_unchanged": executables_unchanged,
        "target_cleaned_between_phases": False, "sqlite_operations_executed": False,
        "public_service_qualified": False, "dependency_provenance_qualified": False,
    })
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
