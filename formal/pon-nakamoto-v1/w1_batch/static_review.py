#!/usr/bin/env python3
"""Retain source-only review results. Never invokes rustc, a guest or a prover."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path: Path, value: bytes) -> None:
    with path.open("xb") as out:
        out.write(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("out", type=Path)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustfmt", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, CARGO_HOME=str(args.cargo_home), PYTHONDONTWRITEBYTECODE="1")
    relative = str(HERE.relative_to(ROOT))
    rust_files = sorted(str(path.relative_to(ROOT)) for path in HERE.rglob("*.rs"))
    commands = [
        ("public-controls", ["python3", f"{relative}/contract_controls.py"]),
        ("rustfmt", [str(args.rustfmt), "--check", "--edition", "2021", *rust_files]),
        ("host-metadata", [str(args.cargo), "metadata", "--offline", "--locked", "--no-deps",
                           "--format-version", "1", "--manifest-path", f"{relative}/Cargo.toml"]),
        ("guest-metadata", [str(args.cargo), "metadata", "--offline", "--locked", "--no-deps",
                            "--format-version", "1", "--manifest-path", f"{relative}/methods/guest/Cargo.toml"]),
    ]
    records = []
    for label, command in commands:
        started = time.monotonic()
        timed_out = False
        try:
            completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=60)
            stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code = error.stdout or b"", error.stderr or b"", None
            timed_out = True
        write_new(args.out / f"{label}.stdout", stdout)
        write_new(args.out / f"{label}.stderr", stderr)
        records.append({"name": label, "command": command, "returncode": code,
                        "timed_out": timed_out, "wall_seconds": time.monotonic() - started,
                        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                        "stderr_sha256": hashlib.sha256(stderr).hexdigest()})
    cache = args.cargo_home / "registry/cache/index.crates.io-1949cf8c6b5b557f"
    locks = []
    for path in (HERE / "Cargo.lock", HERE / "methods/guest/Cargo.lock"):
        packages = tomllib.loads(path.read_text())["package"]
        missing = [f"{row['name']}@{row['version']}" for row in packages
                   if row.get("source", "").startswith("registry+") and
                   not (cache / f"{row['name']}-{row['version']}.crate").is_file()]
        locks.append({"path": str(path.relative_to(ROOT)), "sha256": digest(path),
                      "packages": len(packages), "uncached_registry_archives": missing})
    broken = []
    for path in HERE.glob("*.md"):
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text()):
            if "://" not in target and not target.startswith("#"):
                if not (path.parent / target.split("#", 1)[0]).exists():
                    broken.append({"file": str(path.relative_to(ROOT)), "target": target})
    sources = [{"path": str(path.relative_to(ROOT)), "sha256": digest(path)}
               for path in sorted(HERE.rglob("*")) if path.is_file() and "__pycache__" not in path.parts]
    result = {
        "schema": "TRNM-W1-BATCH-SOURCE-REVIEW1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "commands": records, "locks": locks, "source_files": sources,
        "broken_local_markdown_links": broken,
        "source_checks_pass": all(row["returncode"] == 0 and not row["timed_out"] for row in records) and not broken,
        "rust_compilation_executed": False, "guest_execution_executed": False,
        "receipt_verification_executed": False, "prover_executed": False,
        "new_leaf_proofs": 0, "existing_unique_complete_leaf_proofs": 1,
        "benefit_gate": "UNMEASURED_BATCH_EXISTING_SINGLE_WORK_FAIL",
        "production_activation": False,
    }
    write_new(args.out / "result.json", (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({key: result[key] for key in (
        "schema", "source_checks_pass", "rust_compilation_executed", "guest_execution_executed",
        "receipt_verification_executed", "prover_executed", "benefit_gate")}, sort_keys=True))
    raise SystemExit(0 if result["source_checks_pass"] else 1)


if __name__ == "__main__":
    main()
