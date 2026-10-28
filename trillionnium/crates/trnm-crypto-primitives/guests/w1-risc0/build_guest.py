#!/usr/bin/env python3
"""Build the real, fixed W1 guest with an explicitly installed official compiler.

This does not install software, activate consensus, modify a reviewed image ID,
or produce a cryptographic proof. The image ID must be independently reviewed
and placed in backend-manifest.json before the host verifier accepts receipts.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", required=True, type=Path)
    parser.add_argument("--guest-rustc", required=True, type=Path)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--cargo-home", required=True, type=Path)
    parser.add_argument("--host-linker", type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--unlocked-bootstrap", action="store_true")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    repo = here.parents[4]
    manifest = json.loads((here / "backend-manifest.json").read_text())
    for relative, expected in manifest["guest_source_sha256"].items():
        path = (here / relative).resolve()
        if not path.is_relative_to(repo):
            raise SystemExit(f"source outside repository: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"unreviewed guest source: {relative}: {actual} != {expected}")
    environment = os.environ.copy()
    environment.pop("RUSTUP_TOOLCHAIN", None)
    environment["RUSTC"] = str(args.guest_rustc.resolve())
    environment["CARGO_HOME"] = str(args.cargo_home.resolve())
    environment["CARGO_TARGET_DIR"] = str(args.target_dir.resolve())
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_BUILD_JOBS"] = str(args.jobs)
    if args.host_linker is not None:
        environment["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"] = str(args.host_linker.resolve())
    environment["CARGO_PROFILE_RELEASE_DEBUG"] = "0"
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
        "-C", "passes=lower-atomic",
        "-C", "link-arg=-Ttext=0x00200800",
        "-C", "link-arg=--fatal-warnings",
        "-C", "panic=abort",
        "--cfg", 'getrandom_backend="custom"',
        "--remap-path-prefix", f"{repo}=/trnm",
        "--remap-path-prefix", f"{args.cargo_home.resolve()}=/cargo",
    ])
    command = [str(args.cargo.resolve()), "build", "--release", "--target",
               "riscv32im-risc0-zkvm-elf", "--manifest-path", str(here / "Cargo.toml"),
               "-p", "trnm-w1-risc0-guest"]
    if not args.unlocked_bootstrap:
        command.append("--locked")
    subprocess.run(command, env=environment, check=True)
    print(args.target_dir / "riscv32im-risc0-zkvm-elf/release/trnm-w1-risc0-guest")


if __name__ == "__main__":
    main()
