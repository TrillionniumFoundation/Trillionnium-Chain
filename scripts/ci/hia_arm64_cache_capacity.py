#!/usr/bin/env python3
"""Independent ARM64 ELF runtime diagnostic, not the Chain migration gate."""
from __future__ import annotations

import ctypes
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import struct
import subprocess
import sys

PIN = "f33d8da316de8fdf27b504371f1a5310997ff548"
TARGET = "aarch64-unknown-linux-gnu"
RUST_COMMIT = "59807616e1fa2540724bfbac14d7976d7e4a3860"
SOURCE = "hia/src/data_availability/cache_capacity.hepta"
INPUTS = {
    SOURCE: "170a049cf300bb8c4ff5a165575ae5f824a225e2bac3840c19b7633147b9e033",
    "hia/tests/test_cache_capacity.py": "bb1a1ca8d17020fabed87e48373be53278e48f8cc17186270db6bd57f70a7a7e",
    "trillionnium/crates/trnm-data-availability/src/cell.rs": "e017968bf65b9f47605b9235a17f56b61c3c5c7a7e6a888528b1e9aa58b89d3c",
    "trillionnium/crates/trnm-data-availability/src/cell/cache_budget.rs": "a8f06ff894cc69a770a062728d6437fc1c1f50b4d695c48c5d39d3455813564a",
    "hia/toolchain.lock.json": "8aaacde67240008f4a241bdde99683dd360d648fa68ac84ab5b04461a16adc71",
}
ARCHIVAL_FILES = ("input.txt", "original.stdout", "hia.stdout", "native-driver.rs", "reference.rs")
EXPORTS = frozenset(("cache_max_wal_bytes", "cache_max_shm_bytes"))
DRIVER = r"""
use std::io::{self, BufRead};
extern "C" {
    fn cache_max_wal_bytes(d:u64,l:u64,c:u64,m:u64)->u64;
    fn cache_max_shm_bytes(d:u64,l:u64,c:u64,m:u64)->u64;
}
fn main() {
    for line in io::stdin().lock().lines() {
        let row = line.unwrap();
        let fields: Vec<u64> = row.split_whitespace().map(|v| v.parse().unwrap()).collect();
        let [d,l,c,m] = fields[..] else { panic!("expected four fields"); };
        let (w,s) = unsafe { (cache_max_wal_bytes(d,l,c,m), cache_max_shm_bytes(d,l,c,m)) };
        println!("{w} {s}");
    }
}
"""


def require(ok, why):
    if not ok:
        raise ValueError(why)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def run(argv, *, raw=None, cwd=None, timeout=20):
    p = subprocess.run(argv, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       cwd=cwd, check=False, timeout=timeout)
    require(p.returncode == 0 and not p.stderr and len(p.stdout) <= 262144,
            f"{argv[0]} failed: {p.returncode}; {p.stderr[:1000]!r}")
    return p.stdout


def git(root, *args):
    return run(["git", "-C", str(root), *args]).decode("ascii").strip()


def bound_sources(root, head):
    require(re.fullmatch(r"[0-9a-f]{40}", head) is not None and git(root, "rev-parse", "HEAD") == head,
            "candidate head mismatch")
    require(not git(root, "status", "--porcelain", "--untracked-files=no"), "dirty candidate")
    for rel, expected in INPUTS.items():
        p = root / rel
        require(p.is_file() and not p.is_symlink() and digest(p.read_bytes()) == expected,
                f"exact fixture/oracle source mismatch: {rel}")
    return git(root, "rev-parse", "HEAD^{tree}")


def require_arm():
    require(platform.system() == "Linux" and platform.machine() == "aarch64"
            and os.uname().machine == "aarch64" and sys.byteorder == "little"
            and ctypes.sizeof(ctypes.c_void_p) == 8
            and os.environ.get("RUNNER_ARCH") == "ARM64"
            and os.environ.get("RUNNER_OS") == "Linux", "actual hosted Linux AArch64 LP64 required")


def elf(raw, types):
    require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01", "not little-endian ELF64")
    kind, machine, version = struct.unpack_from("<HHI", raw, 16)
    require(machine == 183 and kind in types and version == 1, "wrong ELF target/type")
    return {"machine": machine, "type": kind, "sha256": digest(raw), "bytes": len(raw)}


def corpus():
    mn, mx, u = 2**18, 2**41, 2**64 - 1
    pages = {64, mx // 4096}
    for reg in (1, 2, 3, 17, 256, 131072):
        pages.update(reg * 4096 - 16 + d for d in (-1, 0, 1))
    rows = [(p * 4096, 1, 1, 1) for p in sorted(pages)]
    below = (4096 - 16) * 4096
    rows.extend(((mx, 2**40, 2**20, 2**20), (below, 1, 1, 1), (below + 4096, 1, 1, 1)))
    base = (mn, 1, 1, 1)
    controls = ((0, mn-4096, mn-1, mn+1, mx-1, mx+1, mx+4096, u-4095, u),
                (0, 2**40+1, u), (0, 2**20+1, u), (0, 2**20+1, u))
    rows += [base[:i] + (v,) + base[i+1:] for i, vs in enumerate(controls) for v in vs]
    rng = random.Random(0xCAB4)
    rows += [(rng.randrange(64, mx//4096+1)*4096, rng.randrange(1, 2**40+1),
              rng.randrange(1, 2**20+1), rng.randrange(1, 2**20+1)) for _ in range(256)]
    rows += [tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(256)]
    require(len(rows) == 553, "invalid fixed corpus")
    return "".join(" ".join(map(str, row)) + "\n" for row in rows).encode("ascii")


def compare(original, native):
    rows = original.splitlines()
    require(len(rows) == 553 and original.endswith(b"\n"), "short or malformed original transcript")
    require(all(re.fullmatch(rb"(0|[1-9][0-9]*) (0|[1-9][0-9]*)", line) for line in rows),
            "noncanonical output")
    require(all(int(x) < 2**64 for row in rows for x in row.split()), "output exceeds u64")
    require(rows[0] == b"329632 65536" and rows[20] == b"2211908223392 4295032832"
            and rows[23:41] == [b"0 0"] * 18 and rows[-256:] == [b"0 0"] * 256
            and all(x != b"0 0" for x in rows[41:-256]), "fixture positive/refusal controls differ")
    require(native == original, "actual AArch64 scalar runtime output differs")


def verify_packet(out, *, head, tree, run_id, attempt):
    p = out / "report.json"
    require(p.stat().st_size <= 131072, "oversized report")
    report = json.loads(p.read_bytes())
    require((report["schema"], report["status"], report["head"], report["tree"], report["run"], report["attempt"])
            == ("trnm-hia-arm64-cache-capacity-v1", "PASS_DIAGNOSTIC_ONLY", head, tree, run_id, attempt),
            "mismatched source/run/attempt readback")
    require(report["target"] == TARGET and report["host"][0] == "Linux"
            and report["host"][-1] == "aarch64" and report["runner_arch"] == "ARM64"
            and report["hepta_pin"] == PIN and report["source_sha256"] == INPUTS
            and report["whole_chain_gate"] is False
            and report["direct_x64_or_selfhost_parity"] is False,
            "unexpected target/source/scope")
    require(report["rows"] == 553 and report["scalar_comparisons"] == 1106, "incomplete comparison")
    files = {}
    for name in ARCHIVAL_FILES:
        p = out / name
        require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 65536, "invalid retained file")
        files[name] = p.read_bytes()
    require(report["raw_sha256"] == {k: digest(v) for k, v in files.items()}, "raw evidence hash mismatch")
    require(files["input.txt"] == corpus() and files["native-driver.rs"] == DRIVER.encode(), "wrong retained inputs")
    obj = out / "native.o"
    require(obj.is_file() and not obj.is_symlink() and obj.stat().st_size <= 65536, "invalid object artifact")
    require(elf(obj.read_bytes(), {1}) == report["binary"]["native.o"], "object binding mismatch")
    require(report["compiler"]["target"] == TARGET
            and report["compiler"]["cross_target_compilation"] is False
            and report["compiler"]["artifact_sha256"] == report["binary"]["native.o"]["sha256"],
            "unexpected compiler target or object binding")
    for name in ("reference", "native-driver"):
        require(report["binary"][name]["machine"] == 183 and report["binary"][name]["type"] in {2, 3},
                "wrong retained executable architecture")
    compare(files["original.stdout"], files["hia.stdout"])


def qualify(root, hepta, out, head):
    require_arm()
    tree = bound_sources(root, head)
    require(git(hepta, "rev-parse", "HEAD") == PIN
            and not git(hepta, "status", "--porcelain", "--untracked-files=no"), "toolchain pin mismatch")
    for env in ("CC", "CFLAGS", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "LD_PRELOAD", "LD_LIBRARY_PATH"):
        require(not os.environ.get(env), f"unsupported compiler override: {env}")
    rustc = Path(shutil.which("rustc")).resolve()
    clang = Path("/usr/bin/clang-20").resolve(strict=True)
    cc = Path("/usr/bin/gcc").resolve(strict=True)
    ld = Path("/usr/bin/ld").resolve(strict=True)
    versions = {str(p): run([p, "-vV" if p == rustc else "--version"]).decode()
                for p in (rustc, clang, cc, ld)}
    require(f"host: {TARGET}\n" in versions[str(rustc)] and f"commit-hash: {RUST_COMMIT}\n" in versions[str(rustc)]
            and "release: 1.95.0\n" in versions[str(rustc)], "wrong actual Rust pin/host")
    tools = {str(p): digest(p.read_bytes()) for p in (rustc, clang, cc, ld)}
    sys.path[:0] = [str(hepta), str(root)]
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
    from hepta.object_symbols import inspect_object_symbols
    require(Path(sys.modules["hepta"].__file__).resolve().parent == hepta / "hepta", "loaded wrong Hepta package")
    oracle = importlib.import_module("hia.tests.test_cache_capacity")
    require(Path(oracle.__file__).resolve() == root / "hia/tests/test_cache_capacity.py", "loaded wrong Rust generator")
    core = assemble_program((root / SOURCE).read_bytes())
    ir = emit_program_llvm(core, target=TARGET)
    require(set(ir.exports) == EXPORTS, "wrong scalar exports")
    obj = out / "native.o"
    commands = []
    receipt = compile_program_llvm(ir, program=core, output=obj, clang=str(clang),
                                   kind="object", command_log=commands)
    require(receipt["target"] == TARGET and receipt["cross_target_compilation"] is False,
            "wrong build host or target")
    symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 183)
    require(symbols["defined"] == EXPORTS and symbols["undefined"] <= {"abort"}, "unexpected native symbols")
    original = oracle.build_reference(out)
    driver = out / "native-driver.rs"
    driver.write_text(DRIVER)
    native = out / "native-driver"
    command = [str(rustc), "--edition=2021", "-C", "strip=symbols", "-C", f"linker={cc}",
               "-C", f"link-arg={obj}", str(driver), "-o", str(native)]
    run(command, timeout=30)
    binary = {p.name: elf(p.read_bytes(), {1} if p == obj else {2, 3}) for p in (obj, original, native)}
    data = corpus()
    expected, reported = run([original], raw=data), run([native], raw=data)
    compare(expected, reported)
    require_arm()
    require(bound_sources(root, head) == tree and git(hepta, "rev-parse", "HEAD") == PIN
            and not git(hepta, "status", "--porcelain", "--untracked-files=no"),
            "source changed during execution")
    require(all(digest(Path(p).read_bytes()) == h for p, h in tools.items())
            and all(digest((out / p).read_bytes()) == bind["sha256"] for p, bind in binary.items()), "tool/artifact changed")
    for name, body in {"input.txt": data, "original.stdout": expected, "hia.stdout": reported}.items():
        (out / name).write_bytes(body)
    values = {name: (out / name).read_bytes() for name in ARCHIVAL_FILES}
    # Keep the finite object, reproducible harness and raw output; executables are
    # hashed/inspected both sides, not attached to the compact public artifact.
    report = {"schema": "trnm-hia-arm64-cache-capacity-v1", "status": "PASS_DIAGNOSTIC_ONLY",
              "head": head, "tree": tree, "hepta_pin": PIN, "target": TARGET,
              "host": list(os.uname()), "runner_arch": os.environ["RUNNER_ARCH"],
              "run": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "source_sha256": INPUTS, "rows": 553, "scalar_comparisons": 1106,
              "tools": tools, "versions": versions, "binary": binary, "commands": commands,
              "driver_compile": command, "actual_invocations": [[str(original)], [str(native)]],
              "raw_sha256": {k: digest(v) for k, v in values.items()}, "compiler": receipt,
              "direct_x64_or_selfhost_parity": False, "whole_chain_gate": False}
    (out / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    verify_packet(out, head=head, tree=tree, run_id=os.environ["GITHUB_RUN_ID"], attempt=os.environ["GITHUB_RUN_ATTEMPT"])


if __name__ == "__main__":
    root, upstream, output = map(lambda v: Path(v).resolve(strict=True), sys.argv[1:4])
    require(len(sys.argv) == 5 and output.is_dir() and not any(output.iterdir()), "empty output directory required")
    qualify(root, upstream, output, sys.argv[4])
