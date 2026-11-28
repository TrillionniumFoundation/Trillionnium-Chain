"""Hosted, source-bound builder for the finite HIA Linux platform fixture.

All runtime instructions come from the two HIA sources and the explicitly
pinned native compiler. This driver does not assemble or synthesize ISA bytes.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import time

HIA = Path(__file__).resolve().parents[1]
PLATFORM = HIA / "platform"
BUILD_SECONDS = 30
CLEANUP_SECONDS = 3
INPUTS = (
    "platform/README.md", "platform/abi.json", "platform/build.py",
    "platform/probe_policy.hepta", "platform/linux_adapter_emitter.hepta",
    "tools/qualify_platform.py", "tests/test_platform_cleanup.py", "toolchain.lock.json",
    "qualification/compiler-binding.json", "qualification/compiler-cold.json",
    "qualification/compiler-cold-full.json.xz",
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def source_manifest() -> dict:
    rows = {}
    for relative in INPUTS:
        path = HIA / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked fixture input: " + relative)
        raw = path.read_bytes()
        rows[relative] = {"bytes": len(raw), "sha256": sha256(raw)}
    return rows


def new_output(path: Path) -> Path:
    path = path.absolute()
    resolved = path.resolve()
    if resolved == HIA or HIA in resolved.parents:
        raise ValueError("Generated artifacts must be outside the HIA source tree")
    if path.exists() or path.is_symlink():
        raise FileExistsError("Use a fresh output directory: " + str(path))
    path.mkdir(parents=True, mode=0o700)
    return path.resolve()


def sealed_executable(raw: bytes, label: str) -> int:
    fd = os.memfd_create(label, os.MFD_ALLOW_SEALING)
    try:
        cursor = 0
        while cursor < len(raw):
            count = os.write(fd, raw[cursor:])
            if count <= 0:
                raise OSError("Short executable capture")
            cursor += count
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), 15)
        return fd
    except BaseException:
        os.close(fd)
        raise


def run_native(raw: bytes, payload: bytes, output: Path, label: str,
               *, timeout: float = BUILD_SECONDS) -> tuple[bytes, dict]:
    """Execute exact sealed bytes; preserve refusals and bounded cleanup."""
    case = output / label
    case.mkdir(mode=0o700)
    (case / "stdin.raw").write_bytes(payload)
    fd = sealed_executable(raw, label)
    argv = ["/proc/self/fd/" + str(fd)]
    start = time.monotonic_ns()
    cleanup = None
    timed_out = False
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=case,
            env={"PATH": ""}, pass_fds=(fd,), start_new_session=True, umask=0o077)
    finally:
        os.close(fd)
    try:
        stdout, stderr = process.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        cleanup_start = time.monotonic_ns()
        try:
            os.killpg(process.pid, signal.SIGKILL)
            signal_outcome = "sent"
        except ProcessLookupError:
            # The timeout and natural exit can race. Reap and retain the real
            # result/output; ESRCH does not turn the observed timeout into PASS.
            signal_outcome = "already_exited"
        stdout, stderr = process.communicate(timeout=CLEANUP_SECONDS)
        cleanup = {"signal": "SIGKILL", "complete": process.returncode is not None,
                   "signal_outcome": signal_outcome,
                   "elapsed_ns": time.monotonic_ns() - cleanup_start}
    end = time.monotonic_ns()
    (case / "stdout.raw").write_bytes(stdout)
    (case / "stderr.raw").write_bytes(stderr)
    row = {"stage": label, "argv": argv, "cwd": str(case), "environment": {"PATH": ""},
        "executable_sha256": sha256(raw), "executable_bytes": len(raw),
        "input_sha256": sha256(payload), "input_bytes": len(payload),
        "output_sha256": sha256(stdout), "output_bytes": len(stdout),
        "stderr_sha256": sha256(stderr), "stderr_hex": stderr.hex(),
        "exit_code": process.returncode, "timed_out": timed_out,
        "wall_limit_seconds": timeout, "cleanup_limit_seconds": CLEANUP_SECONDS,
        "cleanup": cleanup, "start_monotonic_ns": start, "end_monotonic_ns": end}
    write_json(case / "receipt.json", row)
    return stdout, row


def require_success(row: dict) -> None:
    if row["timed_out"] or row["exit_code"] != 0 or row["stderr_hex"]:
        raise RuntimeError("Native stage refused; preserved receipt: " + row["cwd"])


def inspect_executable(raw: bytes) -> dict:
    """Check the exact static ELF profile used by this finite fixture.

    This structural check does not prove the semantics of machine instructions.
    """
    if len(raw) < 176:
        raise ValueError("Truncated ELF")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    expected = (b"\x7fELF\x02\x01\x01" + bytes(9), 2, 62, 1,
                0x4000B0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    if header != expected:
        raise ValueError("ELF header differs from the static fixture profile")
    load = struct.unpack_from("<IIQQQQQQ", raw, 64)
    stack = struct.unpack_from("<IIQQQQQQ", raw, 120)
    if load != (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096):
        raise ValueError("ELF must contain one exact RX load segment")
    if stack != (0x6474E551, 6, 0, 0, 0, 0, 0, 16):
        raise ValueError("ELF must declare a non-executable RW stack")
    return {"format": "ELF64LE", "machine": "x86_64", "type": "ET_EXEC",
            "entry": 0x4000B0, "load_flags": "RX", "stack_flags": "RW",
            "interpreter": None, "dynamic_linker": False,
            "instruction_semantics_verified_by_this_check": False}


class Build:
    def __init__(self, output: Path):
        self.output = output
        self.output.mkdir(mode=0o700)
        self.manifest = source_manifest()
        self.sources = {}
        for name in ("probe_policy.hepta", "linux_adapter_emitter.hepta"):
            raw = (PLATFORM / name).read_bytes()
            if sha256(raw) != self.manifest["platform/" + name]["sha256"]:
                raise ValueError("HIA source changed during input capture")
            self.sources[name] = raw
        self.lock = json.loads((HIA / "toolchain.lock.json").read_text())
        self.binding = json.loads((HIA / "qualification/compiler-binding.json").read_text())
        for name in ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256"):
            if not os.environ.get(name):
                raise RuntimeError("Required explicit native toolchain setting: " + name)
        self.toolchain = Path(os.environ["HIA_TOOLCHAIN_ROOT"]).resolve(strict=True)
        self.compiler_path = Path(os.environ["HIA_NATIVE_COMPILER"]).resolve(strict=True)
        self.compiler = self.compiler_path.read_bytes()
        if (self.lock["target"] != "x86_64-linux-gnu"
                or platform.system() != "Linux"
                or platform.machine().lower() not in {"x86_64", "amd64"}):
            raise RuntimeError("The fixture requires the locked Linux x86-64 target")
        expected = self.binding["compiler_sha256"]
        if (sha256(self.compiler) != expected
                or os.environ["HIA_NATIVE_COMPILER_SHA256"] != expected
                or self.binding["toolchain_revision"] != self.lock["revision"]):
            raise ValueError("Native compiler or qualification pin differs")
        outer = (HIA / "qualification" / self.binding["outer_report"]).read_bytes()
        nested = (HIA / "qualification" / self.binding["nested_report"]).read_bytes()
        if (sha256(outer) != self.binding["outer_sha256"]
                or sha256(nested) != self.binding["compressed_sha256"]
                or json.loads(outer)["status"] != "COLD_SELFHOST_REPLAY_PASS"):
            raise ValueError("Preserved compiler qualification binding differs")
        self.check_pin()
        self.stages = []

    def check_pin(self) -> None:
        head = subprocess.check_output(["git", "-C", str(self.toolchain), "rev-parse", "HEAD"],
                                       text=True, timeout=10).strip()
        dirty = subprocess.check_output(["git", "-C", str(self.toolchain), "status",
            "--porcelain=v1", "--untracked-files=no"], timeout=10)
        if head != self.lock["revision"] or dirty:
            raise ValueError("The locked upstream checkout must be exact and tracked-clean")
        if self.compiler_path.read_bytes() != self.compiler:
            raise ValueError("Native compiler changed during qualification")
        if source_manifest() != self.manifest:
            raise ValueError("A fixture input changed during qualification")

    def stage(self, executable: bytes, payload: bytes, label: str) -> bytes:
        result, receipt = run_native(executable, payload, self.output, label)
        self.stages.append(receipt)
        require_success(receipt)
        return result

    def build(self) -> dict:
        self.policy = self.stage(self.compiler, self.sources["probe_policy.hepta"],
                                 "compile-policy")
        self.emitter = self.stage(self.compiler,
            self.sources["linux_adapter_emitter.hepta"], "compile-emitter")
        emitter_format = inspect_executable(self.emitter)
        self.executable = self.stage(self.emitter, self.policy, "emit-platform-elf")
        executable_format = inspect_executable(self.executable)
        if not (0 < len(self.policy) <= 524288) or not self.executable.endswith(self.policy):
            raise ValueError("The emitted ELF does not contain the exact compiled policy image")
        for name, raw in (("policy.flat.bin", self.policy), ("emitter.elf", self.emitter),
                          ("platform.elf", self.executable)):
            (self.output / name).write_bytes(raw)
        self.check_pin()
        receipt = {"schema": "trnm.hia.platform-fixture-build.v1", "status": "PASS",
            "source_inputs": self.manifest, "toolchain": self.lock,
            "compiler_sha256": sha256(self.compiler),
            "compiler_qualification_binding": self.binding,
            "stages": self.stages,
            "policy": {"sha256": sha256(self.policy), "bytes": len(self.policy)},
            "emitter": {"sha256": sha256(self.emitter), "bytes": len(self.emitter), **emitter_format},
            "executable": {"sha256": sha256(self.executable), "bytes": len(self.executable),
                           **executable_format},
            "adapter_prefix_bytes_including_elf_header": len(self.executable) - len(self.policy),
            "runtime_host_language_or_dynamic_loader": False,
            "hosted_build_and_test_driver": True,
            "core_language_has_generic_syscall_opcode": False,
            "generic_runtime_or_durable_owner_qualified": False}
        write_json(self.output / "build.json", receipt)
        return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = new_output(args.output)
    build = Build(output / "build")
    result = build.build()
    print(json.dumps({"status": result["status"], "executable": result["executable"],
                      "report": str(build.output / "build.json")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
