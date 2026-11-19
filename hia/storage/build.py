"""Source-bound hosted builder for the native streaming transaction owner.

It captures the explicit HIA closure and invokes the pinned native compiler and
HIA ELF writer. It never generates runtime instructions or services persistence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hia.tools.toolchain import checked_source, pinned_toolchain
from hia.platform.build import inspect_executable, new_output, require_success, run_native, write_json

HIA = ROOT / "hia"
STORAGE = HIA / "storage"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Build:
    def __init__(self, output: Path):
        self.output = output
        output.mkdir(mode=0o700)
        checked, self.policy, self.toolchain, self.lock, inputs = checked_source(STORAGE / "owner_policy.hepta")
        self.core = checked.as_dict()
        self.captured = dict(inputs)
        names = ("storage/README.md", "storage/abi.json", "storage/build.py",
                 "storage/linux_adapter_emitter.hepta", "tools/qualify_storage.py",
                 "tools/qualify_storage_recovery.py",
                 "platform/build.py", "tools/toolchain.py", "tests/native_support.py",
                 "toolchain.lock.json", "qualification/compiler-binding.json",
                 "qualification/compiler-cold.json", "qualification/compiler-cold-full.json.xz")
        names += tuple(p.relative_to(HIA).as_posix() for p in sorted((HIA / "tests").glob("test_storage_*.py")))
        for name in names:
            path = HIA / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("Missing or symlinked storage input: " + name)
            self.captured[path] = path.read_bytes()
        self.manifest = {p.relative_to(HIA).as_posix(): {"bytes": len(raw), "sha256": digest(raw)}
                         for p, raw in self.captured.items()}
        self.binding = json.loads(self.captured[HIA / "qualification/compiler-binding.json"])
        for name in ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256"):
            if not os.environ.get(name):
                raise RuntimeError("Explicit native compiler setting required: " + name)
        self.compiler_path = Path(os.environ["HIA_NATIVE_COMPILER"]).resolve(strict=True)
        self.compiler = self.compiler_path.read_bytes()
        if (self.lock["target"] != "x86_64-linux-gnu"
                or digest(self.compiler) != self.binding["compiler_sha256"]
                or os.environ["HIA_NATIVE_COMPILER_SHA256"] != self.binding["compiler_sha256"]
                or self.binding["toolchain_revision"] != self.lock["revision"]):
            raise ValueError("Compiler/target binding differs")
        outer = self.captured[HIA / "qualification" / self.binding["outer_report"]]
        nested = self.captured[HIA / "qualification" / self.binding["nested_report"]]
        if (digest(outer) != self.binding["outer_sha256"] or digest(nested) != self.binding["compressed_sha256"]
                or json.loads(outer)["status"] != "COLD_SELFHOST_REPLAY_PASS"):
            raise ValueError("Compiler qualification binding differs")
        self.stages = []
        self.check_pin()

    def check_pin(self) -> None:
        root, pin = pinned_toolchain()
        if root != self.toolchain or pin != self.lock or self.compiler_path.read_bytes() != self.compiler:
            raise ValueError("Source/compiler changed during storage qualification")
        for path, raw in self.captured.items():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
                raise ValueError("Storage source changed during qualification: " + str(path))

    def stage(self, program: bytes, payload: bytes, label: str) -> bytes:
        result, row = run_native(program, payload, self.output, label)
        self.stages.append(row)
        require_success(row)
        return result

    def build(self) -> dict:
        policy = self.stage(self.compiler, self.policy, "compile-policy")
        emitter = self.stage(self.compiler, self.captured[STORAGE / "linux_adapter_emitter.hepta"], "compile-emitter")
        inspect_executable(emitter)
        self.executable = self.stage(emitter, policy, "emit-storage-elf")
        profile = inspect_executable(self.executable)
        if not self.executable.endswith(policy) or not 0 < len(policy) <= 524288:
            raise ValueError("Emitted image must contain the exact compiled policy")
        for name, raw in (("policy.flat.bin", policy), ("emitter.elf", emitter), ("storage.elf", self.executable)):
            (self.output / name).write_bytes(raw)
        self.check_pin()
        declaration = json.loads(self.captured[HIA / "components.json"])["includes"]
        row = {"schema": "trnm.hia.storage-build.v2", "status": "PASS", "source_inputs": self.manifest,
               "compiler_sha256": digest(self.compiler), "compiler_qualification_binding": self.binding,
               "toolchain": self.lock, "stages": self.stages,
               "composition": {"mode": "explicit independently Core-verified named HIA function includes",
                               "declarations": {name: declaration[name] for name in declaration
                                                if HIA / name in self.captured},
                               "composed_source_sha256": digest(self.policy), "functions": len(self.core["functions"])},
               "executable": {"sha256": digest(self.executable), "bytes": len(self.executable), **profile},
               "source_inputs_stable": True, "hosted_build_and_test_driver": True,
               "runtime_host_language_or_sqlite": False,
               "literal_isa_adapter_is_a_separate_trusted_boundary": True, "whole_node_replaced": False}
        write_json(self.output / "build.json", row)
        return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = new_output(args.output)
    row = Build(output / "build").build()
    print(json.dumps({"status": row["status"], "executable": row["executable"], "output": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
