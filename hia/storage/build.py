"""Source-bound hosted builder for the native HIA transaction StoreOwner.

The driver only captures source, invokes the pinned native compiler, and invokes
the HIA ELF writer. It does not synthesize instructions or service runtime I/O.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

# Direct script execution must not depend on an ambient PYTHONPATH.
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hia.platform.build import inspect_executable, new_output, require_success, run_native, write_json

HIA = Path(__file__).resolve().parents[1]
STORAGE = HIA / "storage"
HELPERS = ("sha256_arena", "sha256_padding_byte", "sha256_rotr32", "sha256_work_load64", "sha256_work_store64")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def inputs() -> tuple[str, ...]:
    own = tuple("storage/" + p.name for p in sorted(STORAGE.iterdir())
                if p.is_file() and p.suffix in {".py", ".hepta", ".json", ".md"})
    tests = tuple(str(p.relative_to(HIA)) for p in sorted((HIA / "tests").glob("test_storage_*.py")))
    return own + tests + (
        "tools/qualify_storage.py", "platform/build.py", "tools/toolchain.py", "tests/native_support.py",
        "src/crypto/sha256_arena.hepta", "components.json",
        "toolchain.lock.json", "qualification/compiler-binding.json",
        "qualification/compiler-cold.json", "qualification/compiler-cold-full.json.xz",
    )


def source_manifest() -> dict:
    result = {}
    for name in inputs():
        path = HIA / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked storage input: " + name)
        raw = path.read_bytes()
        result[name] = {"bytes": len(raw), "sha256": digest(raw)}
    return result


def composed_policy(policy: bytes, sha_source: bytes) -> tuple[bytes, list[str]]:
    """Include exact named HIA functions, without generating an algorithm."""
    text = sha_source.decode("utf-8")
    functions = {}
    for match in re.finditer(r"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end\n", text):
        if match.group(1) in functions:
            raise ValueError("Duplicate SHA helper")
        functions[match.group(1)] = match.group(0)
    # The canonical SHA module deliberately exports f0 separately. Everything
    # after that entry consists of the closed helper set, included exactly once.
    names = [name for name in functions if name != "f0"]
    if names != list(HELPERS):
        raise ValueError("Canonical SHA helper interface changed: " + repr(names))
    if not policy.endswith(b"\n") or not policy.startswith(b"hia-asm.v1 hepta.hia.program.v8 "):
        raise ValueError("Unexpected owner policy text shape")
    return policy + "".join(functions[name] for name in names).encode(), names


class Build:
    def __init__(self, output: Path):
        self.output = output
        self.output.mkdir(mode=0o700)
        self.manifest = source_manifest()
        self.captured = {}
        for name in ("storage/owner_policy.hepta", "storage/linux_adapter_emitter.hepta", "src/crypto/sha256_arena.hepta"):
            raw = (HIA / name).read_bytes()
            if digest(raw) != self.manifest[name]["sha256"]:
                raise ValueError("Storage source changed during capture")
            self.captured[name] = raw
        self.lock = json.loads((HIA / "toolchain.lock.json").read_text())
        self.binding = json.loads((HIA / "qualification/compiler-binding.json").read_text())
        component_raw = (HIA / "components.json").read_bytes()
        if digest(component_raw) != self.manifest["components.json"]["sha256"]:
            raise ValueError("Component declaration changed during capture")
        self.component_declaration = json.loads(component_raw)["includes"].get("storage/owner_policy.hepta")
        if self.component_declaration != [{"source": "src/crypto/sha256_arena.hepta", "functions": list(HELPERS)}]:
            raise ValueError("Storage SHA include declaration differs from the explicit closed helper set")
        for name in ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256"):
            if not os.environ.get(name):
                raise RuntimeError("Explicit native compiler setting required: " + name)
        self.toolchain = Path(os.environ["HIA_TOOLCHAIN_ROOT"]).resolve(strict=True)
        self.compiler_path = Path(os.environ["HIA_NATIVE_COMPILER"]).resolve(strict=True)
        self.compiler = self.compiler_path.read_bytes()
        if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
            raise RuntimeError("Storage owner currently requires Linux x86-64")
        if (self.lock["target"] != "x86_64-linux-gnu"
                or digest(self.compiler) != self.binding["compiler_sha256"]
                or os.environ["HIA_NATIVE_COMPILER_SHA256"] != self.binding["compiler_sha256"]
                or self.binding["toolchain_revision"] != self.lock["revision"]):
            raise ValueError("Compiler/target binding differs")
        outer = (HIA / "qualification" / self.binding["outer_report"]).read_bytes()
        nested = (HIA / "qualification" / self.binding["nested_report"]).read_bytes()
        if (digest(outer) != self.binding["outer_sha256"] or digest(nested) != self.binding["compressed_sha256"]
                or json.loads(outer)["status"] != "COLD_SELFHOST_REPLAY_PASS"):
            raise ValueError("Compiler qualification binding differs")
        self.stages = []
        self.check_pin()

    def check_pin(self) -> None:
        head = subprocess.check_output(["git", "-C", str(self.toolchain), "rev-parse", "HEAD"], text=True, timeout=10).strip()
        dirty = subprocess.check_output(["git", "-C", str(self.toolchain), "status", "--porcelain=v1", "--untracked-files=no"], timeout=10)
        if head != self.lock["revision"] or dirty:
            raise ValueError("Pinned toolchain must be exact and tracked-clean")
        if self.compiler_path.read_bytes() != self.compiler or source_manifest() != self.manifest:
            raise ValueError("Source/compiler changed during storage qualification")

    def stage(self, program: bytes, payload: bytes, label: str) -> bytes:
        result, row = run_native(program, payload, self.output, label)
        self.stages.append(row)
        require_success(row)
        return result

    def build(self) -> dict:
        policy_source, included = composed_policy(self.captured["storage/owner_policy.hepta"], self.captured["src/crypto/sha256_arena.hepta"])
        policy = self.stage(self.compiler, policy_source, "compile-policy")
        emitter = self.stage(self.compiler, self.captured["storage/linux_adapter_emitter.hepta"], "compile-emitter")
        inspect_executable(emitter)
        self.executable = self.stage(emitter, policy, "emit-storage-elf")
        profile = inspect_executable(self.executable)
        if not self.executable.endswith(policy) or not 0 < len(policy) <= 524288:
            raise ValueError("Emitted image must contain the exact compiled policy")
        for name, raw in (("policy.flat.bin", policy), ("emitter.elf", emitter), ("storage.elf", self.executable)):
            (self.output / name).write_bytes(raw)
        self.check_pin()
        row = {"schema": "trnm.hia.storage-build.v1", "status": "PASS", "source_inputs": self.manifest,
               "compiler_sha256": digest(self.compiler), "compiler_qualification_binding": self.binding,
               "toolchain": self.lock, "stages": self.stages,
               "composition": {"mode": "explicit exact named HIA function includes", "source": "src/crypto/sha256_arena.hepta",
                               "functions": included, "declaration": self.component_declaration,
                               "components_manifest_sha256": self.manifest["components.json"]["sha256"],
                               "composed_source_sha256": digest(policy_source)},
               "executable": {"sha256": digest(self.executable), "bytes": len(self.executable), **profile},
               "hosted_build_and_test_driver": True, "runtime_host_language_or_sqlite": False,
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
