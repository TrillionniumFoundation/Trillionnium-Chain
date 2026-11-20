"""Source-bound native HIA peer lease journal owner build; no runtime proxy."""
from __future__ import annotations
import argparse, hashlib, json, os, struct, sys
from pathlib import Path
from hia.platform.build import Build as PinnedBuild, INPUTS as PINNED_INPUTS, inspect_executable
from hia.tools.toolchain import compose_source
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent

def need(value, message):
    if not value:
        raise ValueError(message)

def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def capture(path):
    need(path.is_file() and not path.is_symlink(), "Missing/nonregular source: " + str(path))
    for parent in path.parents:
        if parent == ROOT.parent:
            break
        need(not parent.is_symlink(), "Source ancestor symlink: " + str(parent))
    return path.read_bytes()

def source_capture():
    values = {}
    def add(path):
        raw = capture(path)
        name = path.relative_to(ROOT).as_posix()
        need(name not in values or values[name] == raw, "Source changed during capture")
        values[name] = raw
        return raw
    for path in sorted(HERE.iterdir()):
        if path.is_file() and path.suffix in {".py", ".rs", ".json", ".md", ".hepta"}:
            add(path)
    for name in PINNED_INPUTS:
        add(ROOT / "hia" / name)
    for name in ("hia/tools/toolchain.py", "hia/components.json", "hia/toolchain.lock.json",
                 "AGENTS.md", "PROJECT_ID", "PROJECT_BOUNDARY.json", "scripts/project-preflight.sh",
                 "scripts/ci/project_boundary.py", "config/portability-inventory-v1.json",
                 "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"):
        add(ROOT / name)
    policy, inputs = compose_source(HERE / "owner_policy.hepta")
    for path, raw in inputs:
        need(add(path) == raw, "Composed dependency changed")
    for path in sorted((ROOT / "trillionnium").rglob("*")):
        if any(part in {"target", "__pycache__"} for part in path.relative_to(ROOT).parts):
            continue
        if path.is_file():
            add(path)
    for name in ("trillionnium/Cargo.lock", "trillionnium/Cargo.toml"):
        add(ROOT / name)
    return values, policy

class Build:
    def __init__(self, output: Path):
        self.output = output.absolute()
        need(not self.output.exists() and not self.output.is_symlink(), "Fresh build output required")
        self.output.mkdir(parents=True, mode=0o700)
        self.pinned = PinnedBuild(self.output / "pinned-native")
        sys.path.insert(0, str(self.pinned.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        self.inputs, self.policy = source_capture()
        self.emitter = self.inputs["hia/platform/peer_lease_store/linux_emitter.hepta"]
        self.manifest = {k: identity(v) for k, v in sorted(self.inputs.items())}
        self.core = {}
        for name, raw in (("policy", self.policy), ("emitter", self.emitter)):
            doc = assemble_program(raw).as_dict()
            row = {"functions": len(doc["functions"]),
                   "ops": sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
                   "max_block_parameters": max(len(b["params"]) for f in doc["functions"] for b in f["blocks"])}
            need(row["functions"] <= 128 and row["ops"] <= 8192, "Unchanged native compiler profile exceeded")
            self.core[name] = row
        for name, raw in self.inputs.items():
            path = self.output / "source-snapshot" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.check()
    def check(self):
        self.pinned.check_pin()
        values, policy = source_capture()
        need(values == self.inputs and policy == self.policy, "Complete captured source closure changed")
    def current_inputs(self):
        values, _ = source_capture()
        return values
    def build(self):
        self.check()
        policy = self.pinned.stage(self.pinned.compiler, self.policy, "compile-policy")
        need(0 < len(policy) <= 1048576, "Native policy exceeds fixed compiler profile")
        writer = self.pinned.stage(self.pinned.compiler, self.emitter, "compile-emitter")
        inspect_executable(writer)
        prefix = self.pinned.stage(writer, struct.pack("<Q", len(policy)), "emit-prefix")
        need(176 <= len(prefix) <= 4096, "Native ELF prefix extent")
        executable = prefix + policy
        profile = inspect_executable(executable)
        for name, raw in (("native-compiler.elf", self.pinned.compiler), ("policy-composed.hepta", self.policy), ("policy.flat", policy),
                          ("emitter.elf", writer), ("elf-prefix.raw", prefix), ("owner.elf", executable)):
            (self.output / name).write_bytes(raw)
        self.check()
        report = {"schema": "trnm.hia.peer-lease-store-build.v1", "status": "PASS",
                  "source_inputs": self.manifest, "source_inputs_stable": True, "core": self.core,
                  "build_profile": "actual-native-build-after-complete-Core-admission", "actual_native_build_executed_here": True,
                  "policy": identity(policy), "emitter": identity(writer), "prefix": identity(prefix),
                  "executable": identity(executable) | profile,
                  "compiler": identity(self.pinned.compiler), "toolchain": self.pinned.lock,
                  "compiler_qualification_binding": self.pinned.binding, "stages": self.pinned.stages,
                  "hosted_link_action": "concatenate exact native-emitted prefix and native-compiled policy",
                  "literal_isa_is_separate_trusted_boundary": True, "runtime_host_proxy": False,
                  "rust_or_interpreter_fallback": False, "whole_peer_package_retired": False,
                  "unix_daemon_implemented": False, "core_authentication_implemented": False,
                  "production_activation": False}
        (self.output / "build.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        return executable, report

def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise RuntimeError("Optimized Python is not admitted")
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    _, report = Build(args.output).build()
    print(json.dumps({"status": report["status"], "core": report["core"], "executable": report["executable"]}))
if __name__ == "__main__":
    main()
