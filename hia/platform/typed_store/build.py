"""Source-bound native streaming staging build; hosted code emits no ISA."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from hia.platform.build import Build as PinnedBuild, inspect_executable, sha256
from hia.tools.toolchain import compose_source

HIA = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RELATIVE = "platform/typed_store/"
SKIP = {"target", ".git", "__pycache__", ".pytest_cache"}

def file_identity(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or symlinked source: " + str(path))
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            size += len(block)
            digest.update(block)
    return {"bytes": size, "sha256": digest.hexdigest()}

def original_manifest(repository: Path) -> dict:
    result = {}
    for directory in ("trillionnium", "config", "formal"):
        for path in sorted((repository / directory).rglob("*")):
            relative = path.relative_to(repository)
            if any(part in SKIP for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError("Original source contains a symlink: " + str(relative))
            if path.is_file():
                result[relative.as_posix()] = file_identity(path)
    if "trillionnium/Cargo.lock" not in result:
        raise ValueError("Missing original Cargo graph")
    return result

def describe_core(document: dict) -> dict:
    return {"functions": len(document["functions"]),
        "blocks": sum(len(fn["blocks"]) for fn in document["functions"]),
        "ops": sum(len(block["ops"]) for fn in document["functions"] for block in fn["blocks"])}

def owned_functions(raw: bytes) -> dict[str, bytes]:
    names = re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw)
    matches = list(re.finditer(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw))
    result = {match.group(1).decode(): match.group(0) for match in matches}
    if len(names) != len(set(names)) or len(result) != len(names):
        raise ValueError("Ambiguous HIA function boundaries")
    return result

class Build:
    def __init__(self, output: Path, repository: Path):
        output.mkdir(mode=0o700)
        self.output = output
        self.repository = repository.resolve(strict=True)
        if HIA.resolve() != self.repository / "hia":
            raise ValueError("The builder must run from the requested repository")
        self.pinned = PinnedBuild(output / "pinned-native")
        self.inputs, self.paths, self.core, self.composed = {}, {}, {}, {}
        for path in sorted(HERE.iterdir()):
            if path.is_file() and path.suffix in {".py", ".rs", ".json", ".md", ".hepta"}:
                self.capture("hia/" + path.relative_to(HIA).as_posix(), path)
        for relative in ("platform/build.py", "tools/toolchain.py", "components.json",
                "platform/transport_request/rust_oracle.py", "tests/test_state_root.py",
                "toolchain.lock.json", "qualification/compiler-binding.json"):
            self.capture("hia/" + relative, HIA / relative)
        self.original = original_manifest(self.repository)
        sys.path.insert(0, str(self.pinned.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        self.assemble = assemble_program
        include = json.loads(self.inputs["hia/" + RELATIVE + "includes.json"])
        if set(include) != {"schema", "includes"} or include["schema"] != "trnm.hia.typed-stage-includes.v1":
            raise ValueError("Unsupported typed staging include schema")
        if set(include["includes"]) != {"stage_policy.hepta", "root_finalize.hepta"}:
            raise ValueError("Unexpected typed staging kernels")
        admitted = {}
        for name, rows in include["includes"].items():
            raw = self.inputs["hia/" + RELATIVE + name]
            selected = set(owned_functions(raw))
            blocks = [raw.rstrip() + b"\n"]
            for row in rows:
                if set(row) != {"source", "functions"} or not row["functions"]:
                    raise ValueError("Malformed explicit dependency declaration")
                relative = row["source"]
                if not isinstance(relative, str) or not relative.startswith("src/") or ".." in Path(relative).parts:
                    raise ValueError("Dependency path leaves the canonical HIA sources")
                path = HIA / relative
                if relative not in admitted:
                    combined, captured = compose_source(path)
                    checked = assemble_program(combined)
                    declared = owned_functions(path.read_bytes())
                    if not set(declared) <= {fn["name"] for fn in checked.as_dict()["functions"]}:
                        raise ValueError("Canonical dependency admission differs")
                    admitted[relative] = declared
                    for captured_path, captured_raw in captured:
                        self.capture("hia/" + captured_path.relative_to(HIA).as_posix(), captured_path, captured_raw)
                for function in row["functions"]:
                    if function not in admitted[relative] or function in selected:
                        raise ValueError("Unknown or duplicate explicit callee " + function)
                    selected.add(function)
                    blocks.append(admitted[relative][function].rstrip() + b"\n")
            combined = b"".join(blocks)
            self.core[name] = describe_core(assemble_program(combined).as_dict())
            self.composed[name] = combined
        emitter = self.inputs["hia/" + RELATIVE + "linux_stage_emitter.hepta"]
        self.core["linux_stage_emitter.hepta"] = describe_core(assemble_program(emitter).as_dict())
        self.manifest = {name: {"bytes": len(raw), "sha256": sha256(raw)}
            for name, raw in sorted(self.inputs.items())}
        self.check_sources()

    def capture(self, name: str, path: Path, admitted: bytes | None = None):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked source: " + name)
        raw = path.read_bytes()
        if admitted is not None and raw != admitted:
            raise ValueError("Source changed during independent admission: " + name)
        if name in self.inputs and self.inputs[name] != raw:
            raise ValueError("Inconsistent source capture: " + name)
        self.inputs[name], self.paths[name] = raw, path.resolve(strict=True)

    def check_sources(self):
        self.pinned.check_pin()
        for name, raw in self.inputs.items():
            if self.paths[name].is_symlink() or self.paths[name].read_bytes() != raw:
                raise ValueError("Typed staging source changed: " + name)
        if original_manifest(self.repository) != self.original:
            raise ValueError("Original source changed during native qualification")

    def build(self) -> tuple[bytes, dict]:
        self.check_sources()
        policy = self.pinned.stage(self.pinned.compiler, self.composed["stage_policy.hepta"], "compile-staging-policy")
        root = self.pinned.stage(self.pinned.compiler, self.composed["root_finalize.hepta"], "compile-root-finalize")
        emitter = self.pinned.stage(self.pinned.compiler,
            self.inputs["hia/" + RELATIVE + "linux_stage_emitter.hepta"], "compile-staging-emitter")
        inspect_executable(emitter)
        payload = struct.pack("<Q", len(policy)) + policy + root
        executable = self.pinned.stage(emitter, payload, "emit-staging-elf")
        elf = inspect_executable(executable)
        if not executable.endswith(policy + root):
            raise ValueError("The ELF does not contain both exact compiled HIA images")
        for name, raw in (("stage-policy.flat", policy), ("root-finalize.flat", root),
                ("staging-emitter.elf", emitter), ("staging.elf", executable),
                ("stage-policy-composed.hepta", self.composed["stage_policy.hepta"]),
                ("root-finalize-composed.hepta", self.composed["root_finalize.hepta"])):
            (self.output / name).write_bytes(raw)
        self.executable = executable
        self.check_sources()
        receipt = {"schema": "trnm.hia.typed-staging-build.v1", "status": "PASS",
            "source_inputs": self.manifest, "original_sources": self.original,
            "source_inputs_stable": True, "core": self.core,
            "toolchain": self.pinned.lock, "compiler_sha256": sha256(self.pinned.compiler),
            "compiler_qualification_binding": self.pinned.binding,
            "stages": self.pinned.stages,
            "policy": {"bytes": len(policy), "sha256": sha256(policy)},
            "root_finalize": {"bytes": len(root), "sha256": sha256(root)},
            "emitter": {"bytes": len(emitter), "sha256": sha256(emitter)},
            "executable": {"bytes": len(executable), "sha256": sha256(executable), **elf},
            "source_set_sha256": sha256(json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode()),
            "runtime_host_proxy": False, "interpreter_or_rust_fallback": False,
            "literal_isa_is_a_separate_trusted_boundary": True,
            "typed_namespace_or_atomic_commit_authority": False}
        (self.output / "build.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        return executable, receipt
