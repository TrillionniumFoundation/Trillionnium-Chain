"""Pinned hosted build for the HIA stream reactor and its HIA API fixture.

The driver captures source, checks Core syntax/types, and invokes the qualified
native compiler and HIA emitter. It never assembles runtime instructions.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

HIA = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(HIA.parent))
from hia.platform.build import Build as FixtureBuild
from hia.platform.build import inspect_executable, new_output, sha256, write_json

HERE = Path(__file__).resolve().parent
INPUTS = (
    "platform/reactor/README.md", "platform/reactor/abi.json",
    "platform/reactor/build.py", "platform/reactor/qualify.py",
    "platform/reactor/policy.hepta", "platform/reactor/linux_emitter.hepta",
    "platform/reactor/context_fixture.hepta", "platform/reactor/api_fixture.hepta",
    "platform/reactor/contracts.py", "tests/test_platform_reactor_contracts.py",
    "tests/test_platform_reactor_cleanup.py",
)


def source_manifest() -> dict:
    rows = {}
    for relative in INPUTS:
        path = HIA / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked reactor source: " + relative)
        raw = path.read_bytes()
        rows[relative] = {"sha256": sha256(raw), "bytes": len(raw)}
    return rows


def compose_fixture(canonical: bytes, fixture: bytes) -> tuple[bytes, dict]:
    """Replace only f0; append the exact canonical helper bytes unchanged."""
    pattern = rb"^fn ([A-Za-z_][A-Za-z_0-9]*)\("
    functions = list(re.finditer(pattern, canonical, re.MULTILINE))
    wrappers = list(re.finditer(pattern, fixture, re.MULTILINE))
    if (len(functions) < 2 or functions[0].group(1) != b"f0"
            or any(not row.group(1).startswith(b"reactor_") for row in functions[1:])
            or len(wrappers) != 1 or wrappers[0].group(1) != b"f0"
            or not fixture.startswith(b"hia-asm.v1 hepta.hia.program.v8 ")
            or not fixture.endswith(b"\n")):
        raise ValueError("Unexpected explicit reactor package function inventory")
    helpers = canonical[functions[1].start():]
    combined = fixture + helpers
    return combined, {"method": "exact f0 fixture plus unchanged canonical reactor helpers",
        "canonical_sha256": sha256(canonical), "fixture_sha256": sha256(fixture),
        "helper_bytes": len(helpers), "helper_sha256": sha256(helpers),
        "combined_sha256": sha256(combined), "combined_bytes": len(combined),
        "helper_functions": [row.group(1).decode() for row in functions[1:]]}


class Build(FixtureBuild):
    """Reuse the existing compiler/cold-replay pin and sealed execution guard."""
    def __init__(self, output: Path):
        super().__init__(output)
        self.reactor_manifest = source_manifest()
        self.reactor_sources = {}
        for name in ("policy.hepta", "linux_emitter.hepta", "context_fixture.hepta", "api_fixture.hepta"):
            raw = (HERE / name).read_bytes()
            if sha256(raw) != self.reactor_manifest["platform/reactor/" + name]["sha256"]:
                raise ValueError("Reactor source changed during input capture")
            self.reactor_sources[name] = raw
        self.check_pin()

    @property
    def source_inputs(self) -> dict:
        # The shared build guard also binds the existing finite fixture inputs.
        # They are guard dependencies, not runtime code in the stream reactor.
        return {**self.manifest, **self.reactor_manifest}

    def check_pin(self) -> None:
        super().check_pin()
        if hasattr(self, "reactor_manifest") and source_manifest() != self.reactor_manifest:
            raise ValueError("A reactor input changed during qualification")

    def core_check(self, raw: bytes) -> dict:
        sys.path.insert(0, str(self.toolchain))
        from hepta import hia_agent_assembly
        if self.toolchain not in Path(hia_agent_assembly.__file__).resolve().parents:
            raise ValueError("Core verifier import is not from the locked checkout")
        document = hia_agent_assembly.assemble_program(raw).as_dict()
        return {"status": "CORE_ACCEPTED", "source_sha256": sha256(raw),
            "functions": len(document["functions"]),
            "blocks": sum(len(fn["blocks"]) for fn in document["functions"]),
            "ops": sum(len(block["ops"]) for fn in document["functions"] for block in fn["blocks"]),
            "emitted_isa_semantics_proven": False}

    def pack(self, policy: bytes, label: str) -> tuple[bytes, dict]:
        executable = self.stage(self.emitter, policy, label)
        profile = inspect_executable(executable)
        if not (0 < len(policy) <= 524288) or not executable.endswith(policy):
            raise ValueError("HIA emitter did not retain the exact native policy image")
        return executable, {"sha256": sha256(executable), "bytes": len(executable),
            "adapter_prefix_bytes": len(executable) - len(policy), **profile}

    def build_api_fixture(self) -> dict:
        source, composition = compose_fixture(self.reactor_sources["policy.hepta"],
                                               self.reactor_sources["api_fixture.hepta"])
        core = self.core_check(source)
        self.api_executable = self.stage(self.compiler, source, "compile-api-contract-fixture")
        profile = inspect_executable(self.api_executable)
        (self.output / "api-contract.elf").write_bytes(self.api_executable)
        self.check_pin()
        return {"executable": {"sha256": sha256(self.api_executable),
                "bytes": len(self.api_executable), **profile},
            "composition": composition, "core_check": core,
            "scope": "native HIA policy with explicit synthetic event/state frames; not OS fault injection"}

    def build(self) -> dict:
        source = self.reactor_sources["policy.hepta"]
        emitter_source = self.reactor_sources["linux_emitter.hepta"]
        context_source, composition = compose_fixture(source, self.reactor_sources["context_fixture.hepta"])
        core = {"policy": self.core_check(source), "emitter": self.core_check(emitter_source),
                "context_fixture": self.core_check(context_source)}
        self.policy = self.stage(self.compiler, source, "compile-reactor-policy")
        self.emitter = self.stage(self.compiler, emitter_source, "compile-reactor-emitter")
        emitter_profile = inspect_executable(self.emitter)
        self.executable, executable_profile = self.pack(self.policy, "emit-reactor-elf")
        self.context_policy = self.stage(self.compiler, context_source, "compile-context-fixture")
        self.context_executable, context_profile = self.pack(self.context_policy, "emit-context-fixture-elf")
        api_fixture = self.build_api_fixture()
        for name, raw in (("reactor.elf", self.executable), ("context-fixture.elf", self.context_executable),
                          ("policy.flat.bin", self.policy), ("emitter.elf", self.emitter),
                          ("context-policy.flat.bin", self.context_policy), ("context-composed.hepta", context_source)):
            (self.output / name).write_bytes(raw)
        self.check_pin()
        report = {"schema": "trnm.hia.stream-reactor-build.v1", "status": "PASS",
            "source_inputs": self.source_inputs, "toolchain": self.lock,
            "compiler_sha256": sha256(self.compiler), "compiler_qualification_binding": self.binding,
            "core_checks": core, "stages": self.stages,
            "policy": {"sha256": sha256(self.policy), "bytes": len(self.policy)},
            "emitter": {"sha256": sha256(self.emitter), "bytes": len(self.emitter), **emitter_profile},
            "executable": executable_profile, "context_fixture": context_profile,
            "api_contract_fixture": api_fixture,
            "context_composition": composition,
            "runtime_host_language_or_dynamic_loader": False,
            "hosted_build_test_and_core_verifier": True,
            "core_language_has_generic_syscall_opcode": False,
            "runtime_adapter_is_hia_emitted_isa_data": True,
            "upstream_et_rel_static_linker_qualified_by_this_build": False}
        write_json(self.output / "build.json", report)
        return report


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
