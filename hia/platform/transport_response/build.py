"""Source-bound native response build; Python never emits runtime instructions."""
from __future__ import annotations

import json
from pathlib import Path
import sys

from hia.platform.build import Build as PinnedBuild
from hia.platform.build import inspect_executable, sha256
from hia.platform.private_stack.build import Guard as PrivateStackGuard, INPUTS as PRIVATE_STACK_INPUTS
from hia.tools.toolchain import compose_source

HIA = Path(__file__).resolve().parents[2]
FIXTURE = "platform/transport_response/"
KERNELS = {
    "number": ("src/codec/json_number.hepta", None),
    "value_wire": ("src/codec/json_value_wire.hepta", None),
    "value_encode": ("src/codec/json_value_encode.hepta", 0),
    "sign": ("src/crypto/ed25519_sign.hepta", None),
    "verify": ("src/transport/authenticated_response.hepta", None),
    "encode": ("src/transport/signed_response.hepta", 1),
    "fixture_contract": ("platform/transport_response/fixture_contract.hepta", 0),
}
ORIGINAL_INPUTS = (
    "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
    "trillionnium/crates/trnm-pon-node/Cargo.toml",
    "trillionnium/crates/trnm-pon-node/src/ingress.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/authenticated_recovery_tests.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/owned_ed25519.rs",
)


class Build:
    def __init__(self, output: Path, repository: Path):
        self.output = output
        output.mkdir(mode=0o700)
        self.repository = repository.resolve(strict=True)
        self.guard = PinnedBuild(output / "pinned-native")
        self.inputs: dict[str, bytes] = {}
        self.paths: dict[str, Path] = {}
        self.core = {}
        self.composed = {}
        self.builds = {}
        self.emitted = {}
        for path in sorted((HIA / FIXTURE).iterdir()):
            if path.is_file() and path.suffix in {".py", ".rs", ".json", ".md", ".hepta"}:
                self.capture("hia/" + path.relative_to(HIA).as_posix(), path)
        self.capture("hia/" + FIXTURE + "LICENSE-MIT.zmij", HIA / FIXTURE / "LICENSE-MIT.zmij")
        for relative in ("tools/toolchain.py", "tools/qualify_response.py", "platform/build.py",
                "platform/transport_request/linux_fixture_emitter.hepta",
                "platform/transport_request/cases.py", "platform/transport_request/rust_oracle.py",
                "tests/test_ed25519.py", "toolchain.lock.json", "qualification/compiler-binding.json"):
            self.capture("hia/" + relative, HIA / relative)
        for relative in (*PRIVATE_STACK_INPUTS, "platform/private_stack/deny_cleanup.py",
                "platform/private_stack/deny_cleanup.s"):
            self.capture("hia/" + relative, HIA / relative)
        for relative in ORIGINAL_INPUTS:
            self.capture(relative, self.repository / relative)
        sys.path.insert(0, str(self.guard.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        self.assemble = assemble_program
        for name, (relative, _) in KERNELS.items():
            combined, admitted_inputs = compose_source(HIA / relative)
            for path, raw in admitted_inputs:
                self.capture("hia/" + path.relative_to(HIA).as_posix(), path, raw)
            self.composed[name] = combined
            self.core[name] = self.describe_core(assemble_program(combined).as_dict())
        self.manifest = self.source_manifest()
        self.check_sources()
        self.emitters = {}
        for name, relative in (("fixed", "platform/transport_request/linux_fixture_emitter.hepta"),
                ("variable", FIXTURE + "linux_value_fixture_emitter.hepta")):
            payload = self.inputs["hia/" + relative]
            self.core["fixture_" + name] = self.describe_core(assemble_program(payload).as_dict())
            self.emitters[name] = self.guard.stage(self.guard.compiler, payload, "compile-fixture-" + name)
            inspect_executable(self.emitters[name])
        self.private_stack = PrivateStackGuard(self.guard)
        self.check_sources()

    @staticmethod
    def describe_core(core):
        return {"functions": len(core["functions"]),
            "blocks": sum(len(fn["blocks"]) for fn in core["functions"]),
            "ops": sum(len(block["ops"]) for fn in core["functions"] for block in fn["blocks"])}

    def capture(self, name: str, path: Path, admitted: bytes | None = None) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked source: " + str(path))
        raw = path.read_bytes()
        if admitted is not None and raw != admitted:
            raise ValueError("Composition input changed before capture: " + name)
        if name in self.inputs and self.inputs[name] != raw:
            raise ValueError("Inconsistent captured source: " + name)
        self.inputs[name], self.paths[name] = raw, path.resolve(strict=True)
        return raw

    def source_manifest(self):
        return {name: {"bytes": len(raw), "sha256": sha256(raw)}
                for name, raw in sorted(self.inputs.items())}

    def check_sources(self):
        self.guard.check_pin()
        for name, original in self.inputs.items():
            if self.paths[name].read_bytes() != original:
                raise ValueError("Source changed during response qualification: " + name)

    def kernel(self, name: str):
        if name not in KERNELS or name in self.builds:
            raise ValueError("Unknown or already-built response kernel: " + name)
        self.check_sources()
        source = self.composed[name]
        raw_image = self.guard.stage(self.guard.compiler, source, "compile-" + name)
        image = raw_image
        private_stack = None
        if name == "encode":
            image, private_stack = self.private_stack.wrap(raw_image, "response-producer")
        profile = KERNELS[name][1]
        emitter = self.emitters["fixed" if profile is None else "variable"]
        emitter_input = image if profile is None else profile.to_bytes(8, "little") + image
        executable = self.guard.stage(emitter, emitter_input, "emit-" + name)
        elf = inspect_executable(executable)
        if not executable.endswith(image):
            raise ValueError("Emitter did not retain the exact native kernel image")
        for suffix, raw in ((".hepta", source), (".flat", image), (".elf", executable)):
            (self.output / (name + suffix)).write_bytes(raw)
        if private_stack is not None:
            (self.output / (name + ".raw.flat")).write_bytes(raw_image)
        receipt = {"core": self.core[name], "composition_sha256": sha256(source),
            "raw_image_sha256": sha256(raw_image), "raw_image_bytes": len(raw_image),
            "private_stack": private_stack,
            "image_sha256": sha256(image), "image_bytes": len(image), "fixture_profile": profile,
            "executable": {"sha256": sha256(executable), "bytes": len(executable), **elf}}
        self.builds[name] = receipt
        self.emitted[name] = executable
        self.check_sources()
        return executable, receipt

    def receipt(self):
        self.check_sources()
        return {"schema": "trnm.hia.response-build.v1", "status": "PASS",
            "source_inputs": self.manifest,
            "source_set_sha256": sha256(json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode()),
            "source_paths_observed": {name: str(path) for name, path in sorted(self.paths.items())},
            "source_unchanged": True, "explicit_component_manifest": json.loads(self.inputs["hia/components.json"]),
            "composition": "own functions only; independently Core-verified dependencies; explicit flat callee closure",
            "toolchain": self.guard.lock, "compiler_sha256": sha256(self.guard.compiler),
            "compiler_qualification_binding": self.guard.binding, "pinned_build_source_manifest": self.guard.manifest,
            "core": self.core, "stages": self.guard.stages, "kernels": self.builds,
            "fixture_emitters": {name: sha256(raw) for name, raw in self.emitters.items()},
            "producer_private_stack": self.private_stack.receipt(),
            "runtime_host_proxy": False, "fixture_input_read_only": True,
            "variable_fixture_native_tail_and_redzone_validation": True,
            "fixture_scope": "finite captured input; no socket, replay, terminal-commit or private-key owner"}
