"""Build the captured-input request fixture with the pinned native HIA compiler.

The Python driver validates and passes exact HIA source bytes. Only the native
compiler and the compiled HIA emitter produce runtime instruction bytes.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

from hia.platform.build import Build as PinnedBuild
from hia.platform.build import inspect_executable, run_native, sha256, write_json

HIA = Path(__file__).resolve().parents[2]
REQUEST = "src/transport/authenticated_request.hepta"
STREAM = "src/crypto/sha256_stream.hepta"
FIXTURE = "platform/transport_request/"
OWN_INPUTS = (
    REQUEST, STREAM, FIXTURE + "linux_fixture_emitter.hepta",
    FIXTURE + "build.py", FIXTURE + "cases.py", FIXTURE + "rust_oracle.py",
    FIXTURE + "rust_reference.rs", FIXTURE + "abi.json", FIXTURE + "README.md",
    "tools/qualify_transport.py",
)


def functions(raw: bytes) -> dict[str, bytes]:
    result = {}
    for match in re.finditer(
        rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw
    ):
        name = match.group(1).decode()
        if name in result:
            raise ValueError("Duplicate HIA function: " + name)
        result[name] = match.group(0)
    if not result:
        raise ValueError("No HIA functions in source")
    return result


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest key: " + key)
        result[key] = value
    return result


class Build:
    def __init__(self, output: Path, repository: Path, components: Path | None = None):
        self.output = output
        self.output.mkdir(mode=0o700)
        self.repository = repository.resolve(strict=True)
        self.components = components or self.repository / "hia/components.json"
        self.inputs: dict[str, bytes] = {}
        self.paths: dict[str, Path] = {}
        self.guard = PinnedBuild(self.output / "pinned-native")
        for name in OWN_INPUTS:
            self.capture("hia/" + name, HIA / name)
        component_raw = self.capture("hia/components.json", self.components)
        manifest = json.loads(component_raw, object_pairs_hook=unique_object)
        if (set(manifest) != {"schema", "includes"}
                or manifest["schema"] != "trnm.hia.component-includes.v1"
                or not isinstance(manifest["includes"], dict)):
            raise ValueError("Unsupported explicit component manifest")
        self.includes = manifest["includes"][REQUEST]
        if not isinstance(self.includes, list):
            raise ValueError("Missing exact request function includes")
        self.composed = self.inputs["hia/" + REQUEST]
        names = set(functions(self.composed))
        self.selected = []
        for row in self.includes:
            if set(row) != {"source", "functions"}:
                raise ValueError("Unsupported function include")
            name, selected = row["source"], row["functions"]
            if (not isinstance(name, str) or not name.startswith("src/")
                    or ".." in Path(name).parts or not name.endswith(".hepta")
                    or not isinstance(selected, list) or not selected):
                raise ValueError("Invalid component input")
            path = HIA / name if (HIA / name).is_file() else self.repository / "hia" / name
            raw = self.capture("hia/" + name, path)
            available = functions(raw)
            for function in selected:
                if not isinstance(function, str) or function not in available or function in names:
                    raise ValueError("Unknown or duplicate selected function: " + str(function))
                self.composed += available[function]
                names.add(function)
            self.selected.append({"source": name, "functions": selected,
                                  "source_sha256": sha256(raw)})
        for relative in ("hia/platform/build.py", "hia/tests/test_ed25519.py",
                "hia/toolchain.lock.json", "hia/qualification/compiler-binding.json",
                "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
                "trillionnium/crates/trnm-pon-node/Cargo.toml",
                "trillionnium/crates/trnm-pon-node/src/ingress.rs",
                "trillionnium/crates/trnm-pon-node/src/ingress/account_scope_tests.rs",
                "trillionnium/crates/trnm-pon-node/src/ingress/authenticated_recovery_tests.rs",
                "trillionnium/crates/trnm-transport/src/lib.rs"):
            self.capture(relative, self.repository / relative)
        self.manifest = self.source_manifest()
        sys.path.insert(0, str(self.guard.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        self.core = {}
        for name, raw in (("request", self.composed),
                ("sha256_stream", self.inputs["hia/" + STREAM]),
                ("fixture_emitter", self.inputs["hia/" + FIXTURE + "linux_fixture_emitter.hepta"])):
            core = assemble_program(raw).as_dict()
            self.core[name] = {
                "functions": len(core["functions"]),
                "blocks": sum(len(fn["blocks"]) for fn in core["functions"]),
                "ops": sum(len(block["ops"]) for fn in core["functions"] for block in fn["blocks"]),
            }
        self.emitter = self.guard.stage(self.guard.compiler,
            self.inputs["hia/" + FIXTURE + "linux_fixture_emitter.hepta"], "compile-fixture-emitter")
        inspect_executable(self.emitter)
        self.builds = {}

    def capture(self, name: str, path: Path) -> bytes:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or symlinked source input: " + str(path))
        raw = path.read_bytes()
        if name in self.inputs and self.inputs[name] != raw:
            raise ValueError("Inconsistent source identity: " + name)
        self.inputs[name], self.paths[name] = raw, path.resolve(strict=True)
        return raw

    def source_manifest(self):
        return {name: {"bytes": len(raw), "sha256": sha256(raw)}
                for name, raw in sorted(self.inputs.items())}

    def check_sources(self):
        self.guard.check_pin()
        for name, original in self.inputs.items():
            if self.paths[name].read_bytes() != original:
                raise ValueError("Source changed during qualification: " + name)

    def kernel(self, name: str) -> tuple[bytes, dict]:
        if name not in {"request", "sha256_stream"}:
            raise ValueError("Unknown finite fixture kernel")
        source = self.composed if name == "request" else self.inputs["hia/" + STREAM]
        self.check_sources()
        image = self.guard.stage(self.guard.compiler, source, "compile-" + name)
        executable = self.guard.stage(self.emitter, image, "emit-" + name)
        profile = inspect_executable(executable)
        if not executable.endswith(image):
            raise ValueError("HIA emitter did not preserve the exact kernel image")
        for suffix, raw in ((".hepta", source), (".flat", image), (".elf", executable)):
            (self.output / (name + suffix)).write_bytes(raw)
        receipt = {"core": self.core[name], "composition_sha256": sha256(source),
            "image_sha256": sha256(image), "image_bytes": len(image),
            "executable": {"sha256": sha256(executable), "bytes": len(executable), **profile}}
        self.builds[name] = receipt
        self.check_sources()
        return executable, receipt

    def receipt(self):
        self.check_sources()
        return {"schema": "trnm.hia.transport-request-build.v1", "status": "PASS",
            "source_inputs": self.manifest,
            "source_set_sha256": sha256(json.dumps(self.manifest, sort_keys=True,
                separators=(",", ":")).encode()),
            "source_paths_observed": {name: str(path) for name, path in sorted(self.paths.items())},
            "source_unchanged": True, "exact_function_includes": self.selected,
            "toolchain": self.guard.lock, "compiler_sha256": sha256(self.guard.compiler),
            "compiler_qualification_binding": self.guard.binding,
            "core": self.core, "stages": self.guard.stages, "kernels": self.builds,
            "fixture_emitter_sha256": sha256(self.emitter),
            "runtime_host_proxy": False, "fixture_input_read_only": True,
            "fixture_stdin_capacity": 3 * 1024 * 1024, "fixture_output_bytes": 512,
            "fixture_workspace_bytes": 1024 * 1024,
            "fixture_scope": "complete captured input only; no network or durable owner"}
