"""Build the actual same-worker Work/Host owner from checked HIA sources."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

from hia.platform.build import Build as PinnedBuild, INPUTS as PLATFORM_INPUTS, inspect_executable
from hia.platform.paid_cpu.build import source_manifest as paid_sources
from hia.platform.host_resource.build import source_manifest as resource_sources

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OWNED = (
    "README.md", "abi.json", "build.py", "cases.py", "native_io.py",
    "trace_audit.py", "trace_controls.py", "primitive_qualification.py", "faults.py",
    "qualify.py", "bundle.py", "rust_oracle.py", "test_integrity.py",
    "rust_reference.rs", "rust_bridge.rs", "owner_policy.hepta", "owner_fixture.hepta",
    "work_policy.hepta", "host_method.hepta", "host_fixture.hepta",
    "linux_emitter.hepta", "sha_fixture.hepta", "closed_fd_fixture_emitter.hepta",
)
SHARED = (
    "hia/src/work/verify.hepta", "hia/src/crypto/sha256_arena.hepta",
    "hia/platform/host_checkpoint/owner_policy.hepta",
    "hia/platform/host_resource/resource_policy.hepta",
    "hia/platform/host_resource/native_io.py", "hia/platform/host_resource/cases.py",
    "hia/platform/host_resource/rust_reference.rs",
    "hia/platform/paid_cpu/dependency.py", "hia/platform/transport_request/rust_oracle.py",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs",
    "trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs",
    "trillionnium/crates/trnm-pon-node/src/host_kernel_parent_resource_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs",
    "trillionnium/crates/trnm-pon-node/src/main.rs",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
)
W1_HELPERS = ("f1", "f2", "f3", "f4", "f5", "f9", "f10", "f11", "f14", "f16")
FROZEN = {
    "hia/src/work/verify.hepta": "7f3d088b2bf3f8a275721d95a6bcb43da8e24800d3465b7ecb6208d567dc9ba1",
    "hia/src/crypto/sha256_arena.hepta": "201072727d86f6f55c1c45f0012b4d850fa4ebcd078ba5bad30c682a90be8694",
    "hia/platform/host_checkpoint/owner_policy.hepta": "474aa5ce229c23723fe1f8bdcf7047c3e1bd3f2b95ed24f1a4c183702e86f3be",
    "hia/platform/host_resource/resource_policy.hepta": "9fa7440f953d6e2e1c1fb0f93c5bc96a2a8348f0a9d1a446e156dabeeac6cac8",
}
COMPILER = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"

def need(condition, message):
    if not condition:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(),
         "Noncanonical source/evidence path: " + str(path))
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "Regular single-link input required")
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_nlink)
        need(stamp(path.lstat()) == stamp(before), "Input replaced before capture")
        h = hashlib.sha256()
        size = 0
        for data in iter(lambda: stream.read(1 << 20), b""):
            size += len(data)
            h.update(data)
        need(stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(path.lstat()),
             "Input changed during capture")
    return {"bytes": size, "sha256": h.hexdigest()}

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Duplicate JSON field: " + key)
        result[key] = value
    return result

def read_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)

def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def source_manifest():
    need(__debug__, "Work owner qualification refuses optimized Python")
    inputs = paid_sources()
    for key, value in resource_sources().items():
        need(key not in inputs or inputs[key] == value, "Shared dependency bindings disagree")
        inputs[key] = value
    names = set(SHARED) | {"hia/" + p for p in PLATFORM_INPUTS}
    names |= {"hia/platform/work_owner/" + p for p in OWNED}
    for name in names:
        inputs[name] = identity(ROOT / name)
    for name, expected in FROZEN.items():
        need(inputs[name]["sha256"] == expected, "Frozen production helper changed: " + name)
    return dict(sorted(inputs.items()))

def function_table(raw):
    matches = list(re.finditer(rb"^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw, re.M))
    need(matches and raw.startswith(b"hia-asm.v1 hepta.hia.program.v8 "), "Complete HIA source required")
    result = {}
    for i, match in enumerate(matches):
        name = match[1].decode()
        need(name not in result, "Duplicate HIA function " + name)
        result[name] = raw[match.start():matches[i + 1].start() if i + 1 < len(matches) else len(raw)]
    return result

def suffix(raw, first):
    table = function_table(raw)
    need(first in table, "Missing HIA suffix " + first)
    return raw[raw.index(table[first]):]

def compose(sources):
    owner = sources["owner_policy.hepta"]
    work = sources["work_policy.hepta"]
    host = sources["host_method.hepta"]
    w1 = function_table(sources["hia/src/work/verify.hepta"])
    need(set(W1_HELPERS) <= set(w1), "Missing complete frozen W1 helper")
    helpers = b"".join(w1[name] for name in W1_HELPERS)
    host_helpers = suffix(sources["hia/platform/host_resource/resource_policy.hepta"], "resource_entry")
    host_helpers += suffix(sources["hia/platform/host_checkpoint/owner_policy.hepta"], "host_entry")
    return {
        "owner": owner,
        "owner-fixture": sources["owner_fixture.hepta"] + suffix(owner, "owner_entry"),
        "work": work + helpers,
        "host": host + host_helpers,
        "host-fixture": sources["host_fixture.hepta"] + suffix(host, "work_host_entry") + host_helpers,
        "emitter": sources["linux_emitter.hepta"],
        "sha": sources["sha_fixture.hepta"] + suffix(work, "work_precheck") + helpers,
        "closed-emitter": sources["closed_fd_fixture_emitter.hepta"],
    }

def inspect_owner(raw):
    need(len(raw) >= 232, "Truncated Work owner ELF")
    expected = (b"\x7fELF\x02\x01\x01" + bytes(9), 2, 62, 1, 0x4000e8, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    need(struct.unpack_from("<16sHHIQQQIHHHHHH", raw) == expected, "Unexpected native Work ELF header")
    rows = [struct.unpack_from("<IIQQQQQQ", raw, 64 + i * 56) for i in range(3)]
    need(rows == [(1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096),
                  (1, 6, 0, 0x800000, 0x800000, 0, 4096, 4096),
                  (0x6474e551, 6, 0, 0, 0, 0, 0, 16)], "Unexpected RX/BSS/nonexecuting-stack map")
    return {"format": "ELF64LE", "machine": "x86_64", "static": True, "interpreter": None,
            "entry": 0x4000e8, "instruction_semantics_proved_by_header": False}

def new_output(path):
    p = Path(path).absolute()
    need(p == p.resolve() and not p.exists() and not p.is_symlink(), "Fresh canonical output required")
    need(p != ROOT and ROOT not in p.parents, "Output must be outside repository")
    p.mkdir(parents=True, mode=0o700)
    return p

class Build(PinnedBuild):
    def __init__(self, output):
        need(__debug__, "Work owner builder refuses optimized Python")
        super().__init__(output)
        self.source_inputs = source_manifest()
        names = [name for name in OWNED if name.endswith(".hepta")]
        self.captured = {name: (HERE / name).read_bytes() for name in names}
        self.captured.update({name: (ROOT / name).read_bytes() for name in FROZEN})
        for name, raw in self.captured.items():
            key = name if name.startswith("hia/") else "hia/platform/work_owner/" + name
            need({"bytes": len(raw), "sha256": digest(raw)} == self.source_inputs[key],
                 "Source changed during capture")
        self.abi = read_json(HERE / "abi.json")
        need(digest(self.compiler) == COMPILER, "Compiler differs from qualified exact native compiler")
        self.programs = compose(self.captured)

    def check_pin(self):
        super().check_pin()
        if hasattr(self, "source_inputs"):
            need(source_manifest() == self.source_inputs, "Complete Work owner source closure changed")

    def build(self):
        result = {"schema": "trnm.hia.work-owner-build.v1", "status": "FAIL",
                  "source_inputs": self.source_inputs, "stages": self.stages}
        try:
            sys.path.insert(0, str(self.toolchain))
            from hepta.hia_agent_assembly import assemble_program
            programs = {name: assemble_program(raw).as_dict() for name, raw in self.programs.items()}
            # All method helpers are included in full and checked by the pinned Core.
            cores = {}
            for label, program in programs.items():
                cores[label] = {"functions": len(program["functions"]),
                                "ops": sum(len(b["ops"]) for f in program["functions"] for b in f["blocks"])}
            flats = {}
            for name, raw in self.programs.items():
                function_table(raw)
                (self.output / (name + ".hepta")).write_bytes(raw)
                flats[name] = self.stage(self.compiler, raw, "compile-" + name)
                (self.output / (name + (".elf" if name.endswith("emitter") else ".flat.bin"))).write_bytes(flats[name])
            for name in ("emitter", "closed-emitter"):
                inspect_executable(flats[name])
            images = {}
            for profile, owner, host, emitter in (
                ("owner", "owner", "host", "emitter"),
                ("fixture", "owner-fixture", "host-fixture", "emitter"),
                ("closed-fd", "owner-fixture", "host-fixture", "closed-emitter"),
            ):
                a, b, c = flats[owner], flats["work"], flats[host]
                need(all(0 < len(x) <= 524288 for x in (a, b, c)), "Native section exceeds fixed profile")
                payload = struct.pack("<4Q", int.from_bytes(b"OWBND001", "little"), len(a), len(b), len(c)) + a + b + c
                image = self.stage(flats[emitter], payload, "emit-" + profile)
                elf = inspect_owner(image)
                need(image.endswith(payload), "Emitter did not retain exact checked HIA sections")
                prefix = len(image) - len(payload)
                binding = self.abi["images"][profile]
                need({"bytes": len(image), "sha256": digest(image)} == binding["executable"],
                     "Native owner image differs from reviewed fixed ISA and HIA")
                need(prefix == binding["prefix_bytes"] and digest(image[232:prefix]) == binding["adapter_sha256"],
                     "Native adapter differs from reviewed literal emitter")
                (self.output / (profile + ".elf")).write_bytes(image)
                images[profile] = {"path": profile + ".elf", "bytes": len(image),
                                   "sha256": digest(image), "prefix_bytes": prefix, **elf}
            self.check_pin()
            result.update(status="PASS", images=images, core=cores,
                          native_images={name: {"bytes": len(raw), "sha256": digest(raw)} for name, raw in flats.items()},
                          composed_sources={name: {"bytes": len(raw), "sha256": digest(raw)} for name, raw in self.programs.items()},
                          compiler_sha256=digest(self.compiler), toolchain=self.lock,
                          compiler_qualification_binding=self.binding,
                          runtime_host_language_or_dynamic_loader=False,
                          external_TID_clock_success_or_reauthorization_input=False,
                          complete_Node_or_paid_checkpoint_closed=False)
        except BaseException as error:
            result["failure"] = repr(error)
            raise
        finally:
            write_json(self.output / "build.json", result)
        return result

def main():
    need(__debug__, "Work owner builder refuses optimized Python")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = Build(new_output(args.output) / "build").build()
    print(json.dumps({"status": result["status"], "images": result["images"]}, sort_keys=True))

if __name__ == "__main__":
    main()
