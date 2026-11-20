"""Compile and emit the unchanged HIA metadata owner and test-only observers."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import time
import traceback

from hia.platform.build import Build as PinnedBuild, inspect_executable
from hia.platform.peer_lease_unix.process import Processes
from hia.tools.toolchain import checked_source
from .contract import (HERE, ROOT, IMAGES, OBJECTS, ORDER, LIMITS, FALSE, capture,
                       check_environment, identity, need, source_capture, source_manifest, require_sources)

INDEX_ENTRY = b'''fn f0(input:readbuf,output:mutbuf,scratch:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(input:readbuf,output:mutbuf,scratch:mutbuf)
  zero:u64 = const() {"value":0}
  count:u64 = call(input,zero) {"function":"pl_read"}
  code:u64 = call(scratch,count) {"function":"pw_validate"}
  result:u32 = int.cast(code) {"mode":"wrap"}
  ret(result)
end
'''


def index_source(product):
    pattern = re.compile(rb"(?ms)^fn f0\([^\n]*\n.*?^end(?:\n|$)")
    need(len(pattern.findall(product)) == 1, "Unique original private entry required")
    observed = pattern.sub(lambda _: INDEX_ENTRY, product, count=1)
    need(pattern.sub(b"", observed) == pattern.sub(b"", product), "Private observer changed product functions")
    return observed


def counts(document):
    value = {"functions": len(document["functions"]),
             "blocks": sum(len(fn["blocks"]) for fn in document["functions"]),
             "ops": sum(len(block["ops"]) for fn in document["functions"] for block in fn["blocks"]),
             "max_blocks": max(len(fn["blocks"]) for fn in document["functions"])}
    need(value["functions"] <= 128 and value["blocks"] <= 1536
         and value["ops"] <= 8192 and value["max_blocks"] <= 256,
         "Unchanged native compiler limits exceeded")
    need(document["functions"][0]["name"] == "f0", "Native entry must remain first")
    return value


class Build:
    def __init__(self, output):
        check_environment(os.environ)
        self.output = Path(output).absolute()
        need(not self.output.exists() and not self.output.is_symlink()
             and ROOT not in self.output.resolve().parents, "Build requires fresh output outside repository")
        self.output.mkdir(parents=True, mode=0o700)
        self.started = time.monotonic_ns()
        self.pinned = PinnedBuild(self.output / "pinned-native")
        self.inputs = source_capture()
        self.admitted = tuple(sorted(name[4:] for name in self.inputs
                                    if name.startswith("hia/") and name.endswith(".hepta")))
        self.manifest = source_manifest(self.inputs)
        for name, raw in self.inputs.items():
            path = self.output / "source-snapshot" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.environment = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}
        self.processes = Processes(self.output / "processes", ROOT, self.environment, self.check)
        self.report = {"schema": "trnm.hia.payload-metadata-build.v1", "status": "FAIL",
                       "source_inputs": self.manifest, "images": {}, "objects": {}, "executables": {},
                       "limits": LIMITS, "tools": {}, **dict.fromkeys(FALSE, False)}
        (self.output / "tools").mkdir()
        for name in ("ld", "cc", "strace"):
            path = Path(shutil.which(name, path=self.environment["PATH"])).resolve(strict=True)
            raw = capture(path)
            (self.output / "tools" / name).write_bytes(raw)
            self.report["tools"][name] = {"path": str(path), "retained": "tools/" + name, **identity(raw)}

    def check(self):
        self.pinned.check_pin()
        require_sources(self.inputs, self.admitted)
        for row in getattr(self, "report", {}).get("tools", {}).values():
            need(identity(capture(Path(row["path"]))) == {key: row[key] for key in ("bytes", "sha256")},
                 "Actual build or trace tool changed")

    def compile(self, name, document, composed, *, object_profile=False, generated=False):
        from hepta.hia_agent_assembly import render_assembly
        from hepta.object_symbols import inspect_object_symbols
        self.check()
        core = counts(document)
        value = copy.deepcopy(document)
        if object_profile:
            first = value["functions"][0]
            need([p["type"] for p in first["params"]] == ["readbuf", "mutbuf", "mutbuf"]
                 and first["returns"] == ["u32"] and "exports" not in value,
                 "Private f0 object profile changed")
            value["module"] = "selfhost_elf"
        wire = render_assembly(value).encode()
        (self.output / (name + ".composed.hepta")).write_bytes(composed)
        (self.output / (name + ".compiler-input.hepta")).write_bytes(wire)
        (self.output / (name + ".core.json")).write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
        raw = self.pinned.stage(self.pinned.compiler, wire, "compile-" + name)
        if object_profile:
            symbols = inspect_object_symbols(raw, "ELF64", 62)
            need(symbols["defined"] == frozenset({"f0"}) and symbols["undefined"] <= {"calloc", "free"},
                 "Private observer import/export inventory changed")
        else:
            need(name == "linux_emitter" or 0 < len(raw) <= 524288, "Native image extent changed")
        suffix = ".o" if object_profile else ".native"
        (self.output / (name + suffix)).write_bytes(raw)
        row = {**identity(raw), "core": core, "wire": identity(wire), "composed": identity(composed),
               "path": name + suffix, "test_only_generated_entry": generated}
        self.report["objects" if object_profile else "images"][name] = row
        return raw

    def link(self, name, objects, *, observed=False):
        argv = [self.report["tools"]["ld"]["path"], "-m", "elf_x86_64", "-shared", "-z", "defs",
                "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both"]
        if observed:
            argv += ["--wrap=calloc", "--wrap=free"]
        argv += [str(path) for path in objects] + ["-lc"]
        if observed:
            argv += ["-lpthread"]
        path = self.output / (name + ".so")
        self.processes.run("link-" + name.replace("_", "-"), [*argv, "-o", path], timeout=30)
        raw = capture(path)
        if not observed:
            from hepta.elf_shared_abi import inspect_owned_shared_elf
            inspect_owned_shared_elf(raw, ("f0",))
        self.report["executables"][name] = {"path": path.name, **identity(raw), "test_only": True}

    def build(self):
        documents = {}
        images = {}
        try:
            for name in dict.fromkeys((*IMAGES, *OBJECTS)):
                checked, composed, *rest = checked_source(HERE / (name + ".hepta"))
                for path, raw in rest[-1]:
                    need(self.inputs[path.relative_to(ROOT).as_posix()] == raw, "Unbound compiler input")
                documents[name] = (checked.as_dict(), composed)
                if name in IMAGES:
                    images[name] = self.compile(name, *documents[name])
            inspect_executable(images["linux_emitter"])
            for name, order in (("payload-owner", ORDER), ("view-fixture", ("view_fixture", "metadata_runtime"))):
                request = b"HCSHD001" + struct.pack("<QQ", len(order), 2)
                request += b"".join(struct.pack("<Q", len(images[item])) for item in order)
                prefix = self.pinned.stage(images["linux_emitter"], request, "emit-" + name)
                need(len(prefix) == 5120, "Native Linux prefix extent changed")
                raw = prefix + b"".join(images[item] for item in order)
                path = self.output / (name + ".elf")
                path.write_bytes(raw)
                path.chmod(0o500)
                (self.output / (name + ".prefix")).write_bytes(prefix)
                self.report["executables"][name] = {"path": path.name, **identity(raw),
                    "elf": inspect_executable(raw), "module_order": list(order), "test_only": name != "payload-owner"}
            for name in OBJECTS:
                self.compile(name + "-object", *documents[name], object_profile=True)
                self.link(name, [self.output / (name + "-object.o")])
            from hepta.hia_agent_assembly import assemble_program
            composed = index_source(documents["metadata_log"][1])
            checked = assemble_program(composed)
            self.compile("metadata-index-object", checked.as_dict(), composed, object_profile=True, generated=True)
            self.link("metadata-index", [self.output / "metadata-index-object.o"])
            self.processes.run("compile-allocator-observer", [self.report["tools"]["cc"]["path"],
                "-std=c11", "-O2", "-fPIC", "-Wall", "-Wextra", "-Werror", "-pthread", "-c",
                ROOT / "hia/platform/pq_auth/qualification/allocator_observer.c", "-o",
                self.output / "allocator-observer.o"], timeout=30)
            self.link("metadata-observed", [self.output / "metadata_log-object.o",
                                          self.output / "allocator-observer.o"], observed=True)
            self.check()
            self.report.update(status="PASS", source_inputs_stable=True,
                compiler_sha256=identity(self.pinned.compiler)["sha256"], toolchain=self.pinned.lock,
                compiler_qualification_binding=self.pinned.binding,
                compiler_limits_preserved=True, unchanged_production_functions_in_index_observer=True)
            return self.report
        except BaseException as error:
            self.report.update(failure=repr(error), traceback=traceback.format_exc())
            raise
        finally:
            self.report["compiler_stages"] = self.pinned.stages
            self.report["tool_stages"] = self.processes.rows
            self.report["elapsed_ns"] = time.monotonic_ns() - self.started
            (self.output / "build.json").write_text(json.dumps(self.report, sort_keys=True, indent=2) + "\n")
