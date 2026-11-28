"""Real native minimum-buffer and complete installed-context observations.

Only qualification uses the shared ELF ABI. The product remains the native
standalone owner; these observations grant no publication authority.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from hia.platform.build import write_json
from hia.platform.continuity_store.reference import canonical, configuration

def need(condition, message):
    if not condition:
        raise ValueError(message)

def qualify_context(build, output, controls):
    output.mkdir(mode=0o700)
    build.check_sources()
    from hepta.hia_agent_assembly import render_assembly
    from hepta.elf_shared_abi import inspect_owned_shared_elf
    from hia.tests.native_support import NativeModule
    document = copy.deepcopy(build.assemble(build.composed["context"]).as_dict())
    document["module"] = "selfhost_elf"
    source = render_assembly(document).encode()
    image = build.pinned.stage(build.pinned.compiler, source, "compile-context-abi-object")
    object_path, library = output / "context.o", output / "context.so"
    object_path.write_bytes(image)
    command = ["ld", "-m", "elf_x86_64", "-shared", "-z", "defs",
        "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none",
        "--hash-style=both", str(object_path), "-lc", "-o", str(library)]
    linked = subprocess.run(command, capture_output=True, timeout=30)
    (output / "link.stdout").write_bytes(linked.stdout)
    (output / "link.stderr").write_bytes(linked.stderr)
    need(linked.returncode == 0, "Native context ABI link failed")
    library_bytes = library.read_bytes()
    inspect_owned_shared_elf(library_bytes, ("f0",))
    native = NativeModule.__new__(NativeModule)
    native.library = library
    native.artifact_sha256 = hashlib.sha256(library_bytes).hexdigest()
    native.exports = frozenset(("f0",))
    native.byte_exports = ("f0",)
    native.functions = {function["name"]: function for function in document["functions"]}
    selected = [(f"context-minimum-{variant}", variant, 136, 16384, 1048576, 0)
                for variant in range(4)]
    selected.extend((f"context-tail-guard-{variant}", variant, 136, 16401, 1048576, 0)
                    for variant in range(4))
    selected.extend([
        ("context-short-input", 0, 135, 16384, 1048576, 100),
        ("context-short-output", 0, 136, 16383, 1048576, 100),
        ("context-short-scratch", 0, 136, 16384, 1048575, 100),
        ("context-variant-four", 4, 136, 16384, 1048576, 69),
        ("context-variant-u64-max", (1 << 64) - 1, 136, 16384, 1048576, 69),
    ])
    results, contexts = [], []
    for name, variant, input_size, output_size, scratch_size, code in selected:
        arguments = [(bytes(128) + struct.pack("<Q", variant))[:input_size],
                     bytes([117]) * output_size, bytes([131]) * scratch_size]
        call = native.call("f0", arguments, timeout=30)
        checks = {"native_return": call.status == "returned" and call.returncode == 0
                  and call.abi_status == 0 and call.value == code}
        actual_context = None
        if code == 0 and checks["native_return"]:
            actual = call.arguments[1]
            cfg = configuration(variant)
            maintenance, params = canonical(cfg["record"]), canonical(cfg["params"])
            checks.update(
                input_unchanged=call.arguments[0] == arguments[0],
                output_extent=len(actual) == output_size,
                header=struct.unpack_from("<8Q", actual, 128) == (
                    int.from_bytes(b"CCFG0001", "little"), variant, 20,
                    variant & 1, variant >> 1, len(maintenance), len(params), 0),
                maintenance=actual[480:480 + len(maintenance)] == maintenance,
                parameters=actual[8192:8192 + len(params)] == params,
                tail=actual[16384:] == arguments[1][16384:],
            )
            hashes = {label: actual[offset:offset + 32].hex()
                for label, offset in (("network", 192), ("parameters", 224),
                    ("policy", 256), ("task", 288), ("model", 320), ("input", 352),
                    ("registry", 384), ("growth", 416), ("evaluation", 448))}
            checks["all_native_context_hashes"] = hashes == cfg["context"]
            actual_context = {"variant": variant, "params_hex": actual[8192:8192 + len(params)].hex(),
                "maintenance_hex": actual[480:480 + len(maintenance)].hex(), "context": hashes}
            (output / (name + ".output.raw")).write_bytes(actual)
            if output_size == 16384:
                contexts.append(actual_context)
        elif code != 0 and checks["native_return"]:
            checks["all_buffers_unchanged"] = call.arguments == arguments
        row = {"name": name, "status": "PASS" if all(checks.values()) else "FAIL",
            "checks": checks, "variant": variant, "input_bytes": input_size,
            "output_bytes": output_size, "scratch_bytes": scratch_size,
            "expected_code": code, "native": {"status": call.status,
                "returncode": call.returncode, "abi_status": call.abi_status, "value": call.value},
            "context": actual_context}
        results.append(row)
        controls.append(row)
        write_json(output / "running-controls.json", {"controls": results})
        need(row["status"] == "PASS", "Real native context ABI differs: " + name)
    build.check_sources()
    need(len(contexts) == 4 and len(results) == 13, "Incomplete native context qualification")
    report = {"schema": "trnm.hia.continuity-native-context-qualification.v1",
        "status": "PASS", "controls": results, "contexts": contexts,
        "context_object": {"bytes": len(image), "sha256": hashlib.sha256(image).hexdigest()},
        "shared_elf": {"bytes": len(library_bytes), "sha256": native.artifact_sha256},
        "link": {"argv": command, "exit_code": linked.returncode},
        "native_direct_calls": 13, "original_rust": "NOT_RUN", "publication_authority": False}
    write_json(output / "report.json", report)
    return contexts
