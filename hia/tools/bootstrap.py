#!/usr/bin/env python3
"""Bootstrap a pinned HIA-native compiler for chain component qualification.

The Python direct emitter supplies B0 only. All successor images and the
standalone ELF compiler are emitted by the preceding HIA machine program.
This finite development check is separate from upstream's full cold gate.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import time
from toolchain import pinned_toolchain, sha256


def bootstrap(output: Path):
    root, pin = pinned_toolchain()
    from tools.qualify_hia_selfhost import build_seed, compile_stage, mutate_compiler, SOURCE
    from tools.qualify_hia_selfhost_cli import inspect_executable
    output = output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    original = SOURCE.read_bytes()
    started = time.monotonic()
    seed, seed_receipt = build_seed(output)
    image, generations = seed, []
    for label in ("B1", "B2", "B3"):
        image, receipt = compile_stage(output, label, image, original,
            image_format="seed-shared" if label == "B1" else "flat-x86-64")
        generations.append(receipt)
    if len({entry["produced_sha256"] for entry in generations}) != 1:
        raise AssertionError("Original compiler did not reach the required fixed point")
    modified = mutate_compiler(original)
    modified_image, modifications = image, []
    for label in ("M1", "M2", "M3"):
        modified_image, receipt = compile_stage(output, label, modified_image, modified)
        modifications.append(receipt)
    original_digest = generations[-1]["produced_sha256"]
    modified_digests = [entry["produced_sha256"] for entry in modifications]
    if (modified_digests[0] == modified_digests[1]
            or modified_digests[1] != modified_digests[2]
            or modified_digests[2] == original_digest):
        raise AssertionError("Modified compiler failed the independent propagation witness")
    old = b"hia-asm.v1 hepta.hia.program.v8 selfhost\n"
    new = b"hia-asm.v1 hepta.hia.program.v8 selfhost_exec\n"
    if not original.startswith(old):
        raise ValueError("Pinned compiler executable-profile header changed")
    executable_source = new + original[len(old):]
    executable, executable_receipt = compile_stage(output, "native-compiler", image,
        executable_source, output_extension="")
    executable.chmod(0o500)
    inspection = inspect_executable(executable.read_bytes())
    repeat = subprocess.run([str(executable)], input=executable_source, capture_output=True,
        env={"PATH": ""}, timeout=30, check=False)
    if repeat.returncode or repeat.stderr or repeat.stdout != executable.read_bytes():
        raise AssertionError("Standalone HIA compiler did not reproduce its executable bytes")
    if SOURCE.read_bytes() != original:
        raise ValueError("Compiler source changed during bootstrap")
    # A second revision/dirty check rejects a concurrent upstream source edit.
    pinned_toolchain()
    result = {"schema": "trnm.hia.development-bootstrap.v1", "status": "PASS",
        "repository": pin["repository"], "revision": pin["revision"],
        "compiler_source": SOURCE.relative_to(root).as_posix(),
        "compiler_source_sha256": sha256(original),
        "compiler": str(executable), "compiler_sha256": sha256(executable.read_bytes()),
        "seed_receipt": seed_receipt, "generations": generations,
        "modified_generations": modifications, "executable_receipt": executable_receipt,
        "executable_inspection": inspection, "standalone_exec_fixed_point": True,
        "standalone_runtime_python_or_compiler_dependency": False,
        "bootstrap_python_and_linker_required": True,
        "full_upstream_cold_qualification": False, "whole_chain_native": False,
        "wall_seconds": time.monotonic() - started}
    (output / "bootstrap.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = bootstrap(args.output)
    print(json.dumps({key: result[key] for key in (
        "status", "compiler", "compiler_sha256", "wall_seconds",
        "full_upstream_cold_qualification", "whole_chain_native")}, indent=2))


if __name__ == "__main__":
    main()
