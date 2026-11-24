"""Build a finite freestanding Bench argv observer using only emitted HIA bytes."""
from __future__ import annotations

import json
from pathlib import Path

from hia.platform.build import Build, inspect_executable, sha256
from hia.tools.toolchain import HIA_ROOT, checked_source

POLICY = HIA_ROOT / "src/bench/startup_observer.hepta"
EMITTER = HIA_ROOT / "platform/bench/startup_emitter.hepta"
PREFIX = 552
ADAPTER_SHA256 = "6473b769cf11900af9339eeb75b5b51c61f539b0e1bdb6863991e1a840a02db3"


def build(output: Path) -> tuple[bytes, dict]:
    pinned = Build(output)
    inputs = {}
    wires = {}
    for label, path in (("policy", POLICY), ("emitter", EMITTER)):
        _, raw, _, _, captures = checked_source(path)
        wires[label] = raw
        inputs[label] = {p.relative_to(HIA_ROOT).as_posix(): sha256(b) for p, b in captures}
    flat = pinned.stage(pinned.compiler, wires["policy"], "compile-argv-policy")
    emitter = pinned.stage(pinned.compiler, wires["emitter"], "compile-argv-emitter")
    emitter_profile = inspect_executable(emitter)
    elf = pinned.stage(emitter, flat, "emit-argv-observer")
    profile = inspect_executable(elf)
    if (not 0 < len(flat) <= 524288 or len(elf) != PREFIX + len(flat)
            or elf[PREFIX:] != flat or sha256(elf[176:PREFIX]) != ADAPTER_SHA256):
        raise ValueError("Unexpected argv startup adapter or substituted native policy")
    for source_inputs in inputs.values():
        for relative, expected in source_inputs.items():
            if sha256((HIA_ROOT / relative).read_bytes()) != expected:
                raise ValueError("Native startup input changed during build")
    pinned.check_pin()
    report = {"schema": "trnm.hia.bench-argv-observer.build.v1", "status": "BUILD_PASS",
              "compiler_sha256": sha256(pinned.compiler),
              "toolchain_revision": pinned.lock["revision"], "source_inputs": inputs,
              "stdout_observer_elf": {**profile, "sha256": sha256(elf), "bytes": len(elf)},
              "emitter": {**emitter_profile, "sha256": sha256(emitter), "bytes": len(emitter)},
              "flat_policy": {"sha256": sha256(flat), "bytes": len(flat)},
              "adapter_sha256": ADAPTER_SHA256, "adapter_bytes": PREFIX - 176,
              "stages": pinned.stages, "whole_bench_native_qualified": False,
              "production_entrypoint": False, "original_cli_parser_qualified": False}
    (output / "build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return elf, report
