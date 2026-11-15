#!/usr/bin/env python3
"""Run finite native migration qualification and retain exact source bindings."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sources():
    paths = sorted((ROOT / "hia").rglob("*.hepta"))
    paths += sorted((ROOT / "hia/tools").glob("*.py"))
    paths += sorted((ROOT / "hia/tests").glob("*.py"))
    paths += sorted((ROOT / "hia/tests").glob("*.rs"))
    paths += [ROOT / "hia/components.json", ROOT / "hia/toolchain.lock.json"]
    paths += [ROOT / "hia/qualification/compiler-binding.json"]
    paths += [ROOT / name for name in (
        "trillionnium/crates/trnm-transport/src/lib.rs",
        "trillionnium/crates/trnm-transport/src/proof_admission.rs",
        "trillionnium/crates/trnm-verification-profiles/src/closed_round.rs",
        "trillionnium/crates/trnm-protocol/src/pon_wire.rs",
        "trillionnium/crates/trnm-protocol/src/integer_factor_v2.rs",
        "trillionnium/crates/trnm-protocol/src/integer_evolution_v3.rs",
        "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
        "formal/pon-nakamoto-v1/contract_wire.py",
        "formal/pon-nakamoto-v1/vectors/header.bin",
        "formal/pon-nakamoto-v1/vectors/header-short.bin",
        "formal/pon-nakamoto-v1/vectors/header-version.bin",
        "formal/pon-nakamoto-v1/vectors/header-trailing.bin",
        "formal/pon-nakamoto-v1/vectors/model-evolution-v5.json")]
    return {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-rust-oracle", action="store_true")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Observation output must be a new file")
    if args.require_rust_oracle and not os.environ.get("TRNM_HIA_RUST_REFERENCE"):
        parser.error("The independent Rust oracle is required")
    before = sources()
    from hia.tests.native_support import NativeModule
    builds, calls = [], Counter()
    original_init, original_many = NativeModule.__init__, NativeModule.call_many

    def record_init(self, *values, **options):
        original_init(self, *values, **options)
        receipt = self.receipt
        builds.append({"source": self.source.relative_to(ROOT).as_posix(),
            "artifact_sha256": self.artifact_sha256,
            "object_sha256": receipt.get("object_sha256"),
            "compiler_sha256": receipt.get("compiler_sha256"),
            "exports": sorted(self.exports), "claims": receipt.get("claims"),
            "chain_migration": receipt["chain_migration"]})

    def record_many(self, cases, **options):
        results = original_many(self, cases, **options)
        backend = self.receipt["chain_migration"]["backend"]
        for result in results:
            calls[(backend, result.status)] += 1
        return results

    NativeModule.__init__, NativeModule.call_many = record_init, record_many
    started = time.monotonic()
    try:
        suite = unittest.defaultTestLoader.discover(str(ROOT / "hia/tests"),
                                                   pattern="test_*.py", top_level_dir=str(ROOT))
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    finally:
        NativeModule.__init__, NativeModule.call_many = original_init, original_many
    after = sources()
    stable = before == after
    accepted = result.wasSuccessful() and stable and (not args.require_rust_oracle or not result.skipped)
    binding_path = ROOT / "hia/qualification/compiler-binding.json"
    compiler_binding = json.loads(binding_path.read_text())
    compiler_matches = all(b["compiler_sha256"] == compiler_binding["compiler_sha256"]
        for b in builds if b["chain_migration"]["backend"] == "selfhost")
    accepted = accepted and compiler_matches
    reference = os.environ.get("TRNM_HIA_RUST_REFERENCE")
    report = {"schema": "trnm.hia.native-qualification.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if accepted and not result.skipped else "PASS_WITH_SKIPS" if accepted else "FAIL",
        "source_commit_observed": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True)),
        "source_inputs": before, "source_set_sha256": digest(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()),
        "source_unchanged_during_tests": stable,
        "tests": {"run": result.testsRun, "failures": [(str(test), error) for test, error in result.failures],
            "errors": [(str(test), error) for test, error in result.errors],
            "skipped": [(str(test), why) for test, why in result.skipped]},
        "native_calls_through_shared_runner": [{"backend": b, "outcome": s, "count": count}
                                               for (b, s), count in sorted(calls.items())],
        "additional_raw_abi_probes": "The crypto and closed-round suites also execute explicit native pointer/capacity probes; these are not included in the shared-runner counts.",
        "builds": builds, "wall_seconds": time.monotonic() - started,
        "rust_reference": None if reference is None else {
            "executable_sha256": digest(Path(reference).read_bytes()),
            "compiler": subprocess.check_output(["rustc", "-Vv"], text=True)},
        "upstream_cold_gate_executed_in_this_run": False,
        "retained_compiler_binding_sha256": digest(binding_path.read_bytes()),
        "selfhost_compiler_matches_cold_qualified_image": compiler_matches,
        "whole_chain_native": False,
        "old_stack_can_be_removed": False, "production_activation": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "tests": result.testsRun,
                      "skipped": len(result.skipped), "source_set_sha256": report["source_set_sha256"],
                      "shared_runner_calls": sum(calls.values()), "wall_seconds": report["wall_seconds"]}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
