#!/usr/bin/env python3
"""Run finite native migration qualification and retain exact source bindings."""
from __future__ import annotations

import argparse
from collections import Counter
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.tools.component_partition import (
    WORKER_SHARDS, PLANS, SPLIT_GROUPS, ObservedResult, lineage, record_completion, select_suite, source_bound_plan,
)
RUST_ORACLES = ("TRNM_HIA_RUST_REFERENCE", "TRNM_HIA_RUST_PROTOCOL_REFERENCE",
                "TRNM_HIA_RUST_CHECKPOINT_REFERENCE", "TRNM_HIA_RUST_CRYPTO_REFERENCE",
                "TRNM_HIA_RUST_STATE_REFERENCE")
ML_DSA_ORACLE = "TRNM_HIA_RUST_ML_DSA_REFERENCE"


def rust_oracle_names(group):
    if group not in (*SPLIT_GROUPS, *WORKER_SHARDS, "all"):
        raise ValueError("Unknown component shard")
    return (*RUST_ORACLES, ML_DSA_ORACLE) if group in ("ml-dsa", "all") else RUST_ORACLES


def pinned_rust_oracles(group, environ=None):
    """ML-DSA uses its actual freshly qualified private adapter and explicit pin."""
    env = os.environ if environ is None else environ
    if ML_DSA_ORACLE not in rust_oracle_names(group):
        return {}
    expected = env.get(ML_DSA_ORACLE + "_SHA256")
    path = env.get(ML_DSA_ORACLE)
    if (type(expected) is not str or re.fullmatch(r"[0-9a-f]{64}", expected) is None
            or type(path) is not str or not path):
        raise ValueError("ML-DSA requires its actual original adapter and explicit SHA256")
    from hia.tests.native_support import unlinked_path
    actual = digest(unlinked_path(path).read_bytes())
    if actual != expected:
        raise ValueError("ML-DSA actual original adapter differs from the explicit SHA256")
    return {ML_DSA_ORACLE: expected}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sources():
    paths = sorted((ROOT / "hia").rglob("*.hepta"))
    paths += sorted((ROOT / "hia/tools").glob("*.py"))
    for pattern in ("*.py", "*.rs", "*.json", "*.c"):
        paths += sorted((ROOT / "hia/tests").rglob(pattern))
    for name in ("platform", "storage"):
        directory = ROOT / "hia" / name
        paths += sorted(directory.rglob("*.py"))
        paths += sorted(directory.rglob("*.rs"))
        paths += sorted(directory.rglob("abi.json"))
        paths += sorted(directory.rglob("README.md"))
    paths += [ROOT / "config/hia-migration-v1.json", ROOT / "rust-toolchain.toml",
              ROOT / "hia/components.json", ROOT / "hia/toolchain.lock.json",
              ROOT / "hia/state-value-abi.json", ROOT / "hia/STATE_VALUE.md"]
    paths += [ROOT / "hia/qualification/compiler-binding.json"]
    paths += [ROOT / "hia/src/crypto/ML_DSA.md",
              ROOT / "hia/tests/vectors/ml_dsa_acvp_975de31.json.xz"]
    # The real detached-checkout control executes the original boundary script.
    # Bind every manifest and policy file that its read-only preflight reads.
    from hia.tools.ml_dsa_original import boundary_inputs
    paths += [ROOT / "scripts/project-preflight.sh"]
    paths += [ROOT / name for name in boundary_inputs(ROOT)]
    paths += [ROOT / ".github/workflows/hia-native-migration.yml",
              ROOT / "trillionnium/Cargo.toml", ROOT / "trillionnium/Cargo.lock"]
    for name in ("trnm-protocol", "trnm-checkpoint-types", "trnm-checkpoint-store",
                 "trnm-crypto-primitives",
                 "trnm-mvcc-fee", "trnm-executor", "trnm-types", "trnm-data-availability",
                 "trnm-worker-agent", "trnm-control-plane", "trnm-escrow-vault",
                 "trnm-governance-guard",
                 "trnm-peer-lease", "trnm-oracle", "trnm-research-protocol", "trnm-bench",
                 "trnm-service-settlement", "trnm-task-kernel", "trnm-sqlite-io-boundary"):
        crate = ROOT / "trillionnium/crates" / name
        paths += sorted((crate / "src").rglob("*.rs"))
        paths += sorted((crate / "tests").rglob("*.rs"))
        paths += sorted((crate / "examples").rglob("*.rs"))
        paths.append(crate / "Cargo.toml")
    paths += sorted((ROOT / "config/pon").rglob("*.json"))
    paths += [ROOT / name for name in (
        "hia/platform/task_kernel/provider_abi.json",
        "hia/src/sqlite_io_boundary/README.md",
        "trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c",
        "trillionnium/crates/trnm-state-import/Cargo.toml",
        "trillionnium/crates/trnm-state-import/src/lib.rs",
        "hia/src/state_import/README.md",
        "hia/src/state_import/CUTOVER_AGREEMENT_DIGEST.md",
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
    # M05: bind the exact original implementation files compiled by the
    # independent quota/fairness source adapter, not only its wrapper.
    paths += [ROOT / "trillionnium/crates/trnm-mempool/src/lane_quota.rs",
              ROOT / "trillionnium/crates/trnm-mempool/src/lane_fairness.rs",
              ROOT / "trillionnium/crates/trnm-mempool/src/lib.rs",
              ROOT / "trillionnium/crates/trnm-mempool/src/typed_admission.rs",
              ROOT / "trillionnium/crates/trnm-mempool/Cargo.toml",
              ROOT / "hia/src/mempool/OWNER.md"]
    # Work profile docs are tied to the immutable original schedule and PoN hash inputs below.
    # The complete original M02 module is actually compiled by the independent
    # reference; bind its bytes and both pre-existing integer vector corpora.
    paths += [ROOT / "trillionnium/crates/trnm-pon-node/src/consensus.rs",
              ROOT / "formal/pon-nakamoto-v1/vectors/consensus-arithmetic-v1.json",
              ROOT / "formal/pon-nakamoto-v1/vectors/consensus-domain-v2.json",
              ROOT / "trillionnium/crates/trnm-pon-node/src/research_work_schedule.rs",
              ROOT / "trillionnium/crates/trnm-pon-node/Cargo.toml",
              ROOT / "formal/pon-nakamoto-v1/vectors/quantum-daa-asert-bchn-v1.json",
              ROOT / "hia/src/consensus/ASERT_TARGET.md",
              ROOT / "hia/src/consensus/WORK_SCHEDULE_PROFILE.md",
              ROOT / "hia/src/consensus/README.md"]
    # Local resource metadata oracle compiles the exact original public methods.
    paths += [ROOT / "trillionnium/crates/trnm-pon-node/src/resource_owner_v1.rs",
              ROOT / "hia/src/node/RESOURCE_PROFILE.md"]
    # Exact original data/owner bodies and their complete native contracts.
    paths += [ROOT / name for name in (
        "trillionnium/crates/trnm-audit-events/src/lib.rs",
        "trillionnium/crates/trnm-audit-events/Cargo.toml",
        "trillionnium/crates/trnm-pon-node/src/store/mempool.rs",
        "trillionnium/crates/trnm-pon-node/src/lib.rs",
        "hia/src/audit/README.md", "hia/src/mempool/RAW_BINDINGS.md",
        "hia/src/mempool/LOCAL_POOL_POLICY.md", "hia/src/mempool/local_pool_policy_abi.json",
        "hia/src/data_availability/CELL_PERIODIC_SNAPSHOT_POLICY.md",
        "hia/src/data_availability/CELL_CHUNK_DELTA_VALUE.md",
        "hia/src/data_availability/CELL_CLOSURE_DECLARED_CONTEXT_RELATION.md",
        "hia/src/data_availability/CELL_VERSION_DECLARED_CONTEXT_RELATION.md",
        "hia/src/data_availability/CELL_VERSION_RETENTION_CANONICAL.md",
        "hia/src/data_availability/CELL_RELEASE_RETENTION_CANONICAL.md",
        "hia/src/data_availability/RS46_SHARD_VALUE.md",
        "hia/src/data_availability/RS46_CODEWORD_VALUE.md",
        "hia/src/data_availability/RS46_COMMITTED_SLOT.md",
        "hia/src/data_availability/BEP52_BINDING_VALUE.md",
        "hia/src/data_availability/BEP52_CHUNK_PROOF_VALUE.md",
        "hia/src/data_availability/BEP52_PIECE_COMPARE.md",
        "hia/src/data_availability/BEP52_METAINFO_VALUE.md",
        "hia/src/data_availability/BEP52_MAGNET_VALUE.md",
        "hia/src/data_availability/BEP52_BENCODE_PREFIX.md",
        "hia/src/data_availability/BEP52_BENCODE_ACCESS.md",
        "hia/src/data_availability/CELL_CONTENT_CLOSURE_VALUE.md",
        "hia/src/data_availability/CELL_CONTENT_CLOSURE_OBSERVE.md",
        "hia/src/data_availability/CELL_CONTENT_MANIFEST_OBSERVE.md",
        "hia/src/data_availability/CELL_VERSION_RETENTION_OBJECT_RELATION.md",
        "hia/src/data_availability/CELL_VERSION_RETENTION_OUTER_TERMS.md",
        "hia/src/data_availability/CELL_VERSION_LOADER_PIN_VALUE.md",
        "hia/src/data_availability/CELL_VERSION_CATALOG_ANCHOR_VALUE.md",
        "hia/src/data_availability/CELL_DECLARED_RECOVERY_PLACEMENT.md",
        "hia/src/data_availability/CELL_RECOVERY_PLACEMENT_POLICY_VALUE.md",
        "hia/src/data_availability/CELL_RETENTION_CONTRACT_VALUE.md",
        "hia/src/data_availability/README.md", "hia/src/control_plane/README.md",
        "hia/src/escrow/README.md", "hia/src/governance/README.md", "hia/src/bench/README.md",
        "hia/src/bench/ENVIRONMENT.md", "hia/src/bench/FORMATTING.md",
        "hia/src/bench/LOGARITHM.md", "hia/src/bench/PROFILE.md",
        "hia/src/bench/TEXT.md", "hia/src/bench/REPORT.md",
        "hia/src/research_protocol/README.md", "hia/src/research_protocol/AUTHORITY.md",
        "hia/src/research_protocol/STATE_VALUES.md", "hia/src/research_protocol/STATE_GRAPH.md",
        "hia/src/research_protocol/STATE_TRANSITION.md", "hia/src/research_protocol/STATE_QUERY.md",
        "hia/src/control_plane/LOCAL_GUARD.md", "hia/src/peer_lease/README.md",
        "hia/src/oracle/README.md", "hia/src/types/request_status.md",
        "hia/src/types/transfer.md", "hia/src/types/transcript.md",
        "hia/src/crypto/SHA512_STREAM.md", "hia/src/crypto/KECCAK.md",
        "hia/src/crypto/ML_DSA_POLY.md",
        "scripts/ci/ci_job.sh")]
    # ReleaseBundle finite tests compile these original Rust method bodies
    # and their release-size policy; bind them independently of the adapters.
    paths += [ROOT / name for name in (
        "trillionnium/crates/trnm-release-bundle/src/lib.rs",
        "trillionnium/crates/trnm-release-bundle/src/content_v1.rs",
        "hia/src/release_bundle/ARTIFACT_HEADER.md",
        "hia/src/release_bundle/CONTENT_CLAIM_FRAME.md",
        "hia/src/release_bundle/RAW_ARTIFACT_SHA256.md",
        "hia/src/release_bundle/SHA512_TRANSCRIPT_BOOTSTRAP.md")]
    # The genuine original M12 Store uses frozen trust bytes from this corpus.
    # Its owning Rust crates are bound above and the adapter under hia/tests.
    paths.append(ROOT / "hia/platform/service_settlement/qualification/fixtures.json.xz")
    # Bind the complete retained original Host implementation and typed errors.
    paths += [ROOT / "trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs",
              ROOT / "trillionnium/crates/trnm-pon-node/src/host_kernel_parent_relative_tests.rs",
              ROOT / "trillionnium/crates/trnm-pon-node/src/error.rs"]
    return {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in sorted(paths)}


def _relative_path(name):
    if (type(name) is not str or not name or "\\" in name or "\0" in name
            or Path(name).is_absolute() or ".." in Path(name).parts
            or Path(name).as_posix() != name or name == "."):
        raise ValueError("Noncanonical native provenance path")
    return name


def _native_input(name, *, entry=False):
    _relative_path(name)
    if (not entry and name == "components.json") or (
            name.startswith(("src/", "platform/", "storage/")) and name.endswith(".hepta")):
        return name
    raise ValueError("Native build input is outside the canonical HIA source roots")


def _sha256(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Invalid native source SHA256")
    return value


def _migration_inputs(build):
    migration = build.get("chain_migration") if type(build) is dict else None
    if type(migration) is not dict:
        raise ValueError("Missing actual native build receipt")
    rows = migration.get("inputs")
    if type(rows) is not list or len(rows) < 2:
        raise ValueError("Missing actual native source inputs")
    seen = set()
    for index, row in enumerate(rows):
        if type(row) is not dict or set(row) != {"path", "sha256"}:
            raise ValueError("Malformed actual native source identity")
        name = _native_input(row["path"], entry=index == 0)
        _sha256(row["sha256"])
        if name in seen:
            raise ValueError("Duplicate actual native source input")
        seen.add(name)
    if (rows[1]["path"] != "components.json"
            or _sha256(migration.get("source_sha256")) != rows[0]["sha256"]):
        raise ValueError("Native source identities differ from the actual build receipt")
    return rows


def validate_generated_fixture(build, source_inputs):
    """Read retained fixture bytes as a fixture, with every dependency bound."""
    actual = _migration_inputs(build)
    if "source" not in build or build["source"] is not None:
        raise ValueError("Generated fixture cannot identify a production entry")
    value = build.get("generated_fixture")
    if type(value) is not dict or set(value) != {"owner", "owner_sha256", "entry", "inputs"}:
        raise ValueError("Missing generated fixture provenance")
    owner = _relative_path(value["owner"])
    if (not owner.startswith("hia/tests/") or not owner.endswith(".py")
            or source_inputs.get(owner) != _sha256(value["owner_sha256"])):
        raise ValueError("Generated fixture owner is not a bound test source")
    entry = _native_input(value["entry"], entry=True)
    if "hia/" + entry in source_inputs:
        raise ValueError("Generated fixture entry shadows a production source")
    rows = value["inputs"]
    if type(rows) is not list or not rows:
        raise ValueError("Generated fixture has no actual input bytes")
    identities, seen = [], set()
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "sha256", "utf8"}:
            raise ValueError("Malformed generated fixture input")
        name = _native_input(row["path"])
        if name in seen:
            raise ValueError("Duplicate generated fixture input")
        seen.add(name)
        if type(row["utf8"]) is not str or digest(row["utf8"].encode("utf-8")) != _sha256(row["sha256"]):
            raise ValueError("Generated fixture bytes differ from their identity")
        if name not in (entry, "components.json") and source_inputs.get("hia/" + name) != row["sha256"]:
            raise ValueError("Generated fixture changed a production dependency")
        identities.append({"path": name, "sha256": row["sha256"]})
    if identities != actual or entry != actual[0]["path"]:
        raise ValueError("Generated fixture differs from the actual build receipt")


def validate_build_provenance(build, source_inputs):
    """Bind both product builds and generated fixtures to their actual inputs."""
    actual = _migration_inputs(build)
    if "source" not in build:
        raise ValueError("Missing native build source kind")
    if build["source"] is None:
        validate_generated_fixture(build, source_inputs)
        return
    source = _relative_path(build["source"])
    if "generated_fixture" in build or source != "hia/" + actual[0]["path"]:
        raise ValueError("Native build source differs from its actual entry")
    for row in actual:
        if source_inputs.get("hia/" + row["path"]) != row["sha256"]:
            raise ValueError("Native build input differs from the qualification source map")


def _read_bound(path, expected):
    from hia.tests.native_support import unlinked_path
    path = unlinked_path(path)
    before = path.stat()
    raw = path.read_bytes()
    after = unlinked_path(path).stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, key) != getattr(after, key) for key in fields) or digest(raw) != _sha256(expected):
        raise ValueError("Native source changed after its actual build")
    return raw


def build_provenance(module, source_inputs):
    """Capture actual fixture bytes while the generated source tree still exists."""
    from hia.tests.native_support import unlinked_path
    source = unlinked_path(module.source)
    source_root = unlinked_path(module.source_root, directory=True)
    root = unlinked_path(ROOT, directory=True)
    actual = _migration_inputs(module.receipt)
    try:
        entry = source.relative_to(source_root).as_posix()
    except ValueError:
        raise ValueError("Native entry is outside its actual source root") from None
    if entry != actual[0]["path"]:
        raise ValueError("Native entry differs from its actual build receipt")
    if source.is_relative_to(root):
        if source_root != root / "hia" or module.fixture_owner is not None:
            raise ValueError("Canonical native entry has ambiguous fixture provenance")
        value = {"source": source.relative_to(root).as_posix()}
        validate_build_provenance({**value, "chain_migration": module.receipt["chain_migration"]}, source_inputs)
        for row in actual:
            _read_bound(source_root / row["path"], row["sha256"])
        return value
    if module.fixture_owner is None:
        raise ValueError("External native fixtures require a bound test owner")
    owner_path = unlinked_path(module.fixture_owner)
    try:
        owner = owner_path.relative_to(root).as_posix()
    except ValueError:
        raise ValueError("Generated fixture owner is outside the qualification source root") from None
    owner_sha256 = source_inputs.get(owner)
    _read_bound(owner_path, owner_sha256)
    inputs = []
    for row in actual:
        raw = _read_bound(source_root / row["path"], row["sha256"])
        if row["path"] not in (entry, "components.json"):
            _read_bound(root / "hia" / row["path"], row["sha256"])
        inputs.append({**row, "utf8": raw.decode("utf-8")})
    value = {"source": None, "generated_fixture": {
        "owner": owner, "owner_sha256": owner_sha256, "entry": entry, "inputs": inputs}}
    validate_generated_fixture({**value, "chain_migration": module.receipt["chain_migration"]}, source_inputs)
    return value


def native_build_record(module, source_inputs):
    """The same capture path is used by qualification and bounded regressions."""
    receipt = module.receipt
    return {**build_provenance(module, source_inputs),
            "artifact_sha256": module.artifact_sha256,
            "object_sha256": receipt.get("object_sha256"),
            "compiler_sha256": receipt.get("compiler_sha256"),
            "exports": sorted(module.exports), "claims": receipt.get("claims"),
            "chain_migration": receipt["chain_migration"]}


def direct_native_build_record(source, source_root, output, receipt, source_inputs):
    """Capture an actual canonical build made outside the shared call runner."""
    if receipt.get("ok") is not True:
        raise ValueError("Unsuccessful direct build receipt")
    artifact = _read_bound(output, receipt.get("artifact_sha256"))
    if type(receipt.get("artifact_bytes")) is not int or receipt["artifact_bytes"] != len(artifact):
        raise ValueError("Direct native artifact extent differs from its actual receipt")
    module = SimpleNamespace(source=source, source_root=source_root, fixture_owner=None,
                             receipt=receipt, artifact_sha256=digest(artifact),
                             exports=receipt["exports"])
    value = native_build_record(module, source_inputs)
    if value["source"] is None:
        raise ValueError("Direct native build requires canonical source provenance")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-rust-oracle", action="store_true")
    parser.add_argument("--shard", choices=(*SPLIT_GROUPS, *WORKER_SHARDS, "all"), default="all")
    parser.add_argument("--partition-plan", choices=PLANS)
    args = parser.parse_args()
    if sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") not in (None, "", "0"):
        parser.error("Native component qualification refuses optimized Python")
    if args.output.exists() or args.output.is_symlink():
        parser.error("Observation output must be a new file")
    oracle_names = rust_oracle_names(args.shard)
    missing = [key for key in oracle_names if not os.environ.get(key)]
    if args.require_rust_oracle and missing:
        parser.error("The independent Rust oracles are required: " + ", ".join(missing))
    pinned_oracles = pinned_rust_oracles(args.shard)
    actual_lineage = lineage()
    head_before = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if actual_lineage is not None and actual_lineage["git_head"] != head_before:
        parser.error("Actual component checkout differs from CI lineage")
    plan = source_bound_plan(ROOT, args.partition_plan)
    before = sources()
    from hia.tests.native_support import NativeModule
    from hia.tools import toolchain
    builds, calls = [], Counter()
    original_init, original_many = NativeModule.__init__, NativeModule.call_many
    original_build = toolchain.build_native
    module_build = ContextVar("hia_component_native_module_build", default=False)

    def record_init(self, *values, **options):
        token = module_build.set(True)
        try:
            original_init(self, *values, **options)
        finally:
            module_build.reset(token)
        try:
            builds.append(native_build_record(self, before))
        except BaseException:
            self.close()
            raise

    def record_build(source, output, **options):
        receipt, document = original_build(source, output, **options)
        if not module_build.get():
            builds.append(direct_native_build_record(source, toolchain.HIA_ROOT, output,
                                                     receipt, before))
        return receipt, document

    def record_many(self, cases, **options):
        results = original_many(self, cases, **options)
        backend = self.receipt["chain_migration"]["backend"]
        for result in results:
            calls[(backend, result.status)] += 1
        return results

    NativeModule.__init__, NativeModule.call_many = record_init, record_many
    toolchain.build_native = record_build
    started = time.monotonic()
    try:
        suite = unittest.defaultTestLoader.discover(str(ROOT / "hia/tests"),
                                                   pattern="test_*.py", top_level_dir=str(ROOT))
        suite, partition = select_suite(suite, args.shard, plan)
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2,
                                         resultclass=ObservedResult).run(suite)
    finally:
        NativeModule.__init__, NativeModule.call_many = original_init, original_many
        toolchain.build_native = original_build
    after = sources()
    head_after = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    stable = before == after and head_before == head_after
    partition = record_completion(partition, result)
    accepted = (result.wasSuccessful() and stable and partition["all_selected_completed"]
                and (not args.require_rust_oracle or not result.skipped))
    binding_path = ROOT / "hia/qualification/compiler-binding.json"
    compiler_binding = json.loads(binding_path.read_text())
    compiler_matches = all(b["compiler_sha256"] == compiler_binding["compiler_sha256"]
        for b in builds if b["chain_migration"]["backend"] == "selfhost")
    oracle_records = {key: {"executable_sha256": digest(Path(os.environ[key]).read_bytes())}
                      for key in oracle_names if os.environ.get(key)}
    pins_unchanged = all(oracle_records.get(key) == {"executable_sha256": wanted}
                         for key, wanted in pinned_oracles.items())
    accepted = accepted and compiler_matches and pins_unchanged
    reference = os.environ.get("TRNM_HIA_RUST_REFERENCE")
    report = {"schema": "trnm.hia.native-qualification.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if accepted and not result.skipped else "PASS_WITH_SKIPS" if accepted else "FAIL",
        "source_commit_observed": head_before,
        "lineage": actual_lineage,
        "test_partition": partition,
        "independent_rust_oracles_required": args.require_rust_oracle,
        "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True)),
        "source_inputs": before, "source_set_sha256": digest(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()),
        "source_unchanged_during_tests": stable,
        "tests": {"run": result.testsRun, "failures": [(str(test), error) for test, error in result.failures],
            "errors": [(str(test), error) for test, error in result.errors],
            "skipped": [(str(test), why) for test, why in result.skipped]},
        "native_calls_through_shared_runner": [{"backend": b, "outcome": s, "count": count}
                                               for (b, s), count in sorted(calls.items())],
        "additional_raw_abi_probes": "The crypto, closed-round, state-root and executor suites also execute explicit native pointer/capacity probes outside the shared-runner counts. M05 lane-owner tests retain actual private contexts across raw native calls, compare complete public-operation histories with the original Rust crate and exercise a real allocator refusal. State-root executes the original 65536-row limit in a separately bounded native child; executor executes an 8192-transaction arena with real misalignment. RS46 executes the original 4 MiB chunk and 6292022-byte six-shard input through its separately bounded native runner; these byte calls are outside the shared-runner counts. Escrow and governance execute complete private mutable sessions through bounded native runners, including real allocation failures; their calls and complete original comparisons remain in dedicated raw artifacts outside shared-runner counts. Peer-lease values use another bounded native runner and retain both the complete actual original crate baseline and all private value comparisons in their own artifact. Oracle values and serde_json use separate sealed native children; their calls, four complete original crate configurations, checked-overflow traps and raw comparisons remain in a dedicated artifact outside shared-runner counts. Control-plane value, private-registry and local signature-guard suites retain their actual original Rust and native observations in separate artifacts; the new local Ed25519 provider profile does not establish production identity. Reactor synthetic API contracts are separate native ELF calls, not real OS fault injection. Complete OS reactor, persistence, executor-original, transport-original and RS46-original controls run in their own mandatory workflow steps. Work's deterministic hardware-scheduled handshake regression and complete native runtime regression have dedicated actual process and raw evidence.",
        "builds": builds, "wall_seconds": time.monotonic() - started,
        "rust_reference": None if reference is None else {
            "executable_sha256": digest(Path(reference).read_bytes()),
            "compiler": subprocess.check_output(["rustc", "-Vv"], text=True)},
        "rust_oracles": oracle_records,
        "pinned_rust_oracles": pinned_oracles,
        "pinned_rust_oracles_unchanged": pins_unchanged,
        "rust_libraries": {key: {"rlib_sha256": digest(Path(os.environ[key]).read_bytes())}
                           for key in ("TRNM_HIA_RUST_TYPES_RLIB",) if os.environ.get(key)},
        "upstream_cold_gate_executed_in_this_run": False,
        "retained_compiler_binding_sha256": digest(binding_path.read_bytes()),
        "selfhost_compiler_matches_cold_qualified_image": compiler_matches,
        "whole_chain_native": False,
        "old_stack_can_be_removed": False, "production_activation": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "tests": result.testsRun, "shard": args.shard,
                      "skipped": len(result.skipped), "source_set_sha256": report["source_set_sha256"],
                      "shared_runner_calls": sum(calls.values()), "wall_seconds": report["wall_seconds"]}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
