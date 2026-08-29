#!/usr/bin/env python3
"""Candidate-only differential and state-sync conformance tests.

The test module is deliberately dependency-free (Python standard library only)
and never imports a canonical Rust parser.  It runs both independently authored
binary clients against one exact fixture, then mutates each W3-W7 proof family
and the W0-W7 trace.  A second section exercises the namespace-bound staged
state-sync model and retains rollback/sidecar/WAL/torn mutants as explicit
negative controls.

Nothing in this file changes protocol, production, signer, activation, or
normative-freeze truth.  The fixture and all outputs are candidate evidence.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import sys
import unittest
from dataclasses import replace
from typing import Any

if __package__ in (None, ""):  # direct `python path/to/test_clients_b.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:  # package invocation (`python -m`) and direct unittest discovery
    from . import client_a, client_b
    from .atomicity import (
        REQUIRED_PLANES,
        AtomicityReject,
        PlaneObservation,
        authenticate_snapshot,
        double_sample,
        double_sample_strict,
    )
    from .fixture import fixture
    from .state_sync import StagedStateSync, StateSyncError, verify_manifest
except ImportError:  # pragma: no cover - exercised by `unittest discover -s`
    from conformance.g2f import client_a, client_b
    from conformance.g2f.atomicity import (
        REQUIRED_PLANES,
        AtomicityReject,
        PlaneObservation,
        authenticate_snapshot,
        double_sample,
        double_sample_strict,
    )
    from conformance.g2f.fixture import fixture
    from conformance.g2f.state_sync import StagedStateSync, StateSyncError, verify_manifest


def _layout(raw: bytes) -> dict[str, Any]:
    """Locate mutable fields in the candidate binary without a parser import."""

    cursor = 0
    magic = b"TRNM-G2F1"
    cursor += len(magic)
    version_offset = cursor
    cursor += 2
    flags_offset = cursor
    cursor += 2
    chain_len_offset = cursor
    chain_len = struct.unpack_from("<H", raw, cursor)[0]
    cursor += 2 + chain_len
    context_hash_offsets = [cursor + 32 * index for index in range(7)]
    cursor += 7 * 32
    epoch_offset = cursor
    cursor += 8
    height_offset = cursor
    cursor += 8
    block_id_offset = cursor
    cursor += 32
    root_offset = cursor
    cursor += 32
    tree_offset = cursor
    cursor += 2
    trace_count_offset = cursor
    trace_count = raw[cursor]
    cursor += 1
    trace_offsets: list[dict[str, int]] = []
    for _ in range(trace_count):
        stage_offset = cursor
        cursor += 1
        step_height_offset = cursor
        cursor += 8
        step_hash_offset = cursor
        cursor += 32
        trace_offsets.append(
            {
                "stage": stage_offset,
                "height": step_height_offset,
                "hash": step_hash_offset,
            }
        )
    family_count_offset = cursor
    family_count = raw[cursor]
    cursor += 1
    family_offsets: dict[int, dict[str, int]] = {}
    for _ in range(family_count):
        tag_offset = cursor
        tag = raw[cursor]
        cursor += 1
        size_offset = cursor
        size = struct.unpack_from("<I", raw, cursor)[0]
        cursor += 4
        payload_offset = cursor
        cursor += size
        family_offsets[tag] = {
            "tag": tag_offset,
            "size": size_offset,
            "payload": payload_offset,
            "length": size,
        }
    records_count_offset = cursor
    record_count = struct.unpack_from("<H", raw, cursor)[0]
    cursor += 2
    record_offsets: list[dict[str, int]] = []
    for _ in range(record_count):
        kind_offset = cursor
        cursor += 2
        object_id_offset = cursor
        cursor += 32
        version_record_offset = cursor
        cursor += 8
        value_len_offset = cursor
        value_len = struct.unpack_from("<I", raw, cursor)[0]
        cursor += 4
        value_offset = cursor
        cursor += value_len
        record_offsets.append(
            {
                "kind": kind_offset,
                "object_id": object_id_offset,
                "version": version_record_offset,
                "value_len": value_len_offset,
                "value": value_offset,
                "length": value_len,
            }
        )
    if cursor != len(raw):
        raise AssertionError(f"fixture layout ended at {cursor}, raw length {len(raw)}")
    return {
        "version": version_offset,
        "flags": flags_offset,
        "chain_len": chain_len_offset,
        "context_hashes": context_hash_offsets,
        "epoch": epoch_offset,
        "height": height_offset,
        "block_id": block_id_offset,
        "root": root_offset,
        "tree": tree_offset,
        "trace_count": trace_count_offset,
        "trace": trace_offsets,
        "family_count": family_count_offset,
        "families": family_offsets,
        "records_count": records_count_offset,
        "records": record_offsets,
    }


def _flip(raw: bytes, offset: int) -> bytes:
    mutated = bytearray(raw)
    mutated[offset] ^= 1
    return bytes(mutated)


def _mutant_bytes(raw: bytes) -> dict[str, bytes]:
    """Return named wire mutants; every one must fail in both clients."""

    layout = _layout(raw)
    mutants: dict[str, bytes] = {
        "trailing_bytes": raw + b"\0",
        "truncated_tail": raw[:-1],
        "wrong_version": bytes(bytearray(raw[: layout["version"]] + b"\x02\x00" + raw[layout["version"] + 2 :])),
        "composite_root_flag": bytes(bytearray(raw[: layout["flags"]] + b"\x01\x00" + raw[layout["flags"] + 2 :])),
        "wrong_tree_version": bytes(bytearray(raw[: layout["tree"]] + b"\x01\x00" + raw[layout["tree"] + 2 :])),
        "missing_trace_stage": bytes(bytearray(raw[: layout["trace_count"]] + b"\x07" + raw[layout["trace_count"] + 1 :])),
        "trace_stage_reordered": _flip(raw, layout["trace"][0]["stage"]),
        "trace_digest_mutation": _flip(raw, layout["trace"][3]["hash"]),
        "wrong_block_id": _flip(raw, layout["block_id"]),
        "wrong_application_root": _flip(raw, layout["root"]),
        "missing_family": bytes(bytearray(raw[: layout["family_count"]] + b"\x05" + raw[layout["family_count"] + 1 :])),
    }
    # Mutate one byte in each W3-W7/upgrade family payload.  The family tags
    # are 3..8 in the candidate carrier and each payload is non-empty.
    for tag in (3, 4, 5, 6, 7, 8):
        offset = layout["families"][tag]["payload"]
        mutants[f"family_{tag}_mutation"] = _flip(raw, offset)
    # Swap the first two family tags without touching payload bytes.
    first = layout["families"][3]["tag"]
    second = layout["families"][4]["tag"]
    swapped = bytearray(raw)
    swapped[first], swapped[second] = swapped[second], swapped[first]
    mutants["family_order_swap"] = bytes(swapped)
    # Claim a payload larger than the local proof bound.  The parser must fail
    # before reading attacker-controlled bytes (the original payload remains).
    size_offset = layout["families"][3]["size"]
    oversized = bytearray(raw)
    oversized[size_offset : size_offset + 4] = struct.pack("<I", 513)
    mutants["family_size_bound"] = bytes(oversized)
    # Corrupt the first state record and exercise root/JMT binding.
    if layout["records"]:
        mutants["state_record_value"] = _flip(raw, layout["records"][0]["value"])
        mutants["state_record_kind_zero"] = bytes(
            bytearray(raw[: layout["records"][0]["kind"]] + b"\0\0" + raw[layout["records"][0]["kind"] + 2 :])
        )
    return mutants


def _expected_sync_args(f: Any) -> dict[str, Any]:
    return {
        "expected_block_id": bytes.fromhex(f.manifest["block_id"]),
        "expected_root": bytes.fromhex(f.manifest["state_root"]),
        "expected_height": f.height,
    }


class DifferentialClientTests(unittest.TestCase):
    def test_positive_bundle_agrees(self) -> None:
        f = fixture()
        raw = f.bundle.encoded
        a = client_a.verify_bundle(raw)
        b = client_b.verify_bundle(raw)
        self.assertTrue(a["ok"], a)
        self.assertTrue(b["ok"], b)
        self.assertEqual(a["height"], b["height"])
        self.assertEqual(a["block_id"], b["block_id"])
        self.assertEqual(a["post_state_root"], b["post_state_root"])
        self.assertEqual(a["families"], b["families"])
        self.assertEqual(a["trace_stages"], b["trace_stages"])

    def test_all_wire_mutants_fail_closed_in_both_clients(self) -> None:
        raw = fixture().bundle.encoded
        mutants = _mutant_bytes(raw)
        failures: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        for name, mutant in mutants.items():
            result_a = client_a.verify_bundle(mutant)
            result_b = client_b.verify_bundle(mutant)
            if result_a.get("ok") or result_b.get("ok"):
                failures[name] = (result_a, result_b)
            elif result_a.get("code") != result_b.get("code"):
                failures[name] = (result_a, result_b)
        self.assertFalse(failures, f"accepted wire mutants: {failures}")
        self.assertGreaterEqual(len(mutants), 20)

    def test_clients_are_import_independent(self) -> None:
        """AST check: neither parser imports the other or canonical crates."""

        import ast

        root = Path(__file__).resolve().parent
        forbidden = {"client_a", "client_b", "trnm_poco", "trillionnium"}
        for filename in ("client_a.py", "client_b.py"):
            tree = ast.parse((root / filename).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = {alias.name.split(".", 1)[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    names = {(node.module or "").split(".", 1)[0]}
                else:
                    continue
                self.assertTrue(not (names & forbidden), f"{filename} imports {names & forbidden}")


class AtomicityConformanceTests(unittest.TestCase):
    def test_common_authenticated_cut_and_mixed_plane_rejection(self) -> None:
        transaction = b"t" * 32
        observations = [
            PlaneObservation(name, transaction, 11, name.encode("ascii"), source_generation=4)
            for name in REQUIRED_PLANES
        ]
        snapshot = authenticate_snapshot(observations)
        self.assertEqual(snapshot.version, 11)
        self.assertEqual(snapshot.source_generation, 4)
        mixed = list(observations)
        mixed[-1] = PlaneObservation("Order", transaction, 12, b"Order", source_generation=4)
        with self.assertRaises(AtomicityReject) as error:
            authenticate_snapshot(mixed)
        self.assertEqual(error.exception.code, "mixed_transaction")

    def test_double_sample_rejects_token_bytes_and_generation_aba(self) -> None:
        transaction = b"t" * 32
        first = [
            PlaneObservation(name, transaction, 11, name.encode("ascii"), source_generation=4)
            for name in REQUIRED_PLANES
        ]
        changed = [
            PlaneObservation(name, transaction, 11, name.encode("ascii"), source_generation=5)
            for name in REQUIRED_PLANES
        ]
        changed[0] = PlaneObservation("DA", transaction, 11, b"DA-mutated", source_generation=5)
        with self.assertRaises(AtomicityReject) as error:
            double_sample(iter((first, changed)).__next__)
        self.assertEqual(error.exception.code, "source_changed")

        # A -> B -> A bytes with the same transaction id is not enough to
        # claim an atomic cut; the owner-issued generation must change and a
        # strict consumer refuses an unsequenced source.
        unsequenced = [
            PlaneObservation(name, transaction, 11, name.encode("ascii"))
            for name in REQUIRED_PLANES
        ]
        with self.assertRaises(AtomicityReject) as error:
            double_sample_strict(iter((unsequenced, unsequenced)).__next__)
        self.assertEqual(error.exception.code, "generation_missing")


class StateSyncConformanceTests(unittest.TestCase):
    def test_snapshot_positive_and_root_binding(self) -> None:
        f = fixture()
        view = verify_manifest(f.manifest, f.chunks, f.context, **_expected_sync_args(f))
        self.assertEqual(view.height, f.height)
        self.assertEqual(view.state_root.hex(), f.manifest["state_root"])
        self.assertEqual(len(view.records), len(f.records))

    def test_snapshot_mutants_reject(self) -> None:
        f = fixture()
        mutants: dict[str, tuple[dict[str, Any], tuple[bytes, ...]]] = {}
        wrong_root = copy.deepcopy(f.manifest)
        wrong_root["state_root"] = "ff" * 32
        mutants["state_root"] = (wrong_root, f.chunks)
        wrong_hash = copy.deepcopy(f.manifest)
        wrong_hash["chunk_entries"][0]["uncompressed_hash"] = "ff" * 32
        mutants["chunk_hash"] = (wrong_hash, f.chunks)
        wrong_size = copy.deepcopy(f.manifest)
        wrong_size["total_uncompressed_bytes"] += 1
        mutants["total_size"] = (wrong_size, f.chunks)
        missing_chunk = copy.deepcopy(f.manifest)
        missing_chunk["chunk_count"] = 2
        mutants["missing_chunk"] = (missing_chunk, f.chunks)
        wrong_interval = copy.deepcopy(f.manifest)
        wrong_interval["chunk_entries"][0]["first_state_key"] = "ee" * 32
        mutants["chunk_interval"] = (wrong_interval, f.chunks)
        profile_downgrade = copy.deepcopy(f.manifest)
        profile_downgrade["compression_profile_hash"] = "aa" * 32
        mutants["compression_downgrade"] = (profile_downgrade, f.chunks)
        stale_height = copy.deepcopy(f.manifest)
        stale_height["height"] = 0
        mutants["stale_height"] = (stale_height, f.chunks)
        for name, (manifest, chunks) in mutants.items():
            with self.subTest(name=name):
                with self.assertRaises(StateSyncError):
                    verify_manifest(manifest, chunks, f.context, **_expected_sync_args(f))

    def test_staged_swap_positive_and_external_anchor(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        previous = owner.anchor
        token = owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_expected_sync_args(f),
            generation=1,
        )
        current = owner.commit(token, generation=1, expected_anchor=previous)
        self.assertEqual(current.generation, 1)
        self.assertEqual(current.height, f.height)
        self.assertEqual(current.state_root.hex(), f.manifest["state_root"])
        self.assertIs(owner.active, token)
        self.assertEqual(owner.reopen(), current)

    def test_swap_requires_explicit_external_anchor_compare(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        token = owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_expected_sync_args(f),
            generation=1,
        )
        with self.assertRaises(StateSyncError):
            owner.commit(token, generation=1)

    def test_staged_swap_residue_mutants_reject_before_authority(self) -> None:
        f = fixture()
        for residue in ("sidecar", "wal", "intent"):
            with self.subTest(residue=residue):
                owner = StagedStateSync(f.context["chain_id"])
                if residue == "sidecar":
                    owner.mark_sidecar(".g2f-stage.sidecar")
                elif residue == "wal":
                    owner.mark_wal()
                else:
                    token = owner.stage(
                        f.manifest,
                        f.chunks,
                        f.context,
                        **_expected_sync_args(f),
                        generation=1,
                    )
                    with self.assertRaises(StateSyncError):
                        owner.commit(
                            token,
                            generation=1,
                            expected_anchor=owner.anchor,
                            simulate_crash="before_active",
                        )
                if residue != "intent":
                    with self.assertRaises(StateSyncError):
                        owner.stage(
                            f.manifest,
                            f.chunks,
                            f.context,
                            **_expected_sync_args(f),
                            generation=1,
                        )
                with self.assertRaises(StateSyncError):
                    owner.reopen()

    def test_namespace_copy_and_rename_mutants_reject(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        token = owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_expected_sync_args(f),
            generation=1,
        )
        copied = owner.clone_namespace("copied-namespace")
        with self.assertRaises(StateSyncError):
            copied.commit(token, generation=1, expected_anchor=copied.anchor)
        renamed = replace(token, namespace_id="renamed-namespace")
        with self.assertRaises(StateSyncError):
            owner.commit(renamed, generation=1, expected_anchor=owner.anchor)

    def test_external_anchor_rollback_and_equivocation_mutants_reject(self) -> None:
        f = fixture()
        owner = StagedStateSync(f.context["chain_id"])
        first = owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_expected_sync_args(f),
            generation=1,
        )
        old_anchor = owner.anchor
        owner.commit(first, generation=1, expected_anchor=old_anchor)
        # A stale expected anchor cannot authorize a second stage.
        second = owner.stage(
            f.manifest,
            f.chunks,
            f.context,
            **_expected_sync_args(f),
            generation=2,
        )
        with self.assertRaises(StateSyncError):
            owner.commit(second, generation=2, expected_anchor=old_anchor)
        # Simulate rollback of the external anchor while active state remains;
        # reopen must fence the mismatch before authority use.
        owner._anchor = replace(
            owner.anchor,
            generation=0,
            height=0,
            state_root=b"\0" * 32,
            manifest_digest=b"\0" * 32,
        )
        with self.assertRaises(StateSyncError):
            owner.reopen()


def run_suite() -> dict[str, Any]:
    """Run every discovered G2F test module and return candidate evidence.

    The first version of the harness loaded only this module while reporting
    the count from discovery.  That made the evidence count look complete
    even if an atomicity or state-sync test failed.  Keep discovery and
    execution on the same loader so the result is fail-closed and auditable.
    """

    stream = __import__("io").StringIO()
    loader = unittest.defaultTestLoader
    root = Path(__file__).resolve().parents[2]
    try:
        discovered = loader.discover(
            str(root / "conformance" / "g2f"),
            pattern="test_*.py",
            top_level_dir=str(root),
        )
    except Exception as exc:  # pragma: no cover - discovery is evidence
        stream.write(f"DISCOVERY ERROR: {type(exc).__name__}: {exc}\n")
        return {
            "schema": "trnm-g2f-conformance-result-v1",
            "status": "FAIL",
            "classification": "candidate-non-normative",
            "authority": "candidate",
            "tests_run": 0,
            "discovered_tests": 0,
            "tests_run_positive": False,
            "failures": 0,
            "errors": 1,
            "output": stream.getvalue(),
            "clients": ["client-a", "client-b"],
            "proof_families": ["order", "da", "execution", "result", "settlement", "upgrade"],
            "trace_stages": list(range(8)),
            "known_nonclaims": [
                "not a production signer or activation path",
                "candidate fixture is not a normative W3-W7 wire",
                "no 64-epoch/10000-header campaign",
            ],
        }
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(
        discovered
    )
    discovered_tests = discovered.countTestCases()
    tests_run_positive = result.testsRun > 0 and result.testsRun == discovered_tests
    if not tests_run_positive:
        stream.write(
            "ASSERTION FAILED: executed tests must equal discovered tests and be > 0\n"
        )
    return {
        "schema": "trnm-g2f-conformance-result-v1",
        "status": "PASS" if result.wasSuccessful() and tests_run_positive else "FAIL",
        "classification": "candidate-non-normative",
        "authority": "candidate",
        "tests_run": result.testsRun,
        "discovered_tests": discovered_tests,
        "tests_run_positive": tests_run_positive,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "output": stream.getvalue(),
        "clients": ["client-a", "client-b"],
        "proof_families": ["order", "da", "execution", "result", "settlement", "upgrade"],
        "trace_stages": list(range(8)),
        "known_nonclaims": [
            "not a production signer or activation path",
            "candidate fixture is not a normative W3-W7 wire",
            "no 64-epoch/10000-header campaign",
        ],
    }


if __name__ == "__main__":
    report = run_suite()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
