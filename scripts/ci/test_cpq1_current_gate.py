#!/usr/bin/env python3
"""Bounded controls for CPQ1's current-source entry and retained profile guards.

Only the new orchestration uses a mocked current.inspect result. The profile
predicates and descriptor reader run against six small synthetic files. These
controls never call frozen.check or claim whole-corpus/native qualification.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import check_pq_research_integration as frozen
import cpq1_current_gate as gate
import pq_corpus_current_v2 as current

ROOT = Path(__file__).resolve().parents[2]


class CurrentCpqGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cpq-current-gate-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        native_evidence = "qualification/cpq-current-contract-fixture/README.md"
        account_evidence = "evidence/pon-pq-account-native-20261028/README.md"
        required = sorted(frozen.NATIVE_REQUIRED_PATHS)
        self.manifest = {
            "schema": "trnm-pq-cross-branch-corpus-v1",
            "status": "research-only-hold-no-go",
            "parent_profile": "pon-nakamoto-v1",
            "upstream_heads": {name: "1" * 40 for name in frozen.REQUIRED_UPSTREAM},
            "assertions": {name: False for name in frozen.REQUIRED_FALSE},
            "required_paths": required,
            "pinned_blobs": {path: "1" * 40 for path in required},
            "native_network_owner_slice_v2": {
                **copy.deepcopy(frozen.NATIVE_V2_EXPECTED), "evidence": native_evidence,
            },
            "native_account_owner_slice_v1": {
                "profile": "native-pq-qtx1-account-v1", "feature": "pq-native-openssl",
                "contract": "docs/security/PQ_NATIVE_ACCOUNT_OWNER_V1.md",
                "evidence": account_evidence, "migration_wire": "PQG1/v1",
                "transaction_wire": "QTX1/v1", "transaction_byte_limit": 8192,
                "transaction_count_limit": 16, "liability_mode": "all-source-records-locked",
                "transfer_only": True, "original_m06_nonce_fee_owner": True,
                "dual_possession_signatures_required": True,
                "miner_roster_permission_required": False,
                "independent_source_history_authenticated": False,
                **{name: False for name in frozen.NATIVE_FALSE},
            },
            "overwrites": {
                "formal/pon-nakamoto-v1/pq_cell_custody.py": "cell",
                "formal/pon-nakamoto-v1/pq_account_migration.py": "migration",
                "formal/pon-nakamoto-v1/pq_pql5_quorum.py": "witness",
                "formal/pon-nakamoto-v1/test_pq_pql5_quorum.py": "witness",
            },
        }
        self.policies = {
            "config/consensus-mainline.json": {
                "production_consensus_activation": False, "runtime_implemented": False,
                "active_consensus_implementation": None,
            },
            "config/pon/devnet-v1.json": {
                "production_activation": False, "max_transaction_bytes": 2048,
            },
            "config/pon/post-quantum-transition-v1.json": {
                "production_activation": False, "allow_classical_fallback": False,
                "reference_signature": {"signature_bytes": 3309},
                "existing_devnet_limits": {"post_quantum_transaction_wire_compatible": False},
            },
        }
        for path, value in self.policies.items():
            self.put_json(path, value)
        for path in (native_evidence, account_evidence):
            self.put(path, b"Synthetic metadata fixture; no cryptographic acceptance.\n")
        self.put_json(frozen.REL_MANIFEST, self.manifest)

    def put(self, relative, raw):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)

    def put_json(self, relative, value):
        self.put(relative, (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"))

    def checked_contract(self, manifest=None):
        gate._check_original_contracts(
            self.root, self.manifest if manifest is None else manifest)

    def test_guarded_current_success_keeps_hold_and_false_qualification(self):
        current_report = {
            "schema": current.SCHEMA, "status": "HOLD",
            "current_source_correspondence_checked": True,
            "source_revision_bound": False, **copy.deepcopy(current.QUALIFICATION),
        }
        saved = copy.deepcopy(current_report)
        with mock.patch.object(current, "inspect", return_value=current_report) as inspect:
            result = gate.inspect(self.root)
            inspect.assert_called_once_with(self.root.absolute())
        self.assertEqual(current_report, saved)
        self.assertEqual(result, {
            **saved, "schema": gate.SCHEMA, "original_profile_contracts_checked": True,
        })
        self.assertEqual({key: result[key] for key in current.QUALIFICATION},
                         current.QUALIFICATION)
        self.assertIs(result["source_revision_bound"], False)

    def test_current_refusal_and_midinspection_contract_rewrite_fail_closed(self):
        with mock.patch.object(current, "inspect",
                               side_effect=current.CurrentCorpusError("fixture current mismatch")):
            with self.assertRaisesRegex(current.CurrentCorpusError, "fixture current mismatch"):
                gate.inspect(self.root)
        path = self.root / frozen.REL_MANIFEST
        before = path.read_bytes()

        def rewrite(_root):
            path.write_bytes(before + b" ")
            return {"schema": current.SCHEMA, "status": "HOLD", **current.QUALIFICATION}

        with mock.patch.object(current, "inspect", side_effect=rewrite):
            with self.assertRaisesRegex(frozen.IntegrityError, "original contract changed"):
                gate.inspect(self.root)

    def test_original_namespace_provenance_and_activation_predicates_refuse(self):
        for field, value in (
            ("schema", "unreviewed"), ("status", "PASS"), ("parent_profile", "other"),
            ("upstream_heads", {}), ("upstream_heads", {name: "g" * 40
                                                       for name in frozen.REQUIRED_UPSTREAM}),
            ("assertions", {}),
            ("assertions", {name: True for name in frozen.REQUIRED_FALSE}),
        ):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(self.manifest)
                changed[field] = value
                with self.assertRaises(frozen.IntegrityError):
                    self.checked_contract(changed)
        changed = copy.deepcopy(self.manifest)
        changed["parent_profile"] = "other"
        self.put_json(frozen.REL_MANIFEST, changed)
        with mock.patch.object(current, "inspect") as inspect:
            with self.assertRaisesRegex(frozen.IntegrityError, "wrong profile"):
                gate.inspect(self.root)
            inspect.assert_not_called()

    def test_transport_types_required_roster_and_declared_shapes_refuse(self):
        variants = []
        for field, value in (
            ("signature_bytes", 3310), ("tpq1_peer_purpose", True),
            ("production_activation", True), ("allow_legacy_fallback", True),
        ):
            changed = copy.deepcopy(self.manifest)
            changed["native_network_owner_slice_v2"][field] = value
            variants.append(changed)
        for field, value in (
            ("native_network_owner_slice_v1", {}),
            ("required_paths", self.manifest["required_paths"][1:]),
            ("required_paths", self.manifest["required_paths"] * 2),
            ("pinned_blobs", {}),
        ):
            changed = copy.deepcopy(self.manifest)
            changed[field] = value
            variants.append(changed)
        for index, changed in enumerate(variants):
            with self.subTest(case=index), self.assertRaises(frozen.IntegrityError):
                self.checked_contract(changed)

    def test_account_bounds_and_all_original_false_flags_refuse(self):
        for field, value in (
            ("transaction_byte_limit", True), ("transaction_count_limit", True),
            ("transaction_byte_limit", 8193), ("transaction_count_limit", 17),
            ("dual_possession_signatures_required", False),
            ("miner_roster_permission_required", True),
            ("independent_source_history_authenticated", True),
            *((name, True) for name in sorted(frozen.NATIVE_FALSE)),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.manifest)
                changed["native_account_owner_slice_v1"][field] = value
                with self.assertRaises(frozen.IntegrityError):
                    self.checked_contract(changed)

    def test_evidence_locator_missing_file_and_symlink_are_refused(self):
        changed = copy.deepcopy(self.manifest)
        changed["native_network_owner_slice_v2"]["evidence"] = "other/README.md"
        with self.assertRaisesRegex(frozen.IntegrityError, "evidence locator"):
            self.checked_contract(changed)
        for section in ("native_network_owner_slice_v2", "native_account_owner_slice_v1"):
            relative = self.manifest[section]["evidence"]
            path = self.root / relative
            raw = path.read_bytes()
            with self.subTest(section=section, condition="missing"):
                path.unlink()
                with self.assertRaises(frozen.IntegrityError):
                    self.checked_contract()
                path.write_bytes(raw)
            with self.subTest(section=section, condition="symlink"):
                saved = path.with_suffix(".stored")
                path.rename(saved)
                try:
                    path.symlink_to(saved.name)
                    with self.assertRaises(frozen.IntegrityError):
                        self.checked_contract()
                finally:
                    if path.is_symlink():
                        path.unlink()
                    saved.rename(path)

    def test_installed_consensus_devnet_pq_and_overwrites_guards_refuse(self):
        changed = copy.deepcopy(self.manifest)
        changed["overwrites"]["formal/pon-nakamoto-v1/pq_cell_custody.py"] = "base"
        with self.assertRaisesRegex(frozen.IntegrityError, "source substitution"):
            self.checked_contract(changed)
        mutations = (
            ("config/consensus-mainline.json", "production_consensus_activation", True),
            ("config/consensus-mainline.json", "runtime_implemented", True),
            ("config/consensus-mainline.json", "active_consensus_implementation", "other"),
            ("config/pon/devnet-v1.json", "production_activation", True),
            ("config/pon/devnet-v1.json", "max_transaction_bytes", 2049),
            ("config/pon/post-quantum-transition-v1.json", "production_activation", True),
            ("config/pon/post-quantum-transition-v1.json", "allow_classical_fallback", True),
            ("config/pon/post-quantum-transition-v1.json", "reference_signature",
             {"signature_bytes": 3310}),
            ("config/pon/post-quantum-transition-v1.json", "existing_devnet_limits",
             {"post_quantum_transaction_wire_compatible": True}),
        )
        for path, field, value in mutations:
            with self.subTest(path=path, field=field):
                changed_policy = copy.deepcopy(self.policies[path])
                changed_policy[field] = value
                self.put_json(path, changed_policy)
                try:
                    with self.assertRaisesRegex(frozen.IntegrityError, "installed consensus or PQ gate"):
                        self.checked_contract()
                finally:
                    self.put_json(path, self.policies[path])

    def test_cpq_workflow_keeps_original_commands_caps_and_current_gate(self):
        workflow = (ROOT / ".github/workflows/cpq1-full-content.yml").read_text()
        commands = [line.strip() for line in workflow.splitlines()
                    if line.strip().startswith("record ")]
        self.assertEqual(commands, [
            "record compiler rustc +1.95.0 -Vv",
            "record locked-graph cargo +1.95.0 metadata --locked --manifest-path trillionnium/Cargo.toml --format-version 1",
            "record locked-fuzz-graph cargo +1.95.0 metadata --locked --manifest-path tests/fuzz/Cargo.toml --format-version 1",
            "record vectors python3 scripts/ci/check_content_commitment_vectors.py",
            "record graph-vectors python3 scripts/ci/check_cell_content_graph_vectors_v3.py",
            "record hash-purpose-controls python3 scripts/ci/test_hash_use_contract.py",
            "record hash-purpose-source python3 scripts/ci/hash_use_contract.py",
            "record current-source-contract-controls python3 -B scripts/ci/test_cpq1_current_gate.py -v",
            "record source-integrity python3 -B scripts/ci/cpq1_current_gate.py",
            "record source-controls python3 -m unittest discover -s scripts/ci -p test_pq_research_integration.py -v",
            "record recorder-controls python3 -m unittest discover -s scripts/ci -p test_record_pq_native_command.py -v",
            "record repository python3 scripts/ci/check_repository.py",
            "record inventory python3 scripts/refresh_distributed_source_inventory.py --check",
            'record retained-libraries cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml "${packages[@]}" --lib',
            'record retained-feature-libraries cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml "${packages[@]}" --all-features --lib',
            'record retained-docs cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml "${packages[@]}" --doc',
            "record native-history cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib store::migration_history_v2 -- --test-threads=1",
            "record native-history-features cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib store::migration_history_v2 -- --test-threads=1",
            "record format cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check",
            'record strict-clippy cargo +1.95.0 clippy --locked --manifest-path trillionnium/Cargo.toml "${packages[@]}" -p trnm-pon-node --all-targets --all-features -- -D warnings',
        ])
        self.assertEqual(workflow.count("timeout-minutes: 40"), 1)
        self.assertEqual(workflow.count("runner: [ubuntu-24.04, ubuntu-24.04-arm]"), 1)
        self.assertEqual(workflow.count('--label provider --output "$out"'), 1)
        for path in (
            "scripts/ci/cpq1_current_gate.py", "scripts/ci/test_cpq1_current_gate.py",
            "scripts/ci/pq_corpus_current_v2.py", "config/pon/pq-corpus-current-source-v2.json",
        ):
            self.assertIn("      - " + path + "\n", workflow)

        for relative, command, limits in (
            (".github/workflows/pon-pq-system-continuation.yml",
             'bash "$PQ_OUT/run-command.sh" pq-source python3 -B scripts/ci/cpq1_current_gate.py',
             {"timeout-minutes: 25": 3, "timeout-minutes: 90": 1}),
            (".github/workflows/pon-throughput-evidence.yml",
             "python3 -B scripts/ci/cpq1_current_gate.py",
             {"timeout-minutes: 20": 1, "timeout-minutes: 45": 1}),
        ):
            with self.subTest(workflow=relative):
                body = (ROOT / relative).read_text()
                self.assertEqual([line.strip() for line in body.splitlines()
                                  if "scripts/ci/cpq1_current_gate.py" in line
                                  and not line.strip().startswith("-")], [command])
                self.assertNotIn("python3 scripts/ci/check_pq_research_integration.py", body)
                for timeout, count in limits.items():
                    self.assertEqual(body.count(timeout), count)
                for path in (
                    "scripts/ci/cpq1_current_gate.py", "scripts/ci/test_cpq1_current_gate.py",
                    "scripts/ci/pq_corpus_current_v2.py",
                    "config/pon/pq-corpus-current-source-v2.json",
                ):
                    self.assertIn("      - " + path + "\n", body)


if __name__ == "__main__":
    unittest.main()
