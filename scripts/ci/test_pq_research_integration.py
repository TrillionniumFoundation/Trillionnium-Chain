"""Research-only PQL7 cross-source and activation-negative gate tests."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_pq_research_integration import (
    CONVERGENCE_REQUIRED_PATHS, IntegrityError, NATIVE_FALSE,
    NATIVE_REQUIRED_PATHS, NATIVE_V2_EXPECTED, _safe_regular, check,
)
from test_pq_chain_claim_guard import DescriptorReaderControls


class CorpusReaderRaceTests(DescriptorReaderControls, unittest.TestCase):
    reader = staticmethod(_safe_regular)
    reader_error = IntegrityError
    byte_limit = 4 * 1024 * 1024

REQUIRED = (
    "config/consensus-mainline.json", "config/pon/devnet-v1.json",
    "config/pon/post-quantum-transition-v1.json",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "trillionnium/crates/trnm-protocol/src/lib.rs",
    "trillionnium/crates/trnm-protocol/src/pq_frame.rs",
    "formal/pon-nakamoto-v1/pq_envelope.py",
    "formal/pon-nakamoto-v1/pq_account_migration.py",
    "formal/pon-nakamoto-v1/pq_transaction.py",
    "formal/pon-nakamoto-v1/pq_cell_custody.py",
    "formal/pon-nakamoto-v1/pq_cell_swarm.py",
    "formal/pon-nakamoto-v1/pq_cell_bundle_atomic.py",
    "formal/pon-nakamoto-v1/pq_pql5_quorum.py",
    "formal/pon-nakamoto-v1/pq_pql6_equivocation.py",
    "formal/pon-nakamoto-v1/pqg_native_verify.c",
    "formal/pon-nakamoto-v1/pq_import_projection_verify.c",
    "formal/pon-nakamoto-v1/pql3_native_verify.c",
    "formal/pon-nakamoto-v1/pq_qtx1_verify.c",
    "formal/pon-nakamoto-v1/pq_pql5_native_verify.c",
)
# Independent literal roster from the reviewed 29-file scope.
REVIEWED_CELL_PAGED_PATHS = (
    "docs/development/specs/pon/CELL_SEALED_PAGED_RESEARCH_NEXT_USE_V1.md",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_next_use_v2.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_paged_next_use_v1.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/bep52.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/paged.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/paged/tests.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/snapshot.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/release.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/release/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage/peer.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage/peer/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/codec.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/file.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/restore.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/restore/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release_snapshot.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release_snapshot/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention/reservation_preflight.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/chunk_read.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/shard_plan_paged.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged/recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged/recovery/execute.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged/recovery/preflight.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_paged_shard_plan_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_paged_shard_recovery_tests.rs",
)

OVERWRITES = {
    "formal/pon-nakamoto-v1/pq_cell_custody.py": "cell",
    "formal/pon-nakamoto-v1/pq_account_migration.py": "migration",
    "formal/pon-nakamoto-v1/pq_pql5_quorum.py": "witness",
    "formal/pon-nakamoto-v1/test_pq_pql5_quorum.py": "witness",
}


def blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class CorpusGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pins = {}
        for p in REQUIRED:
            if p == "config/consensus-mainline.json":
                data = b'{"production_consensus_activation":false,"runtime_implemented":false,"active_consensus_implementation":null}'
            elif p == "config/pon/devnet-v1.json":
                data = b'{"production_activation":false,"max_transaction_bytes":2048}'
            elif p == "config/pon/post-quantum-transition-v1.json":
                data = b'{"production_activation":false,"allow_classical_fallback":false,"reference_signature":{"signature_bytes":3309},"existing_devnet_limits":{"post_quantum_transaction_wire_compatible":false}}'
            else:
                data = p.encode()
            self.put(p, data)
        self.put("formal/pon-nakamoto-v1/test_pq_pql5_quorum.py", b"unit-test")
        for p in sorted(NATIVE_REQUIRED_PATHS - set(REQUIRED)):
            self.put(p, p.encode())
        for name in ("trnm-crypto-primitives", "trnm-mvcc-fee", "trnm-pon-node"):
            contents = ('[package.metadata.trnm]\nproduction_activation = false\n'
                        'consensus_authority = false\n[features]\ndefault = []\n'
                        'pq-native-openssl = ["dep:openssl"]\n[dependencies]\n'
                        'openssl = {version = "=0.10.81", optional = true}\n')
            if name == "trnm-crypto-primitives":
                contents += ('ml-dsa = {version = "=0.1.1", default-features = false, '
                             'features = ["alloc", "zeroize"]}\n')
            self.put(f"trillionnium/crates/{name}/Cargo.toml", contents.encode())
        report = "evidence/fixture-pq-native-source/README.md"
        self.put(report, b"Source fixture only; no cryptographic acceptance.")
        account_report = "evidence/pon-pq-account-native-20261028/README.md"
        self.put(account_report, b"Source fixture only; no account acceptance.")
        self.manifest = {
            "schema": "trnm-pq-cross-branch-corpus-v1",
            "status": "research-only-hold-no-go", "parent_profile": "pon-nakamoto-v1",
            "upstream_heads": {k: "1"*40 for k in ("base", "cell", "migration", "witness", "roster", "parity")},
            "required_paths": sorted(set(REQUIRED) | NATIVE_REQUIRED_PATHS), "pinned_blobs": self.pins,
            "overwrites": dict(OVERWRITES),
            "assertions": {x: False for x in (
                "production_activation", "independent_accepted", "native_pq_node_integrated",
                "quantum_pon_hardness_qualified", "physical_rollback_resistant",
                "hepta_final_use_integrated", "public_wan_accepted", "allow_legacy_fallback")},
            "native_network_owner_slice_v2": {
                **NATIVE_V2_EXPECTED,
                "evidence": report,
            },
            "native_account_owner_slice_v1": {
                "profile": "native-pq-qtx1-account-v1",
                "feature": "pq-native-openssl",
                "contract": "docs/security/PQ_NATIVE_ACCOUNT_OWNER_V1.md",
                "evidence": account_report,
                "migration_wire": "PQG1/v1",
                "transaction_wire": "QTX1/v1",
                "transaction_byte_limit": 8192,
                "transaction_count_limit": 16,
                "liability_mode": "all-source-records-locked",
                "transfer_only": True,
                "original_m06_nonce_fee_owner": True,
                "dual_possession_signatures_required": True,
                "miner_roster_permission_required": False,
                "independent_source_history_authenticated": False,
                **{flag: False for flag in NATIVE_FALSE},
            },
        }
        self.save()

    def put(self, p, data):
        q = self.root / p
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_bytes(data)
        self.pins[p] = blob(data)

    def save(self):
        q = self.root / "config/pon/pq-cross-branch-corpus-v1.json"
        q.parent.mkdir(parents=True, exist_ok=True)
        q.write_text(json.dumps(self.manifest))

    def test_valid_offline_fixture_is_still_hold(self):
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertFalse(result["cryptographic_acceptance"])
        self.assertFalse(result["node_activated"])

    def test_consolidation_controls_require_each_path_and_pin(self):
        # Independent literals preserve the selected five-path review scope.
        paths = (
            "scripts/ci/chain_system_security.py",
            "scripts/ci/test_chain_system_security.py",
            "docs/security/SYSTEM_SECURITY_BLOCKERS_V1.md",
            "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/packed_branch_regression_tests.rs",
            "formal/pon-nakamoto-v1/test_pq_sqlite_schema_names.py",
        )
        original = copy.deepcopy(self.manifest)
        for path in paths:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=path, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(path)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][path]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()

    def test_consolidation_control_bytes_are_bound_without_qualification(self):
        paths = (
            "scripts/ci/chain_system_security.py",
            "scripts/ci/test_chain_system_security.py",
            "docs/security/SYSTEM_SECURITY_BLOCKERS_V1.md",
            "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/packed_branch_regression_tests.rs",
            "formal/pon-nakamoto-v1/test_pq_sqlite_schema_names.py",
        )
        for path in paths:
            target = self.root / path
            original = target.read_bytes()
            try:
                target.write_bytes(original + b"changed consolidation control")
                with self.subTest(path=path), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                target.write_bytes(original)
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIs(result["cryptographic_acceptance"], False)
        self.assertIs(result["node_activated"], False)

    def test_reviewed_cell_paged_sources_require_each_path_and_pin(self):
        original = copy.deepcopy(self.manifest)
        for path in REVIEWED_CELL_PAGED_PATHS:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=path, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(path)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][path]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIs(result["cryptographic_acceptance"], False)
        self.assertIs(result["node_activated"], False)

    def test_reviewed_cell_paged_source_bytes_do_not_grant_acceptance(self):
        for path in REVIEWED_CELL_PAGED_PATHS:
            target = self.root / path
            original = target.read_bytes()
            try:
                target.write_bytes(original + b"changed reviewed Cell source")
                with self.subTest(path=path), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                target.write_bytes(original)
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIs(result["cryptographic_acceptance"], False)
        self.assertIs(result["node_activated"], False)

    def test_native_observation_guards_cannot_omit_pins_or_change_bytes(self):
        # Independent names keep the retained archive, native completion and
        # synthetic-clock reader dependencies mandatory even if a roster drifts.
        dependencies = (
            "scripts/ci/prepare_artifact_upload.py",
            "scripts/ci/test_prepare_artifact_upload.py",
            "scripts/ci/w1_native_controls.py",
            "scripts/ci/test_w1_factorial_native_gate.py",
            "scripts/ci/check_w1_native_roster.py",
            "scripts/ci/test_w1_native_roster.py",
            "scripts/ci/w1_native_rosters_v1.json",
            "scripts/pon_fresh_rejection_report.py",
            "scripts/ci/test_fresh_rejection_report.py",
        )
        self.assertFalse(check(self.root)["cryptographic_acceptance"])
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
            self.manifest = copy.deepcopy(original)
            self.save()
            source = self.root / name
            retained = source.read_bytes()
            try:
                source.write_bytes(retained + b"changed native observation guard")
                with self.subTest(path=name, mutation="bytes"), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                source.write_bytes(retained)
        self.assertFalse(check(self.root)["node_activated"])

    def test_deep_event_and_sampler_inputs_cannot_omit_pins_or_change_bytes(self):
        # Independent literals: neither helper declarations nor the checker's
        # required roster supply this source-integrity regression inventory.
        dependencies = (
            "scripts/w1_risc0_deep_event_audit.py",
            "scripts/w1_p3_sampling_audit.py",
            "scripts/ci/test_w1_risc0_deep_event_audit.py",
            "scripts/ci/test_w1_p3_sampling_audit.py",
            "docs/security/W1_RISC0_DEEP_NAMED_EVENTS.md",
            "docs/security/W1_P3_SAMPLING_CONDITIONAL_ACCOUNTING.md",
            "formal/pon-nakamoto-v1/w1_public_stark_research/Cargo.lock",
            "formal/pon-nakamoto-v1/w1_public_stark_research/security_model_audit/vendor_primary/p3-challenger-0.8.0.crate",
            "formal/pon-nakamoto-v1/w1_public_stark_research/security_model_audit/vendor_primary/p3-fri-0.8.0.crate",
        )
        self.assertFalse(check(self.root)["cryptographic_acceptance"])
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
            self.manifest = copy.deepcopy(original)
            self.save()
            source = self.root / name
            retained = source.read_bytes()
            try:
                source.write_bytes(retained + b"changed selected conditional-audit input")
                with self.subTest(path=name, mutation="bytes"), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                source.write_bytes(retained)
        self.assertFalse(check(self.root)["node_activated"])

    def test_changed_signature_or_source_refuses(self):
        self.put("formal/pon-nakamoto-v1/pq_cell_custody.py", b"altered")
        with self.assertRaisesRegex(IntegrityError, "changed source"):
            check(self.root)

    def test_default_chain_activation_refuses(self):
        p = "config/consensus-mainline.json"
        self.put(p, b'{"production_consensus_activation":true,"runtime_implemented":false,"active_consensus_implementation":null}')
        self.save()
        with self.assertRaisesRegex(IntegrityError, "activation|gate"):
            check(self.root)

    def test_malformed_pq_gate_refuses(self):
        p = "config/pon/post-quantum-transition-v1.json"
        self.put(p, b'{"production_activation":true,"allow_classical_fallback":false,"reference_signature":{"signature_bytes":3309},"existing_devnet_limits":{"post_quantum_transaction_wire_compatible":false}}')
        self.save()
        with self.assertRaisesRegex(IntegrityError, "gate"):
            check(self.root)

    def test_unreviewed_overlay_refuses(self):
        self.manifest["overwrites"].pop("formal/pon-nakamoto-v1/pq_cell_custody.py")
        self.save()
        with self.assertRaisesRegex(IntegrityError, "substitution"):
            check(self.root)

    def test_missing_source_refuses(self):
        (self.root / "formal/pon-nakamoto-v1/pq_envelope.py").unlink()
        with self.assertRaisesRegex(IntegrityError, "missing source"):
            check(self.root)

    def test_source_reader_helper_is_required(self):
        path = 'scripts/ci/pq_source_reader.py'
        self.manifest['required_paths'].remove(path)
        del self.manifest['pinned_blobs'][path]
        self.save()
        with self.assertRaises(IntegrityError):
            check(self.root)

    def test_symlinked_checkout_root_refuses(self):
        alias = self.root.parent / (self.root.name + '-alias')
        alias.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(alias.unlink)
        with self.assertRaisesRegex(IntegrityError, 'symlink'):
            check(alias)

    def test_symlinked_checkout_ancestor_refuses(self):
        alias = self.root.parent / (self.root.name + '-parent-alias')
        alias.symlink_to(self.root.parent, target_is_directory=True)
        self.addCleanup(alias.unlink)
        with self.assertRaisesRegex(IntegrityError, 'symlink'):
            check(alias / self.root.name)

    def test_source_symlink_refuses(self):
        p = self.root / "formal/pon-nakamoto-v1/pq_envelope.py"
        p.unlink()
        p.symlink_to(self.root / "formal/pon-nakamoto-v1/pq_transaction.py")
        with self.assertRaisesRegex(IntegrityError, "symlink"):
            check(self.root)

    def test_traversal_pin_refuses(self):
        self.manifest["pinned_blobs"]["../escape.py"] = "0"*40
        self.save()
        with self.assertRaisesRegex(IntegrityError, "unsafe path"):
            check(self.root)

    def test_missing_source_pin_refuses(self):
        del self.manifest["pinned_blobs"]["formal/pon-nakamoto-v1/pq_envelope.py"]
        self.save()
        with self.assertRaisesRegex(IntegrityError, "incomplete source pins"):
            check(self.root)

    def test_duplicate_json_field_refuses(self):
        p = self.root / "config/pon/pq-cross-branch-corpus-v1.json"
        p.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaisesRegex(IntegrityError, "duplicate JSON"):
            check(self.root)


    def test_pqg_native_dual_signature_source_must_have_exact_blob_pin(self):
        # Regression for the real PQL9 corpus's missing required PQG1 verifier SHA.
        path = "formal/pon-nakamoto-v1/pqg_native_verify.c"
        del self.manifest["pinned_blobs"][path]
        self.save()
        with self.assertRaisesRegex(IntegrityError, "incomplete source pins"):
            check(self.root)

    def test_new_unpinned_pq_implementations_fail_closed(self):
        for name in (
            "formal/pon-nakamoto-v1/pq_hidden_downgrade.py",
            "formal/pon-nakamoto-v1/pq_hidden_downgrade.c",
            "formal/pon-nakamoto-v1/pqg_hidden_downgrade.c",
            "formal/pon-nakamoto-v1/pql99_hidden.py",
            "trillionnium/crates/trnm-protocol/src/pq_hidden_downgrade.rs",
            "formal/pon-nakamoto-v1/experiments/pq_nested_downgrade.py",
            "trillionnium/crates/trnm-protocol/src/research/pq_nested_downgrade.rs",
            "trillionnium/crates/trnm-pon-node/src/ingress/pq_other.rs",
            "trillionnium/crates/trnm-pon-node/tests/pq_unpinned.rs",
            "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_unpinned.rs",
            "trillionnium/crates/trnm-mvcc-fee/tests/pq_unpinned.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/pq_unpinned.rs",
            "trillionnium/crates/trnm-data-availability/tests/pq_unpinned.rs",
            "trillionnium/crates/trnm-crypto-primitives/examples/pq_unpinned.rs",
            "trillionnium/crates/trnm-crypto-primitives/tests/independent_backend/pq_unpinned.py",
            "trillionnium/crates/trnm-research-protocol/src/pq_unpinned.rs",
            "trillionnium/crates/trnm-research-protocol/tests/pq_unpinned.rs",
            "trillionnium/crates/trnm-service-settlement/src/pq_unpinned.rs",
            "trillionnium/crates/trnm-service-settlement/tests/pq_unpinned.rs",
            "trillionnium/crates/trnm-release-bundle/src/pq_unpinned.rs",
            "trillionnium/crates/trnm-release-bundle/tests/pq_unpinned.rs",
        ):
            with self.subTest(path=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"untracked research-only implementation")
                with self.assertRaisesRegex(IntegrityError, "unpinned PQ source"):
                    check(self.root)
                path.unlink()

    def test_duplicate_required_pin_refuses_but_base_fixture_is_unique(self):
        # Original #494 fixture duplicated pqg_native_verify.c, masking all
        # positive and many negative checks with early 'incomplete source pins'.
        self.assertEqual(len(REQUIRED), len(set(REQUIRED)))
        self.manifest["required_paths"].append("formal/pon-nakamoto-v1/pqg_native_verify.c")
        self.save()
        with self.assertRaisesRegex(IntegrityError, "incomplete source pins"):
            check(self.root)

    def test_unpinned_pq_named_nested_module_rejects_renamed_native_file(self):
        # #494 scans descendants, but only recognizes PQ-prefixed leaf names.
        for name in (
            "trillionnium/crates/trnm-protocol/src/pq_verifier/native.rs",
            "trillionnium/crates/trnm-crypto-primitives/src/core/pq_authority/mod.rs",
            "formal/pon-nakamoto-v1/pq_next/helper.py",
            "trillionnium/crates/trnm-pon-node/src/store/pq_owner/receipt.rs",
            "trillionnium/crates/trnm-pon-node/tests/pq_owner/replay.rs",
            "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_owner/authorize.rs",
            "trillionnium/crates/trnm-pon-node/src/operator_pq_unpinned.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/pq/hidden.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq3/hidden.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq37.rs",
            "trillionnium/crates/trnm-data-availability/examples/cell_pq_v3/hidden.rs",
            "trillionnium/crates/trnm-data-availability/src/bin/cell_pq/hidden.rs",
            "trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq/hidden.rs",
            "trillionnium/crates/trnm-service-settlement/src/pq_owner/retire.rs",
            "trillionnium/crates/trnm-release-bundle/src/pq_release/rotate.rs",
        ):
            with self.subTest(path=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"untracked nested source with innocent filename")
                with self.assertRaisesRegex(IntegrityError, "unpinned PQ source"):
                    check(self.root)
                path.unlink()

    def test_unpinned_plain_named_recovery_and_release_helpers_refuse(self):
        for name in (
            "trillionnium/crates/trnm-checkpoint-store/src/recovery/proof.rs",
            "trillionnium/crates/trnm-checkpoint-store/tests/replay.rs",
            "trillionnium/crates/trnm-release-bundle/src/storage.rs",
            "trillionnium/crates/trnm-release-bundle/tests/rotation.rs",
            "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/unlisted.rs",
            "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/nested/recovery.rs",
        ):
            with self.subTest(path=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"untracked security owner implementation")
                with self.assertRaisesRegex(IntegrityError, "unpinned PQ source"):
                    check(self.root)
                path.unlink()

    def test_account_profile_cannot_claim_complete_authority_or_miner_roster(self):
        original = copy.deepcopy(self.manifest["native_account_owner_slice_v1"])
        for field, value in (
            ("whole_native_authorization_migrated", True),
            ("allow_legacy_fallback", True),
            ("miner_roster_permission_required", True),
            ("independent_source_history_authenticated", True),
            ("transfer_only", False),
            ("liability_mode", "omit-expired-records"),
            ("dual_possession_signatures_required", False),
            ("transaction_byte_limit", True),
            ("transaction_count_limit", 256),
            ("transaction_wire", "NPQ6/v6"),
            ("feature", "canonical-default-no-feature-required"),
        ):
            with self.subTest(field=field):
                self.manifest["native_account_owner_slice_v1"] = {**original, field: value}
                self.save()
                with self.assertRaisesRegex(IntegrityError, "account bounded-profile"):
                    check(self.root)

    def test_account_owner_or_report_cannot_be_omitted(self):
        saved = copy.deepcopy(self.manifest)
        del self.manifest["native_account_owner_slice_v1"]
        self.save()
        with self.assertRaisesRegex(IntegrityError, "account bounded-profile"):
            check(self.root)
        self.manifest = saved
        self.save()
        (self.root / self.manifest["native_account_owner_slice_v1"]["evidence"]).unlink()
        with self.assertRaisesRegex(IntegrityError, "missing source"):
            check(self.root)

    def test_pinned_pq_named_module_keeps_original_byte_identity(self):
        name = "trillionnium/crates/trnm-protocol/src/pq_verifier/native.rs"
        self.put(name, b"//! independently pinned, no production authority")
        self.save()
        self.assertEqual(check(self.root)["status"], "HOLD_NO_GO")
        (self.root / name).write_bytes(b"changed after pin")
        with self.assertRaisesRegex(IntegrityError, "changed source"):
            check(self.root)

    def test_pq_source_directory_symlink_is_not_trusted(self):
        source = self.root / "trillionnium/crates/trnm-crypto-primitives/src"
        moved = source.with_name("source-before-swap")
        source.rename(moved)
        source.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(IntegrityError, "symlink"):
            check(self.root)

    def test_nested_symlink_directory_refuses_even_without_named_pq_file(self):
        parent = self.root / "formal/pon-nakamoto-v1/experiments"
        parent.mkdir(parents=True, exist_ok=True)
        target = self.root / "foreign"
        target.mkdir()
        (parent / "untracked").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(IntegrityError, "symlink PQ source entry"):
            check(self.root)

    def test_pinned_nested_source_is_checked_by_byte_identity(self):
        name = "formal/pon-nakamoto-v1/experiments/pq_accepted_experiment.py"
        self.put(name, b"research-only verified source\\n")
        self.save()
        self.assertEqual(check(self.root)["status"], "HOLD_NO_GO")
        (self.root / name).write_bytes(b"changed after pin")
        with self.assertRaisesRegex(IntegrityError, "changed source"):
            check(self.root)

    def test_traversal_budget_refuses_before_unbounded_tree_scan(self):
        parent = self.root / "formal/pon-nakamoto-v1/experiments"
        parent.mkdir(parents=True, exist_ok=True)
        for idx in range(10001):
            (parent / f"unused-{idx:05d}").touch()
        with self.assertRaisesRegex(IntegrityError, "traversal budget"):
            check(self.root)

    def test_native_profile_is_mandatory_and_never_claims_whole_authorization(self):
        original = copy.deepcopy(self.manifest["native_network_owner_slice_v2"])
        for field in NATIVE_FALSE:
            for value in (True, 0, None):
                with self.subTest(field=field, value=value):
                    self.manifest["native_network_owner_slice_v2"] = dict(original)
                    self.manifest["native_network_owner_slice_v2"][field] = value
                    self.save()
                    with self.assertRaisesRegex(IntegrityError, "PNQ2 bounded-profile"):
                        check(self.root)
        del self.manifest["native_network_owner_slice_v2"]
        self.save()
        with self.assertRaisesRegex(IntegrityError, "PNQ2 bounded-profile"):
            check(self.root)

    def test_reviewed_endpoint_and_library_closure_cannot_drop_source_or_pin(self):
        # Independent literal roster: deleting the implementation constant must fail.
        dependencies = (
            'config/pon/pq-native-tls-endpoint-required-tests-v1.json',
            'docs/security/PQ_TLS_PINNED_ENDPOINT_V1.md',
            'trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/dht/lookup.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/dht/lookup/tests.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/shared.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/diagnostics.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/endpoint_tests.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/io.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/io/buffer_tests.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/tests.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls_endpoint.rs',
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls_profile.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_tls_cli.rs',
            'trillionnium/crates/trnm-pon-node/src/store.rs',
            'trillionnium/crates/trnm-pon-node/src/store/confirmation_chainwork_tests.rs',
            'trillionnium/crates/trnm-pon-node/src/store/pq_network.rs',
            'trillionnium/crates/trnm-pon-node/tests/pq_tls_endpoint_cli.rs',
            'trillionnium/crates/trnm-pon-node/tests/pq_tls_refusal_diagnostics.rs',
            'trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli/refusal_diagnostics.rs',
            'trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli/support.rs',
        )
        self.assertTrue(set(dependencies).issubset(NATIVE_REQUIRED_PATHS))
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()

    def test_native_owner_guards_and_cli_cannot_be_dropped_from_required_pins(self):
        original = list(self.manifest["required_paths"])
        for path in NATIVE_REQUIRED_PATHS:
            with self.subTest(path=path):
                self.manifest["required_paths"] = [p for p in original if p != path]
                self.save()
                with self.assertRaisesRegex(IntegrityError, "PNQ2 bounded-profile"):
                    check(self.root)

    def test_model_source_composition_v6_sources_cannot_be_dropped_and_repinned(self):
        original = copy.deepcopy(self.manifest)
        self.assertFalse(check(self.root)['cryptographic_acceptance'])
        # Independent names include the V3 policy supplying sources and payees.
        # These tests cover selected source integrity, not dependency closure.
        for path in (
            'config/pon/model-source-composition-v6.json',
            'config/pon/public-evaluation-model-source-composition-v6.json',
            'config/pon/model-evidence-v3.json',
            'trillionnium/crates/trnm-mvcc-fee/src/model_source_composition_v6.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/model_evidence_v3.rs',
            'trillionnium/crates/trnm-pon-node/tests/model_source_composition_v6.rs',
        ):
            with self.subTest(path=path):
                self.manifest = copy.deepcopy(original)
                self.manifest['required_paths'].remove(path)
                del self.manifest['pinned_blobs'][path]
                self.save()
                with self.assertRaisesRegex(IntegrityError, 'PNQ2 bounded-profile'):
                    check(self.root)
        self.manifest = original
        self.save()
        self.assertFalse(check(self.root)['cryptographic_acceptance'])


    def test_upstream_withdrawal_and_posterior_sources_cannot_be_dropped_and_repinned(self):
        original = copy.deepcopy(self.manifest)
        self.assertFalse(check(self.root)['cryptographic_acceptance'])
        # Independent literal names prevent removal from both inventories from
        # silently turning a security-lifecycle check into optional evidence.
        for path in (
            'config/pon/w1-upstream-security-v1.json',
            'scripts/ci/w1_upstream_security.py',
            'scripts/ci/test_w1_upstream_security.py',
            'formal/pon-nakamoto-v1/quantum_posterior_policy.py',
            'evidence/pon-quantum-lifetime-20261111-e464/upstream-security-report.json',
        ):
            with self.subTest(path=path):
                self.manifest = copy.deepcopy(original)
                self.manifest['required_paths'].remove(path)
                del self.manifest['pinned_blobs'][path]
                self.save()
                with self.assertRaises(IntegrityError):
                    check(self.root)
        self.manifest = original
        self.save()
        self.assertFalse(check(self.root)['cryptographic_acceptance'])

    def test_native_wire_numeric_claims_refuse_bool_or_wrong_version(self):
        original = copy.deepcopy(self.manifest["native_network_owner_slice_v2"])
        for field, value in (("tpq1_peer_purpose", True), ("tpq1_peer_purpose", 1),
                             ("signed_frame_bytes", "3487"), ("signed_frame_bytes", 64),
                             ("feature", "pq-native-openssl"), ("profile", "native-pq-network-owner-v1"),
                             ("request_wire", "PNQ1/v1"), ("response_wire", "PNP1/v1"),
                             ("activation_rule", "classical-or-pq"),
                             ("canonical_provider", "OpenSSL-only"),
                             ("ingress_connection_limit", True),
                             ("ingress_byte_limit", 33554433),
                             ("inbound_verification_limit", 65)):
            with self.subTest(field=field, value=value):
                self.manifest["native_network_owner_slice_v2"] = dict(original)
                self.manifest["native_network_owner_slice_v2"][field] = value
                self.save()
                with self.assertRaisesRegex(IntegrityError, "PNQ2 bounded-profile"):
                    check(self.root)

    def test_non_pq_named_owner_dependencies_cannot_be_dropped_and_repinned(self):
        original = copy.deepcopy(self.manifest)
        for name in CONVERGENCE_REQUIRED_PATHS:
            with self.subTest(path=name):
                self.manifest = copy.deepcopy(original)
                self.manifest['required_paths'].remove(name)
                del self.manifest['pinned_blobs'][name]
                self.save()
                with self.assertRaises(IntegrityError):
                    check(self.root)
        self.manifest = original
        self.save()
        self.assertFalse(check(self.root)['cryptographic_acceptance'])

    def test_witness_v5_component_sources_cannot_be_omitted_or_changed(self):
        # Independent names ensure these newly introduced sources remain
        # mandatory even if both a manifest requirement and its pin disappear.
        paths = (
            "scripts/ci/run_pq_root_witness_v5.py",
            "scripts/ci/test_run_pq_root_witness_v5.py",
            "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5.rs",
            "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5/durable.rs",
            "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5/provider_readback.rs",
            "trillionnium/crates/trnm-pon-node/tests/root_witness_provider_v5_native.rs",
            "trillionnium/crates/trnm-pon-node/tests/root_witness_v5_native.rs",
            "trillionnium/crates/trnm-pon-node/tests/root_witness_v5_durable_native.rs",
        )
        original = copy.deepcopy(self.manifest)
        for name in paths:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
            self.manifest = copy.deepcopy(original)
            self.save()
            source = self.root / name
            before = source.read_bytes()
            try:
                source.write_bytes(before + b" changed witness component")
                with self.subTest(path=name, mutation=True), self.assertRaisesRegex(
                        IntegrityError, "changed source"):
                    check(self.root)
            finally:
                source.write_bytes(before)
        self.assertFalse(check(self.root)["cryptographic_acceptance"])

    def test_runtime_verifier_dependency_file_and_pin_cannot_both_be_dropped(self):
        # Keep this real dependency named independently of the checker's set.
        name = 'scripts/ci/runtime-release-requirements.txt'
        self.put(name, b'packaging==26.3\n')
        if name not in self.manifest['required_paths']:
            self.manifest['required_paths'].append(name)
        self.save()
        self.assertEqual(check(self.root)['status'], 'HOLD_NO_GO')
        original = copy.deepcopy(self.manifest)
        for omission in ('required', 'pin', 'required-and-pin'):
            with self.subTest(omission=omission):
                self.manifest = copy.deepcopy(original)
                if omission in ('required', 'required-and-pin'):
                    self.manifest['required_paths'].remove(name)
                if omission in ('pin', 'required-and-pin'):
                    del self.manifest['pinned_blobs'][name]
                self.save()
                with self.assertRaises(IntegrityError):
                    check(self.root)
        self.manifest = original
        self.save()
        self.assertFalse(check(self.root)['cryptographic_acceptance'])

    def test_convergence_owner_source_changes_cannot_reuse_prior_pins(self):
        # Exercise every convergence dependency, including the model codecs,
        # tensor reader, transport, CLI, vector and specification. The separate
        # omission test already deletes each required path and its pin together.
        for name in sorted(CONVERGENCE_REQUIRED_PATHS | {
            'trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs',
            'trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs',
            'trillionnium/crates/trnm-pon-node/src/store/storage_service.rs',
            'trillionnium/crates/trnm-service-settlement/src/native_budget.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/closure.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/retention.rs',
            'trillionnium/crates/trnm-pon-node/src/store/authenticated_migration/growth_rehearsal.rs',
            'trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs',
        }):
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b'changed owner source')
                with self.assertRaisesRegex(IntegrityError, 'changed source'):
                    check(self.root)
                path.write_bytes(original)

    def growth_read_dependency_fixture(self):
        # These plain-named dependencies take part in the actual Growth read
        # boundary. Populate them independently of the checker's required set so
        # the omission controls also exercise a checker that forgot their scope.
        dependencies = (
            "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/multiproof.rs",
            "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/multiproof_tests.rs",
            "trillionnium/crates/trnm-pon-node/src/store/growth/observation.rs",
        )
        for name in dependencies:
            self.put(name, name.encode())
            if name not in self.manifest["required_paths"]:
                self.manifest["required_paths"].append(name)
        self.save()
        self.assertEqual(check(self.root)["status"], "HOLD_NO_GO")
        return dependencies

    def test_growth_read_dependencies_cannot_omit_requirements_or_pins(self):
        dependencies = self.growth_read_dependency_fixture()
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        self.assertFalse(check(self.root)["cryptographic_acceptance"])

    def test_growth_read_dependency_changes_cannot_reuse_original_pins(self):
        for name in self.growth_read_dependency_fixture():
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed authenticated read boundary")
                with self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
                path.write_bytes(original)
        self.assertFalse(check(self.root)["cryptographic_acceptance"])

    def test_native_evidence_must_exist_but_never_grants_acceptance(self):
        report = self.manifest["native_network_owner_slice_v2"]["evidence"]
        del self.manifest["pinned_blobs"][report]
        self.save()
        self.assertFalse(check(self.root)["cryptographic_acceptance"])
        (self.root / report).unlink()
        with self.assertRaisesRegex(IntegrityError, "missing source"):
            check(self.root)

    def test_native_evidence_traversal_or_symlink_refuses(self):
        profile = self.manifest["native_network_owner_slice_v2"]
        report = profile["evidence"]
        del self.manifest["pinned_blobs"][report]
        profile["evidence"] = "evidence/../../foreign/README.md"
        self.save()
        with self.assertRaisesRegex(IntegrityError, "unsafe path"):
            check(self.root)
        profile["evidence"] = report
        self.save()
        (self.root / report).unlink()
        (self.root / report).symlink_to(self.root / REQUIRED[0])
        with self.assertRaisesRegex(IntegrityError, "symlink"):
            check(self.root)

    def test_pnq1_cannot_replace_or_coexist_as_active_candidate(self):
        self.manifest["native_network_owner_slice_v1"] = copy.deepcopy(
            self.manifest["native_network_owner_slice_v2"])
        self.save()
        with self.assertRaisesRegex(IntegrityError, "superseded PNQ1"):
            check(self.root)

    def test_canonical_slice_forbids_fallback_refund_and_unaccepted_combinations(self):
        original = dict(self.manifest["native_network_owner_slice_v2"])
        for field, value in (
            ("independent_provider", "OpenSSL-or-classical-on-canonical-failure"),
            ("failed_verifications_refunded", True),
            ("durable_ingress_budget", False),
            ("canonical_crypto_available_by_default", False),
            ("default_chain_activation", True),
            ("continuous_npq6_combination_accepted", True),
            ("research_archive_pq_accepted", True),
            ("cli_automatic_parent_recovery_pq_accepted", True),
            ("transport_confidentiality", "production-pq-tls"),
            ("unreviewed_classical_acceptance", True),
        ):
            with self.subTest(field=field):
                self.manifest["native_network_owner_slice_v2"] = {**original, field: value}
                self.save()
                with self.assertRaisesRegex(IntegrityError, "PNQ2 bounded-profile"):
                    check(self.root)

    def test_canonical_provider_manifest_change_is_refused_even_if_repinned(self):
        path = "trillionnium/crates/trnm-crypto-primitives/Cargo.toml"
        original = (self.root / path).read_bytes()
        for before, after in (
            (b'version = "=0.1.1"', b'version = "=0.1.2"'),
            (b'default = []', b'default = ["pq-native-openssl"]'),
            (b'default-features = false', b'optional = true, default-features = false'),
            (b'optional = true}', b'optional = false}'),
            (b'production_activation = false', b'production_activation = true'),
        ):
            with self.subTest(change=after):
                self.put(path, original.replace(before, after))
                self.save()
                with self.assertRaisesRegex(IntegrityError, "canonical .*contract changed"):
                    check(self.root)

    def test_new_canonical_sources_and_negative_vectors_keep_exact_blob_identity(self):
        for name in (
            "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/canonical_tests.rs",
            "trillionnium/crates/trnm-pon-node/src/operator_pq_auth.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/pq.rs",
            "trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs",
            "trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs",
            "trillionnium/crates/trnm-crypto-primitives/tests/fixtures/wycheproof/mldsa_65_verify_test.json",
        ):
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed after review")
                with self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
                path.write_bytes(original)

    def test_canonical_provider_malformed_tables_and_feature_shapes_fail_closed(self):
        path = "trillionnium/crates/trnm-crypto-primitives/Cargo.toml"
        original = (self.root / path).read_bytes()
        for altered in (
            b'features = 7\n',
            b'package = false\n',
            b'dependencies = "non-table"\n',
            b'[package]\nmetadata = true\n',
            b'[package.metadata]\ntrnm = []\n',
            original.replace(b'features = ["alloc", "zeroize"]', b'features = true'),
            original.replace(b'features = ["alloc", "zeroize"]', b'features = ["alloc", 7]'),
        ):
            with self.subTest(manifest=altered):
                self.put(path, altered)
                self.save()
                with self.assertRaisesRegex(IntegrityError, "canonical .* (invalid|changed)"):
                    check(self.root)

    def test_all_global_acceptance_flags_stay_false(self):
        original = dict(self.manifest["assertions"])
        for field in original:
            with self.subTest(field=field):
                self.manifest["assertions"] = {**original, field: True}
                self.save()
                with self.assertRaisesRegex(IntegrityError, "unaccepted capability"):
                    check(self.root)


    def postwin_dependency_fixture(self):
        # This literal inventory is independent of the checker's required set.
        # The fixture is source bytes only, never a successful prover/receiver.
        dependencies = (
            ".github/workflows/pon-w1-transparent-profile.yml",
            "scripts/ci/ci_job.sh",
            "scripts/ci/check_ci_contract.py",
            "scripts/ci/test_ci_contract.py",
            "scripts/ci/check_pq_research_integration.py",
            "scripts/ci/test_pq_research_integration.py",
            "formal/pon-nakamoto-v1/experiments/w1_stage_measure.py",
            "formal/pon-nakamoto-v1/experiments/w1_full_staged_run.py",
            "formal/pon-nakamoto-v1/experiments/w1_local_payload.py",
            "scripts/ci/test_w1_cancellation_handoff.py",
            "scripts/ci/test_w1_coordinator_contract.py",
            "scripts/ci/test_w1_postwin_identity.py",
            "scripts/ci/test_w1_kaggle_worker_contract.py",
            "scripts/ci/test_w1_staged_observer.py",
            "formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml",
            "formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock",
            "formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1-staged-prover.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/schedule.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/schedule_tests.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/recursion_tests.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/parallel_segments.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/parallel_segments_tests.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/guest_identity.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/host-v2/Cargo.toml",
            "formal/pon-nakamoto-v1/w1_zkvm/methods-v2/Cargo.toml",
            "formal/pon-nakamoto-v1/w1_zkvm/methods-v2/build.rs",
            "formal/pon-nakamoto-v1/w1_zkvm/Cargo.lock",
            "formal/pon-nakamoto-v1/w1_zkvm/RETAINED_V2_GUEST.md",
            "evidence/pon-w1-backend-sdk-20261107/fixed-sdk-contract.json",
            "scripts/run_w1_receiver.py",
            "scripts/run_w1_postwin_proof.py",
            "scripts/run_w1_deployment_comparison.py",
            "scripts/audit_w1_deployment_comparison.py",
            "scripts/ci/test_w1_deployment_comparison_audit.py",
            "scripts/ci/test_w1_deployment_evidence_binding.py",
            "scripts/w1_owned_process_collector_v1.py",
            "scripts/test_w1_owned_process_collector_v1.py",
            "scripts/ci/test_w1_receiver_real.py",
            "trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_native_winner_v2.rs",
            "trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2.rs",
            "trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2/tests.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/task_owner.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/terminal.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/terminal.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation/tests.rs",
            "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation/timeout.rs",
            "trillionnium/crates/trnm-service-settlement/src/lib.rs",
            "trillionnium/crates/trnm-pon-node/src/store.rs",
            "trillionnium/crates/trnm-pon-node/src/lib.rs",
            "scripts/kaggle_generation_contract_v2.py",
            "scripts/test_kaggle_generation_contract_v2.py",
            "scripts/w1_generation_target_v2.py",
            "scripts/test_w1_generation_target_v2.py",
            "scripts/w1_owner_cancellation_v1.py",
            "scripts/test_w1_owner_cancellation_v1.py",
            "scripts/w1_owned_generation_runtime_v2.py",
            "scripts/test_w1_owned_generation_runtime_v2.py",
            "scripts/build_w1_kaggle_source.py",
            "scripts/w1_kaggle_worker_template.py",
            "scripts/ci/test_w1_kaggle_source_builder.py",
            "evidence/pon-w1-full-v2-20261105/succinct.bin",
            "evidence/pon-w1-full-v2-20261105/input.bin",
            "evidence/pon-w1-full-v2-20261105/header.bin",
            "evidence/pon-w1-full-v2-20261105/expected-artifacts.bin",
            "evidence/pon-w1-full-v2-20261105/guest.bin",
            "evidence/pon-w1-full-v2-20261105/asset-sha256.json",
            "evidence/pon-w1-statement-v2-20261105/input-declaration.json",
            "evidence/pon-w1-statement-v2-20261105/expected-artifacts.bin",
        )
        for name in dependencies:
            if name not in self.pins:
                self.put(name, name.encode())
            if name not in self.manifest["required_paths"]:
                self.manifest["required_paths"].append(name)
        self.save()
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertFalse(result["cryptographic_acceptance"])
        self.assertFalse(result["node_activated"])
        return dependencies

    def test_postwin_dependencies_cannot_omit_requirements_or_pins(self):
        dependencies = self.postwin_dependency_fixture()
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        self.assertFalse(check(self.root)["cryptographic_acceptance"])

    def test_postwin_dependencies_cannot_mutate_under_retained_blob_pins(self):
        for name in self.postwin_dependency_fixture():
            with self.subTest(path=name):
                source = self.root / name
                original = source.read_bytes()
                try:
                    source.write_bytes(original + b"changed post-win source or retained input")
                    with self.assertRaisesRegex(IntegrityError, "changed source"):
                        check(self.root)
                finally:
                    source.write_bytes(original)
        self.assertFalse(check(self.root)["node_activated"])


    def storage_owner_dependency_fixture(self):
        # Independent literal roster: removing a production requirement must not
        # silently remove this negative control.
        dependencies = (
            ".github/workflows/pon-next-architecture-security.yml",
            "docs/development/specs/pon/CELL_STORAGE_CONVERGENCE_DEV_V1.md",
            "evidence/cell-storage-convergence-f2568-20261109/controls/original-auth-server-tests.rs",
            "formal/pon-nakamoto-v1/vectors/cell-storage-owner-vectors-v1.json",
            "formal/pon-nakamoto-v1/vectors/cell-version-retention-v3.json",
            "scripts/cell_storage_descriptor_reference.py",
            "scripts/cell_version_retention_v3_vector.py",
            "scripts/ci/test_cell_storage_convergence_ci.py",
            "trillionnium/crates/trnm-data-availability/src/cell.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth_tests.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider/admission.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider/contract.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider/tests.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/codec.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/file.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/host_handoff.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/host_handoff/tests.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/residency.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/residency/version.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/residency/version_tests.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/retention.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/retention/catalog_inventory.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/retention/payload_read.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/retention/payload_read/tests.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/snapshot_schedule.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/snapshot_schedule/tests.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/catalog.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/codec.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/inventory.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/owner.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/residency.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/shard_plan.rs",
            "trillionnium/crates/trnm-pon-node/src/lib.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard_tests.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/tests.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/version.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_shard_plan_tests.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_tests.rs",
            "scripts/cell_sealed_bootstrap_v1.py",
            "scripts/llm_cell_sealed_worker_v1.py",
            "scripts/prepare_cell_sealed_research_v1.py",
            "scripts/test_llm_cell_sealed_worker_v1.py",
            "trillionnium/crates/trnm-data-availability/Cargo.toml",
            "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_next_use_v1.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/host_handoff/fd_handoff.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/host_handoff/tests/research_fds.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/shard_plan_capacity.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/recovery.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/recovery/execute.rs",
            "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_shard_recovery_tests.rs",
        )
        self.assertTrue(set(dependencies).issubset(NATIVE_REQUIRED_PATHS))
        for name in dependencies:
            if name not in self.pins:
                self.put(name, name.encode())
            if name not in self.manifest["required_paths"]:
                self.manifest["required_paths"].append(name)
        self.save()
        result = check(self.root)
        self.assertFalse(result["cryptographic_acceptance"])
        self.assertFalse(result["node_activated"])
        return dependencies

    def test_storage_owner_dependencies_cannot_omit_requirements_or_pins(self):
        dependencies = self.storage_owner_dependency_fixture()
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        self.assertFalse(check(self.root)["node_activated"])

    def test_storage_owner_dependencies_cannot_mutate_under_retained_blob_pins(self):
        for name in self.storage_owner_dependency_fixture():
            with self.subTest(path=name):
                source = self.root / name
                original = source.read_bytes()
                try:
                    source.write_bytes(original + b" changed storage owner input")
                    with self.assertRaisesRegex(IntegrityError, "changed source"):
                        check(self.root)
                finally:
                    source.write_bytes(original)
        self.assertFalse(check(self.root)["cryptographic_acceptance"])



    def test_reviewed_library_ports_cannot_omit_or_mutate_source(self):
        # Independent literal review scope, not derived from the checker roster.
        dependencies = (
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/task_product_facts.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/task_product_facts/tests.rs',
            'trillionnium/crates/trnm-data-availability/src/cell.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/runtime_root.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/runtime_root_tests.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/store.rs',
            'trillionnium/crates/trnm-sqlite-io-boundary/src/ledger.rs',
            'trillionnium/crates/trnm-sqlite-io-boundary/src/lib.rs',
            'trillionnium/crates/trnm-sqlite-io-boundary/src/owner.rs',
            'trillionnium/crates/trnm-sqlite-io-boundary/src/reservation_v2_tests.rs',
            'trillionnium/crates/trnm-sqlite-io-boundary/src/unsupported.rs',
            'trillionnium/crates/trnm-sqlite-io-boundary/src/vfs.rs',
        )
        self.assertTrue(set(dependencies).issubset(NATIVE_REQUIRED_PATHS))
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        for name in dependencies:
            source = self.root / name
            before = source.read_bytes()
            try:
                source.write_bytes(before + b"changed reviewed library source")
                with self.subTest(path=name), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                source.write_bytes(before)
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIs(result["cryptographic_acceptance"], False)
        self.assertIs(result["node_activated"], False)


    def test_sp27_research_selectors_cannot_omit_or_mutate_source(self):
        # Independent literal review scope, not derived from the checker roster.
        dependencies = (
            'scripts/ci/run_from_zero_host.py',
            'scripts/ci/run_from_zero_native.py',
            'scripts/ci/run_sp27_receiver_controls.py',
            'scripts/ci/run_sp27_strata_controls.py',
            'scripts/ci/test_run_from_zero_native.py',
            'scripts/ci/test_sp27_receiver_controls.py',
            'scripts/ci/test_sp27_strata_controls.py',
            'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs',
            'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_campaign.rs',
            'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_controls.rs',
            'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_strata.rs',
        )
        self.assertTrue(set(dependencies).issubset(NATIVE_REQUIRED_PATHS))
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        for name in dependencies:
            source = self.root / name
            before = source.read_bytes()
            try:
                source.write_bytes(before + b"changed reviewed SP27 research source")
                with self.subTest(path=name), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                source.write_bytes(before)
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIs(result["cryptographic_acceptance"], False)
        self.assertIs(result["node_activated"], False)


    def test_snapshot_and_admission_bridge_cannot_omit_or_mutate_source(self):
        # Independent literal review scope, not derived from the checker roster.
        dependencies = (
            'docs/security/SP27_03_RESEARCH_BRIDGE_RETAINED_V1.md',
            'trillionnium/crates/trnm-pon-node/tests/account_archive_prototype.rs',
            'trillionnium/crates/trnm-research-protocol/examples/sp27_03_authorization_adapter.rs',
        )
        self.assertTrue(set(dependencies).issubset(NATIVE_REQUIRED_PATHS))
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        for name in dependencies:
            source = self.root / name
            before = source.read_bytes()
            try:
                source.write_bytes(before + b"changed reviewed snapshot or admission bridge")
                with self.subTest(path=name), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                source.write_bytes(before)
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIs(result["cryptographic_acceptance"], False)
        self.assertIs(result["node_activated"], False)



    def test_immutable_key_and_legal_producer_sources_cannot_omit_or_mutate(self):
        # Independent literal review scope, not derived from the checker roster.
        dependencies = (
            'trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3/tests.rs',
            'trillionnium/crates/trnm-crypto-primitives/tests/pq_root_v3_native.rs',
            'trillionnium/crates/trnm-crypto-primitives/examples/pq_root_v3_cost_observation.rs',
            'docs/security/PQ_ROOT_SIGNATURE_COST_V1.md',
            'trillionnium/crates/trnm-crypto-primitives/Cargo.toml',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/low_rank_prefix.rs',
            'trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs',
            'trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_rank_batch_v5.rs',
            'scripts/ci/run_pq_root_native_v3.py',
            'scripts/ci/test_run_pq_root_native_v3.py',
            'scripts/ci/pq_root_dependency_register.py',
            'docs/security/PQ_ROOT_DEPENDENCY_REGISTER_V3.md',
            'docs/security/PQ_ROOT_RECOVERY_NATIVE_V3.md',
        )
        self.assertTrue(set(dependencies).issubset(NATIVE_REQUIRED_PATHS))
        original = copy.deepcopy(self.manifest)
        for name in dependencies:
            for omission in ("required", "pin", "required-and-pin"):
                with self.subTest(path=name, omission=omission):
                    self.manifest = copy.deepcopy(original)
                    if omission in ("required", "required-and-pin"):
                        self.manifest["required_paths"].remove(name)
                    if omission in ("pin", "required-and-pin"):
                        del self.manifest["pinned_blobs"][name]
                    self.save()
                    with self.assertRaises(IntegrityError):
                        check(self.root)
        self.manifest = original
        self.save()
        for name in dependencies:
            source = self.root / name
            before = source.read_bytes()
            try:
                source.write_bytes(before + b"changed reviewed library source")
                with self.subTest(path=name), self.assertRaisesRegex(IntegrityError, "changed source"):
                    check(self.root)
            finally:
                source.write_bytes(before)
        result = check(self.root)
        self.assertEqual(result["status"], "HOLD_NO_GO")
        self.assertIs(result["cryptographic_acceptance"], False)
        self.assertIs(result["node_activated"], False)


if __name__ == "__main__":
    unittest.main()
