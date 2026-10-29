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
    IntegrityError, NATIVE_FALSE, NATIVE_REQUIRED_PATHS, NATIVE_V2_EXPECTED, check,
)

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
            "trillionnium/crates/trnm-data-availability/src/bin/cell_pq/hidden.rs",
        ):
            with self.subTest(path=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"untracked nested source with innocent filename")
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

    def test_native_owner_guards_and_cli_cannot_be_dropped_from_required_pins(self):
        original = list(self.manifest["required_paths"])
        for path in NATIVE_REQUIRED_PATHS:
            with self.subTest(path=path):
                self.manifest["required_paths"] = [p for p in original if p != path]
                self.save()
                with self.assertRaisesRegex(IntegrityError, "PNQ2 bounded-profile"):
                    check(self.root)

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


if __name__ == "__main__":
    unittest.main()
