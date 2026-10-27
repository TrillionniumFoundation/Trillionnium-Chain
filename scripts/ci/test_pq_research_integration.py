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
from check_pq_research_integration import IntegrityError, check

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
    "formal/pon-nakamoto-v1/pqg_native_verify.c",
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
        self.manifest = {
            "schema": "trnm-pq-cross-branch-corpus-v1",
            "status": "research-only-hold-no-go", "parent_profile": "pon-nakamoto-v1",
            "upstream_heads": {k: "1"*40 for k in ("base", "cell", "migration", "witness", "roster", "parity")},
            "required_paths": list(REQUIRED), "pinned_blobs": self.pins,
            "overwrites": dict(OVERWRITES),
            "assertions": {x: False for x in (
                "production_activation", "independent_accepted", "native_pq_node_integrated",
                "quantum_pon_hardness_qualified", "physical_rollback_resistant",
                "hepta_final_use_integrated", "public_wan_accepted", "allow_legacy_fallback")},
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
        ):
            with self.subTest(path=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"untracked research-only implementation")
                with self.assertRaisesRegex(IntegrityError, "unpinned PQ source"):
                    check(self.root)
                path.unlink()

    def test_pq_source_directory_symlink_is_not_trusted(self):
        source = self.root / "trillionnium/crates/trnm-crypto-primitives/src"
        moved = source.with_name("source-before-swap")
        source.rename(moved)
        source.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(IntegrityError, "symlink"):
            check(self.root)


if __name__ == "__main__":
    unittest.main()
