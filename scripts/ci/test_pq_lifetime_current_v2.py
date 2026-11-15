"""Finite current-correspondence controls; no historical or native execution."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_lifetime_budget as legacy
import pq_lifetime_current_v2 as current

ROOT = Path(__file__).resolve().parents[2]
MAP = "config/pon/pq128-source-correspondence-current-v2.json"
PATHS = frozenset((
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_profile_auth.rs",
    "trillionnium/crates/trnm-data-availability/src/cell.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/manifest.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/model_root.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/pq.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retained.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_content.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_content_closure_v3.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs",
    "trillionnium/crates/trnm-pon-node/src/consensus.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/src/store/funding/payment.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release.rs",
    "trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_budget.rs",
))
FALSE_FLAGS = ("whole_chain_pq_qualified", "pq_128_qualified", "production_activation",
               "composition_coverage_proved", "theorem_applicability_verified")


class CurrentCorrespondenceTests(unittest.TestCase):
    def setUp(self):
        area = tempfile.TemporaryDirectory(prefix="pq-current-v2-")
        self.addCleanup(area.cleanup)
        self.root = Path(area.name)
        for path in PATHS | {MAP, legacy.DEFAULT_MANIFEST, legacy.DEFAULT_SOURCE_LOCK}:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, target)
        self.mapping = json.loads((self.root / MAP).read_bytes())
        self.source = self.root / "trillionnium/crates/trnm-pon-node/src/store.rs"

    def write_map(self, data):
        (self.root / MAP).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def refuses(self):
        with self.assertRaises(current.CurrentBudgetError):
            current.inspect(self.root)

    def unqualified(self, result):
        self.assertEqual(result["status"], "HOLD")
        self.assertIsNone(result["actual_lifetime_failure_bound"])
        for name in FALSE_FLAGS:
            self.assertIs(result[name], False, name)

    def test_current_map_keeps_frozen_model_and_current_bytes_separate(self):
        report = current.inspect(self.root)
        self.assertEqual(report["schema"], "trnm-pq128-lifetime-current-result-v2")
        self.assertEqual(report["frozen_model_identity"], {
            "source_revision": "0f9b30549328e5be20f4d3e6e27bd132b42d90de",
            "manifest_path": "config/pon/pq128-lifetime-budget-v1.json",
            "manifest_sha256": "0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd",
            "source_lock_path": "config/pon/pq128-source-lock-v1.json",
            "source_lock_sha256": "094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2",
        })
        model = report["frozen_model"]
        self.assertIs(model["source_revision_bound"], False)
        self.assertEqual(model["source_binding_scope"], "unbound")
        self.assertIsNone(model["source_lock_sha256"])
        self.assertEqual(len(model["unknown_terms"]), 8)
        self.assertEqual(len(model["unknown_query_budgets"]), 4)
        self.assertIsNone(model["model_arithmetic_sum"])
        self.assertIsNone(model["target_met_under_declared_bounds"])
        self.unqualified(model)
        observed = report["current_source_correspondence"]
        self.assertEqual(observed["schema"], "trnm-pq128-source-correspondence-current-v2")
        self.assertEqual(set(observed["source_files_sha256"]), PATHS)
        self.assertEqual(len(PATHS), 21)
        self.assertIs(observed["source_files_checked"], True)
        self.assertIs(observed["source_revision_bound"], False)
        self.assertEqual(observed["source_binding_scope"], "declared-event-paths-only")
        self.assertEqual(observed["source_files_sha256"],
                         self.mapping["current_source_files_sha256"])
        self.assertEqual(observed["map_sha256"],
                         hashlib.sha256((self.root / MAP).read_bytes()).hexdigest())
        self.assertFalse((self.root / ".git").exists())
        self.unqualified(report)

    def test_original_v1_reader_does_not_relabel_current_bytes(self):
        with self.assertRaisesRegex(legacy.BudgetError, "source lock hash mismatch"):
            legacy.inspect(self.root)

    def test_changed_current_source_is_refused(self):
        self.source.write_bytes(self.source.read_bytes() + b"\n// changed current fixture\n")
        self.refuses()

    def test_missing_current_source_is_refused(self):
        self.source.unlink()
        self.refuses()

    def test_symlink_source_with_matching_bytes_is_refused(self):
        copy = self.root / "same-source"
        copy.write_bytes(self.source.read_bytes())
        self.source.unlink()
        self.source.symlink_to(copy)
        self.refuses()

    def test_symlinked_source_parent_is_refused(self):
        parent = self.source.parent
        moved = parent.with_name(parent.name + "-copy")
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        self.refuses()

    def test_current_map_missing_or_symlinked_is_refused(self):
        path = self.root / MAP
        raw = path.read_bytes()
        path.unlink()
        self.refuses()
        copy = self.root / "same-map"
        copy.write_bytes(raw)
        path.symlink_to(copy)
        self.refuses()

    def test_map_byte_pin_rejects_semantically_equivalent_reformatting(self):
        path = self.root / MAP
        path.write_bytes(path.read_bytes() + b"\n")
        self.refuses()

    def test_missing_and_extra_current_paths_are_refused(self):
        for add in (False, True):
            with self.subTest(extra=add):
                data = deepcopy(self.mapping)
                if add:
                    data["current_source_files_sha256"]["extra.rs"] = "0" * 64
                else:
                    del data["current_source_files_sha256"][next(iter(PATHS))]
                self.write_map(data)
                self.refuses()

    def test_duplicate_map_json_keys_are_refused(self):
        path = self.root / MAP
        raw = path.read_bytes()
        path.write_bytes(b'{"status":"HOLD",' + raw.lstrip()[1:])
        self.refuses()

    def test_malformed_current_digest_encodings_are_refused(self):
        for digest in ("0" * 40, "A" * 64, "g" * 64, True, None):
            with self.subTest(digest=digest):
                data = deepcopy(self.mapping)
                data["current_source_files_sha256"][next(iter(PATHS))] = digest
                self.write_map(data)
                self.refuses()

    def test_source_and_map_cannot_be_changed_together(self):
        self.source.write_bytes(b"Simultaneously changed source and map fixture.\n")
        data = deepcopy(self.mapping)
        data["current_source_files_sha256"][self.source.relative_to(self.root).as_posix()] = (
            hashlib.sha256(self.source.read_bytes()).hexdigest())
        data["current_source_snapshot_sha256"] = hashlib.sha256(
            current.canonical(data["current_source_files_sha256"])).hexdigest()
        self.write_map(data)
        self.refuses()

    def test_frozen_map_cannot_be_substituted_for_current_map(self):
        lock = json.loads((self.root / legacy.DEFAULT_SOURCE_LOCK).read_bytes())
        data = deepcopy(self.mapping)
        data["current_source_files_sha256"] = lock["files"]
        data["current_source_snapshot_sha256"] = hashlib.sha256(
            current.canonical(lock["files"])).hexdigest()
        self.write_map(data)
        self.refuses()

    def test_current_map_cannot_rewrite_frozen_identity(self):
        data = deepcopy(self.mapping)
        data["frozen_model"]["source_revision"] = "d" * 40
        data["frozen_model"]["source_lock_sha256"] = data["current_source_snapshot_sha256"]
        self.write_map(data)
        self.refuses()

    def test_frozen_manifest_missing_or_modified_is_refused(self):
        path = self.root / legacy.DEFAULT_MANIFEST
        raw = path.read_bytes()
        path.unlink()
        self.refuses()
        path.write_bytes(raw + b"\n")
        self.refuses()

    def test_frozen_lock_missing_or_modified_is_refused(self):
        path = self.root / legacy.DEFAULT_SOURCE_LOCK
        raw = path.read_bytes()
        path.unlink()
        self.refuses()
        path.write_bytes(raw + b"\n")
        self.refuses()

    def test_unknown_fields_and_qualification_promotions_are_refused(self):
        changes = (
            lambda data: data.update(unreviewed=True),
            lambda data: data["qualification"].update(whole_chain_pq_qualified=True),
            lambda data: data["qualification"].update(actual_lifetime_failure_bound=0),
            lambda data: data["qualification"].update(production_activation=0),
        )
        for change in changes:
            data = deepcopy(self.mapping)
            change(data)
            self.write_map(data)
            self.refuses()

    def test_oversize_map_is_refused(self):
        (self.root / MAP).write_bytes(b" " * (32768 + 1))
        self.refuses()

    def test_changed_metadata_during_source_read_is_refused(self):
        original = current.read_regular
        changed = False

        def read(root, path, ceiling):
            nonlocal changed
            raw = original(root, path, ceiling)
            if path == self.source.relative_to(self.root).as_posix() and not changed:
                changed = True
                target = self.root / MAP
                target.write_bytes(target.read_bytes() + b"\n")
            return raw

        with patch.object(current, "read_regular", side_effect=read):
            self.refuses()
        self.assertTrue(changed)

    def test_exact_report_is_revalidated_against_current_bytes(self):
        report = current.inspect(self.root)
        raw = json.dumps(report, sort_keys=True).encode()
        self.assertEqual(current.verify_report(self.root, raw), report)

    def test_old_v1_report_is_not_a_current_report(self):
        data = legacy.strict_json((self.root / legacy.DEFAULT_MANIFEST).read_bytes())
        raw = json.dumps(legacy.evaluate(data)).encode()
        with self.assertRaises(current.CurrentBudgetError):
            current.verify_report(self.root, raw)

    def test_report_false_zero_swaps_extra_and_missing_fields_are_refused(self):
        original = current.inspect(self.root)
        changes = (
            lambda data: data.update(whole_chain_pq_qualified=0),
            lambda data: data.update(actual_lifetime_failure_bound=False),
            lambda data: data.update(extra="unreviewed"),
            lambda data: data.pop("frozen_model_identity"),
            lambda data: data["current_source_correspondence"].update(source_revision_bound=True),
        )
        for change in changes:
            data = deepcopy(original)
            change(data)
            with self.assertRaises(current.CurrentBudgetError):
                current.verify_report(self.root, json.dumps(data).encode())

    def test_map_and_report_hashes_cannot_be_laundered_together(self):
        report = current.inspect(self.root)
        self.source.write_bytes(b"Changed current source for simultaneous-tamper control.\n")
        path = self.source.relative_to(self.root).as_posix()
        data = deepcopy(self.mapping)
        data["current_source_files_sha256"][path] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        snapshot = hashlib.sha256(current.canonical(data["current_source_files_sha256"])).hexdigest()
        data["current_source_snapshot_sha256"] = snapshot
        self.write_map(data)
        report["current_source_correspondence"].update(
            source_files_sha256=data["current_source_files_sha256"],
            source_snapshot_sha256=snapshot,
            map_sha256=hashlib.sha256((self.root / MAP).read_bytes()).hexdigest())
        with self.assertRaises(current.CurrentBudgetError):
            current.verify_report(self.root, json.dumps(report).encode())

    def test_report_cannot_survive_a_later_source_change(self):
        raw = json.dumps(current.inspect(self.root)).encode()
        self.source.write_bytes(self.source.read_bytes() + b"\n")
        with self.assertRaises(current.CurrentBudgetError):
            current.verify_report(self.root, raw)

    def test_report_bytes_are_bounded_and_strict(self):
        for raw in (b"", b" " * (262144 + 1), b'{"status":"HOLD","status":"HOLD"}',
                    b'{"value":NaN}', b'{"value":1.0}', b"[]", "not bytes"):
            with self.subTest(size=len(raw)):
                with self.assertRaises(current.CurrentBudgetError):
                    current.verify_report(self.root, raw)


if __name__ == "__main__":
    unittest.main()
