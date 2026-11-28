#!/usr/bin/env python3
"""Synthetic metadata refusals; exact declared-source inspection belongs to CI.

Only fixture identity constants are replaced. The actual descriptor reader,
original source-coverage traversal and canonical-provider checks remain active.
No synthetic fixture claims a native or historical campaign qualification.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import check_pq_research_integration as frozen
import pq_corpus_current_v2 as current


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


class CurrentCorpusTests(unittest.TestCase):
    CHANGED = "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs"
    ADDED = (
        "trillionnium/crates/trnm-crypto-primitives/src/pon_work/noise_frame.rs",
        "trillionnium/crates/trnm-pon-node/src/pq_rollback_witness/development_observation.rs",
        "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/response_signing_tests.rs",
        "trillionnium/crates/trnm-pon-node/src/pft_selected_readout_v1.rs",
        "trillionnium/crates/trnm-pon-node/src/pft_selected_readout_v1/tests.rs",
    )

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout"
        self.root.mkdir()
        for directory in frozen.PQ_SOURCE_DIRS:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        old_data = {
            self.CHANGED: b"original synthetic work source",
            "scripts/ci/check_pq_research_integration.py": b"synthetic guard fixture",
            "scripts/ci/test_pq_research_integration.py": b"synthetic negative-control fixture",
            "scripts/ci/pq_source_reader.py": b"synthetic descriptor-identity fixture",
        }
        for package in ("trnm-crypto-primitives", "trnm-mvcc-fee", "trnm-pon-node"):
            data = ('[package.metadata.trnm]\nproduction_activation = false\n'
                    'consensus_authority = false\n[features]\ndefault = []\n'
                    'pq-native-openssl = ["dep:openssl"]\n[dependencies]\n'
                    'openssl = {version = "=0.10.81", optional = true}\n')
            if package == "trnm-crypto-primitives":
                data += ('ml-dsa = {version = "=0.1.1", default-features = false, '
                         'features = ["alloc", "zeroize"]}\n')
            old_data[f"trillionnium/crates/{package}/Cargo.toml"] = data.encode()
        for path, raw in old_data.items():
            self.put(path, raw)
        self.original = {
            "schema": "trnm-pq-cross-branch-corpus-v1",
            "status": "research-only-hold-no-go", "parent_profile": "pon-nakamoto-v1",
            "upstream_heads": {key: "1" * 40 for key in frozen.REQUIRED_UPSTREAM},
            "assertions": {key: False for key in frozen.REQUIRED_FALSE},
            "required_paths": sorted(old_data),
            "pinned_blobs": {path: git_blob(raw) for path, raw in sorted(old_data.items())},
        }
        corpus_raw = canonical(self.original) + b"\n"
        self.put(frozen.REL_MANIFEST, corpus_raw)
        frozen_inputs = {
            frozen.REL_MANIFEST: hashlib.sha256(corpus_raw).hexdigest(),
            **{path: hashlib.sha256(raw).hexdigest()
               for path, raw in old_data.items() if path.startswith("scripts/ci/")},
        }
        reviewed = b"reviewed current synthetic work source"
        self.put(self.CHANGED, reviewed)
        self.mapping = {
            "schema": current.MAP_SCHEMA, "status": "HOLD", "scope": current.SCOPE,
            "frozen_inputs_sha256": frozen_inputs,
            "qualification": copy.deepcopy(current.QUALIFICATION),
            "replacements": {
                self.CHANGED: {
                    "frozen_git_blob": self.original["pinned_blobs"][self.CHANGED],
                    "current_git_blob": git_blob(reviewed),
                    "current_sha256": hashlib.sha256(reviewed).hexdigest(),
                },
            },
            "additions": {},
        }
        for path in self.ADDED:
            raw = ("reviewed addition " + path).encode()
            self.put(path, raw)
            self.mapping["additions"][path] = {
                "current_git_blob": git_blob(raw),
                "current_sha256": hashlib.sha256(raw).hexdigest(),
            }
        snapshot = self.snapshot()
        self.mapping["current_git_blob_map_sha256"] = snapshot
        self.save()
        self.enterContext(mock.patch.multiple(
            current,
            FROZEN_INPUTS_SHA256=frozen_inputs,
            EXPECTED_FROZEN_PIN_COUNT=len(old_data),
            EXPECTED_REPLACEMENT_PATHS=frozenset((self.CHANGED,)),
            EXPECTED_ADDED_PATHS=frozenset(self.ADDED),
            EXPECTED_MAP_SHA256=hashlib.sha256(self.map_path.read_bytes()).hexdigest(),
            EXPECTED_CURRENT_BLOBS_SHA256=snapshot,
        ))

    @property
    def map_path(self):
        return self.root / current.DEFAULT_MAP

    def put(self, path, raw):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)

    def snapshot(self):
        pins = dict(self.original["pinned_blobs"])
        for section in ("replacements", "additions"):
            pins.update({path: row["current_git_blob"]
                         for path, row in self.mapping[section].items()})
        return hashlib.sha256(canonical(pins)).hexdigest()

    def save(self):
        self.put(current.DEFAULT_MAP, canonical(self.mapping) + b"\n")

    def inspect_rebound_map(self):
        """Reach structural refusals without disabling the independent snapshot."""
        self.save()
        with mock.patch.object(current, "EXPECTED_MAP_SHA256",
                               hashlib.sha256(self.map_path.read_bytes()).hexdigest()):
            return current.inspect(self.root)

    def test_reviewed_current_fixture_remains_hold(self):
        result = current.inspect(self.root)
        self.assertEqual({key: result[key] for key in current.QUALIFICATION},
                         current.QUALIFICATION)
        self.assertEqual((result["status"], result["current_source_correspondence_checked"],
                          result["source_revision_bound"], result["current_declared_path_count"]),
                         ("HOLD", True, False, len(self.original["pinned_blobs"]) + 5))

    def test_original_v1_entry_still_refuses_changed_source(self):
        with self.assertRaisesRegex(frozen.IntegrityError, "changed source: " + self.CHANGED):
            frozen.check(self.root)

    def test_frozen_corpus_tampering_refuses(self):
        path = self.root / frozen.REL_MANIFEST
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(current.CurrentCorpusError, "frozen input changed"):
            current.inspect(self.root)

    def test_frozen_guard_source_tampering_refuses(self):
        self.put("scripts/ci/check_pq_research_integration.py", b"changed guard")
        with self.assertRaisesRegex(current.CurrentCorpusError, "frozen input changed"):
            current.inspect(self.root)

    def test_missing_original_source_refuses(self):
        (self.root / "trillionnium/crates/trnm-mvcc-fee/Cargo.toml").unlink()
        with self.assertRaises(current.CurrentCorpusError):
            current.inspect(self.root)

    def test_unreviewed_replacement_roster_refuses(self):
        self.mapping["replacements"]["unreviewed.rs"] = self.mapping["replacements"].pop(self.CHANGED)
        with self.assertRaisesRegex(current.CurrentCorpusError, "replacement roster"):
            self.inspect_rebound_map()

    def test_wrong_original_blob_refuses(self):
        self.mapping["replacements"][self.CHANGED]["frozen_git_blob"] = "0" * 40
        with self.assertRaisesRegex(current.CurrentCorpusError, "preserve original blob"):
            self.inspect_rebound_map()

    def test_missing_or_extra_addition_refuses(self):
        original = copy.deepcopy(self.mapping["additions"])
        for additions in ({self.ADDED[0]: original[self.ADDED[0]]},
                          {**original, "extra.rs": original[self.ADDED[0]]}):
            with self.subTest(additions=sorted(additions)):
                self.mapping["additions"] = additions
                with self.assertRaisesRegex(current.CurrentCorpusError, "addition roster"):
                    self.inspect_rebound_map()

    def test_changed_source_cannot_reuse_reviewed_pins(self):
        for path in (self.CHANGED, *self.ADDED,
                     "trillionnium/crates/trnm-mvcc-fee/Cargo.toml"):
            with self.subTest(path=path):
                target = self.root / path
                before = target.read_bytes()
                try:
                    target.write_bytes(before + b"changed")
                    with self.assertRaisesRegex(current.CurrentCorpusError, "current source changed"):
                        current.inspect(self.root)
                finally:
                    target.write_bytes(before)

    def test_unchanged_source_cannot_be_relabelled_as_replacement(self):
        row = self.mapping["replacements"][self.CHANGED]
        row["current_git_blob"] = row["frozen_git_blob"]
        with self.assertRaisesRegex(current.CurrentCorpusError, "unchanged path"):
            self.inspect_rebound_map()

    def test_supplied_self_hash_cannot_replace_independent_snapshot(self):
        raw = b"unapproved new work source"
        self.put(self.CHANGED, raw)
        row = self.mapping["replacements"][self.CHANGED]
        row["current_git_blob"] = git_blob(raw)
        row["current_sha256"] = hashlib.sha256(raw).hexdigest()
        self.mapping["current_git_blob_map_sha256"] = self.snapshot()
        with self.assertRaisesRegex(current.CurrentCorpusError, "independent snapshot pin"):
            self.inspect_rebound_map()

    def test_new_nested_pq_source_refuses(self):
        self.put("trillionnium/crates/trnm-pon-node/src/pq_new_owner/hidden.rs", b"unreviewed")
        with self.assertRaisesRegex(current.CurrentCorpusError, "unpinned PQ source"):
            current.inspect(self.root)

    def test_source_and_checkout_symlinks_refuse(self):
        target = self.root / self.ADDED[0]
        stored = target.with_suffix(".stored")
        target.rename(stored)
        target.symlink_to(stored.name)
        with self.assertRaises(current.CurrentCorpusError):
            current.inspect(self.root)
        target.unlink()
        stored.rename(target)
        link = self.root.parent / "linked-checkout"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(current.CurrentCorpusError):
            current.inspect(link)

    def test_current_map_symlink_refuses(self):
        original = self.map_path.with_suffix(".stored")
        self.map_path.rename(original)
        self.map_path.symlink_to(original.name)
        with self.assertRaises(current.CurrentCorpusError):
            current.inspect(self.root)

    def test_map_changed_during_inspection_refuses(self):
        original_read = current.read_regular
        changed = False

        def read(root, path, maximum):
            nonlocal changed
            result = original_read(root, path, maximum)
            if path == self.CHANGED and not changed:
                changed = True
                self.map_path.write_bytes(self.map_path.read_bytes() + b"\n")
            return result

        with mock.patch.object(current, "read_regular", read):
            with self.assertRaisesRegex(current.CurrentCorpusError, "map changed during inspection"):
                current.inspect(self.root)

    def test_qualification_cannot_be_promoted(self):
        for field in current.QUALIFICATION:
            with self.subTest(field=field):
                self.mapping["qualification"] = {**current.QUALIFICATION, field: True}
                with self.assertRaisesRegex(current.CurrentCorpusError, "cannot grant qualification"):
                    self.inspect_rebound_map()

    def test_reports_are_recomputed_against_current_source(self):
        report = current.inspect(self.root)
        self.assertEqual(current.verify_report(self.root, canonical(report)), report)
        forged = {**report, "native_cryptography_qualified": True}
        with self.assertRaisesRegex(current.CurrentCorpusError, "fresh inspection"):
            current.verify_report(self.root, canonical(forged))
        self.put(self.ADDED[0], b"changed after original report")
        with self.assertRaisesRegex(current.CurrentCorpusError, "current source changed"):
            current.verify_report(self.root, canonical(report))

    def test_duplicate_json_key_refuses(self):
        raw = self.map_path.read_bytes()
        duplicate = b'{"schema":"duplicate",' + raw[1:]
        self.map_path.write_bytes(duplicate)
        with mock.patch.object(current, "EXPECTED_MAP_SHA256", hashlib.sha256(duplicate).hexdigest()):
            with self.assertRaisesRegex(current.CurrentCorpusError, "duplicate JSON key"):
                current.inspect(self.root)


if __name__ == "__main__":
    unittest.main()
