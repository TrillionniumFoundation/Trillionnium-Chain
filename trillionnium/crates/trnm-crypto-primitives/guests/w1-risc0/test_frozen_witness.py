#!/usr/bin/env python3
"""V2 provenance controls on actual original and failed-fresh artifacts."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import segment_continue_source as legacy
import segment_continue_v2 as runner
import segment_frozen_v2 as frozen
from segment_witness import check_chain, decode_segment


class FrozenWitnessControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.manifest = frozen.load_policy()
        cls.files = frozen.original_members(cls.policy, cls.manifest)
        cls.observed = frozen.ROOT / "evidence/pon-w1-frozen-witness-v2-20261028/fresh-session"
        cls.session = legacy.decode(cls.files["segmented/session/session.json"])
        cls.encoded = [cls.files[f"segmented/session/segment-{i}"] for i in range(62)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def original_copy(self):
        directory = self.root / "frozen"
        directory.mkdir()
        for name, data in self.files.items():
            if name.startswith("segmented/session/"):
                legacy.write_bytes(directory / name.removeprefix("segmented/session/"), data)
        return directory

    def fresh_copy(self):
        return Path(shutil.copytree(self.observed, self.root / "fresh"))

    def test_original_62_witnesses_and_61_boundaries_decode_completely(self):
        session, claims = frozen.check_frozen_session(self.files, self.original_copy())
        self.assertEqual(len(claims["segments"]), 62)
        self.assertEqual(session, self.session)
        self.assertFalse(claims["cryptographic_proof_verified"])
        for a, b in zip(claims["segments"], claims["segments"][1:]):
            self.assertEqual(a["post_state"], b["pre_state"])

    def test_actual_fresh_export_is_independent_control_and_v1_still_rejects(self):
        fresh = frozen.compare_fresh_session(self.files, self.observed)
        self.assertEqual(fresh["session_claim_digest"], self.session["session_claim_digest"])
        self.assertTrue(all(a["sha256"] != b["sha256"] for a, b in zip(fresh["segments"], self.session["segments"])))
        with self.assertRaisesRegex(ValueError, "same original session"):
            legacy.compare_fresh_session(self.files, self.observed)

    def test_known_entropy_difference_and_unchanged_ordered_other_reads(self):
        original = decode_segment(self.encoded[0])
        fresh = decode_segment((self.observed / "segment-0").read_bytes())
        self.assertEqual(original["read_record"][0], "69926f804ae3f60aeefeb994005f2ffc")
        self.assertEqual(fresh["read_record"][0], "b926aa81aecabcad2877256e53b52c9a")
        self.assertEqual(original["read_record"][1:], fresh["read_record"][1:])
        self.assertEqual(original["write_record"], fresh["write_record"])
        for index in range(1, 62):
            a = decode_segment(self.encoded[index])
            b = decode_segment((self.observed / f"segment-{index}").read_bytes())
            self.assertEqual(a["read_record"], b["read_record"])
            self.assertEqual(a["write_record"], b["write_record"])
            if 2190 in a["partial_image"]["pages"]:
                self.assertEqual(a["partial_image"]["pages"][2190][768 * 2:784 * 2], original["read_record"][0])
                self.assertEqual(b["partial_image"]["pages"][2190][768 * 2:784 * 2], fresh["read_record"][0])

    def test_substituted_fresh_witness_never_continues_original_receipts(self):
        directory = self.original_copy()
        for i in [0, 25, 26, 61]:
            with self.subTest(index=i):
                p = directory / f"segment-{i}"
                p.write_bytes((self.observed / p.name).read_bytes())
                with self.assertRaisesRegex(ValueError, "frozen witness/session/claim"):
                    frozen.check_frozen_session(self.files, directory)
                p.write_bytes(self.encoded[i])

    def test_single_byte_raw_mutation_and_claim_replacement_refused(self):
        directory = self.original_copy()
        for name in ["segment-0", "segment-26", "segment-61", "session.claim.bin", "session.json"]:
            with self.subTest(name=name):
                p = directory / name
                original = p.read_bytes()
                changed = bytearray(original)
                changed[-1] ^= 1
                p.write_bytes(changed)
                with self.assertRaises(ValueError):
                    frozen.check_frozen_session(self.files, directory)
                p.write_bytes(original)

    def test_missing_reordered_and_duplicate_witness_refused(self):
        for items in [self.encoded[:-1], [self.encoded[1], self.encoded[0], *self.encoded[2:]],
                      [self.encoded[0], self.encoded[0], *self.encoded[2:]]]:
            with self.subTest(count=len(items)), self.assertRaises(ValueError):
                check_chain(self.session, items)

    def test_missing_and_extra_frozen_paths_refused(self):
        directory = self.original_copy()
        p = directory / "segment-61"
        p.unlink()
        with self.assertRaisesRegex(ValueError, "missing/extra"):
            frozen.check_frozen_session(self.files, directory)
        p.write_bytes(self.encoded[61])
        (directory / "extra").write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "missing/extra"):
            frozen.check_frozen_session(self.files, directory)

    def test_fresh_w1_header_claim_input_and_unknown_metadata_refused(self):
        directory = self.fresh_copy()
        original = legacy.read(directory / "session.json")
        for key in ["journal_hex", "statement_id", "session_claim_digest", "input_sha256", "image_id", "unknown"]:
            item = copy.deepcopy(original)
            item[key] = "00"
            (directory / "session.json").write_text(json.dumps(item))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "full W1 statement"):
                frozen.compare_fresh_session(self.files, directory)

    def test_fresh_trace_edit_requires_its_exact_new_raw_hash(self):
        directory = self.fresh_copy()
        p = directory / "segment-0"
        b = bytearray(p.read_bytes())
        b[100] ^= 1
        p.write_bytes(b)
        with self.assertRaisesRegex(ValueError, "identity/hash/order"):
            frozen.compare_fresh_session(self.files, directory)

    def test_fresh_claim_bytes_and_input_bytes_cannot_be_substituted(self):
        directory = self.fresh_copy()
        p = directory / "session.claim.bin"
        b = bytearray(p.read_bytes()); b[-1] ^= 1; p.write_bytes(b)
        with self.assertRaisesRegex(ValueError, "full session claim"):
            frozen.compare_fresh_session(self.files, directory)
        elf, inp = self.root / "guest.bin", self.root / "input.bin"
        elf.write_bytes(self.files["guest.bin"])
        b = bytearray(self.files["input.bin"]); b[4] ^= 1; inp.write_bytes(b)
        with self.assertRaisesRegex(ValueError, "image/input"):
            frozen.compare_fresh_inputs(self.files, elf, inp)

    def test_sdk_shape_truncation_trailing_and_unbounded_length_refused(self):
        b = self.encoded[0]
        for bad in [b[:-1], b + b"x", b[:4] + b"\xff" * 8 + b[12:]]:
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                decode_segment(bad)

    def test_fresh_original_boundary_splice_refused_even_after_rehash(self):
        mixed = list(self.encoded)
        mixed[26] = (self.observed / "segment-26").read_bytes()
        session = copy.deepcopy(self.session)
        session["segments"][26]["sha256"] = legacy.sha(mixed[26])
        with self.assertRaisesRegex(ValueError, "adjacent pre/post"):
            check_chain(session, mixed)

    def test_report_reader_rechecks_equal_length_w1_input_and_elf(self):
        elf, inp = self.root / "guest.bin", self.root / "input.bin"
        elf.write_bytes(self.files["guest.bin"])
        inp.write_bytes(self.files["input.bin"])
        runner.check_report_inputs(self.root, self.files)
        for path in [elf, inp]:
            original = path.read_bytes()
            changed = bytearray(original); changed[4] ^= 1; path.write_bytes(changed)
            self.assertEqual(len(changed), len(original))
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "image/input"):
                runner.check_report_inputs(self.root, self.files)
            path.write_bytes(original)

    def test_assembly_reader_rechecks_actual_receipt_bytes_after_verification(self):
        directory = self.root / "receipts"
        directory.mkdir()
        expected = {i: self.files[f"segmented/receipts/segment-{i}.bin"] for i in range(26)}
        for i, data in expected.items():
            (directory / f"segment-{i}.bin").write_bytes(data)
        # An actual-26 byte inventory is a provenance control, never a full proof.
        runner.check_receipt_directory(directory, expected)
        path = directory / "segment-25.bin"
        original = path.read_bytes()
        changed = bytearray(original); changed[-1] ^= 1; path.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "readback bytes"):
            runner.check_receipt_directory(directory, expected)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "file set"):
            runner.check_receipt_directory(directory, expected)
        with self.assertRaisesRegex(ValueError, "actual 62"):
            runner.check_assembly_material(self.root, self.files, expected)

    def test_v2_policy_cannot_relax_source_or_allow_mixing(self):
        original = legacy.read(frozen.POLICY)
        for key, value in [("legacy_policy_sha256", "0" * 64), ("mix_fresh_and_original_witnesses", True),
                           ("native_receipt_claim_binding_required", False), ("unknown", True)]:
            selected = dict(original); selected[key] = value
            path = self.root / "policy.json"; path.write_text(json.dumps(selected))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "v2 continuation policy"):
                frozen.load_policy(policy_path=path)

    def test_missing_v2_policy_has_no_silent_generation(self):
        with patch.object(frozen, "POLICY", self.root / "absent"):
            with self.assertRaisesRegex(ValueError, "explicit v2"):
                runner.select()


if __name__ == "__main__":
    unittest.main()
