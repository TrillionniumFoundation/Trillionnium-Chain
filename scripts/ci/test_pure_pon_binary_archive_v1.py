#!/usr/bin/env python3
"""Synthetic byte-retention controls, never executable performance evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pure_pon_binary_archive_v1 as archive


class RetentionControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.output, self.target = base / "output", base / "target"
        self.output.mkdir()
        self.target.mkdir()
        self.binaries = {}
        for name in archive.NAMES:
            path = self.target / name
            raw = ("synthetic bytes, not a native executable: " + name).encode()
            path.write_bytes(raw)
            self.binaries[name] = {"path": str(path), "bytes": len(raw),
                                   "sha256": hashlib.sha256(raw).hexdigest()}

    def retain(self):
        return archive.retain(self.output, self.target, self.binaries, "a" * 40, "b" * 40)

    def verify(self):
        return archive.verify(self.output, self.binaries, "a" * 40, "b" * 40)

    def test_complete_actual_bytes_reopen_independently(self):
        result = self.retain()
        self.assertTrue(result["complete"])
        self.assertEqual(result, self.verify())
        for row in result["files"]:
            self.assertEqual((self.output / row["retained_path"]).read_bytes(),
                             Path(row["source_path"]).read_bytes())

    def test_mutating_retained_same_length_bytes_rejects(self):
        result = self.retain()
        path = self.output / result["files"][0]["retained_path"]
        raw = path.read_bytes()
        path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaisesRegex(ValueError, "DIGEST_MISMATCH"):
            self.verify()

    def test_missing_binary_does_not_qualify_other_five(self):
        self.binaries.pop(next(iter(self.binaries)))
        result = self.retain()
        self.assertFalse(result["complete"])
        self.assertTrue(any("EXACT_SIX" in error for error in result["errors"]))
        self.assertEqual([row["name"] for row in result["files"]], sorted(self.binaries))
        for row in result["files"]:
            self.assertTrue(row["complete"])
            self.assertEqual((self.output / row["retained_path"]).read_bytes(),
                             Path(row["source_path"]).read_bytes())
        with self.assertRaisesRegex(ValueError, "COMPLETION"):
            self.verify()

    def test_unknown_binary_is_not_opened_or_copied_and_cannot_qualify_six(self):
        unknown = "unknown-untrusted-executable"
        # This path does not exist and this size exceeds the file bound. Neither
        # can prevent retention of fixed-name members or permit an extra copy.
        self.binaries[unknown] = {"path": str(self.target / unknown),
                                  "bytes": archive.FILE_LIMIT + 1, "sha256": "0" * 64}
        result = self.retain()
        self.assertFalse(result["complete"])
        self.assertTrue(any("EXACT_SIX" in error for error in result["errors"]))
        self.assertEqual([row["name"] for row in result["files"]], sorted(archive.NAMES))
        self.assertTrue(all(row["complete"] for row in result["files"]))
        self.assertEqual(sorted(path.name for path in (self.output / "retained-binaries").iterdir()),
                         sorted(archive.NAMES))
        for row in result["files"]:
            self.assertEqual((self.output / row["retained_path"]).read_bytes(),
                             Path(row["source_path"]).read_bytes())
        with self.assertRaisesRegex(ValueError, "COMPLETION"):
            self.verify()

    def test_source_symlink_and_directory_symlink_reject(self):
        name = sorted(archive.NAMES)[0]
        path = Path(self.binaries[name]["path"])
        actual = path.with_suffix(".actual")
        path.rename(actual)
        path.symlink_to(actual)
        result = self.retain()
        self.assertFalse(result["complete"])
        self.assertFalse(result["files"][0]["complete"])

    def test_retained_symlink_cannot_substitute_matching_source(self):
        row = self.retain()["files"][0]
        path = self.output / row["retained_path"]
        path.unlink()
        path.symlink_to(row["source_path"])
        with self.assertRaises(OSError):
            self.verify()

    def test_fixed_budget_cannot_be_overridden_by_declared_size(self):
        self.binaries[sorted(archive.NAMES)[0]]["bytes"] = archive.FILE_LIMIT + 1
        result = self.retain()
        self.assertFalse(result["complete"])
        self.assertTrue(any("BYTE_BOUND" in error for error in result["errors"]))

    def test_expected_digest_mismatch_retains_failed_original_copy(self):
        name = sorted(archive.NAMES)[0]
        self.binaries[name]["sha256"] = "0" * 64
        result = self.retain()
        self.assertFalse(result["complete"])
        self.assertTrue((self.output / result["files"][0]["retained_path"]).is_file())
        self.assertIn("DIGEST_MISMATCH", result["files"][0]["error"])

    def test_deadline_failure_is_retained_without_zero_fabrication(self):
        with patch.object(archive.time, "monotonic", side_effect=[0] + [archive.READ_SECONDS + 1] * 20):
            result = self.retain()
        self.assertFalse(result["complete"])
        self.assertIsNone(result["files"][0]["sha256"])
        self.assertIn("DEADLINE", result["files"][0]["error"])

    def test_source_head_tree_and_manifest_completion_cannot_be_relabelled(self):
        self.retain()
        with self.assertRaisesRegex(ValueError, "BINDING"):
            archive.verify(self.output, self.binaries, "c" * 40, "b" * 40)
        path = self.output / "binary-archive-v1.json"
        value = json.loads(path.read_text())
        value["complete"] = False
        path.write_text(json.dumps(value) + "\n")
        with self.assertRaisesRegex(ValueError, "COMPLETION"):
            self.verify()

    def test_a_second_capture_cannot_replace_original_manifest(self):
        self.retain()
        before = (self.output / "binary-archive-v1.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.retain()
        self.assertEqual(before, (self.output / "binary-archive-v1.json").read_bytes())

    def test_manifest_duplicate_nonfinite_authority_and_boolean_counts_reject(self):
        self.retain()
        path = self.output / "binary-archive-v1.json"
        original = path.read_text()
        variants = [original.replace('"schema":', '"complete": true, "schema":', 1),
                    original.replace('"native_execution": false', '"native_execution": NaN')]
        for field in ("physical_authentication", "native_execution"):
            value = json.loads(original)
            value[field] = True
            variants.append(json.dumps(value) + "\n")
        for field in ("started_monotonic_ns", "ended_monotonic_ns", "file_limit_bytes"):
            value = json.loads(original)
            value[field] = True
            variants.append(json.dumps(value) + "\n")
        value = json.loads(original)
        value["files"][0]["copied_bytes"] = True
        variants.append(json.dumps(value) + "\n")
        for raw in variants:
            with self.subTest(raw=raw[:80]):
                path.write_text(raw)
                with self.assertRaises(ValueError):
                    self.verify()


if __name__ == "__main__":
    unittest.main()
