"""Negative controls for the separate corrected Bench carrier, no synthetic success."""
from pathlib import Path
import json
import stat
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from hia.tools import bench_corrected_evidence as e

HEAD = "a" * 40
TREE = "b" * 40


class CorrectedEvidenceNegativeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="bench-carrier-neg-")))

    def zip(self, rows):
        archive = self.root / "case.zip"
        with warnings.catch_warnings(), zipfile.ZipFile(archive, "w") as z:
            warnings.simplefilter("ignore", UserWarning)
            for name, raw, mode in rows:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (mode | 0o600) << 16
                z.writestr(info, raw)
        return archive

    def rows(self):
        return [(name, b"", stat.S_IFREG) for name in sorted(e.roster() | {"manifest.json"})]

    def verify(self, archive):
        return e.verify(archive, HEAD, TREE, "22", 1)

    def test_exact_zip_roster_no_duplicate_extra_or_missing(self):
        expected = self.rows()
        for rows in (expected[:-1], [*expected, expected[-1]],
                     [*expected, ("raw/UNRELATED_FIXTURE.env", b"unrelated", stat.S_IFREG)]):
            with self.subTest(members=len(rows)), self.assertRaisesRegex(ValueError, "ZIP roster"):
                self.verify(self.zip(rows))

    def test_reject_archive_link_and_nonregular_member(self):
        rows = self.rows()
        with self.assertRaisesRegex(ValueError, "unsafe ZIP member"):
            self.verify(self.zip([(rows[0][0], b"/no-authority", stat.S_IFLNK), *rows[1:]]))
        link = self.root / "linked.zip"
        link.symlink_to(self.root / "case.zip")
        with self.assertRaises(OSError):
            self.verify(link)

    def test_reject_aggregate_and_member_bombs_before_json_or_decompression(self):
        rows = self.rows()
        archive = self.zip([(rows[0][0], b"12345678", stat.S_IFREG), *rows[1:]])
        with patch.object(e, "MAX_MEMBER", 7), self.assertRaisesRegex(ValueError, "unsafe ZIP member"):
            self.verify(archive)
        with patch.object(e, "MAX_TOTAL", 7), self.assertRaisesRegex(ValueError, "unsafe ZIP member"):
            self.verify(archive)

    def test_exact_real_completion_rejects_duplicate_partial_and_wrong_attempt(self):
        path = self.root / "completion.json"
        wrong_records = [
            {"finished": [*e.METHODS[:-1], e.METHODS[0]]},
            {"started": list(e.METHODS[:-1])},
            {"status": "FAIL"}, {"scope": "local-focused"}, {"attempt": 2}, {"tree": "d" * 40}]
        for changed in wrong_records:
            receipt = {"schema": e.COMPLETION, "scope": "hosted-focused", "status": "PASS",
                       "head": HEAD, "tree": TREE, "run_id": "22", "attempt": 1,
                       "started": list(e.METHODS), "finished": list(e.METHODS),
                       "test_count": len(e.METHODS), "source_files": {}}
            receipt.update(changed)
            path.write_text(json.dumps(receipt))
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "focused qualification"):
                e.completion(path, HEAD, "22", 1, False, TREE)

    def test_reject_duplicate_json_field_and_bad_file_fixed_point(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            e.load_json(b'{"head":"one","head":"two"}')
        with self.assertRaisesRegex(ValueError, "profile byte"):
            e.persistence(b"first\n", b"first\nprofile.report.output_bytes=0\n")
