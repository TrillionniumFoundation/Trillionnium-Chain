"""Exercise the CI carrier without extracting any archive members."""
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from hia.tools.archive_ci_evidence import archive_evidence


class EvidenceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.output = self.base / "carrier" / "evidence.tar"

    def check_members(self, expected):
        for name, data in expected.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        archive_evidence(self.source, self.output)
        with tarfile.open(self.output, encoding="utf-8", errors="surrogateescape") as archive:
            actual = {member.name: archive.extractfile(member).read()
                      for member in archive if member.isfile()}
        self.assertEqual(expected, actual)

    def test_round_trip_literal_carriage_return_and_unchanged_bytes(self):
        self.check_members({
            "report/persistence/carriage\rline/summary.txt": b"\x00\r\n\xff",
            "report/persistence/carriage_line/summary.txt": b"different valid filename",
            ".hidden": b"preserved",
        })

    def test_package_diagnostic_only_producer_failure(self):
        self.check_members({
            "general-cargo-fetch.stdout.raw": b"",
            "general-cargo-fetch.stderr.raw": b"producer failed\n",
        })

    def test_round_trip_hosted_crlf_path_and_undecodable_name(self):
        self.check_members({
            "report/persistence-cases/carriage\r\nline/executor-profile-summary-1709251199.txt":
                b"\x00distinct hosted path\r\n",
            "report/persistence-cases/carriage\nline/executor-profile-summary-1709251199.txt":
                b"not the CRLF path",
            os.fsdecode(b"report/persistence-cases/invalid-\xff/summary.txt"):
                b"invalid UTF-8 name kept unchanged",
        })

    def test_refuse_missing_source(self):
        with self.assertRaises(FileNotFoundError):
            archive_evidence(self.base / "missing", self.output)
        self.assertFalse(self.output.exists())

    def test_refuse_symlink(self):
        (self.source / "link").symlink_to(self.base)
        with self.assertRaisesRegex(ValueError, "unsupported evidence entry"):
            archive_evidence(self.source, self.output)
        self.assertFalse(self.output.exists())
