"""Integrity controls for source-history archival and exact byte retrieval."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import check_historical_archive as archive


class ArchiveControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run_git("init", "-q")
        self.run_git("config", "user.name", "Archive test")
        self.run_git("config", "user.email", "archive-test@example.invalid")
        (self.root / "preparation").mkdir()
        self.original = b'{"result":"FAIL","native_tests_executed":0}\r\n'
        (self.root / "preparation/summary.json").write_bytes(self.original)
        (self.root / "inventory.json").write_text('{"schema":"old"}\n')
        (self.root / "failure.json").write_text('{"result":"FAIL"}\n')
        self.run_git("add", ".")
        self.run_git("commit", "-qm", "original observations")
        commit = self.run_git("rev-parse", "HEAD").decode().strip()
        rows = archive.tree_rows(self.root, commit, ["preparation", "inventory.json", "failure.json"])
        for path, row in rows.items():
            row["sha256"] = hashlib.sha256((self.root / path).read_bytes()).hexdigest()
        (self.root / "retained-summary.json").write_bytes(self.original)
        (self.root / "preparation/summary.json").unlink()
        self.data = {
            "schema": "trnm-historical-source-archive-v1", "source_commit": commit,
            "source_tree": self.run_git("rev-parse", "HEAD^{tree}").decode().strip(),
            "scopes": ["preparation"], "file_count": 1, "total_bytes": len(self.original),
            "files": [rows["preparation/summary.json"]],
            "historical_manifests": [rows["inventory.json"]],
            "retained_copies": [{"path": "retained-summary.json", "archive_path": "preparation/summary.json"}],
            "preserved_files": [rows["failure.json"]],
            "qualification_changed": False, "production_activation": False,
        }
        self.index = self.root / "archive.json"

    def run_git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.DEVNULL)

    def check(self, data=None, selected=None):
        self.index.write_text(json.dumps(self.data if data is None else data))
        return archive.validate(self.root, self.index, selected)

    def test_original_failure_bytes_retrievable_without_execution(self):
        result, raw = self.check(selected="preparation/summary.json")
        self.assertEqual(raw, self.original)
        self.assertEqual(result["current_native_tests_executed"], 0)
        self.assertFalse((self.root / "preparation/summary.json").exists())

    def test_manifest_cannot_omit_original_member(self):
        data = copy.deepcopy(self.data)
        data["files"] = []
        data["file_count"] = data["total_bytes"] = 0
        with self.assertRaises(archive.Invalid):
            self.check(data)

    def test_tampered_commit_tree_blob_digest_size_and_totals_refused(self):
        for field in ("source_commit", "source_tree", "blob", "sha256", "bytes", "file_count", "total_bytes"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.data)
                target = data["files"][0] if field in {"blob", "sha256", "bytes"} else data
                value = target[field]
                target[field] = value + 1 if isinstance(value, int) else "0" * len(value)
                with self.assertRaises(archive.Invalid):
                    self.check(data)

    def test_duplicate_member_and_unsafe_path_refused(self):
        for name in ("../failure.json", "/failure.json", "preparation//summary.json"):
            data = copy.deepcopy(self.data)
            data["files"][0]["path"] = name
            with self.assertRaises(archive.Invalid):
                self.check(data)
        data = copy.deepcopy(self.data)
        data["files"] *= 2
        with self.assertRaises(archive.Invalid):
            self.check(data)

    def test_restored_active_copy_refused(self):
        (self.root / "preparation/summary.json").write_bytes(self.original)
        with self.assertRaises(archive.Invalid):
            self.check()

    def test_failure_cannot_be_relabelled_pass(self):
        (self.root / "failure.json").write_text('{"result":"PASS"}\n')
        with self.assertRaises(archive.Invalid):
            self.check()

    def test_forged_updated_failure_digest_still_refused(self):
        raw = b'{"result":"PASS"}\n'
        (self.root / "failure.json").write_bytes(raw)
        data = copy.deepcopy(self.data)
        data["preserved_files"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(archive.Invalid):
            self.check(data)

    def test_retained_summary_cannot_change(self):
        (self.root / "retained-summary.json").write_bytes(self.original.replace(b"FAIL", b"PASS"))
        with self.assertRaises(archive.Invalid):
            self.check()

    def test_selected_path_must_be_indexed(self):
        with self.assertRaises(archive.Invalid):
            self.check(selected="failure.json")

    def test_symlink_retained_summary_refused(self):
        (self.root / "retained-summary.json").unlink()
        (self.root / "retained-summary.json").symlink_to("failure.json")
        with self.assertRaises(archive.Invalid):
            self.check()

    def test_duplicate_json_key_refused(self):
        self.index.write_text(json.dumps(self.data)[:-1] + ', "schema":"shadow"}')
        with self.assertRaises(archive.Invalid):
            archive.validate(self.root, self.index)

    def test_qualification_promotion_refused(self):
        data = copy.deepcopy(self.data)
        data["qualification_changed"] = True
        with self.assertRaises(archive.Invalid):
            self.check(data)


if __name__ == "__main__":
    unittest.main()
