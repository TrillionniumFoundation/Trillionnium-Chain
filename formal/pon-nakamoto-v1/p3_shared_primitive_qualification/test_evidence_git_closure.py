"""Regression checks for evidence that exists locally but is absent from Git."""
import copy
import gzip
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from verify_evidence_git_closure import PREFIX, digest, verify_commit


class EvidenceGitClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / PREFIX / "test-store"
        self.base.mkdir(parents=True)
        self.git("init", "-q")
        (self.root / ".gitignore").write_text("*.log\n")
        self.plain = b"original ignored log\n"
        self.raw = b"proof payload" * 9
        self.packed = gzip.compress(self.raw, mtime=0)
        (self.base / "proof.log").write_bytes(self.plain)
        (self.base / "payload.gz").write_bytes(self.packed)
        compressed_item = {
            "path": "proof.bin", "bytes": len(self.raw), "sha256": digest(self.raw),
            "storage": {"kind": "gzip_object", "path": "payload.gz",
                        "bytes": len(self.packed), "sha256": digest(self.packed)},
        }
        alias = copy.deepcopy(compressed_item)
        alias["path"] = "duplicate/proof.bin"
        self.index = {
            "schema": "p3-native-observation-file-store-v1",
            "file_count": 3, "total_uncompressed_bytes": len(self.plain) + 2 * len(self.raw),
            "binary_object_count": 1, "compressed_binary_bytes": len(self.packed),
            "files": [
                {"path": "proof.log", "bytes": len(self.plain), "sha256": digest(self.plain),
                 "storage": {"kind": "plain", "path": "proof.log"}},
                compressed_item, alias,
            ],
        }

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.PIPE)

    def commit(self, include_log=True):
        (self.base / "file-index.json").write_text(json.dumps(self.index))
        self.git("add", "-A")
        if include_log:
            self.git("add", "-f", "--", PREFIX + "test-store/proof.log")
        self.git("-c", "user.name=Evidence test", "-c", "user.email=evidence@example.invalid",
                 "commit", "-q", "--allow-empty", "-m", "fixture")
        return self.git("rev-parse", "HEAD").decode().strip()

    def check(self, head):
        return verify_commit(self.root, head, ("test-store",))

    def test_committed_plain_gzip_dedup_and_worktree_independence(self):
        head = self.commit()
        (self.base / "file-index.json").write_text("invalid local index")
        (self.base / "proof.log").unlink()
        result = self.check(head)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["stores"][0]["distinct_storage_files"], 2)
        self.assertFalse(result["working_tree_evidence_used"])

    def test_ignored_local_file_does_not_close_commit(self):
        head = self.commit(include_log=False)
        self.assertTrue((self.base / "proof.log").is_file())
        with self.assertRaisesRegex(ValueError, "missing committed"):
            self.check(head)

    def test_local_repair_does_not_hide_corrupt_committed_blob(self):
        (self.base / "proof.log").write_bytes(b"corrupt")
        head = self.commit()
        (self.base / "proof.log").write_bytes(self.plain)
        with self.assertRaisesRegex(ValueError, "original evidence size/hash"):
            self.check(head)

    def test_replace_ref_cannot_substitute_a_complete_commit(self):
        incomplete = self.commit(include_log=False)
        complete = self.commit()
        self.git("replace", incomplete, complete)
        with self.assertRaisesRegex(ValueError, "missing committed"):
            self.check(incomplete)
        self.assertEqual(self.check(complete)["result"], "PASS")

    def test_symlink_blob_is_not_an_ordinary_file(self):
        (self.base / "proof.log").unlink()
        (self.base / "proof.log").symlink_to("payload.gz")
        with self.assertRaisesRegex(ValueError, "nonordinary committed"):
            self.check(self.commit())

    def test_paths_cannot_escape_store(self):
        for invalid in ("../proof.log", "/proof.log", "a//b", "./proof.log", ""):
            with self.subTest(path=invalid):
                self.index["files"][0]["storage"]["path"] = invalid
                with self.assertRaisesRegex(ValueError, "noncanonical"):
                    self.check(self.commit())

    def test_compressed_hash_and_length_are_checked(self):
        storage = self.index["files"][1]["storage"]
        for field, bad in (("sha256", "0" * 64), ("bytes", len(self.packed) + 1)):
            with self.subTest(field=field):
                old = storage[field]
                storage[field] = bad
                with self.assertRaisesRegex(ValueError, "compressed evidence size/hash"):
                    self.check(self.commit())
                storage[field] = old

    def test_uncompressed_hash_and_expansion_bound_are_checked(self):
        item = self.index["files"][1]
        for field, bad in (("sha256", "0" * 64), ("bytes", len(self.raw) - 1), ("bytes", True)):
            with self.subTest(field=field, bad=bad):
                old = item[field]
                item[field] = bad
                with self.assertRaises(ValueError):
                    self.check(self.commit())
                item[field] = old

    def test_aggregate_counts_and_duplicate_logical_paths_are_checked(self):
        for field in ("file_count", "total_uncompressed_bytes", "binary_object_count", "compressed_binary_bytes"):
            with self.subTest(field=field):
                self.index[field] += 1
                with self.assertRaisesRegex(ValueError, "aggregate mismatch"):
                    self.check(self.commit())
                self.index[field] -= 1
        self.index["files"][2]["path"] = "proof.bin"
        with self.assertRaisesRegex(ValueError, "duplicate logical"):
            self.check(self.commit())


if __name__ == "__main__":
    unittest.main()
