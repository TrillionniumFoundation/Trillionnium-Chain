#!/usr/bin/env python3
"""Source-identity counterexamples; these never execute or certify native code."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "recent_source_profile", ROOT / "scripts/ci/check_recent_batch_source_profile.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
OLD = "original-reviewed-v1"
NEW = "native-pq-quota-v3-reviewed-v1"
WORKFLOW = ".github/workflows/pon-recent-batch-acceptance.yml"
FROZEN_WORKFLOW = ROOT / "scripts/ci/fixtures/pon_recent_batch_original_workflow.yml"
FROZEN_WORKFLOW_BLOB = "59d1e66c6ea27d19dd5de0d43bc2a9d0d594b5c6"


def synthetic_document():
    old = {"src/store.rs": CHECK.git_blob(b"old store\n"),
           "src/owner.rs": CHECK.git_blob(b"old owner\n")}
    new = {"src/store.rs": CHECK.git_blob(b"new store\n"),
           "src/owner.rs": CHECK.git_blob(b"new owner\n")}
    return {"schema": CHECK.SCHEMA, "review_basis_commit": "1" * 40,
            "original_workflow_blob": "2" * 40,
            "profiles": {OLD: {"review": "synthetic old identity", "git_blobs": old},
                         NEW: {"review": "synthetic new identity", "git_blobs": new}}}


def named_steps(text):
    parts = re.split(r"(?=^      - name: )", text, flags=re.MULTILINE)
    result = {}
    for part in parts[1:]:
        name = part.splitlines()[0].removeprefix("      - name: ")
        if name in result:
            raise ValueError("duplicate workflow step")
        result[name] = part
    return result


class SourceProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "src").mkdir()
        (self.root / "src/store.rs").write_bytes(b"new store\n")
        (self.root / "src/owner.rs").write_bytes(b"new owner\n")
        self.document = synthetic_document()

    def test_explicit_new_identity_passes_but_old_never_falls_forward(self):
        self.assertTrue(all(row["matches"] for row in CHECK.verify(self.root, self.document, NEW)))
        old = CHECK.verify(self.root, self.document, OLD)
        self.assertEqual(sum(row["matches"] for row in old), 0)

    def test_unknown_profile_cannot_select_any_identity(self):
        with self.assertRaisesRegex(ValueError, "unknown explicit source profile"):
            CHECK.verify(self.root, self.document, "auto")

    def test_only_updating_store_identity_leaves_hybrid_source_rejected(self):
        (self.root / "src/owner.rs").write_bytes(b"old owner\n")
        rows = CHECK.verify(self.root, self.document, NEW)
        self.assertEqual([row["path"] for row in rows if not row["matches"]], ["src/owner.rs"])
        self.assertFalse(all(row["matches"] for row in CHECK.verify(self.root, self.document, OLD)))

    def test_same_size_late_mutation_is_not_hidden_by_stat_or_earlier_file(self):
        (self.root / "src/store.rs").write_bytes(b"bad store\n")
        rows = CHECK.verify(self.root, self.document, NEW)
        self.assertEqual([row["path"] for row in rows if not row["matches"]], ["src/store.rs"])

    def test_missing_file_and_symlink_alias_refuse(self):
        path = self.root / "src/store.rs"
        path.unlink()
        with self.assertRaisesRegex(ValueError, "missing pinned source"):
            CHECK.verify(self.root, self.document, NEW)
        outside = self.root / "same-bytes.rs"
        outside.write_bytes(b"new store\n")
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symlink source component"):
            CHECK.verify(self.root, self.document, NEW)

    def test_duplicate_manifest_keys_and_unsafe_paths_refuse(self):
        path = self.root / "manifest.json"
        path.write_text('{"schema": "one", "schema": "two"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            CHECK.load_manifest(path)
        for bad in ("../outside.rs", "/outside.rs", "src/../store.rs", ".", "src//store.rs"):
            document = deepcopy(self.document)
            document["profiles"][NEW]["git_blobs"][bad] = "3" * 40
            path.write_text(json.dumps(document))
            with self.subTest(path=bad), self.assertRaisesRegex(ValueError, "noncanonical"):
                CHECK.load_manifest(path)

    def test_cli_failure_retains_exact_profile_and_false_qualification(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(self.document))
        output = self.root / "failure.json"
        process = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ci/check_recent_batch_source_profile.py"),
             "--root", str(self.root), "--manifest", str(manifest), "--profile", OLD,
             "--output", str(output)], capture_output=True, text=True, check=False
        )
        self.assertEqual(process.returncode, 1)
        report = json.loads(output.read_text())
        self.assertEqual((report["profile"], report["result"]), (OLD, "FAIL"))
        for field in ("native_tests_executed", "native_compatibility_qualified", "production_activation"):
            self.assertIs(report[field], False)
        self.assertEqual(len(report["files"]), 2)

    def test_original_sixteen_pins_remain_byte_exact(self):
        raw = FROZEN_WORKFLOW.read_bytes()
        self.assertEqual(CHECK.git_blob(raw), FROZEN_WORKFLOW_BLOB)
        original = dict(re.findall(
            r'test "\$\(git hash-object ([^)]+)\)" = ([0-9a-f]{40})', raw.decode()
        ))
        self.assertEqual(len(original), 16)
        document, _ = CHECK.load_manifest(ROOT / CHECK.MANIFEST)
        self.assertEqual(document["original_workflow_blob"], FROZEN_WORKFLOW_BLOB)
        self.assertEqual(document["profiles"][OLD]["git_blobs"], original)

    def test_reviewed_native_owner_identity_matches_current_source(self):
        document, _ = CHECK.load_manifest(ROOT / CHECK.MANIFEST)
        rows = CHECK.verify(ROOT, document, NEW)
        self.assertEqual(len(rows), 31)
        self.assertTrue(all(row["matches"] for row in rows))
        old = CHECK.verify(ROOT, document, OLD)
        self.assertEqual(sum(not row["matches"] for row in old), 4)

    def test_original_matrix_budgets_and_every_runtime_step_are_unchanged(self):
        original = FROZEN_WORKFLOW.read_text()
        current = (ROOT / WORKFLOW).read_text()
        old_header = original.split("permissions:\n", 1)[1].split("    steps:\n", 1)[0]
        new_header = current.split("permissions:\n", 1)[1].split("    steps:\n", 1)[0]
        new_header = new_header.replace("      SOURCE_PROFILE: native-pq-quota-v3-reviewed-v1\n", "")
        self.assertEqual(new_header, old_header)
        old_steps, new_steps = named_steps(original), named_steps(current)
        identity_step = "Verify exact source, ordered actual main merge and full repository boundary"
        for name, body in old_steps.items():
            if name == identity_step:
                continue
            with self.subTest(step=name):
                self.assertIn(name, new_steps)
                self.assertEqual(new_steps[name], body)
        old_identity = re.sub(
            r'^          test "\$\(git hash-object [^\n]+\n', "", old_steps[identity_step], flags=re.MULTILINE
        )
        new_identity = re.sub(
            r'^          python3 scripts/ci/check_recent_batch_source_profile.py[^\n]+\n', "",
            new_steps[identity_step], flags=re.MULTILINE
        )
        self.assertEqual(old_identity, new_identity)


if __name__ == "__main__":
    unittest.main()
