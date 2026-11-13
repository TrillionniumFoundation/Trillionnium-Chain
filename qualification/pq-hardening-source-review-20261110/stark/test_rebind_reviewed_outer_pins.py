"""Offline tool controls; fixtures do not claim a complete repository checkout."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("reviewed_rebinder", HERE / "rebind_reviewed_outer_pins.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class ReviewedPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = HERE / "integration-base"
        cls.baseline = {path: (base / path).read_bytes() for path in tool.BASE_SHA256}
        lock, _budget, ledger = tool.validated_baseline(cls.baseline)
        cls.selected = {path: (base / path).read_bytes()
                        for path in set(lock["files"]) | set(ledger["SOURCE_PINS"])}
        cls.selected[tool.NETWORK] = (HERE.parent / "identity/working" / tool.NETWORK).read_bytes()
        cls.selected[tool.QUANTUM] = (HERE.parent / "quantum/patched" / tool.QUANTUM).read_bytes()
        cls.network_digest = tool.sha(cls.selected[tool.NETWORK])
        # Only a synthetic marker for exercising pure selected-byte planning.
        # The production CLI independently requires a real ancestor/HEAD commit.
        cls.checkpoint = "a" * 40

    def plan(self, *, baseline=None, selected=None, network_digest=None):
        return tool.build_plan(self.baseline if baseline is None else baseline,
                               self.selected if selected is None else selected,
                               self.checkpoint,
                               self.network_digest if network_digest is None else network_digest)

    def test_only_two_source_pins_and_four_output_files_change(self):
        output = self.plan()
        self.assertEqual(set(output), {tool.LOCK, tool.BUDGET, tool.LEDGER, tool.REPORT})
        old_lock = json.loads(self.baseline[tool.LOCK])
        new_lock = json.loads(output[tool.LOCK])
        self.assertEqual({p for p in old_lock["files"]
                          if old_lock["files"][p] != new_lock["files"][p]}, {tool.NETWORK})
        old_ledger = tool.ledger_declarations(self.baseline[tool.LEDGER])
        new_ledger = tool.ledger_declarations(output[tool.LEDGER])
        self.assertEqual({p for p in old_ledger["SOURCE_PINS"]
                          if old_ledger["SOURCE_PINS"][p] != new_ledger["SOURCE_PINS"][p]}, {tool.QUANTUM})
        self.assertEqual(new_lock["source_revision"], self.checkpoint)
        self.assertEqual(json.loads(output[tool.BUDGET])["experiment"]["source_revision"], self.checkpoint)
        self.assertEqual(new_ledger["SOURCE_BASE"], self.checkpoint)

    def test_report_arithmetic_and_qualification_are_exactly_preserved(self):
        old = json.loads(self.baseline[tool.REPORT])
        new = json.loads(self.plan()[tool.REPORT])
        for key in ("schema", "status", "lifetime_ledger", "counterexamples", "independent_acceptance"):
            self.assertEqual(new[key], old[key], key)
        self.assertIsNone(new["lifetime_ledger"]["conditional_union"]["project_total_error_upper"])
        self.assertIs(new["independent_acceptance"]["all_three_qualified"], False)
        self.assertIs(new["independent_acceptance"]["production_activation"], False)
        self.assertEqual(new["selected_source_survey"]["observations"]["sqrt_cost_is_assumption"]["anchor_line"], "222")
        # The report represents all exact integers as decimal strings.
        row = next(r for r in new["selected_source_survey"]["sources"] if r["path"] == tool.QUANTUM)
        self.assertEqual(row["bytes"], "17730")

    def test_every_other_selected_file_mutation_is_rejected(self):
        for path in sorted(set(self.selected) - {tool.NETWORK, tool.QUANTUM}):
            changed = dict(self.selected)
            changed[path] += b"\n"
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unreviewed source difference"):
                self.plan(selected=changed)

    def test_any_existing_binding_or_report_edit_is_rejected(self):
        for path in self.baseline:
            changed = dict(self.baseline)
            changed[path] += b"\n"
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "immutable baseline differs"):
                self.plan(baseline=changed)

    def test_reviewed_digests_are_not_inferred_from_unknown_working_bytes(self):
        with self.assertRaisesRegex(ValueError, "unreviewed source difference"):
            self.plan(network_digest="0" * 64)
        for path in (tool.NETWORK, tool.QUANTUM):
            changed = dict(self.selected)
            changed[path] += b"\n"
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unreviewed source difference"):
                self.plan(selected=changed)

    def test_selected_roster_cannot_add_or_omit_paths(self):
        for operation in ("add", "omit"):
            changed = dict(self.selected)
            if operation == "add":
                changed["scripts/unreviewed.py"] = b"unreviewed"
            else:
                del changed[tool.NETWORK]
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, "31-path union"):
                self.plan(selected=changed)


class ActualGitBlobModeTests(unittest.TestCase):
    def test_regular_git_blob_matches_and_symlink_blob_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "--quiet", "--template=", "--initial-branch=fixture"], cwd=root, check=True)
            (root / "source.py").write_bytes(b"reviewed bytes\n")
            (root / "alias.py").symlink_to("source.py")
            subprocess.run(["git", "add", "source.py", "alias.py"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                            "commit", "--quiet", "-m", "Synthetic Git object control"], cwd=root, check=True)
            head = tool.git(root, "rev-parse", "HEAD").decode().strip()
            self.assertEqual(tool.git_file(root, head, "source.py"), b"reviewed bytes\n")
            with self.assertRaisesRegex(ValueError, "not an exact regular blob"):
                tool.git_file(root, head, "alias.py")
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                tool.git_file(root, head, "absent.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
