"""Real Git/filesystem boundaries for explicit historical-contract replay."""
from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

import frozen_work_profile_replay_v1 as replay
import work_profile_contract_v1 as contract


class FrozenWorkReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="trnm-frozen-work-reference-")
        cls.reference = Path(cls.temporary.name) / "baseline"
        cls.value = contract.loads((contract.ROOT / contract.CONTRACT_PATH).read_bytes())
        cls.research_head = contract.git(contract.ROOT, "rev-parse", "HEAD").strip().decode()
        subprocess.run(
            ["git", "clone", "--shared", "--no-checkout", str(contract.ROOT), str(cls.reference)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.git("sparse-checkout", "init", "--no-cone")
        subprocess.run(
            ["git", "sparse-checkout", "set", "--no-cone", "--stdin"],
            input="/trillionnium/\n/formal/\n/config/\n/rust-toolchain.toml\n",
            text=True, cwd=cls.reference, check=True, stdout=subprocess.DEVNULL,
        )
        cls.git("checkout", "--detach", contract.BASELINE)
        cls.chosen = cls.value["source_entries"][0]["path"]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def git(cls, *args):
        return subprocess.check_output(
            ["git", "--no-replace-objects", *args], cwd=cls.reference,
            stderr=subprocess.DEVNULL,
        )

    def checked(self):
        return replay.check_reference(self.value, self.reference)

    def test_independent_fixed_reference_keeps_original_scope(self):
        result = self.checked()
        checked = result["baseline_contract_check"]
        self.assertEqual(result["source_commit"], contract.BASELINE)
        self.assertEqual(result["source_tree"], contract.BASELINE_TREE)
        self.assertEqual(checked["verified_source_entries"], 1747)
        self.assertEqual(checked["verified_source_bytes"], 27_613_671)
        self.assertEqual(checked["status"], "HOLD_NO_GO")
        self.assertFalse(result["current_native_cost_qualified"])
        self.assertFalse(result["native_binary_executed"])
        self.assertFalse(result["production_activation"])

    def test_current_reference_and_ancestor_alias_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "FROZEN_REFERENCE_SEPARATION"):
            replay.check_reference(self.value, contract.ROOT)
        with self.assertRaisesRegex(ValueError, "FROZEN_REFERENCE_SEPARATION"):
            replay.check_reference(self.value, self.reference,
                                   research_root=self.reference / "formal")

    def test_descendant_without_its_own_git_root_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "FROZEN_REFERENCE_ROOT"):
            replay.check_reference(self.value, self.reference / "formal")

    def test_changed_head_refuses_even_when_original_bytes_still_match(self):
        self.git("update-ref", "HEAD", self.research_head)
        try:
            self.assertTrue(contract.check_contract(self.value, root=self.reference)
                            ["contract_and_source_consistent"])
            with self.assertRaisesRegex(ValueError, "FROZEN_REFERENCE_HEAD"):
                self.checked()
        finally:
            self.git("update-ref", "HEAD", contract.BASELINE)

    def test_changed_bytes_keep_original_and_new_refusals(self):
        path = self.reference / self.chosen
        original = path.read_bytes()
        path.write_bytes(original + b"\nreal source drift\n")
        try:
            with self.assertRaisesRegex(ValueError, "SOURCE_BYTES"):
                contract.check_contract(self.value, root=self.reference)
            with self.assertRaisesRegex(ValueError, "SOURCE_BYTES"):
                self.checked()
        finally:
            path.write_bytes(original)

    def test_mode_drift_cannot_borrow_matching_content(self):
        path = self.reference / self.chosen
        original = path.stat().st_mode & 0o777
        path.chmod(original ^ 0o111)
        try:
            with self.assertRaisesRegex(ValueError, "SOURCE_MODE"):
                self.checked()
        finally:
            path.chmod(original)

    def test_symlink_cannot_borrow_matching_target_bytes(self):
        path = self.reference / self.chosen
        retained = Path(self.temporary.name) / "retained-original"
        path.rename(retained)
        path.symlink_to(retained)
        try:
            with self.assertRaisesRegex(ValueError, "SOURCE_IO|SOURCE_KIND"):
                self.checked()
        finally:
            path.unlink()
            retained.rename(path)

    def test_replacement_ref_is_not_a_new_baseline(self):
        name = "refs/replace/" + contract.BASELINE
        self.git("update-ref", name, self.research_head)
        try:
            with self.assertRaisesRegex(ValueError, "SOURCE_REPLACEMENT_REFS"):
                self.checked()
        finally:
            self.git("update-ref", "-d", name)

    def test_grafts_are_not_a_new_baseline(self):
        relative = self.git("rev-parse", "--git-path", "info/grafts").strip().decode()
        path = self.reference / relative
        path.write_bytes(b"")
        try:
            with self.assertRaisesRegex(ValueError, "SOURCE_GRAFTS"):
                self.checked()
        finally:
            path.unlink()

    def test_non_repository_directory_is_not_a_source_receipt(self):
        with tempfile.TemporaryDirectory(prefix="trnm-not-baseline-") as name:
            with self.assertRaises(subprocess.CalledProcessError):
                replay.check_reference(self.value, Path(name))

    def test_loaded_relation_modules_must_belong_to_research_source(self):
        with self.assertRaisesRegex(ValueError, "FROZEN_REPLAY_MODULE_ORIGIN"):
            replay.check_reused_inputs(self.value, research_root=self.reference)

    def test_reused_input_pin_is_not_caller_authority(self):
        observed = replay.check_reused_inputs(self.value)
        self.assertIn("formal/pon-nakamoto-v1/work_oracle.py",
                      [row["path"] for row in observed])
        changed = copy.deepcopy(self.value)
        for row in changed["source_entries"]:
            if row["path"] == "formal/pon-nakamoto-v1/work_oracle.py":
                row["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "FROZEN_REPLAY_INPUT_DRIFT:formal/pon-nakamoto-v1/work_oracle"):
            replay.check_reused_inputs(changed)

    def test_current_research_identity_checks_actual_raw_bytes(self):
        with tempfile.TemporaryDirectory(prefix="trnm-current-research-") as name:
            root = Path(name)
            subprocess.run(["git", "init", "-q", "-b", "candidate"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Research source fixture"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            path = root / "study.py"
            path.write_bytes(b"VALUE = 1\n")
            subprocess.run(["git", "add", "study.py"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "source fixture"], cwd=root, check=True)
            head = contract.git(root, "rev-parse", "HEAD").strip().decode()
            result = replay.verify_research_source(root, head)
            self.assertTrue(result["tracked_worktree_verified"])
            self.assertFalse(result["tests_executed_by_identity_check"])
            path.write_bytes(b"VALUE = 2\n")
            with self.assertRaises(ValueError):
                replay.verify_research_source(root, head)


if __name__ == "__main__":
    unittest.main(verbosity=2)
