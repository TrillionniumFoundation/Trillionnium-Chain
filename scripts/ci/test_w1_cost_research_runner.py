#!/usr/bin/env python3
"""Negative evidence controls for the new local research collector."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[1] / "run_w1_cost_research.py"
SPEC = importlib.util.spec_from_file_location("w1_cost_research_runner", SOURCE)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class EvidenceControls(unittest.TestCase):
    def test_native_compiler_and_loader_overrides_are_refused(self):
        runner.validate_build_environment({"PATH": "/usr/bin"})
        for key in ("CC", "CFLAGS", "CC_x86_64_unknown_linux_gnu", "HOST_AR",
                    "TARGET_CXXFLAGS", "LD_PRELOAD", "LD_LIBRARY_PATH", "SQLITE3_LIB_DIR",
                    "CRATE_CC_NO_DEFAULTS", "ARFLAGS", "TARGET_ARFLAGS", "LIBSQLITE3_FLAGS",
                    "SQLITE_MAX_COLUMN", "CROSS_COMPILE", "CXXSTDLIB",
                    "PKG_CONFIG_PATH", "CARGO_PROFILE_RELEASE_LTO", "CARGO_BUILD_RUSTFLAGS",
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_build_environment({key: "unregistered"})

    def test_existing_target_cannot_lend_an_unchecked_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "fresh"
            runner.create_fresh_target(target)
            self.assertTrue(target.is_dir())
            with self.assertRaisesRegex(ValueError, "FRESH_TARGET_REQUIRED"):
                runner.create_fresh_target(target)

    def test_source_validation_calls_existing_raw_byte_guard(self):
        head, tree = "a" * 40, "b" * 40
        with patch.object(runner, "verify_raw_source", side_effect=ValueError("hidden changed bytes")) as guard:
            with self.assertRaisesRegex(ValueError, "hidden changed bytes"):
                runner.validate_source({"head": head, "tree": tree, "status": ""},
                                       head, tree, verify_raw=True)
            guard.assert_called_once_with("head", head, root=runner.ROOT)

    def test_nonzero_child_preserves_both_streams_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = runner.run_step(
                root, "nonzero", [sys.executable, "-c",
                    "import sys; print('retained observation'); "
                    "print('original failure',file=sys.stderr); sys.exit(7)"],
                dict(os.environ), 10, 1024,
            )
            self.assertEqual(result["returncode"], 7)
            self.assertFalse(result["complete_success"])
            self.assertEqual((root / result["stdout"]).read_text(), "retained observation\n")
            self.assertEqual((root / result["stderr"]).read_text(), "original failure\n")
            self.assertEqual(json.loads((root / "nonzero.step.json").read_text()), result)

    def test_existing_observation_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "repeat.stdout"
            original.write_bytes(b"original failure\n")
            with self.assertRaises(FileExistsError):
                runner.run_step(root, "repeat", [sys.executable, "-c", "print('replacement')"],
                                dict(os.environ), 10, 1024)
            self.assertEqual(original.read_bytes(), b"original failure\n")

    def test_zero_exit_truncated_output_is_not_complete_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = runner.run_step(root, "overlong", [sys.executable, "-c",
                "print('x'*100000)"], dict(os.environ), 10, 64)
            self.assertFalse(result["complete_success"])
            self.assertTrue(result["stdout_truncated"])
            self.assertIsNotNone(result["error"])
            self.assertLessEqual(result["stdout_bytes"], 64)

    def test_changed_source_does_not_inherit_old_commit_credit(self):
        head, tree = "a" * 40, "b" * 40
        for mutation in ({"head": "c" * 40}, {"tree": "c" * 40},
                         {"status": "?? uncommitted.rs"}):
            observed = {"head": head, "tree": tree, "status": "", **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                runner.validate_source(observed, head, tree)

    def test_plan_cannot_promote_authority_or_overwrite_job(self):
        plan = {"schema": "pon-w1-cost-research-plan-v1", "production_activation": False,
                "hardness_accepted": False, "jobs": [
                    {"name": "fixed", "args": ["--attempts", "1"], "timeout_seconds": 10}]}
        runner.validate_plan(plan)
        runner.validate_plan({**plan, "collection_output_limit_bytes": 256 * 1024 * 1024})
        for limit in (0, 1, True, 1024 * 1024 * 1024):
            with self.subTest(output_limit=limit), self.assertRaisesRegex(ValueError, "PLAN_OUTPUT_LIMIT"):
                runner.validate_plan({**plan, "collection_output_limit_bytes": limit})
        for field in ("production_activation", "hardness_accepted"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.validate_plan({**plan, field: True})
        with self.assertRaises(ValueError):
            runner.validate_plan({**plan, "jobs": plan["jobs"] * 2})
        for name in ("../escape", "/absolute", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner.validate_plan({**plan, "jobs": [{**plan["jobs"][0], "name": name}]})


if __name__ == "__main__":
    unittest.main()
