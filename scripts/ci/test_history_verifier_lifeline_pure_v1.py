#!/usr/bin/env python3
"""Pure-profile build readback controls; synthetic metadata, no native verdict."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

import read_history_verifier_lifeline_v1 as reader
import read_pure_history_raw_campaign_v1 as pure_reader
import test_history_verifier_lifeline_v1 as fixtures


PROFILES = (
    ("strict-every-native-checkpoint-v1", "separate_process_pure_history_raw_strict_campaign"),
    ("history-account-graph-resource-fence-v1", "separate_process_pure_history_raw_graph_fence_campaign"),
)


def pure_fixture(root, profile, selector):
    fixtures.build_fixture(root)
    result = json.loads((root / "results.json").read_text())
    result.update(
        schema="pon-pure-history-raw-joint-ci-v1",
        work_profile="pure-history-raw-v1",
        admission_search_budget=0,
        history_resource_profile=profile,
        native_selector=selector,
        strict_profile_result_is_separate=True,
        state_backend="authenticated-v1",
        expected_public_policy_id=pure_reader.expected_policy()["policy_id"],
    )
    fixtures.put(root / "results.json", result)
    return result


class PureLifelineBuildControls(unittest.TestCase):
    def test_both_pure_profiles_allow_independent_lifeline_after_failed_campaign(self):
        for profile, selector in PROFILES:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "build"
                result = pure_fixture(root, profile, selector)
                self.assertIs(result["complete_success"], False)
                binary, record = reader.baseline_binary(root, fixtures.HEAD, fixtures.TREE)
                self.assertEqual(binary, root / "public_v3_multiprocess.bin")
                self.assertEqual(record["sha256_before"], reader.hash_file(binary))
                self.assertIs(json.loads((root / "results.json").read_text())["complete_success"], False)

    def test_resource_profile_and_selector_must_be_exact_pairs(self):
        for profile, selector in PROFILES:
            wrong_selector = next(s for p, s in PROFILES if p != profile)
            changes = (
                {"history_resource_profile": "unknown-profile"},
                {"history_resource_profile": True},
                {"native_selector": wrong_selector},
                {"native_selector": "separate_process_work_and_signed_confirmation_campaign"},
                {"strict_profile_result_is_separate": 1},
                {"strict_profile_result_is_separate": False},
            )
            for change in changes:
                with self.subTest(profile=profile, change=change), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary) / "build"
                    result = pure_fixture(root, profile, selector)
                    result.update(change)
                    fixtures.put(root / "results.json", result)
                    with self.assertRaises(ValueError):
                        reader.baseline_binary(root, fixtures.HEAD, fixtures.TREE)

    def test_search_budget_requires_exact_integer_zero(self):
        for value in (False, 0.0, "0", -1, 1, None):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "build"
                result = pure_fixture(root, *PROFILES[0])
                result["admission_search_budget"] = value
                fixtures.put(root / "results.json", result)
                with self.assertRaises(ValueError):
                    reader.baseline_binary(root, fixtures.HEAD, fixtures.TREE)

    def test_pure_policy_work_backend_and_fields_are_mandatory(self):
        changes = (
            {"expected_public_policy_id": "00" * 32},
            {"work_profile": "raw-r13"},
            {"state_backend": "legacy-v2"},
        )
        required = (
            "expected_public_policy_id", "work_profile", "admission_search_budget",
            "state_backend", "history_resource_profile", "native_selector",
            "strict_profile_result_is_separate",
        )
        for number in range(len(changes) + len(required)):
            with self.subTest(number=number), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "build"
                result = pure_fixture(root, *PROFILES[1])
                if number < len(changes):
                    result.update(changes[number])
                else:
                    del result[required[number - len(changes)]]
                fixtures.put(root / "results.json", result)
                with self.assertRaises(ValueError):
                    reader.baseline_binary(root, fixtures.HEAD, fixtures.TREE)

    def test_pure_binding_keeps_original_source_and_elf_checks(self):
        for kind in ("build-source", "campaign-source", "final-source", "elf", "final-elf"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "build"
                result = pure_fixture(root, *PROFILES[0])
                if kind in ("build-source", "campaign-source"):
                    name = "source-before-build.json" if kind == "build-source" else "source-before-campaigns.json"
                    source = fixtures.source()
                    source["tested_tree"] = "ff" * 20
                    fixtures.put(root / name, source)
                elif kind == "final-source":
                    result["source_after"] = copy.deepcopy(result["source_after"])
                    result["source_after"]["tracked_worktree_verified"] = False
                    fixtures.put(root / "results.json", result)
                elif kind == "elf":
                    with (root / "public_v3_multiprocess.bin").open("ab") as stream:
                        stream.write(b"changed")
                else:
                    result["binary"]["sha256_after"] = "ff" * 32
                    fixtures.put(root / "results.json", result)
                with self.assertRaises(ValueError):
                    reader.baseline_binary(root, fixtures.HEAD, fixtures.TREE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
