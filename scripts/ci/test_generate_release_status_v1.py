#!/usr/bin/env python3
"""M17 release projection regressions; these tests grant no release authority."""

from __future__ import annotations

import copy
import unittest
from unittest import mock

import generate_release_status_v1 as generator


class ReleaseStatusTests(unittest.TestCase):
    def test_current_native_truth_generates_without_retired_role(self) -> None:
        truth = generator.load_json("config/consensus-mainline.json")
        self.assertNotIn("poco_consensus", truth)
        status = generator.build_status()
        self.assertEqual(status["consensus"], {
            "mainline": truth["consensus_mainline"],
            "protocol_target": truth["protocol_target"],
            "stage": truth["stage"],
            "production_candidate": truth["production_candidate"],
            "production_consensus_activation": truth["production_consensus_activation"],
        })
        self.assertEqual(status["source"]["commit"], generator.run_git("rev-parse", "HEAD"))
        self.assertEqual(status["source"]["tree"], generator.run_git("rev-parse", "HEAD^{tree}"))

    def test_repeat_projection_preserves_open_gates_and_blockers(self) -> None:
        first = generator.build_status()
        self.assertEqual(generator.encode(first), generator.encode(generator.build_status()))
        policy = generator.load_json("config/repository-policy-v1.json")
        self.assertEqual(first["release_truth"], policy["release_truth"])
        self.assertTrue(all(value is False for value in first["release_truth"].values()))
        self.assertEqual(
            first["external_blockers"],
            [{"id": identity, "status": "open-no-accepted-evidence"}
             for identity in policy["external_blockers"]],
        )

    def test_missing_activation_field_has_no_silent_default(self) -> None:
        original_loader = generator.load_json
        truth = copy.deepcopy(original_loader("config/consensus-mainline.json"))
        del truth["production_consensus_activation"]

        def load(path: str):
            return truth if path == "config/consensus-mainline.json" else original_loader(path)

        with mock.patch.object(generator, "load_json", side_effect=load):
            with self.assertRaises(KeyError):
                generator.build_status()


if __name__ == "__main__":
    unittest.main()
