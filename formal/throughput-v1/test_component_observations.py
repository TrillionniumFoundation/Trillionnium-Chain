#!/usr/bin/env python3
"""Keep native component selection on the V3 observation owner."""
from pathlib import Path
import tempfile
import unittest

import run_component_observations as runner


TCP_NAME = (
    "ingress::public_v3::tests::"
    "write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work"
)
V2_TCP_NAME = TCP_NAME.replace("::public_v3::", "::public_v2::")


class NativeSelectorTests(unittest.TestCase):
    def select(self, names, suffixes=None):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "node-test-list.stdout").write_text(
                "".join(f"{name}: test\n" for name in names)
                + f"\n{len(names)} tests, 0 benchmarks\n",
                encoding="utf-8",
            )
            return runner.selectors(
                output, "node-test-list", suffixes or (runner.TCP_SUFFIX,)
            )

    def test_v2_and_v3_share_function_name_but_only_v3_is_selected(self):
        # The original CI binary contains both names. V2 has no V3 snapshot.
        selected = self.select([V2_TCP_NAME, TCP_NAME])
        self.assertEqual(list(selected.values()), [TCP_NAME])

    def test_v2_cannot_substitute_for_missing_v3_owner(self):
        with self.assertRaisesRegex(ValueError, "requires exactly one"):
            self.select([V2_TCP_NAME])

    def test_duplicate_v3_inventory_is_still_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate native test inventory"):
            self.select([V2_TCP_NAME, TCP_NAME, TCP_NAME])

    def test_multiple_names_matching_pinned_v3_owner_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires exactly one"):
            self.select([TCP_NAME, "unexpected::" + TCP_NAME])

    def test_cancellation_unit_controls_retain_original_module_names(self):
        prefix = "ingress::public_v3::request_observation::tests::"
        names = [prefix + suffix for suffix in runner.UNIT_SUFFIXES]
        selected = self.select(names + [V2_TCP_NAME, TCP_NAME],
                               (*runner.UNIT_SUFFIXES, runner.TCP_SUFFIX))
        self.assertEqual(set(selected.values()), set(names + [TCP_NAME]))


if __name__ == "__main__":
    unittest.main()
