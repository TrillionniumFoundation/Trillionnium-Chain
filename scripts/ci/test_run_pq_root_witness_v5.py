#!/usr/bin/env python3
"""Runner and source-roster controls; these do not execute native witnesses."""
import re
import unittest
from unittest.mock import patch

import run_pq_root_witness_v5 as runner


INVENTORIES = (
    ("WITNESS", "fresh-witness", "root_witness_v5_native", 17),
    ("DURABLE", "durable-witness", "root_witness_v5_durable_native", 12),
)


class WitnessRunnerControls(unittest.TestCase):
    def test_complete_native_targets_keep_features_locked_graph_and_no_filters(self):
        entries = runner.suites()
        self.assertEqual(len(entries), len(INVENTORIES))
        for entry, (attribute, expected_name, target, count) in zip(entries, INVENTORIES):
            with self.subTest(target=target):
                name, argv, required = entry
                self.assertEqual(name, expected_name)
                self.assertEqual(argv, [
                    "cargo", "test", "--locked", "--manifest-path", "trillionnium/Cargo.toml",
                    "-p", "trnm-pon-node", "--features", "pq-root-v3",
                    "--test", target, "--", "--nocapture", "--test-threads=1",
                ])
                self.assertEqual(required, getattr(runner, attribute))
                self.assertEqual(len(required), count)

    def test_frozen_rosters_cover_every_native_source_test_without_ignores(self):
        for attribute, _, target, _ in INVENTORIES:
            with self.subTest(target=target):
                source = (runner.ROOT / ("trillionnium/crates/trnm-pon-node/tests/" + target + ".rs")).read_text()
                actual = re.findall(r"#\[test\]\s*fn\s+(\w+)\s*\(", source)
                self.assertEqual(len(actual), len(set(actual)))
                self.assertEqual(set(actual), set(getattr(runner, attribute)))
                self.assertNotRegex(source, r"#\[ignore(?:\]|\s*=)")

    def test_empty_truncated_duplicate_or_extra_inventories_refuse(self):
        for attribute, _, _, count in INVENTORIES:
            names = getattr(runner, attribute)
            for value in ((), names[:-1], (names[0],) * count, names + ("extra",)):
                with self.subTest(attribute=attribute, value=value), patch.object(runner, attribute, value):
                    with self.assertRaises(ValueError):
                        runner.suites()

    def test_each_actual_name_success_summary_and_process_exit_is_required(self):
        for attribute, _, _, count in INVENTORIES:
            names = getattr(runner, attribute)
            raw = (f"running {len(names)} tests\n" +
                   "".join(f"test {name} ... ok\n" for name in names) +
                   f"test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n")
            self.assertEqual(runner.checked_result(raw, names, 0)["passed"], count)
            for name in names:
                for changed in (raw.replace(name, "wrong_name"),
                                raw.replace(f"test {name} ... ok\n", ""),
                                raw.replace(f"test {name} ... ok", f"test {name} ... ignored"),
                                raw.replace(f"test {name} ... ok", f"test {name} ... FAILED")):
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        runner.checked_result(changed, names, 0)
            for changed, code in ((raw, 101), (raw, -9), (raw, 124),
                                  (raw + raw, 0), (raw.replace(f"{count} passed", f"{count-1} passed"), 0),
                                  (raw.replace("0 ignored", "1 ignored"), 0),
                                  (raw.replace("0 measured", "1 measured"), 0),
                                  (raw.replace("0 filtered out", "1 filtered out"), 0),
                                  ("running 0 tests\n", 0)):
                with self.subTest(attribute=attribute, code=code), self.assertRaises(ValueError):
                    runner.checked_result(changed, names, code)


if __name__ == "__main__":
    unittest.main()
