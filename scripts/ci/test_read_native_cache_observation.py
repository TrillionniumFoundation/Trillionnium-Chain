"""Negative receipt controls; synthetic records are never native evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from read_native_cache_observation import PREFIX, SELECTOR, Rejected, main, strict_json, validate


class NativeCacheReceiptTests(unittest.TestCase):
    def setUp(self):
        self.source = {"schema": "trnm-ci-source-v1", "kind": "head", "candidate": "a" * 40,
                       "tested_commit": "a" * 40, "tested_tree": "b" * 40, "base": None,
                       "prospective_merge": None, "tracked_worktree_verified": True,
                       "tests_executed_by_identity_check": False}
        self.rows = []
        for rows in (1, 257, 4096):
            for round_ in range(4):
                self.rows.append({"delta_root": "c" * 64, "elapsed_ns": 100 + round_,
                                  "full_checks_preserved": True, "independent_operator": False,
                                  "progress_calls": 50 * (3 + rows // 256), "repetitions": 50,
                                  "round": round_, "rows": rows,
                                  "statement_cache_capacity": (0, 16, 16, 0)[round_],
                                  "whole_node_throughput_measured": False, "width": 12})

    def log(self):
        return "\n".join([f"test {SELECTOR} ... ok"] +
                         [PREFIX + json.dumps(row) for row in self.rows] +
                         ["test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 403 filtered out; finished in 1.48s"])

    def check(self, log=None, **kwargs):
        return validate(self.log() if log is None else log, self.source,
                        kwargs.pop("after", copy.deepcopy(self.source)),
                        head=kwargs.pop("head", "a" * 40), kind=kwargs.pop("kind", "head"), **kwargs)

    def rejected(self):
        with self.assertRaises(Rejected):
            self.check()

    def test_complete_head(self):
        result = self.check()
        self.assertEqual(result["complete_calls"], 600)
        self.assertEqual(len(result["observations"]), 12)
        self.assertFalse(result["speed_qualification"])

    def test_complete_merge_and_wrong_merge(self):
        self.source.update(kind="prospective-merge", base="d" * 40, prospective_merge="e" * 40, tested_commit="e" * 40)
        self.check(kind="prospective-merge", base="d" * 40, merge="e" * 40)
        with self.assertRaises(Rejected):
            self.check(kind="prospective-merge", base="d" * 40, merge="f" * 40)

    def test_missing_measurement(self):
        self.rows.pop()
        self.rejected()

    def test_duplicate_measurement(self):
        self.rows[-1] = self.rows[-2]
        self.rejected()

    def test_reordered_measurements(self):
        self.rows[0], self.rows[1] = self.rows[1], self.rows[0]
        self.rejected()

    def test_invalid_integer_fields(self):
        for key in ("elapsed_ns", "progress_calls", "repetitions", "round", "rows", "statement_cache_capacity", "width"):
            for value in (True, "1", 1.0):
                with self.subTest(key=key, value=value):
                    original = self.rows[0][key]
                    self.rows[0][key] = value
                    self.rejected()
                    self.rows[0][key] = original

    def test_invalid_elapsed(self):
        for value in (0, -1, 2**128):
            self.rows[0]["elapsed_ns"] = value
            self.rejected()

    def test_progress_and_dimensions(self):
        for key in ("progress_calls", "repetitions", "width", "statement_cache_capacity"):
            original = self.rows[0][key]
            self.rows[0][key] += 1
            self.rejected()
            self.rows[0][key] = original

    def test_scope_promotions(self):
        for key in ("full_checks_preserved", "independent_operator", "whole_node_throughput_measured"):
            original = self.rows[0][key]
            self.rows[0][key] = not original
            self.rejected()
            self.rows[0][key] = original

    def test_different_or_invalid_roots(self):
        for value in ("d" * 64, "bad", 7):
            self.rows[1]["delta_root"] = value
            self.rejected()

    def test_unknown_and_missing_fields(self):
        self.rows[0]["external_acceptance"] = True
        self.rejected()
        del self.rows[0]["external_acceptance"]
        del self.rows[0]["width"]
        self.rejected()

    def test_failed_and_ambiguous_test_receipts(self):
        good = self.log()
        for log in (good.replace("1 passed; 0 failed", "0 passed; 1 failed"),
                    good + "\ntest result: FAILED. 0 passed; 1 failed;",
                    good + "\nerror: test failed", good + "\nfailures:",
                    good.replace(" ... ok", " ... ignored"), good.replace(SELECTOR, "wrong")):
            with self.subTest(log=log[-80:]), self.assertRaises(Rejected):
                self.check(log)

    def test_wrong_source_and_changed_checkout(self):
        with self.assertRaises(Rejected):
            self.check(head="f" * 40)
        with self.assertRaises(Rejected):
            self.check(after={**self.source, "tested_tree": "e" * 40})
        self.source["tracked_worktree_verified"] = 1
        self.rejected()

    def test_head_cannot_borrow_merge(self):
        with self.assertRaises(Rejected):
            self.check(base="d" * 40, merge="e" * 40)

    def test_invalid_json_duplicate_and_nonfinite(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', '{'):
            with self.subTest(raw=raw), self.assertRaises(Rejected):
                strict_json(raw)

    def test_unknown_version(self):
        with self.assertRaises(Rejected):
            self.check(self.log().replace(PREFIX, PREFIX.replace("v1", "v2"), 1))

    def test_cli_create_new_and_missing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "log").write_text(self.log())
            (root / "source").write_text(json.dumps(self.source))
            args = [str(root / "log"), "--source", str(root / "source"),
                    "--source-after", str(root / "source"), "--expected-head", "a" * 40,
                    "--kind", "head", "--output", str(root / "out")]
            self.assertEqual(main(args), 0)
            original = (root / "out").read_bytes()
            with self.assertRaises(SystemExit):
                main(args)
            self.assertEqual((root / "out").read_bytes(), original)
            (root / "log").unlink()
            with self.assertRaises(SystemExit):
                main(args)

    def test_cli_oversized_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "log").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            with self.assertRaises(SystemExit):
                main([str(root / "log"), "--source", str(root / "absent"),
                      "--source-after", str(root / "absent"), "--expected-head", "a" * 40,
                      "--kind", "head", "--output", str(root / "out")])
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
