#!/usr/bin/env python3
"""Boundary controls for the local runner's available-memory estimate."""
import ast
from pathlib import Path
import unittest

runner = Path(__file__).with_name("run-bounded.py")
tree = ast.parse(runner.read_text(), filename=str(runner))
selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
            node.name in {"available_memory_estimate", "oom_increased"}]
if len(selected) != 2:
    raise RuntimeError("expected exactly the two runner memory controls")
scope = {}
exec(compile(ast.Module(body=selected, type_ignores=[]), str(runner), "exec"), scope)
estimate = scope["available_memory_estimate"]
oom_increased = scope["oom_increased"]


def stats(**overrides):
    result = {"file": 0, "shmem": 0, "file_dirty": 0,
              "file_writeback": 0, "inactive_file": 0}
    result.update(overrides)
    return result


class AvailableMemoryTests(unittest.TestCase):
    def test_no_cache_uses_hard_headroom(self):
        value = estimate(1000, 1000, 800, stats())
        self.assertEqual(value["hard_cgroup_headroom"], 200)
        self.assertEqual(value["reclaimable_inactive_file_estimate"], 0)
        self.assertEqual(value["effective_available"], 200)

    def test_dirty_and_writeback_pages_are_not_available(self):
        value = estimate(1000, 1000, 950, stats(
            file=700, inactive_file=600, file_dirty=400, file_writeback=100))
        self.assertEqual(value["reclaimable_inactive_file_estimate"], 200)
        self.assertEqual(value["effective_available"], 250)

    def test_shmem_is_not_reclaimable_file_budget(self):
        value = estimate(1000, 1000, 950, stats(
            file=900, inactive_file=800, shmem=800))
        self.assertEqual(value["effective_available"], 150)
        self.assertEqual(estimate(1000, 1000, 950, stats(
            file=100, inactive_file=800, shmem=200))["effective_available"], 50)

    def test_missing_required_fields_fail_closed(self):
        for name in stats():
            incomplete = stats()
            del incomplete[name]
            with self.subTest(field=name), self.assertRaises(KeyError):
                estimate(1000, 1000, 950, incomplete)

    def test_negative_or_malformed_fields_fail_closed(self):
        for name in stats():
            with self.subTest(field=name), self.assertRaises(ValueError):
                estimate(1000, 1000, 950, stats(**{name: -1}))
        for host, limit, current in [(-1, 1000, 10), (1000, -1, 10),
                                     (1000, 0, 10), (1000, 1000, -1)]:
            with self.subTest(values=(host, limit, current)), self.assertRaises(ValueError):
                estimate(host, limit, current, stats())
        with self.assertRaises(ValueError):
            estimate(1000, 1000, 10, stats(file=True))

    def test_host_available_caps_reclaim_estimate(self):
        value = estimate(75, 1000, 900, stats(file=800, inactive_file=700))
        self.assertEqual(value["effective_available"], 75)

    def test_oom_or_oom_kill_increment_is_detected(self):
        before = {"event_counters": {"oom": 4, "oom_kill": 2}}
        self.assertFalse(oom_increased(before, before))
        self.assertTrue(oom_increased(before, {"event_counters": {"oom": 5, "oom_kill": 2}}))
        self.assertTrue(oom_increased(before, {"event_counters": {"oom": 4, "oom_kill": 3}}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
