"""CI binding refusal controls; fixtures do not claim native execution."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from hia.tools import qualify_additional_owner_ci as binding


class AdditionalOwnerBinding(unittest.TestCase):
    def setUp(self):
        self.head, self.tree = "1" * 40, "2" * 40
        sources = {"hia/platform/pq_auth/qualify.py": "3" * 64}
        digest = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.report = {"schema": "trnm.hia.pq-public-qualification.v2", "status": "PASS",
                       "source_unchanged_during_tests": True, "source_commit_observed": self.head,
                       "source_tree_observed": self.tree, "source_dirty_observed": "",
                       "source_inputs": sources, "source_set_sha256": digest,
                       "limits": {name: False for name in binding.PQ_FALSE_SCOPES}}
        self.report["limits"]["live_pointer_const_and_exclusive_budget_contract_required"] = True
        self.reader = {"status": "PASS", "source_commit_observed": self.head,
                       "source_tree_observed": self.tree, "source_dirty_observed": "",
                       "source_files": len(sources), "source_set_sha256": digest,
                       "limits": copy.deepcopy(self.report["limits"]), **binding.PQ_COUNTS}

    def test_peer_requires_new_inode_control_and_every_named_group(self):
        report = {"schema": "trnm.hia.peer-unix-qualification.v1", "status": "PASS",
                  "source_inputs_stable": True, "retained_original_tests": {"outer_tests": 121},
                  "integrity_controls": {"count": 14},
                  "groups": dict.fromkeys(("codec", "client", "client-owner", "cli", "daemon",
                                            "storage-faults", "syscall-faults"), {})}
        binding.peer_summary(report, {"status": "PASS"})
        changed = copy.deepcopy(report)
        changed["integrity_controls"]["count"] = 13
        with self.assertRaises(ValueError):
            binding.peer_summary(changed, {"status": "PASS"})
        for name in report["groups"]:
            changed = copy.deepcopy(report)
            del changed["groups"][name]
            changed["groups"]["substituted"] = {}
            with self.subTest(group=name), self.assertRaises(ValueError):
                binding.peer_summary(changed, {"status": "PASS"})
        with self.assertRaises(ValueError):
            binding.peer_summary(report, {"status": "FAIL"})

    def test_complete_pq_summary_keeps_source_count_dynamic(self):
        binding.pq_summary(self.report, self.reader, self.head, self.tree)
        self.report["source_inputs"]["hia/platform/pq_auth/readback.py"] = "4" * 64
        digest = hashlib.sha256(json.dumps(self.report["source_inputs"], sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
        self.report["source_set_sha256"] = self.reader["source_set_sha256"] = digest
        self.reader["source_files"] = 2
        binding.pq_summary(self.report, self.reader, self.head, self.tree)

    def test_pq_refuses_every_missing_count_or_changed_deadline(self):
        for name, count in binding.PQ_COUNTS.items():
            for replacement in (None, count - 1, count + 1, str(count), True):
                changed = copy.deepcopy(self.reader)
                changed[name] = replacement
                with self.subTest(field=name, replacement=replacement), self.assertRaises(ValueError):
                    binding.pq_summary(self.report, changed, self.head, self.tree)

    def test_pq_refuses_stale_dirty_or_partial_execution_and_reader(self):
        for target in ("report", "reader"):
            for name, replacement in (("source_commit_observed", "0" * 40),
                                      ("source_tree_observed", "0" * 40),
                                      ("source_dirty_observed", " M hia/components.json\n"),
                                      ("status", "EXECUTED"), ("status", "FAIL")):
                report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
                (report if target == "report" else reader)[name] = replacement
                with self.subTest(target=target, field=name), self.assertRaises(ValueError):
                    binding.pq_summary(report, reader, self.head, self.tree)
        report = copy.deepcopy(self.report)
        report["source_unchanged_during_tests"] = False
        with self.assertRaises(ValueError):
            binding.pq_summary(report, self.reader, self.head, self.tree)

    def test_pq_refuses_scope_promotion_in_both_reports(self):
        for target in ("report", "reader"):
            for name in self.report["limits"]:
                report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
                limits = (report if target == "report" else reader)["limits"]
                limits[name] = not limits[name]
                with self.subTest(target=target, field=name), self.assertRaises(ValueError):
                    binding.pq_summary(report, reader, self.head, self.tree)

    def test_pq_refuses_source_substitution_and_escaping_paths(self):
        for target in ("report", "reader"):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            (report if target == "report" else reader)["source_set_sha256"] = "0" * 64
            with self.subTest(target=target), self.assertRaises(ValueError):
                binding.pq_summary(report, reader, self.head, self.tree)
        for name in ("../private", "/private", "hia//program", "hia/../private", "hia\\program", ""):
            report = copy.deepcopy(self.report)
            report["source_inputs"] = {name: "3" * 64}
            with self.subTest(path=name), self.assertRaises(ValueError):
                binding.pq_summary(report, self.reader, self.head, self.tree)

    def test_real_zero_exit_reader_cannot_replace_the_executed_report(self):
        with tempfile.TemporaryDirectory(prefix="hia-ci-binding-control-") as temporary:
            base = Path(temporary)
            repository = base / "repository"
            module = repository / "hia/platform/peer_lease_unix/qualify.py"
            module.parent.mkdir(parents=True)
            # This is a deliberately false producer/reader pair for the wrapper
            # refusal test. It is never a replacement native qualification.
            module.write_text('''import argparse,json,pathlib
p=argparse.ArgumentParser();p.add_argument('phase');p.add_argument('--output');p.add_argument('--input')
a=p.parse_args();root=pathlib.Path(a.output or a.input)
if a.phase=='run':
 root.mkdir();(root/'report.json').write_text('{"status":"PASS","fixture":1}\\n')
else:
 (root/'report.json').write_text('{"status":"PASS","fixture":2}\\n')
print(json.dumps({'status':'PASS'}))
''')
            output = base / "observations"
            (output / "observations").mkdir(parents=True)
            with patch.object(binding, "ROOT", repository), self.assertRaises(ValueError):
                binding.run("peer-unix", output, None)
            value = binding.read(output / "observations/process.json")
            self.assertEqual(value["status"], "FAIL")
            self.assertEqual(value["stages"][-1]["exit_code"], 0)
            self.assertIn("changed during independent readback", value["stages"][-1]["failure"])
            self.assertNotEqual(value["stages"][-1]["qualification_report_before"],
                                value["stages"][-1]["qualification_report_after"])


if __name__ == "__main__":
    unittest.main()
