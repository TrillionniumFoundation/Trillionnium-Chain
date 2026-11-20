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

    def test_peer_requires_all_runtime_controls_and_every_named_group(self):
        report = {"schema": "trnm.hia.peer-unix-qualification.v1", "status": "PASS",
                  "source_inputs_stable": True, "retained_original_tests": {"outer_tests": 121},
                  "integrity_controls": {"count": 18},
                  "groups": dict.fromkeys(("codec", "client", "client-owner", "cli", "daemon",
                                            "storage-faults", "syscall-faults"), {})}
        binding.peer_summary(report, {"status": "PASS"})
        for obsolete_count in (13, 14, 17, 19):
            changed = copy.deepcopy(report)
            changed["integrity_controls"]["count"] = obsolete_count
            with self.subTest(count=obsolete_count), self.assertRaises(ValueError):
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


class CandidateOwnerBinding(unittest.TestCase):
    def setUp(self):
        self.head, self.tree = "5" * 40, "6" * 40
        sources = {"hia/platform/pq_candidate/qualify.py": "7" * 64}
        digest = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        limits = {name: False for name in binding.PQ_FALSE_SCOPES}
        limits["live_pointer_const_contract_required"] = True
        image = {"path": "/qualification/native/candidate-owned.so", "retained": "native/candidate-owned.so",
                 "bytes": 301872, "sha256": "8" * 64}
        self.report = {"schema": "trnm.hia.candidate-public-qualification.v1", "status": "PASS",
                       "source_unchanged_during_tests": True, "source_commit_observed": self.head,
                       "source_tree_observed": self.tree, "source_dirty_observed": "",
                       "provider_inputs_unchanged_after_original": True,
                       "provider_inputs_unchanged_after_all_execution": True,
                       "full_host_dependency_closure_claimed": False,
                       "source_inputs": sources, "source_set_sha256": digest, "limits": limits,
                       "case_count": 892, "native_cases": 892, "native_abi_calls": 14680,
                       "alias_original_pairs": 2, "native_original_pairs": 894,
                       "original_mode_signatures_accepted_under_their_own_modes": 12,
                       "original_method_roster": list(binding.CANDIDATE_METHODS), "production_image": image}
        self.reader = {"status": "PASS", "source_commit_observed": self.head,
                       "source_tree_observed": self.tree, "source_dirty_observed": "",
                       "source_files": len(sources), "source_set_sha256": digest,
                       "limits": copy.deepcopy(limits), "production_image": copy.deepcopy(image),
                       **binding.CANDIDATE_COUNTS}

    def check(self, report=None, reader=None):
        binding.candidate_summary(self.report if report is None else report,
                                  self.reader if reader is None else reader, self.head, self.tree)

    def test_complete_candidate_gate_keeps_source_count_dynamic(self):
        self.check()
        self.report["source_inputs"]["hia/platform/pq_candidate/readback.py"] = "9" * 64
        digest = hashlib.sha256(json.dumps(self.report["source_inputs"], sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest()
        self.report["source_set_sha256"] = self.reader["source_set_sha256"] = digest
        self.reader["source_files"] = 2
        self.check()

    def test_candidate_refuses_each_missing_count_type_and_changed_deadline(self):
        for name, count in binding.CANDIDATE_COUNTS.items():
            for replacement in (None, count - 1, count + 1, str(count), True):
                changed = copy.deepcopy(self.reader)
                changed[name] = replacement
                with self.subTest(field=name, replacement=replacement), self.assertRaises(ValueError):
                    self.check(reader=changed)
            changed = copy.deepcopy(self.reader)
            del changed[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.check(reader=changed)

    def test_candidate_refuses_incomplete_execution_methods_and_mode_controls(self):
        for name in ("case_count", "native_cases", "native_abi_calls", "alias_original_pairs",
                     "native_original_pairs", "original_mode_signatures_accepted_under_their_own_modes"):
            for replacement in (None, self.report[name] - 1, self.report[name] + 1, str(self.report[name]), True):
                changed = copy.deepcopy(self.report)
                changed[name] = replacement
                with self.subTest(field=name, replacement=replacement), self.assertRaises(ValueError):
                    self.check(report=changed)
        for roster in ([], list(reversed(binding.CANDIDATE_METHODS)), list(binding.CANDIDATE_METHODS)[:-1],
                       [*binding.CANDIDATE_METHODS[:-1], binding.CANDIDATE_METHODS[0]]):
            changed = copy.deepcopy(self.report)
            changed["original_method_roster"] = roster
            with self.subTest(roster=roster), self.assertRaises(ValueError):
                self.check(report=changed)

    def test_candidate_refuses_old_419_dirty_partial_and_unchecked_provider_results(self):
        for target in ("report", "reader"):
            for name, replacement in (("source_commit_observed", "41948f98b7b9fcb24a6ba7d638d5391a88e26de6"),
                                      ("source_tree_observed", "a1ac8e48f7afd7af67b29909292ac14d4e9d7161"),
                                      ("source_dirty_observed", " M hia/components.json\n"),
                                      ("status", "EXECUTED"), ("status", "FAIL")):
                report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
                (report if target == "report" else reader)[name] = replacement
                with self.subTest(target=target, field=name), self.assertRaises(ValueError):
                    self.check(report, reader)
        for name in ("source_unchanged_during_tests", "provider_inputs_unchanged_after_original",
                     "provider_inputs_unchanged_after_all_execution"):
            changed = copy.deepcopy(self.report)
            changed[name] = False
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.check(report=changed)
        changed = copy.deepcopy(self.report)
        changed["schema"] = "trnm.hia.pq-public-qualification.v2"
        with self.assertRaises(ValueError):
            self.check(report=changed)

    def test_candidate_refuses_scope_promotion_or_substituted_borrow_contract(self):
        for target in ("report", "reader"):
            for name in self.report["limits"]:
                report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
                limits = (report if target == "report" else reader)["limits"]
                limits[name] = not limits[name]
                with self.subTest(target=target, field=name), self.assertRaises(ValueError):
                    self.check(report, reader)
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            limits = (report if target == "report" else reader)["limits"]
            del limits["live_pointer_const_contract_required"]
            limits["live_pointer_const_and_exclusive_budget_contract_required"] = True
            with self.subTest(target=target, contract="foreign"), self.assertRaises(ValueError):
                self.check(report, reader)
        changed = copy.deepcopy(self.report)
        changed["full_host_dependency_closure_claimed"] = True
        with self.assertRaises(ValueError):
            self.check(report=changed)

    def test_candidate_refuses_source_substitution_missing_entries_and_escaping_paths(self):
        for target in ("report", "reader"):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            (report if target == "report" else reader)["source_set_sha256"] = "0" * 64
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.check(report, reader)
        for name in ("../private", "/private", "hia//program", "hia/../private", "hia\\program", "", ".", "hia/\0program"):
            changed = copy.deepcopy(self.report)
            changed["source_inputs"] = {name: "7" * 64}
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.check(report=changed)
        for replacement in ({}, [], None, {"hia/program": "INVALID"}):
            changed = copy.deepcopy(self.report)
            changed["source_inputs"] = replacement
            with self.subTest(sources=replacement), self.assertRaises(ValueError):
                self.check(report=changed)
        for count in (0, 2, True, "1", None):
            changed = copy.deepcopy(self.reader)
            changed["source_files"] = count
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.check(reader=changed)

    def test_candidate_refuses_different_or_malformed_production_image(self):
        for target in ("report", "reader"):
            for name, replacement in (("bytes", 1), ("sha256", "0" * 64), ("path", "/elsewhere.so"),
                                      ("retained", "native/other.so")):
                report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
                (report if target == "report" else reader)["production_image"][name] = replacement
                with self.subTest(target=target, field=name), self.assertRaises(ValueError):
                    self.check(report, reader)
        for name, replacement in (("bytes", True), ("bytes", 0), ("sha256", "A" * 64),
                                  ("path", "relative.so"), ("retained", "native/other.so")):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            report["production_image"][name] = reader["production_image"][name] = replacement
            with self.subTest(field=name, replacement=replacement), self.assertRaises(ValueError):
                self.check(report, reader)

    def fixture_run(self, mutate):
        with tempfile.TemporaryDirectory(prefix="hia-candidate-ci-command-control-") as temporary:
            base = Path(temporary)
            repository, output, rust = base / "repository", base / "output", base / "rust/bin"
            folder = repository / "hia/platform/pq_candidate"
            folder.mkdir(parents=True)
            (output / "observations").mkdir(parents=True)
            rust.mkdir(parents=True)
            # These real subprocesses only test wrapper command capture. Their
            # report deliberately lacks PASS, native cases and all qualifications.
            (folder / "qualify.py").write_text('''import argparse,json,pathlib
p=argparse.ArgumentParser()
for name in ('output','rust-bin','provider-receipt','provider-environment'):p.add_argument('--'+name,required=True)
a=p.parse_args();root=pathlib.Path(a.output);root.mkdir()
(root/'report.json').write_text('{"status":"WRAPPER_TEST_FIXTURE","version":1}\\n')
print(json.dumps({'qualification':False}))
''')
            (folder / "readback.py").write_text('''import argparse,json,pathlib
p=argparse.ArgumentParser();p.add_argument('--report',required=True);a=p.parse_args()
root=pathlib.Path(a.report)
''' + ('''(root/'report.json').write_text('{"status":"WRAPPER_TEST_FIXTURE","version":2}\\n')
''' if mutate else "") + "print(json.dumps({'qualification':False}))\n")
            with patch.object(binding, "ROOT", repository):
                if mutate:
                    with self.assertRaisesRegex(ValueError, "changed during independent readback"):
                        binding.run("pq-candidate", output, rust)
                else:
                    binding.run("pq-candidate", output, rust)
            value = binding.read(output / "observations/process.json")
            self.assertEqual([row["name"] for row in value["stages"]], ["qualification", "readback"])
            expected = [[sys.executable, "-I", "-S", "-B", str(folder / "qualify.py"),
                         "--output", str(output / "qualification"), "--rust-bin", str(rust),
                         "--provider-receipt", str(output / "provider-receipts/pq-provider/provider.json"),
                         "--provider-environment", str(output / "provider.env")],
                        [sys.executable, "-I", "-S", "-B", str(folder / "readback.py"),
                         "--report", str(output / "qualification")]]
            self.assertEqual([row["argv"] for row in value["stages"]], expected)
            self.assertTrue(all(row["cwd"] == str(repository) and row["started"] is True
                                and row["exit_code"] == 0 for row in value["stages"]))
            for row in value["stages"]:
                self.assertEqual(binding.read(output / "observations" / (row["name"] + ".receipt.json")), row)
                for stream in ("stdout", "stderr"):
                    self.assertEqual(binding.identity(output / "observations" / (row["name"] + "." + stream + ".raw")), row[stream])
            self.assertEqual(value["status"], "FAIL" if mutate else "PASS")
            self.assertEqual(value["stages"][-1]["qualification_report_before"] ==
                             value["stages"][-1]["qualification_report_after"], not mutate)
            self.assertEqual(binding.read(output / "qualification/report.json")["status"], "WRAPPER_TEST_FIXTURE")

    def test_actual_candidate_wrapper_records_provider_and_independent_reader(self):
        self.fixture_run(False)

    def test_zero_exit_candidate_reader_cannot_replace_the_executed_report(self):
        self.fixture_run(True)


class PayloadMetadataBinding(unittest.TestCase):
    def setUp(self):
        self.head, self.tree = "a" * 40, "b" * 40
        sources = {"hia/platform/peer_payload/qualify.py": {"bytes": 17, "sha256": "c" * 64}}
        self.report = {"schema": "trnm.hia.payload-metadata-qualification.v1", "status": "PASS",
            "source_inputs_stable": True, "complete_original_tests_preserved": True,
            "original_tests_rerun_in_this_qualification": True, "public_observer_links_unchanged_original": True,
            "private_observer_append_only_test_hook": True, "metadata_owner_public_methods_qualified": 12,
            "failure": None, "traceback": None, "elapsed_ns": 800_000_000_000, "retained_entries": 100,
            "lineage": {"head": self.head, "tree": self.tree, "dirty": False},
            "limits": copy.deepcopy(binding.PAYLOAD_LIMITS), "groups": dict.fromkeys(binding.PAYLOAD_GROUPS, {}),
            "retained_tests": {"outer_tests": 121, "child_reexecutions": 2},
            "production_readback": {"schema": "trnm.hia.payload-metadata-production-readback.v1", "status": "PASS",
                "public_methods": list(binding.PAYLOAD_METHODS), "prior_execution_reused": False,
                "same_round_maximum_replay_index_original": True, **binding.PAYLOAD_COUNTS,
                **dict.fromkeys(binding.PAYLOAD_FALSE_SCOPES, False)},
            "integrity_controls": {"status": "PASS", "tests": 45, "methods": list(binding.PAYLOAD_CONTROL_METHODS),
                "actual": {name: {"family_reaped": True} for name in
                    ("normal", "descendant", "deadline", "native-blocked", "public-close", "ptrace-cleanup")}},
            "source_inputs": sources, **dict.fromkeys(binding.PAYLOAD_FALSE_SCOPES, False)}
        self.refresh_digest()
        self.reader = {key: self.report[key] for key in ("schema", "status", "elapsed_ns", "retained_entries")}

    def refresh_digest(self):
        self.report["source_set_sha256"] = hashlib.sha256((json.dumps(self.report["source_inputs"],
            sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()).hexdigest()

    def check(self, report=None, reader=None):
        binding.payload_summary(self.report if report is None else report,
                                self.reader if reader is None else reader, self.head, self.tree)

    def test_complete_payload_metadata_summary_keeps_source_and_evidence_counts_dynamic(self):
        self.check()
        self.report["source_inputs"]["hia/platform/peer_payload/readback.py"] = {"bytes": 31, "sha256": "d" * 64}
        self.report["retained_entries"] = self.reader["retained_entries"] = 103
        self.refresh_digest()
        self.check()

    def test_payload_metadata_refuses_every_changed_or_missing_actual_count(self):
        for name, count in binding.PAYLOAD_COUNTS.items():
            for value in (None, count - 1, count + 1, str(count), True):
                report = copy.deepcopy(self.report)
                report["production_readback"][name] = value
                with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                    self.check(report=report)
            report = copy.deepcopy(self.report)
            del report["production_readback"][name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.check(report=report)
        for name, count in (("outer_tests", 121), ("child_reexecutions", 2)):
            for value in (None, count - 1, count + 1, str(count), True):
                report = copy.deepcopy(self.report)
                report["retained_tests"][name] = value
                with self.subTest(retained=name, value=value), self.assertRaises(ValueError):
                    self.check(report=report)

    def test_payload_metadata_refuses_scope_promotion_deadline_changes_and_old_head(self):
        for key in binding.PAYLOAD_FALSE_SCOPES:
            for nested in (False, True):
                report = copy.deepcopy(self.report)
                (report["production_readback"] if nested else report)[key] = True
                with self.subTest(scope=key, nested=nested), self.assertRaises(ValueError):
                    self.check(report=report)
        for name, count in binding.PAYLOAD_LIMITS.items():
            for value in (None, count - 1, count + 1, str(count), True):
                report = copy.deepcopy(self.report)
                report["limits"][name] = value
                with self.subTest(limit=name, value=value), self.assertRaises(ValueError):
                    self.check(report=report)
        for name, value in (("head", "0" * 40), ("tree", "0" * 40), ("dirty", True), ("dirty", 0)):
            report = copy.deepcopy(self.report)
            report["lineage"][name] = value
            with self.subTest(lineage=name, value=value), self.assertRaises(ValueError):
                self.check(report=report)

    def test_payload_metadata_refuses_groups_methods_controls_and_missing_process_family(self):
        for name in binding.PAYLOAD_GROUPS:
            report = copy.deepcopy(self.report)
            report["groups"]["replacement"] = report["groups"].pop(name)
            with self.subTest(group=name), self.assertRaises(ValueError):
                self.check(report=report)
        for methods in ([], list(reversed(binding.PAYLOAD_METHODS)), list(binding.PAYLOAD_METHODS)[:-1]):
            report = copy.deepcopy(self.report)
            report["production_readback"]["public_methods"] = methods
            with self.subTest(methods=methods), self.assertRaises(ValueError):
                self.check(report=report)
        for value in (35, 40, 41, 42, 44, 46, "45", True, None):
            report = copy.deepcopy(self.report)
            report["integrity_controls"]["tests"] = value
            with self.subTest(controls=value), self.assertRaises(ValueError):
                self.check(report=report)
        for methods in ([], list(reversed(binding.PAYLOAD_CONTROL_METHODS)), list(binding.PAYLOAD_CONTROL_METHODS)[:-1]):
            report = copy.deepcopy(self.report)
            report["integrity_controls"]["methods"] = methods
            with self.subTest(controls=methods), self.assertRaises(ValueError):
                self.check(report=report)
        for name in self.report["integrity_controls"]["actual"]:
            for omit in (True, False):
                report = copy.deepcopy(self.report)
                if omit:
                    del report["integrity_controls"]["actual"][name]
                else:
                    report["integrity_controls"]["actual"][name]["family_reaped"] = False
                with self.subTest(process=name, omit=omit), self.assertRaises(ValueError):
                    self.check(report=report)

    def test_payload_metadata_refuses_partial_or_stale_independent_readback(self):
        for name, values in (("status", ("FAIL", "EXECUTED", None)),
                             ("schema", ("other", None)),
                             ("elapsed_ns", (None, True, 0, 1_200_000_000_001, 1, float("inf"))),
                             ("retained_entries", (None, True, 0, 99, "100"))):
            for value in values:
                reader = copy.deepcopy(self.reader)
                reader[name] = value
                with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                    self.check(reader=reader)
        for value in (0, 1_200_000_000_001, float("inf"), True, "800000000000"):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            report["elapsed_ns"] = reader["elapsed_ns"] = value
            with self.subTest(total=value), self.assertRaises(ValueError):
                self.check(report=report, reader=reader)
        reader = copy.deepcopy(self.reader)
        reader["borrowed_source_commit"] = "0" * 40
        with self.assertRaises(ValueError):
            self.check(reader=reader)

    def test_payload_metadata_refuses_reused_or_partial_execution(self):
        for name in ("source_inputs_stable", "complete_original_tests_preserved", "original_tests_rerun_in_this_qualification",
                     "public_observer_links_unchanged_original", "private_observer_append_only_test_hook"):
            report = copy.deepcopy(self.report)
            report[name] = False
            with self.subTest(flag=name), self.assertRaises(ValueError):
                self.check(report=report)
        for name, value in (("status", "FAIL"), ("metadata_owner_public_methods_qualified", 11),
                            ("metadata_owner_public_methods_qualified", True), ("failure", "actual failure"),
                            ("traceback", "actual traceback")):
            report = copy.deepcopy(self.report)
            report[name] = value
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.check(report=report)
        for name, value in (("status", "FAIL"), ("prior_execution_reused", True),
                            ("same_round_maximum_replay_index_original", False)):
            report = copy.deepcopy(self.report)
            report["production_readback"][name] = value
            with self.subTest(production=name), self.assertRaises(ValueError):
                self.check(report=report)

    def test_payload_metadata_refuses_source_substitution_and_noncanonical_paths(self):
        for name in ("../private", "/private", "hia//program", "hia/../private", "hia\\program", "", ".", "hia/\0program"):
            report = copy.deepcopy(self.report)
            report["source_inputs"] = {name: {"bytes": 17, "sha256": "c" * 64}}
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.check(report=report)
        for value in ({}, [], None, {"hia/program": {"bytes": True, "sha256": "c" * 64}},
                      {"hia/program": {"bytes": -1, "sha256": "c" * 64}},
                      {"hia/program": {"bytes": 1, "sha256": "INVALID"}},
                      {"hia/program": {"bytes": 1, "sha256": "c" * 64, "extra": True}}):
            report = copy.deepcopy(self.report)
            report["source_inputs"] = value
            with self.subTest(sources=value), self.assertRaises(ValueError):
                self.check(report=report)
        report = copy.deepcopy(self.report)
        report["source_set_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check(report=report)

    def fixture_run(self, mutate):
        with tempfile.TemporaryDirectory(prefix="hia-payload-metadata-ci-command-control-") as temporary:
            base = Path(temporary)
            repository, output = base / "repository", base / "output"
            module = repository / "hia/platform/peer_payload/qualify.py"
            module.parent.mkdir(parents=True)
            (output / "observations").mkdir(parents=True)
            # Actual wrapper children test command/report binding only. They do
            # not claim native metadata execution or the original Cargo gate.
            module.write_text('''import argparse,json,pathlib
p=argparse.ArgumentParser();p.add_argument('phase');p.add_argument('--output');p.add_argument('--input')
a=p.parse_args();root=pathlib.Path(a.output or a.input)
if a.phase=='run':
 root.mkdir();(root/'report.json').write_text('{"status":"WRAPPER_TEST_FIXTURE","version":1}\\n')
''' + ('''else:
 (root/'report.json').write_text('{"status":"WRAPPER_TEST_FIXTURE","version":2}\\n')
''' if mutate else "") + "print(json.dumps({'qualification':False}))\n")
            with patch.object(binding, "ROOT", repository):
                if mutate:
                    with self.assertRaisesRegex(ValueError, "changed during independent readback"):
                        binding.run("payload-metadata", output, None)
                else:
                    binding.run("payload-metadata", output, None)
            process = binding.read(output / "observations/process.json")
            self.assertEqual([row["name"] for row in process["stages"]], ["qualification", "readback"])
            self.assertEqual([row["argv"] for row in process["stages"]], [
                [sys.executable, "-B", "-m", "hia.platform.peer_payload.qualify", "run", "--output", str(output / "q")],
                [sys.executable, "-B", "-m", "hia.platform.peer_payload.qualify", "readback", "--input", str(output / "q")]])
            for row in process["stages"]:
                self.assertEqual(row["cwd"], str(repository))
                self.assertTrue(row["started"])
                self.assertEqual(row["exit_code"], 0)
                self.assertEqual(binding.read(output / "observations" / (row["name"] + ".receipt.json")), row)
                for stream in ("stdout", "stderr"):
                    self.assertEqual(binding.identity(output / "observations" / (row["name"] + "." + stream + ".raw")), row[stream])
            self.assertEqual(process["status"], "FAIL" if mutate else "PASS")
            self.assertEqual(process["stages"][-1]["qualification_report_before"] ==
                             process["stages"][-1]["qualification_report_after"], not mutate)
            self.assertEqual(binding.read(output / "q/report.json")["status"], "WRAPPER_TEST_FIXTURE")

    def test_actual_payload_wrapper_keeps_both_commands_and_complete_streams(self):
        self.fixture_run(False)

    def test_zero_exit_payload_reader_cannot_replace_the_executed_report(self):
        self.fixture_run(True)


class SettlementEngineBinding(unittest.TestCase):
    def setUp(self):
        self.head, self.tree = "a" * 40, "b" * 40
        controls = {"status": "PASS", "roster": list(binding.SETTLEMENT_CONTROL_ROSTER),
                    "passed": len(binding.SETTLEMENT_CONTROL_ROSTER), "failed": 0, "not_run": 0,
                    "report": {"path": "controls/report.json", "bytes": 12, "sha256": "3" * 64},
                    "process_receipt": {"path": "controls/process.json", "bytes": 13, "sha256": "4" * 64}}
        self.report = {
            "schema": "trnm.hia.service-settlement-engine.qualification.v1", "status": "PASS",
            "head": self.head, "tree": self.tree, "repository_clean": True,
            "source_inputs_stable": True, "prior_execution_reused": False,
            "counts": copy.deepcopy(binding.SETTLEMENT_COUNTS),
            "limits": copy.deepcopy(binding.SETTLEMENT_LIMITS),
            "source_inputs": {"hia/platform/service_settlement/qualify.py": {"bytes": 17, "sha256": "c" * 64}},
            "tools": {name: {"path": "/actual-tools/" + name, "bytes": 123, "sha256": "d" * 64}
                      for name in binding.SETTLEMENT_TOOL_LABELS},
            "integrity_controls": controls, **dict.fromkeys(binding.SETTLEMENT_FALSE_SCOPES, False),
        }
        self.report["source_digest"] = self.digest(self.report["source_inputs"])
        self.reader = copy.deepcopy(self.report)
        self.reader["schema"] = "trnm.hia.service-settlement-engine.readback.v1"
        self.reader["qualification_report_sha256"] = "e" * 64

    @staticmethod
    def digest(sources):
        return hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=False).encode("utf-8")).hexdigest()

    def check(self, report=None, reader=None):
        binding.settlement_summary(self.report if report is None else report,
                                   self.reader if reader is None else reader, self.head, self.tree)

    def test_complete_engine_binding_allows_additional_exact_source_inputs(self):
        self.check()
        self.report["source_inputs"]["hia/platform/service_settlement/readback.py"] = {
            "bytes": 23, "sha256": "f" * 64}
        self.reader["source_inputs"] = copy.deepcopy(self.report["source_inputs"])
        self.report["source_digest"] = self.reader["source_digest"] = self.digest(self.report["source_inputs"])
        self.check()

    def test_engine_refuses_changed_counts_even_when_both_summaries_agree(self):
        for field, actual in binding.SETTLEMENT_COUNTS.items():
            for value in (None, actual + 1, str(actual), bool(actual), float(actual)):
                report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
                report["counts"][field] = reader["counts"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.check(report, reader)

    def test_engine_refuses_raised_or_untyped_original_limits(self):
        for field, actual in binding.SETTLEMENT_LIMITS.items():
            for value in (actual + 1, None, str(actual), float(actual), True):
                report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
                report["limits"][field] = reader["limits"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.check(report, reader)

    def test_engine_refuses_old_dirty_failed_and_reused_execution(self):
        for field, value in (("head", "0" * 40), ("tree", "0" * 40), ("repository_clean", False),
                             ("status", "FAIL"), ("status", "EXECUTED"),
                             ("source_inputs_stable", False), ("prior_execution_reused", True)):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            report[field] = reader[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.check(report, reader)

    def test_engine_refuses_every_scope_promotion(self):
        for field in binding.SETTLEMENT_FALSE_SCOPES:
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            report[field] = reader[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(report, reader)

    def test_engine_refuses_source_substitution_and_escaping_paths(self):
        for name in ("", ".", "../escape", "/escape", "hia//duplicate", "hia/../escape", "hia\\escape"):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            report["source_inputs"] = reader["source_inputs"] = {name: {"bytes": 17, "sha256": "c" * 64}}
            report["source_digest"] = reader["source_digest"] = self.digest(report["source_inputs"])
            with self.subTest(path=name), self.assertRaises(ValueError):
                self.check(report, reader)
        reader = copy.deepcopy(self.reader)
        reader["source_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check(reader=reader)

    def test_engine_refuses_omitted_actual_tools_and_controls(self):
        for label in binding.SETTLEMENT_TOOL_LABELS:
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            del report["tools"][label]
            del reader["tools"][label]
            with self.subTest(tool=label), self.assertRaises(ValueError):
                self.check(report, reader)
        original = list(binding.SETTLEMENT_CONTROL_ROSTER)
        for roster in ([], original[:-1], list(reversed(original)), original + original[:1]):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            for value in (report, reader):
                value["integrity_controls"]["roster"] = roster
                value["integrity_controls"]["passed"] = len(roster)
            with self.subTest(roster=roster), self.assertRaises(ValueError):
                self.check(report, reader)
        for field in ("failed", "not_run"):
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            report["integrity_controls"][field] = reader["integrity_controls"][field] = 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(report, reader)

    def test_engine_binds_actual_report_and_receipt_bytes_inside_this_run(self):
        with tempfile.TemporaryDirectory(prefix="hia-engine-evidence-binding-") as temporary:
            root = Path(temporary).resolve()
            qualification = root / "qualification"
            (qualification / "controls").mkdir(parents=True)
            (qualification / "report.json").write_bytes(b'{"status":"WRAPPER_TEST_FIXTURE"}\n')
            for name in ("report.json", "process.json"):
                (qualification / "controls" / name).write_bytes(b'{"qualification":false}\n')
            report, reader = copy.deepcopy(self.report), copy.deepcopy(self.reader)
            reader["qualification_report_sha256"] = binding.identity(qualification / "report.json")["sha256"]
            for field, filename in (("report", "report.json"), ("process_receipt", "process.json")):
                report["integrity_controls"][field] = {
                    "path": "controls/" + filename, **binding.identity(qualification / "controls" / filename)}
            binding.settlement_evidence(report, reader, qualification)
            outside = root / "previous-process.json"
            outside.write_bytes((qualification / "controls/process.json").read_bytes())
            changed = copy.deepcopy(report)
            changed["integrity_controls"]["process_receipt"]["path"] = str(outside)
            with self.assertRaises(ValueError):
                binding.settlement_evidence(changed, reader, qualification)
            (qualification / "controls/process.json").write_bytes(b'{"qualification":false,"replaced":true}\n')
            with self.assertRaises(ValueError):
                binding.settlement_evidence(report, reader, qualification)
            (qualification / "report.json").write_bytes(b'{"status":"WRAPPER_TEST_FIXTURE","changed":true}\n')
            with self.assertRaises(ValueError):
                binding.settlement_evidence(report, reader, qualification)

    def fixture_run(self, mutate):
        with tempfile.TemporaryDirectory(prefix="hia-engine-ci-command-control-") as temporary:
            base = Path(temporary).resolve()
            repository, output, rust_bin = base / "repository", base / "output", base / "rust-bin"
            modules = repository / "hia/platform/service_settlement"
            modules.mkdir(parents=True)
            (output / "observations").mkdir(parents=True)
            rust_bin.mkdir()
            # These actual children test command and immutable-report binding.
            # They deliberately have no PASS qualification or native execution.
            (modules / "qualify.py").write_text(
                "import argparse,json,pathlib\n"
                "p=argparse.ArgumentParser();p.add_argument('phase');p.add_argument('--output');p.add_argument('--rust-bin')\n"
                "a=p.parse_args();q=pathlib.Path(a.output);q.mkdir()\n"
                "q.joinpath('report.json').write_text(json.dumps({'status':'WRAPPER_TEST_FIXTURE','version':1})+'\\n')\n"
                "print(json.dumps({'qualification':False}))\n")
            reader = (
                "import argparse,json,pathlib\n"
                "p=argparse.ArgumentParser();p.add_argument('--input');p.add_argument('--output')\n"
                "a=p.parse_args();q=pathlib.Path(a.input);pathlib.Path(a.output).mkdir()\n")
            if mutate:
                reader += "q.joinpath('report.json').write_text(json.dumps({'status':'WRAPPER_TEST_FIXTURE','version':2})+'\\n')\n"
            reader += "print(json.dumps({'qualification':False}))\n"
            (modules / "readback.py").write_text(reader)
            with patch.object(binding, "ROOT", repository):
                if mutate:
                    with self.assertRaisesRegex(ValueError, "changed during independent readback"):
                        binding.run("settlement-engine", output, rust_bin)
                else:
                    binding.run("settlement-engine", output, rust_bin)
            process = binding.read(output / "observations/process.json")
            expected = [
                [sys.executable, "-B", "-m", "hia.platform.service_settlement.qualify", "run",
                 "--output", str(output / "qualification"), "--rust-bin", str(rust_bin)],
                [sys.executable, "-B", "-m", "hia.platform.service_settlement.readback",
                 "--input", str(output / "qualification"), "--output", str(output / "independent-readback")],
            ]
            self.assertEqual([row["argv"] for row in process["stages"]], expected)
            self.assertEqual([row["name"] for row in process["stages"]], ["qualification", "readback"])
            self.assertEqual(process["status"], "FAIL" if mutate else "PASS")
            for row in process["stages"]:
                self.assertEqual(row["cwd"], str(repository))
                self.assertEqual(row["exit_code"], 0)
                self.assertTrue(row["started"])
                self.assertEqual(binding.read(output / "observations" / (row["name"] + ".receipt.json")), row)
                for stream in ("stdout", "stderr"):
                    self.assertEqual(binding.identity(output / "observations" /
                        (row["name"] + "." + stream + ".raw")), row[stream])
            self.assertEqual(binding.read(output / "qualification/report.json")["status"],
                             "WRAPPER_TEST_FIXTURE")

    def test_actual_engine_wrapper_preserves_both_canonical_commands_and_complete_streams(self):
        self.fixture_run(False)

    def test_zero_exit_engine_reader_cannot_replace_the_qualified_report(self):
        self.fixture_run(True)


if __name__ == "__main__":
    unittest.main()
