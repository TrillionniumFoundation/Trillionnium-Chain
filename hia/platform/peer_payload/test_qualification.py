"""Actual process controls and fail-closed mutations of this round's evidence."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from hia.platform.peer_lease_unix import process
from hia.platform.peer_lease_unix.original_build import cargo_events
from . import contract, readback, readback_observations as observed, original
from .control_readback import ACTUAL


class QualificationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kept = Path(os.environ["TRNM_PEER_UNIX_CONTROL_ROOT"])
        cls.output = cls.kept.parent
        cls.prior = contract.document(cls.output / "pre-controls.json")
        readback.header(cls.prior, final=False)
        cls.compiler_environment = patch.dict(os.environ, cls.prior["compiler_environment"])
        cls.compiler_environment.start()
        cls.native = cls.output / "native/payload-owner.elf"
        cls.sources = {name: contract.capture(cls.output / "native/source-snapshot" / name)
                       for name in cls.prior["source_inputs"]}
        cls.admitted = tuple(sorted(name[4:] for name in cls.sources
                                   if name.startswith("hia/") and name.endswith(".hepta")))

    @classmethod
    def tearDownClass(cls):
        cls.compiler_environment.stop()

    def setUp(self):
        self.root = self.kept / self._testMethodName
        self.root.mkdir(parents=True, mode=0o700)

    def group(self, name):
        path = self.output / "cases" / name
        return path, contract.document(path / "report.json")

    def reject(self, call, expression, *, inputs=None):
        try:
            call()
        except ValueError as error:
            self.assertRegex(str(error), expression)
            record = {"status": "PASS_ACTUAL_READER_REFUSAL", "error": str(error),
                      "required_error": expression, "execution_claimed": False}
            if inputs is not None:
                raw = contract.canonical(inputs)
                (self.root / "mutated-input.json").write_bytes(raw)
                record["input"] = contract.identity(raw)
            (self.root / "refusal.json").write_bytes(contract.canonical(record))
        else:
            self.fail("The actual reader accepted the deliberately damaged evidence")

    def actual(self):
        mode, seconds = ACTUAL[self._testMethodName]
        runner = process.Processes(self.root / "processes", contract.ROOT,
                                   {"PATH": os.environ["PATH"]}, lambda: None)
        argv = [sys.executable, "-B", "-m", "hia.platform.peer_payload.qualification.control_worker",
                "--mode", mode, "--output", self.root / "actual", "--native", self.native]
        if mode in {"deadline", "native-blocked"}:
            with self.assertRaisesRegex(ValueError, "exceeded its original deadline"):
                runner.run("control", argv, timeout=seconds)
            self.assertTrue(runner.rows[-1]["timed_out"])
            self.assertTrue(runner.rows[-1]["collector_readback"]["collector_wait_domain_reaped"])
        else:
            runner.run("control", argv, timeout=seconds)
            readback.processes(runner.output, runner.rows)

    def test_actual_normal_owned_child(self):
        self.actual()

    def test_actual_escaped_descendant_is_reaped(self):
        self.actual()

    def test_actual_escaped_descendant_times_out(self):
        self.actual()

    def test_actual_native_owner_times_out(self):
        self.actual()

    def test_actual_public_close_has_one_cleanup_window(self):
        self.actual()

    def test_actual_stopped_trace_child_cleanup(self):
        self.actual()

    def test_failed_report_cannot_be_promoted(self):
        value = copy.deepcopy(self.prior); value["status"] = "FAIL"
        self.reject(lambda: readback.header(value, final=False), "Failed, partial", inputs=value)

    def test_missing_native_group_is_refused(self):
        value = copy.deepcopy(self.prior); del value["groups"]["wal-maximum-index"]
        self.reject(lambda: readback.header(value, final=False), "Complete native group", inputs=value)

    def test_infinite_elapsed_time_is_refused(self):
        value = copy.deepcopy(self.prior); value["elapsed_ns"] = float("inf")
        self.reject(lambda: readback.header(value, final=False), "Actual unchanged job budget")

    def test_service_four_second_overclaim_is_refused(self):
        value = copy.deepcopy(self.prior); value["original_service_budget_qualified"] = True
        self.reject(lambda: readback.header(value, final=False), "Failed, partial", inputs=value)

    def test_unchanged_240_second_limit_is_enforced(self):
        value = copy.deepcopy(self.prior); value["limits"]["native_seconds"] = 241
        self.reject(lambda: readback.header(value, final=False), "Failed, partial", inputs=value)

    def test_complete_source_byte_mutation_is_refused(self):
        path = contract.HERE / "runtime_queries.hepta"
        raw = path.read_bytes()
        try:
            path.write_bytes(raw + b"\n")
            self.reject(lambda: contract.require_sources(self.sources, self.admitted), "Complete metadata owner source graph")
        finally:
            path.write_bytes(raw)

    def test_new_owned_source_member_is_refused(self):
        path = contract.HERE / "qualification/unadmitted-control.py"
        self.assertFalse(path.exists())
        try:
            path.write_bytes(b"# deliberate membership negative\n")
            self.reject(lambda: contract.require_sources(self.sources, self.admitted), "Complete metadata owner source graph")
        finally:
            path.unlink()

    def test_original_git_blob_mutation_is_refused(self):
        path = contract.ROOT / "trillionnium/crates/trnm-peer-lease/src/payload.rs"
        raw = path.read_bytes()
        try:
            path.write_bytes(raw + b"\n")
            self.reject(lambda: contract.require_sources(self.sources, self.admitted), "Original source differs from current Git blob")
        finally:
            path.write_bytes(raw)

    def test_retained_symlink_is_refused(self):
        path = self.root / "link"; path.symlink_to(self.native)
        self.reject(lambda: readback.check_identity(path, readback.file_identity(self.native)), "Linked retained")

    def test_linked_ancestor_is_refused(self):
        path = self.root / "linked"; path.symlink_to(self.output / "native", target_is_directory=True)
        self.reject(lambda: readback.file_identity(path / "payload-owner.elf"), "Linked retained")

    def test_retained_path_traversal_is_refused(self):
        self.reject(lambda: contract.relative("../native/payload-owner.elf"), "Noncanonical retained path")

    def test_duplicate_json_status_is_refused(self):
        path = self.root / "duplicate.json"; path.write_bytes(b'{"status":"FAIL","status":"PASS"}')
        self.reject(lambda: contract.document(path), "Duplicate JSON key")

    def test_missing_evidence_member_is_refused(self):
        path = self.root / "retained"; path.mkdir()
        (path / "actual.raw").write_bytes(b"retained exact raw")
        raw = contract.canonical(readback.inventory(path))
        (path / "contents.json").write_bytes(raw)
        value = {"contents": contract.identity(raw), "retained_entries": 1}
        (path / "actual.raw").unlink()
        self.reject(lambda: readback.contents_readback(path, value), "Complete evidence member set", inputs=value)

    def test_modified_evidence_bytes_are_refused(self):
        path = self.root / "actual.raw"; path.write_bytes(b"actual before")
        identity = readback.file_identity(path); path.write_bytes(b"actual after")
        self.reject(lambda: readback.check_identity(path, identity), "Retained bytes differ", inputs=identity)

    def test_native_group_command_substitution_is_refused(self):
        rows = {row["name"]: copy.deepcopy(row) for row in self.prior["stages"]}
        rows["primitives"]["argv"] = ["/usr/bin/true"]
        self.reject(lambda: readback.observation_commands(self.output, self.prior, rows), "Actual native group command")

    def test_original_dependency_profile_mutation_is_refused(self):
        events = cargo_events(contract.capture(self.output / "original/complete/processes/retained-original-tests/stdout.raw"))
        events = copy.deepcopy(events)
        changed = [row for row in events if row["target"]["name"] == "sha2" and not row["profile"]["test"]]
        self.assertEqual(len(changed), 1); changed[0]["profile"]["opt_level"] = "0"
        self.reject(lambda: original.selected_libraries(events), "Original dependency/profile not unique")

    def test_native_primitive_pair_count_cannot_shrink(self):
        path, value = self.group("primitives"); value["replay_pairs"] = 839
        self.reject(lambda: observed.primitives(path, value, self.output / "original/metadata-reference.elf"),
                    "Complete primitive/reference", inputs=value)

    def test_runtime_guard_failure_is_refused(self):
        path, value = self.group("runtime"); value["guards_preserved"] = False
        self.reject(lambda: observed.runtime(path, value, {}), "Private runtime coverage", inputs=value)

    def test_allocation_failure_cannot_be_faked_by_count(self):
        path, value = self.group("allocations"); value["actual_allocation_failures"] = 839
        self.reject(lambda: observed.allocations(path, value, {}), "Allocation/lifetime coverage", inputs=value)

    def test_eight_thread_roster_cannot_shrink(self):
        path, value = self.group("allocations"); value["parallel_threads"] = 7
        self.reject(lambda: observed.allocations(path, value, {}), "Allocation/lifetime coverage", inputs=value)

    def test_public_history_names_cannot_be_substituted(self):
        path, value = self.group("public"); value["cases"][0]["name"] = "unexecuted-history"
        self.reject(lambda: observed.public_histories(path, value, "public", self.output / "original/public-reference.elf", self.native),
                    "Public method histories were omitted", inputs=value)

    def original_diagnostic_case(self):
        root = self.output / "cases/public/public-sequence-original"
        inputs = observed.requests("public", "public-sequence", root)
        rows = observed.parse_public(contract.capture(root / "stdout.raw"), inputs)
        raw = contract.capture(root / "stderr.raw")
        observed.public_diagnostics(raw, rows, inputs, original=True)
        return raw, rows, inputs

    def reject_original_diagnostics(self, raw, rows, inputs):
        self.reject(lambda: observed.public_diagnostics(raw, rows, inputs, original=True),
                    "Original diagnostic events differ", inputs={"stderr_hex": raw.hex(),
                    "responses": rows, "requests_hex": [value.hex() for value in inputs]})

    def test_original_diagnostic_event_deletion_is_refused(self):
        raw, rows, inputs = self.original_diagnostic_case()
        lines = raw.splitlines(keepends=True)
        self.assertGreater(len(lines), 1)
        self.reject_original_diagnostics(b"".join(lines[1:]), rows, inputs)

    def test_original_diagnostic_event_addition_is_refused(self):
        raw, rows, inputs = self.original_diagnostic_case()
        self.reject_original_diagnostics(raw + raw.splitlines(keepends=True)[0], rows, inputs)

    def test_original_diagnostic_event_reordering_is_refused(self):
        raw, rows, inputs = self.original_diagnostic_case()
        lines = raw.splitlines(keepends=True)
        self.assertNotEqual(lines[0], lines[-1])
        lines[0], lines[-1] = lines[-1], lines[0]
        self.reject_original_diagnostics(b"".join(lines), rows, inputs)

    def test_original_diagnostic_response_code_substitution_is_refused(self):
        raw, rows, inputs = self.original_diagnostic_case()
        first_replay = next(row for row in rows if row["code"] == 5)
        first_replay["code"] = 3
        self.reject_original_diagnostics(raw, rows, inputs)

    def test_wal_corrupt_history_cannot_be_reported_as_replay(self):
        path = self.output / "cases/wal-small/results/duplicate-sequence-replay/report.json"
        actual = contract.document(path)
        self.assertEqual(observed.wal_replay_value("duplicate-sequence", actual["value"]), 3)
        self.reject(lambda: observed.wal_replay_value("duplicate-sequence", 5),
                    "WAL boundary/error precedence", inputs={"actual_report": readback.file_identity(path),
                    "actual_value": actual["value"], "substituted_value": 5})

    def test_injected_syscall_roster_cannot_shrink(self):
        path, value = self.group("syscalls"); value["actual_fault_pairs"] = 59
        self.reject(lambda: observed.syscall_histories(path, value, self.output / "original/public-reference.elf", self.native),
                    "Real syscall failure coverage", inputs=value)

    def test_published_head_read_cannot_target_a_temporary_file(self):
        root = self.output / "cases/syscalls/admit-head-read-EIO-original"
        value = contract.document(root / "injection-selector.json")
        line = value["actual"]["line"]
        observed.syscall_storage_target("admit-head-read", root / "work", line)
        changed = line.replace("/.journal.head-v1>", "/..journal.head-v1.tmp-0-0-0>")
        self.assertNotEqual(changed, line)
        self.reject(lambda: observed.syscall_storage_target("admit-head-read", root / "work", changed),
                    "Actual fault is unbound", inputs={"phase": "admit-head-read",
                    "actual": value, "substituted_line": changed})

    def test_crash_cut_cannot_claim_power_failure(self):
        path, value = self.group("crash"); value["power_failure_claimed"] = True
        self.reject(lambda: observed.crash_histories(path, value, self.output / "original/public-reference.elf", self.native),
                    "Actual crash/reopen roster", inputs=value)

    def test_crash_cut_cannot_substitute_an_injected_action(self):
        root = self.output / "cases/crash/open-journal-write-native"
        path = root / "trace/trace.json"; actual = contract.document(path)
        value = copy.deepcopy(actual); value["actions"][0]["kind"] = "injected-EIO"
        real = observed.document
        with patch.object(observed, "document", side_effect=lambda p: value if Path(p) == path else real(p)):
            self.reject(lambda: observed.crash_trace(root / "trace", self.native, root / "work",
                "open-journal-write", contract.capture(root / "trace/stdin.raw")), "Crash was not after a real kernel operation", inputs=value)

    def test_wal_partitions_cannot_omit_maximum_index(self):
        groups = {name: self.group(name)[1] for name in ("wal-large", "wal-maximum-replay", "wal-maximum-index")}
        groups["wal-maximum-index"]["cases"][0]["observations"] = []
        self.reject(lambda: readback.wal_union(groups), "exact disjoint full union", inputs=groups)

    def test_wal_partitions_cannot_duplicate_a_native_call(self):
        groups = {name: self.group(name)[1] for name in ("wal-large", "wal-maximum-replay", "wal-maximum-index")}
        groups["wal-large"]["cases"].append(copy.deepcopy(groups["wal-maximum-replay"]["cases"][0]))
        self.reject(lambda: readback.wal_union(groups), "exact disjoint full union", inputs=groups)

    def test_maximum_index_cannot_borrow_another_round(self):
        path, value = self.group("wal-maximum-index"); value["maximum_replay"]["input"]["path"] = "/another-round/input.raw"
        self.reject(lambda: observed.wal(path, value, partition="maximum-index", replay=self.output / "native/metadata_log.so",
                    index=self.output / "native/metadata-index.so", original=self.output / "original/metadata-reference.elf",
                    maximum_replay=readback.maximum_reference(self.output)), "same-round replay and Rust binding", inputs=value)

    def test_compiler_profile_cannot_exceed_8192_ops(self):
        value = {"functions": [{"blocks": [{"ops": [None] * 8193}]}]}
        self.reject(lambda: readback.core_counts(value), "Compiler profile limits increased")

    def test_single_cleanup_budget_cannot_be_renewed(self):
        path = self.output / "cases/public/public-sequence-native/process.json"
        value = contract.document(path); value["cleanup_windows"] = 2
        real = observed.document
        with patch.object(observed, "document", side_effect=lambda p: value if Path(p) == path else real(p)):
            self.reject(lambda: observed.public_child(path.parent, self.native, []), "one cleanup window", inputs=value)


if __name__ == "__main__":
    unittest.main()
