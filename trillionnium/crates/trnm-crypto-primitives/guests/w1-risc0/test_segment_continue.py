#!/usr/bin/env python3
"""Bounded provenance/adversarial controls; no synthetic bytes qualify a proof."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import time
import unittest
from unittest.mock import patch

import segment_continue as continuation
import segment_continue_source as source
import continuation_validate


class ContinuationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.manifest = source.load_policy()
        cls.files = source.original_members(cls.policy, cls.manifest)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def session_copy(self):
        directory = self.root / "session"
        directory.mkdir()
        for name, data in self.files.items():
            if name.startswith("segmented/session/"):
                source.write_bytes(directory / name.removeprefix("segmented/session/"), data)
        return directory

    def test_all_315_real_original_members_and_26_partial_receipts_read_back(self):
        self.assertEqual(len(self.files), 315)
        self.assertEqual(len([n for n in self.files if n.startswith("segmented/receipts/") and n.endswith(".bin")]), 26)
        self.assertNotIn("receipt.bin", self.files)
        phase = source.decode(self.files["prove.process.json"])
        self.assertEqual(phase["returncode"], 1)
        self.assertGreater(phase["user_cpu_seconds"], 13000)

    def test_budget_relaxation_refused(self):
        for key in ["workers_per_shard", "rayon_threads_per_worker", "segment_seconds", "work_stop_seconds", "outer_phase_seconds"]:
            policy = copy.deepcopy(self.policy)
            policy["budgets"][key] += 1
            with self.assertRaisesRegex(ValueError, "budget"):
                source.check_policy(policy)

    def test_overlapping_or_missing_shards_refused(self):
        for indexes in [list(range(26, 44)), list(range(45, 62)), list(range(44, 61))]:
            policy = copy.deepcopy(self.policy)
            policy["shards"][1]["indexes"] = indexes
            with self.assertRaisesRegex(ValueError, "disjoint"):
                source.check_policy(policy)

    def test_other_run_or_success_reclassification_refused(self):
        for field, value in [("run_id", 40511022476), ("conclusion", "success"), ("artifact_id", 1)]:
            policy = copy.deepcopy(self.policy)
            policy["origin"][field] = value
            with self.assertRaisesRegex(ValueError, "reviewed actual failed run"):
                source.check_policy(policy)

    def test_partial_receipt_never_marked_complete(self):
        policy = copy.deepcopy(self.policy)
        policy["partial_receipts_are_complete_proofs"] = True
        with self.assertRaisesRegex(ValueError, "no proof"):
            source.check_policy(policy)

    def test_real_corrupted_archive_part_refused(self):
        item = self.manifest["parts"][0]
        data = bytearray((source.ROOT / item["path"]).read_bytes())
        data[123] ^= 1
        source.write_bytes(self.root / item["path"], data)
        with self.assertRaisesRegex(ValueError, "hash/size"):
            source.original_members(self.policy, self.manifest, self.root)

    def test_archive_part_reorder_refused(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["parts"][0], manifest["parts"][1] = manifest["parts"][1], manifest["parts"][0]
        with self.assertRaisesRegex(ValueError, "order"):
            source.original_members(self.policy, manifest)

    def test_original_source_after_change_refused(self):
        files = dict(self.files)
        identity = source.decode(files["source-after.json"])
        identity["tested_commit"] = "0" * 40
        files["source-after.json"] = json.dumps(identity).encode()
        with self.assertRaisesRegex(ValueError, "source identity"):
            source.check_original(self.policy, files)

    def test_original_failure_cannot_be_rewritten_as_exit_zero(self):
        files = dict(self.files)
        phase = source.decode(files["prove.process.json"])
        phase["returncode"] = 0
        files["prove.process.json"] = json.dumps(phase).encode()
        with self.assertRaisesRegex(ValueError, "remain failed"):
            source.check_original(self.policy, files)

    def test_original_receipt_bytes_tamper_refused(self):
        session = source.decode(self.files["segmented/session/session.json"])
        report = source.decode(self.files["segmented/receipts/segment-0.json"])
        data = bytearray(self.files["segmented/receipts/segment-0.bin"])
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "foreign"):
            source.check_receipt(0, session, data, report)

    def test_orig_receipt_report_extra_pow_or_complete_claim_refused(self):
        session = source.decode(self.files["segmented/session/session.json"])
        original = source.decode(self.files["segmented/receipts/segment-0.json"])
        for field in ["additional_grinding", "complete_w1_proof_verified", "povw_requested", "dev_mode"]:
            report = dict(original)
            report[field] = True
            with self.assertRaisesRegex(ValueError, "scope/profile"):
                source.check_receipt(0, session, self.files["segmented/receipts/segment-0.bin"], report)

    def test_same_actual_export_bytes_allow_only_new_wall_measurement(self):
        directory = self.session_copy()
        item = source.read(directory / "session.json")
        item["execute_and_export_wall_ns"] += 1
        (directory / "session.json").write_text(json.dumps(item))
        fresh = source.compare_fresh_session(self.files, directory)
        self.assertEqual(fresh["user_cycles"], 13364385)

    def test_changed_session_statement_or_segment_metadata_refused(self):
        directory = self.session_copy()
        original = source.read(directory / "session.json")
        for field, value in [("statement_id", "0" * 64), ("user_cycles", 1), ("new_unknown", True)]:
            item = copy.deepcopy(original)
            item[field] = value
            (directory / "session.json").write_text(json.dumps(item))
            with self.assertRaisesRegex(ValueError, "same original session"):
                source.compare_fresh_session(self.files, directory)

    def test_changed_exported_last_segment_refused(self):
        directory = self.session_copy()
        path = directory / "segment-61"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "segment/claim changed"):
            source.compare_fresh_session(self.files, directory)

    def test_unreviewed_session_file_refused(self):
        directory = self.session_copy()
        (directory / "unreviewed").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "unreviewed file"):
            source.compare_fresh_session(self.files, directory)

    def test_retained_proof_session_requires_manifest_and_every_exact_byte(self):
        directory = self.session_copy()
        self.assertEqual(source.checked_original_session(self.files, directory)["user_cycles"], 13364385)
        manifest = source.read(directory / "session.json")
        manifest["execute_and_export_wall_ns"] += 1
        (directory / "session.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "original proof session bytes changed"):
            source.checked_original_session(self.files, directory)

    def test_original_proof_session_rejects_last_segment_tamper(self):
        directory = self.session_copy()
        path = directory / "segment-61"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "original proof session bytes changed"):
            source.checked_original_session(self.files, directory)

    def test_original_proof_session_rejects_missing_or_added_files(self):
        directory = self.session_copy()
        extra = directory / "extra"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "unreviewed or missing"):
            source.checked_original_session(self.files, directory)
        extra.unlink()
        (directory / "segment-61").unlink()
        with self.assertRaisesRegex(ValueError, "unreviewed or missing"):
            source.checked_original_session(self.files, directory)

    def test_independent_trace_cannot_become_original_proof_material(self):
        # Synthetic provenance fixture only: matching a fresh file hash does
        # not validate a trace or produce any STARK/complete receipt.
        directory = self.session_copy()
        path = directory / "segment-26"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        manifest = source.read(directory / "session.json")
        manifest["segments"][26]["sha256"] = source.sha(data)
        (directory / "session.json").write_text(json.dumps(manifest))
        source.check_independent_execution(self.files, directory)
        with self.assertRaisesRegex(ValueError, "original proof session bytes changed"):
            source.checked_original_session(self.files, directory)
        with self.assertRaisesRegex(ValueError, "same original session"):
            source.compare_fresh_session(self.files, directory)
        # Even a freshly self-consistent report cannot replace an original
        # segment: the report reader still binds the original segment digest.
        report = source.decode(self.files["segmented/receipts/segment-0.json"])
        report["segment_sha256"] = manifest["segments"][26]["sha256"]
        with self.assertRaisesRegex(ValueError, "foreign"):
            source.check_receipt(0, source.decode(self.files["segmented/session/session.json"]),
                                 self.files["segmented/receipts/segment-0.bin"], report)

    def test_independent_execution_keeps_all_relation_invariants(self):
        directory = self.session_copy()
        original = source.read(directory / "session.json")
        for field, value in [("statement_id", "0" * 64), ("journal_hex", "00"),
                             ("user_cycles", 1), ("new_unknown", True), ("povw_requested", True)]:
            item = copy.deepcopy(original)
            item[field] = value
            (directory / "session.json").write_text(json.dumps(item))
            with self.assertRaisesRegex(ValueError, "relation invariant"):
                source.check_independent_execution(self.files, directory)

    def test_independent_execution_rejects_unbound_segment_bytes(self):
        directory = self.session_copy()
        path = directory / "segment-61"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "segment bytes/hash changed"):
            source.check_independent_execution(self.files, directory)

    def test_independent_execution_requires_exact_complete_claim(self):
        directory = self.session_copy()
        path = directory / "session.claim.bin"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "complete claim changed"):
            source.check_independent_execution(self.files, directory)

    def test_old_policy_and_fresh_trace_selection_are_refused(self):
        policy = copy.deepcopy(self.policy)
        policy["schema"] = "pon-w1-frozen-session-continuation-policy-v1"
        with self.assertRaisesRegex(ValueError, "policy namespace"):
            source.check_policy(policy)
        policy = copy.deepcopy(self.policy)
        policy["segment_asset_source"] = "fresh-execution"
        with self.assertRaisesRegex(ValueError, "trace ownership"):
            source.check_policy(policy)

    def test_no_symlink_or_parent_escape(self):
        for name in ["../other", "/absolute", "a/../b", "a\\b"]:
            with self.assertRaisesRegex(ValueError, "unsafe"):
                source.path_under(self.root, name)
        (self.root / "link").symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, "symlink"):
            source.path_under(self.root, "link/file")

    def test_duplicate_json_and_nonfinite_refused(self):
        for encoded in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}']:
            with self.assertRaises(ValueError):
                source.decode(encoded)

    def test_missing_owned_cleanup_and_nonfinite_cpu_refused(self):
        original = source.decode(self.files["prove.process.json"])
        for field, value in [("owned_process_group_empty", False), ("child_reaped", False),
                             ("subreaper_enabled", False), ("user_cpu_seconds", float("inf"))]:
            item = copy.deepcopy(original)
            item[field] = value
            with self.assertRaises(ValueError):
                source.require_closed_phase(item, False)

    def test_fresh_image_mutation_refused(self):
        elf, inp = self.root / "guest.bin", self.root / "input.bin"
        elf.write_bytes(self.files["guest.bin"])
        inp.write_bytes(self.files["input.bin"])
        source.compare_fresh_inputs(self.files, elf, inp)
        data = bytearray(elf.read_bytes())
        data[-1] ^= 1
        elf.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "image/input differ"):
            source.compare_fresh_inputs(self.files, elf, inp)

    def test_invalid_declared_policy_has_no_generation_fallback(self):
        invalid = self.root / "policy.json"
        invalid.write_text('{"schema":"unknown"}')
        output = self.root / "outputs"
        with patch.object(source, "POLICY", invalid), patch.object(source, "load_policy", side_effect=ValueError("policy invalid")), \
             patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            with self.assertRaisesRegex(ValueError, "policy invalid"):
                continuation.select()
        self.assertFalse(output.exists())

    def test_absent_policy_keeps_original_generation_selection(self):
        output = self.root / "outputs"
        with patch.object(source, "POLICY", self.root / "absent.json"), \
             patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
             contextlib.redirect_stdout(io.StringIO()):
            continuation.select()
        self.assertEqual(output.read_text(), "mode=generate\n")

    def test_dangling_policy_link_cannot_select_generation(self):
        declared = self.root / "declared-policy.json"
        declared.symlink_to(self.root / "missing-target.json")
        output = self.root / "outputs"
        with patch.object(source, "POLICY", declared), \
             patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            with self.assertRaises(OSError):
                continuation.select()
        self.assertFalse(output.exists())

    def test_policy_link_to_real_file_is_also_refused(self):
        declared = self.root / "declared-policy.json"
        declared.symlink_to(source.POLICY)
        output = self.root / "outputs"
        with patch.object(source, "POLICY", declared), \
             patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            with self.assertRaises(OSError):
                continuation.select()
        self.assertFalse(output.exists())

    def test_actual_zero_exit_child_polled_after_budget_is_refused(self):
        # A real owned child exits zero. WNOWAIT observes without stealing the
        # original Stage's wait4 accounting, then its late completion is refused.
        with patch.dict(os.environ, {"TRNM_EXPECTED_SOURCE_SHA": self.policy["origin"]["source_sha"]}):
            stage = continuation.scheduler.Stage(self.root, "late-zero", [sys.executable, "-c", "pass"], 0.001)
            os.waitid(os.P_PID, stage.process.pid, os.WEXITED | os.WNOWAIT)
            time.sleep(0.005)
            with self.assertRaisesRegex(ValueError, "original wall budget"):
                continuation.check_stage(stage)
            self.assertEqual(stage.record["returncode"], 0)
            self.assertTrue(stage.record["child_reaped"])
            self.assertGreater(stage.record["wall_seconds"], 0.001)
            self.assertEqual(continuation.scheduler.cleanup([stage]), [])

    def test_actual_child_in_budget_retains_original_accounting(self):
        with patch.dict(os.environ, {"TRNM_EXPECTED_SOURCE_SHA": self.policy["origin"]["source_sha"]}):
            stage = continuation.scheduler.Stage(self.root, "in-budget", [sys.executable, "-c", "pass"], 10)
            continuation.wait_stage(stage)
            self.assertEqual(stage.record["returncode"], 0)
            self.assertTrue(stage.record["child_reaped"])
            self.assertGreaterEqual(stage.record["user_cpu_seconds"], 0)
            self.assertEqual(continuation.scheduler.cleanup([stage]), [])

    def test_completed_worker_and_export_costs_keep_original_300_second_cap(self):
        terminal = source.decode(self.files["segmented/steps/segment-0.terminal.json"])
        sha = self.policy["origin"]["source_sha"]
        continuation.check_stage_terminal(terminal, sha, 300)
        for field, value in [("wall_seconds", 300.00001), ("wall_seconds", float("nan")),
                             ("timeout_seconds", 301), ("child_reaped", False),
                             ("source_sha", "0" * 40), ("user_cpu_seconds", -1)]:
            changed = dict(terminal)
            changed[field] = value
            with self.assertRaises(ValueError):
                continuation.check_stage_terminal(changed, sha, 300)

    def test_work_complete_boundary_is_before_3500_seconds(self):
        continuation.require_work_finished(3499.99)
        for elapsed in [None, True, -1, 3500, 3500.01, float("nan"), float("inf")]:
            with self.assertRaisesRegex(ValueError, "work-stop budget"):
                continuation.require_work_finished(elapsed)

    def test_zero_exit_outer_phase_cannot_hide_observed_deadline_overrun(self):
        phase = source.decode(self.files["prove.process.json"])
        phase.update(returncode=0, child_returncode=0)
        source.require_closed_phase(phase, True)
        phase["wall_seconds"] = phase["timeout_seconds"] + 0.001
        with self.assertRaisesRegex(ValueError, "outer wall budget"):
            source.require_closed_phase(phase, True)

    def test_evidence_index_rejects_root_and_child_symlinks(self):
        real = self.root / "real"
        real.mkdir()
        (real / "value").write_bytes(b"observed")
        alias = self.root / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            continuation.indexed_files(alias)
        (real / "alias").symlink_to(real / "value")
        with self.assertRaisesRegex(ValueError, "symlink"):
            continuation.indexed_files(real)

    def test_zero_byte_flood_has_bounded_file_count(self):
        for index in range(source.MAX_EVIDENCE_FILES + 1):
            (self.root / str(index)).touch()
        with self.assertRaisesRegex(ValueError, "file count budget"):
            continuation.indexed_files(self.root)

    def test_empty_directory_flood_and_depth_are_bounded(self):
        for index in range(source.MAX_EVIDENCE_DIRECTORIES):
            (self.root / str(index)).mkdir()
        with self.assertRaisesRegex(ValueError, "directory count budget"):
            continuation.indexed_files(self.root)
        for child in self.root.iterdir():
            child.rmdir()
        path = self.root
        for _ in range(source.MAX_EVIDENCE_DEPTH + 1):
            path = path / "deep"
            path.mkdir()
        with self.assertRaisesRegex(ValueError, "depth budget"):
            continuation.indexed_files(self.root)

    def test_cumulative_bytes_refused_before_reading_excess_file(self):
        (self.root / "one").write_bytes(b"12345")
        (self.root / "two").write_bytes(b"67890")
        with patch.object(source, "MAX_EVIDENCE_BYTES", 9), \
             patch.object(source, "checked_bytes", wraps=source.checked_bytes) as reads:
            with self.assertRaisesRegex(ValueError, "evidence byte budget"):
                continuation.indexed_files(self.root)
            self.assertEqual(reads.call_count, 1)

    def test_fifo_is_refused_without_opening_or_blocking(self):
        os.mkfifo(self.root / "fifo")
        with self.assertRaisesRegex(ValueError, "regular evidence file"):
            continuation.indexed_files(self.root)

    def test_actual_session_index_is_exact_and_sorted(self):
        session = self.session_copy()
        indexed = continuation.indexed_files(session)
        self.assertEqual(list(indexed), sorted(indexed))
        self.assertEqual(indexed["segment-61"]["sha256"], source.sha(self.files["segmented/session/segment-61"]))

    def test_report_refuses_same_sha_with_different_complete_source_identity(self):
        identity = self.policy["origin"]["source_identity"]
        for name in ["source-before.json", "source-after.json"]:
            source.write_json(self.root / name, identity)
        for field, value in [("tested_tree", "0" * 40), ("tracked_entries", -1)]:
            changed = dict(identity)
            changed[field] = value
            with patch.dict(os.environ, {"TRNM_EXPECTED_SOURCE_SHA": identity["tested_commit"],
                "GITHUB_RUN_ID": "40511022475", "GITHUB_RUN_ATTEMPT": "1"}), \
                 patch.object(continuation, "check_shard", return_value=({}, {}, changed)), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "incomplete or unverified"):
                    continuation.report(self.root)
            result = source.read(self.root / "continuation-costs.json")
            self.assertFalse(result["complete_proof_and_audit_observed"])
            self.assertTrue(any("report/shards source trees differ" in e for e in result["errors"]))
            (self.root / "continuation-costs.json").unlink()

    def test_missing_continuations_and_receipt_report_unknown_not_zero(self):
        with patch.dict(os.environ, {"TRNM_EXPECTED_SOURCE_SHA": "5d957878ea82b09b555c713976f5157fde1089a0",
                                    "GITHUB_RUN_ID": "40511022475", "GITHUB_RUN_ATTEMPT": "1"}), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "incomplete or unverified"):
                continuation.report(self.root)
        result = source.read(self.root / "continuation-costs.json")
        self.assertFalse(result["complete_proof_and_audit_observed"])
        self.assertIsNone(result["generation_cpu_seconds_including_original_failure"])
        self.assertIsNone(result["phase_costs"]["continuation_0"]["user_cpu_seconds"])
        self.assertGreater(result["known_generation_cpu_seconds_subtotal"], 13000)
        self.assertFalse(result["original_failure_reclassified"])

    def test_report_rejects_substituted_phase_source_budget_and_run(self):
        # This is only an evidence-reader control: cryptographic validation is
        # explicitly stubbed, and the synthetic output stays in a temporary dir.
        identity = self.policy["origin"]["source_identity"]
        run = {"source_sha": identity["tested_commit"], "run_id": "40511022475", "run_attempt": "1"}
        for name in ["source-before.json", "source-after.json"]:
            source.write_json(self.root / name, identity)
        raw = b"labelled synthetic report-reader control; not a W1 proof"
        source.write_bytes(self.root / "receipt.bin", raw)
        result = {"schema": "pon-w1-continuation-assembly-v1", **run,
                  "real_composite_stark_verified": True,
                  "receipt_bytes": len(raw), "receipt_sha256": source.sha(raw),
                  "original_failure_reclassified": False, "consensus_authority": False,
                  "additional_pow": False, "fresh_generation_phases": 2, "reused_original_segments": 26}
        phase = source.decode(self.files["prove.process.json"])
        phase.update(returncode=0, child_returncode=0, timed_out=False,
                     wall_seconds=1, user_cpu_seconds=1, system_cpu_seconds=0)
        for name, cap in [("assembly", 300), ("verify", 900), ("audit", 900), ("soundness", 120)]:
            source.write_json(self.root / f"{name}.process.json", {**phase, "timeout_seconds": cap})
        stage = {"schema": "pon-w1-segment-worker-process-v1", "returncode": 0,
                 "child_reaped": True, "source_sha": run["source_sha"], "timeout_seconds": 300,
                 "wall_seconds": 1, "user_cpu_seconds": 1, "system_cpu_seconds": 0}
        source.write_json(self.root / "assembly-work/steps/assemble.terminal.json", stage)
        cases = [("assembly", "source_sha", "0" * 40), ("soundness", "source_sha", "0" * 40),
                 ("assembly", "timeout_seconds", 301), ("soundness", "timeout_seconds", 121),
                 ("result", "source_sha", "0" * 40), ("result", "run_id", "40511022476"),
                 ("result", "run_attempt", "2"), (None, None, None)]
        for changed_phase, field, value in cases:
            with self.subTest(phase=changed_phase, field=field):
                (self.root / "continuation-costs.json").unlink(missing_ok=True)
                changed_result = dict(result)
                for name, cap in [("assembly", 300), ("verify", 900), ("audit", 900), ("soundness", 120)]:
                    (self.root / f"{name}.process.json").write_text(json.dumps({**phase, "timeout_seconds": cap}))
                if changed_phase == "result":
                    changed_result[field] = value
                elif changed_phase is not None:
                    path = self.root / f"{changed_phase}.process.json"
                    path.write_text(json.dumps({**source.read(path), field: value}))
                with patch.dict(os.environ, {"TRNM_EXPECTED_SOURCE_SHA": run["source_sha"],
                        "GITHUB_RUN_ID": run["run_id"], "GITHUB_RUN_ATTEMPT": run["run_attempt"]}), \
                     patch.object(continuation, "check_shard", return_value=({}, {}, identity)), \
                     patch.object(continuation, "read_single_result", return_value=changed_result), \
                     patch.object(continuation_validate, "validate", return_value={"synthetic_control": True}), \
                     contextlib.redirect_stdout(io.StringIO()):
                    if changed_phase is None:
                        continuation.report(self.root)
                    else:
                        with self.assertRaisesRegex(ValueError, "incomplete or unverified"):
                            continuation.report(self.root)
                observed = source.read(self.root / "continuation-costs.json")
                self.assertEqual(observed["complete_proof_and_audit_observed"], changed_phase is None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
