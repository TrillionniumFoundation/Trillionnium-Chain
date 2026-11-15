"""Require a fresh actual native journal run; mutated copies are reader negatives."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from native_execution_certificate import CertificateError
from native_owner_journal import DOMAIN, MAGIC, read_frames, read_journal, read_run_journals
from native_owner_score_bridge import local_commitment


def rewrite(path, records):
    output, previous, prefix_hashes = bytearray(MAGIC), "00" * 32, []
    for index, record in enumerate(records):
        payload = record["payload"]
        # Semantic negative controls deliberately have a fresh, internally
        # consistent hash chain, including every in-record supplied prefix pin.
        # They do not reuse or alter any independently retained original pin.
        if payload.get("kind") == "open_intent" and payload["expected_checkpoint"] is not None:
            pin = payload["expected_checkpoint"]
            assert 0 <= pin["sequence"] < index
            pin["record_hash"] = prefix_hashes[pin["sequence"]]
        frame = {"sequence": index, "previous_hash": previous, "payload": payload}
        raw = json.dumps(frame, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        digest = hashlib.sha256(DOMAIN + raw).digest()
        output.extend(len(raw).to_bytes(4, "big") + raw + digest)
        previous = digest.hex()
        prefix_hashes.append(previous)
    path.write_bytes(output)


class ActualNativeOwnerJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("NATIVE_OWNER_JOURNAL_RUN")
        if not configured:
            raise RuntimeError("NATIVE_OWNER_JOURNAL_RUN must name run.json produced by the actual native_owner_journal_v1 executable")
        cls.run_path = Path(configured).resolve()
        cls.document = json.loads(cls.run_path.read_text())
        cls.checked_run = read_run_journals(cls.run_path)
        cls.checked = cls.checked_run["journals"]
        cls.paths = {item["name"]: cls.run_path.parent / item["path"] for item in cls.document["journals"]}
        cls.pins = {item["name"]: item["checkpoint"] for item in cls.document["journals"]}
        required = {"alice", "bob", "crash_recovered", "old_snapshot", "restored_without_pin", "orphan_recovered"}
        if set(cls.paths) != required:
            raise RuntimeError("the complete six-journal native scenario is required; no model fixture fallback")

    def copied(self, name="alice"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "journal"
        shutil.copytree(self.paths[name], path)
        return path

    def mutate(self, name, action):
        path = self.copied(name)
        records = read_frames(path / "journal.pnoj1")
        action(records)
        rewrite(path / "journal.pnoj1", records)
        return path

    def test_actual_complete_run_keeps_security_and_resource_qualifications_false(self):
        self.assertEqual(self.checked_run["journal_count"], 6)
        self.assertGreater(self.checked_run["record_count"], 200)
        for report in self.checked.values():
            self.assertFalse(report["fresh_resource_state_attested"])
            self.assertFalse(report["native_runtime_attested"])
            self.assertFalse(report["trusted_history_anchor"])
            self.assertFalse(report["world_coverage_attested"])
            self.assertFalse(report["physical_clock_authenticated"])
            self.assertFalse(report["six_successor_risk_qualified"])
            self.assertIsNone(report["initial_world_inventory_bound"])
            self.assertIsNone(report["probability_bound"])

    def test_unadmitted_output_then_restart_import_keeps_original_identity_and_source(self):
        block = self.document["references"]["a8_before_restart"]
        row = self.checked["alice"]["registry"][block]
        self.assertEqual(row["origin_class"], "recorded_local_production")
        self.assertEqual(row["first_seen_epoch"], 1)
        self.assertEqual(row["first_seen_sequence"], self.document["before_restart"]["registry"][block]["first_seen_sequence"])
        self.assertTrue(row["native_relation_rechecked_by_census"])
        self.assertEqual(self.checked["alice"]["epochs"], 2)
        self.assertEqual(len(self.checked["alice"]["outside_lease_intervals"]), 1)

    def test_exact_sha_join_does_not_let_invalid_same_id_inherit_valid_work(self):
        pair = self.document["invalid_same_id_packet"]
        report = self.checked["alice"]
        self.assertNotEqual(pair["sha256"], pair["valid_packet_sha256"])
        self.assertEqual(report["raw_artifacts"][pair["sha256"]]["block_id"], pair["id"])
        self.assertIn(pair["valid_packet_sha256"], report["valid_packet_bindings"])
        self.assertNotIn(pair["sha256"], report["valid_packet_bindings"])
        self.assertEqual(report["registry"][pair["id"]]["packet_sha256"], pair["valid_packet_sha256"])

    def test_native_six_successor_confirmation_rechecks_real_transaction_membership(self):
        observations = self.checked["alice"]["confirmations"]
        confirmed = next(item for item in observations if item["checked"]["confirmed"])
        self.assertTrue(confirmed["checked"]["six_successor_profile"])
        self.assertTrue(confirmed["checked"]["membership_rechecked_by_reader"])
        weight = int(self.checked["alice"]["registry"][self.document["references"]["target_block"]]["required_work_hex"], 16)
        self.assertGreaterEqual(confirmed["checked"]["inclusive_K"], 7 * weight)

    def test_actual_strict_reorg_partitions_native_suffix_once(self):
        witnesses = self.checked["alice"]["rollback_witnesses"]
        self.assertEqual(len(witnesses), 1)
        witness = witnesses[0]
        self.assertEqual(sum(witness["origin_partition"].values()), witness["competing_suffix_weight"])
        self.assertGreater(witness["competing_suffix_weight"], witness["incumbent_suffix_weight"])
        self.assertEqual(len(witness["competing_suffix"]), len(set(witness["competing_suffix"])))
        self.assertEqual(witness["new_tip"], self.document["references"]["b8"])
        self.assertIsNone(witness["global_adversarial_weight_lower_bound"])

    def test_real_process_exit_preserves_pending_intent_despite_expected_recovered_tip(self):
        report = self.checked["crash_recovered"]
        self.assertEqual(self.document["crash_child"]["exit_code"], 23)
        self.assertIn('"native_activation_returned_success":true', self.document["crash_child"]["stdout"])
        self.assertEqual(len(report["unresolved_intents"]), 1)
        self.assertEqual(report["unresolved_intents"][0]["operation"], "activate_observed")
        self.assertTrue(report["unresolved_intents"][0]["prepared"])
        self.assertEqual(report["last_census"]["active_tip"], self.document["references"]["b8"])
        self.assertFalse(report["all_recorded_intents_have_terminal_observations"])
        self.assertTrue(report["confirmation_failures"])

    def test_saved_checkpoint_refuses_actual_old_db_and_sidecar_prefix(self):
        self.assertEqual(self.document["stale_checkpoint_refusal"], "OWNER_JOURNAL_CHECKPOINT")
        with self.assertRaisesRegex(CertificateError, "J_CHECKPOINT_MISMATCH"):
            read_journal(self.paths["old_snapshot"], self.pins["crash_recovered"])
        old = read_journal(self.paths["old_snapshot"])
        self.assertFalse(old["trusted_history_anchor"])
        self.assertFalse(old["fresh_resource_state_attested"])
        self.assertIsNone(old["supplied_checkpoint_matches"])

    def test_real_orphan_recovery_keeps_unresolved_production_and_unknown_origin(self):
        report = self.checked["orphan_recovered"]
        self.assertEqual(len(report["orphan_artifact_observations"]), 1)
        self.assertEqual(len(report["registry"]), 1)
        self.assertEqual(len(report["unresolved_intents"]), 1)
        self.assertEqual(report["unresolved_intents"][0]["operation"], "make")
        row = next(iter(report["registry"].values()))
        self.assertEqual(row["origin_class"], "gap_or_recovery_discovery")
        self.assertTrue(row["native_relation_rechecked_by_census"])
        self.assertFalse(self.document["orphan_before_admit"]["registry"])

    def test_future_maturity_and_validation_clock_rewind_do_not_recredit_outputs(self):
        report = self.checked["alice"]
        self.assertTrue(report["clock_regressions"])
        block = self.document["references"]["future_child"]
        deferred = {row["id"]: row for row in self.document["deferred"]["rows"]}
        mature = {row["id"]: row for row in self.document["mature"]["rows"]}
        self.assertFalse(deferred[block]["ancestry_time_eligible"])
        self.assertTrue(mature[block]["ancestry_time_eligible"])
        self.assertEqual(deferred[block]["required_work_hex"], mature[block]["required_work_hex"])
        self.assertIn(block, report["registry"])
        self.assertFalse(report["physical_clock_authenticated"])

    def test_hidden_remote_branch_leaves_same_actual_local_view(self):
        self.assertEqual(self.document["before_hidden"]["local_view_commitment"],
                         self.document["after_hidden"]["local_view_commitment"])
        self.assertGreater(len(self.checked["bob"]["registry"]), 0)
        self.assertIsNone(self.checked["alice"]["initial_world_inventory_bound"])

    def test_torn_tail_rejects_entire_certificate_without_truncation(self):
        path = self.copied()
        journal = path / "journal.pnoj1"
        with journal.open("ab") as output:
            output.write(b"\0")
        before = journal.read_bytes()
        with self.assertRaisesRegex(CertificateError, "J_TORN_TAIL"):
            read_journal(path)
        self.assertEqual(journal.read_bytes(), before)

    def test_missing_referenced_packet_rejects_full_artifact_coverage(self):
        path = self.copied()
        digest = next(iter(self.checked["alice"]["valid_packet_bindings"]))
        (path / "packets" / f"{digest}.pnp1").unlink()
        with self.assertRaisesRegex(CertificateError, "J_ARTIFACT_FILE"):
            read_journal(path)

    def test_hash_valid_recovery_record_cannot_erase_old_pending_intent(self):
        def edit(records):
            record = next(item for item in records if item["payload"]["kind"] == "open_intent"
                          and item["payload"]["prior_unresolved_intents"])
            record["payload"]["prior_unresolved_intents"] = []
        path = self.mutate("crash_recovered", edit)
        with self.assertRaisesRegex(CertificateError, "J_GAP_ERASURE"):
            read_journal(path)

    def test_new_session_or_nonce_cannot_claim_fresh_initial_state(self):
        path = self.mutate("alice", lambda records: records[0]["payload"].update(fresh_resource_state_attested=True))
        with self.assertRaisesRegex(CertificateError, "J_ESCALATION"):
            read_journal(path)

    def test_native_weight_cannot_be_replaced_by_research_credit(self):
        def edit(records):
            record = next(item for item in records if len(item["payload"].get("census", {}).get("rows", [])) > 1)
            census = record["payload"]["census"]
            census["rows"][1]["required_work_hex"] = f"{16:0128x}"
            census["local_view_commitment"] = local_commitment(census)
        path = self.mutate("alice", edit)
        with self.assertRaisesRegex(CertificateError, "REQUIRED_WORK"):
            read_journal(path)

    def test_confirmation_cannot_name_transaction_absent_from_real_block_body(self):
        def edit(records):
            terminal = next(item["payload"] for item in records if item["payload"]["kind"] == "terminal"
                            and item["payload"].get("operation") == "confirmation" and item["payload"]["result"]["ok"])
            terminal["result"]["value"]["transaction"] = "00" * 32
            records[terminal["intent_sequence"]]["payload"]["input"]["transaction"] = "00" * 32
        path = self.mutate("alice", edit)
        with self.assertRaisesRegex(CertificateError, "J_CONFIRM_TRANSACTION_MEMBERSHIP"):
            read_journal(path)

    def test_census_result_cannot_borrow_another_owner_identity(self):
        def edit(records):
            terminal = next(item["payload"] for item in records if item["payload"]["kind"] == "terminal"
                            and item["payload"].get("operation") == "census")
            terminal["result"]["value"]["owner_process_id"] += 1
        path = self.mutate("alice", edit)
        with self.assertRaisesRegex(CertificateError, "J_CENSUS_CALL_RESULT"):
            read_journal(path)

    def test_open_process_identity_must_match_the_actual_owner_census(self):
        def edit(records):
            opening = next(item["payload"] for item in records if item["payload"]["kind"] == "open_intent")
            opening["process_id"] += 1
        path = self.mutate("alice", edit)
        with self.assertRaisesRegex(CertificateError, "J_OWNER_PROCESS_BINDING"):
            read_journal(path)

    def test_native_stop_error_cannot_be_followed_by_a_same_lease_call(self):
        def edit(records):
            terminal = next(item["payload"] for item in records if item["payload"]["kind"] == "terminal"
                            and not item["payload"]["result"]["ok"])
            terminal["result"]["requires_owner_stop"] = True
        path = self.mutate("alice", edit)
        with self.assertRaisesRegex(CertificateError, "J_NATIVE_STOP_REQUIRED"):
            read_journal(path)

    def test_unreferenced_actual_packet_is_visible_debt_without_effective_credit(self):
        path = self.copied("old_snapshot")
        pair = self.document["invalid_same_id_packet"]
        digest = pair["sha256"]
        shutil.copyfile(self.paths["alice"] / "packets" / f"{digest}.pnp1", path / "packets" / f"{digest}.pnp1")
        report = read_journal(path)
        self.assertEqual([item["sha256"] for item in report["unreferenced_artifacts"]], [digest])
        self.assertNotIn(digest, report["valid_packet_bindings"])
        self.assertFalse(report["fresh_resource_state_attested"])

    def test_orphan_origin_cannot_be_promoted_by_a_later_valid_admission(self):
        report = self.checked["orphan_recovered"]
        orphan = report["orphan_artifact_observations"][0]
        row = report["registry"][orphan["block_id"]]
        self.assertEqual(row["first_seen_sequence"], orphan["open_intent_sequence"])
        self.assertEqual(report["raw_artifact_sources"][orphan["sha256"]]["origin_class"], "gap_or_recovery_discovery")
        self.assertIn(orphan["sha256"], report["valid_packet_bindings"])
        self.assertFalse(report["all_recorded_intents_have_terminal_observations"])


if __name__ == "__main__":
    unittest.main()
