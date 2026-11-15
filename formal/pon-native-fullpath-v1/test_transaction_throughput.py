"""Accounting adversaries; synthetic packets never certify work or performance."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import fullpath_gate as gate
import transaction_throughput as throughput
from test_adapt_native import OriginalCollector
from test_fullpath_gate import Campaign, envelope, progress


def transaction(nonce=1, signature_byte=0):
    payload = bytes([2]) * 32 + struct.pack("<Q", 1)
    return (b"PNX1" + bytes([1]) * 32 + bytes([3]) * 32
            + struct.pack("<QQQ", nonce, 1000, 1_000_000) + b"\x01"
            + struct.pack("<H", len(payload)) + payload + bytes([signature_byte]) * 64)


def packet_with_transactions(transactions=(), **kwargs):
    original = envelope(**kwargs)
    header = bytearray(original[4:4 + gate.HEADER_BYTES])
    header[186:218] = gate.sequence_root(transactions)
    body = struct.pack("<H", len(transactions)) + b"".join(
        struct.pack("<H", len(tx)) + tx for tx in transactions)
    return b"PNP2" + bytes(header) + body + original[4 + gate.HEADER_BYTES + 2:]


class TransactionCampaign(Campaign):
    def __init__(self, root, transactions=None, target="ff" * 32, nonce=0,
                 parent="03" * 32, height=1):
        super().__init__(root)
        if transactions is None:
            transactions = [transaction()]
        self.raw = packet_with_transactions(transactions, target=target, nonce=nonce,
                                            parent=parent, height=height)
        self.packet = gate.parse_packet(self.raw)
        self.packet_ref = self.put("packet.pnp2", self.raw)
        self.base_work = height * ((1 << 256) // (int(target, 16) + 1))
        for phase in gate.PHASES:
            receipt = self.native_event(gate.EVENTS[phase])
            if phase == "search":
                receipt["nonce_attempts"] = nonce + 1
            if phase == "verification":
                receipt.update(work_progress=progress(), admission_call_ns=10,
                               admission_reused_existing=False, admitted_block_hex=self.packet["block_hex"])
            if phase == "acceptance":
                receipt["native_observation"] = self.snapshot()
            self.receipts[phase] = receipt
            self.refresh_phase(phase)
        self.manifest.update(required_depth=6, observation_end_ns=throughput.WINDOW_NS)
        self.manifest["schedule"][0].update(deadline_ns=throughput.WINDOW_NS,
                                            reorg_observe_until_ns=throughput.WINDOW_NS,
                                            parent_hex=parent)
        for phase in self.row["stages"]:
            phase["claim_sha256"] = self.packet["claim_sha256"]
        self.row.update(packet=self.packet_ref, claim=self.packet["claim"], wire_bytes=len(self.raw))
        self.row["canonical_checks"] = [
            dict(at_ns=600, receipt=self.row["stages"][-1]["receipt"], canonical_path=[self.packet_ref]),
            dict(at_ns=throughput.WINDOW_NS, receipt=self.put_json("final.json", self.snapshot()),
                 canonical_path=[self.packet_ref])]
        self.report["observed_through_ns"] = throughput.WINDOW_NS
        self.report["resources"]["wire_bytes"] = len(self.raw)

    def snapshot(self, depth=0, tip=None, delta=0, member=True, stored=True):
        value = super().observation(depth=depth, tip=tip, member=member, stored=stored)
        value["block_chainwork_hex"] = f"{self.base_work:0128x}" if stored else None
        value["active_tip_chainwork_hex"] = f"{self.base_work + delta:0128x}"
        value["active_work_depth_hex"] = f"{delta:0128x}" if member else None
        return value

    def add_descendants(self, count=6, target="ff" * 32, at_ns=1_000_000_000):
        current = self.packet
        path = [self.packet_ref]
        delta = 0
        for index in range(count):
            raw = packet_with_transactions(parent=current["block_hex"], height=current["height"] + 1,
                                           nonce=index + 1, target=target)
            current = gate.parse_packet(raw)
            path.append(self.put(f"descendant-{index}.pnp2", raw))
            delta += (1 << 256) // (int(target, 16) + 1)
        value = self.snapshot(count, current, delta)
        reference = self.put_json("depth.json", value)
        self.row["canonical_checks"] = [self.row["canonical_checks"][0],
            dict(at_ns=at_ns, receipt=reference, canonical_path=path)]
        if at_ns < throughput.WINDOW_NS:
            self.row["canonical_checks"].append(dict(at_ns=throughput.WINDOW_NS,
                                                       receipt=reference, canonical_path=path))
        self.report["observed_through_ns"] = max(at_ns, throughput.WINDOW_NS)

    def write(self):
        reference = self.put_json("manifest.json", self.manifest)
        self.report["manifest_sha256"] = reference["sha256"]
        self.put_json("observations.json", self.report)
        return reference["sha256"]

    def read(self):
        return throughput.read_fullpath(self.root, self.write())

    def additional(self, other, identity="again", prefix="other/"):
        planned = copy.deepcopy(other.manifest["schedule"][0])
        planned["id"] = identity
        self.manifest["schedule"].append(planned)
        row = copy.deepcopy(other.row)
        row["id"] = identity
        visited = set()

        def relative(reference):
            if reference is not None and id(reference) not in visited:
                visited.add(id(reference))
                reference["path"] = prefix + reference["path"]

        relative(row["packet"])
        for stage in row["stages"]:
            relative(stage["receipt"])
        for check in row["canonical_checks"]:
            relative(check["receipt"])
            for reference in check["canonical_path"]:
                relative(reference)
        self.report["attempts"].append(row)
        for field in ("cpu_ns", "wire_bytes"):
            self.report["resources"][field] += row[field]
        self.report["resources"]["peak_rss_bytes"] = max(self.report["resources"]["peak_rss_bytes"],
                                                         row["peak_rss_bytes"])
        return row


class TransactionObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.c = TransactionCampaign(self.root)

    def test_depth_zero_admission_is_not_independent_confirmation(self):
        result = self.c.read()
        self.assertEqual(result["fullpath_readback"]["recorded_unique_new_native_blocks"], 1)
        self.assertEqual(result["observed_unique_packet_transactions"], 1)
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 0)
        self.assertIsNone(result["observed_independently_confirmed_transactions"])
        self.assertIsNone(result["qualified_confirmed_tps"])

    def test_depth_and_work_eligibility_has_separate_exact_observation_rate(self):
        self.c.add_descendants()
        result = self.c.read()
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 1)
        self.assertEqual(result["eligibility_observation_rate"],
                         dict(numerator=1, denominator=4, unit="transactions/second"))
        self.assertIsNone(result["independent_confirmation_observation_rate"])
        self.assertFalse(result["exact_transaction_offer_denominator_known"])
        self.assertIsNone(result["preregistered_unique_transaction_offers"])

    def test_six_easy_descendants_do_not_pay_harder_included_work(self):
        self.c = TransactionCampaign(self.root, target="7f" + "ff" * 31)
        self.c.add_descendants()
        result = self.c.read()
        self.assertEqual(result["fullpath_readback"]["timely_accepted_progress"], 1)
        self.assertEqual(result["attempts"][0]["required_work_delta_hex"], f"{12:0128x}")
        self.assertEqual(result["attempts"][0]["canonical_checks"][-1]["work_delta_hex"], f"{6:0128x}")
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 0)

    def test_hard_descendants_pay_both_conditions(self):
        self.c = TransactionCampaign(self.root, target="7f" + "ff" * 31)
        self.c.add_descendants(target="7f" + "ff" * 31)
        self.assertEqual(self.c.read()["observed_unique_depth_and_work_eligible_transactions"], 1)

    def test_insufficient_depth_fails_even_with_sufficient_work(self):
        self.c.add_descendants(count=3, target="3f" + "ff" * 31)
        self.assertEqual(self.c.read()["observed_unique_depth_and_work_eligible_transactions"], 0)

    def test_exact_original_deadline_is_late(self):
        self.c.add_descendants(at_ns=throughput.WINDOW_NS)
        result = self.c.read()
        self.assertEqual(result["fullpath_readback"]["timely_accepted_progress"], 1)
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 0)
        self.assertFalse(result["attempts"][0]["timely_depth_and_work_eligible"])

    def test_late_confirmation_remains_late(self):
        self.c.add_descendants(at_ns=throughput.WINDOW_NS + 1)
        result = self.c.read()
        self.assertEqual(result["attempts"][0]["first_depth_and_work_eligible_ns"], throughput.WINDOW_NS + 1)
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 0)

    def test_empty_block_growth_has_zero_transaction_numerator(self):
        self.c = TransactionCampaign(self.root, transactions=[])
        self.c.add_descendants()
        result = self.c.read()
        self.assertEqual(result["fullpath_readback"]["timely_accepted_progress"], 1)
        self.assertEqual(result["observed_unique_packet_transactions"], 0)
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 0)

    def test_two_entries_of_same_transaction_count_once(self):
        self.c = TransactionCampaign(self.root, transactions=[transaction(), transaction()])
        self.c.add_descendants()
        result = self.c.read()
        self.assertEqual(result["attempts"][0]["duplicate_transaction_entries"], 1)
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 1)

    def test_two_distinct_transactions_have_distinct_numerator(self):
        self.c = TransactionCampaign(self.root, transactions=[transaction(), transaction(nonce=2)])
        self.c.add_descendants()
        result = self.c.read()
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 2)
        self.assertEqual(result["eligibility_observation_rate"]["numerator"], 1)
        self.assertEqual(result["eligibility_observation_rate"]["denominator"], 2)

    def test_same_transaction_in_distinct_blocks_is_not_additional_progress(self):
        self.c.add_descendants()
        other_root = self.root / "other"
        other_root.mkdir()
        other = TransactionCampaign(other_root, nonce=11)
        other.add_descendants()
        self.c.additional(other)
        result = self.c.read()
        self.assertEqual(result["fullpath_readback"]["recorded_unique_new_native_blocks"], 2)
        self.assertEqual(result["individually_observed_unique_depth_and_work_eligible_transactions"], 1)
        self.assertIsNone(result["observed_unique_depth_and_work_eligible_transactions"])
        self.assertIsNone(result["eligibility_observation_rate"])
        self.assertFalse(result["joint_retention_cut_consistent"])
        self.assertEqual(result["transactions"][0]["observed_attempt_ids"], ["valid", "again"])

    def test_conflicting_forks_cannot_sum_distinct_transactions(self):
        self.c.add_descendants()
        other_root = self.root / "other"
        other_root.mkdir()
        other = TransactionCampaign(other_root, transactions=[transaction(nonce=2)], nonce=11)
        other.add_descendants()
        self.c.additional(other)
        result = self.c.read()
        self.assertEqual(result["individually_observed_unique_depth_and_work_eligible_transactions"], 2)
        self.assertIsNone(result["observed_unique_depth_and_work_eligible_transactions"])
        self.assertIsNone(result["eligibility_observation_rate"])
        self.assertIsNone(result["matching_start_eligible_latency"])
        self.assertIn("CONFLICTING_CANONICAL_RETENTION_CUTS", result["reason_codes"])
        self.assertEqual(len(result["retention_cut_observations"]), 2)

    def common_cut(self):
        other_root = self.root / "other"
        other_root.mkdir()
        other = TransactionCampaign(other_root, transactions=[transaction(nonce=2)], nonce=11,
                                    parent=self.c.packet["block_hex"], height=2)
        other.add_descendants()
        descendants = other.row["canonical_checks"][-1]["canonical_path"]
        tip = gate.parse_packet((other.root / descendants[-1]["path"]).read_bytes())
        path = [self.c.packet_ref] + [dict(path="other/" + ref["path"], sha256=ref["sha256"])
                                     for ref in descendants]
        snapshot = self.c.put_json("common-tip.json", self.c.snapshot(depth=7, tip=tip, delta=7))
        self.c.row["canonical_checks"] = [self.c.row["canonical_checks"][0],
            dict(at_ns=1_000_000_000, receipt=snapshot, canonical_path=path),
            dict(at_ns=throughput.WINDOW_NS, receipt=snapshot, canonical_path=path)]
        return other, self.c.additional(other)

    def test_joint_canonical_cut_can_cover_two_distinct_included_blocks(self):
        self.common_cut()
        result = self.c.read()
        self.assertTrue(result["joint_retention_cut_consistent"])
        self.assertEqual(len(result["retention_cut_observations"]), 1)
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 2)
        self.assertEqual(result["eligibility_observation_rate"],
                         dict(numerator=1, denominator=2, unit="transactions/second"))

    def test_same_tip_with_incompatible_generation_does_not_form_joint_cut(self):
        other, row = self.common_cut()
        native = gate.decode((other.root / "depth.json").read_bytes())
        native["generation"] += 1
        ref = self.c.put_json("another-generation.json", native)
        row["canonical_checks"][-1]["receipt"] = ref
        result = self.c.read()
        self.assertFalse(result["joint_retention_cut_consistent"])
        self.assertIsNone(result["observed_unique_depth_and_work_eligible_transactions"])
        self.assertIsNone(result["eligibility_observation_rate"])

    def test_duplicate_resubmission_does_not_reset_earliest_matching_start(self):
        self.c.add_descendants()
        other_root = self.root / "other"
        other_root.mkdir()
        other = TransactionCampaign(other_root, nonce=11)
        other.add_descendants(at_ns=2_000_000_000)
        row = self.c.additional(other)
        # Both starts are frozen at zero; late retry evidence cannot erase it.
        row["status"] = "duplicate"
        result = self.c.read()
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 1)
        self.assertEqual(result["transactions"][0]["first_matching_scheduled_start_ns"], 0)
        self.assertEqual(result["transactions"][0]["latency_from_first_matching_scheduled_start_ns"], 1_000_000_000)

    def test_reorg_then_recovery_preserves_loss(self):
        self.c.add_descendants()
        lost = self.c.put_json("reorg.json", self.c.snapshot(member=False))
        self.c.row["canonical_checks"].insert(2, dict(at_ns=2_000_000_000, receipt=lost, canonical_path=[]))
        result = self.c.read()
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 0)
        self.assertTrue(result["transactions"][0]["observed_reorg_or_absence_after_admission"])

    def test_exact_duplicate_receipt_can_expose_loss_of_original_admission(self):
        self.c.add_descendants()
        planned = copy.deepcopy(self.c.manifest["schedule"][0]); planned["id"] = "duplicate"
        self.c.manifest["schedule"].append(planned)
        row = copy.deepcopy(self.c.row)
        row.update(id="duplicate", status="duplicate", stages=[])
        loss = self.c.put_json("duplicate-loss.json", self.c.snapshot(member=False))
        row["canonical_checks"] = [dict(at_ns=throughput.WINDOW_NS, receipt=loss, canonical_path=[])]
        self.c.report["attempts"].append(row)
        for field in ("cpu_ns", "wire_bytes"):
            self.c.report["resources"][field] += row[field]
        self.assertEqual(self.c.read()["observed_unique_depth_and_work_eligible_transactions"], 0)

    def test_hostile_packet_sharing_tx_bytes_does_not_veto_honest_admission(self):
        self.c.add_descendants()
        hostile = self.c.add_hostile()
        altered = bytearray(self.c.raw); altered[-36] ^= 1
        parsed = gate.parse_packet(bytes(altered))
        hostile.update(packet=self.c.put("hostile.pnp2", bytes(altered)), claim=parsed["claim"])
        hostile["stages"][0]["claim_sha256"] = parsed["claim_sha256"]
        error = self.c.native_event("error")
        error.update(claim=parsed["claim"], stage="verification", error="WORK:Product", cancelled=False,
                     work_progress=progress((1, 512, 1, 0)), admission_call_ns=10)
        hostile["stages"][0]["receipt"] = self.c.put_json("hostile-error.json", error)
        absent = self.c.snapshot(member=False, stored=False)
        hostile["canonical_checks"] = [dict(at_ns=throughput.WINDOW_NS,
            receipt=self.c.put_json("hostile-absent.json", absent), canonical_path=[])]
        result = self.c.read()
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 1)
        self.assertEqual(result["outcomes"]["rejected"], 1)

    def test_missing_start_keeps_denominator_and_rate_unknown(self):
        self.c.add_descendants()
        planned = copy.deepcopy(self.c.manifest["schedule"][0]); planned["id"] = "missing"
        self.c.manifest["schedule"].append(planned)
        result = self.c.read()
        self.assertEqual(result["scheduled_starts"], 2)
        self.assertEqual(result["missing_start_ids"], ["missing"])
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 1)
        self.assertIsNone(result["eligibility_observation_rate"])

    def test_missing_packet_is_unknown_not_zero_offered_transactions(self):
        self.c.row.update(status="error", packet=None, claim=None, stages=[], canonical_checks=[])
        result = self.c.read()
        self.assertEqual(result["unknown_packet_attempt_ids"], ["valid"])
        self.assertIsNone(result["attempts"][0]["transaction_ids"])
        self.assertIsNone(result["preregistered_unique_transaction_offers"])
        self.assertIsNone(result["eligibility_observation_rate"])

    def test_incomplete_observation_window_has_no_zero_rate(self):
        self.c.report["observed_through_ns"] = throughput.WINDOW_NS - 1
        self.c.row["canonical_checks"][-1]["at_ns"] -= 1
        result = self.c.read()
        self.assertIsNone(result["eligibility_observation_rate"])
        self.assertIn("INCOMPLETE_OBSERVATION_WINDOW", result["reason_codes"])

    def test_required_depth_cannot_be_lowered_for_new_tx_reader(self):
        self.c.manifest["required_depth"] = 0
        with self.assertRaisesRegex(ValueError, "ORIGINAL_DEPTH_OR_WINDOW"):
            self.c.read()

    def test_original_window_cannot_be_extended(self):
        self.c.manifest["observation_end_ns"] += 1
        with self.assertRaisesRegex(ValueError, "ORIGINAL_DEPTH_OR_WINDOW"):
            self.c.read()

    def test_queue_start_cannot_move_deadline(self):
        self.c.manifest["schedule"][0]["deadline_ns"] -= 1
        with self.assertRaisesRegex(ValueError, "ORIGINAL_DEADLINE"):
            self.c.read()

    def test_accepted_hostile_input_does_not_become_honest_transaction_progress(self):
        self.c.add_descendants()
        self.c.manifest["schedule"][0]["cohort"] = "hostile"
        result = self.c.read()
        self.assertEqual(result["observed_unique_packet_transactions"], 1)
        self.assertEqual(result["observed_unique_depth_and_work_eligible_transactions"], 0)

    def test_regressed_snapshot_generation_refused(self):
        self.c.add_descendants()
        value = gate.decode((self.root / "depth.json").read_bytes())
        value["generation"] = 0
        self.c.row["canonical_checks"][-1]["receipt"] = self.c.put_json("stale-generation.json", value)
        with self.assertRaisesRegex(ValueError, "CANONICAL_GENERATION"):
            self.c.read()

    def test_foreign_clock_rejected(self):
        self.c.report["clock_id"] = "different-process-clock"
        with self.assertRaisesRegex(ValueError, "REPORT_CONTEXT_OR_CLOCK"):
            self.c.read()

    def test_forged_work_delta_rejected(self):
        self.c.add_descendants()
        value = gate.decode((self.root / "depth.json").read_bytes())
        value["active_work_depth_hex"] = f"{999:0128x}"
        reference = self.c.put_json("depth-forged.json", value)
        self.c.row["canonical_checks"][-1]["receipt"] = reference
        with self.assertRaisesRegex(ValueError, "CANONICAL_CHAINWORK"):
            self.c.read()

    def test_missing_parent_packet_rejected(self):
        self.c.add_descendants()
        self.c.row["canonical_checks"][-1]["canonical_path"].pop(2)
        with self.assertRaisesRegex(ValueError, "CANONICAL_PARENT_CHAIN"):
            self.c.read()

    def test_native_authority_boolean_cannot_upgrade_growth_snapshot(self):
        value = self.c.snapshot(); value["confirmation_authority"] = True
        self.c.row["canonical_checks"][-1]["receipt"] = self.c.put_json("forged-authority.json", value)
        with self.assertRaisesRegex(ValueError, "OBSERVATION_AUTHORITY"):
            self.c.read()

    def test_context_risk_or_campaign_booleans_cannot_promote_qualification(self):
        self.c.context.update(scope="campaign", risk_ledger_consistency_verified=True,
                              qualified_confirmed_tps=1000, production_activation=True)
        reference = self.c.put_json("context.json", self.c.context)
        self.c.manifest["context"] = reference
        self.c.row["context_sha256"] = self.c.report["context_sha256"] = reference["sha256"]
        self.c.add_descendants()
        result = self.c.read()
        self.assertFalse(result["risk_ledger_consistency_verified"])
        self.assertFalse(result["production_activation"])
        self.assertIsNone(result["qualified_confirmed_tps"])

    def test_every_signature_byte_is_in_transaction_identity(self):
        a = throughput.transaction_identities(packet_with_transactions([transaction()]))[0]
        b = throughput.transaction_identities(packet_with_transactions([transaction(signature_byte=1)]))[0]
        self.assertNotEqual(a["transaction"], b["transaction"])
        self.assertNotEqual(a["sha256"], b["sha256"])

    def test_mutated_committed_body_rejected_before_transaction_counting(self):
        raw = bytearray(self.c.raw); raw[4 + gate.HEADER_BYTES + 4 + 100] ^= 1
        with self.assertRaisesRegex(ValueError, "BODY_COMMITMENT"):
            throughput.transaction_identities(bytes(raw))

    def test_one_sample_does_not_create_tail_estimates(self):
        self.c.add_descendants()
        samples = self.c.read()["matching_start_eligible_latency"]
        self.assertEqual(samples["samples"], 1)
        for p in (50, 95, 99):
            self.assertIsNone(samples[f"p{p}_ns"])

    def test_frozen_manifest_hash_is_external(self):
        self.c.write()
        with self.assertRaisesRegex(ValueError, "FROZEN_MANIFEST_HASH"):
            throughput.read_fullpath(self.root, "ff" * 32)

    def test_duplicate_json_keys_cannot_change_confirmation_inputs(self):
        sha = self.c.write()
        raw = (self.root / "observations.json").read_bytes()
        (self.root / "observations.json").write_bytes(raw[:-2] + b',"clock_id":"forged"}\n')
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
            throughput.read_fullpath(self.root, sha)

    def test_oversized_or_symlink_packet_refused(self):
        original = self.root / "packet.pnp2"
        moved = self.root / "elsewhere.pnp2"
        original.rename(moved)
        original.symlink_to(moved)
        with self.assertRaises(OSError):
            self.c.read()

    def test_cli_reports_valid_hold_and_invalid_evidence_separately(self):
        sha = self.c.write()
        with redirect_stdout(io.StringIO()) as out:
            code = throughput.main(["fullpath", str(self.root), "--manifest-sha256", sha])
        self.assertEqual(code, 1)
        self.assertIsNone(json.loads(out.getvalue())["qualified_confirmed_tps"])
        with redirect_stdout(io.StringIO()) as out:
            code = throughput.main(["fullpath", str(self.root), "--manifest-sha256", "ff" * 32])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out.getvalue())["evidence_valid"])


class OriginalProcessProjectionTests(unittest.TestCase):
    def test_original_processes_are_rechecked_and_never_new_preregistration(self):
        with tempfile.TemporaryDirectory() as directory:
            original = OriginalCollector(directory)
            before = (original.root / "preregistration.json").read_bytes()
            result = throughput.read_original(directory, original.plan_ref["sha256"])
            self.assertEqual(result["scheduled_starts"], 4)
            self.assertEqual(result["outcomes"], dict(accepted=1, duplicate=1, rejected=1, cancelled=1))
            self.assertTrue(result["original_process_records_rechecked"])
            self.assertFalse(result["normalization_is_new_preregistration"])
            self.assertIsNone(result["eligibility_observation_rate"])
            self.assertEqual((original.root / "preregistration.json").read_bytes(), before)
            self.assertEqual(throughput.read_original(directory, original.plan_ref["sha256"]), result)

    def test_original_process_record_cannot_be_replaced_by_cached_green_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            original = OriginalCollector(directory)
            throughput.read_original(directory, original.plan_ref["sha256"])
            changed = copy.deepcopy(original.processes[0]); changed["exit_code"] = 9
            original.c.put_json("produce.process.json", changed)
            with self.assertRaisesRegex(ValueError, "PROCESS_ROW_DIFFERS_FROM_ORIGINAL"):
                throughput.read_original(directory, original.plan_ref["sha256"])


class HostProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(throughput.ROOT / "scripts" / "ci"))
        from test_run_from_zero_native import simulated_confirmation_report, ConfirmationObservationTests
        cls.fixture = staticmethod(simulated_confirmation_report)
        cls.fail_pressure = staticmethod(ConfirmationObservationTests.fail_pressure)

    def read(self, change=lambda doc: None):
        document = self.fixture()
        change(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            raw = gate.canonical(document) + b"\n"
            path.write_bytes(raw)
            return throughput.read_host_report(path, gate.sha256(raw))

    def test_host_projection_reuses_native_binding_and_keeps_cohorts_separate(self):
        result = self.read()
        self.assertTrue(result["simulated_control"])
        self.assertIsNone(result["aggregate_confirmation_rate"])
        self.assertIsNone(result["qualified_confirmed_tps"])
        self.assertFalse(result["native_origin_authenticated"])
        for phase in result["phases"]:
            self.assertEqual(phase["signed_submit_ack"]["successful_in_original_window"], 7)
            self.assertEqual(phase["supported_independent_confirmation_count"], 1)
            self.assertEqual(phase["independent_confirmation_observation_rate"]["denominator"], 4)

    def test_ack_and_history_do_not_replace_failed_confirmation(self):
        result = self.read(self.fail_pressure)
        pressure = result["phases"][1]
        self.assertFalse(result["original_gate_consistency_validated"])
        self.assertEqual(pressure["signed_submit_ack"]["successful_in_original_window"], 7)
        self.assertEqual(pressure["supported_independent_confirmation_count"], 0)
        self.assertEqual(pressure["independent_confirmation_observation_rate"]["numerator"], 0)
        self.assertTrue(pressure["reported_zero_has_full_censor_window"])

    def test_missing_native_confirmation_remains_unknown(self):
        def change(doc):
            self.fail_pressure(doc)
            del doc["phases"][1]["client_confirmed_transactions"]
        pressure = self.read(change)["phases"][1]
        self.assertIsNone(pressure["supported_independent_confirmation_count"])
        self.assertIsNone(pressure["independent_confirmation_observation_rate"])
        self.assertTrue(pressure["missing_confirmation_count"])

    def test_zero_cannot_hide_in_window_positive_native_observation(self):
        def change(doc):
            phase = doc["phases"][1]
            phase["client_confirmed_transactions"] = 0
            phase["client_confirmed_before_original_window_end"] = False
            replay = phase["independent_history_page_replay"][-1]
            replay["replay_ended_ns"] = throughput.WINDOW_NS
            replay["replay_wall_ns"] = throughput.WINDOW_NS - replay["replay_started_ns"]
        result = self.read(change)
        pressure = result["phases"][1]
        self.assertEqual(pressure["reported_independently_confirmed_in_window"], 0)
        self.assertTrue(pressure["recorded_native_confirmation"]["confirmed"])
        self.assertEqual(pressure["recorded_confirmation_ended_ns"], 1000)
        self.assertIsNone(pressure["supported_independent_confirmation_count"])
        self.assertIsNone(pressure["independent_confirmation_observation_rate"])
        self.assertTrue(result["confirmation_record_inconsistencies"])

    def test_late_positive_preserves_original_zero_in_window_outcome(self):
        def change(doc):
            phase = doc["phases"][1]
            phase.update(client_confirmed_transactions=0, client_confirmed_before_original_window_end=False,
                         confirmation_ended_ns=throughput.WINDOW_NS + 100,
                         client_confirmation_latency_ns=throughput.WINDOW_NS + 100 - phase["business_started_ns"])
            replay = phase["independent_history_page_replay"][-1]
            replay["replay_ended_ns"] = throughput.WINDOW_NS + 1
            replay["replay_wall_ns"] = replay["replay_ended_ns"] - replay["replay_started_ns"]
            phase["independent_final_confirmation_stage"].update(
                confirmation_started_ns=throughput.WINDOW_NS + 2,
                confirmation_ended_ns=throughput.WINDOW_NS + 3, confirmation_wall_ns=1)
        result = self.read(change)
        pressure = result["phases"][1]
        self.assertTrue(pressure["recorded_native_confirmation"]["confirmed"])
        self.assertEqual(pressure["supported_independent_confirmation_count"], 0)
        self.assertEqual(pressure["independent_confirmation_observation_rate"]["numerator"], 0)
        self.assertIsNone(pressure["confirmation_record_inconsistency"])

    def test_untimed_positive_with_zero_aggregate_keeps_supported_count_unknown(self):
        def change(doc):
            phase = doc["phases"][1]
            phase.update(client_confirmed_transactions=0, client_confirmed_before_original_window_end=False,
                         confirmation_ended_ns=None, client_confirmation_latency_ns=None)
            replay = phase["independent_history_page_replay"][-1]
            replay["replay_ended_ns"] = throughput.WINDOW_NS
            replay["replay_wall_ns"] = throughput.WINDOW_NS - replay["replay_started_ns"]
        pressure = self.read(change)["phases"][1]
        self.assertIsNone(pressure["supported_independent_confirmation_count"])
        self.assertIsNone(pressure["independent_confirmation_observation_rate"])
        self.assertIsNotNone(pressure["confirmation_record_inconsistency"])

    def test_zero_with_short_capture_has_unknown_complete_window_rate(self):
        def change(doc):
            self.fail_pressure(doc)
            replay = doc["phases"][1]["independent_history_page_replay"][0]
            replay.update(replay_ended_ns=200, replay_wall_ns=95)
        pressure = self.read(change)["phases"][1]
        self.assertEqual(pressure["reported_independently_confirmed_in_window"], 0)
        self.assertIsNone(pressure["supported_independent_confirmation_count"])
        self.assertIsNone(pressure["independent_confirmation_observation_rate"])

    def test_positive_depth_zero_report_refused_not_converted_to_measured_zero(self):
        with self.assertRaises(ValueError):
            self.read(lambda d: d["phases"][1]["independent_client_confirmation"].update(depth=0))

    def test_positive_underpaid_work_report_refused(self):
        with self.assertRaises(ValueError):
            self.read(lambda d: d["phases"][1]["independent_client_confirmation"].update(work_delta="00" * 64))

    def test_exact_four_second_native_confirmation_is_late(self):
        def change(doc):
            phase = doc["phases"][1]
            phase.update(confirmation_ended_ns=throughput.WINDOW_NS,
                         client_confirmation_latency_ns=throughput.WINDOW_NS - phase["business_started_ns"])
        with self.assertRaises(ValueError):
            self.read(change)

    def test_positive_cannot_borrow_other_transaction_receipt(self):
        with self.assertRaises(ValueError):
            self.read(lambda d: d["phases"][0]["independent_client_confirmation"].update(transaction="ff" * 32))

    def test_reorged_positive_native_observation_refused(self):
        with self.assertRaises(ValueError):
            self.read(lambda d: d["phases"][0]["independent_client_confirmation"].update(reorged=True))

    def test_unreturned_independent_confirmation_cannot_count(self):
        with self.assertRaises(ValueError):
            self.read(lambda d: d["phases"][0]["independent_final_confirmation_stage"].update(observation_returned=False))

    def test_host_report_requires_external_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(gate.canonical(self.fixture()))
            with self.assertRaisesRegex(ValueError, "HOST_REPORT_HASH_MISMATCH"):
                throughput.read_host_report(path, "ff" * 32)

    def test_host_snapshot_duplicate_json_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            raw = b'{"schema":"x","schema":"public-v3-signed-confirmation-pressure-v1"}'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
                throughput.read_host_report(path, gate.sha256(raw))


class ArithmeticTests(unittest.TestCase):
    def test_rate_null_zero_and_noninteger(self):
        self.assertIsNone(throughput.rate(None))
        self.assertEqual(throughput.rate(0), dict(numerator=0, denominator=1, unit="transactions/second"))
        for value in (True, 1.0, -1):
            with self.assertRaises(ValueError):
                throughput.rate(value)

    def test_tail_sample_resolution_is_not_population_qualification(self):
        two = throughput.latency_samples([1, 9])
        self.assertEqual(two["p50_ns"], 1)
        self.assertIsNone(two["p95_ns"])
        self.assertIsNone(two["p99_ns"])
        self.assertEqual(throughput.latency_samples(list(range(20)))["p95_ns"], 18)
        self.assertEqual(throughput.latency_samples(list(range(100)))["p99_ns"], 98)


if __name__ == "__main__":
    unittest.main()
