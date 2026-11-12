"""Actual native PNRL1 evidence is mandatory; negatives mutate private copies."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from native_execution_certificate import CertificateError, canonical
from native_owner_journal import DOMAIN as NATIVE_DOMAIN, MAGIC as NATIVE_MAGIC
import native_risk_ledger as risk
from native_risk_ledger import DOMAIN, MAGIC, read_frames, read_risk_ledger, read_run


def rewrite(path: Path, records: list[dict], magic=MAGIC, domain=DOMAIN):
    output, previous = bytearray(magic), "00" * 32
    for index, frame in enumerate(records):
        value = {"sequence": index, "previous_hash": previous, "payload": frame["payload"]}
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        digest = hashlib.sha256(domain + raw).digest()
        output.extend(len(raw).to_bytes(4, "big") + raw + digest)
        previous = digest.hex()
    path.write_bytes(output)


def remove_start(records, removed_sequence):
    retained = [frame for frame in records if frame["sequence"] != removed_sequence
                and not (frame["payload"].get("kind") == "outcome"
                         and frame["payload"]["start_sequence"] == removed_sequence)]
    mapping = {frame["sequence"]: index for index, frame in enumerate(retained)}
    spent = 0
    for frame in retained:
        p = frame["payload"]
        if p["kind"] == "start":
            spent += p["allowance_units"]
            p["spent_units"] = spent
        elif p["kind"] == "outcome":
            p["start_sequence"] = mapping[p["start_sequence"]]
        elif p["kind"] in ("lease_open", "lease_end"):
            p["spent_units"] = spent
            if p["kind"] == "lease_open":
                p["prior_unresolved_starts"] = [mapping[i] for i in p["prior_unresolved_starts"] if i != removed_sequence]
    return retained


def exact_prefix(raw: bytes, last_sequence: int) -> bytes:
    position = 8
    for _ in range(last_sequence + 1):
        position += 4 + int.from_bytes(raw[position:position + 4], "big") + 32
    return raw[:position]


class ActualNativeRiskLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("NATIVE_RISK_LEDGER_RUN")
        if not configured:
            raise RuntimeError("NATIVE_RISK_LEDGER_RUN must name run.json from the actual native_risk_ledger_v1 executable")
        cls.path = Path(configured).resolve()
        cls.document = json.loads(cls.path.read_text())
        cls.checked = read_run(cls.path)
        cls.bank = cls.path.parent / cls.document["bank_directory"]
        cls.native = cls.path.parent / cls.document["native_directory"]
        cls.bank_pin = cls.document["bank_checkpoint"]
        cls.native_pin = cls.document["native_checkpoint"]

    def copied(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        bank = Path(temporary.name) / "bank"
        shutil.copytree(self.bank, bank)
        return bank

    def mutated(self, action):
        bank = self.copied()
        records = read_frames(bank / "risk.pnrl1")
        replacement = action(records)
        rewrite(bank / "risk.pnrl1", records if replacement is None else replacement)
        return bank

    def refused(self, bank, code, **kwargs):
        with self.assertRaisesRegex(CertificateError, code):
            read_risk_ledger(bank, self.native, **kwargs)

    def test_real_all_eight_starts_have_exact_nonrefundable_cumulative_spend(self):
        report = self.checked
        self.assertEqual(report["starts_registered"], 8)
        self.assertEqual(report["outcomes_recorded"], 6)
        self.assertEqual(report["native_confirmation_intents_covered"], 7)
        self.assertEqual(report["spent_units"], 36)
        self.assertEqual(report["remaining_units"], 4)
        self.assertEqual([row["allowance_units"] for row in report["starts"]], list(range(1, 9)))
        self.assertTrue(report["all_observed_native_confirmation_intents_registered"])
        self.assertTrue(report["all_registered_starts_charged_without_refunds"])

    def test_actual_unconfirmed_error_and_repeated_success_all_remain_charged(self):
        starts = self.checked["starts"]
        self.assertFalse(starts[0]["native_confirmation_result"]["value"]["confirmed"])
        self.assertTrue(starts[1]["native_confirmation_result"]["value"]["confirmed"])
        self.assertEqual(starts[1]["statement_sha256"], starts[2]["statement_sha256"])
        self.assertFalse(starts[3]["native_confirmation_result"]["ok"])
        self.assertEqual(starts[3]["native_confirmation_result"]["error"], "MEMBERSHIP")
        self.assertTrue(all(row["charge_retained"] for row in starts))

    def test_actual_process_exits_preserve_pre_dispatch_and_post_native_pending_charges(self):
        self.assertEqual([child["exit_code"] for child in self.document["children"]], [31, 32])
        starts = self.checked["starts"]
        self.assertFalse(starts[4]["native_intent_observed"])
        self.assertFalse(starts[4]["outcome_recorded"])
        self.assertTrue(starts[6]["native_terminal_observed"])
        self.assertTrue(starts[6]["native_confirmation_result"]["value"]["confirmed"])
        self.assertFalse(starts[6]["outcome_recorded"])
        self.assertEqual(self.checked["unresolved_starts"], [starts[4]["start_sequence"], starts[6]["start_sequence"]])
        self.assertEqual(self.checked["epochs"], 5)
        self.assertFalse(self.checked["new_outcomes_for_old_pending_starts_inferred"])

    def test_complete_native_intent_enumeration_rejects_a_coherently_omitted_claim(self):
        bank = self.mutated(lambda rows: remove_start(rows, next(f["sequence"] for f in rows if f["payload"]["kind"] == "start")))
        self.refused(bank, "R_UNREGISTERED_NATIVE_CONFIRMATION")

    def test_restart_cannot_refund_a_pre_dispatch_charge(self):
        def action(rows):
            reopen = [f["payload"] for f in rows if f["payload"]["kind"] == "lease_open"][2]
            reopen["spent_units"] -= 5
        self.refused(self.mutated(action), "R_OPEN_STATE")

    def test_restart_cannot_erase_its_pending_set(self):
        def action(rows):
            reopen = [f["payload"] for f in rows if f["payload"]["kind"] == "lease_open"][2]
            reopen["prior_unresolved_starts"] = []
        self.refused(self.mutated(action), "R_OPEN_STATE")

    def test_cross_owner_native_journal_is_refused(self):
        with self.assertRaisesRegex(CertificateError, "R_NATIVE_ID"):
            read_risk_ledger(self.bank, self.path.parent / self.document["foreign_native_directory"])

    def test_a_bank_truncated_to_its_old_snapshot_cannot_cover_current_native_calls(self):
        bank = self.path.parent / self.document["old_bank_directory"]
        self.refused(bank, "R_UNREGISTERED_NATIVE_CONFIRMATION")

    def test_joint_old_snapshot_requires_a_retained_newer_pin(self):
        bank = self.path.parent / self.document["old_bank_directory"]
        native = self.path.parent / self.document["old_native_directory"]
        old = read_risk_ledger(bank, native)
        self.assertEqual(old["spent_units"], 10)
        self.assertFalse(old["latest_checkpoint_authenticated"])
        self.assertIsNone(old["supplied_bank_checkpoint_matches"])
        with self.assertRaisesRegex(CertificateError, "R_CHECKPOINT_MISMATCH"):
            read_risk_ledger(bank, native, expected_checkpoint=self.bank_pin)
        self.assertEqual(self.document["stale_bank_refusal"], "RISK_LEDGER_CHECKPOINT")

    def test_pre_dispatch_only_bank_rollback_is_not_detectable_from_unchanged_native_calls_without_pin(self):
        # Use actual child-31 cut prefixes, without rewriting any frame. Its
        # bank start is durable but no extra native confirmation intent exists.
        actual = read_frames(self.bank / "risk.pnrl1")
        start = [frame for frame in actual if frame["payload"]["kind"] == "start"][4]
        bank = self.copied()
        native = bank.parent / "native-at-child-31-cut"
        shutil.copytree(self.native, native)
        native_file = native / "journal.pnoj1"
        native_file.write_bytes(exact_prefix(native_file.read_bytes(), start["payload"]["native_before"]["sequence"]))
        bank_file = bank / "risk.pnrl1"
        bank_file.write_bytes(exact_prefix(bank_file.read_bytes(), start["sequence"]))
        pin = {"bank_id": self.bank_pin["bank_id"], "sequence": start["sequence"], "record_hash": start["record_hash"]}
        before = read_risk_ledger(bank, native, expected_checkpoint=pin)
        self.assertEqual(before["spent_units"], 15)
        self.assertEqual(len(before["unresolved_starts"]), 1)
        old_bank = self.path.parent / self.document["old_bank_directory"]
        old = read_risk_ledger(old_bank, native)
        self.assertEqual(old["spent_units"], 10)
        self.assertEqual(old["native_confirmation_intents_covered"], before["native_confirmation_intents_covered"])
        self.assertFalse(old["latest_checkpoint_authenticated"])
        with self.assertRaisesRegex(CertificateError, "R_CHECKPOINT_MISMATCH"):
            read_risk_ledger(old_bank, native, expected_checkpoint=pin)

    def test_amount_changed_without_updating_spend_is_rejected(self):
        def action(rows):
            next(f["payload"] for f in rows if f["payload"]["kind"] == "start")["allowance_units"] += 1
        self.refused(self.mutated(action), "R_BUDGET_SPEND")

    def test_coherent_posthoc_allowance_rewrite_is_detected_by_original_pin_not_self_hashing(self):
        def action(rows):
            seen = False
            for frame in rows:
                p = frame["payload"]
                if p["kind"] == "start" and not seen:
                    p["allowance_units"] += 1
                    seen = True
                if seen and "spent_units" in p:
                    p["spent_units"] += 1
        bank = self.mutated(action)
        # A self-consistent rewrite is not independently authenticated history.
        # This explicit counterexample prevents overclaiming reader chronology.
        report = read_risk_ledger(bank, self.native)
        self.assertEqual(report["spent_units"], 37)
        self.assertFalse(report["physical_pre_registration_independently_attested"])
        self.refused(bank, "R_CHECKPOINT_MISMATCH", expected_checkpoint=self.bank_pin)

    def test_scope_mismatch_cannot_be_spent_under_a_common_scope(self):
        def action(rows):
            next(f["payload"] for f in rows if f["payload"]["kind"] == "start")["law_scope_sha256"] = "55" * 32
        self.refused(self.mutated(action), "R_SCOPE_MISMATCH")

    def test_exact_transaction_and_target_bind_native_intent(self):
        for key in ("transaction", "included"):
            def action(rows, key=key):
                next(f["payload"] for f in rows if f["payload"]["kind"] == "start")[key] = "12" * 32
            self.refused(self.mutated(action), "R_NATIVE_QUERY_BINDING")

    def test_start_cannot_point_to_a_post_confirmation_checkpoint(self):
        def action(rows):
            start = next(f["payload"] for f in rows if f["payload"]["kind"] == "start")
            outcome = next(f["payload"] for f in rows if f["payload"]["kind"] == "outcome")
            start["native_before"] = copy.deepcopy(outcome["native_after"])
            start["expected_native_intent_sequence"] = start["native_before"]["sequence"] + 1
        self.refused(self.mutated(action), "R_NATIVE_DISPATCH_ORDER|R_NATIVE_QUERY_BINDING")

    def test_start_after_native_lease_end_is_rejected_without_any_later_intent(self):
        def action(rows):
            self.assertEqual(rows.pop()["payload"]["kind"], "lease_end")
            start = copy.deepcopy([f["payload"] for f in rows if f["payload"]["kind"] == "start"][-1])
            start["native_before"] = self.native_pin
            start["expected_native_intent_sequence"] = self.native_pin["sequence"] + 1
            start["allowance_units"] = 1
            start["spent_units"] = self.checked["spent_units"] + 1
            rows.append({"payload": start})
        # All seven real native intents remain covered. The extra charge is
        # nevertheless impossible for the source owner, whose lease is closed.
        self.refused(self.mutated(action), "R_NATIVE_START_STATE")

    def test_start_requires_an_idle_native_prefix_in_the_same_owner_epoch(self):
        bank_frames = read_frames(self.bank / "risk.pnrl1")
        native_frames = risk.read_native_frames(self.native / "journal.pnoj1")
        for bank_cut, native_cut, kind in ((2, 3, "intent"), (2, 4, "prepared"),
                                           (10, 79, "open_intent"), (10, 80, "open_observed")):
            with self.subTest(native_cut=native_cut, kind=kind):
                before = native_frames[native_cut]
                self.assertEqual(before["payload"]["kind"], kind)
                bank = self.copied()
                native = bank.parent / "native-cut"
                shutil.copytree(self.native, native)
                native_file = native / "journal.pnoj1"
                native_file.write_bytes(exact_prefix(native_file.read_bytes(), native_cut))
                rows = copy.deepcopy(bank_frames[:bank_cut])
                start = copy.deepcopy(bank_frames[2]["payload"])
                start["native_before"] = {"journal_id": self.native_pin["journal_id"],
                                          "sequence": native_cut, "record_hash": before["record_hash"]}
                start["expected_native_intent_sequence"] = native_cut + 1
                start["allowance_units"] = 1
                start["spent_units"] = (0 if bank_cut == 2 else 10) + 1
                rows.append({"payload": start})
                rewrite(bank / "risk.pnrl1", rows)
                with self.assertRaisesRegex(CertificateError, "R_NATIVE_START_STATE"):
                    read_risk_ledger(bank, native)

    def test_start_cannot_follow_a_recorded_native_owner_stop(self):
        bank = self.copied()
        native = bank.parent / "native-recorded-stop"
        shutil.copytree(self.native, native)
        native_file = native / "journal.pnoj1"
        native_frames = risk.read_native_frames(native_file)[:78]
        last = native_frames[-1]["payload"]
        self.assertEqual((last["kind"], last["result"]["error"]), ("terminal", "MEMBERSHIP"))
        # Hostile but self-consistent record mutation. It is not a new claim
        # that the actual membership error required the real owner to stop.
        last["result"]["requires_owner_stop"] = True
        rewrite(native_file, native_frames, NATIVE_MAGIC, NATIVE_DOMAIN)
        native_frames = risk.read_native_frames(native_file)
        rows = read_frames(bank / "risk.pnrl1")[:10]
        rows[-1]["payload"]["confirmation_wrapper_result"]["requires_owner_stop"] = True
        rows[0]["payload"]["native_journal_header_hash"] = native_frames[0]["record_hash"]
        for frame in rows:
            for key in ("native_anchor", "native_checkpoint", "native_before", "native_after"):
                pin = frame["payload"].get(key)
                if pin is not None:
                    pin["record_hash"] = native_frames[pin["sequence"]]["record_hash"]
        start = copy.deepcopy(rows[-2]["payload"])
        start["native_before"] = copy.deepcopy(rows[-1]["payload"]["native_after"])
        start["expected_native_intent_sequence"] = start["native_before"]["sequence"] + 1
        start["allowance_units"] = 1
        start["spent_units"] = 11
        rows.append({"payload": start})
        rewrite(bank / "risk.pnrl1", rows)
        with self.assertRaisesRegex(CertificateError, "R_NATIVE_START_STATE"):
            read_risk_ledger(bank, native)

    def test_native_outcome_cannot_be_changed_to_hide_an_actual_error(self):
        def action(rows):
            outcomes = [f["payload"] for f in rows if f["payload"]["kind"] == "outcome"]
            outcomes[3]["confirmation_wrapper_result"] = copy.deepcopy(outcomes[1]["confirmation_wrapper_result"])
        self.refused(self.mutated(action), "R_NATIVE_OUTCOME_BINDING")

    def test_native_outcome_preserves_boolean_integer_and_float_types(self):
        # The retained native results stay unchanged. Each independently
        # rehashed bank copy has a different typed value that Python equality
        # nevertheless considers equal to that original terminal result.
        aliases = (
            (0, "confirmed", 0),
            (0, "confirmed", 0.0),
            (0, "confirmed", -0.0),
            (1, "confirmed", 1),
            (1, "confirmed", 1.0),
            (0, "included_height", 1.0),
            (0, "included_height", True),
            (0, "observed_now", 100.0),
            (0, "depth", -0.0),
            (0, "depth", False),
            (0, "execution_authority", 0),
        )
        for index, field, changed in aliases:
            def action(rows, index=index, field=field, changed=changed):
                outcomes = [f["payload"] for f in rows if f["payload"]["kind"] == "outcome"]
                result = outcomes[index]["confirmation_wrapper_result"]
                self.assertIs(result["ok"], True)
                original = copy.deepcopy(result)
                result["value"][field] = changed
                self.assertEqual(original, result)
                self.assertNotEqual(canonical(original), canonical(result))
            with self.subTest(outcome=index, field=field, value=repr(changed)):
                bank = self.mutated(action)
                self.refused(bank, "R_NATIVE_OUTCOME_BINDING")
                if index == 0 and field == "confirmed" and type(changed) is int:
                    # An independently retained original pin already rejected
                    # this rewrite. The fix strengthens the inner binding;
                    # it neither bypasses that pin nor attests current custody.
                    self.refused(bank, "R_CHECKPOINT_MISMATCH", expected_checkpoint=self.bank_pin)

    def test_native_outcome_binding_still_rejects_extra_nested_fields(self):
        def action(rows):
            outcome = next(f["payload"] for f in rows if f["payload"]["kind"] == "outcome")
            outcome["confirmation_wrapper_result"]["value"]["additional_authority"] = False
        self.refused(self.mutated(action), "R_NATIVE_OUTCOME_BINDING")

    def test_refund_after_unconfirmed_result_is_not_a_wire_operation(self):
        def action(rows):
            next(f["payload"] for f in rows if f["payload"]["kind"] == "outcome")["refund_units"] = 1
        self.refused(self.mutated(action), "R_OUTCOME_FIELDS")

    def test_a_new_lease_cannot_settle_an_old_pending_start(self):
        def action(rows):
            starts = [f for f in rows if f["payload"]["kind"] == "start"]
            following = next(f["payload"] for f in rows if f["payload"]["kind"] == "outcome"
                             and f["payload"]["start_sequence"] == starts[5]["sequence"])
            following["start_sequence"] = starts[4]["sequence"]
        self.refused(self.mutated(action), "R_OUTCOME_STATE")

    def test_budget_and_integer_encoding_cannot_be_forged(self):
        def action(rows):
            rows[0]["payload"]["budget_units"] = 35
        self.refused(self.mutated(action), "R_BUDGET_SPEND")
        def boolean(rows):
            next(f["payload"] for f in rows if f["payload"]["kind"] == "start")["allowance_units"] = True
        self.refused(self.mutated(boolean), "R_ALLOWANCE")

    def test_probability_and_execution_authority_remain_unproved(self):
        report = self.checked
        for field in ("actual_probability_law_authenticated", "conditional_allowances_proved",
                      "world_confirmation_attempts_covered", "native_conditional_risk_certified",
                      "physical_pre_registration_independently_attested", "trusted_history_anchor"):
            self.assertFalse(report[field])
        self.assertIsNone(report["global_failure_probability"])
        def action(rows):
            rows[0]["payload"]["native_conditional_risk_certified"] = True
        self.refused(self.mutated(action), "R_ESCALATION")

    def test_torn_tail_and_wrong_pin_refuse_without_repair(self):
        bank = self.copied()
        path = bank / "risk.pnrl1"
        with path.open("ab") as out:
            out.write(b"\0")
        before = path.read_bytes()
        self.refused(bank, "R_TORN_TAIL")
        self.assertEqual(path.read_bytes(), before)
        pin = dict(self.bank_pin, record_hash="00" * 32)
        self.refused(self.bank, "R_CHECKPOINT_MISMATCH", expected_checkpoint=pin)

    def test_bank_append_between_parse_and_hash_cannot_bind_a_different_snapshot(self):
        bank = self.copied()
        path = bank / "risk.pnrl1"
        full = path.read_bytes()
        self.assertEqual(read_frames(path)[-1]["payload"]["kind"], "lease_end")
        position, last_start = 8, None
        while position < len(full):
            last_start = position
            position += 4 + int.from_bytes(full[position:position + 4], "big") + 32
        # Both snapshots are real native-run prefixes. Appending only lease_end
        # changes no claim, allowance or native intent; coverage alone cannot
        # detect accidentally hashing this later snapshot after parsing the old.
        path.write_bytes(full[:last_start])
        original = risk._read_snapshot
        switched = False

        def switch_after_snapshot(candidate):
            nonlocal switched
            snapshot = original(candidate)
            if candidate == path and not switched:
                path.write_bytes(full)
                switched = True
            return snapshot

        with mock.patch.object(risk, "_read_snapshot", side_effect=switch_after_snapshot):
            self.refused(bank, "R_SOURCES_CHANGED_DURING_READ")
        self.assertTrue(switched)
        self.assertEqual(path.read_bytes(), full)


if __name__ == "__main__":
    unittest.main()
