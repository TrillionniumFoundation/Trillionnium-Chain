#!/usr/bin/env python3
"""Adversarial synthetic reader controls; no native execution or W1 evidence."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import read_validated_business_goodput as reader
from contract_wire import SCHEMA, header_encode, sequence_root


def slots(*names):
    rows = [dict(phase=name, parent_phase=reader.phases.PHASE_PARENTS_V4.get(name),
                 started=False, completed=False, accepted=None, error_code=None,
                 started_ns=None, ended_ns=None, wall_ns=None, thread_cpu_ns=None)
            for name in reader.phases.PHASES_V4]
    for row in rows:
        if row["phase"] in names:
            row.update(started=True, completed=True, accepted=True, started_ns=20,
                       ended_ns=70, wall_ns=50, thread_cpu_ns=1)
    if "history_import" in names:
        row = next(row for row in rows if row["phase"] == "history_import")
        row.update(started_ns=10, ended_ns=90, wall_ns=80)
    return rows


def native_import(page, packets):
    checks = []
    for name, start, end in (("resolve", 0, 1), ("initial", 2, 3),
                             ("checkpoint", 20, 80), ("final", 91, 92)):
        checks.append(dict(phase=name, calls_started=1, calls_completed=1, calls_accepted=1,
                           calls_rejected=0, calls_unfinished=0, first_started_ns=start,
                           last_ended_ns=end, wall_ns=end-start, thread_cpu_ns=1,
                           wall_clock_unknown_calls=0, cpu_clock_unknown_calls=0, last_error_code=None))
    return dict(schema="pon-local-history-import-observation-v1", packet_capacity=16,
                tip=list(bytes.fromhex(page["tip"])), after=list(bytes.fromhex(page["after"])),
                supplied_packets=len(packets), phases=slots("history_import"),
                packets=[dict(packet_index=i, packet_id=list(bytes.fromhex(p["id"])),
                              phases=slots("history_import", "work")) for i, p in enumerate(packets)],
                measurement_failures=0, host_checks=checks, host_checks_are_nested_not_additive=True,
                cpu_intervals_are_nested_not_additive=True, phase_cpu_excludes_scoped_workers=True,
                host_cpu_includes_each_calling_thread=True, host_cpu_is_full_worker_cpu=False,
                observation_has_consensus_authority=False, clock_scope="synthetic-observer-local-clock")


def fixture(*, repeated_transaction=False):
    """Canonical packet identity bytes with deliberately unverified fake Work."""
    business, packets = [], []
    parent = bytes.fromhex("99" * 32)
    for i in range(21):
        tx_index = 0 if repeated_transaction and i in (7, 14) else i
        transaction = b"PNX1" + bytes([tx_index]) * 196
        transactions = [transaction] if i % 7 == 0 else []
        header = {f["name"]: bytes([1]) * 32 if f["type"] == "hash32" else 0 for f in SCHEMA["header"]}
        header.update(parent=parent, height=5+i, timestamp=1000+i,
                      target=bytes.fromhex("7f" + "ff" * 31),
                      transactions=sequence_root("transactions", transactions), nonce=i)
        raw_header = header_encode(header)
        trace = bytes([i + 1]) * 32
        raw = raw_header + len(transactions).to_bytes(2, "little")
        raw += b"".join(len(tx).to_bytes(2, "little") + tx for tx in transactions)
        raw += b"PNW1" + bytes(12 * 4096) + trace
        parent = reader.H("block", raw_header, trace)
        business.append(dict(id=parent.hex(), header=raw_header.hex(), transactions=[tx.hex() for tx in transactions]))
        packets.append(raw.hex())
    phases = []
    for mode in reader.phases.MODES:
        history, rounds = [], []
        for n in range(3):
            rows = business[n*7:(n+1)*7]
            started = (1+n*4) * 1_000_000_000
            tip, included = rows[-1]["id"], rows[0]["id"]
            after = reader.header_decode(bytes.fromhex(rows[0]["header"]))["parent"].hex()
            page = dict(schema="pon-native-history-v1", network="01"*32, parameters="01"*32, genesis="99"*32,
                        tip=tip, after=after, next=tip, complete=True, packets=packets[n*7:(n+1)*7])
            native = native_import(page, rows)
            history.append(dict(status="ok", error=None, started_ns=started+10, ended_ns=started+20,
                request=dict(op="history", tip=tip, after=after), response=dict(ok=True, value=page),
                client_import=dict(succeeded=True, error=None, started_ns=started+30,
                                   ended_ns=started+100, native_import_observation=native),
                client_confirmation=dict(succeeded=True, started_ns=started+110, ended_ns=started+120)))
            tx = reader.H("tx-id", bytes.fromhex(rows[0]["transactions"][0])).hex()
            observation = dict(transaction=tx, included_block=included, observed_tip=tip,
                policy="installed-depth-and-required-work", genesis="99"*32, network="01"*32,
                parameters="01"*32, included_height=5+n*7, observed_height=11+n*7,
                depth=6, work_delta=f"{12:0128x}", required_work_delta=f"{12:0128x}",
                active_generation=n+1, observed_now=2000, confirmed=True, reorged=False,
                finalized=False, execution_authority=False)
            rounds.append(dict(round=n, transaction=tx, included_block=included, tip=tip,
                               started_ns=started, ended_ns=started+150, observation=observation,
                               confirmed_inside_pressure_window=True))
        phases.append(dict(mode=mode, duration_seconds=30, state_backend="authenticated-v1",
            whole_parent_phase_wall_ns=40_000_000_000, whole_parent_phase_cpu_ns=10_000_000_000,
            history=history, confirmations=rounds, submissions=[{} for _ in business],
            all_signed_rounds_confirmed_in_window=True, finite_phase_criteria_met=False))
    return dict(schema="native-public-v3-separate-process-campaign-v2", state_backend="authenticated-v1",
                settings_profile="native-public-evaluation-dev-v1 + continuity_v1 explicit maintenance",
                preparation=dict(state_backend="authenticated-v1", business_blocks=21,
                                 seed_blocks=4, actual_signed_seed_transfers=1024, business=business,
                                 cpu_ns=1000, wall_ns=2000), phases=phases,
                finite_experiment_criteria_met=False, economics_complete=False,
                **dict.fromkeys(reader.FALSE_FLAGS, False))


class GoodputJoinTests(unittest.TestCase):
    def output(self, doc):
        return reader.analyze_report(doc)["phases"][0]

    def test_count_unique_business_using_actual_inclusive_phase_time(self):
        value = reader.analyze_report(fixture())
        out = value["phases"][0]
        self.assertEqual(out["unique_validated_business_observed"], 3)
        self.assertEqual(out["validated_goodput_per_second"], {"numerator": 3, "denominator": 40})
        self.assertEqual(out["fixed_pressure_window_ns"], 30_000_000_000)
        self.assertFalse(out["finite_phase_criteria_met"])
        self.assertIsNone(value["cross_phase_goodput_sum"])
        self.assertIsNone(value["complete_lifecycle_cost_ns"])

    def test_repeated_transaction_in_distinct_rounds_is_credited_once(self):
        out = self.output(fixture(repeated_transaction=True))
        self.assertEqual(out["original_claimed_confirmation_rounds"], 3)
        self.assertEqual(out["unique_validated_business_observed"], 1)
        self.assertEqual(out["counts"]["repeated_transaction_observations"], 2)
        self.assertEqual(out["validated_goodput_per_second"], {"numerator": 1, "denominator": 40})

    def test_low_sample_tail_latency_is_not_reported_as_p99(self):
        out = self.output(fixture())
        self.assertEqual(out["successful_round_latency_samples"], 3)
        self.assertIsNone(out["successful_round_latency_p95_ns"])
        self.assertIsNone(out["successful_round_latency_p99_ns"])

    def test_missing_scheduled_rounds_remain_in_denominator_and_block_definitive_rate(self):
        doc = fixture()
        phase = doc["phases"][0]
        phase["confirmations"].pop()
        phase["all_signed_rounds_confirmed_in_window"] = False
        out = self.output(doc)
        self.assertEqual((out["planned_rounds"], out["observed_rounds"], out["unobserved_rounds"]), (3, 2, 1))
        self.assertIsNone(out["validated_goodput_per_second"])
        self.assertEqual(out["observed_validated_business_per_actual_second"], {"numerator": 1, "denominator": 20})

    def test_unknown_confirmation_is_not_zero_or_success(self):
        doc = fixture()
        phase = doc["phases"][0]
        phase["confirmations"][0].update(observation=None, confirmed_inside_pressure_window=False)
        phase["all_signed_rounds_confirmed_in_window"] = False
        out = self.output(doc)
        self.assertEqual(out["counts"]["unknown"], 1)
        self.assertIsNone(out["validated_goodput_per_second"])

    def test_submit_ack_without_full_import_never_establishes_goodput(self):
        doc = fixture()
        doc["phases"][0]["history"] = []
        out = self.output(doc)
        self.assertEqual(out["unique_validated_business_observed"], 0)
        self.assertEqual(out["counts"]["validation_evidence_missing"], 3)
        self.assertIsNone(out["validated_goodput_per_second"])

    def test_complete_import_without_packet_work_does_not_establish_new_validation(self):
        doc = fixture()
        for row in doc["phases"][0]["history"]:
            for observation in row["client_import"]["native_import_observation"]["packets"]:
                observation["phases"] = slots("history_import")
        out = self.output(doc)
        self.assertEqual(out["unique_validated_business_observed"], 0)
        self.assertIsNone(out["validated_goodput_per_second"])

    def test_historical_missing_observer_is_an_explicit_gap(self):
        doc = fixture()
        doc["phases"][0]["history"][0]["client_import"].pop("native_import_observation")
        out = self.output(doc)
        self.assertEqual(out["historical_successful_imports_without_work_observation"], 1)
        self.assertEqual(out["unique_validated_business_observed"], 2)
        self.assertIsNone(out["validated_goodput_per_second"])

    def test_partial_packet_roster_cannot_claim_complete_page(self):
        doc = fixture()
        doc["phases"][0]["history"][0]["client_import"]["native_import_observation"]["packets"].pop()
        with self.assertRaisesRegex(ValueError, "packet observation roster"):
            self.output(doc)

    def test_work_observer_packet_id_must_match_original_bytes(self):
        doc = fixture()
        doc["phases"][0]["history"][0]["client_import"]["native_import_observation"]["packets"][0]["packet_id"] = [0]*32
        with self.assertRaisesRegex(ValueError, "packet identity"):
            self.output(doc)

    def test_same_block_id_cannot_reuse_work_after_complete_packet_bytes_change(self):
        doc = fixture()
        phase = doc["phases"][0]
        original = phase["history"][0]
        replay = copy.deepcopy(original)
        original.pop("client_confirmation")
        base = phase["confirmations"][0]["started_ns"]
        original["client_import"]["ended_ns"] = base+80
        replay.update(started_ns=base+81, ended_ns=base+82)
        replay["client_import"].update(started_ns=base+83, ended_ns=base+100)
        changed = bytearray.fromhex(replay["response"]["value"]["packets"][0])
        changed[600] ^= 1  # W1 interior; header, transaction and final trace stay equal.
        replay["response"]["value"]["packets"][0] = changed.hex()
        for row in replay["client_import"]["native_import_observation"]["packets"]:
            row["phases"] = slots("history_import")
        phase["history"].append(replay)
        with self.assertRaisesRegex(ValueError, "conflicting complete packet bytes"):
            self.output(doc)

    def test_transaction_substitution_is_rejected_by_the_header_commitment(self):
        doc = fixture()
        raw = doc["preparation"]["business"][0]["transactions"][0]
        doc["preparation"]["business"][0]["transactions"][0] = raw[:-2] + "ff"
        with self.assertRaisesRegex(ValueError, "transaction commitment"):
            self.output(doc)

    def test_historical_missing_observer_cannot_hide_conflicting_successful_packet_bytes(self):
        doc = fixture()
        phase = doc["phases"][0]
        first = phase["history"][0]
        replay = copy.deepcopy(first)
        first["client_import"].pop("native_import_observation")
        changed = bytearray.fromhex(replay["response"]["value"]["packets"][0])
        changed[600] ^= 1
        replay["response"]["value"]["packets"][0] = changed.hex()
        phase["history"].append(replay)
        with self.assertRaisesRegex(ValueError, "conflicting complete packet bytes"):
            self.output(doc)

    def test_confirmation_transaction_cannot_be_replaced_by_another_round(self):
        doc = fixture()
        rounds = doc["phases"][0]["confirmations"]
        rounds[1]["transaction"] = rounds[0]["transaction"]
        rounds[1]["observation"]["transaction"] = rounds[0]["transaction"]
        with self.assertRaisesRegex(ValueError, "scheduled business"):
            self.output(doc)

    def test_reduced_confirmation_rule_and_invented_work_are_refused(self):
        for field, value in (("required_work_delta", f"{1:0128x}"), ("work_delta", f"{100:0128x}"),
                             ("depth", 5), ("observed_height", 12), ("depth", True)):
            with self.subTest(field=field, value=value):
                doc = fixture()
                doc["phases"][0]["confirmations"][0]["observation"][field] = value
                with self.assertRaisesRegex(ValueError, "depth/work"):
                    self.output(doc)

    def test_cross_chain_or_policy_confirmation_is_refused(self):
        for field, value in (("network", "02"*32), ("parameters", "02"*32),
                             ("policy", "caller-selected"), ("finalized", True)):
            with self.subTest(field=field):
                doc = fixture()
                doc["phases"][0]["confirmations"][0]["observation"][field] = value
                with self.assertRaisesRegex(ValueError, "policy/context"):
                    self.output(doc)

    def test_reorged_confirmation_is_retained_without_credit(self):
        doc = fixture()
        phase = doc["phases"][0]
        row = phase["confirmations"][0]
        row["observation"].update(reorged=True, confirmed=False, work_delta=None, depth=None)
        row["confirmed_inside_pressure_window"] = False
        phase["all_signed_rounds_confirmed_in_window"] = False
        out = self.output(doc)
        self.assertEqual(out["counts"]["reorged"], 1)
        self.assertEqual(out["unique_validated_business_observed"], 2)
        self.assertIsNone(out["stale_work_cost_ns"])

    def test_missing_native_negative_confirmation_receipt_cannot_establish_zero(self):
        doc = fixture()
        phase = doc["phases"][0]
        phase["history"] = []
        for row in phase["confirmations"]:
            row["observation"].update(reorged=True, confirmed=False, work_delta=None, depth=None)
            row["confirmed_inside_pressure_window"] = False
        phase["all_signed_rounds_confirmed_in_window"] = False
        out = self.output(doc)
        self.assertEqual(out["counts"]["validation_evidence_missing"], 3)
        self.assertIsNone(out["validated_goodput_per_second"])

    def test_negative_confirmation_flag_must_match_depth_and_work_rule(self):
        doc = fixture()
        phase = doc["phases"][0]
        for row in phase["confirmations"]:
            row["observation"]["confirmed"] = False
            row["confirmed_inside_pressure_window"] = False
        phase["all_signed_rounds_confirmed_in_window"] = False
        with self.assertRaisesRegex(ValueError, "depth/work confirmation rule"):
            self.output(doc)

    def test_late_result_retains_elapsed_and_cpu_cost_without_goodput(self):
        doc = fixture()
        phase = doc["phases"][0]
        phase["confirmations"][-1].update(ended_ns=reader.WINDOW_NS+1, confirmed_inside_pressure_window=False)
        phase["all_signed_rounds_confirmed_in_window"] = False
        out = self.output(doc)
        self.assertEqual(out["counts"]["late_or_window_refused"], 1)
        self.assertEqual(out["whole_parent_phase_cpu_ns"], 10_000_000_000)
        self.assertEqual(out["actual_parent_phase_wall_ns"], 40_000_000_000)
        self.assertEqual(out["unique_validated_business_observed"], 2)

    def test_late_claim_and_reversed_clock_refused(self):
        for change in ("late", "reversed"):
            doc = fixture()
            row = doc["phases"][0]["confirmations"][-1]
            row["ended_ns"] = reader.WINDOW_NS if change == "late" else 0
            with self.assertRaises(ValueError):
                self.output(doc)

    def test_observer_local_clock_is_not_confused_with_campaign_clock(self):
        # Native times are 10..90; enclosing campaign times exceed 1e9.
        self.assertEqual(self.output(fixture())["unique_validated_business_observed"], 3)

    def test_import_after_confirmation_cannot_support_earlier_credit(self):
        doc = fixture()
        row = doc["phases"][0]["history"][0]
        row["client_import"]["ended_ns"] += 1_000_000_000
        with self.assertRaisesRegex(ValueError, "confirmation campaign clock"):
            self.output(doc)

    def test_later_work_inside_same_round_cannot_pay_for_earlier_confirmation(self):
        doc = fixture()
        phase = doc["phases"][0]
        first = phase["history"][0]
        late = copy.deepcopy(first)
        for observed in first["client_import"]["native_import_observation"]["packets"]:
            observed["phases"] = slots("history_import")
        base = phase["confirmations"][0]["started_ns"]
        late.pop("client_confirmation")
        late.update(started_ns=base+121, ended_ns=base+122)
        late["client_import"].update(started_ns=base+123, ended_ns=base+140)
        phase["history"].append(late)
        out = self.output(doc)
        self.assertEqual(out["outcomes"][0]["state"], "validation_evidence_missing")
        self.assertEqual(out["unique_validated_business_observed"], 2)
        self.assertIsNone(out["validated_goodput_per_second"])

    def test_unknown_actual_elapsed_never_becomes_nominal_window(self):
        doc = fixture()
        doc["phases"][0]["whole_parent_phase_wall_ns"] = None
        out = self.output(doc)
        self.assertEqual(out["unique_validated_business_observed"], 3)
        self.assertIsNone(out["validated_goodput_per_second"])
        self.assertIsNone(out["observed_validated_business_per_actual_second"])

    def test_startup_failure_preserves_three_missing_planned_slots(self):
        doc = fixture()
        doc["phases"][0] = dict(mode="baseline", startup_or_campaign_error="original refusal")
        out = self.output(doc)
        self.assertEqual(out["unobserved_rounds"], 3)
        self.assertEqual(out["startup_or_campaign_error"], "original refusal")
        self.assertIsNone(out["validated_goodput_per_second"])

    def test_unsupported_positive_qualification_is_not_imported(self):
        doc = fixture()
        doc["cryptographic_hardness_qualified"] = True
        with self.assertRaisesRegex(ValueError, "unsupported original qualification"):
            self.output(doc)


class ReceiptBoundaryTests(unittest.TestCase):
    def test_manifest_pin_and_source_head_mismatch_refuse_before_metrics(self):
        result = dict(schema="pon-original-native-campaign-ci-v1", expected_head="1"*40,
                      expected_tree="2"*40, source_kind="head", profile="release", toolchain="1.95.0",
                      state_backend="authenticated-v1", original_inputs=reader.original.INPUTS,
                      planned_complete_runs=3)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            raw = json.dumps(result).encode()
            (root / "results.json").write_bytes(raw)
            manifest = json.dumps({"files": [{"path": "results.json", "bytes": len(raw),
                                             "sha256": hashlib.sha256(raw).hexdigest()}]}).encode()
            (root / "artifact-files.json").write_bytes(manifest)
            with self.assertRaisesRegex(ValueError, "file-list SHA256"):
                reader.read_bundle(root, "0"*64, "1"*40, "2"*40)
            with self.assertRaisesRegex(ValueError, "source-bound"):
                reader.read_bundle(root, hashlib.sha256(manifest).hexdigest(), "3"*40, "2"*40)

    def test_failed_process_receipt_retains_its_original_elapsed_and_exit(self):
        command = ["/synthetic/cargo", "+1.95.0", "test", "--locked", "--offline", "--release",
                   "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--test",
                   "public_v3_multiprocess", reader.original.SELECTOR, "--", "--exact", "--ignored",
                   "--nocapture", "--test-threads=1"]
        step = dict(command=command, name="run-1", outer_stage_timeout_seconds=600, returncode=101,
                    error=None, complete_success=False, elapsed_ns=650_000_000_000, elapsed_seconds=650.0)
        files = {}
        for kind in ("stdout", "stderr"):
            filename = f"run-1.{kind}.log"
            step.update({kind: filename, kind+"_truncated": False, kind+"_bytes": 0,
                         kind+"_sha256": hashlib.sha256(b"").hexdigest()})
            files[filename] = dict(bytes=0, sha256=hashlib.sha256(b"").hexdigest())
        class SyntheticBundle:
            def json(self, name):
                return step
            def raw(self, name):
                return b""
        bundle = SyntheticBundle()
        bundle.files = files
        before = copy.deepcopy(step)
        reader.attempt_step(bundle, step, "run-1")
        self.assertEqual(step, before)
        step["complete_success"] = True
        with self.assertRaisesRegex(ValueError, "outcome contradiction"):
            reader.attempt_step(bundle, step, "run-1")


if __name__ == "__main__":
    unittest.main()
