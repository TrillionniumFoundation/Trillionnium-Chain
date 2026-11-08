"""Packet, failed-attempt ledger, source and complete race-inventory controls."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

FORMAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FORMAL))

import contract_wire as wire
import work_oracle
from test_w1_competing_consensus import reduced_competition
from test_w1_finite_consensus import reduced_native_shaped_dag
from test_w1_quantum_oracle import fixture as oracle_fixture
import w1_competing_consensus as competing
import w1_native_competition as campaign


def ledger_bytes(receipt, block):
    rows = [{"event": "started", "parent_id": receipt["parent_id"], "height": receipt["height"],
             "logical_observed_now": receipt["logical_observed_now"], "max_attempts": 4096},
            {"event": "prepared", "prepare_elapsed_ns": receipt["prepare_elapsed_ns"]},
            *({"event": "attempt", "outcome": row} for row in receipt["attempts"]),
            {"event": "admitted", "selected_block_id": block["block_id"],
             "admit_activate_elapsed_ns": receipt["admit_activate_elapsed_ns"]}]
    return b"".join(campaign.canonical(row) + b"\n" for row in rows)


def complete_scalar_honest_packets(directory):
    """Real scalar PNW1 bytes; no native Node admission is asserted by this test."""
    fields = wire.header_decode(oracle_fixture(nonce_bits=3).header)
    matrices = [0] * work_oracle.CELLS
    fields["work_task"] = work_oracle.task_id(matrices, matrices)
    fields["target"] = ((1 << 255) - 1).to_bytes(32, "big")
    parent, origin = "01" * 32, 1160
    fixture = {"public_tip": {"block_id": parent}, "clock_origin_timestamp": origin}
    blocks, production = [], []
    (directory / "packets").mkdir()
    for depth in (1, 2):
        height, attempts = 16 + depth, []
        fields.update(parent=bytes.fromhex(parent), height=height, timestamp=origin + depth)
        for nonce in range(64):
            fields["nonce"] = nonce
            header = wire.header_encode(fields)
            challenge = wire.H("challenge", header)
            proof = work_oracle.prove(challenge, matrices, matrices)
            block_id = wire.H("block", header, proof[-32:]).hex()
            packet = header + b"\0\0" + proof
            name = "packets/" + block_id + ".pnk"
            (directory / name).write_bytes(packet)
            winner = wire.H("ticket", challenge, proof[-32:]) <= fields["target"]
            block = {"block_id": block_id, "parent_id": parent, "height": height, "timestamp": origin + depth,
                     "target_hex": fields["target"].hex(), "chainwork_hex": f"{2 * height:0128x}",
                     "header_hex": header.hex(), "nonce": nonce, "trace": proof[-32:].hex(),
                     "packet_file": name, "packet_sha256": campaign.sha(packet),
                     "proof_sha256": campaign.sha(proof), "proof_bytes": len(proof),
                     "native_winner": winner, "native_verifier_error": None if winner else "Target",
                     "complete_native_proof_generated": True}
            attempts.append({**block, "proof_elapsed_ns": 1, "verification_elapsed_ns": 2})
            if winner:
                break
        else:
            raise AssertionError("deterministic bounded scalar fixture exhausted")
        receipt = {"parent_id": parent, "height": height, "selected_block_id": block_id, "max_attempts": 4096,
                   "prepare_elapsed_ns": 3, "admit_activate_elapsed_ns": 4, "complete_pipeline_elapsed_ns": 1000,
                   "logical_observed_now": origin + depth, "native_producer_admitted": True, "attempts": attempts,
                   "ledger_file": f"honest-production-fixture-h{height}.jsonl"}
        raw = ledger_bytes(receipt, block)
        (directory / receipt["ledger_file"]).write_bytes(raw)
        receipt.update(ledger_bytes=len(raw), ledger_sha256=campaign.sha(raw))
        blocks.append(block)
        production.append(receipt)
        parent = block_id
    return fixture, {"honest_blocks": blocks, "honest_production": production}


class HonestLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.fixture, cls.competition = complete_scalar_honest_packets(cls.directory)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_complete_scalar_attempts_and_failed_denominator_are_checked(self):
        expected = sum(len(row["attempts"]) for row in self.competition["honest_production"])
        self.assertEqual(campaign.check_honest_inventory(self.directory, self.fixture, self.competition), expected)
        self.assertGreater(expected, 2)
        self.assertTrue(any(not row["native_winner"] for receipt in self.competition["honest_production"]
                            for row in receipt["attempts"]))

    def test_omitted_miss_renumbering_or_late_extra_attempt_refused(self):
        owner = next(i for i, row in enumerate(self.competition["honest_production"]) if len(row["attempts"]) > 1)
        for mode in ("drop", "renumber", "extra"):
            value = deepcopy(self.competition)
            attempts = value["honest_production"][owner]["attempts"]
            if mode == "drop":
                attempts.pop(0)
            elif mode == "renumber":
                attempts[0]["nonce"] += 1
            else:
                attempts.append(deepcopy(attempts[-1]))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                campaign.check_honest_inventory(self.directory, self.fixture, value)

    def test_clock_relabeling_and_wrong_parent_refused(self):
        for field, value in (("parent_id", "ee" * 32), ("max_attempts", 8192),
                             ("logical_observed_now", 99999), ("complete_pipeline_elapsed_ns", 0)):
            changed = deepcopy(self.competition)
            changed["honest_production"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                campaign.check_honest_inventory(self.directory, self.fixture, changed)

    def test_modified_ledger_or_payload_is_not_accepted_with_old_hash(self):
        receipt = self.competition["honest_production"][0]
        path = self.directory / receipt["ledger_file"]
        original = path.read_bytes()
        try:
            path.write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, "HONEST_LEDGER_DIGEST"):
                campaign.check_honest_inventory(self.directory, self.fixture, self.competition)
        finally:
            path.write_bytes(original)
        raw = b"bound payload"
        path = self.directory / "payload"
        path.write_bytes(raw)
        campaign.check_payloads(self.directory, {"payload": campaign.sha(raw)})
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "PAYLOAD_CHANGED"):
            campaign.check_payloads(self.directory, {"payload": campaign.sha(raw)})

    def test_target_miss_still_requires_complete_correct_transcript(self):
        row = next(row for receipt in self.competition["honest_production"] for row in receipt["attempts"]
                   if not row["native_winner"])
        with patch.object(campaign.work_oracle, "prove", return_value=b"wrong complete transcript"):
            with self.assertRaisesRegex(ValueError, "HONEST_COMPLETE_PROOF_REPLAY"):
                campaign.check_honest_attempt(self.directory, row, expected_nonce=row["nonce"],
                                              parent=row["parent_id"], height=row["height"])

    def test_resigned_ledger_cannot_omit_an_attempt(self):
        value = deepcopy(self.competition)
        receipt = value["honest_production"][0]
        path = self.directory / receipt["ledger_file"]
        original = path.read_bytes()
        raw = b"\n".join(original.splitlines()[:-1]) + b"\n"
        receipt.update(ledger_bytes=len(raw), ledger_sha256=campaign.sha(raw))
        try:
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "HONEST_LEDGER_COMPLETE_ATTEMPTS"):
                campaign.check_honest_inventory(self.directory, self.fixture, value)
        finally:
            path.write_bytes(original)


class CompetitionInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = reduced_native_shaped_dag()
        cls.competition = reduced_competition(cls.fixture)
        for row, name in zip(cls.competition["scenarios"], campaign.SCENARIOS):
            row["scenario_id"] = name
        records = {}
        for scenario in campaign.SCENARIOS:
            for execution in campaign.EXECUTIONS:
                for event in competing.RISK_EVENTS:
                    records[campaign.certificate_key(scenario, execution, event)] = competing.analyze_competing_consensus(
                        cls.fixture, cls.competition, campaign.parameters(cls.fixture, scenario, execution, event))
        cls.bundle = {"schema": campaign.CERTIFICATES_SCHEMA, "source": campaign.sources(), "certificates": records}

    def test_complete_two_by_two_by_two_certificate_grid(self):
        campaign.verify_certificates(self.bundle, self.fixture, self.competition)
        self.assertEqual(len(self.bundle["certificates"]), 8)
        with patch.object(competing, "analyze_competing_consensus", side_effect=AssertionError("optimizer forbidden")):
            campaign.verify_certificates(self.bundle, self.fixture, self.competition)

    def test_missing_grid_cell_and_changed_budget_refused(self):
        changed = deepcopy(self.bundle)
        changed["certificates"].pop(next(iter(changed["certificates"])))
        with self.assertRaisesRegex(ValueError, "CERTIFICATE_INVENTORY"):
            campaign.verify_certificates(changed, self.fixture, self.competition)
        changed = deepcopy(self.bundle)
        next(iter(changed["certificates"].values()))["parameters"]["horizon_seconds"] = "40"
        with self.assertRaisesRegex(ValueError, "COST_PREMISES_CHANGED"):
            campaign.verify_certificates(changed, self.fixture, self.competition)

    def test_all_seeded_and_advice_runs_remain_separate(self):
        report = campaign.sample_report(self.fixture, self.competition, {}, self.bundle, "ab" * 32, 0)
        self.assertEqual(report["declared_seeded_run_count"], 6)
        sampled = [row for row in report["runs"] if row["observation_kind"] == "fixed-seed-conditional-competition-sample"]
        advice = [row for row in report["runs"] if row not in sampled]
        self.assertEqual(len(sampled), 6)
        self.assertEqual(len(advice), 2)
        self.assertTrue(all(row["raw_observation"]["seed"] == 9 for row in sampled))
        self.assertTrue(all(row["raw_observation"]["sampled_execution"] is False for row in advice))
        self.assertTrue(all(len(row["receiver_events"]) >= 2 for row in report["runs"]))
        self.assertTrue(all(row["receiver_observed_until_seconds"] == {"numerator": 4, "denominator": 1}
                            for row in report["runs"]))

    def test_plan_retains_original_budget_and_declares_isolated_public_view(self):
        plan = campaign.fixed_plan(1160)
        self.assertEqual(plan["horizon_seconds"], "4")
        self.assertEqual(plan["max_private_attempts"], 2)
        self.assertEqual(plan["sample_seed"], 9)
        self.assertEqual(plan["honest_timestamps"], [1161, 1162])
        self.assertEqual(plan["public_producer_view"], "isolated-public-branch-until-horizon")
        self.assertFalse(plan["native_honest_production_wall_time_is_arrival_time"])
        self.assertEqual(set(plan["scenario_times"]), set(campaign.SCENARIOS))

    def test_false_security_claims_remain_false(self):
        for field in ("physical_clock_calibrated", "whole_network_machine_error_bound_composed",
                      "stochastic_continuing_honest_mining_covered", "long_horizon_settlement_security_proved",
                      "quantum_hardware_executed", "quantum_mining_qualified", "production_activation"):
            self.assertIs(campaign.CLAIMS[field], False)

    def test_duplicate_json_keys_and_nonfinite_values_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                campaign.strict_load(raw)


class FixedPlanTypeTests(unittest.TestCase):
    """Strict loader controls; mocked native admission is not new native evidence."""

    def test_boolean_integer_substitutions_in_plan_and_copy_are_refused(self):
        origin = 1_750_000_160
        fixture = {"genesis_timestamp": 1_750_000_000, "clock_origin_timestamp": origin,
                   "native_source": {"source_sha256": {}}}
        original = campaign.fixed_plan(origin)
        for kind in ("unchanged", "plan_false_as_zero", "plan_one_as_true",
                     "copy_false_as_zero", "copy_one_as_true"):
            plan, copy = deepcopy(original), deepcopy(original)
            changed = plan if kind.startswith("plan_") else copy
            if kind.endswith("false_as_zero"):
                changed["native_honest_production_wall_time_is_arrival_time"] = 0
            elif kind.endswith("one_as_true"):
                changed["scenario_times"][campaign.SCENARIOS[0]][0]["numerator"] = True
            if kind.startswith("plan_"):
                copy = deepcopy(plan)
            plan_raw = campaign.canonical(plan)
            blocks = [{"block_id": "11" * 32}, {"block_id": "22" * 32}]
            competition = {"schema": competing.FIXTURE_SCHEMA, "native_source": fixture["native_source"],
                "base_fixture_file_sha256": "ab" * 32,
                "base_fixture_canonical_sha256": competing.digest(fixture),
                "plan_file_sha256": campaign.sha(plan_raw), "fixed_plan": copy,
                "claims": campaign.FIXTURE_CLAIMS, "honest_blocks": blocks,
                "scenarios": [{"scenario_id": name, "arrivals": [
                    {"block_id": block["block_id"], "at_seconds": at}
                    for block, at in zip(blocks, original["scenario_times"][name])]}
                    for name in campaign.SCENARIOS]}
            files = {"native-competition-plan.json": plan_raw,
                     "native-competition-fixture.json": campaign.canonical(competition)}
            with self.subTest(kind=kind), \
                    patch.object(campaign.bridge, "load_fixture", return_value=(fixture, "ab" * 32, 0)), \
                    patch.object(campaign, "check_honest_inventory", return_value=0), \
                    patch.object(campaign, "read", side_effect=lambda path: files[path.name]):
                if kind == "unchanged":
                    self.assertEqual(campaign.load_fixture(Path("/not-native-evidence"))[1], competition)
                else:
                    with self.assertRaisesRegex(ValueError, "COMPETITION_FIXED_PLAN_CHANGED"):
                        campaign.load_fixture(Path("/not-native-evidence"))


class VerificationSnapshotTests(unittest.TestCase):
    """Boundary controls with semantic checkers mocked; not native evidence."""

    def verify_boundary(self, mutation=None):
        source = {"git_head": "head", "source_sha256": {}}
        fixture = {"native_source": {"source_sha256": {}}}
        files = {name: b"{}" for name in campaign.INPUTS}
        files["competition-samples.json"] = b'{"runs":[]}'
        files["retained-payload"] = b"retained bytes"
        hashes = {name: campaign.sha(files[name]) for name in campaign.INPUTS[:3]}
        payloads = {"retained-payload": campaign.sha(files["retained-payload"])}

        def read(path, limit=32_000_000):
            del limit
            raw = files[path.name]
            if path.name == "competition-samples.json":
                if mutation == "raw":
                    files["native-competition-fixture.json"] += b" "
                elif mutation == "payload":
                    files["retained-payload"] += b" "
            return raw

        final_source = source if mutation != "source" else {**source, "git_head": "changed"}
        with patch.object(campaign, "sources", side_effect=[source, final_source]), \
                patch.object(campaign, "load_fixture", return_value=(fixture, {}, hashes, 0)), \
                patch.object(campaign, "verify_certificates", return_value=None), \
                patch.object(campaign, "sample_report", return_value={"runs": []}), \
                patch.object(campaign, "payload_hashes", return_value=payloads), \
                patch.object(campaign.bridge, "native_source_inventory", return_value={}), \
                patch.object(campaign, "read", side_effect=read):
            return campaign.verify(Path("/not-a-native-observation"))

    def test_returned_receipt_binds_all_raw_inputs_and_consumed_payloads(self):
        receipt = self.verify_boundary()
        self.assertEqual(set(receipt["verified_inputs"]), set(campaign.INPUTS))
        self.assertEqual(set(receipt["verified_payloads"]), {"retained-payload"})
        self.assertEqual(receipt["status"], "VERIFIED")

    def test_semantically_equal_raw_file_change_during_verify_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "INPUT_CHANGED_DURING_VERIFY"):
            self.verify_boundary("raw")

    def test_payload_change_after_scalar_check_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "PAYLOAD_CHANGED"):
            self.verify_boundary("payload")

    def test_source_change_after_model_check_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SOURCE_CHANGED"):
            self.verify_boundary("source")


if __name__ == "__main__":
    unittest.main()
