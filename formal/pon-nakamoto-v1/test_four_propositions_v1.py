"""Original reader replays of synthetic fixtures; no real demand/efficacy claim."""
from __future__ import annotations
import json
import os
from pathlib import Path
from fractions import Fraction
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import four_propositions_v1 as view

HERE = Path(__file__).resolve().parent
SOURCE_ROOT = HERE / "dependencies" if (HERE / "dependencies").is_dir() else HERE.parents[1]
MODULES = view.dependencies(SOURCE_ROOT)
sys.path.insert(0, str(SOURCE_ROOT / "formal/pon-nakamoto-v1"))
import test_demand_evidence as demand_fixture
import test_upgrade_policy as upgrade_fixture
sys.path.pop(0)


def repin(value, pins):
    pins["input_sha256"] = view.sha(value)
    pins["binding_sha256"] = view.sha(value["binding"])


def fixture(*, demand=True, utility=True, upgrade=None):
    d = demand_fixture.DemandTests()
    d.setUp()
    bundle = d.bundle()
    terms = bundle["contract"]
    binding = {k: terms[k] for k in
               ("context", "parent", "inputs", "output_spec", "qualified_work", "evaluation_protocol")}
    binding.update(output_content=bundle["delivery"]["body"]["payload"]["output"],
                   task_content=demand_fixture.ident("owner-admitted-task-content"),
                   work_profile="pon-matmul-transcript-64-v1", cost_unit=demand_fixture.ident("cost-unit"))
    value = dict(schema=view.INPUT_SCHEMA, source_commit=view.REFERENCE_SOURCE, binding=binding,
                 resource_units=dict(view.RESOURCE_UNITS), demand=None, utility=None, upgrade=None)
    pins = dict(schema=view.PIN_SCHEMA, source_commit=view.REFERENCE_SOURCE, input_sha256="0" * 64,
                binding_sha256="0" * 64, demand=None, upgrade=None)
    if demand:
        observation = d.observe(bundle)
        value["demand"] = dict(actions=[dict(bundle=bundle, expected_contract=demand_fixture.validate_contract(terms),
            expected_anchor=d.anchor, height=100, observation=observation)], snapshot=d.book.snapshot())
        pins["demand"] = dict(owner_keys={r: d.keys[r] for r in demand_fixture.ROLES},
                              registry_root=d.registry, bonus_cap=10, max_records=4096)
    if utility:
        add_utility(value)
    if upgrade is not None:
        add_upgrade(value, pins, upgrade)
    repin(value, pins)
    return value, pins


def add_utility(value):
    binding = value["binding"]
    m = MODULES["work_utility"]
    branch = demand_fixture.ident("branch")
    observer = m.UniqueUsefulOutputAccounting(context=binding["context"], current_branch=branch)
    for index in range(2):
        attempt = demand_fixture.ident("attempt" + str(index))
        observer.begin_attempt(attempt=attempt, branch=branch, task_content=binding["task_content"],
            output_content=binding["output_content"], function_fingerprint=demand_fixture.ident("function" + str(index)),
            source=demand_fixture.ident("source" + str(index)), partition="partition" + str(index))
        for stage in m.STAGES:
            observer.record_cost(attempt, stage, observer="synthetic-clock",
                cost=m.measured_cost(cpu_ns=10, wall_ns=20, operations=30, gpu_ns=None))
        observer.finish_verification(attempt, accepted=True, quality_gain=Fraction(1, 2), outcome="synthetic")
        observer.adopt_output(attempt, consumer_operation=demand_fixture.ident("consumer-operation" + str(index)),
            consumer=demand_fixture.ident("consumer"), observed_output=binding["output_content"])
    value["utility"] = dict(initial_branch=branch, required_stages=list(m.STAGES),
        max_attempts=4096, max_events=65536, events=observer.events, snapshot=observer.snapshot())


def add_upgrade(value, pins, mode):
    binding = value["binding"]
    u = upgrade_fixture.UpgradePolicyTests()
    u.setUp()
    public = u.key.public_key().public_bytes(upgrade_fixture.Encoding.Raw, upgrade_fixture.PublicFormat.Raw).hex()
    u.policy = upgrade_fixture.UpgradePolicy(context=binding["context"], owner_key=public, alpha=[1, 20], bonus_cap=150)
    changes = {k: binding[k] for k in ("context", "parent", "evaluation_protocol", "cost_unit")}
    changes["candidate"] = binding["output_content"]
    if mode == "cost-negative":
        changes["overhead"] = {m: upgrade_fixture.zero_costs() for m in upgrade_fixture.MODELS}
        changes["overhead"]["candidate"]["compute"] = 3000
    p = u.plan(**changes)
    raw, plan_id = upgrade_fixture.freeze_plan(**p)
    attempt = u.policy.begin(raw, plan_id, current_parent=p["parent"], height=0)
    u.plans[attempt], u.digests[attempt] = p, plan_id
    actions = [dict(kind="begin", plan=json.loads(raw), expected_plan=plan_id,
                    current_parent=p["parent"], height=0, attempt=attempt)]
    if mode == "timeout":
        u.policy.cancel(attempt, reason="timeout", height=1)
        actions.append(dict(kind="cancel", attempt=attempt, reason="timeout", height=1))
    else:
        rows = u.rows(attempt)
        receipt = u.receipt(attempt, "evaluation", rows, 10)
        u.policy.evaluate(attempt, rows, receipt, current_parent=p["parent"], height=10)
        actions.append(dict(kind="evaluate", attempt=attempt, rows=rows, receipt=receipt,
                            current_parent=p["parent"], height=10))
        if mode == "positive":
            canary = u.canary(attempt)
            receipt = u.receipt(attempt, "canary", canary, 11)
            u.policy.observe_canary(attempt, canary, receipt, current_parent=p["parent"], height=11)
            actions.append(dict(kind="canary", attempt=attempt, observation=canary, receipt=receipt,
                                current_parent=p["parent"], height=11))
            body = u.policy.proposal_body(attempt)
            receipt = u.receipt(attempt, "proposal", body, 12)
            u.policy.propose(attempt, receipt, current_parent=p["parent"], height=12)
            actions.append(dict(kind="propose", attempt=attempt, receipt=receipt,
                                current_parent=p["parent"], height=12))
    value["upgrade"] = dict(actions=actions, observation=u.policy.observation())
    pins["upgrade"] = dict(owner_key=public, alpha=[1, 20], bonus_cap=150,
                           max_attempts=64, target_attempt=attempt)


def project(value, pins):
    return view.project(value, pins, source_root=SOURCE_ROOT)


class FourPropositionsTests(unittest.TestCase):
    def test_missing_reports_remain_missing_without_total_pass(self):
        result = project(*fixture(demand=False, utility=False))
        self.assertEqual({r["observation_state"] for r in result["propositions"].values()}, {"MISSING"})
        self.assertNotIn("result", result)
        self.assertNotIn("PASS", json.dumps(result))
        self.assertFalse(result["supplied_observations_replayed"])
        self.assertEqual(result["supplied_observations_count"], 0)

    def test_full_positive_replay_grants_none_of_the_four_propositions(self):
        result = project(*fixture(upgrade="positive"))
        for row in result["propositions"].values():
            self.assertFalse(row["proven"])
            self.assertTrue(row["unresolved_obligations"])
        self.assertEqual(result["authority"], view.AUTHORITY)
        self.assertFalse(result["execution_source_provenance_authenticated"])
        self.assertFalse(result["cross_proposition_semantic_binding_authenticated"])
        self.assertIsNone(result["propositions"]["sybil"]["facts"]["all_algorithm_cost_bound"])

    def test_signed_delivery_alone_is_not_computation_proof_or_net_benefit(self):
        result = project(*fixture(utility=False))
        comp = result["propositions"]["computation"]
        self.assertEqual(comp["observation_state"], "OBSERVED")
        self.assertFalse(comp["facts"]["raw_computation_proof_verified_by_this_view"])
        self.assertEqual(result["propositions"]["utility"]["observation_state"], "MISSING")

    def test_no_gain_keeps_service_fee_observation_separate(self):
        facts = project(*fixture())["propositions"]["demand"]["facts"]
        row = facts["composition"]["observations"][0]
        self.assertEqual(row["status"], "NoUpdate")
        self.assertEqual(row["paid"], dict(service=20, evaluation=7, availability=3, improvement=0))
        self.assertEqual(facts["data_rights_status"], "UNKNOWN")
        self.assertEqual(facts["customer_independence_status"], "UNKNOWN")

    def test_duplicate_content_and_all_attempt_costs_are_replayed(self):
        facts = project(*fixture())["propositions"]["utility"]["facts"]
        snapshot = facts["output_accounting"]["snapshot"]
        self.assertEqual(snapshot["unique_useful_outputs_actually_adopted"], 1)
        self.assertEqual(snapshot["downstream_adoption_events"], 2)
        self.assertEqual(snapshot["cost_totals"]["cpu_ns"], 80)
        self.assertIsNone(snapshot["cost_totals"]["gpu_ns"])
        self.assertEqual(facts["complete_external_cost_coverage"], "UNKNOWN")

    def test_original_net_arithmetic_retains_negative_cost_result(self):
        facts = project(*fixture(upgrade="cost-negative"))["propositions"]["utility"]["facts"]
        observation = facts["upgrade"]["observation"]
        self.assertEqual(observation["results"][0]["reason"], "insufficient-net-benefit-evidence")
        evaluated = next(e for e in observation["events"] if e["phase"] == "evaluated")
        self.assertEqual(evaluated["value"]["net_means"]["current"], ["-50", "1"])

    def test_timeout_noupdate_is_not_completed_evaluation(self):
        facts = project(*fixture(demand=False, utility=False, upgrade="timeout"))["propositions"]["utility"]["facts"]
        observation = facts["upgrade"]["observation"]
        self.assertEqual(observation["results"][0]["reason"], "timeout")
        self.assertNotIn("evaluated", [e["phase"] for e in observation["events"]])

    def test_report_qualification_boolean_cannot_override_reader(self):
        value, pins = fixture()
        value["demand"]["actions"][0]["observation"]["independent_demand_proven"] = True
        repin(value, pins)
        with self.assertRaisesRegex(ValueError, "FOUR_DEMAND_REPORT"):
            project(value, pins)

    def test_modified_signature_refuses_before_projection(self):
        value, pins = fixture()
        value["demand"]["actions"][0]["bundle"]["request"]["signature"] = "00" * 64
        repin(value, pins)
        with self.assertRaises((ValueError, MODULES["upgrade_policy"].InvalidSignature)):
            project(value, pins)

    def test_source_scope_profile_and_units_are_bound(self):
        for field in ("source", "context", "parent", "output_content", "evaluation_protocol", "work_profile", "cost_unit", "units"):
            value, pins = fixture(upgrade="positive")
            if field == "source":
                value["source_commit"] = "a" * 40
            elif field == "units":
                value["resource_units"]["cpu_ns"] = "seconds"
            else:
                value["binding"][field] = "wrong-profile" if field == "work_profile" else "a" * 64
            repin(value, pins)
            with self.subTest(field=field), self.assertRaises(ValueError):
                project(value, pins)

    def test_missing_raw_rows_cannot_borrow_evaluation_summary(self):
        value, pins = fixture(upgrade="positive")
        del value["upgrade"]["actions"][1]["rows"]
        repin(value, pins)
        with self.assertRaisesRegex(ValueError, "FOUR_FIELDS"):
            project(value, pins)

    def test_tampered_cost_summary_and_unknown_gpu_refuse(self):
        for field in ("cpu_ns", "gpu_ns"):
            value, pins = fixture()
            value["utility"]["snapshot"]["cost_totals"][field] = 0
            repin(value, pins)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "FOUR_UTILITY_SNAPSHOT"):
                project(value, pins)

    def test_input_identity_cannot_silently_change(self):
        value, pins = fixture()
        value["utility"]["events"][0]["partition"] = "changed"
        with self.assertRaisesRegex(ValueError, "FOUR_INPUT_BINDING"):
            project(value, pins)

    def test_malformed_nested_containers_and_missing_event_fields_refuse(self):
        for malformed in ("demand-bundle", "utility-event"):
            value, pins = fixture()
            if malformed == "demand-bundle":
                value["demand"]["actions"][0]["bundle"] = []
            else:
                del value["utility"]["events"][0]["attempt"]
            repin(value, pins)
            with self.subTest(malformed=malformed), self.assertRaisesRegex(ValueError, "^FOUR_INPUT_SHAPE$"):
                project(value, pins)

    def test_unknown_authority_field_refuses_even_when_repinned(self):
        value, pins = fixture()
        value["qualified"] = True
        repin(value, pins)
        with self.assertRaisesRegex(ValueError, "FOUR_FIELDS"):
            project(value, pins)

    def test_strict_json_and_numeric_alias_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                view.loads(raw)
        value, pins = fixture()
        value["utility"]["events"][0]["sequence"] = True
        repin(value, pins)
        with self.assertRaisesRegex(ValueError, "FOUR_UTILITY_SEQUENCE"):
            project(value, pins)

    def test_zero_denominator_and_excessive_integer_text_refuse(self):
        for ratio in (["1", "0"], ["9" * 300, "1"]):
            value, pins = fixture()
            next(e for e in value["utility"]["events"] if e["kind"] == "verification")["quality_gain"] = ratio
            repin(value, pins)
            with self.subTest(ratio=ratio), self.assertRaisesRegex(ValueError, "FOUR_QUALITY_RATIO"):
                project(value, pins)

    def test_empty_utility_container_has_no_cost_observation(self):
        value, pins = fixture(demand=False, utility=False)
        m = MODULES["work_utility"]
        branch = demand_fixture.ident("branch")
        observer = m.UniqueUsefulOutputAccounting(context=value["binding"]["context"], current_branch=branch)
        value["utility"] = dict(initial_branch=branch, required_stages=list(m.STAGES), max_attempts=4096,
                                max_events=65536, events=[], snapshot=observer.snapshot())
        repin(value, pins)
        result = project(value, pins)
        self.assertEqual(result["propositions"]["sybil"]["observation_state"], "MISSING")
        self.assertFalse(result["supplied_observations_replayed"])

    def test_historical_checker_is_not_run_on_current_tree(self):
        with patch.object(MODULES["work_profile_contract_v1"], "check_contract", side_effect=AssertionError("historical replay")):
            result = project(*fixture())
        fact = result["propositions"]["sybil"]["facts"]
        self.assertFalse(fact["original_historical_source_checker_executed"])
        self.assertEqual(fact["original_research_contract_source"], MODULES["work_profile_contract_v1"].BASELINE)

    def test_dependency_byte_drift_refuses_before_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in view.SOURCE_BLOBS:
                destination = target / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE_ROOT / name, destination)
            changed = target / "formal/pon-nakamoto-v1/work_utility.py"
            changed.write_bytes(changed.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "FOUR_SOURCE_BYTES"):
                view.dependencies(target)

    def test_cli_reproduces_view_and_refuses_changed_proven_flag(self):
        value, pins = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "input.json").write_bytes(view.canonical(value))
            (folder / "pins.json").write_bytes(view.canonical(pins))
            command = [sys.executable, str(HERE / "four_propositions_v1.py"), "--input", str(folder / "input.json"),
                       "--pins", str(folder / "pins.json"), "--source-root", str(SOURCE_ROOT)]
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            first = subprocess.run(command, capture_output=True, env=env, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr.decode())
            output = json.loads(first.stdout)
            self.assertEqual(output, project(value, pins))
            output["propositions"]["sybil"]["proven"] = True
            (folder / "view.json").write_bytes(view.canonical(output))
            refused = subprocess.run(command + ["--check-view", str(folder / "view.json")],
                                     capture_output=True, env=env, timeout=30)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(b"FOUR_VIEW_MISMATCH", refused.stderr)
            self.assertEqual(refused.stdout, b"")
            self.assertNotIn(b"Traceback", refused.stderr)


if __name__ == "__main__":
    unittest.main()
