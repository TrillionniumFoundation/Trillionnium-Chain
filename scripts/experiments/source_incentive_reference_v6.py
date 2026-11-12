#!/usr/bin/env python3
"""Independent, standard-library source-incentive reference (research only).

This program does not import the Rust implementation or execute native payments.
Its exact-integer toy utility, digest namespace, and collateral state model are
explicitly separate from Chain execution. --receipt checks reported settlement
arithmetic; it does not authenticate the receipt, source provenance, adoption,
funding, or native game digest.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import itertools
import json
import math
import pathlib
import sys
import unittest
from fractions import Fraction

PROFILE = "reference.signed-i64-vector-addition.v6"
INPUT_SCHEMA = "trnm.source-incentive-reference.input.v6"
OUTPUT_SCHEMA = "trnm.source-incentive-reference.result.v6"
DOMAIN = b"TRNM_SOURCE_INCENTIVE_INDEPENDENT_REFERENCE_V6\0"
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
U64_MAX = (1 << 64) - 1
MAX_BYTES = 16 * 1024 * 1024
MAX_SOURCES, MAX_COMPONENTS, MAX_DIMENSION = 128, 4096, 256


class Rejected(ValueError):
    """A malformed or out-of-profile input, never a zero-valued observation."""


def exact_integer(value, name, minimum=0, maximum=U64_MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Rejected(f"{name}: expected exact integer in [{minimum}, {maximum}]")
    return value


def label(value, name):
    if not isinstance(value, str) or not value or len(value) > 256:
        raise Rejected(f"{name}: nonempty bounded string required")
    if not value.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise Rejected(f"{name}: printable ASCII without spaces required")
    return value


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(kind, value):
    return hashlib.sha512(DOMAIN + kind.encode("ascii") + b"\0"
                          + canonical_bytes(value)).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise Rejected(f"non-finite JSON number: {value}")


def finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise Rejected(f"non-finite JSON numeric literal: {token}")
    return value


def load_json(path):
    with pathlib.Path(path).open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise Rejected("JSON file exceeds 16 MiB")
    return (json.loads(raw, object_pairs_hook=unique_object,
                       parse_constant=reject_constant, parse_float=finite_float),
            hashlib.sha512(raw).hexdigest())


def select_pointer(value, pointer):
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise Rejected("receipt pointer must be an RFC 6901 absolute pointer")
    for encoded in pointer[1:].split("/"):
        if "~" in encoded.replace("~0", "").replace("~1", ""):
            raise Rejected("invalid JSON pointer escape")
        key = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not key.isdigit() or (len(key) > 1 and key.startswith("0")):
                raise Rejected("invalid array index in JSON pointer")
            value = value[int(key)]
        elif isinstance(value, dict):
            value = value[key]
        else:
            raise Rejected("JSON pointer traverses a scalar")
    return value


def vector(value, name, dimension=None):
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_DIMENSION:
        raise Rejected(f"{name}: bounded nonempty vector required")
    if dimension is not None and len(value) != dimension:
        raise Rejected(f"{name}: shape mismatch")
    return [exact_integer(x, f"{name}[{i}]", I64_MIN, I64_MAX)
            for i, x in enumerate(value)]


def canonical_game(spec):
    if not isinstance(spec, dict) or spec.get("schema") != INPUT_SCHEMA:
        raise Rejected("independent input schema mismatch")
    if spec.get("profile") != PROFILE:
        raise Rejected("unsupported reference profile")
    parent_id = label(spec.get("parent_id"), "parent_id")
    plan = label(spec.get("evaluation_plan"), "evaluation_plan")
    parent = vector(spec.get("parent"), "parent")
    target = vector(spec.get("target"), "target", len(parent))
    caps = spec.get("source_caps")
    if not isinstance(caps, dict) or not 1 <= len(caps) <= MAX_SOURCES:
        raise Rejected("source_caps must freeze a bounded nonempty source registry")
    for source, cap in caps.items():
        label(source, "source")
        exact_integer(cap, f"cap[{source}]")
    components = spec.get("components")
    if not isinstance(components, list) or len(components) > MAX_COMPONENTS:
        raise Rejected("component bound exceeded")
    totals = {source: [0] * len(parent) for source in caps}
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise Rejected("component must be an object")
        source = label(component.get("source"), "component.source")
        if source not in caps:
            raise Rejected("component source is outside the frozen registry")
        if component.get("parent_id") != parent_id:
            raise Rejected("component parent mismatch")
        if component.get("profile") != PROFILE:
            raise Rejected("component profile mismatch")
        delta = vector(component.get("delta"), f"delta[{index}]", len(parent))
        label(component.get("payee"), "component.payee")
        # Python integers widen exactly: no intermediate clipping, rounding,
        # saturation, or per-component positive-part operation is permitted.
        totals[source] = [a + b for a, b in zip(totals[source], delta)]
    updates = []
    for source in sorted(totals):
        final = vector(totals[source], f"aggregate[{source}]", len(parent))
        updates.append({"source": source, "delta": final})
    return {
        "schema": "trnm.source-incentive-reference.game.v6",
        "profile": PROFILE,
        "parent_id": parent_id,
        "parent": parent,
        "target": target,
        "evaluation_plan": plan,
        "source_updates": updates,
    }


def negative_squared_error(model, target):
    return -sum((x - y) ** 2 for x, y in zip(model, target))


def source_model(game, omitted=None):
    result = list(game["parent"])
    for update in game["source_updates"]:
        if update["source"] != omitted:
            result = [x + y for x, y in zip(result, update["delta"])]
    return vector(result, "composed_model", len(game["parent"]))


def settle(values, caps, budget, adopted=True):
    budget = exact_integer(budget, "budget")
    if type(adopted) is not bool:
        raise Rejected("adopted must be a boolean")
    if set(values) != set(caps):
        raise Rejected("value/cap source registry mismatch")
    for source, value in values.items():
        # Toy loss differences may exceed u64. Arithmetic is exact and has no
        # consensus-width claim; native receipt fields are separately bounded.
        if type(value) is not int or value < 0:
            raise Rejected(f"value[{source}] must be an exact nonnegative integer")
        exact_integer(caps[source], f"cap[{source}]")
    total = sum(values.values())
    rewards = {
        source: min(caps[source], budget * values[source] // total)
        if adopted and total > 0 else 0
        for source in sorted(values)
    }
    allocated = sum(rewards.values())
    if allocated > budget:
        raise Rejected("budget conservation violated")
    return {"total_weight": total, "budget": budget, "rewards": rewards,
            "allocated": allocated, "refund": budget - allocated}


def run_model(spec):
    game = canonical_game(spec)
    budget = exact_integer(spec.get("budget"), "budget")
    adopted = spec.get("adopted")
    full_valid = spec.get("full_model_valid")
    if type(adopted) is not bool or type(full_valid) is not bool:
        raise Rejected("adopted and full_model_valid must be explicit booleans")
    invalid = spec.get("invalid_counterfactual_sources")
    if not isinstance(invalid, list) or len(set(invalid)) != len(invalid):
        raise Rejected("invalid_counterfactual_sources must be a unique list")
    if any(source not in spec["source_caps"] for source in invalid):
        raise Rejected("invalid counterfactual has an unregistered source")
    contract = {"game_digest": digest("game", game), "budget": budget,
                "source_caps": spec["source_caps"], "adopted": adopted,
                "full_model_valid": full_valid,
                "invalid_counterfactual_sources": sorted(invalid)}
    result = {"game_digest": contract["game_digest"],
              "settlement_contract_digest": digest("contract", contract),
              "canonical_game": game,
              "utility": "exact_integer_negative_squared_error",
              "source_identity_assumed": True,
              "payout_authorization_verified": False}
    failures = []
    if not full_valid:
        failures.append({"kind": "full_model_invalid"})
    try:
        full = source_model(game)
    except Rejected as error:
        full = None
        failures.append({"kind": "full_model_out_of_profile", "reason": str(error)})
    counterfactuals = {}
    for update in game["source_updates"]:
        source = update["source"]
        if source in invalid:
            failures.append({"kind": "counterfactual_invalid", "source": source})
            continue
        try:
            counterfactuals[source] = source_model(game, source)
        except Rejected as error:
            failures.append({"kind": "counterfactual_out_of_profile",
                             "source": source, "reason": str(error)})
    if failures:
        # Missing utility is not materialized as numerical zero. There is no
        # payable score until the frozen counterfactual game is valid.
        result.update({"status": "InsufficientEvidence", "source_values": None,
                       "failures": failures, "allocated": 0, "refund": budget,
                       "rewards": {s: 0 for s in sorted(spec["source_caps"])}})
        return result
    full_utility = negative_squared_error(full, game["target"])
    without = {s: negative_squared_error(m, game["target"])
               for s, m in counterfactuals.items()}
    values = {s: max(0, full_utility - score) for s, score in without.items()}
    result.update({"status": "Adopted" if adopted else "NotAdopted",
                   "full_utility": full_utility, "without_utility": without,
                   "source_values": values})
    result.update(settle(values, spec["source_caps"], budget, adopted))
    return result


def identity_key(value, name):
    if isinstance(value, str):
        label(value, name)
    elif isinstance(value, list) and len(value) in (32, 64):
        for i, byte in enumerate(value):
            exact_integer(byte, f"{name}[{i}]", 0, 255)
    else:
        raise Rejected(f"{name}: expected text identity or 32/64-byte array")
    return canonical_bytes(value).decode("ascii")


def verify_receipt(receipt):
    """Recompute the explicit v6 arithmetic contract, never native execution."""
    if not isinstance(receipt, dict):
        raise Rejected("receipt object required")
    rows, payments = receipt.get("sources"), receipt.get("payments")
    if not isinstance(rows, list) or len(rows) > MAX_SOURCES:
        raise Rejected("bounded receipt sources required")
    if not isinstance(payments, list) or len(payments) > MAX_COMPONENTS:
        raise Rejected("bounded receipt payments required")
    values, caps, claimed = {}, {}, {}
    for row in rows:
        if not isinstance(row, dict):
            raise Rejected("receipt source row must be an object")
        source = identity_key(row.get("source"), "source")
        if source in values:
            raise Rejected("duplicate source row")
        values[source] = exact_integer(row.get("weight"), "weight")
        caps[source] = exact_integer(row.get("cap"), "cap")
        claimed[source] = exact_integer(row.get("reward"), "reward")
        if "standalone_correct" in row:
            exact_integer(row["standalone_correct"], "standalone_correct")
        exact_integer(row.get("without_correct"), "without_correct")
        identity_key(row.get("delta_hash"), "delta_hash")
    computed = settle(values, caps, receipt.get("budget"))
    for key in ("total_weight", "allocated", "refund"):
        if exact_integer(receipt.get(key), key) != computed[key]:
            raise Rejected(f"reported {key} disagrees with independent arithmetic")
    if claimed != computed["rewards"]:
        raise Rejected("source reward differs from source-level floor/cap")
    paid = {source: 0 for source in values}
    seen = set()
    for payment in payments:
        if not isinstance(payment, dict):
            raise Rejected("receipt payment row must be an object")
        source = identity_key(payment.get("source"), "payment.source")
        if source not in paid:
            raise Rejected("payment names an unregistered source")
        payee = identity_key(payment.get("payee"), "payment.payee")
        contribution = identity_key(payment.get("contribution"),
                                    "payment.contribution")
        if exact_integer(payment.get("marker"), "payment.marker") != 1:
            raise Rejected("receipt payment marker must equal model marker 1")
        key = (source, payee, contribution)
        if key in seen:
            raise Rejected("duplicate model payment identity")
        seen.add(key)
        paid[source] += exact_integer(payment.get("amount"), "payment.amount")
    if paid != claimed:
        raise Rejected("payment amounts do not sum to the source entitlements")
    game_digest = identity_key(receipt.get("game_digest"), "game_digest")
    return {
        "result": "PASS_REPORTED_ARITHMETIC_ONLY",
        "sources_checked": len(rows), "payments_checked": len(payments),
        "total_weight": computed["total_weight"], "budget": computed["budget"],
        "allocated": computed["allocated"], "refund": computed["refund"],
        "reported_game_digest": json.loads(game_digest),
        "native_game_digest_recomputed": False,
        "source_values_independently_verified": False,
        "source_provenance_verified": False,
        "funding_verified": False,
        "adoption_verified": False,
        "signature_verified": False,
        "actual_native_execution_verified": False,
        "conditional_rule": "eligible settlement; floor once per source then cap",
    }


def fraction_record(value):
    return {"numerator": str(value.numerator), "denominator": str(value.denominator),
            "decimal_approximation": float(value)}


def shared_deposit_gain(k, cost=Fraction(1), probability=Fraction(1, 20),
                        stake=Fraction(25)):
    exact_integer(k, "k", 0)
    if not 0 <= probability <= 1 or cost < 0 or stake < 0:
        raise Rejected("invalid economic model parameters")
    return k * cost - (1 - (1 - probability) ** k) * stake


class ReservationModel:
    """Finite integer accounting model; no native/real collateral reservation."""
    def __init__(self, deposited):
        self.deposited = exact_integer(deposited, "deposited")
        self.reserved = {}
        self.closed = {}
        self.slashed = 0
        self.withdrawn = 0

    @property
    def available(self):
        return (self.deposited - sum(self.reserved.values())
                - self.slashed - self.withdrawn)

    def invariant(self):
        if self.available < 0:
            raise Rejected("over-reserved collateral")
        return (self.available + sum(self.reserved.values())
                + self.slashed + self.withdrawn == self.deposited)

    def reserve(self, obligation, amount):
        label(obligation, "obligation")
        exact_integer(amount, "reservation", 1)
        if obligation in self.closed:
            raise Rejected("closed obligation cannot be reserved again")
        if obligation in self.reserved:
            if self.reserved[obligation] != amount:
                raise Rejected("reservation retry changed its amount")
            return "idempotent"
        if amount > self.available:
            raise Rejected("insufficient unreserved collateral")
        self.reserved[obligation] = amount
        assert self.invariant()
        return "reserved"

    def resolve(self, obligation, slash, audit_closed):
        if type(slash) is not bool or type(audit_closed) is not bool:
            raise Rejected("resolution flags must be booleans")
        if not audit_closed:
            raise Rejected("unresolved audit/dispute cannot release liability")
        if obligation in self.closed:
            if self.closed[obligation] != slash:
                raise Rejected("conflicting terminal resolution")
            return "idempotent"
        if obligation not in self.reserved:
            raise Rejected("unknown obligation")
        amount = self.reserved.pop(obligation)
        self.closed[obligation] = slash
        if slash:
            self.slashed += amount
        assert self.invariant()
        return "slashed" if slash else "released"

    def withdraw(self, amount):
        exact_integer(amount, "withdrawal")
        if amount > self.available:
            raise Rejected("withdrawal would consume unresolved liability")
        self.withdrawn += amount
        assert self.invariant()


def economic_models():
    p, stake, cost = Fraction(1, 20), Fraction(25), Fraction(1)
    rows = [{"k": k, "gain": fraction_record(shared_deposit_gain(k))}
            for k in (1, 5, 10, 11, 25, 100)]
    return {
        "shared_deposit": {
            "assumptions": ["independent task detections", "one shared slash at most",
                            "rewards already final and unrecoverable",
                            "no other recourse"],
            "cost_per_task": 1, "probability_per_task": fraction_record(p),
            "single_shared_stake": 25, "rows": rows,
            "first_profitable_k_in_1_to_100":
                next(k for k in range(1, 101) if shared_deposit_gain(k) > 0),
        },
        "exclusive_reservations": {
            "assumptions": ["each obligation owns separately executable stake",
                            "conditional effective punishment probability >= 1/20",
                            "cost saving <= 1 and no additional cheating benefit"],
            "independent_detections_required": False,
            "per_task_expected_gain_upper_bound": fraction_record(cost - p * stake),
            "k100_expected_gain_upper_bound": fraction_record(100 * (cost-p*stake)),
            "actual_funded_reservations_executed": False,
        },
        "seed_selection_stress": {
            "assumptions": ["m independent candidate seeds are all known",
                            "attacker may choose any candidate before obligation binds",
                            "each seed audits with probability p=1/20"],
            "formula": "unavoidable_audit_probability = p**m",
            "rows": [{"m": m, "probability": fraction_record(p ** m)}
                     for m in (1, 2, 4, 8)],
            "real_consensus_seed_distribution_verified": False,
        },
    }


def example_input():
    return {
        "schema": INPUT_SCHEMA, "profile": PROFILE, "parent_id": "parent-fixed",
        "parent": [0, 0], "target": [8, 3],
        "evaluation_plan": "toy-squared-error-fixed-v6",
        "source_caps": {"source-a": 100003, "source-b": 100003},
        "budget": 100003, "adopted": True, "full_model_valid": True,
        "invalid_counterfactual_sources": [],
        "components": [
            {"source": "source-a", "parent_id": "parent-fixed", "profile": PROFILE,
             "payee": "authorized-a", "delta": [6, 1]},
            {"source": "source-b", "parent_id": "parent-fixed", "profile": PROFILE,
             "payee": "authorized-b", "delta": [1, 1]},
        ],
    }


def split_example():
    spec = example_input()
    a = copy.deepcopy(spec["components"][0])
    z = copy.deepcopy(a)
    a["delta"], z["delta"] = [106, -39], [-100, 40]
    z["payee"] = "authorized-a-second-alias"
    spec["components"] = [a, z, spec["components"][1]]
    return spec


def example_receipt():
    return {
        "sources": [
            {"source": s, "delta_hash": "hash-" + s,
             "standalone_correct": 1, "without_correct": 1,
             "weight": w, "cap": cap, "reward": reward}
            for s, w, cap, reward in
            (("a", 5, 41, 41), ("b", 3, 101, 30), ("c", 2, 101, 20))
        ],
        "payments": [
            {"contribution": "c-" + s, "source": s, "payee": "p-" + s,
             "marker": 1, "amount": reward}
            for s, reward in (("a", 41), ("b", 30), ("c", 20))
        ],
        "game_digest": "untrusted-fixture-game-digest",
        "total_weight": 10, "budget": 101, "allocated": 91, "refund": 10,
    }


class ReferenceTests(unittest.TestCase):
    def test_known_integer_valuation_and_budget(self):
        got = run_model(example_input())
        self.assertEqual(got["full_utility"], -2)
        self.assertEqual(got["without_utility"], {"source-a": -53, "source-b": -8})
        self.assertEqual(got["source_values"], {"source-a": 51, "source-b": 6})
        self.assertEqual(got["rewards"], {"source-a": 89476, "source-b": 10526})
        self.assertEqual(got["refund"], 1)

    def test_signed_split_and_alias_invariance(self):
        self.assertEqual(run_model(example_input()), run_model(split_example()))

    def test_all_six_component_permutations(self):
        spec = split_example()
        expected = run_model(spec)
        for permutation in itertools.permutations(spec["components"]):
            varied = copy.deepcopy(spec)
            varied["components"] = list(permutation)
            self.assertEqual(run_model(varied), expected)

    def test_alias_only_change(self):
        spec = example_input()
        expected = run_model(spec)
        spec["components"][0]["payee"] = "another-authorized-alias"
        self.assertEqual(run_model(spec), expected)

    def test_zero_sum_components_not_positive_credit(self):
        spec = example_input()
        spec["components"][0]["delta"] = [99, -99]
        second = copy.deepcopy(spec["components"][0])
        second["delta"] = [-99, 99]
        spec["components"].append(second)
        self.assertEqual(run_model(spec)["source_values"]["source-a"], 0)

    def test_wide_accumulation_checks_only_final_source_sum(self):
        spec = example_input()
        spec["components"] = []
        for delta in ([I64_MAX, 0], [1, 0], [-I64_MAX, 1]):
            spec["components"].append(
                {"source": "source-a", "parent_id": "parent-fixed",
                 "profile": PROFILE, "payee": "a", "delta": delta})
        expected = canonical_game(spec)
        self.assertEqual(expected["source_updates"][0]["delta"], [1, 1])
        for permutation in itertools.permutations(spec["components"]):
            varied = copy.deepcopy(spec)
            varied["components"] = list(permutation)
            self.assertEqual(canonical_game(varied), expected)

    def test_out_of_range_source_sum_rejected(self):
        spec = example_input()
        spec["components"][0]["delta"] = [I64_MAX, 0]
        extra = copy.deepcopy(spec["components"][0])
        extra["delta"] = [1, 0]
        spec["components"].append(extra)
        with self.assertRaises(Rejected):
            canonical_game(spec)

    def test_profile_parent_shape_and_unknown_source_rejected(self):
        for key, value in (("profile", "float"), ("parent_id", "other"),
                           ("delta", [1]), ("source", "new-source")):
            with self.subTest(field=key):
                spec = example_input()
                spec["components"][0][key] = value
                with self.assertRaises(Rejected):
                    run_model(spec)

    def test_boolean_and_float_are_not_financial_integers(self):
        for bad in (True, 1.0, -1):
            with self.assertRaises(Rejected):
                settle({"a": 1}, {"a": 100}, bad)

    def test_invalid_counterfactual_is_missing_not_zero(self):
        spec = example_input()
        spec["invalid_counterfactual_sources"] = ["source-a"]
        got = run_model(spec)
        self.assertEqual(got["status"], "InsufficientEvidence")
        self.assertIsNone(got["source_values"])
        self.assertEqual((got["allocated"], got["refund"]), (0, 100003))

    def test_counterfactual_outside_profile_is_missing(self):
        spec = example_input()
        spec["parent"] = [I64_MAX, 0]
        spec["components"][0]["delta"] = [-1, 0]
        spec["components"][1]["delta"] = [1, 0]
        got = run_model(spec)
        self.assertEqual(got["status"], "InsufficientEvidence")
        self.assertTrue(any(x["kind"] == "counterfactual_out_of_profile"
                            for x in got["failures"]))

    def test_invalid_full_model_is_not_adopted(self):
        spec = example_input()
        spec["full_model_valid"] = False
        self.assertEqual(run_model(spec)["status"], "InsufficientEvidence")

    def test_source_cap_rounding_refund(self):
        self.assertEqual(
            settle({"a": 5, "b": 3, "c": 2}, {"a": 41, "b": 101, "c": 101}, 101),
            {"total_weight": 10, "budget": 101,
             "rewards": {"a": 41, "b": 30, "c": 20},
             "allocated": 91, "refund": 10})

    def test_zero_value_and_not_adopted_refund(self):
        for values, adopted in (({"a": 0}, True), ({"a": 1}, False)):
            got = settle(values, {"a": 100}, 100, adopted)
            self.assertEqual((got["allocated"], got["refund"]), (0, 100))

    def test_receipt_arithmetic_only(self):
        got = verify_receipt(example_receipt())
        self.assertEqual(got["result"], "PASS_REPORTED_ARITHMETIC_ONLY")
        self.assertFalse(got["actual_native_execution_verified"])

    def test_receipt_mutations_rejected(self):
        changes = [
            lambda r: r["sources"].append(copy.deepcopy(r["sources"][0])),
            lambda r: r["sources"][0].update(reward=42),
            lambda r: r["payments"][0].update(amount=42),
            lambda r: r["payments"][0].update(marker=True),
            lambda r: r["payments"][0].update(source="unknown"),
            lambda r: r["payments"].append(copy.deepcopy(r["payments"][0])),
            lambda r: r.update(allocated=92),
            lambda r: r.update(refund=11),
            lambda r: r.update(total_weight=11),
        ]
        for mutate in changes:
            receipt = example_receipt()
            mutate(receipt)
            with self.assertRaises(Rejected):
                verify_receipt(receipt)

    def test_duplicate_json_keys_and_nonfinite_rejected(self):
        for raw in ('{"budget":1,"budget":2}', '{"x":NaN}', '{"x":1e999}'):
            with self.assertRaises(Rejected):
                json.loads(raw, object_pairs_hook=unique_object,
                           parse_constant=reject_constant, parse_float=finite_float)

    def test_non_object_receipt_rows_rejected(self):
        for field in ("sources", "payments"):
            receipt = example_receipt()
            receipt[field][0] = "not-an-object"
            with self.assertRaises(Rejected):
                verify_receipt(receipt)

    def test_short_receipt_omits_standalone_metadata(self):
        receipt = example_receipt()
        for row in receipt["sources"]:
            del row["standalone_correct"]
        self.assertEqual(verify_receipt(receipt)["allocated"], 91)

    def test_shared_collateral_exact_counterexample(self):
        self.assertEqual(shared_deposit_gain(1), Fraction(-1, 4))
        self.assertLess(shared_deposit_gain(10), 0)
        self.assertGreater(shared_deposit_gain(11), 0)
        self.assertAlmostEqual(float(shared_deposit_gain(100)), 75.14801323050835)
        self.assertEqual(100 * (Fraction(1) - Fraction(1, 20) * 25), -25)

    def test_reservation_exclusion_and_unresolved_exit(self):
        ledger = ReservationModel(25)
        self.assertEqual(ledger.reserve("task-1", 25), "reserved")
        self.assertEqual(ledger.reserve("task-1", 25), "idempotent")
        for action in (lambda: ledger.reserve("task-2", 25),
                       lambda: ledger.reserve("task-1", 24),
                       lambda: ledger.withdraw(1),
                       lambda: ledger.resolve("task-1", False, False)):
            with self.assertRaises(Rejected):
                action()
        self.assertEqual(ledger.available, 0)
        self.assertEqual(ledger.resolve("task-1", True, True), "slashed")
        self.assertEqual(ledger.resolve("task-1", True, True), "idempotent")
        self.assertEqual(ledger.slashed, 25)
        self.assertTrue(ledger.invariant())
        with self.assertRaises(Rejected):
            ledger.reserve("task-1", 1)

    def test_distinct_obligations_consume_distinct_collateral(self):
        for order in itertools.permutations(("a", "b")):
            ledger = ReservationModel(50)
            for obligation in order:
                ledger.reserve(obligation, 25)
            ledger.resolve("a", True, True)
            ledger.resolve("b", True, True)
            self.assertEqual(ledger.slashed, 50)
            self.assertEqual(ledger.available, 0)

    def test_no_penalty_resolution_releases_only_its_reservation(self):
        ledger = ReservationModel(50)
        ledger.reserve("a", 25)
        ledger.reserve("b", 25)
        ledger.resolve("a", False, True)
        ledger.withdraw(25)
        self.assertEqual(ledger.reserved, {"b": 25})
        self.assertEqual(ledger.available, 0)
        self.assertTrue(ledger.invariant())

    def test_seed_choice_stress_model(self):
        p = Fraction(1, 20)
        self.assertEqual(p ** 2, Fraction(1, 400))
        self.assertLess(p ** 8, p)

    def test_json_pointer(self):
        self.assertEqual(select_pointer({"a/b": {"~": [7]}}, "/a~1b/~0/0"), 7)
        with self.assertRaises(Rejected):
            select_pointer({"x": [1]}, "/x/00")


def self_test_report():
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ReferenceTests))
    return {"result": "PASS" if result.wasSuccessful() else "FAIL",
            "tests_run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "log": stream.getvalue()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--input", help="independent exact-integer toy input JSON")
    parser.add_argument("--receipt", help="native output to inspect, never execute")
    parser.add_argument("--receipt-pointer", default="",
                        help="RFC 6901 pointer to sources/payments settlement object")
    parser.add_argument("--print-example-input", action="store_true")
    args = parser.parse_args(argv)
    if args.print_example_input:
        print(json.dumps(example_input(), sort_keys=True, indent=2))
        return 0
    report = {
        "schema": OUTPUT_SCHEMA, "model_only": True,
        "native_payment_executed": False, "market_test": False,
        "native_acceptance_granted": False,
        "source_file_sha512": hashlib.sha512(
            pathlib.Path(__file__).read_bytes()).hexdigest(),
        "scope": ["independent integer model", "finite collateral accounting model",
                  "reported receipt arithmetic only when explicitly requested"],
    }
    exit_code = 0
    try:
        if args.self_test:
            report["self_test"] = self_test_report()
            if report["self_test"]["result"] != "PASS":
                exit_code = 1
        if args.input:
            spec, input_hash = load_json(args.input)
            report["input_sha512"] = input_hash
        else:
            spec = example_input()
        report["reference"] = run_model(spec)
        report["economic_models"] = economic_models()
        if args.receipt:
            receipt, receipt_hash = load_json(args.receipt)
            report["receipt_sha512"] = receipt_hash
            report["receipt_pointer"] = args.receipt_pointer
            report["receipt_check"] = verify_receipt(
                select_pointer(receipt, args.receipt_pointer))
        if report["reference"]["status"] == "InsufficientEvidence":
            exit_code = max(exit_code, 2)
        report["result"] = ("PASS_MODEL_ONLY" if exit_code == 0 else
                            "INSUFFICIENT_EVIDENCE" if exit_code == 2 else
                            "FAIL_REFERENCE_CHECK")
    except (Rejected, OSError, KeyError, IndexError, TypeError,
            json.JSONDecodeError) as error:
        report["result"] = "REJECTED_REFERENCE_INPUT"
        report["error"] = str(error)
        exit_code = 1
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
