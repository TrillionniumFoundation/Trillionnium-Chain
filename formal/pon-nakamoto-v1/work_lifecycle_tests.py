"""Required real-native tests for authenticated lifecycle observations and help.

WLC_NATIVE_WORK and WLC_NATIVE_PQ must name built existing examples.  No absent
backend is skipped.  This suite is independent of the artifact-producing
work_lifecycle_observe.py command; CI runs both and retains the latter output.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from fractions import Fraction
from functools import lru_cache
import itertools
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

import mandatory_units_relation as mu
import work_lifecycle_certificate as wlc
from work_lifecycle_help import HelpPolicy, HelpSlot, finite_help_weight_bound, multiply_fixed_support
import work_lifecycle_observe as observe


def native_path(variable: str) -> Path:
    value = os.environ.get(variable)
    if value is None or not Path(value).is_file():
        raise RuntimeError(variable + " must name the existing built native example; no fallback")
    return Path(value)


@lru_cache(maxsize=1)
def actual_fixture() -> dict:
    return observe.collect(native_path("WLC_NATIVE_WORK"))


def minimal(policy: HelpPolicy = HelpPolicy(()), events=()):
    key = MLDSA65PrivateKey.generate()
    writer = wlc.ObservationWriter(key, session=wlc.sha256(b"WLC1 test session"),
                                   source_commit=observe.BASE_COMMIT,
                                   source_manifest={"fixture": wlc.sha256(b"fixture")},
                                   help_policy=policy)
    for kind, body in events:
        writer.append(kind, body)
    document, pin = writer.close()
    return key, document, pin


class SignatureAndChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = {wlc.sha256(b"public fixture"): b"public fixture"}
        cls.key, cls.doc, cls.pin = minimal(events=(
            ("resource_reading", {"quantity": "elapsed_ns", "value": 17, "bound_direction": "observation_only"}),
            ("publish_artifact", {"artifact_sha256": wlc.sha256(b"public fixture"),
                                  "artifact_bytes": 14, "role": "classical_help"}),
            ("resource_reading", {"quantity": "process_user_ns", "value": 9, "bound_direction": "observation_only"}),
        ))

    def check(self, doc=None, pin=None, artifacts=None):
        return wlc.verify_collection({"root": self.doc if doc is None else doc},
                                     {"root": self.pin if pin is None else pin},
                                     self.artifacts if artifacts is None else artifacts, "root")

    def test_actual_mldsa_signature_and_pinned_chain_verify(self):
        result = self.check()
        self.assertTrue(result["root"]["signatures_verified_against_supplied_external_pin"])
        self.assertTrue(result["root"]["anchored_observation_fragment_complete"])
        self.assertEqual(len(self.pin.public_spki), 1974)
        self.assertEqual(len(bytes.fromhex(self.doc["end"]["signature"])), 3309)
        self.assertFalse(result["query_budget_eligible"])

    def test_signature_message_or_signature_bit_change_rejects(self):
        for cut in ("start", "end"):
            doc = copy.deepcopy(self.doc)
            signature = bytearray.fromhex(doc[cut]["signature"])
            signature[43] ^= 1
            doc[cut]["signature"] = signature.hex()
            with self.subTest(cut=cut), self.assertRaisesRegex(wlc.LifecycleError, "SIGNATURE_REJECTED"):
                self.check(doc)

    def test_external_key_pin_cannot_be_supplied_by_attacker(self):
        other_key = MLDSA65PrivateKey.generate()
        fake_pin = replace(self.pin, public_spki=wlc.public_spki(other_key))
        with self.assertRaisesRegex(wlc.LifecycleError, "EXTERNAL_SIGNER_PIN"):
            self.check(pin=fake_pin)
        bad = copy.deepcopy(self.doc)
        bad["header"]["key_id"] = wlc.key_id(wlc.public_spki(other_key))
        with self.assertRaisesRegex(wlc.LifecycleError, "EXTERNAL_SIGNER_PIN"):
            self.check(bad)

    def test_classical_or_wrong_pq_key_formats_do_not_downgrade(self):
        for spki in (bytes(32), self.pin.public_spki[:-1], self.pin.public_spki + b"\0"):
            with self.subTest(length=len(spki)), self.assertRaisesRegex(wlc.LifecycleError, "MLDSA65_PINNED_SPKI"):
                self.check(pin=replace(self.pin, public_spki=spki))
        doc = copy.deepcopy(self.doc)
        doc["header"]["algorithm"] = "Ed25519"
        with self.assertRaisesRegex(wlc.LifecycleError, "SIGNATURE_ALGORITHM"):
            self.check(doc)

    def test_first_middle_last_event_omission_rejects_against_pinned_extent(self):
        for position in range(3):
            doc = copy.deepcopy(self.doc)
            del doc["events"][position]
            with self.subTest(position=position), self.assertRaisesRegex(wlc.LifecycleError, "ANCHORED_EVENT_EXTENT"):
                self.check(doc)

    def test_event_reorder_duplicate_or_in_place_change_rejects(self):
        for operation in ("swap", "duplicate", "edit"):
            doc = copy.deepcopy(self.doc)
            if operation == "swap":
                doc["events"][0], doc["events"][1] = doc["events"][1], doc["events"][0]
            elif operation == "duplicate":
                doc["events"][1] = copy.deepcopy(doc["events"][0])
            else:
                doc["events"][0]["body"]["value"] += 1
            with self.subTest(operation=operation), self.assertRaisesRegex(wlc.LifecycleError, "EVENT_CHAIN_ORDER"):
                self.check(doc)

    def test_newly_signed_prefix_is_rejected_by_independent_final_pin(self):
        doc = copy.deepcopy(self.doc)
        del doc["events"][-1]
        statement = doc["end"]["statement"]
        statement["sequence"] = 2
        statement["head"] = wlc.domain_digest(b"event", doc["events"][-1])
        doc["end"]["signature"] = self.key.sign(wlc.checkpoint_message(statement)).hex()
        with self.assertRaisesRegex(wlc.LifecycleError, "ANCHORED_EVENT_EXTENT"):
            self.check(doc)

    def test_artifact_bytes_not_just_names_are_required(self):
        with self.assertRaisesRegex(wlc.LifecycleError, "MISSING_ARTIFACT"):
            self.check(artifacts={})
        bad = {next(iter(self.artifacts)): b"altered bytes"}
        with self.assertRaisesRegex(wlc.LifecycleError, "ARTIFACT_HASH"):
            self.check(artifacts=bad)

    def test_even_signed_claims_cannot_promote_physical_resource_or_initial_state(self):
        _, doc, pin = minimal(events=(("resource_reading", {"quantity": "elapsed_ns", "value": 0,
                                                          "bound_direction": "global_upper_bound"}),))
        with self.assertRaisesRegex(wlc.LifecycleError, "RESOURCE_BOUND_PROMOTION"):
            wlc.verify_collection({"r": doc}, {"r": pin}, {}, "r")
        bad = copy.deepcopy(self.doc)
        bad["header"]["initial_state_certificate"] = "fresh"
        with self.assertRaisesRegex(wlc.LifecycleError, "UNSUPPORTED_RESOURCE_AUTHORITY"):
            self.check(bad)
        for value in (self.check(), {"verified": True, "all_world_events_covered": True}):
            with self.assertRaisesRegex(wlc.LifecycleError, "LIFECYCLE_COVERAGE_AND_INITIAL_STATE_UNATTESTED"):
                wlc.query_budget_from_observation(value)

    def test_signed_complete_work_label_requires_prior_full_predicate_recheck(self):
        for role, message in (("complete_mu1_packet", "PUBLISH_WITHOUT_COMPLETE_MU1_PREDICATE"),
                              ("full_w1_proof", "PUBLISH_WITHOUT_COMPLETE_W1_PREDICATE")):
            _, doc, pin = minimal(events=(("publish_artifact", {
                "artifact_sha256": wlc.sha256(b"public fixture"), "artifact_bytes": 14, "role": role}),))
            with self.subTest(role=role), self.assertRaisesRegex(wlc.LifecycleError, message):
                wlc.verify_collection({"r": doc}, {"r": pin}, self.artifacts, "r")

    def test_duplicate_keys_floats_extra_authority_fields_and_bool_sequences_reject(self):
        with self.assertRaisesRegex(wlc.LifecycleError, "DUPLICATE_JSON_KEY"):
            wlc.strict_load(b'{"a":1,"a":2}')
        for raw in (b'{"a":NaN}', b'{"a":1.5}'):
            with self.assertRaises(wlc.LifecycleError):
                wlc.strict_load(raw)
        bad = copy.deepcopy(self.doc)
        bad["signature_valid"] = True
        with self.assertRaisesRegex(wlc.LifecycleError, "DOCUMENT_FIELDS"):
            self.check(bad)
        bad = copy.deepcopy(self.doc)
        bad["events"][0]["sequence"] = True
        with self.assertRaisesRegex(wlc.LifecycleError, "EVENT_CHAIN_ORDER"):
            self.check(bad)


class NativeAndProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observed = actual_fixture()

    def check(self, documents=None, pins=None, artifacts=None):
        o = self.observed
        return wlc.verify_collection(o["documents"] if documents is None else documents,
                                     o["pins"] if pins is None else pins,
                                     o["artifacts"] if artifacts is None else artifacts, "receiver")

    def test_complete_actual_w1_and_mu1_artifacts_follow_signed_source_chain(self):
        result = self.check()
        self.assertEqual(set(result["verified_sources"]), {"receiver", "public-helper"})
        self.assertEqual(result["root"]["signed_source_links"], ["public-helper"])
        self.assertEqual(result["verified_sources"]["public-helper"]["counters"]["unmetered_import_records"], 2)
        self.assertEqual(result["root"]["counters"]["full_W1_artifact_predicates_rechecked"], 2)
        self.assertEqual(result["root"]["counters"]["reported_native_nonzero_exits"], 1)
        self.assertFalse(result["root"]["all_world_events_covered"])

    def test_actual_openssl_signatures_cross_verify_with_existing_rustcrypto(self):
        row = observe.native_pq_differential(native_path("WLC_NATIVE_PQ"), self.observed)
        self.assertEqual(row["positive_signatures"], 4)
        self.assertEqual(row["negative_controls"], 8)
        self.assertEqual(row["verification_items"], 12)

    def test_public_receipt_matches_native_without_calling_w1_or_native_code(self):
        call = self.observed["calls"][0]["body"]
        inp = self.observed["artifacts"][call["input_sha256"]]
        out = self.observed["artifacts"][call["output_sha256"]]
        with patch.object(observe, "run_bounded", side_effect=AssertionError("native called")), \
                patch.object(mu.w1, "verify", side_effect=AssertionError("W1 checked")):
            self.assertEqual(observe.public_receipt_without_verification(inp), out)
        self.assertEqual(self.observed["receipt_controls"]["native_calls_during_public_receipt_recomputation"], 0)

    def test_invalid_work_has_public_receipt_but_real_native_rejects(self):
        row = self.observed["receipt_controls"]
        self.assertTrue(row["invalid_public_receipt_is_well_formed"])
        self.assertEqual(row["real_native_invalid_returncode"], 2)
        self.assertEqual(row["real_native_invalid_stderr"], "WORK\n")
        self.assertFalse(row["receipt_alone_authenticates_execution"])

    def test_signed_false_execution_claim_still_must_pass_full_artifact_predicate(self):
        o = self.observed
        bad = copy.deepcopy(o["calls"][-1]["body"])
        bad["returncode"] = 0
        receipt = bytes.fromhex(o["receipt_controls"]["invalid_input_public_receipt_hex"])
        bad["output_sha256"] = wlc.sha256(receipt)
        bad["output_bytes"] = 32
        key = MLDSA65PrivateKey.generate()
        writer = wlc.ObservationWriter(key, session=wlc.sha256(b"false signed execution observation"),
                                       source_commit=observe.BASE_COMMIT, source_manifest=o["source_manifest"],
                                       help_policy=HelpPolicy(()))
        writer.append("native_call", bad)
        doc, pin = writer.close()
        with self.assertRaisesRegex(wlc.LifecycleError, "ARTIFACT_FULL_W1_PREDICATE:TRANSCRIPT"):
            wlc.verify_collection({"false": doc}, {"false": pin}, o["artifacts"], "false")

    def test_helper_signature_or_missing_source_cannot_be_replaced_by_valid_boolean(self):
        docs = copy.deepcopy(self.observed["documents"])
        docs["public-helper"]["end"]["signature"] = bytes(3309).hex()
        with self.assertRaisesRegex(wlc.LifecycleError, "SIGNATURE_REJECTED"):
            self.check(documents=docs)
        docs = {"receiver": self.observed["documents"]["receiver"]}
        with self.assertRaisesRegex(wlc.LifecycleError, "UNRESOLVED_SIGNED_SOURCE"):
            self.check(documents=docs)

    def test_new_signed_receiver_cannot_point_to_wrong_source_artifact(self):
        o = self.observed
        body = copy.deepcopy(o["documents"]["receiver"]["events"][0]["body"])
        raw = b"different public help"
        body["payload_sha256"] = wlc.sha256(raw)
        body["delivery"]["payload_bytes"] = len(raw)
        key = MLDSA65PrivateKey.generate()
        writer = wlc.ObservationWriter(key, session=wlc.sha256(b"wrong published source artifact"),
                                       source_commit=observe.BASE_COMMIT, source_manifest=o["source_manifest"],
                                       help_policy=o["policy"])
        writer.append("help_delivery", body)
        doc, pin = writer.close()
        docs, pins, artifacts = dict(o["documents"]), dict(o["pins"]), dict(o["artifacts"])
        docs["receiver"], pins["receiver"] = doc, pin
        artifacts[wlc.sha256(raw)] = raw
        with self.assertRaisesRegex(wlc.LifecycleError, "SIGNED_SOURCE_ARTIFACT_BINDING"):
            self.check(docs, pins, artifacts)

    def test_actual_sha_frame_replays_without_implying_independent_domains(self):
        row = self.observed["hash_composition"]
        self.assertTrue(row["actual_sha256_recomputation_matches"])
        self.assertTrue(row["same_public_SHA256_primitive"])
        self.assertFalse(row["actual_domains_proved_independent_random_functions"])
        self.assertFalse(row["preprocessing_aware_composition_proved"])


class FiniteHelpTests(unittest.TestCase):
    def test_support_counts_all_sources_lengths_absence_errors_and_delivery_bins(self):
        slot = HelpSlot(("a", "b"), 3, 0, 2)
        # Enumerate actual distinct symbolic outcomes independently of the formula.
        alphabet = {("absent",)}
        for source, delivery in itertools.product(("a", "b"), range(3)):
            alphabet.add(("data", source, delivery, b""))
            for error in (0, 1):
                alphabet.add(("error", source, delivery, error))
        self.assertEqual(len(alphabet), 19)
        for cap in (1, 2, 18, 19, 20, 100):
            self.assertEqual(slot.support_capped(cap), min(cap, len(alphabet)))
        byte_alphabet = {("absent",), ("data", b"")}
        byte_alphabet.update(("data", bytes([x])) for x in range(256))
        second = HelpSlot(("a",), 1, 1, 0)
        self.assertEqual(second.support_capped(1000), len(byte_alphabet))
        policy = HelpPolicy((slot, second))
        self.assertEqual(policy.support_capped(10000), len(alphabet) * len(byte_alphabet))

    def test_observed_or_per_oracle_singleton_support_is_a_concrete_counterexample(self):
        p, probability = Fraction(1, 16), Fraction(0)
        used = set()
        for mask in range(1 << 8):
            chosen = next((i for i in range(8) if mask & (1 << i)), 0)
            used.add(chosen)
            # The helper is deterministic for EACH oracle: conditional support=1.
            if mask & (1 << chosen):
                hits = mask.bit_count()
                probability += p ** hits * (1 - p) ** (8 - hits)
        self.assertEqual(probability, 1 - (1 - p) ** 8)
        self.assertGreater(probability, multiply_fixed_support(p, 1))
        self.assertEqual(len(used), 8)
        self.assertLessEqual(probability, multiply_fixed_support(p, 8))

    def test_interactive_classical_help_is_dominated_by_forced_transcripts(self):
        p = Fraction(1, 4)
        actual = Fraction(0)
        forced = [Fraction(0), Fraction(0)]
        for mask in range(1 << 3):
            weight = p ** mask.bit_count() * (1 - p) ** (3 - mask.bit_count())
            first_hit = bool(mask & 1)
            help_bit = 0 if mask & 2 else 1
            if first_hit or mask & (1 << (1 + help_bit)):
                actual += weight
            for t in (0, 1):
                if first_hit or mask & (1 << (1 + t)):
                    forced[t] += weight
        self.assertEqual(actual, 1 - (1 - p) ** 3)
        self.assertEqual(forced[0], forced[1])
        self.assertLessEqual(actual, multiply_fixed_support(forced[0], 2))

    def test_zero_payload_bytes_still_carry_absence_or_error_information(self):
        slot = HelpSlot(("a",), 1, 0, 0)
        self.assertEqual(slot.support_capped(100), 2)  # absent versus empty data
        self.assertEqual(HelpSlot(("a",), 1, 0, 1).support_capped(100), 3)
        self.assertEqual(HelpSlot(("a",), 2, 0, 0).support_capped(100), 3)

    def test_one_byte_help_has_nontrivial_conditional_bound_but_real_packet_does_not(self):
        policy = HelpPolicy((HelpSlot(("fixed-source",), 1, 1, 0),))
        row = finite_help_weight_bound(1, 64, 8192, policy)
        self.assertEqual(row["global_support_capped_at_threshold"], 258)
        self.assertLess(row["bound"], Fraction(12, 100))
        self.assertGreater(row["bound"], Fraction(11, 100))
        self.assertFalse(row["fixed_global_support_verified_by_this_function"])
        self.assertEqual(finite_help_weight_bound(1, 64, 8192, actual_fixture()["policy"])["bound"], 1)

    def test_deliveries_must_fit_predeclared_complete_alphabet(self):
        policy = HelpPolicy((HelpSlot(("fixed",), 2, 1, 1),))
        data = {"slot": 0, "status": "data", "source": "fixed", "delivery_bin": 1,
                "payload_bytes": 1, "error_code": None}
        self.assertEqual(policy.validate_delivery(data, b"a"), 0)
        for field, value in (("slot", 1), ("source", "unlisted"), ("delivery_bin", 2),
                             ("payload_bytes", True), ("error_code", 0)):
            altered = {**data, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.validate_delivery(altered, b"a")
        with self.assertRaisesRegex(ValueError, "HELP_DATA_ENCODING"):
            policy.validate_delivery({**data, "payload_bytes": 2}, b"ab")
        with self.assertRaises(ValueError):
            HelpSlot(("fixed",), "unbounded-real-time", 1, 0).check()

    def test_no_help_and_impossible_output_threshold_boundaries(self):
        policy = HelpPolicy(())
        row = finite_help_weight_bound(1, 64, 8192, policy)
        self.assertEqual(row["bound"], row["fresh_uniform_bound"])
        self.assertEqual(row["global_support_capped_at_threshold"], 1)
        self.assertEqual(finite_help_weight_bound(1, 3, 385, policy)["bound"], 0)
        self.assertEqual(finite_help_weight_bound(0, 0, 0, policy)["bound"], 1)

    def test_unmodeled_support_declarations_are_not_accepted_as_policy(self):
        for bad in ({"schema": "observed-support", "slots": []},
                    {"schema": "pon-work-lifecycle-fixed-classical-help-v1", "slots": [], "observed_support": 1}):
            with self.assertRaises(ValueError):
                HelpPolicy.from_wire(bad)
        for bad in (0, True, None):
            with self.assertRaises(ValueError):
                multiply_fixed_support(Fraction(1, 2), bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
