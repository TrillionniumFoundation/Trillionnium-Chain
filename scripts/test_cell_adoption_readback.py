"""Actual native engineering exports plus hostile byte/binding mutations.

The four positive files are captured from the original Rust owner tests, not
constructed by this Python suite. Their fixture expectations exercise parsing
and relations only; they are not independently authorized deployment pins.
That engineering scope also applies to the fixture-derived intent commitment.
Negative cases may rehash altered public grant bytes to reach a structural
guard; they never create a positive native grant or verify its signature.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import cell_adoption_readback as reader

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "evidence/cell-adoption-20261108/native-readbacks"
PHASES = ("retained_pending", "retained_acked", "adopted_pending", "adopted_acked")


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def encode_payload(payload):
    raw = compact(payload)
    return compact(dict(schema=reader.NATIVE_SCHEMA, payload_json=raw.decode(),
                        payload_digest=list(hashlib.sha256(reader.DOMAIN + raw).digest())))


def rehash_changed_signed_grant(publication):
    """Negative controls only: preserve the public digest, not grant authority."""
    publication["signed_grant_digest"] = list(hashlib.sha256(
        b"hepta.agentd.generation-update-signed-grant.v1\0" + compact(publication["signed"])).digest())


class NativeReadbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((FIXTURES / "fixture-manifest.json").read_bytes())
        if cls.manifest["scope"] != "original-native-engineering-fixtures-not-production":
            raise AssertionError("native fixture provenance scope changed")
        if set(cls.manifest["exports"]) != set(PHASES):
            raise AssertionError("incomplete original native export denominator")

    def case(self, phase="retained_acked"):
        raw = (FIXTURES / (phase + ".json")).read_bytes()
        expected_raw = (FIXTURES / (phase + ".expected.json")).read_bytes()
        record = self.manifest["exports"][phase]
        self.assertEqual(reader.sha(raw), record["sha256"])
        self.assertEqual(len(raw), record["bytes"])
        self.assertEqual(reader.sha(expected_raw), record["fixture_expected_sha256"])
        return raw, json.loads(expected_raw)

    def review(self, raw, expected):
        return reader.review_native_learning_use(raw, expected_readback_sha256=reader.sha(raw), expected=expected)

    def payload(self, phase="retained_acked"):
        raw, expected = self.case(phase)
        return json.loads(json.loads(raw)["payload_json"]), expected

    def test_all_four_original_native_exports_keep_authority_and_completion_boundaries(self):
        for phase in PHASES:
            with self.subTest(phase=phase):
                raw, expected = self.case(phase)
                before = copy.deepcopy(expected)
                result = self.review(raw, expected)
                self.assertEqual(expected, before)
                self.assertTrue(result["first_use_bindings_consistent"])
                self.assertEqual(result["qualification"], "HOLD_NO_GO")
                self.assertEqual(result["pending_delivery"], phase.endswith("_pending"))
                self.assertEqual(result["disposition"], "retained_model" if phase.startswith("retained") else "adopted_model_reset")
                self.assertEqual(result["original_intent_digest"], expected["intent_digest"])
                for key in ("full_learning_iteration_completed", "current_permission_exported",
                            "native_origin_authenticated", "grant_signature_verified_by_this_reader",
                            "request_digest_recomputed",
                            "cost_completeness_verified", "independent_control_accepted",
                            "real_model_training_verified", "physical_installation_accepted",
                            "settlement_verified", "hepta_final_use_accepted", "production_activation"):
                    self.assertIs(result[key], False)

    def test_actual_ack_changes_owner_cut_without_becoming_model_stop_or_learning_completion(self):
        for prefix in ("retained", "adopted"):
            before = self.review(*self.case(prefix + "_pending"))
            after = self.review(*self.case(prefix + "_acked"))
            self.assertNotEqual(before["owner_checkpoint"], after["owner_checkpoint"])
            self.assertEqual(before["manifest_digest"], after["manifest_digest"])
            self.assertEqual(before["committed_prefix_sha256"], after["committed_prefix_sha256"])
            self.assertFalse(after["pending_delivery"])
            self.assertFalse(after["full_learning_iteration_completed"])

    def test_exact_external_byte_pin_cannot_be_replaced_by_a_self_digest(self):
        raw, expected = self.case()
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_READBACK_PIN"):
            reader.review_native_learning_use(raw, expected_readback_sha256="0" * 64, expected=expected)

    def test_changed_payload_with_unchanged_native_commitment_is_refused(self):
        raw, expected = self.case()
        envelope = json.loads(raw)
        envelope["payload_json"] += " "
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_PAYLOAD_DIGEST"):
            self.review(compact(envelope), expected)

    def test_real_historical_download_and_64_forward_result_is_not_native_finaluse(self):
        raw = (ROOT / "evidence/smollm-cell-replica-research-v1/actual/research-result.json").read_bytes()
        self.assertEqual(reader.sha(raw), "21fd6c9a22cb8ae075fed1ffbf6af8bca388d3aa6c2731721ab676b8c59c1592")
        _, expected = self.case()
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_ENVELOPE_FIELDS"):
            self.review(raw, expected)

    def test_transport_complete_and_exit_zero_cannot_substitute_for_original_owner_bytes(self):
        _, expected = self.case()
        for value in (dict(status="transport-complete-handoff-pending", native_consumer_status="EXEC_REQUESTED",
                           native_receipt_status="UNVERIFIED"), dict(exit_code=0, installation_observed=True)):
            with self.subTest(value=value), self.assertRaises(reader.ReadbackRefusal):
                self.review(compact(value), expected)

    def test_authority_or_current_permission_claims_are_rejected_even_with_new_byte_pin(self):
        for field, value in (("authority", "ALLOW"), ("current_permission", "CURRENT")):
            payload, expected = self.payload(); payload[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_AUTHORITY_ESCALATION"):
                self.review(encode_payload(payload), expected)

    def test_wrong_next_task_or_input_cannot_be_spliced_into_an_authentic_publication(self):
        for name in ("task_digest", "input_digest", "source_frontier"):
            payload, expected = self.payload(); payload["intent"][name] = [197] * 32
            with self.subTest(name=name), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_TASK_INPUT_PIN"):
                self.review(encode_payload(payload), expected)

    def test_repinned_intent_still_has_to_match_the_original_first_input_observation(self):
        payload, expected = self.payload()
        payload["intent"]["input_digest"] = [197] * 32
        expected["input_digest"] = bytes([197] * 32).hex()
        # Explicitly change the synthetic expectation as well so this negative
        # reaches the separate original first-advance observation check.
        expected["intent_digest"] = reader.sha(reader.INTENT_DOMAIN + compact(payload["intent"]))
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_FIRST_INPUT_PIN"):
            self.review(encode_payload(payload), expected)

    def test_original_predecessor_and_deadline_are_bound_by_the_independent_intent_pin(self):
        for field in ("predecessor_digest", "deadline_micros"):
            payload, expected = self.payload()
            if field == "predecessor_digest":
                payload["intent"][field][0] ^= 1
            else:
                # A valid native deadline exceeds a nonzero admission time.
                # This remains a positive u64; the mismatch must hit the pin.
                payload["intent"][field] = 1
            with self.subTest(field=field), self.assertRaisesRegex(
                    reader.ReadbackRefusal, "EXPECTED_INTENT_BINDING"):
                self.review(encode_payload(payload), expected)

    def test_no_update_cannot_load_a_candidate_or_carry_a_model_reset_receipt(self):
        payload, expected = self.payload()
        candidate, _ = self.payload("adopted_acked")
        payload["manifest_json"] = candidate["manifest_json"]
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_MANIFEST_PIN"):
            self.review(encode_payload(payload), expected)
        payload, expected = self.payload()
        payload["observation"]["state_cutover_receipt"] = [197] * 32
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_RETAINED_USE_KIND"):
            self.review(encode_payload(payload), expected)

    def test_adopted_manifest_requires_the_exact_original_parent_manifest(self):
        payload, expected = self.payload("adopted_acked")
        payload["previous_manifest_json"] = payload["manifest_json"]
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_ADOPTED_MODEL_BINDING"):
            self.review(encode_payload(payload), expected)

    def test_rejected_cancelled_and_failed_receipts_cannot_become_next_use(self):
        for disposition in ("cancelled", "failed", "rejected", "deadline_exceeded"):
            payload, expected = self.payload()
            step = json.loads(payload["step_receipt_json"]); step["disposition"] = disposition
            raw = compact(step); payload["step_receipt_json"] = raw.decode()
            expected["committed_step_receipt"] = reader.sha(reader.STEP_DOMAIN + raw)
            payload["observation"]["committed_step_receipt"] = list(bytes.fromhex(expected["committed_step_receipt"]))
            with self.subTest(disposition=disposition), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_UNSUCCESSFUL_STEP"):
                self.review(encode_payload(payload), expected)

    def test_original_successful_step_bytes_must_match_the_committed_receipt(self):
        payload, expected = self.payload()
        step = json.loads(payload["step_receipt_json"]); step["proposal_digest"] = [197] * 32
        payload["step_receipt_json"] = compact(step).decode()
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_STEP_RECEIPT_DIGEST"):
            self.review(encode_payload(payload), expected)

    def test_old_learning_cut_cannot_be_relabelled_as_this_publication(self):
        payload, expected = self.payload()
        payload["learning_decision_head"] = [197] * 32
        expected["learning_decision_head"] = bytes([197] * 32).hex()
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_LEARNING_PUBLICATION_OPERATION"):
            self.review(encode_payload(payload), expected)

    def test_pending_output_is_checked_against_the_exact_committed_prefix(self):
        payload, expected = self.payload("retained_pending")
        generation = json.loads(payload["generation_observation_json"])
        generation["pending_output"]["bytes"] = [197]
        payload["generation_observation_json"] = compact(generation).decode()
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_PENDING_PREFIX"):
            self.review(encode_payload(payload), expected)

    def test_bool_and_float_cannot_alias_native_integers_or_digest_bytes(self):
        for value in (True, 1.0, -1, 1 << 64):
            payload, expected = self.payload(); payload["intent"]["deadline_micros"] = value
            with self.subTest(value=value), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_INTEGER"):
                self.review(encode_payload(payload), expected)
        payload, expected = self.payload(); payload["learning_head"][0] = True
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_INTEGER"):
            self.review(encode_payload(payload), expected)

    def test_snapshot_manifest_digest_refuses_float_and_boolean_byte_aliases(self):
        for kind in ("float_alias", "true", "false"):
            payload, expected = self.payload()
            generation = json.loads(payload["generation_observation_json"])
            digest = generation["snapshot"]["manifest_digest"]
            if kind == "float_alias":
                # This would compare equal under Python list equality, unlike
                # serde's [u8; 32]. The original expected manifest stays fixed.
                digest[0] = float(digest[0])
            else:
                value = kind == "true"
                # Prefer a numeric alias if this exact native digest has one;
                # every digest must reject bool bytes regardless of its values.
                index = digest.index(int(value)) if int(value) in digest else 0
                digest[index] = value
            payload["generation_observation_json"] = compact(generation).decode()
            with self.subTest(kind=kind), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_INTEGER"):
                self.review(encode_payload(payload), expected)

    def test_manifest_zero_digest_rejections_match_the_native_required_bindings(self):
        payload, _ = self.payload()
        original = json.loads(payload["manifest_json"])
        paths = [(name,) for name in ("source_digest", "bundle_digest", "runtime_digest",
                                      "device_digest", "input_schema", "state_schema", "output_schema")]
        paths.extend((name,) for name in ("encoder", "head", "memory", "world_model", "decoder")
                     if original[name] is not None)
        paths.extend(("learning", name) for name in original["learning"] if name != "kind")
        paths.extend(("evolution", name) for name in original["evolution"])
        for path in paths:
            manifest = copy.deepcopy(original)
            target = manifest if len(path) == 1 else manifest[path[0]]
            target[path[-1]] = [0] * 32
            # Direct validation reaches the native nonzero rule, instead of an
            # unrelated changed-manifest pin. Absent components stay absent.
            with self.subTest(path=path), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_ZERO_DIGEST"):
                reader.check_manifest(compact(manifest), manifest)

    def test_owner_zero_digest_rejections_match_the_native_required_bindings(self):
        payload, _ = self.payload()
        original = json.loads(payload["publication_json"])["intent"]["target"]
        paths = [("scope", "principal_digest")] + [(name,) for name in (
            "manifest_digest", "task_digest", "source_frontier", "initial_snapshot_digest", "config_digest")]
        for path in paths:
            owner = copy.deepcopy(original)
            target = owner if len(path) == 1 else owner[path[0]]
            target[path[-1]] = [0] * 32
            with self.subTest(path=path), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_ZERO_DIGEST"):
                reader.check_owner(owner)

    def test_consumer_entry_witness_cannot_replace_the_original_dispatch_boundary(self):
        payload, _ = self.payload()
        publication = json.loads(payload["publication_json"])
        publication["witness"]["boundary"] = "consumer_entry"
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_WITNESS_WINDOW"):
            reader.check_public_grant_binding(publication)

    def test_zero_authority_epoch_and_revocation_revision_are_refused(self):
        for field in ("authority_epoch", "revocation_revision"):
            payload, _ = self.payload()
            publication = json.loads(payload["publication_json"])
            if field == "authority_epoch":
                publication["signed"]["grant"]["authority_epoch"] = 0
                publication["witness"]["authority_epoch"] = 0
                rehash_changed_signed_grant(publication)
            else:
                publication["witness"]["authority_ref"]["authority"]["revocation_revision"] = 0
            with self.subTest(field=field), self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_INTEGER"):
                reader.check_public_grant_binding(publication)

    def test_zero_nonce_and_overlong_final_use_window_are_refused(self):
        for case in ("zero_nonce", "overlong_window"):
            payload, _ = self.payload()
            publication = json.loads(payload["publication_json"])
            grant = publication["signed"]["grant"]
            if case == "zero_nonce":
                grant["nonce"] = [0] * 32
                error = "NATIVE_ZERO_DIGEST"
            else:
                grant["expires_at_unix_ms"] = grant["not_before_unix_ms"] + 300001
                error = "NATIVE_GRANT_WINDOW"
            rehash_changed_signed_grant(publication)
            with self.subTest(case=case), self.assertRaisesRegex(reader.ReadbackRefusal, error):
                reader.check_public_grant_binding(publication)

    def test_duplicate_keys_are_rejected_in_outer_and_nested_original_json(self):
        raw, expected = self.case()
        duplicate = raw[:-1] + b',"schema":"hepta.agentd.learning-use-readback.v1"}'
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_DUPLICATE_FIELD"):
            self.review(duplicate, expected)
        payload, expected = self.payload()
        payload["manifest_json"] = payload["manifest_json"][:-1] + ',"profile":"shadow"}'
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_DUPLICATE_FIELD"):
            self.review(encode_payload(payload), expected)

    def test_unknown_fields_and_unsupported_schemas_are_refused(self):
        payload, expected = self.payload(); payload["installation_observed"] = True
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_PAYLOAD_FIELDS"):
            self.review(encode_payload(payload), expected)
        raw, expected = self.case(); envelope = json.loads(raw); envelope["schema"] = "future-unreviewed-v2"
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_SCHEMA"):
            self.review(compact(envelope), expected)

    def test_wire_file_and_expectation_bounds_are_enforced_before_use(self):
        _, expected = self.case()
        with self.assertRaisesRegex(reader.ReadbackRefusal, "NATIVE_WIRE_LIMIT"):
            self.review(b" " * (reader.MAX_WIRE + 1), expected)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "too-large"
            path.write_bytes(b"x" * 65)
            with self.assertRaisesRegex(reader.ReadbackRefusal, "INPUT_FILE_BOUND"):
                reader.read_bounded(path, 64)
            fifo = Path(directory) / "not-a-regular-file"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(reader.ReadbackRefusal, "INPUT_FILE_BOUND"):
                reader.read_bounded(fifo, 64)


if __name__ == "__main__":
    unittest.main()
