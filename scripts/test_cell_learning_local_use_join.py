"""Original HEPLCP04 actor completions and hostile composition controls.

The three positive cases are captured from the exact 93fc43f6 native actor run.
Missing exports are failures, never skips or generated substitutes. Encoders
below are imported only for explicit negative mutations. The native local actor
fixtures have no pending output; pending-state attacks are labelled mutations and
are not presented as native pre-ACK observations.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import capture_cell_learning_local_use as capture
import cell_adoption_readback as native
import cell_learning_iteration_join as legacy
import cell_learning_local_decision_join as local
import cell_learning_local_use_join as joined
from test_cell_adoption_readback import compact, encode_payload
from test_cell_learning_local_decision_join import mutated_encoding, rehash

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "evidence/heplcp04-completed-use-20261111/native-readbacks"
NATIVE_SOURCE = "93fc43f6e87c4514485adcb01a7ffec8ad3b632f"
NATIVE_STDOUT_SHA256 = "3e7ee2dcd9019949256a2987a3c8612d976952a58503d7050198adaab11a5261"
FALSE_CLAIMS = (
    "output_ack_event_verified",
    "full_learning_iteration_completed", "native_origin_authenticated", "source_execution_authenticated",
    "pre_dispatch_freeze_authenticated", "learning_signatures_verified", "root_scope_authenticated",
    "independent_consumer_verified", "independent_control_accepted", "real_model_training_verified",
    "cost_completeness_verified", "physical_installation_accepted", "settlement_verified",
    "current_permission_exported", "grant_signature_verified_by_this_reader", "full_state_restore_qualified",
    "hepta_final_use_accepted", "production_activation")


class LocalDecisionCompletedUseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((FIXTURES / "fixture-manifest.json").read_bytes())
        if (cls.manifest["schema"] != capture.MANIFEST_SCHEMA or
            cls.manifest["scope"] != "original-native-engineering-fixtures-not-production" or
            cls.manifest["native_source"] != NATIVE_SOURCE or
            set(cls.manifest["exports"]) != set(capture.PHASES)):
            raise AssertionError("native fixture scope, source or three-choice denominator changed")
        if (cls.manifest["pins_are_fixture_derived"] is not True or
            cls.manifest["native_test_pass_not_inferred_from_capture"] is not True):
            raise AssertionError("fixture pins cannot establish independent custody or native test success")
        if (cls.manifest["authority"], cls.manifest["current_permission"], cls.manifest["qualification"]) != (
                "DENY_ALL", "NOT_EXPORTED", "HOLD_NO_GO"):
            raise AssertionError("fixture scope gained authority")
        for field in ("native_origin_authenticated", "pre_dispatch_freeze_authenticated",
                      "root_scope_authenticated", "output_ack_event_verified", "actual_model_execution_accepted",
                      "hepta_final_use_accepted", "production_activation"):
            if cls.manifest[field] is not False:
                raise AssertionError("fixture scope gained authentication: " + field)
        cls.log = (FIXTURES / "native.stdout").read_bytes()
        if native.sha(cls.log) != cls.manifest["source_log_sha256"] or native.sha(cls.log) != NATIVE_STDOUT_SHA256:
            raise AssertionError("original native stdout changed")
        for phase, record in cls.manifest["exports"].items():
            if set(record["captures"]) != set(capture.KINDS):
                raise AssertionError("original initial, selection, completion or readback is missing")
            for name, digest in record["files"].items():
                if native.sha((FIXTURES / name).read_bytes()) != digest:
                    raise AssertionError("native corpus file changed: " + name)
            for kind, point in record["captures"].items():
                raw = (FIXTURES / (phase + capture.SUFFIXES[kind])).read_bytes()
                start, length = point["byte_offset"], point["byte_length"]
                prefix = f"HEPTA_LEARNING_{kind} {phase} ".encode()
                if (cls.log[start - len(prefix):start] != prefix or
                    cls.log[start:start + length] != raw or length != len(raw) or
                    native.sha(raw) != point["sha256"]):
                    raise AssertionError("native export is not its original stdout slice")
        for record in cls.manifest["excluded_exports"]:
            start, length = record["byte_offset"], record["byte_length"]
            if (record["phase"] not in capture.LEGACY_PHASES or
                record["scope"] != "legacy-profile-not-a-local-decision-positive" or
                native.sha(cls.log[start:start + length]) != record["sha256"]):
                raise AssertionError("legacy stdout was relabelled as local-decision evidence")

    def case(self, phase="local_adopt"):
        suffixes = (".selection.bin", ".completed.bin", ".json", ".freeze.json", ".expected.json")
        raw = [(FIXTURES / (phase + suffix)).read_bytes() for suffix in suffixes]
        return raw[0], raw[1], raw[2], json.loads(raw[3]), json.loads(raw[4])

    def review(self, selection_raw, completed_raw, readback_raw, frozen, expected, **pins):
        return joined.review_native_local_learning_completion(selection_raw, completed_raw, readback_raw,
            expected_selection_sha256=pins["selection"] if "selection" in pins else native.sha(selection_raw),
            expected_completed_sha256=pins["completed"] if "completed" in pins else native.sha(completed_raw),
            expected_readback_sha256=pins["readback"] if "readback" in pins else native.sha(readback_raw),
            frozen=frozen, expected=expected)

    def test_three_original_native_choices_complete_use_without_becoming_no_update(self):
        for phase in capture.PHASES:
            with self.subTest(phase=phase):
                case = self.case(phase)
                before = copy.deepcopy(case)
                result = self.review(*case)
                self.assertEqual(case, before)
                completed, replay = local.decode_native_local_checkpoint(case[1])
                self.assertEqual(result, json.loads((FIXTURES / (phase + ".review.json")).read_bytes()))
                self.assertEqual(result["local_disposition"], capture.CHOICES[phase])
                self.assertEqual(result["evaluation_disposition"], "qualified")
                self.assertEqual(result["proposal_disposition"], "update_candidates")
                self.assertIs(result["no_update"], False)
                self.assertIs(result["retained_model"], phase != "local_adopt")
                self.assertEqual(result["selected_bundle_digest"], replay["next_task_bundle"])
                self.assertEqual(result["completed_learning_head"], replay["head"])
                self.assertEqual(result["receipt_count"], 8)
                self.assertEqual(result["final_observation"], completed["receipts"][-1]["observation"])
                self.assertEqual(result["next_use_evidence_digest"], completed["receipts"][-1]["evidence_digest"])
                self.assertEqual(result["next_use_observed_unix_seconds"],
                                 completed["receipts"][-1]["observed_unix_seconds"])
                for name in ("original_receipt_prefix_preserved", "native_receipt_chain_complete",
                             "final_next_use_matches_original_actor", "completed_use_observed",
                             "pending_work_and_delivery_clear"):
                    self.assertIs(result[name], True, name)
                self.assertEqual((result["authority"], result["current_permission"], result["qualification"]),
                                 ("DENY_ALL", "NOT_EXPORTED", "HOLD_NO_GO"))
                for name in FALSE_CLAIMS:
                    self.assertIs(result[name], False, name)

    def test_original_initial_wire_is_the_only_fixture_freeze_source(self):
        for phase in capture.PHASES:
            with self.subTest(phase=phase):
                initial = (FIXTURES / (phase + ".initial.bin")).read_bytes()
                self.assertEqual(initial[:8], legacy.MAGIC)
                snapshot, replay = legacy.decode_native_learning_checkpoint(initial)
                self.assertEqual(snapshot["receipts"], [])
                self.assertEqual(replay["head"], replay["initial_head"])
                self.assertEqual(self.case(phase)[3], legacy.frozen_expectations_from_initial_checkpoint(initial))
                for kind, suffix in (("INITIAL_V1", ".initial.bin"), ("CHECKPOINT_V2", ".selection.bin"),
                                     ("COMPLETION_V1", ".completed.bin")):
                    export = json.loads((FIXTURES / (phase + capture.SUFFIXES[kind])).read_bytes())
                    self.assertEqual(capture.checkpoint_bytes(export, kind)[0],
                                     (FIXTURES / (phase + suffix)).read_bytes())

    def test_collector_reproduces_original_slices_and_fixture_only_derivations(self):
        files, manifest = capture.capture(self.log, NATIVE_SOURCE)
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(set(files), {path.name for path in FIXTURES.iterdir()})
        for name, raw in files.items():
            with self.subTest(file=name):
                self.assertEqual(raw, (FIXTURES / name).read_bytes())

    def test_clear_pending_state_does_not_prove_output_ack_stop_or_episode_end(self):
        for phase in capture.PHASES:
            result = self.review(*self.case(phase))
            original = result["native_readback_review"]
            with self.subTest(phase=phase):
                self.assertFalse(original["pending_work"])
                self.assertFalse(original["pending_delivery"])
                self.assertTrue(result["completed_use_observed"])
                self.assertTrue(result["pending_work_and_delivery_clear"])
                self.assertFalse(result["output_ack_event_verified"])
                self.assertNotIn("acknowledged_use_observed", result)
                self.assertEqual(result["model_stop_observed"], original["model_stop_observed"])
                self.assertEqual(result["terminal_episode_observed"], original["terminal_episode_observed"])

    def test_rehashed_defer_retain_swap_cannot_borrow_original_use(self):
        for phase in ("local_defer_cold", "local_retain_cold"):
            selection, completed, readback, frozen, expected = self.case(phase)
            changed = []
            for raw in (selection, completed):
                snapshot, _ = local.decode_native_local_checkpoint(raw)
                choice = snapshot["receipts"][5]["observation"]
                choice["disposition"] = 2 if choice["disposition"] == 1 else 1
                encoded = rehash(snapshot)
                # Both choices retain the parent, so standalone replay still
                # succeeds; the original actor export must bind which occurred.
                local.decode_native_local_checkpoint(encoded)
                changed.append(encoded)
            with self.subTest(phase=phase), self.assertRaisesRegex(native.ReadbackRefusal, "LOCAL_USE_READBACK_HEAD"):
                self.review(*changed, readback, frozen, expected)

    def test_pending_mutations_reach_and_fail_the_pending_use_gate(self):
        for phase in capture.PHASES:
            selection, completed, readback, frozen, expected = self.case(phase)
            for field in ("pending_request_digest", "pending_output"):
                payload = json.loads(json.loads(readback)["payload_json"])
                generation = json.loads(payload["generation_observation_json"])
                if field == "pending_request_digest":
                    generation[field] = [171] * 32
                else:
                    # This is a hostile pending marker, not a captured pre-ACK
                    # native cut. Even an empty delivery remains pending.
                    prefix = generation["snapshot"]["prefix"]
                    generation[field] = dict(operation_id=payload["intent"]["operation_id"],
                        request_digest=json.loads(payload["step_receipt_json"])["request_digest"],
                        prefix_offset=max(len(prefix) - 1, 0), bytes=prefix[-1:])
                payload["generation_observation_json"] = compact(generation).decode()
                changed = encode_payload(payload)
                precheck = native.review_native_learning_use(changed,
                    expected_readback_sha256=native.sha(changed), expected=expected)
                self.assertTrue(precheck["pending_work" if field == "pending_request_digest" else "pending_delivery"])
                with self.subTest(phase=phase, field=field), self.assertRaisesRegex(
                        native.ReadbackRefusal, "LOCAL_USE_PENDING_WORK_OR_DELIVERY"):
                    self.review(selection, completed, changed, frozen, expected)

    def test_final_checkpoint_receipt_publication_reset_and_run_bind_original_actor(self):
        for phase in capture.PHASES:
            selection, completed, readback, frozen, expected = self.case(phase)
            original, _ = local.decode_native_local_checkpoint(completed)
            names = ("checkpoint_digest", "committed_step_receipt",
                     "state_cutover_receipt" if phase == "local_adopt" else "task_owner_publication", "run_id")
            for name in names:
                snapshot = copy.deepcopy(original)
                observed = snapshot["receipts"][-1]["observation"]
                if name == "run_id":
                    observed["state_partition"][name] = "unobserved-distinct-run"
                else:
                    observed[name] = "ab" * 32
                changed = rehash(snapshot)
                local.decode_native_local_checkpoint(changed)
                with self.subTest(phase=phase, field=name), self.assertRaisesRegex(
                        native.ReadbackRefusal, "LOCAL_USE_ORIGINAL_NEXT_USE"):
                    self.review(selection, changed, readback, frozen, expected)

    def test_rehashed_step_receipt_in_readback_cannot_replace_completed_receipt(self):
        selection, completed, readback, frozen, expected = self.case()
        payload = json.loads(json.loads(readback)["payload_json"])
        receipt = json.loads(payload["step_receipt_json"])
        receipt["proposal_digest"] = [171] * 32
        changed_step = compact(receipt)
        payload["step_receipt_json"] = changed_step.decode()
        expected["committed_step_receipt"] = native.sha(native.STEP_DOMAIN + changed_step)
        payload["observation"]["committed_step_receipt"] = list(bytes.fromhex(expected["committed_step_receipt"]))
        changed = encode_payload(payload)
        with self.assertRaisesRegex(native.ReadbackRefusal, "LOCAL_USE_ORIGINAL_NEXT_USE"):
            self.review(selection, completed, changed, frozen, expected)

    def test_publication_bytes_and_recomputed_model_reset_still_have_their_native_gates(self):
        selection, completed, readback, frozen, expected = self.case()
        payload = json.loads(json.loads(readback)["payload_json"])
        publication = json.loads(payload["publication_json"])
        publication["intent"]["previous_observation"] = [171] * 32
        payload["publication_json"] = compact(publication).decode()
        with self.assertRaisesRegex(native.ReadbackRefusal, "NATIVE_PUBLICATION_PIN"):
            self.review(selection, completed, encode_payload(payload), frozen, expected)
        payload = json.loads(json.loads(readback)["payload_json"])
        payload["observation"]["state_cutover_receipt"] = [171] * 32
        expected["state_cutover_receipt"] = "ab" * 32
        with self.assertRaisesRegex(native.ReadbackRefusal, "NATIVE_MODEL_RESET_RECEIPT"):
            self.review(selection, completed, encode_payload(payload), frozen, expected)

    def test_missing_final_foreign_final_and_changed_prefix_are_refused(self):
        selection, completed, readback, frozen, expected = self.case()
        with self.assertRaisesRegex(native.ReadbackRefusal, "LOCAL_USE_EXACT_CONTINUATION"):
            self.review(selection, selection, readback, frozen, expected)
        foreign = self.case("local_retain_cold")[1]
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FROZEN_REQUEST|LOCAL_USE_EXACT_CONTINUATION"):
            self.review(selection, foreign, readback, frozen, expected)
        snapshot, _ = local.decode_native_local_checkpoint(completed)
        snapshot["receipts"][2]["evidence_digest"] = "ab" * 32
        # Preserve the proposal-head observation after rehashing its prefix.
        head = legacy._initial_head(snapshot["request"], snapshot["owners"])
        for receipt in snapshot["receipts"][:5]:
            receipt["predecessor"] = head
            head = native.sha(local.receipt_signing_bytes(receipt))
        snapshot["receipts"][5]["observation"]["proposal_head"] = head
        with self.assertRaisesRegex(native.ReadbackRefusal, "LOCAL_USE_EXACT_CONTINUATION"):
            self.review(selection, rehash(snapshot), readback, frozen, expected)

    def test_final_actor_operation_predecessor_and_time_keep_original_guards(self):
        selection, completed, readback, frozen, expected = self.case()
        original, _ = local.decode_native_local_checkpoint(completed)
        mutations = (("actor_id", "foreign-observer", "LEARNING_ACTOR"),
                     ("operation_id", "foreign-operation", "LEARNING_OPERATION"),
                     ("predecessor", "ab" * 32, "LEARNING_RECEIPT_PREDECESSOR"),
                     ("observed_unix_seconds", original["request"]["envelope"]["expiry_unix_seconds"],
                      "LEARNING_RECEIPT_TIME"))
        for name, value, code in mutations:
            snapshot = copy.deepcopy(original)
            snapshot["receipts"][-1][name] = value
            with self.subTest(field=name), self.assertRaisesRegex(native.ReadbackRefusal, code):
                self.review(selection, mutated_encoding(snapshot), readback, frozen, expected)

    def test_real_freeze_cannot_be_replaced_by_a_self_consistent_other_request(self):
        selection, completed, readback, frozen, expected = self.case()
        frozen["request"]["operation_id"] = "different-frozen-operation"
        frozen["initial_head"] = legacy._initial_head(frozen["request"], frozen["owners"])
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FROZEN_REQUEST"):
            self.review(selection, completed, readback, frozen, expected)

    def test_qualified_local_retention_cannot_be_relabelled_no_update(self):
        for phase in ("local_defer_cold", "local_retain_cold"):
            selection, completed, readback, frozen, expected = self.case(phase)
            for index in (3, 4):
                snapshot, _ = local.decode_native_local_checkpoint(completed)
                snapshot["receipts"][index]["observation"]["disposition"] = 1
                with self.subTest(phase=phase, stage=index), self.assertRaises(native.ReadbackRefusal):
                    self.review(selection, rehash(snapshot), readback, frozen, expected)

    def test_external_pins_codec_versions_and_original_bounds_are_mandatory(self):
        case = self.case()
        for field, code in (("selection", "LOCAL_USE_CHECKPOINT_PIN"), ("completed", "LOCAL_USE_CHECKPOINT_PIN"),
                            ("readback", "NATIVE_READBACK_PIN")):
            with self.subTest(pin=field), self.assertRaisesRegex(native.ReadbackRefusal, code):
                self.review(*case, **{field: "ab" * 32})
        selection, completed, readback, frozen, expected = case
        for raw, code in ((completed + b"\0", "LEARNING_CHECKPOINT_TRAILING_BYTES"),
                          (b"HEPLCP02" + completed[8:], "LEARNING_CHECKPOINT_VERSION"),
                          (b"HEPLCP03" + completed[8:], "LEARNING_CHECKPOINT_VERSION"),
                          (completed[:-1], "LEARNING_CHECKPOINT_TRUNCATED"),
                          (b"x" * (legacy.MAX_CHECKPOINT + 1), "LOCAL_USE_CHECKPOINT_LIMIT")):
            with self.subTest(code=code), self.assertRaisesRegex(native.ReadbackRefusal, code):
                self.review(selection, raw, readback, frozen, expected)
        for raw in (bytearray(completed), "not-native-bytes"):
            with self.subTest(kind=type(raw).__name__), self.assertRaisesRegex(
                    native.ReadbackRefusal, "LOCAL_USE_CHECKPOINT_LIMIT"):
                self.review(selection, raw, readback, frozen, expected, completed="ab" * 32)

    def test_native_readback_cannot_export_authority_through_this_join(self):
        selection, completed, readback, frozen, expected = self.case()
        for field, value in (("authority", "ALLOW_ALL"), ("current_permission", "EXPORTED")):
            payload = json.loads(json.loads(readback)["payload_json"])
            payload[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(native.ReadbackRefusal, "NATIVE_AUTHORITY_ESCALATION"):
                self.review(selection, completed, encode_payload(payload), frozen, expected)

    def test_cli_requires_each_material_and_separate_pin_and_leaves_inputs_unchanged(self):
        selection, completed, readback, frozen, expected = self.case()
        materials = {"selection-checkpoint": selection, "completed-checkpoint": completed,
                     "readback": readback, "freeze": capture.json_bytes(frozen), "expected": capture.json_bytes(expected)}
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-B", str(ROOT / "scripts/cell_learning_local_use_join.py")]
            for name, raw in materials.items():
                path = Path(directory) / name
                path.write_bytes(raw)
                command += ["--" + name, str(path), "--" + name + "-sha256", native.sha(raw)]
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), self.review(selection, completed, readback, frozen, expected))
            for name in materials:
                for flag in ("--" + name, "--" + name + "-sha256"):
                    index = command.index(flag)
                    with self.subTest(missing=flag):
                        missing = command[:index] + command[index + 2:]
                        refused = subprocess.run(missing, capture_output=True, timeout=15)
                        self.assertNotEqual(refused.returncode, 0)
                wrong = command.copy()
                wrong[command.index("--" + name + "-sha256") + 1] = "ab" * 32
                with self.subTest(wrong_pin=name):
                    refused = subprocess.run(wrong, capture_output=True, timeout=15)
                    self.assertNotEqual(refused.returncode, 0)
            self.assertEqual({path.name: path.read_bytes() for path in Path(directory).iterdir()}, materials)

    def test_collector_requires_each_native_cut_and_rejects_duplicate_exports(self):
        for kind in capture.KINDS:
            point = self.manifest["exports"]["local_adopt"]["captures"][kind]
            prefix = f"HEPTA_LEARNING_{kind} local_adopt ".encode()
            start, end = point["byte_offset"] - len(prefix), point["byte_offset"] + point["byte_length"]
            for changed, code in ((self.log[:start] + self.log[end + 1:], "LOCAL_CAPTURE_MISSING_EXPORT"),
                                  (self.log + self.log[start:end] + b"\n", "LOCAL_CAPTURE_EXPORT_ROSTER")):
                with self.subTest(kind=kind, code=code), self.assertRaisesRegex(native.ReadbackRefusal, code):
                    capture.capture(changed, NATIVE_SOURCE)

    def test_collector_rejects_relabelled_choice_and_unauthorized_export_scope(self):
        swapped = self.log.replace(b"local_defer_cold ", b"local_swap_pending ")
        swapped = swapped.replace(b"local_retain_cold ", b"local_defer_cold ")
        swapped = swapped.replace(b"local_swap_pending ", b"local_retain_cold ")
        with self.assertRaisesRegex(native.ReadbackRefusal, "LOCAL_CAPTURE_PHASE_CHOICE"):
            capture.capture(swapped, NATIVE_SOURCE)
        original = json.loads((FIXTURES / "local_adopt.completed-export.json").read_bytes())
        for field, value, code in (("authority", "ALLOW_ALL", "LOCAL_CAPTURE_FIXTURE_SCOPE"),
                                   ("pins_are_fixture_derived", False, "LOCAL_CAPTURE_FIXTURE_SCOPE"),
                                   ("actual_model_execution_accepted", True, "LOCAL_CAPTURE_MODEL_SCOPE")):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(native.ReadbackRefusal, code):
                capture.checkpoint_bytes(changed, "COMPLETION_V1")

    def test_collector_cli_preserves_stdout_and_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "captured"
            command = [sys.executable, "-B", str(ROOT / "scripts/capture_cell_learning_local_use.py"),
                       "--log", str(FIXTURES / "native.stdout"), "--native-source", NATIVE_SOURCE,
                       "--output", str(output)]
            result = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / "native.stdout").read_bytes(), self.log)
            self.assertEqual((output / "fixture-manifest.json").read_bytes(),
                             (FIXTURES / "fixture-manifest.json").read_bytes())
            before = {path.name: path.read_bytes() for path in output.iterdir()}
            refused = subprocess.run(command, capture_output=True, timeout=15)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn(b"LOCAL_CAPTURE_OUTPUT_EXISTS", refused.stderr)
            self.assertEqual({path.name: path.read_bytes() for path in output.iterdir()}, before)


if __name__ == "__main__":
    unittest.main()
