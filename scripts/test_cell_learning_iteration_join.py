"""Original native codec/use joins and adversarial structural mutations.

Positive inputs must be the paired bytes emitted by the original Rust actor and
its production HEPLCP02 codec. They are two controlled engineering fixtures at
two delivery stages, not four independent experiments. The encoder below is
only for mutations; no reconstructed checkpoint is counted as native evidence.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

import cell_adoption_readback as native
import cell_learning_iteration_join as join

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "evidence/cell-learning-iteration-20261108/native-readbacks"
PHASES = ("retained_pending", "retained_acked", "adopted_pending", "adopted_acked")


class MutationWriter:
    """Native persistence shape, used only to construct explicitly altered data."""
    def __init__(self):
        self.raw = bytearray()

    def number(self, value, width):
        self.raw.extend(value.to_bytes(width, "big"))

    def digest(self, value):
        self.raw.extend(bytes.fromhex(value))

    def identifier(self, value):
        raw = value.encode("ascii")
        self.number(len(raw), 1); self.raw.extend(raw)

    def optional(self, value):
        self.number(int(value is not None), 1)
        if value is not None:
            self.digest(value)

    def bundle(self, value):
        self.identifier(value["artifact_id"]); self.number(value["generation"], 8)
        for name in join.COMPONENTS:
            self.digest(value["components"][name])
        self.optional(value["components"]["organ_adapter"])
        self.optional(value["components"]["cell_adapter"])
        self.optional(value["rollback_predecessor"])
        self.number(int(value["training_lineage"] is not None), 1)
        if value["training_lineage"] is not None:
            for name in join.LINEAGE:
                self.digest(value["training_lineage"][name])

    def observation(self, value):
        tag = value["tag"]
        self.number(tag, 1)
        if tag == 0:
            self.digest(value["episode_digest"]); self.digest(value["completed_task_receipt"])
        elif tag == 1:
            for name in ("snapshot_digest", "episode_digest", "withdrawal_frontier"):
                self.digest(value[name])
            self.number(value["rows"], 4); self.number(value["bytes"], 8)
        elif tag == 2:
            self.bundle(value["candidate"])
            for name in ("steps", "milliseconds", "artifact_bytes"):
                self.number(value[name], 8)
        elif tag == 3:
            self.digest(value["candidate_bundle"]); self.digest(value["evaluation_profile"])
            self.number(value["disposition"], 1)
        elif tag == 4:
            self.digest(value["candidate_bundle"]); self.identifier(value["proposal_id"])
            self.digest(value["composition_digest"]); self.number(value["disposition"], 1)
        elif tag == 5:
            self.digest(value["candidate_bundle"]); self.digest(value["selection_digest"])
        else:
            self.digest(value["retained_bundle" if tag == 7 else "candidate_bundle"])
            for name in ("principal_id", "agent_id", "cell_id", "run_id"):
                self.identifier(value["state_partition"][name])
            for name in ("checkpoint_digest", "selection_digest", "committed_step_receipt",
                         "task_owner_publication" if tag == 7 else "state_cutover_receipt"):
                self.digest(value[name])


def mutated_encoding(snapshot):
    writer = MutationWriter()
    writer.raw.extend(join.MAGIC)
    request, owners = snapshot["request"], snapshot["owners"]
    for name in join.REQUEST_IDS:
        writer.identifier(request[name])
    for name in ("completed_task_receipt", "selected_artifact_digest", "evaluation_profile"):
        writer.digest(request[name])
    writer.bundle(request["selected_bundle"])
    envelope = request["envelope"]
    writer.identifier(envelope["envelope_id"])
    for name in join.ENVELOPE_DIGESTS:
        writer.digest(envelope[name])
    for name, width in (("maximum_files", 2), ("maximum_diff_bytes", 8), ("maximum_candidates", 2),
                        ("maximum_parallel_sandboxes", 1), ("expiry_unix_seconds", 8)):
        writer.number(envelope[name], width)
    for name in join.BUDGET_LIMITS:
        writer.number(request["budget"][name], 4 if name == "maximum_dataset_rows" else 8)
    writer.digest(owners["evidence_trust_digest"])
    for name in join.OWNER_IDS:
        writer.identifier(owners[name])
    writer.number(len(snapshot["receipts"]), 1)
    for receipt in snapshot["receipts"]:
        writer.identifier(receipt["operation_id"]); writer.digest(receipt["predecessor"])
        writer.identifier(receipt["actor_id"]); writer.digest(receipt["evidence_digest"])
        writer.number(receipt["observed_unix_seconds"], 8); writer.observation(receipt["observation"])
    writer.digest(snapshot["head_digest"])
    return bytes(writer.raw)


def rehash_mutation(snapshot):
    """Adversarial rehashing never creates a native signature or positive export."""
    head = join._initial_head(snapshot["request"], snapshot["owners"])
    for receipt in snapshot["receipts"]:
        receipt["predecessor"] = head
        head = join._receipt_head(receipt)
    snapshot["head_digest"] = head
    return mutated_encoding(snapshot)


class CheckpointWireBoundaryTests(unittest.TestCase):
    """Negative API boundaries need no manufactured positive native fixture."""
    def test_nonbytes_and_oversized_records_are_refused_before_other_inputs(self):
        for raw in ("HEPLCP02", bytearray(join.MAGIC), memoryview(join.MAGIC), b"x" * (join.MAX_CHECKPOINT + 1)):
            with self.subTest(kind=type(raw).__name__), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_LIMIT"):
                join.review_native_learning_iteration(raw, b"", expected_checkpoint_sha256="0" * 64,
                    expected_readback_sha256="0" * 64, frozen=None, expected=None)

    def test_legacy_or_future_magic_refused_without_filling_new_fields(self):
        for magic in (b"HEPLCP01", b"HEPLCP03", b"OTHER002"):
            with self.subTest(magic=magic), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_VERSION"):
                join.decode_native_learning_checkpoint(magic + b"\0" * 16)

    def test_truncated_header_refused_before_any_identifier(self):
        for length in range(8):
            with self.subTest(length=length), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_TRUNCATED"):
                join.decode_native_learning_checkpoint(join.MAGIC[:length])

    def test_malformed_identifier_is_refused_at_the_actual_wire_boundary(self):
        for suffix, code in ((b"\0", "LEARNING_CHECKPOINT_ID_LENGTH"),
                             (b"\x81", "LEARNING_CHECKPOINT_ID_LENGTH"),
                             (b"\x01\xff", "LEARNING_CHECKPOINT_ID_ENCODING"),
                             (b"\x01/", "NATIVE_STABLE_ID")):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(native.ReadbackRefusal, code):
                join.decode_native_learning_checkpoint(join.MAGIC + suffix)


class NativeLearningJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((FIXTURES / "fixture-manifest.json").read_bytes())
        if cls.manifest["scope"] != "original-native-engineering-fixtures-not-production":
            raise AssertionError("original fixture qualification scope changed")
        if set(cls.manifest["exports"]) != set(PHASES):
            raise AssertionError("missing original checkpoint/use export denominator")
        if cls.manifest["pins_are_fixture_derived"] is not True:
            raise AssertionError("fixture expectations must not claim independent custody")

    def case(self, phase="retained_acked"):
        record = self.manifest["exports"][phase]
        checkpoint = (FIXTURES / (phase + ".checkpoint.bin")).read_bytes()
        readback = (FIXTURES / (phase + ".json")).read_bytes()
        expected_raw = (FIXTURES / (phase + ".expected.json")).read_bytes()
        frozen_raw = (FIXTURES / (phase + ".freeze.json")).read_bytes()
        self.assertEqual(native.sha(checkpoint), record["checkpoint_sha256"])
        self.assertEqual(len(checkpoint), record["checkpoint_bytes"])
        self.assertEqual(native.sha(readback), record["sha256"])
        self.assertEqual(len(readback), record["bytes"])
        self.assertEqual(native.sha(expected_raw), record["fixture_expected_sha256"])
        self.assertEqual(native.sha(frozen_raw), record["fixture_freeze_sha256"])
        expected, frozen = json.loads(expected_raw), json.loads(frozen_raw)
        self.assertEqual(frozen["initial_head"], record["native_initial_head"])
        self.assertEqual(expected["learning_head"], record["native_learning_head"])
        return checkpoint, readback, frozen, expected

    def review(self, checkpoint, readback, frozen, expected):
        return join.review_native_learning_iteration(checkpoint, readback,
            expected_checkpoint_sha256=native.sha(checkpoint), expected_readback_sha256=native.sha(readback),
            frozen=frozen, expected=expected)

    def snapshot(self, phase="retained_acked"):
        checkpoint, *_ = self.case(phase)
        snapshot, _ = join.decode_native_learning_checkpoint(checkpoint)
        return snapshot

    def test_four_original_codec_exports_join_original_actor_bytes(self):
        for phase in PHASES:
            with self.subTest(phase=phase):
                case = self.case(phase)
                before = copy.deepcopy(case)
                result = self.review(*case)
                self.assertEqual(case, before)
                self.assertEqual(result["qualification"], "HOLD_NO_GO")
                self.assertEqual(result["authority"], "DENY_ALL")
                self.assertEqual(result["current_permission"], "NOT_EXPORTED")
                self.assertTrue(result["frozen_request_bindings_consistent"])
                self.assertTrue(result["receipt_chain_bindings_consistent"])
                self.assertTrue(result["evaluation_profile_bound_in_initial_checkpoint"])
                self.assertTrue(result["selection_to_first_use_bindings_consistent"])
                self.assertEqual(result["no_update"], phase.startswith("retained"))
                self.assertEqual(result["evaluation_disposition"], "no_update" if phase.startswith("retained") else "qualified")
                self.assertEqual(result["proposal_disposition"], None if phase.startswith("retained") else "update_candidates")
                checkpoint, readback, _, expected = case
                self.assertEqual(result["native_readback_review"], native.review_native_learning_use(
                    readback, expected_readback_sha256=native.sha(readback), expected=expected))
                self.assertEqual(mutated_encoding(join.decode_native_learning_checkpoint(checkpoint)[0]), checkpoint)
                for name in ("full_learning_iteration_completed", "native_origin_authenticated",
                             "freeze_origin_authenticated", "pre_dispatch_freeze_authenticated",
                             "learning_signatures_verified", "learning_actor_control_binding_verified",
                             "grant_signature_verified_by_this_reader", "cost_completeness_verified",
                             "evaluation_profile_semantics_verified", "independent_control_accepted",
                             "current_permission_exported", "real_model_training_verified",
                             "physical_installation_accepted", "settlement_verified",
                             "hepta_final_use_accepted", "production_activation"):
                    self.assertIs(result[name], False)

    def test_ack_changes_delivery_without_rewriting_frozen_learning_history(self):
        for prefix in ("retained", "adopted"):
            before, after = self.case(prefix + "_pending"), self.case(prefix + "_acked")
            self.assertEqual(before[0], after[0])
            self.assertEqual(before[2], after[2])
            a, b = self.review(*before), self.review(*after)
            self.assertEqual(a["learning_head"], b["learning_head"])
            self.assertNotEqual(a["native_readback_review"]["owner_checkpoint"], b["native_readback_review"]["owner_checkpoint"])

    def test_initial_snapshot_projection_requires_an_initial_checkpoint(self):
        snapshot = self.snapshot()
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FREEZE_NOT_INITIAL"):
            join.frozen_expectations_from_initial_checkpoint(mutated_encoding(snapshot))
        snapshot["receipts"] = []
        snapshot["head_digest"] = join._initial_head(snapshot["request"], snapshot["owners"])
        # Synthetic initial projection tests the API, not an admission witness.
        projected = join.frozen_expectations_from_initial_checkpoint(mutated_encoding(snapshot))
        self.assertEqual(projected, self.case()[2])

    def test_legacy_unfrozen_checkpoint_is_never_promoted(self):
        checkpoint, readback, frozen, expected = self.case()
        legacy = b"HEPLCP01" + checkpoint[8:]
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_VERSION"):
            self.review(legacy, readback, frozen, expected)

    def test_independent_checkpoint_pin_cannot_be_replaced_by_a_self_digest(self):
        checkpoint, readback, frozen, expected = self.case()
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_PIN"):
            join.review_native_learning_iteration(checkpoint, readback,
                expected_checkpoint_sha256="0" * 64, expected_readback_sha256=native.sha(readback),
                frozen=frozen, expected=expected)

    def test_all_original_request_owner_budget_and_source_pins_are_required(self):
        checkpoint, readback, frozen, expected = self.case()
        changes = [("request", name, "changed-id") for name in join.REQUEST_IDS]
        changes += [("request", name, "c7" * 32) for name in ("completed_task_receipt", "selected_artifact_digest", "evaluation_profile")]
        changes += [("owners", name, "changed-owner") for name in join.OWNER_IDS]
        changes.append(("owners", "evidence_trust_digest", "c7" * 32))
        for group, name, value in changes:
            changed = copy.deepcopy(frozen)
            changed[group][name] = value
            changed["initial_head"] = join._initial_head(changed["request"], changed["owners"])
            with self.subTest(group=group, name=name), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FROZEN_REQUEST"):
                self.review(checkpoint, readback, changed, expected)
        for group in ("envelope", "budget"):
            for name in frozen["request"][group]:
                changed = copy.deepcopy(frozen)
                old = changed["request"][group][name]
                changed["request"][group][name] = "changed-id" if name == "envelope_id" else "c7" * 32 if type(old) is str else (old + 1 if old == 1 else old - 1)
                changed["initial_head"] = join._initial_head(changed["request"], changed["owners"])
                with self.subTest(group=group, name=name), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FROZEN_REQUEST"):
                    self.review(checkpoint, readback, changed, expected)
        changed = copy.deepcopy(frozen)
        changed["request"]["selected_bundle"]["components"]["tokenizer"] = "c7" * 32
        changed["initial_head"] = join._initial_head(changed["request"], changed["owners"])
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FROZEN_REQUEST"):
            self.review(checkpoint, readback, changed, expected)

    def test_training_cannot_select_a_later_evaluation_profile(self):
        snapshot = self.snapshot()
        snapshot["receipts"][2]["observation"]["candidate"]["training_lineage"]["evaluation_profile"] = "c7" * 32
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_TRAINING_LINEAGE"):
            join.decode_native_learning_checkpoint(rehash_mutation(snapshot))

    def test_evaluator_cannot_substitute_its_profile(self):
        snapshot = self.snapshot()
        snapshot["receipts"][3]["observation"]["evaluation_profile"] = "c7" * 32
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_EVALUATION_PROFILE"):
            join.decode_native_learning_checkpoint(rehash_mutation(snapshot))

    def test_simultaneous_request_trainer_evaluator_rehash_cannot_replace_freeze(self):
        checkpoint, readback, frozen, expected = self.case()
        snapshot, _ = join.decode_native_learning_checkpoint(checkpoint)
        snapshot["request"]["evaluation_profile"] = "c7" * 32
        candidate = snapshot["receipts"][2]["observation"]["candidate"]
        candidate["training_lineage"]["evaluation_profile"] = "c7" * 32
        snapshot["receipts"][3]["observation"]["evaluation_profile"] = "c7" * 32
        snapshot["receipts"][3]["observation"]["candidate_bundle"] = join.bundle_digest(candidate)
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FROZEN_REQUEST"):
            self.review(rehash_mutation(snapshot), readback, frozen, expected)

    def test_no_update_cannot_select_the_rejected_candidate(self):
        snapshot = self.snapshot()
        self.assertEqual(snapshot["receipts"][3]["observation"]["disposition"], 1)
        snapshot["receipts"][-1]["observation"]["candidate_bundle"] = join.bundle_digest(snapshot["receipts"][2]["observation"]["candidate"])
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_SELECTION_BUNDLE"):
            join.decode_native_learning_checkpoint(rehash_mutation(snapshot))

    def test_eval_no_update_skips_proposal_and_cannot_reset_the_stage_sequence(self):
        snapshot = self.snapshot()
        self.assertEqual([r["observation"]["tag"] for r in snapshot["receipts"]], [0, 1, 2, 3, 5])
        proposal = copy.deepcopy(self.snapshot("adopted_acked")["receipts"][4])
        proposal["operation_id"] = snapshot["request"]["operation_id"]
        snapshot["receipts"].insert(4, proposal)
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_STAGE_ORDER"):
            join.decode_native_learning_checkpoint(rehash_mutation(snapshot))

    def test_synthetic_no_admissible_proposal_uses_parent_and_does_not_become_native_evidence(self):
        snapshot = self.snapshot("adopted_acked")
        snapshot["receipts"][4]["observation"]["disposition"] = 1
        snapshot["receipts"][5]["observation"]["candidate_bundle"] = join.bundle_digest(snapshot["request"]["selected_bundle"])
        _, replay = join.decode_native_learning_checkpoint(rehash_mutation(snapshot))
        self.assertTrue(replay["no_update"])
        self.assertEqual(replay["next_task_bundle"], replay["selected_bundle"])

    def test_intermediate_decision_bundle_matches_original_native_owner_before_selection(self):
        for phase, proposal_no_update in (("retained_acked", False), ("adopted_acked", False), ("adopted_acked", True)):
            snapshot = self.snapshot(phase)
            snapshot["receipts"].pop()  # Exact decision cut before Selection.
            if proposal_no_update:
                snapshot["receipts"][-1]["observation"]["disposition"] = 1
            _, replay = join.decode_native_learning_checkpoint(rehash_mutation(snapshot))
            with self.subTest(phase=phase, proposal_no_update=proposal_no_update):
                self.assertEqual(replay["next_stage"], 5)
                self.assertEqual(replay["next_task_bundle"], replay["selected_bundle"]
                    if phase.startswith("retained") or proposal_no_update else replay["candidate_bundle"])

    def test_completed_synthetic_next_use_cannot_substitute_for_original_pre_use_checkpoint(self):
        checkpoint, readback, frozen, expected = self.case()
        snapshot, _ = join.decode_native_learning_checkpoint(checkpoint)
        payload = json.loads(json.loads(readback)["payload_json"])
        publication = json.loads(payload["publication_json"])
        scope, use = publication["intent"]["target"]["scope"], payload["observation"]
        observation = dict(tag=7, retained_bundle=native.native_digest(use["bundle_digest"]),
            state_partition=dict(principal_id=native.native_digest(scope["principal_digest"]),
                agent_id=scope["agent_id"], cell_id=scope["cell_id"], run_id=scope["run_id"]),
            checkpoint_digest=native.native_digest(use["checkpoint_digest"]),
            selection_digest=native.native_digest(use["selection_digest"]),
            committed_step_receipt=native.native_digest(use["committed_step_receipt"]),
            task_owner_publication=native.native_digest(use["task_owner_publication"]))
        snapshot["receipts"].append(dict(operation_id=snapshot["request"]["operation_id"],
            predecessor=snapshot["head_digest"], actor_id=snapshot["owners"]["next_use_observer"],
            evidence_digest="c7" * 32, observed_unix_seconds=snapshot["receipts"][-1]["observed_unix_seconds"],
            observation=observation))
        changed = rehash_mutation(snapshot)
        self.assertIsNone(join.decode_native_learning_checkpoint(changed)[1]["next_stage"])
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_PRE_USE_SELECTION_REQUIRED"):
            self.review(changed, readback, frozen, expected)

    def test_different_iterations_cannot_splice_an_independently_valid_first_use(self):
        checkpoint, _, frozen, _ = self.case()
        _, readback, _, expected = self.case("adopted_acked")
        # Both individual readers accept their originals. Their association is
        # separately required and cannot be inferred from both reporting HOLD.
        native.review_native_learning_use(readback, expected_readback_sha256=native.sha(readback), expected=expected)
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_READBACK_HEAD"):
            self.review(checkpoint, readback, frozen, expected)

    def test_wrong_actor_operation_timestamp_and_receipt_predecessor_are_refused(self):
        for field, value, code in (("actor_id", "other-owner", "LEARNING_ACTOR"),
                                   ("operation_id", "other-operation", "LEARNING_OPERATION"),
                                   ("observed_unix_seconds", 0, "LEARNING_RECEIPT_TIME"),
                                   ("predecessor", "c7" * 32, "LEARNING_RECEIPT_PREDECESSOR")):
            snapshot = self.snapshot()
            snapshot["receipts"][2][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(native.ReadbackRefusal, code):
                join.decode_native_learning_checkpoint(mutated_encoding(snapshot))
        snapshot = self.snapshot()
        snapshot["receipts"][2]["observed_unix_seconds"] = snapshot["request"]["envelope"]["expiry_unix_seconds"]
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_RECEIPT_TIME"):
            join.decode_native_learning_checkpoint(mutated_encoding(snapshot))

    def test_training_and_dataset_costs_must_fit_the_original_caps(self):
        for index, field, budget, code in ((1, "rows", "maximum_dataset_rows", "LEARNING_DATASET_BINDING"),
                                         (1, "bytes", "maximum_dataset_bytes", "LEARNING_DATASET_BINDING"),
                                         (2, "steps", "maximum_training_steps", "LEARNING_TRAINING_BUDGET"),
                                         (2, "milliseconds", "maximum_training_milliseconds", "LEARNING_TRAINING_BUDGET"),
                                         (2, "artifact_bytes", "maximum_artifact_bytes", "LEARNING_TRAINING_BUDGET")):
            snapshot = self.snapshot()
            snapshot["receipts"][index]["observation"][field] = snapshot["request"]["budget"][budget] + 1
            with self.subTest(field=field), self.assertRaisesRegex(native.ReadbackRefusal, code):
                join.decode_native_learning_checkpoint(rehash_mutation(snapshot))

    def test_bundle_lineage_and_exact_successor_generation_are_required(self):
        for case in ("wrong_generation", "same_artifact", "wrong_dataset", "missing_lineage", "zero_component"):
            snapshot = self.snapshot()
            candidate = snapshot["receipts"][2]["observation"]["candidate"]
            if case == "wrong_generation":
                candidate["generation"] += 1
            elif case == "same_artifact":
                candidate["artifact_id"] = snapshot["request"]["selected_bundle"]["artifact_id"]
            elif case == "wrong_dataset":
                candidate["training_lineage"]["dataset"] = "c7" * 32
            elif case == "missing_lineage":
                candidate["training_lineage"] = None
            else:
                candidate["components"]["base"] = "0" * 64
            with self.subTest(case=case), self.assertRaises(native.ReadbackRefusal):
                join.decode_native_learning_checkpoint(mutated_encoding(snapshot))

    def test_frozen_expectations_refuse_integer_aliases_and_unknown_fields(self):
        checkpoint, readback, frozen, expected = self.case()
        for value in (True, 1.0, -1, 1 << 64):
            changed = copy.deepcopy(frozen)
            changed["request"]["budget"]["maximum_training_steps"] = value
            with self.subTest(value=value), self.assertRaisesRegex(native.ReadbackRefusal, "NATIVE_INTEGER"):
                self.review(checkpoint, readback, changed, expected)
        changed = copy.deepcopy(frozen); changed["authority"] = "ALLOW"
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FREEZE_FIELDS"):
            self.review(checkpoint, readback, changed, expected)
        changed = copy.deepcopy(frozen); changed["initial_head"] = "c7" * 32
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_FREEZE_HEAD"):
            self.review(checkpoint, readback, changed, expected)

    def test_truncation_trailing_data_invalid_ids_and_size_bound_are_refused(self):
        checkpoint, *_ = self.case()
        cuts = sorted(set([0, 1, 7, 8, 9, 136, 137, 256, len(checkpoint) - 33, len(checkpoint) - 1]))
        for cut in cuts:
            with self.subTest(cut=cut), self.assertRaises(native.ReadbackRefusal):
                join.decode_native_learning_checkpoint(checkpoint[:cut])
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_TRAILING_BYTES"):
            join.decode_native_learning_checkpoint(checkpoint + b"\0")
        for length in (0, 129, 255):
            changed = bytearray(checkpoint); changed[8] = length
            with self.subTest(length=length), self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_ID_LENGTH"):
                join.decode_native_learning_checkpoint(bytes(changed))
        changed = bytearray(checkpoint); changed[9] = 255
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_ID_ENCODING"):
            join.decode_native_learning_checkpoint(bytes(changed))
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_CHECKPOINT_LIMIT"):
            join.decode_native_learning_checkpoint(b"x" * (join.MAX_CHECKPOINT + 1))

    def test_cli_rejects_partial_join_arguments_instead_of_silent_v1_fallback(self):
        checkpoint, readback, _, expected = self.case()
        phase = "retained_acked"
        command = [sys.executable, "-B", str(ROOT / "scripts/cell_adoption_readback.py"),
            "--readback", str(FIXTURES / (phase + ".json")), "--readback-sha256", native.sha(readback),
            "--expected", str(FIXTURES / (phase + ".expected.json")), "--expected-sha256",
            native.sha((FIXTURES / (phase + ".expected.json")).read_bytes()),
            "--learning-checkpoint", str(FIXTURES / (phase + ".checkpoint.bin"))]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LEARNING_JOIN_ARGUMENTS", result.stderr)
        self.assertEqual(result.stdout, "")
        command += ["--learning-checkpoint-sha256", native.sha(checkpoint),
            "--learning-freeze", str(FIXTURES / (phase + ".freeze.json")),
            "--learning-freeze-sha256", native.sha((FIXTURES / (phase + ".freeze.json")).read_bytes())]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        reviewed = json.loads(result.stdout)
        self.assertEqual(reviewed["learning_head"], expected["learning_head"])
        self.assertEqual(reviewed["schema"], join.REPORT_SCHEMA)
        self.assertIs(reviewed["production_activation"], False)


if __name__ == "__main__":
    unittest.main()
