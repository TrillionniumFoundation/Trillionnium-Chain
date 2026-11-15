"""HEPLCP03 interoperability and hostile controls, not a learning experiment.

The fixed binary cuts/signing payloads were emitted by the original Rust codec
and coordinator at f97f3c90. The end-to-end readback below is explicitly synthetic:
it changes historical public fields and uses a zero signature. It proves reader
relations only, never original-owner execution, training, custody or FinalUse.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import capture_cell_learning_completion as capture
import cell_adoption_readback as native
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration
import cell_learning_scope_join as scoped
import cell_learning_business_join as business
from test_cell_learning_business_join import original_case
from test_cell_learning_iteration_join import mutated_encoding, rehash_mutation

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "evidence/heplcp03-interop-20261111/native-fixture.json"
FIXTURE_SHA256 = "492d1f9d27a9e8561aecc4cac9c55c8052ffb2d64dc86b2eff24c429826ff2f0"
ORIGINAL = ROOT / "evidence/hepta-real-native-adoption-20261108/chain-reader"


def vector():
    raw = FIXTURE.read_bytes()
    if native.sha(raw) != FIXTURE_SHA256:
        raise AssertionError("original Rust codec fixture bytes changed")
    value = json.loads(raw)
    if value["scope"] != "exact-native-codec-and-coordinator-engineering-fixture-only":
        raise AssertionError("native fixture is not product execution")
    return value


def profile_for(value):
    return dict(schema_version=2, identity_digest="11" * 32, writer_proof_digest="22" * 32,
        initial_snapshot=base64.b64encode(bytes.fromhex(value["initial_hex"])).decode().rstrip("="),
        update_scope=dict(update_scope="cell", update_rule=value["update_rule"], binding=value["scope_binding"]))


def synthetic_completion():
    """Build parser inputs only; none of the changed bytes are native observations."""
    value = vector()
    initial, selection = (bytes.fromhex(value[name + "_hex"]) for name in ("initial", "selection"))
    snapshot, _ = iteration.decode_native_learning_checkpoint(bytes.fromhex(value["completed_hex"]))
    prefix, replay = iteration.decode_native_learning_checkpoint(selection)
    request = snapshot["request"]
    payload = json.loads(json.loads((ORIGINAL / "no-update-v9/readback.json").read_bytes())["payload_json"])
    payload.update(learning_operation_id=request["operation_id"], source_run_id=request["source_run_id"],
                   learning_head=list(bytes.fromhex(replay["head"])),
                   learning_decision_head=list(bytes.fromhex(prefix["receipts"][-1]["predecessor"])),
                   source_task_receipt=list(bytes.fromhex(request["completed_task_receipt"])))
    publication = json.loads(payload["publication_json"])
    update = publication["intent"]
    final = snapshot["receipts"][-1]["observation"]
    update["previous"]["scope"]["run_id"] = request["source_run_id"]
    update["target"]["scope"]["run_id"] = final["state_partition"]["run_id"]
    update["selection"] = list(bytes.fromhex(final["selection_digest"]))
    update["operation_id"] = "learning-retained-task:" + native.sha(
        b"hepta.agentd.learning-retained-task-operation.v1\0" + request["operation_id"].encode() +
        bytes(payload["learning_decision_head"]))
    grant = publication["signed"]["grant"]
    grant["binding"]["request_sha256"] = list(bytes.fromhex(native.sha(
        b"hepta.agentd.generation-update-intent.v1\0" + native.native_json(update))))
    grant["binding"]["payload_sha256"] = list(bytes.fromhex(native.owner_digest(update["target"])))
    publication["signed"]["signature"] = [0] * 64
    publication["witness"]["authority_ref"]["authority"]["binding_sha256"] = list(bytes.fromhex(native.sha(
        b"hepta.kernel.authority.verified-use-binding.final-use.v1\0" + native.native_json(grant["binding"]))))
    publication["signed_grant_digest"] = list(bytes.fromhex(native.sha(
        b"hepta.agentd.generation-update-signed-grant.v1\0" + native.native_json(publication["signed"]))))
    publication_raw = native.native_json(publication)
    publication_id = native.sha(native.PUBLICATION_DOMAIN + publication_raw)
    payload["publication_json"] = publication_raw.decode()
    observation = payload["observation"]
    observation["selection_digest"] = update["selection"]
    observation["state_partition_digest"] = list(bytes.fromhex(native.partition_digest(update["target"]["scope"])))
    observation["task_owner_publication"] = list(bytes.fromhex(publication_id))
    generation = json.loads(payload["generation_observation_json"])
    generation["snapshot"]["scope"] = update["target"]["scope"]
    payload["generation_observation_json"] = native.native_json(generation).decode()
    raw_payload = native.native_json(payload)
    readback = native.native_json(dict(schema=native.NATIVE_SCHEMA, payload_json=raw_payload.decode(),
        payload_digest=list(bytes.fromhex(native.sha(native.DOMAIN + raw_payload)))))
    for name in ("checkpoint_digest", "committed_step_receipt", "task_owner_publication"):
        final[name] = native.native_digest(observation[name])
    # A synthetic completion binds this synthetic use. The separately pinned
    # native completed cut is never changed on disk or described as this result.
    completed = rehash_mutation(snapshot)
    return dict(selection=selection, completed=completed, readback=readback,
        frozen=iteration.frozen_expectations_from_initial_checkpoint(initial),
        expected=capture.fixture_expectations(readback), profile=native.native_json(profile_for(value)))


def review(case):
    return scoped.review_native_scoped_learning_completion(
        case["selection"], case["completed"], case["readback"], case["profile"],
        expected_selection_sha256=native.sha(case["selection"]),
        expected_completed_sha256=native.sha(case["completed"]),
        expected_readback_sha256=native.sha(case["readback"]),
        expected_root_profile_sha256=native.sha(case["profile"]), frozen=case["frozen"], expected=case["expected"])


def synthetic_business():
    """Versioned, explicitly unauthenticated same-operation parser bindings."""
    case = synthetic_completion()
    report = review(case)
    snapshot, _ = iteration.decode_native_learning_checkpoint(case["completed"])
    request, final = snapshot["request"], report["final_observation"]
    use = report["selection_use_review"]["native_readback_review"]
    _, bindings = original_case("no-update-v9")
    bindings.update(schema=business.TRAINER_NO_UPDATE_BINDINGS_SCHEMA,
        operation_id=request["operation_id"], invocation_id="synthetic-heplcp03-business-parser",
        capture_basis="engineering-control", root_envelope_schema=2)
    bindings["source_pair"]["hepta"] = dict(commit="f97f3c90ac1ac3d5171fd9f25b3e34431f44a367",
        tree="7020c0271840f0de369e6ec88d8ef0c0d9acd855")
    bindings["source_pair"]["chain"] = dict(commit="df927b6ffaecff293b9e9428e3ba516f47cd101a",
        tree="a883a05b590fb8b0113b3715f4294eee7a00275b")
    materials = {name: case[name] for name in ("selection", "completed", "readback")}
    materials.update(freeze=native.native_json(case["frozen"]), expected=native.native_json(case["expected"]),
        root_profile=case["profile"])
    bindings["materials"] = {name: dict(sha256=native.sha(raw), operation_id=request["operation_id"],
        source_pair=copy.deepcopy(bindings["source_pair"])) for name, raw in materials.items()}
    bindings["learning"] = dict(initial_head=report["frozen_initial_head"],
        evaluation_profile=request["evaluation_profile"],
        baseline_bundle=iteration.bundle_digest(request["selected_bundle"]), selected_bundle=final["retained_bundle"],
        source_run_id=request["source_run_id"], next_run_id=final["state_partition"]["run_id"],
        next_task_digest=use["task_digest"], next_input_digest=use["input_digest"],
        cost_source_digest=use["cost_source_digest"])
    bindings["consumer"] = {name: final["state_partition"][name] for name in ("principal_id", "agent_id", "cell_id")}
    return materials, bindings


def business_review(materials, bindings):
    raw = native.native_json(bindings)
    return business.review_business_iteration(materials, bindings_raw=raw, expected_bindings_sha256=native.sha(raw))


class TrainingNoUpdateInteropTests(unittest.TestCase):
    def test_original_rust_cuts_and_every_signing_payload_match(self):
        value = vector()
        for name, tags, next_stage in (("initial", [], 0), ("dataset", [0, 1], 2),
                ("training", [0, 1, 8], 5), ("selection", [0, 1, 8, 5], 6),
                ("completed", [0, 1, 8, 5, 7], None)):
            with self.subTest(cut=name):
                raw = bytes.fromhex(value[name + "_hex"])
                snapshot, replay = iteration.decode_native_learning_checkpoint(raw)
                self.assertEqual([r["observation"]["tag"] for r in snapshot["receipts"]], tags)
                self.assertEqual(replay["next_stage"], next_stage)
                self.assertEqual(replay["initial_head"], value["initial_head"])
                for index, receipt in enumerate(snapshot["receipts"]):
                    self.assertEqual(iteration._receipt_head(receipt), native.sha(
                        bytes.fromhex(value["receipt_signing_payloads_hex"][index])))
        self.assertEqual(replay["head"], value["completed_head"])
        self.assertIsNone(replay["candidate_bundle"])
        self.assertTrue(replay["no_update"])
        self.assertEqual(replay["next_task_bundle"], value["selected_bundle"])
        self.assertEqual(native.sha(bytes.fromhex(value["receipt_signing_payloads_hex"][2])),
                         "ef0b4fc9048fecab6ec3a0a568d724ea587ea412b48d8d270e88ac42436d67b7")

    def test_original_tag_six_and_seven_rust_known_vectors_remain_exact(self):
        common = dict(operation_id="operation", predecessor="01" * 32, actor_id="observer",
            evidence_digest="02" * 32, observed_unix_seconds=42)
        observation = dict(tag=6, candidate_bundle="03" * 32,
            state_partition=dict(principal_id="principal", agent_id="agent", cell_id="cell", run_id="run"),
            checkpoint_digest="04" * 32, selection_digest="05" * 32,
            committed_step_receipt="06" * 32, state_cutover_receipt="07" * 32)
        self.assertEqual(iteration._receipt_head(dict(common, observation=observation)),
                         "cea426fda4d553a9ec83a8d376a4e03e20d8e6c34295babc600f7efe5e609cd0")
        observation["tag"] = 7
        observation["retained_bundle"] = observation.pop("candidate_bundle")
        observation["task_owner_publication"] = observation.pop("state_cutover_receipt")
        self.assertEqual(iteration._receipt_head(dict(common, observation=observation)),
                         "c156312f3af93615f6165e23d9e4168f1a1f78f4c401fbe1955ccfd497d62df9")

    def test_version_requires_explicit_outcome_and_never_upgrades_legacy_bytes(self):
        value = vector()
        malformed = [(b"HEPLCP03" + bytes.fromhex(value[name + "_hex"])[8:],
                      "LEARNING_CHECKPOINT_TRAINER_NO_UPDATE_VERSION") for name in ("initial", "dataset")]
        malformed += [(b"HEPLCP02" + bytes.fromhex(value["training_hex"])[8:], "LEARNING_CHECKPOINT_ENUM"),
                      (b"HEPLCP01" + bytes.fromhex(value["completed_hex"])[8:], "LEARNING_CHECKPOINT_VERSION"),
                      (b"HEPLCP04" + bytes.fromhex(value["completed_hex"])[8:], "LEARNING_CHECKPOINT_VERSION")]
        for raw, code in malformed:
            with self.subTest(code=code), self.assertRaisesRegex(native.ReadbackRefusal, code):
                iteration.decode_native_learning_checkpoint(raw)

    def test_unknown_training_tags_and_reason_codes_never_mean_no_update(self):
        original = bytes.fromhex(vector()["training_hex"])
        offset = len(original) - 32 - 114
        self.assertEqual(original[offset:offset + 2], b"\x08\x00")
        for index, values, code in ((offset, (9, 255), "LEARNING_CHECKPOINT_ENUM"),
                                   (offset + 1, (1, 2, 255), "LEARNING_TRAINER_NO_UPDATE_REASON")):
            for value in values:
                raw = bytearray(original); raw[index] = value
                with self.subTest(index=index, value=value), self.assertRaisesRegex(native.ReadbackRefusal, code):
                    iteration.decode_native_learning_checkpoint(bytes(raw))

    def test_original_dataset_baseline_budget_and_generator_are_required(self):
        original, _ = iteration.decode_native_learning_checkpoint(bytes.fromhex(vector()["training_hex"]))
        changes = [("retained_bundle", "ab" * 32, "LEARNING_TRAINER_NO_UPDATE_BINDING"),
                   ("dataset", "ab" * 32, "LEARNING_TRAINER_NO_UPDATE_BINDING"),
                   ("update_rule", "00" * 32, "LEARNING_ZERO_DIGEST"),
                   ("steps", 0, "LEARNING_TRAINING_BUDGET"),
                   ("milliseconds", 0, "LEARNING_TRAINING_BUDGET"),
                   ("steps", original["request"]["budget"]["maximum_training_steps"] + 1, "LEARNING_TRAINING_BUDGET"),
                   ("milliseconds", original["request"]["budget"]["maximum_training_milliseconds"] + 1, "LEARNING_TRAINING_BUDGET")]
        for field, value, code in changes:
            changed = copy.deepcopy(original); changed["receipts"][2]["observation"][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(native.ReadbackRefusal, code):
                iteration.decode_native_learning_checkpoint(mutated_encoding(changed))
        for actor in (original["owners"]["evaluator"], original["owners"]["next_use_observer"]):
            changed = copy.deepcopy(original); changed["receipts"][2]["actor_id"] = actor
            with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ACTOR"):
                iteration.decode_native_learning_checkpoint(rehash_mutation(changed))

    def test_rehashed_extra_evaluation_or_duplicate_training_cannot_change_path(self):
        original, _ = iteration.decode_native_learning_checkpoint(bytes.fromhex(vector()["completed_hex"]))
        changed = copy.deepcopy(original)
        changed["receipts"].insert(3, copy.deepcopy(changed["receipts"][2]))
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_STAGE_ORDER"):
            iteration.decode_native_learning_checkpoint(rehash_mutation(changed))
        changed = copy.deepcopy(original)
        evaluation = copy.deepcopy(changed["receipts"][3])
        evaluation["actor_id"] = changed["owners"]["evaluator"]
        evaluation["observation"] = dict(tag=3, candidate_bundle=vector()["selected_bundle"],
            evaluation_profile=changed["request"]["evaluation_profile"], disposition=1)
        changed["receipts"].insert(3, evaluation)
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_STAGE_ORDER"):
            iteration.decode_native_learning_checkpoint(rehash_mutation(changed))

    def test_next_use_requires_retained_bundle_distinct_run_and_committed_receipt(self):
        original, _ = iteration.decode_native_learning_checkpoint(bytes.fromhex(vector()["completed_hex"]))
        for fault in ("candidate-cutover", "same-run", "different-bundle", "missing-step", "missing-publication"):
            changed = copy.deepcopy(original); value = changed["receipts"][-1]["observation"]
            if fault == "candidate-cutover":
                value["tag"] = 6
                value["candidate_bundle"] = value.pop("retained_bundle")
                value["state_cutover_receipt"] = value.pop("task_owner_publication")
            elif fault == "same-run":
                value["state_partition"]["run_id"] = changed["request"]["source_run_id"]
            elif fault == "different-bundle":
                value["retained_bundle"] = "ab" * 32
            else:
                value["committed_step_receipt" if fault == "missing-step" else "task_owner_publication"] = "00" * 32
            with self.subTest(fault=fault), self.assertRaises(native.ReadbackRefusal):
                iteration.decode_native_learning_checkpoint(mutated_encoding(changed))

    def test_use_join_requires_original_root_scope_before_reading_use(self):
        value = vector(); raw = bytes.fromhex(value["selection_hex"])
        frozen = iteration.frozen_expectations_from_initial_checkpoint(bytes.fromhex(value["initial_hex"]))
        for extra in ({}, {"root_profile_raw": b"{}"}, {"expected_root_profile_sha256": "ab" * 32}):
            with self.subTest(extra=extra), self.assertRaisesRegex(native.ReadbackRefusal,
                    "LEARNING_TRAINER_NO_UPDATE_ROOT_PROFILE_REQUIRED"):
                iteration.review_native_learning_iteration(raw, b"", expected_checkpoint_sha256=native.sha(raw),
                    expected_readback_sha256="ab" * 32, frozen=frozen, expected={}, **extra)

    def test_original_scope_rule_must_match_even_after_all_receipts_are_rehashed(self):
        value = vector(); initial = bytes.fromhex(value["initial_hex"])
        snapshot, _ = iteration.decode_native_learning_checkpoint(bytes.fromhex(value["completed_hex"]))
        snapshot["receipts"][2]["observation"]["update_rule"] = "ab" * 32
        raw = rehash_mutation(snapshot)
        changed, replay = iteration.decode_native_learning_checkpoint(raw)
        profile = native.native_json(profile_for(value))
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_ROOT_SCOPE_RULE"):
            scoped._review_scope(profile, native.sha(profile), changed, replay,
                iteration.frozen_expectations_from_initial_checkpoint(initial))

    def test_native_scope_checks_no_candidate_without_claiming_equal_tensors(self):
        value = vector(); snapshot, replay = iteration.decode_native_learning_checkpoint(bytes.fromhex(value["completed_hex"]))
        raw = native.native_json(profile_for(value))
        result = scoped._review_scope(raw, native.sha(raw), snapshot, replay,
            iteration.frozen_expectations_from_initial_checkpoint(bytes.fromhex(value["initial_hex"])))
        self.assertEqual(result["training_receipts_checked"], 0)
        self.assertEqual(result["trainer_no_update_receipts_checked"], 1)
        self.assertFalse(result["quantized_weights_unchanged_verified"])
        self.assertFalse(result["root_profile_origin_authenticated"])

    def test_explicit_synthetic_full_join_has_five_receipts_and_no_fabricated_evaluation(self):
        result = review(synthetic_completion())
        self.assertEqual(result["schema"], "trnm-cell-learning-scoped-completed-use-review-v2")
        self.assertEqual(result["receipt_count"], 5)
        self.assertTrue(result["no_update"])
        prior = result["selection_use_review"]
        self.assertEqual(prior["schema"], "trnm-cell-learning-iteration-use-review-v3")
        self.assertEqual(prior["checkpoint_schema"], "HEPLCP03")
        self.assertEqual(prior["training_disposition"], "quantized_weights_unchanged")
        self.assertIsNone(prior["evaluation_disposition"])
        self.assertIsNone(prior["proposal_disposition"])
        self.assertFalse(prior["trained_candidate_present"])
        for name in ("full_learning_iteration_completed", "real_model_training_verified", "hepta_final_use_accepted",
                     "independent_control_accepted", "learning_signatures_verified", "production_activation"):
            self.assertIs(result[name], False)
        self.assertEqual((result["qualification"], result["authority"], result["current_permission"]),
                         ("HOLD_NO_GO", "DENY_ALL", "NOT_EXPORTED"))

    def test_missing_selection_next_use_or_original_readback_does_not_complete(self):
        value = vector()
        for cut in ("training", "selection"):
            case = synthetic_completion(); case["completed"] = bytes.fromhex(value[cut + "_hex"])
            with self.subTest(cut=cut), self.assertRaisesRegex(native.ReadbackRefusal, "COMPLETION_EXACT_RECEIPT_PREFIX"):
                review(case)
        case = synthetic_completion()
        case["readback"] = (ORIGINAL / "no-update-v9/readback.json").read_bytes()
        case["expected"] = capture.fixture_expectations(case["readback"])
        with self.assertRaisesRegex(native.ReadbackRefusal, "LEARNING_READBACK_HEAD"):
            review(case)

    def test_pending_or_failed_task_cannot_become_completed_no_update(self):
        for fault in ("pending", "failed", "unknown"):
            case = synthetic_completion()
            payload = json.loads(json.loads(case["readback"])["payload_json"])
            if fault == "pending":
                generation = json.loads(payload["generation_observation_json"])
                generation["pending_request_digest"] = [7] * 32
                payload["generation_observation_json"] = native.native_json(generation).decode()
            else:
                step = json.loads(payload["step_receipt_json"]); step["disposition"] = fault
                raw = native.native_json(step); payload["step_receipt_json"] = raw.decode()
                payload["observation"]["committed_step_receipt"] = list(bytes.fromhex(native.sha(native.STEP_DOMAIN + raw)))
            raw = native.native_json(payload)
            case["readback"] = native.native_json(dict(schema=native.NATIVE_SCHEMA, payload_json=raw.decode(),
                payload_digest=list(bytes.fromhex(native.sha(native.DOMAIN + raw)))))
            case["expected"] = capture.fixture_expectations(case["readback"])
            with self.subTest(fault=fault), self.assertRaisesRegex(native.ReadbackRefusal,
                    "COMPLETION_ACK_PENDING" if fault == "pending" else "NATIVE_UNSUCCESSFUL_STEP"):
                review(case)

    def test_original_heplcp02_six_and_seven_receipt_reports_remain_byte_equivalent(self):
        for name, count in (("adopt-v1", 7), ("no-update-v9", 6)):
            files = {key: (ORIGINAL / name / filename).read_bytes() for key, filename in
                (("selection", "selection.bin"), ("completed", "completed.bin"), ("readback", "readback.json"),
                 ("freeze", "freeze.json"), ("expected", "expected.json"))}
            result = completion.review_native_learning_completion(files["selection"], files["completed"], files["readback"],
                expected_selection_sha256=native.sha(files["selection"]),
                expected_completed_sha256=native.sha(files["completed"]), expected_readback_sha256=native.sha(files["readback"]),
                frozen=json.loads(files["freeze"]), expected=json.loads(files["expected"]))
            self.assertEqual(result["schema"], "trnm-cell-learning-completed-use-review-v1")
            self.assertEqual(result["receipt_count"], count)
            historical = json.loads((ORIGINAL / name / "stdout.json").read_bytes())
            self.assertEqual(result, historical)
            encoded = (json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
            self.assertEqual(encoded, (ORIGINAL / name / "stdout.json").read_bytes())
            paths = ROOT / "evidence/cell-learning-business-readback-20261109/bindings"
            bindings_raw = (paths / (name + ".json")).read_bytes()
            result = business.review_business_iteration(files, bindings_raw=bindings_raw,
                expected_bindings_sha256=native.sha(bindings_raw))
            encoded = (json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
            archived = ROOT / "evidence/next-use-provenance-20261110" / (name + "-review-v2.json")
            self.assertEqual(encoded, archived.read_bytes())

    def test_business_v2_requires_separately_pinned_same_operation_root_material(self):
        materials, original = synthetic_business()
        result = business_review(materials, original)
        self.assertEqual(result["schema"], "trnm-cell-learning-business-review-v3")
        self.assertEqual((result["checkpoint_codec"], result["decision"], result["receipt_count"]),
                         ("HEPLCP03", "NoUpdate", 5))
        self.assertIsNone(result["declared_costs"]["training_artifact_bytes"])
        self.assertFalse(result["trained_candidate_present"])
        self.assertFalse(result["quantized_weights_unchanged_verified"])
        self.assertEqual(result["next_use_provenance"]["status"], "SAME_ORIGINAL_ACTOR_DISTINCT_RUN_ONLY")
        self.assertFalse(result["independent_consumer_verified"])
        self.assertFalse(result["hepta_final_use_accepted"])
        self.assertFalse(result["funded_mapping_observed"])
        for fault, code in (("missing", "BUSINESS_INPUT_FIELDS"), ("pin", "BUSINESS_MATERIAL_PIN"),
                ("source", "BUSINESS_SOURCE_PAIR"), ("operation", "BUSINESS_OPERATION"),
                ("root-schema", "BUSINESS_ROOT_PROFILE_SCHEMA"), ("legacy-schema", "BUSINESS_CHECKPOINT_SCHEMA")):
            bindings, inputs = copy.deepcopy(original), dict(materials)
            if fault == "missing":
                del inputs["root_profile"]
            elif fault == "pin":
                bindings["materials"]["root_profile"]["sha256"] = "ab" * 32
            elif fault == "source":
                bindings["materials"]["root_profile"]["source_pair"]["hepta"]["commit"] = "ab" * 20
            elif fault == "operation":
                bindings["materials"]["root_profile"]["operation_id"] = "foreign-operation"
            elif fault == "root-schema":
                bindings["root_envelope_schema"] = None
            else:
                bindings["schema"] = business.BINDINGS_SCHEMA
                del bindings["materials"]["root_profile"]; del inputs["root_profile"]
            with self.subTest(fault=fault), self.assertRaisesRegex(native.ReadbackRefusal, code):
                business_review(inputs, bindings)

    def test_business_v2_cli_and_legacy_codec_separation(self):
        materials, bindings = synthetic_business()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw = native.native_json(bindings); path = directory / "bindings.json"; path.write_bytes(raw)
            command = [sys.executable, str(ROOT / "scripts/cell_learning_business_join.py"),
                "--bindings", str(path), "--bindings-sha256", native.sha(raw)]
            for name, value in materials.items():
                path = directory / name; path.write_bytes(value)
                command.extend(("--" + name.replace("_", "-"), str(path)))
            run = subprocess.run(command, capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["schema"], "trnm-cell-learning-business-review-v3")
        materials, bindings = original_case("no-update-v9")
        bindings["schema"] = business.TRAINER_NO_UPDATE_BINDINGS_SCHEMA
        materials["root_profile"] = b"{}"
        bindings["materials"]["root_profile"] = dict(sha256=native.sha(b"{}"),
            operation_id=bindings["operation_id"], source_pair=copy.deepcopy(bindings["source_pair"]))
        with self.assertRaisesRegex(native.ReadbackRefusal, "BUSINESS_CHECKPOINT_SCHEMA"):
            business_review(materials, bindings)

    def test_cli_requires_paired_root_inputs_and_emits_only_closed_schema(self):
        case = synthetic_completion()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            command = [sys.executable, str(ROOT / "scripts/cell_learning_completion_join.py")]
            mapping = (("selection-checkpoint", "selection"), ("completed-checkpoint", "completed"),
                       ("readback", "readback"), ("freeze", "frozen"), ("expected", "expected"),
                       ("root-profile", "profile"))
            for name, field in mapping:
                raw = case[field] if type(case[field]) is bytes else native.native_json(case[field])
                path = directory / name; path.write_bytes(raw)
                command += ["--" + name, str(path), "--" + name + "-sha256", native.sha(raw)]
            run = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["schema"], "trnm-cell-learning-completed-use-review-v2")
            index = command.index("--root-profile-sha256")
            run = subprocess.run(command[:index] + command[index + 2:], capture_output=True, timeout=20)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, b"")
            # The original first-use CLI shares the same mandatory Root pin.
            first_use = [sys.executable, str(ROOT / "scripts/cell_adoption_readback.py")]
            for name, field in (("readback", "readback"), ("expected", "expected"),
                    ("learning-checkpoint", "selection"), ("learning-freeze", "frozen"),
                    ("root-profile", "profile")):
                raw = case[field] if type(case[field]) is bytes else native.native_json(case[field])
                path = directory / name; path.write_bytes(raw)
                first_use += ["--" + name, str(path), "--" + name + "-sha256", native.sha(raw)]
            run = subprocess.run(first_use, capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["schema"], "trnm-cell-learning-iteration-use-review-v3")
            run = subprocess.run(first_use[:-2], capture_output=True, timeout=20)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, b"")


if __name__ == "__main__":
    unittest.main()
