"""Join original Hepta learning checkpoints to the existing first-use reader.

HEPLCP02 includes the evaluation profile in the initial commitment. HEPLCP01
has no such pin and is deliberately refused. This read-only adapter replays the native
checkpoint relation; it cannot authenticate its owner, its learning signatures,
current permission, model execution, or settlement. All external qualification
flags remain false, including for correctly bound native engineering fixtures.
"""
from __future__ import annotations

import copy

import cell_adoption_readback as native

MAGIC = b"HEPLCP02"
MAX_CHECKPOINT = 8192
MAX_FREEZE = 65536
MAX_RECEIPTS = 7
FREEZE_SCHEMA = "trnm-cell-learning-freeze-expectations-v2"
REPORT_SCHEMA = "trnm-cell-learning-iteration-use-review-v2"
INITIAL_DOMAIN = b"hepta.learning.iteration-checkpoint.v2\0"
RECEIPT_DOMAIN = b"hepta.learning.iteration-observation.v1\0"
BUNDLE_DOMAIN = b"hepta.cell.compatibility-bundle.v1\0"
PARTITION_DOMAIN = b"hepta.cell.state-partition.v1\0"
REQUEST_IDS = "operation_id principal_id agent_id cell_id source_run_id".split()
OWNER_IDS = "experience dataset trainer evaluator proposal selector next_use_observer".split()
COMPONENTS = "base heads composition encoder tokenizer normalizer calibration numeric_profile output_schema state_schema state_semantics".split()
LINEAGE = "source_bundle dataset update_rule evaluation_profile".split()
ENVELOPE_DIGESTS = "base_commit base_tree objective_digest grammar_digest".split()
BUDGET_LIMITS = {
    "maximum_dataset_rows": 1_000_000,
    "maximum_dataset_bytes": 1 << 30,
    "maximum_training_steps": 1_000_000,
    "maximum_training_milliseconds": 86_400_000,
    "maximum_artifact_bytes": 16 << 30,
}
ENVELOPE_LIMITS = {
    "maximum_files": 100,
    "maximum_diff_bytes": 1024 * 1024,
    "maximum_candidates": 32,
    "maximum_parallel_sandboxes": 8,
    "expiry_unix_seconds": (1 << 64) - 1,
}

require = native.require
fields = native.fields
integer = native.integer
stable_id = native.stable_id
sha = native.sha


def _digest(value, *, nonzero=True):
    native.hex_digest(value)
    require(not nonzero or value != "0" * 64, "LEARNING_ZERO_DIGEST")
    return bytes.fromhex(value)


def _id(value):
    raw = stable_id(value).encode("ascii")
    # The signing domains use u32 lengths. The persistence codec uses u8.
    return len(raw).to_bytes(4, "big") + raw


def _number(value, width, *, maximum=None, minimum=0):
    integer(value, minimum=minimum, maximum=(1 << (width * 8)) - 1 if maximum is None else maximum)
    return value.to_bytes(width, "big")


def _optional(value):
    return b"\0" if value is None else b"\1" + _digest(value)


def bundle_digest(bundle):
    """Original CellCompatibilityBundleV1 digest, including complete lineage."""
    fields(bundle, "artifact_id generation components training_lineage rollback_predecessor", "LEARNING_BUNDLE_FIELDS")
    components = bundle["components"]
    fields(components, " ".join(COMPONENTS + ["organ_adapter", "cell_adapter"]), "LEARNING_COMPONENT_FIELDS")
    raw = bytearray(BUNDLE_DOMAIN + _id(bundle["artifact_id"]))
    raw.extend(_number(bundle["generation"], 8, minimum=1))
    for name in COMPONENTS:
        raw.extend(_digest(components[name]))
    for value in (components["organ_adapter"], components["cell_adapter"], bundle["rollback_predecessor"]):
        raw.extend(_optional(value))
    lineage = bundle["training_lineage"]
    require((lineage is None) == (bundle["rollback_predecessor"] is None), "LEARNING_BUNDLE_LINEAGE")
    if lineage is not None:
        fields(lineage, " ".join(LINEAGE), "LEARNING_LINEAGE_FIELDS")
        for name in LINEAGE:
            raw.extend(_digest(lineage[name]))
        require(lineage["source_bundle"] == bundle["rollback_predecessor"], "LEARNING_BUNDLE_PREDECESSOR")
    return sha(bytes(raw))


def _initial_head(request, owners):
    fields(request, " ".join(REQUEST_IDS) + " completed_task_receipt selected_artifact_digest evaluation_profile selected_bundle envelope budget", "LEARNING_REQUEST_FIELDS")
    fields(owners, "evidence_trust_digest " + " ".join(OWNER_IDS), "LEARNING_OWNERS_FIELDS")
    envelope, budget = request["envelope"], request["budget"]
    fields(envelope, "envelope_id " + " ".join(ENVELOPE_DIGESTS) + " " + " ".join(ENVELOPE_LIMITS), "LEARNING_ENVELOPE_FIELDS")
    fields(budget, " ".join(BUDGET_LIMITS), "LEARNING_BUDGET_FIELDS")
    for name, maximum in ENVELOPE_LIMITS.items():
        integer(envelope[name], minimum=1, maximum=maximum)
    for name, maximum in BUDGET_LIMITS.items():
        integer(budget[name], minimum=1, maximum=maximum)
    for left, right in (("trainer", "evaluator"), ("trainer", "selector"), ("evaluator", "selector"),
                        ("next_use_observer", "trainer"), ("next_use_observer", "selector")):
        require(owners[left] != owners[right], "LEARNING_OWNER_CONFLICT")
    raw = bytearray(INITIAL_DOMAIN)
    for value in [request[name] for name in REQUEST_IDS] + [envelope["envelope_id"]] + [owners[name] for name in OWNER_IDS]:
        raw.extend(_id(value))
    for value in [request["completed_task_receipt"], request["selected_artifact_digest"],
                  request["evaluation_profile"], bundle_digest(request["selected_bundle"]),
                  *[envelope[name] for name in ENVELOPE_DIGESTS], owners["evidence_trust_digest"]]:
        raw.extend(_digest(value))
    for name, width in (("maximum_files", 2), ("maximum_diff_bytes", 8), ("maximum_candidates", 2),
                        ("maximum_parallel_sandboxes", 1), ("expiry_unix_seconds", 8)):
        raw.extend(_number(envelope[name], width))
    for name in BUDGET_LIMITS:
        raw.extend(_number(budget[name], 4 if name == "maximum_dataset_rows" else 8))
    return sha(bytes(raw))


class _Reader:
    def __init__(self, raw):
        require(type(raw) is bytes and len(raw) <= MAX_CHECKPOINT, "LEARNING_CHECKPOINT_LIMIT")
        self.raw, self.offset = raw, 0

    def take(self, length):
        end = self.offset + length
        require(end <= len(self.raw), "LEARNING_CHECKPOINT_TRUNCATED")
        value, self.offset = self.raw[self.offset:end], end
        return value

    def number(self, width):
        return int.from_bytes(self.take(width), "big")

    def digest(self):
        return self.take(32).hex()

    def identifier(self):
        length = self.number(1)
        require(1 <= length <= 128, "LEARNING_CHECKPOINT_ID_LENGTH")
        raw = self.take(length)
        try:
            value = raw.decode("ascii")
        except UnicodeError as error:
            raise native.ReadbackRefusal("LEARNING_CHECKPOINT_ID_ENCODING") from error
        return stable_id(value)

    def flag(self):
        value = self.number(1)
        require(value in (0, 1), "LEARNING_CHECKPOINT_ENUM")
        return value

    def optional(self):
        return self.digest() if self.flag() else None

    def bundle(self):
        artifact_id, generation = self.identifier(), self.number(8)
        components = {name: self.digest() for name in COMPONENTS}
        components.update(organ_adapter=self.optional(), cell_adapter=self.optional())
        rollback = self.optional()
        lineage = {name: self.digest() for name in LINEAGE} if self.flag() else None
        return dict(artifact_id=artifact_id, generation=generation, components=components,
                    training_lineage=lineage, rollback_predecessor=rollback)

    def observation(self):
        tag = self.number(1)
        require(tag <= 7, "LEARNING_CHECKPOINT_ENUM")
        value = dict(tag=tag)
        if tag == 0:
            value.update(episode_digest=self.digest(), completed_task_receipt=self.digest())
        elif tag == 1:
            value.update(snapshot_digest=self.digest(), episode_digest=self.digest(), withdrawal_frontier=self.digest(),
                         rows=self.number(4), bytes=self.number(8))
        elif tag == 2:
            value.update(candidate=self.bundle(), steps=self.number(8), milliseconds=self.number(8), artifact_bytes=self.number(8))
        elif tag == 3:
            value.update(candidate_bundle=self.digest(), evaluation_profile=self.digest(), disposition=self.flag())
        elif tag == 4:
            value.update(candidate_bundle=self.digest(), proposal_id=self.identifier(), composition_digest=self.digest(), disposition=self.flag())
        elif tag == 5:
            value.update(candidate_bundle=self.digest(), selection_digest=self.digest())
        else:
            value["retained_bundle" if tag == 7 else "candidate_bundle"] = self.digest()
            value["state_partition"] = {name: self.identifier() for name in ("principal_id", "agent_id", "cell_id", "run_id")}
            for name in ("checkpoint_digest", "selection_digest", "committed_step_receipt",
                         "task_owner_publication" if tag == 7 else "state_cutover_receipt"):
                value[name] = self.digest()
        return value


def _observation_signing_bytes(value):
    tag = value["tag"]
    raw = bytearray([tag])
    if tag == 0:
        for name in ("episode_digest", "completed_task_receipt"):
            raw.extend(_digest(value[name]))
    elif tag == 1:
        for name in ("snapshot_digest", "episode_digest", "withdrawal_frontier"):
            raw.extend(_digest(value[name]))
        raw.extend(_number(value["rows"], 4)); raw.extend(_number(value["bytes"], 8))
    elif tag == 2:
        raw.extend(_digest(bundle_digest(value["candidate"])))
        for name in ("steps", "milliseconds", "artifact_bytes"):
            raw.extend(_number(value[name], 8))
    elif tag == 3:
        raw.extend(_digest(value["candidate_bundle"])); raw.extend(_digest(value["evaluation_profile"]))
        raw.append(value["disposition"])
    elif tag == 4:
        raw.extend(_digest(value["candidate_bundle"])); raw.extend(_id(value["proposal_id"]))
        raw.extend(_digest(value["composition_digest"])); raw.append(value["disposition"])
    elif tag == 5:
        raw.extend(_digest(value["candidate_bundle"])); raw.extend(_digest(value["selection_digest"]))
    else:
        raw.extend(_digest(value["retained_bundle" if tag == 7 else "candidate_bundle"]))
        partition = PARTITION_DOMAIN + b"".join(_id(value["state_partition"][name]) for name in ("principal_id", "agent_id", "cell_id", "run_id"))
        raw.extend(bytes.fromhex(sha(partition)))
        for name in ("checkpoint_digest", "selection_digest", "committed_step_receipt",
                     "task_owner_publication" if tag == 7 else "state_cutover_receipt"):
            raw.extend(_digest(value[name]))
    return bytes(raw)


def _receipt_head(receipt):
    return sha(RECEIPT_DOMAIN + _id(receipt["operation_id"]) + _digest(receipt["predecessor"]) +
               _id(receipt["actor_id"]) + _digest(receipt["evidence_digest"]) +
               _number(receipt["observed_unix_seconds"], 8, minimum=1) +
               _observation_signing_bytes(receipt["observation"]))


def _replay(snapshot):
    request, owners, receipts = snapshot["request"], snapshot["owners"], snapshot["receipts"]
    initial = head = _initial_head(request, owners)
    require(len(receipts) <= MAX_RECEIPTS, "LEARNING_CHECKPOINT_RECEIPTS")
    expected_tag, prior_time, no_update = 0, 0, False
    selected = bundle_digest(request["selected_bundle"])
    candidate = candidate_id = episode = dataset = selection = decision_bundle = None
    budget = request["budget"]
    for receipt in receipts:
        value, observed = receipt["observation"], receipt["observed_unix_seconds"]
        tag = value["tag"]
        require(tag == expected_tag or (tag == 7 and expected_tag == 6), "LEARNING_STAGE_ORDER")
        require(receipt["operation_id"] == request["operation_id"], "LEARNING_OPERATION")
        require(receipt["actor_id"] == owners[OWNER_IDS[min(tag, 6)]], "LEARNING_ACTOR")
        require(receipt["predecessor"] == head, "LEARNING_RECEIPT_PREDECESSOR")
        require(0 < observed < request["envelope"]["expiry_unix_seconds"] and observed >= prior_time,
                "LEARNING_RECEIPT_TIME")
        _digest(receipt["evidence_digest"])
        if tag == 0:
            episode = value["episode_digest"]
            require(value["completed_task_receipt"] == request["completed_task_receipt"], "LEARNING_SOURCE_TASK")
            expected_tag = 1
        elif tag == 1:
            require(value["episode_digest"] == episode and 1 <= value["rows"] <= budget["maximum_dataset_rows"]
                    and 1 <= value["bytes"] <= budget["maximum_dataset_bytes"], "LEARNING_DATASET_BINDING")
            dataset, expected_tag = value["snapshot_digest"], 2
        elif tag == 2:
            candidate = value["candidate"]
            candidate_id = bundle_digest(candidate)
            lineage = candidate["training_lineage"]
            require(candidate["artifact_id"] != request["selected_bundle"]["artifact_id"]
                    and candidate["generation"] == request["selected_bundle"]["generation"] + 1
                    and candidate["rollback_predecessor"] == selected
                    and lineage is not None and lineage["source_bundle"] == selected
                    and lineage["dataset"] == dataset and lineage["evaluation_profile"] == request["evaluation_profile"],
                    "LEARNING_TRAINING_LINEAGE")
            require(1 <= value["steps"] <= budget["maximum_training_steps"]
                    and 1 <= value["milliseconds"] <= budget["maximum_training_milliseconds"]
                    and 1 <= value["artifact_bytes"] <= budget["maximum_artifact_bytes"], "LEARNING_TRAINING_BUDGET")
            expected_tag = 3
        elif tag == 3:
            require(value["candidate_bundle"] == candidate_id and value["evaluation_profile"] == request["evaluation_profile"],
                    "LEARNING_EVALUATION_PROFILE")
            no_update = value["disposition"] == 1
            decision_bundle = selected if no_update else None
            expected_tag = 5 if no_update else 4
        elif tag == 4:
            require(value["candidate_bundle"] == candidate_id and value["proposal_id"] == request["operation_id"],
                    "LEARNING_PROPOSAL_BINDING")
            no_update = value["disposition"] == 1
            decision_bundle = selected if no_update else candidate_id
            expected_tag = 5
        elif tag == 5:
            require(value["candidate_bundle"] == (selected if no_update else candidate_id), "LEARNING_SELECTION_BUNDLE")
            selection, expected_tag = value["selection_digest"], 6
        else:
            require((tag == 7) == no_update and
                    value["retained_bundle" if tag == 7 else "candidate_bundle"] == (selected if no_update else candidate_id),
                    "LEARNING_NEXT_USE_BUNDLE")
            partition = value["state_partition"]
            require(all(partition[name] == request[name] for name in ("principal_id", "agent_id", "cell_id"))
                    and partition["run_id"] != request["source_run_id"] and value["selection_digest"] == selection,
                    "LEARNING_NEXT_USE_PARTITION")
            expected_tag = None
        head, prior_time = _receipt_head(receipt), observed
    require(head == snapshot["head_digest"], "LEARNING_CHECKPOINT_HEAD")
    return dict(initial_head=initial, head=head, next_stage=expected_tag, no_update=no_update,
                selected_bundle=selected, candidate_bundle=candidate_id,
                next_task_bundle=decision_bundle)


def decode_native_learning_checkpoint(raw):
    """Bounded original HEPLCP02 decoding and structural replay, no authority."""
    reader = _Reader(raw)
    require(reader.take(8) == MAGIC, "LEARNING_CHECKPOINT_VERSION")
    request = {name: reader.identifier() for name in REQUEST_IDS}
    for name in ("completed_task_receipt", "selected_artifact_digest", "evaluation_profile"):
        request[name] = reader.digest()
    request["selected_bundle"] = reader.bundle()
    envelope = dict(envelope_id=reader.identifier())
    envelope.update({name: reader.digest() for name in ENVELOPE_DIGESTS})
    for name, width in (("maximum_files", 2), ("maximum_diff_bytes", 8), ("maximum_candidates", 2),
                        ("maximum_parallel_sandboxes", 1), ("expiry_unix_seconds", 8)):
        envelope[name] = reader.number(width)
    request["envelope"] = envelope
    request["budget"] = {name: reader.number(4 if name == "maximum_dataset_rows" else 8) for name in BUDGET_LIMITS}
    owners = dict(evidence_trust_digest=reader.digest())
    owners.update({name: reader.identifier() for name in OWNER_IDS})
    count = reader.number(1)
    require(count <= MAX_RECEIPTS, "LEARNING_CHECKPOINT_RECEIPTS")
    receipts = []
    for _ in range(count):
        receipts.append(dict(operation_id=reader.identifier(), predecessor=reader.digest(), actor_id=reader.identifier(),
            evidence_digest=reader.digest(), observed_unix_seconds=reader.number(8), observation=reader.observation()))
    snapshot = dict(request=request, owners=owners, receipts=receipts, head_digest=reader.digest())
    require(reader.offset == len(raw), "LEARNING_CHECKPOINT_TRAILING_BYTES")
    replay = _replay(snapshot)
    return snapshot, replay


def frozen_expectations_from_initial_checkpoint(raw):
    """Retain at initial admission, never derive production trust after training.

    The caller must retain these exact values independently before dispatch. A
    candidate-supplied initial checkpoint is not an authenticated freeze owner.
    Test users must label any such expectations fixture-derived.
    """
    snapshot, replay = decode_native_learning_checkpoint(raw)
    require(not snapshot["receipts"], "LEARNING_FREEZE_NOT_INITIAL")
    return dict(schema=FREEZE_SCHEMA, initial_head=replay["initial_head"],
                request=copy.deepcopy(snapshot["request"]), owners=copy.deepcopy(snapshot["owners"]))


def review_native_learning_iteration(checkpoint_raw, readback_raw, *, expected_checkpoint_sha256,
                                     expected_readback_sha256, frozen, expected):
    """Join independently pinned original freeze, checkpoint and first use.

    The original actor exports first use while the learning coordinator awaits
    NextUse. Therefore its last checkpoint receipt must be Selection, not a
    caller-invented complete-iteration receipt. Evaluation NoUpdate skips the
    Proposal stage, while an admitted no-proposal outcome still traverses it.
    """
    require(type(checkpoint_raw) is bytes and len(checkpoint_raw) <= MAX_CHECKPOINT, "LEARNING_CHECKPOINT_LIMIT")
    require(sha(checkpoint_raw) == native.hex_digest(expected_checkpoint_sha256), "LEARNING_CHECKPOINT_PIN")
    fields(frozen, "schema initial_head request owners", "LEARNING_FREEZE_FIELDS")
    require(frozen["schema"] == FREEZE_SCHEMA, "LEARNING_FREEZE_SCHEMA")
    frozen_head = _initial_head(frozen["request"], frozen["owners"])
    require(frozen_head == native.hex_digest(frozen["initial_head"]), "LEARNING_FREEZE_HEAD")
    snapshot, replay = decode_native_learning_checkpoint(checkpoint_raw)
    require(snapshot["request"] == frozen["request"] and snapshot["owners"] == frozen["owners"]
            and replay["initial_head"] == frozen_head, "LEARNING_FROZEN_REQUEST")
    original = native.review_native_learning_use(readback_raw,
        expected_readback_sha256=expected_readback_sha256, expected=expected)
    envelope = native.decode(readback_raw, native.MAX_WIRE)
    _, payload = native.raw_json(envelope["payload_json"])
    require(replay["next_stage"] == 6 and snapshot["receipts"][-1]["observation"]["tag"] == 5,
            "LEARNING_PRE_USE_SELECTION_REQUIRED")
    selection = snapshot["receipts"][-1]
    request = snapshot["request"]
    require(replay["head"] == native.native_digest(payload["learning_head"])
            and selection["predecessor"] == native.native_digest(payload["learning_decision_head"]),
            "LEARNING_READBACK_HEAD")
    require(request["operation_id"] == payload["learning_operation_id"]
            and request["source_run_id"] == payload["source_run_id"]
            and request["completed_task_receipt"] == native.native_digest(payload["source_task_receipt"])
            and request["selected_artifact_digest"] == native.native_digest(payload["source_selected_artifact"])
            and replay["selected_bundle"] == native.native_digest(payload["source_selected_bundle"]),
            "LEARNING_READBACK_SOURCE")
    _, publication = native.raw_json(payload["publication_json"])
    scope = publication["intent"]["target"]["scope"]
    require(request["principal_id"] == native.native_digest(scope["principal_digest"])
            and request["agent_id"] == scope["agent_id"] and request["cell_id"] == scope["cell_id"],
            "LEARNING_READBACK_SCOPE")
    use = payload["observation"]
    require(selection["observation"]["selection_digest"] == native.native_digest(use["selection_digest"])
            and replay["next_task_bundle"] == native.native_digest(use["bundle_digest"]),
            "LEARNING_READBACK_SELECTION")
    require((payload["disposition"] == "retained_model") == replay["no_update"], "LEARNING_READBACK_DISPOSITION")
    return dict(schema=REPORT_SCHEMA, scope="pinned-native-freeze-checkpoint-and-first-use-materials-only",
        checkpoint_sha256=expected_checkpoint_sha256, checkpoint_schema=MAGIC.decode("ascii"),
        frozen_initial_head=frozen_head, learning_head=replay["head"],
        evaluation_profile=request["evaluation_profile"], original_owner_ids=copy.deepcopy(snapshot["owners"]),
        original_budget=copy.deepcopy(request["budget"]), original_envelope=copy.deepcopy(request["envelope"]),
        receipt_count=len(snapshot["receipts"]), no_update=replay["no_update"],
        evaluation_disposition="no_update" if snapshot["receipts"][3]["observation"]["disposition"] else "qualified",
        proposal_disposition=next(("no_admissible_update" if receipt["observation"]["disposition"] else "update_candidates"
            for receipt in snapshot["receipts"] if receipt["observation"]["tag"] == 4), None),
        frozen_request_bindings_consistent=True, receipt_chain_bindings_consistent=True,
        evaluation_profile_bound_in_initial_checkpoint=True, selection_to_first_use_bindings_consistent=True,
        native_readback_review=original, authority="DENY_ALL", current_permission="NOT_EXPORTED",
        full_learning_iteration_completed=False, native_origin_authenticated=False,
        freeze_origin_authenticated=False, pre_dispatch_freeze_authenticated=False, learning_signatures_verified=False,
        grant_signature_verified_by_this_reader=False, cost_completeness_verified=False,
        learning_actor_control_binding_verified=False, evaluation_profile_semantics_verified=False,
        independent_control_accepted=False, current_permission_exported=False,
        real_model_training_verified=False, physical_installation_accepted=False,
        settlement_verified=False, hepta_final_use_accepted=False, production_activation=False,
        qualification="HOLD_NO_GO")
