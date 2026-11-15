"""Review exact native learning-use exports without issuing adoption authority.

The original Hepta actor produces the bytes. Independently retained expectations
bind a particular invocation; a producer must not derive them from its own
submission. JSON, matching hashes and these checks do not authenticate a host,
verify a FinalUse issuer, prove learning efficacy, or export current permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import string

NATIVE_SCHEMA = "hepta.agentd.learning-use-readback.v1"
EXPECTED_SCHEMA = "trnm-cell-learning-use-expectations-v1"
REPORT_SCHEMA = "trnm-cell-learning-use-readback-review-v1"
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_WIRE = 2 * MAX_PAYLOAD + 4096
MAX_EXPECTED = 65536
DOMAIN = b"hepta.agentd.learning-use-readback.v1\0"
MANIFEST_DOMAIN = b"hepta.cell.backend.v2\0"
STEP_DOMAIN = b"hepta.agentd.learning-next-use-receipt.v1\0"
PUBLICATION_DOMAIN = b"hepta.agentd.generation-publication.v1\0"
# An independently retained expectation, not a substitute native request digest.
INTENT_DOMAIN = b"hepta.agentd.learning-use-intent.v1\0"
EXPECTED_FIELDS = "schema disposition learning_operation_id learning_head learning_decision_head source_run_id source_task_receipt source_selected_artifact source_selected_bundle manifest_digest previous_manifest_digest task_digest input_digest source_frontier intent_digest owner_checkpoint publication_digest committed_step_receipt state_partition_digest state_cutover_receipt generation writer_epoch"
PAYLOAD_FIELDS = "disposition learning_operation_id learning_head learning_decision_head source_run_id source_task_receipt source_selected_artifact source_selected_bundle observation intent manifest_json previous_manifest_json publication_json step_receipt_json generation_observation_json authority current_permission"
OBSERVATION_FIELDS = "kind bundle_digest state_partition_digest checkpoint_digest selection_digest committed_step_receipt state_cutover_receipt task_owner_publication"
INTENT_FIELDS = "operation_id task_digest source_frontier predecessor_digest input_digest deadline_micros"
OWNER_FIELDS = "scope manifest_digest task_digest source_frontier initial_snapshot_digest generation writer_epoch config_digest"
SNAPSHOT_FIELDS = "scope manifest_digest generation writer_epoch revision state prefix stopped"
GENERATION_FIELDS = "task_digest source_frontier initial_snapshot_digest first_advance_input_digest owner_checkpoint snapshot cost pending_request_digest pending_output"
MANIFEST_FIELDS = "profile source_digest bundle_digest encoder head memory world_model decoder runtime_digest device_digest input_schema state_schema output_schema learning evolution max_input_bytes max_state_bytes max_delta_bytes max_prefix_bytes max_step_cost_entries max_ack_cost_entries"


class ReadbackRefusal(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ReadbackRefusal(code)


def fields(value, names, code):
    require(type(value) is dict and set(value) == set(names.split()), code)


def integer(value, *, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, "NATIVE_INTEGER")
    return value


def stable_id(value):
    require(type(value) is str and 1 <= len(value) <= 128 and
            all(c in string.ascii_letters + string.digits + "._-:" for c in value), "NATIVE_STABLE_ID")
    return value


def authority_id(value):
    require(type(value) is str and 1 <= len(value) <= 128 and
            all(c in string.ascii_letters + string.digits + "_-.:/" for c in value), "NATIVE_AUTHORITY_ID")
    return value


def hex_digest(value):
    require(type(value) is str and len(value) == 64 and
            all(c in "0123456789abcdef" for c in value), "EXPECTED_DIGEST")
    return value


def byte_array(value, maximum, *, exact=None):
    require(type(value) is list and len(value) <= maximum and
            (exact is None or len(value) == exact), "NATIVE_BYTE_ARRAY")
    for item in value:
        integer(item, maximum=255)
    return bytes(value)


def native_digest(value):
    return byte_array(value, 32, exact=32).hex()


def nonzero_native_digest(value):
    result = native_digest(value)
    require(result != "0" * 64, "NATIVE_ZERO_DIGEST")
    return result


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def native_json(value):
    """Preserve decoded native field order; never sort a signed structure."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def owner_digest(owner):
    return sha(b"hepta.cell.generation-owner-binding.v1\0" + native_json(owner))


def genesis_checkpoint(owner):
    return sha(b"hepta.cell.generation-continuity.v2\0" + b"HPTACG03" +
               bytes(owner["config_digest"]) + (0).to_bytes(8, "big") +
               bytes(32) + (40).to_bytes(8, "big"))


def partition_digest(scope):
    raw = bytearray(b"hepta.cell.state-partition.v1\0")
    for value in (native_digest(scope["principal_digest"]), scope["agent_id"],
                  scope["cell_id"], scope["run_id"]):
        encoded = value.encode("utf-8")
        raw.extend(len(encoded).to_bytes(4, "big")); raw.extend(encoded)
    return sha(raw)


def decode(raw, maximum):
    require(type(raw) is bytes and len(raw) <= maximum, "NATIVE_WIRE_LIMIT")

    def unique(pairs):
        result = {}
        for name, value in pairs:
            require(name not in result, "NATIVE_DUPLICATE_FIELD")
            result[name] = value
        return result

    def no_constant(_):
        raise ReadbackRefusal("NATIVE_NONFINITE")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=no_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReadbackRefusal("NATIVE_JSON") from error
    return value


def raw_json(text):
    require(type(text) is str, "NATIVE_JSON_STRING")
    try:
        raw = text.encode("utf-8")
    except UnicodeError as error:
        raise ReadbackRefusal("NATIVE_JSON_STRING") from error
    return raw, decode(raw, MAX_PAYLOAD)


def check_scope(scope):
    fields(scope, "principal_digest agent_id cell_id run_id", "NATIVE_SCOPE_FIELDS")
    nonzero_native_digest(scope["principal_digest"])
    for name in ("agent_id", "cell_id", "run_id"):
        stable_id(scope[name])


def check_owner(owner):
    fields(owner, OWNER_FIELDS, "NATIVE_OWNER_FIELDS")
    check_scope(owner["scope"])
    for name in OWNER_FIELDS.split():
        if name.endswith("digest") or name == "source_frontier":
            nonzero_native_digest(owner[name])
    integer(owner["generation"], minimum=1)
    integer(owner["writer_epoch"], minimum=1)


def check_manifest(raw, manifest):
    fields(manifest, MANIFEST_FIELDS, "NATIVE_MANIFEST_FIELDS")
    stable_id(manifest["profile"])
    for name in ("source_digest", "bundle_digest", "runtime_digest", "device_digest",
                 "input_schema", "state_schema", "output_schema"):
        nonzero_native_digest(manifest[name])
    components = ("encoder", "head", "memory", "world_model", "decoder")
    require(any(manifest[name] is not None for name in components), "NATIVE_MANIFEST_COMPONENT")
    for name in components:
        if manifest[name] is not None:
            nonzero_native_digest(manifest[name])
    learning = manifest["learning"]
    require(type(learning) is dict and learning.get("kind") in ("frozen", "resumable"), "NATIVE_LEARNING_KIND")
    fields(learning, "kind weights" if learning["kind"] == "frozen" else
           "kind weights optimizer rng sampler training_cursor", "NATIVE_LEARNING_FIELDS")
    for name in set(learning) - {"kind"}:
        nonzero_native_digest(learning[name])
    fields(manifest["evolution"], "structure lineage source_dependencies adoption_receipt", "NATIVE_EVOLUTION_FIELDS")
    for value in manifest["evolution"].values():
        nonzero_native_digest(value)
    for name, maximum in (("max_input_bytes", 65536), ("max_state_bytes", 65536),
                          ("max_delta_bytes", 65536), ("max_prefix_bytes", 262144),
                          ("max_step_cost_entries", 32), ("max_ack_cost_entries", 16)):
        integer(manifest[name], minimum=1, maximum=maximum)
    require(manifest["max_delta_bytes"] <= manifest["max_prefix_bytes"], "NATIVE_MANIFEST_LIMITS")
    return sha(MANIFEST_DOMAIN + raw)


def check_cost_identity(cost, task, source):
    # Cost bytes are preserved, never converted to an asserted complete price.
    # The original native owner retains full cost validation and accounting.
    fields(cost, "schema_version identity entries", "NATIVE_COST_FIELDS")
    require(type(cost["schema_version"]) is int and cost["schema_version"] == 2, "NATIVE_COST_VERSION")
    fields(cost["identity"], "task_digest source_digest", "NATIVE_COST_IDENTITY")
    require(native_digest(cost["identity"]["task_digest"]) == task and
            native_digest(cost["identity"]["source_digest"]) == source, "NATIVE_COST_BINDING")
    require(type(cost["entries"]) is list and len(cost["entries"]) <= 4096, "NATIVE_COST_LIMIT")


def check_public_grant_binding(publication):
    """Recompute public binding relations, without authenticating an issuer.

    Signature validity, issuer enrollment and current revocation remain in the
    original native authority owner. A well-formed witness is not portable use.
    """
    signed, witness, update = publication["signed"], publication["witness"], publication["intent"]
    fields(signed, "grant signature", "NATIVE_SIGNED_GRANT_FIELDS")
    byte_array(signed["signature"], 64, exact=64)
    require(sha(b"hepta.agentd.generation-update-signed-grant.v1\0" + native_json(signed)) ==
            native_digest(publication["signed_grant_digest"]), "NATIVE_SIGNED_GRANT_DIGEST")
    grant = signed["grant"]
    fields(grant, "schema_version signer_id authority_epoch grant_id nonce binding not_before_unix_ms expires_at_unix_ms",
           "NATIVE_GRANT_FIELDS")
    integer(grant["schema_version"], maximum=(1 << 32) - 1)
    require(grant["schema_version"] == 1, "NATIVE_GRANT_VERSION")
    authority_id(grant["signer_id"]); authority_id(grant["grant_id"])
    integer(grant["authority_epoch"], minimum=1); nonzero_native_digest(grant["nonce"])
    integer(grant["not_before_unix_ms"]); integer(grant["expires_at_unix_ms"])
    require(0 < grant["expires_at_unix_ms"] - grant["not_before_unix_ms"] <= 300000, "NATIVE_GRANT_WINDOW")
    binding = grant["binding"]
    fields(binding, "subject_id destination_id request_sha256 scope_sha256 payload_sha256", "NATIVE_GRANT_BINDING_FIELDS")
    authority_id(binding["subject_id"]); authority_id(binding["destination_id"])
    previous, target = update["previous"], update["target"]
    purpose = {"model_stopped": "agentd.cell-generation.replace",
               "owner_drained": "agentd.cell-generation.replace-drained",
               "owner_drained_same_model": "agentd.cell-generation.next-task-same-model"}.get(
                   update.get("completion", "model_stopped"))
    scope = previous["scope"]
    require(purpose is not None and binding["destination_id"] == purpose and
            binding["subject_id"] == scope["agent_id"], "NATIVE_GRANT_PURPOSE")
    scope_wire = native_json([scope["agent_id"], scope["cell_id"], scope["principal_digest"]])
    require(native_digest(binding["request_sha256"]) ==
            sha(b"hepta.agentd.generation-update-intent.v1\0" + native_json(update)) and
            native_digest(binding["scope_sha256"]) == sha(b"hepta.agentd.generation-current-scope.v1\0" + scope_wire) and
            native_digest(binding["payload_sha256"]) == owner_digest(target), "NATIVE_GRANT_BINDING")
    fields(witness, "schema_version authority_epoch verified_at_unix_ms boundary authority_ref", "NATIVE_WITNESS_FIELDS")
    integer(witness["schema_version"], maximum=(1 << 32) - 1)
    require(witness["schema_version"] == 1, "NATIVE_WITNESS_VERSION")
    integer(witness["authority_epoch"], minimum=1); integer(witness["verified_at_unix_ms"])
    require(witness["boundary"] == "dispatch_entry" and
            witness["authority_epoch"] == grant["authority_epoch"] and
            grant["not_before_unix_ms"] <= witness["verified_at_unix_ms"] < grant["expires_at_unix_ms"],
            "NATIVE_WITNESS_WINDOW")
    ref = witness["authority_ref"]
    fields(ref, "authority_family authority", "NATIVE_WITNESS_AUTHORITY_FIELDS")
    require(ref["authority_family"] == "final_use", "NATIVE_WITNESS_FAMILY")
    authority = ref["authority"]
    fields(authority, "signer_id grant_id revocation_revision binding_sha256", "NATIVE_WITNESS_REFERENCE_FIELDS")
    authority_id(authority["signer_id"]); authority_id(authority["grant_id"])
    integer(authority["revocation_revision"], minimum=1)
    require(authority["signer_id"] == grant["signer_id"] and authority["grant_id"] == grant["grant_id"] and
            native_digest(authority["binding_sha256"]) == sha(
                b"hepta.kernel.authority.verified-use-binding.final-use.v1\0" + native_json(binding)),
            "NATIVE_WITNESS_BINDING")
    return native_digest(grant["nonce"])


def review_native_learning_use(raw, *, expected_readback_sha256, expected):
    """Check a pinned original first-use export; never an activation decision.

    expected and the complete-byte pin must be retained independently by the
    original supervisor/qualification owner. Tests deliberately use fixture
    expectations. This function cannot establish that those pins are trusted.
    """
    hex_digest(expected_readback_sha256)
    require(type(raw) is bytes and len(raw) <= MAX_WIRE, "NATIVE_WIRE_LIMIT")
    require(sha(raw) == expected_readback_sha256, "NATIVE_READBACK_PIN")
    fields(expected, EXPECTED_FIELDS, "EXPECTED_FIELDS")
    require(expected["schema"] == EXPECTED_SCHEMA, "EXPECTED_SCHEMA")
    for name in ("learning_operation_id", "source_run_id"):
        stable_id(expected[name])
    for name in set(expected) - {"schema", "disposition", "learning_operation_id", "source_run_id",
                                  "state_cutover_receipt", "generation", "writer_epoch"}:
        hex_digest(expected[name])
    if expected["state_cutover_receipt"] is not None:
        hex_digest(expected["state_cutover_receipt"])
    for name in ("generation", "writer_epoch"):
        integer(expected[name], minimum=1)
    envelope = decode(raw, MAX_WIRE)
    fields(envelope, "schema payload_json payload_digest", "NATIVE_ENVELOPE_FIELDS")
    require(envelope["schema"] == NATIVE_SCHEMA, "NATIVE_SCHEMA")
    payload_raw, payload = raw_json(envelope["payload_json"])
    require(sha(DOMAIN + payload_raw) == native_digest(envelope["payload_digest"]), "NATIVE_PAYLOAD_DIGEST")
    fields(payload, PAYLOAD_FIELDS, "NATIVE_PAYLOAD_FIELDS")
    require(payload["authority"] == "DENY_ALL" and payload["current_permission"] == "NOT_EXPORTED",
            "NATIVE_AUTHORITY_ESCALATION")
    require(payload["disposition"] in ("retained_model", "adopted_model_reset") and
            payload["disposition"] == expected["disposition"], "NATIVE_DISPOSITION")
    for name in ("learning_operation_id", "source_run_id"):
        require(stable_id(payload[name]) == expected[name], "NATIVE_LEARNING_IDENTITY")
    for name in ("learning_head", "learning_decision_head", "source_task_receipt",
                 "source_selected_artifact", "source_selected_bundle"):
        require(native_digest(payload[name]) == expected[name], "NATIVE_LEARNING_PIN")
    observation, intent = payload["observation"], payload["intent"]
    fields(observation, OBSERVATION_FIELDS, "NATIVE_USE_FIELDS")
    fields(intent, INTENT_FIELDS, "NATIVE_INTENT_FIELDS")
    stable_id(intent["operation_id"]); integer(intent["deadline_micros"], minimum=1)
    for name in ("task_digest", "input_digest", "source_frontier"):
        require(native_digest(intent[name]) == expected[name], "NATIVE_TASK_INPUT_PIN")
    native_digest(intent["predecessor_digest"])
    require(sha(INTENT_DOMAIN + native_json(intent)) == expected["intent_digest"], "EXPECTED_INTENT_BINDING")
    for name in ("bundle_digest", "checkpoint_digest", "selection_digest",
                 "committed_step_receipt", "state_partition_digest"):
        native_digest(observation[name])
    require(native_digest(observation["checkpoint_digest"]) == expected["owner_checkpoint"] and
            native_digest(observation["committed_step_receipt"]) == expected["committed_step_receipt"] and
            native_digest(observation["state_partition_digest"]) == expected["state_partition_digest"],
            "NATIVE_USE_PIN")

    manifest_raw, manifest = raw_json(payload["manifest_json"])
    manifest_id = check_manifest(manifest_raw, manifest)
    publication_raw, publication = raw_json(payload["publication_json"])
    fields(publication, "intent witness signed signed_grant_digest", "NATIVE_PUBLICATION_FIELDS")
    native_digest(publication["signed_grant_digest"])
    require(type(publication["signed"]) is dict and type(publication["witness"]) is dict,
            "NATIVE_PUBLICATION_RECORDS")
    publication_id = sha(PUBLICATION_DOMAIN + publication_raw)
    require(publication_id == expected["publication_digest"], "NATIVE_PUBLICATION_PIN")
    update = publication["intent"]
    require(type(update) is dict, "NATIVE_UPDATE_FIELDS")
    update_fields = "operation_id supersedes previous previous_checkpoint previous_observation target genesis_checkpoint selection"
    fields(update, update_fields + (" completion" if "completion" in update else ""), "NATIVE_UPDATE_FIELDS")
    stable_id(update["operation_id"])
    for name in ("previous_checkpoint", "previous_observation", "genesis_checkpoint", "selection"):
        native_digest(update[name])
    if update["supersedes"] is not None:
        native_digest(update["supersedes"])
    previous, target = update["previous"], update["target"]
    check_owner(previous); check_owner(target)
    require(manifest_id == expected["manifest_digest"] == native_digest(target["manifest_digest"]),
            "NATIVE_MANIFEST_PIN")
    require(native_digest(previous["manifest_digest"]) == expected["previous_manifest_digest"],
            "NATIVE_PREDECESSOR_PIN")
    require(native_digest(manifest["bundle_digest"]) == native_digest(observation["bundle_digest"]),
            "NATIVE_SELECTED_BUNDLE")
    require(target["scope"]["run_id"] != previous["scope"]["run_id"] == payload["source_run_id"] and
            target["task_digest"] != previous["task_digest"], "NATIVE_NEXT_TASK_REQUIRED")
    for name in ("principal_digest", "agent_id", "cell_id"):
        require(target["scope"][name] == previous["scope"][name], "NATIVE_SCOPE_CONTINUITY")
    require(target["generation"] == previous["generation"] + 1 == expected["generation"] and
            target["writer_epoch"] == previous["writer_epoch"] + 1 == expected["writer_epoch"],
            "NATIVE_OWNER_EPOCH")
    require(native_digest(target["task_digest"]) == expected["task_digest"] and
            native_digest(target["source_frontier"]) == expected["source_frontier"] and
            update["selection"] == observation["selection_digest"], "NATIVE_PUBLICATION_BINDING")
    require(partition_digest(target["scope"]) == expected["state_partition_digest"], "NATIVE_STATE_PARTITION_DIGEST")
    require(genesis_checkpoint(target) == native_digest(update["genesis_checkpoint"]), "NATIVE_GENESIS_CHECKPOINT")
    grant_nonce = check_public_grant_binding(publication)
    retained = payload["disposition"] == "retained_model"
    operation_domain = (b"hepta.agentd.learning-retained-task-operation.v1\0" if retained else
                        b"hepta.agentd.learning-updated-task-operation.v1\0")
    operation_prefix = "learning-retained-task:" if retained else "learning-updated-task:"
    require(update["operation_id"] == operation_prefix + sha(operation_domain +
            payload["learning_operation_id"].encode("ascii") + bytes(payload["learning_decision_head"])),
            "NATIVE_LEARNING_PUBLICATION_OPERATION")
    if retained:
        require(observation["kind"] == "retained_model_next_use" and
                observation["state_cutover_receipt"] is None and expected["state_cutover_receipt"] is None and
                native_digest(observation["task_owner_publication"]) == publication_id,
                "NATIVE_RETAINED_USE_KIND")
        require(payload["previous_manifest_json"] is None and
                expected["manifest_digest"] == expected["previous_manifest_digest"] and
                native_digest(manifest["bundle_digest"]) == expected["source_selected_bundle"] and
                update.get("completion") == "owner_drained_same_model", "NATIVE_NO_UPDATE_CHANGED_MODEL")
    else:
        require(observation["kind"] == "next_use" and observation["task_owner_publication"] is None and
                native_digest(observation["state_cutover_receipt"]) == expected["state_cutover_receipt"],
                "NATIVE_ADOPTED_USE_KIND")
        old_raw, old_manifest = raw_json(payload["previous_manifest_json"])
        old_id = check_manifest(old_raw, old_manifest)
        require(old_id == expected["previous_manifest_digest"] != manifest_id and
                native_digest(old_manifest["bundle_digest"]) == expected["source_selected_bundle"] and
                old_manifest["bundle_digest"] != manifest["bundle_digest"] and
                update.get("completion", "model_stopped") in ("model_stopped", "owner_drained"),
                "NATIVE_ADOPTED_MODEL_BINDING")
        reset = sha(b"hepta.agentd.learning-published-model-reset.v1\0" +
                    update["operation_id"].encode("ascii") + bytes.fromhex(owner_digest(previous)) +
                    bytes.fromhex(owner_digest(target)) + bytes.fromhex(old_id) +
                    bytes(manifest["bundle_digest"]) + bytes(target["initial_snapshot_digest"]) +
                    bytes.fromhex(genesis_checkpoint(target)) + bytes.fromhex(publication_id))
        require(reset == expected["state_cutover_receipt"], "NATIVE_MODEL_RESET_RECEIPT")

    receipt_raw, receipt = raw_json(payload["step_receipt_json"])
    fields(receipt, "operation_id request_digest proposal_digest checkpoint_after disposition cost", "NATIVE_STEP_FIELDS")
    require(receipt["operation_id"] == intent["operation_id"] and
            receipt["disposition"] in ("advanced", "stopped"), "NATIVE_UNSUCCESSFUL_STEP")
    for name in ("request_digest", "proposal_digest", "checkpoint_after"):
        native_digest(receipt[name])
    require(sha(STEP_DOMAIN + receipt_raw) == expected["committed_step_receipt"], "NATIVE_STEP_RECEIPT_DIGEST")
    generation_raw, generation = raw_json(payload["generation_observation_json"])
    fields(generation, GENERATION_FIELDS, "NATIVE_GENERATION_FIELDS")
    snapshot = generation["snapshot"]
    fields(snapshot, SNAPSHOT_FIELDS, "NATIVE_SNAPSHOT_FIELDS"); check_scope(snapshot["scope"])
    snapshot_manifest = nonzero_native_digest(snapshot["manifest_digest"])
    for name in ("generation", "writer_epoch", "revision"):
        integer(snapshot[name], minimum=1 if name != "revision" else 0)
    require(type(snapshot["stopped"]) is bool, "NATIVE_STOPPED_TYPE")
    byte_array(snapshot["state"], manifest["max_state_bytes"])
    prefix = byte_array(snapshot["prefix"], manifest["max_prefix_bytes"])
    require(snapshot["scope"] == target["scope"] and snapshot_manifest == native_digest(target["manifest_digest"]) and
            snapshot["generation"] == target["generation"] and snapshot["writer_epoch"] == target["writer_epoch"],
            "NATIVE_OBSERVED_OWNER")
    for name in ("task_digest", "source_frontier", "initial_snapshot_digest"):
        require(native_digest(generation[name]) == native_digest(target[name]), "NATIVE_OBSERVATION_BINDING")
    require(native_digest(generation["owner_checkpoint"]) == expected["owner_checkpoint"], "NATIVE_CHECKPOINT_PIN")
    require(native_digest(generation["first_advance_input_digest"]) == expected["input_digest"],
            "NATIVE_FIRST_INPUT_PIN")
    if generation["pending_request_digest"] is not None:
        native_digest(generation["pending_request_digest"])
    pending = generation["pending_output"]
    if pending is not None:
        fields(pending, "operation_id request_digest prefix_offset bytes", "NATIVE_PENDING_FIELDS")
        stable_id(pending["operation_id"]); native_digest(pending["request_digest"])
        offset = integer(pending["prefix_offset"])
        delta = byte_array(pending["bytes"], manifest["max_delta_bytes"])
        require(offset <= len(prefix) and prefix[offset:offset + len(delta)] == delta,
                "NATIVE_PENDING_PREFIX")
    # The cost source binds the metering convention and need not equal the
    # backend source identity. Require the same original task/cost identity in
    # both retained records without inventing that stronger relationship.
    task = expected["task_digest"]
    require(type(generation["cost"]) is dict and type(generation["cost"].get("identity")) is dict,
            "NATIVE_COST_IDENTITY")
    source = native_digest(generation["cost"]["identity"].get("source_digest"))
    check_cost_identity(receipt["cost"], task, source)
    check_cost_identity(generation["cost"], task, source)
    delivery_pending = pending is not None
    work_pending = generation["pending_request_digest"] is not None
    terminal = snapshot["stopped"] and not delivery_pending and not work_pending
    return dict(schema=REPORT_SCHEMA, scope="pinned-native-first-use-materials-only",
        native_readback_sha256=expected_readback_sha256, payload_digest=native_digest(envelope["payload_digest"]),
        disposition=payload["disposition"], learning_operation_id=payload["learning_operation_id"],
        learning_head=expected["learning_head"], manifest_digest=manifest_id, bundle_digest=native_digest(manifest["bundle_digest"]),
        task_digest=task, input_digest=expected["input_digest"], owner_checkpoint=expected["owner_checkpoint"],
        publication_digest=publication_id, first_use_bindings_consistent=True,
        original_grant_nonce=grant_nonce, public_grant_bindings_consistent=True,
        cost_source_digest=source, original_intent_digest=expected["intent_digest"], request_digest_recomputed=False,
        pending_work=work_pending, pending_delivery=delivery_pending, model_stop_observed=snapshot["stopped"],
        terminal_episode_observed=terminal, committed_prefix_bytes=len(prefix), committed_prefix_sha256=sha(prefix),
        full_learning_iteration_completed=False, current_permission_exported=False,
        native_origin_authenticated=False, grant_signature_verified_by_this_reader=False,
        cost_completeness_verified=False, independent_control_accepted=False,
        real_model_training_verified=False, physical_installation_accepted=False,
        settlement_verified=False, hepta_final_use_accepted=False, production_activation=False,
        qualification="HOLD_NO_GO")


def read_bounded(path, maximum):
    # Inspect the descriptor before reading; a FIFO must not block at open().
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "INPUT_FILE_BOUND")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) <= maximum and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "INPUT_FILE_CHANGED")
        return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readback", type=Path, required=True)
    parser.add_argument("--readback-sha256", required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--learning-checkpoint", type=Path)
    parser.add_argument("--learning-checkpoint-sha256")
    parser.add_argument("--learning-freeze", type=Path)
    parser.add_argument("--learning-freeze-sha256")
    parser.add_argument("--root-profile", type=Path)
    parser.add_argument("--root-profile-sha256")
    args = parser.parse_args()
    expected_raw = read_bounded(args.expected, MAX_EXPECTED)
    require(sha(expected_raw) == hex_digest(args.expected_sha256), "EXPECTATIONS_PIN")
    readback_raw = read_bounded(args.readback, MAX_WIRE)
    expected = decode(expected_raw, MAX_EXPECTED)
    joining = (args.learning_checkpoint, args.learning_checkpoint_sha256,
               args.learning_freeze, args.learning_freeze_sha256)
    scope = (args.root_profile, args.root_profile_sha256)
    require((scope[0] is None) == (scope[1] is None), "LEARNING_ROOT_PROFILE_ARGUMENTS")
    if any(value is not None for value in (*joining, *scope)):
        require(all(value is not None for value in joining), "LEARNING_JOIN_ARGUMENTS")
        from cell_learning_iteration_join import MAX_CHECKPOINT, MAX_FREEZE, review_native_learning_iteration
        freeze_raw = read_bounded(args.learning_freeze, MAX_FREEZE)
        require(sha(freeze_raw) == hex_digest(args.learning_freeze_sha256), "LEARNING_FREEZE_PIN")
        result = review_native_learning_iteration(
            read_bounded(args.learning_checkpoint, MAX_CHECKPOINT), readback_raw,
            expected_checkpoint_sha256=args.learning_checkpoint_sha256,
            expected_readback_sha256=args.readback_sha256,
            root_profile_raw=None if args.root_profile is None else read_bounded(args.root_profile, 16384),
            expected_root_profile_sha256=args.root_profile_sha256,
            frozen=decode(freeze_raw, MAX_FREEZE), expected=expected)
    else:
        result = review_native_learning_use(readback_raw,
            expected_readback_sha256=args.readback_sha256, expected=expected)
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
