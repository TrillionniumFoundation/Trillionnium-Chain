"""Join an original scoped Root profile to the completed-learning reader.

The Root profile is a separate original input: HEPLCP02 alone does not encode
FrozenLearningScopeV2. This read-only review checks the same component and rule
restrictions, without authenticating Root custody or granting FinalUse.

The accepted Root JSON layout is pinned to hepta-private-ci commit
71738345326b98d88b738250d2b84ecbcb466eb8. Its nested scope descriptor uses
update_scope; the earlier b8e8c6e layout and mixed layouts are refused.
"""
import argparse
import base64
import binascii
import json
from pathlib import Path

import cell_adoption_readback as native
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration

REPORT_SCHEMA = "trnm-cell-learning-scoped-completed-use-review-v1"
SCOPE_DOMAIN = b"hepta.learning.frozen-update-scope.v2\0"
MAX_PROFILE = 16384


def _review_scope(profile_raw, expected_profile_sha256, snapshot, replay, frozen):
    """Inputs other than the profile were validated by the completion reader."""
    native.require(type(profile_raw) is bytes and len(profile_raw) <= MAX_PROFILE,
                   "LEARNING_ROOT_PROFILE_LIMIT")
    native.require(native.sha(profile_raw) == native.hex_digest(expected_profile_sha256),
                   "LEARNING_ROOT_PROFILE_PIN")
    profile = native.decode(profile_raw, MAX_PROFILE)
    native.fields(profile, "schema_version identity_digest writer_proof_digest initial_snapshot update_scope",
                  "LEARNING_ROOT_PROFILE_FIELDS")
    native.require(type(profile["schema_version"]) is int and profile["schema_version"] == 2,
                   "LEARNING_ROOT_SCOPE_VERSION")
    for field in ("identity_digest", "writer_proof_digest"):
        native.require(native.hex_digest(profile[field]) != "0" * 64,
                       "LEARNING_ROOT_PROFILE_ZERO_PIN")
    encoded = profile["initial_snapshot"]
    native.require(type(encoded) is str and 0 < len(encoded) <= (iteration.MAX_CHECKPOINT + 2) // 3 * 4,
                   "LEARNING_ROOT_INITIAL_LIMIT")
    try:
        initial_raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (ValueError, binascii.Error) as error:
        raise native.ReadbackRefusal("LEARNING_ROOT_INITIAL_BASE64") from error
    native.require(base64.b64encode(initial_raw).decode("ascii").rstrip("=") == encoded,
                   "LEARNING_ROOT_INITIAL_BASE64")
    original = iteration.frozen_expectations_from_initial_checkpoint(initial_raw)
    native.require(original == frozen and replay["initial_head"] == original["initial_head"] and
                   snapshot["request"] == original["request"] and snapshot["owners"] == original["owners"],
                   "LEARNING_ROOT_ORIGINAL_ITERATION")
    description = profile["update_scope"]
    native.fields(description, "update_scope update_rule binding", "LEARNING_ROOT_SCOPE_FIELDS")
    scope = description["update_scope"]
    native.require(type(scope) is str and scope in ("cell", "organ"), "LEARNING_ROOT_SCOPE_KIND")
    rule = native.hex_digest(description["update_rule"])
    native.require(rule != "0" * 64, "LEARNING_ROOT_SCOPE_RULE")
    binding = native.sha(SCOPE_DOMAIN + bytes.fromhex(original["initial_head"]) +
                         bytes([1 if scope == "cell" else 2]) + bytes.fromhex(rule))
    native.require(binding == native.hex_digest(description["binding"]), "LEARNING_ROOT_SCOPE_BINDING")
    allowed = {"heads", "calibration", "composition", scope + "_adapter"}
    incumbent = original["request"]["selected_bundle"]["components"]
    training = [receipt["observation"]["candidate"] for receipt in snapshot["receipts"]
                if receipt["observation"]["tag"] == 2]
    # A later NoUpdate does not remove the original Training obligation.
    for candidate in training:
        components = candidate["components"]
        native.require(set(components) == set(incumbent) and
                       all(components[name] == incumbent[name] for name in incumbent if name not in allowed),
                       "LEARNING_ROOT_SCOPE_COMPONENTS")
        native.require(candidate["training_lineage"]["update_rule"] == rule, "LEARNING_ROOT_SCOPE_RULE")
    return dict(root_profile_sha256=expected_profile_sha256,
                initial_checkpoint_sha256=native.sha(initial_raw), initial_head=original["initial_head"],
                operation_id=original["request"]["operation_id"], identity_digest=profile["identity_digest"],
                writer_proof_digest=profile["writer_proof_digest"], update_scope=scope,
                update_rule=rule, scope_binding=binding, training_receipts_checked=len(training),
                allowed_changed_components=sorted(allowed), frozen_scope_bindings_consistent=True,
                all_recorded_training_observations_within_scope=True,
                root_profile_origin_authenticated=False, tensor_update_mask_verified=False)


def review_native_scoped_learning_completion(
        selection_raw, completed_raw, readback_raw, root_profile_raw, *, expected_root_profile_sha256,
        expected_selection_sha256, expected_completed_sha256, expected_readback_sha256, frozen, expected):
    """Require the existing complete operation/use join and its original scope.

    The independently pinned profile must be retained at original admission.
    Supplying a self-consistent profile afterward proves no historical custody.
    Every authority, signature, installation and settlement limitation from the
    original completion reader is retained unchanged.
    """
    result = completion.review_native_learning_completion(
        selection_raw, completed_raw, readback_raw,
        expected_selection_sha256=expected_selection_sha256,
        expected_completed_sha256=expected_completed_sha256,
        expected_readback_sha256=expected_readback_sha256, frozen=frozen, expected=expected)
    snapshot, replay = iteration.decode_native_learning_checkpoint(completed_raw)
    scope_review = _review_scope(root_profile_raw, expected_root_profile_sha256, snapshot, replay, frozen)
    result.update(schema=REPORT_SCHEMA, scope="pinned-scoped-root-profile-completed-receipt-chain-and-acknowledged-use-only",
                  root_scope_review=scope_review)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("selection-checkpoint", "completed-checkpoint", "readback", "freeze", "expected", "root-profile"):
        parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    args = parser.parse_args()
    frozen_raw = native.read_bounded(args.freeze, iteration.MAX_FREEZE)
    expected_raw = native.read_bounded(args.expected, native.MAX_EXPECTED)
    native.require(native.sha(frozen_raw) == native.hex_digest(args.freeze_sha256), "LEARNING_FREEZE_PIN")
    native.require(native.sha(expected_raw) == native.hex_digest(args.expected_sha256), "EXPECTATIONS_PIN")
    result = review_native_scoped_learning_completion(
        native.read_bounded(args.selection_checkpoint, iteration.MAX_CHECKPOINT),
        native.read_bounded(args.completed_checkpoint, iteration.MAX_CHECKPOINT),
        native.read_bounded(args.readback, native.MAX_WIRE), native.read_bounded(args.root_profile, MAX_PROFILE),
        expected_root_profile_sha256=args.root_profile_sha256,
        expected_selection_sha256=args.selection_checkpoint_sha256,
        expected_completed_sha256=args.completed_checkpoint_sha256,
        expected_readback_sha256=args.readback_sha256,
        frozen=native.decode(frozen_raw, iteration.MAX_FREEZE), expected=native.decode(expected_raw, native.MAX_EXPECTED))
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
