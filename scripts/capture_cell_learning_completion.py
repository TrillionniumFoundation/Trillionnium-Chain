"""Retain exact native fixture exports for completed-learning reader controls.

This collector never executes a model, signs learning receipts, or constructs a
positive checkpoint. Its expectations are explicitly fixture-derived. The
native test run and exact source must be qualified by their separate run record.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

import cell_adoption_readback as native
import cell_learning_completion_join as completion
import cell_learning_iteration_join as iteration

PHASES = ("retained_pending", "retained_acked", "adopted_pending", "adopted_acked")
ACKED = ("retained_acked", "adopted_acked")
MARKER = re.compile(rb"HEPTA_LEARNING_(READBACK_V1|CHECKPOINT_V2|COMPLETION_V1) ([a-z_]+) ")


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def checkpoint_bytes(export, completed=False):
    names = "schema initial_head checkpoint_sha256 checkpoint_base64 learning_head evaluation_profile authority current_permission production_qualification pins_are_fixture_derived"
    if completed:
        names += " selection_head readback_sha256 actual_model_execution_accepted"
    native.fields(export, names, "CAPTURE_CHECKPOINT_FIELDS")
    schema = "hepta.learning.completed-checkpoint.fixture.v1" if completed else "hepta.learning.checkpoint.fixture.v2"
    native.require(export["schema"] == schema and export["authority"] == "DENY_ALL" and
                   export["current_permission"] == "NOT_EXPORTED" and
                   export["production_qualification"] == "HOLD_NO_GO" and
                   export["pins_are_fixture_derived"] is True, "CAPTURE_FIXTURE_SCOPE")
    if completed:
        native.require(export["actual_model_execution_accepted"] is False, "CAPTURE_MODEL_SCOPE")
    encoded = export["checkpoint_base64"]
    native.require(type(encoded) is str and len(encoded) <= 2 * iteration.MAX_CHECKPOINT and
                   re.fullmatch(r"[A-Za-z0-9+/]+", encoded), "CAPTURE_BASE64")
    raw = base64.b64decode(encoded + "=" * ((-len(encoded)) % 4), validate=True)
    native.require(base64.b64encode(raw).decode().rstrip("=") == encoded and
                   native.sha(raw) == export["checkpoint_sha256"], "CAPTURE_CHECKPOINT_BYTES")
    snapshot, replay = iteration.decode_native_learning_checkpoint(raw)
    native.require(replay["initial_head"] == export["initial_head"] and
                   replay["head"] == export["learning_head"] and
                   snapshot["request"]["evaluation_profile"] == export["evaluation_profile"],
                   "CAPTURE_NATIVE_REPLAY")
    return raw, snapshot, replay


def fixture_expectations(raw):
    """Observed fixture values, never production trust or independent custody."""
    envelope = native.decode(raw, native.MAX_WIRE)
    _, payload = native.raw_json(envelope["payload_json"])
    manifest_raw, manifest = native.raw_json(payload["manifest_json"])
    publication_raw, publication = native.raw_json(payload["publication_json"])
    observation, intent = payload["observation"], payload["intent"]
    target, previous = publication["intent"]["target"], publication["intent"]["previous"]
    result = dict(schema=native.EXPECTED_SCHEMA, disposition=payload["disposition"],
                  learning_operation_id=payload["learning_operation_id"], source_run_id=payload["source_run_id"])
    for name in ("learning_head", "learning_decision_head", "source_task_receipt", "source_selected_artifact", "source_selected_bundle"):
        result[name] = native.native_digest(payload[name])
    result.update(manifest_digest=native.check_manifest(manifest_raw, manifest),
                  previous_manifest_digest=native.native_digest(previous["manifest_digest"]),
                  intent_digest=native.sha(native.INTENT_DOMAIN + native.native_json(intent)),
                  owner_checkpoint=native.native_digest(observation["checkpoint_digest"]),
                  publication_digest=native.sha(native.PUBLICATION_DOMAIN + publication_raw))
    for name in ("task_digest", "input_digest", "source_frontier"):
        result[name] = native.native_digest(intent[name])
    for name in ("committed_step_receipt", "state_partition_digest"):
        result[name] = native.native_digest(observation[name])
    cutover = observation["state_cutover_receipt"]
    result["state_cutover_receipt"] = None if cutover is None else native.native_digest(cutover)
    result.update(generation=target["generation"], writer_epoch=target["writer_epoch"])
    native.fields(result, native.EXPECTED_FIELDS, "CAPTURE_EXPECTED_FIELDS")
    return result


def capture(log_raw, native_source):
    native.require(type(log_raw) is bytes and len(log_raw) <= 64 * 1024 * 1024, "CAPTURE_LOG_BOUND")
    native.require(type(native_source) is str and re.fullmatch(r"[0-9a-f]{40}", native_source), "CAPTURE_SOURCE_REF")
    records = {}
    for match in MARKER.finditer(log_raw):
        kind, phase = (part.decode() for part in match.groups())
        key = kind, phase
        native.require(phase in PHASES and (kind != "COMPLETION_V1" or phase in ACKED) and key not in records,
                       "CAPTURE_EXPORT_ROSTER")
        end = log_raw.find(b"\n", match.end())
        native.require(end >= 0, "CAPTURE_INCOMPLETE_LINE")
        if log_raw[end - 1:end] == b"\r":
            end -= 1
        raw = log_raw[match.end():end]
        records[key] = dict(raw=raw, value=native.decode(raw, native.MAX_WIRE),
                            byte_offset=match.end(), byte_length=len(raw))
    required = {(kind, phase) for kind in ("READBACK_V1", "CHECKPOINT_V2") for phase in PHASES}
    required.update(("COMPLETION_V1", phase) for phase in ACKED)
    native.require(set(records) == required, "CAPTURE_MISSING_EXPORT")
    files = {"native.stdout": log_raw}
    manifest = dict(schema="trnm-cell-learning-completion-native-fixtures-v1",
                    scope="original-native-engineering-fixtures-not-production", native_source=native_source,
                    source_log_sha256=native.sha(log_raw), exports={}, pins_are_fixture_derived=True,
                    native_test_pass_not_inferred_from_capture=True, native_origin_authenticated=False,
                    actual_model_execution_accepted=False, production_activation=False, qualification="HOLD_NO_GO")
    for phase in PHASES:
        readback = records["READBACK_V1", phase]
        selection_export = records["CHECKPOINT_V2", phase]
        selection, snapshot, replay = checkpoint_bytes(selection_export["value"])
        expected = fixture_expectations(readback["raw"])
        frozen = dict(schema=iteration.FREEZE_SCHEMA, initial_head=replay["initial_head"],
                      request=copy.deepcopy(snapshot["request"]), owners=copy.deepcopy(snapshot["owners"]))
        review = iteration.review_native_learning_iteration(selection, readback["raw"],
            expected_checkpoint_sha256=native.sha(selection), expected_readback_sha256=native.sha(readback["raw"]),
            frozen=frozen, expected=expected)
        items = {".json": readback["raw"], ".selection.bin": selection,
                 ".selection-export.json": selection_export["raw"], ".expected.json": json_bytes(expected),
                 ".freeze.json": json_bytes(frozen), ".review.json": json_bytes(review)}
        if phase in ACKED:
            final_export = records["COMPLETION_V1", phase]
            final, _, _ = checkpoint_bytes(final_export["value"], completed=True)
            native.require(final_export["value"]["selection_head"] == replay["head"] and
                           final_export["value"]["readback_sha256"] == native.sha(readback["raw"]), "CAPTURE_COMPLETION_PAIR")
            final_review = completion.review_native_learning_completion(selection, final, readback["raw"],
                expected_selection_sha256=native.sha(selection), expected_completed_sha256=native.sha(final),
                expected_readback_sha256=native.sha(readback["raw"]), frozen=frozen, expected=expected)
            items.update({".completed.bin": final, ".completed-export.json": final_export["raw"],
                          ".completed-review.json": json_bytes(final_review)})
        files.update({phase + suffix: raw for suffix, raw in items.items()})
        manifest["exports"][phase] = dict(files={phase + suffix: native.sha(raw) for suffix, raw in items.items()},
            captures={kind: {key: record[key] for key in ("byte_offset", "byte_length")}
                      for (kind, name), record in records.items() if name == phase})
    files["fixture-manifest.json"] = json_bytes(manifest)
    return files, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--native-source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    native.require(not os.path.lexists(args.output), "CAPTURE_OUTPUT_EXISTS")
    files, manifest = capture(native.read_bounded(args.log, 64 * 1024 * 1024), args.native_source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".learning-completion-", dir=args.output.parent))
    try:
        for name, raw in files.items():
            (temporary / name).write_bytes(raw)
            native.require((temporary / name).read_bytes() == raw, "CAPTURE_WRITE_READBACK")
        os.rename(temporary, args.output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print(json.dumps(dict(output=str(args.output), files=len(files),
                         manifest_sha256=native.sha(files["fixture-manifest.json"]),
                         native_source=manifest["native_source"], qualification="HOLD_NO_GO"), sort_keys=True))


if __name__ == "__main__":
    main()
