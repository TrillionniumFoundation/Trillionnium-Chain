"""Retain exact native HEPLCP04 local-choice and completed-use stdout slices.

All positive checkpoints and use exports must already exist in the original
native actor output. This collector decodes their bytes and derives explicitly
fixture-only expectations; it never creates checkpoints, signs receipts, or
infers native test success. Source execution has a separate retained run record.
"""
import argparse
import base64
import os
from pathlib import Path
import re
import shutil
import tempfile

import cell_adoption_readback as native
import cell_learning_iteration_join as legacy
import cell_learning_local_decision_join as local
import cell_learning_local_use_join as joined
from capture_cell_learning_completion import fixture_expectations, json_bytes

PHASES = ("local_defer_cold", "local_retain_cold", "local_adopt")
CHOICES = dict(zip(PHASES, ("defer_candidate", "retain_parent", "adopt_candidate")))
LEGACY_PHASES = ("retained_pending", "retained_acked", "adopted_pending", "adopted_acked")
KINDS = ("INITIAL_V1", "READBACK_V1", "CHECKPOINT_V2", "COMPLETION_V1")
SUFFIXES = {"INITIAL_V1": ".initial-export.json", "READBACK_V1": ".json",
            "CHECKPOINT_V2": ".selection-export.json", "COMPLETION_V1": ".completed-export.json"}
MARKER = re.compile(rb"HEPTA_LEARNING_(INITIAL_V1|READBACK_V1|CHECKPOINT_V2|COMPLETION_V1) ([a-z_]+) ")
MANIFEST_SCHEMA = "trnm-cell-learning-local-use-native-fixtures-v1"
MAX_LOG = 64 * 1024 * 1024


def checkpoint_bytes(export, kind):
    """Decode an original fixture export; there is no positive encoder here."""
    native.require(kind in ("INITIAL_V1", "CHECKPOINT_V2", "COMPLETION_V1"), "LOCAL_CAPTURE_KIND")
    names = "schema initial_head checkpoint_sha256 checkpoint_base64 authority current_permission production_qualification pins_are_fixture_derived"
    if kind != "INITIAL_V1":
        names += " learning_head evaluation_profile"
    if kind == "COMPLETION_V1":
        names += " selection_head readback_sha256 actual_model_execution_accepted"
    native.fields(export, names, "LOCAL_CAPTURE_CHECKPOINT_FIELDS")
    schema = {"INITIAL_V1": "hepta.learning.initial-checkpoint.fixture.v1",
              "CHECKPOINT_V2": "hepta.learning.checkpoint.fixture.v2",
              "COMPLETION_V1": "hepta.learning.completed-checkpoint.fixture.v1"}[kind]
    native.require(export["schema"] == schema and export["authority"] == "DENY_ALL" and
                   export["current_permission"] == "NOT_EXPORTED" and
                   export["production_qualification"] == "HOLD_NO_GO" and
                   export["pins_are_fixture_derived"] is True, "LOCAL_CAPTURE_FIXTURE_SCOPE")
    if kind == "COMPLETION_V1":
        native.require(export["actual_model_execution_accepted"] is False, "LOCAL_CAPTURE_MODEL_SCOPE")
    encoded = export["checkpoint_base64"]
    native.require(type(encoded) is str and len(encoded) <= 2 * legacy.MAX_CHECKPOINT and
                   len(encoded) % 4 != 1 and re.fullmatch(r"[A-Za-z0-9+/]+", encoded),
                   "LOCAL_CAPTURE_BASE64")
    raw = base64.b64decode(encoded + "=" * ((-len(encoded)) % 4), validate=True)
    native.require(base64.b64encode(raw).decode().rstrip("=") == encoded and
                   native.sha(raw) == native.hex_digest(export["checkpoint_sha256"]),
                   "LOCAL_CAPTURE_CHECKPOINT_BYTES")
    if kind == "INITIAL_V1":
        snapshot, replay = legacy.decode_native_learning_checkpoint(raw)
        native.require(not snapshot["receipts"] and replay["head"] == replay["initial_head"],
                       "LOCAL_CAPTURE_INITIAL")
    else:
        snapshot, replay = local.decode_native_local_checkpoint(raw)
        native.require(replay["head"] == native.hex_digest(export["learning_head"]) and
                       snapshot["request"]["evaluation_profile"] == native.hex_digest(export["evaluation_profile"]),
                       "LOCAL_CAPTURE_NATIVE_REPLAY")
        native.require((len(snapshot["receipts"]), replay["next_stage"]) ==
                       ((7, 6) if kind == "CHECKPOINT_V2" else (8, None)), "LOCAL_CAPTURE_CUT")
    native.require(replay["initial_head"] == native.hex_digest(export["initial_head"]),
                   "LOCAL_CAPTURE_INITIAL_HEAD")
    return raw, snapshot, replay


def capture(log_raw, native_source):
    native.require(type(log_raw) is bytes and len(log_raw) <= MAX_LOG, "LOCAL_CAPTURE_LOG_BOUND")
    native.require(type(native_source) is str and re.fullmatch(r"[0-9a-f]{40}", native_source),
                   "LOCAL_CAPTURE_SOURCE_REF")
    records = {}
    for match in MARKER.finditer(log_raw):
        kind, phase = (part.decode() for part in match.groups())
        key = kind, phase
        native.require(phase in PHASES + LEGACY_PHASES and key not in records, "LOCAL_CAPTURE_EXPORT_ROSTER")
        end = log_raw.find(b"\n", match.end())
        native.require(end >= 0, "LOCAL_CAPTURE_INCOMPLETE_LINE")
        if log_raw[end - 1:end] == b"\r":
            end -= 1
        raw = log_raw[match.end():end]
        records[key] = dict(raw=raw, value=native.decode(raw, native.MAX_WIRE),
                            byte_offset=match.end(), byte_length=len(raw), sha256=native.sha(raw))
    required = {(kind, phase) for kind in KINDS for phase in PHASES}
    native.require({key for key in records if key[1] in PHASES} == required, "LOCAL_CAPTURE_MISSING_EXPORT")
    files = {"native.stdout": log_raw}
    manifest = dict(schema=MANIFEST_SCHEMA, scope="original-native-engineering-fixtures-not-production",
                    native_source=native_source, source_log_sha256=native.sha(log_raw), exports={},
                    excluded_exports=[], pins_are_fixture_derived=True,
                    native_test_pass_not_inferred_from_capture=True, native_origin_authenticated=False,
                    pre_dispatch_freeze_authenticated=False, root_scope_authenticated=False,
                    output_ack_event_verified=False,
                    actual_model_execution_accepted=False, hepta_final_use_accepted=False,
                    production_activation=False, authority="DENY_ALL", current_permission="NOT_EXPORTED",
                    qualification="HOLD_NO_GO")
    for (kind, phase), record in records.items():
        if phase in LEGACY_PHASES:
            manifest["excluded_exports"].append(dict(kind=kind, phase=phase,
                scope="legacy-profile-not-a-local-decision-positive", **{
                    key: record[key] for key in ("byte_offset", "byte_length", "sha256")}))
    for phase in PHASES:
        initial_export, readback, selection_export, final_export = (records[kind, phase] for kind in KINDS)
        initial, _, _ = checkpoint_bytes(initial_export["value"], "INITIAL_V1")
        selection, _, before = checkpoint_bytes(selection_export["value"], "CHECKPOINT_V2")
        completed, _, _ = checkpoint_bytes(final_export["value"], "COMPLETION_V1")
        native.require(final_export["value"]["selection_head"] == before["head"] and
                       final_export["value"]["readback_sha256"] == native.sha(readback["raw"]),
                       "LOCAL_CAPTURE_COMPLETION_PAIR")
        frozen = legacy.frozen_expectations_from_initial_checkpoint(initial)
        expected = fixture_expectations(readback["raw"])
        review = joined.review_native_local_learning_completion(selection, completed, readback["raw"],
            expected_selection_sha256=native.sha(selection), expected_completed_sha256=native.sha(completed),
            expected_readback_sha256=native.sha(readback["raw"]), frozen=frozen, expected=expected)
        native.require(review["local_disposition"] == CHOICES[phase], "LOCAL_CAPTURE_PHASE_CHOICE")
        items = {".json": readback["raw"], ".initial.bin": initial,
                 ".initial-export.json": initial_export["raw"], ".selection.bin": selection,
                 ".selection-export.json": selection_export["raw"], ".completed.bin": completed,
                 ".completed-export.json": final_export["raw"], ".freeze.json": json_bytes(frozen),
                 ".expected.json": json_bytes(expected), ".review.json": json_bytes(review)}
        files.update({phase + suffix: raw for suffix, raw in items.items()})
        manifest["exports"][phase] = dict(local_disposition=CHOICES[phase],
            files={phase + suffix: native.sha(raw) for suffix, raw in items.items()},
            captures={kind: {key: records[kind, phase][key] for key in ("byte_offset", "byte_length", "sha256")}
                      for kind in KINDS})
    files["fixture-manifest.json"] = json_bytes(manifest)
    return files, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--native-source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    native.require(not os.path.lexists(args.output), "LOCAL_CAPTURE_OUTPUT_EXISTS")
    files, manifest = capture(native.read_bounded(args.log, MAX_LOG), args.native_source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".learning-local-use-", dir=args.output.parent))
    try:
        for name, raw in files.items():
            (temporary / name).write_bytes(raw)
            native.require((temporary / name).read_bytes() == raw, "LOCAL_CAPTURE_WRITE_READBACK")
        os.rename(temporary, args.output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print(json_bytes(dict(output=str(args.output), files=len(files),
        manifest_sha256=native.sha(files["fixture-manifest.json"]), native_source=manifest["native_source"],
        authority="DENY_ALL", current_permission="NOT_EXPORTED", qualification="HOLD_NO_GO")).decode(), end="")


if __name__ == "__main__":
    main()
