#!/usr/bin/env python3
"""Capture exact paired Rust fixture exports; never rebuild native positives."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

PHASES = ("retained_pending", "retained_acked", "adopted_pending", "adopted_acked")
MARKER = re.compile(rb"HEPTA_LEARNING_(READBACK_V1|CHECKPOINT_V2) ([a-z_]+) ")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()

def expectation(native, readback):
    outer = native.decode(readback, native.MAX_WIRE)
    _, payload = native.raw_json(outer["payload_json"])
    manifest_raw, manifest = native.raw_json(payload["manifest_json"])
    publication_raw, publication = native.raw_json(payload["publication_json"])
    observation, intent = payload["observation"], payload["intent"]
    target, previous = publication["intent"]["target"], publication["intent"]["previous"]
    value = dict(schema=native.EXPECTED_SCHEMA, disposition=payload["disposition"],
        learning_operation_id=payload["learning_operation_id"], source_run_id=payload["source_run_id"])
    for name in ("learning_head", "learning_decision_head", "source_task_receipt", "source_selected_artifact", "source_selected_bundle"):
        value[name] = native.native_digest(payload[name])
    value["manifest_digest"] = native.check_manifest(manifest_raw, manifest)
    value["previous_manifest_digest"] = native.native_digest(previous["manifest_digest"])
    for name in ("task_digest", "input_digest", "source_frontier"):
        value[name] = native.native_digest(intent[name])
    value["intent_digest"] = native.sha(native.INTENT_DOMAIN + native.native_json(intent))
    value["owner_checkpoint"] = native.native_digest(observation["checkpoint_digest"])
    value["publication_digest"] = native.sha(native.PUBLICATION_DOMAIN + publication_raw)
    for name in ("committed_step_receipt", "state_partition_digest"):
        value[name] = native.native_digest(observation[name])
    value["state_cutover_receipt"] = None if observation["state_cutover_receipt"] is None else native.native_digest(observation["state_cutover_receipt"])
    for name in ("generation", "writer_epoch"):
        value[name] = target[name]
    native.fields(value, native.EXPECTED_FIELDS, "CAPTURE_EXPECTED_FIELDS")
    return value

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chain-scripts", type=Path, required=True)
    parser.add_argument("--hepta-source", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.hepta_source), "exact native Git source is required")
    require(not args.output.exists(), "capture output exists; preserve it and choose a new destination")
    sys.path.insert(0, str(args.chain_scripts.resolve()))
    import cell_adoption_readback as native
    import cell_learning_iteration_join as join
    sources, records, blobs = [], {}, {}
    for index, path in enumerate(args.log):
        raw = native.read_bounded(path, 64 * 1024 * 1024)
        stored_name = f"source-{index + 1:02d}.stdout"
        sources.append(dict(file=stored_name, sha256=sha(raw), bytes=len(raw)))
        blobs[stored_name] = raw
        for match in MARKER.finditer(raw):
            kind, phase = match.group(1).decode(), match.group(2).decode()
            require(phase in PHASES, "unexpected fixture phase " + phase)
            key = (kind, phase)
            require(key not in records, "duplicate original native export " + str(key))
            end = raw.find(b"\n", match.end())
            if end < 0:
                end = len(raw)
            record_raw = raw[match.end():end]
            if record_raw.endswith(b"\r"):
                record_raw = record_raw[:-1]; end -= 1
            records[key] = dict(raw=record_raw, value=native.decode(record_raw, native.MAX_WIRE),
                source_log=stored_name, byte_offset=match.end(), byte_length=end - match.end())
    require(set(records) == {(kind, phase) for kind in ("READBACK_V1", "CHECKPOINT_V2") for phase in PHASES},
            "missing original paired native fixture exports")
    manifest = dict(schema="trnm-cell-learning-native-fixtures-v2",
        scope="original-native-engineering-fixtures-not-production", pins_are_fixture_derived=True,
        native_source=args.hepta_source, source_logs=sources, exports={},
        native_test_pass_not_inferred_from_capture=True, actual_model_execution_accepted=False,
        independent_freeze_custody_accepted=False, production_activation=False, qualification="HOLD_NO_GO")
    for phase in PHASES:
        use = records[("READBACK_V1", phase)]
        checkpoint_export = records[("CHECKPOINT_V2", phase)]
        exported = checkpoint_export["value"]
        native.fields(exported, "schema initial_head checkpoint_sha256 checkpoint_base64 learning_head evaluation_profile authority current_permission production_qualification pins_are_fixture_derived", "CAPTURE_CHECKPOINT_FIELDS")
        require(exported["schema"] == "hepta.learning.checkpoint.fixture.v2" and exported["authority"] == "DENY_ALL"
                and exported["current_permission"] == "NOT_EXPORTED" and exported["production_qualification"] == "HOLD_NO_GO"
                and exported["pins_are_fixture_derived"] is True, "native fixture scope changed")
        encoded = exported["checkpoint_base64"]
        require(type(encoded) is str and len(encoded) <= 2 * join.MAX_CHECKPOINT
                and re.fullmatch(r"[A-Za-z0-9+/]+", encoded), "noncanonical fixture base64")
        checkpoint = base64.b64decode(encoded + "=" * ((-len(encoded)) % 4), validate=True)
        require(base64.b64encode(checkpoint).decode().rstrip("=") == encoded, "base64 pad-bit alias")
        require(sha(checkpoint) == exported["checkpoint_sha256"], "native checkpoint checksum mismatch")
        snapshot, replay = join.decode_native_learning_checkpoint(checkpoint)
        require(replay["initial_head"] == exported["initial_head"] and replay["head"] == exported["learning_head"],
                "independent reader differs from original native checkpoint domains")
        require(snapshot["request"]["evaluation_profile"] == exported["evaluation_profile"], "native evaluation profile mismatch")
        expected = expectation(native, use["raw"])
        require(expected["learning_head"] == exported["learning_head"], "native actor/checkpoint mismatch")
        frozen = dict(schema=join.FREEZE_SCHEMA, initial_head=exported["initial_head"],
            request=copy.deepcopy(snapshot["request"]), owners=copy.deepcopy(snapshot["owners"]))
        reviewed = join.review_native_learning_iteration(checkpoint, use["raw"],
            expected_checkpoint_sha256=sha(checkpoint), expected_readback_sha256=sha(use["raw"]), frozen=frozen, expected=expected)
        expected_raw, frozen_raw = json_bytes(expected), json_bytes(frozen)
        blobs[phase + ".json"] = use["raw"]
        blobs[phase + ".checkpoint.bin"] = checkpoint
        blobs[phase + ".checkpoint-export.json"] = checkpoint_export["raw"]
        blobs[phase + ".expected.json"] = expected_raw
        blobs[phase + ".freeze.json"] = frozen_raw
        blobs[phase + ".review.json"] = json_bytes(reviewed)
        manifest["exports"][phase] = dict(
            sha256=sha(use["raw"]), bytes=len(use["raw"]), checkpoint_sha256=sha(checkpoint), checkpoint_bytes=len(checkpoint),
            fixture_expected_sha256=sha(expected_raw), fixture_freeze_sha256=sha(frozen_raw),
            native_initial_head=exported["initial_head"], native_learning_head=exported["learning_head"],
            native_evaluation_profile=exported["evaluation_profile"],
            readback_capture={k: use[k] for k in ("source_log", "byte_offset", "byte_length")},
            checkpoint_capture={k: checkpoint_export[k] for k in ("source_log", "byte_offset", "byte_length")},
            checkpoint_export_sha256=sha(checkpoint_export["raw"]))
    blobs["fixture-manifest.json"] = json_bytes(manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".native-fixture-capture-", dir=args.output.parent))
    try:
        for name, raw in blobs.items():
            path = temporary / name
            path.write_bytes(raw)
            require(path.read_bytes() == raw, "fixture write readback changed")
        os.rename(temporary, args.output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    print(json.dumps(dict(output=str(args.output.resolve()), phases=list(PHASES),
        source_logs=sources, native_test_pass_not_inferred_from_capture=True,
        files=len(blobs), manifest_sha256=sha(blobs["fixture-manifest.json"])), sort_keys=True))

if __name__ == "__main__":
    main()
