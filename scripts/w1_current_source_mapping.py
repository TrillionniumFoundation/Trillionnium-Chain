#!/usr/bin/env python3
"""Map reviewed current source to retained W1 metadata without rewriting history.

The original implementation/lifetime owners still reject the composed source.
This separate namespace first reproduces those exact refusals, then reconstructs
the fixed artifact/control/FRI bindings with their unchanged, hash-pinned readers.
No historical owner, pin, test roster or report is replaced or made successful.
This is selected-source observation, not fresh cryptographic verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
OBSERVER_PATH = "scripts/w1_current_source_observation.py"
OBSERVER_SHA256 = "2860dc4d16c642cc57e94964e1e5c23fda5cc71d52ea1d83f6cf1ef87c323567"
PROFILE_PATH = "config/pon/w1-qrom-current-source-observation-v1.json"
MAPPER_PATH = "scripts/w1_current_source_mapping.py"
REVIEWED_COMMIT = "e798d7125724d4b9f98c24d00cc80031f2eab4a9"
SCHEMA = "TRNM-W1-QROM-CURRENT-SOURCE-MAPPING1"


class MappingError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise MappingError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(root, relative, maximum):
    """Bound the bootstrap read before executing the pinned observer helper."""
    path = root
    require(not root.is_symlink() and root.is_dir(), "mapping root directory")
    parts = Path(relative).parts
    require(parts and not Path(relative).is_absolute()
            and all(part not in (".", "..") for part in parts), "mapping input path")
    for part in parts[:-1]:
        path = path / part
        require(stat.S_ISDIR(path.lstat().st_mode), "mapping ancestor directory")
    path = root / relative
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum,
                "mapping input type or bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) == identity(path.lstat())
                and len(raw) == before.st_size, "mapping input changed during read")
        return raw
    finally:
        os.close(descriptor)


def observer_module(root):
    raw = regular_bytes(root, OBSERVER_PATH, 65536)
    require(sha(raw) == OBSERVER_SHA256, "unreviewed current source observer")
    observer = ModuleType("trnm_current_mapping_original_observer")
    observer.__file__ = str(root / OBSERVER_PATH)
    exec(compile(raw, observer.__file__, "exec"), observer.__dict__)
    return observer, raw


def pinned_files(root, records):
    """Read fixed artifacts nonblocking, with type, identity, size and hash checks."""
    output = {}
    for record in records:
        path = record["path"]
        require(path not in output and type(record["bytes"]) is int
                and 0 < record["bytes"] <= 2 * 1024 * 1024, "pinned input inventory")
        raw = regular_bytes(root, path, record["bytes"])
        require(len(raw) == record["bytes"] and sha(raw) == record["sha256"],
                "pinned mapping input drift: " + path)
        output[path] = raw
    return output


def source_delta_review(inputs, profile):
    """Descriptions apply only to the exact current bytes already checked."""
    records = (
        ("formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs",
         ("fn native_once(", "W1_V2_NATIVE_HEADER_REJECT",
          "profile::verify_image(receipt, image::IMAGE_ID)"),
         "Adds a separately selected one-replay native comparator with independent header and artifact checks; receipt verification still selects the compiled image."),
        ("trillionnium/crates/trnm-protocol/src/pon_wire.rs",
         ("FundedServiceReservationV1::decode(p)?;", "FundedServiceDecisionV1::decode(p)?;"),
         "The reservation/decision payload dispatcher now also decodes funded-service forms. This selected file does not close their transitive or authority semantics."),
        ("trillionnium/crates/trnm-pon-node/src/store.rs",
         ("verify_with_rejection_cache_observed", "node.check_packet_observation_recovery()?;",
          ".checked_add(consensus::required_work(h.target)?)"),
         "Composed native storage adds observation, admission/readback and task owners while retaining target-derived cumulative work. No equivalence or complete reachable-path claim is inferred from anchors."),
    )
    require(sorted(path for path, _, _ in records) == profile["changed_paths"],
            "reviewed current difference set")
    result = []
    for path, anchors, review in records:
        text = inputs[path].decode("utf-8")
        require(all(anchor in text for anchor in anchors), "reviewed source anchor: " + path)
        result.append({"path": path, "sha256": sha(inputs[path]),
                       "review": review, "complete_semantic_equivalence_established": False})
    return result


def build_report(root):
    observer, observer_raw = observer_module(root)
    profile_raw = regular_bytes(root, PROFILE_PATH, 65536)
    profile = observer.checked_profile(profile_raw)
    current_before = observer.selected_inputs(root, profile)
    # These exact old failures are required and never counted as old-roster passes.
    original_observation = observer.observe_selected_sources(root, profile_raw)
    implementation_path = "scripts/w1_qrom_implementation_audit.py"
    implementation = observer.original_module(
        root, implementation_path, current_before[implementation_path],
        "trnm_current_mapping_original_implementation")
    ledger_path = "scripts/w1_lifetime_ledger.py"
    ledger = observer.original_module(root, ledger_path, current_before[ledger_path],
                                      "trnm_current_mapping_original_ledger")
    contract, _ = implementation.load_contract(root)
    # The historical artifact, upstream snapshot and pure helper pins stay exact.
    helpers = pinned_files(root, contract["audit_helpers"])
    asset_records = contract["saved_v2_files"] + [contract["upstream_snapshot"]]
    assets_before = pinned_files(root, asset_records)
    sources, upstream_records = implementation.load_snapshot(
        assets_before[contract["upstream_snapshot"]["path"]], contract["upstream_commit"])
    control_path = "scripts/w1_control_tree_audit.py"
    control = implementation.checked_helper(root, control_path, helpers[control_path])
    control_tree = control.audit_sources(sources)
    require(control_tree["root"] == implementation.CONTROL_ROOT
            and control_tree["matches_fixed_root"] is True, "reconstructed control root")
    saved = implementation.inspect_v2(assets_before, control_tree["final_join"]["merkle_path"])
    profile_helper_path = "scripts/w1_profile_source_map.py"
    profile_helper = implementation.checked_helper(root, profile_helper_path,
                                                   helpers[profile_helper_path])
    stark = profile_helper.extract_stark_parameters(sources["risc0/zkp/src/lib.rs"])
    fri_path = "scripts/w1_fri_transcript_audit.py"
    fri = implementation.checked_helper(root, fri_path, helpers[fri_path])
    transcript = fri.audit_sources(sources, assets_before[implementation.FIXTURE + "succinct.bin"])

    image_path = "formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs"
    declarations = re.findall(r"IMAGE_ID: \[u32; 8\] = \[([^]]+)\]", current_before[image_path].decode())
    require(len(declarations) == 1 and tuple(int(x.strip()) for x in declarations[0].split(",")
            if x.strip()) == implementation.IMAGE, "current compiled image words")
    profile_text = current_before["formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs"].decode()
    require(f'PARAMETERS: &str = "{implementation.PARAMETERS}"' in profile_text
            and f'CONTROL_ID: &str = "{implementation.JOIN}"' in profile_text,
            "current verifier profile constants")
    def protocol(path, name):
        values = re.findall(name + r': ProtocolInfo = ProtocolInfo\(\*b"([^\"]+)"\)', sources[path])
        require(len(values) == 1, "unique protocol declaration: " + name)
        return values[0]
    parameters = implementation.parameter_digest(
        implementation.CONTROL_ROOT, protocol("risc0/zkp/src/adapter.rs", "PROOF_SYSTEM_INFO"),
        protocol("risc0/circuit/recursion/src/info.rs", "CIRCUIT_INFO"))
    require(parameters == implementation.PARAMETERS, "independent parameter digest")
    review = source_delta_review(current_before, profile)
    # Only the original pure arithmetic evaluator is used, never a rebased source_survey.
    unknown_ledger = ledger.serializable(ledger.evaluate(ledger.template()))
    require(unknown_ledger["sum_of_group_adversary_query_envelopes"] is None
            and unknown_ledger["conditional_union"]["project_total_error_upper"] is None,
            "unknown lifetime arithmetic unexpectedly became a security bound")
    current_after = observer.selected_inputs(root, profile)
    assets_after = pinned_files(root, asset_records)
    require(current_before == current_after and assets_before == assets_after,
            "mapping inputs changed during reconstruction")
    require(regular_bytes(root, OBSERVER_PATH, 65536) == observer_raw
            and regular_bytes(root, PROFILE_PATH, 65536) == profile_raw,
            "mapping observation helpers changed")
    inputs = dict(current_before) | assets_before | {OBSERVER_PATH: observer_raw, PROFILE_PATH: profile_raw}
    return {
        "schema": SCHEMA, "result": "CURRENT_SELECTED_MAPPING_RECONSTRUCTED_HOLD",
        "mapping_reviewed_commit": REVIEWED_COMMIT,
        "source_profile_reviewed_commit": profile["reviewed_source_commit"],
        "original_source_observation": original_observation,
        "checked_input_files": {path: {"bytes": len(raw), "sha256": sha(raw)}
                                for path, raw in sorted(inputs.items())},
        "selected_inputs_unchanged": True, "source_delta_review": review,
        "saved_v2": saved, "control_tree": control_tree,
        "upstream_commit": contract["upstream_commit"], "upstream_selected_sources": upstream_records,
        "stark_parameters": stark, "parameter_digest_recomputed": parameters,
        "fri_transcript_mapping": transcript,
        "original_unknown_lifetime_arithmetic": unknown_ledger,
        "original_implementation_lifetime_budget": contract["lifetime_budget"],
        "current_saved_artifact_and_upstream_mapping_reconstructed": True,
        "historical_named_test_rosters_completed": False,
        "historical_workflows_passed": False, "new_complete_proofs_generated": 0,
        "fresh_cryptographic_verification": False, "current_binary_executed": False,
        "whole_repository_source_verified": False, "dependency_closure_complete": False,
        "provenance_authenticated": False, "qualification": dict(observer.QUALIFICATION),
        "security_disposition": "HOLD_NO_GO",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.expected_head) is not None, "exact expected head")
    root = args.root.resolve(strict=True)
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(not output.is_relative_to(root), "mapping output must be outside source")
    def head():
        return subprocess.check_output(["git", "--no-replace-objects", "rev-parse", "HEAD"],
                                       cwd=root, text=True, timeout=10).strip()
    require(head() == args.expected_head, "mapping head differs before reconstruction")
    report = build_report(root)
    observer, _ = observer_module(root)
    mapper_bytes = regular_bytes(root, MAPPER_PATH, 65536)
    require(mapper_bytes == Path(__file__).read_bytes(), "executed mapping code differs from source")
    pins = dict(report["checked_input_files"])
    pins[MAPPER_PATH] = {"bytes": len(mapper_bytes), "sha256": sha(mapper_bytes)}
    # Every consumed input, including the retained proof, is bound to Git blobs.
    commit_profile = {"current_files": pins, "original_owner_files": {}}
    before = observer.selected_commit_inputs(root, args.expected_head, commit_profile)
    for path, record in pins.items():
        raw = regular_bytes(root, path, record["bytes"])
        require(len(raw) == record["bytes"] and sha(raw) == record["sha256"],
                "mapping source changed before publication: " + path)
    after = observer.selected_commit_inputs(root, args.expected_head, commit_profile)
    require(before == after and head() == args.expected_head, "mapping commit changed")
    report.update(observed_current_commit=args.expected_head, selected_commit_blob_ids=after,
                  selected_checked_bytes_match_commit=True, generator_sha256=sha(mapper_bytes))
    with output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"schema": SCHEMA, "result": report["result"],
                      "observed_current_commit": args.expected_head,
                      "selected_commit_inputs": len(after), "new_complete_proofs_generated": 0,
                      "security_disposition": "HOLD_NO_GO"}))


if __name__ == "__main__":
    main()
