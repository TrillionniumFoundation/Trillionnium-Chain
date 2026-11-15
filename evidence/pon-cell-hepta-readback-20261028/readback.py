#!/usr/bin/env python3
"""Read the pinned original Cell receipt export; never execute its contents."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

ARCHIVE_NAME = "hepta-original-cell-receipts-40607183163.zip"
ARCHIVE_BYTES = 3_169_702
ARCHIVE_SHA = "dd0a56247fcb72a18873247540ce49bce04cde72dad1fad88f3639c570fb3306"
HEPTA_SOURCE = "50f4fe8089b43dfcea9e2dfce65dc1c042038918"
HEPTA_MERGE = "6f390d3ebfaefcbd5e82648d5558c5dc2a9a0f72"
HEPTA_TREE = "4318bc2f879a10e049db8d217a95d849c831af9f"
CHAIN_SOURCE = "73ffdd94f0b5461a2217a197a3d03a55b37117d5"
CHAIN_MERGE = "6a84db64dd3b395038b201b6b2cdd9b2b1dbeecb"
EXPORT_SOURCE = "a3745f5485b87cf313b28a8368f6506994b2dd1b"
ORIGINAL_RUN = 40_607_183_163
EXPORT_RUN = 40_611_414_916
PINNED = (
    (
        12781984588,
        "source-head",
        1708544417,
        "adbf3cd2247bb7907c1a5a03899a6953ccd4a3c3e9b7d449c3e0b6aa3dd521d2",
    ),
    (
        12781233928,
        "base-merge",
        1708544504,
        "8674e4291a07cfabbc450bb8addea7b12eb0a2b1a70d84bad082a2b337765997",
    ),
)
SELECTORS = {
    "material": "real_smollm_material_publishes_and_recovers_through_original_artifact_owner",
    "native": "smollm_neural_read::tests::native::real_smollm_parent_query_original_control_final_use_and_terminal_unload",
    "comparison": "real_gen2_gen3_forwards_score_only_after_original_holdout_consumption",
}
FALSE_QUALIFICATIONS = (
    "product_artifact_installed",
    "ordinary_cognitive_context_qualified",
    "independent_accepted",
    "prospective_accepted",
    "public_reward_eligible",
)


def require(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def load(archive, name):
    return json.loads(archive.read(name), object_pairs_hook=unique_object)


def false_flags(value):
    require(
        all(value.get(key) is False for key in FALSE_QUALIFICATIONS),
        "QUALIFICATION_SCOPE",
    )
    return {key: value[key] for key in FALSE_QUALIFICATIONS}


def receipt(archive, prefix, name, source, tested, run, lane):
    raw = archive.read(prefix + name)
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(
        value["source_sha"] == source
        and value["tested_sha"] == tested
        and int(value["run_id"]) == run
        and value["lane"] == lane,
        "EXECUTION_IDENTITY",
    )
    require(
        value["before"] == value["after"]
        and value["before"]["commit"] == tested
        and value["before"]["dirty"] is False,
        "EXECUTION_SOURCE_CHANGED",
    )
    log = archive.read(prefix + value["log_file"])
    require(
        len(log) == value["log_bytes"] and sha(log) == value["log_sha256"],
        "EXECUTION_LOG_DIGEST",
    )
    return dict(value, receipt_path=prefix + name, receipt_sha256=sha(raw)), log


def transport(archive, prefix, generation):
    name = prefix + f"smollm-native/cell-gen{generation}/transport-report.json"
    value = load(archive, name)
    require(
        value["scope"]
        == "one-host-controlled-native-TCL4-complete-model-and-LoRA-replica",
        "TRANSPORT_SCOPE",
    )
    require(
        value["all_model_dependencies_rehashed"] is True
        and value["publisher"]["stopped"] is True
        and value["publisher"]["returncode"] == -15
        and value["independent_operators"] is False
        and value["pq_authenticated_transport"] is False
        and value["original_hepta_installed"] is False
        and value["hepta_final_use"] is False,
        "TRANSPORT_QUALIFICATION",
    )
    require(all(v is False for v in value["authority"].values()), "TRANSPORT_AUTHORITY")
    require(
        value["offline_publisher_negative"]
        == {"no_completion_file": True, "returncode": 1},
        "OFFLINE_NEGATIVE",
    )
    for owner in ("consumer_acquisition", "replica_acquisition"):
        row = value[owner]
        require(
            row["cells"] == 11
            and row["chunks"] == 269
            and row["cached_chunks"] == 0
            and row["downloaded_chunks"] == 269
            and row["connection_attempts"] == 280
            and row["payload_bytes"] == row["downloaded_bytes"] == 272190131
            and row["suppliers"] == 1
            and row["rejected_responses"] == 0,
            "ORIGINAL_TRANSFER_COUNTS",
        )
    require(len(value["members"]) == 11, "MODEL_CLOSURE_COUNT")
    for row in value["members"]:
        require(
            row["pack"]["payload_sha256"] == row["materialization"]["payload_sha256"]
            and row["pack"]["bytes"] == row["materialization"]["bytes"],
            "MODEL_MATERIALIZATION_DIGEST",
        )
    return {
        "generation": generation,
        "receipt_path": name,
        "receipt_sha256": sha(archive.read(name)),
        **{
            key: value[key]
            for key in (
                "scope",
                "release",
                "publisher",
                "replica",
                "consumer_acquisition",
                "replica_acquisition",
                "offline_publisher_negative",
                "authority",
                "all_model_dependencies_rehashed",
                "independent_operators",
                "pq_authenticated_transport",
                "original_hepta_installed",
            )
        },
        "model_member_digests": [
            {"name": row["name"], **row["pack"]} for row in value["members"]
        ],
    }


def lane_report(archive, export, pinned):
    artifact_id, lane, size, digest = pinned
    prefix = f"cell-export/{artifact_id}/"
    metadata_name = f"cell-export/{artifact_id}-metadata.json"
    inventory_name = f"cell-export/{artifact_id}-members.json"
    metadata = load(archive, metadata_name)
    inventory = load(archive, inventory_name)
    observed = next(row for row in export["observations"] if row["id"] == artifact_id)
    require(
        metadata["id"] == artifact_id
        and metadata["size_in_bytes"] == size
        and metadata["digest"] == "sha256:" + digest
        and metadata["workflow_run"]["id"] == ORIGINAL_RUN
        and metadata["workflow_run"]["head_sha"] == HEPTA_SOURCE,
        "ORIGINAL_METADATA_IDENTITY",
    )
    require(
        observed["complete"] is True
        and observed["download_complete"] is True
        and observed["downloaded_bytes"] == size
        and observed["download_sha256"] == digest
        and inventory["original_zip_sha256"] == digest
        and inventory["original_run_reclassified"] is False
        and inventory["model_artifacts_executed"] is False,
        "ORIGINAL_COMPLETE_ZIP_ATTESTATION",
    )
    selected = [row for row in inventory["members"] if row["selected"]]
    require(
        len(selected)
        == inventory["selected_members"]
        == observed["selected_members"]
        == 247,
        "SELECTED_MEMBER_COUNT",
    )
    for row in selected:
        raw = archive.read(prefix + row["path"])
        require(
            len(raw) == row["uncompressed_bytes"] and sha(raw) == row["sha256"],
            "ORIGINAL_MEMBER_BYTES",
        )
    require(
        {name[len(prefix) :] for name in archive.namelist() if name.startswith(prefix)}
        == {row["path"] for row in selected},
        "EXTRA_OR_MISSING_EXPORT_MEMBER",
    )
    require(
        sum(row["uncompressed_bytes"] for row in selected)
        == inventory["selected_bytes"]
        == observed["selected_bytes"],
        "SELECTED_BYTES",
    )

    tested = HEPTA_SOURCE if lane == "source-head" else HEPTA_MERGE
    chain_tested = CHAIN_SOURCE if lane == "source-head" else CHAIN_MERGE
    candidate = load(archive, prefix + "candidate-tuple.json")
    pair = candidate["paired_candidate"]
    require(
        candidate["source_sha"] == HEPTA_SOURCE
        and candidate["tested_sha"] == tested
        and candidate["tested_tree"] == HEPTA_TREE
        and candidate["lane"] == lane
        and pair["source_sha"] == CHAIN_SOURCE
        and pair["tested_sha"] == chain_tested
        and pair["lane"] == lane,
        "ORIGINAL_CANDIDATE_PAIR",
    )

    receipts = {}
    for row in selected:
        name = row["path"]
        if "/" not in name and name.endswith(".json"):
            value = load(archive, prefix + name)
            if value.get("schema_version") == 1 and "command" in value:
                value, _ = receipt(
                    archive, prefix, name, HEPTA_SOURCE, tested, ORIGINAL_RUN, lane
                )
                require(value["before"]["tree"] == HEPTA_TREE, "EXECUTION_TREE")
                if lane == "base-merge":
                    require(
                        value["before"]["parents"]
                        == [candidate["base_sha"], HEPTA_SOURCE]
                        and value["recomputed_merge_tree"] == HEPTA_TREE,
                        "ORIGINAL_MERGE_PARENTS",
                    )
                receipts[name] = value
    require(len(receipts) == 13, "EXECUTION_RECEIPT_DENOMINATOR")
    native = []
    for phase, selector in SELECTORS.items():
        name = "smollm-" + phase + ".json"
        value = receipts[name]
        log = archive.read(prefix + value["log_file"]).decode("utf-8")
        require(
            "test(=" + selector + ")" in value["command"]
            and value["command"][value["command"].index("--retries") + 1] == "0"
            and value["observed_passed_tests"] == value["minimum_tests"] == 1
            and value["observed_failed_tests"] == 0
            and f"test {selector} ... ok" in log,
            "ORIGINAL_NATIVE_SELECTOR",
        )
        libtest = re.findall(
            r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out",
            log,
        )
        require(
            len(libtest) == 1 and libtest[0][:4] == ("1", "0", "0", "0"),
            "ORIGINAL_NATIVE_LIBTEST",
        )
        native.append(
            {
                "phase": phase,
                "selector": selector,
                "filtered_out": int(libtest[0][4]),
                **value,
            }
        )

    root = prefix + "smollm-native/"
    readback = load(archive, root + "readback.json")
    comparison = load(archive, root + "comparison/native-comparison-result.json")
    forwards = load(archive, root + "comparison/actual-forward-observations.json")
    frozen = load(archive, root + "comparison/frozen-controlled-comparison.json")
    material = load(archive, root + "material/material-publication-result.json")
    owner = load(archive, root + "native/native-owner-bridge-result.json")
    for value in (readback, comparison, material, owner):
        false_flags(value)
    require(
        readback["adoption"] == "no-update"
        and readback["original_runner_decision"]
        == comparison["original_runner_decision"]
        == "Ineligible"
        and readback["controlled_contract_only"] is True
        and comparison["controlled_signers"] is True
        and owner["controlled_test_issuer"] is True
        and material["controlled_test_signer"] is True,
        "CONTROLLED_NO_UPDATE",
    )
    require(
        readback["source_pair"]["chain"] == pair
        and readback["source_pair"]["hepta"]
        == {k: v for k, v in candidate.items() if k != "paired_candidate"},
        "READBACK_SOURCE_PAIR",
    )
    links = {
        "original_comparison_result_sha256": "comparison/native-comparison-result.json",
        "original_material_publication_sha256": "material/material-publication-result.json",
        "original_native_result_sha256": "native/native-owner-bridge-result.json",
        "frozen_comparison_sha256": "comparison/frozen-controlled-comparison.json",
        "raw_forward_observations_sha256": "comparison/actual-forward-observations.json",
        "publisher_offline_cell_acquisition_sha256": "cell-acquired.json",
    }
    for key, name in links.items():
        require(
            readback[key] == sha(archive.read(root + name)), "READBACK_RESULT_DIGEST"
        )
    for phase in SELECTORS:
        r = receipts["smollm-" + phase + ".json"]
        require(
            readback["execution"][phase]
            == {"log_sha256": r["log_sha256"], "receipt_sha256": r["receipt_sha256"]},
            "READBACK_EXECUTION_DIGEST",
        )
    rows = forwards["rows"]
    require(
        len(rows)
        == len(frozen["tasks"])
        == readback["actual_forward_rows"]
        == comparison["actual_forward_rows"]
        == 32
        and forwards["result_error"] is None,
        "COMPARISON_DENOMINATOR",
    )
    require(
        len({r["decision_id"] for r in rows}) == 32
        and len({r["query_sha256"] for r in rows}) == 32,
        "COMPARISON_IDENTITY",
    )
    for row, task in zip(rows, frozen["tasks"], strict=True):
        require(
            row["decision_id"] == task["decision_id"]
            and row["query_sha256"] == sha(task["query"].encode())
            and frozen["frozen_at_micros"] < row["decision_at"] < row["observed_at"],
            "FROZEN_QUERY_TEMPORAL_ORDER",
        )
        for name in ("baseline", "candidate"):
            require(
                row[name + "_correct"]
                is (row[name + "_choice"] == task["expected_action"]),
                "FORWARD_SCORE_RECOMPUTATION",
            )
    require(
        comparison["original_final_use_claims"]
        == len(comparison["original_control_requests"])
        == 66
        and owner["original_final_use_claims"]
        == len(owner["original_control_requests"])
        == 3
        and comparison["terminal_unload_observed"] is True
        and owner["terminal_unload_observed"] is True
        and comparison["original_control_reopen_exact"] is True
        and owner["original_control_reopen_exact"] is True,
        "ORIGINAL_FINAL_USE",
    )
    training = []
    for generation in (1, 2, 3):
        value = load(archive, root + f"gen{generation}/worker/actual-receipt.json")
        training.append(value)
        require(
            value["generation"] == generation
            and value["outcome"] == "success"
            and value["training"]["steps"] == 10
            and all(v is False for v in value["authority"].values()),
            "TRAINING_SCOPE",
        )
        if generation > 1:
            require(
                value["actual_loaded_parent"] == training[generation - 2]["artifact"],
                "ACTUAL_PARENT_INHERITANCE",
            )
    return {
        "artifact_id": artifact_id,
        "lane": lane,
        "original_zip_bytes": size,
        "original_zip_sha256": digest,
        "selected_members_rehashed": len(selected),
        "selected_bytes_rehashed": inventory["selected_bytes"],
        "all_original_members_in_inventory": len(inventory["members"]),
        "selected_member_hash_inventory_path": inventory_name,
        "selected_member_hash_inventory_sha256": sha(archive.read(inventory_name)),
        "original_metadata_path": metadata_name,
        "original_metadata_sha256": sha(archive.read(metadata_name)),
        "download_observation": observed,
        "source_pair": readback["source_pair"],
        "execution_receipts": receipts,
        "target_native_selectors": native,
        "execution_totals": {
            "receipts": len(receipts),
            "failed_receipts": sum(r["exit_code"] != 0 for r in receipts.values()),
            "timed_out_receipts": sum(r["timed_out"] for r in receipts.values()),
            "reported_passed_tests_including_python_controls": sum(
                r["observed_passed_tests"] for r in receipts.values()
            ),
            "reported_failed_tests": sum(
                r["observed_failed_tests"] for r in receipts.values()
            ),
        },
        "training": training,
        "transport": [transport(archive, prefix, generation) for generation in (2, 3)],
        "controlled_material_publication": material,
        "controlled_native_owner": owner,
        "comparison": {
            "rows": rows,
            "frozen_tasks": frozen["tasks"],
            "frozen_at_micros": frozen["frozen_at_micros"],
            "baseline_correct": sum(r["baseline_correct"] for r in rows),
            "candidate_correct": sum(r["candidate_correct"] for r in rows),
            "identical_final_choices": sum(
                r["baseline_choice"] == r["candidate_choice"] for r in rows
            ),
            "different_score_vectors": sum(
                r["baseline_scores_q32"] != r["candidate_scores_q32"] for r in rows
            ),
            "original_result": comparison,
            "readback": readback,
        },
    }


def readback(path):
    require(path.stat().st_size == ARCHIVE_BYTES, "EXPORT_ARCHIVE_LENGTH")
    require(sha(path.read_bytes()) == ARCHIVE_SHA, "EXPORT_ARCHIVE_DIGEST")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(
            len(names) == len(set(names)) == 501
            and sum(i.file_size for i in archive.infolist()) == 11289064,
            "EXPORT_ARCHIVE_MEMBERS",
        )
        for name in names:
            p = PurePosixPath(name)
            require(
                not p.is_absolute()
                and ".." not in p.parts
                and str(p) == name
                and "\\" not in name
                and ":" not in name,
                "EXPORT_MEMBER_PATH",
            )
        export = load(archive, "cell-export/export.json")
        require(
            export["completed"] is True
            and export["all_exports_complete"] is True
            and export["original_run_reclassified"] is False
            and export["production_activation"] is False
            and export["plan"]["source"] == HEPTA_SOURCE
            and export["plan"]["run"] == ORIGINAL_RUN
            and len(export["observations"]) == 2,
            "EXPORT_SCOPE",
        )
        execution, _ = receipt(
            archive,
            "",
            "cell-export-execution.json",
            EXPORT_SOURCE,
            EXPORT_SOURCE,
            EXPORT_RUN,
            "source-head",
        )
        require(
            execution["exit_code"] == 0 and execution["timed_out"] is False,
            "EXPORT_EXECUTION_FAILURE",
        )
        lanes = [lane_report(archive, export, row) for row in PINNED]
    return {
        "schema": "hepta-original-cell-evidence-readback-v1",
        "readback_kind": "local-read-only-original-receipt-validation",
        "archive": {
            "name": ARCHIVE_NAME,
            "bytes": ARCHIVE_BYTES,
            "sha256": ARCHIVE_SHA,
        },
        "export_execution": execution,
        "lanes": lanes,
        "selected_original_members_rehashed": sum(
            r["selected_members_rehashed"] for r in lanes
        ),
        "unique_query_digests_across_both_lanes": len(
            {r["query_sha256"] for lane in lanes for r in lane["comparison"]["rows"]}
        ),
        "original_tests_rerun": False,
        "model_artifacts_executed": False,
        "original_run_reclassified": False,
        "production_activation": False,
        "full_work_package_4_accepted": False,
        "independent_wan_accepted": False,
        "whole_chain_post_quantum_accepted": False,
        "scope": "Controlled original owners and unchanged no-update decision; no production install or independent efficacy.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "archive", nargs="?", type=Path, default=Path(__file__).with_name(ARCHIVE_NAME)
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(readback(args.archive), indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(result, end="")
    else:
        require(args.output.resolve() != args.archive.resolve(), "READ_ONLY_INPUT")
        args.output.write_text(result, encoding="utf-8")
