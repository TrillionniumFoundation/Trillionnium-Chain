#!/usr/bin/env python3
"""Verify the retained bac6 archive without extracting or executing its contents.

This standard-library reader checks byte provenance and internal observations.
It does not rerun Rust, cryptographic signatures, model evaluation or the chain.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


SOURCE = "bac6b7659bd7e2d633e25c2da0add60f6a10c7fb"
TREE = "371c3f55de7940e276496efe2008b537ba4d8268"
RUN_ID = "incentive-" + SOURCE + "-20261112-v1"
PREFIX = "incentive-bac6b7659bd7-20261112/"
ARCHIVE_SHA256 = "3d543e24395320c860d342f396ad492baa76365128be1ee91a296ffc23ca09c9"
ARCHIVE_BYTES = 1882840
REQUIREMENTS_SHA256 = "ae117e781e1420b46bfc2c4b9a550da3fe3f98ff9cbe868192036d34c342aed5"
SPLIT_SHA256 = "2a790986b2106b288f1e0343f7b25b2391702dbb5a75b313b951c1ab04fc71fd"
PREVIOUS_SPLIT_SHA256 = "07c11a04880eab6303a66000d23082748a8f8568f8e1defe92d91c0a8b30db40"
RUST_COUNTS = {
    "m06-quorum-evolution": [9, 4],
    "m06-composition-arithmetic": [5],
    "node-public-evaluation-composition": [5, 8],
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def decimal_units(value):
    # The native counterexample serializes its account deltas as decimal strings.
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value),
            "canonical nonnegative decimal account delta")
    return int(value)


def stream_sha256(stream):
    digest = hashlib.sha256()
    size = 0
    for data in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(data)
        size += len(data)
    return size, digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--previous-receipt", type=Path)
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    archive = args.archive or base / "incentive-bac6b7659bd7-raw-20261112.tar.xz"
    with archive.open("rb") as stream:
        size, digest = stream_sha256(stream)
    require((size, digest) == (ARCHIVE_BYTES, ARCHIVE_SHA256), "archive identity")

    with tarfile.open(archive, "r:xz") as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        require(len(names) == 109 and len(set(names)) == 109, "unique archive members")
        require(all(member.isfile() for member in members), "regular members only")
        for name in names:
            require(name.startswith(PREFIX), "archive prefix")
            relative = PurePosixPath(name[len(PREFIX):])
            require(not relative.is_absolute() and ".." not in relative.parts, "safe member path")
            require("environment" not in relative.parts and "__pycache__" not in relative.parts,
                    "excluded installed environments/caches")

        def read(name):
            return tar.extractfile(PREFIX + name).read()

        def js(name):
            return json.loads(read(name))

        manifest_bytes = read("export-owner/archive-manifest.json")
        manifest = json.loads(manifest_bytes)
        require(manifest["source_commit"] == SOURCE and manifest["native_run_id"] == RUN_ID,
                "member manifest source")
        entries = manifest["entries"]
        expected = {PREFIX + row["path"]: row for row in entries}
        require(len(entries) == len(expected) == manifest["files"] == 108, "manifest count")
        require(set(expected) | {PREFIX + "export-owner/archive-manifest.json"} == set(names),
                "complete member manifest")
        observed = {}
        for member in members:
            with tar.extractfile(member) as stream:
                count, digest = stream_sha256(stream)
            observed[member.name[len(PREFIX):]] = {"bytes": count, "sha256": digest}
            require(count == member.size, "member byte count")
            if member.name in expected:
                row = expected[member.name]
                require((count, digest) == (row["bytes"], row["sha256"]), "member digest: " + row["path"])
        require(sum(row["bytes"] for row in entries) == manifest["bytes"], "manifest byte sum")
        require(sum(row["bytes"] for row in observed.values()) == 28288909, "artifact byte sum")

        before = js("source-before.json")
        after = js("source-after.json")
        pinned_source = js("python-pinned/checks/source-after.json")
        for source in [before, after]:
            require(source["commit"] == SOURCE and source["tree"] == TREE, "native source identity")
        require(pinned_source["source_commit"] == SOURCE and pinned_source["tree"] == TREE,
                "pinned source identity")
        for source in [before, after, pinned_source]:
            require(source["files"] == len(source["checks"]) == 28327, "source file count")
            require(source["bytes"] == sum(row["bytes"] for row in source["checks"]) == 2578801275,
                    "source byte count")
            require(not source["missing"] and not source["mismatches"], "source observation refusal")
            require(len({row["path"] for row in source["checks"]}) == 28327, "unique source paths")
        require(before["checks"] == after["checks"], "unchanged native source bytes and Git blobs")
        projected = [{key: row[key] for key in ["path", "bytes", "sha256"]}
                     for row in before["checks"]]
        require(projected == pinned_source["checks"] and pinned_source["unchanged"],
                "unchanged pinned source bytes")

        native = js("terminal.json")
        pinned = js("python-pinned/checks/terminal.json")
        require(native["source_commit"] == pinned["source_commit"] == SOURCE, "terminal source")
        require(native["run_id"] == pinned["native_run_id"] == RUN_ID, "terminal native identity")
        require(native["command_campaign_passed"] and native["source_unchanged"]
                and native["failure"] is None, "native terminal")
        require(pinned["pinned_python_subset_passed"] and pinned["source_unchanged"]
                and pinned["failure"] is None, "pinned terminal")
        require(not pinned["native_tests_started"] and pinned["same_native_input_bytes"],
                "pinned phase did not repeat native")
        require(not pinned["prior_system_python_observation_qualifies_pinned_gate"]
                and not pinned["complete_protocol_contract_lane_claimed"], "pinned qualification scope")
        for terminal in [native, pinned]:
            require(not terminal["production_activation"] and not terminal["economic_security_qualified"],
                    "HOLD qualification flags")
        require(not native["counterexample_is_defense_success"], "counterexample disposition")

        commands = []

        def command(name, location=""):
            receipt = js(location + name + ".receipt.json")
            require(receipt["exit_code"] == 0, "command exit: " + name)
            require(receipt["source_commit_before"] == receipt["source_commit_after"] == SOURCE,
                    "command source: " + name)
            require(receipt["source_status_before"] == receipt["source_status_after"] == "",
                    "clean command source: " + name)
            commands.append({"name": location + name, "argv": receipt["argv"],
                             "exit_code": receipt["exit_code"],
                             "duration_seconds": receipt["duration_seconds"]})
            return receipt

        for result in native["results"]:
            require(result["exit_code"] == 0, "native result exit")
            name = result["name"]
            command(name)
            if name in RUST_COUNTS:
                actual = [int(value) for value in re.findall(
                    r"test result: ok\. (\d+) passed; 0 failed; 0 ignored;", read(name + ".stdout.log").decode())]
                require(actual == result["rust_test_counts"] == RUST_COUNTS[name], "actual Rust counts")
        require(sum(sum(row) for row in RUST_COUNTS.values()) == 31, "Rust total")
        for result in pinned["results"]:
            require(result["exit_code"] == 0, "pinned result exit")
            name = result["name"]
            receipt = command(name, "python-pinned/checks/")
            require(receipt["argv"] == result["argv"], "pinned command identity")
            if name in {"composition-oracle", "composition-native-python"}:
                expected_count = 8 if name == "composition-oracle" else 5
                log = read("python-pinned/checks/" + name + ".stderr.log").decode()
                require(re.findall(r"Ran (\d+) tests? in ", log) == [str(expected_count)]
                        and re.search(r"\nOK\s*$", log), "actual Python count and terminal")
                require(result["python_test_count"] == expected_count, "Python summary count")

        config = js("configuration.json")
        require(config["features"] == "package-default", "native features")
        require(all(value is None for value in config["ambient_build_environment"].values()),
                "no ambient build/profile override")
        require(config["environment"]["RUSTC"].startswith("/"), "absolute compiler")
        tools = js("tool-versions.json")
        require("rustc 1.95.0" in tools["rustc"]["stdout"], "Rust version")
        require("46.0.5" == tools["cryptography"]["stdout"].strip(), "preserved system Python observation")
        versions = js("python-pinned/checks/versions.stdout.log")
        require(versions["numpy"] == "1.26.4" and versions["cryptography"] == "50.0.2"
                and versions["python"].startswith("3.12."), "pinned scientific environment")
        require(sha256(read("python-pinned/requirements.txt")) == REQUIREMENTS_SHA256,
                "unchanged requirements bytes")
        preparation = js("python-pinned/preparation-terminal.json")
        require(preparation["ready"] and preparation["source_unchanged"]
                and not preparation["native_tests_started"] and not preparation["global_environment_modified"],
                "isolated pinned preparation")
        require(all(row["exit_code"] == 0 for row in preparation["results"]), "dependency setup exits")

        inputs_before = read("python-pinned/checks/native-inputs-before.json")
        require(inputs_before == read("python-pinned/checks/native-inputs-after.json"),
                "identical before/after native input inventory")
        identities = js("export-owner/native-observation-identities.json")
        observations = json.loads(inputs_before)
        require(observations == identities["observations"] and len(observations) == 13, "native inventory")
        require({PREFIX + "vectors/" + row["path"] for row in observations}
                == {name for name in names if name.startswith(PREFIX + "vectors/")}, "exact native vector population")
        kinds = {}
        for row in observations:
            raw = read("vectors/" + row["path"])
            data = json.loads(raw)
            require(row["run_id"] == data["run_id"] == RUN_ID, "same native run ID")
            require((len(raw), sha256(raw)) == (row["bytes"], row["sha256"]), "native input identity")
            require(row["kind"] == data["kind"] and row["name"] == data["name"], "native input label")
            kinds[data["kind"]] = kinds.get(data["kind"], 0) + 1
            if data["kind"] == "arithmetic":
                require(len(data["native"]["cases"]) == row["arithmetic_case_count"] == 42, "arithmetic cases")
        require(kinds == {"arithmetic": 1, "release": 9, "claims": 3}, "native observation kinds")

        split_bytes = read("native-split.json")
        require(sha256(split_bytes) == pinned["native_split_sha256"] == SPLIT_SHA256, "native split byte identity")
        split = json.loads(split_bytes)
        require(split["same_complete_bundle"] and split["public_historical_rows"] == 25, "split fixture scope")
        require(split["original"]["bundle_model_hex"] == split["split"]["bundle_model_hex"], "identical complete model")
        require(split["original"]["bundle_artifact"] == split["split"]["bundle_artifact"], "identical complete artifact")
        require(decimal_units(split["split"]["alias_net_account_change_after_all_own_fees"])
                - decimal_units(split["original"]["alias_net_account_change_after_all_own_fees"]) == 26814,
                "split account difference")
        for flag in ["ordinary_Node_submission_verified", "PNW1_chain_verified",
                     "independent_History_confirmation_verified", "source_cap_bypassed",
                     "unauthorized_payer_debit", "unknown_common_control_discovered",
                     "production_activation", "economic_security_qualified"]:
            require(split[flag] is False, "split nonqualification: " + flag)
        checker = js("python-pinned/checks/split-independent.stdout.log")
        require(checker["result"] == "COUNTEREXAMPLE_REPRODUCED" and checker["receipt_sha256"] == SPLIT_SHA256,
                "independent split command result")
        require(checker["observations"]["alias_net_account_increase"] == 26814, "independent split difference")
        mutations = js("python-pinned/checks/split-independent-mutations.stdout.log")
        require(mutations["positive_receipt_sha256"] == SPLIT_SHA256 and mutations["all_rejected"], "mutation source/result")
        controls = mutations["controls"]
        require(len(controls) == len({row["mutation"] for row in controls}) == 6
                and all(row["rejected"] for row in controls), "six unique mutation refusals")

        controller = js("export-owner/controller-captures.json")
        require(controller["source_commit"] == SOURCE and len(controller["pty_streams"]) == 3, "controller streams")
        pty = []
        for row in controller["pty_streams"]:
            raw = base64.b64decode(row["data_base64"], validate=True)
            require(raw == read("export-owner/pty/" + row["label"] + ".output.log"), "PTY byte copy")
            require((len(raw), sha256(raw)) == (row["bytes"], row["sha256"]), "PTY byte identity")
            require(row["status"]["exit_code"] == 0 and row["status"]["output_complete"]
                    and row["status"]["capture_error"] is None, "PTY terminal and complete capture")
            pty.append({"label": row["label"], "bytes": len(raw), "sha256": sha256(raw), "exit_code": 0})

        previous = None
        if args.previous_receipt:
            raw = args.previous_receipt.read_bytes()
            require(sha256(raw) == PREVIOUS_SPLIT_SHA256, "previous receipt identity")
            require(json.loads(raw) == split, "equal previous/new split JSON semantics")
            previous = {"previous_source": "8197606d844e9d4c79c068a07746fabf2506fed4",
                        "previous_bytes": len(raw), "previous_sha256": sha256(raw),
                        "new_bytes": len(split_bytes), "new_sha256": SPLIT_SHA256,
                        "parsed_json_equal": True,
                        "scope": "same counterexample data; distinct execution sources and byte serializations"}

        report = {
            "schema": "chain-incentive-archive-independent-verification-v1", "result": "PASS",
            "source_commit": SOURCE, "source_tree": TREE, "native_run_id": RUN_ID,
            "archive_bytes": ARCHIVE_BYTES, "archive_sha256": ARCHIVE_SHA256,
            "archive_members": len(members), "uncompressed_bytes": 28288909,
            "extracted_files": 0, "all_member_hashes_verified": True,
            "full_source_files": 28327, "full_source_bytes": 2578801275,
            "native_and_pinned_source_bytes_unchanged": True,
            "rust_test_counts": RUST_COUNTS, "rust_tests": 31,
            "pinned_python_pure_tests": 8, "pinned_python_native_differential_tests": 5,
            "pinned_python_versions": versions,
            "native_observation_files": 13, "native_observation_kinds": kinds,
            "arithmetic_cases": 42, "same_native_input_bytes": True,
            "independent_split_mutations": controls, "split_counterexample": checker,
            "previous_split_comparison": previous,
            "pty_streams": pty, "commands": commands,
            "native_tests_started_by_this_reader": False,
            "whole_protocol_contract_lane_qualified": False,
            "prior_system_python_qualifies_pinned_gate": False,
            "production_activation": False, "economic_security_qualified": False,
            "scope": "archive identity and retained observations; no signature/model/native re-execution",
        }
        print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        print(json.dumps({"result": "FAIL", "error": str(error)}), file=sys.stderr)
        raise SystemExit(1) from error
