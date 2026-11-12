#!/usr/bin/env python3
"""Re-read both immutable archives without extracting or executing Rust commands."""
from __future__ import annotations
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

SOURCE = "bac6b7659bd7e2d633e25c2da0add60f6a10c7fb"
TREE = "371c3f55de7940e276496efe2008b537ba4d8268"
CAP = 4 * 1024 * 1024
ROOT = Path(__file__).resolve().parent

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), "regular file required: " + str(path))
    with path.open("rb") as stream:
        raw = stream.read(CAP + 1)
    require(len(raw) <= CAP, "file exceeds unchanged 4 MiB reader cap")
    return raw

def load_archive(spec):
    name = spec["file"]
    require(PurePosixPath(name).name == name, "archive name must be local")
    raw = regular(ROOT / name)
    require(len(raw) == spec["bytes"] and digest(raw) == spec["sha256"], "archive bytes differ")
    require(len(raw) <= CAP, "archive exceeds unchanged 4 MiB reader cap")
    members, hashes = {}, {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|gz") as archive:
        for entry in archive:
            path = PurePosixPath(entry.name)
            require(entry.isfile() and not entry.sparse, "regular nonsparse tar member required")
            require(not path.is_absolute() and ".." not in path.parts, "unsafe tar member")
            require(entry.name not in members, "duplicate tar member")
            require(entry.size <= CAP, "member exceeds unchanged 4 MiB reader cap")
            body = archive.extractfile(entry).read()
            require(len(body) == entry.size, "truncated member")
            total += len(body)
            require(total <= 32 * CAP and len(members) < 256, "archive resource bound")
            members[entry.name] = body
            hashes[entry.name] = {"bytes": len(body), "sha256": digest(body)}
    manifest = json.loads(members["member-manifest.json"])
    require(manifest["source"] == SOURCE and manifest["status"] == "HOLD", "wrong archive source/status")
    declared = {row["path"]: {"bytes": row["bytes"], "sha256": row["sha256"]} for row in manifest["members"]}
    require(len(declared) == len(manifest["members"]), "duplicate declared member")
    require(declared == {k: v for k, v in hashes.items() if k != "member-manifest.json"}, "member manifest differs")
    require(digest(members[spec["driver_member"]]) == spec["driver_sha256"], "actual launcher differs")
    for binding in manifest["log_bindings"]:
        body = members[binding["log"]]
        require(len(body) == binding["bytes"] and digest(body) == binding["sha256"], "raw log binding differs")
    parsed = {k: json.loads(v) for k, v in members.items() if k.endswith(".json")}
    before = parsed["observations/source-before.json"]
    after = parsed["observations/source-after.json"]
    require(members["observations/source-before.json"] == members["observations/source-after.json"], "source bytes changed")
    require(before == after and before["tested_commit"] == SOURCE and before["tested_tree"] == TREE, "wrong source identity")
    require(before["tracked_worktree_verified"] and before["tracked_entries"] == 28327 and before["tracked_bytes"] == 2578801275, "incomplete physical source")
    configuration = parsed["observations/configuration.json"]
    require(parsed["observations/provider-after.json"] == configuration["provider_before"], "provider receipt changed")
    records = []
    for name, value in parsed.items():
        if isinstance(value, dict) and value.get("schema") == "trnm-pq-native-command-v1":
            require(value["status"] == "command_succeeded" and value["exit_code"] == 0, "command did not succeed")
            require(value["before"] == value["after"] and value["before"]["tested_commit"] == SOURCE, "command source changed")
            log = str(PurePosixPath(name).parent / value["log_file"])
            require(len(members[log]) == value["log_bytes"] and digest(members[log]) == value["log_sha256"], "command log differs")
            records.append(name)
    summary = parsed["observations/summary.json"]
    require(summary["source"] == SOURCE and summary["tree"] == TREE, "wrong summary source")
    require(summary["source_before_after_equal"] and summary["provider_before_after_equal"], "missing before/after equality")
    require(summary["status"] == "HOLD" and summary["production_activation"] is False, "activation must remain closed")
    return members, parsed, configuration, summary, {
        "file": spec["file"], "bytes": len(raw), "sha256": digest(raw),
        "members": len(members), "uncompressed_bytes": total,
        "max_member_bytes": max(len(v) for v in members.values()),
        "whole_source_command_receipts": len(records),
        "raw_log_bindings": len(manifest["log_bindings"]),
    }

def native(raw, observation, expected):
    text = "\n".join(raw.decode("utf-8").splitlines())
    names = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ok$", text, flags=re.M)
    results = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [0-9.]+s$", text, flags=re.M)
    require(len(names) == len(set(names)) == len(expected), "duplicate or missing native method")
    require(set(names) == set(expected), "native method inventory differs")
    require(results == [(str(len(expected)), "0", "0", "0", "0")], "native result line differs")
    require(observation["passed"] == len(expected) and observation["filtered_out"] == 0, "observation counts differ")
    require(set(observation["tests"]) == set(expected), "observation names differ")
    return set(names)

def main():
    manifest = json.loads(regular(ROOT / "manifest.json"))
    require(manifest["source"] == SOURCE and manifest["tree"] == TREE, "wrong evidence identity")
    require(set(manifest["archives"]) == {"initial", "full_v4"}, "both execution stages required")
    first = load_archive(manifest["archives"]["initial"])
    full = load_archive(manifest["archives"]["full_v4"])
    a, aj, ac, az, ai = first
    b, bj, bc, bz, bi = full
    require(ai["whole_source_command_receipts"] == 6 and ai["raw_log_bindings"] == 9, "initial receipt inventory differs")
    require(bi["whole_source_command_receipts"] == 1 and bi["raw_log_bindings"] == 4, "full V4 receipt inventory differs")
    require(ac["provider_before"] == bc["provider_before"], "provider changed across stages")
    require(ac["environment"] == bc["environment"], "environment changed across stages")
    require(ac["original_profiles_and_gate_thresholds_modified"] is False, "initial profile override")
    require(bc["original_profiles_features_and_budgets_modified"] is False, "full V4 profile override")
    require(bc["original_timeout_seconds_per_target"] == 1200, "original V4 timeout missing")
    require(ac["source_helpers_sha256"] == bc["source_helpers_sha256"], "source helper changed")
    require(az["all_51_methods_verified"] and az["workspace_all_targets_all_features_strict_clippy_passed"], "initial gate incomplete")
    require(bz["all_29_methods_verified"] and bz["all_66_unique_methods_verified"], "full original V4 gate incomplete")
    v5, initial_names, full_names = set(), set(), set()
    labels = {"fresh-witness": ("fresh-witness", 17), "durable-witness": ("durable-witness", 12), "provider-readback": ("provider-readback-v5", 8)}
    rows = aj["observations/v5-witness/commands.json"]
    require([r["name"] for r in rows] == list(labels), "V5 suite list differs")
    for row in rows:
        key, count = labels[row["name"]]
        expected = ac["expected_names"][key]
        require(len(expected) == count and row["source"] == SOURCE and row["exit_code"] == 0 and row["error"] is None, "V5 target incomplete")
        v5 |= native(a["observations/v5-witness/" + row["log"]], row["observation"], expected)
    inventory = aj["observations/native-inventory-observation.json"]
    selected = ac["expected_names"]["provider-readback-v4"]
    require(len(selected) == 14, "selected V4 provider count differs")
    provider = native(a["observations/records/root-provider-v4.log"], inventory["v4_observation"], selected)
    initial_names = v5 | provider
    expected_full = [("recovery-floor", 9), ("provider-readback", 14), ("callback-budget", 6)]
    full_rows = bj["observations/v4-continuation/commands.json"]
    require([r["name"] for r in full_rows] == [n for n, _ in expected_full], "full V4 suite list differs")
    for row, (name, count) in zip(full_rows, expected_full):
        expected = bc["expected_names"][name]
        require(len(expected) == count and row["source"] == SOURCE and row["exit_code"] == 0 and row["error"] is None, "full V4 target incomplete")
        full_names |= native(b["observations/v4-continuation/" + row["log"]], row["observation"], expected)
    overlap = initial_names & full_names
    require(len(v5) == 37 and len(initial_names) == 51 and len(full_names) == 29, "stage count differs")
    require(overlap == provider and len(overlap) == 14 and len(initial_names | full_names) == 66, "overlap/unique count differs")
    strict = aj["observations/records/workspace-strict-clippy.json"]
    require(strict["argv"] == ["cargo", "clippy", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], "strict Clippy gate was narrowed")
    outer = bj["observations/records/root-continuation-v4-full.json"]
    require(outer["argv"][:2] == ["python3", "scripts/ci/run_pq_root_continuation_v4.py"], "full original V4 runner not executed")
    print(json.dumps({
        "schema": "trnm-root-native-two-stage-archive-verification-v1",
        "scope": "archive revalidation only; no Rust commands executed",
        "source": SOURCE, "tree": TREE, "archives": [ai, bi],
        "initial_v5_methods": 37, "initial_selected_v4_provider_methods": 14,
        "initial_v4_complete_inventory_field_means_selected_provider_only": True,
        "initial_selected_provider_outer_1200_timeout_enforced": False,
        "full_original_v4_methods": 29, "full_original_v4_timeout_seconds_per_target": 1200,
        "method_executions": 80, "repeated_methods": 14, "unique_methods": 66,
        "all_method_names_reparsed_from_raw_logs": True,
        "all_native_results_zero_failed_ignored_filtered": True,
        "workspace_all_targets_all_features_strict_clippy_passed": True,
        "whole_tracked_source_receipts_equal": True, "provider_receipts_equal": True,
        "archive_bytes_and_members_verified": True, "no_files_extracted": True,
        "native_binary_hashes_are_after_execution_not_live_inode_attestation": True,
        "native_qualification_applies_only_to": SOURCE,
        "status": "HOLD", "production_activation": False,
        "independent_custody_verified": False, "actual_external_effects_verified": False,
        "native_m15_production_integration_complete": False,
    }, indent=2))

if __name__ == "__main__":
    main()
