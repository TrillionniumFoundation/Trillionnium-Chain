#!/usr/bin/env python3
"""Recheck archived F observations without running repository tests or extracting files."""
import hashlib, json, pathlib, sys, tarfile
CAP = 4194304
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def require(value, message):
    if not value: raise ValueError(message)
def main(root):
    manifest_raw = (root / "archive-members.json").read_bytes()
    manifest = json.loads(manifest_raw)
    rows = manifest["members"]
    expected = {row["name"]: row for row in rows}
    require(len(expected) == len(rows), "duplicate manifest name")
    stored = {}
    with tarfile.open(root / "full-F-original-observations.tar.gz", "r:gz") as archive:
        for member in archive:
            path = pathlib.PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and ".." not in path.parts
                    and member.size <= CAP and member.name not in stored, "unsafe or duplicate tar member")
            raw = archive.extractfile(member).read(CAP + 1)
            require(len(raw) == member.size and len(raw) <= CAP, "invalid bounded member size")
            stored[member.name] = raw
    require(set(stored) == set(expected) | {"archive-members.json"}, "archive member set mismatch")
    require(stored["archive-members.json"] == manifest_raw, "internal/external manifests differ")
    for name, item in expected.items():
        require(len(stored[name]) == item["bytes"] and sha(stored[name]) == item["sha256"], "member mismatch: " + name)
    summary = json.loads(stored["full-source/summary.json"])
    qualified = json.loads(stored["derived/qualification.json"])
    require(sha(stored["full-source/summary.json"]) == qualified["original_summary_sha256"]
            and summary["all_gates_passed"] is False and summary["python_controls_observed"] == 65
            and qualified["original_driver_exit_code"] == 1, "original parser refusal changed")
    require(summary["source"] == qualified["source"] == manifest["source"]
            and qualified["all_actual_commands_passed"] is True and qualified["python_controls_verified"] == 108,
            "derived qualification identity mismatch")
    for item in qualified["original_files"]:
        raw = stored["full-source/" + item["relative"]]
        require(len(raw) == item["bytes"] and sha(raw) == item["sha256"], "original F artifact mismatch")
    require(len(qualified["command_bindings"]) == 10, "not ten actual commands")
    for binding in qualified["command_bindings"]:
        receipt_raw = stored["full-source/" + binding["receipt_relative"]]
        log_raw = stored["full-source/" + binding["log_relative"]]
        receipt = json.loads(receipt_raw)
        require(sha(receipt_raw) == binding["receipt_sha256"] and receipt["exit_code"] == 0
                and receipt["status"] == "command_succeeded" and receipt["argv"] == binding["argv"],
                "actual command receipt mismatch")
        require(sha(log_raw) == binding["log_sha256"] == receipt["log_sha256"]
                and len(log_raw) == binding["log_bytes"] == receipt["log_bytes"]
                and receipt["before"] == receipt["after"] == qualified["source_identity"],
                "actual log/source binding mismatch")
    original = json.loads(stored["integration-initial/commands.json"])
    require(original[-1]["name"] == "staged-whitespace" and original[-1]["exit_code"] == 2
            and "integration-initial/failure.json" in stored, "initial integration refusal missing")
    continuation = json.loads(stored["integration-continuation/result.json"])
    log_bindings = 0
    for prefix, commands in (("integration-initial", original), ("integration-continuation", continuation["commands"])):
        for command in commands:
            for stream in ("stdout", "stderr"):
                raw = stored[prefix + "/" + command["name"] + "." + stream]
                require(sha(raw) == command[stream + "_sha256"], "integration raw binding mismatch")
                if stream + "_bytes" in command:
                    require(len(raw) == command[stream + "_bytes"], "integration raw length mismatch")
                log_bindings += 1
    require(stored["integration-continuation/head-after.stdout"].decode().strip() == manifest["source"]
            and stored["integration-continuation/clean-after.stdout"] == b""
            and json.loads(stored["integration-continuation/commit.receipt.json"])["exit_code"] == 0,
            "integration continuation did not commit clean F")
    report = {"schema": "trnm-final-source-archive-byte-verification-v1", "source": manifest["source"],
        "archive_members": len(stored), "payload_members": len(expected), "all_member_hashes_match": True,
        "original_F_files_verified": len(qualified["original_files"]), "original_wrapper_exit_code": 1,
        "original_wrapper_all_gates_passed": False, "actual_command_receipts_verified": 10,
        "derived_original_python_methods": 108, "integration_raw_bindings_verified": log_bindings,
        "initial_integration_refusal_retained": True, "continuation_clean_commit_verified": True,
        "new_repository_test_execution": False, "native_tests_executed": False,
        "qualification_is_a_raw_reread_not_a_new_test_run": True}
    print(json.dumps(report, sort_keys=True))
    return report
if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent)
