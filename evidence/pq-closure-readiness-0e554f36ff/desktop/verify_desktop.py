#!/usr/bin/env python3
"""Verify the retained C2 observations; do not execute repository tests."""
import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

C1 = "c09dbbe9921da12db8bf7240a8a95a0e9a789e50"
C2 = "0e554f36ffdde3053a5eb1756eb5e526b1935032"
TREE = "753cdbad6714f00d8ccb9ddbb47f0fd71280ee62"
ARCHIVE_SHA = "3827db21e693108967c13af7d6c79fcd287aa0d591c2e31fb177b62ff5a7c82a"
INDEX_SHA = "cb91435ca1ceac3e84d39a03f184fc4276ffbd4e3a550dcc3281c22c088c99aa"
PRIMARY = "/data/pq-closure-c2-publish-validation-0e554f36ff-d4d2"
SUPPLEMENTAL = "/data/pq-closure-c2-inventory-correction-0e554f36ff-d4d2"
PUBLISHER = "/data/chain-pq-closure-20261111-d4d2-publish"


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        check(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def parse(data):
    return json.loads(data, object_pairs_hook=pairs)


def verify(folder, repo=None):
    archive_bytes = (folder / "desktop-originals-0e554f36ff.tar.xz").read_bytes()
    check(len(archive_bytes) == 46844 and sha(archive_bytes) == ARCHIVE_SHA, "archive identity")
    with tarfile.open(folder / "desktop-originals-0e554f36ff.tar.xz", "r:xz") as archive:
        members = archive.getmembers()
        check(len(members) == 111, "archive member count")
        check(len({m.name for m in members}) == len(members), "duplicate archive member")
        for member in members:
            path = PurePosixPath(member.name)
            check(member.isfile() and not path.is_absolute() and ".." not in path.parts, "unsafe member")
        raw = {m.name: archive.extractfile(m).read() for m in members}
    check(sha(raw["archive-index.json"]) == INDEX_SHA, "original archive index identity")
    index = parse(raw["archive-index.json"])
    check(index["source"] == {"commit": C2, "tree": TREE}, "archive source")
    check(index["raw_file_count"] == 110 and index["raw_bytes"] == 167957, "raw totals")
    rows = index["files"]
    check(len(rows) == 110 and {r["path"] for r in rows} == set(raw) - {"archive-index.json"}, "exact raw inventory")
    for row in rows:
        data = raw[row["path"]]
        check(len(data) == row["bytes"] and sha(data) == row["sha256"], "raw hash: " + row["path"])
    check(sum(len(raw[r["path"]]) for r in rows) == 167957, "raw byte count")

    def obj(name):
        return parse(raw[name])

    first, second = obj("primary/summary.json"), obj("supplemental/summary.json")
    primary_order = ["source-preflight", "clone-shared-full", "set-canonical-origin", "materialize-c1", "new-checkout-preflight", "bundle-verify", "bundle-import-c2", "fast-forward-c2", "c2-preflight", "gnu-time-version", "openssl-version", "source-before", "repository-truth", "distributed-inventory", "corpus-integration", "public-readiness-tests", "patch-whitespace", "source-after"]
    secondary_order = ["source-before", "distributed-inventory-corrected", "source-after"]
    check([r["name"] for r in first["commands"]] == primary_order, "primary exact command order")
    check([r["name"] for r in second["supplemental_commands"]] == secondary_order, "supplemental exact command order")
    for prefix, root, records in [("primary", PRIMARY, first["commands"]), ("supplemental", SUPPLEMENTAL, second["supplemental_commands"])]:
        for receipt in records:
            name = receipt["name"]
            check(obj(prefix + "/" + name + ".receipt.json") == receipt, "receipt/summary: " + name)
            check(receipt["timed_out"] is False, "unexpected timeout: " + name)
            check(receipt["passed"] == (receipt["exit_code"] == 0), "exit/result: " + name)
            started = obj(prefix + "/" + name + ".started.json")
            for key in ["argv", "cwd", "started_utc", "timeout_seconds"]:
                check(started[key] == receipt[key], "started/receipt: " + name + "/" + key)
            for stream in ["stdout", "stderr"]:
                relative = name + "." + stream + ".log"
                data = raw[prefix + "/" + relative]
                meta = receipt[stream]
                check(meta["path"] == root + "/" + relative, "stream origin: " + name)
                check(meta["bytes"] == len(data) and meta["sha256"] == sha(data), "stream hash: " + name)
    check(first["all_commands_passed"] is False, "original failure was erased")
    failures = [r for r in first["commands"] if not r["passed"]]
    check(len(failures) == 1 and failures[0]["name"] == "distributed-inventory" and failures[0]["exit_code"] == 2, "original failure scope")
    check(failures[0]["argv"] == ["/usr/bin/python3", "-B", "scripts/ci/refresh_distributed_source_inventory.py", "--check"], "original incorrect path")
    check(b"No such file or directory" in raw["primary/distributed-inventory.stderr.log"], "wrong-path diagnosis")
    check(obj("primary/failure.json")["error_type"] == "ValueError", "original runner failure missing")
    check(second["original_all_commands_passed"] is False and second["original_failure_preserved"] is True, "separate observation semantics")
    check(second["combined_required_publish_validation_complete"] is True and all(r["passed"] for r in second["supplemental_commands"]), "supplemental completion")
    corrected = obj("supplemental/distributed-inventory-corrected.receipt.json")
    check(corrected["argv"] == ["/usr/bin/python3", "-B", "scripts/refresh_distributed_source_inventory.py", "--check"], "corrected exact argv")
    check(obj("supplemental/original-failed-command.json") == failures[0], "preserved failed-command copy")
    original_summary_identity = obj("supplemental/original-summary-identity.json")
    check(original_summary_identity["sha256"] == sha(raw["primary/summary.json"]), "supplemental binds original summary")

    test = obj("primary/public-readiness-tests.receipt.json")
    log = raw["primary/public-readiness-tests.stderr.log"].decode("utf-8")
    matches = re.findall(r"^test_[A-Za-z0-9_]+ \(__main__\.([A-Za-z0-9_]+\.test_[A-Za-z0-9_]+)\) \.\.\. ok$", log, re.M)
    roster = parse((folder / "source-test-roster.json").read_bytes())
    check(len(matches) == len(set(matches)) == 71, "71 unique actual successes")
    check(sorted(matches) == test["success_ids"] == roster["test_ids"], "actual/receipt/C2 source roster equality")
    check(len(re.findall(r"^test_.*$", log, re.M)) == 71, "unaccounted test outcome")
    check(re.search(r"\nRan 71 tests in [0-9.]+s\n\nOK\n\Z", log) is not None, "terminal unittest completion")
    check(test["exit_code"] == 0 and test["outer_tests"] == 71 and test["complete_71_without_skip"] is True, "test receipt completion")
    check(raw["primary/public-readiness-tests.stdout.log"] == b"", "unexpected test stdout")
    check(roster["source_commit"] == C2 and roster["source_git_blob"] == "ba6c3badfcd5f173bce619b51c84334eeb9e866d", "source roster identity")
    if repo is not None:
        code = subprocess.check_output(["git", "--no-replace-objects", "-C", str(repo), "show", C2 + ":" + roster["source_path"]])
        check(len(code) == roster["source_bytes"] and sha(code) == roster["source_sha256"], "exact C2 test object")
        ids = sorted(cls.name + "." + fn.name for cls in ast.parse(code).body if isinstance(cls, ast.ClassDef) for fn in cls.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.startswith("test_"))
        check(ids == roster["test_ids"], "source AST roster derivation")

    snapshots = [raw[prefix + "/source-" + when + ".json"] for prefix in ["primary", "supplemental"] for when in ["before", "after"]]
    check(all(data == snapshots[0] for data in snapshots), "all four source observations agree")
    source = parse(snapshots[0])
    check(source["tested_commit"] == C2 and source["tested_tree"] == TREE and source["kind"] == "head", "measured source identity")
    check(source["candidate"] == C2 and source["prospective_merge"] is None, "head/merge distinction")
    check(source["tracked_worktree_verified"] is True and source["tests_executed_by_identity_check"] is False, "source check scope")
    check(source["tracked_entries"] == 27912 and source["tracked_bytes"] == 2554108569, "full tracked source totals")
    c1 = obj("primary/original-c1-before.json")
    check(c1["commit"] == C1 and c1["status"] == "", "protected C1 identity")
    for name in ["primary/original-c1-after.json", "primary/original-c1-after-failure.json", "supplemental/original-c1-before.json", "supplemental/original-c1-after.json"]:
        check(obj(name) == c1, "protected C1 HEAD/index/status: " + name)
    c2 = obj("primary/publish-c2-before.json")
    check(c2["commit"] == C2 and c2["tree"] == TREE and c2["status"] == "", "publisher C2 identity")
    check(obj("primary/publish-c2-after.json") == obj("supplemental/publish-c2-after.json") == c2, "publisher source unchanged during validation")
    for summary in [first, second]:
        check(summary["source"] == {"commit": C2, "tree": TREE}, "summary source")
        for field in ["whole_chain_pq_qualified", "production_activation", "push_performed", "pr_edit_performed"]:
            check(summary[field] is False, "observation scope: " + field)
    provider = obj("primary/provider-identity.json")
    check(provider["gnu_time"]["path"] == "/usr/bin/time" and provider["gnu_time"]["sha256"] == "3b11dec50514a8473e9f6efa7a34d584d0657538c09988f61b72d38ad4991a10", "GNU time identity")
    check(b"GNU" in raw["primary/gnu-time-version.stdout.log"], "GNU time version")
    check(len(provider["files"]) == 5 and all(re.fullmatch(r"[0-9a-f]{64}", f["sha256"]) for f in provider["files"]), "provider identity records")
    for name, expected in [("harness/c2_publish_validate.py", "024dd83c5bc1fc2bd8250b0e25a3ee5b57afe92480bc6f385a55fbfc4f8cd336"), ("harness/c2_inventory_supplement.py", "32e508d9dea171f8d13dc78e9ca9a513aaabd313ae00c4fabd89d22d5f80207e"), ("input/pq-closure-readiness-correction.bundle", "5cf89adcb148ba338825626359fb8731104c1468931e474f72ae9da7667c884d")]:
        check(sha(raw[name]) == expected, "input identity: " + name)
    transfer = parse((folder / "h-transfer.json").read_bytes())
    check(transfer["offset"] == 0 and transfer["eof"] is True and transfer["next_offset"] == transfer["size"] == 46844 and transfer["chunk_sha256"] == ARCHIVE_SHA, "bounded transfer identity")
    observations = parse((folder / "h-process-observations.json").read_bytes())

    def h_result(key):
        result = observations[key]
        check(result.get("isError") is not True, "H observation error: " + key)
        return result.get("structuredContent") or parse(next(item["text"] for item in result["content"] if item["type"] == "text"))

    for keys, expected_job in [(["c2-validation-read-1", "c2-validation-read-2", "c2-validation-read-3"], "1a1c9047868-135c4-37f"), (["c2-supplement-read-1"], "1a1c908b0f1-135c4-39d"), (["c2-pack-read"], "1a1c90c7cf9-135c4-3a8")]:
        streams = {"stdout": b"", "stderr": b""}
        for key in keys:
            result = h_result(key)
            check(result["job_id"] == expected_job, "H job binding")
            for stream in streams:
                item = result[stream]
                data = bytes.fromhex(item["bytes_hex"])
                check(data.decode("utf-8") == item["text"], "H text/byte correspondence")
                check(item["offset"] == len(streams[stream]), "H lossless cursor continuity")
                streams[stream] += data
                check(item["next_offset"] == len(streams[stream]), "H next cursor")
        for stream in streams:
            check(result[stream]["eof"] is True and result[stream]["size"] == len(streams[stream]), "H retained stream extent")
        if expected_job == "1a1c9047868-135c4-37f":
            check(b"ValueError: one or more validation commands failed" in streams["stderr"], "original process failure observation")
        if expected_job == "1a1c90c7cf9-135c4-3a8":
            packing = parse(streams["stdout"])
            check(packing["sha256"] == ARCHIVE_SHA and packing["raw_files"] == 110 and packing["raw_bytes"] == 167957, "packing process receipt")
    return {"verified": True, "source_commit": C2, "source_tree": TREE, "raw_files": 110, "raw_bytes": 167957, "archive_bytes": 46844, "archive_sha256": ARCHIVE_SHA, "primary_commands": 18, "primary_failed_commands": ["distributed-inventory"], "primary_all_commands_passed": False, "supplemental_commands": 3, "supplemental_all_commands_passed": True, "actual_unique_outer_tests_passed": 71, "skipped_outer_tests": 0, "source_roster_matches_actual_ids": True, "git_source_roster_rechecked": repo is not None, "all_four_source_observations_identical": True, "tracked_entries": 27912, "tracked_bytes": 2554108569, "original_c1_identity_unchanged": True, "native_tests_executed_by_this_packet": 0, "whole_chain_pq_qualified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, help="Optionally verify the roster again against the exact C2 Git object")
    args = parser.parse_args()
    print(json.dumps(verify(Path(__file__).resolve().parent, args.repo), indent=2, sort_keys=True))
