#!/usr/bin/env python3
"""Verify archived publication records offline; perform no network or Git writes."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

C1 = "c09dbbe9921da12db8bf7240a8a95a0e9a789e50"
C2 = "0e554f36ffdde3053a5eb1756eb5e526b1935032"
TREE = "753cdbad6714f00d8ccb9ddbb47f0fd71280ee62"
BASE = "31543fb6dde565b62b47436e0b1d399b6d0bd772"
BRANCH = "fix/chain-pq-closure-20261111-d4d2"
BASE_BRANCH = "fix/chain-pq-authority-complete-20261110-5778"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
ARCHIVE_SHA = "2a1b7c7fd36c83add8a6a417a8c6019f3588b775648ea675455f62a000d86ceb"
INDEX_SHA = "ec689281f248b794e8edff9e8c8b3d713448ee64a774ca9bf855c2a93564880d"
REST_SUMMARY_SHA = "3090779b55352e4608d651590ddf6a8189c6529b16a43bf5e07f6a5a0327b587"
BODY_SHA = "859bd019bfad528e9269980eee5717d6f5d7de2a6ac8781b22a00ae070c7cb95"


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


def verify(folder):
    archive_path = folder / "publication-originals-0e554f36ff.tar.xz"
    data = archive_path.read_bytes()
    check(len(data) == 16680 and sha(data) == ARCHIVE_SHA, "original archive identity")
    with tarfile.open(archive_path, "r:xz") as archive:
        members = archive.getmembers()
        check(len(members) == 63 and len({m.name for m in members}) == 63, "exact unique member count")
        for member in members:
            path = PurePosixPath(member.name)
            check(member.isfile() and not path.is_absolute() and ".." not in path.parts, "safe regular archive member")
        raw = {m.name: archive.extractfile(m).read() for m in members}
    check(sha(raw["archive-index.json"]) == INDEX_SHA, "index identity")
    index = parse(raw["archive-index.json"])
    check(index["source"] == {"commit": C2, "tree": TREE}, "archive source")
    check(index["raw_file_count"] == 62 and index["raw_bytes"] == 151064, "original file totals")
    check(len(index["files"]) == 62 and {r["path"] for r in index["files"]} == set(raw) - {"archive-index.json"}, "complete original manifest")
    for row in index["files"]:
        value = raw[row["path"]]
        check(len(value) == row["bytes"] and sha(value) == row["sha256"], "original file hash: " + row["path"])
    check(sum(len(raw[r["path"]]) for r in index["files"]) == 151064, "raw byte sum")
    check(index["observed_absent_original_paths"] == ["/data/pq-closure-publish-0e554f36ff-d4d2/summary.json", "/data/pq-closure-publish-0e554f36ff-d4d2/source-after.json"], "original missing tail observation")
    check("original-cli/summary.json" not in raw and "original-cli/source-after.json" not in raw, "original tail was not fabricated")

    def obj(name):
        return parse(raw[name])

    failure = obj("original-cli/failure.json")
    check(failure["error_type"] == "ValueError" and failure["message"] == "command failed: update-pr-body", "original CLI failure retained")
    check(sha(raw["rest-correction/summary.json"]) == REST_SUMMARY_SHA, "REST summary identity")
    summary = obj("rest-correction/summary.json")
    original_names = ["preflight", "actor", "pr-before", "remote-before", "enable-project-hooks", "push-c2", "remote-after", "update-pr-body"]
    rest_names = ["preflight", "actor", "pr-before", "update-pr-rest", "pr-after"]
    check([r["name"] for r in failure["commands"]] == original_names, "original exact command order")
    check([r["name"] for r in summary["commands"]] == rest_names, "REST exact command order")
    for prefix, rows in [("original-cli", failure["commands"]), ("rest-correction", summary["commands"])]:
        for row in rows:
            name = row["name"]
            check(obj(prefix + "/" + name + ".receipt.json") == row, "receipt/aggregate match: " + name)
            started = obj(prefix + "/" + name + ".started.json")
            for key in ["argv", "cwd", "started_utc", "timeout_seconds"]:
                check(started[key] == row[key], "started/receipt match: " + name)
            for stream in ["stdout", "stderr"]:
                filename = name + "." + stream + ".log"
                stream_data = raw[prefix + "/" + filename]
                check(row[stream]["name"] == filename and row[stream]["bytes"] == len(stream_data) and row[stream]["sha256"] == sha(stream_data), "raw stream identity: " + filename)
    check([(r["name"], r["exit_code"]) for r in failure["commands"] if r["exit_code"] != 0] == [("update-pr-body", 1)], "original failure scope")
    check(all(r["exit_code"] == 0 for r in summary["commands"]), "REST all five commands completed")
    check(b"Projects (classic) is being deprecated" in raw["original-cli/update-pr-body.stderr.log"] and b"repository.pullRequest.projectCards" in raw["original-cli/update-pr-body.stderr.log"], "exact GraphQL failure diagnosis")
    check(obj("original-cli/enable-project-hooks.receipt.json")["argv"] == ["git", "config", "--local", "core.hooksPath", ".githooks"], "project hooks enabled")
    pushes = [r for r in failure["commands"] + summary["commands"] if r["argv"][:2] == ["git", "push"]]
    check(len(pushes) == 1 and pushes[0]["argv"] == ["git", "push", "origin", "HEAD:refs/heads/" + BRANCH] and pushes[0]["exit_code"] == 0, "one successful normal push")
    hook = obj("original-cli/push-c2.stdout.log")
    check(hook["result"] == "PASS" and hook["mode"] == "--push" and hook["branch"] == BRANCH and hook["remote_policy_mutated"] is False, "actual pre-push result")
    check(raw["original-cli/remote-before.stdout.log"].decode().split() == [C1, "refs/heads/" + BRANCH], "remote before C1")
    check(raw["original-cli/remote-after.stdout.log"].decode().split() == [C2, "refs/heads/" + BRANCH], "remote after C2")
    check(summary["actor"] == "ProfHepta" and all(raw[p + "/actor.stdout.log"] == b"ProfHepta\n" for p in ["original-cli", "rest-correction"]), "actual actor observations")
    for field in ["original_gh_pr_edit_failed", "original_failure_preserved", "rest_patch_completed_and_read_back", "draft"]:
        check(summary[field] is True, "REST scope: " + field)
    for field in ["push_repeated", "whole_chain_pq_qualified", "production_activation"]:
        check(summary[field] is False, "REST scope: " + field)
    check(summary["source"] == {"commit": C2, "tree": TREE}, "REST exact source")
    check(obj("original-cli/source-before.json") == obj("rest-correction/source-before.json") == obj("rest-correction/source-after.json"), "three actual source observations agree")

    body = raw["reviewed/pq-closure-pr-body-0e554f36ff-d4d2.md"]
    check(len(body) == 6679 and sha(body) == BODY_SHA == summary["reviewed_body_sha256"], "reviewed body identity")
    request = obj("rest-correction/body.json")
    check(set(request) == {"body"} and request["body"].encode("utf-8") == body, "REST modifies only exact reviewed body")
    before_cli = obj("original-cli/pr-before.stdout.log")
    before_rest = obj("rest-correction/pr-before.stdout.log")
    patch_reply = obj("rest-correction/update-pr-rest.stdout.log")
    after = obj("rest-correction/pr-after.stdout.log")
    for pr, head in [(before_cli, C1), (before_rest, C2), (patch_reply, C2), (after, C2)]:
        check(pr["number"] == 901 and pr["draft"] is True and pr["state"] == "open", "PR state")
        check(pr["head"]["sha"] == head and pr["head"]["ref"] == BRANCH and pr["base"]["sha"] == BASE and pr["base"]["ref"] == BASE_BRANCH, "PR base/head identity")
    check(before_cli["body"] == before_rest["body"], "CLI failure left original body")
    check(patch_reply["body"].encode("utf-8") == after["body"].encode("utf-8") == body, "exact PATCH and independent GET body readback")
    check(obj("rest-correction/update-pr-rest.receipt.json")["argv"] == ["gh", "api", "--method", "PATCH", "repos/" + REPO + "/pulls/901", "--input", "/data/pq-closure-pr-rest-0e554f36ff-d4d2/body.json"], "bounded REST correction argv")
    for name, expected in [("controllers/pq-closure-publish-0e554f36ff-d4d2.py", "ab9ce16c25cd17140a1af6e2b28565e80eb33ddb5a5704a1ef7ac34241cfa5b4"), ("controllers/pq-closure-pr-rest-0e554f36ff-d4d2.py", "32091685ef30e292fe66b746f1e839ac7d005c22cba2cdbc96f8f62f3d42a16b")]:
        check(sha(raw[name]) == expected, "original controller identity")
    transfer = parse((folder / "h-transfer.json").read_bytes())
    check(transfer["offset"] == 0 and transfer["eof"] is True and transfer["next_offset"] == transfer["size"] == 16680 and transfer["chunk_sha256"] == ARCHIVE_SHA, "archive transfer identity")
    return {"verified": True, "source_commit": C2, "source_tree": TREE, "raw_files": 62, "raw_bytes": 151064, "archive_bytes": 16680, "archive_sha256": ARCHIVE_SHA, "original_commands": 8, "original_failed_command": "update-pr-body", "original_failed_command_exit_code": 1, "original_summary_absent": True, "original_source_after_absent": True, "normal_push_count_in_retained_operations": 1, "normal_push_exit_code": 0, "pre_push_hook_result": "PASS", "rest_commands": 5, "rest_all_commands_exit_zero": True, "rest_summary_sha256": REST_SUMMARY_SHA, "reviewed_body_bytes": 6679, "reviewed_body_sha256": BODY_SHA, "actor": "ProfHepta", "pr": 901, "draft": True, "read_back_head": C2, "exact_body_read_back": True, "push_repeated": False, "whole_chain_pq_qualified": False, "production_activation": False}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), indent=2, sort_keys=True))
