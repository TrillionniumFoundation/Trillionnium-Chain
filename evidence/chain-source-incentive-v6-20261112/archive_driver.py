#!/usr/bin/env python3
"""Stage and verify an evidence-only child of the exact V6 tested source.

prepare writes only outside the repository. apply is a separate explicit step,
requires a reviewed preparation SHA256 and never commits or pushes. Raw files
are archived byte-for-byte with deterministic tar metadata. verify performs
source-identity comparison only; it does not rerun or relabel native tests.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import traceback

S1 = "8cb8b743bccd93a5fac49a072990d18e0d4b4a21"
T1 = "ad9301c83be53df1937aa2b7eebf5aee131fbb99"
S2 = "214e2224fd4d18134aa9b50dc1467041651112eb"
T2 = "b4b02cca0aff2af5603618ffea510743d54a2f2d"
BASE = "4a59131acdf9b8c3210c9b6cd728aeb6c48291fc"
PLAN = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
EVIDENCE = "evidence/chain-source-incentive-v6-20261112"
OLD_RECEIPT = "evidence/chain-incentive-counterexamples-20261112/node-genesis-split/native.json"
PROTECTED = ("trillionnium", "formal", "scripts", "config")
S2_SUMMARY_SHA = "1e426def36448f75be046f30dd01b1765b07b88e96dbe5a01c1e84cf0001e838"
TERMINAL_SHA = "3b3583b3a3cae374145590ea1e72db6bde7a96373f345ab767e3015b3a60f657"
READER_MANIFEST_SHA512 = "be3255393d2262a4d707e6a70b4aa2c836403abf42a3053438e9797cbf2e2482d8d46f86509876bcc1eac6b9cb2d2dad6f9c58afc66ba9fbca060d4b00297ec0"
READER_SHA512 = "ed7dc94dcf64d53a1ac8b17a25aba34f51293af15a56c62efeed49ce2f03838e2dabbd084ddda2e52605f959669cf822fe65a97bd5d5c481990fd7113f6153eb"
NATIVE_SHA256 = "f374c315f104569850e7164af5627abfb86c5ee33efd05c2241d8b5a578bab7b"
GAME = "3a59900aa1b26ff93376dc4f852c59a9677c08a07a38dfe5cfdb2813be4634f2"
LABELS1 = ("source-identity", "fmt", "metadata", "metadata-all-features",
           "build-native-v6", "native-v6", "mvcc-fee-retained", "native-v4-retained",
           "task-kernel-retained", "native-source-errors", "strict-clippy",
           "repository-links", "source-corpus", "source-integrity-negatives",
           "independent-math-self-tests")
LABELS2 = ("source-identity", "fmt", "metadata", "metadata-all-features",
           "build-native-v6", "native-v6", "independent-native-readback",
           "mvcc-fee-retained", "native-v4-retained", "task-kernel-retained",
           "native-error-registry", "strict-clippy", "source-inventory",
           "authority-source-negatives", "authority-source-register",
           "repository-links", "source-corpus", "source-integrity-negatives",
           "independent-math-self-tests")


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def dump(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode())


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def blob(root, revision, path):
    return git(root, "show", revision + ":" + path)


def blob_id(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def regular(path):
    need(not path.is_symlink(), "symlink input: " + str(path))
    before = path.stat()
    need(stat.S_ISREG(before.st_mode), "nonregular input: " + str(path))
    raw = path.read_bytes()
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
         "input changed while read: " + str(path))
    return raw


def root_path(path):
    root = path.resolve(strict=True)
    need(git(root, "rev-parse", "--show-toplevel").decode().strip() == str(root),
         "--root must name the repository top level")
    return root


def clean_source(root):
    need(git(root, "rev-parse", "HEAD").decode().strip() == S2, "HEAD is not source2")
    need(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == T2, "source2 tree mismatch")
    need(not git(root, "status", "--porcelain", "--untracked-files=all"), "checkout is not clean")


def tree_rows(root, revision):
    result = []
    for line in git(root, "ls-tree", "-rz", revision, "--", *PROTECTED).split(b"\0"):
        if not line:
            continue
        header, path = line.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        need(kind == "blob" and mode in ("100644", "100755", "120000"), "unsupported protected entry")
        result.append({"path": path.decode(), "mode": mode, "git_blob_sha1": oid})
    need(result and len({row["path"] for row in result}) == len(result), "empty/duplicate protected set")
    return sorted(result, key=lambda row: row["path"])


def file_digest(root, row):
    path = root / row["path"]
    info = path.lstat()
    if row["mode"] == "120000":
        need(stat.S_ISLNK(info.st_mode), "protected symlink type changed")
        raw = os.fsencode(os.readlink(path))
        return {**row, "bytes": len(raw), "sha256": sha(raw), "observed_git_blob_sha1": blob_id(raw)}
    need(stat.S_ISREG(info.st_mode), "protected file type changed: " + row["path"])
    need(bool(info.st_mode & 0o111) == (row["mode"] == "100755"), "protected executable mode changed: " + row["path"])
    digest = hashlib.sha256()
    object_digest = hashlib.sha1(b"blob " + str(info.st_size).encode() + b"\0")
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            object_digest.update(chunk)
            size += len(chunk)
    after = path.lstat()
    need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and size == info.st_size,
         "protected file changed during hash: " + row["path"])
    return {**row, "bytes": size, "sha256": digest.hexdigest(), "observed_git_blob_sha1": object_digest.hexdigest()}


def protect(root):
    entries = []
    for row in tree_rows(root, S2):
        full = file_digest(root, row)
        need(full.pop("observed_git_blob_sha1") == row["git_blob_sha1"], "protected source differs: " + row["path"])
        entries.append(full)
    return {"schema": "source-incentive-protected-source-v1", "tested_commit": S2,
            "tested_tree": T2, "roots": list(PROTECTED), "entries": entries,
            "tracked_paths": len(entries), "tracked_bytes": sum(row["bytes"] for row in entries),
            "entries_sha256": sha(canonical(entries)),
            "sole_exception": {"path": CORPUS, "json_path": ["pinned_blobs", PLAN]},
            "native_execution_of_evidence_child": False}


def corpus_replace(before, old_pin, new_pin):
    old = json.loads(before)
    need(old["pinned_blobs"][PLAN] == old_pin, "unexpected prior plan pin")
    needle = (json.dumps(PLAN) + ": " + json.dumps(old_pin)).encode()
    replacement = (json.dumps(PLAN) + ": " + json.dumps(new_pin)).encode()
    need(before.count(needle) == 1, "plan pin must have one exact anchor")
    after = before.replace(needle, replacement, 1)
    expected = copy.deepcopy(old)
    expected["pinned_blobs"][PLAN] = new_pin
    need(json.loads(after) == expected, "corpus changed beyond sole plan pin")
    return after


def libtest(raw, expected):
    matches = re.findall(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", raw.decode())
    need(len(matches) == 1, "expected one libtest summary")
    result = {"status": matches[0][0], **dict(zip(("passed", "failed", "ignored", "measured", "filtered"), map(int, matches[0][1:])))}
    for key, value in expected.items():
        need(result[key] == value, "unexpected test count: " + key)
    return result


def marker(raw, label):
    hits = [line.split(label.encode(), 1)[1] for line in raw.splitlines()
            if label.encode() in line]
    need(len(hits) == 1, "expected one native marker: " + label)
    return hits[0] + b"\n", json.loads(hits[0])


def check_run(root, receipt_root, phase, expected_labels, source, tree, raw):
    summary_name = "source-validation-summary" + ("-2" if phase == 2 else "") + ".json"
    summary_bytes = regular(receipt_root / summary_name)
    if phase == 2:
        need(sha(summary_bytes) == S2_SUMMARY_SHA, "final source2 summary changed")
    summary = json.loads(summary_bytes)
    need(summary["phase"] == "completed" and summary["post_status"] == "", "validation is incomplete or dirty")
    need(summary["tested_commit"] == source and summary["tested_tree"] == tree, "summary source mismatch")
    need(summary["production_activation"] is False and summary["economic_security_qualified"] is False, "unexpected qualification")
    need([row["label"] for row in summary["checks"]] == list(expected_labels), "command roster changed")
    need(summary["all_commands_succeeded"] is (phase == 2), "incorrect overall validation state")
    raw.add("source-" + str(phase) + "/" + summary_name, summary_bytes, str(receipt_root / summary_name))
    receipts = {}
    logs = {}
    for row in summary["checks"]:
        label = row["label"]
        path = receipt_root / ("frozen-source-" + str(phase)) / (label + ".json")
        receipt_bytes = regular(path)
        receipt = json.loads(receipt_bytes)
        log_path = path.with_suffix(".log")
        log = regular(log_path)
        expected_exit = 101 if phase == 1 and label == "native-v6" else 0
        need(receipt["exit_code"] == row["command_exit_code"] == expected_exit, "unexpected command result: " + label)
        expected_status = "command_succeeded" if expected_exit == 0 else "command_failed"
        need(receipt["status"] == row["status"] == expected_status, "command status mismatch: " + label)
        need(row["runner_exit_code"] == expected_exit, "recorder did not finish as expected: " + label)
        need(receipt["log_sha256"] == row["log_sha256"] == sha(log), "log hash mismatch: " + label)
        need(receipt["log_bytes"] == len(log), "log length mismatch: " + label)
        for boundary in ("before", "after"):
            identity = receipt[boundary]
            need(identity["tested_commit"] == source and identity["candidate"] == source and
                 identity["tested_tree"] == tree and identity["kind"] == "head" and
                 identity["tracked_worktree_verified"] is True, "receipt source identity mismatch: " + label)
        raw.add("source-" + str(phase) + "/" + label + ".json", receipt_bytes, str(path))
        raw.add("source-" + str(phase) + "/" + label + ".log", log, str(log_path))
        receipts[label] = receipt
        logs[label] = log
    native = receipts["native-v6"]["native_execution"]
    need(native["status"] == "PINNED_AND_OBSERVED" and native["observation"]["status"] == "OBSERVED", "native process was not observed")
    executable = summary["native_binary"]["sha256"]
    need(native["expected_sha256"] == native["dispatch_object"]["sha256"] ==
         native["dispatch_object_after_sha256"] == native["observation"]["sha256"] == executable,
         "native executable identity mismatch")
    need(native["native_exit_code"] == (0 if phase == 2 else 101) and native["child_reaped"] is True, "native terminal mismatch")
    need(git(root, "rev-parse", source + "^{tree}").decode().strip() == tree, "Git source tree mismatch")
    return summary, receipts, logs


class RawArchive:
    def __init__(self):
        self.members = {}
        self.rows = []

    def add(self, name, content, origin, **extra):
        need(name not in self.members and not name.startswith("/") and ".." not in Path(name).parts, "unsafe/duplicate archive name")
        self.members[name] = content
        self.rows.append({"member": name, "original_location": origin, "bytes": len(content),
                          "sha256": sha(content), "sha512": hashlib.sha512(content).hexdigest(), **extra})

    def add_tree(self, path, prefix):
        need(path.is_dir() and not path.is_symlink(), "missing/symlink evidence tree")
        for item in sorted(path.rglob("*")):
            need(not item.is_symlink(), "symlink evidence tree member")
            if item.is_file():
                self.add(prefix + "/" + item.relative_to(path).as_posix(), regular(item), str(item))

    def write(self, path):
        rows = sorted(self.rows, key=lambda row: row["member"])
        with tarfile.open(path, "w:xz", format=tarfile.USTAR_FORMAT, preset=6) as archive:
            for name in sorted(self.members):
                value = self.members[name]
                info = tarfile.TarInfo(name)
                info.size = len(value)
                info.mode = 0o444
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(value))
        archive_bytes = regular(path)
        return {"schema": "source-incentive-raw-artifact-manifest-v1", "raw_bytes_preserved": True,
                "archive": path.name, "archive_bytes": len(archive_bytes), "archive_sha256": sha(archive_bytes),
                "archive_sha512": hashlib.sha512(archive_bytes).hexdigest(), "members": rows,
                "member_count": len(rows), "uncompressed_member_bytes": sum(row["bytes"] for row in rows)}


def plan_note(native_hash):
    return f"""## 已验证的来源级结算 V6 延续，2026-11-12

固定测试源码 `{S2}`（tree `{T2}`）的第二轮验证已真实完成：
19/19 命令成功，原生 V6 4/4 通过，直接执行的二进制为 `PINNED_AND_OBSERVED`，
SHA256 `{native_hash}`。独立收据复算通过，11 项 reader 自测通过。
MVCC fee 164 通过、9 忽略；保留 V4 5 通过；M10 35 通过；error registry 11 通过。

同一完整来源更新的 original / aliased / split / permuted 四种已准入表示，
该来源 gross entitlement 均为 66,666，另一来源均为 33,333，release 托管残余为 1。
原生报告扣除自身费用后的账户变化依次为 60,051 / 60,051 / 56,980 / 56,980；
独立 reader 不重放账户净变化。残余 1 按既有 expiry 规则处理，不声称观察高度已返款。

四种表示的连续签名 M06 执行与另一个实际 98-packet PNW1 owner / reorg / reopen
测试分别记录。结论限于已知来源、注册 checked-integer profile、相同冻结来源游戏，
且两种表示均通过准入；不授予未知 Sybil、任意 Cell 等价、真实市场或生产资格。
完整模型与来源消融的有效反事实、来源预算/上限/舍入及费用单列保持为规范边界。

[最终原始证据归档](../../{EVIDENCE}/README.md)保留首轮 15 项收据中的真实失败、
preliminary 编译失败、旧 reader 的 release-domain 失败及更正后的实际重跑。
本段和证据目录属于后续文档子提交；原生测试仍归属上述固定源码，不改写为子提交执行。
`trillionnium/`、`formal/`、`scripts/`、`config/` 受完整源码清单保护，唯一例外是
source corpus 已有 sole-plan pin 的单字段更新。原 V4 反例、历史 HOLD 和 false 资格字段保留。

""".encode()


def prepare(args):
    root = root_path(args.root)
    out = args.out.absolute()
    need(not out.exists() and not out.is_relative_to(root), "staging directory must be new and outside repository")
    need(out.parent.resolve(strict=True) == out.parent, "staging parent must exist without symlink alias")
    clean_source(root)
    out.mkdir(mode=0o700)
    try:
        raw = RawArchive()
        terminal_bytes = regular(args.phase2_terminal_json)
        need(sha(terminal_bytes) == TERMINAL_SHA, "authoritative terminal bytes changed")
        terminal = json.loads(terminal_bytes)
        need(terminal["job_id"] == "1a1cede1749-2564-18bc" and terminal["state"] == "succeeded" and
             terminal["exit_code"] == 0 and terminal["timed_out"] is False and terminal["cancelled"] is False,
             "second run has no successful authoritative terminal")
        for field in ("terminal_publication_confirmed", "output_complete", "output_durable"):
            need(terminal[field] is True, "incomplete terminal publication")
        for stream in ("stdout", "stderr"):
            need(terminal["log_truncated"][stream] is False and terminal["log_synced"][stream] is True and
                 terminal["log_errors"][stream] is None and
                 terminal["log_bytes"][stream]["seen"] == terminal["log_bytes"][stream]["stored"], "terminal log incompleteness")
        raw.add("source-2/source-validation-phase2-terminal.json", terminal_bytes, str(args.phase2_terminal_json))
        first, first_receipts, first_logs = check_run(root, args.receipts, 1, LABELS1, S1, T1, raw)
        second, second_receipts, second_logs = check_run(root, args.receipts, 2, LABELS2, S2, T2, raw)
        first_counts = libtest(first_logs["native-v6"], {"status": "FAILED", "passed": 3, "failed": 1, "ignored": 0})
        counts = {"native-v6": libtest(second_logs["native-v6"], {"status": "ok", "passed": 4, "failed": 0, "ignored": 0}),
                  "mvcc-fee-retained": libtest(second_logs["mvcc-fee-retained"], {"status": "ok", "passed": 164, "failed": 0, "ignored": 9}),
                  "native-v4-retained": libtest(second_logs["native-v4-retained"], {"status": "ok", "passed": 5, "failed": 0}),
                  "task-kernel-retained": libtest(second_logs["task-kernel-retained"], {"status": "ok", "passed": 35, "failed": 0}),
                  "native-error-registry": libtest(second_logs["native-error-registry"], {"status": "ok", "passed": 11, "failed": 0, "filtered": 1333})}
        reader = json.loads(second_logs["independent-native-readback"])
        need(reader["result"] == reader["audit"]["result"] == "PASS_FINITE_NATIVE_RECEIPT_RECOMPUTATION", "independent reader failed")
        need(reader["reader_sha512"] == second["reader_sha512"] == READER_SHA512, "reader source hash mismatch")
        self_test = reader["self_test"]
        need(self_test["result"] == "PASS" and self_test["tests_run"] == 11 and
             self_test["failures"] == self_test["errors"] == self_test["skipped"] == 0, "reader self-tests failed")
        need(reader["input_hashes"]["native_log_sha512"] == hashlib.sha512(second_logs["native-v6"]).hexdigest(), "reader read another native log")
        for flag in ("all_full_models_identical", "all_source_rewards_identical", "source_split_permutation_alias_invariance"):
            need(reader["audit"][flag] is True, "reader invariance assertion failed")
        invariant_raw, invariant = marker(second_logs["native-v6"], "native-v6-source-invariance ")
        owner_raw, owner = marker(second_logs["native-v6"], "native-v6-source-owner ")
        need(invariant["schema"] == "native-model-composition-v6-source-invariance-v1" and
             invariant["same_complete_bundle"] is True and invariant["PNW1_chain_verified"] is False and
             invariant["ordinary_Node_submission_verified"] is False, "invariance scope changed")
        need(owner["ordinary_node_packets"] == 98 and owner["paid_source_total"] == 100000 and
             owner["reopen_paid_state_equal"] is True and owner["reorg_source_reservation"] == 0 and
             owner["reopen_reorg_state_equal"] is True, "owner native observation changed")
        variants = []
        for name, expected_net in (("original", "60051"), ("aliased", "60051"), ("split", "56980"), ("permuted", "56980")):
            observation = invariant[name]
            audit = reader["audit"]["variants"][name]
            need(observation["alias_gross_payment"] == audit["alias_gross_payment"] == 66666 and
                 observation["alias_net_account_change_after_all_own_fees"] == expected_net and
                 observation["payments"]["2"]["gross"] == 33333, "variant account observation changed")
            arithmetic = audit["arithmetic"]
            need(arithmetic["budget"] == 100000 and arithmetic["allocated"] == 99999 and arithmetic["refund"] == 1,
                 "variant budget observation changed")
            need(audit["reported_game_digest"] == GAME and audit["native_game_digest_recomputed"] is True and
                 audit["rows"] == 25 and audit["full_correct"] == 25 and audit["parent_correct"] == 3,
                 "variant evaluation observation changed")
            need(audit["frozen_controls_correct"] == {"best_single": 19, "current": 18, "mean_merge": 19, "pooled": 19}, "control scores changed")
            need([(source["standalone_correct"], source["without_correct"], source["weight"], source["reward"])
                  for source in audit["sources"]] == [(24, 23, 80000, 66666), (23, 24, 40000, 33333)], "source scores changed")
            need(audit["actual_claim_accounts_independently_replayed"] is False, "unexpected independent account claim")
            variants.append({"case": name, "known_source_gross": 66666, "other_source_gross": 33333,
                             "unallocated_release_budget": 1, "native_reported_net_account_change": int(expected_net),
                             "independent_net_account_replay": False})
        for name in ("freeze_and_validate.py", "source-validation-phase2.py"):
            raw.add("drivers/" + name, regular(args.receipts / name), str(args.receipts / name))
        for label in ("preliminary-check", "preliminary-node-test-compile", "preliminary-task-test-compile"):
            receipt_path = args.receipts / (label + ".json")
            log_path = args.receipts / (label + ".log")
            receipt_bytes, log = regular(receipt_path), regular(log_path)
            receipt = json.loads(receipt_bytes)
            need(receipt["phase"] == "preliminary-uncommitted-build-only" and receipt["native_execution"] is False and
                 receipt["log_sha256"] == sha(log), "preliminary evidence mismatch")
            need(receipt["exit_code"] == (101 if label == "preliminary-node-test-compile" else 0), "preliminary result changed")
            raw.add("preliminary/" + label + ".json", receipt_bytes, str(receipt_path))
            raw.add("preliminary/" + label + ".log", log, str(log_path))
        preparation = json.loads(regular(args.gates / "review-8cb8b743/preparation.json"))
        gate_apply = json.loads(regular(args.gates / "apply-8cb8b743/summary.json"))
        need(preparation["prior_reader_exit_code"] == 2 and gate_apply["status"] == "PASS", "gate failure/apply evidence missing")
        need(b"source lock hash mismatch" in regular(args.gates / "review-8cb8b743/prior-reader.stderr"), "old authority refusal absent")
        raw.add_tree(args.gates, "source-gate-review-and-apply")
        reader_manifest_bytes = regular(args.reader_manifest)
        need(hashlib.sha512(reader_manifest_bytes).hexdigest() == READER_MANIFEST_SHA512, "reader historical manifest changed")
        reader_manifest = json.loads(reader_manifest_bytes)
        need(reader_manifest["overall_native_suite_pass_claimed"] is False, "historical native failure erased")
        raw.add("reader-history/reader-artifact-manifest-frozen-source-1.json", reader_manifest_bytes, str(args.reader_manifest))
        for index, item in enumerate(reader_manifest["files"]):
            path = Path(item["path"])
            original = regular(path)
            source = "retained-file"
            if sha(original) != item["sha256"] and path.is_relative_to(root):
                original = blob(root, S1, path.relative_to(root).as_posix())
                source = "git:" + S1 + ":" + path.relative_to(root).as_posix()
            need(len(original) == item["bytes"] and sha(original) == item["sha256"] and
                 hashlib.sha512(original).hexdigest() == item["sha512"], "historical reader artifact mismatch: " + str(path))
            raw.add("reader-history/" + str(index + 1).zfill(2) + "-" + path.name, original, str(path), resolved_from=source)
        old = blob(root, BASE, OLD_RECEIPT)
        need(regular(root / OLD_RECEIPT) == old, "original V4 counterexample changed")
        raw.add("historical-v4/native.json", old, BASE + ":" + OLD_RECEIPT)
        native_hash = second["native_binary"]["sha256"]
        need(native_hash == NATIVE_SHA256, "source2 binary hash differs from reviewed observation")
        protected = protect(root)
        old_plan = regular(root / PLAN)
        need(old_plan == blob(root, S2, PLAN), "source plan mismatch")
        new_plan = plan_note(native_hash) + old_plan
        old_corpus = regular(root / CORPUS)
        new_corpus = corpus_replace(old_corpus, blob_id(old_plan), blob_id(new_plan))
        payload = out / "payload"
        evidence = payload / EVIDENCE
        evidence.mkdir(parents=True)
        for path, content in ((PLAN, new_plan), (CORPUS, new_corpus)):
            target = payload / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        driver = regular(Path(__file__).resolve())
        template = regular(args.readme_template)
        need(template.count(b"$native_binary_sha256") == 1, "unexpected README substitution")
        (evidence / "README.md").write_bytes(template.replace(b"$native_binary_sha256", native_hash.encode()))
        (evidence / "archive_driver.py").write_bytes(driver)
        raw.add("archiver/prepare_source_incentive_archive.py", driver, str(Path(__file__).resolve()))
        raw.add("archiver/README.template.md", template, str(args.readme_template))
        for name, content in (("source-validation-summary.json", regular(args.receipts / "source-validation-summary.json")),
                              ("source-validation-summary-2.json", regular(args.receipts / "source-validation-summary-2.json")),
                              ("source-validation-phase2-terminal.json", terminal_bytes),
                              ("native-invariance.json", invariant_raw), ("native-owner.json", owner_raw),
                              ("independent-readback.json", second_logs["independent-native-readback"])):
            (evidence / name).write_bytes(content)
        dump(evidence / "source-protection.json", protected)
        artifacts = raw.write(evidence / "raw-observations.tar.xz")
        dump(evidence / "artifact-manifest.json", artifacts)
        summary = {"schema": "source-incentive-v6-evidence-summary-v1", "status": "PASS_FINITE_PROFILE_EXACT_SOURCE_OBSERVATIONS",
                   "tested_commit": S2, "tested_tree": T2, "native_execution_of_evidence_child": False,
                   "phase2_command_count": len(LABELS2), "phase2_all_commands_succeeded": True,
                   "phase2_terminal_sha256": sha(terminal_bytes), "native_binary_sha256": native_hash,
                   "native_observer_status": "PINNED_AND_OBSERVED", "test_counts": counts,
                   "reader_sha512": READER_SHA512, "reader_self_tests": self_test,
                   "variants": variants, "source_game_digest": GAME, "ordinary_node_packets_in_separate_owner_test": 98,
                   "budget_residual_state": "release escrow remaining; existing expiry rule; refund credit not observed",
                   "source1": {"tested_commit": S1, "tested_tree": T1, "command_count": 15,
                               "successful_commands": 14, "failed_command": "native-v6", "native_counts": first_counts},
                   "production_activation": False, "economic_security_qualified": False, "unknown_source_identity_proven": False,
                   "actual_account_payments_independently_replayed": False,
                   "protected_entries_sha256": protected["entries_sha256"],
                   "raw_archive_sha256": artifacts["archive_sha256"]}
        dump(evidence / "summary.json", summary)
        clean_source(root)
        index = []
        for path in sorted(payload.rglob("*")):
            if path.is_file():
                content = regular(path)
                index.append({"path": path.relative_to(payload).as_posix(), "bytes": len(content), "sha256": sha(content)})
        dump(out / "payload-index.json", index)
        report = {"schema": "source-incentive-archive-preparation-v1", "status": "READY_FOR_REVIEW_NO_REPOSITORY_WRITES",
                  "tested_commit": S2, "tested_tree": T2, "root": str(root), "payload_index_sha256": sha(regular(out / "payload-index.json")),
                  "old_plan_sha256": sha(old_plan), "new_plan_sha256": sha(new_plan), "new_plan_blob": blob_id(new_plan),
                  "old_corpus_sha256": sha(old_corpus), "new_corpus_sha256": sha(new_corpus),
                  "corpus_changed_json_paths": [["pinned_blobs", PLAN]], "artifact_count": artifacts["member_count"],
                  "protected_paths": protected["tracked_paths"], "protected_bytes": protected["tracked_bytes"],
                  "native_tests_executed_by_archiver": False, "committed": False, "pushed": False,
                  "prepared_files": index}
        dump(out / "preparation.json", report)
        print(json.dumps({"status": report["status"], "preparation": str(out / "preparation.json"),
                          "preparation_sha256": sha(regular(out / "preparation.json")), "artifact_count": artifacts["member_count"],
                          "protected_paths": protected["tracked_paths"], "raw_archive_sha256": artifacts["archive_sha256"]}, sort_keys=True))
    except Exception as exc:
        dump(out / "blocked.json", {"status": "BLOCKED_NO_COMPLETION_CLAIM", "error": str(exc),
                                    "traceback": traceback.format_exc(), "repository_writes": False})
        raise


def verify(root, target, manifest_path):
    manifest = json.loads(regular(manifest_path))
    need(manifest["tested_commit"] == S2 and manifest["tested_tree"] == T2 and
         manifest["entries_sha256"] == sha(canonical(manifest["entries"])), "invalid source protection manifest")
    expected = tree_rows(root, S2)
    need([{key: row[key] for key in ("path", "mode", "git_blob_sha1")} for row in manifest["entries"]] == expected,
         "source protection omitted/changed a tracked entry")
    source_plan = blob(root, S2, PLAN)
    source_corpus = blob(root, S2, CORPUS)
    if target == "WORKTREE":
        plan, corpus = regular(root / PLAN), regular(root / CORPUS)
        actual_rows = []
        for row in expected:
            actual = file_digest(root, row)
            actual_rows.append({"path": row["path"], "mode": row["mode"], "git_blob_sha1": actual["observed_git_blob_sha1"]})
            if row["path"] != CORPUS:
                indexed = manifest["entries"][len(actual_rows) - 1]
                need(actual["sha256"] == indexed["sha256"] and actual["bytes"] == indexed["bytes"], "protected SHA256 changed: " + row["path"])
        changed = set(git(root, "diff", "--name-only", "-z", S2).decode().strip("\0").split("\0")) - {""}
        untracked = set(git(root, "ls-files", "--others", "--exclude-standard", "-z").decode().strip("\0").split("\0")) - {""}
        changed |= untracked
        child = git(root, "rev-parse", "HEAD").decode().strip()
        observed_tree = None
    else:
        child = git(root, "rev-parse", target + "^{commit}").decode().strip()
        need(subprocess.run(["git", "merge-base", "--is-ancestor", S2, child], cwd=root).returncode == 0, "child does not descend from tested source")
        actual_rows = tree_rows(root, child)
        plan, corpus = blob(root, child, PLAN), blob(root, child, CORPUS)
        changed = set(git(root, "diff", "--name-only", "-z", S2, child).decode().strip("\0").split("\0")) - {""}
        observed_tree = git(root, "rev-parse", child + "^{tree}").decode().strip()
    need(len(actual_rows) == len(expected), "protected path count changed")
    for before, after in zip(expected, actual_rows):
        need(before["path"] == after["path"] and before["mode"] == after["mode"], "protected path/mode set changed")
        if before["path"] != CORPUS:
            need(before == after, "protected blob changed: " + before["path"])
    expected_plan = plan_note(NATIVE_SHA256) + source_plan
    need(plan == expected_plan, "sole plan is not the exact reviewed prepend")
    need(corpus == corpus_replace(source_corpus, blob_id(source_plan), blob_id(plan)), "corpus change exceeds exact plan pin")
    need({PLAN, CORPUS}.issubset(changed) and any(path.startswith(EVIDENCE + "/") for path in changed), "evidence child is incomplete")
    need(all(path in (PLAN, CORPUS) or path.startswith(EVIDENCE + "/") for path in changed), "unexpected evidence-child change")
    return {"schema": "source-incentive-evidence-child-verification-v1", "status": "PASS",
            "tested_source_commit": S2, "tested_source_tree": T2, "observed_target": target,
            "observed_head_or_child_commit": child, "observed_child_tree": observed_tree,
            "protected_paths": len(expected), "protected_entries_sha256": manifest["entries_sha256"],
            "protected_source_manifest_sha256": sha(regular(manifest_path)),
            "compiled_source_changed": False, "corpus_changed_json_paths": [["pinned_blobs", PLAN]],
            "changed_paths": sorted(changed), "native_tests_executed_by_verifier": False,
            "native_tests_claimed_for_child": False}


def apply(args):
    root = root_path(args.root)
    prepared = args.prepared.resolve(strict=True)
    need(not prepared.is_relative_to(root), "prepared payload must remain outside repository")
    report_bytes = regular(prepared / "preparation.json")
    need(sha(report_bytes) == args.expected_preparation_sha256, "reviewed preparation hash mismatch")
    report = json.loads(report_bytes)
    need(report["status"] == "READY_FOR_REVIEW_NO_REPOSITORY_WRITES" and report["tested_commit"] == S2 and report["tested_tree"] == T2,
         "prepared result was not qualified for application")
    clean_source(root)
    need(not (root / EVIDENCE).exists(), "evidence directory already exists")
    preflight = subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=root, capture_output=True)
    (prepared / "apply-preflight.stdout").write_bytes(preflight.stdout)
    (prepared / "apply-preflight.stderr").write_bytes(preflight.stderr)
    need(preflight.returncode == 0, "project preflight refused evidence application")
    clean_source(root)
    index_bytes = regular(prepared / "payload-index.json")
    need(sha(index_bytes) == report["payload_index_sha256"], "payload index changed after review")
    index = json.loads(index_bytes)
    payload = prepared / "payload"
    actual_paths = sorted(path.relative_to(payload).as_posix() for path in payload.rglob("*") if path.is_file())
    need(actual_paths == sorted(row["path"] for row in index), "payload file roster changed")
    need(index == report["prepared_files"], "prepared file index mismatch")
    for row in index:
        relative = row["path"]
        need(relative in (PLAN, CORPUS) or relative.startswith(EVIDENCE + "/"), "payload outside allowed evidence scope")
        content = regular(payload / relative)
        need(len(content) == row["bytes"] and sha(content) == row["sha256"], "payload changed after review: " + relative)
    need(sha(regular(root / PLAN)) == report["old_plan_sha256"] and sha(regular(root / CORPUS)) == report["old_corpus_sha256"], "prior plan/corpus changed")
    (prepared / "before-plan.md").write_bytes(regular(root / PLAN))
    (prepared / "before-corpus.json").write_bytes(regular(root / CORPUS))
    try:
        shutil.copytree(payload / EVIDENCE, root / EVIDENCE)
        for relative in (PLAN, CORPUS):
            destination = root / relative
            temporary = destination.with_name(destination.name + ".evidence-child-tmp")
            need(not temporary.exists(), "temporary output already exists")
            with temporary.open("xb") as stream:
                stream.write(regular(payload / relative))
            os.replace(temporary, destination)
        result = verify(root, "WORKTREE", root / EVIDENCE / "source-protection.json")
        diff_check = subprocess.run(["git", "diff", "--check"], cwd=root, capture_output=True)
        (prepared / "apply-diff-check.stdout").write_bytes(diff_check.stdout)
        (prepared / "apply-diff-check.stderr").write_bytes(diff_check.stderr)
        need(diff_check.returncode == 0, "tracked diff whitespace check failed")
        result.update({"committed": False, "pushed": False, "reviewed_preparation_sha256": args.expected_preparation_sha256})
        dump(prepared / "apply-verification.json", result)
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:
        dump(prepared / "apply-failed.json", {"status": "FAILED_PARTIAL_APPLICATION_PRESERVED", "error": str(exc), "traceback": traceback.format_exc()})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    stage = sub.add_parser("prepare")
    stage.add_argument("--root", type=Path, required=True)
    stage.add_argument("--out", type=Path, required=True)
    stage.add_argument("--receipts", type=Path, required=True)
    stage.add_argument("--gates", type=Path, required=True)
    stage.add_argument("--reader-manifest", type=Path, required=True)
    stage.add_argument("--phase2-terminal-json", type=Path, required=True)
    stage.add_argument("--readme-template", type=Path, required=True)
    application = sub.add_parser("apply")
    application.add_argument("--root", type=Path, required=True)
    application.add_argument("--prepared", type=Path, required=True)
    application.add_argument("--expected-preparation-sha256", required=True)
    check = sub.add_parser("verify")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--target", required=True)
    check.add_argument("--manifest", type=Path)
    check.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "apply":
        apply(args)
    else:
        root = root_path(args.root)
        need(not args.report.absolute().is_relative_to(root), "verification report must be outside repository")
        result = verify(root, args.target, args.manifest or root / EVIDENCE / "source-protection.json")
        dump(args.report, result)
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
