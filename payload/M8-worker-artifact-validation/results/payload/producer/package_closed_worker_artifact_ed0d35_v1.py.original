#!/usr/bin/env python3
"""Package only the closed M8 worker component evidence; never execute its code."""
import ast, collections, hashlib, json, os, pathlib, re, stat, sys, zipfile, zlib

BASE = pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
SOURCE = BASE / "final-worker-artifact-existing-source-ed0d35-v2"
DRIVER = BASE / "run_final_rog_worker_artifact_existing_source_v2.py"
DEST = BASE / "closed-worker-artifact-ed0d35-package-v1"
CAP = 32 * 1024 * 1024
EXPECTED_HEAD = "ed0d35487f2a67239e4d646fd41c2c7acb5cc740"
EXPECTED_TREE = "1aa9c21812489080980bdc3c1c2bb43611e88354"
CONFIG = json.loads("{\"terminal_receipt\":\"{\\\"archive_path\\\":\\\"/home/qian-qi/.local/state/hepta-runtime-mac-worker/terminals/dpty-3c1b53e95254c2cfd8f432884ac2bc42ee824162d66a7217e6fe2a27fbb35f23/output.log\\\",\\\"available_end\\\":1382,\\\"bytes_hex\\\":\\\"7b22707265636564696e675f6f726967696e616c5f7265706f7369746f72795f6c616e65223a2022706173736564222c2022776f726b65725f65787472615f636f6d706f6e656e745f6f6e6c79223a20747275652c2022666f75725f7365636f6e645f7175616c696669636174696f6e223a2066616c73657d0d0a7b226c6162656c223a2022696e697469616c2d68656164222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022696e697469616c2d74726565222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022696e697469616c2d737461747573222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022707265666c696768742d6175646974222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022727573742d76657273696f6e222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022636172676f2d76657273696f6e222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a20227665726966792d736f757263652d6265666f7265222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022776f726b65722d61727469666163742d6769742d626c6f62222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022776f726b73706163652d666f726d6174222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022776f726b65722d7374726963742d636c69707079222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a2022776f726b65722d61727469666163742d7465737473222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b226c6162656c223a20227665726966792d736f757263652d6166746572222c202265786974223a20302c20226f776e65645f70726f636573735f7465726d696e61746564223a20747275657d0d0a7b22737461747573223a2022706173736564222c202268656164223a202265643064333534383766326136373233396534643634366664343163326337616362356363373430222c202274726565223a202231616139633231383132343839303830393830626463336331633262623433363131653838333534222c202273756d6d617279223a20222f686f6d652f7169616e2d71692f636861696e2d66696e616c2d636f6e736f6c69646174696f6e2d32303236313131342d726f6f742f66696e616c2d776f726b65722d61727469666163742d6578697374696e672d736f757263652d6564306433352d76322f73756d6d6172792e6a736f6e222c202273756d6d6172795f736861323536223a202262386536653836653038653430646638356232626466366537636334306564653934323536303735643164376264353630343761323331306237373963303236227d0d0a\\\",\\\"chunk_sha256\\\":\\\"b9b1e420c96b6b92c5f659a331d3dee00fbdee7525b803d05425e7944c9af234\\\",\\\"host\\\":\\\"rog\\\",\\\"next_offset\\\":1382,\\\"offset\\\":0,\\\"output_complete\\\":true,\\\"persistent_across_runtime_restart\\\":true,\\\"session_id\\\":\\\"dpty-3c1b53e95254c2cfd8f432884ac2bc42ee824162d66a7217e6fe2a27fbb35f23\\\",\\\"status\\\":{\\\"boot\\\":\\\"fcdd2477-a952-4ef2-9bdc-2237255080f1\\\",\\\"bytes_seen\\\":1382,\\\"bytes_stored\\\":1382,\\\"capture_error\\\":null,\\\"closed\\\":false,\\\"created_unix_ms\\\":1794652774511,\\\"exit_code\\\":0,\\\"output_complete\\\":true,\\\"owner_pid\\\":2607333,\\\"pid\\\":2607336,\\\"state\\\":\\\"exited\\\"},\\\"storage\\\":\\\"target_archive\\\",\\\"text\\\":\\\"{\\\\\\\"preceding_original_repository_lane\\\\\\\": \\\\\\\"passed\\\\\\\", \\\\\\\"worker_extra_component_only\\\\\\\": true, \\\\\\\"four_second_qualification\\\\\\\": false}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"initial-head\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"initial-tree\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"initial-status\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"preflight-audit\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"rust-version\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"cargo-version\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"verify-source-before\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"worker-artifact-git-blob\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"workspace-format\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"worker-strict-clippy\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"worker-artifact-tests\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"label\\\\\\\": \\\\\\\"verify-source-after\\\\\\\", \\\\\\\"exit\\\\\\\": 0, \\\\\\\"owned_process_terminated\\\\\\\": true}\\\\r\\\\n{\\\\\\\"status\\\\\\\": \\\\\\\"passed\\\\\\\", \\\\\\\"head\\\\\\\": \\\\\\\"ed0d35487f2a67239e4d646fd41c2c7acb5cc740\\\\\\\", \\\\\\\"tree\\\\\\\": \\\\\\\"1aa9c21812489080980bdc3c1c2bb43611e88354\\\\\\\", \\\\\\\"summary\\\\\\\": \\\\\\\"/home/qian-qi/chain-final-consolidation-20261114-root/final-worker-artifact-existing-source-ed0d35-v2/summary.json\\\\\\\", \\\\\\\"summary_sha256\\\\\\\": \\\\\\\"b8e6e86e08e40df85b2bdf6e7cc40ede94256075d1d7bd56047a2310b779c026\\\\\\\"}\\\\r\\\\n\\\",\\\"text_is_lossy\\\":false,\\\"truncated_before_offset\\\":false,\\\"utf8_pending\\\":false}\",\"summary_sha\":\"b8e6e86e08e40df85b2bdf6e7cc40ede94256075d1d7bd56047a2310b779c026\",\"source_sha\":\"a74be5eb0131658ed16c8e1988806ffa8886a3a6580a6cca2c5a41a1ee88538d\",\"driver_sha\":\"491ce4a207e722f47ef2174690de83678cfc39b59b82db048f22fb95db17c95f\",\"test_outcomes_sha\":\"73b8207addc525502bd49a23431d07d0203c9d260b44b78c82207a67fbe83c02\",\"test_stdout_sha\":\"57393aca2e2b7215a7a17b60ad5e9311ab9909cd6edfe760822bb4e081e8de02\"}")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")

def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)

def valid_name(value):
    require(value not in ("", ".", "..") and "/" not in value and "\\" not in value
            and all(ord(c) >= 32 and ord(c) != 127 for c in value), "unsafe archive component")
    value.encode("utf-8", errors="strict")

def read_regular(path):
    path = pathlib.Path(path)
    before = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            "canonical single-link regular file required: " + str(path))
    require(0 <= before.st_size <= CAP, "file exceeds cap")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        require(fingerprint(os.fstat(fd)) == fingerprint(before), "file changed before read")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, CAP + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= CAP, "read exceeds cap")
        raw = b"".join(chunks)
        require(len(raw) == before.st_size and fingerprint(os.fstat(fd)) == fingerprint(before),
                "file changed during read")
    finally:
        os.close(fd)
    require(fingerprint(path.lstat()) == fingerprint(before), "named file changed after read")
    return raw, fingerprint(before)

def snapshot_tree():
    require(SOURCE.resolve(strict=True) == SOURCE, "noncanonical closed evidence root")
    before = SOURCE.lstat()
    require(stat.S_ISDIR(before.st_mode), "closed evidence directory required")
    root_fd = os.open(SOURCE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    directories, files, buffers, total = {}, {}, {}, 0
    def walk(directory_fd, prefix):
        nonlocal total
        initial = os.fstat(directory_fd)
        require(stat.S_ISDIR(initial.st_mode), "directory type changed")
        directories[prefix] = fingerprint(initial)
        names = sorted(os.listdir(directory_fd))
        for name in names:
            valid_name(name)
            relative = name if not prefix else prefix + "/" + name
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                nested = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
                try:
                    require(fingerprint(os.fstat(nested)) == fingerprint(observed), "directory replaced before descent")
                    walk(nested, relative)
                finally:
                    os.close(nested)
                require(fingerprint(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) == fingerprint(observed),
                        "directory changed after descent")
            else:
                require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1, "symlink, special or linked input: " + relative)
                require(len(files) < 10000 and total + observed.st_size <= CAP, "closed input roster exceeds cap")
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
                try:
                    require(fingerprint(os.fstat(fd)) == fingerprint(observed), "file replaced before read")
                    chunks, got = [], 0
                    while True:
                        chunk = os.read(fd, min(65536, CAP + 1 - got))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        got += len(chunk)
                        require(got <= observed.st_size and got <= CAP, "input grew")
                    raw = b"".join(chunks)
                    require(got == observed.st_size and fingerprint(os.fstat(fd)) == fingerprint(observed), "input changed during read")
                finally:
                    os.close(fd)
                require(fingerprint(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) == fingerprint(observed),
                        "named input changed after read")
                files[relative] = {"identity": fingerprint(observed), "bytes": len(raw), "sha256": sha(raw)}
                buffers[relative] = raw
                total += len(raw)
        require(sorted(os.listdir(directory_fd)) == names and fingerprint(os.fstat(directory_fd)) == fingerprint(initial),
                "directory roster or identity changed")
    try:
        require(fingerprint(os.fstat(root_fd)) == fingerprint(before), "evidence root replaced")
        walk(root_fd, "")
    finally:
        os.close(root_fd)
    require(fingerprint(SOURCE.lstat()) == fingerprint(before), "evidence root changed")
    return {"directories": directories, "files": files, "file_count": len(files), "total_bytes": total}, buffers

def write_new(relative, raw):
    parts = pathlib.PurePosixPath(relative).parts
    require(parts and not pathlib.PurePosixPath(relative).is_absolute(), "relative output required")
    for part in parts:
        valid_name(part)
    path = DEST.joinpath(*parts)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    require(path.parent.resolve(strict=True) == path.parent, "output parent changed")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    reread, _ = read_regular(path)
    require(reread == raw, "output readback differs")
    return path

def main():
    require(not sys.flags.optimize and sys.platform == "linux" and os.getuid() != 0, "ordinary non-root Linux required")
    require(BASE.resolve(strict=True) == BASE, "canonical authorized base required")
    before, raw_files = snapshot_tree()
    require("summary.json" in raw_files and len(raw_files["summary.json"]) == 20498
            and sha(raw_files["summary.json"]) == CONFIG["summary_sha"], "wrong closed run summary")
    summary = json.loads(raw_files["summary.json"])
    require(summary["status"] == "passed" and summary["head"] == EXPECTED_HEAD and summary["tree"] == EXPECTED_TREE,
            "wrong component source or result")
    require(summary["source_before_after_verified"] is True and summary["owned_process_termination_unknown"] is False
            and type(summary["worker_test_exit"]) is int and summary["worker_test_exit"] == 0
            and summary["errors"] == [], "original run did not complete cleanly")
    require(len(summary["steps"]) == 12, "unexpected original step count")
    expected_paths = {"summary.json", "source-before.json", "source-after.json",
                      "artifact-source-before.json", "artifact-source-after.json", "test-outcomes.json"}
    for step in summary["steps"]:
        require(type(step["exit"]) is int and step["exit"] == 0 and step["owned_process_terminated"] is True
                and step["timed_out"] is False, "nonzero or unconfirmed original step")
        for channel in ("stdout", "stderr"):
            original = pathlib.Path(step[channel + "_path"])
            require(original.parent == SOURCE, "step stream outside closed result directory")
            relative = original.name
            expected_paths.add(relative)
            require(relative in raw_files and type(step[channel + "_bytes"]) is int
                    and len(raw_files[relative]) == step[channel + "_bytes"]
                    and sha(raw_files[relative]) == step[channel + "_sha256"], "step original bytes differ")
    require(expected_paths <= set(raw_files), "required originals missing")
    for name in ("source-before.json", "source-after.json", "verify-source-before.stdout", "verify-source-after.stdout"):
        require(len(raw_files[name]) == 423 and sha(raw_files[name]) == CONFIG["source_sha"], "source receipt differs")
    identity = json.loads(raw_files["source-before.json"])
    require(len(identity) == 11 and identity["tested_commit"] == EXPECTED_HEAD and identity["candidate"] == EXPECTED_HEAD
            and identity["tested_tree"] == EXPECTED_TREE and identity["tracked_worktree_verified"] is True
            and identity["tests_executed_by_identity_check"] is False
            and type(identity["tracked_entries"]) is int and identity["tracked_entries"] == 41677
            and type(identity["tracked_bytes"]) is int and identity["tracked_bytes"] == 3994947385, "actual source scope differs")
    driver_raw, driver_identity = read_regular(DRIVER)
    require(len(driver_raw) == 19501 and sha(driver_raw) == CONFIG["driver_sha"]
            and summary["driver"] == {"path": str(DRIVER), "sha256": CONFIG["driver_sha"]}, "actual driver differs")
    source_tree = ast.parse(driver_raw.decode("utf-8"))
    declarations = {node.targets[0].id: node.value for node in source_tree.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    names = ast.literal_eval(declarations["EXPECTED_TESTS"])
    require(len(names) == len(set(names)) == 10 and names[-2:] == (
        "audit::artifact::tests::validation_to_lock_permission_change_is_refused",
        "audit::artifact::tests::validation_to_lock_hardlink_change_is_refused"), "ten-name literal differs")
    test_raw = raw_files["worker-artifact-tests.stdout"]
    require(len(test_raw) == 1134 and sha(test_raw) == CONFIG["test_stdout_sha"], "actual test stdout differs")
    require(len(raw_files["test-outcomes.json"]) == 2650 and sha(raw_files["test-outcomes.json"]) == CONFIG["test_outcomes_sha"],
            "original outcome receipt differs")
    events = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ok\s*$", test_raw.decode(), re.MULTILINE)
    require(collections.Counter(events) == collections.Counter(names), "actual ten named ok events differ")
    require(re.search(r"^test result: ok\. 10 passed; 0 failed; 0 ignored; 0 measured; 373 filtered out;", test_raw.decode(), re.MULTILINE),
            "actual harness summary differs")
    artifact_before = json.loads(raw_files["artifact-source-before.json"])
    require(raw_files["artifact-source-before.json"] == raw_files["artifact-source-after.json"]
            and artifact_before == {"path": "trillionnium/crates/trnm-worker-agent/src/audit/artifact.rs", "bytes": 12283,
                                    "sha256": "12396ec45e2b059d588f7d00feb9f19cc557389e37be0053d9ff5f344825f3cc",
                                    "git_blob": "f021a33e2969305241099998f703172d29b15251"}, "actual artifact identity differs")
    terminal = json.loads(CONFIG["terminal_receipt"])
    require(terminal["offset"] == 0 and terminal["next_offset"] == terminal["available_end"] == 1382
            and terminal["output_complete"] is True and terminal["status"]["state"] == "exited"
            and type(terminal["status"]["exit_code"]) is int and terminal["status"]["exit_code"] == 0
            and terminal["truncated_before_offset"] is False and terminal["text_is_lossy"] is False, "original terminal is incomplete")
    terminal_raw = bytes.fromhex(terminal["bytes_hex"])
    require(len(terminal_raw) == 1382 and sha(terminal_raw) == terminal["chunk_sha256"]
            == "b9b1e420c96b6b92c5f659a331d3dee00fbdee7525b803d05425e7944c9af234", "original terminal bytes differ")
    producer_path = pathlib.Path(__file__).resolve(strict=True)
    producer_raw, producer_identity = read_regular(producer_path)
    DEST.mkdir(mode=0o700, exist_ok=False)
    members, entries = {}, []
    def add(name, raw, origin):
        require(name not in members, "duplicate member")
        write_new(name, raw)
        members[name] = raw
        entries.append({"path": name, "bytes": len(raw), "sha256": sha(raw), "origin": origin})
    for relative, raw in sorted(raw_files.items()):
        add("originals/" + relative, raw, {"host": "rog", "path": str(SOURCE / relative)})
    add("driver/run_final_rog_worker_artifact_existing_source_v2.py.original", driver_raw, {"host": "rog", "path": str(DRIVER)})
    add("producer/package_closed_worker_artifact_ed0d35_v1.py.original", producer_raw, {"host": "rog", "path": str(producer_path)})
    receipt_path = DEST / "terminal/original-worker-pty-receipt.json"
    add("terminal/original-worker-pty-receipt.json", CONFIG["terminal_receipt"].encode(),
        {"host": "rog", "path": str(receipt_path)})
    add("terminal/original-worker-pty.stdout", terminal_raw, {"host": "rog", "path": terminal["archive_path"]})
    after, after_raw = snapshot_tree()
    require(after == before and after_raw == raw_files, "closed original directory changed during capture")
    require(read_regular(DRIVER) == (driver_raw, driver_identity), "worker driver changed")
    require(read_regular(producer_path) == (producer_raw, producer_identity), "packaging producer changed")
    closure = {
        "schema": "trnm-closed-worker-artifact-component-closure-v1",
        "source_directory": str(SOURCE), "original_file_count": before["file_count"], "original_bytes": before["total_bytes"],
        "all_original_files_included": True, "extra_original_paths": sorted(set(raw_files) - expected_paths),
        "source_directory_snapshot_before": before, "source_directory_snapshot_after": after,
        "all_original_content_and_identity_equal": True, "all_named_directory_identities_equal": True,
        "head": EXPECTED_HEAD, "tree": EXPECTED_TREE, "original_step_count": 12, "all_original_step_exits_zero": True,
        "actual_command_seconds": {x["label"]: x["elapsed_seconds"] for x in summary["steps"]
                                  if x["label"] in ("workspace-format", "worker-strict-clippy", "worker-artifact-tests")},
        "actual_test_names": list(names), "actual_harness": {"passed": 10, "failed": 0, "ignored": 0, "measured": 0, "unrelated_filtered": 373},
        "source_identity": identity, "selected_artifact": artifact_before,
        "original_terminal": {"session_id": terminal["session_id"], "offset": 0, "bytes": 1382, "sha256": sha(terminal_raw),
                              "exit_code": 0, "output_complete": True, "acquisition": "official h_pty_read complete original output"},
        "capture_scope": "All regular single-link files in the exact closed directory, its exact actual driver, complete packaging producer and original terminal receipt; no exclusions.",
        "tests_driver_or_helpers_rerun": False, "source_or_git_or_stage_or_configuration_mutated": False,
        "hosted_or_four_second_qualification_claimed": False,
    }
    add("closure.json", canonical(closure), {"host": "rog", "path": str(DEST / "closure.json")})
    readme = ("Closed original Linux worker component evidence for M8 ed0d35487f2a67239e4d646fd41c2c7acb5cc740.\n"
              "All 12 original steps exited zero; workspace format, worker strict Clippy and ten real module tests passed.\n"
              "The two validation_to_lock controls executed; 373 unrelated tests were filtered, no required test ignored.\n"
              "This packaging operation reran no test, driver, source helper, Git or Host workload. It did not write source or stage.\n"
              "This component result is not hosted or 4-second/16-worker confirmation qualification.\n"
              "EVIDENCE_INDEX.json binds every payload member except itself; package-summary.json binds the complete ZIP and all CRC/SHA checks.\n")
    add("README.txt", readme.encode(), {"host": "rog", "path": str(DEST / "README.txt")})
    index = {"schema": "trnm-closed-worker-artifact-originals-index-v1", "file_count": len(entries),
             "total_bytes": sum(x["bytes"] for x in entries), "files": sorted(entries, key=lambda x: x["path"]),
             "index_self_excluded": True, "original_directory_file_count": before["file_count"], "byte_cap": CAP}
    index_raw = canonical(index)
    write_new("EVIDENCE_INDEX.json", index_raw)
    members["EVIDENCE_INDEX.json"] = index_raw
    require(sum(map(len, members.values())) <= CAP, "complete package payload exceeds 32 MiB")
    archive = DEST / "closed-worker-artifact-ed0d35-v1.zip"
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for name, raw in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
    member_checks = []
    with zipfile.ZipFile(archive, "r") as opened:
        require(opened.namelist() == sorted(members) and opened.testzip() is None, "ZIP roster/CRC verification failed")
        for item in opened.infolist():
            raw = opened.read(item.filename)
            expected = members[item.filename]
            require(not item.is_dir() and stat.S_ISREG(item.external_attr >> 16)
                    and item.file_size == len(expected) and raw == expected
                    and item.CRC == (zlib.crc32(expected) & 0xffffffff), "ZIP member differs")
            member_checks.append({"path": item.filename, "bytes": len(raw), "sha256": sha(raw), "crc32": item.CRC})
    final_snapshot, final_bytes = snapshot_tree()
    require(final_snapshot == before and final_bytes == raw_files, "original inputs changed while verifying archive")
    require(read_regular(DRIVER) == (driver_raw, driver_identity), "driver changed at closure")
    zip_raw, zip_identity = read_regular(archive)
    output_summary = {
        "schema": "trnm-closed-worker-artifact-package-summary-v1", "status": "CLOSED_ORIGINALS_PACKAGED_AND_VERIFIED",
        "original_directory": str(SOURCE), "original_file_count": before["file_count"], "original_bytes": before["total_bytes"],
        "unexpected_original_paths_included": sorted(set(raw_files) - expected_paths),
        "driver_bytes": len(driver_raw), "driver_sha256": sha(driver_raw),
        "packaging_producer_bytes": len(producer_raw), "packaging_producer_sha256": sha(producer_raw),
        "payload_file_count": len(entries), "payload_bytes": sum(x["bytes"] for x in entries),
        "index": {"path": str(DEST / "EVIDENCE_INDEX.json"), "bytes": len(index_raw), "sha256": sha(index_raw)},
        "zip": {"path": str(archive), "bytes": len(zip_raw), "sha256": sha(zip_raw), "identity": zip_identity},
        "zip_member_count": len(member_checks), "member_checks": member_checks,
        "source_content_and_all_file_directory_identities_unchanged": True,
        "tests_or_source_helpers_or_git_or_host_executed": False, "stage_written": False,
    }
    summary_raw = canonical(output_summary)
    write_new("package-summary.json", summary_raw)
    print(json.dumps({"status": output_summary["status"], "original_file_count": before["file_count"],
                      "original_bytes": before["total_bytes"], "zip": output_summary["zip"],
                      "index": output_summary["index"], "zip_member_count": len(member_checks),
                      "summary_path": str(DEST / "package-summary.json"), "summary_sha256": sha(summary_raw)}, sort_keys=True))

if __name__ == "__main__":
    main()
