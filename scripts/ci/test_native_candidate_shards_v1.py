#!/usr/bin/env python3
"""Exercise shard admission, execution accounting and actual process cleanup."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import run_native_candidate_shards_v1 as runner

NATIVE_IGNORED = {
    runner.BRIDGE + "historical_replay_continuation_sigkill_child",
    runner.BRIDGE + "historical_replay_install_sigkill_child",
    runner.BRIDGE + "later_descendant_c22_sigkill_child",
    runner.PRE_HANDOFF + "sigkill_child",
}
SAFETY_IGNORED = {
    "journal10_initialization_crash_child",
    "journal10_post_initial_crash_child",
    "journal11_sigkill_child",
    "journal12::journal12_sigkill_child",
}

SAFETY_NAMES = sorted(["future_journal_case", *SAFETY_IGNORED, *runner.SAFETY_REQUIRED_DRIVERS])

NODE_NAMES = sorted(["ordinary::new_test", runner.NODE_EPOCH_PREFIX + "future_runtime", *runner.NODE_REQUIRED_DRIVERS])

NAMES = sorted([
    "ordinary::new_test", runner.BRIDGE + "historical_install_is_atomic",
    runner.BRIDGE + "historical_receiver_c33_is_strict", runner.SCHEMA7 + "selects_branch",
    runner.PRE_HANDOFF + "commits_before_joint_and_attaches_after_cold_recovery",
    runner.POCO_SIGKILL, *NATIVE_IGNORED, *runner.REQUIRED_SIGKILL_DRIVERS,
])


def process_state(pid: int) -> str | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        # procfs may disappear even after open() succeeds when PID1 reaps
        # the killed child. Other read failures must remain visible.
        return None
    return raw.rsplit(") ", 1)[1].split()[0]


class NativeCandidateShardTests(unittest.TestCase):
    def make_workspace(self, base: Path, suite: str = "native") -> tuple[Path, Path]:
        package, _, _ = runner.SUITES[suite]
        ignored = {"native": NATIVE_IGNORED, "safety-epoch": SAFETY_IGNORED, "node-epoch": set()}[suite]
        names = {"node-epoch": NODE_NAMES, "safety-epoch": SAFETY_NAMES}.get(suite, NAMES)
        target_kind = "test" if suite == "safety-epoch" else "lib"
        target_name = "epoch_journal_v2" if suite == "safety-epoch" else package.replace("-", "_")
        relative_source = "tests/epoch_journal_v2.rs" if suite == "safety-epoch" else "src/lib.rs"
        repo = base / "repo"
        source = repo / "trillionnium/crates" / package / relative_source
        source.parent.mkdir(parents=True)
        source.write_text("// fake source used only by runner tests\n")
        for args in (["init", "-q"], ["add", "."], ["-c", "user.name=Runner test", "-c", "user.email=test@invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]):
            subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
        bin_dir = base / "bin"
        bin_dir.mkdir()
        executable = bin_dir / "fake-native"
        executable_text = f"#!{sys.executable} -S\n" + f"NAMES={names!r}\nIGNORED={sorted(ignored)!r}\n" + '''
import os, pathlib, sys
assert 'RUST_MIN_STACK' not in os.environ
case = os.environ.get('SHARD_TEST_CASE', '')
args = sys.argv[1:]
ignored = set(IGNORED)
if case == 'extra-ignored':
    ignored.add(next(name for name in NAMES if name not in ignored))
if case == 'extra-dedicated-child':
    NAMES.append('ordinary::future_sigkill_child')
    ignored.add('ordinary::future_sigkill_child')
pre_handoff_driver = 'later_epoch_checkpoint_bridge::tests::later_pre_handoff_sigkill_commit_and_attach_cuts_preserve_original_evidence'
if case == 'missing-safety-driver':
    NAMES.remove('journal12::journal12_six_sigkill_cuts_keep_actual_source_and_prefix')
if case == 'missing-v8':
    NAMES.remove('epoch_runtime_candidate_v1::tests::actual_epoch_handoff_joint_attachment_and_exact_retry_v8')
if case == 'missing-v9-positive':
    NAMES.remove('epoch_runtime_candidate_v1::tests::actual_epoch_successor_activation_preserves_owners_and_initial_ack_v9')
if case == 'missing-v9-callback':
    NAMES.remove('epoch_runtime_candidate_v1::tests::actual_epoch_successor_activation_after_write_callback_blocks_ack_v9')
if case == 'missing-node-driver':
    NAMES.remove('epoch_runtime_candidate_v1::tests::actual_epoch_seals_apply_original_fronts_then_commit_unattached_pre_handoff_v5')
if case == 'missing-pre-handoff-driver':
    NAMES.remove(pre_handoff_driver)
if case == 'ignored-pre-handoff-driver':
    ignored.add(pre_handoff_driver)
skips, filters = [], []
i = 0
while i < len(args):
    if args[i] == '--skip':
        skips.append(args[i + 1]); i += 2; continue
    if not args[i].startswith('--'):
        filters.append(args[i])
    i += 1
selected = [name for name in NAMES if (not filters or any(x == name if '--exact' in args else x in name for x in filters)) and not any(x in name for x in skips)]
if '--ignored' in args:
    selected = [name for name in selected if name in ignored]
if '--list' in args:
    if case == 'list-failure':
        raise SystemExit(7)
    if case == 'filtered-mismatch' and skips:
        selected = selected[:-1]
    print(''.join(name + ': test\\n' for name in selected), end='')
    raise SystemExit(0)
if case == 'check-progress':
    import json
    progress = json.loads(pathlib.Path(os.environ['SHARD_EVIDENCE_DIR'], 'summary.json').read_text())
    assert progress['status'] == 'failed'
    rows = progress['shards']
    assert sorted(name for row in rows.values() for name in row['tests']) == NAMES
    current = [key for key, row in rows.items() if row['status'] == 'running']
    assert len(current) == 1
    assert rows[current[0]]['tests'] == selected
    assert progress['invocations'][current[0]]['status'] == 'running'
    assert rows[current[0]]['exit_code'] is None
    assert all(row['exit_code'] is None for row in rows.values() if row['status'] == 'not-run')
if selected == ['ordinary::new_test']:
    if case == 'first-timeout':
        import time
        print('first-shard-before-timeout', flush=True)
        time.sleep(30)
    if case in ('first-failure', 'first-failure-and-source-change', 'nonzero-success-summary'):
        if case == 'first-failure-and-source-change':
            pathlib.Path('../untracked-during-test').write_text('changed')
        if case == 'nonzero-success-summary':
            print(f'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {len(NAMES)-1} filtered out; finished in 0.02s')
        raise SystemExit(23)
    if case == 'first-no-summary':
        print('no parent summary')
        raise SystemExit(0)
if case == 'no-summary':
    print('test process exited without a final parent summary')
    raise SystemExit(0)
if case == 'source-change':
    pathlib.Path('../untracked-during-test').write_text('changed')
if case == 'binary-change':
    with open(__file__, 'a') as f:
        f.write('\\n# changed during execution\\n')
passed = len([name for name in selected if name not in ignored])
if case == 'wrong-count':
    passed = max(0, passed - 1)
print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s')
print(f'test result: ok. {passed} passed; 0 failed; {len(set(selected) & ignored)} ignored; 0 measured; {len(NAMES)-len(selected)} filtered out; finished in 0.02s')
'''
        executable.write_text(executable_text)
        executable.chmod(0o755)
        release_executable = bin_dir / "fake-native-release"
        release_executable.write_text(executable_text)
        release_executable.chmod(0o755)
        cargo = bin_dir / "cargo"
        cargo.write_text(f"#!{sys.executable} -S\n" + f"EXE={str(executable)!r}\nRELEASE_EXE={str(release_executable)!r}\nPACKAGE={package!r}\nTARGET_KIND={target_kind!r}\nTARGET_NAME={target_name!r}\nRELATIVE_SOURCE={relative_source!r}\n" + '''
import json, os, pathlib, sys
if os.environ.get('SHARD_TEST_CASE') == 'compile-failure':
    raise SystemExit(9)
if os.environ.get('SHARD_TEST_CASE') == 'foreign-package':
    PACKAGE = 'trnm-native-execution-v0'
executable = RELEASE_EXE if '--release' in sys.argv else EXE
print(json.dumps({'reason':'compiler-artifact', 'target':{'name':TARGET_NAME, 'kind':[TARGET_KIND], 'src_path':str(pathlib.Path.cwd() / 'crates' / PACKAGE / RELATIVE_SOURCE)}, 'profile':{'test':True}, 'executable':executable}))
''')
        cargo.chmod(0o755)
        return repo, bin_dir

    def invoke(self, base: Path, case: str = "", suite: str = "native", deadline: int = 30) -> tuple[int, dict, Path]:
        repo, bin_dir = self.make_workspace(base, suite)
        evidence = base / "evidence"
        if case == "dirty-source":
            (repo / "untracked-before-test").write_text("untracked")
        env = {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"], "SHARD_TEST_CASE": case, "RUST_MIN_STACK": "99999999", "SHARD_EVIDENCE_DIR": str(evidence)}
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        env["TRNM_EXPECTED_SOURCE_SHA"] = "0" * 40 if case == "wrong-source-pin" else head
        with patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = runner.run(["--suite", suite, "--workspace", str(repo / "trillionnium"), "--evidence-dir", str(evidence), "--deadline-seconds", str(deadline)])
        return code, json.loads((evidence / "summary.json").read_text()), evidence

    def test_actual_fake_libtest_execution_covers_inventory_and_children(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, _ = self.invoke(Path(directory))
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(set(summary["shards"]), set(runner.SHARD_NAMES))
        counts = [entry["counts"] for entry in summary["shards"].values()]
        self.assertEqual(sum(entry["passed"] for entry in counts), len(NAMES) - 4)
        self.assertEqual(sum(entry["ignored"] for entry in counts), 4)
        pre_handoff = summary["shards"]["later-pre-handoff"]["counts"]
        self.assertEqual((pre_handoff["passed"], pre_handoff["ignored"]), (2, 1))
        self.assertRegex(summary["executable_sha256"], r"^[0-9a-f]{64}$")

    def test_node_epoch_profile_executes_every_discovered_case_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, evidence = self.invoke(Path(directory), suite="node-epoch")
            self.assertEqual(code, 0)
            self.assertEqual(summary["package"], "trnm-poco-node")
            self.assertEqual(summary["features"], "epoch-runtime-test-fixtures")
            self.assertIn(
                "--release", (evidence / "compile-release.command").read_text()
            )
            self.assertRegex(
                summary["release_executable_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertEqual(set(summary["release_cases"]), runner.NODE_RELEASE_CASES)
            inventory = json.loads((evidence / "inventory.json").read_text())
            self.assertEqual(sorted(sum(inventory.values(), [])), NODE_NAMES)
            self.assertEqual(inventory["general"], ["ordinary::new_test"])
            counts = [entry["counts"] for entry in summary["shards"].values()]
            self.assertEqual(sum(entry["passed"] for entry in counts), len(NODE_NAMES))
            self.assertEqual(sum(entry["ignored"] for entry in counts), 0)
            for shard in inventory:
                if shard != "general":
                    self.assertEqual(len(inventory[shard]), 1)
                    self.assertIn("--exact", (evidence / (shard + ".command")).read_text())
                expected_deadline = runner.NODE_CASE_DEADLINES.get(
                    inventory[shard][0], 30
                )
                self.assertEqual(
                    summary["shards"][shard]["deadline_seconds"], expected_deadline
                )
                expected_profile = (
                    "release"
                    if len(inventory[shard]) == 1
                    and inventory[shard][0] in runner.NODE_RELEASE_CASES
                    else "dev"
                )
                self.assertEqual(
                    summary["shards"][shard]["profile"], expected_profile
                )
                if expected_profile == "release":
                    self.assertIn(
                        "fake-native-release",
                        (evidence / (shard + ".command")).read_text(),
                    )

    def test_full_epoch_case_budgets_are_explicit_and_required(self) -> None:
        self.assertEqual(len(runner.NODE_CASE_DEADLINES), 4)
        self.assertEqual(
            runner.NODE_RELEASE_CASES,
            {
                runner.NODE_EPOCH_PREFIX
                + "actual_successor_core_finalizes_and_applies_first_new_v11"
            },
        )
        for name in runner.NODE_CASE_DEADLINES:
            self.assertEqual(runner.shard_deadline("node-epoch", [name], 300), 600)
            self.assertEqual(runner.shard_deadline("native", [name], 900), 900)
            self.assertEqual(runner.shard_deadline("safety-epoch", [name], 900), 900)
            self.assertEqual(runner.shard_deadline("node-epoch", [name + "_extra"], 300), 300)
        self.assertEqual(runner.shard_deadline("node-epoch", ["ordinary::new_test"], 300), 300)
        self.assertEqual(runner.shard_deadline("node-epoch", list(runner.NODE_CASE_DEADLINES), 300), 300)
        for case in ("missing-v8", "missing-v9-positive", "missing-v9-callback"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, _ = self.invoke(Path(directory), case, "node-epoch")
                self.assertNotEqual(code, 0)
                self.assertEqual(summary["status"], "failed")

    def test_safety_integration_profile_preserves_all_cases_and_actual_child_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, evidence = self.invoke(Path(directory), suite="safety-epoch")
            self.assertEqual(code, 0)
            self.assertEqual(summary["package"], "trnm-consensus-safety-store")
            inventory = json.loads((evidence / "inventory.json").read_text())
            self.assertEqual(sorted(sum(inventory.values(), [])), SAFETY_NAMES)
            self.assertTrue(all(len(names) == 1 for names in inventory.values()))
            self.assertIn("--all-features --test epoch_journal_v2", (evidence / "compile.command").read_text())
            counts = [entry["counts"] for entry in summary["shards"].values()]
            self.assertEqual(sum(entry["passed"] for entry in counts), len(SAFETY_NAMES) - 4)
            self.assertEqual(sum(entry["ignored"] for entry in counts), 4)
        for case in ("foreign-package", "missing-safety-driver", "extra-ignored", "wrong-count"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, _ = self.invoke(Path(directory), case, suite="safety-epoch")
                self.assertNotEqual(code, 0)
                self.assertEqual(summary["status"], "failed")

    def test_node_epoch_profile_refuses_wrong_binary_missing_driver_or_ignored_case(self) -> None:
        for case in ("foreign-package", "missing-node-driver", "extra-ignored", "wrong-count", "filtered-mismatch"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, _ = self.invoke(Path(directory), case, suite="node-epoch")
                self.assertNotEqual(code, 0)
                self.assertEqual(summary["status"], "failed")

    def test_new_dedicated_crash_child_does_not_require_runner_inventory_edit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, _ = self.invoke(Path(directory), "extra-dedicated-child")
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["shards"]["general"]["ignored_count"], 1)

    def test_execution_failures_never_publish_success(self) -> None:
        for case in ("compile-failure", "list-failure", "filtered-mismatch", "extra-ignored", "missing-pre-handoff-driver", "ignored-pre-handoff-driver", "no-summary", "wrong-count", "dirty-source", "source-change", "binary-change", "wrong-source-pin"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, evidence = self.invoke(Path(directory), case)
                self.assertNotEqual(code, 0)
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["exit_code"], code)
                if case in ("dirty-source", "wrong-source-pin"):
                    self.assertFalse((evidence / "compile.command").exists())
                if case == "list-failure":
                    self.assertEqual((evidence / "inventory.exit-code").read_text().strip(), "7")
                if case in ("missing-pre-handoff-driver", "ignored-pre-handoff-driver"):
                    self.assertNotIn("shards", summary)
                    expected_error = (
                        "required SIGKILL drivers are missing or ignored"
                        if case == "missing-pre-handoff-driver"
                        else (
                            "ignored inventory contains non-dedicated crash tests: "
                            + runner.PRE_HANDOFF
                            + "sigkill_commit_and_attach_cuts_preserve_original_evidence"
                        )
                    )
                    self.assertEqual(summary["error"], expected_error)
                    self.assertFalse(any((evidence / f"{shard}.command").exists() for shard in runner.SHARD_NAMES))

    def test_first_failure_retained_while_all_later_shards_execute(self) -> None:
        for suite in ("native", "node-epoch"):
            with self.subTest(suite=suite), tempfile.TemporaryDirectory() as directory:
                code, summary, evidence = self.invoke(Path(directory), "first-failure", suite)
                self.assertEqual(code, 23)
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["shards"]["general"]["status"], "failed")
                self.assertNotIn("counts", summary["shards"]["general"])
                for name, row in summary["shards"].items():
                    self.assertTrue((evidence / (name + ".exit-code")).exists())
                    self.assertGreaterEqual(row["elapsed_ms"], 0)
                    if name != "general":
                        self.assertEqual(row["status"], "passed")
                        self.assertEqual(row["exit_code"], 0)

    def test_zero_exit_without_summary_is_failed_but_not_a_later_test_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, _ = self.invoke(Path(directory), "first-no-summary")
        self.assertEqual(code, 2)
        first = summary["shards"]["general"]
        self.assertEqual(first["exit_code"], 0)
        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["error"], "native shard produced no top-level test result")
        self.assertTrue(all(row["status"] == "passed" for name, row in summary["shards"].items() if name != "general"))

    def test_nonzero_exit_cannot_claim_successful_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, _ = self.invoke(Path(directory), "nonzero-success-summary")
        self.assertEqual(code, 23)
        self.assertEqual(summary["shards"]["general"]["status"], "failed")
        self.assertNotIn("counts", summary["shards"]["general"])
        self.assertEqual(summary["shards"]["poco-sigkill"]["status"], "passed")

    def test_actual_timeout_continues_without_changing_deadline_or_hiding_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, evidence = self.invoke(Path(directory), "first-timeout", deadline=1)
            self.assertIn("first-shard-before-timeout", (evidence / "general.log").read_text())
            self.assertIn("TIMEOUT", (evidence / "general.log").read_text())
        self.assertEqual(code, 124)
        first = summary["shards"]["general"]
        self.assertEqual((first["status"], first["exit_code"], first["deadline_seconds"]), ("failed", 124, 1))
        self.assertTrue(all(row["status"] == "passed" for name, row in summary["shards"].items() if name != "general"))
        self.assertGreaterEqual(first["elapsed_ms"], 1000)

    def test_source_or_binary_change_stops_later_shards_even_after_failure(self) -> None:
        for case in ("source-change", "binary-change", "first-failure-and-source-change"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, evidence = self.invoke(Path(directory), case)
                self.assertNotEqual(code, 0)
                self.assertEqual(summary["shards"]["general"]["status"], "failed")
                for name, row in summary["shards"].items():
                    if name != "general":
                        self.assertEqual(row["status"], "not-run")
                        self.assertIsNone(row["exit_code"])
                        self.assertFalse((evidence / (name + ".command")).exists())

    def test_checkpoint_is_failed_with_full_inventory_before_each_actual_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, evidence = self.invoke(Path(directory), "check-progress")
            self.assertFalse((evidence / ".summary.json.tmp").exists())
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "passed")
        self.assertTrue(all(row["status"] == "passed" for row in summary["shards"].values()))
        self.assertEqual(summary["invocations"]["compile"]["exit_code"], 0)

    def test_reusing_evidence_refuses_without_changing_previous_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence = base / "evidence"
            evidence.mkdir()
            old = b'{"status":"passed"}\n'
            (evidence / "summary.json").write_bytes(old)
            with self.assertRaises(runner.ShardError):
                runner.run(["--workspace", str(base), "--evidence-dir", str(evidence)])
            self.assertEqual({p.name: p.read_bytes() for p in evidence.iterdir()}, {"summary.json": old})

    def test_inventory_and_summary_admission(self) -> None:
        self.assertEqual(runner.classify_test("new_module::new_test"), "general")
        self.assertEqual(runner.classify_test(runner.PRE_HANDOFF + "future_test"), "later-pre-handoff")
        partitions = runner.partition_inventory(iter(NAMES))
        self.assertEqual(sorted(sum(partitions.values(), [])), NAMES)
        self.assertEqual(partitions["later-pre-handoff"], [name for name in NAMES if name.startswith(runner.PRE_HANDOFF)])
        self.assertFalse(any(name.startswith(runner.PRE_HANDOFF) for name in partitions["later-bridge"]))
        for raw in ("a: test\na: test\n", "", ": test\n"):
            with self.assertRaises(runner.ShardError):
                runner.parse_test_inventory(raw)
        with self.assertRaises(runner.ShardError):
            runner.partition_inventory(["general::alone"])
        for raw in ("missing", "test result: ok. wrong", "test result: FAILED. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"):
            with self.assertRaises(runner.ShardError):
                runner.parse_test_summary(raw)

    def test_executable_must_be_exact_native_test_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            item = {"reason": "compiler-artifact", "target": {"name": "trnm_native_execution_v0", "kind": ["lib"], "src_path": str(root / "crates/trnm-native-execution-v0/src/lib.rs")}, "profile": {"test": True}, "executable": str(root / "native")}
            self.assertEqual(runner.find_executable([json.dumps(item)], root), root / "native")
            with self.assertRaises(runner.ShardError):
                runner.find_executable([json.dumps(item), json.dumps(item)], root)
            item["target"]["src_path"] = str(root / "foreign/trnm-native-execution-v0/src/lib.rs")
            with self.assertRaises(runner.ShardError):
                runner.find_executable([json.dumps(item)], root)

    def test_timeout_reaps_parent_and_kills_term_ignoring_pipe_holder(self) -> None:
        for close_pipes in (False, True):
            with self.subTest(close_pipes=close_pipes):
                child = "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('READY:'+str(os.getpid()),flush=True); "
                if close_pipes:
                    child += "fd=os.open(os.devnull,os.O_WRONLY); os.dup2(fd,1); os.dup2(fd,2); os.close(fd); "
                child += "time.sleep(30)"
                parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-S','-c',{child!r}]); time.sleep(30)"
                start = time.monotonic()
                with tempfile.TemporaryDirectory() as directory:
                    output, code = runner.run_bounded([sys.executable, "-S", "-c", parent], cwd=Path(directory), env=os.environ.copy(), timeout=1)
                self.assertEqual(code, 124)
                self.assertLess(time.monotonic() - start, 12)
                self.assertIn("TIMEOUT", output)
                ready = next(line for line in output.splitlines() if line.startswith("READY:"))
                child_pid = int(ready.split(":")[1])
                until = time.monotonic() + 1
                state = process_state(child_pid)
                while state not in (None, "Z") and time.monotonic() < until:
                    time.sleep(0.01)
                    state = process_state(child_pid)
                self.assertIn(state, (None, "Z"), "owned child is still running")

    def test_cleanup_observation_handles_reaping_without_hiding_other_failures(self) -> None:
        for error in (FileNotFoundError(), ProcessLookupError()):
            with self.subTest(error=type(error).__name__), patch.object(Path, "read_text", side_effect=error):
                self.assertIsNone(process_state(123))
        with patch.object(Path, "read_text", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                process_state(123)
        for state in ("S", "R", "Z"):
            with patch.object(Path, "read_text", return_value=f"123 (child) {state} 1 2"):
                self.assertEqual(process_state(123), state)


if __name__ == "__main__":
    unittest.main()
