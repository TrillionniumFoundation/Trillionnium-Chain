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

SAFETY_NAMES = sorted(["future_journal_case", *runner.SAFETY_IGNORED, *runner.SAFETY_REQUIRED_DRIVERS])

NODE_NAMES = sorted(["ordinary::new_test", runner.NODE_EPOCH_PREFIX + "future_runtime", *runner.NODE_REQUIRED_DRIVERS])

NAMES = sorted([
    "ordinary::new_test", runner.BRIDGE + "historical_install_is_atomic",
    runner.BRIDGE + "historical_receiver_c33_is_strict", runner.SCHEMA7 + "selects_branch",
    runner.PRE_HANDOFF + "commits_before_joint_and_attaches_after_cold_recovery",
    runner.POCO_SIGKILL, *runner.ALLOWED_IGNORED, *runner.REQUIRED_SIGKILL_DRIVERS,
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
        package, _, ignored, _ = runner.SUITES[suite]
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
        executable.write_text(f"#!{sys.executable} -S\n" + f"NAMES={names!r}\nIGNORED={sorted(ignored)!r}\n" + '''
import os, pathlib, sys
assert 'RUST_MIN_STACK' not in os.environ
case = os.environ.get('SHARD_TEST_CASE', '')
args = sys.argv[1:]
ignored = set(IGNORED)
if case == 'extra-ignored':
    ignored.add(next(name for name in NAMES if name not in ignored))
pre_handoff_driver = 'later_epoch_checkpoint_bridge::tests::later_pre_handoff_sigkill_commit_and_attach_cuts_preserve_original_evidence'
if case == 'missing-safety-driver':
    NAMES.remove('journal12::journal12_six_sigkill_cuts_keep_actual_source_and_prefix')
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
    if case == 'inventory-source-change' and selected == ['ordinary::new_test']:
        pathlib.Path('../untracked-from-inventory').write_text('changed')
    print(''.join(name + ': test\\n' for name in selected), end='')
    raise SystemExit(0)
execution_record = pathlib.Path(__file__).with_name('executed.jsonl')
with execution_record.open('a') as record:
    record.write(__import__('json').dumps(selected) + '\\n')
if selected == ['ordinary::new_test']:
    if case in ('first-failure', 'two-failures'):
        print('original failure: 17', flush=True)
        raise SystemExit(17)
    if case == 'timeout-first':
        print('original timeout started', flush=True)
        __import__('time').sleep(10)
    if case == 'source-change-failure':
        pathlib.Path('../untracked-during-test').write_text('changed')
        raise SystemExit(17)
    if case == 'binary-change-failure':
        with open(__file__, 'a') as changed:
            changed.write('\\n# substituted executable\\n')
        raise SystemExit(18)
    if case == 'empty-first':
        raise SystemExit(0)
    if case == 'counts-first':
        print('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s')
        raise SystemExit(0)
if case == 'two-failures' and selected != ['ordinary::new_test']:
    raise SystemExit(19)
if case == 'checkpoint-visible':
    snapshot = __import__('json').loads(pathlib.Path(os.environ['SHARD_TEST_EVIDENCE'], 'summary.json').read_text())
    assert snapshot['status'] != 'passed'
    assert snapshot['shards'][snapshot['phase']]['status'] == 'running'
    assert snapshot['shards'][snapshot['phase']]['tests'] == selected
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
''')
        executable.chmod(0o755)
        cargo = bin_dir / "cargo"
        cargo.write_text(f"#!{sys.executable} -S\n" + f"EXE={str(executable)!r}\nPACKAGE={package!r}\nTARGET_KIND={target_kind!r}\nTARGET_NAME={target_name!r}\nRELATIVE_SOURCE={relative_source!r}\n" + '''
import json, os, pathlib, sys
if os.environ.get('SHARD_TEST_CASE') == 'compile-failure':
    raise SystemExit(9)
if os.environ.get('SHARD_TEST_CASE') == 'foreign-package':
    PACKAGE = 'trnm-native-execution-v0'
print(json.dumps({'reason':'compiler-artifact', 'target':{'name':TARGET_NAME, 'kind':[TARGET_KIND], 'src_path':str(pathlib.Path.cwd() / 'crates' / PACKAGE / RELATIVE_SOURCE)}, 'profile':{'test':True}, 'executable':EXE}))
''')
        cargo.chmod(0o755)
        return repo, bin_dir

    def invoke(self, base: Path, case: str = "", suite: str = "native") -> tuple[int, dict, Path]:
        repo, bin_dir = self.make_workspace(base, suite)
        evidence = base / "evidence"
        if case == "dirty-source":
            (repo / "untracked-before-test").write_text("untracked")
        env = {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"], "SHARD_TEST_CASE": case, "RUST_MIN_STACK": "99999999", "SHARD_TEST_EVIDENCE": str(evidence)}
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        env["TRNM_EXPECTED_SOURCE_SHA"] = "0" * 40 if case == "wrong-source-pin" else head
        with patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = runner.run(["--suite", suite, "--workspace", str(repo / "trillionnium"), "--evidence-dir", str(evidence), "--deadline-seconds", "30"])
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
                expected_deadline = runner.NODE_CASE_DEADLINES.get(inventory[shard][0], 30)
                self.assertEqual(summary["shards"][shard]["deadline_seconds"], expected_deadline)

    def test_v9_budget_is_exact_and_both_genuine_cases_are_required(self) -> None:
        self.assertEqual(len(runner.NODE_CASE_DEADLINES), 2)
        for name in runner.NODE_CASE_DEADLINES:
            self.assertEqual(runner.shard_deadline("node-epoch", [name], 300), 600)
            self.assertEqual(runner.shard_deadline("native", [name], 900), 900)
            self.assertEqual(runner.shard_deadline("safety-epoch", [name], 900), 900)
            self.assertEqual(runner.shard_deadline("node-epoch", [name + "_extra"], 300), 300)
        self.assertEqual(runner.shard_deadline("node-epoch", ["ordinary::new_test"], 300), 300)
        self.assertEqual(runner.shard_deadline("node-epoch", list(runner.NODE_CASE_DEADLINES), 300), 300)
        for case in ("missing-v9-positive", "missing-v9-callback"):
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
                        else "ignored inventory differs from dedicated SIGKILL children"
                    )
                    self.assertEqual(summary["error"], expected_error)
                    self.assertFalse(any((evidence / f"{shard}.command").exists() for shard in runner.SHARD_NAMES))

    def test_failed_shards_do_not_hide_remaining_execution(self) -> None:
        for case in ("first-failure", "two-failures", "empty-first", "counts-first"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                code, summary, evidence = self.invoke(base, case)
                expected_code = 17 if case in ("first-failure", "two-failures") else 2
                self.assertEqual(code, expected_code)
                self.assertEqual(summary["status"], "failed")
                executed = [json.loads(line) for line in (base / "bin/executed.jsonl").read_text().splitlines()]
                planned = json.loads((evidence / "inventory.json").read_text())
                self.assertEqual(executed, list(planned.values()))
                self.assertEqual(summary["first_failure"]["shard"], "general")
                self.assertEqual(summary["first_failure"]["exit_code"], expected_code)
                self.assertEqual(summary["shards"]["general"]["status"], "failed")
                self.assertTrue(summary["source_confirmed"])
                self.assertTrue(all(row["status"] in ("passed", "failed") for row in summary["shards"].values()))
                if case == "first-failure":
                    self.assertEqual(summary["failed_shards"], ["general"])
                    self.assertIn("original failure: 17", (evidence / "general.log").read_text())
                if case in ("empty-first", "counts-first"):
                    self.assertEqual(summary["shards"]["general"]["exit_code"], 0)
                    self.assertIn("error", summary["shards"]["general"])

    def test_timeout_keeps_original_exit_and_runs_later_shards(self) -> None:
        actual_run = runner.run_bounded

        def short_fixture_timeout(command, *, cwd, env, timeout):
            # Accelerate only the sleeping fake parent; use real TERM/KILL cleanup.
            if command[0].endswith("fake-native") and "--list" not in command and "--skip" in command and len(command) > 10:
                if env.get("SHARD_TEST_CASE") == "timeout-first" and command[1] == "--skip":
                    timeout = 1
            return actual_run(command, cwd=cwd, env=env, timeout=timeout)

        with tempfile.TemporaryDirectory() as directory, patch.object(runner, "run_bounded", side_effect=short_fixture_timeout):
            base = Path(directory)
            code, summary, evidence = self.invoke(base, "timeout-first")
            self.assertEqual(code, 124)
            self.assertEqual(summary["first_failure"]["exit_code"], 124)
            self.assertEqual(summary["shards"]["general"]["deadline_seconds"], 30)
            self.assertIn("TIMEOUT", (evidence / "general.log").read_text())
            self.assertEqual(len((base / "bin/executed.jsonl").read_text().splitlines()), len(runner.SHARD_NAMES))
            self.assertEqual(summary["failed_shards"], ["general"])

    def test_source_or_binary_mutation_stops_before_the_next_shard(self) -> None:
        for case, expected_exit in (("source-change-failure", 17), ("binary-change-failure", 18)):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                code, summary, evidence = self.invoke(base, case)
                self.assertNotEqual(code, 0)
                self.assertFalse(summary["source_confirmed"])
                self.assertEqual(summary["first_failure"]["exit_code"], expected_exit)
                self.assertEqual((evidence / "general.exit-code").read_text().strip(), str(expected_exit))
                executed = (base / "bin/executed.jsonl").read_text().splitlines()
                self.assertEqual(len(executed), 1)
                self.assertTrue(all(row["status"] == "not-run" for name, row in summary["shards"].items() if name != "general"))
                self.assertIn("error", summary)

    def test_inventory_mutation_never_reaches_test_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            code, summary, _ = self.invoke(base, "inventory-source-change")
            self.assertNotEqual(code, 0)
            self.assertFalse((base / "bin/executed.jsonl").exists())
            self.assertFalse(summary["source_confirmed"])

    def test_progress_checkpoint_and_elapsed_time_are_observations_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, evidence = self.invoke(Path(directory), "checkpoint-visible")
            self.assertEqual(code, 0)
            planned = json.loads((evidence / "inventory.json").read_text())
            for name, outcome in summary["shards"].items():
                self.assertEqual(outcome["tests"], planned[name])
                self.assertEqual(outcome["status"], "passed")
                self.assertGreaterEqual(outcome["elapsed_seconds"], 0)
            self.assertEqual(summary["planned_shard_count"], len(planned))
            self.assertEqual(summary["failed_shards"], [])
            self.assertGreaterEqual(summary["elapsed_seconds"], 0)

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

    def test_failed_parent_cannot_leave_a_pipe_closed_child_running(self) -> None:
        child = (
            "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "print('READY:'+str(os.getpid()),flush=True); "
            "fd=os.open(os.devnull,os.O_WRONLY); os.dup2(fd,1); os.dup2(fd,2); os.close(fd); time.sleep(30)"
        )
        parent = (
            f"import subprocess,sys; child=subprocess.Popen([sys.executable,'-S','-c',{child!r}],stdout=subprocess.PIPE,text=True); "
            "print(child.stdout.readline(),end='',flush=True); raise SystemExit(17)"
        )
        with tempfile.TemporaryDirectory() as directory:
            output, code = runner.run_bounded([sys.executable, "-S", "-c", parent], cwd=Path(directory), env=os.environ.copy(), timeout=5)
        self.assertEqual(code, 17)
        child_pid = int(next(line for line in output.splitlines() if line.startswith("READY:")).split(":")[1])
        until = time.monotonic() + 1
        while process_state(child_pid) not in (None, "Z") and time.monotonic() < until:
            time.sleep(0.01)
        try:
            self.assertIn(process_state(child_pid), (None, "Z"))
        finally:
            # Red-control runs must not leave the deliberately leaked fixture alive.
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

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
