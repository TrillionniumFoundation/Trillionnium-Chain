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

NAMES = sorted([
    "ordinary::new_test", runner.BRIDGE + "historical_install_is_atomic",
    runner.BRIDGE + "historical_receiver_c33_is_strict", runner.SCHEMA7 + "selects_branch",
    runner.POCO_SIGKILL, *runner.ALLOWED_IGNORED, *runner.REQUIRED_SIGKILL_DRIVERS,
])


class NativeCandidateShardTests(unittest.TestCase):
    def make_workspace(self, base: Path) -> tuple[Path, Path]:
        repo = base / "repo"
        source = repo / "trillionnium/crates/trnm-native-execution-v0/src/lib.rs"
        source.parent.mkdir(parents=True)
        source.write_text("// fake source used only by runner tests\n")
        for args in (["init", "-q"], ["add", "."], ["-c", "user.name=Runner test", "-c", "user.email=test@invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"]):
            subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
        bin_dir = base / "bin"
        bin_dir.mkdir()
        executable = bin_dir / "fake-native"
        executable.write_text(f"#!{sys.executable}\n" + f"NAMES={NAMES!r}\nIGNORED={sorted(runner.ALLOWED_IGNORED)!r}\n" + '''
import os, pathlib, sys
assert 'RUST_MIN_STACK' not in os.environ
case = os.environ.get('SHARD_TEST_CASE', '')
args = sys.argv[1:]
ignored = set(IGNORED)
if case == 'extra-ignored':
    ignored.add('ordinary::new_test')
skips, filters = [], []
i = 0
while i < len(args):
    if args[i] == '--skip':
        skips.append(args[i + 1]); i += 2; continue
    if not args[i].startswith('--'):
        filters.append(args[i])
    i += 1
selected = [name for name in NAMES if (not filters or any(x in name for x in filters)) and not any(x in name for x in skips)]
if '--ignored' in args:
    selected = [name for name in selected if name in ignored]
if '--list' in args:
    if case == 'list-failure':
        raise SystemExit(7)
    if case == 'filtered-mismatch' and skips:
        selected = selected[:-1]
    print(''.join(name + ': test\\n' for name in selected), end='')
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
''')
        executable.chmod(0o755)
        cargo = bin_dir / "cargo"
        cargo.write_text(f"#!{sys.executable}\n" + f"EXE={str(executable)!r}\n" + '''
import json, os, pathlib, sys
if os.environ.get('SHARD_TEST_CASE') == 'compile-failure':
    raise SystemExit(9)
print(json.dumps({'reason':'compiler-artifact', 'target':{'name':'trnm_native_execution_v0', 'kind':['lib'], 'src_path':str(pathlib.Path.cwd() / 'crates/trnm-native-execution-v0/src/lib.rs')}, 'profile':{'test':True}, 'executable':EXE}))
''')
        cargo.chmod(0o755)
        return repo, bin_dir

    def invoke(self, base: Path, case: str = "") -> tuple[int, dict, Path]:
        repo, bin_dir = self.make_workspace(base)
        evidence = base / "evidence"
        if case == "dirty-source":
            (repo / "untracked-before-test").write_text("untracked")
        env = {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"], "SHARD_TEST_CASE": case, "RUST_MIN_STACK": "99999999"}
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        env["TRNM_EXPECTED_SOURCE_SHA"] = "0" * 40 if case == "wrong-source-pin" else head
        with patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = runner.run(["--workspace", str(repo / "trillionnium"), "--evidence-dir", str(evidence), "--deadline-seconds", "30"])
        return code, json.loads((evidence / "summary.json").read_text()), evidence

    def test_actual_fake_libtest_execution_covers_inventory_and_children(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, summary, _ = self.invoke(Path(directory))
        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(set(summary["shards"]), set(runner.SHARD_NAMES))
        counts = [entry["counts"] for entry in summary["shards"].values()]
        self.assertEqual(sum(entry["passed"] for entry in counts), len(NAMES) - 3)
        self.assertEqual(sum(entry["ignored"] for entry in counts), 3)
        self.assertRegex(summary["executable_sha256"], r"^[0-9a-f]{64}$")

    def test_execution_failures_never_publish_success(self) -> None:
        for case in ("compile-failure", "list-failure", "filtered-mismatch", "extra-ignored", "no-summary", "wrong-count", "dirty-source", "source-change", "binary-change", "wrong-source-pin"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                code, summary, evidence = self.invoke(Path(directory), case)
                self.assertNotEqual(code, 0)
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["exit_code"], code)
                if case in ("dirty-source", "wrong-source-pin"):
                    self.assertFalse((evidence / "compile.command").exists())
                if case == "list-failure":
                    self.assertEqual((evidence / "inventory.exit-code").read_text().strip(), "7")

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
        self.assertEqual(sorted(sum(runner.partition_inventory(iter(NAMES)).values(), [])), NAMES)
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
                parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(30)"
                start = time.monotonic()
                with tempfile.TemporaryDirectory() as directory:
                    output, code = runner.run_bounded([sys.executable, "-c", parent], cwd=Path(directory), env=os.environ.copy(), timeout=1)
                self.assertEqual(code, 124)
                self.assertLess(time.monotonic() - start, 12)
                self.assertIn("TIMEOUT", output)
                ready = next(line for line in output.splitlines() if line.startswith("READY:"))
                child_pid = int(ready.split(":")[1])
                stat = Path(f"/proc/{child_pid}/stat")
                until = time.monotonic() + 1
                while stat.exists() and stat.read_text().split(") ", 1)[1][0] != "Z" and time.monotonic() < until:
                    time.sleep(0.01)
                if stat.exists():
                    self.assertEqual(stat.read_text().split(") ", 1)[1][0], "Z", "owned child is still running")


if __name__ == "__main__":
    unittest.main()
