#!/usr/bin/env python3
"""Real Git/process tests of the policy wrapper, not privileged-policy acceptance.

The two controlled validators record source selection and block on bounded test
handshakes. The existing shell mutation suite separately tests the real rules.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import signal
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check_cargo_offline_policy.sh"
BASELINE = ".github/workflows/trnm-required-baseline.yml"
PRIVILEGED = "scripts/check_privileged_cargo_offline_policy.sh"

# External driver bytes are test fixtures; they never replace repository rules.
DRIVER = r'''import json, os, pathlib, subprocess, sys, time
root = pathlib.Path.cwd()
mode, version = sys.argv[1:]
control = pathlib.Path(os.environ["FIXTURE_CONTROL"])
def read(name):
    if mode == "--worktree":
        return (root / name).read_text()
    ref = ":" if mode == "--staged" else "HEAD:"
    return subprocess.check_output(["git", "show", ref + name], text=True)
scripts = subprocess.check_output([
    "git", "ls-files", "-co", "--exclude-standard", "--", "scripts/*.sh"
], text=True).splitlines()
record = {
    "root": str(root), "mode": mode, "version": version,
    "payload": read("payload.txt"),
    "baseline_present": (root / ".github/workflows/trnm-required-baseline.yml").is_file(),
    "workflows": sorted(p.name for p in (root / ".github/workflows").iterdir()),
    "scripts": sorted(set(scripts)),
    "deleted_script_present": (root / "scripts/deleted.sh").exists(),
}
(control / "record.json").write_text(json.dumps(record))
(control / "ready").touch()
if os.environ.get("FIXTURE_BLOCK") == "1":
    deadline = time.monotonic() + 10
    while not (control / "release").exists():
        if time.monotonic() >= deadline:
            raise SystemExit(98)
        time.sleep(0.01)
print("cargo_offline_policy=fixture jobs=26 cargo_jobs=22 no_cargo_jobs=4", flush=True)
raise SystemExit(int(os.environ.get("FIXTURE_PRIVILEGED_RC", "0")))
'''

HOST = r'''#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  --worktree) test -f .github/workflows/trnm-required-baseline.yml || exit 41 ;;
  --staged) git cat-file -e :.github/workflows/trnm-required-baseline.yml || exit 41 ;;
  --head) git cat-file -e HEAD:.github/workflows/trnm-required-baseline.yml || exit 41 ;;
esac
exit "${FIXTURE_HOST_RC:-0}"
'''


@unittest.skipUnless(os.name == "posix", "signal and process-group tests require POSIX")
class ReadonlyPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="trnm-readonly-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = pathlib.Path(self.tmp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.driver = self.base / "validator.py"
        self.driver.write_text(DRIVER, encoding="utf-8")
        self.write(BASELINE, "name: immutable-baseline\n")
        self.write(".github/workflows/privileged.yml", "name: privileged-fixture\n")
        self.write("scripts/check_ci_runner_policy.sh", HOST)
        self.write(PRIVILEGED, self.privileged("head"))
        self.write("scripts/deleted.sh", "# tracked fixture\n")
        self.write("payload.txt", "head\n")
        self.git("init", "-q")
        self.git("config", "user.name", "policy-fixture")
        self.git("config", "user.email", "policy-fixture@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.sequence = 0

    def privileged(self, version: str) -> str:
        return '#!/usr/bin/env bash\nset -euo pipefail\npython3 "$FIXTURE_DRIVER" "$1" ' + version + "\n"

    def write(self, name: str, text: str) -> None:
        target = self.repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def git(self, *args: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args], text=True,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"}, timeout=10,
        ).strip()

    def source_identity(self) -> tuple:
        baseline = self.repo / BASELINE
        stat = baseline.stat()
        index = self.repo / ".git/index"
        return (
            baseline.read_bytes(), stat.st_ino, stat.st_mtime_ns, stat.st_mode,
            hashlib.sha256(index.read_bytes()).hexdigest(),
            self.git("rev-parse", "HEAD"),
        )

    @staticmethod
    def stop(process: subprocess.Popen) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)

    def launch(self, mode: str = "--worktree", block: bool = False, **extra: str):
        self.sequence += 1
        control = self.base / f"control-{self.sequence}"
        control.mkdir()
        output = (control / "output.log").open("w", encoding="utf-8")
        self.addCleanup(output.close)
        env = {
            **os.environ, "GIT_OPTIONAL_LOCKS": "0",
            "FIXTURE_DRIVER": str(self.driver), "FIXTURE_CONTROL": str(control),
            "FIXTURE_BLOCK": "1" if block else "0",
            "TMPDIR": str(self.base), **extra,
        }
        process = subprocess.Popen(
            ["bash", str(CHECKER), mode], cwd=self.repo, env=env,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
        self.addCleanup(self.stop, process)
        return process, control

    def ready(self, process, control) -> dict:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if (control / "ready").exists():
                return json.loads((control / "record.json").read_text())
            if process.poll() is not None:
                break
            time.sleep(0.01)
        self.fail("validator did not become ready: " + (control / "output.log").read_text())

    def finish(self, process, control, expected: int = 0) -> str:
        (control / "release").touch()
        self.assertEqual(process.wait(timeout=8), expected, (control / "output.log").read_text())
        return (control / "output.log").read_text()

    def test_worktree_baseline_remains_visible_during_validation(self) -> None:
        before = self.source_identity()
        process, control = self.launch(block=True)
        record = self.ready(process, control)
        self.assertTrue(record["baseline_present"], "validator observed the baseline removed")
        self.assertEqual(self.source_identity(), before)
        self.finish(process, control)
        self.assertEqual(self.source_identity(), before)

    def test_parallel_checks_do_not_hide_each_others_baseline(self) -> None:
        before = self.source_identity()
        first, first_control = self.launch(block=True)
        self.ready(first, first_control)
        second, second_control = self.launch(block=True)
        self.ready(second, second_control)
        self.assertEqual(self.source_identity(), before)
        self.finish(first, first_control)
        self.finish(second, second_control)
        self.assertEqual(self.source_identity(), before)

    def test_sigkill_cannot_remove_the_required_workflow(self) -> None:
        before = self.source_identity()
        process, control = self.launch(block=True)
        self.ready(process, control)
        self.stop(process)
        self.assertTrue((self.repo / BASELINE).is_file(), "killed validator removed the source workflow")
        self.assertEqual(self.source_identity(), before)

    def test_worktree_does_not_overwrite_a_concurrent_edit(self) -> None:
        process, control = self.launch(block=True)
        self.ready(process, control)
        self.write(BASELINE, "name: newer-workflow-edit\n")
        self.finish(process, control)
        self.assertEqual((self.repo / BASELINE).read_text(), "name: newer-workflow-edit\n")

    def test_sigterm_leaves_source_and_index_unchanged(self) -> None:
        before = self.source_identity()
        process, control = self.launch(block=True)
        self.ready(process, control)
        os.killpg(process.pid, signal.SIGTERM)
        self.assertNotEqual(process.wait(timeout=5), 0)
        self.assertEqual(self.source_identity(), before)

    def test_privileged_failure_is_preserved_not_reported_as_pass(self) -> None:
        before = self.source_identity()
        process, control = self.launch(FIXTURE_PRIVILEGED_RC="17")
        output = self.finish(process, control, 17)
        self.assertNotIn("mixed_trust_cargo_policy=passed", output)
        self.assertEqual(self.source_identity(), before)

    def test_host_failure_prevents_privileged_execution(self) -> None:
        before = self.source_identity()
        process, control = self.launch(FIXTURE_HOST_RC="23")
        output = self.finish(process, control, 23)
        self.assertFalse((control / "ready").exists())
        self.assertNotIn("mixed_trust_cargo_policy=passed", output)
        self.assertEqual(self.source_identity(), before)

    def test_missing_baseline_is_still_rejected(self) -> None:
        (self.repo / BASELINE).unlink()
        process, control = self.launch()
        self.finish(process, control, 41)
        self.assertFalse((control / "ready").exists())
        self.assertFalse((self.repo / BASELINE).exists())

    def test_invalid_source_mode_is_rejected_before_validators(self) -> None:
        process, control = self.launch("--unknown")
        self.finish(process, control, 2)
        self.assertFalse((control / "ready").exists())

    def test_worktree_keeps_ignored_workflows_and_tracked_missing_scripts_in_view(self) -> None:
        self.write(".gitignore", ".github/workflows/extra.yml\n")
        self.write(".github/workflows/extra.yml", "name: ignored-but-visible\n")
        self.write("scripts/untracked.sh", "# still a policy input\n")
        (self.repo / "scripts/deleted.sh").unlink()
        process, control = self.launch()
        record = self.ready(process, control)
        self.finish(process, control)
        self.assertIn("extra.yml", record["workflows"])
        self.assertIn("scripts/untracked.sh", record["scripts"])
        self.assertIn("scripts/deleted.sh", record["scripts"])
        self.assertFalse(record["deleted_script_present"])

    def test_staged_and_head_use_selected_bytes_not_modified_worktree_helpers(self) -> None:
        self.write("payload.txt", "index\n")
        self.write(PRIVILEGED, self.privileged("index"))
        self.git("add", "payload.txt", PRIVILEGED)
        self.write("payload.txt", "worktree\n")
        self.write(PRIVILEGED, self.privileged("worktree"))
        before = self.source_identity()
        for mode, expected in (("--head", "head"), ("--staged", "index"), ("--worktree", "worktree")):
            with self.subTest(mode=mode):
                process, control = self.launch(mode)
                record = self.ready(process, control)
                self.finish(process, control)
                self.assertEqual(record["payload"], expected + "\n")
                self.assertEqual(record["version"], expected)
                if mode != "--worktree":
                    self.assertNotEqual(record["root"], str(self.repo))
                    self.assertFalse(record["baseline_present"])
                self.assertEqual(self.source_identity(), before)

    def test_staged_and_head_failures_still_preserve_original_source(self) -> None:
        before = self.source_identity()
        for mode in ("--head", "--staged"):
            with self.subTest(mode=mode):
                process, control = self.launch(mode, FIXTURE_PRIVILEGED_RC="19")
                output = self.finish(process, control, 19)
                self.assertNotIn("mixed_trust_cargo_policy=passed", output)
                self.assertEqual(self.source_identity(), before)

    def test_snapshot_does_not_rewrite_the_callers_alternate_index(self) -> None:
        before = self.source_identity()
        alternate = self.base / "alternate.index"
        for mode in ("--head", "--staged"):
            with self.subTest(mode=mode):
                shutil.copyfile(self.repo / ".git/index", alternate)
                self.write("payload.txt", "alternate-index\n")
                subprocess.run(
                    ["git", "-C", str(self.repo), "add", "payload.txt"],
                    env={**os.environ, "GIT_INDEX_FILE": str(alternate)},
                    check=True, timeout=10,
                )
                self.write("payload.txt", "unstaged-worktree\n")
                alternate_before = alternate.read_bytes()
                process, control = self.launch(mode, GIT_INDEX_FILE=str(alternate))
                record = self.ready(process, control)
                self.finish(process, control)
                self.assertEqual(record["payload"], "head\n" if mode == "--head" else "alternate-index\n")
                self.assertEqual(alternate.read_bytes(), alternate_before)
                self.assertEqual(self.source_identity(), before)

    def test_snapshot_does_not_commit_into_inherited_git_directory(self) -> None:
        before = self.source_identity()
        process, control = self.launch(
            "--head", GIT_DIR=str(self.repo / ".git"),
            GIT_WORK_TREE=str(self.repo), GIT_COMMON_DIR=str(self.repo / ".git"),
        )
        self.ready(process, control)
        self.finish(process, control)
        self.assertEqual(self.source_identity(), before)

    def test_success_summary_and_worktree_input_selection_are_retained(self) -> None:
        self.write("payload.txt", "worktree\n")
        before = self.source_identity()
        process, control = self.launch()
        record = self.ready(process, control)
        output = self.finish(process, control)
        self.assertEqual(record["payload"], "worktree\n")
        self.assertIn("mixed_trust_cargo_policy=passed", output)
        self.assertIn("source=worktree", output)
        self.assertEqual(self.source_identity(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
