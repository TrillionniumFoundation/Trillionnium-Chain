#!/usr/bin/env python3
"""POSIX subprocess lifecycle fixtures, not Rust package qualification."""
from __future__ import annotations

import contextlib
import copy
import json
import io
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import run_bounded_workspace_tests_v1 as runner
import check_cargo_source_inventory_v1 as inventory


@unittest.skipUnless(os.name == 'posix', 'process-group contract is POSIX-only')
class ProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.cargo = self.root / 'cargo-fixture'
        self.output = io.StringIO()

    def run_fixture(self, code: str, timeout: int = 3):
        self.cargo.write_text('#!' + sys.executable + '\n' + code)
        self.cargo.chmod(0o700)
        with contextlib.redirect_stdout(self.output):
            return runner.run_package(self.root, str(self.cargo), 'fixture', timeout)

    def test_success(self) -> None:
        result = self.run_fixture('print("a real child process completed")\n')
        self.assertEqual(result.status, 'success')
        self.assertEqual(result.returncode, 0)
        self.assertIn('a real child process', self.output.getvalue())

    def test_failure_exit_is_preserved(self) -> None:
        result = self.run_fixture('import sys\nprint("failure")\nsys.exit(7)\n')
        self.assertEqual((result.status, result.returncode), ('failed', 7))

    def test_timeout_is_not_success(self) -> None:
        result = self.run_fixture('import time\ntime.sleep(60)\n', timeout=1)
        self.assertEqual(result.status, 'timeout')
        self.assertLess(result.elapsed_seconds, 8)

    def test_invalid_utf8_does_not_silently_kill_output_thread(self) -> None:
        result = self.run_fixture('import os\nos.write(1, b"bad byte: \\xff\\n")\n')
        self.assertEqual(result.status, 'success')
        self.assertIn('\\xff', self.output.getvalue())

    def test_successful_parent_with_inherited_pipe_is_rejected(self) -> None:
        result = self.run_fixture('''import os, signal, time
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(60)
    os._exit(0)
os._exit(0)
''')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.status, 'failed')
        self.assertIn('process leak', self.output.getvalue())
        self.assertLess(result.elapsed_seconds, 8)

    def test_detached_output_but_same_group_child_is_rejected(self) -> None:
        result = self.run_fixture('''import os, signal, time
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.close(1)
    os.close(2)
    time.sleep(60)
    os._exit(0)
time.sleep(0.1)
os._exit(0)
''')
        self.assertEqual(result.status, 'failed')
        self.assertEqual(result.returncode, 0)

    def test_output_exception_is_not_success(self) -> None:
        def failed_pump(stream, errors):
            stream.read()
            stream.close()
            errors.append(OSError('retained output mutant'))
        with mock.patch.object(runner, 'pump_output', failed_pump):
            result = self.run_fixture('print("hello")\n')
        self.assertEqual(result.status, 'failed')

    def test_terminate_kills_group_even_after_parent_has_exited(self) -> None:
        child_pid = self.root / 'child.pid'
        code = f'''import os, signal, time
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    open({str(child_pid)!r}, 'w').write(str(os.getpid()))
    time.sleep(60)
    os._exit(0)
time.sleep(0.1)
os._exit(0)
'''
        proc = subprocess.Popen([sys.executable, '-c', code], start_new_session=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(runner.terminate_process_tree, proc)
        proc.wait(timeout=3)
        self.assertIsNotNone(proc.poll())
        runner.terminate_process_tree(proc)
        pid = int(child_pid.read_text())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            stat = pathlib.Path(f'/proc/{pid}/stat')
            if not stat.exists() or stat.read_text().split()[2] == 'Z':
                break
            time.sleep(0.02)
        else:
            self.fail('SIGTERM-ignoring child remained alive after group cleanup')


class PackageSelectionTests(unittest.TestCase):
    """Real Git/process fixtures; Cargo output is synthetic, not Rust acceptance."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name).resolve()
        self.repo = self.root / 'repo'
        self.workspace = self.repo / 'trillionnium'
        self.workspace.mkdir(parents=True)
        (self.workspace / 'Cargo.toml').write_text(
            '[workspace]\nmembers = ["crates/a", "crates/b"]\n', encoding='utf-8'
        )
        (self.workspace / 'Cargo.lock').write_text('version = 4\n', encoding='utf-8')
        packages = []
        for name in ('a', 'b'):
            crate = self.workspace / 'crates' / name
            (crate / 'src').mkdir(parents=True)
            (crate / 'Cargo.toml').write_text(
                f'[package]\nname = "{name}"\nversion = "0.1.0"\n', encoding='utf-8'
            )
            (crate / 'src/lib.rs').write_text('pub fn fixture() {}\n', encoding='utf-8')
            packages.append({
                'id': f'fixture-{name}', 'name': name, 'manifest_path': str(crate / 'Cargo.toml'),
                'targets': [{'name': name, 'kind': ['lib'], 'src_path': str(crate / 'src/lib.rs')}],
            })
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.git('add', '.')
        self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                 'commit', '-qm', 'source fixture')
        self.head = self.git('rev-parse', 'HEAD')
        self.metadata = {
            'version': 1, 'workspace_root': str(self.workspace),
            'workspace_members': ['fixture-a', 'fixture-b'], 'packages': packages,
        }
        self.metadata_path = self.root / 'metadata.json'
        self.test_marker = self.root / 'test-invocations.txt'
        self.cargo = self.root / 'cargo-fixture'
        self.cargo.write_text(
            '#!' + sys.executable + '\n'
            'import pathlib, sys\n'
            'if sys.argv[1] == "metadata":\n'
            f'    print(pathlib.Path({str(self.metadata_path)!r}).read_text())\n'
            'elif sys.argv[1] == "test":\n'
            f'    with pathlib.Path({str(self.test_marker)!r}).open("a") as stream:\n'
            '        stream.write(sys.argv[sys.argv.index("--package") + 1] + "\\n")\n'
            '    print("synthetic Cargo test process")\n'
            'else:\n'
            '    sys.exit(7)\n', encoding='utf-8'
        )
        self.cargo.chmod(0o700)
        environment = mock.patch.dict(os.environ, {
            'CARGO': str(self.cargo), 'TRNM_EXPECTED_SOURCE_SHA': self.head,
        })
        environment.start()
        self.addCleanup(environment.stop)

    def git(self, *args: str) -> str:
        return inventory.git(self.repo, *args)

    def write_metadata(self) -> None:
        self.metadata_path.write_text(json.dumps(self.metadata), encoding='utf-8')

    def names(self):
        self.write_metadata()
        return runner.workspace_packages(self.workspace, str(self.cargo))

    def run_main(self):
        self.write_metadata()
        output = io.StringIO()
        args = ['runner', '--workspace-root', str(self.workspace), '--package-timeout-seconds', '3']
        with mock.patch.object(sys, 'argv', args), contextlib.redirect_stdout(output):
            result = runner.main()
        return result, output.getvalue()

    def test_valid_metadata_selects_each_tracked_member_once(self) -> None:
        self.metadata['packages'].reverse()
        self.assertEqual(self.names(), ['a', 'b'])

    def test_missing_package_row_cannot_shrink_the_test_set(self) -> None:
        self.metadata['packages'].pop()
        with self.assertRaises(inventory.InventoryError): self.names()

    def test_missing_member_id_cannot_hide_a_declared_crate(self) -> None:
        self.metadata['workspace_members'].pop()
        self.metadata['packages'].pop()
        with self.assertRaises(inventory.InventoryError): self.names()

    def test_duplicate_member_id_is_not_silently_deduplicated(self) -> None:
        self.metadata['workspace_members'].append('fixture-a')
        with self.assertRaises(inventory.InventoryError): self.names()

    def test_duplicate_package_id_cannot_select_a_second_package_name(self) -> None:
        forged = copy.deepcopy(self.metadata['packages'][0])
        forged['name'] = 'forged'
        self.metadata['packages'].append(forged)
        with self.assertRaises(inventory.InventoryError): self.names()

    def test_package_name_cannot_override_its_tracked_manifest(self) -> None:
        self.metadata['packages'][0]['name'] = 'forged'
        with self.assertRaises(inventory.InventoryError): self.names()

    def test_unknown_workspace_and_target_are_rejected(self) -> None:
        original = copy.deepcopy(self.metadata)
        self.metadata['workspace_root'] = str(self.repo)
        with self.assertRaises(inventory.InventoryError): self.names()
        self.metadata = original
        self.metadata['packages'][0]['targets'][0]['src_path'] = str(self.root / 'missing.rs')
        with self.assertRaises((inventory.InventoryError, OSError)): self.names()

    def test_dirty_source_is_not_qualified(self) -> None:
        (self.workspace / 'crates/a/src/lib.rs').write_text('changed\n', encoding='utf-8')
        with self.assertRaises(inventory.InventoryError): self.names()

    def test_wrong_expected_source_is_not_replaced_by_local_head(self) -> None:
        with mock.patch.dict(os.environ, {'TRNM_EXPECTED_SOURCE_SHA': '0' * 40}):
            with self.assertRaises(inventory.InventoryError): self.names()

    def test_duplicate_json_members_are_rejected(self) -> None:
        self.write_metadata()
        raw = self.metadata_path.read_text(encoding='utf-8')
        self.metadata_path.write_text(raw[:-1] + ',"version":1}', encoding='utf-8')
        with self.assertRaises(inventory.InventoryError):
            runner.workspace_packages(self.workspace, str(self.cargo))

    def test_non_json_numeric_constants_are_rejected(self) -> None:
        self.write_metadata()
        raw = self.metadata_path.read_text(encoding='utf-8')
        self.metadata_path.write_text(raw[:-1] + ',"unused":NaN}', encoding='utf-8')
        with self.assertRaises(inventory.InventoryError):
            runner.workspace_packages(self.workspace, str(self.cargo))

    def test_invalid_selection_never_launches_a_test_process(self) -> None:
        self.metadata['packages'].pop()
        with self.assertRaises(inventory.InventoryError): self.run_main()
        self.assertFalse(self.test_marker.exists())

    def test_success_runs_both_packages_and_keeps_a_clean_source(self) -> None:
        result, output = self.run_main()
        self.assertEqual(result, 0)
        self.assertEqual(self.test_marker.read_text().splitlines(), ['a', 'b'])
        self.assertIn('bounded_workspace_tests_ok package_count=2', output)
        self.assertEqual(self.git('status', '--porcelain', '--untracked-files=all'), '')

    def test_test_process_source_mutation_cannot_end_in_success(self) -> None:
        def mutate_source(_workspace, _cargo, package, _timeout):
            (self.workspace / 'crates/a/src/lib.rs').write_text('changed\n', encoding='utf-8')
            return runner.PackageResult(package, 'success', 0, 0)
        with mock.patch.object(runner, 'run_package', mutate_source):
            with self.assertRaises(inventory.InventoryError): self.run_main()

    def test_clean_head_move_during_tests_cannot_rebind_evidence(self) -> None:
        changed = False
        def move_head(_workspace, _cargo, package, _timeout):
            nonlocal changed
            if not changed:
                self.git('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                         'commit', '--allow-empty', '-qm', 'unexpected source move')
                changed = True
            return runner.PackageResult(package, 'success', 0, 0)
        with mock.patch.object(runner, 'run_package', move_head):
            with self.assertRaises(inventory.InventoryError): self.run_main()

    def test_cli_rejection_returns_nonzero_without_traceback_or_test_execution(self) -> None:
        self.metadata['packages'].pop()
        self.write_metadata()
        completed = subprocess.run(
            [sys.executable, runner.__file__, '--workspace-root', str(self.workspace)],
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn('Traceback', completed.stderr)
        self.assertNotIn('bounded_workspace_tests_ok', completed.stdout)
        self.assertFalse(self.test_marker.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
