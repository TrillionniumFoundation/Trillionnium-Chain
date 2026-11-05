#!/usr/bin/env python3
"""Explicit installed-image controls; no model, Fleet or FinalUse qualification.

For actual deployment-permission positives, a CI fixture installer supplies a new
root-owned nonwritable directory with native-argv-probe and hepta-neural-agentd.
Run this suite as the original nonroot caller, never as the installer. The native
daemon must include the Cell-specific pre-alias image gate.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import signal
import time
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import llm_cell_host_handoff as handoff
import llm_cell_installed_executable as installed
from test_llm_cell_host_handoff import CAPS, fixture, save

FIXTURE = os.environ.get("HEPTA_INSTALLED_TEST_DIR")
NATIVE = os.environ.get("TRNM_CELL_BIN")


def subject_status(uid, **overrides):
    fields = dict(Uid=f"{uid}\t{uid}\t{uid}\t{uid}", CapEff="0", CapPrm="0", CapAmb="0", CapInh="0", CapBnd="ffffffffffffffff")
    fields.update(overrides)
    return "\n".join(f"{name}:\t{value}" for name, value in fields.items()).encode()


def exec_image(image, argv, environment):
    # The child inherits this exact held image, not a reopened installation path.
    # Like the native CLI controls, helper-only observations have a ten-second cap.
    result = subprocess.run(argv, executable=f"/proc/self/fd/{image.fileno()}",
        pass_fds=(image.fileno(),), env=environment, capture_output=True, text=True, timeout=10)
    return result.returncode, result.stdout + result.stderr


class InstalledPolicyTests(unittest.TestCase):
    def test_new_schema_profile_is_mandatory_and_never_reinterpreted_as_v2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = {name: None for name in ("host", "executable", "workspace", "generation", "loader_profile", "context", "authentication")}
            cases = [(dict(base, schema=handoff.INSTALLED_SCHEMA), "handoff-v3 fields"),
                     (dict(base, schema=handoff.SCHEMA, execution_profile=installed.PROFILE), "handoff-v2 fields"),
                     (dict(base, schema=handoff.INSTALLED_SCHEMA, execution_profile="unknown"), "explicit protected-installed")]
            environment = {name: "controlled-original-owner" for name in handoff.REQUIRED_ENV}
            for value, reason in cases:
                pin = save(root / "config.json", handoff.canonical(value))
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    handoff.load(Path(pin["path"]), pin["sha256"], root / "absent-output", environment)
            self.assertFalse((root / "absent-output").exists())

    def test_active_or_inheritable_capability_and_saved_root_are_rejected(self):
        # Parser controls are not evidence of root-owned filesystem admission.
        installed.validate_subject_status(subject_status(12345), 12345)
        for field in installed.CAPABILITY_FIELDS:
            with self.subTest(field=field), self.assertRaisesRegex(installed.ProfileUnavailable, "zero Cap"):
                installed.validate_subject_status(subject_status(12345, **{field: "1"}), 12345)
        for identities in ("12345 0 12345 12345", "12345 12345 0 12345", "12345 12345 12345 0"):
            with self.subTest(identities=identities), self.assertRaises(installed.ProfileUnavailable):
                installed.validate_subject_status(subject_status(12345, Uid=identities), 12345)
        with self.assertRaises(installed.ProfileUnavailable):
            installed.validate_subject_status(subject_status(0), 0)
        with self.assertRaises(installed.ProfileUnavailable):
            installed.validate_subject_status(b"Uid: 12345 12345 12345 12345", 12345)

    def test_actual_caller_writable_elf_cannot_select_installed_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "caller-writable-echo"
            shutil.copyfile(shutil.which("echo"), source)
            source.chmod(0o700)
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                installed.prepare(source, expected)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), expected)


class RecoveryHandoffTests(unittest.TestCase):
    """Actual protected-file reads and ELF argv transfer, never a Hepta receipt.

    The opaque metadata below is intentionally unqualified. /usr/bin/echo observes
    the held-image invocation only; it cannot authenticate recovery or use a model.
    Root test runners drop privileges in the forked probe before admission.
    """

    @staticmethod
    def fixture(root, schema=handoff.RECOVERY_SCHEMA):
        root.chmod(0o755)
        def put(name, raw):
            path = root / name
            pin = save(path, raw)
            path.chmod(0o644)
            return pin
        for name in ('workspace', 'fleet', 'home', 'run'):
            (root / name).mkdir(mode=0o755)
        output = root / 'absent-transport-output'
        snapshot = put('runtime-snapshot.json', b'{"scope":"argv-control-not-runtime"}')
        descriptor = put('descriptor.json', b'{"scope":"not-a-qualified-bootstrap"}')
        issuer = put('issuer.json', b'{"scope":"not-an-authority"}')
        recovery = dict(profile=handoff.RECOVERY_PROFILE,
            frontier=put('frontier.json', b'{"scope":"argv-control-not-signed-frontier"}'),
            signer_trust=put('trust.json', b'{"scope":"argv-control-not-signer-trust"}'))
        worker = dict(runtime_snapshot=snapshot, materials=str(output / 'consumer-materials'),
            target_contract=dict(path=str(output / 'consumer-parent/target-contract.json'), sha256='44' * 32),
            wrapped_adapter=dict(path=str(output / 'consumer-parent/wrapped-adapter.json'), sha256='55' * 32))
        owner = dict(schema='hepta-smollm-cognitive-host-v2', worker=worker,
                     descriptor=descriptor, final_use_authorizer_config=issuer['path'])
        host = dict(schema=handoff.HOST_SCHEMA, owner=owner, operation_id='unqualified-argv-probe',
            sidecar=dict(path=str(output / 'consumer-cell-sidecar.json'), sha256='66' * 32),
            dependency_closure=dict(path=str(output / 'consumer-release.tcd1'), sha256='77' * 32),
            dependency_closure_id='88' * 32)
        host_pin = put('host.json', handoff.canonical(host))
        image = Path(shutil.which('echo')).resolve(strict=True)
        value = dict(schema=schema, execution_profile=installed.PROFILE,
            host=host_pin, executable=dict(path=str(image), sha256=handoff.checksum(image.read_bytes())),
            workspace=str(root / 'workspace'), generation=1, loader_profile='33' * 32,
            context=dict(family='unqualified-argv-control', **{name: '11' * 32 for name in
                         ('base', 'parent', 'tokenizer', 'layout', 'runtime')}),
            authentication=dict(profile='content-cache-v1'))
        if schema == handoff.RECOVERY_SCHEMA:
            value['evidence_recovery'] = recovery
        pin = put('handoff.json', handoff.canonical(value))
        environment = dict(os.environ, HEPTA_FLEET_ROOT=str(root / 'fleet'),
            HEPTA_AGENT_ID='00000000-0000-4000-8000-000000000219', HEPTA_AGENT_GENERATION='1',
            HEPTA_AGENT_HOME=str(root / 'home'), HEPTA_AGENT_RUN_ROOT=str(root / 'run'),
            CODEX_HOME=str(root / 'home'))
        return SimpleNamespace(root=root, output=output, value=value, pin=pin,
                               environment=environment, recovery=recovery)

    def run_probe(self, fixture, after_load=None):
        if not sys.platform.startswith('linux') or not hasattr(os, 'fork'):
            self.skipTest('real protected ELF descriptor probe requires Linux fork')
        if os.geteuid() == 0:
            fields = dict(line.split(':', 1) for line in Path('/proc/thread-self/status').read_text().splitlines() if ':' in line)
            required = (1 << 6) | (1 << 7)  # CAP_SETGID and CAP_SETUID for this control child only.
            if int(fields.get('CapEff', '0'), 16) & required != required:
                self.skipTest('root test runner lacks CAP_SETGID/CAP_SETUID; real nonroot exec was not run')
        output_read, output_write = os.pipe()
        ready_read, ready_write = os.pipe()
        go_read, go_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(output_read); os.close(ready_read); os.close(go_write)
                os.dup2(output_write, 1); os.dup2(output_write, 2); os.close(output_write)
                if os.geteuid() == 0:
                    try:
                        os.setgroups([])
                        os.setresgid(65534, 65534, 65534)
                        os.setresuid(65534, 65534, 65534)
                    except PermissionError as error:
                        os.write(2, ('CONTROL_SUBJECT_UNAVAILABLE: ' + str(error) + '\n').encode())
                        os._exit(77)
                os.environ.update(fixture.environment)
                plan = handoff.load(Path(fixture.pin['path']), fixture.pin['sha256'],
                                    fixture.output, fixture.environment)
                try:
                    os.write(ready_write, b'R'); os.close(ready_write)
                    if os.read(go_read, 1) != b'G':
                        raise RuntimeError('probe was not released')
                    os.close(go_read)
                    plan.exec_owner()
                finally:
                    plan.close()
            except BaseException as error:
                os.write(2, (type(error).__name__ + ': ' + str(error) + '\n').encode())
                os._exit(65)
            os._exit(123)
        os.close(output_write); os.close(ready_write); os.close(go_read)
        reaped = False
        try:
            readable, _, _ = select.select([ready_read], [], [], 10)
            self.assertTrue(readable, 'probe did not reach admission in time')
            ready = os.read(ready_read, 1)
            if ready == b'R':
                if after_load is not None:
                    after_load()
                os.write(go_write, b'G')
            os.close(go_write); go_write = None
            deadline, chunks = time.monotonic() + 10, []
            while True:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, 'probe output deadline exceeded')
                readable, _, _ = select.select([output_read], [], [], remaining)
                self.assertTrue(readable, 'probe output deadline exceeded')
                raw = os.read(output_read, 4096)
                if not raw:
                    break
                chunks.append(raw)
                self.assertLess(sum(map(len, chunks)), 65536)
            while True:
                found, status = os.waitpid(pid, os.WNOHANG)
                if found:
                    reaped = True
                    code, observed = os.waitstatus_to_exitcode(status), b''.join(chunks).decode()
                    if code == 77 and observed.startswith('CONTROL_SUBJECT_UNAVAILABLE:'):
                        self.skipTest(observed.strip())
                    return code, observed
                self.assertLess(time.monotonic(), deadline, 'probe exit deadline exceeded')
                time.sleep(.01)
        finally:
            for fd in (output_read, ready_read, go_write):
                if fd is not None:
                    os.close(fd)
            if not reaped:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    def test_v4_requires_two_pins_and_explicit_profile_without_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(Path(directory))
            cases = []
            for name in ('frontier', 'signer_trust', 'profile'):
                value = copy.deepcopy(f.value)
                del value['evidence_recovery'][name]
                cases.append(value)
            cases.extend((dict(copy.deepcopy(f.value), execution_profile='sealed-elf-v1'),
                          dict(copy.deepcopy(f.value), schema=handoff.INSTALLED_SCHEMA),
                          dict(copy.deepcopy(f.value), schema=handoff.SCHEMA)))
            unknown = copy.deepcopy(f.value)
            unknown['evidence_recovery']['profile'] = 'unknown'
            cases.append(unknown)
            absent = copy.deepcopy(f.value)
            del absent['evidence_recovery']
            cases.append(absent)
            with mock.patch.object(handoff, 'sealed_executable', side_effect=AssertionError('no sealed fallback')), \
                    mock.patch.object(installed, 'prepare', side_effect=AssertionError('no executable admission')):
                for value in cases:
                    pin = save(f.root / 'invalid.json', handoff.canonical(value))
                    with self.subTest(value=value), self.assertRaises(ValueError):
                        handoff.load(Path(pin['path']), pin['sha256'], f.output, f.environment)
            self.assertFalse(f.output.exists())

    def test_two_actual_pinned_files_produce_only_the_original_native_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(Path(directory))
            arguments = handoff.recovery_arguments(f.recovery, f.value['workspace'], f.environment)
            self.assertEqual(arguments, ['--evidence-recovery-frontier-file', f.recovery['frontier']['path'],
                '--evidence-recovery-frontier-trust-file', f.recovery['signer_trust']['path']])
            self.assertFalse(f.output.exists())
            self.assertEqual(set(f.recovery), {'profile', 'frontier', 'signer_trust'})

    def test_rechecking_the_original_pin_refuses_an_actual_later_trust_file_change(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(Path(directory))
            handoff.recovery_arguments(f.recovery, f.value['workspace'], f.environment)
            Path(f.recovery['signer_trust']['path']).write_bytes(b'changed after first owner read')
            with self.assertRaisesRegex(ValueError, 'independent owner file digest mismatch'):
                handoff.recovery_arguments(f.recovery, f.value['workspace'], f.environment)
            self.assertFalse(f.output.exists())

    def test_each_external_pin_and_native_byte_bound_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(Path(directory))
            for name, _, maximum in handoff.RECOVERY_INPUTS:
                spec = copy.deepcopy(f.recovery)
                spec[name]['sha256'] = 'ab' * 32
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    handoff.recovery_arguments(spec, f.value['workspace'], f.environment)
                large = save(f.root / (name + '-oversized.json'), b'x' * (maximum + 1))
                with self.assertRaisesRegex(ValueError, 'bounded'):
                    handoff.recovery_arguments(dict(f.recovery, **{name: large}), f.value['workspace'], f.environment)
                path = Path(f.recovery[name]['path'])
                path.chmod(0o666)
                with self.assertRaisesRegex(ValueError, 'protected'):
                    handoff.recovery_arguments(f.recovery, f.value['workspace'], f.environment)
                path.chmod(0o644)
                alias = f.root / (name + '-alias.json'); alias.symlink_to(path)
                with self.assertRaisesRegex(ValueError, 'canonical'):
                    handoff.recovery_arguments(dict(f.recovery, **{name: dict(path=str(alias), sha256=f.recovery[name]['sha256'])}),
                                               f.value['workspace'], f.environment)
            self.assertFalse(f.output.exists())

    def test_recovery_inputs_cannot_share_the_agent_rollback_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(Path(directory))
            roots = [f.value['workspace'], *(f.environment[name] for name in
                     ('HEPTA_AGENT_HOME', 'HEPTA_AGENT_RUN_ROOT', 'HEPTA_FLEET_ROOT'))]
            for root in roots:
                pin = save(Path(root) / 'forbidden-frontier.json', b'owner-root control')
                with self.subTest(root=root), self.assertRaisesRegex(ValueError, 'rollback domains'):
                    handoff.recovery_arguments(dict(f.recovery, frontier=pin), f.value['workspace'], f.environment)
            missing = dict(path=str(f.root / 'absent.json'), sha256='ab' * 32)
            with self.assertRaises(FileNotFoundError):
                handoff.recovery_arguments(dict(f.recovery, signer_trust=missing), f.value['workspace'], f.environment)
            self.assertFalse(f.output.exists())

    def test_actual_nonroot_held_elf_receives_v4_files_and_v3_keeps_its_argv(self):
        for schema in (handoff.RECOVERY_SCHEMA, handoff.INSTALLED_SCHEMA):
            with tempfile.TemporaryDirectory() as directory:
                f = self.fixture(Path(directory), schema)
                code, output = self.run_probe(f)
                expected = ['--host-format', 'cell-v2', '--host-config', f.value['host']['path'],
                            '--host-config-sha256', f.value['host']['sha256']]
                if schema == handoff.RECOVERY_SCHEMA:
                    expected += handoff.recovery_arguments(f.recovery, f.value['workspace'], f.environment)
                self.assertEqual((code, output), (0, ' '.join(expected) + '\n'))
                self.assertFalse(f.output.exists())

    def test_changed_frontier_after_load_is_refused_before_actual_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            f = self.fixture(Path(directory))
            code, output = self.run_probe(f, lambda: Path(f.recovery['frontier']['path']).write_bytes(b'changed'))
            self.assertEqual(code, 65, output)
            self.assertIn('independent owner file digest mismatch', output)
            self.assertNotIn('--host-format cell-v2', output)
            self.assertFalse(f.output.exists())


@unittest.skipUnless(FIXTURE and NATIVE, "requires independently installed protected ELF fixtures and exact TRNM_CELL_BIN")
class InstalledDeploymentTests(unittest.TestCase):
    def setUp(self):
        installed.require_subject()
        self.deployment = Path(FIXTURE)
        self.probe = self.deployment / "native-argv-probe"
        self.host = self.deployment / "hepta-neural-agentd"
        self.probe_sha = hashlib.sha256(self.probe.read_bytes()).hexdigest()

    def plan(self, root):
        f = fixture(root)
        f.value.update(schema=handoff.INSTALLED_SCHEMA, execution_profile=installed.PROFILE,
                       executable=dict(path=str(self.probe), sha256=self.probe_sha))
        pin = save(Path(f.config_pin["path"]), handoff.canonical(f.value))
        return f, handoff.load(Path(pin["path"]), pin["sha256"], f.args.output, f.environment)

    def test_root_installed_elf_executes_held_image_and_caller_cannot_write_or_replace_it(self):
        with installed.prepare(self.probe, self.probe_sha) as image:
            with self.assertRaises(PermissionError):
                fd = os.open(self.probe, os.O_WRONLY)
                os.close(fd)
            with self.assertRaises(PermissionError):
                os.replace(self.probe, self.deployment / "must-not-move-protected-image")
            self.assertTrue(self.probe.exists())
            code, output = exec_image(image, [str(self.probe), "installed-image-exec-control"], handoff.checked_environment(os.environ))
            self.assertEqual((code, output.strip()), (0, "installed-image-exec-control"))
            self.assertEqual(hashlib.sha256(self.probe.read_bytes()).hexdigest(), self.probe_sha)

    def test_explicit_v3_uses_original_path_without_memfd_or_old_schema_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(handoff.os, "memfd_create", side_effect=AssertionError("installed profile must not select memfd")):
                f, plan = self.plan(Path(directory))
            try:
                self.assertEqual(plan.execution_profile, installed.PROFILE)
                self.assertEqual(os.fstat(plan.executable.fileno()).st_ino, self.probe.stat().st_ino)
                self.assertFalse(f.args.output.exists())
                read_fd, write_fd = os.pipe()
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(read_fd)
                        os.dup2(write_fd, 1)
                        os.close(write_fd)
                        plan.exec_owner()
                    finally:
                        os._exit(123)
                os.close(write_fd)
                with os.fdopen(read_fd, "rb") as stream:
                    observed = stream.read()
                _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                self.assertIn(b"--host-format cell-v2 --host-config", observed)
                for change in ({"schema": handoff.SCHEMA}, {"execution_profile": "unknown"}):
                    bad = dict(copy.deepcopy(f.value), **change)
                    pin = save(Path(f.config_pin["path"]), handoff.canonical(bad))
                    with self.assertRaises(ValueError):
                        handoff.load(Path(pin["path"]), pin["sha256"], f.args.output, f.environment)
                self.assertFalse(f.args.output.exists())
            finally:
                plan.close()

    def test_pin_alias_writable_ancestor_suid_sgid_and_file_caps_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "independent owner pin"):
            installed.prepare(self.probe, "77" * 32)
        for name, reason in (("suid-probe", "without SUID/SGID"), ("sgid-probe", "without SUID/SGID"),
                             ("capability-probe", "file capabilities are forbidden"), ("writable-probe", "without SUID/SGID"),
                             ("writable-parent/native-argv-probe", "ancestors"), ("linked-probe", "unaliased")):
            path = self.deployment / name
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, reason):
                installed.prepare(path, expected)
        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / "alias"
            alias.symlink_to(self.probe)
            with self.assertRaises((ValueError, OSError)):
                installed.prepare(alias, self.probe_sha)

    def test_actual_installed_hepta_cell_entry_and_original_apply_patch_dispatch(self):
        expected = hashlib.sha256(self.host.read_bytes()).hexdigest()
        with installed.prepare(self.host, expected) as image, tempfile.TemporaryDirectory() as directory:
            environment = handoff.checked_environment(dict(os.environ, CODEX_HOME=str(Path(directory) / "codex-home")))
            code, output = exec_image(image, [str(self.host), "--host-format", "cell-v2", "--help"], environment)
            self.assertEqual(code, 0, output)
            self.assertIn("--host-format owner-v2|cell-v2", output)
            code, output = exec_image(image, ["apply_patch", "--host-format", "cell-v2"], environment)
            self.assertEqual(code, 2, output)
            self.assertIn("apply_patch accepts exactly one argument", output)
            self.assertNotIn("requires a reopenable native image", output)

    def test_actual_v3_transport_records_installed_profile_without_model_success(self):
        with tempfile.TemporaryDirectory() as directory:
            f, plan = self.plan(Path(directory))
            plan.close()
            pin = dict(path=f.config_pin["path"], sha256=handoff.checksum(Path(f.config_pin["path"]).read_bytes()))
            argv = [sys.executable, str(SCRIPTS / "run_llm_cell_native_handoff.py"), *CAPS,
                    "--runtime-snapshot", str(f.args.runtime_snapshot),
                    "--runtime-snapshot-sha256", f.args.runtime_snapshot_sha256,
                    "--consumer-mode", "cell-host-v2", "--handoff-config", pin["path"],
                    "--handoff-config-sha256", pin["sha256"]]
            for name, value in {"chain": f.args.chain, "hepta": Path(directory) / "not-opened-hepta",
                "source-parent": f.args.source_parent, "source-materials": f.args.source_materials, "output": f.args.output,
                "python": f.args.python, "cell-bin": f.args.cell_bin, "just": Path(directory) / "not-invoked-just",
                "hepta-target": Path(directory) / "not-invoked-target"}.items():
                argv.extend(("--" + name, str(value)))
            completed = subprocess.run(argv, env=dict(os.environ, **f.environment), capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("--host-format cell-v2 --host-config", completed.stdout)
            report = json.loads((f.args.output / "handoff.json").read_bytes())
            self.assertEqual((report["schema"], report["execution_profile"], report["status"], report["native_receipt_status"]),
                (handoff.INSTALLED_SCHEMA, installed.PROFILE, "transport-complete-handoff-pending", "UNVERIFIED"))
            self.assertTrue(report["transfer"]["within_original_deadline"])
            self.assertEqual(report["transfer"]["limit_seconds"], 35)
            self.assertEqual((f.args.output / "consumer-release.tcd1").read_bytes(), f.tcd)
            for name in ("installation_observed", "final_use_observed", "product_qualification", "production_activation"):
                self.assertIs(report[name], False)


if __name__ == "__main__":
    if os.environ.get("HEPTA_REQUIRE_INSTALLED_FIXTURE") == "1" and (not FIXTURE or not NATIVE):
        raise SystemExit("NOT_CONFIGURED: protected installed ELF fixture and native Cell binary are mandatory for this CI control")
    unittest.main()
