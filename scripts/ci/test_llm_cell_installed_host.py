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
            self.assertIn("--host-format owner-v1|cell-v2", output)
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
