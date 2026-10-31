#!/usr/bin/env python3
"""Synthetic command-owner boundary tests; no native execution or cost evidence."""

from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import run_w1_reused_cost_v3 as runner


class ExecutionBoundaryTests(unittest.TestCase):
    def observe(self, *, before=None, after=None, environment=None, machine="x86_64",
                elf=62, campaign_exit=0, reader_error=None, alerts=None,
                configuration=None, configuration_place="home", change_configuration=None):
        with tempfile.TemporaryDirectory(prefix="reuse-v3-owner-test-") as directory:
            root = Path(directory)
            output, target = root / "receipt", root / "target"
            output.mkdir()
            checkout, cargo_home = root / "checkout", root / "cargo-home"
            checkout.mkdir()
            cargo_home.mkdir()
            config_dir = {"home": cargo_home, "checkout": checkout / ".cargo",
                          "ancestor": root / ".cargo"}[configuration_place]
            config_file = config_dir / "config.toml"
            if configuration is not None:
                config_dir.mkdir(exist_ok=True)
                config_file.write_text(configuration)
            commands = []
            native = target / "x86_64-unknown-linux-gnu/release/examples" / runner.EXAMPLE
            source = {"source_state": "committed-clean", "commit": "a" * 40}

            def capture(command, destination, name, *, timeout, cwd):
                self.assertEqual(cwd, checkout)
                commands.append(command)
                stdout, stderr = destination / (name + ".stdout"), destination / (name + ".stderr")
                stdout.write_text("synthetic boundary fixture\n")
                stderr.write_text("")
                if name == "rustc":
                    stdout.write_text("rustc\nrelease: 1.95.0\nhost: x86_64-unknown-linux-gnu\n")
                if name == "build":
                    native.parent.mkdir(parents=True)
                    native.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + elf.to_bytes(2, "little"))
                    if change_configuration is not None:
                        config_dir.mkdir(exist_ok=True)
                        config_file.write_text(change_configuration)
                return {"command": command, "exit_code": campaign_exit if name == "campaign" else 0,
                    "timed_out": False, "timeout_seconds": timeout,
                    "stdout": stdout.name, "stderr": stderr.name}

            actual_copy = runner.shutil.copyfile

            def copy(source, destination):
                if str(source) == "/proc/cpuinfo":
                    Path(destination).write_text("synthetic CPU identity, not hardware evidence\n")
                    return destination
                return actual_copy(source, destination)

            env = {"CARGO_TARGET_DIR": str(target), "CARGO_HOME": str(cargo_home),
                   **(environment or {})}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(sys, "argv", ["runner", "--arch", "x64", "--local"]), \
                 mock.patch.object(runner, "receipt_root", return_value=output), \
                 mock.patch.object(runner, "ROOT", checkout), \
                 mock.patch.object(runner, "source", side_effect=[before or source, after or source]), \
                 mock.patch.object(runner.platform, "system", return_value="Linux"), \
                 mock.patch.object(runner.platform, "machine", return_value=machine), \
                 mock.patch.object(runner, "capture", side_effect=capture), \
                 mock.patch.object(runner.shutil, "copyfile", side_effect=copy), \
                 mock.patch.object(runner, "analyze", side_effect=reader_error,
                    return_value={"semantic_alerts": alerts or []}), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = runner.main()
            return code, json.loads((output / "manifest.json").read_text()), commands

    def test_explicit_original_release_command_and_selector_are_retained(self):
        code, report, commands = self.observe()
        self.assertEqual(code, 0)
        self.assertEqual(report["execution_context"], "local-native-preflight")
        self.assertEqual(report["schema"], "trnm-w1-actual-reuse-execution-v4")
        self.assertTrue(report["default_release_configuration_checked"])
        self.assertIn(["cargo", "+1.95.0", "build", "--locked", "--release", "--manifest-path",
            "trillionnium/Cargo.toml", "--target", "x86_64-unknown-linux-gnu", "-p", "trnm-pon-node",
            "--example", runner.EXAMPLE], commands)
        self.assertEqual(commands[-1][-1], "--actual-reuse-v3")
        self.assertFalse(report["source_changed"])
        for flag in runner.FALSE_FLAGS:
            self.assertIs(report[flag], False)

    def test_local_mode_cannot_bypass_dirty_source(self):
        code, report, commands = self.observe(before={"source_state": "dirty-candidate"})
        self.assertNotEqual(code, 0)
        self.assertEqual(commands, [])
        self.assertIn("committed source", report["error"])

    def test_test_build_codegen_override_cannot_be_promoted_to_release(self):
        code, report, commands = self.observe(environment={"CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "64"})
        self.assertNotEqual(code, 0)
        self.assertEqual(commands, [])
        self.assertIn("forbids overrides", report["error"])

    def test_requested_architecture_cannot_replace_observed_machine(self):
        code, _, commands = self.observe(machine="aarch64")
        self.assertNotEqual(code, 0)
        self.assertEqual(commands, [])

    def test_wrong_elf_is_refused_before_campaign(self):
        code, report, commands = self.observe(elf=183)
        self.assertNotEqual(code, 0)
        self.assertEqual(len(commands), 4)
        self.assertIn("ELF architecture", report["error"])

    def test_nonzero_native_campaign_is_retained(self):
        code, report, _ = self.observe(campaign_exit=1)
        self.assertNotEqual(code, 0)
        self.assertEqual(report["observations"][-1]["exit_code"], 1)

    def test_zero_or_incomplete_reader_observation_cannot_pass(self):
        code, report, _ = self.observe(reader_error=ValueError("fixed 13-arm/9-class reuse grid incomplete"))
        self.assertNotEqual(code, 0)
        self.assertIn("grid incomplete", report["error"])

    def test_source_change_after_complete_run_still_fails(self):
        code, report, _ = self.observe(after={"source_state": "committed-clean", "commit": "b" * 40})
        self.assertNotEqual(code, 0)
        self.assertTrue(report["source_changed"])

    def test_native_disagreement_cannot_pass_execution_owner(self):
        code, report, _ = self.observe(alerts=[{"outcome": "Product"}])
        self.assertNotEqual(code, 0)
        self.assertEqual(report["reader"]["semantic_alerts"], [{"outcome": "Product"}])

    def test_cargo_aliases_cannot_hide_compiler_flags_or_wrappers_from_rustc_probe(self):
        for name, value in {
            "CARGO_BUILD_RUSTFLAGS": "-C opt-level=0",
            "CARGO_BUILD_RUSTC": "/synthetic/compiler",
            "CARGO_BUILD_RUSTC_WRAPPER": "/synthetic/wrapper",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "/synthetic/workspace-wrapper",
            "CARGO_INCREMENTAL": "1", "CARGO_BUILD_INCREMENTAL": "true",
            "CARGO_BUILD_TARGET": "aarch64-unknown-linux-gnu",
        }.items():
            with self.subTest(name=name):
                code, report, commands = self.observe(environment={name: value})
                self.assertNotEqual(code, 0)
                self.assertEqual(commands, [])
                self.assertEqual(report["build_environment_overrides"], {name: value})
                self.assertFalse(report["default_release_configuration_checked"])

    def test_worktree_ancestor_and_cargo_home_codegen_configuration_are_refused(self):
        for place in ("home", "checkout", "ancestor"):
            with self.subTest(place=place):
                code, report, commands = self.observe(configuration_place=place,
                    configuration='[build]\nrustflags = ["-C", "opt-level=0"]\n')
                self.assertNotEqual(code, 0)
                self.assertEqual(commands, [])
                self.assertTrue(report["cargo_configuration_before"]["violations"])
                self.assertFalse(report["default_release_configuration_checked"])

    def test_release_profile_target_env_and_include_are_not_unrecorded_inputs(self):
        for configuration in (
            '[profile.release]\nopt-level = 0\n',
            '[target.x86_64-unknown-linux-gnu]\nrustflags = ["--cfg", "unchecked"]\n',
            '[env]\nRUSTC_BOOTSTRAP = "1"\n',
            'include = ["unobserved.toml"]\n',
            '[build]\nrustc-wrapper = "/synthetic/wrapper"\n',
        ):
            with self.subTest(configuration=configuration):
                code, report, commands = self.observe(configuration=configuration)
                self.assertNotEqual(code, 0)
                self.assertEqual(commands, [])
                self.assertIn("configuration", report["error"])

    def test_verified_vendor_cache_and_job_settings_remain_usable_and_hashed(self):
        configuration = ('[source.crates-io]\nreplace-with = "verified-vendor"\n'
            '[source.verified-vendor]\ndirectory = "/verified/vendor"\n'
            '[build]\njobs = 2\n[net]\noffline = true\n')
        code, report, _ = self.observe(configuration=configuration,
                                      environment={"CARGO_BUILD_JOBS": "2"})
        self.assertEqual(code, 0)
        self.assertEqual(report["build_environment_overrides"], {})
        self.assertTrue(report["default_release_configuration_checked"])
        present = [row for row in report["cargo_configuration_before"]["files"]
                   if row["state"] == "regular"]
        self.assertEqual(len(present), 1)
        self.assertEqual(present[0]["bytes"], len(configuration))
        self.assertEqual(report["cargo_configuration_before"], report["cargo_configuration_after"])

    def test_changed_neutral_configuration_still_invalidates_the_original_input_epoch(self):
        code, report, _ = self.observe(configuration='[build]\njobs = 2\n',
                                      change_configuration='[build]\njobs = 3\n')
        self.assertNotEqual(code, 0)
        self.assertTrue(report["cargo_configuration_changed"])
        self.assertFalse(report["default_release_configuration_checked"])
        self.assertIn("changed", report["cargo_configuration_error"])

    def test_new_configuration_after_start_cannot_escape_absent_path_inventory(self):
        code, report, _ = self.observe(change_configuration='[build]\njobs = 2\n')
        self.assertNotEqual(code, 0)
        self.assertTrue(report["cargo_configuration_changed"])

    def test_invalid_configuration_never_copies_credentials_into_the_receipt(self):
        secret = "synthetic-credential-do-not-retain"
        code, report, commands = self.observe(configuration='[registry]\ntoken = "' + secret)
        self.assertNotEqual(code, 0)
        self.assertEqual(commands, [])
        self.assertNotIn(secret, json.dumps(report))


class ConfigurationInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cargo-config-observer-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.cargo_home = self.root / "cargo-home"
        self.cargo_home.mkdir()
        self.environment = {"CARGO_HOME": str(self.cargo_home)}

    def observe(self):
        return runner.cargo_configuration_snapshot(self.checkout, self.environment)

    def test_legacy_config_cannot_be_hidden_by_a_clean_config_toml(self):
        (self.cargo_home / "config").write_text('[build]\nrustflags = ["-Copt-level=0"]\n')
        (self.cargo_home / "config.toml").write_text('[build]\njobs = 2\n')
        result = self.observe()
        self.assertEqual(len(result["violations"]), 1)
        self.assertTrue(result["violations"][0]["path"].endswith("/config"))

    def test_relative_cargo_home_is_resolved_from_invocation_directory(self):
        self.environment["CARGO_HOME"] = "../cargo-home"
        (self.cargo_home / "config.toml").write_text('[build]\nrustc = "/other/compiler"\n')
        self.assertTrue(self.observe()["violations"])

    def test_empty_cargo_home_still_reads_default_home_configuration(self):
        user_directory = self.root / "user"
        default_cargo = user_directory / ".cargo"
        default_cargo.mkdir(parents=True)
        (default_cargo / "config.toml").write_text(
            '[build]\nrustflags = ["-Copt-level=0"]\n')
        self.environment = {"HOME": str(user_directory)}
        unset = self.observe()
        self.environment["CARGO_HOME"] = ""
        empty = self.observe()
        self.assertEqual(empty, unset)
        self.assertTrue(empty["violations"])

    def test_empty_and_relative_home_use_the_actual_invocation_directory(self):
        for user_directory in ("", "relative-user"):
            with self.subTest(home=user_directory):
                expected = self.checkout / user_directory / ".cargo" / "config.toml"
                expected.parent.mkdir(parents=True)
                expected.write_text('[build]\nrustc = "/other/compiler"\n')
                self.environment = {"HOME": user_directory, "CARGO_HOME": ""}
                result = self.observe()
                self.assertIn({"path": str(expected), "reason": "build.rustc"},
                              result["violations"])
                expected.unlink()

    def test_manifest_directory_does_not_replace_the_actual_cargo_cwd(self):
        nested = self.checkout / "trillionnium"
        (nested / ".cargo").mkdir(parents=True)
        config = nested / ".cargo" / "config.toml"
        config.write_text('[build]\nrustflags = ["-Copt-level=0"]\n')
        from_root = self.observe()
        self.assertFalse(from_root["violations"])
        from_nested = runner.cargo_configuration_snapshot(nested, self.environment)
        self.assertIn({"path": str(config), "reason": "build.rustflags"},
                      from_nested["violations"])

    def test_linked_and_dangling_configuration_cannot_be_absent(self):
        config = self.cargo_home / "config.toml"
        for target in (self.root / "missing", self.root / "real"):
            if target.name == "real":
                target.write_text('[build]\njobs = 2\n')
            config.symlink_to(target)
            self.assertTrue(self.observe()["violations"])
            config.unlink()

    def test_cargo_home_directory_link_retargeting_changes_the_input_snapshot(self):
        other = self.root / "other-cargo-home"
        other.mkdir()
        for directory in (self.cargo_home, other):
            (directory / "config.toml").write_text('[build]\njobs = 2\n')
        alias = self.root / "cargo-home-alias"
        alias.symlink_to(self.cargo_home, target_is_directory=True)
        self.environment["CARGO_HOME"] = str(alias)
        before = self.observe()
        alias.unlink()
        alias.symlink_to(other, target_is_directory=True)
        after = self.observe()
        self.assertFalse(before["violations"])
        self.assertFalse(after["violations"])
        self.assertNotEqual(before, after)

    def test_configuration_read_is_bounded_and_special_files_do_not_block(self):
        config = self.cargo_home / "config.toml"
        config.write_bytes(b"#" * (1024 * 1024 + 1))
        self.assertTrue(self.observe()["violations"])
        config.unlink()
        os.mkfifo(config)
        self.assertTrue(self.observe()["violations"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
