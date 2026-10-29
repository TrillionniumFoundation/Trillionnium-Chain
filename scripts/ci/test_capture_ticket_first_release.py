#!/usr/bin/env python3
"""Capture-contract controls with a mocked child; no native work is executed.

Temporary source/binary bytes exercise capture identity, failure preservation
and the explicit new release selector. These tests are not build or cost
evidence and do not supply a successful substitute for the native campaign.
"""
import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import capture_pure_pon_campaign as capture


class Capture(unittest.TestCase):
    def invoke(self, *, profile=None, name="pon_ticket_first_cost_v1", timeout=610,
               arguments=(), environment=None, child_exit=0, child_timeout=False,
               change_binary=False, configuration=None, config_name="config.toml",
               stdout=b'{"synthetic":true}\n', stderr=b"synthetic partial stderr\n"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout/project"
            environment = dict(environment or {})
            environment.setdefault("CARGO_HOME", str(Path(directory) / "isolated-cargo-home"))
            if configuration is not None:
                folder = {"root": root / ".cargo", "ancestor": root.parent / ".cargo",
                          "cargo-home": Path(environment["CARGO_HOME"])}[configuration]
                folder.mkdir(parents=True)
                (folder / config_name).write_text('[build]\nrustflags = ["-C", "opt-level=1"]\n')
            code = root / "trillionnium/crates/trnm-pon-node/examples" / (name + ".rs")
            code.parent.mkdir(parents=True, exist_ok=True)
            code.write_text("// Explicit synthetic source control; never compiled.\n")
            (root / "trillionnium/Cargo.lock").write_text("synthetic lock control\n")
            (root / "trillionnium/Cargo.toml").write_text("synthetic manifest control\n")
            binary = root / "bin" / name
            binary.parent.mkdir()
            binary.write_bytes(b"synthetic non-executable control bytes")
            output = root / "observations"
            argv = ["capture_pure_pon_campaign.py", "--binary", str(binary),
                    "--output", str(output), "--timeout", str(timeout)]
            if profile is not None:
                argv += ["--build-profile", profile]
            argv += list(arguments)

            def git(*args):
                return {("rev-parse", "--show-toplevel"): str(root),
                        ("rev-parse", "HEAD"): "1" * 40,
                        ("rev-parse", "HEAD^{tree}"): "2" * 40}[args]

            class Child:
                pid = 12345

                def __init__(self):
                    self.calls = 0

                def wait(self, timeout=None):
                    self.calls += 1
                    if child_timeout and self.calls == 1:
                        raise subprocess.TimeoutExpired([str(binary)], timeout)
                    return -9 if child_timeout else child_exit

            def spawn(command, **options):
                self.assertTrue(options["start_new_session"])
                options["stdout"].write(stdout)
                options["stderr"].write(stderr)
                if change_binary:
                    binary.write_bytes(b"changed synthetic executable identity")
                return Child()

            printed, errors = io.StringIO(), io.StringIO()
            result, failure = None, None
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(capture, "git", side_effect=git))
                stack.enter_context(mock.patch.object(capture.subprocess, "run", return_value=SimpleNamespace(returncode=0)))
                stack.enter_context(mock.patch.object(capture.subprocess, "check_output", return_value="rustc synthetic control\n"))
                spawned = stack.enter_context(mock.patch.object(capture.subprocess, "Popen", side_effect=spawn))
                killed = stack.enter_context(mock.patch.object(capture.os, "killpg"))
                stack.enter_context(mock.patch.object(capture.platform, "platform", return_value="synthetic-control"))
                stack.enter_context(mock.patch.object(capture.platform, "machine", return_value="x86_64"))
                stack.enter_context(mock.patch.object(capture.resource, "getrusage", side_effect=[
                    SimpleNamespace(ru_utime=0.0, ru_stime=0.0, ru_maxrss=0),
                    SimpleNamespace(ru_utime=0.25, ru_stime=0.125, ru_maxrss=1024)]))
                stack.enter_context(mock.patch.object(capture.time, "monotonic_ns", side_effect=[100, 200]))
                stack.enter_context(mock.patch.dict(capture.os.environ, environment, clear=True))
                stack.enter_context(mock.patch("sys.argv", argv))
                stack.enter_context(contextlib.redirect_stdout(printed))
                stack.enter_context(contextlib.redirect_stderr(errors))
                try:
                    result = capture.main()
                except SystemExit as error:
                    failure = error.code
            report = json.loads((output / "capture.json").read_text()) if (output / "capture.json").exists() else None
            return {
                "returncode": result, "parser_exit": failure, "errors": errors.getvalue(),
                "spawn_calls": spawned.call_count, "kill_calls": killed.call_args_list,
                "output_created": output.exists(), "report": report,
                "raw_stdout": gzip.decompress((output / "stdout.jsonl.gz").read_bytes())
                    if (output / "stdout.jsonl.gz").exists() else None,
                "raw_stderr": (output / "stderr.log").read_bytes() if (output / "stderr.log").exists() else None,
            }

    def test_default_test_profile_keeps_old_schema_overrides_and_runtime_arguments(self):
        observed = self.invoke(name="pon_legal_ticket_batch_v4", timeout=250,
            arguments=("--", "/synthetic/packets"),
            configuration="root",
            environment={"CARGO_BUILD_JOBS": "7", "RUSTFLAGS": "legacy-control-not-a-real-build"})
        self.assertEqual(observed["returncode"], 0)
        report = observed["report"]
        self.assertEqual(report["schema"], "pon-pure-native-capture-v1")
        self.assertEqual(report["build_profile"], "cargo --profile test; repository package overrides")
        self.assertEqual(report["package_opt_levels"],
                         {"trnm-pon-node": 3, "trnm-crypto-primitives": 3, "trnm-mvcc-fee": 1})
        self.assertEqual(report["build_jobs"], 1)
        self.assertNotIn("build_environment_overrides", report)
        self.assertEqual(report["argv"][1:], ["/synthetic/packets"])

    def test_explicit_release_identity_records_observed_jobs_and_no_overrides(self):
        observed = self.invoke(profile="ticket-first-release", environment={
            "CARGO_BUILD_JOBS": "3", "CARGO_INCREMENTAL": "0", "CARGO_TARGET_DIR": "/synthetic/cache",
            "RUSTUP_TOOLCHAIN": "1.95.0"})
        self.assertEqual(observed["returncode"], 0)
        report = observed["report"]
        self.assertEqual(report["schema"], "pon-ticket-first-release-capture-v1")
        self.assertEqual(report["build_profile"], "cargo --release; original repository release defaults")
        self.assertEqual(report["package_opt_levels"],
                         {"trnm-pon-node": 3, "trnm-crypto-primitives": 3, "trnm-mvcc-fee": 3})
        self.assertEqual(report["build_jobs"], 3)
        self.assertEqual(report["build_environment_overrides"], {})
        self.assertEqual(len(report["argv"]), 1)
        self.assertEqual(report["stderr_sha256"], hashlib.sha256(observed["raw_stderr"]).hexdigest())

    def test_release_selector_rejects_other_driver_timeout_or_runtime_arguments(self):
        for changed in (dict(name="pon_legal_ticket_cost_v5"), dict(timeout=250),
                        dict(arguments=("--", "override")), dict(arguments=("--",))):
            with self.subTest(changed=changed):
                observed = self.invoke(profile="ticket-first-release", environment={"CARGO_BUILD_JOBS": "1"}, **changed)
                self.assertEqual(observed["parser_exit"], 2)
                self.assertEqual(observed["spawn_calls"], 0)
                self.assertFalse(observed["output_created"])

    def test_release_overrides_fail_before_artifacts_or_spawn_without_printing_values(self):
        names = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                 "RUSTC_BOOTSTRAP", "CARGO_BUILD_TARGET", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC",
                 "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                 "CARGO_PROFILE_RELEASE_OPT_LEVEL", "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS",
                 "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                 "CARGO_INCREMENTAL", "RUSTDOCFLAGS", "LD_PRELOAD", "CPPFLAGS", "CARGO_PROFILE_TEST_DEBUG")
        for name in names:
            with self.subTest(name=name):
                observed = self.invoke(profile="ticket-first-release", environment={
                    "CARGO_BUILD_JOBS": "1", name: "do-not-print-this-value"})
                self.assertEqual(observed["parser_exit"], 2)
                self.assertEqual(observed["spawn_calls"], 0)
                self.assertFalse(observed["output_created"])
                self.assertIn(name, observed["errors"])
                self.assertNotIn("do-not-print-this-value", observed["errors"])

    def test_empty_overrides_cannot_suppress_configuration_silently(self):
        for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "LD_LIBRARY_PATH",
                     "CARGO_PROFILE_RELEASE_DEBUG", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                     "CARGO_INCREMENTAL"):
            with self.subTest(name=name):
                observed = self.invoke(profile="ticket-first-release", environment={"CARGO_BUILD_JOBS": "1", name: ""})
                self.assertEqual(observed["parser_exit"], 2)
                self.assertEqual(observed["spawn_calls"], 0)
                self.assertFalse(observed["output_created"])
                self.assertIn(name, observed["errors"])

    def test_cargo_config_in_project_ancestor_or_cargo_home_fails_before_spawn(self):
        for location in ("root", "ancestor", "cargo-home"):
            for name in ("config", "config.toml"):
                with self.subTest(location=location, name=name):
                    observed = self.invoke(profile="ticket-first-release", environment={"CARGO_BUILD_JOBS": "1"},
                                           configuration=location, config_name=name)
                    self.assertEqual(observed["parser_exit"], 2)
                    self.assertEqual(observed["spawn_calls"], 0)
                    self.assertFalse(observed["output_created"])
                    self.assertIn("CARGO_CONFIG_OVERRIDE_NOT_ALLOWED", observed["errors"])

    def test_missing_or_invalid_jobs_cannot_be_reported_as_observed_one(self):
        for value in (None, "", "not-an-integer", "0", "-1"):
            with self.subTest(value=value):
                environment = {} if value is None else {"CARGO_BUILD_JOBS": value}
                observed = self.invoke(profile="ticket-first-release", environment=environment)
                self.assertEqual(observed["parser_exit"], 2)
                self.assertEqual(observed["spawn_calls"], 0)
                self.assertFalse(observed["output_created"])

    def test_nonzero_child_preserves_complete_partial_stdout_and_stderr(self):
        stdout = b'{"kind":"begin","synthetic_control":true}\n'
        stderr = b'{"kind":"trial-start","synthetic_control":true}\nACTUAL_TEST_FAILURE\n'
        observed = self.invoke(profile="ticket-first-release", environment={"CARGO_BUILD_JOBS": "1"},
                               child_exit=7, stdout=stdout, stderr=stderr)
        self.assertEqual(observed["returncode"], 1)
        self.assertEqual(observed["report"]["exit_code"], 7)
        self.assertFalse(observed["report"]["timed_out"])
        self.assertEqual(observed["raw_stdout"], stdout)
        self.assertEqual(observed["raw_stderr"], stderr)
        self.assertEqual(observed["report"]["stdout_uncompressed_sha256"], hashlib.sha256(stdout).hexdigest())
        self.assertEqual(observed["report"]["stderr_sha256"], hashlib.sha256(stderr).hexdigest())

    def test_timeout_cleanup_and_changed_binary_remain_failures(self):
        timed = self.invoke(profile="ticket-first-release", environment={"CARGO_BUILD_JOBS": "1"}, child_timeout=True)
        self.assertEqual(timed["returncode"], 1)
        self.assertTrue(timed["report"]["timed_out"])
        self.assertEqual(timed["kill_calls"], [mock.call(12345, signal.SIGKILL)])
        changed = self.invoke(profile="ticket-first-release", environment={"CARGO_BUILD_JOBS": "1"}, change_binary=True)
        self.assertEqual(changed["returncode"], 1)
        self.assertFalse(changed["report"]["stable_binary"])
        self.assertNotEqual(changed["report"]["binary_sha256_before"], changed["report"]["binary_sha256_after"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
