#!/usr/bin/env python3
"""Behavioral failure controls, not a native campaign or toolchain attestation."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import run_pure_pon_admission_daa_v2 as runner


RUSTC = """rustc 1.95.0 (59807616e 2026-04-14)
binary: rustc
commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860
commit-date: 2026-04-14
host: x86_64-unknown-linux-gnu
release: 1.95.0
LLVM version: 22.1.2
"""
CARGO = """cargo 1.95.0 (f2d3ce0bd 2026-03-21)
release: 1.95.0
commit-hash: f2d3ce0bd7f24a49f8f72d9000448f8838c4e850
commit-date: 2026-03-21
host: x86_64-unknown-linux-gnu
"""


def summary(passed=1, failed=0):
    return (f"test result: ok. {passed} passed; {failed} failed; 1 ignored; "
            "0 measured; 0 filtered out; finished in 0.01s\n\n")


class BuildOverrideControls(unittest.TestCase):
    def test_declared_paths_parallelism_and_locked_toolchain_are_allowed(self):
        runner.validate_build_environment({
            "PATH": "/usr/bin", "CARGO_HOME": "/tmp/cargo", "RUSTUP_HOME": "/tmp/rustup",
            "CARGO_TARGET_DIR": "/tmp/target", "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
            "RUSTUP_TOOLCHAIN": "1.95.0", "RUST_TEST_THREADS": "1"})

    def test_target_flags_cannot_override_manifest_profile_behind_json(self):
        for host in ("X86_64_UNKNOWN_LINUX_GNU", "AARCH64_UNKNOWN_LINUX_GNU"):
            for suffix in ("RUSTFLAGS", "RUSTDOCFLAGS", "LINKER", "RUNNER", "AR"):
                name = f"CARGO_TARGET_{host}_{suffix}"
                with self.subTest(name), self.assertRaisesRegex(ValueError, "UNDECLARED_BUILD_OVERRIDE"):
                    runner.validate_build_environment({name: "-C opt-level=0"})

    def test_compiler_profile_native_flags_and_empty_overrides_are_rejected(self):
        names = ("RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                 "RUSTC_BOOTSTRAP", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_OPT_LEVEL",
                 "CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL", "CARGO_BUILD_RUSTC",
                 "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET", "CC", "CXX",
                 "CC_aarch64_unknown_linux_gnu", "HOST_CFLAGS", "TARGET_AR", "LD_PRELOAD",
                 "LD_LIBRARY_PATH", "CMAKE_C_FLAGS_RELEASE", "DYLD_INSERT_LIBRARIES")
        for name in names:
            for value in ("override", ""):
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, name):
                    runner.validate_build_environment({name: value})

    def test_override_diagnostic_does_not_echo_values(self):
        with self.assertRaises(ValueError) as caught:
            runner.validate_build_environment({"RUSTFLAGS": "private-token-value"})
        self.assertNotIn("private-token-value", str(caught.exception))

    def test_cargo_home_local_ancestor_and_dangling_configs_cannot_bypass_env(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, home = base / "parent/repo", base / "cargo-home"
            root.mkdir(parents=True)
            home.mkdir()
            environment = {"CARGO_HOME": str(home)}
            runner.validate_cargo_configuration(environment, root)
            for path in (home / "config.toml", root / ".cargo/config",
                         root.parent / ".cargo/config.toml"):
                path.parent.mkdir(exist_ok=True)
                path.write_text('[build]\nrustflags = ["-Copt-level=0"]\n')
                with self.subTest(path), self.assertRaisesRegex(ValueError, "CARGO_CONFIG_OVERRIDE"):
                    runner.validate_cargo_configuration(environment, root)
                path.unlink()
            dangling = home / "config"
            dangling.symlink_to(home / "not-present")
            with self.assertRaisesRegex(ValueError, "CARGO_CONFIG_OVERRIDE"):
                runner.validate_cargo_configuration(environment, root)


class ActualToolchainControls(unittest.TestCase):
    def test_actual_version_commit_and_native_host_are_retained_without_attestation(self):
        value = runner.toolchain_identity(RUSTC, CARGO, "x86_64")
        self.assertEqual(value["rustc"]["release"], "1.95.0")
        self.assertEqual(value["rustc"]["commit-hash"], "59807616e1fa2540724bfbac14d7976d7e4a3860")
        self.assertFalse(value["supply_chain_attestation"])
        arm = lambda text: text.replace("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")
        self.assertEqual(runner.toolchain_identity(arm(RUSTC), arm(CARGO), "aarch64")
                         ["native_machine"], "aarch64")

    def test_requested_toolchain_name_cannot_replace_wrong_actual_output(self):
        for compiler, cargo in (
                (RUSTC.replace("1.95.0", "1.94.0"), CARGO),
                (RUSTC, CARGO.replace("release: 1.95.0", "release: 1.94.0")),
                (RUSTC.replace("1.95.0 (", "1.95.0-nightly ("), CARGO),
                (RUSTC.replace("commit-hash: 598", "commit-hash: 599"), CARGO),
                (RUSTC + "release: 1.95.0\n", CARGO),
                ("", CARGO), (RUSTC, "cargo 1.95.0\n")):
            with self.subTest(compiler=compiler, cargo=cargo), self.assertRaises(ValueError):
                runner.toolchain_identity(compiler, cargo, "x86_64")

    def test_cross_host_and_missing_compiler_identity_fail(self):
        with self.assertRaisesRegex(ValueError, "NATIVE_HOST"):
            runner.toolchain_identity(RUSTC, CARGO.replace("x86_64", "aarch64"), "x86_64")
        with self.assertRaisesRegex(ValueError, "NATIVE_HOST"):
            runner.toolchain_identity(RUSTC, CARGO, "aarch64")
        with self.assertRaisesRegex(ValueError, "IDENTITY_INCOMPLETE"):
            runner.toolchain_identity(RUSTC.replace("binary: rustc\n", ""), CARGO, "x86_64")


class NativeCompletionControls(unittest.TestCase):
    @staticmethod
    def complete_steps():
        return [{"name": name, "complete_success": True}
                for name in sorted(runner.CLIENT_READER_GATES)]

    def test_zero_tests_has_zero_process_exit_but_never_qualifies(self):
        process = {"complete_success": True, "returncode": 0, "error": None}
        original = deepcopy(process)
        value = runner.native_verdict("pure-cli", process, summary(0))
        self.assertTrue(value["process_complete_success"])
        self.assertFalse(value["nonempty_test_pass"])
        self.assertFalse(value["qualified"])
        self.assertEqual(process, original)

    def test_earlier_nested_success_cannot_hide_zero_test_terminal(self):
        value = runner.native_verdict("pure-cli", {"complete_success": True}, summary(20) + summary(0))
        self.assertFalse(value["qualified"])
        for text in ("", summary().replace("finished in", "truncated at"), summary(failed=1)):
            with self.subTest(text):
                self.assertFalse(runner.native_verdict("pure-cli", {"complete_success": True}, text)["qualified"])

    def test_process_failure_cannot_be_overruled_by_printed_success(self):
        self.assertFalse(runner.native_verdict("pure-cli", {"complete_success": False}, summary())["qualified"])

    def test_cost_contract_cannot_be_satisfied_by_an_unselected_native_test(self):
        steps = self.complete_steps()
        verdicts = [runner.native_verdict(name, steps[0], summary()) for name in sorted(runner.NATIVE_GATES)]
        cost = next(row for row in verdicts if row["name"] == "pressure-attacker-cost-contract")
        original = deepcopy(cost)
        cost.update(runner.native_verdict(cost["name"], steps[0], summary(0)))
        self.assertTrue(cost["process_complete_success"])
        self.assertFalse(runner.terminal_success(steps, verdicts, None, []))
        cost.update(original)
        # A failed independent ledger read stays failed even when every native
        # test and the old pressure service test completed successfully.
        self.assertFalse(runner.terminal_success(
            steps + [{"name": "pure-attacker-cost-reader", "complete_success": False}], verdicts, None, []))

    def test_all_required_native_gates_and_finalization_must_pass(self):
        steps = self.complete_steps()
        verdicts = [runner.native_verdict(name, steps[0], summary()) for name in sorted(runner.NATIVE_GATES)]
        self.assertTrue(runner.terminal_success(steps, verdicts, None, []))
        self.assertFalse(runner.terminal_success(steps, verdicts[:-1], None, []))
        self.assertFalse(runner.terminal_success(steps, verdicts + [verdicts[0]], None, []))
        self.assertFalse(runner.terminal_success([], verdicts, None, []))
        self.assertFalse(runner.terminal_success(steps + [{"complete_success": False}], verdicts, None, []))
        for failure in ("SOURCE_TREE_CHANGED", "TEST_BINARY_CHANGED", "ACTUAL_400_PERCENT_16_GIB_REQUIRED"):
            with self.subTest(failure):
                self.assertFalse(runner.terminal_success(steps, verdicts, None, [failure]))
                self.assertFalse(runner.terminal_success(steps, verdicts, failure, []))
        verdicts[0] = runner.native_verdict(verdicts[0]["name"], steps[0], summary(0))
        self.assertFalse(runner.terminal_success(steps, verdicts, None, []))

    def test_native_pass_cannot_replace_missing_duplicate_or_failed_client_owner_readback(self):
        steps = self.complete_steps()
        verdicts = [runner.native_verdict(name, steps[0], summary()) for name in sorted(runner.NATIVE_GATES)]
        self.assertTrue(runner.terminal_success(steps, verdicts, None, []))
        for changed in (steps[:-1], steps + [steps[0]],
                        [dict(row, complete_success=False) for row in steps],
                        [dict(row, name="original-pressure-reader") for row in steps]):
            with self.subTest(steps=changed):
                self.assertFalse(runner.terminal_success(changed, verdicts, None, []))


class CargoArtifactControls(unittest.TestCase):
    def test_only_complete_release_builds_with_bounded_executable_paths_are_collected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            binary = target / "native-test"
            binary.write_bytes(b"synthetic executable identity; not a native observation")
            path = root / "cargo.jsonl"
            artifact = {"reason": "compiler-artifact", "target": {"name": "fixture"},
                        "profile": {"test": True, "opt_level": "3", "debug_assertions": False},
                        "executable": str(binary)}

            def collect(rows):
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                return runner.test_artifacts(path, target)

            finish = {"reason": "build-finished", "success": True}
            actual = collect([artifact, finish])
            self.assertEqual(actual["fixture"]["sha256"], runner.bounds.sha(binary))
            for rows in ([artifact], [artifact, dict(finish, success=False)],
                         [artifact, dict(finish, success=1)],
                         [artifact, finish, finish], [artifact, artifact, finish]):
                with self.subTest(rows), self.assertRaises(ValueError):
                    collect(rows)
            for profile in ({"test": True, "opt_level": "0", "debug_assertions": False},
                            {"test": True, "opt_level": "3", "debug_assertions": True}):
                with self.subTest(profile), self.assertRaisesRegex(ValueError, "RELEASE_PROFILE"):
                    collect([dict(artifact, profile=profile), finish])
            outside = root / "outside-test"
            outside.write_bytes(b"outside")
            with self.assertRaisesRegex(ValueError, "OUTSIDE_TARGET"):
                collect([dict(artifact, executable=str(outside)), finish])
            link = target / "outside-link"
            link.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "OUTSIDE_TARGET"):
                collect([dict(artifact, executable=str(link)), finish])

    def test_cli_child_executable_is_pinned_even_without_a_test_harness(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            binary = target / "trnm-pon-node"
            binary.write_bytes(b"synthetic CLI identity")
            path = target / "cargo.jsonl"
            executable = {"reason": "compiler-artifact", "target": {"name": "trnm-pon-node", "kind": ["bin"]},
                          "profile": {"test": False, "opt_level": "3", "debug_assertions": False},
                          "executable": str(binary)}
            build_script = deepcopy(executable)
            build_script["target"] = {"name": "build-script-build", "kind": ["custom-build"]}
            path.write_text("".join(json.dumps(row) + "\n" for row in (
                executable, build_script, {"reason": "build-finished", "success": True})))
            actual = runner.test_artifacts(path, target)
            self.assertEqual(set(actual), {"trnm-pon-node"})
            self.assertFalse(actual["trnm-pon-node"]["test_harness"])
            self.assertEqual(actual["trnm-pon-node"]["sha256"], runner.bounds.sha(binary))


if __name__ == "__main__":
    unittest.main(verbosity=2)
