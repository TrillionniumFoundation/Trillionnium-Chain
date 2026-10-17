#!/usr/bin/env python3
"""Negative tests for scripts.ci.check_supply_chain."""
from __future__ import annotations

import pathlib
import shutil
import tempfile
import unittest

import check_supply_chain


class SupplyChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="trnm-supply-chain-")
        cls.root = pathlib.Path(cls.temporary.name) / "source"
        shutil.copytree(check_supply_chain.ROOT, cls.root, ignore=shutil.ignore_patterns(".git", "target", "__pycache__"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def reject(self, relative: str, mutate):
        path = self.root / relative
        original = path.read_bytes()
        try:
            mutate(path)
            with self.assertRaises(check_supply_chain.Invalid):
                check_supply_chain.check(self.root)
        finally:
            path.write_bytes(original)

    def test_current_inputs_pass(self):
        report = check_supply_chain.check(self.root)
        self.assertEqual(report["workspace_packages"], 24)
        self.assertEqual(report["registry_packages"], 120)
        self.assertEqual(report["pinned_actions"], 6)

    def test_registry_checksum_is_required(self):
        # Keep this mutation simple and deterministic: replace the first
        # checksum value with a non-hex digest of the wrong length.
        def mutate(path):
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                if line.startswith("checksum = "):
                    lines[i] = 'checksum = "bad"'
                    break
            path.write_text("\n".join(lines) + "\n")

        self.reject("trillionnium/Cargo.lock", mutate)

    def test_unknown_dependency_source_is_rejected(self):
        def mutate(path):
            text = path.read_text()
            path.write_text(text.replace("registry+https://github.com/rust-lang/crates.io-index", "git+https://example.invalid/evil", 1))

        self.reject("trillionnium/Cargo.lock", mutate)

    def test_git_manifest_dependency_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + '\n[dependencies.bad]\ngit = "https://example.invalid/evil"\n')

        self.reject("trillionnium/crates/trnm-types/Cargo.toml", mutate)

    def test_external_path_dependency_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + '\n[dependencies.bad]\npath = "../../../../outside"\n')

        self.reject("trillionnium/crates/trnm-types/Cargo.toml", mutate)

    def test_wildcard_manifest_dependency_is_rejected(self):
        def mutate(path):
            text = path.read_text().replace('sha2 = "0.10"', 'sha2 = "*"', 1)
            path.write_text(text)

        self.reject("trillionnium/crates/trnm-types/Cargo.toml", mutate)

    def test_first_party_build_script_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace('[package]\n', '[package]\nbuild = "build.rs"\n', 1))

        self.reject("trillionnium/crates/trnm-types/Cargo.toml", mutate)

    def test_implicit_first_party_build_script_is_rejected(self):
        path = self.root / "trillionnium/crates/trnm-types/build.rs"
        path.write_text("fn main() {}\n")
        try:
            with self.assertRaises(check_supply_chain.Invalid):
                check_supply_chain.check(self.root)
        finally:
            path.unlink()

    def test_first_party_proc_macro_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\n[lib]\nproc-macro = true\n")

        self.reject("trillionnium/crates/trnm-types/Cargo.toml", mutate)

    def test_publishable_workspace_crate_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("publish = false", "publish = true", 1))

        self.reject("trillionnium/crates/trnm-types/Cargo.toml", mutate)

    def test_dependency_patch_override_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + '\n[patch.crates-io]\nsha2 = { git = "https://example.invalid/evil" }\n')

        self.reject("trillionnium/Cargo.toml", mutate)

    def test_workspace_git_dependency_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + '\n[workspace.dependencies]\nunsafe-helper = { git = "https://example.invalid/evil" }\n')

        self.reject("trillionnium/Cargo.toml", mutate)

    def test_unpinned_action_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "actions/checkout@main", 1))

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_quoted_unpinned_action_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "\"uses\": actions/checkout@main", 1))

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_unreviewed_action_owner_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "evil/checkout@11d5960a326750d5838078e36cf38b85af677262", 1))

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_write_permission_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\npermissions:\n  pull-requests: write\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_missing_root_permission_floor_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("permissions: {}\n", "", 1))

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_project_write_permission_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\npermissions: {}\njobs:\n  project: { permissions: { repository-projects: write } }\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_quoted_flow_write_permission_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\njobs: { project: { \"permissions\": { \"contents\": \"write\" } } }\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_flow_write_all_permission_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\njobs: { project: { permissions: write-all } }\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_checkout_credentials_must_be_disabled(self):
        def mutate(path):
            path.write_text(path.read_text().replace("persist-credentials: false", "persist-credentials: true", 1))

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_conditional_required_step_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\n      - if: false\n        run: true\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_continue_on_error_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\n      - continue-on-error: true\n        run: true\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_flow_continue_on_error_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\njobs: { verify: { continue-on-error: true } }\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_flow_conditional_job_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\njobs: { verify: { if: false } }\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_suppressed_shell_failure_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\n      - run: bash scripts/ci/ci_job.sh supply-chain || true\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_fail_fast_disable_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\n      - run: set +e\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_unreviewed_workflow_container_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\ncontainer: evil/image:latest\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_unpinned_workflow_runner_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest", 1))

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_flow_deployment_surface_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\njobs: { deploy: { environment: production } }\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_flow_style_write_permission_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\npermissions: { contents: write }\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_release_surface_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\n      - uses: actions/upload-artifact@0123456789012345678901234567890123456789\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_privileged_event_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("  pull_request:\n", "  pull_request_target:\n", 1))

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_deny_advisory_ignore_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace("ignore = [\n]", 'ignore = ["RUSTSEC-0000-0000"]', 1))

        self.reject("deny.toml", mutate)

    def test_deny_license_allowlist_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace('  "Zlib",\n', '  "GPL-3.0-only",\n', 1))

        self.reject("deny.toml", mutate)

    def test_deny_license_exception_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + '\n[[licenses.exceptions]]\nname = "evil"\nallow = ["MIT"]\n')

        self.reject("deny.toml", mutate)

    def test_unlicensed_policy_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text().replace('unlicensed = "deny"', 'unlicensed = "allow"', 1))

        self.reject("deny.toml", mutate)

    def test_secret_expression_with_spacing_is_rejected(self):
        def mutate(path):
            path.write_text(path.read_text() + "\n# ${{ secrets [ 'TOKEN' ] }}\n")

        self.reject(".github/workflows/trnm-required-baseline.yml", mutate)

    def test_local_cargo_configuration_is_rejected(self):
        path = self.root / ".cargo" / "config.toml"
        path.parent.mkdir()
        try:
            path.write_text("[source.crates-io]\nreplace-with = \"evil\"\n")
            with self.assertRaises(check_supply_chain.Invalid):
                check_supply_chain.check(self.root)
        finally:
            path.unlink()
            path.parent.rmdir()


if __name__ == "__main__":
    unittest.main(verbosity=2)
