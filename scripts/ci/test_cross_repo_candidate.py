#!/usr/bin/env python3
"""Adversarial source-binding tests using committed, temporary Git repositories.

The fixture fixes the dependency URL, package roster and Bazel extension shape
independently of the verifier. It creates no native acceptance or model evidence.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "cross_repo_candidate_under_test", HERE / "check_cross_repo_candidate.py"
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

# Independently declared protocol expectations, not copied from verifier output.
CHAIN_URL = "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git"
PACKAGES = (
    "trnm-crypto-primitives",
    "trnm-protocol",
    "trnm-release-bundle",
)
BAZEL_EXTENSION = "@@rules_rs+//rs:extensions.bzl%crate"
HISTORICAL_PIN = "e445769cb44272c0de78ec98a10c3105fc786541"
HISTORICAL_TARGET = "5bb29d6ae39fa0c71f9151f3dce31fa1a3ab1800"


def git(root, *args):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.run(
        ["git", "-C", str(root), *args],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()


def write(root, path, text):
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def commit(root):
    git(root, "add", "--all")
    git(root, "-c", "commit.gpgsign=false", "commit", "-qm", "fixed test material")
    return git(root, "rev-parse", "HEAD")


def source(query, fragment=None, url=CHAIN_URL):
    return f"git+{url}?rev={query}#{query if fragment is None else fragment}"


def fleet(revision):
    return (
        '[package]\nname = "hepta-fleet"\nversion = "0.1.0"\nedition = "2021"\n'
        '[dependencies]\ntrnm-release-bundle = { git = "'
        + CHAIN_URL
        + '", rev = "'
        + revision
        + '" }\n'
    )


def cargo_lock(revision, fragment=None, names=PACKAGES, version="0.1.0"):
    return "version = 4\n" + "".join(
        f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        f'source = "{source(revision, fragment)}"\n'
        for name in names
    )


def bazel_lock(revision, fragment=None, names=PACKAGES):
    return {
        "lockFileVersion": 28,
        "facts": {
            BAZEL_EXTENSION: {
                source(revision, fragment) + "_" + name: json.dumps(
                    {"dependencies": [], "features": {}, "strip_prefix": "crates/" + name}
                )
                for name in names
            }
        },
    }


class CrossRepositoryCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-cross-repo-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.chain = Path(self.temporary.name) / "chain"
        self.hepta = Path(self.temporary.name) / "hepta"
        for root in (self.chain, self.hepta):
            root.mkdir()
            git(root, "init", "-q")
            git(root, "config", "user.name", "Source Binding Test")
            git(root, "config", "user.email", "source-binding-test@example.invalid")
        # Required configuration paths may grow; their exact byte identities are
        # still committed. Dependency semantics below are declared independently.
        for root, paths in ((self.chain, VERIFIER.CHAIN_FILES), (self.hepta, VERIFIER.HEPTA_FILES)):
            for path in paths:
                write(root, path, "{}\n" if path.endswith(".json") else "# test material\n")
        write(self.chain, "trillionnium/Cargo.toml", '[workspace]\nresolver = "2"\nmembers = []\n')
        write(self.chain, "trillionnium/Cargo.lock", "version = 4\n")
        write(self.chain, "rust-toolchain.toml", '[toolchain]\nchannel = "1.95.0"\n')
        for name in PACKAGES:
            write(self.chain, f"trillionnium/crates/{name}/Cargo.toml", f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n')
            write(self.chain, f"trillionnium/crates/{name}/src/lib.rs", "// Unexecuted fixture crate.\n")
        self.chain_commit = commit(self.chain)
        self.hepta_files = {
            "codex-rs/Cargo.toml": '[workspace]\nresolver = "2"\nmembers = ["hepta-fleet"]\n',
            "codex-rs/Cargo.lock": cargo_lock(self.chain_commit),
            "codex-rs/rust-toolchain.toml": '[toolchain]\nchannel = "1.95.0"\n',
            "codex-rs/hepta-fleet/Cargo.toml": fleet(self.chain_commit),
            "codex-rs/hepta-fleet/src/lib.rs": "// Unexecuted fixture crate.\n",
            "MODULE.bazel": 'module(name = "hepta_fixture", version = "0.1.0")\n',
            "MODULE.bazel.lock": json.dumps(bazel_lock(self.chain_commit)),
        }
        for path, text in self.hepta_files.items():
            write(self.hepta, path, text)
        self.hepta_commit = commit(self.hepta)

    def inspect(self, hepta_commit=None):
        return VERIFIER.inspect(
            self.chain, self.chain_commit, self.hepta,
            self.hepta_commit if hepta_commit is None else hepta_commit,
        )

    def changed(self, path, text):
        write(self.hepta, path, text)
        return self.inspect(commit(self.hepta))

    def assert_failed(self, report):
        self.assertEqual(report["source_dependency_alignment"], "FAIL", report)
        self.assertTrue(report["issues"])
        self.assertFalse(report["complete_candidate_qualified"])
        self.assertFalse(report["production_activation"])

    def test_consistent_objects_never_grant_build_model_or_native_acceptance(self):
        report = self.inspect()
        self.assertEqual(report["source_dependency_alignment"], "PASS", report["issues"])
        self.assertEqual({row["package"] for row in report["cargo_chain_packages"]}, set(PACKAGES))
        for key in (
            "working_tree_verified", "effective_build_environment_verified",
            "model_material_bytes_verified", "release_binary_set_verified",
            "complete_candidate_qualified", "independent_accepted", "production_activation",
        ):
            self.assertIs(report[key], False, key)
        self.assertEqual(report["native_tests_executed"], 0)

    def test_historical_e445_declaration_cargo_and_bazel_are_all_rejected(self):
        write(self.hepta, "codex-rs/hepta-fleet/Cargo.toml", fleet(HISTORICAL_PIN))
        write(self.hepta, "codex-rs/Cargo.lock", cargo_lock(HISTORICAL_PIN))
        report = self.changed("MODULE.bazel.lock", json.dumps(bazel_lock(HISTORICAL_PIN)))
        self.assert_failed(report)
        codes = [issue["code"] for issue in report["issues"]]
        self.assertEqual(codes.count("CARGO_DECLARATION_CHAIN_MISMATCH"), 1)
        self.assertEqual(codes.count("CARGO_LOCK_CHAIN_MISMATCH"), 3)
        self.assertEqual(codes.count("BAZEL_LOCK_CHAIN_MISMATCH"), 3)

    def test_cargo_query_and_fragment_must_both_match(self):
        for query, fragment in ((self.chain_commit, HISTORICAL_PIN), (HISTORICAL_PIN, self.chain_commit), (HISTORICAL_TARGET, HISTORICAL_PIN)):
            with self.subTest(query=query, fragment=fragment):
                self.assert_failed(self.changed("codex-rs/Cargo.lock", cargo_lock(query, fragment)))

    def test_bazel_query_and_fragment_must_both_match(self):
        for query, fragment in ((self.chain_commit, HISTORICAL_PIN), (HISTORICAL_PIN, self.chain_commit), (HISTORICAL_TARGET, HISTORICAL_PIN)):
            with self.subTest(query=query, fragment=fragment):
                self.assert_failed(self.changed("MODULE.bazel.lock", json.dumps(bazel_lock(query, fragment))))

    def test_bazel_lookalike_subtree_is_not_the_lock_extension(self):
        data = {"lockFileVersion": 28, "documentation": bazel_lock(self.chain_commit)["facts"]}
        self.assert_failed(self.changed("MODULE.bazel.lock", json.dumps(data)))

    def test_bazel_malformed_key_or_strip_prefix_is_rejected(self):
        for mutation in ("key", "prefix"):
            with self.subTest(mutation=mutation):
                data = bazel_lock(self.chain_commit)
                facts = data["facts"][BAZEL_EXTENSION]
                key = next(iter(facts))
                if mutation == "key":
                    facts[key + "_unexpected"] = facts.pop(key)
                else:
                    facts[key] = json.dumps({"strip_prefix": "../crates/trnm-crypto-primitives"})
                self.assert_failed(self.changed("MODULE.bazel.lock", json.dumps(data)))

    def test_extra_fork_and_encoded_bazel_sources_cannot_hide_behind_valid_roster(self):
        for url in (
            "https://github.com/fork/alternate.git",
            "https://github.com/TrillionniumFoundation/Trillionnium%2DChain.git",
        ):
            with self.subTest(url=url):
                data = bazel_lock(self.chain_commit)
                data["facts"][BAZEL_EXTENSION][source(HISTORICAL_PIN, url=url) + "_trnm-protocol"] = json.dumps({"strip_prefix": "crates/trnm-protocol"})
                self.assert_failed(self.changed("MODULE.bazel.lock", json.dumps(data)))

    def test_bazel_consumer_version_and_serialized_metadata_are_strict(self):
        for version in ("28", True, 27):
            with self.subTest(version=version):
                data = bazel_lock(self.chain_commit)
                data["lockFileVersion"] = version
                write(self.hepta, "MODULE.bazel.lock", json.dumps(data))
                with self.assertRaisesRegex(ValueError, "Bazel lock consumer schema"):
                    self.inspect(commit(self.hepta))
        data = bazel_lock(self.chain_commit)
        data["facts"][BAZEL_EXTENSION][source(self.chain_commit) + "_trnm-protocol"] = {"strip_prefix": "crates/trnm-protocol"}
        write(self.hepta, "MODULE.bazel.lock", json.dumps(data))
        with self.assertRaisesRegex(ValueError, "serialized JSON"):
            self.inspect(commit(self.hepta))

    def test_duplicate_bazel_keys_are_rejected_before_last_value_wins(self):
        key = source(self.chain_commit) + "_trnm-protocol"
        value = json.dumps(json.dumps({"strip_prefix": "crates/trnm-protocol"}))
        raw = '{"facts":{' + json.dumps(BAZEL_EXTENSION) + ':{' + json.dumps(key) + ':' + value + ',' + json.dumps(key) + ':' + value + '}}}'
        write(self.hepta, "MODULE.bazel.lock", raw)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.inspect(commit(self.hepta))

    def test_duplicate_metadata_keys_are_rejected(self):
        data = bazel_lock(self.chain_commit)
        key = source(self.chain_commit) + "_trnm-protocol"
        data["facts"][BAZEL_EXTENSION][key] = '{"strip_prefix":"wrong","strip_prefix":"crates/trnm-protocol"}'
        write(self.hepta, "MODULE.bazel.lock", json.dumps(data))
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.inspect(commit(self.hepta))

    def test_required_cargo_package_cannot_disappear_with_its_bazel_row(self):
        reduced = tuple(name for name in PACKAGES if name != "trnm-protocol")
        write(self.hepta, "codex-rs/Cargo.lock", cargo_lock(self.chain_commit, names=reduced))
        self.assert_failed(self.changed("MODULE.bazel.lock", json.dumps(bazel_lock(self.chain_commit, names=reduced))))

    def test_bazel_package_cannot_disappear_or_duplicate_in_another_namespace(self):
        reduced = PACKAGES[:-1]
        self.assert_failed(self.changed("MODULE.bazel.lock", json.dumps(bazel_lock(self.chain_commit, names=reduced))))
        data = bazel_lock(self.chain_commit)
        data["other_extension"] = {source(self.chain_commit) + "_trnm-protocol": json.dumps({"strip_prefix": "crates/trnm-protocol"})}
        self.assert_failed(self.changed("MODULE.bazel.lock", json.dumps(data)))

    def test_duplicate_cargo_packages_and_wrong_versions_are_rejected(self):
        duplicate = cargo_lock(self.chain_commit, names=PACKAGES + ("trnm-protocol",))
        self.assert_failed(self.changed("codex-rs/Cargo.lock", duplicate))
        self.assert_failed(self.changed("codex-rs/Cargo.lock", cargo_lock(self.chain_commit, version="99.0.0")))

    def test_nested_cargo_lock_is_inspected_without_forbidding_consistent_subsets(self):
        nested = "tools/isolated-helper/Cargo.lock"
        correct = self.changed(nested, cargo_lock(self.chain_commit, names=("trnm-protocol",)))
        self.assertEqual(correct["source_dependency_alignment"], "PASS", correct["issues"])
        self.assert_failed(self.changed(nested, cargo_lock(HISTORICAL_PIN, names=("trnm-protocol",))))

    def test_alias_target_build_dev_patch_and_replace_cannot_hide_a_stale_pin(self):
        base = self.hepta_files["codex-rs/Cargo.toml"]
        for table, key in (
            ("workspace.dependencies", "alias"),
            ('target.\'cfg(target_os = "windows")\'.dependencies', "alias"),
            ("build-dependencies", "alias"),
            ("dev-dependencies", "alias"),
            ('patch."' + CHAIN_URL + '"', "trnm-protocol"),
            ("replace", '"trnm-protocol:0.1.0"'),
        ):
            with self.subTest(table=table):
                extra = f'\n[{table}]\n{key} = {{ package = "trnm-protocol", git = "{CHAIN_URL}", rev = "{HISTORICAL_PIN}" }}\n'
                self.assert_failed(self.changed("codex-rs/Cargo.toml", base + extra))

    def test_registry_string_dependencies_cannot_be_ignored(self):
        base = self.hepta_files["codex-rs/Cargo.toml"]
        for table in ("workspace.dependencies", 'target.\'cfg(target_os = "windows")\'.dependencies', "build-dependencies", "dev-dependencies"):
            with self.subTest(table=table):
                self.assert_failed(self.changed("codex-rs/Cargo.toml", base + f'\n[{table}]\ntrnm-protocol = "0.1.0"\n'))

    def test_alias_to_lowercase_chain_url_cannot_hide_a_stale_pin(self):
        text = self.hepta_files["codex-rs/Cargo.toml"]
        text += f'\n[workspace.dependencies]\nhidden = {{ package = "innocuous", git = "{CHAIN_URL.lower()}", rev = "{HISTORICAL_PIN}" }}\n'
        self.assert_failed(self.changed("codex-rs/Cargo.toml", text))

    def test_path_dependency_and_unresolved_workspace_are_not_qualified(self):
        for dependency in ('{ path = "../local", package = "trnm-protocol" }', "{ workspace = true }"):
            with self.subTest(dependency=dependency):
                text = self.hepta_files["codex-rs/Cargo.toml"] + f'\n[workspace.dependencies]\ntrnm-protocol = {dependency}\n'
                self.assert_failed(self.changed("codex-rs/Cargo.toml", text))

    def test_checked_in_cargo_overrides_require_resolution(self):
        overrides = (
            '[source."' + CHAIN_URL + '"]\nreplace-with = "local"\n[source.local]\ndirectory = "vendor"\n',
            'paths = ["vendor/trnm-protocol"]\n',
            '[patch."' + CHAIN_URL + '"]\ntrnm-protocol = { path = "vendor/trnm-protocol" }\n',
            '[replace]\n"trnm-protocol:0.1.0" = { path = "vendor/trnm-protocol" }\n',
        )
        for config in overrides:
            with self.subTest(config=config):
                self.assert_failed(self.changed(".cargo/config.toml", config))

    def test_git_replace_cannot_relabel_good_or_bad_source(self):
        original = self.hepta_commit
        write(self.hepta, "codex-rs/hepta-fleet/Cargo.toml", fleet(HISTORICAL_PIN))
        bad = commit(self.hepta)
        git(self.hepta, "replace", original, bad)
        self.assertIn(HISTORICAL_PIN, git(self.hepta, "show", original + ":codex-rs/hepta-fleet/Cargo.toml"))
        self.assertEqual(self.inspect(original)["source_dependency_alignment"], "PASS")
        git(self.hepta, "replace", "-d", original)
        git(self.hepta, "replace", bad, original)
        self.assertNotIn(HISTORICAL_PIN, git(self.hepta, "show", bad + ":codex-rs/hepta-fleet/Cargo.toml"))
        self.assert_failed(self.inspect(bad))

    def test_committed_symlink_is_not_a_required_regular_input(self):
        path = self.hepta / "MODULE.bazel.lock"
        path.unlink()
        write(self.hepta, "other-lock.json", self.hepta_files["MODULE.bazel.lock"])
        path.symlink_to("other-lock.json")
        with self.assertRaisesRegex(ValueError, "non-regular source"):
            self.inspect(commit(self.hepta))

    def test_dirty_tree_does_not_change_or_qualify_committed_material(self):
        before = self.inspect()
        write(self.hepta, "codex-rs/hepta-fleet/Cargo.toml", fleet(HISTORICAL_PIN))
        write(self.chain, "config/pon/work-profile-v1.json", '{"uncommitted":true}\n')
        write(self.hepta, ".cargo/config.toml", 'paths = ["uncommitted-override"]\n')
        self.assertTrue(git(self.hepta, "status", "--porcelain"))
        after = self.inspect()
        self.assertEqual(after["candidate_sha256"], before["candidate_sha256"])
        self.assertEqual(after["source_dependency_alignment"], "PASS")
        self.assertIs(after["working_tree_verified"], False)
        self.assertIs(after["effective_build_environment_verified"], False)
        self.assertIs(after["complete_candidate_qualified"], False)

    def test_wrong_expected_candidate_digest_is_refused_by_cli(self):
        completed = subprocess.run(
            [sys.executable, str(HERE / "check_cross_repo_candidate.py"),
             "--chain-root", str(self.chain), "--chain-commit", self.chain_commit,
             "--hepta-root", str(self.hepta), "--hepta-commit", self.hepta_commit,
             "--expected-candidate-sha256", "0" * 64],
            text=True, capture_output=True, timeout=30, check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        error = json.loads(completed.stderr)
        self.assertIn("candidate identity changed", error["error"])
        self.assertIs(error["complete_candidate_qualified"], False)


if __name__ == "__main__":
    unittest.main()
