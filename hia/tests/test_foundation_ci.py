"""Adversarial CI transfer and predecessor-boundary controls, not native tests."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from hia.tools import qualify_foundation_ci as ci


class FoundationTransfer(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-foundation-transfer-")
        self.root = Path(self.temporary.name)
        self.environment = {
            "TRNM_EXPECTED_SOURCE_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"
        }

    def tearDown(self):
        self.temporary.cleanup()

    def parent(self):
        return {"schema": ci.SCHEMA, "stage": "continuity-native", "status": "PASS",
                "lineage": ci.lineage(self.environment), "native_controls": 659,
                "semantic_cases": 572, "original_rust": "NOT_RUN",
                "whole_node_or_commit_authority": False, "physical_power_loss": False}

    def test_previous_source_run_attempt_and_incomplete_results_are_refused(self):
        parent = self.parent()
        ci.check_parent(parent, ci.lineage(self.environment))
        variants = []
        for key, value in (("git_head", "b" * 40), ("run_id", "124"), ("attempt", 1)):
            changed = copy.deepcopy(parent)
            changed["lineage"][key] = value
            variants.append(changed)
        for key, value in (("status", "FAIL"), ("stage", "continuity-capacity"),
                           ("native_controls", 658), ("semantic_cases", 571),
                           ("original_rust", "PASS"), ("whole_node_or_commit_authority", True)):
            changed = copy.deepcopy(parent)
            changed[key] = value
            variants.append(changed)
        variants.extend(({}, None))
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                ci.check_parent(value, ci.lineage(self.environment))


    def test_json_counts_and_lineage_reject_numeric_type_substitution(self):
        expected = ci.lineage({**self.environment, "GITHUB_RUN_ATTEMPT": "1"})
        parent = self.parent()
        parent["lineage"] = copy.deepcopy(expected)
        ci.check_parent(parent, expected)
        for key, value in (("native_controls", 659.0), ("semantic_cases", 572.0)):
            changed = copy.deepcopy(parent)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                ci.check_parent(changed, expected)
        for attempt in (True, 1.0, "1", None):
            changed = copy.deepcopy(parent)
            changed["lineage"]["attempt"] = attempt
            with self.subTest(attempt=repr(attempt)), self.assertRaises(ValueError):
                ci.check_parent(changed, expected)

    def test_json_nonfinite_constants_and_numeric_overflow_are_refused(self):
        target = self.root / "numbers.json"
        for token in ("NaN", "Infinity", "-Infinity", "1e10000", "-1e10000"):
            target.write_text('{"nested":[{"value":' + token + '}]}')
            with self.subTest(token=token), self.assertRaises(ValueError):
                ci.read(target)
        target.write_text('{"elapsed_seconds":1.25,"integer":1,"flag":true,"empty":null}')
        value = ci.read(target)
        self.assertIs(type(value["elapsed_seconds"]), float)
        self.assertEqual(value["elapsed_seconds"], 1.25)
        self.assertIs(type(value["integer"]), int)
        self.assertIs(value["flag"], True)
        self.assertIsNone(value["empty"])

    def test_nested_json_identity_keeps_boolean_integer_and_float_distinct(self):
        self.assertTrue(ci.same({"a": [1, True, 1.0, None]}, {"a": [1, True, 1.0, None]}))
        for left, right in ((True, 1), (1, 1.0), (False, 0), (None, 0),
                            ({"a": [1]}, {"a": [True]}), ([1], [1, 2]),
                            ({"a": 1}, {"a": 1, "b": 2}),
                            (float("nan"), float("nan")),
                            (float("inf"), float("inf"))):
            with self.subTest(left=repr(left), right=repr(right)):
                self.assertFalse(ci.same(left, right))

    def test_archive_member_sizes_require_actual_integers_before_extraction(self):
        for index, (raw, invalid) in enumerate(((b"x", True), (b"x", 1.0),
                                               (b"", False), (b"", 0.0))):
            archive = self.root / ("numeric-" + str(index) + ".tar.xz")
            member = tarfile.TarInfo("native/result.raw")
            member.size = len(raw)
            with tarfile.open(archive, "x:xz") as stream:
                stream.addfile(member, io.BytesIO(raw))
            entry = {"type": "0", "linkname": "", "bytes": invalid,
                     "sha256": hashlib.sha256(raw).hexdigest()}
            output = self.root / ("numeric-out-" + str(index))
            with self.subTest(index=index), self.assertRaises(ValueError):
                ci.extract_regular(archive, output, {"native/result.raw": entry})
            self.assertFalse(output.exists())

    def archive(self, names):
        path = self.root / "input.tar.xz"
        entries = {}
        with tarfile.open(path, "w:xz") as stream:
            for name in names:
                raw = b"actual fixture bytes\n"
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                stream.addfile(item, io.BytesIO(raw))
                entries[name] = {"bytes": len(raw), "type": item.type.decode("ascii"),
                                 "linkname": "", "sha256": hashlib.sha256(raw).hexdigest()}
        return path, entries

    def test_traversal_duplicate_and_unexpected_roots_are_refused_before_extraction(self):
        for index, names in enumerate((["../escape"], ["native/../escape"], ["/native/file"],
                                       ["original/file"], ["native/file", "native/file"])):
            with self.subTest(names=names):
                archive, entries = self.archive(names)
                output = self.root / ("unpacked-" + str(index))
                with self.assertRaises(ValueError):
                    ci.extract_regular(archive, output, entries)
                self.assertFalse(output.exists())

    def test_missing_extra_and_changed_regular_bytes_are_refused(self):
        archive, entries = self.archive(["native/file"])
        for index, changed in enumerate(({}, {**entries, "native/extra": entries["native/file"]},
                                        {"native/file": {**entries["native/file"], "sha256": "0" * 64}})):
            with self.subTest(index=index), self.assertRaises(ValueError):
                ci.extract_regular(archive, self.root / ("bad-" + str(index)), changed)

    def test_pack_retains_real_fifo_and_link_metadata_without_opening_or_restoring_them(self):
        native = self.root / "hia-continuity-native"
        native.mkdir()
        (native / "regular").write_bytes(b"recorded evidence\n")
        os.mkfifo(native / "pipe")
        outside = self.root / "outside"
        outside.write_bytes(b"outside must remain untouched\n")
        (native / "alias").symlink_to(outside)
        with patch.dict(os.environ, self.environment):
            result = ci.pack("continuity-native", self.root)
        self.assertIs(result["qualification_status_not_changed_by_packaging"], True)
        artifact = self.root / "hia-foundation-artifact"
        package = ci.read(artifact / "package-manifest.json")
        output = self.root / "unpacked"
        skipped = ci.extract_regular(artifact / "complete-evidence.tar.xz", output, package["entries"])
        self.assertEqual({row["name"] for row in skipped}, {"native/pipe", "native/alias"})
        self.assertFalse((output / "native/pipe").exists())
        self.assertFalse((output / "native/alias").is_symlink())
        self.assertEqual((output / "native/regular").read_bytes(), b"recorded evidence\n")
        self.assertEqual(outside.read_bytes(), b"outside must remain untouched\n")

    def test_aliased_receipts_and_duplicate_json_fields_are_refused(self):
        original = self.root / "original.json"
        original.write_text('{"status":"PASS","status":"FAIL"}')
        with self.assertRaises(ValueError):
            ci.read(original)
        alias = self.root / "alias.json"
        alias.symlink_to(original)
        with self.assertRaises(ValueError):
            ci.identity(alias)

    def test_failed_transfer_keeps_actual_downloaded_archive_and_metadata(self):
        download = self.root / "hia-continuity-download"
        download.mkdir()
        original = {"complete-evidence.tar.xz": b"actual invalid archive bytes\n",
                    "package-manifest.json": b'{"status":"invalid fixture"}\n',
                    "native-binding.json": b'{"status":"FAIL"}\n'}
        for name, raw in original.items():
            (download / name).write_bytes(raw)
        with patch.dict(os.environ, self.environment):
            ci.pack("continuity-original", self.root)
        artifact = self.root / "hia-foundation-artifact"
        record = ci.read(artifact / "package-manifest.json")
        self.assertIs(record["downloaded_package_retained_even_on_transfer_failure"], True)
        self.assertEqual(record["transfer_receipts"]["native-binding.json"]["status"], "ABSENT")
        with tarfile.open(artifact / "complete-evidence.tar.xz", "r:xz") as stream:
            for name, raw in original.items():
                self.assertEqual(stream.extractfile("download/" + name).read(), raw)

    def test_untracked_or_mutated_source_cannot_claim_committed_identity(self):
        repo = self.root / "repository"
        repo.mkdir()
        for command in (["git", "init", "-q"],):
            subprocess.run(command, cwd=repo, check=True, capture_output=True)
        source = repo / "runtime.hepta"
        source.write_bytes(b"original native fixture\n")
        subprocess.run(["git", "add", "runtime.hepta"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "-c", "commit.gpgSign=false", "commit", "-qm", "fixture"],
                       cwd=repo, check=True, capture_output=True)
        self.assertEqual(ci.check_committed_sources({"runtime.hepta": ci.identity(source)}, repo), 1)
        floating_identity = ci.identity(source)
        floating_identity["bytes"] = float(floating_identity["bytes"])
        with self.assertRaises(ValueError):
            ci.check_committed_sources({"runtime.hepta": floating_identity}, repo)
        source.write_bytes(b"changed native fixture\n")
        with self.assertRaises(ValueError):
            ci.check_committed_sources({"runtime.hepta": ci.identity(source)}, repo)
        extra = repo / "untracked.hepta"
        extra.write_bytes(b"untracked native fixture\n")
        with self.assertRaises(ValueError):
            ci.check_committed_sources({"untracked.hepta": ci.identity(extra)}, repo)

    def test_optimized_public_cli_fails_before_transfer(self):
        done = subprocess.run(
            [sys.executable, "-B", "-OO", "-m", "hia.tools.qualify_foundation_ci", "unpack"],
            cwd=ci.ROOT, env={**os.environ, **self.environment, "RUNNER_TEMP": str(self.root)},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"refuses optimized Python", done.stderr)
        self.assertFalse((self.root / "hia-continuity-prior").exists())


if __name__ == "__main__":
    unittest.main()
