"""Adversarial hosted Genesis evidence gates; fixtures confer no native authority."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from hia.tools import qualify_genesis_ci as gate
from hia.platform.genesis_store import rust_oracle as oracle

OBSERVATIONS = []
ERRORS = (ValueError, OSError, KeyError, TypeError, lzma.LZMAError, tarfile.TarError)


def digest(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class GenesisEvidenceGates(unittest.TestCase):
    """Only fixture/transport observations; no HIA or original Rust process runs."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ng-ci-")
        self.root = Path(self.temp.name)
        self.environment = {
            "TRNM_EXPECTED_SOURCE_SHA": "a" * 40, "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2", "RUNNER_TEMP": str(self.root),
        }
        self.patcher = patch.dict(os.environ, self.environment)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.addCleanup(self.temp.cleanup)

    def okay(self, name, action):
        value = action()
        OBSERVATIONS.append({"name": name, "expected": "ACCEPT", "status": "PASS"})
        return value

    def refuse(self, name, action):
        with self.assertRaises(ERRORS):
            action()
        OBSERVATIONS.append({"name": name, "expected": "REJECT", "status": "PASS"})

    def parent(self):
        observed = {
            "tested_commit": "a" * 40, "candidate": "a" * 40, "tested_tree": "b" * 40,
            "kind": "head", "tracked_worktree_verified": True, "tracked_entries": 4,
        }
        return {
            "schema": gate.SCHEMA, "stage": "genesis-semantic", "status": "PASS",
            "lineage": gate.lineage(), "native_controls": 30, "native_processes": 62,
            "semantic_cases": 30, "original_rust": "NOT_RUN",
            "whole_node_or_successor_admission": False, "arbitrary_commit": False,
            "physical_power_loss": False, "continuous_hostile_same_uid_safety": False,
            "source_observations": {"before": observed, "after": copy.deepcopy(observed)},
        }

    def test_parent_requires_same_head_run_attempt_and_finite_complete_proof(self):
        value = self.parent()
        self.okay("same-complete-semantic-predecessor", lambda: gate.check_parent(value, gate.lineage()))
        mutations = {
            "foreign-schema": lambda v: v.update(schema=gate.base.SCHEMA),
            "wrong-stage": lambda v: v.update(stage="genesis-crash"),
            "failed-stage": lambda v: v.update(status="FAIL"),
            "foreign-head": lambda v: v["lineage"].update(git_head="c" * 40),
            "foreign-run": lambda v: v["lineage"].update(run_id="124"),
            "foreign-attempt": lambda v: v["lineage"].update(attempt=3),
            "bool-attempt": lambda v: v["lineage"].update(attempt=True),
            "native-count": lambda v: v.update(native_controls=29),
            "bool-count": lambda v: v.update(semantic_cases=True),
            "process-count": lambda v: v.update(native_processes=61),
            "original-pretended": lambda v: v.update(original_rust="PASS"),
            "full-node-claim": lambda v: v.update(whole_node_or_successor_admission=True),
            "arbitrary-commit-claim": lambda v: v.update(arbitrary_commit=True),
            "powerloss-claim": lambda v: v.update(physical_power_loss=True),
            "sameuid-claim": lambda v: v.update(continuous_hostile_same_uid_safety=True),
            "source-after-missing": lambda v: v["source_observations"].pop("after"),
            "source-after-not-verified": lambda v: v["source_observations"]["after"].update(tracked_worktree_verified=False),
            "source-head-mismatch": lambda v: v["source_observations"]["before"].update(tested_commit="c" * 40),
            "source-tree-changed": lambda v: v["source_observations"]["after"].update(tested_tree="c" * 40),
            "tracked-extent-changed": lambda v: v["source_observations"]["after"].update(tracked_entries=3),
            "bool-tracked-extent": lambda v: v["source_observations"]["before"].update(tracked_entries=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                bad = copy.deepcopy(value)
                mutate(bad)
                self.refuse(name, lambda: gate.check_parent(bad, gate.lineage()))

    def test_complete_before_after_and_actual_git_blob_identity(self):
        repository = self.root / "repository"
        repository.mkdir()
        subprocess.run(["git", "init", "-q", str(repository)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "-C", str(repository), "config", "user.name", "Genesis CI Fixture"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.email", "genesis-fixture@example.invalid"], check=True)
        (repository / "tracked.txt").write_bytes(b"exact committed fixture\n")
        subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)
        head = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"]).decode().strip()
        tree = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"]).decode().strip()
        expected = {**gate.lineage(), "git_head": head}
        source = {"tested_commit": head, "candidate": head, "tested_tree": tree, "kind": "head",
                  "tracked_worktree_verified": True, "tracked_entries": 1}
        observations = self.root / "observations"
        put(observations / "source-before.json", source)
        put(observations / "source-after.json", source)
        with patch.object(gate.base, "ROOT", repository):
            self.okay("real-git-before-after-proof", lambda: gate.source_pair(observations, expected))
            for field, replacement in (("tested_commit", "c" * 40), ("tested_tree", "c" * 40),
                                       ("tracked_entries", True), ("tracked_worktree_verified", False), ("kind", "merge")):
                changed = {**source, field: replacement}
                put(observations / "source-after.json", changed)
                self.refuse("source-after-" + field, lambda: gate.source_pair(observations, expected))
            (observations / "source-after.json").unlink()
            self.refuse("source-after-absent", lambda: gate.source_pair(observations, expected))
        sources = {"tracked.txt": gate.identity(repository / "tracked.txt")}
        self.okay("actual-git-blob-match", lambda: gate.base.check_committed_sources(sources, repository))
        (repository / "tracked.txt").write_bytes(b"uncommitted mutation\n")
        self.refuse("actual-git-blob-mutation", lambda: gate.base.check_committed_sources(
            {"tracked.txt": gate.identity(repository / "tracked.txt")}, repository))
        (repository / "untracked.txt").write_bytes(b"untracked\n")
        self.refuse("actual-untracked-input", lambda: gate.base.check_committed_sources(
            {"untracked.txt": gate.identity(repository / "untracked.txt")}, repository))
        self.refuse("captured-path-escape", lambda: gate.base.check_committed_sources({"../escape": digest(b"")}, repository))

    def test_shallow_head_still_verifies_every_current_tracked_byte(self):
        from scripts.ci.verify_ci_source import verify
        origin = self.root / "shallow-origin"
        origin.mkdir()
        subprocess.run(["git", "init", "-q", str(origin)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for key, value in (("user.name", "Genesis CI Fixture"), ("user.email", "fixture@example.invalid")):
            subprocess.run(["git", "-C", str(origin), "config", key, value], check=True)
        for value in (b"first version\n", b"exact current version\n"):
            (origin / "current.txt").write_bytes(value)
            subprocess.run(["git", "-C", str(origin), "add", "current.txt"], check=True)
            subprocess.run(["git", "-C", str(origin), "commit", "-qm", "fixture"], check=True)
        shallow = self.root / "shallow-checkout"
        subprocess.run(["git", "clone", "-q", "--depth", "1", origin.as_uri(), str(shallow)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(subprocess.check_output(["git", "-C", str(shallow), "rev-parse", "--is-shallow-repository"]), b"true\n")
        self.assertEqual(subprocess.check_output(["git", "-C", str(shallow), "rev-list", "--count", "HEAD"]), b"1\n")
        head = subprocess.check_output(["git", "-C", str(shallow), "rev-parse", "HEAD"]).decode().strip()
        value = self.okay("real-depth-one-complete-head-source", lambda: verify("head", head, root=shallow))
        self.assertIs(value["tracked_worktree_verified"], True)
        self.assertEqual(value["tracked_entries"], 1)
        self.okay("real-depth-one-current-blob-binding", lambda: gate.base.check_committed_sources(
            {"current.txt": gate.identity(shallow / "current.txt")}, shallow))
        self.refuse("real-depth-one-foreign-head", lambda: verify("head", "a" * 40, root=shallow))
        (shallow / "current.txt").write_bytes(b"changed working source\n")
        self.refuse("real-depth-one-mutated-current-file", lambda: verify("head", head, root=shallow))

    def native_fixture(self, count=62):
        directory = self.root / "native-fixture"
        directory.mkdir()
        executable = digest(b"FIXTURE_ONLY_NOT_EXECUTABLE")
        rows = []
        for index in range(count):
            folder = directory / ("process-%04d-fixture" % index)
            folder.mkdir()
            stdin, stdout, stderr = b"fixture-offered", b"fixture-observed", b""
            row = {"schema": "trnm.native-genesis-process.v1", "path": str(folder),
                   "executable": executable, "pid": index + 1, "exit_code": 0, "elapsed_ns": 1,
                   "timed_out": False, "child_budget_seconds": 240, "cleanup_budget_seconds": 3,
                   "stdin": digest(stdin), "stdin_hex": stdin.hex(), "stdin_actual_hex": stdin.hex(),
                   "stdin_actual_write_bytes": len(stdin), "stdout": digest(stdout), "stderr": digest(stderr),
                   "stderr_hex": stderr.hex(), "events": []}
            for name, raw in (("stdin.raw", stdin), ("stdout.raw", stdout), ("stderr.raw", stderr), ("events.raw", b"")):
                (folder / name).write_bytes(raw)
            put(folder / "events.json", [])
            put(folder / "process.json", row)
            rows.append(row)
        sources = {"fixture": digest(b"uncommitted-fixture")}
        build = {"source_inputs": sources, "original_sources": sources,
                 "source_set_sha256": gate.object_hash(sources), "executable": executable}
        controls = [{"name": "fixture-%d" % index, "status": "PASS", "processes": []} for index in range(30)]
        for index, row in enumerate(rows):
            controls[index % 30]["processes"].append(row)
        report = {"schema": "trnm.native-default-genesis-qualification.v1", "status": "PASS",
                  "suite": "semantic", "controls_total": 30, "real_native_processes": count, "controls": controls,
                  "scope": copy.deepcopy(gate.NATIVE_SCOPE), "build": build,
                  "native_child_budget_seconds": 240, "cleanup_budget_seconds": 3,
                  "verification": {"source_after": {"status": "PASS", "source_set_sha256": gate.object_hash(sources),
                                   "native_source_files": 1, "original_source_files": 1},
                                   "primary_error": None, "cleanup_errors": []}}
        return directory, report, rows

    def test_native_complete_counts_scope_and_cleanup_cannot_be_forged(self):
        directory, report, _ = self.native_fixture()
        self.okay("complete-hosted-native-receipt-fixture",
                  lambda: gate.validate_native_results(report, "semantic", directory, directory))
        mutations = {
            "missing-control": lambda v: v["controls"].pop(),
            "duplicate-control": lambda v: v["controls"][1].update(name=v["controls"][0]["name"]),
            "failed-control": lambda v: v["controls"][0].update(status="FAIL"),
            "bool-control-count": lambda v: v.update(controls_total=True),
            "wrong-process-count": lambda v: v.update(real_native_processes=61),
            "bool-process-count": lambda v: v.update(real_native_processes=True),
            "wrong-native-suite": lambda v: v.update(suite="crash"),
            "native-timeout-budget-expanded": lambda v: v.update(native_child_budget_seconds=241),
            "native-cleanup-budget-expanded": lambda v: v.update(cleanup_budget_seconds=4),
            "native-complete-node-claim": lambda v: v["scope"].update(complete_node=True),
            "native-unknown-scope": lambda v: v["scope"].update(unreviewed_success=True),
            "native-failed-source-fence": lambda v: v["verification"]["source_after"].update(status="FAIL"),
            "native-source-digest-mismatch": lambda v: v["verification"]["source_after"].update(source_set_sha256="0" * 64),
            "native-primary-error": lambda v: v["verification"].update(primary_error="execution failed"),
            "native-cleanup-error": lambda v: v["verification"].update(cleanup_errors=["child did not settle"]),
            "native-unknown-verification": lambda v: v["verification"].update(unclassified_failure="x"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                bad = copy.deepcopy(report)
                mutate(bad)
                self.refuse(name, lambda: gate.validate_native_results(bad, "semantic", directory, directory))
        self.refuse("fixture-cannot-be-native-build-authority", lambda: gate.genesis_build(report["build"], directory))

    def test_real_process_streams_and_transfer_origin_are_checked(self):
        directory, report, rows = self.native_fixture(1)
        self.okay("raw-process-receipt-fixture", lambda: gate.validate_process_files(report, directory, directory))
        folder = Path(rows[0]["path"])
        for name in ("stdin.raw", "stdout.raw", "stderr.raw", "events.raw"):
            raw = (folder / name).read_bytes()
            (folder / name).write_bytes(raw + b"mutation")
            self.refuse("changed-" + name, lambda: gate.validate_process_files(report, directory, directory))
            (folder / name).write_bytes(raw)
        put(folder / "events.json", [{"unexpected": 1}])
        self.refuse("changed-events-json", lambda: gate.validate_process_files(report, directory, directory))
        put(folder / "events.json", [])
        receipt = (folder / "process.json").read_bytes()
        put(folder / "process.json", {**rows[0], "exit_code": 1})
        self.refuse("changed-complete-process-receipt", lambda: gate.validate_process_files(report, directory, directory))
        (folder / "process.json").write_bytes(receipt)
        extra = directory / "process-unreported"
        extra.mkdir()
        self.refuse("unreported-process-directory", lambda: gate.validate_process_files(report, directory, directory))
        extra.rmdir()
        bad = copy.deepcopy(report)
        bad["controls"][0]["processes"].append({**rows[0], "exit_code": 1})
        self.refuse("same-path-conflicting-receipt", lambda: gate.validate_process_files(bad, directory, directory))
        bad = copy.deepcopy(report)
        bad["controls"][0]["processes"][0]["path"] = str(self.root / "outside")
        self.refuse("process-origin-escape", lambda: gate.validate_process_files(bad, directory, directory))
        transferred = self.root / "transferred"
        shutil.copytree(directory, transferred)
        self.okay("same-raw-observations-rebased-with-explicit-origin",
                  lambda: gate.validate_process_files(report, transferred, directory))

    def test_special_files_are_metadata_only_and_failure_download_is_preserved(self):
        native = self.root / "hia-genesis-semantic"
        native.mkdir()
        (native / "raw.log").write_bytes(b"full observed failure output\n")
        (native / "regular-alias").hardlink_to(native / "raw.log")
        os.mkfifo(native / "fixture.fifo")
        (native / "fixture.link").symlink_to("raw.log")
        (native / "fixture.dangling").symlink_to("missing")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(native / "fixture.sock"))
        put(self.root / "hia-genesis-observations/ci-bind-failure.json", {"status": "FAIL", "primary": "fixture"})
        special = {str(native / name) for name in ("fixture.fifo", "fixture.link", "fixture.dangling", "fixture.sock")}
        real_open = os.open
        opened = []
        def tracked_open(path, flags, *args, **kwargs):
            opened.append(str(path))
            if str(path) in special:
                raise AssertionError("Special fixture must not be opened")
            return real_open(path, flags, *args, **kwargs)
        with patch.object(gate.os, "open", side_effect=tracked_open):
            self.okay("actual-fifo-socket-symlink-safe-pack", lambda: gate.pack("genesis-semantic", self.root))
        package = gate.read(self.root / "hia-genesis-artifact/package-manifest.json")
        self.assertEqual(len(package["special_entries"]), 4)
        self.assertTrue(all(row["opened"] is False for row in package["special_entries"].values()))
        self.assertFalse(special & set(opened))
        self.assertNotIn("binding", package)
        self.assertFalse((self.root / "hia-genesis-artifact/native-binding.json").exists())
        archive = self.root / "hia-genesis-artifact/complete-evidence.tar.xz"
        with tarfile.open(archive) as stream:
            members = stream.getmembers()
            self.assertTrue(all(member.isfile() or member.isdir() for member in members))
            self.assertEqual(stream.extractfile("native/raw.log").read(), b"full observed failure output\n")
            self.assertEqual(stream.extractfile("native/regular-alias").read(), b"full observed failure output\n")
        destination = self.root / "restored"
        self.okay("safe-regular-transfer-no-special-materialization",
                  lambda: gate.safe_extract(archive, destination, package["entries"]))
        self.assertFalse(any(path.is_symlink() for path in destination.rglob("*")))
        self.assertFalse((destination / "native/fixture.fifo").exists())
        other = self.root / "failed-transfer"
        other.mkdir()
        download = other / "hia-genesis-download"
        download.mkdir()
        (download / "broken-package.raw").write_bytes(b"actual rejected download")
        put(other / "hia-genesis-observations/ci-unpack-failure.json", {"status": "FAIL", "error": "bad digest"})
        self.okay("original-failed-download-still-packed", lambda: gate.pack("genesis-original", other))
        record = gate.read(other / "hia-genesis-artifact/package-manifest.json")
        self.assertTrue(record["downloaded_package_retained_even_on_transfer_failure"])
        with tarfile.open(other / "hia-genesis-artifact/complete-evidence.tar.xz") as stream:
            self.assertEqual(stream.extractfile("download/broken-package.raw").read(), b"actual rejected download")
            self.assertIn("observations/ci-unpack-failure.json", stream.getnames())
        self.assertEqual(record["transfer_receipts"]["native-binding.json"], {"status": "ABSENT"})

    def archive(self, label, members):
        path = self.root / (label + ".tar.xz")
        entries = {}
        with tarfile.open(path, "w:xz", preset=1) as stream:
            for name, kind, raw, link in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = link
                info.size = len(raw) if kind == tarfile.REGTYPE else 0
                stream.addfile(info, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
                entry = {"type": kind.decode("ascii"), "bytes": info.size, "linkname": link}
                if kind == tarfile.REGTYPE:
                    entry.update(digest(raw))
                entries[name] = entry
        return path, entries

    def test_complete_archive_roster_and_metadata_are_required(self):
        good = [("native", tarfile.DIRTYPE, b"", ""), ("native/report.json", tarfile.REGTYPE, b"full data", "")]
        archive, entries = self.archive("normal", good)
        self.okay("regular-exact-tar-roster", lambda: gate.safe_extract(archive, self.root / "normal-out", entries))
        self.refuse("fresh-transfer-directory-required", lambda: gate.safe_extract(archive, self.root / "normal-out", entries))
        for index, name in enumerate(("../escape", "/absolute", "native//double", "native/./dot",
                                      "native/../escape", "native\\slash", "native/\x00bad", "alien/file", "native\nline")):
            bad = {name: {"type": "0", "bytes": 0, "sha256": digest(b"")["sha256"], "linkname": ""}}
            self.refuse("unsafe-member-%d" % index, lambda: gate.validate_entries(bad))
        for index, kind in enumerate((tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE)):
            path, roster = self.archive("special-%d" % index, [("native/special", kind, b"", "target" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else "")])
            self.refuse("archive-special-%d" % index, lambda: gate.safe_extract(path, self.root / ("special-out-%d" % index), roster))
        path, roster = self.archive("duplicate", good + [good[1]])
        self.refuse("duplicate-actual-tar-member", lambda: gate.safe_extract(path, self.root / "duplicate-out", roster))
        path, roster = self.archive("extra", good + [("native/extra", tarfile.REGTYPE, b"extra", "")])
        roster.pop("native/extra")
        self.refuse("extra-actual-tar-member", lambda: gate.safe_extract(path, self.root / "extra-out", roster))
        bad = copy.deepcopy(entries)
        bad["native/missing"] = {"type": "0", **digest(b"missing"), "linkname": ""}
        self.refuse("missing-actual-tar-member", lambda: gate.safe_extract(archive, self.root / "missing-out", bad))
        for field, value in (("bytes", 1), ("sha256", "0" * 64), ("type", "5"), ("linkname", "target")):
            bad = copy.deepcopy(entries)
            bad["native/report.json"][field] = value
            self.refuse("changed-tar-" + field, lambda: gate.safe_extract(archive, self.root / ("mutant-" + field), bad))
        bad = {"native/a": {"type": "0", **digest(b"a"), "linkname": ""},
               "native/a/b": {"type": "0", **digest(b"b"), "linkname": ""}}
        self.refuse("regular-ancestor-conflict", lambda: gate.validate_entries(bad))
        bad = copy.deepcopy(entries)
        bad["native/report.json"]["bytes"] = True
        self.refuse("bool-member-extent", lambda: gate.validate_entries(bad))
        with patch.object(gate, "MAX_TRANSFER_BYTES", 2):
            self.refuse("transfer-total-bound", lambda: gate.validate_entries(entries))
        with patch.object(gate, "MAX_TRANSFER_MEMBERS", 1):
            self.refuse("transfer-member-count-bound", lambda: gate.validate_entries(entries))

    def test_xz_truncation_concatenation_and_expansion_are_rejected(self):
        raw = lzma.compress(b"exact complete bytes", preset=1)
        path = self.root / "bounded.xz"
        path.write_bytes(raw)
        self.okay("complete-single-xz-stream", lambda: gate.bounded_xz(path))
        for name, bad in (("truncated-xz", raw[:-1]), ("trailing-xz", raw + b"\0"),
                          ("concatenated-xz", raw + raw), ("wrong-format", b"not xz")):
            path.write_bytes(bad)
            self.refuse(name, lambda: gate.bounded_xz(path))
        path.write_bytes(lzma.compress(b"x" * 1025, preset=1))
        with patch.object(gate, "MAX_TRANSFER_TAR_BYTES", 1024):
            self.refuse("actual-xz-expansion-bound", lambda: gate.bounded_xz(path))

    def original_metadata_fixture(self):
        sources = {"fixture": digest(b"uncommitted fixture")}
        parent = {"source_inputs": sources, "source_set_sha256": gate.object_hash(sources),
                  "original_source_set_sha256": gate.object_hash(sources), "bundle_artifacts": {},
                  "corpus": {"raw": digest(b"")}}
        fences = [{"label": name, "status": "PASS", "errors": []} for name in
                  ("source-before", "isolated-source-before", "compiled-source-and-binary-before", "source-and-binary-after")]
        result = {
            "schema": oracle.REPORT_SCHEMA, "status": "PASS", "primary_error": None, "final_errors": [], "missing_tools": [],
            "controls": 30, "passed": 30, "failed": 0, "original_case_rows_observed": 30,
            "original_tests": list(oracle.ORIGINAL_TESTS), "required_original_tests": list(oracle.ORIGINAL_TESTS),
            "required_original_ignored_child": oracle.REQUIRED_IGNORED_CHILD,
            "source_inputs": sources, "original_sources": sources, "native_source_set_sha256": gate.object_hash(sources),
            "native_bundle_artifacts": {}, "exact_corpus": digest(b""),
            "original_production_function_bytes_preserved": True, "complete_node": False, "successor_admission": False,
            "arbitrary_commit": False, "cross_format_sqlite_compatibility_claimed": False,
            "original_error_strings_equivalent": False, "physical_power_loss": False, "source_fences": fences,
        }
        directory = self.root / "original-fixture"
        directory.mkdir()
        for row in fences:
            put(directory / (row["label"] + ".json"), row)
        return result, directory, parent

    def test_original_requires_actual_complete_tests_sources_and_settled_stages(self):
        result, directory, parent = self.original_metadata_fixture()
        mutations = {
            "not-run-original": lambda v: v.update(status="NOT_RUN"),
            "original-primary-failure": lambda v: v.update(primary_error="failed"),
            "original-cleanup-failure": lambda v: v.update(final_errors=["cleanup"]),
            "original-missing-tool": lambda v: v.update(missing_tools=["cargo"]),
            "original-case-count": lambda v: v.update(controls=29),
            "original-bool-count": lambda v: v.update(failed=False),
            "original-no-row": lambda v: v.update(original_case_rows_observed=29),
            "original-retained-missing": lambda v: v.update(original_tests=list(oracle.ORIGINAL_TESTS[:-1])),
            "original-ignored-child-missing": lambda v: v.update(required_original_ignored_child="wrong"),
            "original-source-mismatch": lambda v: v.update(native_source_set_sha256="0" * 64),
            "original-bundle-mismatch": lambda v: v.update(native_bundle_artifacts={"wrong": digest(b"x")}),
            "original-corpus-mismatch": lambda v: v.update(exact_corpus=digest(b"changed")),
            "original-producer-modified": lambda v: v.update(original_production_function_bytes_preserved=False),
            "original-complete-node-claim": lambda v: v.update(complete_node=True),
            "original-arbitrary-commit-claim": lambda v: v.update(arbitrary_commit=True),
            "original-error-string-parity-claim": lambda v: v.update(original_error_strings_equivalent=True),
            "original-final-source-fence-missing": lambda v: v["source_fences"].pop(),
            "original-source-fence-failed": lambda v: v["source_fences"][0].update(status="FAIL"),
            "original-source-fence-errors": lambda v: v["source_fences"][0].update(errors=["mutated"]),
            "original-fence-raw-mismatch": lambda v: v["source_fences"][0].update(unreported=1),
            "original-stages-missing": lambda v: v.update(stages=[]),
        }
        for name, mutate in mutations.items():
            bad = copy.deepcopy(result)
            mutate(bad)
            self.refuse(name, lambda: gate.check_original_results(bad, directory, parent, {"cases": []}))
        names = ["rustc-version", "cargo-original-metadata", "cargo-original-test-build", "list-original-tests",
                 "retained-original-0", "retained-original-1", "retained-original-2", "actual-default-genesis-corpus"]
        stages = []
        for name in names:
            row = {"stage": name, "status": "PASS", "exit_code": 0, "timed_out": False, "launch_error": None,
                   "cleanup_error": None, "output_files_closed": True, "stdout": digest(b""), "stderr": digest(b"")}
            put(directory / name / "receipt.json", row)
            (directory / name / "stdout.raw").write_bytes(b"")
            (directory / name / "stderr.raw").write_bytes(b"")
            stages.append(row)
        result["stages"] = stages
        for field, value in (("exit_code", 1), ("exit_code", False), ("timed_out", True), ("cleanup_error", "wait"),
                             ("launch_error", "launch"), ("output_files_closed", False)):
            bad = copy.deepcopy(result)
            bad["stages"][-1][field] = value
            self.refuse("original-stage-" + field + "-" + str(value),
                        lambda: gate.check_original_results(bad, directory, parent, {"cases": []}))
        self.refuse("original-binary-missing",
                    lambda: gate.check_original_results(result, directory, parent, {"cases": []}))

    def test_cli_optimization_and_failed_binding_preserve_failure(self):
        for option in ("-O", "-OO"):
            child = subprocess.run([sys.executable, option, "-B", "-m", "hia.tools.qualify_genesis_ci",
                                    "bind", "--stage", "genesis-semantic"],
                                   env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertNotEqual(child.returncode, 0)
            self.assertIn(b"refuses optimized Python", child.stderr)
            self.assertFalse((self.root / "hia-genesis-observations/binding.json").exists())
            OBSERVATIONS.append({"name": "actual-cli-" + option, "expected": "REJECT", "status": "PASS"})
        env = {**os.environ, "PYTHONOPTIMIZE": "1"}
        child = subprocess.run([sys.executable, "-B", "-m", "hia.tools.qualify_genesis_ci",
                                "pack", "--stage", "genesis-semantic"], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertNotEqual(child.returncode, 0)
        self.assertFalse((self.root / "hia-genesis-artifact").exists())
        OBSERVATIONS.append({"name": "actual-cli-optimize-environment", "expected": "REJECT", "status": "PASS"})
        child = subprocess.run([sys.executable, "-B", "-m", "hia.tools.qualify_genesis_ci",
                                "bind", "--stage", "genesis-semantic"], env=os.environ.copy(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(child.returncode, 1)
        receipt = gate.read(self.root / "hia-genesis-observations/ci-bind-failure.json")
        self.assertEqual(receipt["status"], "FAIL")
        self.assertIn("FileNotFoundError", receipt["error"])
        self.assertFalse((self.root / "hia-genesis-observations/binding.json").exists())
        OBSERVATIONS.append({"name": "actual-cli-missing-source-preserves-failure", "expected": "REJECT", "status": "PASS"})


if __name__ == "__main__":
    unittest.main()
