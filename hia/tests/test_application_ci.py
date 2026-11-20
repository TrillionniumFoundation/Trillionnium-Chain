"""Adversarial application evidence fixtures; these tests confer no runtime qualification."""
from __future__ import annotations

import copy
import hashlib
import json
import lzma
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from hia.tools import qualify_application_ci as gate


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


class ApplicationEvidenceBoundaries(unittest.TestCase):
    controls = 0

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="application-ci-boundary-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = {"TRNM_EXPECTED_SOURCE_SHA": "a" * 40, "GITHUB_RUN_ID": "123",
                    "GITHUB_RUN_ATTEMPT": "2", "RUNNER_TEMP": str(self.root)}
        environment = patch.dict(os.environ, self.env)
        environment.start()
        self.addCleanup(environment.stop)

    def rejected(self, call, message=None):
        type(self).controls += 1
        manager = self.assertRaisesRegex((ValueError, OSError, KeyError), message) if message else \
            self.assertRaises((ValueError, OSError, KeyError))
        with manager:
            call()

    def accepted(self, call):
        type(self).controls += 1
        return call()

    def binding(self, root=None):
        root = self.root if root is None else root
        sources = {"fixture/source.py": gate.bytes_id(b"source fixture, not executed")}
        from hia.platform.execution_application import rust_oracle as oracle
        artifacts = {}
        for logical, field in (("native/report.json", "native_report"), ("physical/report.json", "physical_report"),
                               ("integrity/report.json", "integrity_report"), ("original/report.json", "original_report"),
                               ("original/original-test-binary", "original_binary")):
            role, name = logical.split("/", 1)
            target = gate.evidence_roots(root)[role] / name
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"explicit unittest fixture, not executed\\n")
            artifacts[field] = gate.identity(target)
        files, special = gate.evidence_inventory(gate.evidence_roots(root))
        if not files:
            p = gate.observations(root) / "fixture.json"
            put(p, {"fixture_only": True})
            files, special = gate.evidence_inventory(gate.evidence_roots(root))
        counts = {"native_histories": 328, "native_transactions": 335, "native_state_commands": 8784,
                  "native_processes": 9, "physical_controls": 32, "physical_processes": 23,
                  "integrity_groups": 9, "integrity_controls": len(gate.integrity_roster(sources)),
                  "public_cli_rejections": 16, "original_histories": 328, "original_transactions": 335}
        return {"schema": gate.SCHEMA, "stage": gate.STAGE, "status": "PASS", "lineage": gate.base.lineage(),
                "source_inputs": sources, "original_sources": sources,
                "source_set_sha256": gate.object_hash(sources), "original_source_set_sha256": gate.object_hash(sources),
                "physical_trace": "PASS", "original_rust": "PASS",
                "whole_node_or_commit_authority": False, "admission_persistence": False,
                "batch_execution_qualified": False, "physical_power_loss": False, "nondefault_configurations": False,
                "evidence_files": files, "evidence_set_sha256": gate.object_hash(files),
                "special_evidence_metadata": special, "source_observations": {"fixture_only": True},
                "retained_original_tests": list(oracle.TESTS), **artifacts, **counts}

    def test_binding_requires_exact_head_run_attempt_complete_counts_and_finite_scope(self):
        value = self.binding()
        self.accepted(lambda: gate.check_binding(value, gate.base.lineage()))
        mutations = [
            lambda v: v.update(schema="other"),
            lambda v: v.update(stage="prepare-semantic"),
            lambda v: v.update(status="FAIL"),
            lambda v: v["lineage"].update(git_head="b" * 40),
            lambda v: v["lineage"].update(run_id="124"),
            lambda v: v["lineage"].update(attempt=1),
            lambda v: v["lineage"].update(attempt=True),
            lambda v: v.update(source_set_sha256="0" * 64),
            lambda v: v.update(original_source_set_sha256="0" * 64),
            lambda v: v.update(evidence_set_sha256="0" * 64),
            lambda v: v.update(evidence_files={}),
            lambda v: v.update(physical_trace="NOT_RUN"),
            lambda v: v.update(original_rust="NOT_RUN"),
            lambda v: v.update(retained_original_tests=[]),
            lambda v: v.update(original_binary=gate.bytes_id(b"other-binary"))]
        for key in ("native_histories", "native_transactions", "native_state_commands", "native_processes",
                    "physical_controls", "physical_processes", "integrity_groups", "integrity_controls",
                    "public_cli_rejections", "original_histories", "original_transactions"):
            mutations.extend((lambda v, key=key: v.update({key: v[key] - 1}),
                              lambda v, key=key: v.update({key: True})))
        for key in ("whole_node_or_commit_authority", "admission_persistence", "batch_execution_qualified",
                    "physical_power_loss", "nondefault_configurations"):
            mutations.append(lambda v, key=key: v.update({key: True}))
        for index, change in enumerate(mutations):
            changed = copy.deepcopy(value)
            change(changed)
            with self.subTest(control=index):
                self.rejected(lambda: gate.check_binding(changed, gate.base.lineage()))
        omitted = copy.deepcopy(value)
        del omitted["evidence_files"]["original/original-test-binary"]
        omitted["evidence_set_sha256"] = gate.object_hash(omitted["evidence_files"])
        self.rejected(lambda: gate.check_binding(omitted, gate.base.lineage()))
        for name in ("../escape", "/absolute", "native/../escape", "unadmitted/file"):
            changed = copy.deepcopy(value)
            changed["evidence_files"] = {name: gate.bytes_id(b"x")}
            changed["evidence_set_sha256"] = gate.object_hash(changed["evidence_files"])
            self.rejected(lambda: gate.check_binding(changed, gate.base.lineage()))

    def test_committed_blob_and_source_pair_use_actual_git_head(self):
        repo = self.root / "git-fixture"
        repo.mkdir()
        (repo / "source.txt").write_bytes(b"source fixture\n")
        for argv in (["git", "init", "-q"], ["git", "add", "source.txt"],
                     ["git", "-c", "user.name=Evidence Fixture", "-c", "user.email=fixture@invalid",
                      "commit", "-q", "-m", "evidence boundary fixture"]):
            subprocess.run(argv, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        source = {"source.txt": gate.identity(repo / "source.txt")}
        self.accepted(lambda: gate.base.check_committed_sources(source, repo))
        self.rejected(lambda: gate.base.check_committed_sources({"source.txt": gate.bytes_id(b"changed")}, repo))
        self.rejected(lambda: gate.base.check_committed_sources({"missing": gate.bytes_id(b"")}, repo))
        for name in ("../escape", "/absolute", "source.txt\nother"):
            self.rejected(lambda name=name: gate.base.check_committed_sources({name: gate.bytes_id(b"")}, repo))
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
        observed = self.root / "source-proof"
        before = {"tested_commit": head, "candidate": head, "tested_tree": tree, "kind": "head",
                  "tracked_entries": 1, "tracked_worktree_verified": True}
        expected = {"git_head": head, "run_id": "123", "attempt": 2}
        put(observed / "source-before.json", before)
        put(observed / "source-after.json", before)
        with patch.object(gate.base, "ROOT", repo):
            self.accepted(lambda: gate.transfer.source_pair(observed, expected))
            for key, value in (("candidate", "c" * 40), ("tested_commit", "c" * 40), ("tested_tree", "c" * 40),
                               ("kind", "merge"), ("tracked_entries", True), ("tracked_worktree_verified", False)):
                changed = {**before, key: value}
                put(observed / "source-before.json", changed)
                self.rejected(lambda: gate.transfer.source_pair(observed, expected))
            put(observed / "source-before.json", before)
            for key, value in (("tracked_entries", 2), ("tested_tree", "d" * 40), ("tracked_worktree_verified", False)):
                put(observed / "source-after.json", {**before, key: value})
                self.rejected(lambda: gate.transfer.source_pair(observed, expected))

    def stage(self):
        directory = self.root / "original-stage"
        name = "actual-test"
        path = directory / name
        path.mkdir(parents=True)
        stdout = b"running 1 test\ntest a::actual ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out\n"
        (path / "stdout.raw").write_bytes(stdout)
        (path / "stderr.raw").write_bytes(b"")
        row = {"stage": name, "argv": ["/independent-test", "--exact", "a::actual"], "cwd": "/isolated",
               "wall_limit_seconds": 240, "cleanup_limit_seconds": 10,
               "started_monotonic_ns": 1000, "finished_monotonic_ns": 2000, "elapsed_ns": 1000,
               "pid": 123, "exit_code": 0, "timed_out": False, "launch_error": None,
               "cleanup_error": None, "output_files_closed": True, "status": "PASS",
               "stdout": gate.bytes_id(stdout), "stderr": gate.bytes_id(b"")}
        put(path / "receipt.json", row)
        return directory, row

    def test_actual_original_stages_preserve_raw_named_execution_and_independent_receipts(self):
        directory, row = self.stage()
        self.accepted(lambda: gate.shared.original_stages(directory, {"stages": [row]}, ("actual-test",)))
        raw = (directory / "actual-test/stdout.raw").read_bytes()
        self.accepted(lambda: gate.shared.positive_test(raw, "a::actual"))
        for changed in (b"", raw.replace(b"a::actual", b"a::other"),
                        raw.replace(b"running 1 test", b"running 0 tests"),
                        raw.replace(b"1 passed; 0 failed; 0 ignored", b"0 passed; 0 failed; 1 ignored"),
                        raw.replace(b"test result: ok.", b"test result: FAILED.")):
            self.rejected(lambda changed=changed: gate.shared.positive_test(changed, "a::actual"))
        for key, value in (("status", "FAIL"), ("exit_code", False), ("exit_code", 1),
                           ("timed_out", True), ("cleanup_error", "unreaped"),
                           ("launch_error", "exec"), ("output_files_closed", False),
                           ("cleanup_limit_seconds", 0), ("elapsed_ns", 0)):
            changed = {**row, key: value}
            put(directory / "actual-test/receipt.json", changed)
            self.rejected(lambda: gate.shared.original_stages(directory, {"stages": [changed]}, ("actual-test",)))
        put(directory / "actual-test/receipt.json", row)
        for rows in ([], [row, row], [{**row, "stage": "not-the-original"}]):
            self.rejected(lambda rows=rows: gate.shared.original_stages(directory, {"stages": rows}, ("actual-test",)))
        (directory / "actual-test/stdout.raw").write_bytes(raw + b"trailing changed byte")
        self.rejected(lambda: gate.shared.original_stages(directory, {"stages": [row]}, ("actual-test",)))

    def test_full_frame_journal_is_the_complete_actual_output_and_input_prefix(self):
        directory = self.root / "frames"
        directory.mkdir()
        frames = [{"sent_hex": "", "received_hex": (b"APREADY1" + bytes(8)).hex(), "elapsed_ns": 1},
                  {"sent_hex": b"request".hex(), "received_hex": (b"SVPRES01" + bytes(16)).hex(), "elapsed_ns": 2}]
        raw = b"".join(struct.pack("<Q", len(bytes.fromhex(r["received_hex"]))) +
                       bytes.fromhex(r["received_hex"]) for r in frames)
        put(directory / "observed-frames.json", frames)
        self.accepted(lambda: gate.frame_journal(directory, b"requestunfinished-refused-tail", raw))
        for output in (raw[:-1], raw + b"x", raw[1:]):
            self.rejected(lambda output=output: gate.frame_journal(directory, b"request", output))
        self.rejected(lambda: gate.frame_journal(directory, b"changed", raw))
        for key, value in (("sent_hex", "aa "), ("received_hex", "GG"), ("elapsed_ns", True),
                           ("elapsed_ns", -1)):
            changed = copy.deepcopy(frames)
            changed[1][key] = value
            put(directory / "observed-frames.json", changed)
            self.rejected(lambda: gate.frame_journal(directory, b"request", raw))

    def test_private_call_pairing_capabilities_and_fixture_writes_reject_fabrication(self):
        path = self.root / "private.jsonl"
        image = gate.bytes_id(b"fixture image; not native execution")
        start = {"kind": "native-call-start", "index": 1, "image": "settings", "image_identity": image,
                 "capacities": [1, 1, 1], "input_hex": "01", "output_before_hex": "02", "private_before_hex": "03"}
        finish = {**start, "kind": "native-call-complete", "return": 1,
                  "input_after_hex": "01", "output_after_hex": "02", "private_after_hex": "03"}
        def check(rows, pattern):
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.rejected(lambda: gate.private_journal(path, {"settings": image}, {}, {}), pattern)
        check([start], "Incomplete")
        check([finish], "completion differs")
        check([start, start], "Missing, duplicate")
        check([{**start, "index": 2}], "Missing, duplicate")
        check([start, {**finish, "input_after_hex": "ff"}], "readonly input")
        check([start, {**finish, "output_after_hex": ""}], "capability extent")
        check([start, {**finish, "return": -1}], "private image")
        check([start, {**finish, "image_identity": gate.bytes_id(b"other")}], "completion differs")
        check([{"kind": "private-adapter-fixture-write", "production_input": True}], "Fixture overlaps")
        check([{"kind": "private-adapter-fixture-write", "production_input": False, "offset": 0,
                "before_hex": "0102", "after_hex": "ff03", "bytes_hex": "ff"}], "outside its declared extent")
        check([{"kind": "unknown"}], "Unknown")

    def test_physical_receipt_rechecks_actual_bytes_exit_and_instrumentation(self):
        directory = self.root / "physical-process"
        directory.mkdir()
        frame = b"APREADY1" + bytes(8)
        stdout = struct.pack("<Q", len(frame)) + frame
        stdin = b"rejected"
        stderr = b"SVPFAIL1" + struct.pack("<Q", 64)
        for name, raw in (("stdin", stdin), ("stdout", stdout), ("stderr", stderr)):
            (directory / (name + ".raw")).write_bytes(raw)
        put(directory / "observed-frames.json",
            [{"sent_hex": "", "received_hex": frame.hex(), "elapsed_ns": 1}])
        elf = gate.bytes_id(b"fixture ELF, not executed")
        row = {"schema": "trnm.execution-state-native-process.v1", "executable": elf,
               "exit_code": 64, "cleanup": None, "cleanup_limit_seconds": 3, "wall_limit_seconds": 240,
               "runtime_host_proxy": False, "instrumentation": {"trace": False, "mremap_errno_injected": False},
               "unconsumed_stdout_hex": "", "pid": 123, "elapsed_ns": 100, "clean_close": False,
               "files": {name + ".raw": gate.bytes_id(raw) for name, raw in
                         (("stdin", stdin), ("stdout", stdout), ("stderr", stderr))},
               "stdin_attempted_bytes": len(stdin), "stdin_actual_write_bytes": len(stdin),
               "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}
        put(directory / "receipt.json", row)
        self.accepted(lambda: gate.physical_process(directory, row, {"executable": elf}, 64))
        for key, value in (("exit_code", 0), ("cleanup", "SIGKILL"), ("runtime_host_proxy", True),
                           ("wall_limit_seconds", 1), ("instrumentation", {"trace": True, "mremap_errno_injected": False}),
                           ("stdin_actual_write_bytes", 0), ("stdout_bytes", 0), ("clean_close", True)):
            changed = {**row, key: value}
            put(directory / "receipt.json", changed)
            self.rejected(lambda: gate.physical_process(directory, changed, {"executable": elf}, 64))
        put(directory / "receipt.json", row)
        (directory / "stderr.raw").write_bytes(b"forged")
        self.rejected(lambda: gate.physical_process(directory, row, {"executable": elf}, 64))

    def integrity_fixture(self):
        directory = self.root / "integrity"
        repository = self.root / "repository"
        bundle = self.root / "actual-bundle-fixture"
        for p in (directory, repository, bundle):
            p.mkdir()
        sources = {"fixture.py": gate.bytes_id(b"fixture")}
        raw = b'{"fixture_only":true}\n'
        admitted = {"source_inputs": sources, "bundle_artifacts": {"fixture": gate.bytes_id(b"fixture")},
                    "corpus_raw": raw}
        controls = []
        for group, name in gate.integrity_roster(sources):
            row = {"group": group, "name": name, "status": "PASS"}
            if name == "actual-complete-dynamic-source-fixture":
                row.update(native_execution_claim=False, source_files=1)
            elif name == "source-derived-328-histories":
                row.update(corpus=gate.bytes_id(raw), histories=328, transactions=335)
            elif name == "actual-complete-native-bundle":
                row.update(histories=328, artifacts=1)
            elif group == "public-cli":
                folder = directory / ("cli-" + name)
                folder.mkdir()
                selected = (directory / "unexecuted-empty-bundle" if name.startswith("override-") or name == "optimized-python"
                            else bundle if name == "target-inside-repository" else directory / "mutant-bundle")
                argv = ["/fixture/python3", "-B"] + (["-O"] if name == "optimized-python" else []) + [
                    "-m", "hia.platform.execution_application.rust_oracle", "--repository", str(repository),
                    "--bundle", str(selected), "--output", str(folder / "output")]
                if name == "target-inside-repository":
                    argv += ["--target-dir", str(repository / "tria-invalid-application-target")]
                stderr = b"Optimized Python is not admitted" if name == "optimized-python" else b""
                (folder / "stdout.raw").write_bytes(b"")
                (folder / "stderr.raw").write_bytes(stderr)
                receipt = {"argv": argv, "exit_code": 1, "elapsed_ns": 100,
                           "source_copy_created": False, "original_rust_executed": False,
                           "stdout": gate.bytes_id(b""), "stderr": gate.bytes_id(stderr),
                           "report_written": name != "optimized-python"}
                put(folder / "receipt.json", receipt)
                if name != "optimized-python":
                    put(folder / "output/report.json", {"status": "FAIL", "stages": [],
                        "original_test_binary": None, "actual_rust_tools": None, "original_case_rows_observed": 0,
                        "controls": 0, "passed": 0, "failed": 0, "original_tests": [],
                        "failure": {"error": "explicit unittest fixture rejection"}})
                row["receipt"] = receipt
            controls.append(row)
        (directory / "xz-fixture.xz").write_bytes(lzma.compress(raw))
        report = {"schema": "trnm.execution-application-integrity.v1", "status": "PASS", "primary_error": None,
                  "source_after": {"status": "PASS", "errors": []}, "source_inputs": sources,
                  "source_set_sha256": gate.object_hash(sources), "actual_bundle_checked": True,
                  "source_fixture_is_native_execution_claim": False, "original_rust_executed": False,
                  "groups": 9, "controls_total": len(controls), "public_cli_controls": 16, "controls": controls}
        put(directory / "report.json", report)
        return directory, repository, bundle, admitted, report

    def test_public_admission_refusals_cannot_hide_original_execution_or_missing_raw(self):
        from hia.platform.execution_application import source_graph, rust_oracle
        directory, repository, bundle, admitted, report = self.integrity_fixture()
        with patch.object(source_graph, "complete_sources", return_value=(admitted["source_inputs"], {})), \
             patch.object(rust_oracle, "validate_bundle", return_value=admitted):
            self.accepted(lambda: gate.integrity(directory, repository, admitted, bundle))
            selected = next(row for row in report["controls"] if row["name"] == "override-rustc")
            folder = directory / "cli-override-rustc"
            original = copy.deepcopy(selected["receipt"])
            for key, value in (("exit_code", 0), ("source_copy_created", True),
                               ("original_rust_executed", True), ("report_written", False)):
                selected["receipt"] = {**original, key: value}
                put(folder / "receipt.json", selected["receipt"])
                put(directory / "report.json", report)
                self.rejected(lambda: gate.integrity(directory, repository, admitted, bundle))
            selected["receipt"] = original
            put(folder / "receipt.json", original)
            put(directory / "report.json", report)
            failed = json.loads((folder / "output/report.json").read_text())
            for key, value in (("stages", [{"stage": "cargo-built"}]), ("original_test_binary", {"bytes": 1}),
                               ("actual_rust_tools", {}), ("original_tests", ["a::test"]),
                               ("original_case_rows_observed", 1), ("status", "PASS")):
                put(folder / "output/report.json", {**failed, key: value})
                self.rejected(lambda: gate.integrity(directory, repository, admitted, bundle))
            put(folder / "output/report.json", failed)
            copied = folder / "output/isolated-source"
            copied.mkdir()
            self.rejected(lambda: gate.integrity(directory, repository, admitted, bundle))
            copied.rmdir()
            (folder / "stderr.raw").write_bytes(b"changed actual raw")
            self.rejected(lambda: gate.integrity(directory, repository, admitted, bundle))

    def test_omission_roster_changes_with_the_complete_dynamic_source_set(self):
        first = {"a": gate.bytes_id(b"a"), "b": gate.bytes_id(b"b")}
        rows = gate.integrity_roster(first)
        enlarged = gate.integrity_roster({**first, "future/owned.py": gate.bytes_id(b"future")})
        self.accepted(lambda: self.assertEqual(len(enlarged), len(rows) + 1))
        self.accepted(lambda: self.assertIn(("every-source-omission", "omitted-future/owned.py"), enlarged))
        self.accepted(lambda: self.assertEqual([row for row in rows if row[0] == "every-source-omission"],
                                             [("every-source-omission", "omitted-a"), ("every-source-omission", "omitted-b")]))
        self.accepted(lambda: self.assertEqual(sum(row[0] == "public-cli" for row in rows), 16))

    def test_always_pack_keeps_failed_raw_independent_binary_and_special_metadata(self):
        original = self.root / (gate.PREFIX + "-original")
        original.mkdir()
        binary = b"\x7fELFcomplete-original-binary-fixture"
        (original / "original-test-binary").write_bytes(binary)
        (original / "original-test-binary").chmod(0o500)
        put(original / "report.json", {"status": "FAIL", "failure": {"error": "actual compilation fixture"}})
        put(original / "source-capture/hook.rs", {"prefix_unchanged_fixture": True})
        (original / "isolated-source").mkdir()
        (original / "isolated-source/reconstructible").write_bytes(b"not copied twice")
        physical = self.root / (gate.PREFIX + "-physical")
        physical.mkdir()
        os.mkfifo(physical / "pipe")
        target = self.root / "external-secret-not-evidence"
        target.write_bytes(b"must not be followed")
        (physical / "link").symlink_to(target)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(physical / "socket"))
        self.accepted(lambda: gate.pack(self.root))
        folder = self.root / (gate.PREFIX + "-artifact")
        package = gate.read(folder / "package-manifest.json")
        self.assertEqual(package["packing_status"], "PASS")
        self.assertEqual(package["qualification_status"], "NOT_BOUND")
        self.assertTrue(package["complete_original_test_binary_is_not_excluded"])
        self.assertEqual(set(package["special_entries"]), {"physical/pipe", "physical/link", "physical/socket"})
        self.assertTrue(all(row["opened"] is False for row in package["special_entries"].values()))
        with tarfile.open(folder / "complete-evidence.tar.xz", "r:xz") as archive:
            names = archive.getnames()
            self.assertNotIn("original/isolated-source", names)
            self.assertNotIn("physical/link", names)
            self.assertEqual(archive.extractfile("original/original-test-binary").read(), binary)
            self.assertEqual(archive.getmember("original/original-test-binary").mode, 0o500)
            self.assertIn("original/source-capture/hook.rs", names)
            for member in archive:
                if member.isfile():
                    row = package["entries"][member.name]
                    self.assertEqual(gate.bytes_id(archive.extractfile(member).read()),
                                     {key: row[key] for key in ("bytes", "sha256")})

    def test_pack_detects_bound_evidence_change_and_still_preserves_all_actual_bytes(self):
        for label, mode in (("changed", "bytes"), ("missing", "missing"), ("aliased", "link"),
                            ("other-run", "lineage")):
            root = self.root / label
            root.mkdir()
            observed = gate.observations(root)
            observed.mkdir()
            original = root / (gate.PREFIX + "-original")
            original.mkdir()
            actual = original / "original-test-binary"
            actual.write_bytes(b"\x7fELFfixture-independent-original")
            value = self.binding(root)
            put(observed / "binding.json", value)
            if mode == "bytes":
                actual.write_bytes(b"\x7fELFchanged")
            elif mode == "missing":
                actual.unlink()
            elif mode == "link":
                actual.unlink()
                actual.symlink_to(self.root / "not-followed")
            else:
                value["lineage"]["run_id"] = "124"
                put(observed / "binding.json", value)
            with patch.object(gate.transfer, "source_pair", return_value=value["source_observations"]):
                self.rejected(lambda: gate.pack(root))
            package = gate.read(root / (gate.PREFIX + "-artifact/package-manifest.json"))
            self.assertEqual(package["packing_status"], "FAIL")
            self.assertEqual(package["qualification_status"], "NOT_BOUND")
            self.assertTrue(package["capture_errors"])
            self.assertIn("partial_archive", package)
            self.assertTrue((root / (gate.PREFIX + "-artifact/complete-evidence.tar.xz")).is_file())


    def test_written_archive_reopen_rejects_damage_missing_duplicate_special_and_hidden_members(self):
        import io
        target = self.root / "archive.xz"
        payload = {"native/report.json": b"complete fixture report",
                   "original/original-test-binary": b"\x7fELFfull fixture binary"}
        entries = {name: {"type": "0", **gate.bytes_id(raw), "linkname": ""}
                   for name, raw in payload.items()}
        def encoded(members):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:") as archive:
                for name, raw, kind in members:
                    member = tarfile.TarInfo(name)
                    member.mode = 0o500 if name == "original/original-test-binary" else 0o600
                    member.type = kind
                    if kind == tarfile.REGTYPE:
                        member.size = len(raw)
                        archive.addfile(member, io.BytesIO(raw))
                    else:
                        member.linkname = "outside-evidence"
                        archive.addfile(member)
            return lzma.compress(buffer.getvalue(), preset=1)
        members = [(name, raw, tarfile.REGTYPE) for name, raw in payload.items()]
        valid = encoded(members)
        target.write_bytes(valid)
        value = self.accepted(lambda: gate.verify_archive(target, entries))
        self.assertEqual(value["regular_members"], 2)
        self.assertEqual(value["regular_bytes"], sum(map(len, payload.values())))
        mutants = [
            encoded(members[:-1]),
            encoded(members + [members[0]]),
            encoded(members + [("native/extra", b"extra", tarfile.REGTYPE)]),
            encoded([(members[0][0], b"changed", tarfile.REGTYPE), members[1]]),
            encoded([(members[0][0], b"", tarfile.SYMTYPE), members[1]]),
            valid[:-1], valid + b"trailing", valid + lzma.compress(b""),
            lzma.compress(lzma.decompress(valid) + b"hidden nonzero tar payload", preset=1)]
        damaged = bytearray(valid)
        damaged[len(damaged) // 2] ^= 1
        mutants.append(bytes(damaged))
        for index, raw in enumerate(mutants):
            target.write_bytes(raw)
            with self.subTest(mutant=index):
                self.rejected(lambda: gate.verify_archive(target, entries))
        target.write_bytes(valid)
        changed = copy.deepcopy(entries)
        changed["native/report.json"]["sha256"] = "0" * 64
        self.rejected(lambda: gate.verify_archive(target, changed))

    def test_public_optimized_reader_refuses_before_work_and_pack_never_invents_a_binding(self):
        root = self.root / "public"
        root.mkdir()
        env = dict(os.environ, RUNNER_TEMP=str(root), PYTHONDONTWRITEBYTECODE="1")
        env.pop("PYTHONOPTIMIZE", None)
        optimized = subprocess.run([sys.executable, "-B", "-O", "-m", "hia.tools.qualify_application_ci", "bind"],
                                   cwd=gate.ROOT, env=env, capture_output=True, timeout=30)
        self.accepted(lambda: self.assertNotEqual(optimized.returncode, 0))
        self.assertIn(b"Optimized application CI evidence reader is not admitted", optimized.stderr)
        self.assertFalse(gate.observations(root).exists())
        packed = subprocess.run([sys.executable, "-B", "-m", "hia.tools.qualify_application_ci", "pack"],
                                cwd=gate.ROOT, env=env, capture_output=True, timeout=30)
        self.accepted(lambda: self.assertEqual(packed.returncode, 0, packed.stderr.decode()))
        value = json.loads(packed.stdout)
        self.assertEqual(value["qualification_status"], "NOT_BOUND")
        self.assertTrue(value["qualification_status_not_changed_by_packaging"])


if __name__ == "__main__":
    unittest.main()
