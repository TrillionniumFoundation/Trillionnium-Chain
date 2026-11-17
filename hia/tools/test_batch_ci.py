"""Adversarial tests for exact-source Batch/Prefix CI evidence, not runtime qualification."""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import unittest
from unittest.mock import patch

OBSERVATIONS = []
CLI_CALLS = []
ARGUMENTS = None
HELPER = None
ROOT = None


def accept(name, fn):
    result = fn()
    OBSERVATIONS.append({"name": name, "status": "PASS", "expected": "ACCEPT"})
    return result


def refuse(name, fn):
    try:
        fn()
    except (ValueError, OSError, EOFError, lzma.LZMAError, tarfile.TarError, KeyError, TypeError) as error:
        OBSERVATIONS.append({"name": name, "status": "PASS", "expected": "REFUSE",
                             "actual_error": repr(error)})
        return
    raise AssertionError("Unexpected acceptance: " + name)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as out:
        json.dump(value, out, sort_keys=True, indent=2, allow_nan=False)
        out.write("\n")


def cli(name, argv, wanted):
    directory = ROOT / "cli" / name
    directory.mkdir(parents=True)
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                       PYTHONPATH=str(ARGUMENTS.repository))
    environment.pop("PYTHONOPTIMIZE", None)
    command = [sys.executable, *argv]
    started = time.monotonic_ns()
    process = subprocess.Popen(command, cwd=ARGUMENTS.repository, env=environment,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=240)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=3)
    (directory / "stdout.raw").write_bytes(stdout)
    (directory / "stderr.raw").write_bytes(stderr)
    row = {"name": name, "argv": command, "pid": process.pid,
           "exit_code": process.returncode, "timed_out": timed_out,
           "wall_limit_seconds": 240, "cleanup_limit_seconds": 3,
           "elapsed_ns": time.monotonic_ns() - started,
           "stdout": HELPER.identity(stdout), "stderr": HELPER.identity(stderr)}
    write_json(directory / "receipt.json", row)
    CLI_CALLS.append(row)
    if timed_out or ((process.returncode == 0) != wanted):
        raise AssertionError("Unexpected actual CLI outcome: " + repr(row))
    OBSERVATIONS.append({"name": name, "status": "PASS",
                         "expected": "ACCEPT" if wanted else "REFUSE",
                         "actual_cli": True})
    return row


class EvidenceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = Path(tempfile.mkdtemp(prefix="bci-", dir="/tmp"))
        cls.environment = {
            "TRNM_EXPECTED_SOURCE_SHA": "1" * 40,
            "GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "2",
        }

    def path(self, name):
        result = self.scratch / name
        result.mkdir()
        return result

    def test_01_strict_scalars_paths_and_lineage(self):
        for value in (False, True, 0.0, 1.0, None, "0"):
            refuse("natural-refuses-" + repr(value), lambda value=value:
                   HELPER.natural(value, "actual count"))
        accept("integer-zero-is-valid", lambda: HELPER.natural(0, "actual count"))
        for value in ("../a", "/a", "a//b", "a/./b", "a/../b", "a\\b", "a\0b", "a\nb"):
            refuse("relative-path-" + repr(value), lambda value=value: HELPER.relative(value))
        for value in ("relative", "/a/../b", "/a//b", "/a\0b"):
            refuse("absolute-path-" + repr(value), lambda value=value: HELPER.absolute(value))
        self.assertEqual(accept("actual-lineage-shape", lambda: HELPER.lineage(self.environment)),
                         {"git_head": "1" * 40, "run_id": "1234", "attempt": 2})
        for key, value in (("TRNM_EXPECTED_SOURCE_SHA", "1" * 39),
                           ("TRNM_EXPECTED_SOURCE_SHA", "A" * 40),
                           ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "02"),
                           ("GITHUB_RUN_ATTEMPT", True), ("GITHUB_RUN_ID", None)):
            env = dict(self.environment, **{key: value})
            refuse("lineage-" + key + "-" + repr(value), lambda env=env: HELPER.lineage(env))
        env = dict(self.environment)
        del env["TRNM_EXPECTED_SOURCE_SHA"]
        env["GITHUB_SHA"] = "2" * 40
        refuse("PR-merge-sha-does-not-substitute-source-head", lambda: HELPER.lineage(env))

    def test_02_exact_git_head_blobs(self):
        repo = self.path("git-source")
        commands = [
            ["git", "init", "-q"],
            ["git", "config", "user.name", "Evidence fixture"],
            ["git", "config", "user.email", "fixture@example.invalid"],
        ]
        for command in commands:
            subprocess.run(command, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        raw = b"actual committed fixture\n"
        (repo / "source").write_bytes(raw)
        subprocess.run(["git", "add", "source"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
        accept("HEAD-actual-byte-source", lambda: HELPER.committed_sources(
            repo, {"source": HELPER.identity(raw)}))
        refuse("HEAD-self-consistent-wrong-source", lambda: HELPER.committed_sources(
            repo, {"source": HELPER.identity(raw + b"changed")}))
        refuse("HEAD-missing-source", lambda: HELPER.committed_sources(
            repo, {"absent": HELPER.identity(b"")}))
        refuse("HEAD-empty-source-map", lambda: HELPER.committed_sources(repo, {}))
        refuse("HEAD-bool-source-size", lambda: HELPER.committed_sources(
            repo, {"source": {"bytes": False, "sha256": HELPER.identity(raw)["sha256"]}}))
        refuse("HEAD-request-newline", lambda: HELPER.committed_sources(
            repo, {"source\nHEAD:source": HELPER.identity(raw)}))

    def test_03_descriptor_and_special_file_inventory(self):
        root = self.path("objects")
        (root / "file").write_bytes(b"regular")
        os.mkfifo(root / "pipe")
        link = root / "symbolic"
        link.symlink_to("/does-not-get-opened")
        peer = socket.socket(socket.AF_UNIX)
        try:
            peer.bind(str(root / "socket"))
            rows = accept("special-objects-metadata-only", lambda: HELPER.object_inventory(root))
            self.assertEqual(rows["pipe"]["type"], "fifo-metadata")
            self.assertEqual(rows["socket"]["type"], "socket-metadata")
            self.assertEqual(rows["symbolic"]["type"], "symlink-metadata")
            for name in ("pipe", "socket", "symbolic"):
                refuse("regular-read-refuses-" + name, lambda name=name:
                       HELPER.file_identity(root, name))
        finally:
            peer.close()
        accept("actual-regular-descriptor-read", lambda: HELPER.file_identity(root, "file"))
        os.link(root / "file", root / "hard")
        refuse("hardlink-evidence-refused", lambda: HELPER.file_identity(root, "file"))
        os.unlink(root / "hard")
        alias = self.scratch / "root-alias"
        alias.symlink_to(root, target_is_directory=True)
        refuse("symbolic-root-refused", lambda: HELPER.file_identity(alias, "file"))
        before = len(list(Path("/proc/self/fd").iterdir()))
        for _ in range(4):
            try:
                HELPER.file_identity(root, "pipe")
            except ValueError:
                pass
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)
        OBSERVATIONS.append({"name": "repeated-special-refusal-leaks-no-FD", "status": "PASS",
                             "expected": "CLOSED_DESCRIPTORS"})

    def baseline_archive(self, suffix):
        root = self.path("archive-input-" + suffix)
        (root / "nested").mkdir()
        (root / "one").write_bytes(b"one\n")
        (root / "nested/two").write_bytes(b"two\n")
        os.mkfifo(root / "pipe")
        artifact = ROOT / ("archive-" + suffix)
        with patch.dict(os.environ, self.environment):
            manifest = HELPER.pack({"observations": root}, artifact, "prefix",
                                   root, "failure")
        return root, artifact, manifest

    def test_04_real_pack_regular_roundtrip_and_metadata(self):
        root, artifact, manifest = accept("archive-complete-real-bytes",
                                          lambda: self.baseline_archive("base"))
        destination = self.scratch / "restored"
        accept("archive-real-regular-roundtrip",
               lambda: HELPER.verify_archive(artifact, destination))
        self.assertEqual((destination / "observations/one").read_bytes(), b"one\n")
        self.assertEqual((destination / "observations/nested/two").read_bytes(), b"two\n")
        self.assertFalse((destination / "observations/pipe").exists())
        self.assertEqual(manifest["entries"]["observations/pipe"]["type"], "fifo-metadata")
        OBSERVATIONS.append({"name": "FIFO-is-only-metadata-after-unpack", "status": "PASS",
                             "expected": "NO_SPECIAL_OBJECT_CREATED"})
        refuse("existing-extract-destination", lambda: HELPER.verify_archive(artifact, destination))
        with patch.dict(os.environ, self.environment):
            refuse("success-without-real-binding", lambda: HELPER.pack(
                {"observations": root}, ROOT / "false-success", "prefix", root, "success"))
            refuse("archive-output-inside-input", lambda: HELPER.pack(
                {"observations": root}, root / "out", "prefix", root, "failure"))

    def test_05_coherent_archive_corruptions(self):
        _, artifact, manifest = self.baseline_archive("mutations")
        compressed = (artifact / "evidence.tar.xz").read_bytes()
        raw = lzma.decompress(compressed)
        def mutant(name, encoded, tar_raw=None, mutate=None):
            target = ROOT / ("mutant-" + name)
            target.mkdir()
            m = copy.deepcopy(manifest)
            if tar_raw is not None:
                m["tar"] = HELPER.identity(tar_raw)
            m["archive"] = HELPER.identity(encoded)
            if mutate:
                mutate(m)
            (target / "evidence.tar.xz").write_bytes(encoded)
            write_json(target / "manifest.json", m)
            refuse("coherent-archive-" + name, lambda: HELPER.verify_archive(target, None))
        mutant("truncated-xz", compressed[:-7])
        mutant("extra-xz-stream", compressed + lzma.compress(b"trailing"))
        mutant("extra-raw-compressed-tail", compressed + b"tail")
        extra_tar = raw + b"hidden-after-tar-end"
        mutant("hidden-tar-tail", lzma.compress(extra_tar), extra_tar)
        def tar_records(rows):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode="w", format=tarfile.GNU_FORMAT) as stream:
                for name, data, kind in rows:
                    member = tarfile.TarInfo(name)
                    member.mode = 0o600
                    member.uid = member.gid = member.mtime = 0
                    member.type = kind
                    if kind == tarfile.REGTYPE:
                        member.size = len(data)
                        stream.addfile(member, io.BytesIO(data))
                    else:
                        member.linkname = "/untrusted"
                        stream.addfile(member)
            return out.getvalue()
        normal = [("observations/nested/two", b"two\n", tarfile.REGTYPE),
                  ("observations/one", b"one\n", tarfile.REGTYPE)]
        variants = {
            "duplicate": normal + [normal[-1]],
            "traversal": [("../escape", b"x", tarfile.REGTYPE)],
            "symlink": [("observations/one", b"", tarfile.SYMTYPE)],
            "hardlink": [("observations/one", b"", tarfile.LNKTYPE)],
            "missing": normal[:1],
            "changed-content": [normal[0], ("observations/one", b"bad\n", tarfile.REGTYPE)],
            "extra-member": normal + [("observations/extra", b"x", tarfile.REGTYPE)],
        }
        for name, rows in variants.items():
            altered = tar_records(rows)
            mutant(name, lzma.compress(altered), altered)
        mutant("boolean-size", compressed, mutate=lambda m:
               m["entries"]["observations/one"].update(bytes=False))
        mutant("boolean-mode", compressed, mutate=lambda m:
               m["entries"]["observations/one"].update(mode=False))
        mutant("extra-manifest-field", compressed, mutate=lambda m: m.update(unobserved=True))
        mutant("missing-parent", compressed, mutate=lambda m:
               m["entries"].pop("observations/nested"))
        mutant("duplicate-root", compressed, mutate=lambda m:
               m["roots"].append(m["roots"][0]))
        mutant("failed-archive-forged-success", compressed, mutate=lambda m:
               m.update(stage_status="success"))
        extra = ROOT / "extra-container-file"
        extra.mkdir()
        (extra / "evidence.tar.xz").write_bytes(compressed)
        write_json(extra / "manifest.json", manifest)
        (extra / "unknown").write_bytes(b"unobserved")
        refuse("archive-extra-container-file", lambda: HELPER.verify_archive(extra, None))

    def test_06_actual_stage_roster_budgets_and_types(self):
        self.assertIsNotNone(ARGUMENTS.original,
                             "Original scope requires the actual original output")
        report = HELPER.safe.load(ARGUMENTS.original, "report.json")
        rows = accept("actual-original-stage-positive", lambda:
                      HELPER.actual_stages(ARGUMENTS.original, report, ARGUMENTS.profile))
        mutations = [
            ("missing-stage", lambda r: r["stages"].pop()),
            ("duplicate-stage", lambda r: r["stages"].append(copy.deepcopy(r["stages"][0]))),
            ("reorder-stage", lambda r: r["stages"].reverse()),
            ("exit-bool", lambda r: r["stages"][0].update(exit_code=False)),
            ("budget-bool", lambda r: r["stages"][0].update(wall_limit_seconds=True)),
            ("budget-relaxed", lambda r: r["stages"][0].update(wall_limit_seconds=900)),
            ("cleanup-relaxed", lambda r: r["stages"][0].update(cleanup_limit_seconds=20)),
            ("timed-out", lambda r: r["stages"][0].update(timed_out=True)),
            ("unknown-field", lambda r: r["stages"][0].update(ignored_failure=False)),
            ("missing-stdout", lambda r: r["stages"][0]["stdout"].update(bytes=0)),
        ]
        for name, mutate in mutations:
            changed = copy.deepcopy(report)
            mutate(changed)
            refuse("actual-original-stage-" + name, lambda changed=changed:
                   HELPER.actual_stages(ARGUMENTS.original, changed, ARGUMENTS.profile))
        self.actual_report, self.actual_rows = report, rows

    def test_07_actual_compiler_argv_and_library_selection(self):
        self.assertIsNotNone(ARGUMENTS.original,
                             "Original scope requires the actual original output")
        report = HELPER.safe.load(ARGUMENTS.original, "report.json")
        rows = HELPER.actual_stages(ARGUMENTS.original, report, ARGUMENTS.profile)
        result = accept("actual-original-tools-positive", lambda:
                        HELPER.actual_tools(ARGUMENTS.original, report, rows, ARGUMENTS.profile))
        mutations = [
            ("replacement-rustc", lambda r, q: r["actual_rust_tools"]["rustc"].update(
                path="/unobserved/rustc")),
            ("relative-cargo", lambda r, q: r["actual_rust_tools"]["cargo"].update(path="cargo")),
            ("boolean-tool-size", lambda r, q: r["actual_rust_tools"]["rustdoc"].update(bytes=True)),
            ("changed-rust-version", lambda r, q: q["rustc-selected-version"][1].update(
                stdout=b"unobserved")),
            ("wrong-target-host", lambda r, q: (
                q["rustc-version"][1].update(stdout=b"host: aarch64-unknown-linux-gnu\n"),
                q["rustc-selected-version"][1].update(stdout=b"host: aarch64-unknown-linux-gnu\n"))),
            ("unlocked-build", lambda r, q: q["cargo-original-test-build"][0]["argv"].remove("--locked")),
            ("foreign-manifest", lambda r, q: q["cargo-original-metadata"][0]["argv"].__setitem__(
                -1, "/different/Cargo.toml")),
            ("unobserved-binary", lambda r, q: r["original_test_binary"].update(
                path="/different/original-test-binary")),
            ("omit-test-single-thread", lambda r, q: q["retained-original-0"][0]["argv"].pop()),
        ]
        for name, mutate in mutations:
            changed_report, changed_rows = copy.deepcopy(report), copy.deepcopy(rows)
            mutate(changed_report, changed_rows)
            refuse("actual-tool-" + name, lambda r=changed_report, q=changed_rows:
                   HELPER.actual_tools(ARGUMENTS.original, r, q, ARGUMENTS.profile))
        _, _, target, serde_row, _ = result
        accept("metadata-union-but-actual-default-std-lib", lambda:
               HELPER.actual_serde(ARGUMENTS.original, report, rows,
                                   ARGUMENTS.repository, serde_row, target, False))
        for name, mutate in [
            ("custom-build-not-lib", lambda r: r["target"].update(kind=["custom-build"])),
            ("compiled-arbitrary-precision", lambda r: r["features"].append("arbitrary_precision")),
            ("foreign-package", lambda r: r.update(package_id="foreign")),
            ("foreign-lib-source", lambda r: r["target"].update(src_path="/foreign/lib.rs")),
        ]:
            changed = copy.deepcopy(serde_row)
            mutate(changed)
            refuse("actual-serde-" + name, lambda changed=changed:
                   HELPER.actual_serde(ARGUMENTS.original, report, rows,
                                       ARGUMENTS.repository, changed, target, False))

    def test_08_captured_actual_source_prefix_and_registry(self):
        self.assertIsNotNone(ARGUMENTS.original,
                             "Original scope requires the actual original output")
        report = HELPER.safe.load(ARGUMENTS.original, "report.json")
        captured = ARGUMENTS.original / HELPER.SNAPSHOT
        accept("complete-captured-locked-registry", lambda: HELPER.check_captured_registry(
            captured, report["serde_json_source"]))
        for name, mutate in [
            ("archive-digest", lambda s: s["registry_archive"].update(sha256="0" * 64)),
            ("empty-source-map", lambda s: s.update(archive_source_files={})),
            ("unknown-unpacked-source", lambda s: s["crate_sources"].update(
                {"extra": HELPER.identity(b"")})),
            ("missing-generated-marker", lambda s: s.update(optional_cargo_generated_files={})),
        ]:
            changed = copy.deepcopy(report["serde_json_source"])
            mutate(changed)
            refuse("captured-registry-" + name, lambda changed=changed:
                   HELPER.check_captured_registry(captured, changed))
        raw, sources = HELPER.expected_adaptation(
            ARGUMENTS.repository, ARGUMENTS.profile, report["original_sources"])
        store = raw[HELPER.oracle.STORE]
        original = HELPER.safe.read(ARGUMENTS.repository, HELPER.oracle.STORE)
        self.assertTrue(store.startswith(original))
        self.assertEqual(len(sources), len(report["original_sources"]) + 1)
        OBSERVATIONS.append({"name": "actual-source-only-appended-cfg-test-hook",
                             "status": "PASS", "expected": "UNCHANGED_PRODUCTION_PREFIX"})

    def test_09_actual_cli_fail_closed_and_failure_pack(self):
        helper_path = str(Path(__file__).with_name("qualify_batch_ci.py"))
        cli("optimized-python", ["-O", helper_path, "validate", "--kind", "prefix",
             "--native", str(self.scratch / "absent"), "--report", str(ROOT / "optimized.json")], False)
        cli("unknown-profile", ["-B", helper_path, "validate", "--kind", "unknown"], False)
        cli("missing-native-artifact", ["-B", helper_path, "validate", "--kind", "prefix",
             "--native", str(self.scratch / "absent"), "--report", str(ROOT / "missing.json")], False)
        root = self.path("cli-fixture")
        (root / "failure.raw").write_bytes(b"actual failing child output\n")
        os.mkfifo(root / "pipe")
        with patch.dict(os.environ, self.environment):
            cli("failure-archive-actual", ["-B", helper_path, "pack", "--kind", "prefix",
                "--root", "observations=" + str(root), "--observations", str(root),
                "--destination", str(ROOT / "cli-failure-archive"), "--stage-status", "failure"], True)
            cli("failed-predecessor-refused", ["-B", helper_path, "unpack", "--repository",
                str(ARGUMENTS.repository), "--artifact", str(ROOT / "cli-failure-archive"),
                "--destination", str(self.scratch / "invalid-prior"), "--profile", "prefix",
                "--part", "0"], False)

    @classmethod
    def tearDownClass(cls):
        # These are our test fixtures. Keep their byte/metadata inventory in the
        # report; retain the actual files for failure review, without opening specials.
        write_json(ROOT / "fixture-inventory.json", {
            "root": str(cls.scratch), "entries": HELPER.object_inventory(cls.scratch)})


TRANSPORT_GROUPS = [
    "test_01_strict_scalars_paths_and_lineage",
    "test_02_exact_git_head_blobs",
    "test_03_descriptor_and_special_file_inventory",
    "test_04_real_pack_regular_roundtrip_and_metadata",
    "test_05_coherent_archive_corruptions",
    "test_09_actual_cli_fail_closed_and_failure_pack"
]
ORIGINAL_GROUPS = [
    "test_01_strict_scalars_paths_and_lineage",
    "test_02_exact_git_head_blobs",
    "test_03_descriptor_and_special_file_inventory",
    "test_04_real_pack_regular_roundtrip_and_metadata",
    "test_05_coherent_archive_corruptions",
    "test_06_actual_stage_roster_budgets_and_types",
    "test_07_actual_compiler_argv_and_library_selection",
    "test_08_captured_actual_source_prefix_and_registry",
    "test_09_actual_cli_fail_closed_and_failure_pack"
]


class RequiredGroupResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_group_names = []

    def startTest(self, test):
        self.executed_group_names.append(test._testMethodName)
        super().startTest(test)


def main():
    global ARGUMENTS, HELPER, ROOT
    p = argparse.ArgumentParser()
    p.add_argument("--repository", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--scope", choices=("transport", "original"), required=True)
    p.add_argument("--original", type=Path)
    p.add_argument("--profile", choices=("batch", "prefix"), default="prefix")
    ARGUMENTS = p.parse_args()
    if ARGUMENTS.scope == "original" and ARGUMENTS.original is None:
        p.error("--scope original requires --original")
    if ARGUMENTS.scope == "transport" and ARGUMENTS.original is not None:
        p.error("--scope transport does not accept --original")
    required = TRANSPORT_GROUPS if ARGUMENTS.scope == "transport" else ORIGINAL_GROUPS
    discovered = unittest.defaultTestLoader.getTestCaseNames(EvidenceControls)
    if discovered != ORIGINAL_GROUPS:
        raise ValueError("Required group roster differs from the declared original scope")
    need_fresh = not ARGUMENTS.report.exists()
    if not need_fresh:
        raise ValueError("Fresh test report required")
    ROOT = ARGUMENTS.report.parent
    ROOT.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ARGUMENTS.repository))
    path = Path(__file__).with_name("qualify_batch_ci.py")
    spec = importlib.util.spec_from_file_location("batch_ci_candidate", path)
    HELPER = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(HELPER)
    started = time.monotonic_ns()
    suite = unittest.TestSuite(EvidenceControls(name) for name in required)
    result = unittest.TextTestRunner(verbosity=2, resultclass=RequiredGroupResult).run(suite)
    passed = (result.wasSuccessful() and not result.skipped
              and result.testsRun == len(required)
              and result.executed_group_names == required)
    report = {
        "schema": "trnm.execution-batch-ci-controls.v2",
        "status": "PASS" if passed else "FAIL",
        "scope": ARGUMENTS.scope, "required_groups": len(required),
        "required_group_names": required,
        "executed_group_names": result.executed_group_names,
        "groups": result.testsRun, "groups_failed": len(result.failures) + len(result.errors),
        "groups_skipped": len(result.skipped), "controls": OBSERVATIONS,
        "actual_cli_calls": CLI_CALLS, "elapsed_ns": time.monotonic_ns() - started,
        "helper": HELPER.identity(path.read_bytes()),
        "test_source": HELPER.identity(Path(__file__).read_bytes()),
        "failures": [{"test": str(test), "traceback": text}
                     for test, text in [*result.failures, *result.errors]],
        "skipped": [{"test": str(test), "reason": reason}
                    for test, reason in result.skipped],
        "actual_original_input": str(ARGUMENTS.original) if ARGUMENTS.original else None,
        "actual_original_profile": ARGUMENTS.profile if ARGUMENTS.original else None,
        "runtime_native_or_rust_executed": False,
        "ci_lineage_values_in_unit_tests_are_fixtures": True,
    }
    write_json(ARGUMENTS.report, report)
    print(json.dumps({key: report[key] for key in
                     ("status", "scope", "required_groups", "groups", "groups_failed", "groups_skipped")},
                     sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
