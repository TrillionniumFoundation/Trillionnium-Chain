"""Exercise the real unchanged verifier and original-view refusal boundaries."""
from contextlib import redirect_stderr
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import check_historical_archive as history
import check_w1_complete_archive as archive


REPOSITORY = Path(__file__).resolve().parents[2]


def original_checker():
    raw = history.git(REPOSITORY, "cat-file", "blob", archive.CHECKER_BLOB)
    if archive.digest(raw) != archive.CHECKER_SHA256:
        raise AssertionError("the actual original checker is unavailable or changed")
    return raw


def tar_bytes(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:xz", format=tarfile.PAX_FORMAT) as tar:
        for name, raw, kind in members:
            member = tarfile.TarInfo(name)
            member.mtime = 0
            member.mode = 0o644
            member.type = kind
            member.size = len(raw) if kind == tarfile.REGTYPE else 0
            tar.addfile(member, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
    return stream.getvalue()


class OriginalViewFixture(unittest.TestCase):
    def setUp(self):
        self.make_fixture()

    def make_fixture(self, bad_member=False):
        temporary = tempfile.TemporaryDirectory(prefix="trnm-w1-complete-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.package = self.root / archive.PACKAGE
        self.package.mkdir(parents=True)
        self.git("init", "-q")
        self.git("config", "user.name", "W1 byte fixture")
        self.git("config", "user.email", "archive@example.invalid")
        files = {"README.md": b"HOLD; four service failures and incomplete CodeQL\n",
                 archive.CHECKER: original_checker(),
                 "failure.json": b'{"result":"FAIL","production_activation":false}\n',
                 ".gitignore": b"*.log\n"}
        all_archives = []

        def add_archive(name):
            raw = (name + ": original capture\n").encode()
            members = [{"path": "capture.log", "bytes": len(raw), "sha256": archive.digest(raw)},
                       {"path": "empty.stderr.log", "bytes": 0, "sha256": archive.digest(b"")}]
            content = tar_bytes([("capture.log", raw, tarfile.REGTYPE),
                                 ("empty.stderr.log", b"", tarfile.REGTYPE)])
            files[name] = content
            all_archives.append((name, members))
            return {"archive": Path(name).name, "bytes": len(content),
                    "sha256": archive.digest(content), "members": members}

        for run in archive.RUNS:
            prefix = f"run-{run}/"
            row = add_archive(prefix + "capture.tar.xz")
            capture = {"capture_archive": row["archive"], "capture_archive_bytes": row["bytes"],
                       "capture_archive_sha256": row["sha256"], "members": row["members"]}
            if bad_member and run == archive.RUNS[0]:
                capture["members"][0]["sha256"] = "0" * 64
            files[prefix + "CAPTURE_INDEX.json"] = json.dumps({"artifacts": [capture]}).encode()
            files[prefix + "READBACK_INDEX.json"] = json.dumps(
                {"archives": [add_archive(prefix + "readback.tar.xz")]}).encode()
            files[prefix + "service-report.json"] = b'{"result":"FAIL","UNKNOWN":true}\n'
            files[prefix + "empty.stderr.log"] = b""
        for scope in ("other-ci-8327719", "codeql-export"):
            row = add_archive(scope + "/capture.tar.xz")
            files[scope + "/RETAINED_CAPTURE_INDEX.json"] = json.dumps({"captures": [{
                "retained_archive": row["archive"], "retained_archive_bytes": row["bytes"],
                "retained_archive_sha256": row["sha256"], "members": row["members"]}]}).encode()
            files[scope + "/failure.log"] = b"failed; complete=false\n"
        files["recent-ci-repair/READBACK_INDEX.json"] = json.dumps({"archives": [
            add_archive("recent-ci-repair/readback.tar.xz")]}).encode()
        files["recent-ci-repair/observation.json"] = b'{"historical_only":true}\n'
        files["VALIDATION_INDEX.json"] = json.dumps(add_archive("validation.tar.xz")).encode()
        inventory = {"schema": "pon-w1-complete-work-evidence-files-v1", "runs": archive.RUNS,
                     "files_exclude": ["FILE_INDEX.json", "SHA256SUMS"],
                     "payload_files": len(files), "payload_bytes": sum(map(len, files.values())),
                     "original_zip_containers_included": False,
                     "new_native_execution_by_archive_verification": False,
                     "files": [{"path": name, "bytes": len(raw), "sha256": archive.digest(raw),
                                "git_blob_sha": archive.blob_id(raw)} for name, raw in sorted(files.items())]}
        files["FILE_INDEX.json"] = json.dumps(inventory).encode()
        files["SHA256SUMS"] = "".join(archive.digest(raw) + "  " + name + "\n"
                                          for name, raw in sorted(files.items())).encode()
        for name, raw in files.items():
            target = self.package / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        self.git("add", "--force", ".")
        self.git("commit", "-qm", "Original complete W1 fixture")
        commit = self.git("rev-parse", "HEAD").decode().strip()
        tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        self.original = history.tree_rows(self.root, commit, [archive.PACKAGE])
        rows = [dict(row, sha256=archive.digest((self.root / row["path"]).read_bytes()))
                for row in self.original.values()]
        prefix = archive.PACKAGE + "/"
        selected = [row for row in rows if any(row["path"].startswith(prefix + scope + "/")
                                               for scope in archive.SCOPES)]
        payload = [row for row in selected if row["path"].endswith(".tar.xz")]
        small = [row for row in selected if row not in payload]
        copies = [{"path": prefix + "retained-" + row["path"][len(prefix):],
                   "archive_path": row["path"]} for row in small]
        changed = {prefix + "README.md", prefix + archive.CHECKER}
        self.data = {"schema": "trnm-historical-source-archive-v1", "source_commit": commit,
                     "source_tree": tree, "scopes": [prefix + name for name in archive.SCOPES],
                     "file_count": len(selected), "total_bytes": sum(row["bytes"] for row in selected),
                     "files": selected,
                     "historical_manifests": [row for row in rows if row["path"] in
                                              {prefix + name for name in archive.MANIFESTS}],
                     "preserved_files": [row for row in rows if row not in selected
                                         and row["path"] not in changed],
                     "retained_copies": copies, "qualification_changed": False,
                     "production_activation": False}
        for row in copies:
            target = self.root / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((self.root / row["archive_path"]).read_bytes())
        for scope in archive.SCOPES:
            shutil.rmtree(self.package / scope)
        (self.package / archive.CHECKER).write_bytes(archive.current_source(files[archive.CHECKER]))
        (self.package / "README.md").write_bytes(files["README.md"] + b"Original bytes archived.\n")
        self.index = self.package / archive.INDEX_NAME
        self.write(self.data)
        self.git("add", "--force", "-A")
        pins = {name: (archive.blob_id(files[name]), len(files[name]), archive.digest(files[name]))
                for name in archive.MANIFESTS}
        patcher = patch.multiple(archive, COMMIT=commit, TREE=tree, ORIGINAL_FILES=len(rows),
                                 ORIGINAL_BYTES=sum(row["bytes"] for row in rows),
                                 ARCHIVED_FILES=len(selected), ARCHIVED_BYTES=sum(row["bytes"] for row in selected),
                                 PAYLOAD_FILES=len(payload), PAYLOAD_BYTES=sum(row["bytes"] for row in payload),
                                 SMALL_FILES=len(small), ARCHIVES=len(all_archives),
                                 MEMBERS=sum(len(members) for _, members in all_archives),
                                 MEMBER_BYTES=sum(row["bytes"] for _, members in all_archives for row in members),
                                 CONTROL_PINS=pins)
        patcher.start()
        self.addCleanup(patcher.stop)

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=self.root,
                                       stderr=subprocess.PIPE)

    def write(self, data):
        self.index.write_text(json.dumps(data))

    def stage_index(self):
        self.git("add", "--force", str(self.index.relative_to(self.root)))

    def check(self):
        return archive.fixed_inputs(self.root, self.index)

    def snapshot(self):
        return {path.relative_to(self.package).as_posix(): path.read_bytes()
                for path in self.package.rglob("*") if path.is_file() and path != self.index}

    def test_complete_fixture_executes_the_actual_original_verifier_and_all_members(self):
        before = self.snapshot()
        result = archive.validate(self.root, self.index)
        self.assertTrue(result["original_checker_executed"])
        self.assertEqual(result["original_archives_verified"], 12)
        self.assertEqual(result["original_archive_members_rehashed"], 24)
        self.assertEqual(result["original_observation"]["result"], "PASS_RETAINED_BYTES")
        self.assertFalse(result["current_work_or_service_qualification"])
        self.assertFalse(result["whole_chain_native"])
        self.assertEqual(result["current_runtime_tests_executed"], 0)
        self.assertEqual(before, self.snapshot())

    def test_metadata_success_does_not_hide_a_real_original_member_failure(self):
        self.make_fixture(bad_member=True)
        self.assertEqual(self.check()[5]["result"], "PASS")
        before = self.snapshot()
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaisesRegex(history.Invalid, "original W1 evidence verifier failed"):
            archive.validate(self.root, self.index)
        self.assertIn('"original_checker_exit": 1', errors.getvalue())
        self.assertIn("member identity mismatch", errors.getvalue())
        self.assertEqual(before, self.snapshot())

    def test_omitted_duplicate_reordered_archive_rows_are_refused(self):
        for mutate in (lambda x: x["files"].pop(), lambda x: x["files"].reverse(),
                       lambda x: x["files"].append(x["files"][0])):
            data = copy.deepcopy(self.data)
            mutate(data)
            self.write(data)
            with self.assertRaises(history.Invalid):
                self.check()

    def test_wrong_snapshot_scope_denominator_or_manifest_location_is_refused(self):
        for key, value in (("source_commit", "0" * 40), ("source_tree", "0" * 40),
                           ("scopes", [archive.PACKAGE + "/elsewhere"]),
                           ("file_count", True), ("total_bytes", 0)):
            data = copy.deepcopy(self.data)
            data[key] = value
            self.write(data)
            with self.subTest(key=key), self.assertRaises(history.Invalid):
                self.check()
        self.write(self.data)
        with self.assertRaisesRegex(history.Invalid, "outside the fixed package"):
            archive.fixed_inputs(self.root, self.root / "fake.json")

    def test_all_small_copies_and_preserved_root_validation_are_mandatory(self):
        for key in ("retained_copies", "preserved_files", "historical_manifests"):
            data = copy.deepcopy(self.data)
            data[key].pop()
            self.write(data)
            with self.subTest(key=key), self.assertRaises(history.Invalid):
                self.check()
        self.write(self.data)
        p = self.package / "validation.tar.xz"
        original = p.read_bytes()
        p.unlink()
        with self.assertRaises(history.Invalid): self.check()
        p.write_bytes(original + b"changed")
        with self.assertRaises(history.Invalid): self.check()

    def test_missing_changed_symlinked_or_special_copies_are_refused_before_read(self):
        p = self.package / "retained-codeql-export/failure.log"
        for mode in ("missing", "changed", "symlink", "fifo"):
            if p.exists() or p.is_symlink(): p.unlink()
            if mode == "changed": p.write_bytes(b"complete=true\n")
            elif mode == "symlink": p.symlink_to(self.package / "failure.json")
            elif mode == "fifo": os.mkfifo(p, 0o600)
            with self.subTest(mode=mode), self.assertRaises(history.Invalid):
                self.check()

    def test_extra_file_and_restored_original_path_are_refused(self):
        for p in (self.package / "extra", self.package / "codeql-export/failure.log"):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"extra")
            with self.assertRaises(history.Invalid): self.check()
            p.unlink()

    def test_failure_cannot_be_promoted_by_resigning_retained_metadata(self):
        p = self.package / "failure.json"
        p.write_bytes(b'{"result":"PASS","production_activation":true}\n')
        data = copy.deepcopy(self.data)
        row = next(r for r in data["preserved_files"] if r["path"].endswith("/failure.json"))
        row.update(bytes=p.stat().st_size, sha256=archive.digest(p.read_bytes()),
                   blob=archive.blob_id(p.read_bytes()))
        self.write(data)
        self.stage_index()
        with self.assertRaises(history.Invalid): self.check()

    def test_tracking_requires_empty_logs_and_exact_current_bytes_modes(self):
        for p in (self.package / "retained-run-41297071118/empty.stderr.log", self.index):
            name = p.relative_to(self.root).as_posix()
            self.git("rm", "--cached", "-q", name)
            with self.subTest(path=name), self.assertRaisesRegex(history.Invalid, "Git index roster differs"):
                self.check()
            self.git("add", "--force", name)
        p = self.package / "retained-codeql-export/failure.log"
        name = p.relative_to(self.root).as_posix()
        raw = p.read_bytes()
        p.write_bytes(b"wrong staged bytes")
        self.git("add", "--force", name)
        p.write_bytes(raw)
        with self.assertRaisesRegex(history.Invalid, "staged bytes or mode differ"):
            self.check()
        self.git("add", "--force", name)
        self.git("update-index", "--chmod=+x", name)
        with self.assertRaisesRegex(history.Invalid, "staged bytes or mode differ"):
            self.check()

    def test_intent_to_add_archive_index_is_refused(self):
        name = self.index.relative_to(self.root).as_posix()
        self.git("rm", "--cached", "-q", name)
        self.git("add", "-N", name)
        with self.assertRaisesRegex(history.Invalid, "staged bytes or mode differ"):
            self.check()

    def test_missing_original_blob_is_an_error_without_network_or_fallback(self):
        row = next(row for row in self.data["files"] if row["path"].endswith(".tar.xz"))
        oid = row["blob"]
        (self.root / ".git/objects" / oid[:2] / oid[2:]).unlink()
        before = self.snapshot()
        with self.assertRaisesRegex(history.Invalid, "snapshot unavailable"):
            self.check()
        self.assertEqual(before, self.snapshot())

    def test_original_functions_and_unconditional_dispatch_cannot_change(self):
        p = self.package / archive.CHECKER
        original = p.read_bytes()
        for changed in (original.replace(b"1024 * 1024", b"1024", 1),
                        original + b"\n# fallback proposed\n"):
            p.write_bytes(changed)
            with self.assertRaisesRegex(history.Invalid, "functions or unconditional archive dispatch changed"):
                self.check()
        p.write_bytes(original)

    def test_qualification_flags_duplicate_and_nonfinite_json_are_refused(self):
        for flag in ("qualification_changed", "production_activation"):
            data = copy.deepcopy(self.data)
            data[flag] = True
            self.write(data)
            with self.assertRaises(history.Invalid): self.check()
        self.index.write_text(json.dumps(self.data)[:-1] + ', "schema":"shadow"}')
        with self.assertRaises(history.Invalid): self.check()
        self.index.write_text(json.dumps(self.data)[:-1] + ', "injected":NaN}')
        with self.assertRaises(history.Invalid): self.check()

    def test_actual_current_cli_missing_dangling_or_foreign_package_refuses_without_writes(self):
        scripts = self.root / "scripts/ci"
        scripts.mkdir(parents=True)
        for name in ("check_w1_complete_archive.py", "check_historical_archive.py"):
            shutil.copyfile(REPOSITORY / "scripts/ci" / name, scripts / name)
        entry = self.package / archive.CHECKER
        before = self.snapshot()
        self.index.unlink()
        caller = self.root / "unrelated"
        caller.mkdir()
        for mode in ("missing", "dangling", "foreign"):
            if mode == "dangling": self.index.symlink_to(self.root / "missing-index")
            args = [sys.executable, "-B", str(entry)]
            if mode == "foreign": args.append(str(caller))
            result = subprocess.run(args, cwd=caller, capture_output=True, text=True, timeout=5)
            with self.subTest(mode=mode):
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("W1 complete archive check failed", result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(before, self.snapshot())
            if self.index.is_symlink(): self.index.unlink()


class OriginalTarVerifierControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = {"__name__": "frozen_original_verifier"}
        exec(compile(original_checker(), "original-verify_archives.py", "exec"), cls.original)

    def test_actual_original_member_verifier_rejects_member_set_type_size_and_hash_changes(self):
        with tempfile.TemporaryDirectory(prefix="trnm-w1-tar-negative-") as directory:
            root = Path(directory)
            expected = [{"path": "file", "bytes": 4, "sha256": archive.digest(b"data")}]
            cases = {
                "extra": [("file", b"data", tarfile.REGTYPE), ("extra", b"x", tarfile.REGTYPE)],
                "missing": [],
                "duplicate": [("file", b"data", tarfile.REGTYPE), ("file", b"data", tarfile.REGTYPE)],
                "directory": [("file", b"", tarfile.DIRTYPE)],
                "short": [("file", b"dat", tarfile.REGTYPE)],
                "same_length_wrong_bytes": [("file", b"fake", tarfile.REGTYPE)],
            }
            for name, members in cases.items():
                raw = tar_bytes(members)
                (root / "test.tar.xz").write_bytes(raw)
                with self.subTest(case=name), self.assertRaises(ValueError):
                    self.original["archive"](root, "test.tar.xz", archive.digest(raw), len(raw), expected)
            raw = tar_bytes([("file", b"data", tarfile.REGTYPE)])
            (root / "test.tar.xz").write_bytes(raw)
            self.assertEqual(self.original["archive"](root, "test.tar.xz", archive.digest(raw), len(raw), expected), (1, 4))
            for sha, size in (("0" * 64, len(raw)), (archive.digest(raw), len(raw) - 1)):
                with self.assertRaisesRegex(ValueError, "archive identity mismatch"):
                    self.original["archive"](root, "test.tar.xz", sha, size, expected)
            with self.assertRaisesRegex(ValueError, "duplicate manifest member"):
                self.original["archive"](root, "test.tar.xz", archive.digest(raw), len(raw), expected + expected)


if __name__ == "__main__":
    unittest.main()
