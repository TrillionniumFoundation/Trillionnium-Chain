"""Original-byte metadata and unchanged archive-verifier adversarial controls."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import check_hosted_cost_archive as archive
import check_historical_archive as history


REPOSITORY = Path(__file__).resolve().parents[2]


def original_checker():
    raw = history.git(REPOSITORY, "cat-file", "blob", archive.CHECKER_BLOB)
    assert hashlib.sha256(raw).hexdigest() == archive.CHECKER_SHA256
    return raw


class HostedArchiveMetadata(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-hosted-cost-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = self.root / archive.PACKAGE
        self.package.mkdir(parents=True)
        self.git("init", "-q")
        self.git("config", "user.name", "Archive fixture")
        self.git("config", "user.email", "archive@example.invalid")
        files = {"README.md": b"HOLD; no activation\n", "verify_evidence.py": original_checker(),
                 "verification-receipt.json": b'{"result":"historical-only"}\n',
                 "failure.json": b'{"result":"FAIL"}\n',
                 "hosted-cost/one.tar.xz": b"first part", "hosted-cost/two.tar.xz": b"second part"}
        for name in archive.SMALL_RECORDS:
            files["hosted-cost/" + name] = b'{"archives":[]}\n' if name == "ARCHIVES.json" else b"frozen record\n"
        inventory = {"schema": "pon-eight-sample-evidence-inventory-v1",
                     "qualified_work_cost": False, "public_service_qualified": False,
                     "production_activation": False,
                     "files": [{"path": name, "bytes": len(raw), "sha256": archive.digest(raw)}
                               for name, raw in sorted(files.items()) if name != "verification-receipt.json"]}
        files["INDEX.json"] = json.dumps(inventory).encode()
        for name, raw in files.items():
            path = self.package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.git("add", ".")
        self.git("commit", "-qm", "Original evidence fixture")
        commit = self.git("rev-parse", "HEAD").decode().strip()
        tree = self.git("rev-parse", "HEAD^{tree}").decode().strip()
        original = history.tree_rows(self.root, commit, [archive.PACKAGE])
        rows = []
        for row in original.values():
            rows.append(dict(row, sha256=archive.digest((self.root / row["path"]).read_bytes())))
        prefix = archive.PACKAGE + "/"
        archived = [r for r in rows if r["path"].startswith(prefix + "hosted-cost/")]
        copies = [{"path": prefix + "retained-hosted-cost/" + name,
                   "archive_path": prefix + "hosted-cost/" + name}
                  for name in sorted(archive.SMALL_RECORDS)]
        changed = {prefix + "README.md", prefix + archive.CHECKER}
        self.data = {"schema": "trnm-historical-source-archive-v1", "source_commit": commit,
                     "source_tree": tree, "scopes": [prefix + "hosted-cost"],
                     "files": archived, "file_count": len(archived),
                     "total_bytes": sum(r["bytes"] for r in archived),
                     "historical_manifests": [r for r in rows if r["path"] in {prefix + n for n in archive.MANIFESTS}],
                     "retained_copies": copies,
                     "preserved_files": [r for r in rows if r not in archived and r["path"] not in changed],
                     "qualification_changed": False, "production_activation": False}
        for row in copies:
            target = self.root / row["path"]
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(self.root / row["archive_path"], target)
        shutil.rmtree(self.package / "hosted-cost")
        self.index = self.package / archive.INDEX_NAME
        self.write(self.data)
        self.git("add", "-A")
        self.addCleanup(patch.stopall)
        patch.multiple(archive, COMMIT=commit, TREE=tree, ORIGINAL_FILES=len(rows),
                       ORIGINAL_BYTES=sum(r["bytes"] for r in rows), ARCHIVED_FILES=len(archived),
                       ARCHIVED_BYTES=sum(r["bytes"] for r in archived), PAYLOAD_FILES=2,
                       PAYLOAD_BYTES=len(files["hosted-cost/one.tar.xz"]) + len(files["hosted-cost/two.tar.xz"])).start()

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=self.root,
                                       stderr=subprocess.PIPE)

    def write(self, data):
        self.index.write_text(json.dumps(data))

    def check(self):
        return archive.fixed_inputs(self.root, self.index)

    def test_complete_tracked_metadata_is_verified_without_claiming_semantic_execution(self):
        report = self.check()[5]
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["current_native_tests_executed"], 0)
        self.assertNotIn("original_checker_executed", report)

    def test_metadata_pass_cannot_replace_the_real_original_verifier(self):
        # These tiny containers deliberately are not the twelve real archives.
        # The actual original checker runs and rejects them plus missing sections.
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(history.Invalid):
            archive.validate(self.root, self.index)
        self.assertIn('"original_checker_exit": 1', output.getvalue())
        self.assertIn('"result": "FAIL"', output.getvalue())
        self.assertEqual((self.package / "verification-receipt.json").read_bytes(),
                         b'{"result":"historical-only"}\n')

    def test_omitted_or_reordered_original_member_is_refused(self):
        for mutate in (lambda d: d["files"].pop(), lambda d: d["files"].reverse()):
            data = copy.deepcopy(self.data)
            mutate(data)
            self.write(data)
            with self.assertRaises(history.Invalid):
                self.check()

    def test_wrong_snapshot_scope_or_denominator_is_refused(self):
        for key, value in (("source_commit", "0" * 40), ("source_tree", "0" * 40),
                           ("scopes", [archive.PACKAGE + "/elsewhere"]),
                           ("total_bytes", 0), ("file_count", True)):
            data = copy.deepcopy(self.data)
            data[key] = value
            self.write(data)
            with self.subTest(key=key), self.assertRaises(history.Invalid):
                self.check()

    def test_missing_changed_or_symlinked_retained_record_is_refused(self):
        p = self.package / "retained-hosted-cost/hosted-cost-analysis.log"
        p.unlink()
        with self.assertRaises(history.Invalid): self.check()
        p.write_bytes(b"changed\n")
        with self.assertRaises(history.Invalid): self.check()
        p.unlink()
        p.symlink_to(self.package / "failure.json")
        with self.assertRaises(history.Invalid): self.check()

    def test_preserved_failure_cannot_be_promoted_even_with_resigned_metadata(self):
        p = self.package / "failure.json"
        p.write_bytes(b'{"result":"PASS"}\n')
        data = copy.deepcopy(self.data)
        row = next(r for r in data["preserved_files"] if r["path"].endswith("/failure.json"))
        row["bytes"], row["sha256"] = p.stat().st_size, archive.digest(p.read_bytes())
        self.write(data)
        with self.assertRaises(history.Invalid): self.check()

    def test_untracked_index_or_retained_log_is_refused(self):
        for name in (self.index, self.package / "retained-hosted-cost/hosted-cost-analysis.log"):
            relative = name.relative_to(self.root).as_posix()
            self.git("rm", "--cached", "-q", relative)
            with self.subTest(name=name), self.assertRaises(history.Invalid): self.check()
            self.git("add", relative)

    def test_unexpected_file_and_restored_archived_path_are_refused(self):
        for p in (self.package / "extra", self.package / "hosted-cost/one.tar.xz"):
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(b"unexpected")
            with self.subTest(path=p), self.assertRaises(history.Invalid): self.check()
            p.unlink()

    def test_special_file_is_refused_before_read(self):
        p = self.package / "failure.json"
        p.unlink()
        os.mkfifo(p, 0o600)
        with self.assertRaises(history.Invalid): self.check()

    def test_checker_function_mutation_is_refused(self):
        p = self.package / archive.CHECKER
        p.write_bytes(p.read_bytes().replace(b"CHUNK = 1024 * 1024", b"CHUNK = 1", 1))
        with self.assertRaises(history.Invalid): self.check()

    def test_actual_cli_missing_or_dangling_index_never_overwrites_old_receipts(self):
        scripts = self.root / "scripts/ci"
        scripts.mkdir(parents=True)
        for name in ("check_hosted_cost_archive.py", "check_historical_archive.py"):
            shutil.copyfile(REPOSITORY / "scripts/ci" / name, scripts / name)
        entry = self.package / archive.CHECKER
        entry.write_bytes((REPOSITORY / archive.PACKAGE / archive.CHECKER).read_bytes())
        before = {p.relative_to(self.package).as_posix(): p.read_bytes()
                  for p in self.package.rglob("*") if p.is_file() and p != self.index}
        self.index.unlink()
        unrelated = self.root / "caller"
        unrelated.mkdir()
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        for dangling in (False, True):
            if dangling:
                self.index.symlink_to(self.root / "missing-index")
            result = subprocess.run([sys.executable, "-B", str(entry)], cwd=unrelated,
                                    env=env, capture_output=True, text=True, timeout=5)
            with self.subTest(dangling=dangling):
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("Hosted-cost archive check failed", result.stderr)
                after = {p.relative_to(self.package).as_posix(): p.read_bytes()
                         for p in self.package.rglob("*") if p.is_file() and p != self.index}
                self.assertEqual(after, before)
            if dangling:
                self.index.unlink()

    def test_qualification_flags_duplicate_json_and_nonfinite_json_are_refused(self):
        for key in ("qualification_changed", "production_activation"):
            data = copy.deepcopy(self.data)
            data[key] = True
            self.write(data)
            with self.subTest(key=key), self.assertRaises(history.Invalid): self.check()
        self.index.write_text(json.dumps(self.data)[:-1] + ', "schema":"shadow"}')
        with self.assertRaises(history.Invalid): self.check()
        self.index.write_text(json.dumps(self.data)[:-1] + ', "injected":NaN}')
        with self.assertRaises(history.Invalid): self.check()


class OriginalHostedTarControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="trnm-original-verifier-")
        path = Path(cls.directory.name) / "original.py"
        path.write_bytes(original_checker())
        spec = importlib.util.spec_from_file_location("original_cost_verifier", path)
        cls.verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.verifier)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="trnm-original-tar-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def container(self, names):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            for name, payload, kind in names:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(payload) if kind == tarfile.REGTYPE else 0
                member.linkname = "target" if kind == tarfile.SYMTYPE else ""
                tar.addfile(member, io.BytesIO(payload) if kind == tarfile.REGTYPE else None)
        return lzma.compress(stream.getvalue())

    def verify(self, raw, expected):
        p = self.root / "sample.tar.xz"
        p.write_bytes(raw)
        return self.verifier.verify_tar([p], expected)

    def test_original_tar_reads_every_byte_without_extracting(self):
        raw = b"payload\0with binary\xff"
        report = self.verify(self.container([("nested/one", raw, tarfile.REGTYPE)]),
                             {"nested/one": {"bytes": len(raw), "sha256": archive.digest(raw)}})
        self.assertEqual(report["regular_members"], 1)
        self.assertEqual(report["extracted_files"], 0)
        self.assertFalse((self.root / "nested").exists())

    def test_duplicate_extra_unsafe_or_symlinked_member_is_refused(self):
        expected = {"one": {"bytes": 1, "sha256": archive.digest(b"x")}}
        for members in ([('one', b'x', tarfile.REGTYPE)] * 2,
                        [('one', b'x', tarfile.REGTYPE), ('extra', b'x', tarfile.REGTYPE)],
                        [('../one', b'x', tarfile.REGTYPE)],
                        [('one', b'', tarfile.SYMTYPE)]):
            with self.subTest(members=members), self.assertRaises(self.verifier.VerificationError):
                self.verify(self.container(members), expected)

    def test_missing_member_or_forged_member_hash_is_refused(self):
        raw = self.container([('one', b'x', tarfile.REGTYPE)])
        for expected in ({"missing": {"bytes": 1, "sha256": archive.digest(b"x")}},
                         {"one": {"bytes": 1, "sha256": archive.digest(b"y")}}):
            with self.assertRaises(self.verifier.VerificationError): self.verify(raw, expected)

    def test_concatenation_order_and_whole_digest_are_required(self):
        parts = []
        for name, raw in (("part01", b"abc"), ("part02", b"def")):
            (self.root / name).write_bytes(raw)
            parts.append({"path": name, "bytes": len(raw), "sha256": archive.digest(raw)})
        self.verifier.verify_container_parts(self.root, parts, 6, archive.digest(b"abcdef"))
        with self.assertRaises(self.verifier.VerificationError):
            self.verifier.verify_container_parts(self.root, list(reversed(parts)), 6, archive.digest(b"abcdef"))
        with self.assertRaises(self.verifier.VerificationError):
            self.verifier.verify_container_parts(self.root, parts, 6, "0" * 64)


if __name__ == "__main__":
    unittest.main()
