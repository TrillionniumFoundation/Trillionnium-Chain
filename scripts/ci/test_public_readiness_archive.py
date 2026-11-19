"""Fail-closed storage and CLI controls; real historical replay is a separate gate."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_historical_archive as history
import check_public_readiness_archive as archive


class PublicReadinessArchiveControls(unittest.TestCase):
    def snapshot(self, *, semantic_transfers=20480, gate_extra=""):
        temporary = tempfile.TemporaryDirectory(prefix="public-archive-control-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / archive.PACKAGE

        def git(*arguments):
            return subprocess.check_output(["git", *arguments], cwd=root,
                                           stderr=subprocess.DEVNULL)

        def encode(value):
            return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

        def write(name, raw):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

        git("init", "-q")
        git("config", "user.name", "Public archive negative control")
        git("config", "user.email", "public-archive-control@example.invalid")
        # This small subprocess fixture tests invocation/error propagation. It
        # is never presented as the real c2 semantic validator or qualification.
        checker = b'''import argparse, json, pathlib, subprocess
p=argparse.ArgumentParser();p.add_argument('--root',type=pathlib.Path)
p.add_argument('--evidence',type=pathlib.Path);p.add_argument('--historical',action='store_true')
a=p.parse_args();value=json.loads((a.evidence/'semantics.json').read_text())
if value['confirmed_transfers'] != 20480: raise ValueError('semantic confirmed transfer mismatch')
if (a.root/'scripts/required_source.py').read_text() != 'SOURCE_PIN = 1\\n':
 raise ValueError('wrong measured source bytes')
c=subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.root,text=True).strip()
r={'measured_commit':c,'current_source_qualified_by_this_check':not a.historical,
   'runtime_matches':not a.historical,'engineering_observations_verified':True,
   'pipeline_cases':4,'actual_confirmed_transfers':20480,
   'public_network_ready':False,'production_activation':False,'independent_accepted':False,
   'future_window_accepted':False,'work_profile_qualified':False,'physical_power_loss':False}
if a.historical:r['historical_semantics_verified']=True
'''
        checker += gate_extra.encode() + b"\nprint(json.dumps(r,sort_keys=True))\n"
        write(archive.CHECKER_PATH, checker)
        write("scripts/required_source.py", b"SOURCE_PIN = 1\n")
        write("README.md", b"Synthetic repository for storage-reader controls only.\n")
        write(".gitignore", b"*.log\n")
        git("add", ".")
        git("commit", "-qm", "synthetic measured source")
        measured_commit = git("rev-parse", "HEAD").decode().strip()
        measured_tree = git("rev-parse", "HEAD^{tree}").decode().strip()
        checker_oid = git("rev-parse", "HEAD:" + archive.CHECKER_PATH).decode().strip()
        source_hashes = {archive.CHECKER_PATH: archive.digest(checker),
                         "scripts/required_source.py": archive.digest(b"SOURCE_PIN = 1\n")}
        flags = {flag: False for flag in archive.FLAGS}
        for position, scope in enumerate(archive.SCOPES):
            write(scope + "/payload.json", encode({"original_observation": position, **flags}))
        prefix = archive.PACKAGE + "/"
        write(prefix + "README.md", b"# Original observation\n\nAll public and production claims remain false.\n")
        write(prefix + "qualification.json", encode({
            "source_commit": measured_commit, "source_tree": measured_tree,
            "source_files_sha256": source_hashes, **flags}))
        write(prefix + "semantics.json", encode({"confirmed_transfers": semantic_transfers, **flags}))
        write(prefix + "observations/b-original-check-failure.log", b"baseline attack contamination\n")
        write(prefix + "observations/empty.stderr.log", b"")
        for letter in "ae":
            write(prefix + "observations/failed-qualification-" + letter + "/qualification.json",
                  encode({"all_commands_passed": False, "error": "QUALIFICATION_FAILED", **flags}))
        files = {path.relative_to(package).as_posix(): archive.digest(path.read_bytes())
                 for path in package.rglob("*") if path.is_file()}
        manifest = {"schema": "trnm-public-readiness-evidence-v1",
                    "implementation_commit": measured_commit, "implementation_tree": measured_tree,
                    "files": files, **flags}
        write(prefix + "manifest.json", encode(manifest))
        git("add", "-f", "--", archive.PACKAGE)
        git("commit", "-qm", "synthetic original observation")
        commit = git("rev-parse", "HEAD").decode().strip()
        tree = git("rev-parse", "HEAD^{tree}").decode().strip()
        rows = history.tree_rows(root, commit, [archive.PACKAGE])
        for name, row in rows.items():
            row["sha256"] = archive.digest((root / name).read_bytes())
        archived = {name for name in rows if any(name.startswith(scope + "/") for scope in archive.SCOPES)}
        data = {"schema": "trnm-historical-source-archive-v1", "source_commit": commit,
                "source_tree": tree, "scopes": list(archive.SCOPES), "file_count": len(archived),
                "total_bytes": sum(rows[name]["bytes"] for name in archived),
                "files": [rows[name] for name in sorted(archived)],
                "historical_manifests": [rows[prefix + name] for name in sorted(archive.HISTORICAL_MANIFESTS)],
                "retained_copies": [],
                "preserved_files": [rows[name] for name in sorted(set(rows) - archived - {prefix + "README.md"})],
                "qualification_changed": False, "production_activation": False}
        index = package / archive.INDEX_NAME
        index.write_bytes(encode(data))
        readme = package / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\nStorage appendix: original bytes remain indexed.\n")
        for name in archived:
            (root / name).unlink()
        git("add", "-f", "--", prefix + archive.INDEX_NAME, prefix + "README.md")
        constants = {"ARCHIVE_COMMIT": commit, "ARCHIVE_TREE": tree,
                     "MEASURED_COMMIT": measured_commit, "MEASURED_TREE": measured_tree,
                     "CHECKER_BLOB": checker_oid, "CHECKER_BYTES": len(checker),
                     "CHECKER_SHA256": archive.digest(checker), "SOURCE_FILES": len(source_hashes),
                     "ORIGINAL_FILES": len(rows), "ORIGINAL_BYTES": sum(row["bytes"] for row in rows.values()),
                     "ARCHIVED_FILES": len(archived), "ARCHIVED_BYTES": data["total_bytes"]}
        return SimpleNamespace(root=root, package=package, index=index, data=data,
                               constants=constants, rows=rows, archived=archived, git=git)

    def check(self, fixture):
        with patch.multiple(archive, **fixture.constants):
            return archive.validate(fixture.root, fixture.index)

    def rejected(self, fixture, message=None):
        with self.assertRaisesRegex(history.Invalid, message or "."):
            self.check(fixture)

    @staticmethod
    def save_index(fixture):
        fixture.index.write_text(json.dumps(fixture.data))

    def run_existing_cli(self, fixture, folder=None):
        output = io.StringIO()
        script = Path(__file__).with_name("check_public_readiness_evidence.py")
        args = [str(script), "--root", str(fixture.root), "--historical",
                "--evidence", str(folder or fixture.package)]
        with patch.multiple(archive, **fixture.constants), patch.object(sys, "argv", args), \
                contextlib.redirect_stdout(output):
            runpy.run_path(str(script), run_name="__main__")
        return json.loads(output.getvalue().splitlines()[-1])

    def test_complete_original_view_runs_semantics_and_preserves_current_files(self):
        fixture = self.snapshot()
        before = {p.relative_to(fixture.package): p.read_bytes()
                  for p in fixture.package.rglob("*") if p.is_file()}
        refs = fixture.git("show-ref")
        index = (fixture.root / ".git/index").read_bytes()
        result = self.check(fixture)
        self.assertTrue(result["original_semantic_gate_executed"])
        self.assertTrue(result["historical_semantics_verified"])
        self.assertEqual(result["original_manifest_entries"], len(fixture.rows) - 1)
        self.assertEqual(result["original_source_files_sha256"], 2)
        self.assertEqual(result["network_fetches"], 0)
        self.assertEqual(result["actual_confirmed_transfers"], 20480)
        for key in (*archive.FLAGS, "native_execution_authenticated", "runtime_matches",
                    "current_source_qualified_by_this_check", "qualification_changed"):
            self.assertIs(result[key], False)
        after = {p.relative_to(fixture.package): p.read_bytes()
                 for p in fixture.package.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(refs, fixture.git("show-ref"))
        self.assertEqual(index, (fixture.root / ".git/index").read_bytes())
        self.assertFalse(any((fixture.root / name).exists() for name in fixture.archived))

    def test_existing_historical_cli_dispatches_the_fixed_archive(self):
        result = self.run_existing_cli(self.snapshot())
        self.assertTrue(result["original_semantic_gate_executed"])
        self.assertTrue(result["current_and_original_tracking_verified"])
        self.assertFalse(result["current_source_qualified_by_this_check"])

    def test_absent_archive_preserves_original_full_physical_cli_path(self):
        fixture = self.snapshot()
        for name in fixture.archived | {archive.PACKAGE + "/README.md"}:
            (fixture.root / name).write_bytes(fixture.git("cat-file", "blob", fixture.rows[name]["blob"]))
        fixture.index.unlink()
        result = self.run_existing_cli(fixture)
        self.assertTrue(result["historical_semantics_verified"])
        self.assertFalse(result["current_source_qualified_by_this_check"])
        self.assertNotIn("original_semantic_gate_executed", result)

    def test_missing_archive_index_cannot_hide_missing_original_files(self):
        fixture = self.snapshot()
        fixture.index.unlink()
        with self.assertRaisesRegex(ValueError, "artifact inventory mismatch"):
            self.run_existing_cli(fixture)

    def test_other_package_cannot_select_archive_reader(self):
        fixture = self.snapshot()
        fake = fixture.root / "evidence/fake-public-readiness"
        fake.mkdir()
        (fake / archive.INDEX_NAME).write_text("{}")
        (fake / "qualification.json").write_text("{}")
        (fake / "manifest.json").write_text(json.dumps({
            "files": {"qualification.json": archive.digest(b"{}")}}))
        self.assertIsNone(archive.dispatch_historical_archive(fixture.root, fake))
        with self.assertRaisesRegex(ValueError, "artifact inventory mismatch"):
            self.run_existing_cli(fixture, fake)

    def test_every_retained_file_and_new_index_must_be_tracked_even_if_physically_present(self):
        for name in (archive.INDEX_NAME, "observations/b-original-check-failure.log", "observations/empty.stderr.log"):
            with self.subTest(name=name):
                fixture = self.snapshot()
                fixture.git("update-index", "--force-remove", "--", archive.PACKAGE + "/" + name)
                self.assertTrue((fixture.package / name).is_file())
                self.rejected(fixture, "untracked retained evidence or archive index")

    def test_root_manifest_cannot_be_resealed_to_omit_original_entries(self):
        fixture = self.snapshot()
        path = fixture.package / "manifest.json"
        value = json.loads(path.read_text())
        value["files"].pop(next(iter(value["files"])))
        path.write_text(json.dumps(value))
        self.rejected(fixture, "original root manifest changed")

    def test_qualification_and_source_pin_changes_are_refused(self):
        for mutate in (lambda value: value.update(public_network_ready=True),
                       lambda value: value["source_files_sha256"].update({archive.CHECKER_PATH: "0" * 64})):
            fixture = self.snapshot()
            path = fixture.package / "qualification.json"
            value = json.loads(path.read_text()); mutate(value); path.write_text(json.dumps(value))
            self.rejected(fixture, "original qualification changed")

    def test_counterexamples_and_original_readme_claims_cannot_be_changed_or_omitted(self):
        for name in ("README.md", "observations/b-original-check-failure.log",
                     "observations/failed-qualification-a/qualification.json"):
            with self.subTest(name=name):
                fixture = self.snapshot()
                (fixture.package / name).write_text("ALL_PASSED")
                self.rejected(fixture)
        fixture = self.snapshot()
        fixture.data["preserved_files"].pop()
        self.save_index(fixture)
        self.rejected(fixture, "every retained original file")

    def test_extra_files_symlinks_and_overlapping_scopes_are_refused(self):
        fixture = self.snapshot()
        extra = fixture.package / "extra-success.json"; extra.write_text("{}")
        self.rejected(fixture, "missing or extra")
        extra.unlink(); (fixture.package / "observations/link").symlink_to("../README.md")
        self.rejected(fixture, "symlink")
        fixture = self.snapshot(); fixture.data["scopes"].append(archive.PACKAGE + "/observations")
        self.save_index(fixture); self.rejected(fixture, "21 complete original scopes")

    def test_archived_original_path_cannot_be_omitted_or_replaced_with_current_file(self):
        fixture = self.snapshot(); fixture.data["files"].pop(); self.save_index(fixture)
        self.rejected(fixture, "every fixed original path")
        fixture = self.snapshot(); name = sorted(fixture.archived)[0]
        (fixture.root / name).write_text("replacement")
        self.rejected(fixture, "missing or extra")

    def test_original_history_and_checker_identity_are_fixed(self):
        fixture = self.snapshot(); fixture.data["source_commit"] = "0" * 40
        self.save_index(fixture); self.rejected(fixture, "fixed original package snapshot")
        fixture = self.snapshot(); fixture.constants["MEASURED_TREE"] = "0" * 40
        self.rejected(fixture, "fixed original tree differs")
        fixture = self.snapshot(); fixture.constants["CHECKER_SHA256"] = "0" * 64
        self.rejected(fixture, "original semantic checker differs")

    def test_missing_source_or_archive_blob_fails_locally_without_remote_helper(self):
        for kind in ("source", "payload", "commit"):
            with self.subTest(kind=kind):
                fixture = self.snapshot()
                oid = (fixture.constants["CHECKER_BLOB"] if kind == "source"
                       else fixture.constants["MEASURED_COMMIT"] if kind == "commit"
                       else fixture.rows[sorted(fixture.archived)[0]]["blob"])
                (fixture.root / ".git/objects" / oid[:2] / oid[2:]).unlink()
                fixture.git("config", "remote.origin.url", "public-archive-probe::never")
                fixture.git("config", "remote.origin.promisor", "true")
                helper = fixture.root / "helpers"; helper.mkdir()
                marker = fixture.root / "network-helper-was-called"
                executable = helper / "git-remote-public-archive-probe"
                executable.write_text("#!/bin/sh\nprintf bad > '" + str(marker) + "'\nexit 99\n")
                executable.chmod(0o755)
                with patch.dict(archive.os.environ, {"PATH": str(helper) + ":" + archive.os.environ["PATH"]}):
                    self.rejected(fixture, "local.*(missing|unavailable)")
                self.assertFalse(marker.exists())

    def test_semantic_failure_propagates_despite_complete_matching_manifest(self):
        fixture = self.snapshot(semantic_transfers=20479)
        self.rejected(fixture, "(?s)original historical semantic gate failed.*semantic confirmed transfer mismatch")

    def test_original_semantic_result_cannot_promote_or_change_outcomes(self):
        for statement in ("r['public_network_ready']=True", "r['runtime_matches']=True",
                          "r['production_activation']=0", "r['actual_confirmed_transfers']=20479"):
            with self.subTest(statement=statement):
                self.rejected(self.snapshot(gate_extra=statement), "original historical outcome")


if __name__ == "__main__":
    unittest.main()
