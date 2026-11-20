"""Full sealed-package checks after original ZIPs move to reachable Git history."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

import check_historical_archive as history
import check_sealed_ci_archive as sealed


class SealedArchiveControls(unittest.TestCase):
    def snapshot(self, artifact_change=None, seal_change=None, checksum_change=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        def git(*arguments):
            return subprocess.check_output(["git", *arguments], cwd=root,
                                           stderr=subprocess.DEVNULL)

        git("init", "-q")
        git("config", "user.name", "Sealed archive test")
        git("config", "user.email", "sealed-test@example.invalid")
        package = root / "package"

        def write(name, raw):
            path = package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

        def encode(value):
            return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

        candidate = "a" * 40
        artifacts = []
        archives = {}
        for identity in (101, 102):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as container:
                container.writestr(zipfile.ZipInfo("result.json"), b'{"result":"FAIL"}\n')
                container.writestr(zipfile.ZipInfo("original-reader.py"),
                                   b'raise RuntimeError("archived helpers must never run")\n')
            raw = stream.getvalue()
            archive_name = f"archives/{identity}.zip"
            readback_name = f"artifacts/{identity}/readback.json"
            archives[archive_name] = raw
            write(archive_name, raw)
            write(readback_name, encode({"artifact_id": identity, "result": "FAIL"}))
            artifacts.append({
                "artifact_id": identity, "archive": archive_name, "readback": readback_name,
                "github_metadata": {"id": identity, "size_in_bytes": len(raw),
                                    "digest": "sha256:" + sealed.digest(raw),
                                    "workflow_run": {"head_sha": candidate}},
            })
        if artifact_change is not None:
            artifact_change(artifacts)
        core = {"verdict": "HOLD", "candidate": candidate,
                "workflow_jobs": {"total": 5, "success": 2, "failure": 3},
                "native_lanes": {"total": 4, "success": 2, "failure": 2}}
        write("README.md", b"Original fixed HOLD package.\n")
        write("GATE_CORE.json", encode(core))
        write("ARTIFACT_INDEX.json", encode(artifacts))
        write("FILES.json", encode({"original_archive_names": sorted(archives)}))
        write("OBSERVER_NOTES.json", encode({"preparation_result": "FAIL"}))
        write("readbacks/core.json", encode({"verdict": "HOLD", "failed_native_lanes": 2}))
        write("source-resolvers/context.json", encode({"candidate": candidate, "result": "FAIL"}))
        write("detail/run.log", b"native result FAIL, exit 101, 0 passed, 1 failed\n")
        payloads = {path.relative_to(package).as_posix(): path.read_bytes()
                    for path in package.rglob("*") if path.is_file()}
        sums = "".join(sealed.digest(raw) + "  " + name + "\n"
                       for name, raw in sorted(payloads.items())).encode()
        if checksum_change is not None:
            sums = checksum_change(sums)
        write("SHA256SUMS", sums)
        seal = {"schema": sealed.SEAL_SCHEMA, "verdict": "HOLD", "candidate": candidate,
                "core_lane_count": len(archives), "workflow_jobs": 5, "native_lanes": 4,
                "archives": len(archives), "archive_bytes": sum(map(len, archives.values())),
                "payload_files": len(payloads), "payload_bytes": sum(map(len, payloads.values())),
                "sha256sums_bytes": len(sums), "sha256sums_sha256": sealed.digest(sums),
                "gate_core_bytes": len(payloads["GATE_CORE.json"]),
                "gate_core_sha256": sealed.digest(payloads["GATE_CORE.json"])}
        if seal_change is not None:
            seal_change(seal)
        write("SEAL.json", encode(seal))
        git("add", ".")
        git("commit", "-qm", "original sealed failed observations")
        commit = git("rev-parse", "HEAD").decode().strip()
        rows = history.tree_rows(root, commit, ["package"])
        for name, row in rows.items():
            row["sha256"] = hashlib.sha256((root / name).read_bytes()).hexdigest()
        data = {
            "schema": "trnm-historical-source-archive-v1", "source_commit": commit,
            "source_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "scopes": ["package/archives"], "file_count": len(archives),
            "total_bytes": sum(map(len, archives.values())),
            "files": [rows["package/" + name] for name in sorted(archives)],
            "historical_manifests": [rows["package/" + name] for name in
                                     sorted(sealed.CONTROL_FILES | {"README.md"})],
            "retained_copies": [],
            "preserved_files": [rows["package/" + name] for name in
                                sorted(sealed.CONTROL_FILES | {"readbacks/core.json",
                                                              "source-resolvers/context.json"})],
            "qualification_changed": False, "production_activation": False,
        }
        index = package / "ORIGINAL_ZIP_ARCHIVE.json"
        index.write_bytes(encode(data))
        for name in archives:
            (package / name).unlink()
        write("README.md", b"Storage changed; original verdict remains HOLD.\n")
        return SimpleNamespace(root=root, package=package, index=index, data=data,
                               payloads=payloads, archives=archives)

    @staticmethod
    def check(fixture):
        return sealed.validate(fixture.root, fixture.index)

    def assert_rejected(self, fixture):
        with self.assertRaises(history.Invalid):
            self.check(fixture)

    def test_original_full_checksum_roster_and_read_only_retrieval(self):
        fixture = self.snapshot()
        before = {p.relative_to(fixture.package): p.read_bytes()
                  for p in fixture.package.rglob("*") if p.is_file()}
        result = self.check(fixture)
        self.assertEqual(result["original_sealed_payload_files"], len(fixture.payloads))
        self.assertEqual(result["original_sealed_payload_bytes"], sum(map(len, fixture.payloads.values())))
        self.assertEqual(result["original_artifact_bindings"], 2)
        self.assertEqual(result["original_gate_verdict"], "HOLD")
        self.assertEqual(result["current_native_tests_executed"], 0)
        self.assertFalse(result["archived_helpers_executed"])
        self.assertFalse(result["current_business_qualification"])
        for name, original in fixture.archives.items():
            _, raw = history.validate(fixture.root, fixture.index, "package/" + name)
            self.assertEqual(raw, original)
            self.assertFalse((fixture.package / name).exists())
        after = {p.relative_to(fixture.package): p.read_bytes()
                 for p in fixture.package.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_missing_retained_payload_is_not_resolved_from_history(self):
        for name in ("artifacts/101/readback.json", "detail/run.log",
                     "source-resolvers/context.json"):
            with self.subTest(name=name):
                fixture = self.snapshot()
                (fixture.package / name).unlink()
                self.assert_rejected(fixture)

    def test_unlisted_failure_log_cannot_be_changed_to_pass(self):
        fixture = self.snapshot()
        path = fixture.package / "detail/run.log"
        self.assertNotIn("package/detail/run.log", {x["path"] for x in fixture.data["preserved_files"]})
        path.write_bytes(path.read_bytes().replace(b"FAIL", b"PASS"))
        self.assert_rejected(fixture)

    def test_original_control_file_cannot_change(self):
        for name in sealed.CONTROL_FILES:
            with self.subTest(name=name):
                fixture = self.snapshot()
                path = fixture.package / name
                path.write_bytes(path.read_bytes() + b"\n")
                self.assert_rejected(fixture)

    def test_controls_cannot_be_removed_from_preserved_roster(self):
        fixture = self.snapshot()
        fixture.data["preserved_files"] = [x for x in fixture.data["preserved_files"]
                                           if x["path"] != "package/SEAL.json"]
        fixture.index.write_text(json.dumps(fixture.data))
        self.assert_rejected(fixture)

    def test_extra_current_file_and_symlink_are_refused(self):
        fixture = self.snapshot()
        extra = fixture.package / "later-observation.json"
        extra.write_text('{"result":"PASS"}')
        self.assert_rejected(fixture)
        extra.unlink()
        target = fixture.package / "detail/run.log"
        target.unlink()
        target.symlink_to("../README.md")
        self.assert_rejected(fixture)

    def test_original_storage_readme_must_be_bound(self):
        fixture = self.snapshot()
        fixture.data["historical_manifests"] = [x for x in fixture.data["historical_manifests"]
                                               if x["path"] != "package/README.md"]
        fixture.index.write_text(json.dumps(fixture.data))
        self.assert_rejected(fixture)

    def test_even_a_committed_promoted_seal_is_not_a_hold_observation(self):
        fixture = self.snapshot(seal_change=lambda seal: seal.update(verdict="PASS"))
        self.assert_rejected(fixture)

    def test_original_denominator_mismatch_is_rejected(self):
        for field in ("payload_files", "payload_bytes", "archives", "core_lane_count",
                      "archive_bytes", "workflow_jobs", "native_lanes"):
            with self.subTest(field=field):
                fixture = self.snapshot(seal_change=lambda seal: seal.update({field: seal[field] + 1}))
                self.assert_rejected(fixture)

    def test_original_github_metadata_mismatch_is_rejected(self):
        mutations = [
            lambda rows: rows[0]["github_metadata"].update(digest="sha256:" + "0" * 64),
            lambda rows: rows[0]["github_metadata"].update(size_in_bytes=1),
            lambda rows: rows[0]["github_metadata"].update(id=999),
            lambda rows: rows[0]["github_metadata"]["workflow_run"].update(head_sha="b" * 40),
            lambda rows: rows[0].update(readback="artifacts/missing/readback.json"),
            lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])),
        ]
        for position, mutation in enumerate(mutations):
            with self.subTest(position=position):
                self.assert_rejected(self.snapshot(artifact_change=mutation))

    def test_corrupt_checksum_roster_is_rejected_even_with_updated_seal_hash(self):
        mutations = [
            lambda raw: raw + raw.splitlines(keepends=True)[0],
            lambda raw: b"".join(raw.splitlines(keepends=True)[1:]),
            lambda raw: raw.replace(b"  README.md\n", b"  ../README.md\n"),
            lambda raw: b"0" * 63 + raw[64:],
            lambda raw: b"0" * 64 + raw[64:],
        ]
        for position, mutation in enumerate(mutations):
            with self.subTest(position=position):
                self.assert_rejected(self.snapshot(checksum_change=mutation))


if __name__ == "__main__":
    unittest.main()
