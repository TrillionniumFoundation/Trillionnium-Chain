"""Regression controls for the preserved joint-resource archive observation."""
import copy
import gzip
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

import check_historical_archive as history
import check_joint_resource_archive as joint


class JointResourceArchiveControls(unittest.TestCase):
    def snapshot(self, artifacts_change=None, metadata_change=None,
                 checksum_change=None, crosscheck_change=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / "package"

        def git(*arguments):
            return subprocess.check_output(["git", *arguments], cwd=root,
                                           stderr=subprocess.DEVNULL)

        def encode(value):
            return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

        def write(name, raw):
            path = package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

        git("init", "-q")
        git("config", "user.name", "Joint-resource archive test")
        git("config", "user.email", "joint-resource-test@example.invalid")
        failed = b'{"result":"FAIL","native_exit":101}\n'
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr(zipfile.ZipInfo("failure.json"), failed)
        packed = io.BytesIO()
        with tarfile.open(fileobj=packed, mode="w:xz") as archive:
            entry = tarfile.TarInfo("failure.json")
            entry.size = len(failed)
            archive.addfile(entry, io.BytesIO(failed))
        archives = {"archives/original.zip": zipped.getvalue(),
                    "archives/preparation.tar.xz": packed.getvalue()}
        rows = []
        for position, (name, raw) in enumerate(sorted(archives.items())):
            write(name, raw)
            metadata_name = f"inventories/archive-{position}.json"
            metadata = {"file": Path(name).name, "bytes": len(raw),
                        "sha256": joint.digest(raw), "file_count": 1,
                        "uncompressed_bytes": len(failed)}
            rows.append(dict(metadata, path=name, metadata=metadata_name,
                             scope="Original failed observation"))
            if metadata_change is not None and position == 0:
                metadata_change(metadata)
            write(metadata_name, encode(metadata))
            write(f"inventories/archive-{position}-files.json",
                  encode([{"path": "failure.json", "bytes": len(failed),
                           "sha256": joint.digest(failed)}]))
        artifacts = {"schema": joint.SCHEMA, "tested_implementation": "a" * 40,
                     "tested_tree": "b" * 40, "archives": rows, "archive_count": len(rows),
                     "total_archive_bytes": sum(map(len, archives.values())),
                     **{flag: False for flag in joint.QUALIFICATION_FLAGS}}
        if artifacts_change is not None:
            artifacts_change(artifacts)
        crosscheck = {"failure": "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED", "complete_campaigns": 0,
                      "actual_campaigns": 3, "planned_campaigns": 3}
        if crosscheck_change is not None:
            crosscheck_change(crosscheck)
        write("README.md", b"# Original observation\n\n**HOLD / NO-GO.**\n")
        write("artifacts.json", encode(artifacts))
        write("original-campaign-root-crosscheck.json", encode(crosscheck))
        write("integrity/verify_archives.py.gz", gzip.compress(
            b'raise RuntimeError("historical helpers must never execute")\n', mtime=0))
        write("integrity/verification.json", encode({"passed": True, "archive_contents_executed": False}))
        write("original-failure.log", b"ORIGINAL_THREE_RUN_CAMPAIGN_FAILED\n")
        payloads = {path.relative_to(package).as_posix(): path.read_bytes()
                    for path in package.rglob("*") if path.is_file()}
        checksums = "".join(joint.digest(raw) + "  " + name + "\n"
                            for name, raw in sorted(payloads.items())).encode()
        if checksum_change is not None:
            checksums = checksum_change(checksums)
        write("SHA256SUMS", checksums)
        git("add", ".")
        git("commit", "-qm", "original joint-resource observation")
        commit = git("rev-parse", "HEAD").decode().strip()
        original = history.tree_rows(root, commit, ["package"])
        for name, row in original.items():
            row["sha256"] = joint.digest((root / name).read_bytes())
        archived_names = {"package/" + name for name in archives}
        data = {"schema": "trnm-historical-source-archive-v1", "source_commit": commit,
                "source_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
                "scopes": ["package/archives"], "file_count": len(archives),
                "total_bytes": sum(map(len, archives.values())),
                "files": [original[name] for name in sorted(archived_names)],
                "historical_manifests": [original["package/" + name]
                                         for name in sorted(joint.HISTORICAL_MANIFESTS)],
                "retained_copies": [],
                "preserved_files": [original[name] for name in sorted(
                    set(original) - archived_names - {"package/README.md"})],
                "qualification_changed": False, "production_activation": False}
        index = package / "ORIGINAL_ARCHIVE_INDEX.json"
        index.write_bytes(encode(data))
        for name in archives:
            (package / name).unlink()
        write("README.md", b"# Storage update\n\n**HOLD / NO-GO.** Original bytes remain indexed.\n")
        return SimpleNamespace(root=root, package=package, index=index, data=data,
                               archives=archives, payloads=payloads)

    @staticmethod
    def check(fixture):
        return joint.validate(fixture.root, fixture.index)

    def assert_rejected(self, fixture):
        with self.assertRaises(history.Invalid):
            self.check(fixture)

    def test_complete_original_checksum_roster_and_read_only_retrieval(self):
        fixture = self.snapshot()
        before = {p.relative_to(fixture.package): p.read_bytes()
                  for p in fixture.package.rglob("*") if p.is_file()}
        result = self.check(fixture)
        self.assertEqual(result["original_sealed_payload_files"], len(fixture.payloads))
        self.assertEqual(result["original_sealed_payload_bytes"], sum(map(len, fixture.payloads.values())))
        self.assertEqual(result["original_artifact_bindings"], 2)
        self.assertEqual(result["original_gate_verdict"], "HOLD / NO-GO")
        self.assertEqual(result["original_complete_campaigns"], 0)
        self.assertEqual(result["original_planned_campaigns"], 3)
        self.assertFalse(result["archive_members_rehashed"])
        self.assertFalse(result["archived_helpers_executed"])
        self.assertFalse(result["archives_extracted"])
        self.assertFalse(result["current_business_qualification"])
        for name, raw in fixture.archives.items():
            _, actual = history.validate(fixture.root, fixture.index, "package/" + name)
            self.assertEqual(raw, actual)
            self.assertFalse((fixture.package / name).exists())
        after = {p.relative_to(fixture.package): p.read_bytes()
                 for p in fixture.package.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_missing_retained_failure_inventory_or_control_is_refused(self):
        for name in ("original-failure.log", "inventories/archive-0-files.json", "SHA256SUMS"):
            with self.subTest(name=name):
                fixture = self.snapshot()
                (fixture.package / name).unlink()
                self.assert_rejected(fixture)

    def test_changed_original_failure_cannot_be_rebound_by_new_digest(self):
        fixture = self.snapshot()
        path = fixture.package / "original-failure.log"
        path.write_bytes(b"ALL_CAMPAIGNS_PASSED\n")
        row = next(x for x in fixture.data["preserved_files"]
                   if x["path"] == "package/original-failure.log")
        row.update(bytes=path.stat().st_size, sha256=joint.digest(path.read_bytes()))
        fixture.index.write_text(json.dumps(fixture.data))
        self.assert_rejected(fixture)

    def test_retained_original_cannot_be_omitted_from_preserved_roster(self):
        fixture = self.snapshot()
        fixture.data["preserved_files"] = [x for x in fixture.data["preserved_files"]
                                           if x["path"] != "package/original-failure.log"]
        fixture.index.write_text(json.dumps(fixture.data))
        self.assert_rejected(fixture)

    def test_original_storage_readme_must_be_bound(self):
        fixture = self.snapshot()
        fixture.data["historical_manifests"] = [x for x in fixture.data["historical_manifests"]
                                               if x["path"] != "package/README.md"]
        fixture.index.write_text(json.dumps(fixture.data))
        self.assert_rejected(fixture)

    def test_extra_current_file_and_symlink_are_refused(self):
        fixture = self.snapshot()
        extra = fixture.package / "later-success.json"
        extra.write_text('{"result":"PASS"}')
        self.assert_rejected(fixture)
        extra.unlink()
        path = fixture.package / "original-failure.log"
        path.unlink()
        path.symlink_to("README.md")
        self.assert_rejected(fixture)

    def test_original_checksum_roster_cannot_omit_duplicate_or_change_entries(self):
        mutations = [lambda raw: raw + raw.splitlines(keepends=True)[0],
                     lambda raw: b"".join(raw.splitlines(keepends=True)[1:]),
                     lambda raw: raw.replace(b"  README.md\n", b"  ../README.md\n"),
                     lambda raw: b"0" * 64 + raw[64:]]
        for position, mutation in enumerate(mutations):
            with self.subTest(position=position):
                self.assert_rejected(self.snapshot(checksum_change=mutation))

    def test_original_artifact_roster_and_denominators_are_verified(self):
        mutations = [lambda doc: doc.update(archive_count=doc["archive_count"] + 1),
                     lambda doc: doc.update(total_archive_bytes=doc["total_archive_bytes"] + 1),
                     lambda doc: doc["archives"].__setitem__(1, copy.deepcopy(doc["archives"][0])),
                     lambda doc: doc["archives"][0].update(sha256="0" * 64),
                     lambda doc: doc["archives"][0].update(path="archives/unindexed.zip")]
        for position, mutation in enumerate(mutations):
            with self.subTest(position=position):
                self.assert_rejected(self.snapshot(artifacts_change=mutation))

    def test_original_sidecar_metadata_must_match_complete_artifact_record(self):
        for field, value in (("file", "different.zip"), ("file_count", 99), ("bytes", 1)):
            with self.subTest(field=field):
                self.assert_rejected(self.snapshot(metadata_change=lambda doc: doc.update({field: value})))

    def test_original_qualification_cannot_be_promoted_or_type_confused(self):
        for flag in joint.QUALIFICATION_FLAGS:
            for value in (True, 0):
                with self.subTest(flag=flag, value=value):
                    self.assert_rejected(self.snapshot(artifacts_change=lambda doc: doc.update({flag: value})))

    def test_original_failed_campaign_denominator_cannot_be_relabelled(self):
        mutations = [lambda doc: doc.update(failure="ALL_CAMPAIGNS_PASSED"),
                     lambda doc: doc.update(complete_campaigns=1),
                     lambda doc: doc.update(planned_campaigns=2),
                     lambda doc: doc.update(actual_campaigns=2)]
        for position, mutation in enumerate(mutations):
            with self.subTest(position=position):
                self.assert_rejected(self.snapshot(crosscheck_change=mutation))


if __name__ == "__main__":
    unittest.main()
