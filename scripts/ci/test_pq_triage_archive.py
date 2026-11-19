"""Integrity and live-consumer counterexamples for the archived PQ CI capture."""
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import check_historical_archive as history
import check_pq_triage_archive as triage


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def fingerprint(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class PQTriageArchiveControls(unittest.TestCase):
    def snapshot(self, change_index=None, change_followup=None, legacy=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        package = root / "package"

        def git(*arguments):
            return subprocess.check_output(["git", *arguments], cwd=root, stderr=subprocess.DEVNULL)

        def write(name, raw):
            path = package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

        git("init", "-q")
        git("config", "user.name", "PQ triage archive test")
        git("config", "user.email", "pq-triage-test@example.invalid")
        for name in triage.LARGE:
            write(triage.CAPTURE + "/" + name, b"original failed capture: " + name.encode() + b"\n")
        write(triage.CAPTURE + "/report-summary.json", encoded({"outcome": "FAIL", "startup": "UNKNOWN"}))
        write(triage.CAPTURE + "/attempt-streams/run-1.stderr.log", b"")
        stdout = b"STARTUP: UNKNOWN\noriginal FAIL preserved\n"
        compressed_name = triage.CAPTURE + "/attempt-streams/run-1.stdout.log.gz"
        original_name = compressed_name[:-3]
        compressed = gzip.compress(stdout, mtime=0)
        write(compressed_name, compressed)
        for name in triage.PRESERVED - {"artifact-index.json", "followup-archive-inventory.json", "external-artifacts.json"}:
            write(name, encoded({"result": "UNKNOWN", "native_execution": False}))
        write("README.md", b"# Original observations\nNo whole-chain PQ qualification.\n")
        write("notes/status.json", encoded({"original_failure": "UNKNOWN"}))
        write("external-artifacts.json", encoded({"files": [], "silent_omissions": False}))
        legacy_rows = {}
        if legacy:
            for name in triage.HASH_ONLY_GZIP:
                original_raw = b'{"observation":"UNKNOWN"}\n'
                stored = gzip.compress(original_raw, mtime=0)
                write(name, stored)
                legacy_rows[name] = {"compressed_bytes": len(stored),
                    "compressed_sha256": hashlib.sha256(stored).hexdigest(),
                    "uncompressed": fingerprint(original_raw)}
        captured = {path.relative_to(package).as_posix(): path.read_bytes()
                    for path in (package / triage.CAPTURE).rglob("*") if path.is_file()}
        directory = triage.CAPTURE.split("/")[0]
        original_rows = {name[len(directory) + 1:]: fingerprint(raw) for name, raw in captured.items()
                         if name != compressed_name}
        original_rows[original_name[len(directory) + 1:]] = fingerprint(stdout)
        followup = {"schema": "trnm-pq-authority-followup-archives-v1", "capture_bytes_trimmed": False,
                    "source_receipts_rewritten": False, "hosted_ci_passed": False,
                    "directories": {directory: {"copied_original_files": original_rows}}}
        if change_followup is not None:
            change_followup(followup)
        write("followup-archive-inventory.json", encoded(followup))
        payloads = {path.relative_to(package).as_posix(): path.read_bytes()
                    for path in package.rglob("*") if path.is_file()}
        original_index = {
            "schema": "trnm-pq-authority-artifacts-v1", "whole_chain_pq_qualified": False,
            "production_activation": False, "files": {name: fingerprint(raw) for name, raw in payloads.items()},
            "compression": {compressed_name: {"compressed_bytes": len(compressed),
                "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
                "uncompressed": dict(fingerprint(stdout), relative_path=original_name)}}}
        original_index["compression"].update(legacy_rows)
        if change_index is not None:
            change_index(original_index)
        write("artifact-index.json", encoded(original_index))
        corpus_path = root / triage.CORPUS
        corpus_path.parent.mkdir(parents=True)
        corpus_path.write_bytes(encoded({"pinned_blobs": {}, "required_paths": []}))
        git("add", ".")
        git("commit", "-qm", "original PQ triage observations")
        commit = git("rev-parse", "HEAD").decode().strip()
        rows = history.tree_rows(root, commit, ["package"])
        for name, row in rows.items():
            row["sha256"] = hashlib.sha256((root / name).read_bytes()).hexdigest()
        archive_names = {"package/" + name for name in captured}
        copies = [{"archive_path": "package/" + name,
                   "path": "package/" + triage.RETAINED + "/" + name[len(triage.CAPTURE) + 1:]}
                  for name in sorted(captured) if name[len(triage.CAPTURE) + 1:] not in triage.LARGE]
        data = {"schema": "trnm-historical-source-archive-v1", "source_commit": commit,
                "source_tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
                "scopes": ["package/" + triage.CAPTURE], "file_count": len(archive_names),
                "total_bytes": sum(rows[name]["bytes"] for name in archive_names),
                "files": [rows[name] for name in sorted(archive_names)],
                "historical_manifests": [rows["package/" + name] for name in sorted(triage.MANIFESTS)],
                "retained_copies": copies,
                "preserved_files": [rows["package/" + name] for name in sorted(triage.PRESERVED)],
                "qualification_changed": False, "production_activation": False}
        for copy in copies:
            path = root / copy["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((root / copy["archive_path"]).read_bytes())
        for name in archive_names:
            (root / name).unlink()
        index = package / "NATIVE_TRIAGE_ARCHIVE.json"
        index.write_bytes(encoded(data))
        write("README.md", b"# Archive storage\nOriginal findings unchanged.\n")
        return SimpleNamespace(root=root, package=package, index=index, data=data,
                               payloads=payloads, captured=captured, corpus=corpus_path)

    @staticmethod
    def check(fixture):
        return triage.validate(fixture.root, fixture.index)

    def assert_rejected(self, fixture):
        with self.assertRaises(history.Invalid):
            self.check(fixture)

    def test_original_checksums_compression_accounting_and_readonly_retrieval(self):
        fixture = self.snapshot()
        before = {p.relative_to(fixture.package): p.read_bytes()
                  for p in fixture.package.rglob("*") if p.is_file()}
        result = self.check(fixture)
        self.assertEqual(result["original_package_files"], len(fixture.payloads))
        self.assertEqual(result["original_compression_bindings_verified"], 1)
        self.assertEqual(result["original_followup_file_bindings_verified"], len(fixture.captured))
        self.assertEqual(result["history_only_large_files"], 4)
        self.assertEqual(result["retained_capture_records"], 3)
        self.assertFalse(result["original_hosted_ci_passed"])
        self.assertFalse(result["whole_chain_pq_qualified"])
        self.assertFalse(result["new_campaign_execution"])
        selected = triage.CAPTURE + "/selected/run-1-raw/report.json"
        _, raw = history.validate(fixture.root, fixture.index, "package/" + selected)
        self.assertEqual(raw, fixture.captured[selected])
        after = {p.relative_to(fixture.package): p.read_bytes()
                 for p in fixture.package.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_missing_retained_copy_or_unlisted_outside_file_is_refused(self):
        for name in (triage.RETAINED + "/report-summary.json", "notes/status.json"):
            with self.subTest(name=name):
                fixture = self.snapshot()
                (fixture.package / name).unlink()
                self.assert_rejected(fixture)

    def test_unknown_and_failure_records_cannot_be_relabelled(self):
        for name in (triage.RETAINED + "/report-summary.json", "notes/status.json"):
            with self.subTest(name=name):
                fixture = self.snapshot()
                path = fixture.package / name
                path.write_bytes(path.read_bytes().replace(b"UNKNOWN", b"PASS"))
                self.assert_rejected(fixture)

    def test_smaller_capture_record_cannot_be_silently_discarded(self):
        fixture = self.snapshot()
        discarded = fixture.data["retained_copies"].pop()
        (fixture.root / discarded["path"]).unlink()
        fixture.index.write_bytes(encoded(fixture.data))
        self.assert_rejected(fixture)

    def test_original_index_cannot_omit_or_forge_a_checksum(self):
        for mutation in (lambda data: data["files"].pop("notes/status.json"),
                         lambda data: data["files"]["notes/status.json"].update(sha256="0" * 64)):
            self.assert_rejected(self.snapshot(change_index=mutation))

    def test_original_compression_binding_is_actually_decompressed(self):
        mutations = [lambda row: row.update(compressed_sha256="0" * 64),
                     lambda row: row["uncompressed"].update(sha256="0" * 64),
                     lambda row: row["uncompressed"].update(bytes=1),
                     lambda row: row["uncompressed"].update(relative_path="notes/status.json"),
                     lambda row: row["uncompressed"].pop("relative_path")]
        for position, mutation in enumerate(mutations):
            with self.subTest(position=position):
                self.assert_rejected(self.snapshot(change_index=lambda data: mutation(next(iter(data["compression"].values())))))

    def test_original_hash_only_gzip_records_are_checked_without_invented_paths(self):
        result = self.check(self.snapshot(legacy=True))
        self.assertEqual(result["original_compression_bindings_verified"], 3)
        self.assertEqual(result["original_compression_source_paths_named"], 1)

    def test_original_followup_accounting_cannot_forge_a_source_hash(self):
        def mutate(data):
            directory = next(iter(data["directories"].values()))
            next(iter(directory["copied_original_files"].values())).update(sha256="0" * 64)
        self.assert_rejected(self.snapshot(change_followup=mutate))

    def test_original_scope_cannot_be_promoted_or_failure_trimmed(self):
        for field in ("whole_chain_pq_qualified", "production_activation"):
            self.assert_rejected(self.snapshot(change_index=lambda data: data.update({field: True})))
        for field in ("hosted_ci_passed", "capture_bytes_trimmed", "source_receipts_rewritten"):
            self.assert_rejected(self.snapshot(change_followup=lambda data: data.update({field: True})))

    def test_new_live_corpus_consumer_blocks_archival(self):
        for field in ("pinned_blobs", "required_paths"):
            with self.subTest(field=field):
                fixture = self.snapshot()
                name = "package/" + triage.CAPTURE + "/selected/run-1-raw/report.json"
                corpus = {"pinned_blobs": {}, "required_paths": []}
                corpus[field] = {name: "a" * 40} if field == "pinned_blobs" else [name]
                fixture.corpus.write_bytes(encoded(corpus))
                self.assert_rejected(fixture)

    def test_unlisted_new_observation_is_refused(self):
        fixture = self.snapshot()
        (fixture.package / "later-success.json").write_bytes(b'{"passed":true}\n')
        self.assert_rejected(fixture)


if __name__ == "__main__":
    unittest.main()
