#!/usr/bin/env python3
"""Lossless evidence mapping and real filesystem refusal controls."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import prepare_artifact_upload as mapper

SCRIPT = Path(mapper.__file__).resolve()
ACTUAL_REFUSED_NAME = (
    "native-storage-component-cell::host_handoff::tests::research_fds::"
    "research_fd_sender_refuses_changed_pins_budget_task_parent_or_expiry_before_any_byte.exit"
)


class ArtifactUploadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "upload"

    def put(self, name, content):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def command(self):
        return [sys.executable, "-B", str(SCRIPT), "--source", str(self.source),
                "--output", str(self.output)]

    def verify(self, original):
        manifest = json.loads((self.output / "artifact-path-map-v1.json").read_text())
        rows = manifest["files"]
        self.assertEqual(manifest["file_count"], len(original))
        self.assertEqual(manifest["total_bytes"], sum(map(len, original.values())))
        self.assertEqual({row["original_path"] for row in rows}, set(original))
        self.assertEqual(len({row["mapped_path"] for row in rows}), len(original))
        actual = {path.relative_to(self.output).as_posix() for path in self.output.rglob("*") if path.is_file()}
        self.assertEqual(actual, {row["mapped_path"] for row in rows} | {"artifact-path-map-v1.json"})
        for row in rows:
            self.assertRegex(row["mapped_path"], r"\Afiles/[0-9]{8}\.bin\Z")
            content = original[row["original_path"]]
            self.assertEqual((self.source / row["original_path"]).read_bytes(), content)
            self.assertEqual((self.output / row["mapped_path"]).read_bytes(), content)
            self.assertEqual(row["bytes"], len(content))
            self.assertEqual(row["sha256"], hashlib.sha256(content).hexdigest())
        return manifest

    def test_actual_colon_log_and_nested_hidden_empty_binary_files_are_lossless(self):
        original = {
            ACTUAL_REFUSED_NAME: b"0\n", "same:name.log": b"raw failure\x00\xff\n",
            "same?name.log": b"different failure\n", "sameNAME.log": b"different case\n",
            "nested?/child::stdout.log": b"nested original\n", ".hidden/.zero": b"",
            "unicode-\u6d4b\u8bd5\nline.log": b"unaltered observations\n",
        }
        for name, content in original.items():
            self.put(name, content)
        result = subprocess.run(self.command(), capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.verify(original)

    def test_mapping_is_deterministic_and_identical_bytes_do_not_merge_paths(self):
        original = {"a:b": b"same bytes", "a?b": b"same bytes", "nested/item": b"third"}
        for name, content in reversed(tuple(original.items())):
            self.put(name, content)
        mapper.prepare_upload(self.source, self.output)
        self.verify(original)
        second = self.root / "second"
        mapper.prepare_upload(self.source, second)
        self.assertEqual((self.output / "artifact-path-map-v1.json").read_bytes(),
                         (second / "artifact-path-map-v1.json").read_bytes())

    def test_existing_output_is_refused_without_merging_or_overwriting(self):
        self.put("original.log", b"original")
        self.output.mkdir()
        (self.output / "marker").write_bytes(b"retained")
        with self.assertRaises(FileExistsError):
            mapper.prepare_upload(self.source, self.output)
        self.assertEqual((self.output / "marker").read_bytes(), b"retained")
        self.assertEqual(list(self.output.iterdir()), [self.output / "marker"])

    def test_output_inside_source_and_empty_source_refuse(self):
        with self.assertRaises(mapper.ArtifactMapError):
            mapper.prepare_upload(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.put("original.log", b"original")
        for output in (self.source, self.source / "nested-upload"):
            with self.assertRaises(mapper.ArtifactMapError):
                mapper.prepare_upload(self.source, output)
        self.assertEqual({p.name for p in self.source.iterdir()}, {"original.log"})

    def test_real_fifo_and_symlinks_refuse_without_waiting_or_success_manifest(self):
        target = self.root / "target"
        target.write_bytes(b"outside bytes")
        for kind in ("fifo", "file-link", "directory-link"):
            path = self.source / "special"
            if kind == "fifo":
                os.mkfifo(path)
            else:
                path.symlink_to(target if kind == "file-link" else self.root, target_is_directory=kind == "directory-link")
            result = subprocess.run(self.command(), capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 2, kind)
            self.assertFalse(self.output.exists())
            path.unlink()

    def test_symlink_root_or_ancestor_is_not_followed(self):
        self.put("original.log", b"original")
        linked = self.root / "linked"
        linked.symlink_to(self.source, target_is_directory=True)
        for source in (linked, self.root / "parent-link" / "source"):
            if "parent-link" in source.parts:
                (self.root / "parent-link").symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(OSError):
                mapper.prepare_upload(source, self.output)
            self.assertFalse(self.output.exists())

    def test_added_removed_changed_or_replaced_source_prevents_publication(self):
        self.put("a.log", b"first")
        self.put("z.log", b"last")
        original_copy = mapper._copy_regular
        for mutation in ("add", "remove", "change", "replace"):
            def copy_and_mutate(root_fd, relative, snapshot, destination):
                record = original_copy(root_fd, relative, snapshot, destination)
                if relative == "z.log":
                    if mutation == "add":
                        self.put("extra.log", b"new")
                    elif mutation == "remove":
                        (self.source / "a.log").unlink()
                    elif mutation == "change":
                        self.put("a.log", b"other")
                    else:
                        temporary = self.source / "replacement"
                        temporary.write_bytes(b"first")
                        temporary.replace(self.source / "a.log")
                return record
            with self.subTest(mutation=mutation), patch.object(mapper, "_copy_regular", side_effect=copy_and_mutate):
                with self.assertRaises(mapper.ArtifactMapError):
                    mapper.prepare_upload(self.source, self.output)
            self.assertFalse(self.output.exists())
            self.put("a.log", b"first")
            (self.source / "extra.log").unlink(missing_ok=True)

    def test_copy_failure_keeps_originals_and_leaves_no_partial_success(self):
        self.put("original.log", b"retained failure")
        with patch.object(mapper, "_copy_regular", side_effect=OSError("copy refused")):
            with self.assertRaises(OSError):
                mapper.prepare_upload(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual((self.source / "original.log").read_bytes(), b"retained failure")


if __name__ == "__main__":
    unittest.main()
