#!/usr/bin/env python3
"""Hostile fixture encodings are synthetic test data, never positive W1 proofs."""
import copy
import gzip
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile
import zlib

import prepare_w1_audit_one_fixture as fixture


class FixtureControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = {"guest.bin": b"synthetic-not-an-ELF" * 17,
                     "input.bin": bytes(range(256)) * 3,
                     "receipt.bin": b"synthetic-not-a-proof" * 57}
        self.assets = {n: {"bytes": len(b), "sha256": fixture.digest(b)}
                       for n, b in self.data.items()}
        self.out = self.root / "restored"

    def archive(self, entries=None):
        path = self.root / "capture.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                for name, raw in entries if entries is not None else self.data.items():
                    zipped.writestr(name, raw)
        return path

    def load_archive(self, path, assets=None, digest=None):
        return fixture.restore_archive(path, self.out, assets or self.assets,
                                       path.stat().st_size, digest or fixture.digest(path.read_bytes()))

    @staticmethod
    def compressed(raw):
        stream = io.BytesIO()
        with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as output:
            output.write(raw)
        return stream.getvalue()

    def objects(self, transform=None, receipt_cut=None):
        directory = self.root / "objects"
        directory.mkdir()
        pins = {}
        for name, raw in self.data.items():
            encoded = self.compressed(raw)
            if transform and name == "receipt.bin":
                encoded = transform(encoded)
            if name == "receipt.bin":
                cut = receipt_cut if receipt_cut is not None else len(encoded) // 2
                parts = [encoded[:cut], encoded[cut:]]
            else:
                parts = [encoded]
            chunks = []
            for part in parts:
                digest = fixture.digest(part)
                filename = digest + (".gz" if len(parts) == 1 else ".gz.part")
                (directory / filename).write_bytes(part)
                chunks.append({"file": filename, "bytes": len(part), "sha256": digest})
            pins[name] = {"bytes": len(encoded), "sha256": fixture.digest(encoded), "chunks": chunks}
        self.manifest(directory, pins)
        return directory, pins

    @staticmethod
    def chunk_path(directory, pins, name, index=0):
        return directory / pins[name]["chunks"][index]["file"]

    def manifest(self, directory, pins, assets=None):
        (directory / "manifest.json").write_bytes(fixture.manifest_bytes(assets or self.assets, pins))

    def refuse(self, call):
        with self.assertRaises((ValueError, OSError, zipfile.BadZipFile, EOFError, zlib.error)):
            call()
        self.assertFalse(self.out.exists())

    def test_archive_round_trip_is_not_proof_verification(self):
        record = self.load_archive(self.archive())
        self.assertTrue(record["historical_zip_verified_this_run"])
        self.assertFalse(record["proof_verified"])
        self.assertFalse(record["new_proof_generated"])
        self.assertEqual({p.name: p.read_bytes() for p in self.out.iterdir()}, self.data)

    def test_archive_requires_whole_zip_hash(self):
        path = self.archive()
        self.refuse(lambda: self.load_archive(path, digest="0" * 64))

    def test_archive_checks_each_asset_hash_after_zip_pin(self):
        pins = copy.deepcopy(self.assets)
        pins["input.bin"]["sha256"] = "0" * 64
        path = self.archive()
        self.refuse(lambda: self.load_archive(path, assets=pins))

    def test_archive_requires_exact_root_asset(self):
        path = self.archive([(n if n != "receipt.bin" else "nested/receipt.bin", b)
                             for n, b in self.data.items()])
        self.refuse(lambda: self.load_archive(path))

    def test_archive_rejects_duplicate_members(self):
        path = self.archive(list(self.data.items()) + [("input.bin", b"duplicate")])
        self.refuse(lambda: self.load_archive(path))

    def test_archive_rejects_traversal_even_for_unselected_entry(self):
        path = self.archive(list(self.data.items()) + [("../escape", b"x")])
        self.refuse(lambda: self.load_archive(path))

    def test_archive_rejects_absolute_entry(self):
        path = self.archive(list(self.data.items()) + [("/absolute", b"x")])
        self.refuse(lambda: self.load_archive(path))

    def test_archive_rejects_symlink_member(self):
        info = zipfile.ZipInfo("unselected-link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        path = self.archive(list(self.data.items()) + [(info, b"input.bin")])
        self.refuse(lambda: self.load_archive(path))

    def test_archive_rejects_oversized_member_count(self):
        path = self.archive()
        with patch.object(fixture, "MAX_MEMBERS", 2):
            self.refuse(lambda: self.load_archive(path))

    def test_archive_rejects_total_expansion(self):
        path = self.archive()
        with patch.object(fixture, "MAX_TOTAL_EXPANDED_BYTES", 1):
            self.refuse(lambda: self.load_archive(path))

    def test_archive_rejects_symlink_file(self):
        path = self.archive()
        link = self.root / "archive-link"
        link.symlink_to(path)
        self.refuse(lambda: self.load_archive(link))

    def test_archive_does_not_overwrite_existing_output(self):
        path = self.archive()
        self.out.mkdir()
        (self.out / "sentinel").write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.load_archive(path)
        self.assertEqual((self.out / "sentinel").read_bytes(), b"preserve")

    def test_object_round_trip_keeps_zip_check_false(self):
        directory, pins = self.objects()
        record = fixture.restore_objects(directory, self.out, self.assets, pins)
        self.assertFalse(record["historical_zip_verified_this_run"])
        self.assertFalse(record["proof_verified"])
        self.assertEqual(record["object_packaging_schema"], "pon-w1-durable-gzip-objects-v2")
        self.assertEqual(record["chunks_verified"], 4)
        self.assertTrue(record["whole_compressed_objects_verified"])
        self.assertEqual({p.name: p.read_bytes() for p in self.out.iterdir()}, self.data)

    def test_object_requires_exact_manifest(self):
        directory, pins = self.objects()
        path = directory / "manifest.json"
        raw = path.read_bytes().replace(b"pon-w1-durable", b"pon-w2-durable")
        path.write_bytes(raw)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_extra_entry(self):
        directory, pins = self.objects()
        (directory / "unexpected").write_bytes(b"x")
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_missing_entry(self):
        directory, pins = self.objects()
        self.chunk_path(directory, pins, "guest.bin").unlink()
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_changed_compressed_bytes(self):
        directory, pins = self.objects()
        path = self.chunk_path(directory, pins, "receipt.bin", 1)
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_changed_raw_hash_after_compressed_pin(self):
        directory, pins = self.objects()
        assets = copy.deepcopy(self.assets)
        assets["receipt.bin"]["sha256"] = "0" * 64
        self.manifest(directory, pins, assets)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, assets, pins))

    def test_object_rejects_truncated_gzip_with_consistent_outer_hash(self):
        directory, pins = self.objects(lambda encoded: encoded[:-1])
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_trailing_bytes_with_consistent_outer_hash(self):
        directory, pins = self.objects(lambda encoded: encoded + b"x")
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_two_members_with_consistent_outer_hash(self):
        directory, pins = self.objects(lambda encoded: encoded + gzip.compress(b"second"))
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_expansion_past_declared_asset(self):
        directory, pins = self.objects()
        assets = copy.deepcopy(self.assets)
        assets["receipt.bin"]["bytes"] -= 1
        self.manifest(directory, pins, assets)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, assets, pins))

    def test_object_rejects_symlink_data(self):
        directory, pins = self.objects()
        path = self.chunk_path(directory, pins, "receipt.bin", 1)
        held = self.root / "held"
        path.rename(held)
        path.symlink_to(held)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_fifo_without_blocking(self):
        directory, pins = self.objects()
        path = self.chunk_path(directory, pins, "receipt.bin", 1)
        path.unlink()
        os.mkfifo(path)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_directory_symlink(self):
        directory, pins = self.objects()
        link = self.root / "linked-objects"
        link.symlink_to(directory, target_is_directory=True)
        self.refuse(lambda: fixture.restore_objects(link, self.out, self.assets, pins))

    def test_object_requires_each_receipt_chunk(self):
        directory, pins = self.objects()
        self.chunk_path(directory, pins, "receipt.bin", 1).unlink()
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_chunk_order_is_part_of_exact_manifest(self):
        directory, pins = self.objects()
        changed = copy.deepcopy(pins)
        changed["receipt.bin"]["chunks"].reverse()
        self.manifest(directory, changed)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_reordered_pinned_chunks_cannot_form_another_stream(self):
        directory, pins = self.objects()
        pins["receipt.bin"]["chunks"].reverse()
        self.manifest(directory, pins)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_checks_whole_gzip_after_individually_pinned_chunks(self):
        directory, pins = self.objects()
        pins["receipt.bin"]["sha256"] = "0" * 64
        self.manifest(directory, pins)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_repeated_chunk_reference(self):
        directory, pins = self.objects()
        pin = pins["receipt.bin"]
        pin["chunks"][1] = copy.deepcopy(pin["chunks"][0])
        pin["bytes"] = sum(chunk["bytes"] for chunk in pin["chunks"])
        self.manifest(directory, pins)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_third_chunk_even_with_consistent_byte_total(self):
        directory, pins = self.objects()
        pin = pins["receipt.bin"]
        pin["chunks"].append(copy.deepcopy(pin["chunks"][0]))
        pin["bytes"] = sum(chunk["bytes"] for chunk in pin["chunks"])
        self.manifest(directory, pins)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_whole_and_chunk_length_disagreement(self):
        directory, pins = self.objects()
        pins["receipt.bin"]["bytes"] += 1
        self.manifest(directory, pins)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_chunk_over_transport_cap(self):
        directory, pins = self.objects()
        with patch.object(fixture, "MAX_OBJECT_CHUNK_BYTES", 1):
            self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_total_compressed_and_expanded_caps(self):
        directory, pins = self.objects()
        for cap in ("MAX_TOTAL_OBJECT_BYTES", "MAX_TOTAL_OBJECT_EXPANDED_BYTES"):
            with self.subTest(cap=cap), patch.object(fixture, cap, 1):
                self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_chunk_name_traversal(self):
        directory, pins = self.objects()
        pins["receipt.bin"]["chunks"][1]["file"] = "../escape.gz.part"
        self.manifest(directory, pins)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_refuses_legacy_monolithic_object_as_extra_entry(self):
        directory, pins = self.objects()
        (directory / (pins["receipt.bin"]["sha256"] + ".gz")).write_bytes(
            self.compressed(self.data["receipt.bin"]))
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_second_member_at_exact_chunk_boundary(self):
        cut = len(self.compressed(self.data["receipt.bin"]))
        directory, pins = self.objects(lambda encoded: encoded + gzip.compress(b"second"), receipt_cut=cut)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_object_rejects_trailing_byte_at_exact_chunk_boundary(self):
        cut = len(self.compressed(self.data["receipt.bin"]))
        directory, pins = self.objects(lambda encoded: encoded + b"x", receipt_cut=cut)
        self.refuse(lambda: fixture.restore_objects(directory, self.out, self.assets, pins))

    def test_cli_requires_exactly_one_explicit_source(self):
        script = Path(fixture.__file__)
        for args in [[], ["--archive", "a", "--objects", "b"]]:
            result = subprocess.run([sys.executable, str(script), "--out", str(self.out), *args],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
