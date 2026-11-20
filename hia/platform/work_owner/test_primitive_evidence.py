"""Real descriptor, byte and guard controls for primitive evidence capture."""
from __future__ import annotations
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch
from . import primitive_evidence as evidence


def fixture(root, body=b"actual original bytes", left=evidence.LEFT):
    root.mkdir()
    (root / "chunks").mkdir()
    raw = left + body + evidence.RIGHT
    chunks = []
    sizes = {}
    for offset in range(0, len(raw), evidence.CHUNK_BYTES):
        part = raw[offset:offset + evidence.CHUNK_BYTES]
        key = hashlib.sha256(part).hexdigest()
        if key not in sizes:
            (root / "chunks" / (key + ".bin")).write_bytes(part)
            sizes[key] = len(part)
        chunks.append(key)
    key = hashlib.sha256(raw).hexdigest()
    index = {"chunk_sizes": sizes, "snapshots": {key: {"bytes": len(raw), "chunks": chunks}}}
    (root / "calls.jsonl").write_bytes(b"")
    (root / "manifest.json").write_bytes(evidence.encoded(index))
    return index, key


class PrimitiveBytes(unittest.TestCase):
    def fd_count(self):
        return len(os.listdir("/proc/self/fd"))

    def test_public_byte_reader_refuses_optimized_python_before_output(self):
        with tempfile.TemporaryDirectory(prefix="hia-wraw-cli-") as tmp:
            root = Path(tmp)
            output = root / "readback"
            argv = [sys.executable, "-O", "-m", "hia.platform.work_owner.primitive_evidence",
                    "--build", str(root / "build"), "--capture", str(root / "capture"),
                    "--primitive-report", str(root / "primitive.json"), "--output", str(output)]
            result = subprocess.run(argv, cwd=Path(__file__).resolve().parents[3],
                                    capture_output=True, timeout=30,
                                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"Primitive evidence CLI refuses optimized Python", result.stderr)
            self.assertFalse(output.exists())

    def test_whole_buffer_reconstruction_and_original_guard_bytes(self):
        body = bytes(range(256)) * 35 + b"last partial chunk"
        with tempfile.TemporaryDirectory(prefix="hia-wraw-") as tmp:
            root = Path(tmp) / "capture"
            index, key = fixture(root, body)
            with_reader = evidence.SafeRoot(root)
            try:
                snapshots = evidence.Snapshots(with_reader, index)
                self.assertEqual(snapshots.body(key, len(body)), body)
                self.assertEqual(snapshots.body(key, len(body)), body)
                with_reader.fence()
            finally:
                with_reader.close()
        for left in (b"\0" + evidence.LEFT[1:], evidence.LEFT[:-1] + b"\0"):
            with self.subTest(left=left.hex()), tempfile.TemporaryDirectory(prefix="hia-wraw-") as tmp:
                root = Path(tmp) / "capture"
                index, key = fixture(root, body, left=left)
                reader = evidence.SafeRoot(root)
                try:
                    snapshots = evidence.Snapshots(reader, index)
                    with self.assertRaisesRegex(ValueError, "guard"):
                        snapshots.body(key, len(body))
                finally:
                    reader.close()

    def test_chunk_omission_extra_and_content_change_are_real_file_refusals(self):
        for mutation in ("omit", "extra", "change", "wrong-extent"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="hia-wraw-") as tmp:
                root = Path(tmp) / "capture"
                index, key = fixture(root, b"retained source bytes")
                chunk = next(iter(index["chunk_sizes"]))
                path = root / "chunks" / (chunk + ".bin")
                if mutation == "omit":
                    path.unlink()
                elif mutation == "extra":
                    (root / "chunks" / ("0" * 64 + ".bin")).write_bytes(b"unlisted")
                elif mutation == "change":
                    raw = path.read_bytes()
                    path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
                else:
                    index["chunk_sizes"][chunk] += 1
                reader = evidence.SafeRoot(root)
                try:
                    with self.assertRaises(ValueError):
                        evidence.Snapshots(reader, index)
                finally:
                    reader.close()

    def test_regular_file_and_alias_requirements_do_not_block_on_fifo(self):
        for mutation in ("fifo", "directory", "symlink", "hardlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="hia-wraw-") as tmp:
                root = Path(tmp) / "capture"
                fixture(root)
                target = root / "calls.jsonl"
                target.unlink()
                outside = Path(tmp) / "outside"
                outside.write_bytes(b"")
                if mutation == "fifo":
                    os.mkfifo(target)
                elif mutation == "directory":
                    target.mkdir()
                elif mutation == "symlink":
                    target.symlink_to(outside)
                else:
                    os.link(outside, target)
                before = self.fd_count()
                reader = evidence.SafeRoot(root)
                try:
                    with self.assertRaises((ValueError, OSError)):
                        reader.read("calls.jsonl", 4096)
                finally:
                    reader.close()
                self.assertEqual(self.fd_count(), before)

    def test_ancestor_replacement_before_open_is_refused_and_after_pin_cannot_redirect(self):
        for when in ("before-parent-open", "after-parent-pin"):
            with self.subTest(when=when), tempfile.TemporaryDirectory(prefix="hia-wraw-") as tmp:
                base = Path(tmp)
                parent = base / "parent"
                parent.mkdir()
                alternate = base / "alternate"
                alternate.mkdir()
                original, key = fixture(parent / "capture", b"ORIGINAL")
                fixture(alternate / "capture", b"SUBSTITUTED")
                original_open = os.open
                fired = []
                before = self.fd_count()

                def transition(path, flags, *args, **kwargs):
                    selected = "parent" if when == "before-parent-open" else "capture"
                    if path == selected and kwargs.get("dir_fd") is not None and not fired:
                        fired.append(True)
                        parent.rename(base / "held")
                        parent.symlink_to(alternate, target_is_directory=True)
                    return original_open(path, flags, *args, **kwargs)

                with patch.object(evidence.os, "open", side_effect=transition):
                    if when == "before-parent-open":
                        with self.assertRaises(OSError):
                            evidence.SafeRoot(parent / "capture")
                    else:
                        reader = evidence.SafeRoot(parent / "capture")
                        try:
                            data = evidence.Snapshots(reader, original).body(key, len(b"ORIGINAL"))
                            self.assertEqual(data, b"ORIGINAL")
                            reader.fence()
                        finally:
                            reader.close()
                self.assertEqual(fired, [True])
                self.assertEqual(self.fd_count(), before)
                self.assertEqual((base / "held/capture/manifest.json").read_bytes(), evidence.encoded(original))

    def test_final_fence_detects_same_content_replacement_and_new_roster(self):
        for mutation in ("same-content-inode", "new-file"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="hia-wraw-") as tmp:
                root = Path(tmp) / "capture"
                fixture(root)
                reader = evidence.SafeRoot(root)
                try:
                    original = reader.read("manifest.json", 65536)
                    if mutation == "same-content-inode":
                        replacement = Path(tmp) / "replacement"
                        replacement.write_bytes(original)
                        replacement.replace(root / "manifest.json")
                    else:
                        (root / "extra").write_bytes(b"extra")
                    with self.assertRaises(ValueError):
                        reader.fence()
                finally:
                    reader.close()

    def test_buffer_extent_and_metadata_numeric_types_cannot_substitute(self):
        for mutation in ("float-size", "bool-size", "short-buffer", "unreferenced-chunk"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="hia-wraw-") as tmp:
                root = Path(tmp) / "capture"
                index, key = fixture(root, b"complete")
                if mutation == "float-size":
                    index["snapshots"][key]["bytes"] = float(index["snapshots"][key]["bytes"])
                elif mutation == "bool-size":
                    chunk = next(iter(index["chunk_sizes"]))
                    index["chunk_sizes"][chunk] = True
                elif mutation == "short-buffer":
                    index["snapshots"][key]["bytes"] -= 1
                else:
                    raw = b"unreferenced retained bytes"
                    extra = hashlib.sha256(raw).hexdigest()
                    (root / "chunks" / (extra + ".bin")).write_bytes(raw)
                    index["chunk_sizes"][extra] = len(raw)
                reader = evidence.SafeRoot(root)
                try:
                    with self.assertRaises(ValueError):
                        evidence.Snapshots(reader, index)
                finally:
                    reader.close()


if __name__ == "__main__":
    unittest.main()
