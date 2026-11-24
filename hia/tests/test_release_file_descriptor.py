"""Exact Unix held-file policy; the host, not HIA, acquires the observations."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_release_artifact_header import ALIASES
from hia.tests import test_release_transcript_composition as transcript

SOURCE = transcript.RAC1.with_name("file_descriptor.hepta")
HEAD = b"RFD1"
RULES = {"ok": 0, "wire": 100, "identity": 101}
STAT = struct.Struct("<QQI4xQqqqq")


def record(info):
    secs, nanos = divmod(info.st_mtime_ns, 1_000_000_000)
    changed, changed_nanos = divmod(info.st_ctime_ns, 1_000_000_000)
    return STAT.pack(info.st_dev, info.st_ino, info.st_mode, info.st_size,
                     secs, nanos, changed, changed_nanos)


def before_frame(expected, position, snap):
    return HEAD + struct.pack("<IQQ", 1, expected, position) + snap


def after_frame(before, after):
    return HEAD + struct.pack("<I", 2) + before + after


def rust_input(case, scenario):
    return (bytes([scenario]) + case.profile + case.instance
            + struct.pack("<QBQQQ", case.generation, case.kind, case.max_reads, case.max_bytes, case.size)
            + case.locator + b"".join(ALIASES[1:]) + case.data)


@contextmanager
def held_fixture(case, scenario):
    with tempfile.TemporaryDirectory(prefix="trnm-held-native-artifact-") as directory:
        root = Path(directory) / "only-fixture"
        root.mkdir()
        path = root / "artifact"
        if scenario == 3:
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd, None
            finally:
                os.close(fd)
            return
        path.write_bytes(case.data)
        with path.open("rb", buffering=0) as opened:
            if scenario == 1:
                path.rename(root / "moved-file")
                assert not path.exists()
            elif scenario == 2:
                opened.seek(1)
            elif scenario == 4:
                root.rename(Path(directory) / "moved-root")
                assert not path.exists()
            yield opened.fileno(), opened


class ReleaseFileDescriptor(unittest.TestCase):
    call = transcript.ReleaseTranscriptComposition.call

    @classmethod
    def setUpClass(cls):
        temporary = Path(cls.enterClassContext(tempfile.TemporaryDirectory(prefix="trnm-held-rust-oracle-")))
        cls.rust = transcript.original_reference(temporary, held_file=True)
        sources = (SOURCE, transcript.RAC1, transcript.CCH1, transcript.BOOT, transcript.SHA256, transcript.SHA512)
        cls.modules = {backend: {source: cls.enterClassContext(
            NativeModule(source, backend=backend, byte_exports=("f0",))) for source in sources}
            for backend in ("direct", "selfhost")}
        if cls.modules["direct"][SOURCE].artifact_sha256 == cls.modules["selfhost"][SOURCE].artifact_sha256:
            raise ValueError("expected independent native policy images")

    def observe_rust(self, case, scenario):
        with tempfile.TemporaryDirectory(prefix="trnm-held-original-artifact-") as directory:
            outcome = subprocess.run([str(self.rust), directory], input=rust_input(case, scenario),
                                     check=True, capture_output=True, timeout=20)
        self.assertEqual(outcome.stderr, b"")
        data = outcome.stdout
        self.assertIn(len(data), (162, 162 + 213))
        return struct.unpack_from("<BBQQQQ", data), data[34:98], data[98:162], data[162:]

    def observe_native(self, modules, case, scenario, head_expect, status_expect):
        with held_fixture(case, scenario) as (fd, file):
            meta = os.fstat(fd)
            before = record(meta)
            start = file.tell() if file is not None and stat.S_ISREG(meta.st_mode) and meta.st_size == case.size else 0
            pre = before_frame(case.size, start, before)
            self.assert_checked(modules[SOURCE], pre, head_expect)
            if head_expect != 0:
                return (head_expect, 0, start, start, 0, 0), b""

            result = transcript.ReleaseTranscriptComposition.observed(self, modules, case, reader=file)
            code, full, reads, charge, consumed, calls = struct.unpack_from("<BBQQQH", result)
            self.assertEqual(code, status_expect)
            self.assertEqual(file.tell(), consumed)
            claim = result[28 + 2 * calls:]
            if not code:
                self.assert_checked(modules[SOURCE], after_frame(before, record(os.fstat(fd))), 0)
            else:
                self.assertEqual(claim, b"")
            return (code, full, start, consumed, reads, charge), claim

    def assert_checked(self, native, frame, status):
        canaries = [frame, b"unchanged-proposal", b"unchanged-scratch"]
        result = native.call("f0", canaries).require_returned()
        self.assertEqual(result.value, status)
        self.assertEqual(result.arguments, canaries)

    def test_fresh_original_descriptor_and_native_held_bytes(self):
        data = transcript.sample(transcript.BLOCK + 9)
        item = transcript.Case(data, len(data), hashlib.sha256(data).digest(), name=b"node")
        wrong = replace(item, locator=bytes([0x81]) * 32)
        alternative_scope = replace(item, generation=item.generation + 1)
        rows = (
            (item, 0, 0, 0), (item, 1, 0, 0), (item, 4, 0, 0),
            (alternative_scope, 0, 0, 0),
            (item, 2, 101, 101), (item, 3, 101, 101),
            (replace(wrong, size=item.size + 1, kind=1, max_bytes=1), 0, 101, 101),
            (replace(wrong, kind=1, max_bytes=1), 0, 0, 1),
            (replace(wrong, max_bytes=1), 0, 0, 2), (wrong, 0, 0, 6),
        )
        original = [self.observe_rust(case, scenario) for case, scenario, _, _ in rows]
        self.assertEqual(original[0][-1], original[1][-1])
        self.assertEqual(original[0][-1], original[2][-1])
        self.assertNotEqual(original[0][-1][149:], original[3][-1][149:])

        for name, modules in self.modules.items():
            for row, (status, before, after, claim) in zip(rows, original, strict=True):
                case, scenario, pre, expected = row
                with self.subTest(backend=name, scenario=scenario, pre=pre, expected=expected):
                    self.assertEqual(status[0], expected)
                    self.assert_checked(modules[SOURCE], before_frame(case.size, status[2], before), pre)
                    if not expected:
                        self.assertEqual(before, after)
                        self.assert_checked(modules[SOURCE], after_frame(before, after), 0)
                    self.assertEqual(self.observe_native(modules, *row), (status, claim))

    def test_each_typed_metadata_field_and_exact_extent(self):
        data = b"disposable metadata fixture"
        case = transcript.Case(data, len(data), hashlib.sha256(data).digest(), name=b"node")
        _, before, after, _ = self.observe_rust(case, 0)
        self.assertEqual(before, after)
        pre, post = before_frame(case.size, 0, before), after_frame(before, after)
        controls = [(b"", 100), (pre[:-1], 100), (post + b"\x00", 100),
                    (b"BAD!" + pre[4:], 100), (pre[:4] + b"\x02" + pre[5:], 100)]
        for offset in (0, 8, 16, 24, 32, 40, 48, 56):
            different = bytearray(after)
            different[offset] ^= 1
            controls.append((after_frame(before, bytes(different)), 101))
        for index, source in ((44, pre), (28, post), (92, post)):
            noncanonical = bytearray(source)
            noncanonical[index] = 1
            controls.append((bytes(noncanonical), 100))
        for modules in self.modules.values():
            self.assert_checked(modules[SOURCE], pre, 0)
            self.assert_checked(modules[SOURCE], post, 0)
            for packet, status in controls:
                self.assert_checked(modules[SOURCE], packet, status)


if __name__ == "__main__":
    unittest.main()
